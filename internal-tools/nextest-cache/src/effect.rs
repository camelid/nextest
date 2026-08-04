// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-process I/O tracing and cacheability decisions.

use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::process::id;
use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, Metadata},
    io::{self, BufRead, BufReader, Read},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus},
    time::SystemTime,
};
use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

const MANIFEST_VERSION: u32 = 1;
const HASH_BUFFER_SIZE: usize = 256 * 1024;
const TRACED_SYSCALLS: &str = concat!(
    "trace=",
    "open,openat,openat2,creat,",
    "stat,lstat,newfstatat,statx,access,faccessat,faccessat2,readlink,readlinkat,",
    "unlink,unlinkat,rmdir,truncate,rename,renameat,renameat2,link,linkat,",
    "symlink,symlinkat,mkdir,mkdirat,mknod,mknodat,",
    "chmod,fchmodat,chown,lchown,fchownat,utime,utimes,utimensat,",
    "connect,bind,listen,accept,accept4,execve,execveat",
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectPolicy {
    Off,
    Conservative,
    ContentAddressed,
}

impl EffectPolicy {
    pub(crate) fn default_for_platform() -> Self {
        if cfg!(target_os = "linux") {
            Self::ContentAddressed
        } else {
            Self::Off
        }
    }

    pub(crate) fn key(self) -> &'static [u8] {
        match self {
            Self::Off => b"effect-ledger-v1:off",
            Self::Conservative => b"effect-ledger-v1:conservative",
            Self::ContentAddressed => b"effect-ledger-v1:content-addressed",
        }
    }

    pub(crate) fn traces(self) -> bool {
        self != Self::Off
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EffectManifest {
    format_version: u32,
    inputs: Vec<FileInput>,
}

impl EffectManifest {
    pub(crate) fn off() -> Self {
        Self {
            format_version: MANIFEST_VERSION,
            inputs: Vec::new(),
        }
    }

    pub(crate) fn is_current(&self) -> Result<bool, EffectError> {
        if self.format_version != MANIFEST_VERSION {
            return Ok(false);
        }
        for input in &self.inputs {
            if hash_file(Path::new(&input.path))? != input.xxh3_128 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
struct FileInput {
    path: String,
    xxh3_128: String,
}

#[derive(Debug)]
pub(crate) struct EffectTrace {
    temp: camino_tempfile::Utf8TempDir,
    trace_prefix: PathBuf,
    cwd: PathBuf,
    artifact: PathBuf,
}

impl EffectTrace {
    pub(crate) fn new(cwd: PathBuf, artifact: PathBuf) -> Result<Self, EffectError> {
        let temp = camino_tempfile::tempdir().map_err(|source| EffectError::Io {
            context: "failed to create the effect trace directory".to_owned(),
            source,
        })?;
        let trace_prefix = temp.path().join("strace").into();
        Ok(Self {
            temp,
            trace_prefix,
            cwd,
            artifact,
        })
    }

    pub(crate) fn status(
        &self,
        program: &OsStr,
        args: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> Result<ExitStatus, EffectError> {
        Command::new("strace")
            .args([
                OsStr::new("-ff"),
                OsStr::new("-qq"),
                OsStr::new("-s"),
                OsStr::new("0"),
                OsStr::new("-yy"),
                OsStr::new("-e"),
                OsStr::new(TRACED_SYSCALLS),
                OsStr::new("-e"),
                OsStr::new("raw=execve,execveat"),
                OsStr::new("-o"),
            ])
            .arg(&self.trace_prefix)
            .arg("--")
            .arg(program)
            .args(args)
            .env_clear()
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .status()
            .map_err(|source| EffectError::Io {
                context: "failed to execute strace".to_owned(),
                source,
            })
    }

    pub(crate) fn finish(self, policy: EffectPolicy) -> Result<EffectClassification, EffectError> {
        let ledger = EffectLedger::read(
            self.temp.path().as_std_path(),
            &self.trace_prefix,
            &self.cwd,
        )?;
        ledger.classify(policy, &self.cwd, &self.artifact)
    }
}

#[derive(Debug)]
pub(crate) enum EffectClassification {
    Cacheable(EffectManifest),
    Uncacheable(Vec<EffectReason>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EffectReason {
    ExternalRead(PathBuf),
    ExternalWrite(PathBuf),
    Network,
    Subprocess,
    UnhashableInput(PathBuf),
}

impl fmt::Display for EffectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalRead(path) => write!(formatter, "external read from {}", path.display()),
            Self::ExternalWrite(path) => {
                write!(formatter, "external write to {}", path.display())
            }
            Self::Network => formatter.write_str("network I/O"),
            Self::Subprocess => formatter.write_str("subprocess execution"),
            Self::UnhashableInput(path) => {
                write!(formatter, "unhashable input {}", path.display())
            }
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum EffectError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("strace did not observe the test program starting")]
    TestNotStarted,
}

#[derive(Default)]
struct EffectLedger {
    reads: BTreeSet<PathBuf>,
    failed_reads: BTreeSet<PathBuf>,
    writes: BTreeSet<PathBuf>,
    produced: BTreeSet<PathBuf>,
    network: bool,
    exec_count: usize,
}

impl EffectLedger {
    fn read(trace_dir: &Path, trace_prefix: &Path, cwd: &Path) -> Result<Self, EffectError> {
        let prefix = trace_prefix
            .file_name()
            .expect("a trace prefix has a file name");
        let mut ledger = Self::default();
        let entries = fs::read_dir(trace_dir).map_err(|source| EffectError::Io {
            context: format!(
                "failed to read the effect trace directory {}",
                trace_dir.display()
            ),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| EffectError::Io {
                context: format!(
                    "failed to read an entry in the effect trace directory {}",
                    trace_dir.display()
                ),
                source,
            })?;
            if !entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(prefix.as_encoded_bytes())
            {
                continue;
            }
            ledger.read_file(&entry.path(), cwd)?;
        }
        Ok(ledger)
    }

    fn read_file(&mut self, path: &Path, cwd: &Path) -> Result<(), EffectError> {
        let file = File::open(path).map_err(|source| EffectError::Io {
            context: format!("failed to open the effect trace {}", path.display()),
            source,
        })?;
        let mut loader_phase = false;
        for line in BufReader::new(file).split(b'\n') {
            let line = line.map_err(|source| EffectError::Io {
                context: format!("failed to read the effect trace {}", path.display()),
                source,
            })?;
            self.record_line(&line, cwd, &mut loader_phase);
        }
        Ok(())
    }

    fn record_line(&mut self, line: &[u8], cwd: &Path, loader_phase: &mut bool) {
        let Some((name, arguments)) = syscall(line) else {
            return;
        };
        let succeeded = syscall_succeeded(line);
        match name {
            b"execve" | b"execveat" => {
                self.exec_count += 1;
                *loader_phase = succeeded;
            }
            b"connect" | b"bind" | b"listen" | b"accept" | b"accept4" => {
                if !has_flag(arguments, br#"AF_UNIX, sun_path="""#) {
                    self.network = true;
                }
            }
            b"open" | b"openat" | b"openat2" => {
                let Some(path) = first_path(arguments).map(|path| normalize_path(cwd, &path))
                else {
                    return;
                };
                if *loader_phase {
                    if is_loader_path(&path, cwd) {
                        return;
                    }
                    *loader_phase = false;
                }
                if has_flag(arguments, b"O_TMPFILE") {
                    return;
                }
                if has_flag(arguments, b"O_WRONLY")
                    || has_flag(arguments, b"O_RDWR")
                    || has_flag(arguments, b"O_CREAT")
                    || has_flag(arguments, b"O_TRUNC")
                {
                    self.writes.insert(path.clone());
                }
                if succeeded && has_flag(arguments, b"O_CREAT") && has_flag(arguments, b"O_EXCL") {
                    self.produced.insert(path.clone());
                }
                if !has_flag(arguments, b"O_WRONLY") {
                    if !succeeded {
                        self.failed_reads.insert(path.clone());
                    }
                    self.reads.insert(path);
                }
            }
            b"creat" | b"mkdir" | b"mkdirat" | b"mknod" | b"mknodat" => {
                if let Some(path) = first_path(arguments).map(|path| normalize_path(cwd, &path)) {
                    if succeeded {
                        self.produced.insert(path.clone());
                    }
                    self.writes.insert(path);
                }
            }
            b"unlink" | b"unlinkat" | b"rmdir" | b"truncate" | b"rename" | b"renameat"
            | b"renameat2" | b"link" | b"linkat" | b"symlink" | b"symlinkat" | b"chmod"
            | b"fchmodat" | b"chown" | b"lchown" | b"fchownat" | b"utime" | b"utimes"
            | b"utimensat" => {
                for path in paths(arguments) {
                    self.writes.insert(normalize_path(cwd, &path));
                }
            }
            b"stat" | b"lstat" | b"newfstatat" | b"statx" | b"access" | b"faccessat"
            | b"faccessat2" | b"readlink" | b"readlinkat" => {
                if let Some(path) = first_path(arguments) {
                    if path.as_os_str().is_empty() && has_flag(arguments, b"AT_EMPTY_PATH") {
                        return;
                    }
                    let path = normalize_path(cwd, &path);
                    if *loader_phase {
                        if is_loader_path(&path, cwd) {
                            return;
                        }
                        *loader_phase = false;
                    }
                    if !succeeded {
                        self.failed_reads.insert(path.clone());
                    }
                    self.reads.insert(path);
                }
            }
            _ => {}
        }
    }

    fn classify(
        self,
        policy: EffectPolicy,
        cwd: &Path,
        artifact: &Path,
    ) -> Result<EffectClassification, EffectError> {
        let artifact = normalize_path(cwd, artifact);
        let temp_root = normalize_path(cwd, &env::temp_dir());
        let mut reasons = BTreeSet::new();
        let mut inputs = BTreeSet::new();

        if self.exec_count == 0 {
            return Err(EffectError::TestNotStarted);
        }
        if self.network {
            reasons.insert(EffectReason::Network);
        }
        if self.exec_count > 1 {
            reasons.insert(EffectReason::Subprocess);
        }

        for path in self.writes {
            let private_and_ephemeral =
                self.produced.contains(&path) && path.starts_with(&temp_root) && !path.exists();
            if !private_and_ephemeral {
                reasons.insert(EffectReason::ExternalWrite(path));
            }
        }

        for path in self.reads {
            if path == artifact
                || path == temp_root
                || self.produced.contains(&path)
                || is_ambient_path(&path)
            {
                continue;
            }
            if self.failed_reads.contains(&path) {
                reasons.insert(EffectReason::UnhashableInput(path));
                continue;
            }
            match policy {
                EffectPolicy::Off => {}
                EffectPolicy::Conservative => {
                    reasons.insert(EffectReason::ExternalRead(path));
                }
                EffectPolicy::ContentAddressed => {
                    let Some(path_string) = path.to_str() else {
                        reasons.insert(EffectReason::UnhashableInput(path));
                        continue;
                    };
                    match hash_file(&path) {
                        Ok(xxh3_128) => {
                            inputs.insert(FileInput {
                                path: path_string.to_owned(),
                                xxh3_128,
                            });
                        }
                        Err(_) => {
                            reasons.insert(EffectReason::UnhashableInput(path));
                        }
                    }
                }
            }
        }

        if reasons.is_empty() {
            Ok(EffectClassification::Cacheable(EffectManifest {
                format_version: MANIFEST_VERSION,
                inputs: inputs.into_iter().collect(),
            }))
        } else {
            Ok(EffectClassification::Uncacheable(
                reasons.into_iter().collect(),
            ))
        }
    }
}

fn syscall(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let open = line.iter().position(|byte| *byte == b'(')?;
    let name_start = line[..open]
        .iter()
        .rposition(|byte| byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    let close = line.windows(2).rposition(|window| window == b") ")? + 1;
    Some((&line[name_start..open], &line[open + 1..close]))
}

fn syscall_succeeded(line: &[u8]) -> bool {
    line.windows(4).any(|window| window == b") = ")
        && !line.windows(5).any(|window| window == b"= -1 ")
}

fn has_flag(arguments: &[u8], flag: &[u8]) -> bool {
    arguments.windows(flag.len()).any(|window| window == flag)
}

fn first_path(arguments: &[u8]) -> Option<PathBuf> {
    paths(arguments).next()
}

fn paths(arguments: &[u8]) -> impl Iterator<Item = PathBuf> + '_ {
    QuotedStrings {
        remaining: arguments,
    }
    .map(PathBuf::from)
}

struct QuotedStrings<'a> {
    remaining: &'a [u8],
}

impl Iterator for QuotedStrings<'_> {
    type Item = OsString;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.remaining.iter().position(|byte| *byte == b'"')? + 1;
        let bytes = &self.remaining[start..];
        let mut value = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'"' => {
                    self.remaining = &bytes[index + 1..];
                    return Some(os_string_from_bytes(value));
                }
                b'\\' => {
                    index += 1;
                    let escaped = *bytes.get(index)?;
                    match escaped {
                        b'\\' | b'"' => value.push(escaped),
                        b'n' => value.push(b'\n'),
                        b'r' => value.push(b'\r'),
                        b't' => value.push(b'\t'),
                        b'x' => {
                            let high = hex_digit(*bytes.get(index + 1)?)?;
                            let low = hex_digit(*bytes.get(index + 2)?)?;
                            value.push(high << 4 | low);
                            index += 2;
                        }
                        b'0'..=b'7' => {
                            let mut byte = escaped - b'0';
                            for _ in 0..2 {
                                let Some(digit @ b'0'..=b'7') = bytes.get(index + 1).copied()
                                else {
                                    break;
                                };
                                byte = byte.saturating_mul(8).saturating_add(digit - b'0');
                                index += 1;
                            }
                            value.push(byte);
                        }
                        _ => value.push(escaped),
                    }
                }
                byte => value.push(byte),
            }
            index += 1;
        }
        self.remaining = &[];
        None
    }
}

#[cfg(unix)]
fn os_string_from_bytes(bytes: Vec<u8>) -> OsString {
    use std::os::unix::ffi::OsStringExt;

    OsString::from_vec(bytes)
}

#[cfg(not(unix))]
fn os_string_from_bytes(bytes: Vec<u8>) -> OsString {
    String::from_utf8_lossy(&bytes).into_owned().into()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn normalize_path(cwd: &Path, path: &Path) -> PathBuf {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component),
        }
    }
    normalized
}

fn is_ambient_path(path: &Path) -> bool {
    let system_path = [
        "/dev",
        "/proc",
        "/sys",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/share/locale",
        "/usr/share/terminfo",
        "/usr/share/zoneinfo",
        "/etc/terminfo",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix));
    let user_terminfo = env::var_os("HOME")
        .map(PathBuf::from)
        .is_some_and(|home| path.starts_with(home.join(".terminfo")));
    system_path || user_terminfo
}

fn is_loader_path(path: &Path, cwd: &Path) -> bool {
    if [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }

    ["LD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"]
        .iter()
        .filter_map(env::var_os)
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|root| normalize_path(cwd, &root))
        .any(|root| !root.as_os_str().is_empty() && path.starts_with(root))
}

fn hash_file(path: &Path) -> Result<String, EffectError> {
    hash_file_with(path, || {})
}

fn hash_file_with(path: &Path, after_read: impl FnOnce()) -> Result<String, EffectError> {
    let path_before = fs::metadata(path).map_err(|source| EffectError::Io {
        context: format!(
            "failed to read metadata for the effect input {}",
            path.display()
        ),
        source,
    })?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(source) => {
            return Err(EffectError::Io {
                context: format!("failed to open the effect input {}", path.display()),
                source,
            });
        }
    };
    let file_before = file.metadata().map_err(|source| EffectError::Io {
        context: format!(
            "failed to read metadata for the effect input {}",
            path.display()
        ),
        source,
    })?;
    let identity = InputIdentity::new(&file_before);
    if InputIdentity::new(&path_before) != identity {
        return Err(input_changed(path));
    }
    if !file_before.is_file() {
        return Err(EffectError::Io {
            context: format!("the effect input {} is not a regular file", path.display()),
            source: io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
        });
    }

    let mut hasher = Xxh3::new();
    let mut buffer = vec![0; HASH_BUFFER_SIZE];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(EffectError::Io {
                    context: format!("failed to hash the effect input {}", path.display()),
                    source,
                });
            }
        }
    }

    after_read();
    let file_after = file.metadata().map_err(|source| EffectError::Io {
        context: format!(
            "failed to re-read metadata for the effect input {}",
            path.display()
        ),
        source,
    })?;
    let path_after = fs::metadata(path).map_err(|source| EffectError::Io {
        context: format!(
            "failed to re-read path metadata for the effect input {}",
            path.display()
        ),
        source,
    })?;
    if InputIdentity::new(&file_after) != identity || InputIdentity::new(&path_after) != identity {
        return Err(input_changed(path));
    }
    Ok(hex::encode(hasher.digest128().to_be_bytes()))
}

fn input_changed(path: &Path) -> EffectError {
    EffectError::Io {
        context: format!(
            "the effect input {} changed while it was hashed",
            path.display()
        ),
        source: io::Error::new(io::ErrorKind::InvalidData, "input changed"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

impl InputIdentity {
    fn new(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            change_seconds: metadata.ctime(),
            #[cfg(unix)]
            change_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(lines: &[&[u8]], cwd: &Path) -> EffectLedger {
        let mut ledger = EffectLedger::default();
        let mut loader_phase = false;
        for line in lines {
            ledger.record_line(line, cwd, &mut loader_phase);
        }
        ledger
    }

    #[test]
    fn parses_file_network_and_process_effects() {
        let ledger = ledger(
            &[
                br#"openat(AT_FDCWD, "input\x2etxt", O_RDONLY|O_CLOEXEC) = 3</cwd/input.txt>"#,
                br#"openat(AT_FDCWD, "/tmp/out", O_WRONLY|O_CREAT|O_EXCL, 0600) = 4</tmp/out>"#,
                br#"connect(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0"#,
                br#"execve(0x1234, 0x5678, 0x9abc) = 0"#,
                br#"execve(0x1234, 0x5678, 0x9abc) = 0"#,
            ],
            Path::new("/cwd"),
        );

        assert!(ledger.reads.contains(Path::new("/cwd/input.txt")));
        assert!(ledger.writes.contains(Path::new("/tmp/out")));
        assert!(ledger.produced.contains(Path::new("/tmp/out")));
        assert!(ledger.network);
        assert_eq!(ledger.exec_count, 2);
    }

    #[test]
    fn records_failed_file_reads_and_ignores_anonymous_unix_sockets() {
        let ledger = ledger(
            &[
                br#"execve(0x1, 0x2, 0x3) = 0"#,
                br#"statx(AT_FDCWD, "/usr/lib/glibc-hwcaps/x86-64-v4", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = -1 ENOENT (No such file or directory)"#,
                br#"openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
                br#"connect(3, {sa_family=AF_UNIX, sun_path=""}, 2) = 0"#,
                br#"statx(3</proc/self/cgroup>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, 0x1) = 0"#,
            ],
            Path::new("/cwd"),
        );

        assert_eq!(ledger.reads, [PathBuf::from("/missing")].into());
        assert_eq!(ledger.failed_reads, [PathBuf::from("/missing")].into());
        assert!(!ledger.network);
    }

    #[test]
    fn named_unix_sockets_are_external_network() {
        let ledger = ledger(
            &[br#"connect(3, {sa_family=AF_UNIX, sun_path="/tmp/service"}, 15) = 0"#],
            Path::new("/cwd"),
        );

        assert!(ledger.network);
    }

    #[test]
    fn conservative_rejects_external_reads_and_writes() {
        let ledger = ledger(
            &[
                br#"execve(0x1, 0x2, 0x3) = 0"#,
                br#"openat(AT_FDCWD, "/fixture", O_RDONLY) = 3</fixture>"#,
                br#"openat(AT_FDCWD, "/output", O_WRONLY|O_CREAT, 0666) = 4</output>"#,
            ],
            Path::new("/cwd"),
        );
        let EffectClassification::Uncacheable(reasons) = ledger
            .classify(
                EffectPolicy::Conservative,
                Path::new("/cwd"),
                Path::new("/artifact"),
            )
            .unwrap()
        else {
            panic!("external effects should be uncacheable");
        };
        assert_eq!(
            reasons,
            [
                EffectReason::ExternalRead(PathBuf::from("/fixture")),
                EffectReason::ExternalWrite(PathBuf::from("/output")),
            ],
        );
    }

    #[test]
    fn failed_reads_and_external_process_effects_are_uncacheable() {
        let ledger = ledger(
            &[
                br#"execve(0x1, 0x2, 0x3) = 0"#,
                br#"openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
                br#"connect(3, {sa_family=AF_INET, sin_port=htons(80)}, 16) = -1 ECONNREFUSED (Connection refused)"#,
                br#"execve(0x4, 0x5, 0x6) = -1 ENOENT (No such file or directory)"#,
            ],
            Path::new("/cwd"),
        );
        let EffectClassification::Uncacheable(reasons) = ledger
            .classify(
                EffectPolicy::ContentAddressed,
                Path::new("/cwd"),
                Path::new("/artifact"),
            )
            .unwrap()
        else {
            panic!("failed external effects should be uncacheable");
        };

        assert_eq!(
            reasons,
            [
                EffectReason::Network,
                EffectReason::Subprocess,
                EffectReason::UnhashableInput(PathBuf::from("/missing")),
            ],
        );
    }

    #[test]
    fn removed_exclusive_temporary_files_are_cacheable() {
        let path = env::temp_dir().join(format!("nextest-cache-effect-ledger-test-{}", id()));
        assert!(!path.exists());
        let open = format!(
            "openat(AT_FDCWD, {path:?}, O_RDWR|O_CREAT|O_EXCL, 0600) = 3<{}>",
            path.display(),
        );
        let unlink = format!("unlink({path:?}) = 0");
        let ledger = ledger(
            &[
                br#"execve(0x1, 0x2, 0x3) = 0"#,
                open.as_bytes(),
                unlink.as_bytes(),
            ],
            Path::new("/cwd"),
        );

        assert!(matches!(
            ledger
                .classify(
                    EffectPolicy::Conservative,
                    Path::new("/cwd"),
                    Path::new("/artifact"),
                )
                .unwrap(),
            EffectClassification::Cacheable(_),
        ));
    }

    #[test]
    fn content_addressed_inputs_are_validated() {
        let temp = camino_tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::write(&input, b"first").unwrap();
        let line = format!(
            "openat(AT_FDCWD, {:?}, O_RDONLY) = 3<{}>",
            input.as_str(),
            input
        );
        let ledger = ledger(
            &[br#"execve(0x1, 0x2, 0x3) = 0"#, line.as_bytes()],
            Path::new("/cwd"),
        );
        let EffectClassification::Cacheable(manifest) = ledger
            .classify(
                EffectPolicy::ContentAddressed,
                Path::new("/cwd"),
                Path::new("/artifact"),
            )
            .unwrap()
        else {
            panic!("a regular-file input should be cacheable");
        };

        assert!(manifest.is_current().unwrap());
        fs::write(input, b"second").unwrap();
        assert!(!manifest.is_current().unwrap());
    }

    #[test]
    fn inputs_changing_while_hashed_are_rejected() {
        let temp = camino_tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::write(&input, b"first").unwrap();

        assert!(
            hash_file_with(input.as_std_path(), || fs::write(&input, b"second")
                .unwrap())
            .is_err(),
        );
    }
}
