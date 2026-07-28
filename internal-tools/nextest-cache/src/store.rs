// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persistent clean-pass entries and per-run artifact hash memos.

use crate::{cache::domain_digest, error::CacheError};
use atomicwrites::{AllowOverwrite, AtomicFile};
use etcetera::{BaseStrategy, choose_base_strategy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, Metadata, OpenOptions, TryLockError},
    io::{self, Read},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const CACHE_DIR_ENV: &str = "NEXTEST_CACHE_DIR";
const STORAGE_VERSION_DIR: &str = "storage-v2";
const ENTRY_VERSION: u32 = 1;
const RUN_HASH_VERSION: u32 = 1;
const RUN_ID_DOMAIN: &[u8] = b"nextest-wrapper-cache-run-id-v1";
const ARTIFACT_PATH_DOMAIN: &[u8] = b"nextest-wrapper-cache-artifact-path-v1";
const HASH_BUFFER_SIZE: usize = 256 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const RUN_HASH_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Clone, Debug)]
pub(crate) struct CacheStore {
    root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactDigest {
    pub(crate) bytes: [u8; 32],
    pub(crate) was_hashed: bool,
}

impl CacheStore {
    pub(crate) fn discover() -> Result<Self, CacheError> {
        let base = match env::var_os(CACHE_DIR_ENV) {
            Some(path) => PathBuf::from(path),
            None => choose_base_strategy()
                .map_err(|error| CacheError::CacheDirectory(error.to_string()))?
                .cache_dir()
                .join("nextest")
                .join("cache"),
        };
        Ok(Self {
            root: base.join(STORAGE_VERSION_DIR),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_root(root: PathBuf) -> Self {
        Self {
            root: root.join(STORAGE_VERSION_DIR),
        }
    }

    pub(crate) fn contains_clean_pass(&self, token: &str) -> Result<bool, CacheError> {
        validate_token(token)?;
        let path = self.entry_path(token);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(CacheError::io(
                    format!("failed to read the cache entry {}", path.display()),
                    error,
                ));
            }
        };

        let Ok(entry) = serde_json::from_slice::<CacheEntry>(&bytes) else {
            return Ok(false);
        };
        Ok(entry.version == ENTRY_VERSION)
    }

    pub(crate) fn store_clean_pass(&self, token: &str) -> Result<(), CacheError> {
        validate_token(token)?;
        self.with_lock(&self.entry_lock_path(token), "the cache entry lock", || {
            let path = self.entry_path(token);
            atomic_write_json(
                &path,
                &CacheEntry {
                    version: ENTRY_VERSION,
                },
                "the cache entry",
            )
        })
    }

    pub(crate) fn invalidate(&self, token: &str) -> Result<(), CacheError> {
        validate_token(token)?;
        self.with_lock(&self.entry_lock_path(token), "the cache entry lock", || {
            let path = self.entry_path(token);
            match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(CacheError::io(
                    format!("failed to remove the cache entry {}", path.display()),
                    error,
                )),
            }
        })
    }

    pub(crate) fn load_or_hash_for_run(
        &self,
        run_id: &OsStr,
        artifact: &Path,
    ) -> Result<ArtifactDigest, CacheError> {
        let run_token = domain_digest(RUN_ID_DOMAIN, run_id);
        let artifact_token = domain_digest(ARTIFACT_PATH_DOMAIN, artifact.as_os_str());
        let _run_lease = self.acquire_run_lease(&run_token)?;
        self.ensure_run_directory(&run_token)?;
        self.touch_run_directory(&run_token)?;

        self.with_lock(
            &self.run_hash_lock_path(&run_token, &artifact_token),
            "the per-run artifact lock",
            || {
                let current_identity = metadata_identity(artifact)?;
                let memo_path = self.run_hash_path(&run_token, &artifact_token);
                if let Some(digest) =
                    read_run_hash_memo(&memo_path, &artifact_token, &current_identity)?
                {
                    let identity_after = metadata_identity(artifact)?;
                    if identity_after == current_identity {
                        return Ok(ArtifactDigest {
                            bytes: digest,
                            was_hashed: false,
                        });
                    }
                }

                let (digest, identity) = hash_artifact(artifact)?;
                atomic_write_json(
                    &memo_path,
                    &RunHashMemo {
                        version: RUN_HASH_VERSION,
                        artifact_path_digest: artifact_token,
                        artifact_identity: identity,
                        sha256: hex::encode(digest),
                    },
                    "the per-run artifact hash memo",
                )?;
                Ok(ArtifactDigest {
                    bytes: digest,
                    was_hashed: true,
                })
            },
        )
    }

    fn ensure_run_directory(&self, run_token: &str) -> Result<(), CacheError> {
        let run_hashes = self.root.join("run-hashes");
        fs::create_dir_all(&run_hashes).map_err(|error| {
            CacheError::io(
                format!(
                    "failed to create the run-hash directory {}",
                    run_hashes.display()
                ),
                error,
            )
        })?;
        let run_directory = run_hashes.join(run_token);
        match fs::create_dir(&run_directory) {
            Ok(()) => self.prune_run_hashes(run_token),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(CacheError::io(
                    format!(
                        "failed to create the run-hash directory {}",
                        run_directory.display()
                    ),
                    error,
                ));
            }
        }
        Ok(())
    }

    fn prune_run_hashes(&self, current_run_token: &str) {
        self.prune_run_hashes_older_than(current_run_token, RUN_HASH_RETENTION);
    }

    fn prune_run_hashes_older_than(&self, current_run_token: &str, retention: Duration) {
        let Ok(gate) = self.open_lock_file(&self.run_hash_prune_lock_path()) else {
            return;
        };
        if gate.try_lock().is_err() {
            return;
        }

        let run_hashes = self.root.join("run-hashes");
        let Ok(entries) = fs::read_dir(&run_hashes) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() || entry.file_name() == current_run_token {
                continue;
            }
            let modified = fs::metadata(self.run_hash_last_used_path(&entry.file_name()))
                .or_else(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        entry.metadata()
                    } else {
                        Err(error)
                    }
                })
                .and_then(|metadata| metadata.modified());
            let Ok(modified) = modified else {
                continue;
            };
            if now
                .duration_since(modified)
                .is_ok_and(|age| age >= retention)
            {
                self.try_prune_run_hash(entry.file_name(), entry.path());
            }
        }
    }

    fn touch_run_directory(&self, run_token: &str) -> Result<(), CacheError> {
        let path = self.run_hash_last_used_path(OsStr::new(run_token));
        // A directory mtime does not change when an existing memo is reused.
        let marker = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|error| {
                CacheError::io(
                    format!("failed to open the run-hash marker {}", path.display()),
                    error,
                )
            })?;
        marker.set_modified(SystemTime::now()).map_err(|error| {
            CacheError::io(
                format!("failed to update the run-hash marker {}", path.display()),
                error,
            )
        })
    }

    fn try_prune_run_hash(&self, run_token: OsString, run_hash_path: PathBuf) {
        let lease_path = self.run_hash_lease_path(&run_token);
        let lease = match OpenOptions::new().read(true).write(true).open(&lease_path) {
            Ok(lease) => {
                if lease.try_lock().is_err() {
                    return;
                }
                Some(lease)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return,
        };

        if fs::remove_dir_all(run_hash_path).is_err() {
            return;
        }
        let _ = fs::remove_dir_all(self.root.join("locks").join("run-hashes").join(&run_token));
        drop(lease);
        let _ = fs::remove_file(lease_path);
    }

    fn acquire_run_lease(&self, run_token: &str) -> Result<File, CacheError> {
        let gate = self.open_lock_file(&self.run_hash_prune_lock_path())?;
        acquire_shared_lock(&gate, "the run-hash lifecycle gate", LOCK_TIMEOUT)?;

        let lease = self.open_lock_file(&self.run_hash_lease_path(OsStr::new(run_token)))?;
        acquire_shared_lock(&lease, "the run-hash lease", LOCK_TIMEOUT)?;
        Ok(lease)
    }

    fn with_lock<T>(
        &self,
        lock_path: &Path,
        context: &str,
        operation: impl FnOnce() -> Result<T, CacheError>,
    ) -> Result<T, CacheError> {
        let lock = self.open_lock_file(lock_path)?;
        acquire_lock(&lock, context, LOCK_TIMEOUT)?;
        operation()
    }

    fn open_lock_file(&self, lock_path: &Path) -> Result<File, CacheError> {
        let parent = lock_path.parent().expect("a lock path has a parent");
        fs::create_dir_all(parent).map_err(|error| {
            CacheError::io(
                format!("failed to create the lock directory {}", parent.display()),
                error,
            )
        })?;
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|error| {
                CacheError::io(
                    format!("failed to open the lock {}", lock_path.display()),
                    error,
                )
            })
    }

    fn entry_path(&self, token: &str) -> PathBuf {
        self.root
            .join("entries")
            .join(&token[..2])
            .join(format!("{token}.json"))
    }

    fn entry_lock_path(&self, token: &str) -> PathBuf {
        self.root
            .join("locks")
            .join("entries")
            .join(&token[..2])
            .join(format!("{token}.lock"))
    }

    fn run_hash_path(&self, run_token: &str, artifact_token: &str) -> PathBuf {
        self.root
            .join("run-hashes")
            .join(run_token)
            .join(&artifact_token[..2])
            .join(format!("{artifact_token}.json"))
    }

    fn run_hash_last_used_path(&self, run_token: &OsStr) -> PathBuf {
        self.root
            .join("run-hashes")
            .join(run_token)
            .join(".last-used")
    }

    fn run_hash_lock_path(&self, run_token: &str, artifact_token: &str) -> PathBuf {
        self.root
            .join("locks")
            .join("run-hashes")
            .join(run_token)
            .join(&artifact_token[..2])
            .join(format!("{artifact_token}.lock"))
    }

    fn run_hash_prune_lock_path(&self) -> PathBuf {
        self.root.join("locks").join("run-hash-prune.lock")
    }

    fn run_hash_lease_path(&self, run_token: &OsStr) -> PathBuf {
        self.root
            .join("locks")
            .join("run-hash-leases")
            .join(run_token)
            .with_extension("lock")
    }
}

fn read_run_hash_memo(
    path: &Path,
    artifact_token: &str,
    identity: &ArtifactIdentity,
) -> Result<Option<[u8; 32]>, CacheError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CacheError::io(
                format!("failed to read the run-hash memo {}", path.display()),
                error,
            ));
        }
    };
    let Ok(memo) = serde_json::from_slice::<RunHashMemo>(&bytes) else {
        return Ok(None);
    };
    if memo.version != RUN_HASH_VERSION
        || memo.artifact_path_digest != artifact_token
        || memo.artifact_identity != *identity
    {
        return Ok(None);
    }
    let Ok(digest) = hex::decode(memo.sha256) else {
        return Ok(None);
    };
    Ok(digest.try_into().ok())
}

fn hash_artifact(path: &Path) -> Result<([u8; 32], ArtifactIdentity), CacheError> {
    hash_artifact_with(path, || {})
}

fn hash_artifact_with(
    path: &Path,
    after_read: impl FnOnce(),
) -> Result<([u8; 32], ArtifactIdentity), CacheError> {
    let path_before = fs::metadata(path).map_err(|error| {
        CacheError::io(
            format!("failed to read artifact metadata for {}", path.display()),
            error,
        )
    })?;
    let mut file = File::open(path).map_err(|error| {
        CacheError::io(
            format!("failed to open the artifact {}", path.display()),
            error,
        )
    })?;
    let file_before = file.metadata().map_err(|error| {
        CacheError::io(
            format!(
                "failed to read opened artifact metadata for {}",
                path.display()
            ),
            error,
        )
    })?;
    let identity = ArtifactIdentity::new(&file_before);
    if ArtifactIdentity::new(&path_before) != identity {
        return Err(CacheError::ArtifactChanged);
    }

    let mut hasher = Sha256::new();
    let mut buffer = vec![0; HASH_BUFFER_SIZE];
    loop {
        let count = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(CacheError::io(
                    format!("failed to read the artifact {}", path.display()),
                    error,
                ));
            }
        };
        hasher.update(&buffer[..count]);
    }

    after_read();
    let file_after = file.metadata().map_err(|error| {
        CacheError::io(
            format!(
                "failed to re-read opened artifact metadata for {}",
                path.display()
            ),
            error,
        )
    })?;
    let path_after = fs::metadata(path).map_err(|error| {
        CacheError::io(
            format!("failed to re-read artifact metadata for {}", path.display()),
            error,
        )
    })?;
    if ArtifactIdentity::new(&file_after) != identity
        || ArtifactIdentity::new(&path_after) != identity
    {
        return Err(CacheError::ArtifactChanged);
    }

    Ok((hasher.finalize().into(), identity))
}

fn metadata_identity(path: &Path) -> Result<ArtifactIdentity, CacheError> {
    fs::metadata(path)
        .map(|metadata| ArtifactIdentity::new(&metadata))
        .map_err(|error| {
            CacheError::io(
                format!("failed to read artifact metadata for {}", path.display()),
                error,
            )
        })
}

fn atomic_write_json(path: &Path, value: &impl Serialize, context: &str) -> Result<(), CacheError> {
    let parent = path.parent().expect("an atomic-write path has a parent");
    fs::create_dir_all(parent).map_err(|error| {
        CacheError::io(
            format!(
                "failed to create the storage directory {}",
                parent.display()
            ),
            error,
        )
    })?;
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| serde_json::to_writer(file, value).map_err(io::Error::other))
        .map_err(|error| CacheError::AtomicWrite {
            context: context.to_owned(),
            message: error.to_string(),
        })
}

fn acquire_lock(file: &File, context: &str, timeout: Duration) -> Result<(), CacheError> {
    acquire_lock_with(file, context, timeout, File::try_lock)
}

fn acquire_shared_lock(file: &File, context: &str, timeout: Duration) -> Result<(), CacheError> {
    acquire_lock_with(file, context, timeout, File::try_lock_shared)
}

fn acquire_lock_with(
    file: &File,
    context: &str,
    timeout: Duration,
    try_lock: impl Fn(&File) -> Result<(), TryLockError>,
) -> Result<(), CacheError> {
    let started = Instant::now();
    loop {
        match try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= timeout {
                    return Err(CacheError::LockTimeout {
                        context: context.to_owned(),
                        timeout,
                    });
                }
                thread::sleep(LOCK_RETRY_INTERVAL.min(timeout));
            }
            Err(TryLockError::Error(error)) => {
                return Err(CacheError::io(
                    format!("failed to acquire {context}"),
                    error,
                ));
            }
        }
    }
}

fn validate_token(token: &str) -> Result<(), CacheError> {
    if token.len() != 64
        || !token
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(CacheError::InvalidInvocation(
            "a cache token must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CacheEntry {
    version: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct RunHashMemo {
    version: u32,
    artifact_path_digest: String,
    artifact_identity: ArtifactIdentity,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct ArtifactIdentity {
    len: u64,
    created: Option<Timestamp>,
    modified: Option<Timestamp>,
}

impl ArtifactIdentity {
    fn new(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            created: metadata.created().ok().map(Timestamp::new),
            modified: metadata.modified().ok().map(Timestamp::new),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Timestamp {
    before_epoch: bool,
    seconds: u64,
    nanoseconds: u32,
}

impl Timestamp {
    fn new(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                before_epoch: false,
                seconds: duration.as_secs(),
                nanoseconds: duration.subsec_nanos(),
            },
            Err(error) => Self {
                before_epoch: true,
                seconds: error.duration().as_secs(),
                nanoseconds: error.duration().subsec_nanos(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn clean_pass_hit_store_and_invalidate() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());

        assert!(!store.contains_clean_pass(TOKEN).unwrap());
        store.store_clean_pass(TOKEN).unwrap();
        assert!(store.contains_clean_pass(TOKEN).unwrap());
        store.invalidate(TOKEN).unwrap();
        store.invalidate(TOKEN).unwrap();
        assert!(!store.contains_clean_pass(TOKEN).unwrap());
    }

    #[test]
    fn corrupt_and_unknown_entries_are_misses() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());
        let path = store.entry_path(TOKEN);
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        fs::write(&path, b"not json").unwrap();
        assert!(!store.contains_clean_pass(TOKEN).unwrap());
        fs::write(&path, br#"{"version":999}"#).unwrap();
        assert!(!store.contains_clean_pass(TOKEN).unwrap());
    }

    #[test]
    fn concurrent_stores_never_expose_partial_json() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = Arc::new(CacheStore::from_root(temp.path().into()));
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..20 {
                    store.store_clean_pass(TOKEN).unwrap();
                }
            }));
        }
        barrier.wait();
        for _ in 0..100 {
            match fs::read(store.entry_path(TOKEN)) {
                Ok(bytes) => {
                    let entry: CacheEntry = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(entry.version, ENTRY_VERSION);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("failed to read an entry: {error}"),
            }
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(store.contains_clean_pass(TOKEN).unwrap());
    }

    #[test]
    fn a_stable_artifact_memo_is_reused_within_a_run() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact").unwrap();
        let store = CacheStore::from_root(temp.path().join("cache").into());

        let first = store
            .load_or_hash_for_run(OsStr::new("run"), artifact.as_std_path())
            .unwrap();
        let second = store
            .load_or_hash_for_run(OsStr::new("run"), artifact.as_std_path())
            .unwrap();
        assert!(first.was_hashed);
        assert!(!second.was_hashed);
        assert_eq!(first.bytes, second.bytes);
    }

    #[test]
    fn different_runs_hash_independently() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact").unwrap();
        let store = CacheStore::from_root(temp.path().join("cache").into());

        assert!(
            store
                .load_or_hash_for_run(OsStr::new("run-1"), artifact.as_std_path())
                .unwrap()
                .was_hashed
        );
        assert!(
            store
                .load_or_hash_for_run(OsStr::new("run-2"), artifact.as_std_path())
                .unwrap()
                .was_hashed
        );
    }

    #[test]
    fn corrupt_run_memo_triggers_a_rehash() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact").unwrap();
        let store = CacheStore::from_root(temp.path().join("cache").into());
        let run_id = OsStr::new("run");
        store
            .load_or_hash_for_run(run_id, artifact.as_std_path())
            .unwrap();

        let run_token = domain_digest(RUN_ID_DOMAIN, run_id);
        let artifact_token =
            domain_digest(ARTIFACT_PATH_DOMAIN, artifact.as_std_path().as_os_str());
        fs::write(
            store.run_hash_path(&run_token, &artifact_token),
            b"not json",
        )
        .unwrap();
        assert!(
            store
                .load_or_hash_for_run(run_id, artifact.as_std_path())
                .unwrap()
                .was_hashed
        );
    }

    #[test]
    fn modifying_an_artifact_invalidates_its_run_memo() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"before").unwrap();
        let store = CacheStore::from_root(temp.path().join("cache").into());
        let run_id = OsStr::new("run");
        let before = store
            .load_or_hash_for_run(run_id, artifact.as_std_path())
            .unwrap();

        fs::write(&artifact, b"after, with a different length").unwrap();
        let after = store
            .load_or_hash_for_run(run_id, artifact.as_std_path())
            .unwrap();
        assert!(after.was_hashed);
        assert_ne!(before.bytes, after.bytes);
    }

    #[test]
    fn concurrent_callers_hash_once() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, vec![42; HASH_BUFFER_SIZE * 2]).unwrap();
        let store = Arc::new(CacheStore::from_root(temp.path().join("cache").into()));
        let artifact = Arc::new(PathBuf::from(artifact.as_std_path()));
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let artifact = artifact.clone();
            let barrier = barrier.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                store
                    .load_or_hash_for_run(OsStr::new("run"), &artifact)
                    .unwrap()
            }));
        }

        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.was_hashed).count(), 1);
        assert!(
            results
                .windows(2)
                .all(|pair| pair[0].bytes == pair[1].bytes)
        );
    }

    #[test]
    fn artifact_changes_during_hashing_are_detected() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"before").unwrap();

        let error = hash_artifact_with(artifact.as_std_path(), || {
            fs::write(&artifact, b"after, with a different length").unwrap();
        })
        .unwrap_err();
        assert!(matches!(error, CacheError::ArtifactChanged));
    }

    #[test]
    fn lock_timeout_is_reported() {
        let temp = camino_tempfile::tempdir().unwrap();
        let path = temp.path().join("lock");
        let first = File::create(&path).unwrap();
        first.lock().unwrap();
        let second = File::open(&path).unwrap();

        let error = acquire_lock(&second, "the test lock", Duration::from_millis(10)).unwrap_err();
        assert!(matches!(error, CacheError::LockTimeout { .. }));
    }

    #[test]
    fn pruning_does_not_remove_a_leased_run() {
        let temp = camino_tempfile::tempdir().unwrap();
        let store = CacheStore::from_root(temp.path().into());
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact").unwrap();
        let old_run = domain_digest(RUN_ID_DOMAIN, OsStr::new("old-run"));
        let current_run = domain_digest(RUN_ID_DOMAIN, OsStr::new("current-run"));

        store
            .load_or_hash_for_run(OsStr::new("old-run"), artifact.as_std_path())
            .unwrap();
        let lease = store.acquire_run_lease(&old_run).unwrap();
        store.prune_run_hashes_older_than(&current_run, Duration::ZERO);
        assert!(store.root.join("run-hashes").join(&old_run).is_dir());

        drop(lease);
        store.prune_run_hashes_older_than(&current_run, Duration::ZERO);
        assert!(!store.root.join("run-hashes").join(&old_run).exists());
        assert!(!store.run_hash_lease_path(OsStr::new(&old_run)).exists());
    }
}
