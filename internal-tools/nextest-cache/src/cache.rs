// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cache-key derivation and wrapper command recognition.

use serde::Serialize;
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use xxhash_rust::xxh3::Xxh3;

pub(crate) const RUN_ID_ENV: &str = "NEXTEST_RUN_ID";
pub(crate) const ATTEMPT_ENV: &str = "NEXTEST_ATTEMPT";
pub(crate) const STRESS_CURRENT_ENV: &str = "NEXTEST_STRESS_CURRENT";
pub(crate) const DISABLE_ENV: &str = "NEXTEST_CACHE_DISABLE";
pub(crate) const TRACE_ENV: &str = "NEXTEST_CACHE_TRACE";

const KEY_DOMAIN: &[u8] = b"nextest-wrapper-cache-key";
pub(crate) type CacheDigest = [u8; 16];
const FILTERED_ENVIRONMENT: [&str; 9] = [
    RUN_ID_ENV,
    "NEXTEST_ATTEMPT_ID",
    ATTEMPT_ENV,
    "NEXTEST_TEST_GLOBAL_SLOT",
    "NEXTEST_TEST_GROUP_SLOT",
    STRESS_CURRENT_ENV,
    "NEXTEST_STRESS_TOTAL",
    "NEXTEST_CACHE_DIR",
    TRACE_ENV,
];

pub(crate) fn find_artifact(command: &[OsString], cwd: &Path) -> Option<PathBuf> {
    let exact_indices = command
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (arg == "--exact").then_some(index))
        .collect::<Vec<_>>();
    let [exact_index] = exact_indices.as_slice() else {
        return None;
    };
    if *exact_index == 0
        || command.get(exact_index + 1).is_none()
        || command
            .get(exact_index + 2)
            .is_none_or(|arg| arg != "--nocapture")
    {
        return None;
    }

    let path = PathBuf::from(&command[exact_index - 1]);
    Some(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
}

pub(crate) fn effective_environment() -> Vec<(OsString, OsString)> {
    env::vars_os().collect()
}

pub(crate) fn derive_token(
    artifact_digest: &CacheDigest,
    command: &[OsString],
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> String {
    let mut environment = environment
        .iter()
        .filter(|(name, _)| !is_filtered_environment(name))
        .collect::<Vec<_>>();
    environment.sort_by(|(left_name, left_value), (right_name, right_value)| {
        left_name
            .as_encoded_bytes()
            .cmp(right_name.as_encoded_bytes())
            .then_with(|| {
                left_value
                    .as_encoded_bytes()
                    .cmp(right_value.as_encoded_bytes())
            })
    });

    let mut hasher = Xxh3::new();
    update_field(&mut hasher, KEY_DOMAIN);
    update_field(&mut hasher, artifact_digest);
    update_count(&mut hasher, command.len());
    for arg in command {
        update_field(&mut hasher, arg.as_encoded_bytes());
    }
    update_field(&mut hasher, cwd.as_os_str().as_encoded_bytes());
    update_count(&mut hasher, environment.len());
    for (name, value) in &environment {
        update_field(&mut hasher, name.as_encoded_bytes());
        update_field(&mut hasher, value.as_encoded_bytes());
    }
    hex::encode(hasher.digest128().to_be_bytes())
}

pub(crate) fn domain_digest(domain: &[u8], value: &OsStr) -> String {
    let mut hasher = Xxh3::new();
    update_field(&mut hasher, domain);
    update_field(&mut hasher, value.as_encoded_bytes());
    hex::encode(hasher.digest128().to_be_bytes())
}

pub(crate) fn trace_artifact_hash(path: &Path, digest: &CacheDigest) {
    let Some(trace_path) = env::var_os(TRACE_ENV) else {
        return;
    };
    let event = TraceArtifactHash {
        event: "artifact-hashed",
        path: path.to_string_lossy(),
        xxh3_128: hex::encode(digest),
    };
    let mut line = match serde_json::to_vec(&event) {
        Ok(line) => line,
        Err(error) => {
            eprintln!("nextest-cache: failed to serialize a trace event: {error}");
            return;
        }
    };
    line.push(b'\n');

    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(trace_path)
    {
        Ok(mut file) => {
            if let Err(error) = file.write_all(&line) {
                eprintln!("nextest-cache: failed to write a trace event: {error}");
            }
        }
        Err(error) => eprintln!("nextest-cache: failed to open the trace file: {error}"),
    }
}

fn update_count(hasher: &mut Xxh3, count: usize) {
    update_field(hasher, &(count as u64).to_be_bytes());
}

fn update_field(hasher: &mut Xxh3, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn is_filtered_environment(name: &OsStr) -> bool {
    FILTERED_ENVIRONMENT
        .iter()
        .any(|candidate| environment_name_eq(name, candidate))
}

#[cfg(windows)]
fn environment_name_eq(name: &OsStr, candidate: &str) -> bool {
    name.as_encoded_bytes()
        .eq_ignore_ascii_case(candidate.as_bytes())
}

#[cfg(not(windows))]
fn environment_name_eq(name: &OsStr, candidate: &str) -> bool {
    name == candidate
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TraceArtifactHash<'a> {
    event: &'static str,
    path: std::borrow::Cow<'a, str>,
    xxh3_128: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> Vec<(OsString, OsString)> {
        vec![
            (OsString::from("A"), OsString::from("one")),
            (OsString::from("B"), OsString::from("two")),
        ]
    }

    fn token(
        digest: CacheDigest,
        command: &[&str],
        cwd: &str,
        environment: &[(OsString, OsString)],
    ) -> String {
        derive_token(
            &digest,
            &command.iter().map(OsString::from).collect::<Vec<_>>(),
            Path::new(cwd),
            environment,
        )
    }

    #[test]
    fn key_derivation_is_stable_and_sensitive_to_inputs() {
        let base = token(
            [1; 16],
            &["runner", "artifact", "--exact", "test"],
            "/cwd",
            &environment(),
        );
        assert_eq!(base, "16d45b172876d76f1d3d1c961112cc8d");
        assert_ne!(
            base,
            token(
                [2; 16],
                &["runner", "artifact", "--exact", "test"],
                "/cwd",
                &environment()
            )
        );
        assert_ne!(
            base,
            token(
                [1; 16],
                &["runner", "artifact", "--exact", "other"],
                "/cwd",
                &environment()
            )
        );
        assert_ne!(
            base,
            token(
                [1; 16],
                &["runner", "artifact", "--exact", "test"],
                "/other",
                &environment()
            )
        );

        let mut changed_environment = environment();
        changed_environment[0].1 = OsString::from("changed");
        assert_ne!(
            base,
            token(
                [1; 16],
                &["runner", "artifact", "--exact", "test"],
                "/cwd",
                &changed_environment,
            )
        );
    }

    #[test]
    fn environment_order_does_not_matter_after_sorting() {
        let first = environment();
        let mut second = environment();
        second.reverse();
        assert_eq!(
            token([1; 16], &["artifact"], "/cwd", &first),
            token([1; 16], &["artifact"], "/cwd", &second),
        );
    }

    #[test]
    fn volatile_environment_is_filtered() {
        for name in FILTERED_ENVIRONMENT {
            assert!(is_filtered_environment(OsStr::new(name)), "{name}");
            let mut with_control = environment();
            with_control.push((OsString::from(name), OsString::from("value")));
            assert_eq!(
                token([1; 16], &["artifact"], "/cwd", &environment()),
                token([1; 16], &["artifact"], "/cwd", &with_control),
                "{name}",
            );
        }
        assert!(!is_filtered_environment(OsStr::new("NEXTEST_TEST_NAME")));
        assert!(!is_filtered_environment(OsStr::new(
            "NEXTEST_TOTAL_ATTEMPTS"
        )));
    }

    #[test]
    fn artifact_recognition_rejects_ambiguous_commands() {
        let cwd = Path::new("/cwd");
        let command = ["runner", "artifact", "--exact", "test", "--nocapture"].map(OsString::from);
        assert_eq!(
            find_artifact(&command, cwd),
            Some(PathBuf::from("/cwd/artifact"))
        );

        let ambiguous = [
            "runner",
            "--exact",
            "runner-value",
            "artifact",
            "--exact",
            "test",
            "--nocapture",
        ]
        .map(OsString::from);
        assert_eq!(find_artifact(&ambiguous, cwd), None);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_inputs_are_hashed_losslessly() {
        use std::os::unix::ffi::OsStringExt;

        let command = vec![OsString::from_vec(vec![b'a', 0x80])];
        let changed_command = vec![OsString::from_vec(vec![b'a', 0x81])];
        let environment = vec![(
            OsString::from_vec(vec![b'K', 0x80]),
            OsString::from_vec(vec![b'V', 0x80]),
        )];
        let changed_environment = vec![(
            OsString::from_vec(vec![b'K', 0x80]),
            OsString::from_vec(vec![b'V', 0x81]),
        )];

        let base = derive_token(&[0; 16], &command, Path::new("/cwd"), &environment);
        assert_ne!(
            base,
            derive_token(&[0; 16], &changed_command, Path::new("/cwd"), &environment,)
        );
        assert_ne!(
            base,
            derive_token(&[0; 16], &command, Path::new("/cwd"), &changed_environment,)
        );
    }
}
