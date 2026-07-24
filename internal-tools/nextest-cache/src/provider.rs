// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol operations for the reference cache provider.

use crate::{error::CacheError, store::CacheStore};
use camino::Utf8Path;
use nextest_runner::cache_protocol::{
    ArtifactRequest, CommitRequest, CommitResponse, MAX_BYPASS_REASON_LEN, PrepareDecision,
    PrepareRequest, PrepareResponse, ProtocolVersion,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    time::SystemTime,
};

const HASH_BUFFER_SIZE: usize = 256 * 1024;
const MAX_NAMESPACE_LEN: usize = 1024 * 1024;
const MAX_EXECUTION_KEY_LEN: usize = 4 * 1024 * 1024;
const TRACE_ENV: &str = "NEXTEST_CACHE_TRACE";

pub(crate) fn prepare(request: PrepareRequest) -> Result<PrepareResponse, CacheError> {
    let store = CacheStore::discover()?;
    prepare_with_hasher(request, &store, |artifact| {
        let digest = hash_artifact(&artifact.path)?;
        trace_artifact_hash(artifact, &digest);
        Ok(digest)
    })
}

pub(crate) fn commit(request: CommitRequest) -> Result<CommitResponse, CacheError> {
    if !request.version.is_v1_compatible() {
        return Err(CacheError::InvalidRequest(format!(
            "unsupported protocol version {:?}",
            request.version
        )));
    }
    let store = CacheStore::discover()?;
    store.apply_updates(&request.updates)?;
    Ok(CommitResponse {
        version: ProtocolVersion::V1,
    })
}

fn prepare_with_hasher(
    request: PrepareRequest,
    store: &CacheStore,
    mut hash: impl FnMut(&ArtifactRequest) -> Result<[u8; 32], CacheError>,
) -> Result<PrepareResponse, CacheError> {
    validate_prepare_request(&request)?;

    let mut decisions = Vec::new();
    for artifact in &request.artifacts {
        match hash(artifact) {
            Ok(artifact_digest) => {
                for test in &artifact.tests {
                    let token = derive_token(
                        request.namespace.as_bytes(),
                        &artifact_digest,
                        test.execution_key.as_bytes(),
                    );
                    let decision = if request.consult {
                        match store.contains_valid(&token) {
                            Ok(true) => PrepareDecision::Hit {
                                test_id: test.test_id,
                                token,
                            },
                            Ok(false) => PrepareDecision::Miss {
                                test_id: test.test_id,
                                token,
                            },
                            Err(error) => PrepareDecision::Bypass {
                                test_id: test.test_id,
                                reason: bounded_reason(format!(
                                    "failed to consult cache entry: {error}"
                                )),
                            },
                        }
                    } else {
                        PrepareDecision::Miss {
                            test_id: test.test_id,
                            token,
                        }
                    };
                    decisions.push(decision);
                }
            }
            Err(error) => {
                let reason = bounded_reason(format!("failed to hash artifact: {error}"));
                decisions.extend(artifact.tests.iter().map(|test| PrepareDecision::Bypass {
                    test_id: test.test_id,
                    reason: reason.clone(),
                }));
            }
        }
    }

    Ok(PrepareResponse {
        version: ProtocolVersion::V1,
        decisions,
    })
}

fn validate_prepare_request(request: &PrepareRequest) -> Result<(), CacheError> {
    if !request.version.is_v1_compatible() {
        return Err(CacheError::InvalidRequest(format!(
            "unsupported protocol version {:?}",
            request.version
        )));
    }
    if request.namespace.is_empty() || request.namespace.len() > MAX_NAMESPACE_LEN {
        return Err(CacheError::InvalidRequest(format!(
            "namespace must contain between 1 and {MAX_NAMESPACE_LEN} bytes"
        )));
    }

    let mut artifact_ids = HashSet::with_capacity(request.artifacts.len());
    let mut test_ids = HashSet::new();
    for artifact in &request.artifacts {
        if !artifact_ids.insert(artifact.artifact_id) {
            return Err(CacheError::InvalidRequest(format!(
                "duplicate artifact ID {}",
                artifact.artifact_id
            )));
        }
        if artifact.binary_id.is_empty() {
            return Err(CacheError::InvalidRequest(format!(
                "artifact ID {} has an empty binary ID",
                artifact.artifact_id
            )));
        }
        if artifact.path.as_str().is_empty() {
            return Err(CacheError::InvalidRequest(format!(
                "artifact ID {} has an empty path",
                artifact.artifact_id
            )));
        }
        if artifact.tests.is_empty() {
            return Err(CacheError::InvalidRequest(format!(
                "artifact ID {} has no tests",
                artifact.artifact_id
            )));
        }

        for test in &artifact.tests {
            if !test_ids.insert(test.test_id) {
                return Err(CacheError::InvalidRequest(format!(
                    "duplicate test ID {}",
                    test.test_id
                )));
            }
            if test.execution_key.is_empty() || test.execution_key.len() > MAX_EXECUTION_KEY_LEN {
                return Err(CacheError::InvalidRequest(format!(
                    "test ID {} has an execution key outside the supported size range",
                    test.test_id
                )));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    len: u64,
    created: Option<SystemTime>,
    modified: Option<SystemTime>,
}

impl ArtifactIdentity {
    fn new(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            created: metadata.created().ok(),
            modified: metadata.modified().ok(),
        }
    }
}

fn hash_artifact(path: &Utf8Path) -> Result<[u8; 32], CacheError> {
    let path_before = fs::metadata(path).map_err(|error| {
        CacheError::io(
            format!("failed to read artifact metadata for {path}"),
            error,
        )
    })?;
    let mut file = File::open(path)
        .map_err(|error| CacheError::io(format!("failed to open artifact {path}"), error))?;
    let file_before = file.metadata().map_err(|error| {
        CacheError::io(
            format!("failed to read opened artifact metadata for {path}"),
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
                    format!("failed to read artifact {path}"),
                    error,
                ));
            }
        };
        hasher.update(&buffer[..count]);
    }

    let file_after = file.metadata().map_err(|error| {
        CacheError::io(
            format!("failed to re-read opened artifact metadata for {path}"),
            error,
        )
    })?;
    let path_after = fs::metadata(path).map_err(|error| {
        CacheError::io(
            format!("failed to re-read artifact metadata for {path}"),
            error,
        )
    })?;
    if ArtifactIdentity::new(&file_after) != identity
        || ArtifactIdentity::new(&path_after) != identity
    {
        return Err(CacheError::ArtifactChanged);
    }

    Ok(hasher.finalize().into())
}

fn derive_token(namespace: &[u8], artifact_digest: &[u8; 32], execution_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nextest-cache-token-v1");
    update_field(&mut hasher, namespace);
    update_field(&mut hasher, artifact_digest);
    update_field(&mut hasher, execution_key);
    hex::encode(hasher.finalize())
}

fn update_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn bounded_reason(mut reason: String) -> String {
    if reason.len() <= MAX_BYPASS_REASON_LEN {
        return reason;
    }
    let mut end = MAX_BYPASS_REASON_LEN;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.truncate(end);
    reason
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TraceArtifactHash<'a> {
    event: &'static str,
    artifact_id: u64,
    binary_id: &'a str,
    path: &'a Utf8Path,
    sha256: String,
}

fn trace_artifact_hash(artifact: &ArtifactRequest, digest: &[u8; 32]) {
    let Some(trace_path) = env::var_os(TRACE_ENV) else {
        return;
    };
    let event = TraceArtifactHash {
        event: "artifact-hashed",
        artifact_id: artifact.artifact_id,
        binary_id: &artifact.binary_id,
        path: &artifact.path,
        sha256: hex::encode(digest),
    };
    let mut line = match serde_json::to_vec(&event) {
        Ok(line) => line,
        Err(error) => {
            eprintln!("nextest-cache: failed to serialize trace event: {error}");
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
                eprintln!("nextest-cache: failed to write trace event: {error}");
            }
        }
        Err(error) => eprintln!("nextest-cache: failed to open trace file: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextest_runner::cache_protocol::{
        ArtifactRequest, CacheExecutionData, CommitDisposition, CommitUpdate, TestRequest,
    };
    use std::{cell::Cell, fs};

    fn request(path: &Utf8Path, execution_keys: &[&str], consult: bool) -> PrepareRequest {
        PrepareRequest {
            version: ProtocolVersion::V1,
            namespace: "workspace".to_owned(),
            consult,
            record: true,
            artifacts: vec![ArtifactRequest {
                artifact_id: 7,
                binary_id: "binary".to_owned(),
                path: path.to_owned(),
                tests: execution_keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| TestRequest {
                        test_id: index as u64,
                        test_name: format!("test-{index}"),
                        execution_key: (*key).to_owned(),
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn hashes_each_artifact_once() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact contents").unwrap();
        let store = CacheStore::from_root(temp.path().as_std_path().join("cache"));
        let hash_count = Cell::new(0);

        let response = prepare_with_hasher(
            request(&artifact, &["key-1", "key-2"], true),
            &store,
            |_| {
                hash_count.set(hash_count.get() + 1);
                Ok([42; 32])
            },
        )
        .unwrap();

        assert_eq!(hash_count.get(), 1);
        assert_eq!(response.decisions.len(), 2);
        assert!(
            response
                .decisions
                .iter()
                .all(|decision| matches!(decision, PrepareDecision::Miss { .. }))
        );
    }

    #[test]
    fn clean_pass_hits_and_invalidation_misses() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact contents").unwrap();
        let store = CacheStore::from_root(temp.path().as_std_path().join("cache"));

        let first =
            prepare_with_hasher(request(&artifact, &["key"], true), &store, |_| Ok([1; 32]))
                .unwrap();
        let PrepareDecision::Miss { test_id, token } = &first.decisions[0] else {
            panic!("first decision should be a miss");
        };
        store
            .apply_updates(&[CommitUpdate {
                test_id: *test_id,
                token: token.clone(),
                disposition: CommitDisposition::CleanPass,
                execution: CacheExecutionData::default(),
            }])
            .unwrap();

        let second =
            prepare_with_hasher(request(&artifact, &["key"], true), &store, |_| Ok([1; 32]))
                .unwrap();
        assert!(matches!(second.decisions[0], PrepareDecision::Hit { .. }));

        store
            .apply_updates(&[CommitUpdate {
                test_id: *test_id,
                token: token.clone(),
                disposition: CommitDisposition::Invalidate,
                execution: CacheExecutionData::default(),
            }])
            .unwrap();
        let third =
            prepare_with_hasher(request(&artifact, &["key"], true), &store, |_| Ok([1; 32]))
                .unwrap();
        assert!(matches!(third.decisions[0], PrepareDecision::Miss { .. }));
    }

    #[test]
    fn execution_key_changes_the_token() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact contents").unwrap();
        let store = CacheStore::from_root(temp.path().as_std_path().join("cache"));

        let first = prepare_with_hasher(request(&artifact, &["before"], false), &store, |_| {
            Ok([3; 32])
        })
        .unwrap();
        let second = prepare_with_hasher(request(&artifact, &["after"], false), &store, |_| {
            Ok([3; 32])
        })
        .unwrap();
        let PrepareDecision::Miss { token: first, .. } = &first.decisions[0] else {
            panic!("expected a miss");
        };
        let PrepareDecision::Miss { token: second, .. } = &second.decisions[0] else {
            panic!("expected a miss");
        };
        assert_ne!(first, second);
    }

    #[test]
    fn artifact_hash_detects_stable_contents() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact contents").unwrap();
        let first = hash_artifact(&artifact).unwrap();
        let second = hash_artifact(&artifact).unwrap();
        assert_eq!(first, second);
    }
}
