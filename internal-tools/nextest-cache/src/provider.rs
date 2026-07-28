// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protocol operations for the reference cache provider.

use crate::{error::CacheError, store::CacheStore};
use camino::Utf8Path;
use nextest_runner::cache_protocol::{
    ArtifactRequest, CACHE_CAPTURE_STRATEGY_ENV, CommandSpec, CommitRequest, MAX_BYPASS_REASON_LEN,
    PrepareDecision, PrepareRequest, PrepareResponse, TestRequest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    time::SystemTime,
};

const HASH_BUFFER_SIZE: usize = 256 * 1024;
const MAX_NAMESPACE_LEN: usize = 1024 * 1024;
const MAX_KEY_INPUT_LEN: usize = 4 * 1024 * 1024;
const TRACE_ENV: &str = "NEXTEST_CACHE_TRACE";
const GLOBAL_KEY_ENV: [&str; 5] = [
    CACHE_CAPTURE_STRATEGY_ENV,
    "NEXTEST_REQUIRED_VERSION",
    "NEXTEST_RECOMMENDED_VERSION",
    "NEXTEST_TEST_THREADS",
    "NEXTEST_VERSION",
];
const WORKSPACE_ROOT_ENV: &str = "NEXTEST_WORKSPACE_ROOT";

pub(crate) fn prepare(request: PrepareRequest) -> Result<PrepareResponse, CacheError> {
    let namespace = env::var(WORKSPACE_ROOT_ENV).map_err(|_| {
        CacheError::InvalidInvocation(format!("{WORKSPACE_ROOT_ENV} must contain valid UTF-8"))
    })?;
    let global_context = GLOBAL_KEY_ENV
        .into_iter()
        .map(|name| {
            env::var(name)
                .map(|value| (name.to_owned(), value))
                .map_err(|_| {
                    CacheError::InvalidInvocation(format!(
                        "{name} must be set and contain valid UTF-8"
                    ))
                })
        })
        .collect::<Result<_, _>>()?;
    let store = CacheStore::discover()?;
    prepare_with_hasher(
        request,
        &store,
        namespace.as_bytes(),
        &global_context,
        |artifact| {
            let digest = hash_artifact(&artifact.path)?;
            trace_artifact_hash(artifact, &digest);
            Ok(digest)
        },
    )
}

pub(crate) fn commit(request: CommitRequest) -> Result<(), CacheError> {
    CacheStore::discover()?.apply_updates(&request.updates)
}

fn prepare_with_hasher(
    request: PrepareRequest,
    store: &CacheStore,
    namespace: &[u8],
    global_context: &BTreeMap<String, String>,
    mut hash: impl FnMut(&ArtifactRequest) -> Result<[u8; 32], CacheError>,
) -> Result<PrepareResponse, CacheError> {
    validate_prepare_request(&request, namespace)?;

    let mut decisions = Vec::new();
    for artifact in &request.artifacts {
        match hash(artifact) {
            Ok(artifact_digest) => {
                for test in &artifact.tests {
                    let decision =
                        match derive_token(namespace, &artifact_digest, global_context, test) {
                            Ok(token) if request.consult => match store.contains_valid(&token) {
                                Ok(true) => PrepareDecision::Hit,
                                Ok(false) => PrepareDecision::Miss { token },
                                Err(error) => PrepareDecision::Bypass {
                                    reason: bounded_reason(format!(
                                        "failed to consult cache entry: {error}"
                                    )),
                                },
                            },
                            Ok(token) => PrepareDecision::Miss { token },
                            Err(error) => PrepareDecision::Bypass {
                                reason: bounded_reason(error.to_string()),
                            },
                        };
                    decisions.push(decision);
                }
            }
            Err(error) => {
                let reason = bounded_reason(format!("failed to hash artifact: {error}"));
                decisions.extend(artifact.tests.iter().map(|_| PrepareDecision::Bypass {
                    reason: reason.clone(),
                }));
            }
        }
    }

    Ok(PrepareResponse { decisions })
}

fn validate_prepare_request(request: &PrepareRequest, namespace: &[u8]) -> Result<(), CacheError> {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_LEN {
        return Err(CacheError::InvalidRequest(format!(
            "the provider namespace must contain between 1 and {MAX_NAMESPACE_LEN} bytes"
        )));
    }

    for artifact in &request.artifacts {
        if artifact.path.as_str().is_empty() {
            return Err(CacheError::InvalidRequest(
                "an artifact has an empty path".to_owned(),
            ));
        }
        if artifact.tests.is_empty() {
            return Err(CacheError::InvalidRequest(format!(
                "artifact {} has no tests",
                artifact.path
            )));
        }
        if artifact
            .tests
            .iter()
            .any(|test| test.command.program.is_empty())
        {
            return Err(CacheError::InvalidRequest(format!(
                "artifact {} has a test with an empty command",
                artifact.path
            )));
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

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ProviderKey<'a> {
    format: &'static str,
    command: &'a CommandSpec,
    global_context: &'a BTreeMap<String, String>,
    test_context: &'a BTreeMap<String, String>,
}

fn derive_token(
    namespace: &[u8],
    artifact_digest: &[u8; 32],
    global_context: &BTreeMap<String, String>,
    test: &TestRequest,
) -> Result<String, CacheError> {
    let key = serde_json::to_vec(&ProviderKey {
        format: "nextest-reference-provider-key-v1",
        command: &test.command,
        global_context,
        test_context: &test.context,
    })
    .map_err(CacheError::SerializeKey)?;
    if key.len() > MAX_KEY_INPUT_LEN {
        return Err(CacheError::InvalidRequest(format!(
            "a test has more than {MAX_KEY_INPUT_LEN} bytes of cache-key input"
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"nextest-cache-token-v2");
    update_field(&mut hasher, namespace);
    update_field(&mut hasher, artifact_digest);
    update_field(&mut hasher, &key);
    Ok(hex::encode(hasher.finalize()))
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
    path: &'a Utf8Path,
    sha256: String,
}

fn trace_artifact_hash(artifact: &ArtifactRequest, digest: &[u8; 32]) {
    let Some(trace_path) = env::var_os(TRACE_ENV) else {
        return;
    };
    let event = TraceArtifactHash {
        event: "artifact-hashed",
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
        CommandSpec, CommitAction, CommitUpdate, EnvironmentVariable,
    };
    use std::{cell::Cell, fs};

    fn request(path: &Utf8Path, keys: &[&str], consult: bool) -> PrepareRequest {
        PrepareRequest {
            consult,
            artifacts: vec![ArtifactRequest {
                path: path.to_owned(),
                tests: keys
                    .iter()
                    .map(|key| TestRequest {
                        command: CommandSpec {
                            program: "wrapper".to_owned(),
                            args: vec![(*key).to_owned()],
                            cwd: "/workspace".into(),
                            environment: Vec::<EnvironmentVariable>::new(),
                        },
                        context: BTreeMap::new(),
                    })
                    .collect(),
            }],
        }
    }

    fn global_context() -> BTreeMap<String, String> {
        BTreeMap::from([("nextest-version".to_owned(), "test".to_owned())])
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
            b"workspace",
            &global_context(),
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

        let first = prepare_with_hasher(
            request(&artifact, &["key"], true),
            &store,
            b"workspace",
            &global_context(),
            |_| Ok([1; 32]),
        )
        .unwrap();
        let PrepareDecision::Miss { token, .. } = &first.decisions[0] else {
            panic!("first decision should be a miss");
        };
        store
            .apply_updates(&[CommitUpdate {
                token: token.clone(),
                action: CommitAction::Store,
            }])
            .unwrap();

        let second = prepare_with_hasher(
            request(&artifact, &["key"], true),
            &store,
            b"workspace",
            &global_context(),
            |_| Ok([1; 32]),
        )
        .unwrap();
        assert!(matches!(second.decisions[0], PrepareDecision::Hit));

        store
            .apply_updates(&[CommitUpdate {
                token: token.clone(),
                action: CommitAction::Invalidate,
            }])
            .unwrap();
        let third = prepare_with_hasher(
            request(&artifact, &["key"], true),
            &store,
            b"workspace",
            &global_context(),
            |_| Ok([1; 32]),
        )
        .unwrap();
        assert!(matches!(third.decisions[0], PrepareDecision::Miss { .. }));
    }

    #[test]
    fn provider_key_inputs_change_the_token() {
        let temp = camino_tempfile::tempdir().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"artifact contents").unwrap();
        let store = CacheStore::from_root(temp.path().as_std_path().join("cache"));

        let first = prepare_with_hasher(
            request(&artifact, &["before"], false),
            &store,
            b"workspace",
            &global_context(),
            |_| Ok([3; 32]),
        )
        .unwrap();
        let mut changed_context = request(&artifact, &["before"], false);
        changed_context.artifacts[0].tests[0]
            .context
            .insert("setting".to_owned(), "changed".to_owned());
        let second = prepare_with_hasher(
            changed_context,
            &store,
            b"workspace",
            &global_context(),
            |_| Ok([3; 32]),
        )
        .unwrap();
        let PrepareDecision::Miss { token: first, .. } = &first.decisions[0] else {
            panic!("expected a miss");
        };
        let PrepareDecision::Miss { token: second, .. } = &second.decisions[0] else {
            panic!("expected a miss");
        };
        assert_ne!(first, second);

        let mut changed_global_context = global_context();
        changed_global_context.insert("nextest-version".to_owned(), "changed".to_owned());
        let third = prepare_with_hasher(
            request(&artifact, &["before"], false),
            &store,
            b"workspace",
            &changed_global_context,
            |_| Ok([3; 32]),
        )
        .unwrap();
        let PrepareDecision::Miss { token: third, .. } = &third.decisions[0] else {
            panic!("expected a miss");
        };
        assert_ne!(first, third);
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
