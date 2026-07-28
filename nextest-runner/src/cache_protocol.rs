// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire types for the experimental nextest cache-provider protocol.
//!
//! A provider receives resolved test commands before scheduling, returns one
//! decision per test in artifact-major request order, wraps misses normally,
//! and receives authoritative outcomes after the run. Control invocations also
//! receive `NEXTEST_PROFILE`, `NEXTEST_WORKSPACE_ROOT`, `NEXTEST_VERSION`,
//! `NEXTEST_REQUIRED_VERSION`, `NEXTEST_RECOMMENDED_VERSION`,
//! `NEXTEST_TEST_THREADS`, and [`CACHE_CAPTURE_STRATEGY_ENV`]. Provider failures
//! disable caching for affected work rather than failing the test run. A
//! successful commit process exit acknowledges the request; it has no response.

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The environment variable that selects the cache protocol version.
pub const CACHE_PROTOCOL_ENV: &str = "NEXTEST_CACHE_PROTOCOL";

/// The environment variable that selects a cache control-plane operation.
pub const CACHE_OPERATION_ENV: &str = "NEXTEST_CACHE_OPERATION";

/// The environment variable containing the run's output capture strategy.
pub const CACHE_CAPTURE_STRATEGY_ENV: &str = "NEXTEST_CACHE_CAPTURE_STRATEGY";

/// The environment variable containing the opaque token for a cache miss.
pub const CACHE_TOKEN_ENV: &str = "NEXTEST_CACHE_TOKEN";

/// The protocol value for version 1.
pub const CACHE_PROTOCOL_V1: &str = "1";

/// The operation value for preparing cache decisions.
pub const CACHE_OPERATION_PREPARE: &str = "prepare";

/// The operation value for committing authoritative outcomes.
pub const CACHE_OPERATION_COMMIT: &str = "commit";

/// The maximum UTF-8 length of an opaque cache token.
pub const MAX_CACHE_TOKEN_LEN: usize = 4096;

/// The maximum UTF-8 length of a provider bypass reason.
pub const MAX_BYPASS_REASON_LEN: usize = 16 * 1024;

/// A request to prepare cache decisions for a run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrepareRequest {
    /// Whether the provider may reuse existing entries.
    pub consult: bool,

    /// The executable artifacts containing selected tests.
    pub artifacts: Vec<ArtifactRequest>,
}

/// An executable artifact and the selected tests within it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArtifactRequest {
    /// The executable path. Providers decide how to fingerprint it.
    pub path: Utf8PathBuf,

    /// Tests selected from this artifact.
    pub tests: Vec<TestRequest>,
}

/// A selected test considered for caching.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TestRequest {
    /// The resolved command that would execute this test.
    pub command: CommandSpec,

    /// Stable runner inputs not represented by the command itself.
    ///
    /// Providers own cache-key policy and may use any or all of these values.
    pub context: BTreeMap<String, String>,
}

/// A resolved test command supplied as cache-key input.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommandSpec {
    /// The program to execute.
    pub program: String,

    /// Arguments passed to the program.
    pub args: Vec<String>,

    /// The command's working directory.
    pub cwd: Utf8PathBuf,

    /// Explicit environment changes applied by nextest.
    pub environment: Vec<EnvironmentVariable>,
}

/// One explicit command environment change.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EnvironmentVariable {
    /// The environment variable name.
    pub name: PlatformString,

    /// The value to set, or `None` to remove the variable.
    pub value: Option<PlatformString>,
}

/// A lossless platform-native string.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "encoding", content = "units", rename_all = "kebab-case")]
pub enum PlatformString {
    /// Unix bytes.
    Unix(Vec<u8>),

    /// Windows UTF-16 code units.
    Windows(Vec<u16>),
}

/// A provider's response to a prepare request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrepareResponse {
    /// One decision per requested test, traversing `artifacts` and each
    /// artifact's `tests` in vector order.
    pub decisions: Vec<PrepareDecision>,
}

/// A provider decision for one requested test.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum PrepareDecision {
    /// A successful cached result may be consumed without execution.
    Hit,

    /// The test must execute and may be committed afterward.
    Miss {
        /// An opaque token identifying the provider's cache entry. It must be
        /// unique within this response.
        token: String,
    },

    /// The provider cannot safely cache this test in this invocation.
    Bypass {
        /// A bounded human-readable diagnostic.
        reason: String,
    },
}

/// A request to commit authoritative outcomes after a run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitRequest {
    /// Cache-entry updates for misses that produced final results. A miss with
    /// no final result is omitted.
    pub updates: Vec<CommitUpdate>,
}

/// An authoritative update for one opaque provider token.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitUpdate {
    /// The opaque token returned for the cache miss.
    pub token: String,

    /// The update to apply.
    pub action: CommitAction,
}

/// An authoritative cache-entry update.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitAction {
    /// Store an ordinary pass that completed in exactly one attempt.
    Store,

    /// Invalidate after any other final execution outcome.
    Invalidate,
}
