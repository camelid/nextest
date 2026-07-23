// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire types for the experimental nextest cache-provider protocol.
//!
//! Cache providers are run-scoped wrapper scripts. Nextest invokes the provider
//! before the run to prepare decisions, invokes it normally around cache misses,
//! and invokes it after the run to commit authoritative outcomes.

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// The environment variable that selects the cache protocol version.
pub const CACHE_PROTOCOL_ENV: &str = "NEXTEST_CACHE_PROTOCOL";

/// The environment variable that selects a cache control-plane operation.
pub const CACHE_OPERATION_ENV: &str = "NEXTEST_CACHE_OPERATION";

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

/// A cache protocol version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProtocolVersion {
    /// The incompatible protocol generation.
    pub major: u32,

    /// The backwards-compatible protocol revision.
    pub minor: u32,
}

impl ProtocolVersion {
    /// The version implemented by these wire types.
    pub const V1: Self = Self { major: 1, minor: 0 };

    /// Returns whether this version is compatible with version 1.
    pub fn is_v1_compatible(self) -> bool {
        self.major == Self::V1.major
    }
}

/// A request to prepare cache decisions for a run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrepareRequest {
    /// The protocol version used by nextest.
    pub version: ProtocolVersion,

    /// A provider-defined isolation namespace for this workspace.
    pub namespace: String,

    /// Whether existing entries may be consulted.
    pub consult: bool,

    /// Whether nextest intends to commit outcomes after the run.
    pub record: bool,

    /// The test artifacts and tests considered for caching.
    pub artifacts: Vec<ArtifactRequest>,
}

/// A test artifact whose contents contribute to cache tokens.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArtifactRequest {
    /// An invocation-local artifact identifier.
    pub artifact_id: u64,

    /// Nextest's stable binary identifier.
    pub binary_id: String,

    /// The path to the executable artifact.
    pub path: Utf8PathBuf,

    /// Tests selected from this artifact.
    pub tests: Vec<TestRequest>,
}

/// A selected test considered for caching.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TestRequest {
    /// An invocation-local test identifier.
    pub test_id: u64,

    /// The test name.
    pub test_name: String,

    /// An opaque, deterministic description of nextest execution semantics.
    pub execution_key: String,
}

/// A provider's response to a prepare request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrepareResponse {
    /// The protocol version used by the provider.
    pub version: ProtocolVersion,

    /// Exactly one decision for each submitted test.
    pub decisions: Vec<PrepareDecision>,
}

/// A provider decision for a selected test.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum PrepareDecision {
    /// A clean cached result may be consumed without executing the test.
    Hit {
        /// The invocation-local test identifier.
        test_id: u64,

        /// An opaque token identifying the cache entry.
        token: String,
    },

    /// The test must execute and may be committed afterward.
    Miss {
        /// The invocation-local test identifier.
        test_id: u64,

        /// An opaque token identifying the cache entry.
        token: String,
    },

    /// The provider cannot safely cache this test in this invocation.
    Bypass {
        /// The invocation-local test identifier.
        test_id: u64,

        /// A bounded, human-readable diagnostic.
        reason: String,
    },
}

impl PrepareDecision {
    /// Returns the invocation-local test identifier for this decision.
    pub fn test_id(&self) -> u64 {
        match self {
            Self::Hit { test_id, .. }
            | Self::Miss { test_id, .. }
            | Self::Bypass { test_id, .. } => *test_id,
        }
    }
}

/// A request to commit outcomes after a run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitRequest {
    /// The protocol version used by nextest.
    pub version: ProtocolVersion,

    /// Authoritative outcome updates produced during the run.
    pub updates: Vec<CommitUpdate>,
}

/// A provider's response to a commit request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitResponse {
    /// The protocol version used by the provider.
    pub version: ProtocolVersion,
}

/// An authoritative outcome update for one test.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitUpdate {
    /// The invocation-local test identifier from the prepare request.
    pub test_id: u64,

    /// The opaque token returned by the provider.
    pub token: String,

    /// How the provider should update this token.
    pub disposition: CommitDisposition,

    /// Optional execution data reserved for protocol extensions.
    pub execution: CacheExecutionData,
}

/// How a provider should update an entry after nextest classifies the result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitDisposition {
    /// Nextest consumed an existing cache hit.
    Hit,

    /// The test had one ordinary passing attempt and is safe to store.
    CleanPass,

    /// Any existing entry must be invalidated.
    Invalidate,
}

/// Execution data that can refine cache eligibility in future revisions.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheExecutionData {
    /// A future description of effects observed while executing the test.
    ///
    /// Version 1 requires this to be `None`.
    pub effect_ledger: Option<EffectLedgerEnvelope>,
}

/// A versioned envelope reserved for a future effect ledger.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EffectLedgerEnvelope {
    /// The ledger format understood by the provider.
    pub format: String,

    /// Provider-specific ledger data.
    pub data: serde_json::Value,
}
