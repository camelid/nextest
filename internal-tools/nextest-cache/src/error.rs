// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{io, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum CacheError {
    #[error("invalid invocation: {0}")]
    InvalidInvocation(String),

    #[error("invalid protocol request: {0}")]
    InvalidRequest(String),

    #[error("failed to deserialize protocol request: {0}")]
    DeserializeRequest(serde_json::Error),

    #[error("failed to serialize cache-key input: {0}")]
    SerializeKey(serde_json::Error),

    #[error("failed to serialize protocol response: {0}")]
    SerializeResponse(serde_json::Error),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("cache lock remained busy for {0:?}")]
    LockTimeout(Duration),

    #[error("failed to determine the platform cache directory: {0}")]
    CacheDirectory(String),

    #[error("failed to atomically update a cache entry: {0}")]
    AtomicWrite(String),

    #[error("failed to apply cache updates: {0}")]
    UpdateFailures(String),

    #[error("artifact changed while it was being hashed")]
    ArtifactChanged,
}

impl CacheError {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}
