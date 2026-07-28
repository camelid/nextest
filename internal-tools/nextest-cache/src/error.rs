// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{io, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum CacheError {
    #[error("invalid invocation: {0}")]
    InvalidInvocation(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("{context} remained busy for {timeout:?}")]
    LockTimeout { context: String, timeout: Duration },

    #[error("failed to determine the platform cache directory: {0}")]
    CacheDirectory(String),

    #[error("failed to atomically update {context}: {message}")]
    AtomicWrite { context: String, message: String },

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
