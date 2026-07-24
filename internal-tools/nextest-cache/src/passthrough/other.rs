// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::CacheError;
use std::{ffi::OsString, process::Command};

pub(crate) fn run(program: OsString, args: Vec<OsString>) -> Result<(), CacheError> {
    let status = Command::new(&program)
        .args(args)
        .status()
        .map_err(|error| {
            CacheError::io(
                format!("failed to execute child program {program:?}"),
                error,
            )
        })?;
    std::process::exit(status.code().unwrap_or(1));
}
