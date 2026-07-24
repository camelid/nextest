// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::CacheError;
use std::{ffi::OsString, os::unix::process::CommandExt, process::Command};

pub(crate) fn run(program: OsString, args: Vec<OsString>) -> Result<(), CacheError> {
    let error = Command::new(&program).args(args).exec();
    Err(CacheError::io(
        format!("failed to execute child program {program:?}"),
        error,
    ))
}
