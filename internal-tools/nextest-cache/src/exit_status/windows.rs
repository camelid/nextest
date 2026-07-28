// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::process::{self, ExitStatus};

pub(crate) fn exit(status: ExitStatus) -> ! {
    process::exit(status.code().unwrap_or(1));
}
