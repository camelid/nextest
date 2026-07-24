// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::process::Command;

#[test]
fn passthrough_preserves_child_exit_status() {
    let provider = env!("CARGO_BIN_EXE_nextest-cache");

    #[cfg(unix)]
    let status = Command::new(provider)
        .args(["/bin/sh", "-c", "exit 23"])
        .status()
        .unwrap();

    #[cfg(windows)]
    let status = Command::new(provider)
        .args(["cmd.exe", "/C", "exit 23"])
        .status()
        .unwrap();

    #[cfg(not(any(unix, windows)))]
    let status = Command::new(provider).args(["false"]).status().unwrap();

    #[cfg(any(unix, windows))]
    let expected_code = 23;
    #[cfg(not(any(unix, windows)))]
    let expected_code = 1;

    assert_eq!(status.code(), Some(expected_code));
}
