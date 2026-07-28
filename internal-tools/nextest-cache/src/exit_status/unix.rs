// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{mem, os::unix::process::ExitStatusExt, process, process::ExitStatus, ptr};

pub(crate) fn exit(status: ExitStatus) -> ! {
    if let Some(code) = status.code() {
        process::exit(code);
    }

    let signal = status.signal().unwrap_or(libc::SIGABRT);
    // Restore and unblock the signal before raising it so the wrapper has the
    // same externally observable termination as its child.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        let mut signals = mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, signal);
        libc::sigprocmask(libc::SIG_UNBLOCK, &signals, ptr::null_mut());
        libc::raise(signal);
    }

    process::exit(128 + signal);
}
