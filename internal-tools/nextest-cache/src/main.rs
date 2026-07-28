// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A reference run-scoped cache-provider wrapper for nextest.

mod error;
mod passthrough;
mod provider;
mod store;

use crate::error::CacheError;
use nextest_runner::cache_protocol::{
    CACHE_OPERATION_COMMIT, CACHE_OPERATION_ENV, CACHE_OPERATION_PREPARE, CACHE_PROTOCOL_ENV,
    CACHE_PROTOCOL_V1, CommitRequest, PrepareRequest,
};
use serde::de::DeserializeOwned;
use std::{env, ffi::OsString, io, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nextest-cache: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CacheError> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let protocol = env::var_os(CACHE_PROTOCOL_ENV);
    let operation = env::var_os(CACHE_OPERATION_ENV);

    match (protocol, operation) {
        (None, None) => {
            let mut args = args.into_iter();
            let program = args.next().ok_or_else(|| {
                CacheError::InvalidInvocation(
                    "ordinary wrapper mode requires a child program".to_owned(),
                )
            })?;
            passthrough::run(program, args.collect())
        }
        (Some(protocol), Some(operation)) => {
            if protocol != CACHE_PROTOCOL_V1 {
                return Err(CacheError::InvalidInvocation(format!(
                    "unsupported value for {CACHE_PROTOCOL_ENV}: {protocol:?}"
                )));
            }
            if !args.is_empty() {
                return Err(CacheError::InvalidInvocation(
                    "the reference provider does not accept configured wrapper arguments"
                        .to_owned(),
                ));
            }

            if operation == CACHE_OPERATION_PREPARE {
                let request: PrepareRequest = read_request()?;
                write_response(&provider::prepare(request)?)
            } else if operation == CACHE_OPERATION_COMMIT {
                let request: CommitRequest = read_request()?;
                provider::commit(request)
            } else {
                Err(CacheError::InvalidInvocation(format!(
                    "unsupported value for {CACHE_OPERATION_ENV}: {operation:?}"
                )))
            }
        }
        _ => Err(CacheError::InvalidInvocation(format!(
            "{CACHE_PROTOCOL_ENV} and {CACHE_OPERATION_ENV} must either both be set or both be absent"
        ))),
    }
}

fn read_request<T: DeserializeOwned>() -> Result<T, CacheError> {
    serde_json::from_reader(io::stdin().lock()).map_err(CacheError::DeserializeRequest)
}

fn write_response(response: &impl serde::Serialize) -> Result<(), CacheError> {
    serde_json::to_writer(io::stdout().lock(), response).map_err(CacheError::SerializeResponse)
}
