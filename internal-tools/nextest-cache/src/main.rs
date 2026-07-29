// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ordinary run-wrapper that caches successful nextest test executions.

mod cache;
mod error;
mod exit_status;
mod store;

use crate::{
    cache::{ATTEMPT_ENV, DISABLE_ENV, RUN_ID_ENV, STRESS_CURRENT_ENV},
    error::CacheError,
    store::{CacheStore, RunLease},
};
use std::{
    env,
    ffi::{OsStr, OsString},
    process::{Command, ExitCode, ExitStatus},
};

fn main() -> ExitCode {
    let command = match ChildCommand::parse(env::args_os().skip(1).collect()) {
        Ok(command) => command,
        Err(error) => return report_fatal(error),
    };

    let prepared = prepare_cache(&command);
    if prepared.as_ref().is_some_and(|cache| cache.hit) {
        return ExitCode::SUCCESS;
    }

    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            if let Some(cache) = &prepared {
                warn_cache_update(cache.store.invalidate(&cache.token));
            }
            return report_fatal(CacheError::io(
                format!("failed to execute the child program {:?}", command.program),
                error,
            ));
        }
    };

    if let Some(cache) = prepared {
        let update = if status.success() && cache.mode == CacheMode::FirstAttempt {
            cache.store.store_clean_pass(&cache.token)
        } else {
            cache.store.invalidate(&cache.token)
        };
        warn_cache_update(update);
    }

    exit_status::exit(status)
}

#[derive(Debug)]
struct ChildCommand {
    program: OsString,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl ChildCommand {
    fn parse(mut args: Vec<OsString>) -> Result<Self, CacheError> {
        let additional_environment = parse_environment_options(&mut args)?;
        if args.first().is_some_and(|arg| arg == "--") {
            args.remove(0);
        }
        let mut args = args.into_iter();
        let program = args.next().ok_or_else(|| {
            CacheError::InvalidInvocation("the wrapper requires a child program".to_owned())
        })?;
        Ok(Self {
            program,
            args: args.collect(),
            environment: cache::selected_environment(&additional_environment),
        })
    }

    fn command_line(&self) -> Vec<OsString> {
        let mut command = Vec::with_capacity(self.args.len() + 1);
        command.push(self.program.clone());
        command.extend(self.args.iter().cloned());
        command
    }

    fn status(&self) -> Result<ExitStatus, std::io::Error> {
        Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .status()
    }
}

fn parse_environment_options(args: &mut Vec<OsString>) -> Result<Vec<String>, CacheError> {
    let mut environment = Vec::new();
    while args.first().is_some_and(|arg| arg == "--env") {
        if args.len() < 2 {
            return Err(CacheError::InvalidInvocation(
                "`--env` requires an environment variable name".to_owned(),
            ));
        }
        let name = args.remove(1);
        args.remove(0);
        environment.push(validate_environment_name(&name)?);
    }

    if !environment.is_empty() && args.first().is_none_or(|arg| arg != "--") {
        return Err(CacheError::InvalidInvocation(
            "`--env` options must be followed by `--` and the child program".to_owned(),
        ));
    }
    Ok(environment)
}

fn validate_environment_name(name: &OsStr) -> Result<String, CacheError> {
    let Some(name) = name.to_str() else {
        return Err(CacheError::InvalidInvocation(
            "an environment variable name must be valid UTF-8".to_owned(),
        ));
    };
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(CacheError::InvalidInvocation(format!(
            "{name:?} is not a valid environment variable name"
        )));
    }
    if name
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"NEXTEST"))
    {
        return Err(CacheError::InvalidInvocation(format!(
            "{name:?} begins with `NEXTEST`, which is reserved for nextest"
        )));
    }
    Ok(name.to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheMode {
    FirstAttempt,
    Retry,
}

impl CacheMode {
    fn from_environment() -> Option<Self> {
        if env::var_os(DISABLE_ENV).is_some() {
            return None;
        }
        if env::var_os(STRESS_CURRENT_ENV).is_some_and(|value| value != "none") {
            return None;
        }
        match env::var(ATTEMPT_ENV) {
            Ok(attempt) if attempt == "1" => Some(Self::FirstAttempt),
            Ok(attempt) if attempt.parse::<u32>().is_ok_and(|attempt| attempt > 1) => {
                Some(Self::Retry)
            }
            Ok(attempt) => {
                warn(format!(
                    "{ATTEMPT_ENV} has unsupported value {attempt:?}; running without caching"
                ));
                None
            }
            Err(_) => {
                warn(format!(
                    "{ATTEMPT_ENV} is not set to a valid nextest attempt; running without caching"
                ));
                None
            }
        }
    }
}

#[derive(Debug)]
struct PreparedCache {
    store: CacheStore,
    token: String,
    mode: CacheMode,
    hit: bool,
    _run_lease: RunLease,
}

fn prepare_cache(command: &ChildCommand) -> Option<PreparedCache> {
    let mode = CacheMode::from_environment()?;
    let run_id = match env::var_os(RUN_ID_ENV) {
        Some(run_id) if !run_id.as_encoded_bytes().is_empty() => run_id,
        _ => {
            warn(format!(
                "{RUN_ID_ENV} is missing or empty; running without caching"
            ));
            return None;
        }
    };
    match try_prepare_cache(command, &run_id, mode) {
        Ok(prepared) => Some(prepared),
        Err(error) => {
            warn(format!(
                "cache access failed: {error}; running without caching"
            ));
            None
        }
    }
}

fn try_prepare_cache(
    command: &ChildCommand,
    run_id: &OsStr,
    mode: CacheMode,
) -> Result<PreparedCache, CacheError> {
    let cwd = env::current_dir()
        .map_err(|error| CacheError::io("failed to determine the current directory", error))?;
    let command_line = command.command_line();
    let artifact = cache::find_artifact(&command_line, &cwd).ok_or_else(|| {
        CacheError::InvalidInvocation(
            "the child command does not contain one unambiguous `--exact` test invocation"
                .to_owned(),
        )
    })?;
    let store = CacheStore::discover()?;
    let artifact_digest = store.load_or_hash_for_run(run_id, &artifact)?;
    if artifact_digest.was_hashed {
        cache::trace_artifact_hash(&artifact, &artifact_digest.bytes);
    }
    let token = cache::derive_token(
        &artifact_digest.bytes,
        &command_line,
        &cwd,
        &command.environment,
    );

    if mode == CacheMode::Retry {
        warn_cache_update(store.invalidate(&token));
        return Ok(PreparedCache {
            store,
            token,
            mode,
            hit: false,
            _run_lease: artifact_digest.run_lease,
        });
    }
    let hit = store.contains_clean_pass(&token)?;
    Ok(PreparedCache {
        store,
        token,
        mode,
        hit,
        _run_lease: artifact_digest.run_lease,
    })
}

fn warn_cache_update(result: Result<(), CacheError>) {
    if let Err(error) = result {
        warn(format!("failed to update the cache: {error}"));
    }
}

fn warn(message: impl std::fmt::Display) {
    eprintln!("nextest-cache: warning: {message}");
}

fn report_fatal(error: CacheError) -> ExitCode {
    eprintln!("nextest-cache: {error}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_options_are_parsed_before_the_separator() {
        let mut args = ["--env", "FIRST", "--env", "SECOND", "--", "child"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(
            parse_environment_options(&mut args).unwrap(),
            ["FIRST", "SECOND"],
        );
        assert_eq!(args, ["--", "child"].map(OsString::from));
    }

    #[test]
    fn environment_options_require_a_separator() {
        let mut args = ["--env", "SELECTED", "child"].map(OsString::from).to_vec();
        let error = parse_environment_options(&mut args).unwrap_err();
        assert!(matches!(error, CacheError::InvalidInvocation(_)));
    }

    #[test]
    fn environment_names_are_portable_and_not_reserved() {
        for valid in ["NAME", "_NAME", "NAME_2"] {
            assert_eq!(validate_environment_name(OsStr::new(valid)).unwrap(), valid);
        }
        for invalid in ["", "2_NAME", "A=B", "NEXTEST", "NEXTEST_PROFILE"] {
            let error = validate_environment_name(OsStr::new(invalid)).unwrap_err();
            assert!(
                matches!(error, CacheError::InvalidInvocation(_)),
                "{invalid}"
            );
        }
    }
}
