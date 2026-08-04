// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ordinary run-wrapper that caches successful nextest test executions.

mod cache;
mod effect;
mod error;
mod exit_status;
mod fingerprint;
mod store;

use crate::{
    cache::{ATTEMPT_ENV, DISABLE_ENV, RUN_ID_ENV, STRESS_CURRENT_ENV},
    effect::{EffectClassification, EffectError, EffectManifest, EffectPolicy, EffectTrace},
    error::CacheError,
    store::{CacheStore, RunLease},
};
use clap::{Parser, ValueEnum};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Write,
    process::{Command, ExitCode, ExitStatus},
};

const RUN_WRAPPER_REPORT_ENV: &str = "NEXTEST_RUN_WRAPPER_REPORT";
const NOT_CACHED_IO_EFFECTS: &str = "not cached: I/O effects";
const NOT_CACHED_TRACING_UNAVAILABLE: &str = "not cached: tracing unavailable";
const NOT_CACHED_TRACING_ERROR: &str = "not cached: tracing error";
const RERUN_INPUTS_CHANGED: &str = "rerun: inputs changed";

fn main() -> ExitCode {
    let command = match ChildCommand::parse(env::args_os().skip(1).collect()) {
        Ok(command) => command,
        Err(error) => return report_fatal(error),
    };

    let prepared = prepare_cache(&command);
    if prepared.as_ref().is_some_and(|cache| cache.hit) {
        report_cache_hit();
        return ExitCode::SUCCESS;
    }
    if prepared.as_ref().is_some_and(|cache| cache.inputs_changed) {
        report_wrapper_label(RERUN_INPUTS_CHANGED);
    }

    let execution_policy = prepared
        .as_ref()
        .filter(|cache| cache.mode == CacheMode::FirstAttempt)
        .map(|cache| cache.policy);
    let (status, effects) = match command.status(execution_policy) {
        Ok(status) => status,
        Err(error) => {
            if let Some(cache) = &prepared {
                warn_cache_update(cache.store.invalidate(&cache.token));
            }
            return report_fatal(error);
        }
    };

    if let Some(cache) = prepared {
        let update = if status.success() && cache.mode == CacheMode::FirstAttempt {
            match effects {
                Some(EffectClassification::Cacheable(manifest)) => {
                    cache.store.store_clean_pass(&cache.token, manifest)
                }
                Some(EffectClassification::Uncacheable(reasons)) => {
                    for reason in reasons {
                        warn(format!(
                            "not caching this test because it performed {reason}"
                        ));
                    }
                    report_wrapper_label(NOT_CACHED_IO_EFFECTS);
                    cache.store.invalidate(&cache.token)
                }
                None => cache.store.invalidate(&cache.token),
            }
        } else {
            cache.store.invalidate(&cache.token)
        };
        warn_cache_update(update);
    }

    exit_status::exit(status)
}

fn report_cache_hit() {
    report_wrapper_label("cached");
}

fn report_wrapper_label(label: &str) {
    let Some(path) = env::var_os(RUN_WRAPPER_REPORT_ENV) else {
        return;
    };
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| write!(file, r#"{{"label":"{label}"}}"#));
    if let Err(error) = result
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        warn(format!(
            "failed to write the run wrapper report to {path:?}: {error}"
        ));
    }
}

#[derive(Debug)]
struct ChildCommand {
    program: OsString,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    effect_policy: EffectPolicy,
}

impl ChildCommand {
    fn parse(mut args: Vec<OsString>) -> Result<Self, CacheError> {
        let has_separator = args.iter().any(|arg| arg == "--");
        let starts_with_wrapper_option = args
            .first()
            .is_some_and(|arg| arg == "--env" || arg == "--io-policy");
        if !has_separator && !starts_with_wrapper_option {
            args.insert(0, OsString::from("--"));
        }
        let options = WrapperOptions::try_parse_from(args)
            .map_err(|error| CacheError::InvalidInvocation(error.to_string()))?;
        if options.requires_separator() && !has_separator {
            return Err(CacheError::InvalidInvocation(
                "wrapper options must be followed by `--` and the child program".to_owned(),
            ));
        }
        let mut command = options.command.into_iter();
        let program = command
            .next()
            .expect("clap requires at least one child command argument");
        Ok(Self {
            program,
            args: command.collect(),
            environment: cache::selected_environment(&options.additional_environment),
            effect_policy: options
                .effect_policy
                .map(EffectPolicy::from)
                .unwrap_or_else(EffectPolicy::default_for_platform),
        })
    }

    fn command_line(&self) -> Vec<OsString> {
        let mut command = Vec::with_capacity(self.args.len() + 1);
        command.push(self.program.clone());
        command.extend(self.args.iter().cloned());
        command
    }

    fn status(
        &self,
        policy: Option<EffectPolicy>,
    ) -> Result<(ExitStatus, Option<EffectClassification>), CacheError> {
        let Some(policy) = policy.filter(|policy| policy.traces()) else {
            return self
                .plain_status()
                .map(|status| {
                    (
                        status,
                        Some(EffectClassification::Cacheable(EffectManifest::off())),
                    )
                })
                .map_err(|error| CacheError::io("failed to execute the child program", error));
        };
        let cwd = env::current_dir()
            .map_err(|error| CacheError::io("failed to determine the current directory", error))?;
        let command_line = self.command_line();
        let Some(artifact) = cache::find_artifact(&command_line, &cwd) else {
            return self
                .plain_status()
                .map(|status| (status, None))
                .map_err(|error| CacheError::io("failed to execute the child program", error));
        };
        let trace = match EffectTrace::new(cwd, artifact) {
            Ok(trace) => trace,
            Err(error) => {
                warn(format!(
                    "I/O tracing is unavailable: {error}; running without caching"
                ));
                report_wrapper_label(NOT_CACHED_TRACING_UNAVAILABLE);
                return self
                    .plain_status()
                    .map(|status| (status, None))
                    .map_err(|error| CacheError::io("failed to execute the child program", error));
            }
        };
        let status = match trace.status(&self.program, &self.args, &self.environment) {
            Ok(status) => status,
            Err(error) => {
                warn(format!(
                    "I/O tracing is unavailable: {error}; running without caching"
                ));
                report_wrapper_label(NOT_CACHED_TRACING_UNAVAILABLE);
                return self
                    .plain_status()
                    .map(|status| (status, None))
                    .map_err(|error| CacheError::io("failed to execute the child program", error));
            }
        };
        let effects = match trace.finish(policy) {
            Ok(effects) => Some(effects),
            Err(EffectError::TestNotStarted) if !status.success() => {
                warn("strace did not start the test; retrying without caching");
                report_wrapper_label(NOT_CACHED_TRACING_UNAVAILABLE);
                return self
                    .plain_status()
                    .map(|status| (status, None))
                    .map_err(|error| CacheError::io("failed to execute the child program", error));
            }
            Err(error) => {
                warn(format!(
                    "failed to read the I/O effect ledger: {error}; running without caching"
                ));
                report_wrapper_label(NOT_CACHED_TRACING_ERROR);
                None
            }
        };
        Ok((status, effects))
    }

    fn plain_status(&self) -> Result<ExitStatus, std::io::Error> {
        Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .status()
    }
}

#[derive(Debug, Parser)]
#[command(
    no_binary_name = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
struct WrapperOptions {
    #[arg(long = "env", value_name = "NAME", value_parser = validate_environment_name)]
    additional_environment: Vec<String>,
    #[arg(long = "io-policy", value_enum)]
    effect_policy: Option<EffectPolicyArg>,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

impl WrapperOptions {
    fn requires_separator(&self) -> bool {
        !self.additional_environment.is_empty() || self.effect_policy.is_some()
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EffectPolicyArg {
    Off,
    Conservative,
    ContentAddressed,
}

impl From<EffectPolicyArg> for EffectPolicy {
    fn from(value: EffectPolicyArg) -> Self {
        match value {
            EffectPolicyArg::Off => Self::Off,
            EffectPolicyArg::Conservative => Self::Conservative,
            EffectPolicyArg::ContentAddressed => Self::ContentAddressed,
        }
    }
}

fn validate_environment_name(name: &str) -> Result<String, String> {
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(format!("{name:?} is not a valid environment variable name"));
    }
    if name
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"NEXTEST"))
    {
        return Err(format!(
            "{name:?} begins with `NEXTEST`, which is reserved for nextest"
        ));
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
    inputs_changed: bool,
    policy: EffectPolicy,
    _run_lease: RunLease,
}

fn prepare_cache(command: &ChildCommand) -> Option<PreparedCache> {
    let mode = CacheMode::from_environment()?;
    let policy = command.effect_policy;
    let run_id = match env::var_os(RUN_ID_ENV) {
        Some(run_id) if !run_id.as_encoded_bytes().is_empty() => run_id,
        _ => {
            warn(format!(
                "{RUN_ID_ENV} is missing or empty; running without caching"
            ));
            return None;
        }
    };
    match try_prepare_cache(command, &run_id, mode, policy) {
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
    policy: EffectPolicy,
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
        policy.key(),
    );

    if mode == CacheMode::Retry {
        warn_cache_update(store.invalidate(&token));
        return Ok(PreparedCache {
            store,
            token,
            mode,
            hit: false,
            inputs_changed: false,
            policy,
            _run_lease: artifact_digest.run_lease,
        });
    }
    let (hit, inputs_changed) = match store.load_clean_pass(&token)? {
        Some(manifest) => {
            let is_current = manifest.is_current().unwrap_or(false);
            (is_current, !is_current)
        }
        None => (false, false),
    };
    Ok(PreparedCache {
        store,
        token,
        mode,
        hit,
        inputs_changed,
        policy,
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
        let args = ["--env", "FIRST", "--env", "SECOND", "--", "child"]
            .map(OsString::from)
            .to_vec();
        let command = ChildCommand::parse(args).unwrap();
        assert_eq!(command.program, "child");
        assert!(command.args.is_empty());
    }

    #[test]
    fn environment_options_require_a_separator() {
        let args = ["--env", "SELECTED", "child"].map(OsString::from).to_vec();
        let error = ChildCommand::parse(args).unwrap_err();
        assert!(matches!(error, CacheError::InvalidInvocation(_)));
    }

    #[test]
    fn io_policy_is_parsed_with_wrapper_options() {
        let args = [
            "--env",
            "SELECTED",
            "--io-policy",
            "conservative",
            "--",
            "child",
        ]
        .map(OsString::from)
        .to_vec();
        let command = ChildCommand::parse(args).unwrap();
        assert_eq!(command.effect_policy, EffectPolicy::Conservative);
        assert_eq!(command.program, "child");
    }

    #[test]
    fn environment_names_are_portable_and_not_reserved() {
        for valid in ["NAME", "_NAME", "NAME_2"] {
            assert_eq!(validate_environment_name(valid).unwrap(), valid);
        }
        for invalid in ["", "2_NAME", "A=B", "NEXTEST", "NEXTEST_PROFILE"] {
            validate_environment_name(invalid).unwrap_err();
        }
    }
}
