// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ordinary run-wrapper that caches successful nextest test executions.

mod cache;
mod effect;
mod error;
mod exit_status;
mod store;

use crate::{
    cache::{ATTEMPT_ENV, DISABLE_ENV, RUN_ID_ENV, STRESS_CURRENT_ENV},
    effect::{EffectClassification, EffectError, EffectManifest, EffectPolicy, EffectTrace},
    error::CacheError,
    store::{CacheStore, RunLease},
};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Write,
    process::{Command, ExitCode, ExitStatus},
};

const RUN_WRAPPER_REPORT_ENV: &str = "NEXTEST_RUN_WRAPPER_REPORT";

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
                    report_wrapper_label("cache-io-bypass");
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
    if let Err(error) = result {
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
        let options = parse_wrapper_options(&mut args)?;
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
            environment: cache::selected_environment(&options.additional_environment),
            effect_policy: options.effect_policy,
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
                report_wrapper_label("cache-io-unavailable");
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
                report_wrapper_label("cache-io-unavailable");
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
                report_wrapper_label("cache-io-unavailable");
                return self
                    .plain_status()
                    .map(|status| (status, None))
                    .map_err(|error| CacheError::io("failed to execute the child program", error));
            }
            Err(error) => {
                warn(format!(
                    "failed to read the I/O effect ledger: {error}; running without caching"
                ));
                report_wrapper_label("cache-io-error");
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

#[derive(Debug, Eq, PartialEq)]
struct WrapperOptions {
    additional_environment: Vec<String>,
    effect_policy: EffectPolicy,
}

fn parse_wrapper_options(args: &mut Vec<OsString>) -> Result<WrapperOptions, CacheError> {
    let mut additional_environment = Vec::new();
    let mut effect_policy = None;
    let mut parsed_option = false;
    loop {
        if args.first().is_some_and(|arg| arg == "--env") {
            if args.len() < 2 {
                return Err(CacheError::InvalidInvocation(
                    "`--env` requires an environment variable name".to_owned(),
                ));
            }
            let name = args.remove(1);
            args.remove(0);
            additional_environment.push(validate_environment_name(&name)?);
            parsed_option = true;
        } else if args.first().is_some_and(|arg| arg == "--io-policy") {
            if args.len() < 2 {
                return Err(CacheError::InvalidInvocation(
                    "`--io-policy` requires a policy name".to_owned(),
                ));
            }
            if effect_policy.is_some() {
                return Err(CacheError::InvalidInvocation(
                    "`--io-policy` may only be specified once".to_owned(),
                ));
            }
            let value = args.remove(1);
            args.remove(0);
            effect_policy = Some(
                EffectPolicy::parse(&value)
                    .map_err(|error| CacheError::InvalidInvocation(error.to_string()))?,
            );
            parsed_option = true;
        } else {
            break;
        }
    }

    if parsed_option && args.first().is_none_or(|arg| arg != "--") {
        return Err(CacheError::InvalidInvocation(
            "wrapper options must be followed by `--` and the child program".to_owned(),
        ));
    }
    Ok(WrapperOptions {
        additional_environment,
        effect_policy: effect_policy.unwrap_or_else(EffectPolicy::default_for_platform),
    })
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
            policy,
            _run_lease: artifact_digest.run_lease,
        });
    }
    let hit = match store.load_clean_pass(&token)? {
        Some(manifest) => manifest.is_current().unwrap_or(false),
        None => false,
    };
    Ok(PreparedCache {
        store,
        token,
        mode,
        hit,
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
        let mut args = ["--env", "FIRST", "--env", "SECOND", "--", "child"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(
            parse_wrapper_options(&mut args)
                .unwrap()
                .additional_environment,
            ["FIRST", "SECOND"]
        );
        assert_eq!(args, ["--", "child"].map(OsString::from));
    }

    #[test]
    fn environment_options_require_a_separator() {
        let mut args = ["--env", "SELECTED", "child"].map(OsString::from).to_vec();
        let error = parse_wrapper_options(&mut args).unwrap_err();
        assert!(matches!(error, CacheError::InvalidInvocation(_)));
    }

    #[test]
    fn io_policy_is_parsed_with_wrapper_options() {
        let mut args = [
            "--env",
            "SELECTED",
            "--io-policy",
            "conservative",
            "--",
            "child",
        ]
        .map(OsString::from)
        .to_vec();
        let options = parse_wrapper_options(&mut args).unwrap();
        assert_eq!(options.additional_environment, ["SELECTED"]);
        assert_eq!(options.effect_policy, EffectPolicy::Conservative);
        assert_eq!(args, ["--", "child"].map(OsString::from));
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
