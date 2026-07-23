// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client-side support for run-scoped cache-provider wrappers.

use super::{Interceptor, VersionEnvVars};
use crate::{
    cache_protocol::{
        ArtifactRequest, CACHE_OPERATION_COMMIT, CACHE_OPERATION_ENV, CACHE_OPERATION_PREPARE,
        CACHE_PROTOCOL_ENV, CACHE_PROTOCOL_V1, CACHE_TOKEN_ENV, CacheExecutionData,
        CommitDisposition, CommitRequest, CommitResponse, CommitUpdate, MAX_BYPASS_REASON_LEN,
        MAX_CACHE_TOKEN_LEN, PrepareDecision, PrepareRequest, PrepareResponse, ProtocolVersion,
        TestRequest,
    },
    config::{
        core::EvaluatableProfile,
        elements::{
            FlakyResult, LeakTimeout, LeakTimeoutResult, RetryPolicy, SlowTimeout,
            SlowTimeoutResult, TestGroup,
        },
        scripts::{WrapperScriptConfig, WrapperScriptProtocol, WrapperScriptTargetRunner},
    },
    list::{
        OwnedTestInstanceId, TestExecuteContext, TestInstance, TestInstanceId, TestInstanceIdKey,
        TestList,
    },
    reporter::events::{ExecutionResultDescription, ReporterEvent, TestEventKind},
    run_mode::NextestRunMode,
    target_runner::TargetRunner,
    test_command::TestCommand,
    test_output::CaptureStrategy,
};
use camino::Utf8PathBuf;
use nextest_metadata::{FilterMatch, RustBinaryId};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsStr,
    io::{self, Write},
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Clone, Debug, Default)]
pub(super) struct CacheLookup {
    entries: Arc<HashMap<OwnedTestInstanceId, PreparedCacheTest>>,
}

impl CacheLookup {
    pub(super) fn is_hit(&self, id: TestInstanceId<'_>) -> bool {
        self.get(id)
            .is_some_and(|prepared| prepared.kind == PreparedKind::Hit)
    }

    pub(super) fn token(&self, id: TestInstanceId<'_>) -> Option<&str> {
        self.get(id).and_then(|prepared| {
            (prepared.kind == PreparedKind::Miss).then_some(prepared.token.as_str())
        })
    }

    fn get(&self, id: TestInstanceId<'_>) -> Option<&PreparedCacheTest> {
        self.entries.get(&id as &dyn TestInstanceIdKey)
    }
}

#[derive(Clone, Debug)]
struct PreparedCacheTest {
    provider_index: usize,
    test_id: u64,
    token: String,
    kind: PreparedKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedKind {
    Hit,
    Miss,
}

#[derive(Debug)]
pub(super) struct CacheSession {
    lookup: CacheLookup,
    providers: Vec<PreparedProvider>,
}

impl CacheSession {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn prepare<'a>(
        test_list: &'a TestList<'a>,
        profile: &'a EvaluatableProfile<'a>,
        run_id: quick_junit::ReportUuid,
        version_env_vars: &VersionEnvVars,
        double_spawn: &crate::double_spawn::DoubleSpawnInfo,
        target_runner: &TargetRunner,
        test_threads: usize,
        capture_strategy: CaptureStrategy,
        force_retries: Option<RetryPolicy>,
        force_flaky_result: Option<FlakyResult>,
        consult: bool,
    ) -> Option<Self> {
        if test_list.mode() != NextestRunMode::Test {
            return None;
        }
        let Some(capture_strategy) = CacheCaptureStrategy::new(capture_strategy) else {
            debug!("cache provider disabled because output capture is disabled");
            return None;
        };
        if !profile.setup_scripts(test_list).is_empty() {
            debug!("cache provider disabled because setup scripts are active");
            return None;
        }

        let execute_context = TestExecuteContext {
            run_id,
            version_env_vars,
            profile_name: profile.name(),
            double_spawn,
            target_runner,
        };
        let mut groups: Vec<ProviderCandidates<'a>> = Vec::new();

        for instance in test_list
            .iter_tests()
            .filter(|instance| matches!(instance.test_info.filter_match, FilterMatch::Matches))
        {
            let settings = profile.settings_for(test_list.mode(), &instance.to_test_query());
            let Some(wrapper) = settings.run_wrapper() else {
                continue;
            };
            if wrapper.protocol != WrapperScriptProtocol::NextestCacheV1 {
                continue;
            }
            if matches!(
                wrapper.target_runner,
                WrapperScriptTargetRunner::OverridesWrapper
            ) && target_runner
                .for_build_platform(instance.suite_info.build_platform)
                .is_some()
            {
                debug!(
                    test = %instance.id(),
                    "cache provider disabled because a target runner overrides the wrapper"
                );
                continue;
            }

            let group = match groups
                .iter_mut()
                .find(|group| std::ptr::eq(group.wrapper, wrapper))
            {
                Some(group) => group,
                None => {
                    groups.push(ProviderCandidates {
                        wrapper,
                        candidates: Vec::new(),
                    });
                    groups.last_mut().expect("group was just pushed")
                }
            };
            group.candidates.push(CacheCandidate { instance, settings });
        }

        if groups.is_empty() {
            return None;
        }
        if groups.len() > 1 {
            warn!(
                "cache provider disabled because more than one protocol wrapper is active in this run"
            );
            return None;
        }

        let mut entries = HashMap::new();
        let mut providers = Vec::new();

        for group in groups {
            let command = ProviderCommand::new(group.wrapper, test_list, profile.name(), run_id);
            let request_data = match build_prepare_request(
                &group,
                &execute_context,
                test_list,
                test_threads,
                capture_strategy,
                force_retries,
                force_flaky_result,
                consult,
            ) {
                Ok(data) => data,
                Err(error) => {
                    warn!(
                        provider = %command.program,
                        %error,
                        "cache provider request could not be built; executing affected tests"
                    );
                    continue;
                }
            };

            let response = match command
                .execute::<_, PrepareResponse>(CACHE_OPERATION_PREPARE, &request_data.request)
            {
                Ok(response) => response,
                Err(error) => {
                    warn!(
                        provider = %command.program,
                        %error,
                        "cache provider prepare failed; executing affected tests"
                    );
                    continue;
                }
            };
            let decisions = match validate_prepare_response(
                response,
                &request_data.test_ids,
                consult,
            ) {
                Ok(decisions) => decisions,
                Err(error) => {
                    warn!(
                        provider = %command.program,
                        %error,
                        "cache provider returned an invalid prepare response; executing affected tests"
                    );
                    continue;
                }
            };

            let provider_index = providers.len();
            let mut prepared_count = 0;
            for decision in decisions.into_values() {
                match decision {
                    ValidatedDecision::Hit { test_id, token } => {
                        let test_instance = request_data
                            .test_ids
                            .get(&test_id)
                            .expect("validated decision has a known test ID")
                            .clone();
                        entries.insert(
                            test_instance,
                            PreparedCacheTest {
                                provider_index,
                                test_id,
                                token,
                                kind: PreparedKind::Hit,
                            },
                        );
                        prepared_count += 1;
                    }
                    ValidatedDecision::Miss { test_id, token } => {
                        let test_instance = request_data
                            .test_ids
                            .get(&test_id)
                            .expect("validated decision has a known test ID")
                            .clone();
                        entries.insert(
                            test_instance,
                            PreparedCacheTest {
                                provider_index,
                                test_id,
                                token,
                                kind: PreparedKind::Miss,
                            },
                        );
                        prepared_count += 1;
                    }
                    ValidatedDecision::Bypass { test_id, reason } => {
                        debug!(
                            provider = %command.program,
                            test_id,
                            reason,
                            "cache provider bypassed test"
                        );
                    }
                }
            }

            if prepared_count > 0 {
                providers.push(PreparedProvider {
                    command,
                    updates: BTreeMap::new(),
                });
            }
        }

        if entries.is_empty() {
            None
        } else {
            Some(Self {
                lookup: CacheLookup {
                    entries: Arc::new(entries),
                },
                providers,
            })
        }
    }

    pub(super) fn lookup(&self) -> CacheLookup {
        self.lookup.clone()
    }

    pub(super) fn observe(&mut self, event: &ReporterEvent<'_>) {
        let ReporterEvent::Test(event) = event else {
            return;
        };

        match &event.kind {
            TestEventKind::TestAttemptFailedWillRetry { test_instance, .. } => {
                self.record_disposition(*test_instance, CommitDisposition::Invalidate);
            }
            TestEventKind::TestFinished {
                test_instance,
                run_statuses,
                ..
            } => {
                let Some(prepared) = self.lookup.get(*test_instance) else {
                    return;
                };
                let disposition = if prepared.kind == PreparedKind::Hit {
                    CommitDisposition::Hit
                } else if run_statuses.len() == 1
                    && matches!(
                        run_statuses.last_status().result,
                        ExecutionResultDescription::Pass
                    )
                {
                    CommitDisposition::CleanPass
                } else {
                    CommitDisposition::Invalidate
                };
                self.record_disposition(*test_instance, disposition);
            }
            _ => {}
        }
    }

    pub(super) fn commit(self) {
        for provider in self.providers {
            if provider.updates.is_empty() {
                continue;
            }
            let request = CommitRequest {
                version: ProtocolVersion::V1,
                updates: provider.updates.into_values().collect(),
            };
            match provider
                .command
                .execute::<_, CommitResponse>(CACHE_OPERATION_COMMIT, &request)
            {
                Ok(response) if response.version.is_v1_compatible() => {}
                Ok(response) => warn!(
                    provider = %provider.command.program,
                    version = ?response.version,
                    "cache provider returned an incompatible commit response"
                ),
                Err(error) => warn!(
                    provider = %provider.command.program,
                    %error,
                    "cache provider commit failed"
                ),
            }
        }
    }

    fn record_disposition(
        &mut self,
        test_instance: TestInstanceId<'_>,
        disposition: CommitDisposition,
    ) {
        let Some(prepared) = self.lookup.get(test_instance).cloned() else {
            return;
        };

        let disposition = match (prepared.kind, disposition) {
            (PreparedKind::Hit, CommitDisposition::Hit) => CommitDisposition::Hit,
            (PreparedKind::Miss, CommitDisposition::CleanPass) => CommitDisposition::CleanPass,
            (PreparedKind::Miss, CommitDisposition::Invalidate) => CommitDisposition::Invalidate,
            (kind, disposition) => {
                warn!(
                    test = %test_instance,
                    ?kind,
                    ?disposition,
                    "cache provider observed an inconsistent prepared state; invalidating entry"
                );
                CommitDisposition::Invalidate
            }
        };

        let provider = self
            .providers
            .get_mut(prepared.provider_index)
            .expect("prepared provider index is valid");
        let update = CommitUpdate {
            test_id: prepared.test_id,
            token: prepared.token,
            disposition,
            execution: CacheExecutionData::default(),
        };
        if let Some(existing) = provider.updates.get_mut(&prepared.test_id) {
            existing.disposition = merge_dispositions(existing.disposition, update.disposition);
        } else {
            provider.updates.insert(prepared.test_id, update);
        }
    }
}

fn merge_dispositions(existing: CommitDisposition, new: CommitDisposition) -> CommitDisposition {
    if existing == CommitDisposition::Invalidate || new == CommitDisposition::Invalidate {
        CommitDisposition::Invalidate
    } else {
        new
    }
}

#[derive(Debug)]
struct PreparedProvider {
    command: ProviderCommand,
    updates: BTreeMap<u64, CommitUpdate>,
}

struct ProviderCandidates<'a> {
    wrapper: &'a WrapperScriptConfig,
    candidates: Vec<CacheCandidate<'a>>,
}

struct CacheCandidate<'a> {
    instance: TestInstance<'a>,
    settings: crate::config::overrides::TestSettings<'a>,
}

struct PrepareRequestData {
    request: PrepareRequest,
    test_ids: BTreeMap<u64, OwnedTestInstanceId>,
}

#[expect(clippy::too_many_arguments)]
fn build_prepare_request(
    group: &ProviderCandidates<'_>,
    execute_context: &TestExecuteContext<'_>,
    test_list: &TestList<'_>,
    test_threads: usize,
    capture_strategy: CacheCaptureStrategy,
    force_retries: Option<RetryPolicy>,
    force_flaky_result: Option<FlakyResult>,
    consult: bool,
) -> Result<PrepareRequestData, serde_json::Error> {
    let mut artifact_indexes: BTreeMap<&RustBinaryId, usize> = BTreeMap::new();
    let mut artifacts: Vec<ArtifactRequest> = Vec::new();
    let mut test_ids = BTreeMap::new();

    for (test_id, candidate) in group.candidates.iter().enumerate() {
        let test_id = test_id as u64;
        let suite = candidate.instance.suite_info;
        let artifact_index = match artifact_indexes.get(&suite.binary_id) {
            Some(index) => *index,
            None => {
                let index = artifacts.len();
                artifact_indexes.insert(&suite.binary_id, index);
                artifacts.push(ArtifactRequest {
                    artifact_id: index as u64,
                    binary_id: suite.binary_id.to_string(),
                    path: suite.binary_path.clone(),
                    tests: Vec::new(),
                });
                index
            }
        };

        let execution_key = execution_key(
            candidate,
            group.wrapper,
            execute_context,
            test_list,
            test_threads,
            capture_strategy,
            force_retries,
            force_flaky_result,
        )?;
        artifacts[artifact_index].tests.push(TestRequest {
            test_id,
            test_name: candidate.instance.name.to_string(),
            execution_key,
        });
        test_ids.insert(test_id, candidate.instance.id().to_owned());
    }

    Ok(PrepareRequestData {
        request: PrepareRequest {
            version: ProtocolVersion::V1,
            namespace: test_list.workspace_root().to_string(),
            consult,
            record: true,
            artifacts,
        },
        test_ids,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ExecutionKey<'a> {
    format: &'static str,
    nextest_version: String,
    required_version: Option<String>,
    recommended_version: Option<String>,
    profile_name: &'a str,
    mode: String,
    binary_id: &'a str,
    test_name: &'a str,
    working_directory: &'a str,
    command_line: Vec<String>,
    command_environment: CommandEnvironmentKey,
    capture_strategy: CacheCaptureStrategy,
    test_group: &'a TestGroup,
    test_threads: usize,
    retries: RetryPolicyKey,
    flaky_result: FlakyResult,
    slow_timeout: SlowTimeoutKey,
    leak_timeout: LeakTimeoutKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CacheCaptureStrategy {
    Split,
    Combined,
}

impl CacheCaptureStrategy {
    fn new(strategy: CaptureStrategy) -> Option<Self> {
        match strategy {
            CaptureStrategy::Split => Some(Self::Split),
            CaptureStrategy::Combined => Some(Self::Combined),
            CaptureStrategy::None => None,
        }
    }
}

#[cfg(unix)]
type CommandEnvironmentUnit = u8;
#[cfg(windows)]
type CommandEnvironmentUnit = u16;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct CommandEnvironmentKey {
    encoding: &'static str,
    variables: Vec<CommandEnvironmentVariableKey>,
}

#[derive(Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CommandEnvironmentVariableKey {
    name: Vec<CommandEnvironmentUnit>,
    value: Option<Vec<CommandEnvironmentUnit>>,
}

fn command_environment_key(command: &TestCommand) -> CommandEnvironmentKey {
    command_environment_key_from_iter(command.explicit_env())
}

fn command_environment_key_from_iter<'a>(
    environment: impl IntoIterator<Item = (&'a OsStr, Option<&'a OsStr>)>,
) -> CommandEnvironmentKey {
    let mut variables = environment
        .into_iter()
        .map(|(name, value)| CommandEnvironmentVariableKey {
            name: os_str_units(name),
            value: value.map(os_str_units),
        })
        .collect::<Vec<_>>();
    variables.sort_unstable();

    CommandEnvironmentKey {
        encoding: COMMAND_ENVIRONMENT_ENCODING,
        variables,
    }
}

#[cfg(unix)]
const COMMAND_ENVIRONMENT_ENCODING: &str = "unix-bytes";
#[cfg(windows)]
const COMMAND_ENVIRONMENT_ENCODING: &str = "windows-utf16";

#[cfg(unix)]
fn os_str_units(value: &OsStr) -> Vec<CommandEnvironmentUnit> {
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_str_units(value: &OsStr) -> Vec<CommandEnvironmentUnit> {
    value.encode_wide().collect()
}

#[derive(Serialize)]
#[serde(tag = "backoff", rename_all = "kebab-case")]
enum RetryPolicyKey {
    Fixed {
        count: u32,
        delay: DurationKey,
        jitter: bool,
    },
    Exponential {
        count: u32,
        delay: DurationKey,
        jitter: bool,
        max_delay: Option<DurationKey>,
    },
}

impl From<RetryPolicy> for RetryPolicyKey {
    fn from(value: RetryPolicy) -> Self {
        match value {
            RetryPolicy::Fixed {
                count,
                delay,
                jitter,
            } => Self::Fixed {
                count,
                delay: delay.into(),
                jitter,
            },
            RetryPolicy::Exponential {
                count,
                delay,
                jitter,
                max_delay,
            } => Self::Exponential {
                count,
                delay: delay.into(),
                jitter,
                max_delay: max_delay.map(Into::into),
            },
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
struct DurationKey {
    secs: u64,
    nanos: u32,
}

impl From<Duration> for DurationKey {
    fn from(value: Duration) -> Self {
        Self {
            secs: value.as_secs(),
            nanos: value.subsec_nanos(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct SlowTimeoutKey {
    period: DurationKey,
    terminate_after: Option<usize>,
    grace_period: DurationKey,
    on_timeout: SlowTimeoutResult,
}

impl From<SlowTimeout> for SlowTimeoutKey {
    fn from(value: SlowTimeout) -> Self {
        Self {
            period: value.period.into(),
            terminate_after: value.terminate_after.map(Into::into),
            grace_period: value.grace_period.into(),
            on_timeout: value.on_timeout,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct LeakTimeoutKey {
    period: DurationKey,
    result: LeakTimeoutResult,
}

impl From<LeakTimeout> for LeakTimeoutKey {
    fn from(value: LeakTimeout) -> Self {
        Self {
            period: value.period.into(),
            result: value.result,
        }
    }
}

#[expect(clippy::too_many_arguments)]
fn execution_key(
    candidate: &CacheCandidate<'_>,
    wrapper: &WrapperScriptConfig,
    execute_context: &TestExecuteContext<'_>,
    test_list: &TestList<'_>,
    test_threads: usize,
    capture_strategy: CacheCaptureStrategy,
    force_retries: Option<RetryPolicy>,
    force_flaky_result: Option<FlakyResult>,
) -> Result<String, serde_json::Error> {
    let settings = &candidate.settings;
    let command = candidate.instance.make_command(
        execute_context,
        test_list,
        Some(wrapper),
        settings.run_extra_args(),
        &Interceptor::None,
    );

    let key = ExecutionKey {
        format: "nextest-execution-key-v1",
        nextest_version: execute_context.version_env_vars.current_version.to_string(),
        required_version: execute_context
            .version_env_vars
            .required_version
            .as_ref()
            .map(ToString::to_string),
        recommended_version: execute_context
            .version_env_vars
            .recommended_version
            .as_ref()
            .map(ToString::to_string),
        profile_name: execute_context.profile_name,
        mode: test_list.mode().to_string(),
        binary_id: candidate.instance.suite_info.binary_id.as_str(),
        test_name: candidate.instance.name.as_str(),
        working_directory: candidate.instance.suite_info.cwd.as_str(),
        command_line: candidate.instance.command_line(
            execute_context,
            test_list,
            Some(wrapper),
            settings.run_extra_args(),
        ),
        command_environment: command_environment_key(&command),
        capture_strategy,
        test_group: settings.test_group(),
        test_threads,
        retries: force_retries.unwrap_or_else(|| settings.retries()).into(),
        flaky_result: force_flaky_result.unwrap_or_else(|| settings.flaky_result()),
        slow_timeout: settings.slow_timeout().into(),
        leak_timeout: settings.leak_timeout().into(),
    };
    serde_json::to_string(&key)
}

#[derive(Debug)]
enum ValidatedDecision {
    Hit { test_id: u64, token: String },
    Miss { test_id: u64, token: String },
    Bypass { test_id: u64, reason: String },
}

fn validate_prepare_response(
    response: PrepareResponse,
    expected: &BTreeMap<u64, OwnedTestInstanceId>,
    consult: bool,
) -> Result<BTreeMap<u64, ValidatedDecision>, InvalidPrepareResponse> {
    if !response.version.is_v1_compatible() {
        return Err(InvalidPrepareResponse::IncompatibleVersion(
            response.version,
        ));
    }
    if response.decisions.len() != expected.len() {
        return Err(InvalidPrepareResponse::WrongDecisionCount {
            expected: expected.len(),
            actual: response.decisions.len(),
        });
    }

    let mut decisions = BTreeMap::new();
    for decision in response.decisions {
        let test_id = decision.test_id();
        if !expected.contains_key(&test_id) {
            return Err(InvalidPrepareResponse::UnknownTestId(test_id));
        }
        if decisions.contains_key(&test_id) {
            return Err(InvalidPrepareResponse::DuplicateTestId(test_id));
        }

        let decision = match decision {
            PrepareDecision::Hit { test_id, token } => {
                if !consult {
                    return Err(InvalidPrepareResponse::HitWhileConsultDisabled(test_id));
                }
                validate_token(test_id, &token)?;
                ValidatedDecision::Hit { test_id, token }
            }
            PrepareDecision::Miss { test_id, token } => {
                validate_token(test_id, &token)?;
                ValidatedDecision::Miss { test_id, token }
            }
            PrepareDecision::Bypass { test_id, reason } => {
                if reason.is_empty() || reason.len() > MAX_BYPASS_REASON_LEN {
                    return Err(InvalidPrepareResponse::InvalidBypassReason(test_id));
                }
                ValidatedDecision::Bypass { test_id, reason }
            }
        };
        decisions.insert(test_id, decision);
    }

    Ok(decisions)
}

fn validate_token(test_id: u64, token: &str) -> Result<(), InvalidPrepareResponse> {
    if token.is_empty() || token.len() > MAX_CACHE_TOKEN_LEN || token.contains('\0') {
        Err(InvalidPrepareResponse::InvalidToken(test_id))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
enum InvalidPrepareResponse {
    #[error("incompatible protocol version {0:?}")]
    IncompatibleVersion(ProtocolVersion),
    #[error("expected {expected} decisions, but received {actual}")]
    WrongDecisionCount { expected: usize, actual: usize },
    #[error("decision referenced unknown test ID {0}")]
    UnknownTestId(u64),
    #[error("decision duplicated test ID {0}")]
    DuplicateTestId(u64),
    #[error("provider returned a hit for test ID {0} while consultation was disabled")]
    HitWhileConsultDisabled(u64),
    #[error("provider returned an invalid token for test ID {0}")]
    InvalidToken(u64),
    #[error("provider returned an invalid bypass reason for test ID {0}")]
    InvalidBypassReason(u64),
}

#[derive(Clone, Debug)]
struct ProviderCommand {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    workspace_root: Utf8PathBuf,
    profile_name: String,
    run_id: quick_junit::ReportUuid,
}

impl ProviderCommand {
    fn new(
        wrapper: &WrapperScriptConfig,
        test_list: &TestList<'_>,
        profile_name: &str,
        run_id: quick_junit::ReportUuid,
    ) -> Self {
        Self {
            program: wrapper.command.program(
                test_list.workspace_root(),
                &test_list.rust_build_meta().target_directory,
            ),
            args: wrapper.command.args.clone(),
            env: wrapper
                .command
                .env
                .iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
            workspace_root: test_list.workspace_root().to_owned(),
            profile_name: profile_name.to_owned(),
            run_id,
        }
    }

    fn execute<T: Serialize, R: DeserializeOwned>(
        &self,
        operation: &'static str,
        request: &T,
    ) -> Result<R, ProviderProcessError> {
        let request =
            serde_json::to_vec(request).map_err(ProviderProcessError::SerializeRequest)?;
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .env("NEXTEST", "1")
            .env("NEXTEST_PROFILE", &self.profile_name)
            .env("NEXTEST_RUN_ID", self.run_id.to_string())
            .env("NEXTEST_WORKSPACE_ROOT", &self.workspace_root)
            .env(CACHE_PROTOCOL_ENV, CACHE_PROTOCOL_V1)
            .env(CACHE_OPERATION_ENV, operation)
            .env_remove(CACHE_TOKEN_ENV)
            .current_dir(&self.workspace_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(ProviderProcessError::Spawn)?;
        let mut stdin = child.stdin.take().expect("stdin was configured as piped");
        let writer = thread::spawn(move || -> io::Result<()> {
            stdin.write_all(&request)?;
            stdin.flush()
        });
        let output = child
            .wait_with_output()
            .map_err(ProviderProcessError::Wait)?;
        let writer_result = writer
            .join()
            .map_err(|_| ProviderProcessError::WriterPanic)?;

        if !output.status.success() {
            return Err(ProviderProcessError::Exit {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        writer_result.map_err(ProviderProcessError::WriteRequest)?;
        serde_json::from_slice(&output.stdout).map_err(ProviderProcessError::DeserializeResponse)
    }
}

#[derive(Debug, Error)]
enum ProviderProcessError {
    #[error("failed to serialize request: {0}")]
    SerializeRequest(serde_json::Error),
    #[error("failed to spawn provider: {0}")]
    Spawn(io::Error),
    #[error("failed while waiting for provider: {0}")]
    Wait(io::Error),
    #[error("provider exited with {status}; stderr: {stderr}")]
    Exit { status: ExitStatus, stderr: String },
    #[error("failed to write provider request: {0}")]
    WriteRequest(io::Error),
    #[error("provider stdin writer panicked")]
    WriterPanic,
    #[error("failed to deserialize provider response: {0}")]
    DeserializeResponse(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextest_metadata::{RustBinaryId, TestCaseName};

    const TOKEN: &str = "opaque-token";

    fn expected() -> BTreeMap<u64, OwnedTestInstanceId> {
        [
            (
                10,
                OwnedTestInstanceId {
                    binary_id: RustBinaryId::new("binary"),
                    test_name: TestCaseName::new("test-a"),
                },
            ),
            (
                20,
                OwnedTestInstanceId {
                    binary_id: RustBinaryId::new("binary"),
                    test_name: TestCaseName::new("test-b"),
                },
            ),
        ]
        .into_iter()
        .collect()
    }

    fn response(decisions: Vec<PrepareDecision>) -> PrepareResponse {
        PrepareResponse {
            version: ProtocolVersion::V1,
            decisions,
        }
    }

    #[test]
    fn prepare_response_accepts_complete_reordered_decisions() {
        let decisions = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    test_id: 20,
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Hit {
                    test_id: 10,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            true,
        )
        .unwrap();

        assert!(matches!(decisions[&10], ValidatedDecision::Hit { .. }));
        assert!(matches!(decisions[&20], ValidatedDecision::Miss { .. }));
    }

    #[test]
    fn prepare_response_rejects_wrong_count() {
        let error = validate_prepare_response(
            response(vec![PrepareDecision::Miss {
                test_id: 10,
                token: TOKEN.to_owned(),
            }]),
            &expected(),
            true,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InvalidPrepareResponse::WrongDecisionCount { .. }
        ));
    }

    #[test]
    fn prepare_response_rejects_duplicate_ids() {
        let error = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    test_id: 10,
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Miss {
                    test_id: 10,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            true,
        )
        .unwrap_err();
        assert!(matches!(error, InvalidPrepareResponse::DuplicateTestId(10)));
    }

    #[test]
    fn prepare_response_rejects_unknown_ids() {
        let error = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    test_id: 10,
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Miss {
                    test_id: 30,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            true,
        )
        .unwrap_err();
        assert!(matches!(error, InvalidPrepareResponse::UnknownTestId(30)));
    }

    #[test]
    fn prepare_response_rejects_hit_when_consultation_is_disabled() {
        let error = validate_prepare_response(
            response(vec![
                PrepareDecision::Hit {
                    test_id: 10,
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Miss {
                    test_id: 20,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InvalidPrepareResponse::HitWhileConsultDisabled(10)
        ));
    }

    #[test]
    fn prepare_response_rejects_invalid_tokens_and_reasons() {
        let token_error = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    test_id: 10,
                    token: String::new(),
                },
                PrepareDecision::Miss {
                    test_id: 20,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            true,
        )
        .unwrap_err();
        assert!(matches!(
            token_error,
            InvalidPrepareResponse::InvalidToken(10)
        ));

        let reason_error = validate_prepare_response(
            response(vec![
                PrepareDecision::Bypass {
                    test_id: 10,
                    reason: String::new(),
                },
                PrepareDecision::Miss {
                    test_id: 20,
                    token: TOKEN.to_owned(),
                },
            ]),
            &expected(),
            true,
        )
        .unwrap_err();
        assert!(matches!(
            reason_error,
            InvalidPrepareResponse::InvalidBypassReason(10)
        ));
    }

    #[test]
    fn command_environment_changes_execution_key_fragment() {
        let mut first = Command::new("test");
        first.env("CACHE_SEMANTIC", "one");
        let mut second = Command::new("test");
        second.env("CACHE_SEMANTIC", "two");

        let first =
            serde_json::to_string(&command_environment_key_from_iter(first.get_envs())).unwrap();
        let second =
            serde_json::to_string(&command_environment_key_from_iter(second.get_envs())).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn command_environment_key_is_order_independent() {
        let mut first = Command::new("test");
        first.env("SECOND", "two").env("FIRST", "one");
        let mut second = Command::new("test");
        second.env("FIRST", "one").env("SECOND", "two");

        let first =
            serde_json::to_string(&command_environment_key_from_iter(first.get_envs())).unwrap();
        let second =
            serde_json::to_string(&command_environment_key_from_iter(second.get_envs())).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn no_capture_is_not_cacheable_and_capture_modes_are_distinct() {
        assert_eq!(CacheCaptureStrategy::new(CaptureStrategy::None), None);

        let split =
            serde_json::to_string(&CacheCaptureStrategy::new(CaptureStrategy::Split).unwrap())
                .unwrap();
        let combined =
            serde_json::to_string(&CacheCaptureStrategy::new(CaptureStrategy::Combined).unwrap())
                .unwrap();
        assert_ne!(split, combined);
    }

    #[test]
    fn invalidation_is_monotonic() {
        for disposition in [
            CommitDisposition::Hit,
            CommitDisposition::CleanPass,
            CommitDisposition::Invalidate,
        ] {
            assert_eq!(
                merge_dispositions(CommitDisposition::Invalidate, disposition),
                CommitDisposition::Invalidate
            );
            assert_eq!(
                merge_dispositions(disposition, CommitDisposition::Invalidate),
                CommitDisposition::Invalidate
            );
        }
    }

    #[test]
    fn test_group_changes_execution_key_fragment() {
        let global = serde_json::to_string(&TestGroup::Global).unwrap();
        let custom = serde_json::to_string(&"custom".parse::<TestGroup>().unwrap()).unwrap();

        assert_ne!(global, custom);
    }
}
