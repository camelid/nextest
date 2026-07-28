// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client-side support for run-scoped cache-provider wrappers.

use super::{Interceptor, VersionEnvVars};
use crate::{
    cache_protocol::{
        ArtifactRequest, CACHE_CAPTURE_STRATEGY_ENV, CACHE_OPERATION_COMMIT, CACHE_OPERATION_ENV,
        CACHE_OPERATION_PREPARE, CACHE_PROTOCOL_ENV, CACHE_PROTOCOL_V1, CACHE_TOKEN_ENV,
        CommandSpec, CommitAction, CommitRequest, CommitUpdate, EnvironmentVariable,
        MAX_BYPASS_REASON_LEN, MAX_CACHE_TOKEN_LEN, PlatformString, PrepareDecision,
        PrepareRequest, PrepareResponse, TestRequest,
    },
    config::{
        core::EvaluatableProfile,
        elements::{LeakTimeoutResult, RetryPolicy, SlowTimeoutResult},
        scripts::{
            ScriptCommand, WrapperScriptConfig, WrapperScriptProtocol, WrapperScriptTargetRunner,
        },
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
use camino::{Utf8Path, Utf8PathBuf};
use nextest_metadata::FilterMatch;
use serde::{Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
        matches!(self.get(id), Some(PreparedCacheTest::Hit))
    }

    pub(super) fn token(&self, id: TestInstanceId<'_>) -> Option<&str> {
        match self.get(id) {
            Some(PreparedCacheTest::Miss(token)) => Some(token),
            Some(PreparedCacheTest::Hit) | None => None,
        }
    }

    fn get(&self, id: TestInstanceId<'_>) -> Option<&PreparedCacheTest> {
        self.entries.get(&id as &dyn TestInstanceIdKey)
    }
}

#[derive(Clone, Debug)]
enum PreparedCacheTest {
    Hit,
    Miss(String),
}

#[derive(Debug)]
pub(super) struct CacheSession {
    lookup: CacheLookup,
    provider: ProviderCommand,
    updates: HashMap<OwnedTestInstanceId, CommitUpdate>,
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
        consult: bool,
    ) -> Option<Self> {
        if test_list.mode() != NextestRunMode::Test {
            return None;
        }
        let Some(capture_strategy) = capture_strategy_name(capture_strategy) else {
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
        let mut wrapper: Option<&WrapperScriptConfig> = None;
        let mut candidates = Vec::new();
        for instance in test_list
            .iter_tests()
            .filter(|instance| matches!(instance.test_info.filter_match, FilterMatch::Matches))
        {
            let settings = profile.settings_for(test_list.mode(), &instance.to_test_query());
            let Some(candidate_wrapper) = settings.run_wrapper() else {
                continue;
            };
            if candidate_wrapper.protocol != WrapperScriptProtocol::NextestCacheV1 {
                continue;
            }
            if matches!(
                candidate_wrapper.target_runner,
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
            if wrapper.is_some_and(|wrapper| !std::ptr::eq(wrapper, candidate_wrapper)) {
                warn!(
                    "cache provider disabled because more than one protocol wrapper is active in this run"
                );
                return None;
            }
            wrapper = Some(candidate_wrapper);
            candidates.push(CacheCandidate { instance, settings });
        }

        let wrapper = wrapper?;
        let provider = ProviderCommand::new(
            wrapper,
            test_list,
            profile.name(),
            run_id,
            version_env_vars,
            test_threads,
            capture_strategy,
        );
        let (request, test_instances) = build_prepare_request(
            &candidates,
            wrapper,
            &execute_context,
            test_list,
            force_retries,
            consult,
        );
        let response =
            match provider.request::<_, PrepareResponse>(CACHE_OPERATION_PREPARE, &request) {
                Ok(response) => response,
                Err(error) => {
                    warn!(
                        provider = %provider.command.program,
                        %error,
                        "cache provider prepare failed; executing affected tests"
                    );
                    return None;
                }
            };
        let decisions = match validate_prepare_response(response, test_instances.len(), consult) {
            Ok(decisions) => decisions,
            Err(error) => {
                warn!(
                    provider = %provider.command.program,
                    %error,
                    "cache provider returned an invalid prepare response; executing affected tests"
                );
                return None;
            }
        };

        let mut entries = HashMap::with_capacity(decisions.len());
        for (test_instance, decision) in test_instances.into_iter().zip(decisions) {
            match decision {
                PrepareDecision::Hit => {
                    entries.insert(test_instance, PreparedCacheTest::Hit);
                }
                PrepareDecision::Miss { token } => {
                    entries.insert(test_instance, PreparedCacheTest::Miss(token));
                }
                PrepareDecision::Bypass { reason } => {
                    debug!(
                        provider = %provider.command.program,
                        test = ?test_instance,
                        reason,
                        "cache provider bypassed test"
                    );
                }
            }
        }

        (!entries.is_empty()).then(|| Self {
            lookup: CacheLookup {
                entries: Arc::new(entries),
            },
            provider,
            updates: HashMap::new(),
        })
    }

    pub(super) fn lookup(&self) -> CacheLookup {
        self.lookup.clone()
    }

    pub(super) fn observe(&mut self, event: &ReporterEvent<'_>) {
        let ReporterEvent::Test(event) = event else {
            return;
        };
        let TestEventKind::TestFinished {
            test_instance,
            run_statuses,
            ..
        } = &event.kind
        else {
            return;
        };
        let Some(PreparedCacheTest::Miss(token)) = self.lookup.get(*test_instance).cloned() else {
            return;
        };

        let action = cache_action(run_statuses.len(), &run_statuses.last_status().result);
        self.updates
            .insert(test_instance.to_owned(), CommitUpdate { token, action });
    }

    pub(super) fn commit(self) {
        if self.updates.is_empty() {
            return;
        }
        let request = CommitRequest {
            updates: self.updates.into_values().collect(),
        };
        if let Err(error) = self.provider.execute(CACHE_OPERATION_COMMIT, &request) {
            warn!(
                provider = %self.provider.command.program,
                %error,
                "cache provider commit failed"
            );
        }
    }
}

fn cache_action(attempts: usize, result: &ExecutionResultDescription) -> CommitAction {
    if attempts == 1 && matches!(result, ExecutionResultDescription::Pass) {
        CommitAction::Store
    } else {
        CommitAction::Invalidate
    }
}

struct CacheCandidate<'a> {
    instance: TestInstance<'a>,
    settings: crate::config::overrides::TestSettings<'a>,
}

fn build_prepare_request(
    candidates: &[CacheCandidate<'_>],
    wrapper: &WrapperScriptConfig,
    execute_context: &TestExecuteContext<'_>,
    test_list: &TestList<'_>,
    force_retries: Option<RetryPolicy>,
    consult: bool,
) -> (PrepareRequest, Vec<OwnedTestInstanceId>) {
    let mut indexes: BTreeMap<&Utf8Path, usize> = BTreeMap::new();
    let mut artifacts: Vec<ArtifactRequest> = Vec::new();
    let mut instances: Vec<Vec<OwnedTestInstanceId>> = Vec::new();

    for candidate in candidates {
        let suite = candidate.instance.suite_info;
        let index = *indexes.entry(&suite.binary_path).or_insert_with(|| {
            let index = artifacts.len();
            artifacts.push(ArtifactRequest {
                path: suite.binary_path.clone(),
                tests: Vec::new(),
            });
            instances.push(Vec::new());
            index
        });
        let command = candidate.instance.make_command(
            execute_context,
            test_list,
            Some(wrapper),
            candidate.settings.run_extra_args(),
            &Interceptor::None,
        );
        artifacts[index].tests.push(TestRequest {
            command: command_spec(&command, &suite.cwd),
            context: runner_context(candidate, force_retries),
        });
        instances[index].push(candidate.instance.id().to_owned());
    }

    (
        PrepareRequest { consult, artifacts },
        instances.into_iter().flatten().collect(),
    )
}

fn command_spec(command: &TestCommand, cwd: &Utf8Path) -> CommandSpec {
    let mut environment = command
        .explicit_env()
        .map(|(name, value)| EnvironmentVariable {
            name: platform_string(name),
            value: value.map(platform_string),
        })
        .collect::<Vec<_>>();
    environment.sort_unstable();
    CommandSpec {
        program: command.program().to_owned(),
        args: command.args().to_owned(),
        cwd: cwd.to_owned(),
        environment,
    }
}

#[cfg(unix)]
fn platform_string(value: &OsStr) -> PlatformString {
    PlatformString::Unix(value.as_bytes().to_vec())
}

#[cfg(windows)]
fn platform_string(value: &OsStr) -> PlatformString {
    PlatformString::Windows(value.encode_wide().collect())
}

fn runner_context(
    candidate: &CacheCandidate<'_>,
    force_retries: Option<RetryPolicy>,
) -> BTreeMap<String, String> {
    let settings = &candidate.settings;
    // Only the attempt count is visible to a clean first attempt. Retry timing
    // and flaky-result policy apply after failures, whose outcomes are never stored.
    let retries = force_retries.unwrap_or_else(|| settings.retries());
    let slow = settings.slow_timeout();
    let leak = settings.leak_timeout();
    [
        ("leak-timeout-period", duration_key(leak.period)),
        (
            "leak-timeout-result",
            leak_timeout_result(leak.result).to_owned(),
        ),
        (
            "nextest-binary-id",
            candidate.instance.suite_info.binary_id.to_string(),
        ),
        ("nextest-test-group", settings.test_group().to_string()),
        ("nextest-test-name", candidate.instance.name.to_string()),
        ("nextest-total-attempts", (retries.count() + 1).to_string()),
        ("slow-timeout-grace-period", duration_key(slow.grace_period)),
        ("slow-timeout-period", duration_key(slow.period)),
        (
            "slow-timeout-result",
            slow_timeout_result(slow.on_timeout).to_owned(),
        ),
        (
            "slow-timeout-terminate-after",
            slow.terminate_after
                .map_or_else(|| "none".to_owned(), |value| value.get().to_string()),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn duration_key(duration: Duration) -> String {
    format!("{}:{:09}", duration.as_secs(), duration.subsec_nanos())
}

fn slow_timeout_result(result: SlowTimeoutResult) -> &'static str {
    match result {
        SlowTimeoutResult::Fail => "fail",
        SlowTimeoutResult::Pass => "pass",
    }
}

fn leak_timeout_result(result: LeakTimeoutResult) -> &'static str {
    match result {
        LeakTimeoutResult::Fail => "fail",
        LeakTimeoutResult::Pass => "pass",
    }
}

fn capture_strategy_name(strategy: CaptureStrategy) -> Option<&'static str> {
    match strategy {
        CaptureStrategy::Split => Some("split"),
        CaptureStrategy::Combined => Some("combined"),
        CaptureStrategy::None => None,
    }
}

fn validate_prepare_response(
    response: PrepareResponse,
    expected: usize,
    consult: bool,
) -> Result<Vec<PrepareDecision>, InvalidPrepareResponse> {
    if response.decisions.len() != expected {
        return Err(InvalidPrepareResponse::WrongDecisionCount {
            expected,
            actual: response.decisions.len(),
        });
    }

    let mut tokens = HashSet::new();
    for (index, decision) in response.decisions.iter().enumerate() {
        match decision {
            PrepareDecision::Hit if !consult => {
                return Err(InvalidPrepareResponse::HitWhileConsultDisabled(index));
            }
            PrepareDecision::Miss { token } => {
                if token.is_empty() || token.len() > MAX_CACHE_TOKEN_LEN || token.contains('\0') {
                    return Err(InvalidPrepareResponse::InvalidToken(index));
                }
                if !tokens.insert(token) {
                    return Err(InvalidPrepareResponse::DuplicateToken(index));
                }
            }
            PrepareDecision::Bypass { reason }
                if reason.is_empty() || reason.len() > MAX_BYPASS_REASON_LEN =>
            {
                return Err(InvalidPrepareResponse::InvalidBypassReason(index));
            }
            PrepareDecision::Hit | PrepareDecision::Bypass { .. } => {}
        }
    }
    Ok(response.decisions)
}

#[derive(Debug, Error)]
enum InvalidPrepareResponse {
    #[error("expected {expected} decisions, but received {actual}")]
    WrongDecisionCount { expected: usize, actual: usize },
    #[error("decision {0} reused another miss token")]
    DuplicateToken(usize),
    #[error("provider returned a hit for decision {0} while consultation was disabled")]
    HitWhileConsultDisabled(usize),
    #[error("provider returned an invalid token for decision {0}")]
    InvalidToken(usize),
    #[error("provider returned an invalid bypass reason for decision {0}")]
    InvalidBypassReason(usize),
}

#[derive(Clone, Debug)]
struct ProviderCommand {
    command: ScriptCommand,
    workspace_root: Utf8PathBuf,
    profile_name: String,
    run_id: quick_junit::ReportUuid,
    version_env_vars: VersionEnvVars,
    test_threads: usize,
    capture_strategy: &'static str,
}

impl ProviderCommand {
    fn new(
        wrapper: &WrapperScriptConfig,
        test_list: &TestList<'_>,
        profile_name: &str,
        run_id: quick_junit::ReportUuid,
        version_env_vars: &VersionEnvVars,
        test_threads: usize,
        capture_strategy: &'static str,
    ) -> Self {
        let mut command = wrapper.command.clone();
        command.program = command.program(
            test_list.workspace_root(),
            &test_list.rust_build_meta().target_directory,
        );
        Self {
            command,
            workspace_root: test_list.workspace_root().to_owned(),
            profile_name: profile_name.to_owned(),
            run_id,
            version_env_vars: version_env_vars.clone(),
            test_threads,
            capture_strategy,
        }
    }

    fn request<T: Serialize, R: DeserializeOwned>(
        &self,
        operation: &'static str,
        request: &T,
    ) -> Result<R, ProviderProcessError> {
        serde_json::from_slice(&self.execute(operation, request)?)
            .map_err(ProviderProcessError::DeserializeResponse)
    }

    fn execute<T: Serialize>(
        &self,
        operation: &'static str,
        request: &T,
    ) -> Result<Vec<u8>, ProviderProcessError> {
        let request =
            serde_json::to_vec(request).map_err(ProviderProcessError::SerializeRequest)?;
        let mut process = Command::new(&self.command.program);
        self.command.env.apply_env(&mut process);
        self.version_env_vars.apply_env(&mut process);
        process
            .env("NEXTEST_TEST_THREADS", self.test_threads.to_string())
            .env(CACHE_CAPTURE_STRATEGY_ENV, self.capture_strategy)
            .args(&self.command.args)
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

        let mut child = process.spawn().map_err(ProviderProcessError::Spawn)?;
        let mut stdin = child.stdin.take().expect("stdin was configured as piped");
        let writer = thread::spawn(move || stdin.write_all(&request));
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
        Ok(output.stdout)
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
    use crate::config::scripts::{ScriptCommandEnvMap, ScriptCommandRelativeTo};
    use semver::Version;

    const IPC_CHILD_ENV: &str = "CACHE_IPC_CHILD_TEST";
    const TOKEN: &str = "opaque-token";

    #[test]
    fn provider_ipc_child() {
        if std::env::var_os(IPC_CHILD_ENV).is_none() {
            return;
        }
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(10));
            std::process::exit(1);
        });
        io::stdout().write_all(&vec![b'x'; 256 * 1024]).unwrap();
        io::stdout().flush().unwrap();
        io::copy(&mut io::stdin().lock(), &mut io::sink()).unwrap();
    }

    #[test]
    fn provider_output_is_drained_while_writing_request() {
        let command = ScriptCommand {
            program: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            args: vec![
                "--exact".to_owned(),
                "runner::cache::tests::provider_ipc_child".to_owned(),
                "--nocapture".to_owned(),
            ],
            env: ScriptCommandEnvMap::new(BTreeMap::from([(
                IPC_CHILD_ENV.to_owned(),
                "1".to_owned(),
            )]))
            .unwrap(),
            relative_to: ScriptCommandRelativeTo::None,
        };
        let provider = ProviderCommand {
            command,
            workspace_root: Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap(),
            profile_name: "default".to_owned(),
            run_id: quick_junit::ReportUuid::new_v4(),
            version_env_vars: VersionEnvVars {
                current_version: Version::new(0, 1, 0),
                required_version: None,
                recommended_version: None,
            },
            test_threads: 1,
            capture_strategy: "split",
        };

        let output = provider
            .execute(CACHE_OPERATION_PREPARE, &"x".repeat(1024 * 1024))
            .unwrap();
        assert!(output.iter().filter(|byte| **byte == b'x').count() >= 256 * 1024);
    }

    #[test]
    fn only_a_single_ordinary_pass_is_stored() {
        assert_eq!(
            cache_action(1, &ExecutionResultDescription::Pass),
            CommitAction::Store
        );
        assert_eq!(
            cache_action(2, &ExecutionResultDescription::Pass),
            CommitAction::Invalidate
        );
        assert_eq!(
            cache_action(
                1,
                &ExecutionResultDescription::Leak {
                    result: LeakTimeoutResult::Pass,
                },
            ),
            CommitAction::Invalidate
        );
        assert_eq!(
            cache_action(
                1,
                &ExecutionResultDescription::Timeout {
                    result: SlowTimeoutResult::Pass,
                },
            ),
            CommitAction::Invalidate
        );
    }

    fn response(decisions: Vec<PrepareDecision>) -> PrepareResponse {
        PrepareResponse { decisions }
    }

    #[test]
    fn prepare_response_accepts_valid_decisions() {
        let decisions = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Hit,
            ]),
            2,
            true,
        )
        .unwrap();
        assert!(matches!(decisions[0], PrepareDecision::Miss { .. }));
        assert!(matches!(decisions[1], PrepareDecision::Hit));
    }

    #[test]
    fn prepare_response_rejects_count_and_disabled_hit() {
        let count =
            validate_prepare_response(response(vec![PrepareDecision::Hit]), 2, true).unwrap_err();
        assert!(matches!(
            count,
            InvalidPrepareResponse::WrongDecisionCount { .. }
        ));

        let hit =
            validate_prepare_response(response(vec![PrepareDecision::Hit]), 1, false).unwrap_err();
        assert!(matches!(
            hit,
            InvalidPrepareResponse::HitWhileConsultDisabled(0)
        ));
    }

    #[test]
    fn prepare_response_rejects_invalid_provider_data() {
        let invalid_token = validate_prepare_response(
            response(vec![PrepareDecision::Miss {
                token: String::new(),
            }]),
            1,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            invalid_token,
            InvalidPrepareResponse::InvalidToken(0)
        ));

        let duplicate_token = validate_prepare_response(
            response(vec![
                PrepareDecision::Miss {
                    token: TOKEN.to_owned(),
                },
                PrepareDecision::Miss {
                    token: TOKEN.to_owned(),
                },
            ]),
            2,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            duplicate_token,
            InvalidPrepareResponse::DuplicateToken(1)
        ));

        let reason = validate_prepare_response(
            response(vec![PrepareDecision::Bypass {
                reason: String::new(),
            }]),
            1,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            reason,
            InvalidPrepareResponse::InvalidBypassReason(0)
        ));
    }

    #[test]
    fn command_environment_is_order_independent() {
        let mut first = Command::new("test");
        first.env("SECOND", "two").env("FIRST", "one");
        let mut second = Command::new("test");
        second.env("FIRST", "one").env("SECOND", "two");
        let convert = |command: &Command| {
            let mut environment = command
                .get_envs()
                .map(|(name, value)| EnvironmentVariable {
                    name: platform_string(name),
                    value: value.map(platform_string),
                })
                .collect::<Vec<_>>();
            environment.sort_unstable();
            environment
        };
        assert_eq!(convert(&first), convert(&second));
    }

    #[test]
    fn no_capture_is_not_cacheable() {
        assert_eq!(capture_strategy_name(CaptureStrategy::None), None);
        assert_eq!(capture_strategy_name(CaptureStrategy::Split), Some("split"));
        assert_eq!(
            capture_strategy_name(CaptureStrategy::Combined),
            Some("combined")
        );
    }
}
