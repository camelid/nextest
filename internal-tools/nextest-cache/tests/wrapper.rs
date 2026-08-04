// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

const MARKER_ENV: &str = "CACHE_FIXTURE_MARKER";
const EXIT_ENV: &str = "CACHE_FIXTURE_EXIT";
const INPUT_ENV: &str = "CACHE_FIXTURE_INPUT";
const REQUIRED_ENV: &str = "CACHE_FIXTURE_REQUIRED";
const TRACE_LINE_ENV: &str = "CACHE_FIXTURE_TRACE_LINE";
const UNSELECTED_ENV: &str = "CACHE_FIXTURE_UNSELECTED";
const WRAPPER_REPORT_ENV: &str = "NEXTEST_RUN_WRAPPER_REPORT";
#[cfg(unix)]
const SIGNAL_ENV: &str = "CACHE_FIXTURE_SIGNAL";

#[test]
fn fixture_child() {
    run_fixture_child();
}

#[test]
fn fixture_child_two() {
    run_fixture_child();
}

fn run_fixture_child() {
    let Some(marker) = env::var_os(MARKER_ENV) else {
        return;
    };
    if env::var_os("PATH").is_none()
        || env::var_os(REQUIRED_ENV).is_none()
        || env::var_os(UNSELECTED_ENV).is_some()
    {
        std::process::exit(90);
    }
    let mut contents = fs::read(&marker).unwrap_or_default();
    contents.extend_from_slice(b"executed\n");
    fs::write(marker, contents).unwrap();
    if let Some(input) = env::var_os(INPUT_ENV) {
        fs::read(input).unwrap();
    }

    #[cfg(unix)]
    if env::var_os(SIGNAL_ENV).is_some() {
        unsafe {
            libc::raise(libc::SIGTERM);
        }
    }
    if let Ok(code) = env::var(EXIT_ENV) {
        std::process::exit(code.parse().unwrap());
    }
}

#[test]
fn successful_execution_is_cached() {
    let fixture = Fixture::new();
    let first = fixture.run("run-1", "fixture_child");
    assert!(first.success());
    let second = fixture.run("run-1", "fixture_child");
    assert!(second.success());
    assert_eq!(fixture.executions(), 1);
}

#[test]
fn cache_hits_write_a_wrapper_report() {
    let fixture = Fixture::new();
    let report = fixture.temp.path().join("wrapper-report.json");

    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env(WRAPPER_REPORT_ENV, &report)
            .status()
            .unwrap()
            .success()
    );
    assert!(!report.exists());

    assert!(
        fixture
            .command("run-2", "fixture_child")
            .env(WRAPPER_REPORT_ENV, &report)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read_to_string(report).unwrap(), r#"{"label":"cached"}"#,);
}

#[test]
fn selected_environment_is_passed_and_affects_the_key() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env(REQUIRED_ENV, "one")
            .status()
            .unwrap()
            .success()
    );
    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env(REQUIRED_ENV, "two")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);

    assert!(
        fixture
            .command("run-2", "fixture_child")
            .env(REQUIRED_ENV, "two")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);
}

#[test]
fn unselected_environment_is_cleared_and_does_not_affect_the_key() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env(UNSELECTED_ENV, "one")
            .status()
            .unwrap()
            .success()
    );
    assert!(
        fixture
            .command("run-2", "fixture_child")
            .env(UNSELECTED_ENV, "two")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 1);
}

#[test]
fn artifact_is_hashed_once_per_run_and_entries_persist_across_runs() {
    let fixture = Fixture::new();
    assert!(fixture.run("run-1", "fixture_child").success());
    assert!(fixture.run("run-1", "fixture_child_two").success());
    assert_eq!(fixture.executions(), 2);
    assert_eq!(fixture.hash_events(), 1);

    assert!(fixture.run("run-2", "fixture_child").success());
    assert!(fixture.run("run-2", "fixture_child_two").success());
    assert_eq!(fixture.executions(), 2);
    assert_eq!(fixture.hash_events(), 2);
}

#[test]
fn an_artifact_change_invalidates_the_run_memo_and_entry() {
    let fixture = Fixture::new();
    assert!(fixture.run("run-1", "fixture_child").success());
    assert_eq!(fixture.executions(), 1);
    assert_eq!(fixture.hash_events(), 1);

    let mut bytes = fs::read(&fixture.artifact).unwrap();
    bytes.push(0);
    fs::write(&fixture.artifact, bytes).unwrap();
    assert!(fixture.run("run-1", "fixture_child").success());
    assert_eq!(fixture.executions(), 2);
    assert_eq!(fixture.hash_events(), 2);
}

#[test]
fn a_failing_child_is_not_cached_and_its_status_is_preserved() {
    let fixture = Fixture::new();
    let first = fixture
        .command("run-1", "fixture_child")
        .env(EXIT_ENV, "23")
        .status()
        .unwrap();
    assert_eq!(first.code(), Some(23));
    let second = fixture
        .command("run-1", "fixture_child")
        .env(EXIT_ENV, "23")
        .status()
        .unwrap();
    assert_eq!(second.code(), Some(23));
    assert_eq!(fixture.executions(), 2);
}

#[test]
fn retry_and_stress_attempts_bypass_caching() {
    let fixture = Fixture::new();
    assert!(fixture.run("run-1", "fixture_child").success());
    assert_eq!(fixture.executions(), 1);

    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env("NEXTEST_ATTEMPT", "2")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);

    assert!(fixture.run("run-2", "fixture_child").success());
    assert_eq!(fixture.executions(), 3);
    assert!(
        fixture
            .command("run-3", "fixture_child")
            .env("NEXTEST_STRESS_CURRENT", "1")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 4);
}

#[test]
fn explicit_disable_bypasses_caching() {
    let fixture = Fixture::new();
    assert!(fixture.run("run-1", "fixture_child").success());
    assert_eq!(fixture.executions(), 1);

    assert!(
        fixture
            .command("run-2", "fixture_child")
            .env("NEXTEST_CACHE_DISABLE", "1")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);

    assert!(fixture.run("run-3", "fixture_child").success());
    assert_eq!(fixture.executions(), 2);
}

#[test]
fn unavailable_effect_tracing_executes_without_caching() {
    let fixture = Fixture::new();
    let report = fixture.temp.path().join("unavailable-report.json");
    for (index, run_id) in ["run-1", "run-2"].into_iter().enumerate() {
        let mut command =
            fixture.command_with_policy(run_id, "fixture_child", Some("conservative"));
        command.env("PATH", fixture.temp.path());
        if index == 0 {
            command.env(WRAPPER_REPORT_ENV, &report);
        }
        assert!(command.status().unwrap().success());
    }
    assert_eq!(fixture.executions(), 2);
    assert_eq!(
        fs::read_to_string(report).unwrap(),
        r#"{"label":"cache-io-unavailable"}"#,
    );
}

#[cfg(unix)]
#[test]
fn conservative_effect_tracking_rejects_external_reads() {
    let fixture = Fixture::new();
    let input = fixture.temp.path().join("input");
    fs::write(&input, b"input").unwrap();
    let trace_line = format!("openat(AT_FDCWD, {input:?}, O_RDONLY) = 3<{input}>");

    for run_id in ["run-1", "run-2"] {
        assert!(
            fixture
                .traced_command(run_id, "fixture_child", "conservative", &trace_line)
                .env(INPUT_ENV, &input)
                .status()
                .unwrap()
                .success()
        );
    }
    assert_eq!(fixture.executions(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn content_addressed_effect_tracking_validates_external_reads() {
    let fixture = Fixture::new();
    let input = fixture.temp.path().join("input");
    fs::write(&input, b"first").unwrap();
    let trace_line = format!("openat(AT_FDCWD, {input:?}, O_RDONLY) = 3<{input}>");

    for run_id in ["run-1", "run-2"] {
        assert!(
            fixture
                .traced_command(run_id, "fixture_child", "content-addressed", &trace_line)
                .env(INPUT_ENV, &input)
                .status()
                .unwrap()
                .success()
        );
    }
    assert_eq!(fixture.executions(), 1);

    fs::write(&input, b"second").unwrap();
    assert!(
        fixture
            .traced_command("run-3", "fixture_child", "content-addressed", &trace_line)
            .env(INPUT_ENV, &input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);
    assert!(
        fixture
            .traced_command("run-4", "fixture_child", "content-addressed", &trace_line)
            .env(INPUT_ENV, &input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);

    let mode = fs::metadata(&input).unwrap().permissions().mode();
    fs::set_permissions(&input, fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
    assert!(
        fixture
            .traced_command("run-5", "fixture_child", "content-addressed", &trace_line)
            .env(INPUT_ENV, &input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 3);
    assert!(
        fixture
            .traced_command("run-6", "fixture_child", "content-addressed", &trace_line)
            .env(INPUT_ENV, &input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 3);
}

#[cfg(unix)]
#[test]
fn effect_tracking_rejects_existing_file_writes() {
    let fixture = Fixture::new();
    let output = fixture.temp.path().join("output");
    fs::write(&output, b"output").unwrap();
    let trace_line = format!("openat(AT_FDCWD, {output:?}, O_WRONLY) = 3<{output}>");

    assert!(
        fixture
            .traced_command("run-1", "fixture_child", "content-addressed", &trace_line)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        fixture
            .traced_command("run-2", "fixture_child", "content-addressed", &trace_line)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);
}

#[test]
fn cache_infrastructure_failures_execute_the_child() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .command("run-1", "fixture_child")
            .env_remove("NEXTEST_RUN_ID")
            .status()
            .unwrap()
            .success()
    );

    let unusable_cache = fixture.temp.path().join("not-a-directory");
    fs::write(&unusable_cache, b"file").unwrap();
    assert!(
        fixture
            .command("run-2", "fixture_child")
            .env("NEXTEST_CACHE_DIR", &unusable_cache)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fixture.executions(), 2);
}

#[test]
fn corrupt_run_memos_are_replaced() {
    let fixture = Fixture::new();
    assert!(fixture.run("run-1", "fixture_child").success());
    let memo = find_json_file(&fixture.cache.join("storage/run-hashes"));
    fs::write(memo, b"not json").unwrap();

    assert!(fixture.run("run-1", "fixture_child").success());
    assert_eq!(fixture.executions(), 1);
    assert_eq!(fixture.hash_events(), 2);
}

#[test]
fn leading_separator_is_optional_and_missing_child_is_an_error() {
    let fixture = Fixture::new();
    let mut without_separator = Command::new(env!("CARGO_BIN_EXE_nextest-cache"));
    without_separator
        .arg(&fixture.artifact)
        .arg("--exact")
        .arg("fixture_child")
        .arg("--nocapture");
    assert!(without_separator.status().unwrap().success());

    assert!(
        !Command::new(env!("CARGO_BIN_EXE_nextest-cache"))
            .status()
            .unwrap()
            .success()
    );
}

#[cfg(unix)]
#[test]
fn signal_termination_is_mirrored() {
    use std::os::unix::process::ExitStatusExt;

    let fixture = Fixture::new();
    let status = fixture
        .command_with_policy("run-1", "fixture_child", Some("off"))
        .env(SIGNAL_ENV, "1")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}

struct Fixture {
    temp: camino_tempfile::Utf8TempDir,
    artifact: PathBuf,
    cache: PathBuf,
    marker: PathBuf,
    trace: PathBuf,
    #[cfg(unix)]
    fake_bin: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = camino_tempfile::tempdir().unwrap();
        let source = env::current_exe().unwrap();
        let artifact = temp.path().as_std_path().join(source.file_name().unwrap());
        fs::copy(source, &artifact).unwrap();
        #[cfg(unix)]
        let fake_bin = install_fake_strace(temp.path().as_std_path());
        Self {
            cache: temp.path().join("cache").into(),
            marker: temp.path().join("marker").into(),
            trace: temp.path().join("trace").into(),
            artifact,
            #[cfg(unix)]
            fake_bin,
            temp,
        }
    }

    fn command(&self, run_id: &str, test_name: &str) -> Command {
        self.command_with_policy(run_id, test_name, None)
    }

    fn command_with_policy(&self, run_id: &str, test_name: &str, policy: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nextest-cache"));
        if let Some(policy) = policy {
            command.arg("--io-policy").arg(policy);
        }
        command
            .arg("--env")
            .arg(MARKER_ENV)
            .arg("--env")
            .arg(REQUIRED_ENV)
            .arg("--env")
            .arg(EXIT_ENV);
        command
            .arg("--env")
            .arg(INPUT_ENV)
            .arg("--env")
            .arg(TRACE_LINE_ENV);
        #[cfg(unix)]
        command.arg("--env").arg(SIGNAL_ENV);
        command
            .arg("--")
            .arg(&self.artifact)
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env("NEXTEST_RUN_ID", run_id)
            .env("NEXTEST_ATTEMPT", "1")
            .env("NEXTEST_STRESS_CURRENT", "none")
            .env("NEXTEST_CACHE_DIR", &self.cache)
            .env("NEXTEST_CACHE_TRACE", &self.trace)
            .env(MARKER_ENV, &self.marker)
            .env(REQUIRED_ENV, "present")
            .env("NEXTEST_TOTAL_ATTEMPTS", "1");
        #[cfg(target_os = "linux")]
        command.env("PATH", &self.fake_bin);
        command
    }

    #[cfg(unix)]
    fn traced_command(
        &self,
        run_id: &str,
        test_name: &str,
        policy: &str,
        trace_line: &str,
    ) -> Command {
        let mut command = self.command_with_policy(run_id, test_name, Some(policy));
        command
            .env("PATH", &self.fake_bin)
            .env(TRACE_LINE_ENV, trace_line);
        command
    }

    fn run(&self, run_id: &str, test_name: &str) -> ExitStatus {
        self.command(run_id, test_name).status().unwrap()
    }

    fn executions(&self) -> usize {
        fs::read_to_string(&self.marker)
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn hash_events(&self) -> usize {
        fs::read_to_string(&self.trace)
            .unwrap_or_default()
            .lines()
            .count()
    }
}

#[cfg(unix)]
fn install_fake_strace(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let strace = bin.join("strace");
    fs::write(
        &strace,
        br#"#!/bin/sh
trace=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            trace=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            shift
            ;;
    esac
done
"$@"
status=$?
printf '%s\n' 'execve(0x1, 0x2, 0x3) = 0' > "$trace.$$"
if [ -n "$CACHE_FIXTURE_TRACE_LINE" ]; then
    printf '%s\n' "$CACHE_FIXTURE_TRACE_LINE" >> "$trace.$$"
fi
exit "$status"
"#,
    )
    .unwrap();
    fs::set_permissions(&strace, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn find_json_file(root: &Path) -> PathBuf {
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                return entry.path();
            }
        }
    }
    panic!("no JSON file found under {}", root.display());
}
