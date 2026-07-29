// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

const MARKER_ENV: &str = "CACHE_FIXTURE_MARKER";
const EXIT_ENV: &str = "CACHE_FIXTURE_EXIT";
const REQUIRED_ENV: &str = "CACHE_FIXTURE_REQUIRED";
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
        .command("run-1", "fixture_child")
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
}

impl Fixture {
    fn new() -> Self {
        let temp = camino_tempfile::tempdir().unwrap();
        let source = env::current_exe().unwrap();
        let artifact = temp.path().as_std_path().join(source.file_name().unwrap());
        fs::copy(source, &artifact).unwrap();
        Self {
            cache: temp.path().join("cache").into(),
            marker: temp.path().join("marker").into(),
            trace: temp.path().join("trace").into(),
            artifact,
            temp,
        }
    }

    fn command(&self, run_id: &str, test_name: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nextest-cache"));
        command
            .arg("--env")
            .arg(MARKER_ENV)
            .arg("--env")
            .arg(REQUIRED_ENV)
            .arg("--env")
            .arg(EXIT_ENV);
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
