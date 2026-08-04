// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Notes reported by run wrapper scripts.

use crate::{errors::ChildStartError, reporter::events::RunWrapperReport};
use camino_tempfile::Utf8TempPath;
use std::{
    fs::{self, File},
    io::{self, Read},
    sync::Arc,
};
use thiserror::Error;
use tracing::warn;

pub(super) const RUN_WRAPPER_REPORT_ENV: &str = "NEXTEST_RUN_WRAPPER_REPORT";

const MAX_REPORT_SIZE: u64 = 1024;
const MAX_LABEL_LEN: usize = 32;

#[derive(Debug, Error)]
enum RunWrapperReportError {
    #[error("failed to open the report: {0}")]
    Open(#[source] io::Error),
    #[error("failed to read the report: {0}")]
    Read(#[source] io::Error),
    #[error("the report exceeds {MAX_REPORT_SIZE} bytes")]
    TooLarge,
    #[error("failed to parse the report: {0}")]
    Parse(#[source] serde_json::Error),
    #[error(
        "the label must contain 1 to {MAX_LABEL_LEN} ASCII letters, digits, spaces, `_`, `-`, `:`, or `/`, and must start and end with a letter or digit"
    )]
    InvalidLabel,
}

pub(super) fn new_report_path() -> Result<Utf8TempPath, ChildStartError> {
    let path = camino_tempfile::Builder::new()
        .prefix("nextest-run-wrapper-report")
        .tempfile()
        .map_err(|error| ChildStartError::TempPath(Arc::new(error)))?
        .into_temp_path();

    // The absence of a file means that the wrapper ran the test normally.
    fs::remove_file(&path).map_err(|error| ChildStartError::TempPath(Arc::new(error)))?;
    Ok(path)
}

pub(super) fn read_report(path: Option<&Utf8TempPath>) -> Option<RunWrapperReport> {
    let path = path?;

    match try_read_report(path) {
        Ok(report) => report,
        Err(error) => {
            warn!(%error, path = path.as_str(), "failed to read run wrapper report");
            None
        }
    }
}

fn try_read_report(path: &Utf8TempPath) -> Result<Option<RunWrapperReport>, RunWrapperReportError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RunWrapperReportError::Open(error)),
    };

    let mut contents = Vec::new();
    file.take(MAX_REPORT_SIZE + 1)
        .read_to_end(&mut contents)
        .map_err(RunWrapperReportError::Read)?;
    if contents.len() as u64 > MAX_REPORT_SIZE {
        return Err(RunWrapperReportError::TooLarge);
    }

    let report: RunWrapperReport =
        serde_json::from_slice(&contents).map_err(RunWrapperReportError::Parse)?;
    if !valid_label(&report.label) {
        return Err(RunWrapperReportError::InvalidLabel);
    }

    Ok(Some(report))
}

fn valid_label(label: &str) -> bool {
    label
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && label.len() <= MAX_LABEL_LEN
        && label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b':' | b'/')
        })
        && label
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn report_path(contents: &[u8]) -> Utf8TempPath {
        let mut file = camino_tempfile::NamedUtf8TempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file.into_temp_path()
    }

    #[test]
    fn valid_report_is_loaded() {
        let path = report_path(br#"{"label":"not cached: I/O effects"}"#);
        let report = read_report(Some(&path)).unwrap();
        assert_eq!(report.label, "not cached: I/O effects");
    }

    #[test]
    fn absent_report_is_not_an_error() {
        let path = new_report_path().unwrap();
        assert_eq!(read_report(Some(&path)), None);
    }

    #[test]
    fn invalid_reports_are_ignored() {
        for contents in [
            br#"not json"#.as_slice(),
            br#"{"label":""}"#,
            br#"{"label":" leading space"}"#,
            br#"{"label":"trailing space "}"#,
            br#"{"label":"bad(label)"}"#,
            br#"{"label":"bad\nlabel"}"#,
        ] {
            let path = report_path(contents);
            assert_eq!(read_report(Some(&path)), None);
        }
    }

    #[test]
    fn oversized_reports_are_ignored() {
        let path = report_path(&vec![b'x'; MAX_REPORT_SIZE as usize + 1]);
        assert_eq!(read_report(Some(&path)), None);
    }
}
