//! Cooperative Python trial diagnostics, separate from functional failures.
//! This validates the adapter's report; it is not independent test attestation.

use crate::{sha256_str, FailureSignature, RawExecutionResult, TestAttemptRecord};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const COVERAGE_FAILURE_KIND: &str = "PythonTrialCoverageIncompleteV1";
const PREFIX: &str = "TOMORROWCI_TRIAL_SUMMARY=";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialSummary {
    schema_version: u32,
    framework: String,
    exit_code: i32,
    framework_exit_code: i32,
    coverage_valid: bool,
    gate_errors: Vec<String>,
    collected: u64,
    tests_run: u64,
    failed: u64,
    errors: u64,
    skipped: u64,
    expected_failures: u64,
    unexpected_successes: u64,
    collection_errors: u64,
    #[serde(default)]
    doctest_skip_directives: u64,
    test_ids_sha256: String,
    executed_test_ids_sha256: String,
    source_origins: BTreeMap<String, String>,
    observed_source_origins: Option<BTreeMap<String, String>>,
    session_finished: Option<bool>,
}

pub fn python_coverage_failure(raw: &RawExecutionResult) -> Option<FailureSignature> {
    if raw.exit_code != Some(6) || raw.timed_out || raw.signal.is_some() {
        return None;
    }
    let mut records = raw
        .stdout
        .lines()
        .chain(raw.stderr.lines())
        .filter_map(|line| line.strip_prefix(PREFIX));
    let record = records.next()?;
    if records.next().is_some() {
        return None;
    }
    // A typed struct rejects duplicate fields, wrong scalar types and unknown
    // versions/fields instead of interpreting arbitrary exit-code-6 output.
    let summary: TrialSummary = serde_json::from_str(record).ok()?;
    let hash_valid = |hash: &str| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if summary.schema_version != 1
        || !matches!(summary.framework.as_str(), "unittest" | "pytest")
        || summary.exit_code != 6
        || summary.framework_exit_code != 0
        || summary.coverage_valid
        || summary.gate_errors.is_empty()
        || summary
            .gate_errors
            .iter()
            .any(|error| error.trim().is_empty())
        || summary.failed != 0
        || summary.errors != 0
        || summary.collection_errors != 0
        || summary.unexpected_successes != 0
        || summary.tests_run > summary.collected
        || summary.expected_failures > summary.collected
        || (summary.framework == "unittest" && summary.skipped > summary.collected)
        || !hash_valid(&summary.test_ids_sha256)
        || !hash_valid(&summary.executed_test_ids_sha256)
        || summary.source_origins.is_empty()
        || summary
            .source_origins
            .iter()
            .any(|(name, path)| name.is_empty() || path.is_empty())
        || (summary.framework == "pytest" && summary.session_finished.is_none())
    {
        return None;
    }
    // Require a concrete gap as well as the adapter's error description.
    let has_gap = summary.collected == 0
        || summary.tests_run != summary.collected
        || summary.skipped > 0
        || summary.expected_failures > 0
        || summary.doctest_skip_directives > 0
        || summary.session_finished == Some(false)
        || summary.observed_source_origins.as_ref() != Some(&summary.source_origins);
    if !has_gap {
        return None;
    }
    let mut reasons = summary.gate_errors;
    reasons.sort();
    reasons.dedup();
    let detail = reasons.join("; ");
    Some(FailureSignature {
        kind: COVERAGE_FAILURE_KIND.into(),
        summary: format!("Test coverage incomplete: {detail}")
            .chars()
            .take(500)
            .collect(),
        normalized_hash: sha256_str(&format!(
            "python-trial-coverage-v1\n{}\n{detail}",
            summary.framework
        )),
        primary_frame: None,
    })
}

pub fn is_coverage_attempt(attempt: &TestAttemptRecord) -> bool {
    attempt.exit_code == Some(6)
        && !attempt.timed_out
        && attempt
            .failure
            .as_ref()
            .is_some_and(|failure| failure.kind == COVERAGE_FAILURE_KIND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn summary() -> Value {
        json!({"schema_version":1,"framework":"unittest","exit_code":6,
            "framework_exit_code":0,"coverage_valid":false,"gate_errors":["skipped=1"],
            "collected":2,"tests_run":2,"failed":0,"errors":0,"skipped":1,
            "expected_failures":0,"unexpected_successes":0,"collection_errors":0,
            "test_ids_sha256":"a".repeat(64),"executed_test_ids_sha256":"a".repeat(64),
            "source_origins":{"pkg":"pkg/__init__.py"},
            "observed_source_origins":{"pkg":"pkg/__init__.py"}})
    }
    fn raw(value: &Value) -> RawExecutionResult {
        RawExecutionResult {
            workspace_preparation: None,
            exit_code: Some(6),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: format!("{PREFIX}{value}\n"),
            stderr: String::new(),
            network_used: false,
        }
    }

    #[test]
    fn accepts_only_successful_framework_with_concrete_coverage_gap() {
        assert!(python_coverage_failure(&raw(&summary())).is_some());
        for (key, value) in [
            ("framework_exit_code", json!(1)),
            ("failed", json!(1)),
            ("errors", json!(1)),
            ("schema_version", json!(2)),
            ("coverage_valid", json!(true)),
            ("gate_errors", json!([])),
            ("collected", json!("2")),
            ("skipped", json!(-1)),
            ("skipped", json!(0)),
            ("test_ids_sha256", json!("bad")),
        ] {
            let mut input = summary();
            input[key] = value;
            assert!(python_coverage_failure(&raw(&input)).is_none(), "{key}");
        }
        let mut pytest = summary();
        pytest["framework"] = json!("pytest");
        pytest["session_finished"] = json!(true);
        assert!(python_coverage_failure(&raw(&pytest)).is_some());
    }

    #[test]
    fn rejects_exit_only_duplicates_malformed_and_timeout() {
        let original = raw(&summary());
        let mut input = original.clone();
        input.stderr = input.stdout.clone();
        assert!(python_coverage_failure(&input).is_none());
        input = original.clone();
        input.stdout = input.stdout.replacen('{', "{\"exit_code\":6,", 1);
        assert!(python_coverage_failure(&input).is_none());
        input.stdout = format!("{PREFIX}not-json");
        assert!(python_coverage_failure(&input).is_none());
        input.stdout.clear();
        assert!(python_coverage_failure(&input).is_none());
        input = original.clone();
        input.timed_out = true;
        assert!(python_coverage_failure(&input).is_none());
        input = original;
        input.exit_code = Some(1);
        assert!(python_coverage_failure(&input).is_none());
    }
}
