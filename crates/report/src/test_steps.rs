//! Display-only observations from the optional Python multi-step driver.
//! Counts are framework-reported, never inputs to verdicts or coverage gates.

use serde::Deserialize;
use std::io::Read;
use std::path::Path;
use tomorrowci_core::{RunManifest, Verdict};

const PREFIX: &str = "TOMORROWCI_STEPS_SUMMARY=";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepPlan {
    schema_version: u32,
    steps: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StepCounts {
    passed: u64,
    failed: u64,
    errors: u64,
    skipped: u64,
    xfailed: u64,
    xpassed: u64,
    deselected: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StepObservation {
    index: usize,
    argv: Vec<String>,
    status: String,
    exit_code: Option<i32>,
    duration_ms: u64,
    counts: Option<StepCounts>,
    counts_source: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepsObservation {
    schema_version: u32,
    python_version: String,
    steps: Vec<StepObservation>,
    exit_code: i32,
}

fn bounded_text(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_RECORD_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_RECORD_BYTES).then_some(text)
}

fn parse_observation(
    plan: &str,
    stdout: &str,
    stderr: &str,
    expected_exit: Option<i32>,
    timed_out: bool,
) -> Option<StepsObservation> {
    if timed_out || expected_exit.is_none() {
        return None;
    }
    let plan: StepPlan = serde_json::from_str(plan).ok()?;
    if plan.schema_version != 1 || plan.steps.is_empty() || plan.steps.len() > 100 {
        return None;
    }
    let mut records = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| line.strip_prefix(PREFIX));
    let observation: StepsObservation = serde_json::from_str(records.next()?).ok()?;
    if records.next().is_some()
        || observation.schema_version != 1
        || Some(observation.exit_code) != expected_exit
        || observation.steps.len() != plan.steps.len()
        || observation.python_version.is_empty()
        || observation.python_version.len() > 40
        || !observation
            .python_version
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
    {
        return None;
    }
    let mut first_failure = None;
    for (index, (step, argv)) in observation.steps.iter().zip(&plan.steps).enumerate() {
        if step.index != index + 1 || step.argv != *argv || argv.is_empty() {
            return None;
        }
        if first_failure.is_some() {
            if step.status != "not_run" || step.exit_code.is_some() || step.duration_ms != 0 {
                return None;
            }
        } else {
            let exit = step.exit_code?;
            if !matches!(step.status.as_str(), "completed" | "start_error")
                || (step.status == "start_error" && exit == 0)
            {
                return None;
            }
            if exit != 0 {
                first_failure = Some(if exit < 0 {
                    128_i32.checked_sub(exit)?
                } else {
                    exit
                });
            }
        }
        match (&step.counts, step.counts_source.as_deref()) {
            (Some(_), Some("pytest-terminal-summary")) if step.status == "completed" => {
                let pytest = argv[0] == "pytest"
                    || (matches!(argv[0].as_str(), "python" | "python3")
                        && argv.get(1).is_some_and(|arg| arg == "-m")
                        && argv.get(2).is_some_and(|arg| arg == "pytest"));
                if !pytest {
                    return None;
                }
            }
            (None, None) => {}
            _ => return None,
        }
    }
    (observation.exit_code == first_failure.unwrap_or(0)).then_some(observation)
}

/// `run_root` must be the caller's actual evidence directory, not a saved
/// absolute path from a relocated manifest. The caller verifies evidence first.
pub fn read_step_observation(
    run_root: &Path,
    log_dir: &Path,
    expected_exit: Option<i32>,
    timed_out: bool,
) -> Option<StepsObservation> {
    // Existing legacy and custom-command runs have no step plan; report unknown.
    let plan = bounded_text(&run_root.join("workspace/.tomorrowci-steps.json"))?;
    let stdout = bounded_text(&log_dir.join("stdout.log"))?;
    let stderr = bounded_text(&log_dir.join("stderr.log"))?;
    parse_observation(&plan, &stdout, &stderr, expected_exit, timed_out)
}

pub fn render_step_observation(observation: Option<&StepsObservation>) -> String {
    let Some(observation) = observation else {
        return "  Test steps/counts: UNKNOWN (no complete, consistent step record; inspect logs).\n".into();
    };
    let mut out = format!(
        "  Python {}; {} ordered test steps:\n",
        observation.python_version,
        observation.steps.len()
    );
    for step in &observation.steps {
        let command = serde_json::to_string(&step.argv).unwrap_or_default();
        let status = match step.status.as_str() {
            "not_run" => "NOT_RUN",
            "start_error" => "START_ERROR",
            _ if step.exit_code == Some(0) => "COMPLETED",
            _ => "FAILED",
        };
        let exit = step
            .exit_code
            .map_or_else(|| "not executed".into(), |value| value.to_string());
        out.push_str(&format!(
            "    {}. {status} exit={exit} step_ms={} command={command}\n",
            step.index, step.duration_ms
        ));
        if let Some(counts) = &step.counts {
            out.push_str(&format!(
                "       Framework-reported: {} passed, {} failed, {} errors, {} skipped, {} xfailed, {} xpassed, {} deselected.\n",
                counts.passed, counts.failed, counts.errors, counts.skipped,
                counts.xfailed, counts.xpassed, counts.deselected
            ));
        } else {
            out.push_str("       Test counts: UNKNOWN.\n");
        }
    }
    out.push_str("  Counts are per step, not unique tests across steps; reported by the framework, not independent coverage proof.\n");
    out
}

/// A display statement about original scenario verdicts, never a new verdict.
pub fn upgrade_observation(manifest: &RunManifest) -> String {
    let baselines: Vec<_> = manifest
        .plan
        .scenarios
        .iter()
        .filter(|s| s.is_baseline)
        .collect();
    let baseline_ok = baselines.len() == 1
        && manifest.results.iter().any(|r| {
            r.scenario_id == baselines[0].id
                && r.verdict == Verdict::BaselinePass
                && r.attempt > 0
                && r.exit_code == Some(0)
                && !r.timed_out
        });
    if !baseline_ok {
        return "Upgrade observation: baseline did not establish a passing test command; inspect scenario results.".into();
    }
    let candidates: Vec<_> = manifest
        .plan
        .scenarios
        .iter()
        .filter(|s| !s.is_baseline)
        .collect();
    if candidates.is_empty() {
        return "Upgrade observation: no candidate versions were tested.".into();
    }
    if candidates.iter().all(|s| {
        manifest.results.iter().any(|r| {
            r.scenario_id == s.id
                && r.verdict == Verdict::FuturePass
                && r.attempt > 0
                && r.exit_code == Some(0)
                && !r.timed_out
        })
    }) {
        return format!("Upgrade observation: baseline and all {} candidate test commands passed in the observed environments.", candidates.len());
    }
    if candidates.iter().any(|s| {
        manifest
            .results
            .iter()
            .any(|r| r.scenario_id == s.id && r.verdict == Verdict::FutureFail)
    }) {
        return "Upgrade observation: a candidate test command failure was observed; inspect all scenario results for remaining gaps.".into();
    }
    "Upgrade observation: incomplete or mixed results; inspect scenario statuses and logs.".into()
}

/// Shared CLI/HTML/job summary text. No source output can change the verdict.
pub fn render_test_steps(manifest: &RunManifest, run_root: &Path) -> String {
    let mut out = String::new();
    for result in &manifest.results {
        // Defense in depth for report callers holding a not-yet-verified manifest.
        if !result
            .scenario_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            || result.scenario_id.is_empty()
            || matches!(result.scenario_id.as_str(), "." | "..")
        {
            continue;
        }
        let relative = format!("scenarios/{}", result.scenario_id);
        let observation = read_step_observation(
            run_root,
            &run_root.join(&relative),
            result.exit_code,
            result.timed_out,
        );
        out.push_str(&format!(
            "{} ({:?}; final attempt {}):\n",
            result.scenario_id, result.verdict, result.attempt
        ));
        out.push_str(&render_step_observation(observation.as_ref()));
        out.push_str(&format!(
            "  Logs: {relative}/stdout.log | {relative}/stderr.log\n"
        ));
        out.push_str(&format!(
            "  Rerun: tomorrowci replay {} --scenario {}\n",
            manifest.run_id, result.scenario_id
        ));
    }
    out
}

/// Counts/argv/status equality is advisory; unlike replay exit/signature it is
/// never a PASS gate. Missing or partial records cannot compare as equal.
pub fn compare_step_observations(
    original: Option<&StepsObservation>,
    replay: Option<&StepsObservation>,
) -> &'static str {
    match (original, replay) {
        (Some(a), Some(b)) if a.steps.len() == b.steps.len() => {
            let known_difference = a.steps.iter().zip(&b.steps).any(|(x, y)| {
                x.argv != y.argv
                    || x.status != y.status
                    || x.exit_code != y.exit_code
                    || matches!((&x.counts, &y.counts), (Some(left), Some(right)) if left != right)
            });
            if known_difference {
                "DIFFERENT (inspect original and replay logs)"
            } else if a.steps.iter().any(|s| s.counts.is_none())
                || b.steps.iter().any(|s| s.counts.is_none())
            {
                "UNKNOWN (one or more step counts unavailable)"
            } else {
                "MATCH (commands, statuses, exits and framework-reported counts; not test IDs)"
            }
        }
        (Some(_), Some(_)) => "DIFFERENT (step sequence lengths differ)",
        _ => "UNKNOWN (complete step records unavailable)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (String, serde_json::Value) {
        let argv = json!(["python", "-m", "pytest"]);
        let plan = json!({"schema_version":1,"steps":[argv.clone(),argv.clone()]}).to_string();
        let step = json!({"index":1,"argv":argv,"status":"completed","exit_code":0,"duration_ms":12,"counts":{"passed":941,"failed":0,"errors":0,"skipped":0,"xfailed":0,"xpassed":0,"deselected":0},"counts_source":"pytest-terminal-summary"});
        let mut second = step.clone();
        second["index"] = json!(2);
        (
            plan,
            json!({"schema_version":1,"python_version":"3.14.10","steps":[step,second],"exit_code":0}),
        )
    }
    fn parse(plan: &str, value: &serde_json::Value, exit: i32) -> Option<StepsObservation> {
        parse_observation(plan, &format!("{PREFIX}{value}\n"), "", Some(exit), false)
    }
    #[test]
    fn complete_records_show_counts_without_summing_repeated_tests() {
        let (plan, value) = fixture();
        let record = parse(&plan, &value, 0).unwrap();
        let text = render_step_observation(Some(&record));
        assert_eq!(text.matches("941 passed").count(), 2);
        assert!(!text.contains("1882"));
        assert!(text.contains("not independent coverage proof"));
    }
    #[test]
    fn rejects_duplicate_forged_order_exit_and_partial_timeout_records() {
        let (plan, value) = fixture();
        let marker = format!("{PREFIX}{value}\n");
        assert!(parse_observation(&plan, &marker, &marker, Some(0), false).is_none());
        assert!(parse_observation(&plan, &marker, "", Some(0), true).is_none());
        assert!(parse_observation(&plan, &marker, "", Some(1), false).is_none());
        for key in ["argv", "index", "status", "counts"] {
            let mut bad = value.clone();
            bad["steps"][1][key] = json!("invalid");
            assert!(parse(&plan, &bad, 0).is_none(), "{key}");
        }
        let mut bad = value.clone();
        bad["steps"].as_array_mut().unwrap().pop();
        assert!(parse(&plan, &bad, 0).is_none());
    }
    #[test]
    fn failed_step_requires_remaining_not_run_and_preserves_failure() {
        let (plan, mut value) = fixture();
        let original = parse(&plan, &value, 0).unwrap();
        value["steps"][0]["exit_code"] = json!(2);
        value["exit_code"] = json!(2);
        assert!(parse(&plan, &value, 2).is_none());
        value["steps"][1]["status"] = json!("not_run");
        value["steps"][1]["exit_code"] = json!(null);
        value["steps"][1]["duration_ms"] = json!(0);
        value["steps"][1]["counts"] = json!(null);
        value["steps"][1]["counts_source"] = json!(null);
        let record = parse(&plan, &value, 2).unwrap();
        let text = render_step_observation(Some(&record));
        assert!(text.contains("FAILED"));
        assert!(text.contains("NOT_RUN"));
        assert!(compare_step_observations(Some(&original), Some(&record)).starts_with("DIFFERENT"));
    }
    #[test]
    fn unknown_counts_never_become_zero_or_a_replay_match() {
        let (plan, mut value) = fixture();
        value["steps"][0]["counts"] = json!(null);
        value["steps"][0]["counts_source"] = json!(null);
        let record = parse(&plan, &value, 0).unwrap();
        assert!(render_step_observation(Some(&record)).contains("Test counts: UNKNOWN"));
        assert!(compare_step_observations(Some(&record), Some(&record)).starts_with("UNKNOWN"));
        assert!(render_step_observation(None).contains("UNKNOWN"));
    }
    #[test]
    fn replay_count_changes_are_visible_even_when_exits_match() {
        let (plan, mut value) = fixture();
        let before = parse(&plan, &value, 0).unwrap();
        value["steps"][0]["duration_ms"] = json!(1000);
        let same = parse(&plan, &value, 0).unwrap();
        assert!(compare_step_observations(Some(&before), Some(&same)).starts_with("MATCH"));
        value["steps"][0]["counts"]["passed"] = json!(940);
        let changed = parse(&plan, &value, 0).unwrap();
        assert!(compare_step_observations(Some(&before), Some(&changed)).starts_with("DIFFERENT"));
    }

    #[test]
    fn upgrade_statement_never_promotes_unresolved_or_missing_results() {
        let mut manifest: RunManifest = serde_json::from_str(include_str!(
            "../../../examples/reports/python-runtime-break/run.json"
        ))
        .unwrap();
        for result in &mut manifest.results {
            result.verdict = if manifest
                .plan
                .scenarios
                .iter()
                .any(|s| s.id == result.scenario_id && s.is_baseline)
            {
                Verdict::BaselinePass
            } else {
                Verdict::FuturePass
            };
            result.exit_code = Some(0);
            result.timed_out = false;
            result.attempt = 1;
        }
        assert!(upgrade_observation(&manifest).contains("test commands passed"));
        let candidate_index = manifest
            .results
            .iter()
            .position(|r| r.verdict == Verdict::FuturePass)
            .unwrap();
        for verdict in [
            Verdict::Blocked,
            Verdict::Unsupported,
            Verdict::Inconclusive,
            Verdict::CoverageIncomplete,
            Verdict::Flaky,
        ] {
            manifest.results[candidate_index].verdict = verdict;
            assert!(
                upgrade_observation(&manifest).contains("incomplete or mixed"),
                "{verdict:?}"
            );
            assert_eq!(manifest.results[candidate_index].verdict, verdict);
        }
        manifest.results[candidate_index].verdict = Verdict::FutureFail;
        assert!(upgrade_observation(&manifest).contains("failure was observed"));
        manifest.results.remove(candidate_index);
        assert!(upgrade_observation(&manifest).contains("incomplete or mixed"));
        manifest
            .results
            .iter_mut()
            .find(|r| r.verdict == Verdict::BaselinePass)
            .unwrap()
            .verdict = Verdict::BaselineInvalid;
        assert!(upgrade_observation(&manifest).contains("baseline did not establish"));
    }

    #[test]
    fn relocated_reports_read_real_root_and_escape_step_arguments() {
        let (plan, value) = fixture();
        let mut manifest: RunManifest = serde_json::from_str(include_str!(
            "../../../examples/reports/python-runtime-break/run.json"
        ))
        .unwrap();
        manifest.results.truncate(1);
        manifest.results[0].exit_code = Some(0);
        manifest.results[0].timed_out = false;
        manifest.evidence_root = "stale-original-location".into();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("relocated");
        let log_dir = root
            .join("scenarios")
            .join(&manifest.results[0].scenario_id);
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::create_dir_all(&log_dir).unwrap();
        let mut plan: serde_json::Value = serde_json::from_str(&plan).unwrap();
        let mut value = value;
        plan["steps"][0]
            .as_array_mut()
            .unwrap()
            .push(json!("<script>literal</script>"));
        value["steps"][0]["argv"] = plan["steps"][0].clone();
        std::fs::write(
            root.join("workspace/.tomorrowci-steps.json"),
            plan.to_string(),
        )
        .unwrap();
        std::fs::write(log_dir.join("stdout.log"), format!("{PREFIX}{value}\n")).unwrap();
        std::fs::write(log_dir.join("stderr.log"), "").unwrap();
        let html = dir.path().join("staging/report.html");
        crate::write_html_report_from_verified_root(&manifest, &root, &html).unwrap();
        let body = std::fs::read_to_string(html).unwrap();
        assert!(body.contains("941 passed"));
        assert!(body.contains("&lt;script&gt;literal&lt;/script&gt;"));
        assert!(!body.contains("<script>literal</script>"));
        let md = dir.path().join("staging/job-summary.md");
        crate::write_github_job_summary_from_verified_root(&manifest, &root, &md).unwrap();
        assert!(std::fs::read_to_string(md).unwrap().contains("941 passed"));
    }
}
