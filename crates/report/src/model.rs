use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use tomorrowci_core::{Result, RunManifest, Verdict};

pub const REPORT_MODEL_SCHEMA: &str = "tomorrowci.report/v1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportModel {
    pub(crate) schema_version: &'static str,
    pub(crate) evidence_schema_version: u32,
    pub(crate) run: ReportRun,
    pub(crate) baseline: ReportBaseline,
    pub(crate) frontier: ReportFrontier,
    pub(crate) scenarios: Vec<ReportScenario>,
    pub(crate) replay_attempts: Vec<ReportReplayAttempt>,
    pub(crate) denominator: ReportDenominator,
    pub(crate) evidence_links: Vec<ReportLink>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportRun {
    pub(crate) id: String,
    pub(crate) tool_version: String,
    pub(crate) ecosystem: String,
    pub(crate) source: String,
    pub(crate) commit_sha: Option<String>,
    pub(crate) config_hash: String,
    pub(crate) started_at: String,
    pub(crate) finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportBaseline {
    pub(crate) runtime: String,
    pub(crate) dependencies: String,
    pub(crate) declared_by: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportFrontier {
    pub(crate) observed: bool,
    pub(crate) authorization: &'static str,
    pub(crate) horizon_label: Option<String>,
    pub(crate) first_failing_scenario: Option<String>,
    pub(crate) last_passing_scenario: Option<String>,
    pub(crate) grade: String,
    pub(crate) changed_axes: Vec<String>,
    pub(crate) failure_hash: Option<String>,
    pub(crate) failure_summary: Option<String>,
    pub(crate) replay_command: Option<String>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportScenario {
    pub(crate) order: usize,
    pub(crate) id: String,
    pub(crate) is_baseline: bool,
    pub(crate) runtime: String,
    pub(crate) dependencies: String,
    pub(crate) axes_changed: Vec<String>,
    pub(crate) verdict: &'static str,
    pub(crate) tone: &'static str,
    pub(crate) duration_ms: Option<u64>,
    pub(crate) test_attempts: u32,
    pub(crate) image: Option<String>,
    pub(crate) image_digest: Option<String>,
    pub(crate) failure_kind: Option<String>,
    pub(crate) failure_summary: Option<String>,
    pub(crate) links: ScenarioLinks,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScenarioLinks {
    pub(crate) scenario: String,
    pub(crate) environment: String,
    pub(crate) result: String,
    pub(crate) replay_descriptor: String,
    pub(crate) replays: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportReplayAttempt {
    pub(crate) scenario_id: String,
    pub(crate) attempt: u32,
    pub(crate) result_href: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportDenominator {
    pub(crate) total: usize,
    pub(crate) pass: usize,
    pub(crate) fail: usize,
    pub(crate) flaky: usize,
    pub(crate) blocked: usize,
    pub(crate) unsupported: usize,
    pub(crate) inconclusive: usize,
    pub(crate) not_run: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReportLink {
    pub(crate) label: &'static str,
    pub(crate) href: &'static str,
    pub(crate) description: &'static str,
}

pub fn build_report_model(
    manifest: &RunManifest,
    replay_root: Option<&Path>,
) -> Result<ReportModel> {
    let mut scenarios = Vec::new();
    let mut known_results = HashSet::new();

    for (order, planned) in manifest.plan.scenarios.iter().enumerate() {
        let result = manifest
            .results
            .iter()
            .find(|result| result.scenario_id == planned.id);
        if result.is_some() {
            known_results.insert(planned.id.as_str());
        }
        scenarios.push(ReportScenario {
            order,
            id: planned.id.clone(),
            is_baseline: planned.is_baseline,
            runtime: planned.runtime.clone(),
            dependencies: planned.dependencies.clone(),
            axes_changed: planned
                .axes_changed
                .iter()
                .map(|axis| format!("{axis:?}").to_ascii_uppercase())
                .collect(),
            verdict: result.map_or("NOT_RUN", |result| verdict_label(result.verdict)),
            tone: result.map_or("other", |result| verdict_tone(result.verdict)),
            duration_ms: result.map(|result| result.duration_ms),
            test_attempts: result.map_or(0, |result| result.attempt),
            image: result.map(|result| result.environment.image.clone()),
            image_digest: result.and_then(|result| result.environment.image_digest.clone()),
            failure_kind: result
                .and_then(|result| result.failure.as_ref().map(|failure| failure.kind.clone())),
            failure_summary: result.and_then(|result| {
                result
                    .failure
                    .as_ref()
                    .map(|failure| failure.summary.clone())
            }),
            links: scenario_links(&planned.id),
        });
    }

    // A verified current-v2 bundle has exact plan/result closure. Keeping an
    // explicit fallback makes an unfinalized writer state visible as data
    // rather than silently dropping it or promoting it to PASS.
    for result in &manifest.results {
        if known_results.contains(result.scenario_id.as_str()) {
            continue;
        }
        scenarios.push(ReportScenario {
            order: scenarios.len(),
            id: result.scenario_id.clone(),
            is_baseline: false,
            runtime: "Unplanned".into(),
            dependencies: "Unplanned".into(),
            axes_changed: Vec::new(),
            verdict: verdict_label(result.verdict),
            tone: verdict_tone(result.verdict),
            duration_ms: Some(result.duration_ms),
            test_attempts: result.attempt,
            image: Some(result.environment.image.clone()),
            image_digest: result.environment.image_digest.clone(),
            failure_kind: result.failure.as_ref().map(|failure| failure.kind.clone()),
            failure_summary: result
                .failure
                .as_ref()
                .map(|failure| failure.summary.clone()),
            links: scenario_links(&result.scenario_id),
        });
    }

    let mut denominator = ReportDenominator {
        total: scenarios.len(),
        ..ReportDenominator::default()
    };
    for scenario in &scenarios {
        match scenario.verdict {
            "PASS" => denominator.pass += 1,
            "FAIL" => denominator.fail += 1,
            "FLAKY" => denominator.flaky += 1,
            "BLOCKED" => denominator.blocked += 1,
            "UNSUPPORTED" => denominator.unsupported += 1,
            "INCONCLUSIVE" | "COVERAGE_INCOMPLETE" => denominator.inconclusive += 1,
            "NOT_RUN" => denominator.not_run += 1,
            _ => unreachable!("report verdict mapping is exhaustive"),
        }
    }

    let replay_attempts = replay_root
        .map(|root| collect_replay_attempts(root, &scenarios))
        .transpose()?
        .unwrap_or_default();

    Ok(ReportModel {
        schema_version: REPORT_MODEL_SCHEMA,
        evidence_schema_version: manifest.evidence_schema_version,
        run: ReportRun {
            id: manifest.run_id.clone(),
            tool_version: manifest.tool_version.clone(),
            ecosystem: format!("{:?}", manifest.detection.ecosystem).to_ascii_uppercase(),
            source: manifest.repository.source.clone(),
            commit_sha: manifest.repository.commit_sha.clone(),
            config_hash: manifest.config_hash.clone(),
            started_at: manifest.started_at.to_rfc3339(),
            finished_at: manifest.finished_at.map(|timestamp| timestamp.to_rfc3339()),
        },
        baseline: ReportBaseline {
            runtime: manifest.baseline.runtime.clone(),
            dependencies: manifest.baseline.dependencies.clone(),
            declared_by: manifest.baseline.declared_by.clone(),
        },
        frontier: ReportFrontier {
            observed: manifest.frontier.observed,
            authorization: if manifest.frontier.observed {
                "AUTHORIZED_BY_VERIFIED_FRONTIER"
            } else {
                "NOT_AUTHORIZED"
            },
            horizon_label: manifest.frontier.horizon_label.clone(),
            first_failing_scenario: manifest.frontier.first_failing_scenario.clone(),
            last_passing_scenario: manifest.frontier.last_passing_scenario.clone(),
            grade: format!("{:?}", manifest.frontier.grade).to_ascii_uppercase(),
            changed_axes: manifest
                .frontier
                .changed_axes
                .iter()
                .map(|axis| format!("{axis:?}").to_ascii_uppercase())
                .collect(),
            failure_hash: manifest
                .frontier
                .failure_signature
                .as_ref()
                .map(|failure| failure.normalized_hash.clone()),
            failure_summary: manifest
                .frontier
                .failure_signature
                .as_ref()
                .map(|failure| failure.summary.clone()),
            replay_command: manifest.frontier.replay_command.clone(),
            notes: manifest.frontier.notes.clone(),
        },
        scenarios,
        replay_attempts,
        denominator,
        evidence_links: vec![
            ReportLink {
                label: "Run manifest",
                href: "run.json",
                description: "Verified run identity, plan, results, and frontier mirror.",
            },
            ReportLink {
                label: "Frontier",
                href: "frontier.json",
                description: "Checked breakage-frontier projection.",
            },
            ReportLink {
                label: "Checksums",
                href: "checksums.txt",
                description: "Exact current-v2 evidence inventory.",
            },
            ReportLink {
                label: "Workspace manifest",
                href: "workspace-manifest.json",
                description: "Captured source-file sizes and content hashes.",
            },
            ReportLink {
                label: "Claims",
                href: "claims.json",
                description: "Bounded claims derived from verified results.",
            },
        ],
    })
}

fn scenario_links(id: &str) -> ScenarioLinks {
    if !is_safe_component(id) {
        return ScenarioLinks {
            scenario: "scenarios/".into(),
            environment: "scenarios/".into(),
            result: "scenarios/".into(),
            replay_descriptor: "scenarios/".into(),
            replays: "scenarios/".into(),
        };
    }
    let root = format!("scenarios/{id}");
    ScenarioLinks {
        scenario: format!("{root}/scenario.json"),
        environment: format!("{root}/environment.json"),
        result: format!("{root}/result.json"),
        replay_descriptor: format!("{root}/replay.json"),
        replays: format!("{root}/replays/"),
    }
}

fn collect_replay_attempts(
    run_root: &Path,
    scenarios: &[ReportScenario],
) -> Result<Vec<ReportReplayAttempt>> {
    let mut attempts = Vec::new();
    for scenario in scenarios {
        if !is_safe_component(&scenario.id) {
            continue;
        }
        let replay_root = run_root
            .join("scenarios")
            .join(&scenario.id)
            .join("replays");
        let metadata = match std::fs::symlink_metadata(&replay_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let mut scenario_attempts = Vec::new();
        for entry in std::fs::read_dir(&replay_root)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(attempt) = replay_attempt_number(&name) else {
                continue;
            };
            let metadata = entry.metadata()?;
            let result = entry.path().join("result.json");
            let result_metadata = match std::fs::symlink_metadata(&result) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || result_metadata.file_type().is_symlink()
                || !result_metadata.is_file()
            {
                continue;
            }
            scenario_attempts.push(ReportReplayAttempt {
                scenario_id: scenario.id.clone(),
                attempt,
                result_href: format!(
                    "scenarios/{}/replays/attempt-{attempt}/result.json",
                    scenario.id
                ),
            });
        }
        scenario_attempts.sort_by_key(|attempt| attempt.attempt);
        attempts.extend(scenario_attempts);
    }
    Ok(attempts)
}

fn replay_attempt_number(name: &str) -> Option<u32> {
    let raw = name.strip_prefix("attempt-")?;
    let number = raw.parse().ok()?;
    (number > 0 && name == format!("attempt-{number}")).then_some(number)
}

fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::BaselinePass | Verdict::FuturePass => "PASS",
        Verdict::BaselineInvalid | Verdict::FutureFail => "FAIL",
        Verdict::Flaky => "FLAKY",
        Verdict::Blocked => "BLOCKED",
        Verdict::Unsupported => "UNSUPPORTED",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::CoverageIncomplete => "COVERAGE_INCOMPLETE",
    }
}

fn verdict_tone(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::BaselinePass | Verdict::FuturePass => "pass",
        Verdict::BaselineInvalid | Verdict::FutureFail => "fail",
        Verdict::Flaky => "flaky",
        Verdict::Blocked => "blocked",
        Verdict::Unsupported | Verdict::Inconclusive | Verdict::CoverageIncomplete => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_replay_attempt_names_only() {
        assert_eq!(replay_attempt_number("attempt-1"), Some(1));
        assert_eq!(replay_attempt_number("attempt-22"), Some(22));
        assert_eq!(replay_attempt_number("attempt-0"), None);
        assert_eq!(replay_attempt_number("attempt-01"), None);
        assert_eq!(replay_attempt_number("attempt-x"), None);
    }

    #[test]
    fn report_paths_require_plain_components() {
        assert!(is_safe_component("node22-locked"));
        assert!(!is_safe_component("../escape"));
        assert!(!is_safe_component("nested/path"));
        assert!(!is_safe_component(".."));
    }
}
