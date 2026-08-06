use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use tomorrowci_core::{Result, RunManifest, Verdict};

/// Per-run measurement counters written next to evidence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanMetrics {
    pub run_id: String,
    pub recorded_at: DateTime<Utc>,
    pub scenarios_total: u32,
    pub scenarios_pass: u32,
    pub scenarios_fail: u32,
    pub scenarios_flaky: u32,
    pub scenarios_blocked: u32,
    pub scenarios_unsupported: u32,
    pub scenarios_inconclusive: u32,
    pub baseline_ok: bool,
    pub frontier_observed: bool,
    pub total_duration_ms: u64,
    pub mean_duration_ms: f64,
    pub evidence_grade: String,
    pub ecosystem: String,
    /// Wall-clock of orchestration if provided.
    pub wall_ms: Option<u64>,
    pub verdict_histogram: BTreeMap<String, u32>,
}

impl ScanMetrics {
    pub fn from_manifest(m: &RunManifest, wall_ms: Option<u64>) -> Self {
        let mut hist = BTreeMap::new();
        let mut pass = 0;
        let mut fail = 0;
        let mut flaky = 0;
        let mut blocked = 0;
        let mut unsupported = 0;
        let mut inconclusive = 0;
        let mut total_dur = 0u64;
        let mut baseline_ok = false;

        for r in &m.results {
            let key = format!("{:?}", r.verdict);
            *hist.entry(key).or_insert(0) += 1;
            total_dur += r.duration_ms;
            match r.verdict {
                Verdict::BaselinePass => {
                    pass += 1;
                    baseline_ok = true;
                }
                Verdict::FuturePass => pass += 1,
                Verdict::BaselineInvalid | Verdict::FutureFail => fail += 1,
                Verdict::Flaky => flaky += 1,
                Verdict::Blocked => blocked += 1,
                Verdict::Unsupported => unsupported += 1,
                Verdict::Inconclusive => inconclusive += 1,
            }
        }
        let n = m.results.len() as u32;
        Self {
            run_id: m.run_id.clone(),
            recorded_at: Utc::now(),
            scenarios_total: n,
            scenarios_pass: pass,
            scenarios_fail: fail,
            scenarios_flaky: flaky,
            scenarios_blocked: blocked,
            scenarios_unsupported: unsupported,
            scenarios_inconclusive: inconclusive,
            baseline_ok,
            frontier_observed: m.frontier.observed,
            total_duration_ms: total_dur,
            mean_duration_ms: if n == 0 {
                0.0
            } else {
                total_dur as f64 / n as f64
            },
            evidence_grade: format!("{:?}", m.frontier.grade),
            ecosystem: format!("{:?}", m.detection.ecosystem),
            wall_ms,
            verdict_histogram: hist,
        }
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn summary_line(&self) -> String {
        format!(
            "metrics: eco={} total={} pass={} fail={} flaky={} blocked={} frontier={} mean_ms={:.1}",
            self.ecosystem,
            self.scenarios_total,
            self.scenarios_pass,
            self.scenarios_fail,
            self.scenarios_flaky,
            self.scenarios_blocked,
            self.frontier_observed,
            self.mean_duration_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use indexmap::IndexMap;
    use tomorrowci_core::*;

    fn empty_manifest() -> RunManifest {
        RunManifest {
            run_id: "t1".into(),
            tool_version: "0.1.0".into(),
            started_at: Utc::now(),
            finished_at: None,
            repository: RepositorySnapshot {
                source: ".".into(),
                path: ".".into(),
                commit_sha: None,
                is_disposable_copy: true,
            },
            config_hash: "sha256:x".into(),
            detection: ProjectDetection {
                ecosystem: Ecosystem::Python,
                manifests: vec![],
                package_manager: "pip".into(),
                confidence: 1.0,
                notes: vec![],
            },
            baseline: Baseline {
                runtime: "3.9".into(),
                dependencies: "locked".into(),
                declared_by: "t".into(),
            },
            plan: ExecutionPlan {
                plan_id: "p".into(),
                scenarios: vec![],
                selection_notes: vec![],
                budget_max: 10,
            },
            results: vec![ExecutionResult {
                scenario_id: "baseline".into(),
                attempt: 1,
                verdict: Verdict::BaselinePass,
                exit_code: Some(0),
                duration_ms: 100,
                timed_out: false,
                failure: None,
                environment: EnvironmentSpec {
                    image: "python:3.9".into(),
                    image_digest: None,
                    workdir: "/work".into(),
                    env: IndexMap::new(),
                    network_mode: "none".into(),
                    memory_mb: 1,
                    cpus: 1.0,
                    pids_limit: 1,
                    user: None,
                    read_only_root: true,
                },
                commands: vec![],
            }],
            frontier: BreakageFrontier {
                observed: false,
                horizon_label: None,
                first_failing_scenario: None,
                last_passing_scenario: None,
                changed_axes: vec![],
                failure_signature: None,
                grade: EvidenceGrade::Inconclusive,
                replay_command: None,
                notes: vec![],
            },
            evidence_root: ".".into(),
        }
    }

    #[test]
    fn counts_baseline_pass() {
        let m = ScanMetrics::from_manifest(&empty_manifest(), Some(50));
        assert_eq!(m.scenarios_pass, 1);
        assert!(m.baseline_ok);
        assert!(m.summary_line().contains("pass=1"));
    }
}
