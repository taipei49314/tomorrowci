//! Micro-benchmarks with honest methodology (no invented SLAs).

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use tomorrowci_core::{
    config::Config, Candidate, DependencyMode, EnvironmentAxis, EvidenceGrade, Planner, RunId,
    Scenario, ScenarioId, ScenarioKind, Ecosystem,
};
use tomorrowci_sandbox::detect_engine;

use crate::claims::{ClaimRecord, ClaimStatus, Ledger};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchSample {
    pub name: String,
    pub iterations: usize,
    pub samples_ms: Vec<f64>,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub mean_ms: f64,
    pub methodology: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub samples: Vec<BenchSample>,
    pub ledger: Ledger,
    pub note: String,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn summarize(name: &str, mut samples_ms: Vec<f64>, methodology: &str) -> BenchSample {
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = if samples_ms.is_empty() {
        0.0
    } else {
        samples_ms.iter().sum::<f64>() / samples_ms.len() as f64
    };
    BenchSample {
        name: name.into(),
        iterations: samples_ms.len(),
        p50_ms: percentile(&samples_ms, 50.0),
        p95_ms: percentile(&samples_ms, 95.0),
        mean_ms: mean,
        samples_ms,
        methodology: methodology.into(),
    }
}

/// Run local micro-benchmarks (no containers for pure CPU paths).
pub fn run_benches(repo_root: &Path) -> BenchReport {
    let mut ledger = Ledger::default();
    let mut samples = Vec::new();

    // 1) Config parse
    {
        let raw = include_str!("../../../packages/schema/config-v1.json");
        let _ = raw; // schema presence
        let yaml = r#"
version: 1
project: { ecosystem: auto, test_command: auto, build_command: auto }
execution: { max_scenarios: 24, timeout_seconds: 900, reruns_on_failure: 2, max_parallel: 2 }
"#;
        let mut times = Vec::new();
        for _ in 0..200 {
            let t0 = Instant::now();
            let _ = Config::load_from_str(yaml).unwrap();
            times.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let s = summarize(
            "config_parse",
            times,
            "200 iterations of Config::load_from_str on default-shaped YAML; warm process",
        );
        ledger.push(
            ClaimRecord::new(
                "bench.config_parse",
                "config parse microbench recorded",
                "bench",
                ClaimStatus::Pass,
                format!("p50={:.3}ms p95={:.3}ms", s.p50_ms, s.p95_ms),
                s.p50_ms as u64,
            )
            .with_command("tomorrowci measure bench"),
        );
        samples.push(s);
    }

    // 2) Planner
    {
        let cfg = Config::default();
        let baseline = Scenario {
            id: ScenarioId::new("baseline"),
            kind: ScenarioKind::Baseline,
            ecosystem: Ecosystem::Python,
            label: "baseline".into(),
            runtime_version: "3.9".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.9".into(),
            axes_changed: vec![],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: true,
            selection_reason: "bench".into(),
        };
        let cands: Vec<Candidate> = (10..20)
            .map(|m| Candidate {
                id: format!("py3{m}"),
                axis: EnvironmentAxis::Runtime,
                label: format!("3.{m}"),
                runtime_version: Some(format!("3.{m}")),
                dependency_mode: DependencyMode::Locked,
                image_ref: format!("python:3.{m}"),
                channel: "stable".into(),
                order_key: format!("3.{m}"),
                evidence_grade: EvidenceGrade::Observed,
                notes: vec![],
            })
            .collect();
        let mut times = Vec::new();
        for _ in 0..200 {
            let planner = Planner::new(RunId::new(), cfg.clone());
            let t0 = Instant::now();
            let _ = planner
                .plan_initial(baseline.clone(), cands.clone(), vec![])
                .unwrap();
            times.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let s = summarize(
            "planner_initial",
            times,
            "200 iterations plan_initial with 10 runtime candidates; in-process",
        );
        // Mission aspirational: baseline planning under 1s — we record, not invent pass/fail on host variance
        ledger.push(
            ClaimRecord::new(
                "bench.planner_initial",
                "planner microbench recorded (target informally <1000ms)",
                "bench",
                ClaimStatus::Pass,
                format!("p50={:.3}ms p95={:.3}ms", s.p50_ms, s.p95_ms),
                s.p50_ms as u64,
            )
            .with_command("tomorrowci measure bench"),
        );
        samples.push(s);
    }

    // 3) Engine detect
    {
        let mut times = Vec::new();
        let mut last_ok = false;
        for _ in 0..10 {
            let t0 = Instant::now();
            last_ok = detect_engine("auto").is_ok();
            times.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        let s = summarize(
            "engine_detect",
            times,
            "10 iterations of detect_engine(auto); includes docker info probe",
        );
        ledger.push(
            ClaimRecord::new(
                "bench.engine_detect",
                "sandbox engine detection measured",
                "bench",
                if last_ok {
                    ClaimStatus::Pass
                } else {
                    ClaimStatus::Blocked
                },
                format!(
                    "available={} p50={:.1}ms p95={:.1}ms",
                    last_ok, s.p50_ms, s.p95_ms
                ),
                s.p50_ms as u64,
            )
            .with_command("tomorrowci measure bench"),
        );
        samples.push(s);
    }

    // 4) CLI binary presence / mtime (startup measured externally if binary exists)
    {
        let bin = if cfg!(windows) {
            repo_root.join("target/release/tomorrowci.exe")
        } else {
            repo_root.join("target/release/tomorrowci")
        };
        if bin.exists() {
            let mut times = Vec::new();
            for _ in 0..15 {
                let t0 = Instant::now();
                let status = std::process::Command::new(&bin)
                    .arg("--version")
                    .output();
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                if status.map(|o| o.status.success()).unwrap_or(false) {
                    times.push(ms);
                }
            }
            if times.is_empty() {
                ledger.push(ClaimRecord::new(
                    "bench.cli_version",
                    "CLI --version samples",
                    "bench",
                    ClaimStatus::Fail,
                    "binary exists but --version failed",
                    0,
                ));
            } else {
                let s = summarize(
                    "cli_version_startup",
                    times,
                    "15 cold-ish process spawns of `tomorrowci --version` (includes process create, not container work). Mission aspirational CLI startup <300ms excluding container work — recorded, not hard-gated.",
                );
                ledger.push(
                    ClaimRecord::new(
                        "bench.cli_version",
                        "CLI --version spawn latency recorded",
                        "bench",
                        ClaimStatus::Pass,
                        format!("p50={:.1}ms p95={:.1}ms", s.p50_ms, s.p95_ms),
                        s.p50_ms as u64,
                    )
                    .with_artifact(bin),
                );
                samples.push(s);
            }
        } else {
            ledger.push(ClaimRecord::new(
                "bench.cli_version",
                "CLI --version spawn latency",
                "bench",
                ClaimStatus::NotRun,
                format!("release binary missing at {}", bin.display()),
                0,
            ));
        }
    }

    BenchReport {
        samples,
        ledger,
        note: "Benchmarks document methodology and measured distributions. They do not invent production SLAs. Host load affects spawn latency.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic() {
        let v = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&v, 50.0), 3.0);
    }
}
