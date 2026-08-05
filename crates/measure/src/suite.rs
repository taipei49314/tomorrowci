//! Fixture suite runner — execute, assert expectations, emit ledger.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tomorrowci_core::policy::{evaluate_policy, PolicyConfig};
use tomorrowci_core::{Config, Verdict};
use tomorrowci_runner::{scan, ScanRequest};
use tomorrowci_sandbox::detect_engine;

use crate::claims::{ClaimRecord, ClaimStatus, Ledger};
use crate::expect::{default_catalog, FixtureExpectation};

#[derive(Debug, Clone)]
pub struct SuiteOptions {
    pub repo_root: PathBuf,
    pub evidence_root: PathBuf,
    pub work_root: PathBuf,
    pub only: Option<Vec<String>>,
    pub catalog: Vec<FixtureExpectation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureResult {
    pub id: String,
    pub path: PathBuf,
    pub duration_ms: u64,
    pub run_id: Option<String>,
    pub evidence_dir: Option<PathBuf>,
    pub claims: Vec<ClaimRecord>,
    pub terminal_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasureReport {
    pub tool_version: String,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: chrono::DateTime<Utc>,
    pub engine_available: bool,
    pub engine_detail: String,
    pub fixtures: Vec<FixtureResult>,
    pub ledger: Ledger,
    pub trustworthy: bool,
}

pub async fn run_fixture_suite(opts: SuiteOptions) -> MeasureReport {
    let started_at = Utc::now();
    let mut ledger = Ledger::default();
    let mut fixtures = Vec::new();

    let engine = detect_engine("auto");
    let (engine_available, engine_detail) = match &engine {
        Ok(e) => (
            true,
            format!("{} {} at {}", e.kind.binary(), e.version, e.path.display()),
        ),
        Err(e) => (false, e.to_string()),
    };
    ledger.push(
        ClaimRecord::new(
            "infra.container_engine",
            "Container engine available for fixture execution",
            "infra",
            if engine_available {
                ClaimStatus::Pass
            } else {
                ClaimStatus::Blocked
            },
            engine_detail.clone(),
            0,
        )
        .with_command("detect_engine(auto)"),
    );

    let only = opts.only.clone();
    let catalog: Vec<FixtureExpectation> = opts
        .catalog
        .clone()
        .into_iter()
        .filter(|f| {
            only.as_ref()
                .map(|ids| ids.iter().any(|id| id == &f.id))
                .unwrap_or(true)
        })
        .collect();

    for exp in catalog {
        let result = measure_one_fixture(&opts, &exp, engine_available).await;
        for c in &result.claims {
            ledger.push(c.clone());
        }
        fixtures.push(result);
    }

    let finished_at = Utc::now();
    let trustworthy = ledger.all_trustworthy();
    MeasureReport {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at,
        finished_at,
        engine_available,
        engine_detail,
        fixtures,
        ledger,
        trustworthy,
    }
}

async fn measure_one_fixture(
    opts: &SuiteOptions,
    exp: &FixtureExpectation,
    engine_available: bool,
) -> FixtureResult {
    let mut claims = Vec::new();
    let path = opts.repo_root.join(&exp.path);
    let t0 = Instant::now();

    if !path.exists() {
        claims.push(ClaimRecord::new(
            format!("fixture.{}.exists", exp.id),
            format!("fixture path exists: {}", exp.path),
            "fixture",
            ClaimStatus::Fail,
            format!("missing {}", path.display()),
            t0.elapsed().as_millis() as u64,
        ));
        return FixtureResult {
            id: exp.id.clone(),
            path,
            duration_ms: t0.elapsed().as_millis() as u64,
            run_id: None,
            evidence_dir: None,
            claims,
            terminal_summary: None,
        };
    }
    claims.push(ClaimRecord::new(
        format!("fixture.{}.exists", exp.id),
        format!("fixture path exists: {}", exp.path),
        "fixture",
        ClaimStatus::Pass,
        path.display().to_string(),
        0,
    ));

    if exp.require_engine && !engine_available {
        claims.push(
            ClaimRecord::new(
                format!("fixture.{}.scan", exp.id),
                format!("scan {}", exp.id),
                "fixture",
                ClaimStatus::Blocked,
                "container engine unavailable — not executed; not a PASS",
                t0.elapsed().as_millis() as u64,
            )
            .with_command(format!("tomorrowci scan {}", exp.path)),
        );
        // Mark expectation claims as NOT_RUN (not FAIL)
        for suffix in ["baseline", "horizon", "verdict", "signature"] {
            claims.push(ClaimRecord::new(
                format!("fixture.{}.{}", exp.id, suffix),
                format!("{} expectation", suffix),
                "fixture",
                ClaimStatus::NotRun,
                "blocked on infrastructure",
                0,
            ));
        }
        return FixtureResult {
            id: exp.id.clone(),
            path,
            duration_ms: t0.elapsed().as_millis() as u64,
            run_id: None,
            evidence_dir: None,
            claims,
            terminal_summary: None,
        };
    }

    let config = load_fixture_config(&path, exp);
    let scan_t0 = Instant::now();
    let outcome = scan(ScanRequest {
        target: path.display().to_string(),
        config,
        config_path: exp.config.as_ref().map(|c| path.join(c)),
        output_root: opts.evidence_root.clone(),
        work_root: opts.work_root.clone(),
    })
    .await;
    let scan_ms = scan_t0.elapsed().as_millis() as u64;

    match outcome {
        Err(e) => {
            claims.push(
                ClaimRecord::new(
                    format!("fixture.{}.scan", exp.id),
                    format!("scan {}", exp.id),
                    "fixture",
                    ClaimStatus::Fail,
                    e.to_string(),
                    scan_ms,
                )
                .with_command(format!("tomorrowci scan {}", exp.path)),
            );
            FixtureResult {
                id: exp.id.clone(),
                path,
                duration_ms: t0.elapsed().as_millis() as u64,
                run_id: None,
                evidence_dir: None,
                claims,
                terminal_summary: None,
            }
        }
        Ok(out) => {
            claims.push(
                ClaimRecord::new(
                    format!("fixture.{}.scan", exp.id),
                    format!("scan completed {}", exp.id),
                    "fixture",
                    ClaimStatus::Pass,
                    format!("run_id={} scenarios={}", out.run_id, out.verdicts.len()),
                    scan_ms,
                )
                .with_command(format!("tomorrowci scan {}", exp.path))
                .with_artifact(out.evidence_dir.clone()),
            );

            // min scenarios
            if exp.min_scenarios > 0 {
                let ok = out.verdicts.len() >= exp.min_scenarios;
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.min_scenarios", exp.id),
                    format!("at least {} scenarios", exp.min_scenarios),
                    "fixture",
                    if ok {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    format!("got {}", out.verdicts.len()),
                    0,
                ));
            }

            // baseline
            if let Some(expected) = exp.expect_baseline {
                let baseline = out
                    .verdicts
                    .iter()
                    .find(|v| v.scenario_id.0 == "baseline")
                    .or_else(|| out.verdicts.first());
                let status = match baseline {
                    Some(v) if expected.matches(v.verdict) => ClaimStatus::Pass,
                    Some(_v) => ClaimStatus::Fail,
                    None => ClaimStatus::Fail,
                };
                let detail = baseline
                    .map(|v| format!("{:?} (want {})", v.verdict, expected.label()))
                    .unwrap_or_else(|| "no baseline verdict".into());
                // If engine blocked mid-run
                let status = if baseline
                    .map(|v| v.verdict == Verdict::Blocked)
                    .unwrap_or(false)
                    && exp.require_engine
                {
                    ClaimStatus::Blocked
                } else {
                    status
                };
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.baseline", exp.id),
                    format!("baseline verdict is {}", expected.label()),
                    "fixture",
                    status,
                    detail,
                    0,
                ));
            }

            // horizon
            if exp.expect_horizon {
                let ok = out.frontier.observed
                    && exp
                        .horizon_contains
                        .as_ref()
                        .map(|s| {
                            out.frontier
                                .horizon_label
                                .as_deref()
                                .unwrap_or("")
                                .contains(s)
                        })
                        .unwrap_or(true);
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.horizon", exp.id),
                    "observed breakage horizon matches expectation",
                    "fixture",
                    if ok {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    format!(
                        "observed={} label={:?}",
                        out.frontier.observed, out.frontier.horizon_label
                    ),
                    0,
                ));
            }
            if exp.expect_no_horizon {
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.no_horizon", exp.id),
                    "no breakage horizon authorized",
                    "fixture",
                    if !out.frontier.observed {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    format!(
                        "observed={} — {}",
                        out.frontier.observed, out.frontier.explanation
                    ),
                    0,
                ));
            }

            // any verdict
            if let Some(want) = exp.expect_any_verdict {
                let ok = out.verdicts.iter().any(|v| want.matches(v.verdict));
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.verdict", exp.id),
                    format!("at least one scenario is {}", want.label()),
                    "fixture",
                    if ok {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    format!(
                        "verdicts={:?}",
                        out.verdicts
                            .iter()
                            .map(|v| v.verdict.short_label())
                            .collect::<Vec<_>>()
                    ),
                    0,
                ));
            }

            // signature
            if let Some(sub) = &exp.signature_contains {
                let hay = out
                    .verdicts
                    .iter()
                    .filter_map(|v| v.failure_signature.as_ref())
                    .map(|s| s.summary.clone())
                    .chain(
                        out.frontier
                            .failure_signature
                            .as_ref()
                            .map(|s| s.summary.clone()),
                    )
                    .collect::<Vec<_>>()
                    .join("\n");
                let ok = hay.contains(sub);
                claims.push(ClaimRecord::new(
                    format!("fixture.{}.signature", exp.id),
                    format!("failure signature contains '{sub}'"),
                    "fixture",
                    if ok {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    if hay.is_empty() {
                        "no signatures recorded".to_string()
                    } else {
                        hay.chars().take(120).collect::<String>()
                    },
                    0,
                ));
            }

            // evidence bundle files
            let required = ["run.json", "verdicts.json", "frontier.json", "report.html"];
            let mut missing = Vec::new();
            for f in required {
                if !out.evidence_dir.join(f).exists() {
                    missing.push(f);
                }
            }
            claims.push(
                ClaimRecord::new(
                    format!("fixture.{}.evidence", exp.id),
                    "evidence bundle has required files",
                    "fixture",
                    if missing.is_empty() {
                        ClaimStatus::Pass
                    } else {
                        ClaimStatus::Fail
                    },
                    if missing.is_empty() {
                        out.evidence_dir.display().to_string()
                    } else {
                        format!("missing {missing:?}")
                    },
                    0,
                )
                .with_artifact(out.evidence_dir.clone()),
            );

            FixtureResult {
                id: exp.id.clone(),
                path,
                duration_ms: t0.elapsed().as_millis() as u64,
                run_id: Some(out.run_id.0.clone()),
                evidence_dir: Some(out.evidence_dir),
                claims,
                terminal_summary: Some(out.terminal_summary),
            }
        }
    }
}

fn load_fixture_config(fixture_path: &Path, exp: &FixtureExpectation) -> Config {
    if let Some(rel) = &exp.config {
        let p = fixture_path.join(rel);
        if p.exists() {
            return Config::load_from_path(&p).unwrap_or_default();
        }
    }
    let default = fixture_path.join(".tomorrowci.yml");
    if default.exists() {
        Config::load_from_path(&default).unwrap_or_default()
    } else {
        Config::default()
    }
}

/// Convenience: catalog from defaults.
pub fn catalog_or_default(custom: Option<Vec<FixtureExpectation>>) -> Vec<FixtureExpectation> {
    custom.unwrap_or_else(default_catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_nonempty() {
        assert!(!default_catalog().is_empty());
    }
}
