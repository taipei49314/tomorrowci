//! Policy gate — deterministic fail-if rules over run evidence / compare.

use crate::compare::{HorizonCompare, HorizonMovement};
use crate::domain::{ScenarioVerdict, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub fail_if: FailIf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FailIf {
    /// Fail when baseline did not pass.
    #[serde(default = "default_true")]
    pub baseline_invalid: bool,
    /// Fail when any FUTURE_FAIL is observed (horizon or not).
    #[serde(default)]
    pub new_future_failure: bool,
    /// Fail when compare reports horizon regression (requires compare input).
    #[serde(default = "default_true")]
    pub horizon_regression: bool,
    /// Fail when blocked/unsupported/inconclusive ratio exceeds this (0.0–1.0).
    /// `None` disables.
    #[serde(default = "default_blocked_ratio")]
    pub blocked_ratio_above: Option<f64>,
}

impl Default for FailIf {
    fn default() -> Self {
        Self {
            baseline_invalid: true,
            new_future_failure: false,
            horizon_regression: true,
            blocked_ratio_above: Some(0.50),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_blocked_ratio() -> Option<f64> {
    Some(0.50)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReport {
    pub decision: PolicyDecision,
    pub violations: Vec<PolicyViolation>,
    pub stats: PolicyStats,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    pub scenario_count: usize,
    pub baseline_invalid: bool,
    pub future_fail_count: usize,
    pub blocked_like_count: usize,
    pub blocked_ratio: f64,
    pub horizon_regression: bool,
}

/// Evaluate policy against a single run's verdicts (+ optional compare).
///
/// Never converts BLOCKED into PASS; high blocked ratio can FAIL if configured.
pub fn evaluate_policy(
    policy: &PolicyConfig,
    verdicts: &[ScenarioVerdict],
    compare: Option<&HorizonCompare>,
) -> PolicyReport {
    let mut violations = Vec::new();

    let baseline_invalid = verdicts.iter().any(|v| {
        v.scenario_id.0 == "baseline" && v.verdict == Verdict::BaselineInvalid
            || v.verdict == Verdict::BaselineInvalid
    });
    let future_fail_count = verdicts
        .iter()
        .filter(|v| v.verdict == Verdict::FutureFail)
        .count();
    let blocked_like_count = verdicts
        .iter()
        .filter(|v| {
            matches!(
                v.verdict,
                Verdict::Blocked | Verdict::Unsupported | Verdict::Inconclusive
            )
        })
        .count();
    let n = verdicts.len().max(1);
    let blocked_ratio = blocked_like_count as f64 / n as f64;
    let horizon_regression = compare.map(|c| c.is_regression).unwrap_or(false);

    if policy.fail_if.baseline_invalid && baseline_invalid {
        violations.push(PolicyViolation {
            rule: "baseline_invalid".into(),
            detail: "baseline did not pass; future comparisons not authorized".into(),
        });
    }
    if policy.fail_if.new_future_failure && future_fail_count > 0 {
        violations.push(PolicyViolation {
            rule: "new_future_failure".into(),
            detail: format!("{future_fail_count} FUTURE_FAIL scenario(s)"),
        });
    }
    if policy.fail_if.horizon_regression && horizon_regression {
        let mov = compare
            .map(|c| format!("{:?}", c.movement))
            .unwrap_or_else(|| "REGRESSED".into());
        violations.push(PolicyViolation {
            rule: "horizon_regression".into(),
            detail: format!("horizon compare movement={mov}"),
        });
    }
    if let Some(thresh) = policy.fail_if.blocked_ratio_above {
        if blocked_ratio > thresh {
            violations.push(PolicyViolation {
                rule: "blocked_ratio_above".into(),
                detail: format!(
                    "blocked_like_ratio={blocked_ratio:.2} exceeds {thresh:.2} ({blocked_like_count}/{n})"
                ),
            });
        }
    }

    // Explicit: compare Unchanged/Improved never fail solely on blocked-absent compare
    let _ = compare.map(|c| c.movement == HorizonMovement::Unchanged);

    PolicyReport {
        decision: if violations.is_empty() {
            PolicyDecision::Pass
        } else {
            PolicyDecision::Fail
        },
        violations,
        stats: PolicyStats {
            scenario_count: verdicts.len(),
            baseline_invalid,
            future_fail_count,
            blocked_like_count,
            blocked_ratio,
            horizon_regression,
        },
        policy: policy.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EvidenceGrade, ScenarioId};

    fn v(id: &str, verdict: Verdict) -> ScenarioVerdict {
        ScenarioVerdict {
            scenario_id: ScenarioId::new(id),
            label: id.into(),
            verdict,
            evidence_grade: EvidenceGrade::Observed,
            attempts: 1,
            failure_signature: None,
            evidence: None,
            notes: vec![],
        }
    }

    #[test]
    fn baseline_invalid_fails_default_policy() {
        let r = evaluate_policy(
            &PolicyConfig::default(),
            &[v("baseline", Verdict::BaselineInvalid)],
            None,
        );
        assert_eq!(r.decision, PolicyDecision::Fail);
        assert!(r.violations.iter().any(|x| x.rule == "baseline_invalid"));
    }

    #[test]
    fn clean_pass() {
        let r = evaluate_policy(
            &PolicyConfig::default(),
            &[
                v("baseline", Verdict::BaselinePass),
                v("py310", Verdict::FuturePass),
            ],
            None,
        );
        assert_eq!(r.decision, PolicyDecision::Pass);
    }

    #[test]
    fn blocked_ratio_gate() {
        let mut p = PolicyConfig::default();
        p.fail_if.baseline_invalid = false;
        p.fail_if.blocked_ratio_above = Some(0.4);
        let r = evaluate_policy(
            &p,
            &[
                v("a", Verdict::Blocked),
                v("b", Verdict::Blocked),
                v("c", Verdict::FuturePass),
            ],
            None,
        );
        assert_eq!(r.decision, PolicyDecision::Fail);
    }
}
