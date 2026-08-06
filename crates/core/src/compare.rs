//! Base/head breakage-horizon comparison for PRs (M4).

use crate::domain::BreakageFrontier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HorizonDelta {
    /// Head has an earlier/new failure that base did not.
    Regression,
    /// Head fixed or delayed a horizon that existed on base.
    Improvement,
    /// Same observation state (both none, or same label).
    Unchanged,
    /// Not enough data (blocked/missing runs).
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HorizonCompare {
    pub delta: HorizonDelta,
    pub base_observed: bool,
    pub head_observed: bool,
    pub base_label: Option<String>,
    pub head_label: Option<String>,
    pub summary: String,
}

pub fn compare_horizons(base: &BreakageFrontier, head: &BreakageFrontier) -> HorizonCompare {
    let base_label = base.horizon_label.clone();
    let head_label = head.horizon_label.clone();
    let (delta, summary) = match (base.observed, head.observed) {
        (false, false) => (
            HorizonDelta::Unchanged,
            "Neither base nor head observed a breakage horizon.".into(),
        ),
        (false, true) => (
            HorizonDelta::Regression,
            format!(
                "Head introduces observed horizon {}; base had none.",
                head_label.as_deref().unwrap_or("?")
            ),
        ),
        (true, false) => (
            HorizonDelta::Improvement,
            format!(
                "Head clears base horizon {}.",
                base_label.as_deref().unwrap_or("?")
            ),
        ),
        (true, true) => {
            if base_label == head_label {
                (
                    HorizonDelta::Unchanged,
                    format!(
                        "Horizon unchanged at {}.",
                        head_label.as_deref().unwrap_or("?")
                    ),
                )
            } else {
                // Different labels: treat as regression if head fails "earlier" string-wise is weak;
                // report as regression when labels differ (PR moved the frontier).
                (
                    HorizonDelta::Regression,
                    format!(
                        "Horizon moved: base={:?} head={:?}.",
                        base_label, head_label
                    ),
                )
            }
        }
    };
    HorizonCompare {
        delta,
        base_observed: base.observed,
        head_observed: head.observed,
        base_label,
        head_label,
        summary,
    }
}

/// Policy gate evaluation for CI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGateResult {
    pub fail: bool,
    pub reasons: Vec<String>,
}

pub fn evaluate_policy_gate(
    baseline_invalid: bool,
    new_future_failure: bool,
    horizon_regression: bool,
    blocked_ratio: f64,
    policy_blocked_ratio_above: Option<f64>,
    fail_if_baseline_invalid: bool,
    fail_if_new_future_failure: bool,
    fail_if_horizon_regression: bool,
) -> PolicyGateResult {
    let mut reasons = Vec::new();
    if fail_if_baseline_invalid && baseline_invalid {
        reasons.push("baseline_invalid".into());
    }
    if fail_if_new_future_failure && new_future_failure {
        reasons.push("new_future_failure".into());
    }
    if fail_if_horizon_regression && horizon_regression {
        reasons.push("horizon_regression".into());
    }
    if let Some(th) = policy_blocked_ratio_above {
        if blocked_ratio > th {
            reasons.push(format!("blocked_ratio_above ({blocked_ratio:.2} > {th:.2})"));
        }
    }
    PolicyGateResult {
        fail: !reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EvidenceGrade;

    fn fr(obs: bool, label: Option<&str>) -> BreakageFrontier {
        BreakageFrontier {
            observed: obs,
            horizon_label: label.map(|s| s.into()),
            first_failing_scenario: None,
            last_passing_scenario: None,
            changed_axes: vec![],
            failure_signature: None,
            grade: EvidenceGrade::Observed,
            replay_command: None,
            notes: vec![],
        }
    }

    #[test]
    fn regression_when_head_new_horizon() {
        let c = compare_horizons(&fr(false, None), &fr(true, Some("3.10")));
        assert_eq!(c.delta, HorizonDelta::Regression);
    }

    #[test]
    fn improvement_when_head_clears() {
        let c = compare_horizons(&fr(true, Some("3.10")), &fr(false, None));
        assert_eq!(c.delta, HorizonDelta::Improvement);
    }

    #[test]
    fn policy_gate_blocks_regression() {
        let g = evaluate_policy_gate(false, false, true, 0.0, Some(0.5), true, true, true);
        assert!(g.fail);
        assert!(g.reasons.iter().any(|r| r.contains("horizon_regression")));
    }
}
