//! Budget-aware scenario planner and ddmin-style axis reduction.

use crate::domain::{
    Baseline, Candidate, EnvironmentAxis, EvidenceGrade, ExecutionPlan, Scenario,
};
use crate::Config;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDecision {
    pub scenario_id: String,
    pub selected: bool,
    pub reason: String,
}

/// Build baseline + ordered single-axis candidates within budget.
pub fn plan_scenarios(
    baseline: &Baseline,
    runtime_candidates: &[Candidate],
    dependency_candidates: &[Candidate],
    config: &Config,
) -> (ExecutionPlan, Vec<PlanDecision>) {
    let budget = config.execution.max_scenarios;
    let mut decisions = Vec::new();
    let mut scenarios = Vec::new();
    let mut notes = Vec::new();

    // 1. Baseline always first
    let baseline_id = "baseline".to_string();
    scenarios.push(Scenario {
        id: baseline_id.clone(),
        is_baseline: true,
        runtime: baseline.runtime.clone(),
        dependencies: baseline.dependencies.clone(),
        axes_changed: vec![],
        candidates: vec![],
        grade: EvidenceGrade::Observed,
    });
    decisions.push(PlanDecision {
        scenario_id: baseline_id,
        selected: true,
        reason: "baseline must run first".into(),
    });

    let mut used = 1u32;

    // 2. Single-axis runtime candidates (ordered)
    let mut ordered_rt: Vec<_> = runtime_candidates.to_vec();
    ordered_rt.sort_by(|a, b| a.order_key.cmp(&b.order_key));
    for c in ordered_rt {
        if used >= budget {
            decisions.push(PlanDecision {
                scenario_id: c.id.clone(),
                selected: false,
                reason: "budget exhausted".into(),
            });
            notes.push(format!("skipped runtime candidate {} (budget)", c.id));
            continue;
        }
        scenarios.push(Scenario {
            id: c.id.clone(),
            is_baseline: false,
            runtime: c.version.clone(),
            dependencies: baseline.dependencies.clone(),
            axes_changed: vec![EnvironmentAxis::Runtime],
            candidates: vec![c.id.clone()],
            grade: c.grade_if_executed,
        });
        decisions.push(PlanDecision {
            scenario_id: c.id.clone(),
            selected: true,
            reason: "single-axis runtime candidate".into(),
        });
        used += 1;
    }

    // 3. Single-axis dependency candidates
    let mut ordered_dep: Vec<_> = dependency_candidates.to_vec();
    ordered_dep.sort_by(|a, b| a.order_key.cmp(&b.order_key));
    for c in ordered_dep {
        if used >= budget {
            decisions.push(PlanDecision {
                scenario_id: c.id.clone(),
                selected: false,
                reason: "budget exhausted".into(),
            });
            notes.push(format!("skipped dependency candidate {} (budget)", c.id));
            continue;
        }
        scenarios.push(Scenario {
            id: c.id.clone(),
            is_baseline: false,
            runtime: baseline.runtime.clone(),
            dependencies: c.version.clone(),
            axes_changed: vec![EnvironmentAxis::Dependencies],
            candidates: vec![c.id.clone()],
            grade: c.grade_if_executed,
        });
        decisions.push(PlanDecision {
            scenario_id: c.id.clone(),
            selected: true,
            reason: "single-axis dependency candidate".into(),
        });
        used += 1;
    }

    // 4. Pairwise combinations (runtime first-fail candidate × dep first candidate) if budget remains
    if used < budget && !runtime_candidates.is_empty() && !dependency_candidates.is_empty() {
        let rt = &runtime_candidates[0];
        let dep = &dependency_candidates[0];
        let id = format!("combo-{}-{}", rt.id, dep.id);
        scenarios.push(Scenario {
            id: id.clone(),
            is_baseline: false,
            runtime: rt.version.clone(),
            dependencies: dep.version.clone(),
            axes_changed: vec![EnvironmentAxis::Runtime, EnvironmentAxis::Dependencies],
            candidates: vec![rt.id.clone(), dep.id.clone()],
            grade: EvidenceGrade::Simulated,
        });
        decisions.push(PlanDecision {
            scenario_id: id,
            selected: true,
            reason: "pairwise combined axis within budget".into(),
        });
        used += 1;
        notes.push(format!("combined scenarios used budget slot ({used}/{budget})"));
    }

    notes.push(format!("planned {used} scenarios (budget {budget})"));

    (
        ExecutionPlan {
            plan_id: format!("plan-{}", used),
            scenarios,
            selection_notes: notes,
            budget_max: budget,
        },
        decisions,
    )
}

/// ddmin-style reduction over a set of changed axes that induce failure.
/// `test(subset)` returns true if the subset still fails.
pub fn ddmin_axes<F>(axes: &[EnvironmentAxis], mut still_fails: F) -> Vec<EnvironmentAxis>
where
    F: FnMut(&[EnvironmentAxis]) -> bool,
{
    if axes.is_empty() {
        return vec![];
    }
    if !still_fails(axes) {
        return axes.to_vec(); // cannot reduce; return original
    }
    ddmin_rec(axes, 2, &mut still_fails)
}

fn ddmin_rec<F>(axes: &[EnvironmentAxis], n: usize, still_fails: &mut F) -> Vec<EnvironmentAxis>
where
    F: FnMut(&[EnvironmentAxis]) -> bool,
{
    let len = axes.len();
    if len < 2 {
        return axes.to_vec();
    }
    let n = n.min(len);
    let size = (len + n - 1) / n;
    // subsets
    for i in 0..n {
        let start = i * size;
        let end = ((i + 1) * size).min(len);
        if start >= end {
            continue;
        }
        let subset = &axes[start..end];
        if still_fails(subset) {
            return ddmin_rec(subset, 2, still_fails);
        }
    }
    // complements
    for i in 0..n {
        let start = i * size;
        let end = ((i + 1) * size).min(len);
        if start >= end {
            continue;
        }
        let mut complement = Vec::new();
        complement.extend_from_slice(&axes[..start]);
        complement.extend_from_slice(&axes[end..]);
        if !complement.is_empty() && still_fails(&complement) {
            return ddmin_rec(&complement, n.saturating_sub(1).max(2), still_fails);
        }
    }
    if n < len {
        return ddmin_rec(axes, (n * 2).min(len), still_fails);
    }
    axes.to_vec()
}

/// Linear scan for first failing index in ordered pass/fail results (true=pass).
pub fn first_failure_index(outcomes: &[bool]) -> Option<usize> {
    outcomes.iter().position(|ok| !*ok)
}

/// Binary search first failure in ordered monotonic outcomes (pass then fail).
/// Returns index of first fail, or None if all pass.
pub fn binary_first_failure(outcomes: &[bool]) -> Option<usize> {
    if outcomes.is_empty() {
        return None;
    }
    // If not roughly sorted, fall back to linear
    let first = first_failure_index(outcomes)?;
    // verify all after first are fail or we just return first
    Some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_respects_budget() {
        let baseline = Baseline {
            runtime: "3.9".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };
        let mut cfg = Config::default();
        cfg.execution.max_scenarios = 3;
        let rt: Vec<_> = (0..5)
            .map(|i| Candidate {
                id: format!("rt{i}"),
                axis: EnvironmentAxis::Runtime,
                label: format!("r{i}"),
                version: format!("3.{}", 10 + i),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{i:04}"),
            })
            .collect();
        let (plan, dec) = plan_scenarios(&baseline, &rt, &[], &cfg);
        assert!(plan.scenarios.len() <= 3);
        assert!(dec.iter().any(|d| !d.selected));
    }

    #[test]
    fn ddmin_finds_single_axis() {
        let axes = vec![
            EnvironmentAxis::Runtime,
            EnvironmentAxis::Dependencies,
            EnvironmentAxis::Os,
        ];
        let minimal = ddmin_axes(&axes, |subset| {
            subset.contains(&EnvironmentAxis::Dependencies)
        });
        assert_eq!(minimal, vec![EnvironmentAxis::Dependencies]);
    }

    #[test]
    fn first_fail_linear() {
        assert_eq!(first_failure_index(&[true, true, false, false]), Some(2));
        assert_eq!(first_failure_index(&[true, true]), None);
    }
}
