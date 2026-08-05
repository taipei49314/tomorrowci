//! Budget-aware scenario planner with search-space reduction.

use crate::config::Config;
use crate::domain::{
    Candidate, DependencyMode, EnvironmentAxis, EvidenceGrade, ExecutionPlan, PlanDecisionRecord,
    RunId, Scenario, ScenarioId, ScenarioKind, UntestedArea,
};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct PlanDecision {
    pub action: String,
    pub reason: String,
    pub scenario_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlannerOutput {
    pub plan: ExecutionPlan,
    pub decisions: Vec<PlanDecision>,
}

pub struct Planner {
    pub run_id: RunId,
    pub config: Config,
}

impl Planner {
    pub fn new(run_id: RunId, config: Config) -> Self {
        Self { run_id, config }
    }

    /// Build an initial plan: baseline first, then ordered single-axis candidates.
    /// Combined scenarios are added by the engine after single-axis results.
    pub fn plan_initial(
        &self,
        baseline: Scenario,
        runtime_candidates: Vec<Candidate>,
        dep_candidates: Vec<Candidate>,
    ) -> Result<PlannerOutput> {
        let budget = self.config.execution.max_scenarios;
        let mut scenarios = Vec::new();
        let mut decisions = Vec::new();
        let mut untested = Vec::new();

        // 1. Baseline always first
        decisions.push(PlanDecision {
            action: "select".into(),
            reason: "baseline must pass before future comparisons are authorized".into(),
            scenario_id: Some(baseline.id.0.clone()),
        });
        scenarios.push(baseline);

        // 2. Ordered single-axis runtime candidates
        let mut ordered_runtime = runtime_candidates;
        ordered_runtime.sort_by(|a, b| a.order_key.cmp(&b.order_key));
        if ordered_runtime.len() > self.config.candidates.runtime.max_versions {
            for c in ordered_runtime
                .iter()
                .skip(self.config.candidates.runtime.max_versions)
            {
                untested.push(UntestedArea {
                    axis: EnvironmentAxis::Runtime,
                    label: c.label.clone(),
                    reason: format!(
                        "exceeded candidates.runtime.max_versions={}",
                        self.config.candidates.runtime.max_versions
                    ),
                });
                decisions.push(PlanDecision {
                    action: "skip".into(),
                    reason: "max_versions budget".into(),
                    scenario_id: Some(c.id.clone()),
                });
            }
            ordered_runtime.truncate(self.config.candidates.runtime.max_versions);
        }

        for c in ordered_runtime {
            if scenarios.len() >= budget {
                untested.push(UntestedArea {
                    axis: c.axis.clone(),
                    label: c.label.clone(),
                    reason: format!("scenario budget exhausted (max_scenarios={budget})"),
                });
                decisions.push(PlanDecision {
                    action: "skip".into(),
                    reason: "max_scenarios budget".into(),
                    scenario_id: Some(c.id.clone()),
                });
                continue;
            }
            let sc = candidate_to_scenario(&c, ScenarioKind::SingleAxis);
            decisions.push(PlanDecision {
                action: "select".into(),
                reason: "single-axis runtime candidate in order".into(),
                scenario_id: Some(sc.id.0.clone()),
            });
            scenarios.push(sc);
        }

        // 3. Dependency single-axis
        for c in dep_candidates {
            if scenarios.len() >= budget {
                untested.push(UntestedArea {
                    axis: EnvironmentAxis::Dependencies,
                    label: c.label.clone(),
                    reason: format!("scenario budget exhausted (max_scenarios={budget})"),
                });
                decisions.push(PlanDecision {
                    action: "skip".into(),
                    reason: "max_scenarios budget".into(),
                    scenario_id: Some(c.id.clone()),
                });
                continue;
            }
            let sc = candidate_to_scenario(&c, ScenarioKind::SingleAxis);
            decisions.push(PlanDecision {
                action: "select".into(),
                reason: "single-axis dependency candidate".into(),
                scenario_id: Some(sc.id.0.clone()),
            });
            scenarios.push(sc);
        }

        let plan = ExecutionPlan {
            run_id: self.run_id.clone(),
            max_scenarios: budget,
            decisions: decisions
                .iter()
                .map(|d| PlanDecisionRecord {
                    scenario_id: d.scenario_id.clone(),
                    action: d.action.clone(),
                    reason: d.reason.clone(),
                })
                .collect(),
            scenarios,
            untested,
        };

        Ok(PlannerOutput { plan, decisions })
    }

    /// Locate first failing index in an ordered result list.
    /// Uses linear scan for small sets, binary search for larger ordered sets.
    pub fn first_failure_index(ordered_pass: &[bool]) -> Option<usize> {
        if ordered_pass.len() <= 8 {
            return ordered_pass.iter().position(|&p| !p);
        }
        // Binary search for first false, assuming monotonic failure horizon
        // (once fail, later may also fail). Falls back to linear if non-monotonic.
        let mut lo = 0usize;
        let mut hi = ordered_pass.len();
        let mut found = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if ordered_pass[mid] {
                lo = mid + 1;
            } else {
                found = Some(mid);
                hi = mid;
            }
        }
        // Verify monotonic assumption; if not, linear
        if let Some(i) = found {
            if ordered_pass.iter().take(i).all(|&p| p) {
                return Some(i);
            }
        }
        ordered_pass.iter().position(|&p| !p)
    }

    /// Propose pairwise combined scenarios within remaining budget.
    pub fn propose_combined(
        &self,
        runtime_pass_ids: &[(String, String)], // (scenario_id, runtime_version)
        dep_pass_ids: &[(String, DependencyMode)],
        remaining_budget: usize,
    ) -> Vec<Scenario> {
        let mut out = Vec::new();
        if remaining_budget == 0 {
            return out;
        }
        for (rt_id, rt_ver) in runtime_pass_ids {
            for (dep_id, dep_mode) in dep_pass_ids {
                if out.len() >= remaining_budget {
                    break;
                }
                // Skip pure baseline-equivalent
                if dep_mode == &DependencyMode::Locked {
                    continue;
                }
                let id = format!("combined-{}-{}", rt_id, dep_id);
                out.push(Scenario {
                    id: ScenarioId::new(id.clone()),
                    kind: ScenarioKind::Combined,
                    ecosystem: crate::domain::Ecosystem::Python, // filled by engine
                    label: format!("{rt_ver} + {dep_mode}"),
                    runtime_version: rt_ver.clone(),
                    dependency_mode: dep_mode.clone(),
                    image_ref: String::new(),
                    axes_changed: vec![EnvironmentAxis::Runtime, EnvironmentAxis::Dependencies],
                    evidence_grade: EvidenceGrade::Simulated,
                    is_baseline: false,
                    selection_reason: "pairwise combination after single-axis passes".into(),
                });
            }
        }
        out
    }
}

fn candidate_to_scenario(c: &Candidate, kind: ScenarioKind) -> Scenario {
    Scenario {
        id: ScenarioId::new(c.id.clone()),
        kind,
        ecosystem: crate::domain::Ecosystem::Python,
        label: c.label.clone(),
        runtime_version: c.runtime_version.clone().unwrap_or_default(),
        dependency_mode: c.dependency_mode.clone(),
        image_ref: c.image_ref.clone(),
        axes_changed: vec![c.axis.clone()],
        evidence_grade: c.evidence_grade,
        is_baseline: false,
        selection_reason: format!("candidate on axis {}", c.axis),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Ecosystem;

    fn baseline() -> Scenario {
        Scenario {
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
            selection_reason: "baseline".into(),
        }
    }

    fn rt(id: &str, ver: &str, order: &str) -> Candidate {
        Candidate {
            id: id.into(),
            axis: EnvironmentAxis::Runtime,
            label: format!("Python {ver}"),
            runtime_version: Some(ver.into()),
            dependency_mode: DependencyMode::Locked,
            image_ref: format!("python:{ver}"),
            channel: "stable".into(),
            order_key: order.into(),
            evidence_grade: EvidenceGrade::Observed,
            notes: vec![],
        }
    }

    #[test]
    fn baseline_first_and_budget() {
        let mut cfg = Config::default();
        cfg.execution.max_scenarios = 3;
        cfg.candidates.runtime.max_versions = 10;
        let planner = Planner::new(RunId::new(), cfg);
        let cands = vec![
            rt("a", "3.10", "3.10"),
            rt("b", "3.11", "3.11"),
            rt("c", "3.12", "3.12"),
        ];
        let out = planner.plan_initial(baseline(), cands, vec![]).unwrap();
        assert_eq!(out.plan.scenarios.len(), 3);
        assert!(out.plan.scenarios[0].is_baseline);
        assert!(!out.plan.untested.is_empty());
    }

    #[test]
    fn first_failure_linear() {
        assert_eq!(Planner::first_failure_index(&[true, true, false]), Some(2));
        assert_eq!(Planner::first_failure_index(&[true, true]), None);
    }

    #[test]
    fn first_failure_binary_monotonic() {
        let v: Vec<bool> = (0..20).map(|i| i < 12).collect();
        assert_eq!(Planner::first_failure_index(&v), Some(12));
    }
}
