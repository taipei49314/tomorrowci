//! Deterministic verdict authorization and classification.

use crate::domain::{
    BreakageFrontier, EnvironmentAxis, EvidenceGrade, FailureSignature, Scenario, ScenarioVerdict,
    Verdict,
};

/// Classify a single scenario from execution outcomes (deterministic).
pub fn classify_scenario(
    scenario: &Scenario,
    outcomes: &[bool],
    failure: Option<FailureSignature>,
    blocked: Option<String>,
    unsupported: Option<String>,
) -> ScenarioVerdict {
    let mut notes = Vec::new();
    if let Some(reason) = unsupported {
        return ScenarioVerdict {
            scenario_id: scenario.id.clone(),
            label: scenario.label.clone(),
            verdict: Verdict::Unsupported,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: outcomes.len() as u32,
            failure_signature: None,
            evidence: None,
            notes: vec![reason],
        };
    }
    if let Some(reason) = blocked {
        return ScenarioVerdict {
            scenario_id: scenario.id.clone(),
            label: scenario.label.clone(),
            verdict: Verdict::Blocked,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: outcomes.len() as u32,
            failure_signature: None,
            evidence: None,
            notes: vec![reason],
        };
    }
    if outcomes.is_empty() {
        return ScenarioVerdict {
            scenario_id: scenario.id.clone(),
            label: scenario.label.clone(),
            verdict: Verdict::Inconclusive,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: 0,
            failure_signature: None,
            evidence: None,
            notes: vec!["no execution outcomes recorded".into()],
        };
    }

    let passes = outcomes.iter().filter(|&&o| o).count();
    let fails = outcomes.len() - passes;

    let verdict = if scenario.is_baseline {
        if fails == 0 {
            Verdict::BaselinePass
        } else if passes == 0 {
            Verdict::BaselineInvalid
        } else {
            notes.push("baseline produced inconsistent outcomes".into());
            Verdict::Flaky
        }
    } else if fails == 0 {
        Verdict::FuturePass
    } else if passes == 0 {
        Verdict::FutureFail
    } else {
        notes.push("inconsistent outcomes across reruns".into());
        Verdict::Flaky
    };

    ScenarioVerdict {
        scenario_id: scenario.id.clone(),
        label: scenario.label.clone(),
        verdict,
        evidence_grade: scenario.evidence_grade,
        attempts: outcomes.len() as u32,
        failure_signature: failure,
        evidence: None,
        notes,
    }
}

#[derive(Debug, Clone)]
pub struct FrontierAuthorization {
    pub allowed: bool,
    pub reason: String,
}

/// A Breakage Horizon may only be emitted when all authorization rules pass.
pub fn authorize_frontier(
    baseline: Option<&ScenarioVerdict>,
    ordered: &[ScenarioVerdict],
    first_fail: Option<&ScenarioVerdict>,
    prior_pass: Option<&ScenarioVerdict>,
    has_replay: bool,
    has_evidence_dir: bool,
) -> (FrontierAuthorization, BreakageFrontier) {
    let none_frontier = |msg: &str| {
        (
            FrontierAuthorization {
                allowed: false,
                reason: msg.to_string(),
            },
            BreakageFrontier {
                observed: false,
                horizon_label: None,
                scenario_id: None,
                axis: None,
                from_label: None,
                to_label: None,
                failure_signature: None,
                evidence_grade: None,
                replay_command: None,
                explanation: msg.to_string(),
            },
        )
    };

    let Some(baseline) = baseline else {
        return none_frontier("No baseline verdict; future comparisons are not authorized.");
    };
    if baseline.verdict != Verdict::BaselinePass {
        return none_frontier(
            "Baseline did not pass; future comparisons are not authorized. No observed breakage horizon.",
        );
    }

    let Some(fail) = first_fail else {
        return none_frontier("No observed breakage horizon within tested candidates.");
    };
    if fail.verdict != Verdict::FutureFail {
        return none_frontier(
            "First candidate failure is not a reproducible FUTURE_FAIL; horizon not authorized.",
        );
    }
    if fail.attempts < 2 {
        return none_frontier(
            "First failing candidate was not rerun; horizon requires consistent failure.",
        );
    }
    if let Some(prior) = prior_pass {
        if !matches!(
            prior.verdict,
            Verdict::BaselinePass | Verdict::FuturePass
        ) {
            return none_frontier(
                "Immediately earlier candidate did not pass; horizon not authorized.",
            );
        }
    }
    // If no prior exists, still allowed (first candidate fails).
    if !has_replay || !has_evidence_dir {
        return none_frontier(
            "Replay command or evidence directory missing; horizon not authorized.",
        );
    }

    // Ensure at least one FUTURE_FAIL exists in ordered set
    if !ordered.iter().any(|v| v.verdict == Verdict::FutureFail) {
        return none_frontier("No FUTURE_FAIL candidates observed.");
    }

    let explanation = format!(
        "Observed breakage horizon at '{}'. Minimal changed axis relative to prior passing environment. Evidence grade: {:?}. Suspected cause correlates with failure signature (correlation, not proven root cause).",
        fail.label, fail.evidence_grade
    );

    (
        FrontierAuthorization {
            allowed: true,
            reason: "all horizon authorization rules satisfied".into(),
        },
        BreakageFrontier {
            observed: true,
            horizon_label: Some(fail.label.clone()),
            scenario_id: Some(fail.scenario_id.clone()),
            axis: Some(EnvironmentAxis::Runtime),
            from_label: prior_pass.map(|p| p.label.clone()).or_else(|| {
                Some(baseline.label.clone())
            }),
            to_label: Some(fail.label.clone()),
            failure_signature: fail.failure_signature.clone(),
            evidence_grade: Some(fail.evidence_grade),
            replay_command: Some(format!(
                "tomorrowci replay <run-id> --scenario {}",
                fail.scenario_id
            )),
            explanation,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        DependencyMode, Ecosystem, EvidenceGrade, ScenarioId, ScenarioKind,
    };

    fn sc(id: &str, baseline: bool) -> Scenario {
        Scenario {
            id: ScenarioId::new(id),
            kind: if baseline {
                ScenarioKind::Baseline
            } else {
                ScenarioKind::SingleAxis
            },
            ecosystem: Ecosystem::Python,
            label: id.into(),
            runtime_version: "3.10".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.10".into(),
            axes_changed: vec![],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: baseline,
            selection_reason: "test".into(),
        }
    }

    #[test]
    fn baseline_fail_blocks_horizon() {
        let baseline = classify_scenario(&sc("base", true), &[false, false], None, None, None);
        assert_eq!(baseline.verdict, Verdict::BaselineInvalid);
        let (auth, frontier) =
            authorize_frontier(Some(&baseline), &[], None, None, true, true);
        assert!(!auth.allowed);
        assert!(!frontier.observed);
    }

    #[test]
    fn flaky_not_future_fail() {
        let s = sc("py311", false);
        let v = classify_scenario(&s, &[true, false], None, None, None);
        assert_eq!(v.verdict, Verdict::Flaky);
    }

    #[test]
    fn horizon_requires_rerun() {
        let baseline = classify_scenario(&sc("base", true), &[true], None, None, None);
        let fail = ScenarioVerdict {
            scenario_id: ScenarioId::new("f"),
            label: "py310".into(),
            verdict: Verdict::FutureFail,
            evidence_grade: EvidenceGrade::Observed,
            attempts: 1,
            failure_signature: None,
            evidence: None,
            notes: vec![],
        };
        let (auth, _) =
            authorize_frontier(Some(&baseline), &[fail.clone()], Some(&fail), None, true, true);
        assert!(!auth.allowed);
    }

    #[test]
    fn horizon_authorized_when_rules_met() {
        let baseline = classify_scenario(&sc("base", true), &[true, true], None, None, None);
        let fail = ScenarioVerdict {
            scenario_id: ScenarioId::new("py310"),
            label: "Python 3.10 + locked".into(),
            verdict: Verdict::FutureFail,
            evidence_grade: EvidenceGrade::Observed,
            attempts: 2,
            failure_signature: Some(FailureSignature {
                kind: "ImportError".into(),
                summary: "MutableMapping".into(),
                primary_error: Some("ImportError".into()),
                fingerprint: "abc".into(),
                framework_hints: vec![],
                evidence_grade: EvidenceGrade::Observed,
            }),
            evidence: None,
            notes: vec![],
        };
        let (auth, frontier) = authorize_frontier(
            Some(&baseline),
            &[fail.clone()],
            Some(&fail),
            Some(&baseline),
            true,
            true,
        );
        assert!(auth.allowed);
        assert!(frontier.observed);
        assert_eq!(frontier.horizon_label.as_deref(), Some("Python 3.10 + locked"));
    }

    #[test]
    fn blocked_not_converted_to_pass() {
        let s = sc("x", false);
        let v = classify_scenario(&s, &[], None, Some("no docker".into()), None);
        assert_eq!(v.verdict, Verdict::Blocked);
        assert!(!v.verdict.is_pass());
    }
}
