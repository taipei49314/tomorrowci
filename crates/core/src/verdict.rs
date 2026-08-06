//! Verdict authorization: breakage horizon rules and safety invariants.

use crate::domain::{
    BreakageFrontier, EvidenceGrade, ExecutionResult, FailureSignature, Scenario, Verdict,
};

/// Authorize a breakage horizon only under strict conditions (mission §4).
pub fn compute_breakage_frontier(
    baseline_ok: bool,
    ordered_results: &[(Scenario, ExecutionResult)],
    rerun_confirmed_fail: bool,
    replay_command: Option<String>,
) -> BreakageFrontier {
    if !baseline_ok {
        return BreakageFrontier {
            observed: false,
            horizon_label: None,
            first_failing_scenario: None,
            last_passing_scenario: None,
            changed_axes: vec![],
            failure_signature: None,
            grade: EvidenceGrade::Inconclusive,
            replay_command: None,
            notes: vec![
                "No observed breakage horizon: baseline is not BASELINE_PASS.".into(),
            ],
        };
    }

    let mut last_pass: Option<String> = None;
    let mut first_fail: Option<(String, Option<FailureSignature>, String)> = None;

    for (scenario, result) in ordered_results {
        match result.verdict {
            Verdict::BaselinePass | Verdict::FuturePass => {
                last_pass = Some(scenario.id.clone());
            }
            Verdict::FutureFail if rerun_confirmed_fail || scenario.is_baseline => {
                // only treat as horizon when confirmed
                if first_fail.is_none() && !scenario.is_baseline {
                    first_fail = Some((
                        scenario.id.clone(),
                        result.failure.clone(),
                        scenario.runtime.clone(),
                    ));
                    break;
                }
            }
            Verdict::FutureFail => {
                // unconfirmed — do not claim horizon yet
                return BreakageFrontier {
                    observed: false,
                    horizon_label: None,
                    first_failing_scenario: Some(scenario.id.clone()),
                    last_passing_scenario: last_pass,
                    changed_axes: scenario.axes_changed.clone(),
                    failure_signature: result.failure.clone(),
                    grade: EvidenceGrade::Inconclusive,
                    replay_command: None,
                    notes: vec![
                        "First failure not yet confirmed by reruns; horizon not authorized."
                            .into(),
                    ],
                };
            }
            Verdict::Flaky | Verdict::Blocked | Verdict::Unsupported | Verdict::Inconclusive => {
                // skip for horizon search
            }
            Verdict::BaselineInvalid => {}
        }
    }

    match first_fail {
        Some((sid, sig, label)) if rerun_confirmed_fail => BreakageFrontier {
            observed: true,
            horizon_label: Some(label),
            first_failing_scenario: Some(sid.clone()),
            last_passing_scenario: last_pass,
            changed_axes: ordered_results
                .iter()
                .find(|(s, _)| s.id == sid)
                .map(|(s, _)| s.axes_changed.clone())
                .unwrap_or_default(),
            failure_signature: sig,
            grade: EvidenceGrade::Observed,
            replay_command,
            notes: vec!["Breakage horizon authorized after confirmed FUTURE_FAIL.".into()],
        },
        _ => BreakageFrontier {
            observed: false,
            horizon_label: None,
            first_failing_scenario: None,
            last_passing_scenario: last_pass,
            changed_axes: vec![],
            failure_signature: None,
            grade: EvidenceGrade::Inconclusive,
            replay_command: None,
            notes: vec![
                "No observed breakage horizon within tested candidates.".into(),
            ],
        },
    }
}

/// Never convert BLOCKED / UNSUPPORTED / INCONCLUSIVE into PASS.
pub fn enforce_verdict_honesty(v: Verdict) -> Verdict {
    // identity — callers must not map these to pass; this documents the rule in code.
    debug_assert!(
        !matches!(
            v,
            Verdict::Blocked | Verdict::Unsupported | Verdict::Inconclusive
        ) || !v.is_pass_like()
    );
    v
}

/// Classify flaky from rerun outcomes.
pub fn classify_from_reruns(outcomes: &[bool]) -> Verdict {
    // outcomes: true = pass, false = fail
    if outcomes.is_empty() {
        return Verdict::Inconclusive;
    }
    let all_pass = outcomes.iter().all(|o| *o);
    let all_fail = outcomes.iter().all(|o| !*o);
    if all_pass {
        Verdict::FuturePass
    } else if all_fail {
        Verdict::FutureFail
    } else {
        Verdict::Flaky
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EnvironmentAxis, EnvironmentSpec};
    use indexmap::IndexMap;

    fn env() -> EnvironmentSpec {
        EnvironmentSpec {
            image: "python:3.9".into(),
            image_digest: Some("sha256:abc".into()),
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 1024,
            cpus: 1.0,
            pids_limit: 256,
            user: Some("nobody".into()),
            read_only_root: true,
        }
    }

    fn scenario(id: &str, baseline: bool, runtime: &str) -> Scenario {
        Scenario {
            id: id.into(),
            is_baseline: baseline,
            runtime: runtime.into(),
            dependencies: "locked".into(),
            axes_changed: if baseline {
                vec![]
            } else {
                vec![EnvironmentAxis::Runtime]
            },
            candidates: vec![],
            grade: EvidenceGrade::Observed,
        }
    }

    fn result(sid: &str, v: Verdict) -> ExecutionResult {
        ExecutionResult {
            scenario_id: sid.into(),
            attempt: 1,
            verdict: v,
            exit_code: Some(if v.is_pass_like() { 0 } else { 1 }),
            duration_ms: 10,
            timed_out: false,
            failure: if v == Verdict::FutureFail {
                Some(FailureSignature {
                    kind: "ImportError".into(),
                    summary: "cannot import name".into(),
                    normalized_hash: "sha256:x".into(),
                    primary_frame: None,
                })
            } else {
                None
            },
            environment: env(),
            commands: vec![],
        }
    }

    #[test]
    fn no_horizon_without_baseline() {
        let ordered = vec![(
            scenario("b", true, "3.9"),
            result("b", Verdict::BaselineInvalid),
        )];
        let f = compute_breakage_frontier(false, &ordered, true, None);
        assert!(!f.observed);
    }

    #[test]
    fn horizon_when_confirmed() {
        let ordered = vec![
            (scenario("b", true, "3.9"), result("b", Verdict::BaselinePass)),
            (
                scenario("py310", false, "3.10"),
                result("py310", Verdict::FutureFail),
            ),
        ];
        let f = compute_breakage_frontier(
            true,
            &ordered,
            true,
            Some("tomorrowci replay r --scenario py310".into()),
        );
        assert!(f.observed);
        assert_eq!(f.horizon_label.as_deref(), Some("3.10"));
        assert_eq!(f.grade, EvidenceGrade::Observed);
    }

    #[test]
    fn flaky_classification() {
        assert_eq!(
            classify_from_reruns(&[true, false, true]),
            Verdict::Flaky
        );
        assert_eq!(
            classify_from_reruns(&[false, false]),
            Verdict::FutureFail
        );
    }

    #[test]
    fn blocked_not_pass_like() {
        assert!(!Verdict::Blocked.is_pass_like());
        assert!(!Verdict::Unsupported.is_pass_like());
        assert!(!Verdict::Inconclusive.is_pass_like());
        assert!(Verdict::Blocked.may_not_be_promoted_to_pass());
    }
}
