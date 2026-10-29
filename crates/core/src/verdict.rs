//! Verdict authorization: breakage horizon rules and safety invariants.

use crate::domain::{
    BreakageFrontier, EvidenceGrade, ExecutionResult, FailureSignature, Scenario,
    TestAttemptRecord, Verdict,
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
            notes: vec!["No observed breakage horizon: baseline is not BASELINE_PASS.".into()],
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
                        "First failure not yet confirmed by reruns; horizon not authorized.".into(),
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
            grade: ordered_results
                .iter()
                .find(|(scenario, _)| scenario.id == sid)
                .map(|(scenario, _)| scenario.grade)
                .unwrap_or(EvidenceGrade::Inconclusive),
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
            notes: vec!["No observed breakage horizon within tested candidates.".into()],
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

/// Classify a non-baseline live candidate from its semantic attempt records.
/// A repeatable failure requires two or more failures with one normalized
/// signature; signature drift remains inconclusive.
pub fn classify_candidate_attempts(attempts: &[TestAttemptRecord]) -> Verdict {
    if attempts.is_empty() {
        return Verdict::Inconclusive;
    }
    let passes: Vec<_> = attempts
        .iter()
        .map(|attempt| attempt.exit_code == Some(0) && !attempt.timed_out)
        .collect();
    if passes.iter().all(|passed| *passed) {
        return Verdict::FuturePass;
    }
    if passes.iter().any(|passed| *passed) {
        return Verdict::Flaky;
    }
    if attempts.len() < 2 {
        return Verdict::Inconclusive;
    }
    let mut hashes = attempts.iter().map(|attempt| {
        attempt
            .failure
            .as_ref()
            .map(|failure| failure.normalized_hash.as_str())
    });
    let first = hashes.next().flatten();
    if first.is_some() && hashes.all(|hash| hash == first) {
        Verdict::FutureFail
    } else {
        Verdict::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EnvironmentAxis, EnvironmentSpec};
    use chrono::Utc;
    use indexmap::IndexMap;

    fn env() -> EnvironmentSpec {
        EnvironmentSpec {
            image_tag: "python:3.9".into(),
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
            scenario_state_root: None,
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
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
            resolved_dependencies: None,
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

    fn failed_attempt(hash: &str) -> TestAttemptRecord {
        let now = Utc::now();
        TestAttemptRecord {
            workspace_preparation: None,
            attempt: 1,
            started_at: now,
            finished_at: now,
            exit_code: Some(1),
            timed_out: false,
            duration_ms: 1,
            failure: Some(FailureSignature {
                kind: "DependencyApiBreak".into(),
                summary: "TOMORROWCI_DEPENDENCY_BREAK".into(),
                normalized_hash: hash.into(),
                primary_frame: None,
            }),
        }
    }

    #[test]
    fn stable_failure_requires_matching_normalized_hashes() {
        let stable = vec![
            failed_attempt(&format!("sha256:{}", "a".repeat(64))),
            failed_attempt(&format!("sha256:{}", "a".repeat(64))),
        ];
        assert_eq!(classify_candidate_attempts(&stable), Verdict::FutureFail);

        let drift = vec![
            failed_attempt(&format!("sha256:{}", "a".repeat(64))),
            failed_attempt(&format!("sha256:{}", "b".repeat(64))),
        ];
        assert_eq!(classify_candidate_attempts(&drift), Verdict::Inconclusive);
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
            (
                scenario("b", true, "3.9"),
                result("b", Verdict::BaselinePass),
            ),
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
        assert_eq!(classify_from_reruns(&[true, false, true]), Verdict::Flaky);
        assert_eq!(classify_from_reruns(&[false, false]), Verdict::FutureFail);
    }

    #[test]
    fn blocked_not_pass_like() {
        assert!(!Verdict::Blocked.is_pass_like());
        assert!(!Verdict::Unsupported.is_pass_like());
        assert!(!Verdict::Inconclusive.is_pass_like());
        assert!(Verdict::Blocked.may_not_be_promoted_to_pass());
    }
}
