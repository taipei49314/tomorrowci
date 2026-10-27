//! Deterministic, bounded selection of live dependency reduction probes.
//!
//! Each observation is the aggregate result of one scenario, including its
//! reruns. The caller must establish a passing baseline, enforce its scenario
//! budget, and verify each recorded request against the preceding observations.
//! `None` means no further safe probe is selected, not that minimality is proven.

use crate::{ContentHash, DependencyProbeVerdict, EvidenceGrade, Result, TcError};
use std::collections::{BTreeMap, BTreeSet};

/// The scenario evidence needed to choose the next concrete dependency subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyScheduleObservation {
    pub change_ids: Vec<String>,
    pub verdict: DependencyProbeVerdict,
    pub failure_hash: Option<ContentHash>,
    pub attempts: u32,
    pub authority: EvidenceGrade,
}

/// Short, content-derived identities keep large experiments portable to
/// filesystems with bounded component lengths. The full candidate retains its
/// declared identity for compatibility with the reduction evidence contract.
pub fn adaptive_dependency_probe_id(
    full_id: &str,
    original_ids: &[String],
    subset_ids: &[String],
) -> Result<String> {
    let mut original = original_ids.to_vec();
    original.sort();
    let mut subset = subset_ids.to_vec();
    subset.sort();
    if subset.is_empty()
        || subset.windows(2).any(|pair| pair[0] == pair[1])
        || subset.iter().any(|id| !original.contains(id))
    {
        return Err(invalid("probe identity requires a nonempty exact subset"));
    }
    if subset == original {
        return Ok(full_id.to_owned());
    }
    let hash = crate::sha256_bytes(&serde_json::to_vec(&subset)?);
    Ok(format!("dep-{}", &hash.trim_start_matches("sha256:")[..20]))
}

/// Select the next nonempty subset without enumerating the power set.
///
/// The full candidate runs first. Once it has at least three observed failures
/// with one hash, sorted single-change deletions reduce that same failure. Each
/// new stable reduction restarts the deletion search. A cached result is reused
/// only for its exact subset. The final additions and subtractions required by
/// the live reduction proof must also be observed; an empty subtraction uses
/// the caller's passing baseline and is never scheduled here.
///
/// This finds a deterministic 1-minimal candidate, not a globally minimum set.
/// Blocked, flaky, simulated, and underconfirmed results stop the search rather
/// than becoming evidence that a change is necessary or irrelevant. The caller
/// still derives the final proof and status from the recorded evidence.
pub fn next_dependency_subset(
    original_ids: &[String],
    observations: &[DependencyScheduleObservation],
) -> Result<Option<Vec<String>>> {
    if original_ids.is_empty() || original_ids.len() > 64 {
        return Err(invalid(
            "dependency scheduling requires between one and 64 changes",
        ));
    }
    let mut original = original_ids.to_vec();
    original.sort();
    if original.iter().any(|id| id.trim().is_empty())
        || original.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(invalid(
            "dependency scheduling requires unique, nonempty change IDs",
        ));
    }
    let declared: BTreeSet<_> = original.iter().map(String::as_str).collect();
    let mut by_subset = BTreeMap::new();
    for observation in observations {
        let mut ids = observation.change_ids.clone();
        ids.sort();
        if ids.is_empty()
            || ids.windows(2).any(|pair| pair[0] == pair[1])
            || ids.iter().any(|id| !declared.contains(id.as_str()))
        {
            return Err(invalid(
                "dependency observation is not a nonempty exact subset",
            ));
        }
        match observation.verdict {
            DependencyProbeVerdict::Fail if observation.failure_hash.is_none() => {
                return Err(invalid("failed dependency observation has no failure hash"));
            }
            DependencyProbeVerdict::Pass if observation.failure_hash.is_some() => {
                return Err(invalid("passing dependency observation has a failure hash"));
            }
            DependencyProbeVerdict::Pass | DependencyProbeVerdict::Fail
                if observation.attempts == 0 =>
            {
                return Err(invalid(
                    "completed dependency observation has no test attempts",
                ));
            }
            _ => {}
        }
        if by_subset.insert(ids, observation).is_some() {
            return Err(invalid("dependency observations repeat an exact subset"));
        }
    }

    if observations.is_empty() {
        return Ok(Some(original));
    }
    let mut first_ids = observations[0].change_ids.clone();
    first_ids.sort();
    if first_ids != original {
        return Err(invalid(
            "the first dependency observation must be the full candidate",
        ));
    }
    let full = by_subset
        .get(&original)
        .expect("the first observation is the full candidate");
    let Some(target_hash) = full.failure_hash.as_ref() else {
        return Ok(None);
    };
    if !stable_target_failure(full, target_hash) {
        return Ok(None);
    }

    // Choosing the smallest observed matching failure on every call implements
    // the restart after a successful deletion and agrees with reduction.json's
    // deterministic size/lexical tie break. No unobserved subset is assumed.
    let current = by_subset
        .iter()
        .filter(|(_, observation)| stable_target_failure(observation, target_hash))
        .map(|(ids, _)| ids)
        .min_by(|left, right| left.len().cmp(&right.len()).then(left.cmp(right)))
        .expect("the stable full failure is present")
        .clone();

    // At most one deletion per current member is considered. A new matching
    // failure is adopted on the next call, so the search has at most n levels.
    // These exact observations also supply the final subtraction proof.
    for removed in &current {
        let remaining: Vec<_> = current
            .iter()
            .filter(|id| *id != removed)
            .cloned()
            .collect();
        if remaining.is_empty() {
            continue;
        }
        let Some(observation) = by_subset.get(&remaining) else {
            return Ok(Some(remaining));
        };
        if !decisive_non_target(observation, target_hash) {
            return Ok(None);
        }
    }

    // Excluded changes must each preserve the failure when restored to the
    // final subset. A search observation for a larger set cannot stand in for
    // this exact addition. Cache reuse matches the existing live proof rules.
    for added in original.iter().filter(|id| !current.contains(id)) {
        let mut combined = current.clone();
        combined.push(added.clone());
        combined.sort();
        let Some(observation) = by_subset.get(&combined) else {
            return Ok(Some(combined));
        };
        if !stable_target_failure(observation, target_hash) {
            return Ok(None);
        }
    }
    Ok(None)
}

fn stable_target_failure(
    observation: &DependencyScheduleObservation,
    target_hash: &ContentHash,
) -> bool {
    observation.authority == EvidenceGrade::Observed
        && observation.verdict == DependencyProbeVerdict::Fail
        && observation.failure_hash.as_ref() == Some(target_hash)
        && observation.attempts >= 3
}

fn decisive_non_target(
    observation: &DependencyScheduleObservation,
    target_hash: &ContentHash,
) -> bool {
    observation.authority == EvidenceGrade::Observed
        && match observation.verdict {
            DependencyProbeVerdict::Pass => observation.attempts >= 1,
            DependencyProbeVerdict::Fail => {
                observation.attempts >= 2 && observation.failure_hash.as_ref() != Some(target_hash)
            }
            _ => false,
        }
}

fn invalid(message: &str) -> TcError {
    TcError::InvalidState(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    fn observed(change_ids: Vec<String>, fails: bool) -> DependencyScheduleObservation {
        DependencyScheduleObservation {
            change_ids,
            verdict: if fails {
                DependencyProbeVerdict::Fail
            } else {
                DependencyProbeVerdict::Pass
            },
            failure_hash: fails.then(|| ContentHash::of_bytes(b"target failure")),
            attempts: if fails { 3 } else { 1 },
            authority: EvidenceGrade::Observed,
        }
    }

    #[test]
    fn full_first_then_restarts_deletions_and_requests_exact_addition_proof() {
        let original = ids(&["c", "a", "b"]);
        let mut history = Vec::new();
        for expected in [
            ids(&["a", "b", "c"]),
            ids(&["b", "c"]),
            ids(&["c"]),
            ids(&["a", "c"]),
        ] {
            assert_eq!(
                next_dependency_subset(&original, &history).unwrap(),
                Some(expected.clone())
            );
            history.push(observed(expected, true));
        }
        assert_eq!(next_dependency_subset(&original, &history).unwrap(), None);
    }

    #[test]
    fn twelve_changes_reduce_and_prove_without_exhaustive_enumeration() {
        let original: Vec<_> = (0..12).map(|index| format!("change-{index:02}")).collect();
        let mut history = Vec::new();
        while let Some(next) = next_dependency_subset(&original, &history).unwrap() {
            assert!(
                history.len() < 3 * original.len(),
                "scheduler did not converge"
            );
            assert!(!history
                .iter()
                .any(|record: &DependencyScheduleObservation| record.change_ids == next));
            let fails = next.contains(&original[0]);
            history.push(observed(next, fails));
        }
        let minimal = history
            .iter()
            .filter(|record| record.verdict == DependencyProbeVerdict::Fail)
            .min_by_key(|record| record.change_ids.len())
            .unwrap();
        assert_eq!(minimal.change_ids, vec![original[0].clone()]);
        for excluded in &original[1..] {
            assert!(history.iter().any(|record| record.change_ids
                == vec![original[0].clone(), excluded.clone()]
                && record.verdict == DependencyProbeVerdict::Fail));
        }
        assert!(history.len() <= 3 * original.len());
    }

    #[test]
    fn all_changes_necessary_requires_only_full_and_single_subtractions() {
        let original: Vec<_> = (0..12).map(|index| format!("change-{index:02}")).collect();
        let mut history = Vec::new();
        while let Some(next) = next_dependency_subset(&original, &history).unwrap() {
            assert!(history.len() <= original.len());
            let fails = next == original;
            history.push(observed(next, fails));
        }
        assert_eq!(history.len(), original.len() + 1);
    }

    #[test]
    fn uncertain_subtractions_never_become_negative_evidence() {
        let original = ids(&["a", "b", "c"]);
        for verdict in [
            DependencyProbeVerdict::Blocked,
            DependencyProbeVerdict::Flaky,
            DependencyProbeVerdict::Inconclusive,
        ] {
            let mut uncertain = observed(ids(&["b", "c"]), true);
            uncertain.verdict = verdict;
            let history = vec![observed(original.clone(), true), uncertain];
            assert_eq!(next_dependency_subset(&original, &history).unwrap(), None);
        }
        let mut underconfirmed = observed(ids(&["b", "c"]), true);
        underconfirmed.attempts = 2;
        assert_eq!(
            next_dependency_subset(
                &original,
                &[observed(original.clone(), true), underconfirmed]
            )
            .unwrap(),
            None
        );
        let mut simulated = observed(ids(&["b", "c"]), false);
        simulated.authority = EvidenceGrade::Simulated;
        assert_eq!(
            next_dependency_subset(&original, &[observed(original.clone(), true), simulated])
                .unwrap(),
            None
        );
    }

    #[test]
    fn distinct_confirmed_failure_is_negative_evidence_but_does_not_shrink_target() {
        let original = ids(&["a", "b", "c"]);
        let mut different = observed(ids(&["b", "c"]), true);
        different.failure_hash = Some(ContentHash::of_bytes(b"different failure"));
        different.attempts = 2;
        assert_eq!(
            next_dependency_subset(&original, &[observed(original.clone(), true), different])
                .unwrap(),
            Some(ids(&["a", "c"]))
        );
    }

    #[test]
    fn full_candidate_must_be_an_observed_three_attempt_failure() {
        let original = ids(&["a", "b"]);
        let mut full = observed(original.clone(), true);
        full.attempts = 2;
        assert_eq!(next_dependency_subset(&original, &[full]).unwrap(), None);
        let mut full = observed(original.clone(), true);
        full.authority = EvidenceGrade::Simulated;
        assert_eq!(next_dependency_subset(&original, &[full]).unwrap(), None);
        assert_eq!(
            next_dependency_subset(&original, &[observed(original.clone(), false)]).unwrap(),
            None
        );
    }

    #[test]
    fn proof_uses_smallest_observed_target_and_lexical_tie_break() {
        let original = ids(&["a", "b", "c", "d"]);
        let history = vec![
            observed(original.clone(), true),
            observed(ids(&["b", "d"]), true),
            observed(ids(&["a", "c"]), true),
        ];
        assert_eq!(
            next_dependency_subset(&original, &history).unwrap(),
            Some(ids(&["c"]))
        );
    }

    #[test]
    fn invalid_subsets_duplicates_and_verdict_payloads_are_rejected() {
        let original = ids(&["a", "b"]);
        for subset in [vec![], ids(&["a", "unknown"]), ids(&["a", "a"])] {
            let history = vec![observed(original.clone(), true), observed(subset, true)];
            assert!(next_dependency_subset(&original, &history).is_err());
        }
        assert!(next_dependency_subset(
            &original,
            &[
                observed(original.clone(), true),
                observed(ids(&["b", "a"]), true)
            ]
        )
        .is_err());
        assert!(next_dependency_subset(&original, &[observed(ids(&["a"]), true)]).is_err());
        let mut bad = observed(original.clone(), true);
        bad.failure_hash = None;
        assert!(next_dependency_subset(&original, &[bad]).is_err());
        let mut bad = observed(original.clone(), false);
        bad.failure_hash = Some(ContentHash::of_bytes(b"unexpected"));
        assert!(next_dependency_subset(&original, &[bad]).is_err());
        let mut bad = observed(original.clone(), false);
        bad.attempts = 0;
        assert!(next_dependency_subset(&original, &[bad]).is_err());
    }

    #[test]
    fn input_bound_includes_sixty_four_without_bit_masks() {
        let original: Vec<_> = (0..64).map(|index| format!("change-{index:02}")).collect();
        assert_eq!(
            next_dependency_subset(&original, &[]).unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            next_dependency_subset(&original, &[observed(original.clone(), true)]).unwrap(),
            Some(original[1..].to_vec())
        );
        let mut oversized = original;
        oversized.push("extra".into());
        assert!(next_dependency_subset(&oversized, &[]).is_err());
        assert!(next_dependency_subset(&[], &[]).is_err());
        assert!(next_dependency_subset(&ids(&["a", "a"]), &[]).is_err());
        assert!(next_dependency_subset(&ids(&[" "]), &[]).is_err());
    }
}
