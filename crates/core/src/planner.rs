//! Budget-aware scenario planner and ddmin-style axis reduction.

use crate::domain::{
    Baseline, Candidate, ContentHash, DependencyAdditionCheck, DependencyCandidateSet,
    DependencyChange, DependencyMinimalityCheck, DependencyProbeObservation, DependencyProbeRecord,
    DependencyProbeRequest, DependencyProbeVerdict, DependencyReduction, DependencyReductionStatus,
    EnvironmentAxis, EvidenceGrade, ExecutionPlan, ResolvedDependencySet, Scenario,
};
use crate::{Config, Result, TcError};
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
    let mut resolved_baseline = None;
    let mut baseline_identity = None;
    let mut conflicting_baselines = false;
    let mut saw_concrete_dependency_candidate = false;
    for candidate in dependency_candidates {
        let Some(set) = candidate.dependency_set.as_ref() else {
            continue;
        };
        saw_concrete_dependency_candidate = true;
        if let Err(error) = set.validate() {
            notes.push(format!(
                "dependency candidate {} has invalid concrete set: {error}",
                candidate.id
            ));
            continue;
        }
        let identity = set
            .baseline
            .stable_identity()
            .expect("validated dependency baseline must be serializable");
        match baseline_identity.as_ref() {
            None => {
                baseline_identity = Some(identity);
                resolved_baseline = Some(set.baseline.clone());
            }
            Some(expected) if expected == &identity => {}
            Some(_) => conflicting_baselines = true,
        }
    }
    if conflicting_baselines {
        notes.push("concrete dependency candidates do not share one exact baseline".into());
        resolved_baseline = None;
    }
    let baseline_grade = if saw_concrete_dependency_candidate && resolved_baseline.is_none() {
        EvidenceGrade::Inconclusive
    } else {
        EvidenceGrade::Observed
    };

    // 1. Baseline always first
    let baseline_id = "baseline".to_string();
    scenarios.push(Scenario {
        id: baseline_id.clone(),
        is_baseline: true,
        runtime: baseline.runtime.clone(),
        dependencies: baseline.dependencies.clone(),
        axes_changed: vec![],
        candidates: vec![],
        grade: baseline_grade,
        resolved_dependencies: resolved_baseline.clone(),
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
            resolved_dependencies: resolved_baseline.clone(),
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
        let (grade, resolved_dependencies, reason) =
            dependency_candidate_binding(&c, resolved_baseline.as_ref());
        if reason != "single-axis concrete dependency candidate" {
            notes.push(format!("dependency candidate {}: {reason}", c.id));
        }
        scenarios.push(Scenario {
            id: c.id.clone(),
            is_baseline: false,
            runtime: baseline.runtime.clone(),
            dependencies: c.version.clone(),
            axes_changed: vec![EnvironmentAxis::Dependencies],
            candidates: vec![c.id.clone()],
            grade,
            resolved_dependencies,
        });
        decisions.push(PlanDecision {
            scenario_id: c.id.clone(),
            selected: true,
            reason,
        });
        used += 1;
    }

    // 4. Pairwise combinations (runtime first-fail candidate × dep first candidate) if budget remains
    if used < budget && !runtime_candidates.is_empty() && !dependency_candidates.is_empty() {
        let rt = &runtime_candidates[0];
        let dep = &dependency_candidates[0];
        let (_, resolved_dependencies, _) =
            dependency_candidate_binding(dep, resolved_baseline.as_ref());
        let id = format!("combo-{}-{}", rt.id, dep.id);
        scenarios.push(Scenario {
            id: id.clone(),
            is_baseline: false,
            runtime: rt.version.clone(),
            dependencies: dep.version.clone(),
            axes_changed: vec![EnvironmentAxis::Runtime, EnvironmentAxis::Dependencies],
            candidates: vec![rt.id.clone(), dep.id.clone()],
            grade: EvidenceGrade::Simulated,
            resolved_dependencies,
        });
        decisions.push(PlanDecision {
            scenario_id: id,
            selected: true,
            reason: "pairwise combined axis within budget".into(),
        });
        used += 1;
        notes.push(format!(
            "combined scenarios used budget slot ({used}/{budget})"
        ));
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

fn dependency_candidate_binding(
    candidate: &Candidate,
    resolved_baseline: Option<&ResolvedDependencySet>,
) -> (EvidenceGrade, Option<ResolvedDependencySet>, String) {
    if candidate.axis != EnvironmentAxis::Dependencies {
        return (
            EvidenceGrade::Inconclusive,
            None,
            "dependency candidate declared a non-dependency axis".into(),
        );
    }
    let Some(set) = candidate.dependency_set.as_ref() else {
        return (
            EvidenceGrade::Simulated,
            None,
            "legacy label-only dependency candidate is non-authoritative".into(),
        );
    };
    if let Err(error) = set.validate() {
        return (
            EvidenceGrade::Inconclusive,
            None,
            format!("invalid concrete dependency set: {error}"),
        );
    }
    let Some(baseline) = resolved_baseline else {
        return (
            EvidenceGrade::Inconclusive,
            None,
            "no single exact dependency baseline binds the plan".into(),
        );
    };
    let expected = baseline
        .stable_identity()
        .expect("validated dependency baseline must be serializable");
    let actual = set
        .baseline
        .stable_identity()
        .expect("validated dependency baseline must be serializable");
    if actual != expected {
        return (
            EvidenceGrade::Inconclusive,
            None,
            "candidate dependency baseline differs from the plan baseline".into(),
        );
    }
    (
        candidate.grade_if_executed,
        Some(set.candidate.clone()),
        "single-axis concrete dependency candidate".into(),
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
    let size = len.div_ceil(n);
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

/// Live dependency reduction policy. Three executions means the original
/// candidate failure plus two independent reruns before reduction begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDdminOptions {
    pub required_failure_executions: u32,
}

impl Default for DependencyDdminOptions {
    fn default() -> Self {
        Self {
            required_failure_executions: 3,
        }
    }
}

/// Execute dependency ddmin against concrete artifact transitions. The
/// callback is invoked for every probe and must return an independently
/// checksummed scenario reference. No expected fixture label is consulted.
pub fn ddmin_dependency_changes<F>(
    candidate: &DependencyCandidateSet,
    execute: F,
) -> Result<DependencyReduction>
where
    F: FnMut(&DependencyProbeRequest) -> Result<DependencyProbeObservation>,
{
    ddmin_dependency_changes_with_options(candidate, DependencyDdminOptions::default(), execute)
}

pub fn ddmin_dependency_changes_with_options<F>(
    candidate: &DependencyCandidateSet,
    options: DependencyDdminOptions,
    execute: F,
) -> Result<DependencyReduction>
where
    F: FnMut(&DependencyProbeRequest) -> Result<DependencyProbeObservation>,
{
    if options.required_failure_executions < 3 {
        return Err(TcError::InvalidState(
            "dependency ddmin requires the original failure plus at least two reruns".into(),
        ));
    }
    candidate.validate().map_err(TcError::InvalidState)?;

    let candidate_hash = candidate.stable_identity()?;
    let candidate_id = candidate.stable_candidate_id()?;
    let mut original = candidate.changes.clone();
    original.sort_by(|left, right| left.id.cmp(&right.id));
    let mut probe_executor = DependencyProbeExecutor {
        candidate,
        candidate_id: candidate_id.clone(),
        candidate_hash: candidate_hash.clone(),
        next_sequence: 1,
        records: Vec::new(),
        evidence_locations: std::collections::BTreeSet::new(),
        execute,
    };

    let first = probe_executor.run(&original)?;
    let stable_failure_hash = match first.verdict {
        DependencyProbeVerdict::Fail => first.failure_hash.clone().ok_or_else(|| {
            TcError::InvalidState("failing dependency probe omitted failure_hash".into())
        })?,
        DependencyProbeVerdict::Pass => {
            return Ok(build_dependency_reduction(
                candidate,
                candidate_id,
                candidate_hash,
                &original,
                DependencyReductionOutcome {
                    minimal_changes: original.clone(),
                    probes: probe_executor.records,
                    addition_probes: vec![],
                    subtraction_probes: vec![],
                    stable_failure_hash: None,
                    status: DependencyReductionStatus::OriginalPassed,
                },
            ));
        }
        verdict => {
            return Ok(build_dependency_reduction(
                candidate,
                candidate_id,
                candidate_hash,
                &original,
                DependencyReductionOutcome {
                    minimal_changes: original.clone(),
                    probes: probe_executor.records,
                    addition_probes: vec![],
                    subtraction_probes: vec![],
                    stable_failure_hash: None,
                    status: status_for_non_failure(verdict),
                },
            ));
        }
    };

    for _ in 1..options.required_failure_executions {
        let rerun = probe_executor.run(&original)?;
        if rerun.verdict != DependencyProbeVerdict::Fail
            || rerun.failure_hash.as_ref() != Some(&stable_failure_hash)
        {
            let status = match rerun.verdict {
                DependencyProbeVerdict::Blocked => DependencyReductionStatus::Blocked,
                DependencyProbeVerdict::Inconclusive => DependencyReductionStatus::Inconclusive,
                _ => DependencyReductionStatus::UnstableFailure,
            };
            return Ok(build_dependency_reduction(
                candidate,
                candidate_id,
                candidate_hash,
                &original,
                DependencyReductionOutcome {
                    minimal_changes: original.clone(),
                    probes: probe_executor.records,
                    addition_probes: vec![],
                    subtraction_probes: vec![],
                    stable_failure_hash: None,
                    status,
                },
            ));
        }
    }

    // One-change-at-a-time delta debugging. Restart after every successful
    // reduction so interactions are retested against the new concrete set.
    let mut minimal = original.clone();
    let mut index = 0;
    while index < minimal.len() {
        let mut subset = minimal.clone();
        subset.remove(index);
        let probe = probe_executor.run(&subset)?;
        match probe.verdict {
            DependencyProbeVerdict::Fail
                if probe.failure_hash.as_ref() == Some(&stable_failure_hash) =>
            {
                minimal = subset;
                index = 0;
            }
            DependencyProbeVerdict::Pass | DependencyProbeVerdict::Fail => index += 1,
            verdict => {
                return Ok(build_dependency_reduction(
                    candidate,
                    candidate_id,
                    candidate_hash,
                    &original,
                    DependencyReductionOutcome {
                        minimal_changes: minimal,
                        probes: probe_executor.records,
                        addition_probes: vec![],
                        subtraction_probes: vec![],
                        stable_failure_hash: Some(stable_failure_hash),
                        status: status_for_non_failure(verdict),
                    },
                ));
            }
        }
    }

    // A reduced set is itself a new concrete experiment. Confirm it with the
    // same independent-execution threshold before claiming causality.
    if minimal != original {
        for _ in 0..options.required_failure_executions {
            let confirmation = probe_executor.run(&minimal)?;
            if confirmation.verdict != DependencyProbeVerdict::Fail
                || confirmation.failure_hash.as_ref() != Some(&stable_failure_hash)
            {
                let status = match confirmation.verdict {
                    DependencyProbeVerdict::Blocked => DependencyReductionStatus::Blocked,
                    DependencyProbeVerdict::Inconclusive => DependencyReductionStatus::Inconclusive,
                    _ => DependencyReductionStatus::UnstableFailure,
                };
                return Ok(build_dependency_reduction(
                    candidate,
                    candidate_id,
                    candidate_hash,
                    &original,
                    DependencyReductionOutcome {
                        minimal_changes: minimal,
                        probes: probe_executor.records,
                        addition_probes: vec![],
                        subtraction_probes: vec![],
                        stable_failure_hash: Some(stable_failure_hash),
                        status,
                    },
                ));
            }
        }
    }

    // Re-add every excluded change in an independent execution. An excluded
    // change is irrelevant only when the same normalized failure is observed.
    let minimal_ids: std::collections::BTreeSet<_> =
        minimal.iter().map(|change| change.id.as_str()).collect();
    let excluded: Vec<_> = original
        .iter()
        .filter(|change| !minimal_ids.contains(change.id.as_str()))
        .cloned()
        .collect();
    let mut addition_probes = Vec::new();
    for change in excluded {
        let mut combined = minimal.clone();
        combined.push(change.clone());
        combined.sort_by(|left, right| left.id.cmp(&right.id));
        let probe = probe_executor.run(&combined)?;
        let irrelevant = probe.authority == EvidenceGrade::Observed
            && probe.verdict == DependencyProbeVerdict::Fail
            && probe.failure_hash.as_ref() == Some(&stable_failure_hash);
        addition_probes.push(DependencyAdditionCheck {
            added_change_id: change.id,
            combined_change_ids: probe.change_ids.clone(),
            probe_sequence: probe.sequence,
            scenario_id: probe.scenario_id.clone(),
            verdict: probe.verdict,
            failure_hash: probe.failure_hash.clone(),
            irrelevant,
            authority: probe.authority,
        });
        if !irrelevant {
            let status = status_for_non_minimal_probe(&probe);
            return Ok(build_dependency_reduction(
                candidate,
                candidate_id,
                candidate_hash,
                &original,
                DependencyReductionOutcome {
                    minimal_changes: minimal,
                    probes: probe_executor.records,
                    addition_probes,
                    subtraction_probes: vec![],
                    stable_failure_hash: Some(stable_failure_hash),
                    status,
                },
            ));
        }
    }

    // Independent subtraction executions form the actual 1-minimality proof;
    // earlier search probes are not silently reused as proof.
    let mut subtraction_probes = Vec::new();
    for change in minimal.clone() {
        let remaining: Vec<_> = minimal
            .iter()
            .filter(|item| item.id != change.id)
            .cloned()
            .collect();
        let probe = probe_executor.run(&remaining)?;
        let necessary = probe.authority == EvidenceGrade::Observed
            && matches!(
                probe.verdict,
                DependencyProbeVerdict::Pass | DependencyProbeVerdict::Fail
            )
            && !(probe.verdict == DependencyProbeVerdict::Fail
                && probe.failure_hash.as_ref() == Some(&stable_failure_hash));
        subtraction_probes.push(DependencyMinimalityCheck {
            removed_change_id: change.id,
            remaining_change_ids: probe.change_ids.clone(),
            probe_sequence: probe.sequence,
            scenario_id: probe.scenario_id.clone(),
            verdict: probe.verdict,
            failure_hash: probe.failure_hash.clone(),
            necessary,
            authority: probe.authority,
        });
        if !necessary {
            let status = status_for_non_minimal_probe(&probe);
            return Ok(build_dependency_reduction(
                candidate,
                candidate_id,
                candidate_hash,
                &original,
                DependencyReductionOutcome {
                    minimal_changes: minimal,
                    probes: probe_executor.records,
                    addition_probes,
                    subtraction_probes,
                    stable_failure_hash: Some(stable_failure_hash),
                    status,
                },
            ));
        }
    }

    let authority = aggregate_dependency_authority(&probe_executor.records);
    let status = if minimal.is_empty() || authority != EvidenceGrade::Observed {
        DependencyReductionStatus::Inconclusive
    } else {
        DependencyReductionStatus::ProvenMinimal
    };
    Ok(build_dependency_reduction(
        candidate,
        candidate_id,
        candidate_hash,
        &original,
        DependencyReductionOutcome {
            minimal_changes: minimal,
            probes: probe_executor.records,
            addition_probes,
            subtraction_probes,
            stable_failure_hash: Some(stable_failure_hash),
            status,
        },
    ))
}

struct DependencyProbeExecutor<'a, F> {
    candidate: &'a DependencyCandidateSet,
    candidate_id: String,
    candidate_hash: ContentHash,
    next_sequence: u32,
    records: Vec<DependencyProbeRecord>,
    evidence_locations: std::collections::BTreeSet<(String, String)>,
    execute: F,
}

impl<F> DependencyProbeExecutor<'_, F>
where
    F: FnMut(&DependencyProbeRequest) -> Result<DependencyProbeObservation>,
{
    fn run(&mut self, changes: &[DependencyChange]) -> Result<DependencyProbeRecord> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| TcError::InvalidState("dependency probe sequence overflowed".into()))?;
        let mut changes = changes.to_vec();
        changes.sort_by(|left, right| left.id.cmp(&right.id));
        let subset_hash = dependency_subset_hash(&changes)?;
        let scenario_id = format!(
            "dependency-ddmin-{}-{sequence:04}-{}",
            &self.candidate_hash.hex()[..12],
            &subset_hash.hex()[..12]
        );
        let resolved_dependencies = self
            .candidate
            .resolution_for_changes(&changes)
            .map_err(TcError::InvalidState)?;
        let request = DependencyProbeRequest {
            sequence,
            scenario_id: scenario_id.clone(),
            candidate_id: self.candidate_id.clone(),
            changes,
            resolved_dependencies: resolved_dependencies.clone(),
        };
        let observation = (self.execute)(&request)?;
        validate_probe_observation(&request, &observation)?;
        let evidence_location = (
            observation.evidence.run_id.clone(),
            observation.evidence.path.clone(),
        );
        if !self.evidence_locations.insert(evidence_location) {
            return Err(TcError::InvalidState(format!(
                "dependency probe {} reused an earlier evidence location",
                request.scenario_id
            )));
        }
        let record = DependencyProbeRecord {
            sequence,
            scenario_id,
            candidate_id: self.candidate_id.clone(),
            change_ids: request
                .changes
                .iter()
                .map(|change| change.id.clone())
                .collect(),
            subset_hash,
            resolved_manifest_sha256: resolved_dependencies.manifest_sha256,
            verdict: observation.verdict,
            failure_hash: observation.failure_hash,
            evidence: observation.evidence,
            authority: observation.authority,
        };
        self.records.push(record.clone());
        Ok(record)
    }
}

fn dependency_subset_hash(changes: &[DependencyChange]) -> Result<ContentHash> {
    let mut normalized = changes.to_vec();
    normalized.sort_by(|left, right| left.id.cmp(&right.id));
    let hash = crate::canonical_json_hash(&normalized)?;
    ContentHash::try_from(hash).map_err(TcError::InvalidState)
}

fn validate_probe_observation(
    request: &DependencyProbeRequest,
    observation: &DependencyProbeObservation,
) -> Result<()> {
    if observation.evidence.scenario_id != request.scenario_id {
        return Err(TcError::InvalidState(format!(
            "dependency probe {} returned evidence for scenario {}",
            request.scenario_id, observation.evidence.scenario_id
        )));
    }
    if observation.evidence.run_id.trim().is_empty() || observation.evidence.path.trim().is_empty()
    {
        return Err(TcError::InvalidState(format!(
            "dependency probe {} returned an incomplete evidence reference",
            request.scenario_id
        )));
    }
    crate::validate_canonical_relative_path(&observation.evidence.path).map_err(|error| {
        TcError::InvalidState(format!(
            "dependency probe {} returned a noncanonical evidence path: {error}",
            request.scenario_id
        ))
    })?;
    match observation.verdict {
        DependencyProbeVerdict::Fail if observation.failure_hash.is_none() => {
            Err(TcError::InvalidState(format!(
                "dependency probe {} failed without a normalized failure hash",
                request.scenario_id
            )))
        }
        DependencyProbeVerdict::Pass if observation.failure_hash.is_some() => {
            Err(TcError::InvalidState(format!(
                "dependency probe {} passed but returned a failure hash",
                request.scenario_id
            )))
        }
        _ => Ok(()),
    }
}

struct DependencyReductionOutcome {
    minimal_changes: Vec<DependencyChange>,
    probes: Vec<DependencyProbeRecord>,
    addition_probes: Vec<DependencyAdditionCheck>,
    subtraction_probes: Vec<DependencyMinimalityCheck>,
    stable_failure_hash: Option<ContentHash>,
    status: DependencyReductionStatus,
}

fn build_dependency_reduction(
    candidate: &DependencyCandidateSet,
    candidate_id: String,
    candidate_hash: ContentHash,
    original: &[DependencyChange],
    outcome: DependencyReductionOutcome,
) -> DependencyReduction {
    let authority = aggregate_dependency_authority(&outcome.probes);
    DependencyReduction {
        candidate_set_id: candidate.set_id.clone(),
        candidate_id,
        candidate_hash,
        original_change_ids: original.iter().map(|change| change.id.clone()).collect(),
        minimal_changes: outcome.minimal_changes,
        probes: outcome.probes,
        addition_probes: outcome.addition_probes,
        subtraction_probes: outcome.subtraction_probes,
        stable_failure_hash: outcome.stable_failure_hash,
        status: outcome.status,
        authority,
    }
}

fn aggregate_dependency_authority(probes: &[DependencyProbeRecord]) -> EvidenceGrade {
    if probes
        .iter()
        .any(|probe| probe.authority == EvidenceGrade::Inconclusive)
    {
        EvidenceGrade::Inconclusive
    } else if probes
        .iter()
        .any(|probe| probe.authority == EvidenceGrade::Simulated)
    {
        EvidenceGrade::Simulated
    } else if probes
        .iter()
        .any(|probe| probe.authority == EvidenceGrade::ScheduledRisk)
    {
        EvidenceGrade::ScheduledRisk
    } else {
        EvidenceGrade::Observed
    }
}

fn status_for_non_failure(verdict: DependencyProbeVerdict) -> DependencyReductionStatus {
    match verdict {
        DependencyProbeVerdict::Blocked => DependencyReductionStatus::Blocked,
        DependencyProbeVerdict::Inconclusive => DependencyReductionStatus::Inconclusive,
        DependencyProbeVerdict::Flaky => DependencyReductionStatus::UnstableFailure,
        DependencyProbeVerdict::Pass => DependencyReductionStatus::OriginalPassed,
        DependencyProbeVerdict::Fail => DependencyReductionStatus::Inconclusive,
    }
}

fn status_for_non_minimal_probe(probe: &DependencyProbeRecord) -> DependencyReductionStatus {
    match probe.verdict {
        DependencyProbeVerdict::Blocked => DependencyReductionStatus::Blocked,
        DependencyProbeVerdict::Flaky => DependencyReductionStatus::UnstableFailure,
        DependencyProbeVerdict::Inconclusive
        | DependencyProbeVerdict::Pass
        | DependencyProbeVerdict::Fail => DependencyReductionStatus::Inconclusive,
    }
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
    use crate::{
        DependencyArtifactDeclaration, DependencyCandidateDeclaration, DependencyChangeDeclaration,
        DependencyChangeKind, DependencyExperimentManifest, DependencyProbeEvidence,
        DependencyRuntimeIdentity, DependencySetReference, DependencySourceKind, Ecosystem,
        ResolvedDependency, ResolvedDependencySet,
    };
    use std::collections::BTreeSet;

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
                dependency_set: None,
            })
            .collect();
        let (plan, dec) = plan_scenarios(&baseline, &rt, &[], &cfg);
        assert!(plan.scenarios.len() <= 3);
        assert!(dec.iter().any(|d| !d.selected));
    }

    #[test]
    fn planner_downgrades_label_only_dependency_candidate() {
        let baseline = Baseline {
            runtime: "20".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };
        let candidate = Candidate {
            id: "legacy-dependency-label".into(),
            axis: EnvironmentAxis::Dependencies,
            label: "latest".into(),
            version: "latest".into(),
            channel: "legacy".into(),
            grade_if_executed: EvidenceGrade::Observed,
            order_key: "0001".into(),
            dependency_set: None,
        };
        let (plan, _) = plan_scenarios(&baseline, &[], &[candidate], &Config::default());
        let scenario = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.id == "legacy-dependency-label")
            .unwrap();
        assert_eq!(scenario.grade, EvidenceGrade::Simulated);
        assert!(scenario.resolved_dependencies.is_none());
    }

    #[test]
    fn planner_downgrades_conflicting_concrete_baselines() {
        let baseline = Baseline {
            runtime: "20".into(),
            dependencies: "concrete".into(),
            declared_by: "test".into(),
        };
        let candidates = [
            concrete_candidate(
                "dep-one",
                dependency_candidate_with_versions("1.0.0", "2.0.0"),
            ),
            concrete_candidate(
                "dep-two",
                dependency_candidate_with_versions("0.9.0", "2.0.0"),
            ),
        ];
        let (plan, _) = plan_scenarios(&baseline, &[], &candidates, &Config::default());

        assert_eq!(plan.scenarios[0].grade, EvidenceGrade::Inconclusive);
        assert!(plan.scenarios[0].resolved_dependencies.is_none());
        assert!(plan.scenarios.iter().skip(1).all(|scenario| {
            scenario.grade == EvidenceGrade::Inconclusive
                && scenario.resolved_dependencies.is_none()
        }));
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
    fn concrete_dependency_candidate_identity_is_stable() {
        let candidate = dependency_candidate();
        let expected = candidate.stable_identity().unwrap();

        let mut reordered = candidate;
        reordered.set_id = "human-label-does-not-authorize".into();
        reordered.baseline.set_id = "other-baseline-label".into();
        reordered.candidate.set_id = "other-candidate-label".into();
        reordered.baseline.dependencies.reverse();
        reordered.candidate.dependencies.reverse();
        reordered.changes.reverse();

        assert_eq!(reordered.stable_identity().unwrap(), expected);
        assert!(reordered.validate().is_ok());
    }

    #[test]
    fn live_ddmin_removes_irrelevant_dependency_change() {
        let reduction = execute_dependency_reduction();
        let minimal_ids: Vec<_> = reduction
            .minimal_changes
            .iter()
            .map(|change| change.id.as_str())
            .collect();

        assert_eq!(reduction.status, DependencyReductionStatus::ProvenMinimal);
        assert_eq!(minimal_ids, ["change-left", "change-right"]);
        assert!(!minimal_ids.contains(&"change-noise"));
        assert_eq!(reduction.addition_probes.len(), 1);
        assert_eq!(reduction.addition_probes[0].added_change_id, "change-noise");
        assert!(reduction.addition_probes[0].irrelevant);
        assert_eq!(
            reduction.addition_probes[0].authority,
            EvidenceGrade::Observed
        );
        assert!(
            reduction
                .probes
                .iter()
                .filter(|probe| probe.change_ids == ["change-left", "change-right"])
                .count()
                >= 3
        );
        assert_eq!(reduction.stable_failure_hash, Some(failure_hash()));
        assert!(reduction.probes.len() >= 3);
    }

    #[test]
    fn live_ddmin_proves_each_retained_change_necessary() {
        let reduction = execute_dependency_reduction();
        let minimal_ids: BTreeSet<_> = reduction
            .minimal_changes
            .iter()
            .map(|change| change.id.as_str())
            .collect();
        let removed_ids: BTreeSet<_> = reduction
            .subtraction_probes
            .iter()
            .map(|probe| probe.removed_change_id.as_str())
            .collect();
        let scenario_ids: BTreeSet<_> = reduction
            .probes
            .iter()
            .map(|probe| probe.scenario_id.as_str())
            .collect();

        assert_eq!(removed_ids, minimal_ids);
        assert!(reduction
            .subtraction_probes
            .iter()
            .all(|probe| probe.necessary && probe.authority == EvidenceGrade::Observed));
        assert_eq!(scenario_ids.len(), reduction.probes.len());
        assert!(reduction.probes.iter().all(|probe| {
            probe.evidence.scenario_id == probe.scenario_id
                && probe
                    .resolved_manifest_sha256
                    .as_str()
                    .starts_with("sha256:")
        }));
    }

    #[test]
    fn dependency_manifest_hash_and_transition_closure_are_enforced() {
        let candidate = dependency_candidate();
        assert!(candidate.validate().is_ok());

        let mut forged_hash = candidate.clone();
        forged_hash.candidate.manifest_sha256 = ContentHash::of_bytes(b"wrong manifest");
        assert!(forged_hash.validate().is_err());

        let mut manager_transition = candidate.clone();
        manager_transition.candidate.package_manager = "pnpm".into();
        manager_transition.candidate.manifest_sha256 = manager_transition
            .candidate
            .expected_manifest_sha256()
            .unwrap();
        assert!(manager_transition.validate().is_err());

        let mut noncanonical_source = dependency("unsafe", "1.0.0");
        noncanonical_source.source = "artifacts\\unsafe".into();
        assert!(noncanonical_source.validate().is_err());

        let mut omitted_change = candidate;
        omitted_change.changes.pop();
        assert!(omitted_change.validate().is_err());
    }

    #[test]
    fn experiment_manifest_excludes_expected_verdict_oracles() {
        let candidate = dependency_candidate();
        let manifest = DependencyExperimentManifest {
            schema_version: 1,
            unchanged: Vec::new(),
            ecosystem: Ecosystem::Node,
            runtime: DependencyRuntimeIdentity {
                version: "20".into(),
                container_image: format!("node@sha256:{}", "a".repeat(64)),
            },
            content_hash_algorithm: "sha256-tree-v1".into(),
            baseline: DependencySetReference {
                set_id: candidate.baseline.set_id.clone(),
            },
            candidate: DependencyCandidateDeclaration {
                set_id: candidate.candidate.set_id.clone(),
                changes: candidate
                    .changes
                    .iter()
                    .map(|change| DependencyChangeDeclaration {
                        id: change.id.clone(),
                        name: change.name.clone(),
                        before: artifact_declaration(change.before.as_ref().unwrap()),
                        after: artifact_declaration(change.after.as_ref().unwrap()),
                    })
                    .collect(),
            },
        };
        assert!(manifest.to_candidate_set("npm").unwrap().validate().is_ok());

        let mut mutable_runtime = manifest.clone();
        mutable_runtime.runtime.container_image = "node:latest".into();
        assert!(mutable_runtime.to_candidate_set("npm").is_err());

        let mut with_oracle = serde_json::to_value(&manifest).unwrap();
        with_oracle
            .as_object_mut()
            .unwrap()
            .insert("expected_verdict".into(), serde_json::json!("FAIL"));
        assert!(serde_json::from_value::<DependencyExperimentManifest>(with_oracle).is_err());
    }

    #[test]
    fn simulated_probe_results_never_authorize_dependency_minimality() {
        let reduction = execute_dependency_reduction_with_authority(EvidenceGrade::Simulated);
        assert_eq!(reduction.status, DependencyReductionStatus::Inconclusive);
        assert_eq!(reduction.authority, EvidenceGrade::Simulated);
        assert!(reduction
            .addition_probes
            .iter()
            .all(|probe| !probe.irrelevant));
        assert!(reduction
            .subtraction_probes
            .iter()
            .all(|probe| !probe.necessary));
    }

    #[test]
    fn drifting_full_candidate_hash_is_not_reported_as_stable() {
        let candidate = dependency_candidate();
        let reduction = ddmin_dependency_changes(&candidate, |request| {
            let hash = if request.sequence == 1 { "a" } else { "b" };
            Ok(DependencyProbeObservation {
                verdict: DependencyProbeVerdict::Fail,
                failure_hash: Some(ContentHash::sha256(hash.repeat(64)).unwrap()),
                evidence: DependencyProbeEvidence {
                    run_id: "unit-drift".into(),
                    scenario_id: request.scenario_id.clone(),
                    path: format!("scenarios/{}/result.json", request.scenario_id),
                    checksum: ContentHash::sha256(format!("{:064x}", request.sequence)).unwrap(),
                },
                authority: EvidenceGrade::Observed,
            })
        })
        .unwrap();

        assert_eq!(reduction.status, DependencyReductionStatus::UnstableFailure);
        assert_eq!(reduction.stable_failure_hash, None);
    }

    #[test]
    fn dependency_probe_rejects_reused_or_noncanonical_evidence_paths() {
        let candidate = dependency_candidate();
        let reused = ddmin_dependency_changes(&candidate, |request| {
            Ok(probe_observation(
                request,
                EvidenceGrade::Observed,
                "scenarios/shared/result.json",
            ))
        });
        assert!(
            matches!(reused, Err(TcError::InvalidState(message)) if message.contains("reused"))
        );

        let noncanonical = ddmin_dependency_changes(&candidate, |request| {
            Ok(probe_observation(
                request,
                EvidenceGrade::Observed,
                "scenarios/probe/../shared.json",
            ))
        });
        assert!(
            matches!(noncanonical, Err(TcError::InvalidState(message)) if message.contains("noncanonical"))
        );
    }

    #[test]
    fn first_fail_linear() {
        assert_eq!(first_failure_index(&[true, true, false, false]), Some(2));
        assert_eq!(first_failure_index(&[true, true]), None);
    }

    fn execute_dependency_reduction() -> DependencyReduction {
        execute_dependency_reduction_with_authority(EvidenceGrade::Observed)
    }

    fn execute_dependency_reduction_with_authority(
        authority: EvidenceGrade,
    ) -> DependencyReduction {
        let candidate = dependency_candidate();
        ddmin_dependency_changes(&candidate, |request| {
            request
                .resolved_dependencies
                .validate()
                .map_err(TcError::InvalidState)?;
            Ok(probe_observation(
                request,
                authority,
                &format!("scenarios/{}/result.json", request.scenario_id),
            ))
        })
        .unwrap()
    }

    fn dependency_candidate() -> DependencyCandidateSet {
        dependency_candidate_with_versions("1.0.0", "2.0.0")
    }

    fn dependency_candidate_with_versions(
        baseline_version: &str,
        candidate_version: &str,
    ) -> DependencyCandidateSet {
        let baseline_dependencies = ["left", "noise", "right"]
            .into_iter()
            .map(|name| dependency(name, baseline_version))
            .collect::<Vec<_>>();
        let candidate_dependencies = ["left", "noise", "right"]
            .into_iter()
            .map(|name| dependency(name, candidate_version))
            .collect::<Vec<_>>();
        let baseline = dependency_set("baseline-readable", baseline_dependencies.clone());
        let candidate = dependency_set("candidate-readable", candidate_dependencies.clone());
        let changes = baseline_dependencies
            .into_iter()
            .zip(candidate_dependencies)
            .map(|(before, after)| DependencyChange {
                id: format!("change-{}", before.name),
                name: before.name.clone(),
                kind: DependencyChangeKind::Update,
                before: Some(before),
                after: Some(after),
            })
            .collect();
        let candidate = DependencyCandidateSet {
            set_id: "interaction-candidate".into(),
            baseline,
            candidate,
            changes,
        };
        candidate.validate().unwrap();
        candidate
    }

    fn concrete_candidate(id: &str, dependency_set: DependencyCandidateSet) -> Candidate {
        Candidate {
            id: id.into(),
            axis: EnvironmentAxis::Dependencies,
            label: id.into(),
            version: dependency_set.candidate.set_id.clone(),
            channel: "vendored".into(),
            grade_if_executed: EvidenceGrade::Observed,
            order_key: id.into(),
            dependency_set: Some(dependency_set),
        }
    }

    fn probe_observation(
        request: &DependencyProbeRequest,
        authority: EvidenceGrade,
        path: &str,
    ) -> DependencyProbeObservation {
        let changes: BTreeSet<_> = request
            .changes
            .iter()
            .map(|change| change.id.as_str())
            .collect();
        let fails = changes.contains("change-left") && changes.contains("change-right");
        DependencyProbeObservation {
            verdict: if fails {
                DependencyProbeVerdict::Fail
            } else {
                DependencyProbeVerdict::Pass
            },
            failure_hash: fails.then(failure_hash),
            evidence: DependencyProbeEvidence {
                run_id: "unit-live-ddmin".into(),
                scenario_id: request.scenario_id.clone(),
                path: path.into(),
                checksum: ContentHash::of_bytes(request.scenario_id.as_bytes()),
            },
            authority,
        }
    }

    fn dependency(name: &str, version: &str) -> ResolvedDependency {
        ResolvedDependency {
            id: format!("{name}@{version}"),
            name: name.into(),
            version: version.into(),
            source: format!("artifacts/{name}-{version}"),
            source_kind: DependencySourceKind::VendoredTreeSha256V1,
            content_sha256: ContentHash::of_bytes(format!("{name}-{version}").as_bytes()),
        }
    }

    fn dependency_set(
        set_id: &str,
        dependencies: Vec<ResolvedDependency>,
    ) -> ResolvedDependencySet {
        let mut set = ResolvedDependencySet {
            set_id: set_id.into(),
            ecosystem: Ecosystem::Node,
            package_manager: "npm".into(),
            manifest_sha256: ContentHash::of_bytes(b"placeholder"),
            dependencies,
        };
        set.manifest_sha256 = set.expected_manifest_sha256().unwrap();
        set
    }

    fn failure_hash() -> ContentHash {
        ContentHash::of_bytes(b"left-right-interaction-failure")
    }

    fn artifact_declaration(dependency: &ResolvedDependency) -> DependencyArtifactDeclaration {
        DependencyArtifactDeclaration {
            version: dependency.version.clone(),
            source: dependency.source.clone(),
            content_sha256: dependency.content_sha256.clone(),
        }
    }
}
