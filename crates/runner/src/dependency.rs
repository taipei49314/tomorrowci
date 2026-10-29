//! Content-addressed dependency experiment loading and materialization.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tomorrowci_core::{
    sha256_file_v1, sha256_tree_v1, validate_image_digest, CommandSpec, ContentHash,
    DependencyAdditionCheck, DependencyCandidateSet, DependencyChange,
    DependencyExperimentManifest, DependencyMinimalityCheck, DependencyProbeEvidence,
    DependencyProbeRecord, DependencyProbeVerdict, DependencyReduction, DependencyReductionStatus,
    Ecosystem, EvidenceGrade, ExecutionPlan, ExecutionResult, ResolvedDependencySet, Result,
    Scenario, TcError, Verdict,
};

pub const DEPENDENCY_EXPERIMENT_FILE: &str = ".tomorrowci-dependencies.json";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ConcreteDependencyProbe {
    pub id: String,
    pub change_ids: Vec<String>,
    pub dependency_set: DependencyCandidateSet,
}

#[derive(Debug, Clone)]
pub struct DependencyExperiment {
    pub manifest: DependencyExperimentManifest,
    pub baseline: ResolvedDependencySet,
    pub probes: Vec<ConcreteDependencyProbe>,
}

impl DependencyExperiment {
    pub fn probe_for_subset(&self, selected_ids: Vec<String>) -> Result<ConcreteDependencyProbe> {
        let full = self
            .manifest
            .to_candidate_set(package_manager(self.manifest.ecosystem))
            .map_err(TcError::Config)?;
        let original_ids: Vec<_> = full
            .changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        let probe_id = if self.manifest.schema_version == 2 {
            tomorrowci_core::adaptive_dependency_probe_id(
                &self.manifest.candidate.set_id,
                &original_ids,
                &selected_ids,
            )?
        } else if selected_ids.len() == full.changes.len() {
            self.manifest.candidate.set_id.clone()
        } else {
            format!("ddmin-{}", selected_ids.join("--"))
        };
        let mut selected_changes = Vec::new();
        for id in &selected_ids {
            selected_changes.push(
                full.changes
                    .iter()
                    .find(|change| &change.id == id)
                    .ok_or_else(|| TcError::Config(format!("unknown dependency change {id}")))?
                    .clone(),
            );
        }
        let mut candidate = full
            .resolution_for_changes(&selected_changes)
            .map_err(TcError::Config)?;
        candidate.set_id = format!("{}--{}", self.manifest.candidate.set_id, probe_id);
        let dependency_set = DependencyCandidateSet {
            set_id: candidate.set_id.clone(),
            baseline: full.baseline,
            candidate,
            changes: selected_changes,
        };
        dependency_set.validate().map_err(TcError::Config)?;
        Ok(ConcreteDependencyProbe {
            id: probe_id,
            change_ids: selected_ids,
            dependency_set,
        })
    }

    pub fn next_probe(
        &self,
        plan: &ExecutionPlan,
        results: &[ExecutionResult],
    ) -> Result<Option<ConcreteDependencyProbe>> {
        if self.manifest.schema_version != 2 {
            return Ok(None);
        }
        let mut observations = Vec::new();
        for probe in &self.probes {
            let Some(result) = results.iter().find(|result| result.scenario_id == probe.id) else {
                return Ok(None);
            };
            let authority = plan
                .scenarios
                .iter()
                .find(|scenario| scenario.id == probe.id)
                .map(|scenario| scenario.grade)
                .unwrap_or(EvidenceGrade::Inconclusive);
            observations.push(tomorrowci_core::DependencyScheduleObservation {
                change_ids: probe.change_ids.clone(),
                verdict: dependency_probe_verdict(result.verdict),
                failure_hash: result
                    .failure
                    .as_ref()
                    .map(|failure| ContentHash::try_from(failure.normalized_hash.as_str()))
                    .transpose()
                    .map_err(TcError::InvalidState)?,
                attempts: result.attempt,
                authority,
            });
        }
        let original_ids: Vec<_> = self
            .manifest
            .candidate
            .changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        tomorrowci_core::next_dependency_subset(&original_ids, &observations)?
            .map(|subset| self.probe_for_subset(subset))
            .transpose()
    }

    pub fn full_candidate_probe(&self) -> Option<&ConcreteDependencyProbe> {
        let all: BTreeSet<_> = self
            .manifest
            .candidate
            .changes
            .iter()
            .map(|change| change.id.as_str())
            .collect();
        self.probes.iter().find(|probe| {
            probe
                .change_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == all
        })
    }
}

/// Derive a typed reduction exclusively from independently executed scenario
/// evidence. Fixture expectations are intentionally absent from this path.
pub fn derive_observed_dependency_reduction(
    run_id: &str,
    run_root: &Path,
    experiment: &DependencyExperiment,
    plan: &ExecutionPlan,
    results: &[ExecutionResult],
) -> Result<DependencyReduction> {
    let full_probe = experiment.full_candidate_probe().ok_or_else(|| {
        TcError::InvalidState("dependency experiment has no full candidate probe".into())
    })?;
    let full_set = &full_probe.dependency_set;
    let candidate_hash = full_set
        .stable_identity()
        .map_err(|error| TcError::InvalidState(error.to_string()))?;
    let candidate_id = full_set
        .stable_candidate_id()
        .map_err(|error| TcError::InvalidState(error.to_string()))?;
    let mut original_changes = full_set.changes.clone();
    original_changes.sort_by(|left, right| left.id.cmp(&right.id));
    let original_change_ids: Vec<_> = original_changes
        .iter()
        .map(|change| change.id.clone())
        .collect();

    let scenario_grades: BTreeMap<_, _> = plan
        .scenarios
        .iter()
        .map(|scenario| (scenario.id.as_str(), scenario.grade))
        .collect();
    let result_by_id: BTreeMap<_, _> = results
        .iter()
        .map(|result| (result.scenario_id.as_str(), result))
        .collect();

    let mut records = Vec::new();
    let mut observed_by_subset = BTreeMap::new();
    for (index, probe) in experiment.probes.iter().enumerate() {
        let Some(result) = result_by_id.get(probe.id.as_str()).copied() else {
            continue;
        };
        let authority = scenario_grades
            .get(probe.id.as_str())
            .copied()
            .unwrap_or(EvidenceGrade::Inconclusive);
        let verdict = dependency_probe_verdict(result.verdict);
        let failure_hash = result
            .failure
            .as_ref()
            .map(|failure| ContentHash::try_from(failure.normalized_hash.as_str()))
            .transpose()
            .map_err(TcError::InvalidState)?;
        let evidence = dependency_probe_evidence(run_id, run_root, &probe.id)?;
        let subset_hash = dependency_subset_hash(&probe.dependency_set.changes)?;
        let record = DependencyProbeRecord {
            sequence: u32::try_from(index + 1)
                .map_err(|_| TcError::InvalidState("dependency probe sequence overflow".into()))?,
            scenario_id: probe.id.clone(),
            candidate_id: candidate_id.clone(),
            change_ids: probe.change_ids.clone(),
            subset_hash,
            resolved_manifest_sha256: probe.dependency_set.candidate.manifest_sha256.clone(),
            verdict,
            failure_hash: failure_hash.clone(),
            evidence,
            authority,
        };
        observed_by_subset.insert(probe.change_ids.clone(), (record.clone(), result));
        records.push(record);
    }

    let full_observation = observed_by_subset.get(&original_change_ids);
    let Some((full_record, full_result)) = full_observation else {
        return Ok(DependencyReduction {
            candidate_set_id: full_set.set_id.clone(),
            candidate_id,
            candidate_hash,
            original_change_ids,
            minimal_changes: original_changes,
            probes: records,
            addition_probes: vec![],
            subtraction_probes: vec![],
            stable_failure_hash: None,
            status: DependencyReductionStatus::Blocked,
            authority: EvidenceGrade::Inconclusive,
        });
    };
    let stable_failure_hash = if full_record.authority == EvidenceGrade::Observed
        && full_record.verdict == DependencyProbeVerdict::Fail
        && full_result.attempt >= 3
    {
        full_record.failure_hash.clone()
    } else {
        None
    };
    let Some(stable_failure_hash) = stable_failure_hash else {
        let status = match full_record.verdict {
            DependencyProbeVerdict::Pass => DependencyReductionStatus::OriginalPassed,
            DependencyProbeVerdict::Blocked => DependencyReductionStatus::Blocked,
            DependencyProbeVerdict::Flaky => DependencyReductionStatus::UnstableFailure,
            DependencyProbeVerdict::Fail | DependencyProbeVerdict::Inconclusive => {
                DependencyReductionStatus::Inconclusive
            }
        };
        return Ok(DependencyReduction {
            candidate_set_id: full_set.set_id.clone(),
            candidate_id,
            candidate_hash,
            original_change_ids,
            minimal_changes: original_changes,
            probes: records,
            addition_probes: vec![],
            subtraction_probes: vec![],
            stable_failure_hash: None,
            status,
            authority: EvidenceGrade::Inconclusive,
        });
    };

    let mut failing_subsets: Vec<_> = observed_by_subset
        .iter()
        .filter(|(_, (record, result))| {
            record.authority == EvidenceGrade::Observed
                && record.verdict == DependencyProbeVerdict::Fail
                && record.failure_hash.as_ref() == Some(&stable_failure_hash)
                && result.attempt >= 3
        })
        .map(|(ids, _)| ids.clone())
        .collect();
    failing_subsets.sort_by(|left, right| left.len().cmp(&right.len()).then(left.cmp(right)));
    let minimal_ids = failing_subsets
        .first()
        .cloned()
        .ok_or_else(|| TcError::InvalidState("stable full failure vanished from probes".into()))?;
    let minimal_id_set: BTreeSet<_> = minimal_ids.iter().cloned().collect();
    let minimal_changes: Vec<_> = original_changes
        .iter()
        .filter(|change| minimal_id_set.contains(&change.id))
        .cloned()
        .collect();

    let mut addition_probes = Vec::new();
    let mut subtraction_probes = Vec::new();
    let mut proven = true;
    for excluded in original_changes
        .iter()
        .filter(|change| !minimal_id_set.contains(&change.id))
    {
        let mut combined = minimal_ids.clone();
        combined.push(excluded.id.clone());
        combined.sort();
        let observation = observed_by_subset.get(&combined);
        let irrelevant = observation.is_some_and(|(record, result)| {
            record.authority == EvidenceGrade::Observed
                && record.verdict == DependencyProbeVerdict::Fail
                && record.failure_hash.as_ref() == Some(&stable_failure_hash)
                && result.attempt >= 3
        });
        proven &= irrelevant;
        if let Some((record, _)) = observation {
            addition_probes.push(DependencyAdditionCheck {
                added_change_id: excluded.id.clone(),
                combined_change_ids: combined,
                probe_sequence: record.sequence,
                scenario_id: record.scenario_id.clone(),
                verdict: record.verdict,
                failure_hash: record.failure_hash.clone(),
                irrelevant,
                authority: record.authority,
            });
        } else {
            proven = false;
        }
    }

    for retained in &minimal_changes {
        let remaining: Vec<_> = minimal_ids
            .iter()
            .filter(|change_id| **change_id != retained.id)
            .cloned()
            .collect();
        let observation = if remaining.is_empty() {
            baseline_probe_record(run_id, run_root, plan, &result_by_id, &candidate_id)?
        } else {
            observed_by_subset
                .get(&remaining)
                .map(|(record, _)| record.clone())
        };
        let necessary = observation.as_ref().is_some_and(|record| {
            record.authority == EvidenceGrade::Observed
                && !(record.verdict == DependencyProbeVerdict::Fail
                    && record.failure_hash.as_ref() == Some(&stable_failure_hash))
                && matches!(
                    record.verdict,
                    DependencyProbeVerdict::Pass | DependencyProbeVerdict::Fail
                )
        });
        proven &= necessary;
        if let Some(record) = observation {
            subtraction_probes.push(DependencyMinimalityCheck {
                removed_change_id: retained.id.clone(),
                remaining_change_ids: remaining,
                probe_sequence: record.sequence,
                scenario_id: record.scenario_id,
                verdict: record.verdict,
                failure_hash: record.failure_hash,
                necessary,
                authority: record.authority,
            });
        } else {
            proven = false;
        }
    }

    Ok(DependencyReduction {
        candidate_set_id: full_set.set_id.clone(),
        candidate_id,
        candidate_hash,
        original_change_ids,
        minimal_changes,
        probes: records,
        addition_probes,
        subtraction_probes,
        stable_failure_hash: Some(stable_failure_hash),
        status: if proven {
            DependencyReductionStatus::ProvenMinimal
        } else {
            DependencyReductionStatus::Inconclusive
        },
        authority: if proven {
            EvidenceGrade::Observed
        } else {
            EvidenceGrade::Inconclusive
        },
    })
}

fn baseline_probe_record(
    run_id: &str,
    run_root: &Path,
    plan: &ExecutionPlan,
    results: &BTreeMap<&str, &ExecutionResult>,
    candidate_id: &str,
) -> Result<Option<DependencyProbeRecord>> {
    let Some(scenario) = plan.scenarios.iter().find(|scenario| scenario.is_baseline) else {
        return Ok(None);
    };
    let Some(result) = results.get(scenario.id.as_str()).copied() else {
        return Ok(None);
    };
    let failure_hash = result
        .failure
        .as_ref()
        .map(|failure| ContentHash::try_from(failure.normalized_hash.as_str()))
        .transpose()
        .map_err(TcError::InvalidState)?;
    let resolved_manifest_sha256 = scenario
        .resolved_dependencies
        .as_ref()
        .map(|set| set.manifest_sha256.clone())
        .ok_or_else(|| {
            TcError::InvalidState("dependency baseline lacks exact resolved set".into())
        })?;
    Ok(Some(DependencyProbeRecord {
        sequence: 0,
        scenario_id: scenario.id.clone(),
        candidate_id: candidate_id.to_owned(),
        change_ids: vec![],
        subset_hash: dependency_subset_hash(&[])?,
        resolved_manifest_sha256,
        verdict: dependency_probe_verdict(result.verdict),
        failure_hash,
        evidence: dependency_probe_evidence(run_id, run_root, &scenario.id)?,
        authority: scenario.grade,
    }))
}

fn dependency_probe_evidence(
    run_id: &str,
    run_root: &Path,
    scenario_id: &str,
) -> Result<DependencyProbeEvidence> {
    let relative = format!("scenarios/{scenario_id}/result.json");
    let checksum = tomorrowci_evidence::file_checksum(&run_root.join(&relative))?;
    Ok(DependencyProbeEvidence {
        run_id: run_id.to_owned(),
        scenario_id: scenario_id.to_owned(),
        path: relative,
        checksum: ContentHash::try_from(checksum).map_err(TcError::InvalidState)?,
    })
}

fn dependency_subset_hash(changes: &[DependencyChange]) -> Result<ContentHash> {
    let mut normalized = changes.to_vec();
    normalized.sort_by(|left, right| left.id.cmp(&right.id));
    let hash = tomorrowci_core::canonical_json_hash(&normalized)?;
    ContentHash::try_from(hash).map_err(TcError::InvalidState)
}

fn dependency_probe_verdict(verdict: Verdict) -> DependencyProbeVerdict {
    match verdict {
        Verdict::BaselinePass | Verdict::FuturePass => DependencyProbeVerdict::Pass,
        Verdict::BaselineInvalid | Verdict::FutureFail => DependencyProbeVerdict::Fail,
        Verdict::Flaky => DependencyProbeVerdict::Flaky,
        Verdict::Blocked | Verdict::Unsupported => DependencyProbeVerdict::Blocked,
        Verdict::Inconclusive | Verdict::CoverageIncomplete => DependencyProbeVerdict::Inconclusive,
    }
}

pub fn load_dependency_experiment(
    workspace: &Path,
    ecosystem: Ecosystem,
    baseline_runtime: &str,
) -> Result<Option<DependencyExperiment>> {
    let path = workspace.join(DEPENDENCY_EXPERIMENT_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) || !metadata.is_file() {
        return Err(TcError::Config(format!(
            "dependency experiment manifest must be a plain file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(TcError::Config(format!(
            "dependency experiment manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let bytes = std::fs::read(&path)?;
    let manifest: DependencyExperimentManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            TcError::Config(format!("invalid {DEPENDENCY_EXPERIMENT_FILE}: {error}"))
        })?;
    validate_manifest(&manifest, ecosystem, baseline_runtime)?;

    let full = manifest
        .to_candidate_set(package_manager(ecosystem))
        .map_err(TcError::Config)?;
    for dependency in full
        .baseline
        .dependencies
        .iter()
        .chain(full.candidate.dependencies.iter())
    {
        let source = safe_source(workspace, &dependency.source)?;
        let actual = if manifest.schema_version == 2 {
            sha256_file_v1(&source)?
        } else {
            sha256_tree_v1(&source)?
        };
        if actual != dependency.content_sha256 {
            return Err(TcError::Blocked(format!(
                "dependency artifact {} {} content changed: declared={} actual={}",
                dependency.name, dependency.version, dependency.content_sha256, actual
            )));
        }
    }
    let mut change_ids: Vec<_> = full
        .changes
        .iter()
        .map(|change| change.id.clone())
        .collect();
    change_ids.sort();
    let subsets = if manifest.schema_version == 2 {
        tomorrowci_core::next_dependency_subset(&change_ids, &[])?;
        vec![change_ids]
    } else {
        exhaustive_nonempty_subsets(&change_ids)?
    };
    let mut experiment = DependencyExperiment {
        manifest,
        baseline: full.baseline,
        probes: Vec::new(),
    };
    for subset in subsets {
        experiment.probes.push(experiment.probe_for_subset(subset)?);
    }
    Ok(Some(experiment))
}

/// Build the exact, replayable commands that materialize a scenario's resolved
/// vendored set. Sources are content-verified before planning and every command
/// is persisted in the normal fetch evidence.
pub fn concrete_dependency_fetch_commands(
    ecosystem: Ecosystem,
    scenario: &Scenario,
) -> Result<Option<Vec<CommandSpec>>> {
    let Some(set) = scenario.resolved_dependencies.as_ref() else {
        return Ok(None);
    };
    set.validate().map_err(TcError::Config)?;
    if set.ecosystem != ecosystem {
        return Err(TcError::InvalidState(format!(
            "scenario {} dependency ecosystem {:?} does not match detected {:?}",
            scenario.id, set.ecosystem, ecosystem
        )));
    }
    tomorrowci_core::dependency_materialization_commands(scenario)
}

fn validate_manifest(
    manifest: &DependencyExperimentManifest,
    ecosystem: Ecosystem,
    baseline_runtime: &str,
) -> Result<()> {
    if !matches!(manifest.schema_version, 1 | 2) {
        return Err(TcError::Config(format!(
            "unsupported dependency experiment schema {}",
            manifest.schema_version
        )));
    }
    if manifest.ecosystem != ecosystem {
        return Err(TcError::Config(format!(
            "dependency experiment ecosystem {:?} does not match detected {:?}",
            manifest.ecosystem, ecosystem
        )));
    }
    if manifest.content_hash_algorithm
        != if manifest.schema_version == 2 {
            "sha256-file-v1"
        } else {
            "sha256-tree-v1"
        }
    {
        return Err(TcError::Config(format!(
            "unsupported dependency content hash algorithm {:?}",
            manifest.content_hash_algorithm
        )));
    }
    if manifest.runtime.version != baseline_runtime {
        return Err(TcError::Config(format!(
            "dependency experiment runtime {:?} does not match baseline {:?}",
            manifest.runtime.version, baseline_runtime
        )));
    }
    if manifest.runtime.container_image.trim().is_empty()
        || manifest.baseline.set_id.trim().is_empty()
        || manifest.candidate.set_id.trim().is_empty()
        || manifest.candidate.changes.is_empty()
    {
        return Err(TcError::Config(
            "dependency experiment identities and changes must not be empty".into(),
        ));
    }
    validate_image_digest(&manifest.runtime.container_image).map_err(|error| {
        TcError::Config(format!(
            "dependency experiment runtime image must be immutable: {error}"
        ))
    })?;

    let mut change_ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for change in &manifest.candidate.changes {
        validate_component(&change.id, "dependency change id")?;
        if change.name.trim().is_empty()
            || !change_ids.insert(change.id.clone())
            || !names.insert(change.name.clone())
        {
            return Err(TcError::Config(format!(
                "dependency change ids and names must be unique: {}",
                change.id
            )));
        }
    }

    Ok(())
}

fn exhaustive_nonempty_subsets(change_ids: &[String]) -> Result<Vec<Vec<String>>> {
    if change_ids.is_empty() || change_ids.len() > 8 {
        return Err(TcError::Config(
            "dependency experiments require between one and eight concrete changes".into(),
        ));
    }
    let full_mask = (1usize << change_ids.len()) - 1;
    let mut subsets = vec![change_ids.to_vec()];
    let mut remaining = Vec::new();
    for mask in 1..full_mask {
        let subset = change_ids
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1usize << index) != 0)
            .map(|(_, id)| id.clone())
            .collect::<Vec<_>>();
        remaining.push(subset);
    }
    remaining.sort_by(|left, right| left.len().cmp(&right.len()).then(left.cmp(right)));
    subsets.extend(remaining);
    Ok(subsets)
}

fn safe_source(workspace: &Path, source: &str) -> Result<PathBuf> {
    if source.is_empty()
        || source.starts_with('/')
        || source.starts_with('\\')
        || source.ends_with('/')
        || source.contains("//")
        || source.contains('\\')
        || source.contains(':')
        || source.contains('\0')
        || source.as_bytes().get(1) == Some(&b':')
        || source
            .split(['/', '\\'])
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(TcError::Config(format!(
            "dependency source is not a canonical workspace-relative path: {source:?}"
        )));
    }
    let mut current = workspace.to_path_buf();
    for component in source.split('/') {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata_is_alias(&metadata) {
            return Err(TcError::Config(format!(
                "dependency source contains an alias: {}",
                current.display()
            )));
        }
    }
    let path = workspace.join(source.replace('/', std::path::MAIN_SEPARATOR_STR));
    let canonical_workspace = std::fs::canonicalize(workspace).map_err(|error| {
        TcError::Blocked(format!(
            "dependency workspace is unavailable at {}: {error}",
            workspace.display()
        ))
    })?;
    let canonical_path = std::fs::canonicalize(&path).map_err(|error| {
        TcError::Blocked(format!(
            "dependency artifact is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if !canonical_path.starts_with(&canonical_workspace) {
        return Err(TcError::Config(format!(
            "dependency source escapes the workspace: {source:?}"
        )));
    }
    Ok(path)
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(TcError::Config(format!(
            "{label} is not a canonical identifier: {value:?}"
        )));
    }
    Ok(())
}

fn package_manager(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Python => "pip",
        Ecosystem::Node => "npm",
        Ecosystem::Rust => "cargo",
        Ecosystem::Unknown => "unknown",
    }
}

fn metadata_is_alias(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn tree_hash_is_ordered_and_content_sensitive() {
        let root = tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("z.txt"), "z\n").unwrap();
        std::fs::write(root.path().join("nested/a.txt"), "a\n").unwrap();
        let first = sha256_tree_v1(root.path()).unwrap();
        let second = sha256_tree_v1(root.path()).unwrap();
        assert_eq!(first, second);
        std::fs::write(root.path().join("nested/a.txt"), "changed\n").unwrap();
        assert_ne!(first, sha256_tree_v1(root.path()).unwrap());
    }

    #[test]
    fn unsafe_dependency_source_is_rejected() {
        let root = tempdir().unwrap();
        assert!(safe_source(root.path(), "../escape").is_err());
        assert!(safe_source(root.path(), "/absolute").is_err());
        assert!(safe_source(root.path(), "C:/drive").is_err());
    }

    fn write_wheel_experiment(root: &Path, count: usize) -> serde_json::Value {
        let artifact = |name: &str, version: &str| {
            let source = format!("{name}-{version}-py3-none-any.whl");
            std::fs::write(root.join(&source), format!("artifact {name} {version}")).unwrap();
            serde_json::json!({"source": source, "version": version,
                "content_sha256": sha256_file_v1(&root.join(source)).unwrap()})
        };
        let changes: Vec<_> = (0..count)
            .map(|i| {
                let name = format!("package-{i}");
                serde_json::json!({"id": name, "name": name,
                "before": artifact(&name, "1.0"), "after": artifact(&name, "2.0")})
            })
            .collect();
        let manifest = serde_json::json!({
            "schema_version": 2, "ecosystem": "python",
            "runtime": {"version": "3.11", "container_image": format!("python@sha256:{}", "a".repeat(64))},
            "content_hash_algorithm": "sha256-file-v1", "baseline": {"set_id": "before"},
            "candidate": {"set_id": "after", "changes": changes},
            "unchanged": [{"id": "fixed", "name": "fixed", "artifact": artifact("fixed", "3.0")}]
        });
        std::fs::write(
            root.join(DEPENDENCY_EXPERIMENT_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn wheel_experiment_keeps_full_closure_and_seeds_only_one_of_twelve_changes() {
        let root = tempdir().unwrap();
        write_wheel_experiment(root.path(), 12);
        let experiment = load_dependency_experiment(root.path(), Ecosystem::Python, "3.11")
            .unwrap()
            .unwrap();
        assert_eq!(experiment.probes.len(), 1);
        assert_eq!(experiment.baseline.dependencies.len(), 13);
        let probe = experiment
            .probe_for_subset(vec!["package-0".into()])
            .unwrap();
        assert_eq!(probe.dependency_set.candidate.dependencies.len(), 13);
        assert_eq!(
            probe
                .dependency_set
                .candidate
                .dependencies
                .iter()
                .filter(|d| d.version == "2.0")
                .count(),
            1
        );
        assert!(probe.id.len() < 32);
        assert!(probe
            .dependency_set
            .candidate
            .dependencies
            .iter()
            .any(|d| d.name == "fixed" && d.version == "3.0"));
    }

    #[test]
    fn unchanged_wheel_tampering_is_rejected_before_execution() {
        let root = tempdir().unwrap();
        write_wheel_experiment(root.path(), 1);
        std::fs::write(root.path().join("fixed-3.0-py3-none-any.whl"), "tampered").unwrap();
        let error = load_dependency_experiment(root.path(), Ecosystem::Python, "3.11")
            .unwrap_err()
            .to_string();
        assert!(error.contains("content changed"), "{error}");
    }

    #[test]
    fn wheel_contract_rejects_duplicate_fixed_members_and_unbounded_identifiers() {
        let root = tempdir().unwrap();
        let value = write_wheel_experiment(root.path(), 1);
        let mut manifest: DependencyExperimentManifest = serde_json::from_value(value).unwrap();
        manifest.unchanged.push(manifest.unchanged[0].clone());
        assert!(manifest.to_candidate_set("pip").is_err());
        manifest.unchanged.pop();
        manifest.candidate.set_id = "baseline".into();
        assert!(manifest.to_candidate_set("pip").is_err());
        manifest.candidate.set_id = "dep-0123456789abcdef0123".into();
        assert!(manifest.to_candidate_set("pip").is_err());
        manifest.candidate.set_id = "after".into();
        manifest.candidate.changes[0].name = "--bad-option".into();
        assert!(manifest.to_candidate_set("pip").is_err());
    }

    #[test]
    fn mutable_dependency_runtime_image_is_rejected_on_production_load_path() {
        let root = tempdir().unwrap();
        let digest = format!("sha256:{}", "0".repeat(64));
        let manifest = serde_json::json!({
            "schema_version": 1,
            "ecosystem": "python",
            "runtime": {
                "version": "3.11",
                "container_image": "python:latest"
            },
            "content_hash_algorithm": "sha256-tree-v1",
            "baseline": { "set_id": "baseline" },
            "candidate": {
                "set_id": "candidate",
                "changes": [{
                    "id": "breaking-api",
                    "name": "example",
                    "before": {
                        "version": "1.0.0",
                        "source": "vendor/v1",
                        "content_sha256": digest
                    },
                    "after": {
                        "version": "2.0.0",
                        "source": "vendor/v2",
                        "content_sha256": format!("sha256:{}", "1".repeat(64))
                    }
                }]
            }
        });
        std::fs::write(
            root.path().join(DEPENDENCY_EXPERIMENT_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let error = load_dependency_experiment(root.path(), Ecosystem::Python, "3.11")
            .unwrap_err()
            .to_string();
        assert!(error.contains("runtime image must be immutable"), "{error}");
    }
}
