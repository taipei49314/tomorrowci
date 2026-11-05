//! Verify a rollback in a separate, independently verifiable experiment.
//! A minimal failing subset is never itself evidence that its complement passes.

use crate::orchestrate::{replay_scenario, scan_local_into, ScanOptions};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tomorrowci_core::{
    Config, DependencyExperimentManifest, DependencyFixedDeclaration, DependencyReduction,
    DependencyReductionStatus, Ecosystem, EvidenceGrade, ExecutionResult, Result, RunManifest,
    TcError, Verdict,
};
use tomorrowci_evidence::{
    file_checksum, metadata_is_alias, validate_existing_ancestors, validate_identifier,
    verify_run_root, ChecksumCompatibility, WorkspaceManifest,
};

const EXPERIMENT: &str = ".tomorrowci-dependencies.json";
const REQUEST: &str = "rollback-request.json";
const RESULT: &str = "rollback-result.json";
const SCOPE: &str = "Only VERIFIED_COMMANDS_PASS establishes that the selected unchanged commands passed and replayed for this exact rollback/runtime. It does not establish universal compatibility, test-ID equality, or a globally minimal repair.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub schema_version: u32,
    pub diagnosis_run_id: String,
    pub diagnosis_files: BTreeMap<String, String>,
    pub rolled_back_change_ids: Vec<String>,
    pub retained_change_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackStatus {
    PreparedNotExecuted,
    NoRetainedUpdates,
    ValidationFailed,
    VerifiedCommandsPass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackResult {
    pub schema_version: u32,
    pub status: RollbackStatus,
    pub diagnosis_run_id: String,
    pub validation_run_id: Option<String>,
    pub candidate_scenario_id: Option<String>,
    pub replay_attempt: Option<u32>,
    pub artifacts: BTreeMap<String, String>,
    pub scope: String,
}

struct Proposal {
    request: RollbackRequest,
    experiment: DependencyExperimentManifest,
    config: Config,
    workspace: WorkspaceManifest,
    artifacts: BTreeMap<String, String>,
}

fn invalid(message: impl Into<String>) -> TcError {
    TcError::InvalidState(message.into())
}

fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    validate_existing_ancestors(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata_is_alias(&metadata) || metadata.len() > 16 * 1024 * 1024 {
        return Err(invalid(format!(
            "invalid rollback record: {}",
            path.display()
        )));
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn verified_run(root: &Path) -> Result<RunManifest> {
    let report = verify_run_root(root)?;
    if !report.ok || report.checksum_compatibility != ChecksumCompatibility::CurrentV2 {
        return Err(invalid(format!(
            "rollback requires verified current-v2 evidence: {:?}",
            report.errors
        )));
    }
    json(&root.join("run.json"))
}

fn successful(result: &ExecutionResult, verdict: Verdict) -> bool {
    result.verdict == verdict
        // The runner stops on the first passing attempt. A baseline that only
        // passes after an earlier failure is not a stable repair control.
        && result.attempt == 1
        && result.exit_code == Some(0)
        && !result.timed_out
        && result.failure.is_none()
}

fn canonical_destination(path: &Path) -> Result<std::path::PathBuf> {
    let mut ancestor = path;
    let mut tail = Vec::new();
    while !ancestor.exists() {
        tail.push(
            ancestor
                .file_name()
                .ok_or_else(|| invalid("invalid rollback output"))?,
        );
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("rollback output has no existing ancestor"))?;
    }
    let mut resolved = std::fs::canonicalize(ancestor)?;
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn propose(root: &Path) -> Result<Proposal> {
    let manifest = verified_run(root)?;
    if root.join("remote-source.json").exists() {
        return Err(invalid("rollback currently requires a local dependency trial; remote synthetic Git environments must not be silently changed"));
    }
    let mut experiment: DependencyExperimentManifest =
        json(&root.join("dependency-experiment.json"))?;
    if experiment.schema_version != 2 || experiment.ecosystem != Ecosystem::Python {
        return Err(invalid(
            "rollback currently requires a Python wheel-backed v2 dependency experiment",
        ));
    }
    let reduction: DependencyReduction = json(&root.join("reduction.json"))?;
    if reduction.status != DependencyReductionStatus::ProvenMinimal
        || reduction.authority != EvidenceGrade::Observed
    {
        return Err(invalid("rollback requires an observed PROVEN_MINIMAL diagnosis; unresolved results cannot propose a repair"));
    }
    let baseline = manifest
        .results
        .iter()
        .find(|r| r.scenario_id == "baseline");
    if !baseline.is_some_and(|r| successful(r, Verdict::BaselinePass)) {
        return Err(invalid("rollback diagnosis has no passing baseline"));
    }
    let full = experiment.to_candidate_set("pip").map_err(invalid)?;
    let all: BTreeSet<_> = full.changes.iter().map(|c| c.id.clone()).collect();
    let rolled: BTreeSet<_> = reduction
        .minimal_changes
        .iter()
        .map(|c| c.id.clone())
        .collect();
    if rolled.is_empty()
        || !rolled.is_subset(&all)
        || rolled.len() != reduction.minimal_changes.len()
    {
        return Err(invalid(
            "rollback diagnosis does not identify a unique nonempty subset",
        ));
    }
    let retained: Vec<_> = all.difference(&rolled).cloned().collect();
    let mut diagnosis_files = BTreeMap::new();
    for name in [
        "run.json",
        "workspace-manifest.json",
        "dependency-experiment.json",
        "reduction.json",
        "config.normalized.json",
    ] {
        diagnosis_files.insert(name.into(), file_checksum(&root.join(name))?);
    }
    let request = RollbackRequest {
        schema_version: 1,
        diagnosis_run_id: manifest.run_id,
        diagnosis_files,
        rolled_back_change_ids: rolled.iter().cloned().collect(),
        retained_change_ids: retained,
    };
    let chosen: Vec<_> = full
        .changes
        .iter()
        .filter(|c| !rolled.contains(&c.id))
        .cloned()
        .collect();
    let repaired = full.resolution_for_changes(&chosen).map_err(invalid)?;
    let after = full.candidate;
    let pins = |set: &tomorrowci_core::ResolvedDependencySet| {
        let mut rows: Vec<_> = set
            .dependencies
            .iter()
            .map(|d| format!("{}=={} --hash={}\n", d.name, d.version, d.content_sha256))
            .collect();
        rows.sort();
        rows.join("")
    };
    let old_text = pins(&after);
    let repaired_text = pins(&repaired);
    let before_text = pins(&full.baseline);
    let patch =
        format!(
        "--- a/requirements.after.txt\n+++ b/requirements.rollback.txt\n@@ -1,{} +1,{} @@\n{}{}",
        old_text.lines().count(), repaired_text.lines().count(),
        old_text.lines().map(|s| format!("-{s}\n")).collect::<String>(),
        repaired_text.lines().map(|s| format!("+{s}\n")).collect::<String>()
    );
    let artifacts = BTreeMap::from([
        ("requirements.before.txt".into(), before_text),
        ("requirements.after.txt".into(), old_text),
        ("requirements.rollback.txt".into(), repaired_text),
        ("requirements.patch".into(), patch),
    ]);
    experiment = rollback_experiment(experiment, &rolled);
    if !request.retained_change_ids.is_empty() {
        experiment.to_candidate_set("pip").map_err(invalid)?;
    }
    let mut config: Config = json(&root.join("config.normalized.json"))?;
    config.execution.max_scenarios = 2;
    config.validate()?;
    let workspace = json(&root.join("workspace-manifest.json"))?;
    Ok(Proposal {
        request,
        experiment,
        config,
        workspace,
        artifacts,
    })
}

fn rollback_experiment(
    mut experiment: DependencyExperimentManifest,
    rolled: &BTreeSet<String>,
) -> DependencyExperimentManifest {
    let mut kept = Vec::new();
    for change in experiment.candidate.changes.drain(..) {
        if rolled.contains(&change.id) {
            experiment.unchanged.push(DependencyFixedDeclaration {
                id: change.id,
                name: change.name,
                artifact: change.before,
            });
        } else {
            kept.push(change);
        }
    }
    experiment.candidate.changes = kept;
    experiment.candidate.set_id = "rollback-validation".into();
    experiment.unchanged.sort_by(|a, b| a.id.cmp(&b.id));
    experiment
}

fn expected_workspace(proposal: &Proposal, old_root: &Path, new_root: &Path) -> Result<()> {
    // Permit exactly one source-file replacement: the dependency experiment.
    // Tests, configuration files, wheel bytes and all other source stay exact.
    let new: WorkspaceManifest = json(&new_root.join("workspace-manifest.json"))?;
    if proposal.workspace.files.keys().collect::<Vec<_>>() != new.files.keys().collect::<Vec<_>>() {
        return Err(invalid(
            "rollback validation changed the source file inventory",
        ));
    }
    for (name, meta) in &proposal.workspace.files {
        if name != EXPERIMENT && new.files.get(name) != Some(meta) {
            return Err(invalid(format!(
                "rollback validation changed source/test file {name}"
            )));
        }
    }
    let actual: DependencyExperimentManifest = json(&new_root.join("dependency-experiment.json"))?;
    if actual != proposal.experiment {
        return Err(invalid(
            "rollback dependency set is not full after minus exactly the diagnosed updates",
        ));
    }
    let actual_config: Config = json(&new_root.join("config.normalized.json"))?;
    if serde_json::to_value(actual_config)? != serde_json::to_value(&proposal.config)? {
        return Err(invalid(
            "rollback changed the original test/build/runtime/sandbox configuration",
        ));
    }
    for (name, checksum) in &proposal.request.diagnosis_files {
        if file_checksum(&old_root.join(name))? != *checksum {
            return Err(invalid("diagnosis changed while rollback was checked"));
        }
    }
    Ok(())
}

fn candidate_passes(manifest: &RunManifest) -> bool {
    manifest.plan.scenarios.len() == 2
        && manifest
            .plan
            .scenarios
            .iter()
            .all(|s| s.grade == EvidenceGrade::Observed)
        && manifest.results.len() == 2
        && manifest
            .results
            .iter()
            .any(|r| r.scenario_id == "baseline" && successful(r, Verdict::BaselinePass))
        && manifest
            .results
            .iter()
            .any(|r| r.scenario_id == "rollback-validation" && successful(r, Verdict::FuturePass))
}

/// Preserve the original diagnosis and test its complement in a new run.
/// Only verified success followed by a successful replay publishes repair pins.
pub fn validate_python_rollback(diagnosis_root: &Path, output: &Path) -> Result<RollbackResult> {
    let proposal = propose(diagnosis_root)?;
    let output = validate_existing_ancestors(output)?;
    let diagnosis_root = validate_existing_ancestors(diagnosis_root)?;
    let resolved_output = canonical_destination(&output)?;
    let resolved_diagnosis = std::fs::canonicalize(&diagnosis_root)?;
    if resolved_output.starts_with(&resolved_diagnosis)
        || resolved_diagnosis.starts_with(&resolved_output)
    {
        return Err(invalid(
            "rollback output and diagnosis directories must not overlap",
        ));
    }
    std::fs::create_dir(&output)
        .map_err(|e| invalid(format!("rollback output must be a new directory: {e}")))?;
    save(&output.join(REQUEST), &proposal.request)?;
    let mut record = RollbackResult {
        schema_version: 1,
        status: RollbackStatus::PreparedNotExecuted,
        diagnosis_run_id: proposal.request.diagnosis_run_id.clone(),
        validation_run_id: None,
        candidate_scenario_id: None,
        replay_attempt: None,
        artifacts: BTreeMap::new(),
        scope: SCOPE.into(),
    };
    if proposal.request.retained_change_ids.is_empty() {
        record.status = RollbackStatus::NoRetainedUpdates;
        save(&output.join(RESULT), &record)?;
        return Ok(record);
    }
    save(&output.join(RESULT), &record)?;
    let source = output.join("source");
    std::fs::create_dir(&source)?;
    for (name, meta) in &proposal.workspace.files {
        let old = diagnosis_root.join("workspace").join(name);
        validate_existing_ancestors(&old)?;
        let new = source.join(name);
        if let Some(parent) = new.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&old, &new)?;
        if file_checksum(&new)? != meta.sha256 || std::fs::metadata(&new)?.len() != meta.size {
            return Err(invalid(format!(
                "diagnosis workspace changed while copying {name}"
            )));
        }
    }
    save(&source.join(EXPERIMENT), &proposal.experiment)?;
    // Snapshot equality and semantic verification are checked again before any
    // target execution. Only the separately verified experiment file may differ.
    verified_run(&diagnosis_root)?;
    for (name, checksum) in &proposal.request.diagnosis_files {
        if file_checksum(&diagnosis_root.join(name))? != *checksum {
            return Err(invalid("diagnosis changed before rollback execution"));
        }
    }
    let outcome = scan_local_into(
        &source,
        &output,
        ScanOptions {
            config: proposal.config.clone(),
            allow_scripted: false,
        },
        false,
    )?;
    record.validation_run_id = Some(outcome.manifest.run_id.clone());
    record.candidate_scenario_id = Some("rollback-validation".into());
    record.status = RollbackStatus::ValidationFailed;
    save(&output.join(RESULT), &record)?;
    let validated = verified_run(&outcome.evidence_root)?;
    expected_workspace(&proposal, &diagnosis_root, &outcome.evidence_root)?;
    if !candidate_passes(&validated) {
        return Ok(record);
    }
    let replay = replay_scenario(&output, &validated.run_id, "rollback-validation");
    match replay {
        Ok(text) => std::fs::write(output.join("replay.txt"), text)?,
        Err(error) => {
            std::fs::write(output.join("replay-error.txt"), error.to_string())?;
            return Ok(record);
        }
    }
    verified_run(&outcome.evidence_root)?;
    record.replay_attempt = Some(1);
    record.status = RollbackStatus::VerifiedCommandsPass;
    for (name, text) in &proposal.artifacts {
        std::fs::write(output.join(name), text)?;
        record
            .artifacts
            .insert(name.clone(), file_checksum(&output.join(name))?);
    }
    save(&output.join(RESULT), &record)?;
    finalize_publication(&output, &mut record, || {
        verify_python_rollback(&diagnosis_root, &output)
    })
}

fn finalize_publication(
    output: &Path,
    record: &mut RollbackResult,
    verify: impl FnOnce() -> Result<RollbackResult>,
) -> Result<RollbackResult> {
    match verify() {
        Ok(verified) => Ok(verified),
        Err(error) => {
            // Preserve raw failed evidence, but never leave a success claim or
            // repair pins after the final cross-run check failed.
            record.status = RollbackStatus::ValidationFailed;
            let names: Vec<_> = record.artifacts.keys().cloned().collect();
            record.artifacts.clear();
            save(&output.join(RESULT), record)?;
            for name in names {
                let path = output.join(name);
                if path.exists() {
                    std::fs::remove_file(path)?;
                }
            }
            Err(error)
        }
    }
}

/// Independently rebuild the proposed dependency set and repair text, verify
/// both runs, and require a passing candidate plus replay before trusting it.
pub fn verify_python_rollback(diagnosis_root: &Path, output: &Path) -> Result<RollbackResult> {
    let proposal = propose(diagnosis_root)?;
    let request: RollbackRequest = json(&output.join(REQUEST))?;
    if request != proposal.request {
        return Err(invalid(
            "rollback request is not derived from the verified diagnosis",
        ));
    }
    let record: RollbackResult = json(&output.join(RESULT))?;
    if record.schema_version != 1
        || record.diagnosis_run_id != request.diagnosis_run_id
        || record.scope != SCOPE
    {
        return Err(invalid("rollback result identity is inconsistent"));
    }
    if record.status != RollbackStatus::VerifiedCommandsPass {
        return Err(invalid(format!(
            "rollback did not establish a verified passing repair: {:?}",
            record.status
        )));
    }
    if request.retained_change_ids.is_empty()
        || record.replay_attempt != Some(1)
        || record.candidate_scenario_id.as_deref() != Some("rollback-validation")
    {
        return Err(invalid(
            "rollback success is missing retained updates or candidate replay",
        ));
    }
    let run_id = record
        .validation_run_id
        .as_deref()
        .ok_or_else(|| invalid("missing validation run"))?;
    validate_identifier(run_id, "rollback run_id").map_err(invalid)?;
    let root = output.join(".tomorrowci/runs").join(run_id);
    let manifest = verified_run(&root)?;
    expected_workspace(&proposal, diagnosis_root, &root)?;
    if !candidate_passes(&manifest) {
        return Err(invalid(
            "rollback candidate did not pass the original commands",
        ));
    }
    require_successful_replays(&root.join("scenarios/rollback-validation/replays"))?;
    if record.artifacts.len() != proposal.artifacts.len() {
        return Err(invalid("rollback repair artifact inventory differs"));
    }
    for (name, expected) in &proposal.artifacts {
        let path = output.join(name);
        validate_existing_ancestors(&path)?;
        if std::fs::read(&path)? != expected.as_bytes()
            || record.artifacts.get(name) != Some(&file_checksum(&path)?)
        {
            return Err(invalid(format!(
                "rollback repair artifact is not derived from verified inputs: {name}"
            )));
        }
    }
    Ok(record)
}

fn require_successful_replays(replays: &Path) -> Result<()> {
    // A later, properly recorded failed replay invalidates an earlier repair
    // success. Never cherry-pick attempt-1 from an internally valid run.
    json::<serde_json::Value>(&replays.join("attempt-1/result.json"))?;
    for entry in std::fs::read_dir(replays)? {
        let entry = entry?;
        let replay: serde_json::Value = json(&entry.path().join("result.json"))?;
        if replay["ok"] != true
            || replay["replay_exit"] != 0
            || replay["timed_out"] != false
            || replay["exit_match"] != true
            || replay["signature_match"] != true
        {
            return Err(invalid("rollback replay did not reproduce success"));
        }
    }
    Ok(())
}

pub fn render_rollback_summary(record: &RollbackResult, output: &Path) -> String {
    format!("Rollback validation: {:?}\nDiagnosis: {}\nValidation run: {}\nEvidence and repair files: {}\n{}\n",
        record.status, record.diagnosis_run_id,
        record.validation_run_id.as_deref().unwrap_or("NOT_RUN"), output.display(), record.scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_then_passing_baseline_and_incomplete_candidates_are_not_repair_controls() {
        let mut result: ExecutionResult = serde_json::from_value(serde_json::json!({
            "scenario_id":"baseline", "attempt":1, "verdict":"BASELINE_PASS",
            "exit_code":0, "duration_ms":10, "timed_out":false, "failure":null,
            "commands":[], "environment":{
                "image":"python", "image_digest":null, "workdir":"/work", "env":{},
                "network_mode":"none", "memory_mb":512, "cpus":1.0, "pids_limit":128,
                "user":null, "read_only_root":true
            }
        }))
        .unwrap();
        assert!(successful(&result, Verdict::BaselinePass));
        result.attempt = 2; // Existing runner labels fail -> pass as BASELINE_PASS.
        assert!(!successful(&result, Verdict::BaselinePass));
        result.attempt = 1;
        for verdict in [
            Verdict::Flaky,
            Verdict::Blocked,
            Verdict::Unsupported,
            Verdict::CoverageIncomplete,
            Verdict::Inconclusive,
        ] {
            result.verdict = verdict;
            assert!(!successful(&result, Verdict::FuturePass));
        }
        result.verdict = Verdict::FuturePass;
        result.timed_out = true;
        assert!(!successful(&result, Verdict::FuturePass));
    }

    #[test]
    fn a_later_failed_or_timeout_replay_invalidates_the_earlier_pass() {
        let dir = tempfile::tempdir().unwrap();
        let good = serde_json::json!({"ok":true, "replay_exit":0, "timed_out":false,
                                     "exit_match":true, "signature_match":true});
        std::fs::create_dir(dir.path().join("attempt-1")).unwrap();
        save(&dir.path().join("attempt-1/result.json"), &good).unwrap();
        assert!(require_successful_replays(dir.path()).is_ok());
        std::fs::create_dir(dir.path().join("attempt-2")).unwrap();
        for (field, value) in [
            ("ok", serde_json::json!(false)),
            ("timed_out", serde_json::json!(true)),
            ("replay_exit", serde_json::json!(1)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            save(&dir.path().join("attempt-2/result.json"), &bad).unwrap();
            assert!(require_successful_replays(dir.path()).is_err());
        }
        save(&dir.path().join("attempt-2/result.json"), &good).unwrap();
        assert!(require_successful_replays(dir.path()).is_ok());
    }

    #[test]
    fn final_verifier_failure_revokes_published_repair() {
        let dir = tempfile::tempdir().unwrap();
        let name = "requirements.rollback.txt";
        std::fs::write(dir.path().join(name), "unsafe==2\n").unwrap();
        let mut record = RollbackResult {
            schema_version: 1,
            status: RollbackStatus::VerifiedCommandsPass,
            diagnosis_run_id: "diagnosis".into(),
            validation_run_id: Some("validation".into()),
            candidate_scenario_id: Some("rollback-validation".into()),
            replay_attempt: Some(1),
            artifacts: BTreeMap::from([(name.into(), "sha256:invalid".into())]),
            scope: SCOPE.into(),
        };
        save(&dir.path().join(RESULT), &record).unwrap();
        let result = finalize_publication(dir.path(), &mut record, || {
            Err(invalid("injected final verification failure"))
        });
        assert!(result.is_err());
        let saved: RollbackResult = json(&dir.path().join(RESULT)).unwrap();
        assert_eq!(saved.status, RollbackStatus::ValidationFailed);
        assert!(saved.artifacts.is_empty());
        assert!(!dir.path().join(name).exists());
    }

    #[test]
    fn destination_resolution_preserves_nonexistent_tail() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("new/child");
        assert_eq!(
            canonical_destination(&output).unwrap(),
            std::fs::canonicalize(dir.path()).unwrap().join("new/child")
        );
        assert!(!output.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_variant_cannot_hide_nested_output() {
        let dir = tempfile::tempdir().unwrap();
        let diagnosis = dir.path().join("DiagnosisCase");
        std::fs::create_dir(&diagnosis).unwrap();
        let output = dir.path().join("DIAGNOSISCASE/new/child");
        assert!(canonical_destination(&output)
            .unwrap()
            .starts_with(std::fs::canonicalize(&diagnosis).unwrap()));
        assert!(!output.exists());
    }
}
