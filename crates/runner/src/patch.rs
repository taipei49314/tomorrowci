//! Patch Lab: apply a strict text patch only to a disposable source copy, run
//! the ordinary container scan, exact-replay every scenario, and seal a proof
//! that is independent from both run bundles.

use super::*;
use std::fs::Metadata;
use std::io::Write;
use tomorrowci_core::{
    patch::{
        PatchDisposition, PatchProof, PatchReplayOutcome, PatchReplayReceipt, PatchScenarioRepair,
        PatchSourceBinding, ValidatedPatch, DEFAULT_MAX_PATCH_BYTES, DEFAULT_MAX_PATCH_FILES,
        DEFAULT_MAX_PATCH_WITNESS_BYTES, PATCH_PROOF_SCHEMA_VERSION,
    },
    ExactReplayManifestV2, ScenarioKind, SourceFileEntryV2, SourceSnapshotManifestV2,
};
use tomorrowci_evidence::{
    verify_patch_proof_bundle, write_independent_attempt_bundle_v2, BundleKind, VerifiedPatchProof,
    INVENTORY_VERSION_V2,
};

#[derive(Debug, Clone)]
pub struct PatchLabRequest {
    /// Verifier-owned path to the original sealed v2 run bundle.
    pub original_run_dir: PathBuf,
    /// Verifier-owned exact source tree matching that run's source manifest.
    pub original_workspace: PathBuf,
    pub patch_file: PathBuf,
    pub output_root: PathBuf,
    pub work_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PatchLabOutcome {
    pub disposition: PatchDisposition,
    pub disposition_reason: String,
    pub proof_dir: PathBuf,
    pub proof_sha256: String,
    pub proof_inventory_sha256: String,
    pub patched_run_id: String,
    pub patched_run_dir: PathBuf,
}

impl PatchLabOutcome {
    pub fn is_green(&self) -> bool {
        self.disposition.is_green()
    }
}

pub async fn patch_lab(req: PatchLabRequest) -> Result<PatchLabOutcome> {
    let patch_bytes = read_patch_file(&req.patch_file)?;
    let patch = tomorrowci_core::validate_unified_patch(
        &patch_bytes,
        DEFAULT_MAX_PATCH_BYTES,
        DEFAULT_MAX_PATCH_FILES,
    )
    .map_err(|error| RunnerError::Msg(format!("BLOCKED: invalid patch: {error}")))?;
    let patch_text = std::str::from_utf8(&patch_bytes)
        .expect("strict patch validation already accepted UTF-8 bytes");
    if redact_secrets(patch_text) != patch_text {
        return Err(RunnerError::Msg(
            "BLOCKED: patch contains secret-like material that cannot be sealed safely".into(),
        ));
    }

    let original_verified =
        tomorrowci_evidence::verify_bundle(&req.original_run_dir).map_err(|error| {
            RunnerError::Msg(format!("BLOCKED: original run is not sealed: {error}"))
        })?;
    if original_verified.kind != BundleKind::Run
        || original_verified.version != INVENTORY_VERSION_V2
    {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: Patch Lab requires a sealed v2 run, got {:?} v{}",
            original_verified.kind, original_verified.version
        )));
    }
    let original_run: RunManifest = original_verified
        .read_json("run.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let original_source: SourceSnapshotManifestV2 = original_verified
        .read_json("source-manifest.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let config: Config = original_verified
        .read_json("config.normalized.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let original_verdicts: Vec<ScenarioVerdict> = original_verified
        .read_json("verdicts.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let original_frontier: BreakageFrontier = original_verified
        .read_json("frontier.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let original_binding = run_binding(
        &original_verified,
        &original_run,
        &original_source,
        &config,
        &original_verdicts,
    )?;
    ensure_source_matches(&req.original_workspace, &original_source)?;

    let lab_id = RunId::new().0;
    // Keep the proposed source outside any parent Git worktree. Otherwise
    // `git rev-parse` could accidentally bind the disposable copy to the
    // TomorrowCI/operator repository that happens to contain --work-root.
    let lab_temp = tempfile::Builder::new()
        .prefix("tomorrowci-patch-lab-")
        .tempdir()
        .map_err(|error| RunnerError::Msg(format!("create Patch Lab workspace: {error}")))?;
    let lab_root = lab_temp.path();
    let trusted_patch_file = lab_root.join("proposal.patch");
    write_new_file(&trusted_patch_file, &patch_bytes, "stage exact patch bytes")?;
    let disposable = lab_root.join("source");
    strict_materialize_manifest(&req.original_workspace, &disposable, &original_source)?;
    ensure_source_matches(&disposable, &original_source)?;
    ensure_patch_targets_safe(&disposable, &patch)?;
    apply_validated_patch(&disposable, &trusted_patch_file)?;

    let applied_source = capture_source_snapshot_v2(
        &RunId(format!("patch{lab_id}")),
        &disposable,
        "patch-lab-disposable",
        None,
        SourceIdentityKindV2::NonGit,
        false,
        Utc::now(),
    )
    .map_err(|error| RunnerError::Msg(format!("BLOCKED: patched tree is unsafe: {error}")))?;
    if applied_source.tree_sha256 == original_source.tree_sha256 {
        return Err(RunnerError::Msg(
            "BLOCKED: patch made no content change to the disposable source tree".into(),
        ));
    }

    // The scan workspace must remain available for later user-requested
    // replay, so only the pre-scan patch copy is temporary.
    let scan_work_root = req.work_root.join("patch-lab-scans").join(&lab_id);
    let patched_outcome = scan(ScanRequest {
        target: disposable.display().to_string(),
        config: config.clone(),
        config_path: None,
        output_root: req.output_root.clone(),
        work_root: scan_work_root,
    })
    .await?;
    let patched_verified = tomorrowci_evidence::verify_bundle(&patched_outcome.evidence_dir)
        .map_err(|error| {
            RunnerError::Msg(format!("BLOCKED: patched run did not verify: {error}"))
        })?;
    let patched_source: SourceSnapshotManifestV2 = patched_verified
        .read_json("source-manifest.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let patched_config: Config = patched_verified
        .read_json("config.normalized.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let patched_verdicts: Vec<ScenarioVerdict> = patched_verified
        .read_json("verdicts.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let patched_binding = run_binding(
        &patched_verified,
        &patched_outcome.manifest,
        &patched_source,
        &patched_config,
        &patched_verdicts,
    )?;
    if patched_source.tree_sha256 != applied_source.tree_sha256 {
        return Err(RunnerError::Msg(
            "BLOCKED: scan workspace does not contain the exact patched source tree".into(),
        ));
    }

    let patch_hex = patch
        .sha256
        .strip_prefix("sha256:")
        .unwrap_or(&patch.sha256);
    ensure_safe_directory(&req.output_root, false)?;
    let patches_root = req.output_root.join("patches");
    ensure_safe_directory(&patches_root, true)?;
    let proof_dir = patches_root.join(format!(
        "{}-{}-{}",
        original_run.run_id.0,
        &patch_hex[..16.min(patch_hex.len())],
        patched_outcome.run_id.0
    ));
    if std::fs::symlink_metadata(&proof_dir).is_ok() {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: refusing to overwrite PatchProof directory {}",
            proof_dir.display()
        )));
    }
    std::fs::create_dir(&proof_dir)
        .map_err(|error| RunnerError::Msg(format!("create PatchProof directory: {error}")))?;

    let replay_receipts = replay_patched_scenarios(
        &proof_dir,
        &patched_outcome,
        &patched_verified,
        &patched_source,
        &patched_config,
    )
    .await?;
    write_patch_source_witnesses(
        &proof_dir,
        &patch,
        &req.original_workspace,
        &original_source,
        &disposable,
        &patched_source,
    )?;
    let repaired_scenarios = repaired_scenario_witness(
        &original_frontier,
        &original_verdicts,
        &patched_verdicts,
        &replay_receipts,
    );

    let original_unchanged = original_still_matches(
        &req.original_run_dir,
        &req.original_workspace,
        &original_binding,
        &original_source,
    );
    let mut proof = PatchProof {
        schema_version: PATCH_PROOF_SCHEMA_VERSION,
        created_at: Utc::now(),
        original: original_binding,
        original_had_observed_breakage: original_frontier.observed,
        patch,
        patched: patched_binding,
        repaired_scenarios,
        replay_receipts,
        original_unchanged,
        disposition: PatchDisposition::Proposal,
        disposition_reason: String::new(),
    };
    (proof.disposition, proof.disposition_reason) = proof.evaluate_disposition();

    write_new_file(
        &proof_dir.join("proposal.patch"),
        &patch_bytes,
        "write sealed patch",
    )?;
    let proof_json =
        serde_json::to_vec_pretty(&proof).map_err(|error| RunnerError::Msg(error.to_string()))?;
    write_new_file(
        &proof_dir.join("patch-proof.json"),
        &proof_json,
        "write PatchProof",
    )?;
    tomorrowci_evidence::seal_bundle(&proof_dir, BundleKind::Generic)
        .map_err(|error| RunnerError::Msg(format!("seal PatchProof: {error}")))?;
    let verified = verify_patch_proof_bundle(
        &proof_dir,
        &req.original_run_dir,
        &patched_outcome.evidence_dir,
    )
    .map_err(|error| {
        RunnerError::Msg(format!("BLOCKED: PatchProof verification failed: {error}"))
    })?;
    Ok(outcome_from_verified(
        verified,
        proof_dir,
        patched_outcome.evidence_dir,
    ))
}

fn outcome_from_verified(
    verified: VerifiedPatchProof,
    proof_dir: PathBuf,
    patched_run_dir: PathBuf,
) -> PatchLabOutcome {
    PatchLabOutcome {
        disposition: verified.proof.disposition,
        disposition_reason: verified.proof.disposition_reason,
        proof_dir,
        proof_sha256: verified.proof_sha256,
        proof_inventory_sha256: verified.sealed_inventory_sha256,
        patched_run_id: verified.proof.patched.run_id,
        patched_run_dir,
    }
}

async fn replay_patched_scenarios(
    proof_dir: &Path,
    outcome: &ScanOutcome,
    verified_run: &VerifiedBundle,
    source: &SourceSnapshotManifestV2,
    config: &Config,
) -> Result<Vec<PatchReplayReceipt>> {
    let mut receipts = Vec::new();
    let workspace = &outcome.manifest.repository.workspace_copy;
    ensure_source_matches(workspace, source)?;
    let engine = detect_engine("auto")
        .map_err(|error| format!("BLOCKED: exact replay engine is unavailable: {error}"));
    let context = ReplayContextV2 {
        run_id: outcome.run_id.clone(),
        source_manifest_sha256: canonical_sha256(source)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        config_sha256: canonical_sha256(config)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
    };

    for verdict in &outcome.verdicts {
        let scenario_id = &verdict.scenario_id.0;
        let scenario_path = verified_run.root.join("scenarios").join(scenario_id);
        let scenario_verified = match tomorrowci_evidence::verify_bundle(&scenario_path) {
            Ok(bundle) if bundle.kind == BundleKind::Scenario => bundle,
            Ok(bundle) => {
                receipts.push(blocked_receipt(
                    verdict,
                    ScenarioKind::Replay,
                    format!("scenario evidence has kind {:?}", bundle.kind),
                ));
                continue;
            }
            Err(error) => {
                receipts.push(blocked_receipt(
                    verdict,
                    ScenarioKind::Replay,
                    format!("sealed scenario evidence unavailable: {error}"),
                ));
                continue;
            }
        };
        let scenario: Scenario = scenario_verified
            .read_json("scenario.json")
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let manifest: ExactReplayManifestV2 = scenario_verified
            .read_json("replay-manifest-v2.json")
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let environment: EnvironmentSpec = scenario_verified
            .read_json("environment.json")
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let commands: Vec<CommandSpec> = scenario_verified
            .read_json("commands.json")
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let manifest_sha256 =
            canonical_sha256(&manifest).map_err(|error| RunnerError::Msg(error.to_string()))?;
        let scenario_inventory_sha256 = scenario_verified
            .inventory_sha256()
            .map_err(|error| RunnerError::Msg(error.to_string()))?;

        let engine = match &engine {
            Ok(engine) => engine,
            Err(detail) => {
                receipts.push(PatchReplayReceipt {
                    scenario_id: scenario_id.clone(),
                    scenario_kind: scenario.kind,
                    verdict: verdict.verdict,
                    scenario_inventory_sha256: Some(scenario_inventory_sha256),
                    exact_replay_manifest_sha256: Some(manifest_sha256),
                    replay_attempt_path: None,
                    replay_attempt_inventory_sha256: None,
                    outcome: PatchReplayOutcome::Blocked,
                    detail: terminal_text(detail),
                });
                continue;
            }
        };
        if engine_identity_v2(engine) != manifest.engine {
            receipts.push(PatchReplayReceipt {
                scenario_id: scenario_id.clone(),
                scenario_kind: scenario.kind,
                verdict: verdict.verdict,
                scenario_inventory_sha256: Some(scenario_inventory_sha256),
                exact_replay_manifest_sha256: Some(manifest_sha256),
                replay_attempt_path: None,
                replay_attempt_inventory_sha256: None,
                outcome: PatchReplayOutcome::Blocked,
                detail: "BLOCKED: current engine identity differs from sealed exact manifest"
                    .into(),
            });
            continue;
        }

        let evidence = match execute_recorded_attempt(
            engine,
            workspace,
            &scenario,
            &environment,
            &commands,
            1,
            AttemptKindV2::Replay,
        )
        .await
        {
            Ok(mut attempt) => {
                if !attempt.completed.passed {
                    let mut signature = normalize_patch_failure(&scenario, &attempt.completed.raw);
                    signature.evidence_grade = scenario.evidence_grade;
                    attempt.completed.signature = Some(redact_failure_signature(&signature));
                }
                attempt_evidence_v2(&context, &scenario, &manifest, &attempt)?
            }
            Err(failure) => attempt_failure_evidence_v2(&context, &scenario, &manifest, &failure)?,
        };
        let relative = format!("replays/{scenario_id}/attempt-000001");
        let attempt_dir = proof_dir
            .join("replays")
            .join(scenario_id)
            .join("attempt-000001");
        let sealed_attempt =
            write_independent_attempt_bundle_v2(&attempt_dir, &evidence, &manifest)
                .map_err(|error| RunnerError::Msg(format!("seal Patch Lab replay: {error}")))?;
        let replay_outcome = match evidence.attempt.result.outcome_class {
            AttemptOutcomeClassV2::Passed => PatchReplayOutcome::Passed,
            AttemptOutcomeClassV2::Failed => PatchReplayOutcome::Failed,
            AttemptOutcomeClassV2::Blocked => PatchReplayOutcome::Blocked,
        };
        receipts.push(PatchReplayReceipt {
            scenario_id: scenario_id.clone(),
            scenario_kind: scenario.kind,
            verdict: verdict.verdict,
            scenario_inventory_sha256: Some(scenario_inventory_sha256),
            exact_replay_manifest_sha256: Some(manifest_sha256),
            replay_attempt_path: Some(relative),
            replay_attempt_inventory_sha256: Some(
                sealed_attempt
                    .inventory_sha256()
                    .map_err(|error| RunnerError::Msg(error.to_string()))?,
            ),
            outcome: replay_outcome,
            detail: replay_attempt_detail(&evidence.attempt),
        });
    }
    ensure_source_matches(workspace, source)?;
    Ok(receipts)
}

fn normalize_patch_failure(scenario: &Scenario, raw: &RawExecutionResult) -> FailureSignature {
    match scenario.ecosystem {
        Ecosystem::Python => PythonAdapter::new().normalize_failure(raw),
        Ecosystem::Node => NodeAdapter::new().normalize_failure(raw),
        Ecosystem::Rust => RustAdapter::new().normalize_failure(raw),
    }
}

fn blocked_receipt(
    verdict: &ScenarioVerdict,
    scenario_kind: ScenarioKind,
    detail: String,
) -> PatchReplayReceipt {
    PatchReplayReceipt {
        scenario_id: verdict.scenario_id.0.clone(),
        scenario_kind,
        verdict: verdict.verdict,
        scenario_inventory_sha256: None,
        exact_replay_manifest_sha256: None,
        replay_attempt_path: None,
        replay_attempt_inventory_sha256: None,
        outcome: PatchReplayOutcome::Blocked,
        detail: terminal_text(&detail),
    }
}

fn replay_attempt_detail(attempt: &ExecutionAttemptV2) -> String {
    format!(
        "exact replay {:?}: exit={:?}, timed_out={}, duration_ms={}",
        attempt.result.outcome_class,
        attempt.result.exit_code,
        attempt.result.timed_out,
        attempt.result.duration_ms
    )
}

fn run_binding(
    verified: &VerifiedBundle,
    run: &RunManifest,
    source: &SourceSnapshotManifestV2,
    config: &Config,
    verdicts: &[ScenarioVerdict],
) -> Result<PatchSourceBinding> {
    Ok(PatchSourceBinding {
        run_id: run.run_id.0.clone(),
        run_inventory_sha256: verified
            .inventory_sha256()
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        source_manifest_sha256: canonical_sha256(source)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        source_tree_sha256: source.tree_sha256.clone(),
        config_sha256: canonical_sha256(config)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        verdicts_sha256: canonical_sha256(&verdicts)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        run_status: run.status,
        scenario_count: run.scenario_count,
    })
}

fn repaired_scenario_witness(
    frontier: &BreakageFrontier,
    original_verdicts: &[ScenarioVerdict],
    patched_verdicts: &[ScenarioVerdict],
    receipts: &[PatchReplayReceipt],
) -> Vec<PatchScenarioRepair> {
    let Some(scenario_id) = frontier.scenario_id.as_ref().filter(|_| frontier.observed) else {
        return Vec::new();
    };
    let Some(original) = original_verdicts
        .iter()
        .find(|verdict| verdict.scenario_id == *scenario_id && verdict.verdict.is_fail())
    else {
        return Vec::new();
    };
    let Some(patched) = patched_verdicts
        .iter()
        .find(|verdict| verdict.scenario_id == *scenario_id && verdict.verdict.is_pass())
    else {
        return Vec::new();
    };
    let Some(receipt) = receipts
        .iter()
        .find(|receipt| receipt.scenario_id == scenario_id.0)
    else {
        return Vec::new();
    };
    vec![PatchScenarioRepair {
        scenario_id: scenario_id.0.clone(),
        scenario_kind: receipt.scenario_kind,
        original_verdict: original.verdict,
        patched_verdict: patched.verdict,
    }]
}

fn write_patch_source_witnesses(
    proof_dir: &Path,
    patch: &ValidatedPatch,
    original_root: &Path,
    original_manifest: &SourceSnapshotManifestV2,
    patched_root: &Path,
    patched_manifest: &SourceSnapshotManifestV2,
) -> Result<()> {
    let original_files: BTreeMap<&str, &SourceFileEntryV2> = original_manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let patched_files: BTreeMap<&str, &SourceFileEntryV2> = patched_manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let witness_root = proof_dir.join("source-witness");
    std::fs::create_dir(&witness_root)
        .map_err(|error| RunnerError::Msg(format!("create source witness: {error}")))?;
    let original_witness_root = witness_root.join("original");
    let patched_witness_root = witness_root.join("patched");
    std::fs::create_dir(&original_witness_root)
        .and_then(|()| std::fs::create_dir(&patched_witness_root))
        .map_err(|error| RunnerError::Msg(format!("create source witness sides: {error}")))?;

    let mut total_bytes = 0_u64;
    for change in &patch.changes {
        if let Some(path) = change.old_path.as_deref() {
            let entry = original_files.get(path).copied().ok_or_else(|| {
                RunnerError::Msg(format!(
                    "BLOCKED: proposal.patch expects original path absent from source manifest: {path}"
                ))
            })?;
            copy_source_witness(
                original_root,
                &original_witness_root,
                entry,
                &mut total_bytes,
            )?;
        }
        if let Some(path) = change.new_path.as_deref() {
            let entry = patched_files.get(path).copied().ok_or_else(|| {
                RunnerError::Msg(format!(
                    "BLOCKED: proposal.patch expects patched path absent from source manifest: {path}"
                ))
            })?;
            copy_source_witness(patched_root, &patched_witness_root, entry, &mut total_bytes)?;
        }
    }
    Ok(())
}

fn copy_source_witness(
    source_root: &Path,
    witness_root: &Path,
    entry: &SourceFileEntryV2,
    total_bytes: &mut u64,
) -> Result<()> {
    tomorrowci_core::validate_patch_path(&entry.path)
        .map_err(|error| RunnerError::Msg(format!("BLOCKED: unsafe witness path: {error}")))?;
    let relative = portable_source_path(&entry.path)?;
    let source = source_root.join(&relative);
    let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
        RunnerError::Msg(format!(
            "BLOCKED: inspect changed source {}: {error}",
            entry.path
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: changed source witness is not a regular file: {}",
            entry.path
        )));
    }
    let bytes = std::fs::read(&source).map_err(|error| {
        RunnerError::Msg(format!("read changed source {}: {error}", entry.path))
    })?;
    *total_bytes = total_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| RunnerError::Msg("BLOCKED: source witness byte count overflowed".into()))?;
    if *total_bytes > DEFAULT_MAX_PATCH_WITNESS_BYTES {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: changed-file witness exceeds {DEFAULT_MAX_PATCH_WITNESS_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        RunnerError::Msg(format!(
            "BLOCKED: changed source witness must be UTF-8 text: {}",
            entry.path
        ))
    })?;
    if redact_secrets(text) != text {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: changed source witness contains secret-like material: {}",
            entry.path
        )));
    }
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if bytes.len() as u64 != entry.size_bytes || sha256 != entry.sha256 {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: changed source bytes no longer match source manifest: {}",
            entry.path
        )));
    }
    let target = witness_root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| RunnerError::Msg(format!("create witness directory: {error}")))?;
    }
    write_new_file(&target, &bytes, "write changed source witness")
}

fn read_patch_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| RunnerError::Msg(format!("BLOCKED: cannot inspect patch: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(RunnerError::Msg(
            "BLOCKED: patch input must be one regular, non-symlink file".into(),
        ));
    }
    if metadata.len() > DEFAULT_MAX_PATCH_BYTES {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: patch exceeds {} bytes",
            DEFAULT_MAX_PATCH_BYTES
        )));
    }
    std::fs::read(path).map_err(|error| RunnerError::Msg(format!("read patch: {error}")))
}

fn ensure_safe_directory(path: &Path, create_if_missing: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !is_reparse_point(&metadata) =>
        {
            Ok(())
        }
        Ok(_) => Err(RunnerError::Msg(format!(
            "BLOCKED: path is not a regular directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_if_missing => {
            std::fs::create_dir(path)
                .map_err(|error| RunnerError::Msg(format!("create directory: {error}")))?;
            ensure_safe_directory(path, false)
        }
        Err(error) => Err(RunnerError::Msg(format!(
            "BLOCKED: cannot inspect directory {}: {error}",
            path.display()
        ))),
    }
}

fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| RunnerError::Msg(format!("{label}: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| RunnerError::Msg(format!("{label}: {error}")))
}

fn strict_materialize_manifest(
    source_root: &Path,
    destination: &Path,
    manifest: &SourceSnapshotManifestV2,
) -> Result<()> {
    if destination.exists() {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: disposable patch workspace already exists: {}",
            destination.display()
        )));
    }
    std::fs::create_dir_all(destination)
        .map_err(|error| RunnerError::Msg(format!("create disposable patch workspace: {error}")))?;
    for file in &manifest.files {
        let relative = portable_source_path(&file.path)?;
        let source = source_root.join(&relative);
        let metadata = std::fs::symlink_metadata(&source)
            .map_err(|error| RunnerError::Msg(format!("inspect source {}: {error}", file.path)))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(RunnerError::Msg(format!(
                "BLOCKED: source entry is not a regular file: {}",
                file.path
            )));
        }
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                RunnerError::Msg(format!("create disposable source directory: {error}"))
            })?;
        }
        std::fs::copy(&source, &target)
            .map_err(|error| RunnerError::Msg(format!("copy source {}: {error}", file.path)))?;
    }
    Ok(())
}

fn portable_source_path(value: &str) -> Result<PathBuf> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: unsafe source path {value}"
        )));
    }
    let mut out = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(RunnerError::Msg(format!(
                "BLOCKED: unsafe source path {value}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

fn ensure_source_matches(workspace: &Path, expected: &SourceSnapshotManifestV2) -> Result<()> {
    let actual = capture_source_snapshot_v2(
        &expected.run_id,
        workspace,
        &expected.repository_source,
        expected.commit_sha.clone(),
        expected.identity_kind,
        expected.dirty,
        expected.captured_at,
    )
    .map_err(|error| RunnerError::Msg(format!("BLOCKED: source snapshot mismatch: {error}")))?;
    if actual != *expected {
        return Err(RunnerError::Msg(
            "BLOCKED: source tree differs from the sealed source manifest".into(),
        ));
    }
    Ok(())
}

fn original_still_matches(
    run_dir: &Path,
    workspace: &Path,
    expected_binding: &PatchSourceBinding,
    expected_source: &SourceSnapshotManifestV2,
) -> bool {
    let bundle_matches = tomorrowci_evidence::verify_bundle(run_dir)
        .and_then(|verified| verified.inventory_sha256())
        .is_ok_and(|digest| digest == expected_binding.run_inventory_sha256);
    bundle_matches && ensure_source_matches(workspace, expected_source).is_ok()
}

fn ensure_patch_targets_safe(root: &Path, patch: &ValidatedPatch) -> Result<()> {
    for change in &patch.changes {
        let relative = portable_source_path(change.target_path())?;
        let mut cursor = root.to_path_buf();
        let component_count = relative.components().count();
        for (index, component) in relative.components().enumerate() {
            cursor.push(component.as_os_str());
            if !cursor.exists() {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&cursor).map_err(|error| {
                RunnerError::Msg(format!("BLOCKED: inspect patch target: {error}"))
            })?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(RunnerError::Msg(format!(
                    "BLOCKED: patch target traverses a symlink/reparse point: {}",
                    change.target_path()
                )));
            }
            if index + 1 < component_count && !metadata.is_dir() {
                return Err(RunnerError::Msg(format!(
                    "BLOCKED: patch target parent is not a directory: {}",
                    change.target_path()
                )));
            }
            if index + 1 == component_count && !metadata.is_file() {
                return Err(RunnerError::Msg(format!(
                    "BLOCKED: existing patch target is not a regular file: {}",
                    change.target_path()
                )));
            }
        }
    }
    Ok(())
}

fn apply_validated_patch(workspace: &Path, patch_file: &Path) -> Result<()> {
    for check_only in [true, false] {
        let mut command = std::process::Command::new("git");
        command
            .args(["-c", "core.autocrlf=false", "-c", "core.safecrlf=true"])
            .arg("apply")
            .arg("--whitespace=error-all");
        if check_only {
            command.arg("--check");
        }
        let output = command
            .arg("--")
            .arg(patch_file)
            .current_dir(workspace)
            .output()
            .map_err(|error| RunnerError::Msg(format!("BLOCKED: launch git apply: {error}")))?;
        if !output.status.success() {
            return Err(RunnerError::Msg(format!(
                "BLOCKED: patch {} failed in disposable workspace: {}",
                if check_only { "check" } else { "apply" },
                terminal_text(&String::from_utf8_lossy(&output.stderr))
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::fs;
    use tempfile::tempdir;

    fn source_manifest(root: &Path) -> SourceSnapshotManifestV2 {
        capture_source_snapshot_v2(
            &RunId("0123456789ab".into()),
            root,
            "fixture",
            None,
            SourceIdentityKindV2::NonGit,
            false,
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn patch_is_applied_only_to_disposable_copy() {
        let root = tempdir().unwrap();
        let original = root.path().join("original");
        let disposable = root.path().join("disposable");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("hello.txt"), "old\n").unwrap();
        let manifest = source_manifest(&original);
        strict_materialize_manifest(&original, &disposable, &manifest).unwrap();
        let patch_path = root.path().join("change.patch");
        fs::write(
            &patch_path,
            "diff --git a/hello.txt b/hello.txt\n--- a/hello.txt\n+++ b/hello.txt\n@@ -1 +1 @@\n-old\n+new\n",
        )
        .unwrap();
        let patch = tomorrowci_core::validate_unified_patch(
            &fs::read(&patch_path).unwrap(),
            DEFAULT_MAX_PATCH_BYTES,
            DEFAULT_MAX_PATCH_FILES,
        )
        .unwrap();
        ensure_patch_targets_safe(&disposable, &patch).unwrap();
        apply_validated_patch(&disposable, &patch_path).unwrap();
        assert_eq!(
            fs::read_to_string(original.join("hello.txt")).unwrap(),
            "old\n"
        );
        assert_eq!(
            fs::read_to_string(disposable.join("hello.txt")).unwrap(),
            "new\n"
        );
        ensure_source_matches(&original, &manifest).unwrap();
    }

    #[test]
    fn original_rewrite_is_detected() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("hello.txt"), "old\n").unwrap();
        let manifest = source_manifest(root.path());
        fs::write(root.path().join("hello.txt"), "rewritten\n").unwrap();
        let error = ensure_source_matches(root.path(), &manifest).unwrap_err();
        assert!(error
            .to_string()
            .contains("differs from the sealed source manifest"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_patch_target_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        fs::write(root.path().join("real.txt"), "old\n").unwrap();
        symlink(root.path().join("real.txt"), root.path().join("link.txt")).unwrap();
        let patch = tomorrowci_core::validate_unified_patch(
            b"diff --git a/link.txt b/link.txt\n--- a/link.txt\n+++ b/link.txt\n@@ -1 +1 @@\n-old\n+new\n",
            DEFAULT_MAX_PATCH_BYTES,
            DEFAULT_MAX_PATCH_FILES,
        )
        .unwrap();
        assert!(ensure_patch_targets_safe(root.path(), &patch).is_err());
    }
}
