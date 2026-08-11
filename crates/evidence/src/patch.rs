//! Semantic verification for independently sealed PatchProof bundles.

use super::*;
use tomorrowci_core::redaction::redact_secrets;
use tomorrowci_core::{
    canonical_sha256, validate_patch_path, validate_unified_patch, AttemptKindV2,
    AttemptOutcomeClassV2, BreakageFrontier, Config, ExactReplayManifestV2, ExecutionAttemptV2,
    PatchChangeKind, PatchDisposition, PatchFileChange, PatchProof, PatchReplayOutcome,
    PatchScenarioRepair, PatchSourceBinding, RunManifest, Scenario, ScenarioVerdict,
    SourceFileEntryV2, SourceSnapshotManifestV2, DEFAULT_MAX_PATCH_BYTES, DEFAULT_MAX_PATCH_FILES,
    DEFAULT_MAX_PATCH_WITNESS_BYTES, PATCH_PROOF_SCHEMA_VERSION,
};

#[derive(Debug, Clone)]
pub struct VerifiedPatchProof {
    pub proof: PatchProof,
    pub proof_sha256: String,
    pub sealed_inventory_sha256: String,
}

/// Verify a PatchProof plus both immutable run bundles it cross-references.
///
/// Paths are supplied by the verifier and are never loaded from proof JSON.
/// This keeps an untrusted proof from selecting arbitrary host files.
pub fn verify_patch_proof_bundle(
    proof_dir: &Path,
    original_run_dir: &Path,
    patched_run_dir: &Path,
) -> Result<VerifiedPatchProof> {
    let sealed = verify_bundle(proof_dir)?;
    if sealed.kind != BundleKind::Generic {
        return semantic_error(
            "patch-proof.bundle_kind",
            format!("expected generic, got {:?}", sealed.kind),
        );
    }
    for required in ["patch-proof.json", "proposal.patch"] {
        if !sealed.contains(required) {
            return Err(EvidenceError::Missing(required.into()));
        }
    }
    let proof: PatchProof = sealed.read_json("patch-proof.json")?;
    if proof.schema_version != PATCH_PROOF_SCHEMA_VERSION {
        return semantic_error(
            "patch-proof.json.schema_version",
            format!(
                "expected {PATCH_PROOF_SCHEMA_VERSION}, got {}",
                proof.schema_version
            ),
        );
    }
    let patch_bytes = sealed.read_bytes("proposal.patch")?;
    let patch_text =
        std::str::from_utf8(&patch_bytes).map_err(|_| EvidenceError::InvalidSemantics {
            field: "proposal.patch".into(),
            detail: "patch is not UTF-8".into(),
        })?;
    if redact_secrets(patch_text) != patch_text {
        return semantic_error(
            "proposal.patch",
            "patch contains secret-like material that cannot be accepted as sealed evidence",
        );
    }
    let parsed = validate_unified_patch(
        &patch_bytes,
        DEFAULT_MAX_PATCH_BYTES,
        DEFAULT_MAX_PATCH_FILES,
    )
    .map_err(|error| EvidenceError::InvalidSemantics {
        field: "proposal.patch".into(),
        detail: error.to_string(),
    })?;
    ensure_semantic_equality(
        "patch-proof.json.patch",
        &proof.patch,
        "proposal.patch",
        &parsed,
    )?;

    let original = verify_patch_run(original_run_dir, "original")?;
    let patched = verify_patch_run(patched_run_dir, "patched")?;
    ensure_semantic_equality(
        "patch-proof.json.original",
        &proof.original,
        "original run bundle",
        &original.binding,
    )?;
    ensure_semantic_equality(
        "patch-proof.json.patched",
        &proof.patched,
        "patched run bundle",
        &patched.binding,
    )?;
    verify_source_transition(
        &sealed,
        &patch_bytes,
        &parsed,
        &original.source,
        &patched.source,
    )?;
    ensure_semantic_equality(
        "patch-proof.json.original_had_observed_breakage",
        &proof.original_had_observed_breakage,
        "original frontier",
        &original.frontier.observed,
    )?;
    let repaired_scenarios = derive_repaired_scenarios(&original, &patched)?;
    ensure_semantic_equality(
        "patch-proof.json.repaired_scenarios",
        &proof.repaired_scenarios,
        "verifier-derived repaired scenarios",
        &repaired_scenarios,
    )?;
    verify_replay_cross_links(proof_dir, &proof, &patched)?;

    let (expected_disposition, expected_reason) = proof.evaluate_disposition();
    ensure_semantic_equality(
        "patch-proof.json.disposition",
        &proof.disposition,
        "recomputed disposition",
        &expected_disposition,
    )?;
    ensure_semantic_equality(
        "patch-proof.json.disposition_reason",
        &proof.disposition_reason,
        "recomputed disposition reason",
        &expected_reason,
    )?;
    if proof.disposition == PatchDisposition::Qualified && !proof.original_unchanged {
        return semantic_error(
            "patch-proof.json.original_unchanged",
            "qualified proof cannot report a changed original",
        );
    }

    Ok(VerifiedPatchProof {
        proof_sha256: canonical_sha256(&proof).map_err(EvidenceError::Json)?,
        sealed_inventory_sha256: sealed.inventory_sha256()?,
        proof,
    })
}

struct VerifiedPatchRun {
    root: PathBuf,
    binding: PatchSourceBinding,
    source: SourceSnapshotManifestV2,
    frontier: BreakageFrontier,
    verdicts: Vec<ScenarioVerdict>,
}

fn verify_patch_run(dir: &Path, label: &str) -> Result<VerifiedPatchRun> {
    let verified = verify_bundle(dir)?;
    if verified.kind != BundleKind::Run || verified.version != INVENTORY_VERSION_V2 {
        return semantic_error(
            &format!("patch-proof.json.{label}"),
            format!(
                "requires a sealed v2 run bundle, got {:?} v{}",
                verified.kind, verified.version
            ),
        );
    }
    let run: RunManifest = verified.read_json("run.json")?;
    let source: SourceSnapshotManifestV2 = verified.read_json("source-manifest.json")?;
    let config: Config = verified.read_json("config.normalized.json")?;
    let verdicts: Vec<ScenarioVerdict> = verified.read_json("verdicts.json")?;
    let frontier: BreakageFrontier = verified.read_json("frontier.json")?;
    if run.scenario_count != verdicts.len() {
        return semantic_error(
            &format!("{label}.scenario_count"),
            "run manifest and verdict list differ",
        );
    }
    let config_sha256 = canonical_sha256(&config).map_err(EvidenceError::Json)?;
    let binding = PatchSourceBinding {
        run_id: run.run_id.0,
        run_inventory_sha256: verified.inventory_sha256()?,
        source_manifest_sha256: canonical_sha256(&source).map_err(EvidenceError::Json)?,
        source_tree_sha256: source.tree_sha256.clone(),
        config_sha256,
        verdicts_sha256: canonical_sha256(&verdicts).map_err(EvidenceError::Json)?,
        run_status: run.status,
        scenario_count: run.scenario_count,
    };
    Ok(VerifiedPatchRun {
        root: dir.to_path_buf(),
        binding,
        source,
        frontier,
        verdicts,
    })
}

fn verify_source_transition(
    sealed_proof: &VerifiedBundle,
    patch_bytes: &[u8],
    patch: &tomorrowci_core::ValidatedPatch,
    original: &SourceSnapshotManifestV2,
    patched: &SourceSnapshotManifestV2,
) -> Result<()> {
    let original_files = source_file_map(original, "original source manifest")?;
    let patched_files = source_file_map(patched, "patched source manifest")?;
    let patch_changes: BTreeMap<&str, &PatchFileChange> = patch
        .changes
        .iter()
        .map(|change| (change.target_path(), change))
        .collect();

    let all_paths: BTreeSet<&str> = original_files
        .keys()
        .chain(patched_files.keys())
        .copied()
        .collect();
    let mut actual_changed_paths = BTreeSet::new();
    for path in all_paths {
        let before = original_files.get(path).copied();
        let after = patched_files.get(path).copied();
        let actual_kind = match (before, after) {
            (None, Some(_)) => Some(PatchChangeKind::Add),
            (Some(_), None) => Some(PatchChangeKind::Delete),
            (Some(left), Some(right)) if left != right => Some(PatchChangeKind::Modify),
            (Some(_), Some(_)) => None,
            (None, None) => unreachable!("path came from the manifest union"),
        };
        let Some(actual_kind) = actual_kind else {
            continue;
        };
        actual_changed_paths.insert(path);
        let change = patch_changes
            .get(path)
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: "source-manifest delta".into(),
                detail: format!("changed path {path} is missing from proposal.patch"),
            })?;
        if change.kind != actual_kind {
            return semantic_error(
                "source-manifest delta",
                format!(
                    "path {path} is {:?} in the manifests but {:?} in proposal.patch",
                    actual_kind, change.kind
                ),
            );
        }
        verify_change_mode(change, before, after)?;
    }
    for change in &patch.changes {
        if !actual_changed_paths.contains(change.target_path()) {
            return semantic_error(
                "source-manifest delta",
                format!(
                    "proposal.patch lists {}, but that path is unchanged or absent in both manifests",
                    change.target_path()
                ),
            );
        }
    }

    let mut witness_bytes = 0_u64;
    let mut original_witnesses = BTreeMap::new();
    let mut patched_witnesses = BTreeMap::new();
    let mut expected_witness_paths = BTreeSet::new();
    for change in &patch.changes {
        let path = change.target_path();
        match original_files.get(path).copied() {
            Some(entry) => {
                let bytes =
                    read_source_witness(sealed_proof, "original", entry, &mut witness_bytes)?;
                original_witnesses.insert(path.to_string(), bytes);
                expected_witness_paths.insert(format!("original/{path}"));
            }
            None => ensure_witness_absent(sealed_proof, "original", path)?,
        }
        match patched_files.get(path).copied() {
            Some(entry) => {
                let bytes =
                    read_source_witness(sealed_proof, "patched", entry, &mut witness_bytes)?;
                patched_witnesses.insert(path.to_string(), bytes);
                expected_witness_paths.insert(format!("patched/{path}"));
            }
            None => ensure_witness_absent(sealed_proof, "patched", path)?,
        }
    }
    let actual_witness_paths = collect_temp_files(&sealed_proof.root.join("source-witness"))?;
    if actual_witness_paths != expected_witness_paths {
        return semantic_error(
            "source witness file set",
            format!("expected {expected_witness_paths:?}, got {actual_witness_paths:?}"),
        );
    }

    apply_patch_to_witnesses(patch_bytes, &original_witnesses, &patched_witnesses)
}

fn source_file_map<'a>(
    manifest: &'a SourceSnapshotManifestV2,
    label: &str,
) -> Result<BTreeMap<&'a str, &'a SourceFileEntryV2>> {
    let mut files = BTreeMap::new();
    let mut portable_identities = BTreeSet::new();
    for file in &manifest.files {
        if files.insert(file.path.as_str(), file).is_some() {
            return Err(EvidenceError::DuplicateIdentity {
                kind: label.into(),
                id: file.path.clone(),
            });
        }
        if !portable_identities.insert(file.path.to_lowercase()) {
            return semantic_error(
                label,
                format!("case-insensitive source path collision at {}", file.path),
            );
        }
    }
    Ok(files)
}

fn verify_change_mode(
    change: &PatchFileChange,
    before: Option<&SourceFileEntryV2>,
    after: Option<&SourceFileEntryV2>,
) -> Result<()> {
    let coherent = match change.kind {
        PatchChangeKind::Add => {
            before.is_none()
                && after.is_some_and(|entry| change.new_executable == Some(entry.executable))
                && change.old_executable.is_none()
        }
        PatchChangeKind::Delete => {
            after.is_none()
                && before.is_some_and(|entry| change.old_executable == Some(entry.executable))
                && change.new_executable.is_none()
        }
        PatchChangeKind::Modify => before.zip(after).is_some_and(|(left, right)| {
            left.executable == right.executable
                && change.old_executable.is_none()
                && change.new_executable.is_none()
        }),
    };
    if !coherent {
        return semantic_error(
            "source-manifest delta executable mode",
            format!(
                "mode transition is not exactly described for {}",
                change.target_path()
            ),
        );
    }
    Ok(())
}

fn witness_path(side: &str, path: &str) -> String {
    format!("source-witness/{side}/{path}")
}

fn ensure_witness_absent(sealed: &VerifiedBundle, side: &str, path: &str) -> Result<()> {
    let relative = witness_path(side, path);
    if sealed.contains(&relative) {
        return semantic_error(
            "source witness",
            format!("unexpected {side} witness for absent path {path}"),
        );
    }
    Ok(())
}

fn read_source_witness(
    sealed: &VerifiedBundle,
    side: &str,
    entry: &SourceFileEntryV2,
    total_bytes: &mut u64,
) -> Result<Vec<u8>> {
    let relative = witness_path(side, &entry.path);
    let bytes = sealed.read_bytes(&relative)?;
    *total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or_else(|| {
        EvidenceError::InvalidSemantics {
            field: "source witness".into(),
            detail: "witness byte count overflowed".into(),
        }
    })?;
    if *total_bytes > DEFAULT_MAX_PATCH_WITNESS_BYTES {
        return semantic_error(
            "source witness",
            format!("changed-file witness exceeds {DEFAULT_MAX_PATCH_WITNESS_BYTES} bytes"),
        );
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| EvidenceError::InvalidSemantics {
        field: relative.clone(),
        detail: "changed-file witness must be UTF-8 text".into(),
    })?;
    if redact_secrets(text) != text {
        return semantic_error(
            &relative,
            "changed-file witness contains secret-like material that cannot be public evidence",
        );
    }
    let actual_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if bytes.len() as u64 != entry.size_bytes || actual_sha256 != entry.sha256 {
        return semantic_error(
            &relative,
            format!(
                "bytes do not match source manifest (expected {} bytes {}, got {} bytes {})",
                entry.size_bytes,
                entry.sha256,
                bytes.len(),
                actual_sha256
            ),
        );
    }
    Ok(bytes)
}

fn apply_patch_to_witnesses(
    patch_bytes: &[u8],
    original: &BTreeMap<String, Vec<u8>>,
    patched: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let temp = PatchVerifyTemp::create()?;
    let source = temp.root.join("source");
    fs::create_dir(&source)?;
    for (path, bytes) in original {
        write_temp_file(&source, path, bytes)?;
    }
    let patch_path = temp.root.join("proposal.patch");
    fs::write(&patch_path, patch_bytes)?;
    for check_only in [true, false] {
        let mut command = std::process::Command::new("git");
        command.args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=true",
            "-c",
            "core.hooksPath=NUL",
            "apply",
            "--whitespace=error-all",
        ]);
        if check_only {
            command.arg("--check");
        }
        let output = command
            .arg("--")
            .arg(&patch_path)
            .current_dir(&source)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .map_err(|error| EvidenceError::InvalidSemantics {
                field: "proposal.patch transformation".into(),
                detail: format!("could not launch git apply: {error}"),
            })?;
        if !output.status.success() {
            let detail = redact_secrets(&String::from_utf8_lossy(&output.stderr));
            return semantic_error(
                "proposal.patch transformation",
                format!(
                    "git apply{} rejected the sealed witnesses: {}",
                    if check_only { " --check" } else { "" },
                    detail.trim()
                ),
            );
        }
    }

    let actual_paths = collect_temp_files(&source)?;
    let expected_paths: BTreeSet<String> = patched.keys().cloned().collect();
    if actual_paths != expected_paths {
        return semantic_error(
            "proposal.patch transformation",
            format!(
                "applied witness file set differs: expected {expected_paths:?}, got {actual_paths:?}"
            ),
        );
    }
    for (path, expected) in patched {
        let actual = fs::read(source.join(path.replace('/', std::path::MAIN_SEPARATOR_STR)))?;
        if &actual != expected {
            return semantic_error(
                "proposal.patch transformation",
                format!("applied bytes for {path} do not equal the patched witness"),
            );
        }
    }
    Ok(())
}

fn write_temp_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    validate_patch_path(relative).map_err(|error| EvidenceError::UnsafePath(error.to_string()))?;
    let path = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn collect_temp_files(root: &Path) -> Result<BTreeSet<String>> {
    fn visit(root: &Path, current: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(EvidenceError::NonRegularEntry(
                    entry.path().display().to_string(),
                ));
            }
            if metadata.is_dir() {
                visit(root, &entry.path(), out)?;
            } else if metadata.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| EvidenceError::UnsafePath(entry.path().display().to_string()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative);
            } else {
                return Err(EvidenceError::NonRegularEntry(
                    entry.path().display().to_string(),
                ));
            }
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

struct PatchVerifyTemp {
    root: PathBuf,
}

impl PatchVerifyTemp {
    fn create() -> Result<Self> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..128 {
            let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "tomorrowci-patch-verify-{}-{ordinal}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self { root }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(EvidenceError::Other(
            "could not allocate an exclusive PatchProof verifier directory".into(),
        ))
    }
}

impl Drop for PatchVerifyTemp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn derive_repaired_scenarios(
    original: &VerifiedPatchRun,
    patched: &VerifiedPatchRun,
) -> Result<Vec<PatchScenarioRepair>> {
    if !original.frontier.observed {
        return Ok(Vec::new());
    }
    let scenario_id =
        original
            .frontier
            .scenario_id
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: "original frontier scenario".into(),
                detail: "observed frontier has no scenario identity".into(),
            })?;
    let original_verdict = original
        .verdicts
        .iter()
        .find(|verdict| verdict.scenario_id == *scenario_id)
        .ok_or_else(|| EvidenceError::IdentityMismatch {
            field: "original frontier scenario".into(),
            detail: format!("{} is not an original verdict", scenario_id.0),
        })?;
    if !original_verdict.verdict.is_fail() {
        return semantic_error(
            "original frontier scenario",
            "observed frontier does not reference a failing verdict",
        );
    }
    let Some(patched_verdict) = patched
        .verdicts
        .iter()
        .find(|verdict| verdict.scenario_id == *scenario_id)
    else {
        return Ok(Vec::new());
    };
    let original_scenario = read_run_scenario(original, &scenario_id.0, "original")?;
    let patched_scenario = read_run_scenario(patched, &scenario_id.0, "patched")?;
    ensure_same_repaired_scenario(&original_scenario, &patched_scenario)?;
    if !patched_verdict.verdict.is_pass() {
        return Ok(Vec::new());
    }
    Ok(vec![PatchScenarioRepair {
        scenario_id: scenario_id.0.clone(),
        scenario_kind: original_scenario.kind,
        original_verdict: original_verdict.verdict,
        patched_verdict: patched_verdict.verdict,
    }])
}

fn ensure_same_repaired_scenario(original: &Scenario, patched: &Scenario) -> Result<()> {
    ensure_semantic_equality(
        "original repaired scenario",
        original,
        "patched repaired scenario",
        patched,
    )
}

fn read_run_scenario(run: &VerifiedPatchRun, scenario_id: &str, label: &str) -> Result<Scenario> {
    validate_single_component(scenario_id, "patch repaired scenario id")?;
    let verified = verify_bundle(&run.root.join("scenarios").join(scenario_id))?;
    if verified.kind != BundleKind::Scenario || verified.version != INVENTORY_VERSION_V2 {
        return semantic_error(
            "patch repaired scenario bundle",
            format!(
                "expected {label} scenario v2, got {:?} v{}",
                verified.kind, verified.version
            ),
        );
    }
    let scenario: Scenario = verified.read_json("scenario.json")?;
    ensure_identity(
        &format!("{label} repaired scenario id"),
        &scenario.id.0,
        scenario_id,
    )?;
    Ok(scenario)
}

fn verify_replay_cross_links(
    proof_dir: &Path,
    proof: &PatchProof,
    patched: &VerifiedPatchRun,
) -> Result<()> {
    let mut receipt_ids = BTreeSet::new();
    for receipt in &proof.replay_receipts {
        validate_single_component(&receipt.scenario_id, "patch replay scenario id")?;
        if !receipt_ids.insert(receipt.scenario_id.clone()) {
            return Err(EvidenceError::DuplicateIdentity {
                kind: "patch replay scenario".into(),
                id: receipt.scenario_id.clone(),
            });
        }
        let verdict = patched
            .verdicts
            .iter()
            .find(|verdict| verdict.scenario_id.0 == receipt.scenario_id)
            .ok_or_else(|| EvidenceError::IdentityMismatch {
                field: "patch-proof.json.replay_receipts.scenario_id".into(),
                detail: format!("{} is not a patched verdict", receipt.scenario_id),
            })?;
        ensure_semantic_equality(
            "patch replay verdict",
            &receipt.verdict,
            "patched verdict",
            &verdict.verdict,
        )?;

        let has_no_evidence_links = receipt.scenario_inventory_sha256.is_none()
            && receipt.exact_replay_manifest_sha256.is_none()
            && receipt.replay_attempt_path.is_none()
            && receipt.replay_attempt_inventory_sha256.is_none();
        if has_no_evidence_links && receipt.outcome == PatchReplayOutcome::Blocked {
            if verdict.evidence.is_some() {
                return semantic_error(
                    "patch replay blocked receipt",
                    "sealed scenario evidence exists but receipt omitted its cross-links",
                );
            }
            continue;
        }

        verdict
            .evidence
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: format!("patched verdict {}.evidence", receipt.scenario_id),
                detail: "patch qualification requires sealed scenario evidence".into(),
            })?;
        // Reconstruct below the verifier-supplied patched run root.  The
        // absolute directory serialized in historical verdict evidence is
        // deliberately ignored so downloaded bundles remain portable.
        let scenario_path = patched.root.join("scenarios").join(&receipt.scenario_id);
        let scenario_verified = verify_bundle(&scenario_path)?;
        if scenario_verified.kind != BundleKind::Scenario
            || scenario_verified.version != INVENTORY_VERSION_V2
        {
            return semantic_error(
                "patch replay scenario bundle",
                format!(
                    "expected scenario v2, got {:?} v{}",
                    scenario_verified.kind, scenario_verified.version
                ),
            );
        }
        ensure_semantic_equality(
            "patch replay scenario inventory",
            &receipt.scenario_inventory_sha256,
            "sealed scenario inventory",
            &Some(scenario_verified.inventory_sha256()?),
        )?;
        let scenario: Scenario = scenario_verified.read_json("scenario.json")?;
        ensure_semantic_equality(
            "patch replay scenario kind",
            &receipt.scenario_kind,
            "scenario.json.kind",
            &scenario.kind,
        )?;
        let manifest: ExactReplayManifestV2 =
            scenario_verified.read_json("replay-manifest-v2.json")?;
        let manifest_sha256 = canonical_sha256(&manifest).map_err(EvidenceError::Json)?;
        ensure_semantic_equality(
            "patch replay exact manifest",
            &receipt.exact_replay_manifest_sha256,
            "replay-manifest-v2.json",
            &Some(manifest_sha256.clone()),
        )?;

        match (
            receipt.replay_attempt_path.as_deref(),
            receipt.replay_attempt_inventory_sha256.as_deref(),
        ) {
            (Some(relative), Some(expected_inventory)) => {
                validate_patch_path(relative)
                    .map_err(|error| EvidenceError::UnsafePath(error.to_string()))?;
                let expected_prefix = format!("replays/{}/", receipt.scenario_id);
                if !relative.starts_with(&expected_prefix) {
                    return semantic_error(
                        "patch replay attempt path",
                        format!("must be below {expected_prefix}"),
                    );
                }
                let attempt_dir =
                    proof_dir.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
                let attempt_verified = verify_bundle(&attempt_dir)?;
                if attempt_verified.kind != BundleKind::ReplayAttempt
                    || attempt_verified.version != INVENTORY_VERSION_V2
                {
                    return semantic_error(
                        "patch replay attempt bundle",
                        format!(
                            "expected replay-attempt v2, got {:?} v{}",
                            attempt_verified.kind, attempt_verified.version
                        ),
                    );
                }
                ensure_identity(
                    "patch replay attempt inventory",
                    expected_inventory,
                    &attempt_verified.inventory_sha256()?,
                )?;
                let attempt: ExecutionAttemptV2 = attempt_verified.read_json("attempt.json")?;
                ensure_identity(
                    "patch replay attempt run_id",
                    &attempt.run_id.0,
                    &patched.binding.run_id,
                )?;
                ensure_identity(
                    "patch replay attempt scenario_id",
                    &attempt.scenario_id.0,
                    &receipt.scenario_id,
                )?;
                ensure_identity(
                    "patch replay attempt source",
                    &attempt.source_manifest_sha256,
                    &patched.binding.source_manifest_sha256,
                )?;
                ensure_identity(
                    "patch replay attempt config",
                    &attempt.config_sha256,
                    &patched.binding.config_sha256,
                )?;
                ensure_identity(
                    "patch replay attempt manifest",
                    &attempt.replay_manifest_sha256,
                    &manifest_sha256,
                )?;
                if attempt.kind != AttemptKindV2::Replay || attempt.scenario_kind != scenario.kind {
                    return semantic_error(
                        "patch replay attempt kind",
                        "receipt is not an exact replay of the patched scenario",
                    );
                }
                let expected_outcome = match attempt.result.outcome_class {
                    AttemptOutcomeClassV2::Passed => PatchReplayOutcome::Passed,
                    AttemptOutcomeClassV2::Failed => PatchReplayOutcome::Failed,
                    AttemptOutcomeClassV2::Blocked => PatchReplayOutcome::Blocked,
                };
                ensure_semantic_equality(
                    "patch replay outcome",
                    &receipt.outcome,
                    "sealed attempt outcome",
                    &expected_outcome,
                )?;
            }
            (None, None) if receipt.outcome == PatchReplayOutcome::Blocked => {}
            _ => {
                return semantic_error(
                    "patch replay attempt reference",
                    "path and inventory digest must both be present",
                )
            }
        }
    }
    if receipt_ids.len() != patched.verdicts.len()
        || patched
            .verdicts
            .iter()
            .any(|verdict| !receipt_ids.contains(&verdict.scenario_id.0))
    {
        return semantic_error(
            "patch-proof.json.replay_receipts",
            "receipts must be an exact set of patched verdict identities",
        );
    }
    Ok(())
}

fn semantic_error<T>(field: &str, detail: impl Into<String>) -> Result<T> {
    Err(EvidenceError::InvalidSemantics {
        field: field.into(),
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use tomorrowci_core::{
        DependencyMode, Ecosystem, EvidenceGrade, RunId, ScenarioId, SourceIdentityKindV2,
        REPLAY_SCHEMA_VERSION_V2,
    };

    const PATCH: &[u8] = b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

    fn file(path: &str, bytes: &[u8]) -> SourceFileEntryV2 {
        SourceFileEntryV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            path: path.into(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            size_bytes: bytes.len() as u64,
            executable: false,
        }
    }

    fn source(run_id: &str, files: Vec<SourceFileEntryV2>) -> SourceSnapshotManifestV2 {
        SourceSnapshotManifestV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            run_id: RunId(run_id.into()),
            source_id: format!("tree:{run_id}"),
            identity_kind: SourceIdentityKindV2::NonGit,
            repository_source: "fixture".into(),
            commit_sha: None,
            dirty: false,
            tree_sha256: format!("sha256:{run_id:0>64}"),
            files,
            captured_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        }
    }

    fn empty_sealed_proof() -> (tempfile::TempDir, VerifiedBundle) {
        let dir = tempfile::tempdir().unwrap();
        seal_bundle(dir.path(), BundleKind::Generic).unwrap();
        let verified = verify_bundle(dir.path()).unwrap();
        (dir, verified)
    }

    #[test]
    fn unrelated_patch_cannot_bind_successful_patched_source() {
        let (_dir, sealed) = empty_sealed_proof();
        let parsed = validate_unified_patch(PATCH, 4096, 2).unwrap();
        let original = source("original", vec![file("src/lib.rs", b"old\n")]);
        let patched = source("patched", vec![file("src/lib.rs", b"old\n")]);
        let error =
            verify_source_transition(&sealed, PATCH, &parsed, &original, &patched).unwrap_err();
        assert!(error.to_string().contains("unchanged or absent"));
    }

    #[test]
    fn extra_and_missing_changed_paths_are_rejected() {
        let (_dir, sealed) = empty_sealed_proof();
        let parsed = validate_unified_patch(PATCH, 4096, 2).unwrap();
        let original = source(
            "original",
            vec![file("src/lib.rs", b"old\n"), file("extra.txt", b"a\n")],
        );
        let patched = source(
            "patched",
            vec![file("src/lib.rs", b"new\n"), file("extra.txt", b"b\n")],
        );
        let extra =
            verify_source_transition(&sealed, PATCH, &parsed, &original, &patched).unwrap_err();
        assert!(extra.to_string().contains("extra.txt is missing"));

        let two_path_patch = b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/extra.txt b/extra.txt\n--- a/extra.txt\n+++ b/extra.txt\n@@ -1 +1 @@\n-a\n+b\n";
        let parsed = validate_unified_patch(two_path_patch, 4096, 3).unwrap();
        let patched_without_extra_delta = source(
            "patched",
            vec![file("src/lib.rs", b"new\n"), file("extra.txt", b"a\n")],
        );
        let missing = verify_source_transition(
            &sealed,
            two_path_patch,
            &parsed,
            &original,
            &patched_without_extra_delta,
        )
        .unwrap_err();
        assert!(missing.to_string().contains("extra.txt"));
        assert!(missing.to_string().contains("unchanged or absent"));
    }

    #[test]
    fn exact_changed_file_witness_is_applied_and_verified() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("source-witness/original/src")).unwrap();
        fs::create_dir_all(dir.path().join("source-witness/patched/src")).unwrap();
        fs::write(
            dir.path().join("source-witness/original/src/lib.rs"),
            b"old\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("source-witness/patched/src/lib.rs"),
            b"new\n",
        )
        .unwrap();
        seal_bundle(dir.path(), BundleKind::Generic).unwrap();
        let sealed = verify_bundle(dir.path()).unwrap();
        let parsed = validate_unified_patch(PATCH, 4096, 2).unwrap();
        let original = source("original", vec![file("src/lib.rs", b"old\n")]);
        let patched = source("patched", vec![file("src/lib.rs", b"new\n")]);
        verify_source_transition(&sealed, PATCH, &parsed, &original, &patched).unwrap();
    }

    #[test]
    fn repaired_scenario_identity_mismatch_is_rejected() {
        let original = Scenario {
            id: ScenarioId("future".into()),
            kind: tomorrowci_core::ScenarioKind::SingleAxis,
            ecosystem: Ecosystem::Python,
            label: "Python 3.14".into(),
            runtime_version: "3.14".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.14@sha256:fixture".into(),
            axes_changed: vec![tomorrowci_core::EnvironmentAxis::Runtime],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: false,
            selection_reason: "future runtime".into(),
        };
        let mut mismatched = original.clone();
        mismatched.runtime_version = "3.15".into();
        let error = ensure_same_repaired_scenario(&original, &mismatched).unwrap_err();
        assert!(error.to_string().contains("repaired scenario"));
    }
}
