use super::*;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use tomorrowci_core::{
    attempt_equivalence, canonical_sha256, AttemptKindV2, AttemptMismatchV2, AttemptOutcomeClassV2,
    ExactReplayManifestV2, ExecutionAttemptResultV2, ExecutionAttemptV2,
    NormalizedFailureSignatureV2, PublicReplayReceiptV2, ReplayCommandV2, ReplayQualificationV2,
    RunId, SourceFileEntryV2, SourceIdentityKindV2, SourceSnapshotManifestV2,
    PUBLIC_REPLAY_RECEIPT_SCHEMA_VERSION, REPLAY_SCHEMA_VERSION_V2,
};

const PUBLIC_RECEIPT_FILE: &str = "public-replay-receipt.json";
const ORIGIN_RUN_INVENTORY: &str = "origin/run.checksums.txt";
const ORIGIN_SOURCE: &str = "origin/source-manifest.json";
const ORIGIN_CONFIG: &str = "origin/config.normalized.json";
const ORIGIN_SCENARIO_INVENTORY: &str = "origin/scenario.checksums.txt";
const ORIGIN_SCENARIO: &str = "origin/scenario.json";
const ORIGIN_ENVIRONMENT: &str = "origin/environment.json";
const ORIGIN_COMMANDS: &str = "origin/commands.json";
const ORIGIN_REPLAY_MANIFEST: &str = "origin/replay-manifest-v2.json";
const ORIGIN_ATTEMPT_INVENTORY: &str = "origin/original-attempt.checksums.txt";
const ORIGIN_ATTEMPT: &str = "origin/original-attempt.json";

/// Runtime bytes paired with the strict, persisted attempt model.
#[derive(Debug, Clone)]
pub struct AttemptEvidenceV2 {
    pub attempt: ExecutionAttemptV2,
    pub stdout: String,
    pub stderr: String,
}

/// Capture the exact disposable source tree that every attempt must copy.
pub fn capture_source_snapshot_v2(
    run_id: &RunId,
    workspace: &Path,
    repository_source: &str,
    commit_sha: Option<String>,
    identity_kind: SourceIdentityKindV2,
    dirty: bool,
    captured_at: DateTime<Utc>,
) -> Result<SourceSnapshotManifestV2> {
    ensure_directory(workspace)?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    let mut entries = 0_usize;
    collect_source_files(
        workspace,
        workspace,
        "",
        0,
        &mut total_bytes,
        &mut entries,
        &mut files,
    )?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let tree_sha256 = canonical_sha256(&files).map_err(EvidenceError::Json)?;
    let source_id = match (&identity_kind, &commit_sha) {
        (SourceIdentityKindV2::GitCommit, Some(commit)) => format!("git:{commit}:{tree_sha256}"),
        (SourceIdentityKindV2::DirtyWorktree, Some(commit)) => {
            format!("dirty-git:{commit}:{tree_sha256}")
        }
        (SourceIdentityKindV2::DirtyWorktree, None) => format!("dirty:{tree_sha256}"),
        (SourceIdentityKindV2::NonGit, _) => format!("tree:{tree_sha256}"),
        (SourceIdentityKindV2::GitCommit, None) => {
            return Err(EvidenceError::InvalidSemantics {
                field: "source-manifest.json.commit_sha".into(),
                detail: "git_commit identity requires an exact commit SHA".into(),
            })
        }
    };
    Ok(SourceSnapshotManifestV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        run_id: run_id.clone(),
        source_id,
        identity_kind,
        repository_source: redact_secrets(repository_source),
        commit_sha,
        dirty,
        tree_sha256,
        files,
        captured_at,
    })
}

impl EvidenceStore {
    pub fn write_source_manifest_v2(&self, manifest: &SourceSnapshotManifestV2) -> Result<()> {
        ensure_identity(
            "source-manifest.json.run_id",
            &manifest.run_id.0,
            &self.run_id,
        )?;
        self.write_json("source-manifest.json", manifest)?;
        Ok(())
    }

    pub fn write_replay_qualifications_v2(
        &self,
        qualifications: &[ReplayQualificationV2],
    ) -> Result<()> {
        for qualification in qualifications {
            ensure_identity(
                "replay-qualifications.json.run_id",
                &qualification.run_id.0,
                &self.run_id,
            )?;
        }
        self.write_json("replay-qualifications.json", qualifications)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write_scenario_bundle_v2(
        &self,
        scenario: &Scenario,
        env: &EnvironmentSpec,
        commands: &[CommandSpec],
        raw: &RawExecutionResult,
        result: &ExecutionResult,
        failure: Option<&FailureSignature>,
        replay_manifest: &ExactReplayManifestV2,
        attempts: &[AttemptEvidenceV2],
    ) -> Result<(PathBuf, Option<ReplayQualificationV2>)> {
        self.ensure_unsealed()?;
        validate_single_component(&scenario.id.0, "scenario id")?;
        if attempts.is_empty() {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("scenarios/{}/attempts", scenario.id),
                detail: "v2 scenario evidence requires at least one original attempt".into(),
            });
        }
        ensure_identity(
            "replay-manifest-v2.json.run_id",
            &replay_manifest.run_id.0,
            &self.run_id,
        )?;
        ensure_identity(
            "replay-manifest-v2.json.scenario_id",
            &replay_manifest.scenario_id.0,
            &scenario.id.0,
        )?;

        let dir = self.scenario_dir(&scenario.id.0);
        ensure_directory(&self.root)?;
        ensure_directory(&self.root.join("scenarios"))?;
        fs::create_dir(&dir).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                EvidenceError::Other(format!(
                    "refusing to overwrite existing scenario directory: {}",
                    dir.display()
                ))
            } else {
                EvidenceError::Io(error)
            }
        })?;
        ensure_directory(&dir)?;

        let scenario = redact_scenario(scenario)?;
        let env = redact_environment(env);
        let commands: Vec<CommandSpec> = commands.iter().map(redact_command).collect();
        let result = redact_execution_result(result);
        let failure = failure.map(redact_failure_signature);
        write_json(&dir.join("scenario.json"), &scenario)?;
        write_json(&dir.join("environment.json"), &env)?;
        write_json(&dir.join("commands.json"), &commands)?;
        let stdout = cap_bytes(&redact_secrets(&raw.stdout), 2 * 1024 * 1024);
        let stderr = cap_bytes(&redact_secrets(&raw.stderr), 2 * 1024 * 1024);
        persist_regular_file(&dir.join("stdout.log"), stdout.as_bytes())?;
        persist_regular_file(&dir.join("stderr.log"), stderr.as_bytes())?;
        write_json(&dir.join("result.json"), &result)?;
        if let Some(signature) = &failure {
            write_json(&dir.join("failure-signature.json"), signature)?;
        }

        let replay_v1 = ReplayManifest {
            run_id: self.run_id.clone(),
            scenario_id: scenario.id.0.clone(),
            image_ref: env.image_ref.clone(),
            image_digest: env.image_digest.clone(),
            commands: commands.clone(),
            workdir: env.workdir.clone(),
            memory_mb: env.memory_mb,
            cpus: env.cpus,
            pids_limit: env.pids_limit,
            timeout_seconds: env.timeout_seconds,
            network_mode: format!("{:?}", env.network_mode),
        };
        let replay_manifest = redact_exact_manifest(replay_manifest, &scenario)?;
        write_json(&dir.join("replay-manifest.json"), &replay_v1)?;
        write_json(&dir.join("replay-manifest-v2.json"), &replay_manifest)?;
        write_static_replay_helpers(&dir)?;

        let mut originals = Vec::new();
        let mut replays = Vec::new();
        let mut seen = BTreeSet::new();
        for evidence in attempts {
            let attempt = redact_attempt(evidence, &replay_manifest)?;
            if !seen.insert(attempt.attempt.attempt_id.clone()) {
                return Err(EvidenceError::DuplicateIdentity {
                    kind: "attempt".into(),
                    id: attempt.attempt.attempt_id,
                });
            }
            ensure_identity("attempt.run_id", &attempt.attempt.run_id.0, &self.run_id)?;
            ensure_identity(
                "attempt.scenario_id",
                &attempt.attempt.scenario_id.0,
                &scenario.id.0,
            )?;
            let group = match attempt.attempt.kind {
                AttemptKindV2::Original => "attempts",
                AttemptKindV2::Replay => "replays",
            };
            let attempt_dir = dir
                .join(group)
                .join(format!("attempt-{:06}", attempt.attempt.ordinal));
            fs::create_dir_all(&attempt_dir)?;
            write_attempt_bundle(&attempt_dir, &attempt)?;
            match attempt.attempt.kind {
                AttemptKindV2::Original => originals.push(attempt.attempt),
                AttemptKindV2::Replay => replays.push(attempt.attempt),
            }
        }
        originals.sort_by_key(|attempt| attempt.ordinal);
        replays.sort_by_key(|attempt| attempt.ordinal);
        let original = originals
            .last()
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: format!("scenarios/{}/attempts", scenario.id),
                detail: "v2 scenario evidence has no original attempt".into(),
            })?;
        let qualification = if replays.is_empty() {
            None
        } else {
            let qualification = ReplayQualificationV2::evaluate(original, &replays, Utc::now())
                .map_err(EvidenceError::Json)?;
            write_json(&dir.join("replay-qualification.json"), &qualification)?;
            Some(qualification)
        };
        seal_bundle_version(&dir, BundleKind::Scenario, INVENTORY_VERSION_V2)?;
        Ok((dir, qualification))
    }
}

fn write_static_replay_helpers(dir: &Path) -> Result<()> {
    persist_regular_file(
        &dir.join("replay.sh"),
        b"#!/usr/bin/env bash\nset -euo pipefail\n# The CLI consumes replay-manifest-v2.json.\necho 'Use: tomorrowci replay RUN_ID --scenario SCENARIO_ID'\n",
    )?;
    persist_regular_file(
        &dir.join("replay.ps1"),
        b"# The CLI consumes replay-manifest-v2.json.\nWrite-Host 'Use: tomorrowci replay RUN_ID --scenario SCENARIO_ID'\n",
    )?;
    Ok(())
}

fn write_attempt_bundle(dir: &Path, evidence: &AttemptEvidenceV2) -> Result<()> {
    ensure_directory(dir)?;
    write_attempt_files(dir, evidence)?;
    seal_bundle_version(dir, BundleKind::ReplayAttempt, INVENTORY_VERSION_V2)?;
    Ok(())
}

fn write_attempt_files(dir: &Path, evidence: &AttemptEvidenceV2) -> Result<()> {
    ensure_directory(dir)?;
    let stdout = cap_bytes(&redact_secrets(&evidence.stdout), 2 * 1024 * 1024);
    let stderr = cap_bytes(&redact_secrets(&evidence.stderr), 2 * 1024 * 1024);
    let stdout_digest = prefixed_sha256(stdout.as_bytes());
    let stderr_digest = prefixed_sha256(stderr.as_bytes());
    if evidence.attempt.result.stdout_sha256.as_deref() != Some(&stdout_digest)
        || evidence.attempt.result.stderr_sha256.as_deref() != Some(&stderr_digest)
    {
        return Err(EvidenceError::IdentityMismatch {
            field: format!("attempt {} log digests", evidence.attempt.attempt_id),
            detail: "attempt result does not match the persisted redacted log bytes".into(),
        });
    }
    write_json(&dir.join("attempt.json"), &evidence.attempt)?;
    write_json(&dir.join("environment.json"), &evidence.attempt.environment)?;
    write_json(&dir.join("commands.json"), &evidence.attempt.commands)?;
    write_json(&dir.join("result.json"), &evidence.attempt.result)?;
    if let Some(signature) = &evidence.attempt.failure_signature {
        write_json(&dir.join("failure-signature.json"), signature)?;
    }
    persist_regular_file(&dir.join("stdout.log"), stdout.as_bytes())?;
    persist_regular_file(&dir.join("stderr.log"), stderr.as_bytes())?;
    Ok(())
}

/// Verified origin generation needed to authorize one detached public replay.
#[derive(Debug, Clone)]
pub struct PublicReplayOriginV2 {
    pub run: VerifiedBundle,
    pub scenario: VerifiedBundle,
    pub original_attempt: VerifiedBundle,
    pub source: SourceSnapshotManifestV2,
    pub config: Config,
    pub scenario_record: Scenario,
    pub environment: EnvironmentSpec,
    pub commands: Vec<CommandSpec>,
    pub manifest: ExactReplayManifestV2,
    pub original: ExecutionAttemptV2,
}

/// Readback returned only after the detached receipt has sealed and verified.
#[derive(Debug, Clone)]
pub struct SealedPublicReplayReceiptV2 {
    pub bundle: VerifiedBundle,
    pub receipt: PublicReplayReceiptV2,
}

/// Recomputed result for exactly two detached public replay receipts.
#[derive(Debug, Clone)]
pub struct VerifiedPublicReplayPairV2 {
    pub run_id: RunId,
    pub scenario_id: tomorrowci_core::ScenarioId,
    pub receipt_ids: Vec<String>,
    pub receipt_inventory_sha256: Vec<String>,
    pub original_attempt_sha256: String,
    pub outcome_class: AttemptOutcomeClassV2,
    pub target_exit_code: Option<i32>,
}

/// Persist one independently sealed v2 attempt bundle.
///
/// Patch Lab uses this for successful and unsuccessful exact replays without
/// mutating the already sealed scenario/run bundles that supplied the replay
/// manifest.
pub fn write_independent_attempt_bundle_v2(
    dir: &Path,
    evidence: &AttemptEvidenceV2,
    manifest: &ExactReplayManifestV2,
) -> Result<VerifiedBundle> {
    if dir.exists() {
        return Err(EvidenceError::Other(format!(
            "refusing to overwrite attempt bundle: {}",
            dir.display()
        )));
    }
    fs::create_dir_all(dir)?;
    let redacted = redact_attempt(evidence, manifest)?;
    write_attempt_bundle(dir, &redacted)?;
    verify_bundle(dir)
}

/// Resolve the exact final original attempt and every sealed origin generation
/// needed by a public replay receipt.
pub fn load_public_replay_origin_v2(
    run: &VerifiedBundle,
    scenario_id: &str,
) -> Result<PublicReplayOriginV2> {
    validate_single_component(scenario_id, "scenario id")?;
    if run.version != INVENTORY_VERSION_V2 || run.kind != BundleKind::Run {
        return Err(EvidenceError::InvalidSemantics {
            field: "public replay origin".into(),
            detail: "public replay receipts require a verified v2 run".into(),
        });
    }

    let run_id = run_id_from_verified_run(run)?;
    let scenario_relative = format!("scenarios/{scenario_id}");
    let scenario = verify_bundle_internal(
        &run.root.join("scenarios").join(scenario_id),
        Some(&run_id),
        Some(scenario_id),
    )?;
    if scenario.version != INVENTORY_VERSION_V2 || scenario.kind != BundleKind::Scenario {
        return Err(EvidenceError::InvalidSemantics {
            field: format!("{scenario_relative}/checksums.txt"),
            detail: "public replay requires a verified v2 scenario".into(),
        });
    }
    ensure_inventory_generation_is_nested(
        run,
        &format!("{scenario_relative}/checksums.txt"),
        &scenario,
    )?;

    let mut originals = Vec::new();
    for entry in &scenario.inventory.entries {
        let Some(directory) = entry.path.strip_suffix("/attempt.json") else {
            continue;
        };
        if !directory.starts_with("attempts/attempt-") || directory.split('/').count() != 2 {
            continue;
        }
        let attempt = verify_bundle_internal(
            &scenario.root.join(directory),
            Some(&run_id),
            Some(scenario_id),
        )?;
        if attempt.version != INVENTORY_VERSION_V2 || attempt.kind != BundleKind::ReplayAttempt {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("{scenario_relative}/{directory}/checksums.txt"),
                detail: "original attempt is not a sealed v2 replay-attempt bundle".into(),
            });
        }
        ensure_inventory_generation_is_nested(
            &scenario,
            &format!("{directory}/checksums.txt"),
            &attempt,
        )?;
        let record: ExecutionAttemptV2 = attempt.read_json("attempt.json")?;
        if record.kind != AttemptKindV2::Original {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("{scenario_relative}/{directory}/attempt.json.kind"),
                detail: "attempts/ may contain only original attempts".into(),
            });
        }
        originals.push((record.ordinal, directory.to_string(), attempt, record));
    }
    originals.sort_by_key(|(ordinal, _, _, _)| *ordinal);
    let (_, original_directory, original_attempt, original) = originals
        .pop()
        .ok_or_else(|| EvidenceError::Missing(format!("{scenario_relative}/attempts")))?;

    let source: SourceSnapshotManifestV2 = run.read_json("source-manifest.json")?;
    let config: Config = run.read_json("config.normalized.json")?;
    let scenario_record: Scenario = scenario.read_json("scenario.json")?;
    let environment: EnvironmentSpec = scenario.read_json("environment.json")?;
    let commands: Vec<CommandSpec> = scenario.read_json("commands.json")?;
    let manifest: ExactReplayManifestV2 = scenario.read_json("replay-manifest-v2.json")?;
    let manifest_sha256 = canonical_sha256(&manifest).map_err(EvidenceError::Json)?;
    ensure_identity(
        "original attempt replay manifest",
        &original.replay_manifest_sha256,
        &manifest_sha256,
    )?;

    let original_attempt_path = format!("{scenario_relative}/{original_directory}");
    ensure_identity(
        "public replay source identity",
        &manifest.source_manifest_sha256,
        &canonical_sha256(&source).map_err(EvidenceError::Json)?,
    )?;
    ensure_identity(
        "public replay config identity",
        &manifest.config_sha256,
        &canonical_sha256(&config).map_err(EvidenceError::Json)?,
    )?;
    ensure_identity(
        "public replay original path ordinal",
        &original_attempt_path,
        &format!(
            "{scenario_relative}/attempts/attempt-{:06}",
            original.ordinal
        ),
    )?;

    Ok(PublicReplayOriginV2 {
        run: run.clone(),
        scenario,
        original_attempt,
        source,
        config,
        scenario_record,
        environment,
        commands,
        manifest,
        original,
    })
}

fn run_id_from_verified_run(run: &VerifiedBundle) -> Result<String> {
    let manifest: RunManifest = run.read_json("run.json")?;
    Ok(manifest.run_id.0)
}

fn ensure_inventory_generation_is_nested(
    parent: &VerifiedBundle,
    relative: &str,
    child: &VerifiedBundle,
) -> Result<()> {
    let nested = parent.read_bytes(relative)?;
    let canonical = child.inventory.to_canonical_string()?.into_bytes();
    if nested != canonical {
        return Err(EvidenceError::IdentityMismatch {
            field: relative.into(),
            detail: "nested inventory differs from the parent inventory generation".into(),
        });
    }
    Ok(())
}

/// Persist one create-only public replay receipt outside the sealed run.
pub fn write_public_replay_receipt_v2(
    evidence_root: &Path,
    origin: &PublicReplayOriginV2,
    evidence: &AttemptEvidenceV2,
    observed_engine: &tomorrowci_core::EngineIdentityV2,
) -> Result<SealedPublicReplayReceiptV2> {
    validate_single_component(&evidence.attempt.attempt_id, "public replay receipt id")?;
    ensure_identity(
        "public replay attempt run id",
        &evidence.attempt.run_id.0,
        &origin.manifest.run_id.0,
    )?;
    ensure_identity(
        "public replay attempt scenario id",
        &evidence.attempt.scenario_id.0,
        &origin.manifest.scenario_id.0,
    )?;
    if evidence.attempt.kind != AttemptKindV2::Replay {
        return Err(EvidenceError::InvalidSemantics {
            field: "public replay attempt kind".into(),
            detail: "detached public receipts require kind replay".into(),
        });
    }

    ensure_directory(evidence_root)?;
    let receipt_root = ensure_plain_child(evidence_root, "replay-receipts")?;
    let run_root = ensure_plain_child(&receipt_root, &origin.manifest.run_id.0)?;
    let scenario_root = ensure_plain_child(&run_root, &origin.manifest.scenario_id.0)?;
    let receipt_dir = scenario_root.join(&evidence.attempt.attempt_id);
    fs::create_dir(&receipt_dir).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            EvidenceError::Other(format!(
                "refusing to overwrite public replay receipt: {}",
                receipt_dir.display()
            ))
        } else {
            EvidenceError::Io(error)
        }
    })?;
    ensure_directory(&receipt_dir)?;
    let origin_dir = receipt_dir.join("origin");
    fs::create_dir(&origin_dir)?;
    ensure_directory(&origin_dir)?;

    let redacted = redact_attempt(evidence, &origin.manifest)?;
    write_attempt_files(&receipt_dir, &redacted)?;

    let run_inventory = origin.run.inventory.to_canonical_string()?;
    let scenario_inventory = origin.scenario.inventory.to_canonical_string()?;
    let original_inventory = origin.original_attempt.inventory.to_canonical_string()?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_RUN_INVENTORY),
        run_inventory.as_bytes(),
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_SOURCE),
        &origin.run.read_bytes("source-manifest.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_CONFIG),
        &origin.run.read_bytes("config.normalized.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_SCENARIO_INVENTORY),
        scenario_inventory.as_bytes(),
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_SCENARIO),
        &origin.scenario.read_bytes("scenario.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_ENVIRONMENT),
        &origin.scenario.read_bytes("environment.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_COMMANDS),
        &origin.scenario.read_bytes("commands.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_REPLAY_MANIFEST),
        &origin.scenario.read_bytes("replay-manifest-v2.json")?,
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_ATTEMPT_INVENTORY),
        original_inventory.as_bytes(),
    )?;
    persist_regular_file(
        &receipt_dir.join(ORIGIN_ATTEMPT),
        &origin.original_attempt.read_bytes("attempt.json")?,
    )?;

    let mut equivalence = attempt_equivalence(&origin.original, &redacted.attempt);
    if *observed_engine != origin.manifest.engine {
        equivalence.equivalent = false;
        equivalence
            .mismatches
            .push(AttemptMismatchV2::EngineIdentity);
    }
    let receipt = PublicReplayReceiptV2 {
        schema_version: PUBLIC_REPLAY_RECEIPT_SCHEMA_VERSION,
        receipt_id: redacted.attempt.attempt_id.clone(),
        created_at: redacted.attempt.finished_at,
        run_id: redacted.attempt.run_id.clone(),
        scenario_id: redacted.attempt.scenario_id.clone(),
        original_run_inventory_sha256: origin.run.inventory_sha256()?,
        original_scenario_inventory_sha256: origin.scenario.inventory_sha256()?,
        original_attempt_inventory_sha256: origin.original_attempt.inventory_sha256()?,
        original_attempt_path: format!(
            "scenarios/{}/attempts/attempt-{:06}",
            origin.original.scenario_id.0, origin.original.ordinal
        ),
        original_attempt_id: origin.original.attempt_id.clone(),
        source_manifest_sha256: canonical_sha256(&origin.source).map_err(EvidenceError::Json)?,
        config_sha256: canonical_sha256(&origin.config).map_err(EvidenceError::Json)?,
        scenario_sha256: canonical_sha256(&origin.scenario_record).map_err(EvidenceError::Json)?,
        replay_manifest_sha256: canonical_sha256(&origin.manifest).map_err(EvidenceError::Json)?,
        original_attempt_sha256: canonical_sha256(&origin.original).map_err(EvidenceError::Json)?,
        replay_attempt_sha256: canonical_sha256(&redacted.attempt).map_err(EvidenceError::Json)?,
        expected_engine: origin.manifest.engine.clone(),
        observed_engine: observed_engine.clone(),
        image_digest: origin.manifest.image_digest.clone(),
        original_result: origin.original.result.clone(),
        replay_result: redacted.attempt.result.clone(),
        equivalent_to_original: equivalence.equivalent,
        mismatches: equivalence.mismatches,
    };
    write_json(&receipt_dir.join(PUBLIC_RECEIPT_FILE), &receipt)?;
    seal_bundle_version(
        &receipt_dir,
        BundleKind::ReplayAttempt,
        INVENTORY_VERSION_V2,
    )?;
    let bundle = verify_bundle(&receipt_dir)?;
    let verified_receipt: PublicReplayReceiptV2 = bundle.read_json(PUBLIC_RECEIPT_FILE)?;
    ensure_semantic_equality(
        PUBLIC_RECEIPT_FILE,
        &verified_receipt,
        "receipt written by producer",
        &receipt,
    )?;
    Ok(SealedPublicReplayReceiptV2 {
        bundle,
        receipt: verified_receipt,
    })
}

fn ensure_plain_child(parent: &Path, name: &str) -> Result<PathBuf> {
    validate_single_component(name, "receipt directory component")?;
    ensure_directory(parent)?;
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_directory(&child)?;
    Ok(child)
}

/// Return the next monotonic public replay ordinal below one run/scenario.
/// Existing entries must all be independently sealed receipts; an interrupted
/// or attacker-preseeded directory therefore blocks rather than being skipped.
pub fn next_public_replay_ordinal_v2(
    evidence_root: &Path,
    run_id: &str,
    scenario_id: &str,
) -> Result<u32> {
    validate_single_component(run_id, "run id")?;
    validate_single_component(scenario_id, "scenario id")?;
    let root = evidence_root
        .join("replay-receipts")
        .join(run_id)
        .join(scenario_id);
    if !root.exists() {
        return Ok(1);
    }
    ensure_directory(&root)?;
    let mut ordinals = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(EvidenceError::NonRegularEntry(
                entry.path().display().to_string(),
            ));
        }
        let (bundle, receipt, attempt) = read_public_replay_receipt_v2(&entry.path())?;
        ensure_identity("existing receipt run id", &receipt.run_id.0, run_id)?;
        ensure_identity(
            "existing receipt scenario id",
            &receipt.scenario_id.0,
            scenario_id,
        )?;
        drop(bundle);
        ordinals.push(attempt.ordinal);
    }
    ordinals.sort_unstable();
    let expected: Vec<u32> = (1..=ordinals.len() as u32).collect();
    if ordinals != expected {
        return Err(EvidenceError::InvalidSemantics {
            field: root.display().to_string(),
            detail: "existing public replay ordinals are not unique and consecutive from 1".into(),
        });
    }
    u32::try_from(ordinals.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| EvidenceError::InvalidSemantics {
            field: root.display().to_string(),
            detail: "public replay ordinal overflowed".into(),
        })
}

/// Verify and read one detached public replay receipt.
pub fn read_public_replay_receipt_v2(
    path: &Path,
) -> Result<(VerifiedBundle, PublicReplayReceiptV2, ExecutionAttemptV2)> {
    let bundle = verify_bundle(path)?;
    if bundle.version != INVENTORY_VERSION_V2
        || bundle.kind != BundleKind::ReplayAttempt
        || !bundle.contains(PUBLIC_RECEIPT_FILE)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: path.display().to_string(),
            detail: "expected a detached v2 public replay receipt".into(),
        });
    }
    let receipt: PublicReplayReceiptV2 = bundle.read_json(PUBLIC_RECEIPT_FILE)?;
    let attempt: ExecutionAttemptV2 = bundle.read_json("attempt.json")?;
    Ok((bundle, receipt, attempt))
}

/// Verify exactly two distinct receipts and recompute their common-origin,
/// equivalence, ordering, and timing gates.
pub fn verify_public_replay_receipt_pair_v2(
    original_run: &Path,
    paths: &[PathBuf],
) -> Result<VerifiedPublicReplayPairV2> {
    if paths.len() != 2 {
        return Err(EvidenceError::InvalidSemantics {
            field: "public replay receipt pair".into(),
            detail: format!(
                "exactly two receipt paths are required, found {}",
                paths.len()
            ),
        });
    }
    let first_path = fs::canonicalize(&paths[0])?;
    let second_path = fs::canonicalize(&paths[1])?;
    if first_path == second_path {
        return Err(EvidenceError::DuplicateIdentity {
            kind: "public replay receipt path".into(),
            id: first_path.display().to_string(),
        });
    }
    let first = read_public_replay_receipt_v2(&first_path)?;
    let second = read_public_replay_receipt_v2(&second_path)?;
    let mut pair = [first, second];
    pair.sort_by_key(|(_, _, attempt)| attempt.ordinal);
    let (first_bundle, first_receipt, first_attempt) = &pair[0];
    let (second_bundle, second_receipt, second_attempt) = &pair[1];
    if first_receipt.receipt_id == second_receipt.receipt_id
        || first_attempt.attempt_id == second_attempt.attempt_id
    {
        return Err(EvidenceError::DuplicateIdentity {
            kind: "public replay receipt".into(),
            id: first_receipt.receipt_id.clone(),
        });
    }
    let first_inventory_sha = first_bundle.inventory_sha256()?;
    let second_inventory_sha = second_bundle.inventory_sha256()?;
    if first_inventory_sha == second_inventory_sha {
        return Err(EvidenceError::DuplicateIdentity {
            kind: "public replay receipt inventory".into(),
            id: first_inventory_sha,
        });
    }
    if !public_receipts_share_origin(first_receipt, second_receipt) {
        return Err(EvidenceError::IdentityMismatch {
            field: "public replay receipt pair origin".into(),
            detail: "receipts do not bind the same run generation and original attempt".into(),
        });
    }
    let verified_run = verify_bundle(original_run)?;
    if verified_run.version != INVENTORY_VERSION_V2 || verified_run.kind != BundleKind::Run {
        return Err(EvidenceError::InvalidSemantics {
            field: original_run.display().to_string(),
            detail: "pair qualification requires the complete verified v2 origin run".into(),
        });
    }
    let verified_origin =
        load_public_replay_origin_v2(&verified_run, &first_receipt.scenario_id.0)?;
    let verdicts: Vec<ScenarioVerdict> = verified_run.read_json("verdicts.json")?;
    let verdict = verdicts
        .iter()
        .find(|verdict| verdict.scenario_id == first_receipt.scenario_id)
        .ok_or_else(|| EvidenceError::Missing("public replay pair origin verdict".into()))?;
    if !matches!(
        verdict.verdict,
        Verdict::BaselinePass
            | Verdict::BaselineInvalid
            | Verdict::FuturePass
            | Verdict::FutureFail
    ) {
        return Err(EvidenceError::InvalidSemantics {
            field: "public replay receipt pair origin verdict".into(),
            detail: format!(
                "{:?} cannot be promoted to an exact replay qualification",
                verdict.verdict
            ),
        });
    }
    for receipt in [first_receipt, second_receipt] {
        ensure_receipt_matches_verified_origin(receipt, &verified_origin)?;
    }
    for (receipt, attempt) in [
        (first_receipt, first_attempt),
        (second_receipt, second_attempt),
    ] {
        if !receipt.equivalent_to_original
            || !receipt.mismatches.is_empty()
            || receipt.observed_engine != receipt.expected_engine
            || receipt.receipt_id == receipt.original_attempt_id
            || attempt.kind != AttemptKindV2::Replay
        {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("public replay receipt {}", receipt.receipt_id),
                detail: "receipt is not an exact equivalent replay of its sealed original".into(),
            });
        }
    }
    if second_attempt.ordinal != first_attempt.ordinal.saturating_add(1)
        || second_attempt.started_at < first_attempt.finished_at
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "public replay receipt pair order".into(),
            detail: "receipt ordinals must be consecutive and executions must not overlap".into(),
        });
    }
    Ok(VerifiedPublicReplayPairV2 {
        run_id: first_receipt.run_id.clone(),
        scenario_id: first_receipt.scenario_id.clone(),
        receipt_ids: vec![
            first_receipt.receipt_id.clone(),
            second_receipt.receipt_id.clone(),
        ],
        receipt_inventory_sha256: vec![first_inventory_sha, second_inventory_sha],
        original_attempt_sha256: first_receipt.original_attempt_sha256.clone(),
        outcome_class: first_attempt.result.outcome_class,
        target_exit_code: first_attempt.result.exit_code,
    })
}

fn ensure_receipt_matches_verified_origin(
    receipt: &PublicReplayReceiptV2,
    origin: &PublicReplayOriginV2,
) -> Result<()> {
    let expected_original_path = format!(
        "scenarios/{}/attempts/attempt-{:06}",
        origin.original.scenario_id.0, origin.original.ordinal
    );
    let checks = [
        (
            "original_run_inventory_sha256",
            receipt.original_run_inventory_sha256.clone(),
            origin.run.inventory_sha256()?,
        ),
        (
            "original_scenario_inventory_sha256",
            receipt.original_scenario_inventory_sha256.clone(),
            origin.scenario.inventory_sha256()?,
        ),
        (
            "original_attempt_inventory_sha256",
            receipt.original_attempt_inventory_sha256.clone(),
            origin.original_attempt.inventory_sha256()?,
        ),
        (
            "original_attempt_path",
            receipt.original_attempt_path.clone(),
            expected_original_path,
        ),
        (
            "original_attempt_id",
            receipt.original_attempt_id.clone(),
            origin.original.attempt_id.clone(),
        ),
        (
            "source_manifest_sha256",
            receipt.source_manifest_sha256.clone(),
            canonical_sha256(&origin.source).map_err(EvidenceError::Json)?,
        ),
        (
            "config_sha256",
            receipt.config_sha256.clone(),
            canonical_sha256(&origin.config).map_err(EvidenceError::Json)?,
        ),
        (
            "scenario_sha256",
            receipt.scenario_sha256.clone(),
            canonical_sha256(&origin.scenario_record).map_err(EvidenceError::Json)?,
        ),
        (
            "replay_manifest_sha256",
            receipt.replay_manifest_sha256.clone(),
            canonical_sha256(&origin.manifest).map_err(EvidenceError::Json)?,
        ),
        (
            "original_attempt_sha256",
            receipt.original_attempt_sha256.clone(),
            canonical_sha256(&origin.original).map_err(EvidenceError::Json)?,
        ),
        (
            "image_digest",
            receipt.image_digest.clone(),
            origin.manifest.image_digest.clone(),
        ),
    ];
    for (field, actual, expected) in checks {
        ensure_identity(
            &format!("public receipt trusted origin {field}"),
            &actual,
            &expected,
        )?;
    }
    ensure_identity(
        "public receipt trusted origin run id",
        &receipt.run_id.0,
        &origin.manifest.run_id.0,
    )?;
    ensure_identity(
        "public receipt trusted origin scenario id",
        &receipt.scenario_id.0,
        &origin.manifest.scenario_id.0,
    )?;
    ensure_semantic_equality(
        "public receipt trusted origin expected engine",
        &receipt.expected_engine,
        "verified origin manifest engine",
        &origin.manifest.engine,
    )?;
    ensure_semantic_equality(
        "public receipt trusted origin result",
        &receipt.original_result,
        "verified origin original result",
        &origin.original.result,
    )
}

fn public_receipts_share_origin(
    left: &PublicReplayReceiptV2,
    right: &PublicReplayReceiptV2,
) -> bool {
    left.run_id == right.run_id
        && left.scenario_id == right.scenario_id
        && left.original_run_inventory_sha256 == right.original_run_inventory_sha256
        && left.original_scenario_inventory_sha256 == right.original_scenario_inventory_sha256
        && left.original_attempt_inventory_sha256 == right.original_attempt_inventory_sha256
        && left.original_attempt_path == right.original_attempt_path
        && left.original_attempt_id == right.original_attempt_id
        && left.source_manifest_sha256 == right.source_manifest_sha256
        && left.config_sha256 == right.config_sha256
        && left.scenario_sha256 == right.scenario_sha256
        && left.replay_manifest_sha256 == right.replay_manifest_sha256
        && left.original_attempt_sha256 == right.original_attempt_sha256
        && left.expected_engine == right.expected_engine
        && left.image_digest == right.image_digest
        && left.original_result == right.original_result
}

fn redact_attempt(
    evidence: &AttemptEvidenceV2,
    manifest: &ExactReplayManifestV2,
) -> Result<AttemptEvidenceV2> {
    let mut redacted = evidence.clone();
    redacted.stdout = redact_secrets(&redacted.stdout);
    redacted.stderr = redact_secrets(&redacted.stderr);
    redacted.attempt.attempt_id = redact_secrets(&redacted.attempt.attempt_id);
    redacted.attempt.image_ref = manifest.image_ref.clone();
    redacted.attempt.image_digest = manifest.image_digest.clone();
    redacted.attempt.commands = manifest.commands.clone();
    redacted.attempt.environment = manifest.environment.clone();
    redacted.attempt.engine = manifest.engine.clone();
    redacted.attempt.replay_manifest_sha256 =
        canonical_sha256(manifest).map_err(EvidenceError::Json)?;
    redacted.attempt.result.blocked_reason = redacted
        .attempt
        .result
        .blocked_reason
        .as_deref()
        .map(redact_secrets);
    if let Some(signature) = &mut redacted.attempt.failure_signature {
        signature.kind = redact_secrets(&signature.kind);
        signature.summary = redact_secrets(&signature.summary);
        signature.primary_error = signature.primary_error.as_deref().map(redact_secrets);
        signature.framework_hints = signature
            .framework_hints
            .iter()
            .map(|hint| redact_secrets(hint))
            .collect();
        signature.fingerprint = FailureSignature::compute_fingerprint(
            &signature.kind,
            signature.primary_error.as_deref().unwrap_or_default(),
            &signature.summary,
        );
    }
    let stdout = cap_bytes(&redacted.stdout, 2 * 1024 * 1024);
    let stderr = cap_bytes(&redacted.stderr, 2 * 1024 * 1024);
    redacted.attempt.result.stdout_sha256 = Some(prefixed_sha256(stdout.as_bytes()));
    redacted.attempt.result.stderr_sha256 = Some(prefixed_sha256(stderr.as_bytes()));
    Ok(redacted)
}

fn redact_exact_manifest(
    manifest: &ExactReplayManifestV2,
    scenario: &Scenario,
) -> Result<ExactReplayManifestV2> {
    let mut redacted = manifest.clone();
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.scenario_sha256 = canonical_sha256(scenario).map_err(EvidenceError::Json)?;
    redacted.engine.name = redact_secrets(&redacted.engine.name);
    redacted.engine.client_version = redact_secrets(&redacted.engine.client_version);
    redacted.engine.server_version = redacted
        .engine
        .server_version
        .as_deref()
        .map(redact_secrets);
    redacted.engine.api_version = redacted.engine.api_version.as_deref().map(redact_secrets);
    redacted.engine.os = redact_secrets(&redacted.engine.os);
    redacted.engine.arch = redact_secrets(&redacted.engine.arch);
    redacted.environment.workdir = redact_secrets(&redacted.environment.workdir);
    redacted.environment.user = redacted.environment.user.as_deref().map(redact_secrets);
    for value in redacted.environment.env.values_mut() {
        *value = redact_secrets(value);
    }
    for mount in &mut redacted.environment.mounts {
        mount.source = redact_secrets(&mount.source);
        mount.container_path = redact_secrets(&mount.container_path);
    }
    for command in &mut redacted.commands {
        command.program = redact_secrets(&command.program);
        command.args = command
            .args
            .iter()
            .map(|argument| redact_secrets(argument))
            .collect();
        command.workdir = redact_secrets(&command.workdir);
        for value in command.env.values_mut() {
            *value = redact_secrets(value);
        }
    }
    Ok(redacted)
}

fn collect_source_files(
    root: &Path,
    current: &Path,
    relative_parent: &str,
    depth: usize,
    total_bytes: &mut u64,
    entry_count: &mut usize,
    files: &mut Vec<SourceFileEntryV2>,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(current)? {
        *entry_count += 1;
        if *entry_count > MAX_BUNDLE_FILES {
            return Err(EvidenceError::InvalidSemantics {
                field: "source-manifest.json.files".into(),
                detail: format!("source contains more than {MAX_BUNDLE_FILES} entries"),
            });
        }
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            EvidenceError::UnsafePath(format!("non-UTF-8 source path under {}", root.display()))
        })?;
        let relative = if relative_parent.is_empty() {
            name.to_string()
        } else {
            format!("{relative_parent}/{name}")
        };
        validate_inventory_path(&relative)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(EvidenceError::NonRegularEntry(relative));
        }
        if metadata.is_dir() {
            if depth >= MAX_BUNDLE_DEPTH {
                return Err(EvidenceError::InvalidSemantics {
                    field: relative,
                    detail: format!("source nesting exceeds {MAX_BUNDLE_DEPTH}"),
                });
            }
            collect_source_files(
                root,
                &path,
                &relative,
                depth + 1,
                total_bytes,
                entry_count,
                files,
            )?;
        } else if metadata.is_file() {
            *total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                EvidenceError::InvalidSemantics {
                    field: relative.clone(),
                    detail: "source byte count overflowed".into(),
                }
            })?;
            if *total_bytes > MAX_BUNDLE_BYTES {
                return Err(EvidenceError::InvalidSemantics {
                    field: relative,
                    detail: format!("source exceeds {MAX_BUNDLE_BYTES} bytes"),
                });
            }
            files.push(SourceFileEntryV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                path: relative,
                sha256: format!("sha256:{}", sha256_regular_file(&path)?),
                size_bytes: metadata.len(),
                executable: executable_bit(&metadata),
            });
        } else {
            return Err(EvidenceError::NonRegularEntry(relative));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable_bit(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bit(_metadata: &Metadata) -> bool {
    false
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(super) fn verify_attempt_v2_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<()> {
    if inventory.version != INVENTORY_VERSION_V2 {
        return Err(EvidenceError::UnsupportedInventoryVersion(format!(
            "replay-attempt inventory v{}",
            inventory.version
        )));
    }
    let attempt: ExecutionAttemptV2 = read_typed_json(dir, inventory, "attempt.json")?;
    let environment: tomorrowci_core::ExactEnvironmentV2 =
        read_typed_json(dir, inventory, "environment.json")?;
    let commands: Vec<ReplayCommandV2> = read_typed_json(dir, inventory, "commands.json")?;
    let result: ExecutionAttemptResultV2 = read_typed_json(dir, inventory, "result.json")?;
    ensure_semantic_equality(
        "attempt.json.environment",
        &attempt.environment,
        "environment.json",
        &environment,
    )?;
    ensure_semantic_equality(
        "attempt.json.commands",
        &attempt.commands,
        "commands.json",
        &commands,
    )?;
    ensure_semantic_equality(
        "attempt.json.result",
        &attempt.result,
        "result.json",
        &result,
    )?;
    validate_attempt_v2(&attempt, expected_run_id, expected_scenario_id)?;

    let signature_path = "failure-signature.json";
    let signature = if inventory_has(inventory, signature_path) {
        Some(read_typed_json::<NormalizedFailureSignatureV2>(
            dir,
            inventory,
            signature_path,
        )?)
    } else {
        None
    };
    ensure_semantic_equality(
        "attempt.json.failure_signature",
        &attempt.failure_signature,
        signature_path,
        &signature,
    )?;
    validate_attempt_outcome(&attempt)?;

    let stdout = read_inventory_bytes(dir, inventory, "stdout.log")?;
    let stderr = read_inventory_bytes(dir, inventory, "stderr.log")?;
    ensure_optional_identity(
        "result.json.stdout_sha256",
        attempt.result.stdout_sha256.as_deref(),
        Some(&prefixed_sha256(&stdout)),
    )?;
    ensure_optional_identity(
        "result.json.stderr_sha256",
        attempt.result.stderr_sha256.as_deref(),
        Some(&prefixed_sha256(&stderr)),
    )?;
    let has_receipt = inventory_has(inventory, PUBLIC_RECEIPT_FILE);
    let has_origin = inventory
        .entries
        .iter()
        .any(|entry| entry.path.starts_with("origin/"));
    match (has_receipt, has_origin) {
        (true, true) => verify_public_replay_receipt_semantics(dir, inventory, &attempt),
        (false, false) => Ok(()),
        _ => Err(EvidenceError::InvalidSemantics {
            field: "public replay receipt layout".into(),
            detail: "receipt metadata and its detached origin records must appear together".into(),
        }),
    }
}

fn verify_public_replay_receipt_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    attempt: &ExecutionAttemptV2,
) -> Result<()> {
    let mut allowed: BTreeSet<&str> = [
        "attempt.json",
        "commands.json",
        "environment.json",
        "result.json",
        "stderr.log",
        "stdout.log",
        "failure-signature.json",
        PUBLIC_RECEIPT_FILE,
        ORIGIN_RUN_INVENTORY,
        ORIGIN_SOURCE,
        ORIGIN_CONFIG,
        ORIGIN_SCENARIO_INVENTORY,
        ORIGIN_SCENARIO,
        ORIGIN_ENVIRONMENT,
        ORIGIN_COMMANDS,
        ORIGIN_REPLAY_MANIFEST,
        ORIGIN_ATTEMPT_INVENTORY,
        ORIGIN_ATTEMPT,
    ]
    .into_iter()
    .collect();
    if attempt.failure_signature.is_none() {
        allowed.remove("failure-signature.json");
    }
    for entry in &inventory.entries {
        if !allowed.contains(entry.path.as_str()) {
            return Err(EvidenceError::Unlisted(format!(
                "unexpected public replay receipt path {}",
                entry.path
            )));
        }
    }
    for required in [
        PUBLIC_RECEIPT_FILE,
        ORIGIN_RUN_INVENTORY,
        ORIGIN_SOURCE,
        ORIGIN_CONFIG,
        ORIGIN_SCENARIO_INVENTORY,
        ORIGIN_SCENARIO,
        ORIGIN_ENVIRONMENT,
        ORIGIN_COMMANDS,
        ORIGIN_REPLAY_MANIFEST,
        ORIGIN_ATTEMPT_INVENTORY,
        ORIGIN_ATTEMPT,
    ] {
        if !inventory_has(inventory, required) {
            return Err(EvidenceError::Missing(required.into()));
        }
    }

    let receipt: PublicReplayReceiptV2 = read_typed_json(dir, inventory, PUBLIC_RECEIPT_FILE)?;
    if receipt.schema_version != PUBLIC_REPLAY_RECEIPT_SCHEMA_VERSION {
        return Err(EvidenceError::InvalidSemantics {
            field: format!("{PUBLIC_RECEIPT_FILE}.schema_version"),
            detail: format!(
                "expected {PUBLIC_REPLAY_RECEIPT_SCHEMA_VERSION}, found {}",
                receipt.schema_version
            ),
        });
    }
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.receipt_id"),
        &receipt.receipt_id,
        &attempt.attempt_id,
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.run_id"),
        &receipt.run_id.0,
        &attempt.run_id.0,
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.scenario_id"),
        &receipt.scenario_id.0,
        &attempt.scenario_id.0,
    )?;
    if receipt.created_at != attempt.finished_at || attempt.kind != AttemptKindV2::Replay {
        return Err(EvidenceError::InvalidSemantics {
            field: PUBLIC_RECEIPT_FILE.into(),
            detail: "receipt timestamp or replay kind differs from attempt.json".into(),
        });
    }

    let run_inventory_bytes = read_inventory_bytes(dir, inventory, ORIGIN_RUN_INVENTORY)?;
    let scenario_inventory_bytes = read_inventory_bytes(dir, inventory, ORIGIN_SCENARIO_INVENTORY)?;
    let attempt_inventory_bytes = read_inventory_bytes(dir, inventory, ORIGIN_ATTEMPT_INVENTORY)?;
    let run_inventory = parse_embedded_inventory(&run_inventory_bytes, BundleKind::Run)?;
    let scenario_inventory =
        parse_embedded_inventory(&scenario_inventory_bytes, BundleKind::Scenario)?;
    let original_inventory =
        parse_embedded_inventory(&attempt_inventory_bytes, BundleKind::ReplayAttempt)?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.original_run_inventory_sha256"),
        &receipt.original_run_inventory_sha256,
        &sha256_hex(&run_inventory_bytes),
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.original_scenario_inventory_sha256"),
        &receipt.original_scenario_inventory_sha256,
        &sha256_hex(&scenario_inventory_bytes),
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.original_attempt_inventory_sha256"),
        &receipt.original_attempt_inventory_sha256,
        &sha256_hex(&attempt_inventory_bytes),
    )?;

    let source_bytes = read_inventory_bytes(dir, inventory, ORIGIN_SOURCE)?;
    let config_bytes = read_inventory_bytes(dir, inventory, ORIGIN_CONFIG)?;
    let scenario_bytes = read_inventory_bytes(dir, inventory, ORIGIN_SCENARIO)?;
    let environment_bytes = read_inventory_bytes(dir, inventory, ORIGIN_ENVIRONMENT)?;
    let commands_bytes = read_inventory_bytes(dir, inventory, ORIGIN_COMMANDS)?;
    let manifest_bytes = read_inventory_bytes(dir, inventory, ORIGIN_REPLAY_MANIFEST)?;
    let original_bytes = read_inventory_bytes(dir, inventory, ORIGIN_ATTEMPT)?;
    let scenario_prefix = format!("scenarios/{}", receipt.scenario_id.0);
    bind_embedded_bytes(&run_inventory, "source-manifest.json", &source_bytes)?;
    bind_embedded_bytes(&run_inventory, "config.normalized.json", &config_bytes)?;
    bind_embedded_bytes(
        &run_inventory,
        &format!("{scenario_prefix}/checksums.txt"),
        &scenario_inventory_bytes,
    )?;
    for (name, bytes) in [
        ("scenario.json", scenario_bytes.as_slice()),
        ("environment.json", environment_bytes.as_slice()),
        ("commands.json", commands_bytes.as_slice()),
        ("replay-manifest-v2.json", manifest_bytes.as_slice()),
    ] {
        bind_embedded_bytes(&scenario_inventory, name, bytes)?;
        bind_embedded_bytes(&run_inventory, &format!("{scenario_prefix}/{name}"), bytes)?;
    }

    validate_inventory_path(&receipt.original_attempt_path)?;
    let original_relative = receipt
        .original_attempt_path
        .strip_prefix(&format!("{scenario_prefix}/"))
        .ok_or_else(|| EvidenceError::IdentityMismatch {
            field: format!("{PUBLIC_RECEIPT_FILE}.original_attempt_path"),
            detail: "path is not below the bound scenario".into(),
        })?;
    bind_embedded_bytes(
        &scenario_inventory,
        &format!("{original_relative}/checksums.txt"),
        &attempt_inventory_bytes,
    )?;
    bind_embedded_bytes(
        &run_inventory,
        &format!("{}/checksums.txt", receipt.original_attempt_path),
        &attempt_inventory_bytes,
    )?;
    bind_embedded_bytes(
        &scenario_inventory,
        &format!("{original_relative}/attempt.json"),
        &original_bytes,
    )?;
    bind_embedded_bytes(
        &run_inventory,
        &format!("{}/attempt.json", receipt.original_attempt_path),
        &original_bytes,
    )?;
    bind_embedded_bytes(&original_inventory, "attempt.json", &original_bytes)?;

    let source: SourceSnapshotManifestV2 = parse_embedded_json(ORIGIN_SOURCE, &source_bytes)?;
    let config: Config = parse_embedded_json(ORIGIN_CONFIG, &config_bytes)?;
    let scenario: Scenario = parse_embedded_json(ORIGIN_SCENARIO, &scenario_bytes)?;
    let environment: EnvironmentSpec = parse_embedded_json(ORIGIN_ENVIRONMENT, &environment_bytes)?;
    let commands: Vec<CommandSpec> = parse_embedded_json(ORIGIN_COMMANDS, &commands_bytes)?;
    let manifest: ExactReplayManifestV2 =
        parse_embedded_json(ORIGIN_REPLAY_MANIFEST, &manifest_bytes)?;
    let original: ExecutionAttemptV2 = parse_embedded_json(ORIGIN_ATTEMPT, &original_bytes)?;
    validate_detached_source_manifest(&source)?;
    config
        .validate()
        .map_err(|error| EvidenceError::InvalidSemantics {
            field: ORIGIN_CONFIG.into(),
            detail: error.to_string(),
        })?;
    validate_exact_manifest(&manifest, &scenario, &environment, &commands)?;
    validate_attempt_v2(
        &original,
        Some(&receipt.run_id.0),
        Some(&receipt.scenario_id.0),
    )?;
    validate_attempt_outcome(&original)?;
    if original.kind != AttemptKindV2::Original {
        return Err(EvidenceError::InvalidSemantics {
            field: ORIGIN_ATTEMPT.into(),
            detail: "bound origin attempt is not original".into(),
        });
    }
    ensure_identity(
        &format!("{ORIGIN_SOURCE}.run_id"),
        &source.run_id.0,
        &receipt.run_id.0,
    )?;
    ensure_identity(
        &format!("{ORIGIN_SCENARIO}.id"),
        &scenario.id.0,
        &receipt.scenario_id.0,
    )?;
    ensure_attempt_matches_manifest(&original, &manifest, "origin original attempt")?;
    ensure_attempt_matches_manifest(attempt, &manifest, "public replay attempt")?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.original_attempt_id"),
        &receipt.original_attempt_id,
        &original.attempt_id,
    )?;
    if receipt.receipt_id == receipt.original_attempt_id {
        return Err(EvidenceError::DuplicateIdentity {
            kind: "original/public replay attempt".into(),
            id: receipt.receipt_id.clone(),
        });
    }
    ensure_selected_final_original(&scenario_inventory, original_relative, original.ordinal)?;

    let source_sha = canonical_sha256(&source).map_err(EvidenceError::Json)?;
    let config_sha = canonical_sha256(&config).map_err(EvidenceError::Json)?;
    let scenario_sha = canonical_sha256(&scenario).map_err(EvidenceError::Json)?;
    let manifest_sha = canonical_sha256(&manifest).map_err(EvidenceError::Json)?;
    let original_sha = canonical_sha256(&original).map_err(EvidenceError::Json)?;
    let replay_sha = canonical_sha256(attempt).map_err(EvidenceError::Json)?;
    for (field, actual, expected) in [
        (
            "source_manifest_sha256",
            receipt.source_manifest_sha256.as_str(),
            source_sha.as_str(),
        ),
        (
            "config_sha256",
            receipt.config_sha256.as_str(),
            config_sha.as_str(),
        ),
        (
            "scenario_sha256",
            receipt.scenario_sha256.as_str(),
            scenario_sha.as_str(),
        ),
        (
            "replay_manifest_sha256",
            receipt.replay_manifest_sha256.as_str(),
            manifest_sha.as_str(),
        ),
        (
            "original_attempt_sha256",
            receipt.original_attempt_sha256.as_str(),
            original_sha.as_str(),
        ),
        (
            "replay_attempt_sha256",
            receipt.replay_attempt_sha256.as_str(),
            replay_sha.as_str(),
        ),
    ] {
        ensure_identity(&format!("{PUBLIC_RECEIPT_FILE}.{field}"), actual, expected)?;
    }
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.source_manifest_sha256"),
        &receipt.source_manifest_sha256,
        &manifest.source_manifest_sha256,
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.config_sha256"),
        &receipt.config_sha256,
        &manifest.config_sha256,
    )?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.scenario_sha256"),
        &receipt.scenario_sha256,
        &manifest.scenario_sha256,
    )?;
    ensure_semantic_equality(
        &format!("{PUBLIC_RECEIPT_FILE}.expected_engine"),
        &receipt.expected_engine,
        "origin replay manifest engine",
        &manifest.engine,
    )?;
    validate_engine(&receipt.observed_engine)?;
    ensure_identity(
        &format!("{PUBLIC_RECEIPT_FILE}.image_digest"),
        &receipt.image_digest,
        &manifest.image_digest,
    )?;
    ensure_semantic_equality(
        &format!("{PUBLIC_RECEIPT_FILE}.original_result"),
        &receipt.original_result,
        "origin original result",
        &original.result,
    )?;
    ensure_semantic_equality(
        &format!("{PUBLIC_RECEIPT_FILE}.replay_result"),
        &receipt.replay_result,
        "public replay result",
        &attempt.result,
    )?;

    let mut calculated = attempt_equivalence(&original, attempt);
    if receipt.observed_engine != manifest.engine {
        calculated.equivalent = false;
        calculated
            .mismatches
            .push(AttemptMismatchV2::EngineIdentity);
        if attempt.result.outcome_class != AttemptOutcomeClassV2::Blocked {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("{PUBLIC_RECEIPT_FILE}.observed_engine"),
                detail: "an engine identity mismatch must fail closed as BLOCKED".into(),
            });
        }
    }
    if receipt.equivalent_to_original != calculated.equivalent
        || receipt.mismatches != calculated.mismatches
    {
        return Err(EvidenceError::IdentityMismatch {
            field: PUBLIC_RECEIPT_FILE.into(),
            detail: "recorded equivalence differs from recomputed origin/result equivalence".into(),
        });
    }
    Ok(())
}

fn parse_embedded_inventory(bytes: &[u8], kind: BundleKind) -> Result<BundleInventory> {
    let text = std::str::from_utf8(bytes).map_err(|_| EvidenceError::MalformedInventory {
        line: 0,
        reason: "embedded inventory is not UTF-8".into(),
    })?;
    let inventory = BundleInventory::parse(text)?;
    if inventory.version != INVENTORY_VERSION_V2 || inventory.kind != kind {
        return Err(EvidenceError::IdentityMismatch {
            field: "embedded inventory header".into(),
            detail: format!(
                "expected v2 {kind:?}, found v{} {:?}",
                inventory.version, inventory.kind
            ),
        });
    }
    if inventory.to_canonical_string()?.as_bytes() != bytes {
        return Err(EvidenceError::MalformedInventory {
            line: 0,
            reason: "embedded inventory is not canonical".into(),
        });
    }
    Ok(inventory)
}

fn parse_embedded_json<T: DeserializeOwned>(path: &str, bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_TYPED_JSON_BYTES {
        return Err(EvidenceError::InvalidSemantics {
            field: path.into(),
            detail: "embedded JSON exceeds the typed read limit".into(),
        });
    }
    serde_json::from_slice(bytes).map_err(|source| EvidenceError::InvalidJson {
        path: path.into(),
        source,
    })
}

fn bind_embedded_bytes(inventory: &BundleInventory, path: &str, bytes: &[u8]) -> Result<()> {
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| EvidenceError::Missing(format!("embedded inventory path {path}")))?;
    ensure_identity(path, &sha256_hex(bytes), &entry.sha256)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn ensure_attempt_matches_manifest(
    attempt: &ExecutionAttemptV2,
    manifest: &ExactReplayManifestV2,
    field: &str,
) -> Result<()> {
    let manifest_sha = canonical_sha256(manifest).map_err(EvidenceError::Json)?;
    if attempt.run_id != manifest.run_id
        || attempt.scenario_id != manifest.scenario_id
        || attempt.scenario_kind != manifest.scenario_kind
        || attempt.source_manifest_sha256 != manifest.source_manifest_sha256
        || attempt.config_sha256 != manifest.config_sha256
        || attempt.replay_manifest_sha256 != manifest_sha
        || attempt.image_ref != manifest.image_ref
        || attempt.image_digest != manifest.image_digest
        || attempt.commands != manifest.commands
        || attempt.environment != manifest.environment
        || attempt.engine != manifest.engine
    {
        return Err(EvidenceError::IdentityMismatch {
            field: field.into(),
            detail: "attempt identity differs from the bound exact replay manifest".into(),
        });
    }
    Ok(())
}

fn ensure_selected_final_original(
    inventory: &BundleInventory,
    selected: &str,
    ordinal: u32,
) -> Result<()> {
    let mut ordinals = Vec::new();
    for entry in &inventory.entries {
        let Some(path) = entry.path.strip_suffix("/attempt.json") else {
            continue;
        };
        let Some(name) = path.strip_prefix("attempts/attempt-") else {
            continue;
        };
        if name.contains('/') || name.len() != 6 || !name.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "embedded scenario original attempt paths".into(),
                detail: format!("non-canonical original attempt path {path}"),
            });
        }
        ordinals.push(
            name.parse::<u32>()
                .map_err(|_| EvidenceError::InvalidSemantics {
                    field: "embedded scenario original attempt paths".into(),
                    detail: "attempt ordinal is invalid".into(),
                })?,
        );
    }
    ordinals.sort_unstable();
    let expected: Vec<u32> = (1..=ordinals.len() as u32).collect();
    if ordinals != expected || ordinals.last().copied() != Some(ordinal) {
        return Err(EvidenceError::InvalidSemantics {
            field: "embedded scenario original attempts".into(),
            detail: "selected original is not the final member of a consecutive original set"
                .into(),
        });
    }
    ensure_identity(
        "selected original attempt path",
        selected,
        &format!("attempts/attempt-{ordinal:06}"),
    )
}

fn validate_detached_source_manifest(source: &SourceSnapshotManifestV2) -> Result<()> {
    if !source.identity_is_coherent() {
        return Err(EvidenceError::InvalidSemantics {
            field: ORIGIN_SOURCE.into(),
            detail: "source identity kind, commit, dirty flag, or schema is incoherent".into(),
        });
    }
    let mut prior: Option<&str> = None;
    let mut portable = BTreeSet::new();
    for file in &source.files {
        validate_inventory_path(&file.path)?;
        validate_digest("origin source file digest", &file.sha256)?;
        if prior.is_some_and(|previous| previous >= file.path.as_str())
            || !portable.insert(file.path.to_lowercase())
        {
            return Err(EvidenceError::DuplicatePath(file.path.clone()));
        }
        prior = Some(&file.path);
    }
    ensure_identity(
        "origin source tree digest",
        &source.tree_sha256,
        &canonical_sha256(&source.files).map_err(EvidenceError::Json)?,
    )
}

pub(super) fn verify_scenario_v2_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<()> {
    if inventory.version != INVENTORY_VERSION_V2 {
        return Ok(());
    }
    let scenario: Scenario = read_typed_json(dir, inventory, "scenario.json")?;
    let environment: EnvironmentSpec = read_typed_json(dir, inventory, "environment.json")?;
    let commands: Vec<CommandSpec> = read_typed_json(dir, inventory, "commands.json")?;
    let manifest: ExactReplayManifestV2 =
        read_typed_json(dir, inventory, "replay-manifest-v2.json")?;
    validate_exact_manifest(&manifest, &scenario, &environment, &commands)?;
    if let Some(expected) = expected_run_id {
        ensure_identity(
            "replay-manifest-v2.json.run_id",
            &manifest.run_id.0,
            expected,
        )?;
    }
    if let Some(expected) = expected_scenario_id {
        ensure_identity(
            "replay-manifest-v2.json.scenario_id",
            &manifest.scenario_id.0,
            expected,
        )?;
    }

    let (originals, replays) = load_attempts(dir, inventory, &manifest)?;
    if originals.is_empty() {
        return Err(EvidenceError::Missing(
            "v2 scenario requires attempts/attempt-000001".into(),
        ));
    }
    require_consecutive_attempts(&originals, AttemptKindV2::Original)?;
    require_consecutive_attempts(&replays, AttemptKindV2::Replay)?;
    let qualification = if inventory_has(inventory, "replay-qualification.json") {
        Some(read_typed_json::<ReplayQualificationV2>(
            dir,
            inventory,
            "replay-qualification.json",
        )?)
    } else {
        None
    };
    match (qualification, replays.is_empty()) {
        (None, true) => {}
        (Some(qualification), false) => {
            let original = originals.last().expect("checked non-empty");
            let rebuilt =
                ReplayQualificationV2::evaluate(original, &replays, qualification.qualified_at)
                    .map_err(EvidenceError::Json)?;
            ensure_semantic_equality(
                "replay-qualification.json",
                &qualification,
                "recomputed replay qualification",
                &rebuilt,
            )?;
        }
        (None, false) => {
            return Err(EvidenceError::Missing(
                "replay attempts require replay-qualification.json".into(),
            ))
        }
        (Some(_), true) => {
            return Err(EvidenceError::InvalidSemantics {
                field: "replay-qualification.json".into(),
                detail: "qualification has no replay attempt bundles".into(),
            })
        }
    }
    Ok(())
}

pub(super) fn verify_run_v2_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
) -> Result<()> {
    if inventory.version != INVENTORY_VERSION_V2 {
        return Ok(());
    }
    let run: RunManifest = read_typed_json(dir, inventory, "run.json")?;
    let repository: RepositorySnapshot = read_typed_json(dir, inventory, "repository.json")?;
    let config: Config = read_typed_json(dir, inventory, "config.normalized.json")?;
    let frontier: BreakageFrontier = read_typed_json(dir, inventory, "frontier.json")?;
    let verdicts: Vec<ScenarioVerdict> = read_typed_json(dir, inventory, "verdicts.json")?;
    let source: SourceSnapshotManifestV2 = read_typed_json(dir, inventory, "source-manifest.json")?;
    let qualifications: Vec<ReplayQualificationV2> =
        read_typed_json(dir, inventory, "replay-qualifications.json")?;
    if let Some(expected) = expected_run_id {
        ensure_identity("source-manifest.json.run_id", &source.run_id.0, expected)?;
    }
    ensure_identity(
        "source-manifest.json.run_id",
        &source.run_id.0,
        &run.run_id.0,
    )?;
    validate_source_manifest(&source, &repository, run.started_at, run.finished_at)?;
    let source_sha256 = canonical_sha256(&source).map_err(EvidenceError::Json)?;
    let config_sha256 = canonical_sha256(&config).map_err(EvidenceError::Json)?;

    let mut aggregate = BTreeMap::new();
    for qualification in &qualifications {
        if aggregate
            .insert(qualification.scenario_id.0.clone(), qualification)
            .is_some()
        {
            return Err(EvidenceError::DuplicateIdentity {
                kind: "replay qualification scenario".into(),
                id: qualification.scenario_id.0.clone(),
            });
        }
        ensure_identity(
            "replay-qualifications.json.run_id",
            &qualification.run_id.0,
            &run.run_id.0,
        )?;
        ensure_identity(
            "replay-qualifications.json.source_manifest_sha256",
            &qualification.source_manifest_sha256,
            &source_sha256,
        )?;
        ensure_identity(
            "replay-qualifications.json.config_sha256",
            &qualification.config_sha256,
            &config_sha256,
        )?;
    }

    let scenario_ids = scenario_ids_from_inventory(inventory)?;
    let mut scenario_qualifications = BTreeMap::new();
    for scenario_id in &scenario_ids {
        let prefix = format!("scenarios/{scenario_id}/");
        let nested = inventory
            .entries
            .iter()
            .find(|entry| entry.path == format!("{prefix}checksums.txt"))
            .ok_or_else(|| EvidenceError::Missing(format!("{prefix}checksums.txt")))?;
        let _ = nested;
        let scenario_dir = dir.join("scenarios").join(scenario_id);
        let nested_inventory = read_inventory(&scenario_dir)?;
        if nested_inventory.version != INVENTORY_VERSION_V2
            || nested_inventory.kind != BundleKind::Scenario
        {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("scenarios/{scenario_id}/checksums.txt"),
                detail: "a v2 run requires a v2 scenario inventory".into(),
            });
        }
        let manifest: ExactReplayManifestV2 = read_typed_json(
            dir,
            inventory,
            &format!("scenarios/{scenario_id}/replay-manifest-v2.json"),
        )?;
        ensure_identity(
            &format!("scenarios/{scenario_id}/source_manifest_sha256"),
            &manifest.source_manifest_sha256,
            &source_sha256,
        )?;
        ensure_identity(
            &format!("scenarios/{scenario_id}/config_sha256"),
            &manifest.config_sha256,
            &config_sha256,
        )?;
        let qualification_path = format!("scenarios/{scenario_id}/replay-qualification.json");
        if inventory_has(inventory, &qualification_path) {
            let qualification: ReplayQualificationV2 =
                read_typed_json(dir, inventory, &qualification_path)?;
            scenario_qualifications.insert(scenario_id.clone(), qualification);
        }
    }
    if aggregate.len() != scenario_qualifications.len() {
        return Err(EvidenceError::IdentityMismatch {
            field: "replay-qualifications.json".into(),
            detail: "aggregate count differs from scenario qualification files".into(),
        });
    }
    for (scenario_id, qualification) in &scenario_qualifications {
        let root_record =
            aggregate
                .get(scenario_id)
                .ok_or_else(|| EvidenceError::IdentityMismatch {
                    field: "replay-qualifications.json".into(),
                    detail: format!("missing scenario qualification {scenario_id}"),
                })?;
        ensure_semantic_equality(
            &format!("scenarios/{scenario_id}/replay-qualification.json"),
            qualification,
            "replay-qualifications.json entry",
            *root_record,
        )?;
    }

    let verdict_by_id: BTreeMap<_, _> = verdicts
        .iter()
        .map(|verdict| (verdict.scenario_id.0.as_str(), verdict))
        .collect();
    for (scenario_id, verdict) in verdict_by_id {
        if verdict.verdict == Verdict::FutureFail && !aggregate.contains_key(scenario_id) {
            return Err(EvidenceError::Missing(format!(
                "FUTURE_FAIL {scenario_id} has no two-replay qualification evidence"
            )));
        }
    }
    if frontier.observed {
        let scenario_id = frontier
            .scenario_id
            .as_ref()
            .ok_or_else(|| EvidenceError::Missing("observed frontier scenario id".into()))?;
        let qualification = aggregate.get(&scenario_id.0).ok_or_else(|| {
            EvidenceError::Missing(format!(
                "observed frontier {} has no replay qualification",
                scenario_id.0
            ))
        })?;
        let scenario_dir = dir.join("scenarios").join(&scenario_id.0);
        let scenario_inventory = read_inventory(&scenario_dir)?;
        let manifest: ExactReplayManifestV2 = read_typed_json(
            &scenario_dir,
            &scenario_inventory,
            "replay-manifest-v2.json",
        )?;
        let (originals, replays) = load_attempts(&scenario_dir, &scenario_inventory, &manifest)?;
        let original = originals
            .last()
            .ok_or_else(|| EvidenceError::Missing("observed frontier original attempt".into()))?;
        if !qualification.qualified_against(original, &replays) {
            return Err(EvidenceError::InvalidSemantics {
                field: "frontier.json.observed".into(),
                detail: "observed frontier is not backed by two recomputed equivalent replays"
                    .into(),
            });
        }
    }
    Ok(())
}

fn validate_attempt_v2(
    attempt: &ExecutionAttemptV2,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<()> {
    require_v2("attempt.json.schema_version", attempt.schema_version)?;
    validate_single_component(&attempt.attempt_id, "attempt id")?;
    validate_single_component(&attempt.run_id.0, "attempt run id")?;
    validate_single_component(&attempt.scenario_id.0, "attempt scenario id")?;
    if let Some(expected) = expected_run_id {
        ensure_identity("attempt.json.run_id", &attempt.run_id.0, expected)?;
    }
    if let Some(expected) = expected_scenario_id {
        ensure_identity("attempt.json.scenario_id", &attempt.scenario_id.0, expected)?;
    }
    if attempt.ordinal == 0 || attempt.finished_at < attempt.started_at {
        return Err(EvidenceError::InvalidSemantics {
            field: "attempt.json ordinal/timestamps".into(),
            detail: "ordinal must be positive and finished_at must not precede started_at".into(),
        });
    }
    validate_digest(
        "attempt.json.source_manifest_sha256",
        &attempt.source_manifest_sha256,
    )?;
    validate_digest("attempt.json.config_sha256", &attempt.config_sha256)?;
    validate_digest(
        "attempt.json.replay_manifest_sha256",
        &attempt.replay_manifest_sha256,
    )?;
    validate_image_identity(
        "attempt.json.image",
        &attempt.image_ref,
        Some(&attempt.image_digest),
    )?;
    validate_engine(&attempt.engine)?;
    validate_exact_environment(&attempt.environment)?;
    validate_replay_commands(&attempt.commands)?;
    require_v2(
        "attempt.json.result.schema_version",
        attempt.result.schema_version,
    )?;
    if let Some(signature) = &attempt.failure_signature {
        require_v2(
            "attempt.json.failure_signature.schema_version",
            signature.schema_version,
        )?;
        validate_failure_signature_v2(signature)?;
    }
    Ok(())
}

fn validate_attempt_outcome(attempt: &ExecutionAttemptV2) -> Result<()> {
    let result = &attempt.result;
    let passed = result.exit_code == Some(0)
        && result.signal.is_none()
        && !result.timed_out
        && result.blocked_reason.is_none();
    match result.outcome_class {
        AttemptOutcomeClassV2::Passed if passed && attempt.failure_signature.is_none() => Ok(()),
        AttemptOutcomeClassV2::Failed
            if !passed
                && result.blocked_reason.is_none()
                && attempt.failure_signature.is_some() =>
        {
            Ok(())
        }
        AttemptOutcomeClassV2::Blocked
            if result
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty())
                && attempt.failure_signature.is_none() =>
        {
            Ok(())
        }
        _ => Err(EvidenceError::InvalidSemantics {
            field: "attempt.json.result.outcome_class".into(),
            detail: "outcome class, exit/signal/timeout/block reason, and signature disagree"
                .into(),
        }),
    }
}

fn validate_exact_manifest(
    manifest: &ExactReplayManifestV2,
    scenario: &Scenario,
    environment: &EnvironmentSpec,
    commands: &[CommandSpec],
) -> Result<()> {
    require_v2(
        "replay-manifest-v2.json.schema_version",
        manifest.schema_version,
    )?;
    ensure_identity(
        "replay-manifest-v2.json.scenario_id",
        &manifest.scenario_id.0,
        &scenario.id.0,
    )?;
    if manifest.scenario_kind != scenario.kind {
        return Err(EvidenceError::IdentityMismatch {
            field: "replay-manifest-v2.json.scenario_kind".into(),
            detail: "does not match scenario.json".into(),
        });
    }
    validate_digest(
        "replay-manifest-v2.json.source_manifest_sha256",
        &manifest.source_manifest_sha256,
    )?;
    validate_digest(
        "replay-manifest-v2.json.config_sha256",
        &manifest.config_sha256,
    )?;
    validate_digest(
        "replay-manifest-v2.json.scenario_sha256",
        &manifest.scenario_sha256,
    )?;
    ensure_identity(
        "replay-manifest-v2.json.scenario_sha256",
        &manifest.scenario_sha256,
        &canonical_sha256(scenario).map_err(EvidenceError::Json)?,
    )?;
    validate_image_identity(
        "replay-manifest-v2.json.image",
        &manifest.image_ref,
        Some(&manifest.image_digest),
    )?;
    ensure_identity(
        "replay-manifest-v2.json.image_ref",
        &manifest.image_ref,
        &environment.image_ref,
    )?;
    ensure_optional_identity(
        "replay-manifest-v2.json.image_digest",
        Some(&manifest.image_digest),
        environment.image_digest.as_deref(),
    )?;
    validate_engine(&manifest.engine)?;
    validate_exact_environment(&manifest.environment)?;
    validate_replay_commands(&manifest.commands)?;
    ensure_exact_environment_matches(&manifest.environment, environment)?;
    ensure_commands_match(&manifest.commands, commands)?;
    Ok(())
}

fn load_attempts(
    scenario_dir: &Path,
    inventory: &BundleInventory,
    manifest: &ExactReplayManifestV2,
) -> Result<(Vec<ExecutionAttemptV2>, Vec<ExecutionAttemptV2>)> {
    let mut dirs = BTreeSet::new();
    for entry in &inventory.entries {
        let parts: Vec<_> = entry.path.split('/').collect();
        if parts.len() >= 3
            && matches!(parts[0], "attempts" | "replays")
            && parts[1].starts_with("attempt-")
        {
            dirs.insert((parts[0].to_string(), parts[1].to_string()));
        }
    }
    let manifest_sha = canonical_sha256(manifest).map_err(EvidenceError::Json)?;
    let mut originals = Vec::new();
    let mut replays = Vec::new();
    for (group, name) in dirs {
        let attempt_dir = scenario_dir.join(&group).join(&name);
        let verified = verify_bundle_internal(
            &attempt_dir,
            Some(&manifest.run_id.0),
            Some(&manifest.scenario_id.0),
        )?;
        if verified.version != INVENTORY_VERSION_V2 || verified.kind != BundleKind::ReplayAttempt {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("{group}/{name}/checksums.txt"),
                detail: "expected a v2 replay-attempt bundle".into(),
            });
        }
        let attempt: ExecutionAttemptV2 = verified.read_json("attempt.json")?;
        ensure_identity(
            &format!("{group}/{name}/attempt.json.replay_manifest_sha256"),
            &attempt.replay_manifest_sha256,
            &manifest_sha,
        )?;
        let expected_group = match attempt.kind {
            AttemptKindV2::Original => "attempts",
            AttemptKindV2::Replay => "replays",
        };
        ensure_identity("attempt directory group", &group, expected_group)?;
        ensure_identity(
            "attempt directory name",
            &name,
            &format!("attempt-{:06}", attempt.ordinal),
        )?;
        match attempt.kind {
            AttemptKindV2::Original => originals.push(attempt),
            AttemptKindV2::Replay => replays.push(attempt),
        }
    }
    originals.sort_by_key(|attempt| attempt.ordinal);
    replays.sort_by_key(|attempt| attempt.ordinal);
    Ok((originals, replays))
}

fn require_consecutive_attempts(
    attempts: &[ExecutionAttemptV2],
    kind: AttemptKindV2,
) -> Result<()> {
    let mut ids = BTreeSet::new();
    for (index, attempt) in attempts.iter().enumerate() {
        if attempt.kind != kind || attempt.ordinal != index as u32 + 1 {
            return Err(EvidenceError::InvalidSemantics {
                field: "attempt ordinals".into(),
                detail: format!("{kind:?} attempts must be consecutive from 1"),
            });
        }
        if !ids.insert(attempt.attempt_id.clone()) {
            return Err(EvidenceError::DuplicateIdentity {
                kind: "attempt".into(),
                id: attempt.attempt_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_source_manifest(
    source: &SourceSnapshotManifestV2,
    repository: &RepositorySnapshot,
    run_started: DateTime<Utc>,
    run_finished: Option<DateTime<Utc>>,
) -> Result<()> {
    require_v2("source-manifest.json.schema_version", source.schema_version)?;
    ensure_identity(
        "source-manifest.json.repository_source",
        &source.repository_source,
        &repository.source,
    )?;
    ensure_semantic_equality(
        "source-manifest.json.commit_sha",
        &source.commit_sha,
        "repository.json.commit_sha",
        &repository.commit_sha,
    )?;
    if source.captured_at < run_started
        || run_finished.is_some_and(|finished| source.captured_at > finished)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "source-manifest.json.captured_at".into(),
            detail: "source capture must occur within the recorded run interval".into(),
        });
    }
    match source.identity_kind {
        SourceIdentityKindV2::GitCommit if !source.dirty && source.commit_sha.is_some() => {}
        SourceIdentityKindV2::DirtyWorktree if source.dirty => {}
        SourceIdentityKindV2::NonGit if !source.dirty && source.commit_sha.is_none() => {}
        _ => {
            return Err(EvidenceError::InvalidSemantics {
                field: "source-manifest.json.identity_kind".into(),
                detail: "identity kind, dirty flag, and commit SHA disagree".into(),
            })
        }
    }
    if let Some(commit) = &source.commit_sha {
        if !matches!(commit.len(), 40 | 64)
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "source-manifest.json.commit_sha".into(),
                detail: "commit SHA must be 40 or 64 lowercase hexadecimal characters".into(),
            });
        }
    }
    let mut prior: Option<&str> = None;
    let mut portable = BTreeSet::new();
    for file in &source.files {
        require_v2(
            "source-manifest.json.files[].schema_version",
            file.schema_version,
        )?;
        validate_inventory_path(&file.path)?;
        validate_digest("source-manifest.json.files[].sha256", &file.sha256)?;
        if prior.is_some_and(|previous| previous >= file.path.as_str())
            || !portable.insert(file.path.to_lowercase())
        {
            return Err(EvidenceError::DuplicatePath(file.path.clone()));
        }
        prior = Some(&file.path);
    }
    ensure_identity(
        "source-manifest.json.tree_sha256",
        &source.tree_sha256,
        &canonical_sha256(&source.files).map_err(EvidenceError::Json)?,
    )?;
    let expected_source_id = match (&source.identity_kind, &source.commit_sha) {
        (SourceIdentityKindV2::GitCommit, Some(commit)) => {
            format!("git:{commit}:{}", source.tree_sha256)
        }
        (SourceIdentityKindV2::DirtyWorktree, Some(commit)) => {
            format!("dirty-git:{commit}:{}", source.tree_sha256)
        }
        (SourceIdentityKindV2::DirtyWorktree, None) => {
            format!("dirty:{}", source.tree_sha256)
        }
        (SourceIdentityKindV2::NonGit, _) => format!("tree:{}", source.tree_sha256),
        _ => unreachable!("invalid combinations returned above"),
    };
    ensure_identity(
        "source-manifest.json.source_id",
        &source.source_id,
        &expected_source_id,
    )?;
    Ok(())
}

fn validate_engine(engine: &tomorrowci_core::EngineIdentityV2) -> Result<()> {
    require_v2("engine.schema_version", engine.schema_version)?;
    for (field, value) in [
        ("engine.name", engine.name.as_str()),
        ("engine.client_version", engine.client_version.as_str()),
        ("engine.os", engine.os.as_str()),
        ("engine.arch", engine.arch.as_str()),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(EvidenceError::InvalidSemantics {
                field: field.into(),
                detail: "must be non-empty and control-free".into(),
            });
        }
    }
    Ok(())
}

fn validate_exact_environment(environment: &tomorrowci_core::ExactEnvironmentV2) -> Result<()> {
    require_v2("environment.schema_version", environment.schema_version)?;
    if environment.workdir.trim().is_empty()
        || environment.timeout_seconds == 0
        || environment.memory_mb == 0
        || environment.cpu_millis == 0
        || environment.pids_limit == 0
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "exact environment".into(),
            detail: "workdir and resource limits must be non-zero".into(),
        });
    }
    for mount in &environment.mounts {
        require_v2("environment.mounts[].schema_version", mount.schema_version)?;
        if mount.source != "workspace"
            || mount.container_path.trim().is_empty()
            || mount.container_path.chars().any(char::is_control)
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "environment.mounts".into(),
                detail: "v2 only permits the logical workspace source and safe container paths"
                    .into(),
            });
        }
    }
    Ok(())
}

fn validate_replay_commands(commands: &[ReplayCommandV2]) -> Result<()> {
    if commands.is_empty() {
        return Err(EvidenceError::InvalidSemantics {
            field: "commands".into(),
            detail: "exact replay requires at least one command".into(),
        });
    }
    for command in commands {
        require_v2("commands[].schema_version", command.schema_version)?;
        if command.program.trim().is_empty()
            || command.program.chars().any(char::is_control)
            || command.workdir.chars().any(char::is_control)
            || command
                .args
                .iter()
                .any(|argument| argument.chars().any(char::is_control))
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "commands".into(),
                detail: "program/workdir/arguments must be non-empty and control-free".into(),
            });
        }
    }
    Ok(())
}

fn ensure_exact_environment_matches(
    exact: &tomorrowci_core::ExactEnvironmentV2,
    environment: &EnvironmentSpec,
) -> Result<()> {
    let env: BTreeMap<_, _> = environment
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mounts: Vec<_> = environment
        .mounts
        .iter()
        .map(|mount| (mount.container_path.as_str(), mount.read_only))
        .collect();
    let exact_mounts: Vec<_> = exact
        .mounts
        .iter()
        .map(|mount| (mount.container_path.as_str(), mount.read_only))
        .collect();
    let cpu_millis = (environment.cpus * 1000.0).round() as u32;
    if exact.workdir != environment.workdir
        || exact.user != environment.user
        || exact.env != env
        || exact_mounts != mounts
        || exact.network_mode != environment.network_mode
        || exact.read_only_root != environment.read_only_root
        || exact.memory_mb != environment.memory_mb
        || exact.cpu_millis != cpu_millis
        || exact.pids_limit != environment.pids_limit
        || exact.timeout_seconds != environment.timeout_seconds
    {
        return Err(EvidenceError::IdentityMismatch {
            field: "replay-manifest-v2.json.environment".into(),
            detail: "does not match environment.json".into(),
        });
    }
    Ok(())
}

fn ensure_commands_match(exact: &[ReplayCommandV2], commands: &[CommandSpec]) -> Result<()> {
    if exact.len() != commands.len() {
        return Err(EvidenceError::IdentityMismatch {
            field: "replay-manifest-v2.json.commands".into(),
            detail: "command count differs from commands.json".into(),
        });
    }
    for (left, right) in exact.iter().zip(commands) {
        let env: BTreeMap<_, _> = right
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if left.phase != right.phase
            || left.program != right.program
            || left.args != right.args
            || left.workdir != right.workdir
            || left.network_required != right.network_required
            || left.env != env
        {
            return Err(EvidenceError::IdentityMismatch {
                field: "replay-manifest-v2.json.commands".into(),
                detail: "does not match commands.json".into(),
            });
        }
    }
    Ok(())
}

fn validate_failure_signature_v2(signature: &NormalizedFailureSignatureV2) -> Result<()> {
    let expected = FailureSignature::compute_fingerprint(
        &signature.kind,
        signature.primary_error.as_deref().unwrap_or_default(),
        &signature.summary,
    );
    ensure_identity(
        "failure signature fingerprint",
        &signature.fingerprint,
        &expected,
    )
}

fn validate_digest(field: &str, digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(EvidenceError::InvalidSemantics {
            field: field.into(),
            detail: "must use sha256:<64 lowercase hex>".into(),
        });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceError::InvalidSemantics {
            field: field.into(),
            detail: "must use sha256:<64 lowercase hex>".into(),
        });
    }
    Ok(())
}

fn require_v2(field: &str, version: u32) -> Result<()> {
    if version == REPLAY_SCHEMA_VERSION_V2 {
        Ok(())
    } else {
        Err(EvidenceError::InvalidSemantics {
            field: field.into(),
            detail: format!("expected schema version 2, found {version}"),
        })
    }
}

fn read_inventory_bytes(
    dir: &Path,
    inventory: &BundleInventory,
    relative: &str,
) -> Result<Vec<u8>> {
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.path == relative)
        .ok_or_else(|| EvidenceError::Missing(relative.into()))?;
    read_verified_bytes(dir, entry)
}
