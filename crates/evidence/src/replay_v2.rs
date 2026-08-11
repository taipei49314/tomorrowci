use super::*;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use tomorrowci_core::{
    canonical_sha256, AttemptKindV2, AttemptOutcomeClassV2, ExactReplayManifestV2,
    ExecutionAttemptResultV2, ExecutionAttemptV2, NormalizedFailureSignatureV2, ReplayCommandV2,
    ReplayQualificationV2, RunId, SourceFileEntryV2, SourceIdentityKindV2,
    SourceSnapshotManifestV2, REPLAY_SCHEMA_VERSION_V2,
};

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
    seal_bundle_version(dir, BundleKind::ReplayAttempt, INVENTORY_VERSION_V2)?;
    Ok(())
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
    Ok(())
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
