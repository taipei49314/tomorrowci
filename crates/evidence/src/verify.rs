//! Evidence integrity verification.

use crate::{
    file_checksum, metadata_is_alias, safe_join, validate_existing_ancestors, validate_identifier,
    validate_manifest_path, validate_sha256, write_checksums, CHECKSUM_FORMAT_V2,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tomorrowci_core::{
    adaptive_dependency_probe_id, canonical_image_digest_value, canonical_json_hash,
    classify_candidate_attempts, compute_breakage_frontier, dependency_fetch_network,
    dependency_materialization_commands, next_dependency_subset, plan_scenarios, sha256_bytes,
    sha256_file_v1, sha256_tree_v1, synthetic_git_blob_sha1, synthetic_git_index_v1,
    validate_image_digest, BreakageFrontier, Candidate, CommandSpec, Config, ContentHash,
    DependencyAdditionCheck, DependencyCandidateSet, DependencyChange,
    DependencyExperimentManifest, DependencyMinimalityCheck, DependencyProbeEvidence,
    DependencyProbeRecord, DependencyProbeVerdict, DependencyReduction, DependencyReductionStatus,
    DependencyScheduleObservation, Ecosystem, EnvironmentAxis, EnvironmentSpec, EvidenceGrade,
    ExecutionPlan, ExecutionResult, FailureSignature, PlanDecision, RemoteSourceRecord,
    RepositorySnapshot, ResolvedDependencySet, Result, RunManifest, Scenario,
    SyntheticGitIndexEntry, SyntheticGitIndexRecord, TcError, TestAttemptsSummary,
    TestExecutionStatus, Verdict, WorkspaceIsolation, WorkspacePreparation, SYNTHETIC_GIT_ENV,
    SYNTHETIC_GIT_INDEX_KIND, SYNTHETIC_GIT_INDEX_SOURCE,
};

pub const RUN_REQUIRED: &[&str] = &[
    "run.json",
    "repository.json",
    "config.normalized.json",
    "candidates.json",
    "plan.json",
    "plan-decisions.json",
    "verdicts.json",
    "frontier.json",
    "metrics.json",
    "claims.json",
    "report.json",
    "report.html",
    "job-summary.md",
    "summary.txt",
    "workspace-manifest.json",
    "checksums.txt",
];

pub const SCENARIO_REQUIRED: &[&str] = &[
    "scenario.json",
    "environment.json",
    "fetch-commands.json",
    "test-commands.json",
    "result.json",
    "stdout.log",
    "stderr.log",
    "replay.json",
    "replay.sh",
    "replay.ps1",
    "checksums.txt",
];

const RUN_OPTIONAL: &[&str] = &[
    "dependency-experiment.json",
    "reduction.json",
    "remote-source.json",
    "report.sarif.json",
];
const SCENARIO_OPTIONAL: &[&str] = &[
    "commands.json",
    "resolved-dependencies.json",
    "test-attempts.json",
    "image-resolve-phase.json",
    "fetch-phase.json",
    "test-phase.json",
    "fetch-result.json",
    "test-result.json",
    "failure-signature.json",
    "fetch-stdout.log",
    "fetch-stderr.log",
    "replay-result.json",
];
const REPLAY_REQUIRED: &[&str] = &["result.json", "stdout.log", "stderr.log"];
const LEGACY_TOOL_VERSION: &str = "0.1.1-alpha.2";

// v0.1.1-alpha.2 wrote these files but omitted them from checksum inventories.
// Headerless v1 manifests remain readable only for these exact omissions. Unknown
// or newly added files are rejected in both formats.
const LEGACY_RUN_UNLISTED: &[&str] = &["reduction.json"];
const LEGACY_SCENARIO_UNLISTED: &[&str] = &["commands.json", "image-resolve-phase.json"];

const WORKSPACE_IGNORED: &[&str] = &[
    ".tomorrowci",
    "target",
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumCompatibility {
    CurrentV2,
    LegacyV1ReadCompatible,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub run_id: String,
    pub errors: Vec<String>,
    pub checked_files: usize,
    #[serde(default)]
    pub checksum_compatibility: ChecksumCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub files: BTreeMap<String, WorkspaceFileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceFileMeta {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseEvidence {
    phase: String,
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network: String,
    image: String,
    image_digest: Option<String>,
    argv: Vec<Vec<String>>,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResultSummary {
    #[serde(default)]
    workspace_preparation: Option<WorkspacePreparation>,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network_used: bool,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayDescriptor {
    #[serde(default)]
    workspace_isolation: Option<WorkspaceIsolation>,
    scenario_id: String,
    engine: Option<String>,
    engine_version: Option<String>,
    image: String,
    image_digest: Option<String>,
    workdir: String,
    user: Option<String>,
    memory_mb: u32,
    cpus: f32,
    pids_limit: u32,
    read_only_root: bool,
    fetch_network: String,
    test_network: String,
    fetch_timeout_seconds: Option<u64>,
    test_timeout_seconds: Option<u64>,
    fetch_argv: Vec<Vec<String>>,
    test_argv: Vec<Vec<String>>,
    expected_exit_code: Option<i32>,
    expected_timed_out: bool,
    expected_failure_signature: Option<FailureSignature>,
    #[serde(default)]
    resolved_dependencies: Option<ResolvedDependencySet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReplayAttemptEvidence {
    #[serde(default)]
    workspace_preparation: Option<WorkspacePreparation>,
    scenario_id: String,
    attempt: usize,
    phase: String,
    ok: bool,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    original_exit: Option<i32>,
    fetch_exit: Option<i32>,
    replay_exit: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    original_signature: Option<String>,
    replay_signature: Option<String>,
    exit_match: Option<bool>,
    signature_match: Option<bool>,
    recorded_digest: String,
    resolved_digest: String,
    engine: String,
    engine_version: String,
    image_tag: String,
    fetch_timeout_seconds: u64,
    test_timeout_seconds: u64,
    #[serde(default)]
    dependency_manifest_sha256: Option<tomorrowci_core::ContentHash>,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SemanticClaimStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SemanticClaimRow {
    claim: String,
    status: SemanticClaimStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SemanticClaimLedger {
    rows: Vec<SemanticClaimRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SemanticMetrics {
    run_id: String,
    scenarios_total: u32,
    scenarios_pass: u32,
    scenarios_fail: u32,
    scenarios_flaky: u32,
    scenarios_blocked: u32,
    scenarios_unsupported: u32,
    scenarios_inconclusive: u32,
    baseline_ok: bool,
    frontier_observed: bool,
    total_duration_ms: u64,
    verdict_histogram: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChecksumFormat {
    CurrentV2,
    LegacyV1,
}

impl From<ChecksumFormat> for ChecksumCompatibility {
    fn from(value: ChecksumFormat) -> Self {
        match value {
            ChecksumFormat::CurrentV2 => Self::CurrentV2,
            ChecksumFormat::LegacyV1 => Self::LegacyV1ReadCompatible,
        }
    }
}

#[derive(Debug)]
struct ChecksumManifest {
    format: ChecksumFormat,
    entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
enum InventoryScope {
    Run,
    Scenario,
}

pub fn write_workspace_manifest(work: &Path, out: &Path) -> Result<WorkspaceManifest> {
    ensure_directory_no_alias(work)?;
    validate_existing_ancestors(out)?;
    if let Ok(metadata) = std::fs::symlink_metadata(out) {
        if metadata_is_alias(&metadata) || !metadata.is_file() {
            return Err(TcError::InvalidState(format!(
                "refusing unsafe workspace-manifest output path: {}",
                out.display()
            )));
        }
    }
    let mut files = BTreeMap::new();
    walk_workspace(work, work, &mut files)?;
    let manifest = WorkspaceManifest { files };
    std::fs::write(out, serde_json::to_string_pretty(&manifest)?)?;
    validate_existing_ancestors(out)?;
    Ok(manifest)
}

fn walk_workspace(
    root: &Path,
    current: &Path,
    output: &mut BTreeMap<String, WorkspaceFileMeta>,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let name = utf8_file_name(&entry)?;
        let metadata = safe_metadata(&path)?;
        if WORKSPACE_IGNORED.contains(&name.as_str()) {
            continue;
        }

        if metadata.is_dir() {
            walk_workspace(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = relative_path(root, &path)?;
            validate_manifest_path(&relative).map_err(TcError::InvalidState)?;
            let data = std::fs::read(&path)?;
            let previous = output.insert(
                relative.clone(),
                WorkspaceFileMeta {
                    size: data.len() as u64,
                    sha256: sha256_bytes(&data),
                },
            );
            if previous.is_some() {
                return Err(TcError::InvalidState(format!(
                    "duplicate workspace path: {relative}"
                )));
            }
        } else {
            return Err(TcError::InvalidState(format!(
                "unsupported workspace filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Recompute versioned, exact inventories after every evidence writer has finished.
pub fn finalize_run_checksums(run_root: &Path) -> Result<()> {
    ensure_directory_no_alias(run_root)?;

    let scenarios_root = safe_join(run_root, "scenarios")?;
    if scenarios_root.exists() {
        ensure_directory_no_alias(&scenarios_root)?;
        let mut scenarios = Vec::new();
        for entry in std::fs::read_dir(&scenarios_root)? {
            let entry = entry?;
            let path = entry.path();
            let name = utf8_file_name(&entry)?;
            validate_single_component(&name)?;
            let metadata = safe_metadata(&path)?;
            if !metadata.is_dir() {
                return Err(TcError::InvalidState(format!(
                    "scenario entry is not a directory: {}",
                    path.display()
                )));
            }
            scenarios.push(path);
        }
        scenarios.sort();
        for scenario in scenarios {
            finalize_scenario_checksums(&scenario)?;
        }
    }

    let inventory = collect_inventory(run_root, InventoryScope::Run)?;
    require_current_inventory(InventoryScope::Run, &inventory)?;
    let mut pairs = Vec::with_capacity(inventory.len());
    for relative in inventory {
        let path = safe_join(run_root, &relative)?;
        pairs.push((relative.clone(), file_checksum(&path)?));
    }
    write_checksums(run_root, &pairs)
}

fn finalize_scenario_checksums(scenario_root: &Path) -> Result<()> {
    let inventory = collect_inventory(scenario_root, InventoryScope::Scenario)?;
    require_current_inventory(InventoryScope::Scenario, &inventory)?;
    let mut pairs = Vec::with_capacity(inventory.len());
    for relative in inventory {
        let path = safe_join(scenario_root, &relative)?;
        pairs.push((relative.clone(), file_checksum(&path)?));
    }
    write_checksums(scenario_root, &pairs)
}

fn require_current_inventory(scope: InventoryScope, inventory: &BTreeSet<String>) -> Result<()> {
    let required: Vec<&str> = match scope {
        InventoryScope::Run => RUN_REQUIRED
            .iter()
            .copied()
            .filter(|name| *name != "checksums.txt")
            .collect(),
        InventoryScope::Scenario => SCENARIO_REQUIRED
            .iter()
            .copied()
            .filter(|name| *name != "checksums.txt")
            .chain([
                "commands.json",
                "test-attempts.json",
                "image-resolve-phase.json",
            ])
            .collect(),
    };
    for relative in required {
        if !inventory.contains(relative) {
            return Err(TcError::InvalidState(format!(
                "cannot finalize current-v2 {} inventory without required file: {relative}",
                scope_name(scope)
            )));
        }
    }
    Ok(())
}

pub fn verify_run(repo: &Path, run_id: &str) -> Result<VerifyReport> {
    validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
    let run_root = safe_join(repo, &format!(".tomorrowci/runs/{run_id}"))?;
    if !run_root.exists() {
        return Err(TcError::Blocked(format!(
            "run directory missing: {}",
            run_root.display()
        )));
    }
    verify_run_root(&run_root)
}

pub fn verify_run_root(run_root: &Path) -> Result<VerifyReport> {
    let mut errors = Vec::new();
    let mut checked = 0usize;
    let run_id = run_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    if let Err(error) = validate_identifier(&run_id, "run_id") {
        errors.push(error);
    }

    match ensure_directory_no_alias(run_root) {
        Ok(()) => {}
        Err(error) => errors.push(error.to_string()),
    }
    if !errors.is_empty() {
        return Ok(VerifyReport {
            ok: false,
            run_id,
            errors,
            checked_files: checked,
            checksum_compatibility: ChecksumCompatibility::Unknown,
        });
    }

    for name in RUN_REQUIRED {
        let path = safe_join(run_root, name)?;
        require_regular_file(&path, &format!("required run file {name}"), &mut errors)?;
    }

    let run_manifest = read_run_manifest_for_verification(run_root, &mut errors)?;
    let legacy_eligible = run_manifest.as_ref().is_some_and(legacy_schema_eligible);
    let root_checksums = parse_checksum_manifest(
        &safe_join(run_root, "checksums.txt")?,
        "run checksums",
        &mut errors,
    )?;
    let root_format = root_checksums.as_ref().map(|manifest| manifest.format);
    if let Some(manifest) = &root_checksums {
        if manifest.format == ChecksumFormat::LegacyV1 && !legacy_eligible {
            errors.push(format!(
                "legacy-v1 checksum format is not permitted for tool/schema; only {LEGACY_TOOL_VERSION} evidence is read-compatible"
            ));
        }
        verify_checksum_inventory(
            run_root,
            InventoryScope::Run,
            manifest,
            &mut errors,
            &mut checked,
        )?;
    }

    let current_v2 = root_format == Some(ChecksumFormat::CurrentV2)
        && run_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.evidence_schema_version == 2);
    if root_format == Some(ChecksumFormat::CurrentV2) {
        match run_manifest
            .as_ref()
            .map(|manifest| manifest.evidence_schema_version)
        {
            Some(2) => {}
            Some(0) => errors.push(
                "current checksum bundle is pre-schema evidence; migration to evidence_schema_version=2 is required"
                    .into(),
            ),
            Some(version) => errors.push(format!(
                "unsupported evidence_schema_version {version}; supported strict schema is 2"
            )),
            None => {}
        }
    }
    verify_workspace(run_root, current_v2, &mut errors, &mut checked)?;
    if let Some(manifest) = &run_manifest {
        verify_identity(run_root, manifest, &run_id, current_v2, &mut errors)?;
    }
    verify_scenarios(run_root, root_format, &mut errors, &mut checked)?;
    if let Some(manifest) = &run_manifest {
        verify_cross_file_closure(run_root, manifest, current_v2, &mut errors)?;
    }

    Ok(VerifyReport {
        ok: errors.is_empty(),
        run_id,
        errors,
        checked_files: checked,
        checksum_compatibility: root_format
            .map(ChecksumCompatibility::from)
            .unwrap_or_default(),
    })
}

fn read_run_manifest_for_verification(
    run_root: &Path,
    errors: &mut Vec<String>,
) -> Result<Option<RunManifest>> {
    let run_path = safe_join(run_root, "run.json")?;
    if regular_file_metadata(&run_path, "run.json", errors)?.is_none() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&run_path)?;
    match serde_json::from_str(&raw) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => {
            errors.push(format!("run.json is malformed: {error}"));
            Ok(None)
        }
    }
}

fn legacy_schema_eligible(manifest: &RunManifest) -> bool {
    manifest.evidence_schema_version == 0
        && manifest.tool_version == LEGACY_TOOL_VERSION
        && !manifest
            .identity
            .as_ref()
            .is_some_and(|identity| identity.tool_version != LEGACY_TOOL_VERSION)
}

fn verify_workspace(
    run_root: &Path,
    current_v2: bool,
    errors: &mut Vec<String>,
    checked: &mut usize,
) -> Result<()> {
    let manifest_path = safe_join(run_root, "workspace-manifest.json")?;
    if !manifest_path.exists() {
        return Ok(());
    }
    if regular_file_metadata(&manifest_path, "workspace-manifest", errors)?.is_none() {
        return Ok(());
    }
    let manifest: WorkspaceManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let workspace = safe_join(run_root, "workspace")?;
    match ensure_directory_no_alias(&workspace) {
        Ok(()) => {}
        Err(error) => {
            errors.push(error.to_string());
            return Ok(());
        }
    }

    let actual = match collect_workspace_inventory(&workspace) {
        Ok(actual) => actual,
        Err(error) => {
            errors.push(error.to_string());
            BTreeSet::new()
        }
    };
    let mut listed = BTreeSet::new();

    for (relative, expected) in &manifest.files {
        if let Err(error) = validate_manifest_path(relative) {
            errors.push(format!(
                "invalid workspace-manifest path {relative:?}: {error}"
            ));
            continue;
        }
        if !listed.insert(relative.clone()) {
            errors.push(format!("duplicate workspace-manifest path: {relative}"));
            continue;
        }

        let path = safe_join(&workspace, relative)?;
        let metadata = match regular_file_metadata(&path, "workspace-manifest", errors)? {
            Some(metadata) => metadata,
            None => continue,
        };
        if metadata.len() != expected.size {
            errors.push(format!("workspace-manifest size mismatch: {relative}"));
        }

        let expected_hash = if current_v2 {
            crate::validate_sha256(&expected.sha256)
                .ok()
                .map(|()| expected.sha256.clone())
        } else {
            normalize_workspace_hash(&expected.sha256)
        };
        match expected_hash {
            Some(expected_hash) => {
                let actual_hash = file_checksum(&path)?;
                if actual_hash != expected_hash {
                    errors.push(format!("workspace-manifest hash mismatch: {relative}"));
                } else {
                    *checked += 1;
                }
            }
            None => errors.push(format!(
                "workspace-manifest invalid sha256 for {relative}: {:?}",
                expected.sha256
            )),
        }
    }

    for relative in actual.difference(&listed) {
        errors.push(format!(
            "workspace contains unlisted source file: {relative}"
        ));
    }
    for relative in listed.difference(&actual) {
        errors.push(format!("workspace-manifest lists missing file: {relative}"));
    }
    Ok(())
}

fn verify_identity(
    run_root: &Path,
    manifest: &RunManifest,
    run_id: &str,
    current_v2: bool,
    errors: &mut Vec<String>,
) -> Result<()> {
    if let Err(error) = validate_identifier(&manifest.run_id, "run.json run_id") {
        errors.push(error);
    }
    if manifest.run_id != run_id {
        errors.push(format!(
            "run.json run_id {:?} does not match directory {run_id:?}",
            manifest.run_id
        ));
    }
    if current_v2 && manifest.identity.is_none() {
        errors.push("current-v2 run.json requires a non-null identity".into());
    }
    if manifest.finished_at.is_none() {
        errors.push("run.json finished_at must be present".into());
    }
    if let Some(finished) = manifest.finished_at {
        if finished < manifest.started_at {
            errors.push("run.json finished_at precedes started_at".into());
        }
    }

    if current_v2 && !is_valid_semver(&manifest.tool_version) {
        errors.push(format!(
            "current-v2 run tool_version is not valid SemVer: {:?}",
            manifest.tool_version
        ));
    }

    let config_path = safe_join(run_root, "config.normalized.json")?;
    if let Some(config) = read_json_file::<Config>(&config_path, "config.normalized.json", errors)?
    {
        if let Err(error) = config.validate() {
            errors.push(format!("config.normalized.json is invalid: {error}"));
        }
        match config.content_hash() {
            Ok(hash) if hash != manifest.config_hash => errors.push(format!(
                "config.normalized.json content_hash {hash} != run.json config_hash {}",
                manifest.config_hash
            )),
            Err(error) => errors.push(format!(
                "config.normalized.json content_hash could not be computed: {error}"
            )),
            _ => {}
        }
    }

    if let Some(identity) = &manifest.identity {
        if identity.source_commit != manifest.repository.commit_sha {
            errors.push("identity.source_commit != repository.commit_sha".into());
        }
        if identity.config_hash != manifest.config_hash {
            errors.push("identity.config_hash != manifest.config_hash".into());
        }
        if current_v2 {
            if identity.tool_version != manifest.tool_version {
                errors.push("identity.tool_version must equal run.tool_version".into());
            }
            let expected_adapter = match manifest.detection.ecosystem {
                Ecosystem::Python => Some("python"),
                Ecosystem::Node => Some("node"),
                Ecosystem::Rust => Some("rust"),
                Ecosystem::Unknown => None,
            };
            match expected_adapter {
                Some(expected) if identity.adapter_name != expected => errors.push(format!(
                    "identity.adapter_name {:?} does not match detected ecosystem adapter {expected:?}",
                    identity.adapter_name
                )),
                None => errors.push(
                    "current-v2 identity cannot claim a concrete adapter for unknown ecosystem"
                        .into(),
                ),
                _ => {}
            }
            if identity.adapter_version != manifest.tool_version {
                errors.push("identity.adapter_version does not equal writer tool version".into());
            }
            if identity.started_at != manifest.started_at
                || identity.finished_at != manifest.finished_at
            {
                errors.push("identity timestamps do not exactly match run timestamps".into());
            }
            if identity.dirty_tree.is_none() && manifest.repository.commit_sha.is_some() {
                errors.push(
                    "identity dirty_tree is unknown despite a claimed Git commit; source status was not established"
                        .into(),
                );
            }
            verify_manifest_hashes(run_root, manifest, identity, errors)?;
            for result in manifest.results.iter().filter(|result| result.attempt > 0) {
                if result.environment.engine != identity.container_engine
                    || result.environment.engine_version != identity.container_engine_version
                {
                    errors.push(format!(
                        "scenario {} engine identity does not match run identity",
                        result.scenario_id
                    ));
                }
            }
        }
    }

    if let Some(commit) = &manifest.repository.commit_sha {
        if !is_canonical_git_object_id(commit) {
            errors.push(format!(
                "repository commit_sha is not canonical: {commit:?}"
            ));
        }
    }
    if manifest.repository.source.trim().is_empty() {
        errors.push("repository source identity is empty".into());
    }
    if current_v2 && !manifest.repository.is_disposable_copy {
        errors.push("current-v2 execution evidence must use a disposable workspace copy".into());
    }
    for scenario in &manifest.plan.scenarios {
        if let Err(error) = validate_identifier(&scenario.id, "planned scenario_id") {
            errors.push(error);
        }
    }
    for result in &manifest.results {
        if let Err(error) = validate_identifier(&result.scenario_id, "result scenario_id") {
            errors.push(error);
        }
        let tag = result.environment.tag();
        if let Some(digest) = &result.environment.image_digest {
            if tag.contains("sha256:") {
                errors.push(format!(
                    "scenario {} image_tag must not be a digest",
                    result.scenario_id
                ));
            }
            if let Err(error) = validate_image_digest(digest) {
                errors.push(format!(
                    "scenario {} invalid image digest: {error}",
                    result.scenario_id
                ));
            }
        }
        if current_v2 && result.attempt > 0 {
            if result.environment.image_digest.is_none() {
                errors.push(format!(
                    "scenario {} executed without an immutable image digest",
                    result.scenario_id
                ));
            }
            if !matches!(
                result.environment.engine.as_deref(),
                Some("docker" | "podman")
            ) || result
                .environment
                .engine_version
                .as_deref()
                .is_none_or(str::is_empty)
            {
                errors.push(format!(
                    "scenario {} executed without exact engine name/version",
                    result.scenario_id
                ));
            }
        }
    }
    verify_remote_source_identity(run_root, manifest, current_v2, errors)?;
    Ok(())
}

fn verify_remote_source_identity(
    run_root: &Path,
    manifest: &RunManifest,
    current_v2: bool,
    errors: &mut Vec<String>,
) -> Result<()> {
    const REMOTE_CLONE_TIMEOUT_SECONDS: u64 = 120;
    const REMOTE_MAX_FILES: u64 = 10_000;
    const REMOTE_MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
    const REMOTE_MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
    const REMOTE_MAX_CLONE_DISK_BYTES: u64 = 256 * 1024 * 1024;
    let path = safe_join(run_root, "remote-source.json")?;
    if !path.exists() {
        return Ok(());
    }
    if !current_v2 {
        errors.push("remote-source.json is only valid in current-v2 evidence".into());
        return Ok(());
    }
    let Some(record) = read_json_file::<RemoteSourceRecord>(&path, "remote-source.json", errors)?
    else {
        return Ok(());
    };
    if !matches!(record.schema_version, 1 | 2) {
        errors.push(format!(
            "remote-source.json has unsupported schema_version {}",
            record.schema_version
        ));
    }
    if !canonical_github_repository_url(&record.requested_url) {
        errors
            .push("remote-source requested_url is not a canonical HTTPS GitHub repository".into());
    }
    if record.canonical_origin != format!("origin:{}", record.requested_url)
        || record.canonical_origin != manifest.repository.source
    {
        errors.push("remote-source canonical origin does not match repository identity".into());
    }
    if record.requested_commit != record.resolved_commit
        || manifest.repository.commit_sha.as_deref() != Some(record.resolved_commit.as_str())
        || manifest
            .identity
            .as_ref()
            .and_then(|identity| identity.source_commit.as_deref())
            != Some(record.resolved_commit.as_str())
        || !is_canonical_exact_github_commit(&record.resolved_commit)
    {
        errors.push("remote-source exact commit does not match run identity".into());
    }
    if !record.clean_tree
        || manifest
            .identity
            .as_ref()
            .and_then(|identity| identity.dirty_tree)
            != Some(false)
    {
        errors.push("remote-source evidence must bind a verified clean tree".into());
    }
    if record.moving_ref_allowed
        || record.redirects_allowed
        || record.credentials_allowed
        || record.submodules_allowed
        || record.lfs_allowed
    {
        errors.push(
            "remote-source evidence cannot authorize moving refs, redirects, credentials, submodules, or LFS"
                .into(),
        );
    }
    if record.clone_timeout_seconds != REMOTE_CLONE_TIMEOUT_SECONDS
        || record.max_files != REMOTE_MAX_FILES
        || record.max_file_bytes != REMOTE_MAX_FILE_BYTES
        || record.max_total_bytes != REMOTE_MAX_TOTAL_BYTES
        || record.max_clone_disk_bytes != REMOTE_MAX_CLONE_DISK_BYTES
        || record.snapshot_file_count > record.max_files
        || record.snapshot_total_bytes > record.max_total_bytes
    {
        errors.push("remote-source bounds are absent or exceeded".into());
    }

    let workspace_manifest_path = safe_join(run_root, "workspace-manifest.json")?;
    if crate::validate_sha256(&record.workspace_manifest_sha256).is_err()
        || file_checksum(&workspace_manifest_path)? != record.workspace_manifest_sha256
    {
        errors.push("remote-source workspace manifest digest mismatch".into());
    }
    if let Some(workspace) = read_json_file::<WorkspaceManifest>(
        &workspace_manifest_path,
        "workspace-manifest.json",
        errors,
    )? {
        let total = workspace
            .files
            .values()
            .try_fold(0_u64, |sum, file| sum.checked_add(file.size));
        if workspace.files.len() as u64 != record.snapshot_file_count
            || total != Some(record.snapshot_total_bytes)
            || workspace
                .files
                .values()
                .any(|file| file.size > record.max_file_bytes)
        {
            errors.push("remote-source snapshot bounds do not match workspace-manifest".into());
        }
        match (record.schema_version, &record.synthetic_git_index) {
            (1, None) => {}
            (1, Some(_)) => {
                errors.push("remote-source schema v1 cannot claim a synthetic Git index".into())
            }
            (2, Some(actual)) => {
                match derive_synthetic_git_index_record(
                    run_root,
                    &workspace,
                    &record.workspace_manifest_sha256,
                ) {
                    Ok(expected) if actual == &expected => {
                        let allowed_git_env: BTreeSet<&str> =
                            SYNTHETIC_GIT_ENV.iter().map(|(key, _)| *key).collect();
                        for result in &manifest.results {
                            if result.environment.workdir != "/work"
                                || SYNTHETIC_GIT_ENV.iter().any(|(key, value)| {
                                    result.environment.env.get(*key).map(String::as_str)
                                        != Some(*value)
                                })
                                || result.environment.env.keys().any(|key| {
                                    key.starts_with("GIT_")
                                        && !allowed_git_env.contains(key.as_str())
                                })
                            {
                                errors.push(format!(
                                    "scenario {} does not bind the synthetic Git environment",
                                    result.scenario_id
                                ));
                            }
                        }
                    }
                    Ok(_) => errors.push(
                        "remote-source synthetic Git index does not match workspace-manifest"
                            .into(),
                    ),
                    Err(error) => errors.push(format!(
                        "could not derive remote synthetic Git index: {error}"
                    )),
                }
            }
            (2, None) => errors
                .push("remote-source schema v2 requires a synthetic Git index contract".into()),
            _ => {}
        }
    }
    Ok(())
}

fn derive_synthetic_git_index_record(
    run_root: &Path,
    workspace: &WorkspaceManifest,
    workspace_manifest_sha256: &str,
) -> Result<SyntheticGitIndexRecord> {
    let workspace_root = safe_join(run_root, "workspace")?;
    let mut entries = Vec::with_capacity(workspace.files.len());
    for (relative, expected) in &workspace.files {
        let path = safe_join(&workspace_root, relative)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata_is_alias(&metadata) || !metadata.is_file() || metadata.len() != expected.size {
            return Err(TcError::InvalidState(format!(
                "synthetic Git workspace entry is not exact: {relative:?}"
            )));
        }
        let bytes = std::fs::read(&path)?;
        if sha256_bytes(&bytes) != expected.sha256 {
            return Err(TcError::InvalidState(format!(
                "synthetic Git workspace bytes changed: {relative:?}"
            )));
        }
        entries.push(SyntheticGitIndexEntry {
            path: relative.clone(),
            size: expected.size,
            blob_sha1: synthetic_git_blob_sha1(&bytes),
        });
    }
    let index = synthetic_git_index_v1(&entries)?;
    Ok(SyntheticGitIndexRecord {
        kind: SYNTHETIC_GIT_INDEX_KIND.into(),
        source: SYNTHETIC_GIT_INDEX_SOURCE.into(),
        workspace_manifest_sha256: workspace_manifest_sha256.into(),
        index_sha256: sha256_bytes(&index),
        entry_count: workspace.files.len() as u64,
        history_present: false,
        hooks_present: false,
        object_files_present: false,
        ref_files_present: false,
        remotes_present: false,
    })
}

fn canonical_github_repository_url(raw: &str) -> bool {
    if raw.len() > 256 {
        return false;
    }
    let Some(path) = raw.strip_prefix("https://github.com/") else {
        return false;
    };
    if raw.contains(['\r', '\n', '\0', '?', '#', '%', '@'])
        || path.contains(':')
        || path.ends_with('/')
        || path.ends_with(".git")
    {
        return false;
    }
    let parts: Vec<_> = path.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 100
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn is_canonical_exact_github_commit(raw: &str) -> bool {
    raw.len() == 40
        && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !raw.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn is_canonical_git_object_id(raw: &str) -> bool {
    matches!(raw.len(), 40 | 64)
        && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !raw.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn is_valid_semver(raw: &str) -> bool {
    let (core_and_pre, build) = raw
        .split_once('+')
        .map(|(left, right)| (left, Some(right)))
        .unwrap_or((raw, None));
    if build.is_some_and(|value| !valid_semver_identifiers(value, false)) {
        return false;
    }
    let (core, prerelease) = core_and_pre
        .split_once('-')
        .map(|(left, right)| (left, Some(right)))
        .unwrap_or((core_and_pre, None));
    let parts: Vec<_> = core.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return false;
    }
    !prerelease.is_some_and(|value| !valid_semver_identifiers(value, true))
}

fn valid_semver_identifiers(raw: &str, reject_numeric_leading_zero: bool) -> bool {
    !raw.is_empty()
        && raw.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !(reject_numeric_leading_zero
                    && part.len() > 1
                    && part.starts_with('0')
                    && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

fn verify_manifest_hashes(
    run_root: &Path,
    manifest: &RunManifest,
    identity: &tomorrowci_core::RunIdentity,
    errors: &mut Vec<String>,
) -> Result<()> {
    let workspace_manifest_path = safe_join(run_root, "workspace-manifest.json")?;
    let workspace_manifest: Option<WorkspaceManifest> =
        read_json_file(&workspace_manifest_path, "workspace-manifest.json", errors)?;
    let mut expected = BTreeSet::new();
    for relative in &manifest.detection.manifests {
        if let Err(error) = validate_manifest_path(relative) {
            errors.push(format!("invalid detection manifest {relative:?}: {error}"));
            continue;
        }
        if !expected.insert(relative.clone()) {
            errors.push(format!("duplicate detection manifest: {relative}"));
        }
    }
    let actual: BTreeSet<String> = identity.manifest_hashes.keys().cloned().collect();
    for missing in expected.difference(&actual) {
        errors.push(format!(
            "identity manifest_hashes missing detection manifest: {missing}"
        ));
    }
    for extra in actual.difference(&expected) {
        errors.push(format!(
            "identity manifest_hashes contains extra manifest: {extra}"
        ));
    }

    if let Some(workspace_manifest) = workspace_manifest {
        for relative in expected.intersection(&actual) {
            let Some(recorded_hash) = identity.manifest_hashes.get(relative) else {
                continue;
            };
            if crate::validate_sha256(recorded_hash).is_err() {
                errors.push(format!(
                    "identity manifest_hashes has noncanonical hash for {relative}"
                ));
                continue;
            }
            match workspace_manifest.files.get(relative) {
                Some(meta) => match normalize_workspace_hash(&meta.sha256) {
                    Some(hash) if &hash != recorded_hash => errors.push(format!(
                        "identity manifest hash does not match workspace-manifest for {relative}"
                    )),
                    None => errors.push(format!(
                        "workspace-manifest has invalid manifest hash for {relative}"
                    )),
                    _ => {}
                },
                None => errors.push(format!(
                    "workspace-manifest missing detected manifest: {relative}"
                )),
            }
        }
    }
    Ok(())
}

fn verify_cross_file_closure(
    run_root: &Path,
    manifest: &RunManifest,
    current_v2: bool,
    errors: &mut Vec<String>,
) -> Result<()> {
    if current_v2 {
        verify_run_level_duplicates(run_root, manifest, errors)?;
    }
    let planned = index_scenarios(&manifest.plan.scenarios, "run.json plan", errors);
    let run_results = index_results(&manifest.results, "run.json results", errors);
    let config = if current_v2 {
        let parsed = read_json_file::<Config>(
            &safe_join(run_root, "config.normalized.json")?,
            "config.normalized.json",
            errors,
        )?;
        if let Some(config) = &parsed {
            if let Err(error) = config.validate() {
                errors.push(format!("config.normalized.json is not executable: {error}"));
            }
        }
        parsed
    } else {
        None
    };

    let verdicts_path = safe_join(run_root, "verdicts.json")?;
    let verdicts: Vec<ExecutionResult> =
        read_json_file(&verdicts_path, "verdicts.json", errors)?.unwrap_or_default();
    let verdict_results = index_results(&verdicts, "verdicts.json", errors);

    let scenarios_root = safe_join(run_root, "scenarios")?;
    let scenario_directories = collect_scenario_directories(&scenarios_root, errors)?;

    compare_scenario_ids(
        "run.json results",
        run_results.keys(),
        "verdicts.json",
        verdict_results.keys(),
        errors,
    );
    compare_scenario_ids(
        "run.json results",
        run_results.keys(),
        "scenario directories",
        scenario_directories.iter(),
        errors,
    );

    for scenario_id in run_results.keys() {
        if !planned.contains_key(scenario_id) {
            errors.push(format!(
                "run.json result references scenario absent from plan: {scenario_id}"
            ));
        }
    }

    if current_v2 && !(planned.is_empty() && run_results.is_empty()) {
        let baseline_ids: Vec<_> = planned
            .values()
            .filter(|scenario| scenario.is_baseline)
            .map(|scenario| scenario.id.as_str())
            .collect();
        if baseline_ids.len() != 1 {
            errors.push(format!(
                "current-v2 plan must contain exactly one baseline scenario; found {}",
                baseline_ids.len()
            ));
        } else {
            let baseline_id = baseline_ids[0];
            match run_results.get(baseline_id) {
                None => errors.push(format!(
                    "current-v2 results are missing planned baseline scenario: {baseline_id}"
                )),
                Some(result) if result.verdict == Verdict::BaselinePass => {
                    for scenario_id in planned.keys() {
                        if !run_results.contains_key(scenario_id) {
                            errors.push(format!(
                                "baseline passed but run.json results are missing planned scenario: {scenario_id}"
                            ));
                        }
                    }
                }
                Some(_) => {
                    for scenario_id in run_results.keys() {
                        if scenario_id != baseline_id {
                            errors.push(format!(
                                "baseline did not pass but run.json results contain a later scenario: {scenario_id}"
                            ));
                        }
                    }
                }
            }
        }
    }

    for scenario_id in &scenario_directories {
        let scenario_root = safe_join(&scenarios_root, scenario_id)?;
        let scenario_path = safe_join(&scenario_root, "scenario.json")?;
        if let Some(scenario) = read_json_file::<Scenario>(
            &scenario_path,
            &format!("scenario {scenario_id} scenario.json"),
            errors,
        )? {
            if scenario.id != *scenario_id {
                errors.push(format!(
                    "scenario.json id {:?} does not match directory {scenario_id:?}",
                    scenario.id
                ));
            }
            match planned.get(scenario_id) {
                Some(expected) if !json_equivalent(expected, &scenario)? => errors.push(format!(
                    "scenario {scenario_id} scenario.json does not match run.json plan"
                )),
                None => errors.push(format!(
                    "scenario {scenario_id} scenario.json has no matching run.json plan entry"
                )),
                _ => {}
            }
        }

        let result_path = safe_join(&scenario_root, "result.json")?;
        if let Some(result) = read_json_file::<ExecutionResult>(
            &result_path,
            &format!("scenario {scenario_id} result.json"),
            errors,
        )? {
            if result.scenario_id != *scenario_id {
                errors.push(format!(
                    "scenario result.json scenario_id {:?} does not match directory {scenario_id:?}",
                    result.scenario_id
                ));
            }
            match run_results.get(scenario_id) {
                Some(expected) if !json_equivalent(expected, &result)? => errors.push(format!(
                    "scenario {scenario_id} result.json does not match run.json results"
                )),
                None => errors.push(format!(
                    "scenario {scenario_id} result.json has no matching run.json result"
                )),
                _ => {}
            }
            match verdict_results.get(scenario_id) {
                Some(expected) if !json_equivalent(expected, &result)? => errors.push(format!(
                    "scenario {scenario_id} result.json does not match verdicts.json"
                )),
                None => errors.push(format!(
                    "scenario {scenario_id} result.json has no matching verdicts.json entry"
                )),
                _ => {}
            }
            if current_v2 {
                verify_current_scenario_semantics(
                    &scenario_root,
                    scenario_id,
                    planned.get(scenario_id),
                    &result,
                    manifest,
                    config.as_ref(),
                    errors,
                )?;
            }
        }
    }

    if current_v2 {
        if let Some(config) = &config {
            verify_plan_semantics(run_root, manifest, config, errors)?;
        }
        verify_frontier_semantics(run_root, manifest, &planned, &run_results, errors)?;
    }

    Ok(())
}

fn verify_run_level_duplicates(
    run_root: &Path,
    manifest: &RunManifest,
    errors: &mut Vec<String>,
) -> Result<()> {
    if let Some(repository) = read_json_file::<RepositorySnapshot>(
        &safe_join(run_root, "repository.json")?,
        "repository.json",
        errors,
    )? {
        if !json_equivalent(&repository, &manifest.repository)? {
            errors.push("repository.json does not exactly match run.json repository".into());
        }
    }
    if let Some(plan) =
        read_json_file::<ExecutionPlan>(&safe_join(run_root, "plan.json")?, "plan.json", errors)?
    {
        if !json_equivalent(&plan, &manifest.plan)? {
            errors.push("plan.json does not exactly match run.json plan".into());
        }
    }
    if let Some(frontier) = read_json_file::<BreakageFrontier>(
        &safe_join(run_root, "frontier.json")?,
        "frontier.json",
        errors,
    )? {
        if !json_equivalent(&frontier, &manifest.frontier)? {
            errors.push("frontier.json does not exactly match run.json frontier".into());
        }
    }
    if let Some(report) =
        read_json_file::<RunManifest>(&safe_join(run_root, "report.json")?, "report.json", errors)?
    {
        if !json_equivalent(&report, manifest)? {
            errors.push("report.json does not exactly match verified run.json".into());
        }
    }
    verify_metrics_semantics(run_root, manifest, errors)?;
    verify_claim_semantics(run_root, manifest, errors)?;
    Ok(())
}

fn verify_plan_semantics(
    run_root: &Path,
    manifest: &RunManifest,
    config: &Config,
    errors: &mut Vec<String>,
) -> Result<()> {
    let candidates = read_json_file::<Vec<Candidate>>(
        &safe_join(run_root, "candidates.json")?,
        "candidates.json",
        errors,
    )?
    .unwrap_or_default();
    let decisions = read_json_file::<Vec<PlanDecision>>(
        &safe_join(run_root, "plan-decisions.json")?,
        "plan-decisions.json",
        errors,
    )?
    .unwrap_or_default();

    // A schema-2 bundle may represent a completed no-op inspection. It carries
    // no execution authority, but its empty planning mirrors must still agree.
    if manifest.plan.scenarios.is_empty() && manifest.results.is_empty() {
        if !candidates.is_empty() || !decisions.is_empty() {
            errors.push("empty run plan has nonempty candidates or plan decisions".into());
        }
        return Ok(());
    }

    let mut candidate_ids = BTreeSet::new();
    for candidate in &candidates {
        if let Err(error) = validate_identifier(&candidate.id, "candidate_id") {
            errors.push(error);
        }
        if !candidate_ids.insert(candidate.id.clone()) {
            errors.push(format!(
                "candidates.json contains duplicate candidate id: {}",
                candidate.id
            ));
        }
        match (&candidate.axis, &candidate.dependency_set) {
            (EnvironmentAxis::Runtime, Some(_)) => errors.push(format!(
                "runtime candidate {} must not carry a dependency set",
                candidate.id
            )),
            (EnvironmentAxis::Dependencies, Some(set)) => {
                if let Err(error) = set.validate() {
                    errors.push(format!(
                        "dependency candidate {} is not a valid exact set: {error}",
                        candidate.id
                    ));
                }
                if candidate.grade_if_executed != EvidenceGrade::Observed
                    || candidate.channel != "content-addressed"
                    || candidate.version != set.candidate.set_id
                {
                    errors.push(format!(
                        "dependency candidate {} is not bound to observed content-addressed identity",
                        candidate.id
                    ));
                }
            }
            (_, Some(_)) => errors.push(format!(
                "candidate {} carries a dependency set on the wrong axis",
                candidate.id
            )),
            _ => {}
        }
    }

    verify_dependency_semantics(run_root, manifest, &candidates, config, errors)?;

    let runtime_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.axis == EnvironmentAxis::Runtime)
        .cloned()
        .collect();
    verify_explicit_runtime_candidates(
        &manifest.baseline,
        manifest.detection.ecosystem,
        config,
        &runtime_candidates,
        errors,
    );
    let concrete_dependency_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.axis == EnvironmentAxis::Dependencies)
        .cloned()
        .collect();
    let dependency_candidates = if concrete_dependency_candidates
        .iter()
        .any(|candidate| candidate.dependency_set.is_some())
    {
        if concrete_dependency_candidates
            .iter()
            .any(|candidate| candidate.dependency_set.is_none())
        {
            errors
                .push("candidates.json mixes concrete and synthetic dependency candidates".into());
        }
        concrete_dependency_candidates
    } else {
        expected_dependency_candidates(&manifest.baseline, config)
    };
    let (expected_plan, expected_decisions) = plan_scenarios(
        &manifest.baseline,
        &runtime_candidates,
        &dependency_candidates,
        config,
    );
    if !json_equivalent(&expected_plan, &manifest.plan)? {
        errors.push("run plan cannot be derived from candidates.json and normalized config".into());
    }
    if !json_equivalent(&expected_decisions, &decisions)? {
        errors.push(
            "plan-decisions.json cannot be derived from candidates.json and normalized config"
                .into(),
        );
    }
    Ok(())
}

fn verify_explicit_runtime_candidates(
    baseline: &tomorrowci_core::Baseline,
    ecosystem: Ecosystem,
    config: &Config,
    candidates: &[Candidate],
    errors: &mut Vec<String>,
) {
    let Some(versions) = &config.candidates.runtime.versions else {
        return;
    };
    if ecosystem != Ecosystem::Python {
        errors.push("explicit runtime versions require the Python ecosystem".into());
        return;
    }
    if versions.len() != candidates.len() {
        errors.push("runtime candidate count differs from explicit configured versions".into());
    }
    let base = tomorrowci_core::parse_explicit_python_version(&baseline.runtime);
    for (version, candidate) in versions.iter().zip(candidates) {
        let Some((major, minor)) = tomorrowci_core::parse_explicit_python_version(version) else {
            errors.push("invalid explicit runtime version in normalized config".into());
            continue;
        };
        if match base {
            Some(value) => (major, minor) <= value,
            None => true,
        } {
            errors.push(format!(
                "explicit runtime {version} is not later than canonical baseline"
            ));
        }
        if candidate.id != format!("py{major}{minor}-locked")
            || candidate.version != *version
            || candidate.label != format!("Python {version} + locked dependencies")
            || candidate.order_key != format!("{major:03}.{minor:03}")
            || candidate.channel != "stable"
            || candidate.axis != EnvironmentAxis::Runtime
            || candidate.grade_if_executed != EvidenceGrade::Observed
            || candidate.dependency_set.is_some()
        {
            errors.push(format!(
                "runtime candidate {} differs from explicit configured version {version}",
                candidate.id
            ));
        }
    }
}

fn verify_dependency_semantics(
    run_root: &Path,
    manifest: &RunManifest,
    candidates: &[Candidate],
    config: &Config,
    errors: &mut Vec<String>,
) -> Result<()> {
    let concrete: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            candidate.axis == EnvironmentAxis::Dependencies && candidate.dependency_set.is_some()
        })
        .collect();
    // Optional paths are inspected lexically here. The recursive inventory has
    // already recorded aliases/reparse points as verification errors; resolving
    // them with `safe_join` would turn an ordinary FAIL report into an API error.
    let experiment_path = run_root.join("dependency-experiment.json");
    let reduction_path = run_root.join("reduction.json");

    if concrete.is_empty() {
        if experiment_path.exists() {
            errors.push(
                "dependency-experiment.json is present without concrete dependency candidates"
                    .into(),
            );
        }
        if reduction_path.exists() {
            errors.push("reduction.json is present without concrete dependency candidates".into());
        }
        return Ok(());
    }

    let Some(experiment) = read_json_file::<DependencyExperimentManifest>(
        &experiment_path,
        "dependency-experiment.json",
        errors,
    )?
    else {
        errors.push("concrete dependency candidates require dependency-experiment.json".into());
        return Ok(());
    };
    if experiment.ecosystem != manifest.detection.ecosystem {
        errors.push(
            "dependency experiment ecosystem does not match verified project detection".into(),
        );
    }
    if experiment.runtime.version != manifest.baseline.runtime {
        errors.push("dependency experiment runtime does not match verified baseline".into());
    }

    let workspace = safe_join(run_root, "workspace")?;
    let workspace_experiment_path = safe_join(&workspace, ".tomorrowci-dependencies.json")?;
    if let Some(workspace_experiment) = read_json_file::<DependencyExperimentManifest>(
        &workspace_experiment_path,
        "workspace .tomorrowci-dependencies.json",
        errors,
    )? {
        if !json_equivalent(&workspace_experiment, &experiment)? {
            errors.push(
                "dependency-experiment.json does not exactly match the recorded workspace manifest"
                    .into(),
            );
        }
    }

    let Some(first_set) = concrete
        .first()
        .and_then(|candidate| candidate.dependency_set.as_ref())
    else {
        return Ok(());
    };
    let package_manager = first_set.baseline.package_manager.as_str();
    let declared_full = match experiment.to_candidate_set(package_manager) {
        Ok(set) => set,
        Err(error) => {
            errors.push(format!(
                "dependency experiment contract is invalid: {error}"
            ));
            return Ok(());
        }
    };
    verify_dependency_artifacts(&workspace, &experiment, errors)?;

    if declared_full.baseline.ecosystem != manifest.detection.ecosystem
        || declared_full.baseline.package_manager != manifest.detection.package_manager
    {
        errors.push(
            "dependency experiment resolution identity contradicts detected package manager".into(),
        );
    }
    for candidate in &concrete {
        if let Some(set) = &candidate.dependency_set {
            if set.baseline.package_manager != package_manager {
                errors.push(format!(
                    "dependency candidate {} changes package manager within one experiment",
                    candidate.id
                ));
            }
        }
    }

    let expected_probes = if experiment.schema_version == 2 {
        if candidates
            .iter()
            .any(|candidate| candidate.axis != EnvironmentAxis::Dependencies)
        {
            errors.push(
                "adaptive dependency experiments cannot mix runtime or other-axis candidates"
                    .into(),
            );
        }
        expected_adaptive_dependency_probes(
            &experiment,
            &declared_full,
            &concrete,
            manifest,
            config,
            errors,
        )?
    } else {
        expected_dependency_probes(&experiment, &declared_full, errors)?
    };
    let expected_ids: Vec<_> = expected_probes.iter().map(|(id, _)| id.as_str()).collect();
    let actual_ids: Vec<_> = concrete
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    if actual_ids != expected_ids {
        let strategy = if experiment.schema_version == 2 {
            "adaptive"
        } else {
            "exhaustive"
        };
        errors.push(format!(
            "concrete dependency candidates are not the canonical {strategy} probe sequence: expected {expected_ids:?}, got {actual_ids:?}"
        ));
    }

    let candidate_by_id: BTreeMap<_, _> = concrete
        .iter()
        .map(|candidate| (candidate.id.as_str(), *candidate))
        .collect();
    for (index, (probe_id, selected_changes)) in expected_probes.iter().enumerate() {
        let Some(candidate) = candidate_by_id.get(probe_id.as_str()).copied() else {
            errors.push(format!(
                "dependency experiment is missing canonical probe candidate {probe_id}"
            ));
            continue;
        };
        let Some(set) = candidate.dependency_set.as_ref() else {
            continue;
        };
        let expected_resolution = match declared_full.resolution_for_changes(selected_changes) {
            Ok(set) => set,
            Err(error) => {
                errors.push(format!(
                    "cannot derive dependency probe {probe_id} resolution: {error}"
                ));
                continue;
            }
        };
        let expected_readable_set_id = format!("{}--{probe_id}", experiment.candidate.set_id);
        let expected_identity = set
            .stable_identity()
            .map_err(|error| TcError::InvalidState(error.to_string()))?;
        let expected_label = format!(
            "{} dependency probe {} ({})",
            manifest.baseline.runtime, probe_id, expected_identity
        );
        if candidate.order_key != format!("{index:04}")
            || candidate.label != expected_label
            || candidate.version != expected_readable_set_id
            || set.set_id != expected_readable_set_id
            || set.candidate.set_id != expected_readable_set_id
        {
            errors.push(format!(
                "dependency candidate {probe_id} readable identity/order is not canonically derived"
            ));
        }
        if !json_equivalent(&set.baseline, &declared_full.baseline)? {
            errors.push(format!(
                "dependency candidate {probe_id} baseline set differs from the trusted experiment"
            ));
        }
        if !json_equivalent(&set.changes, selected_changes)? {
            errors.push(format!(
                "dependency candidate {probe_id} changes differ from its canonical subset"
            ));
        }
        if !dependency_resolution_equivalent(&set.candidate, &expected_resolution) {
            errors.push(format!(
                "dependency candidate {probe_id} resolved set is not derived from its exact change subset"
            ));
        }
    }

    for scenario in &manifest.plan.scenarios {
        let expected = if scenario.is_baseline
            || !scenario
                .axes_changed
                .contains(&EnvironmentAxis::Dependencies)
        {
            Some(&declared_full.baseline)
        } else {
            candidate_by_id
                .get(scenario.id.as_str())
                .and_then(|candidate| candidate.dependency_set.as_ref())
                .map(|set| &set.candidate)
        };
        if let Some(expected) = expected {
            if scenario.resolved_dependencies.as_ref() != Some(expected) {
                errors.push(format!(
                    "scenario {} is not bound to its exact dependency resolution",
                    scenario.id
                ));
            }
        }
        if scenario.resolved_dependencies.is_some() {
            verify_dependency_runtime(scenario, &experiment.runtime.version, errors);
            if let Some(result) = manifest
                .results
                .iter()
                .find(|result| result.scenario_id == scenario.id && result.attempt > 0)
            {
                if result.environment.run_image_ref() != experiment.runtime.container_image {
                    errors.push(format!(
                        "executed dependency scenario {} did not use the manifest-pinned runtime image",
                        scenario.id
                    ));
                }
            }
        }
    }

    let baseline_passed = manifest.results.iter().any(|result| {
        manifest
            .plan
            .scenarios
            .iter()
            .any(|scenario| scenario.is_baseline && scenario.id == result.scenario_id)
            && result.verdict == Verdict::BaselinePass
    });
    if baseline_passed && !reduction_path.exists() {
        errors.push("completed dependency experiment is missing reduction.json".into());
        return Ok(());
    }
    if reduction_path.exists() {
        if let Some(recorded) =
            read_json_file::<DependencyReduction>(&reduction_path, "reduction.json", errors)?
        {
            if let Some(expected) = derive_expected_dependency_reduction(
                run_root,
                manifest,
                &experiment,
                &expected_probes,
                &candidate_by_id,
                errors,
            )? {
                if !json_equivalent(&recorded, &expected)? {
                    errors.push(
                        "reduction.json cannot be independently derived from observed dependency probe evidence"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Schema-v1 dependency artifacts bind one runtime. Historical mixed-axis
/// bundles may be internally checksummed yet describe an unexecuted runtime.
fn verify_dependency_runtime(scenario: &Scenario, pinned_runtime: &str, errors: &mut Vec<String>) {
    if scenario.runtime != pinned_runtime {
        errors.push(format!(
            "dependency scenario {} declares runtime {} but the experiment pins {}; mixed-runtime dependency evidence is unsupported",
            scenario.id, scenario.runtime, pinned_runtime
        ));
    }
}

fn verify_dependency_artifacts(
    workspace: &Path,
    experiment: &DependencyExperimentManifest,
    errors: &mut Vec<String>,
) -> Result<()> {
    let artifacts = experiment
        .candidate
        .changes
        .iter()
        .flat_map(|declaration| {
            [
                (&declaration.id, &declaration.name, &declaration.before),
                (&declaration.id, &declaration.name, &declaration.after),
            ]
        })
        .chain(
            experiment
                .unchanged
                .iter()
                .map(|fixed| (&fixed.id, &fixed.name, &fixed.artifact)),
        );
    for (id, name, artifact) in artifacts {
        if let Err(error) = validate_manifest_path(&artifact.source) {
            errors.push(format!(
                "dependency artifact {} has unsafe source path: {error}",
                id
            ));
            continue;
        }
        let source = match safe_join(workspace, &artifact.source) {
            Ok(source) => source,
            Err(error) => {
                errors.push(format!(
                    "dependency artifact {} source cannot be resolved: {error}",
                    id
                ));
                continue;
            }
        };
        let actual = if experiment.schema_version == 2 {
            // `safe_join` checks every existing ancestor. The metadata
            // check rejects aliases and non-files before reading bytes;
            // the core file hasher also checks the leaf without following it.
            if regular_file_metadata(&source, &format!("dependency wheel {id}"), errors)?.is_none()
            {
                continue;
            }
            sha256_file_v1(&source)
        } else {
            sha256_tree_v1(&source)
        };
        match actual {
            Ok(actual) if actual == artifact.content_sha256 => {}
            Ok(actual) => errors.push(format!(
                "dependency artifact {} {} content hash mismatch: declared={}, actual={}",
                name, artifact.version, artifact.content_sha256, actual
            )),
            Err(error) => errors.push(format!(
                "dependency artifact {} {} cannot be hashed: {error}",
                name, artifact.version
            )),
        }
    }
    Ok(())
}

/// Reconstruct every adaptive request from only the observations preceding it.
/// Validating a final bag of subsets would let a forged bundle choose whichever
/// evidence makes its claimed reduction look convincing.
fn expected_adaptive_dependency_probes(
    experiment: &DependencyExperimentManifest,
    declared_full: &DependencyCandidateSet,
    concrete: &[&Candidate],
    manifest: &RunManifest,
    config: &Config,
    errors: &mut Vec<String>,
) -> Result<Vec<(String, Vec<DependencyChange>)>> {
    if config.execution.reruns_on_failure < 3 || config.execution.max_scenarios < 2 {
        errors.push("adaptive dependency experiments require at least three failure attempts and two scenario slots".into());
    }
    if manifest.plan.budget_max != config.execution.max_scenarios {
        errors.push("adaptive dependency plan budget differs from normalized config".into());
    }
    let mut changes = declared_full.changes.clone();
    changes.sort_by(|left, right| left.id.cmp(&right.id));
    let original_ids: Vec<_> = changes.iter().map(|change| change.id.clone()).collect();
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    let initial = match next_dependency_subset(&original_ids, &observations) {
        Ok(Some(initial)) => initial,
        Ok(None) => return Ok(expected),
        Err(error) => {
            errors.push(format!("invalid adaptive dependency declaration: {error}"));
            return Ok(expected);
        }
    };
    let full_id =
        adaptive_dependency_probe_id(&experiment.candidate.set_id, &original_ids, &initial)?;
    expected.push((full_id.clone(), changes.clone()));
    if concrete.first().map(|candidate| candidate.id.as_str()) != Some(full_id.as_str()) {
        errors.push("adaptive dependency candidates must start with the full candidate".into());
        return Ok(expected);
    }

    let baseline = manifest
        .plan
        .scenarios
        .iter()
        .find(|scenario| scenario.is_baseline);
    let baseline_result = baseline.and_then(|scenario| {
        manifest
            .results
            .first()
            .filter(|result| result.scenario_id == scenario.id)
    });
    if baseline_result.is_none() {
        errors.push("adaptive dependency results must start with the baseline result".into());
    }
    let baseline_passed = baseline
        .zip(baseline_result)
        .is_some_and(|(scenario, result)| {
            scenario.grade == EvidenceGrade::Observed && result.verdict == Verdict::BaselinePass
        });
    if !baseline_passed {
        if concrete.len() != 1 || manifest.results.len() != 1 {
            errors.push(
                "adaptive dependency probing continued without an observed passing baseline".into(),
            );
        }
        return Ok(expected);
    }

    for (index, candidate) in concrete.iter().enumerate() {
        if index as u64 + 2 > u64::from(config.execution.max_scenarios) {
            errors.push(
                "adaptive dependency candidates exceed the scenario budget including baseline"
                    .into(),
            );
            return Ok(expected);
        }
        let next = match next_dependency_subset(&original_ids, &observations) {
            Ok(Some(next)) => next,
            Ok(None) => {
                errors.push(format!(
                    "adaptive dependency candidate {} appears after scheduling stopped",
                    candidate.id
                ));
                return Ok(expected);
            }
            Err(error) => {
                errors.push(format!(
                    "adaptive dependency observation prefix is invalid: {error}"
                ));
                return Ok(expected);
            }
        };
        let expected_id =
            adaptive_dependency_probe_id(&experiment.candidate.set_id, &original_ids, &next)?;
        let selected: Vec<_> = changes
            .iter()
            .filter(|change| next.contains(&change.id))
            .cloned()
            .collect();
        if index > 0 {
            expected.push((expected_id.clone(), selected));
        }
        if candidate.id != expected_id {
            errors.push(format!("adaptive dependency candidate {} is out of order: expected {expected_id} from the preceding observations", candidate.id));
            return Ok(expected);
        }
        let Some(result) = manifest.results.get(index + 1) else {
            errors.push(format!(
                "adaptive dependency candidate {expected_id} has no executed result"
            ));
            return Ok(expected);
        };
        if result.scenario_id != expected_id {
            errors.push(format!(
                "adaptive dependency result {} is out of order: expected {expected_id}",
                result.scenario_id
            ));
            return Ok(expected);
        }
        let Some(scenario) = manifest
            .plan
            .scenarios
            .get(index + 1)
            .filter(|scenario| scenario.id == expected_id)
        else {
            errors.push(format!(
                "adaptive dependency candidate {expected_id} is not the next planned scenario"
            ));
            return Ok(expected);
        };
        observations.push(DependencyScheduleObservation {
            change_ids: next,
            verdict: dependency_probe_verdict(result.verdict),
            failure_hash: dependency_failure_hash(result, &expected_id, errors),
            attempts: result.attempt,
            authority: scenario.grade,
        });
    }
    if manifest.results.len() != concrete.len() + 1 {
        errors.push("adaptive dependency results contain an unselected or extra execution".into());
    }
    match next_dependency_subset(&original_ids, &observations) {
        Ok(Some(_)) if concrete.len() as u64 + 1 < u64::from(config.execution.max_scenarios) => {
            errors.push("adaptive dependency schedule omits a required next probe before the scenario budget is exhausted".into());
        }
        Err(error) => errors.push(format!(
            "adaptive dependency observation prefix is invalid: {error}"
        )),
        _ => {}
    }
    Ok(expected)
}

fn expected_dependency_probes(
    experiment: &DependencyExperimentManifest,
    declared_full: &DependencyCandidateSet,
    errors: &mut Vec<String>,
) -> Result<Vec<(String, Vec<DependencyChange>)>> {
    let mut changes = declared_full.changes.clone();
    changes.sort_by(|left, right| left.id.cmp(&right.id));
    if changes.is_empty() || changes.len() > 8 {
        errors.push("dependency experiments require between one and eight concrete changes".into());
        return Ok(Vec::new());
    }
    let full_mask = (1usize << changes.len()) - 1;
    let mut subsets = vec![changes.clone()];
    let mut remaining = Vec::new();
    for mask in 1..full_mask {
        let subset = changes
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1usize << index) != 0)
            .map(|(_, change)| change.clone())
            .collect::<Vec<_>>();
        remaining.push(subset);
    }
    remaining.sort_by(|left, right| {
        let left_ids: Vec<_> = left.iter().map(|change| change.id.as_str()).collect();
        let right_ids: Vec<_> = right.iter().map(|change| change.id.as_str()).collect();
        left.len().cmp(&right.len()).then(left_ids.cmp(&right_ids))
    });
    subsets.extend(remaining);
    Ok(subsets
        .into_iter()
        .map(|subset| {
            let ids: Vec<_> = subset.iter().map(|change| change.id.as_str()).collect();
            let id = if subset.len() == changes.len() {
                experiment.candidate.set_id.clone()
            } else {
                format!("ddmin-{}", ids.join("--"))
            };
            (id, subset)
        })
        .collect())
}

fn dependency_resolution_equivalent(
    actual: &ResolvedDependencySet,
    expected: &ResolvedDependencySet,
) -> bool {
    actual.ecosystem == expected.ecosystem
        && actual.package_manager == expected.package_manager
        && actual.manifest_sha256 == expected.manifest_sha256
        && actual.dependencies == expected.dependencies
}

fn derive_expected_dependency_reduction(
    run_root: &Path,
    manifest: &RunManifest,
    experiment: &DependencyExperimentManifest,
    expected_probes: &[(String, Vec<DependencyChange>)],
    candidate_by_id: &BTreeMap<&str, &Candidate>,
    errors: &mut Vec<String>,
) -> Result<Option<DependencyReduction>> {
    let Some(full_candidate) = candidate_by_id.get(experiment.candidate.set_id.as_str()) else {
        errors.push("dependency experiment has no full candidate probe".into());
        return Ok(None);
    };
    let Some(full_set) = full_candidate.dependency_set.as_ref() else {
        errors.push("dependency experiment full candidate has no exact set".into());
        return Ok(None);
    };
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
    let scenario_grades: BTreeMap<_, _> = manifest
        .plan
        .scenarios
        .iter()
        .map(|scenario| (scenario.id.as_str(), scenario.grade))
        .collect();
    let result_by_id: BTreeMap<_, _> = manifest
        .results
        .iter()
        .map(|result| (result.scenario_id.as_str(), result))
        .collect();

    let mut records = Vec::new();
    let mut observed_by_subset = BTreeMap::new();
    for (index, (probe_id, selected_changes)) in expected_probes.iter().enumerate() {
        let Some(candidate) = candidate_by_id.get(probe_id.as_str()) else {
            continue;
        };
        let Some(set) = candidate.dependency_set.as_ref() else {
            continue;
        };
        let Some(result) = result_by_id.get(probe_id.as_str()).copied() else {
            continue;
        };
        let change_ids: Vec<_> = selected_changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        let record = DependencyProbeRecord {
            sequence: u32::try_from(index + 1)
                .map_err(|_| TcError::InvalidState("dependency probe sequence overflow".into()))?,
            scenario_id: probe_id.clone(),
            candidate_id: candidate_id.clone(),
            change_ids: change_ids.clone(),
            subset_hash: dependency_subset_hash(selected_changes)?,
            resolved_manifest_sha256: set.candidate.manifest_sha256.clone(),
            verdict: dependency_probe_verdict(result.verdict),
            failure_hash: dependency_failure_hash(result, probe_id, errors),
            evidence: dependency_probe_evidence(run_root, &manifest.run_id, probe_id)?,
            authority: scenario_grades
                .get(probe_id.as_str())
                .copied()
                .unwrap_or(EvidenceGrade::Inconclusive),
        };
        observed_by_subset.insert(change_ids, (record.clone(), result));
        records.push(record);
    }

    let Some((full_record, full_result)) = observed_by_subset.get(&original_change_ids) else {
        return Ok(Some(DependencyReduction {
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
        }));
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
        return Ok(Some(DependencyReduction {
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
        }));
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
    let Some(minimal_ids) = failing_subsets.first().cloned() else {
        errors.push("stable dependency failure vanished from observed probes".into());
        return Ok(None);
    };
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
            .filter(|change_id| change_id.as_str() != retained.id)
            .cloned()
            .collect();
        let observation = if remaining.is_empty() {
            baseline_dependency_probe_record(
                run_root,
                manifest,
                &result_by_id,
                &candidate_id,
                errors,
            )?
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

    Ok(Some(DependencyReduction {
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
    }))
}

fn baseline_dependency_probe_record(
    run_root: &Path,
    manifest: &RunManifest,
    results: &BTreeMap<&str, &ExecutionResult>,
    candidate_id: &str,
    errors: &mut Vec<String>,
) -> Result<Option<DependencyProbeRecord>> {
    let Some(scenario) = manifest
        .plan
        .scenarios
        .iter()
        .find(|scenario| scenario.is_baseline)
    else {
        return Ok(None);
    };
    let Some(result) = results.get(scenario.id.as_str()).copied() else {
        return Ok(None);
    };
    let Some(resolved) = scenario.resolved_dependencies.as_ref() else {
        errors.push("dependency experiment baseline lacks an exact resolved set".into());
        return Ok(None);
    };
    Ok(Some(DependencyProbeRecord {
        sequence: 0,
        scenario_id: scenario.id.clone(),
        candidate_id: candidate_id.to_owned(),
        change_ids: vec![],
        subset_hash: dependency_subset_hash(&[])?,
        resolved_manifest_sha256: resolved.manifest_sha256.clone(),
        verdict: dependency_probe_verdict(result.verdict),
        failure_hash: dependency_failure_hash(result, &scenario.id, errors),
        evidence: dependency_probe_evidence(run_root, &manifest.run_id, &scenario.id)?,
        authority: scenario.grade,
    }))
}

fn dependency_probe_evidence(
    run_root: &Path,
    run_id: &str,
    scenario_id: &str,
) -> Result<DependencyProbeEvidence> {
    let relative = format!("scenarios/{scenario_id}/result.json");
    let checksum = ContentHash::try_from(file_checksum(&safe_join(run_root, &relative)?)?)
        .map_err(TcError::InvalidState)?;
    Ok(DependencyProbeEvidence {
        run_id: run_id.to_owned(),
        scenario_id: scenario_id.to_owned(),
        path: relative,
        checksum,
    })
}

fn dependency_subset_hash(changes: &[DependencyChange]) -> Result<ContentHash> {
    let mut normalized = changes.to_vec();
    normalized.sort_by(|left, right| left.id.cmp(&right.id));
    ContentHash::try_from(canonical_json_hash(&normalized)?).map_err(TcError::InvalidState)
}

fn dependency_failure_hash(
    result: &ExecutionResult,
    scenario_id: &str,
    errors: &mut Vec<String>,
) -> Option<ContentHash> {
    let raw = result.failure.as_ref()?.normalized_hash.as_str();
    match ContentHash::try_from(raw) {
        Ok(hash) => Some(hash),
        Err(error) => {
            errors.push(format!(
                "dependency scenario {scenario_id} has invalid failure hash: {error}"
            ));
            None
        }
    }
}

fn dependency_probe_verdict(verdict: Verdict) -> DependencyProbeVerdict {
    match verdict {
        Verdict::BaselinePass | Verdict::FuturePass => DependencyProbeVerdict::Pass,
        Verdict::BaselineInvalid | Verdict::FutureFail => DependencyProbeVerdict::Fail,
        Verdict::Flaky => DependencyProbeVerdict::Flaky,
        Verdict::Blocked | Verdict::Unsupported => DependencyProbeVerdict::Blocked,
        Verdict::Inconclusive => DependencyProbeVerdict::Inconclusive,
    }
}

fn expected_dependency_candidates(
    baseline: &tomorrowci_core::Baseline,
    config: &Config,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    if config.candidates.dependencies.latest_allowed {
        candidates.push(Candidate {
            id: "deps-latest-allowed".into(),
            axis: EnvironmentAxis::Dependencies,
            label: format!("{} + latest allowed dependencies", baseline.runtime),
            version: "latest-allowed".into(),
            channel: "stable".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0001".into(),
            dependency_set: None,
        });
    }
    if config.candidates.dependencies.prerelease {
        candidates.push(Candidate {
            id: "deps-prerelease".into(),
            axis: EnvironmentAxis::Dependencies,
            label: "prerelease dependencies".into(),
            version: "prerelease".into(),
            channel: "preview".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0002".into(),
            dependency_set: None,
        });
    }
    candidates
}

fn verify_frontier_semantics(
    run_root: &Path,
    manifest: &RunManifest,
    planned: &BTreeMap<String, Scenario>,
    results: &BTreeMap<String, ExecutionResult>,
    errors: &mut Vec<String>,
) -> Result<()> {
    let mut ordered = Vec::new();
    for scenario in &manifest.plan.scenarios {
        if let Some(result) = results.get(&scenario.id) {
            ordered.push((scenario.clone(), result.clone()));
        }
    }
    let baseline_ok = ordered
        .iter()
        .any(|(scenario, result)| scenario.is_baseline && result.verdict == Verdict::BaselinePass);
    let first_future_fail = ordered
        .iter()
        .find(|(scenario, result)| !scenario.is_baseline && result.verdict == Verdict::FutureFail);
    let mut confirmed = false;
    let mut replay_command = None;
    if let Some((scenario, _)) = first_future_fail {
        let summary = read_json_file::<TestAttemptsSummary>(
            &safe_join(
                &safe_join(&safe_join(run_root, "scenarios")?, &scenario.id)?,
                "test-attempts.json",
            )?,
            &format!("scenario {} test-attempts.json", scenario.id),
            errors,
        )?;
        confirmed = summary.as_ref().is_some_and(|summary| {
            summary.status == TestExecutionStatus::Completed
                && summary.attempts.len() >= 2
                && summary
                    .attempts
                    .iter()
                    .all(|attempt| attempt.exit_code != Some(0) || attempt.timed_out)
        });
        if confirmed {
            replay_command = Some(format!(
                "tomorrowci replay {} --scenario {}",
                manifest.run_id, scenario.id
            ));
        }
    }
    let reduction_path = run_root.join("reduction.json");
    let minimal_replay_scenario = if confirmed && reduction_path.exists() {
        read_json_file::<DependencyReduction>(
            &reduction_path,
            "reduction.json frontier binding",
            errors,
        )?
        .filter(|reduction| {
            reduction.status == DependencyReductionStatus::ProvenMinimal
                && reduction.authority == EvidenceGrade::Observed
        })
        .and_then(|reduction| {
            let mut minimal_ids: Vec<_> = reduction
                .minimal_changes
                .iter()
                .map(|change| change.id.clone())
                .collect();
            minimal_ids.sort();
            reduction
                .probes
                .into_iter()
                .find(|probe| probe.change_ids == minimal_ids)
                .map(|probe| probe.scenario_id)
        })
    } else {
        None
    };
    if let Some(scenario_id) = &minimal_replay_scenario {
        replay_command = Some(format!(
            "tomorrowci replay {} --scenario {scenario_id}",
            manifest.run_id
        ));
    }
    let mut expected = compute_breakage_frontier(baseline_ok, &ordered, confirmed, replay_command);
    if let Some(scenario_id) = minimal_replay_scenario {
        expected.notes.push(format!(
            "dependency reduction proved 1-minimal at scenario {scenario_id}"
        ));
    }
    if !json_equivalent(&expected, &manifest.frontier)? {
        errors.push(
            "run/frontier.json breakage frontier cannot be derived from verified results and rerun confirmation"
                .into(),
        );
    }
    for scenario_id in results.keys() {
        if !planned.contains_key(scenario_id) {
            errors.push(format!(
                "frontier input result is absent from the verified plan: {scenario_id}"
            ));
        }
    }
    Ok(())
}

fn verify_metrics_semantics(
    run_root: &Path,
    manifest: &RunManifest,
    errors: &mut Vec<String>,
) -> Result<()> {
    let Some(metrics) = read_json_file::<SemanticMetrics>(
        &safe_join(run_root, "metrics.json")?,
        "metrics.json",
        errors,
    )?
    else {
        return Ok(());
    };
    let mut pass = 0;
    let mut fail = 0;
    let mut flaky = 0;
    let mut blocked = 0;
    let mut unsupported = 0;
    let mut inconclusive = 0;
    let mut total_duration = 0;
    let mut histogram = BTreeMap::new();
    for result in &manifest.results {
        *histogram
            .entry(format!("{:?}", result.verdict))
            .or_insert(0) += 1;
        total_duration += result.duration_ms;
        match result.verdict {
            Verdict::BaselinePass | Verdict::FuturePass => pass += 1,
            Verdict::BaselineInvalid | Verdict::FutureFail => fail += 1,
            Verdict::Flaky => flaky += 1,
            Verdict::Blocked => blocked += 1,
            Verdict::Unsupported => unsupported += 1,
            Verdict::Inconclusive => inconclusive += 1,
        }
    }
    let mismatch = metrics.run_id != manifest.run_id
        || metrics.scenarios_total != manifest.results.len() as u32
        || metrics.scenarios_pass != pass
        || metrics.scenarios_fail != fail
        || metrics.scenarios_flaky != flaky
        || metrics.scenarios_blocked != blocked
        || metrics.scenarios_unsupported != unsupported
        || metrics.scenarios_inconclusive != inconclusive
        || metrics.baseline_ok
            != manifest
                .results
                .iter()
                .any(|result| result.verdict == Verdict::BaselinePass)
        || metrics.frontier_observed != manifest.frontier.observed
        || metrics.total_duration_ms != total_duration
        || metrics.verdict_histogram != histogram;
    if mismatch {
        errors.push("metrics.json contradicts verified run results".into());
    }
    Ok(())
}

fn verify_claim_semantics(
    run_root: &Path,
    manifest: &RunManifest,
    errors: &mut Vec<String>,
) -> Result<()> {
    let Some(ledger) = read_json_file::<SemanticClaimLedger>(
        &safe_join(run_root, "claims.json")?,
        "claims.json",
        errors,
    )?
    else {
        return Ok(());
    };
    let scan_completed_authoritatively = !manifest.results.is_empty()
        && manifest.results.iter().all(|result| {
            !matches!(
                result.verdict,
                Verdict::Blocked
                    | Verdict::Unsupported
                    | Verdict::Inconclusive
                    | Verdict::BaselineInvalid
                    | Verdict::Flaky
            )
        });
    if !scan_completed_authoritatively
        && ledger
            .rows
            .iter()
            .any(|row| row.status == SemanticClaimStatus::Pass && !row.claim.trim().is_empty())
    {
        errors.push("claims.json contains PASS stronger than verified run results".into());
    }
    Ok(())
}

fn verify_current_scenario_semantics(
    scenario_root: &Path,
    scenario_id: &str,
    scenario: Option<&Scenario>,
    result: &ExecutionResult,
    manifest: &RunManifest,
    config: Option<&Config>,
    errors: &mut Vec<String>,
) -> Result<()> {
    let Some(scenario) = scenario else {
        return Ok(());
    };

    let environment = read_json_file::<EnvironmentSpec>(
        &safe_join(scenario_root, "environment.json")?,
        &format!("scenario {scenario_id} environment.json"),
        errors,
    )?;
    if let Some(environment) = &environment {
        if !json_equivalent(environment, &result.environment)? {
            errors.push(format!(
                "scenario {scenario_id} environment.json does not match result environment"
            ));
        }
        if let Some(config) = config {
            let requested_engine_matches = match config.sandbox.engine.as_str() {
                "auto" => matches!(environment.engine.as_deref(), Some("docker" | "podman")),
                requested => environment.engine.as_deref() == Some(requested),
            };
            if environment.memory_mb != config.sandbox.memory_mb
                || environment.cpus != config.sandbox.cpus
                || environment.pids_limit != config.sandbox.pids_limit
                || environment.fetch_timeout_seconds
                    != Some(config.execution.timeout_seconds.min(600))
                || environment.test_timeout_seconds != Some(config.execution.timeout_seconds)
                || environment.network_mode != "none"
                || (result.attempt > 0 && !requested_engine_matches)
            {
                errors.push(format!(
                    "scenario {scenario_id} environment contradicts normalized sandbox/execution config"
                ));
            }
        }
    }

    let resolved_path = safe_join(scenario_root, "resolved-dependencies.json")?;
    match &scenario.resolved_dependencies {
        Some(expected) => {
            if let Err(error) = expected.validate() {
                errors.push(format!(
                    "scenario {scenario_id} resolved dependency set is invalid: {error}"
                ));
            }
            if let Some(recorded) = read_json_file::<ResolvedDependencySet>(
                &resolved_path,
                &format!("scenario {scenario_id} resolved-dependencies.json"),
                errors,
            )? {
                if !json_equivalent(&recorded, expected)? {
                    errors.push(format!(
                        "scenario {scenario_id} resolved-dependencies.json does not match the plan"
                    ));
                }
            }
        }
        None if resolved_path.exists() => errors.push(format!(
            "scenario {scenario_id} has unbound resolved-dependencies.json"
        )),
        None => {}
    }

    let fetch_commands = read_json_file::<Vec<CommandSpec>>(
        &safe_join(scenario_root, "fetch-commands.json")?,
        &format!("scenario {scenario_id} fetch-commands.json"),
        errors,
    )?
    .unwrap_or_default();
    verify_dependency_materialization_contract(scenario, &fetch_commands, errors)?;
    let test_commands = read_json_file::<Vec<CommandSpec>>(
        &safe_join(scenario_root, "test-commands.json")?,
        &format!("scenario {scenario_id} test-commands.json"),
        errors,
    )?
    .unwrap_or_default();
    let commands = read_json_file::<Vec<CommandSpec>>(
        &safe_join(scenario_root, "commands.json")?,
        &format!("scenario {scenario_id} commands.json"),
        errors,
    )?
    .unwrap_or_default();
    let mut combined = fetch_commands.clone();
    combined.extend(test_commands.clone());
    if !json_equivalent(&combined, &commands)? || !json_equivalent(&combined, &result.commands)? {
        errors.push(format!(
            "scenario {scenario_id} fetch/test/commands.json do not exactly bind result commands"
        ));
    }
    if let Some(environment) = &environment {
        if combined
            .iter()
            .any(|command| command.cwd.as_deref() != Some(environment.workdir.as_str()))
        {
            errors.push(format!(
                "scenario {scenario_id} command cwd does not exactly match the recorded container workdir"
            ));
        }
    }
    if fetch_commands
        .iter()
        .any(|command| command.phase != "fetch")
    {
        errors.push(format!(
            "scenario {scenario_id} fetch commands contain non-fetch/offline semantics"
        ));
    }
    if test_commands
        .iter()
        .any(|command| command.phase != "test" || command.network)
    {
        errors.push(format!(
            "scenario {scenario_id} test commands contain non-test/networked semantics"
        ));
    }

    let replay = read_json_file::<ReplayDescriptor>(
        &safe_join(scenario_root, "replay.json")?,
        &format!("scenario {scenario_id} replay.json"),
        errors,
    )?;
    if let (Some(replay), Some(environment)) = (&replay, &environment) {
        verify_replay_descriptor(
            replay,
            scenario,
            environment,
            result,
            &fetch_commands,
            &test_commands,
            errors,
        )?;
    }

    let image_phase = read_json_file::<PhaseEvidence>(
        &safe_join(scenario_root, "image-resolve-phase.json")?,
        &format!("scenario {scenario_id} image-resolve-phase.json"),
        errors,
    )?;
    if let Some(phase) = &image_phase {
        verify_phase_time(phase, manifest, scenario_id, errors);
        if phase.phase != "image-resolve"
            || phase.network != "n/a"
            || !phase.argv.is_empty()
            || phase.image != result.environment.tag()
            || phase.image_digest != result.environment.image_digest
            || phase.ok != result.environment.image_digest.is_some()
        {
            errors.push(format!(
                "scenario {scenario_id} image-resolve phase does not bind the recorded image identity"
            ));
        }
    }

    let fetch_phase = verify_fetch_semantics(
        scenario_root,
        scenario,
        &fetch_commands,
        result,
        manifest,
        image_phase.as_ref(),
        errors,
    )?;

    let summary = read_json_file::<TestAttemptsSummary>(
        &safe_join(scenario_root, "test-attempts.json")?,
        &format!("scenario {scenario_id} test-attempts.json"),
        errors,
    )?;
    if let Some(summary) = &summary {
        if replay
            .as_ref()
            .is_some_and(|descriptor| descriptor.workspace_isolation != summary.workspace_isolation)
        {
            errors.push(format!(
                "scenario {scenario_id} replay workspace isolation does not match test attempts"
            ));
        }
        verify_test_attempts(
            scenario_root,
            scenario_id,
            scenario,
            result,
            summary,
            manifest,
            fetch_phase.as_ref().or(image_phase.as_ref()),
            &test_commands,
            config,
            errors,
        )?;
    }

    verify_failure_signature_file(scenario_root, scenario_id, result, errors)?;
    verify_replay_attempt_semantics(scenario_root, scenario_id, scenario, result, errors)?;
    Ok(())
}

fn verify_replay_descriptor(
    replay: &ReplayDescriptor,
    scenario: &Scenario,
    environment: &EnvironmentSpec,
    result: &ExecutionResult,
    fetch_commands: &[CommandSpec],
    test_commands: &[CommandSpec],
    errors: &mut Vec<String>,
) -> Result<()> {
    let scenario_id = scenario.id.as_str();
    let fetch_argv: Vec<_> = fetch_commands
        .iter()
        .map(|command| command.argv.clone())
        .collect();
    let test_argv: Vec<_> = test_commands
        .iter()
        .map(|command| command.argv.clone())
        .collect();
    let mismatch = replay.scenario_id != scenario_id
        || replay.engine != environment.engine
        || replay.engine_version != environment.engine_version
        || replay.image != environment.tag()
        || replay.image_digest != environment.image_digest
        || replay.workdir != environment.workdir
        || replay.user != environment.user
        || replay.memory_mb != environment.memory_mb
        || replay.cpus != environment.cpus
        || replay.pids_limit != environment.pids_limit
        || replay.read_only_root != environment.read_only_root
        || replay.fetch_network != dependency_fetch_network(scenario)
        || replay.test_network != "none"
        || replay.fetch_timeout_seconds != environment.fetch_timeout_seconds
        || replay.test_timeout_seconds != environment.test_timeout_seconds
        || replay.fetch_argv != fetch_argv
        || replay.test_argv != test_argv
        || replay.expected_exit_code != result.exit_code
        || replay.expected_timed_out != result.timed_out
        || !json_equivalent(&replay.expected_failure_signature, &result.failure)?
        || !json_equivalent(
            &replay.resolved_dependencies,
            &scenario.resolved_dependencies,
        )?;
    if mismatch {
        errors.push(format!(
            "scenario {scenario_id} replay.json does not exactly bind environment, commands, and expected result"
        ));
    }
    Ok(())
}

fn verify_workspace_preparation(
    isolation: Option<WorkspaceIsolation>,
    preparation: Option<&WorkspacePreparation>,
    environment: &EnvironmentSpec,
    duration_ms: u64,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    match (isolation, preparation) {
        (None, None) => {} // Historical shared-workspace evidence stays historical.
        (Some(WorkspaceIsolation::FreshPreparedCopyV1), Some(preparation))
            if preparation.strategy == WorkspaceIsolation::FreshPreparedCopyV1
                && preparation.seed_mount == "/tomorrowci-seed"
                && preparation.seed_read_only
                && preparation.destination_mount == "/work"
                && environment.workdir == "/work"
                && preparation.argv == tomorrowci_core::prepared_workspace_copy_argv()
                && Some(&preparation.image_digest) == environment.image_digest.as_ref()
                && preparation.network == "none"
                && preparation.exit_code == Some(0)
                && !preparation.timed_out
                && preparation.duration_ms <= duration_ms => {}
        _ => errors.push(format!(
            "scenario {scenario_id} workspace preparation does not prove the recorded isolated attempt contract"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_test_attempts(
    scenario_root: &Path,
    scenario_id: &str,
    scenario: &Scenario,
    result: &ExecutionResult,
    summary: &TestAttemptsSummary,
    manifest: &RunManifest,
    image_phase: Option<&PhaseEvidence>,
    test_commands: &[CommandSpec],
    config: Option<&Config>,
    errors: &mut Vec<String>,
) -> Result<()> {
    if summary.scenario_id != scenario_id {
        errors.push(format!(
            "scenario {scenario_id} test-attempts scenario_id mismatch"
        ));
    }
    let mut previous_finished = None;
    for (index, attempt) in summary.attempts.iter().enumerate() {
        verify_workspace_preparation(
            summary.workspace_isolation,
            attempt.workspace_preparation.as_ref(),
            &result.environment,
            attempt.duration_ms,
            scenario_id,
            errors,
        );
        let expected = (index + 1) as u32;
        if attempt.attempt != expected {
            errors.push(format!(
                "scenario {scenario_id} test attempts are not contiguous at {expected}"
            ));
        }
        if attempt.finished_at < attempt.started_at {
            errors.push(format!(
                "scenario {scenario_id} attempt {expected} finished before it started"
            ));
        }
        if previous_finished.is_some_and(|finished| attempt.started_at < finished) {
            errors.push(format!(
                "scenario {scenario_id} attempt {expected} overlaps or precedes its predecessor"
            ));
        }
        previous_finished = Some(attempt.finished_at);
        let passed = attempt.exit_code == Some(0) && !attempt.timed_out;
        if passed != attempt.failure.is_none() {
            errors.push(format!(
                "scenario {scenario_id} attempt {expected} failure signature contradicts raw exit/timeout"
            ));
        }
        if let Some(failure) = &attempt.failure {
            if crate::validate_sha256(&failure.normalized_hash).is_err() {
                errors.push(format!(
                    "scenario {scenario_id} attempt {expected} has invalid failure hash"
                ));
            }
        }
        for prefix in ["stdout", "stderr"] {
            let path = safe_join(
                scenario_root,
                &format!("{prefix}.attempt{}.log", attempt.attempt),
            )?;
            require_regular_file(
                &path,
                &format!(
                    "scenario {scenario_id} attempt {} {prefix} log",
                    attempt.attempt
                ),
                errors,
            )?;
        }
    }

    match summary.status {
        TestExecutionStatus::Completed => {
            if summary.attempts.is_empty() || summary.error.is_some() {
                errors.push(format!(
                    "scenario {scenario_id} completed test summary must contain attempts and no execution error"
                ));
                return Ok(());
            }
            let passes: Vec<_> = summary
                .attempts
                .iter()
                .map(|attempt| attempt.exit_code == Some(0) && !attempt.timed_out)
                .collect();
            if scenario.is_baseline && summary.attempts.len() != 1 {
                errors.push(format!(
                    "scenario {scenario_id} baseline must have exactly one test attempt"
                ));
            }
            if !scenario.is_baseline {
                if let Some(config) = config {
                    if summary.attempts.len() > config.execution.reruns_on_failure as usize {
                        errors.push(format!(
                            "scenario {scenario_id} exceeds the normalized rerun budget"
                        ));
                    }
                }
                if passes
                    .iter()
                    .position(|passed| *passed)
                    .is_some_and(|position| position + 1 != passes.len())
                {
                    errors.push(format!(
                        "scenario {scenario_id} contains attempts after the first passing rerun"
                    ));
                }
            }
            let expected_verdict = if scenario.is_baseline {
                if passes.iter().any(|passed| *passed) {
                    Verdict::BaselinePass
                } else {
                    Verdict::BaselineInvalid
                }
            } else {
                classify_candidate_attempts(&summary.attempts)
            };
            if result.verdict != expected_verdict {
                errors.push(format!(
                    "scenario {scenario_id} verdict {:?} contradicts attempt-derived verdict {:?}",
                    result.verdict, expected_verdict
                ));
            }
            let last = summary.attempts.last().expect("checked non-empty");
            let expected_failure = if expected_verdict == Verdict::Flaky {
                summary
                    .attempts
                    .iter()
                    .rev()
                    .find_map(|attempt| attempt.failure.clone())
            } else {
                last.failure.clone()
            };
            if result.attempt != summary.attempts.len() as u32
                || result.exit_code != last.exit_code
                || result.timed_out != last.timed_out
                || result.duration_ms != last.duration_ms
                || !json_equivalent(&result.failure, &expected_failure)?
            {
                errors.push(format!(
                    "scenario {scenario_id} result does not match final test attempt"
                ));
            }
            verify_test_phase_and_result(
                scenario_root,
                scenario_id,
                last,
                summary,
                result,
                test_commands,
                manifest,
                image_phase,
                errors,
            )?;
            let final_attempt = summary.attempts.len() as u32;
            for prefix in ["stdout", "stderr"] {
                let canonical = std::fs::read(safe_join(scenario_root, &format!("{prefix}.log"))?)?;
                let attempt = std::fs::read(safe_join(
                    scenario_root,
                    &format!("{prefix}.attempt{final_attempt}.log"),
                )?)?;
                if canonical != attempt {
                    errors.push(format!(
                        "scenario {scenario_id} {prefix}.log does not match final attempt log"
                    ));
                }
            }
        }
        TestExecutionStatus::NotRun => {
            if !summary.attempts.is_empty()
                || summary.error.as_deref().is_none_or(str::is_empty)
                || !matches!(result.verdict, Verdict::Blocked | Verdict::Unsupported)
                || result.attempt != 0
            {
                errors.push(format!(
                    "scenario {scenario_id} not-run summary cannot authorize verdict {:?}",
                    result.verdict
                ));
            }
        }
        TestExecutionStatus::ExecutionError => {
            if summary.error.as_deref().is_none_or(str::is_empty)
                || result.verdict != Verdict::Blocked
                || result.attempt != summary.attempts.len() as u32
            {
                errors.push(format!(
                    "scenario {scenario_id} execution-error summary must remain BLOCKED"
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_test_phase_and_result(
    scenario_root: &Path,
    scenario_id: &str,
    last: &tomorrowci_core::TestAttemptRecord,
    summary: &TestAttemptsSummary,
    result: &ExecutionResult,
    test_commands: &[CommandSpec],
    manifest: &RunManifest,
    previous_phase: Option<&PhaseEvidence>,
    errors: &mut Vec<String>,
) -> Result<()> {
    let phase = read_json_file::<PhaseEvidence>(
        &safe_join(scenario_root, "test-phase.json")?,
        &format!("scenario {scenario_id} test-phase.json"),
        errors,
    )?;
    let raw = read_json_file::<RawResultSummary>(
        &safe_join(scenario_root, "test-result.json")?,
        &format!("scenario {scenario_id} test-result.json"),
        errors,
    )?;
    if let Some(phase) = &phase {
        verify_phase_time(phase, manifest, scenario_id, errors);
        let argv: Vec<_> = test_commands
            .iter()
            .map(|command| command.argv.clone())
            .collect();
        let expected_duration = elapsed_ms_between(phase.started_at, phase.finished_at);
        let first = summary
            .attempts
            .first()
            .expect("completed summary is non-empty");
        if phase.phase != "test"
            || phase.network != "none"
            || phase.argv != argv
            || phase.image != result.environment.tag()
            || phase.image_digest != result.environment.image_digest
            || phase.exit_code != last.exit_code
            || phase.timed_out != last.timed_out
            || phase.duration_ms != expected_duration
            || phase.ok != (last.exit_code == Some(0) && !last.timed_out)
            || phase.started_at != first.started_at
            || phase.finished_at != last.finished_at
        {
            errors.push(format!(
                "scenario {scenario_id} test-phase contradicts its commands, environment, or complete attempt span"
            ));
        }
        if let Some(previous) = previous_phase {
            if phase.started_at < previous.finished_at {
                errors.push(format!(
                    "scenario {scenario_id} test phase begins before image resolution finished"
                ));
            }
        }
    }
    if let Some(raw) = &raw {
        if raw.exit_code != last.exit_code
            || raw.workspace_preparation != last.workspace_preparation
            || raw.timed_out != last.timed_out
            || raw.duration_ms != last.duration_ms
            || raw.network_used
            || raw.started_at != last.started_at
            || raw.finished_at != last.finished_at
        {
            errors.push(format!(
                "scenario {scenario_id} test-result contradicts final attempt"
            ));
        }
    }
    Ok(())
}

fn elapsed_ms_between(started_at: DateTime<Utc>, finished_at: DateTime<Utc>) -> u64 {
    finished_at
        .signed_duration_since(started_at)
        .num_milliseconds()
        .max(0) as u64
}

fn verify_failure_signature_file(
    scenario_root: &Path,
    scenario_id: &str,
    result: &ExecutionResult,
    errors: &mut Vec<String>,
) -> Result<()> {
    let path = safe_join(scenario_root, "failure-signature.json")?;
    if path.exists() {
        let failure = read_json_file::<FailureSignature>(
            &path,
            &format!("scenario {scenario_id} failure-signature.json"),
            errors,
        )?;
        if !json_equivalent(&failure, &result.failure)? {
            errors.push(format!(
                "scenario {scenario_id} failure-signature.json does not match result"
            ));
        }
    } else if result.failure.is_some() {
        errors.push(format!(
            "scenario {scenario_id} result failure is missing failure-signature.json"
        ));
    }
    if result.verdict.is_pass_like() && result.failure.is_some() {
        errors.push(format!(
            "scenario {scenario_id} pass-like verdict carries a failure signature"
        ));
    }
    Ok(())
}

fn verify_dependency_materialization_contract(
    scenario: &Scenario,
    recorded: &[CommandSpec],
    errors: &mut Vec<String>,
) -> Result<()> {
    if scenario.resolved_dependencies.is_none() {
        return Ok(());
    }
    match dependency_materialization_commands(scenario) {
        Ok(Some(expected)) if json_equivalent(&expected, &recorded.to_vec())? => {}
        Ok(Some(_)) => errors.push(format!(
            "scenario {} fetch commands do not materialize its exact dependency set",
            scenario.id
        )),
        Ok(None) => errors.push(format!(
            "scenario {} has exact dependencies without a materialization contract",
            scenario.id
        )),
        Err(error) => errors.push(format!(
            "scenario {} dependency materialization contract is invalid: {error}",
            scenario.id
        )),
    }
    Ok(())
}

fn verify_fetch_semantics(
    scenario_root: &Path,
    scenario: &Scenario,
    fetch_commands: &[CommandSpec],
    result: &ExecutionResult,
    manifest: &RunManifest,
    image_phase: Option<&PhaseEvidence>,
    errors: &mut Vec<String>,
) -> Result<Option<PhaseEvidence>> {
    let scenario_id = scenario.id.as_str();
    let expected_network = dependency_fetch_network(scenario);
    let phase_path = safe_join(scenario_root, "fetch-phase.json")?;
    let raw_path = safe_join(scenario_root, "fetch-result.json")?;
    let phase = if phase_path.exists() {
        read_json_file::<PhaseEvidence>(
            &phase_path,
            &format!("scenario {scenario_id} fetch-phase.json"),
            errors,
        )?
    } else {
        None
    };
    let raw = if raw_path.exists() {
        read_json_file::<RawResultSummary>(
            &raw_path,
            &format!("scenario {scenario_id} fetch-result.json"),
            errors,
        )?
    } else {
        None
    };
    if !fetch_commands.is_empty() && result.environment.image_digest.is_some() && phase.is_none() {
        errors.push(format!(
            "scenario {scenario_id} has fetch commands after image resolution but no fetch phase"
        ));
    }
    if let Some(phase) = &phase {
        verify_phase_time(phase, manifest, scenario_id, errors);
        let argv: Vec<_> = fetch_commands
            .iter()
            .map(|command| command.argv.clone())
            .collect();
        if phase.phase != "fetch"
            || phase.network != expected_network
            || phase.argv != argv
            || phase.image != result.environment.tag()
            || phase.image_digest != result.environment.image_digest
        {
            errors.push(format!(
                "scenario {scenario_id} fetch phase does not bind commands/environment"
            ));
        }
        if let Some(previous) = image_phase {
            if phase.started_at < previous.finished_at {
                errors.push(format!(
                    "scenario {scenario_id} fetch begins before image resolution finished"
                ));
            }
        }
    }
    if let Some(raw) = &raw {
        if raw.network_used != (expected_network != "none") || raw.finished_at < raw.started_at {
            errors.push(format!(
                "scenario {scenario_id} fetch-result has invalid network/time semantics"
            ));
        }
        match &phase {
            Some(phase)
                if raw.exit_code == phase.exit_code
                    && raw.timed_out == phase.timed_out
                    && raw.duration_ms == phase.duration_ms
                    && raw.started_at == phase.started_at
                    && raw.finished_at == phase.finished_at => {}
            _ => errors.push(format!(
                "scenario {scenario_id} fetch-result does not match fetch phase"
            )),
        }
    }
    Ok(phase)
}

fn verify_phase_time(
    phase: &PhaseEvidence,
    manifest: &RunManifest,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if phase.finished_at < phase.started_at {
        errors.push(format!(
            "scenario {scenario_id} {} phase finished before it started",
            phase.phase
        ));
    }
    if phase.started_at < manifest.started_at
        || manifest
            .finished_at
            .is_some_and(|finished| phase.finished_at > finished)
    {
        errors.push(format!(
            "scenario {scenario_id} {} phase lies outside run timestamps",
            phase.phase
        ));
    }
}

fn index_scenarios(
    scenarios: &[Scenario],
    label: &str,
    errors: &mut Vec<String>,
) -> BTreeMap<String, Scenario> {
    let mut indexed = BTreeMap::new();
    for scenario in scenarios {
        if let Err(error) = validate_identifier(&scenario.id, "scenario_id") {
            errors.push(format!("{label}: {error}"));
            continue;
        }
        if indexed
            .insert(scenario.id.clone(), scenario.clone())
            .is_some()
        {
            errors.push(format!(
                "{label} contains duplicate scenario_id: {}",
                scenario.id
            ));
        }
    }
    indexed
}

fn index_results(
    results: &[ExecutionResult],
    label: &str,
    errors: &mut Vec<String>,
) -> BTreeMap<String, ExecutionResult> {
    let mut indexed = BTreeMap::new();
    for result in results {
        if let Err(error) = validate_identifier(&result.scenario_id, "scenario_id") {
            errors.push(format!("{label}: {error}"));
            continue;
        }
        if indexed
            .insert(result.scenario_id.clone(), result.clone())
            .is_some()
        {
            errors.push(format!(
                "{label} contains duplicate scenario_id: {}",
                result.scenario_id
            ));
        }
    }
    indexed
}

fn collect_scenario_directories(
    scenarios_root: &Path,
    errors: &mut Vec<String>,
) -> Result<BTreeSet<String>> {
    let mut directories = BTreeSet::new();
    let metadata = match safe_metadata_report(scenarios_root, errors)? {
        Some(metadata) => metadata,
        None => return Ok(directories),
    };
    if !metadata.is_dir() {
        errors.push(format!(
            "scenarios root is not a directory: {}",
            scenarios_root.display()
        ));
        return Ok(directories);
    }

    for entry in std::fs::read_dir(scenarios_root)? {
        let entry = entry?;
        let scenario_id = match utf8_file_name(&entry) {
            Ok(scenario_id) => scenario_id,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        if let Err(error) = validate_identifier(&scenario_id, "scenario directory") {
            errors.push(error);
            continue;
        }
        let metadata = match safe_metadata_report(&entry.path(), errors)? {
            Some(metadata) => metadata,
            None => continue,
        };
        if !metadata.is_dir() {
            errors.push(format!(
                "scenario entry is not a directory: {}",
                entry.path().display()
            ));
            continue;
        }
        directories.insert(scenario_id);
    }
    Ok(directories)
}

fn compare_scenario_ids<'a>(
    left_label: &str,
    left: impl Iterator<Item = &'a String>,
    right_label: &str,
    right: impl Iterator<Item = &'a String>,
    errors: &mut Vec<String>,
) {
    let left: BTreeSet<&String> = left.collect();
    let right: BTreeSet<&String> = right.collect();
    for scenario_id in left.difference(&right) {
        errors.push(format!(
            "{right_label} missing scenario present in {left_label}: {scenario_id}"
        ));
    }
    for scenario_id in right.difference(&left) {
        errors.push(format!(
            "{right_label} contains orphan scenario absent from {left_label}: {scenario_id}"
        ));
    }
}

fn read_json_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
    errors: &mut Vec<String>,
) -> Result<Option<T>> {
    if regular_file_metadata(path, label, errors)?.is_none() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    match serde_json::from_str(&raw) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            errors.push(format!("{label} is malformed: {error}"));
            Ok(None)
        }
    }
}

fn json_equivalent<T: Serialize>(left: &T, right: &T) -> Result<bool> {
    Ok(serde_json::to_value(left)? == serde_json::to_value(right)?)
}

fn verify_scenarios(
    run_root: &Path,
    expected_format: Option<ChecksumFormat>,
    errors: &mut Vec<String>,
    checked: &mut usize,
) -> Result<()> {
    let scenarios_root = safe_join(run_root, "scenarios")?;
    let metadata = match std::fs::symlink_metadata(&scenarios_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            errors.push("missing scenarios directory".into());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) {
        errors.push(format!(
            "refusing scenario symlink/reparse point: {}",
            scenarios_root.display()
        ));
        return Ok(());
    }
    if !metadata.is_dir() {
        errors.push("scenarios entry is not a directory".into());
        return Ok(());
    }

    for entry in std::fs::read_dir(&scenarios_root)? {
        let entry = entry?;
        let scenario_root = entry.path();
        let scenario_name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => {
                errors.push("scenario directory name is not UTF-8".into());
                continue;
            }
        };
        if let Err(error) = validate_single_component(&scenario_name) {
            errors.push(error.to_string());
            continue;
        }
        let scenario_metadata = safe_metadata_report(&scenario_root, errors)?;
        if !scenario_metadata
            .as_ref()
            .is_some_and(std::fs::Metadata::is_dir)
        {
            if scenario_metadata.is_some() {
                errors.push(format!(
                    "scenario entry is not a directory: {}",
                    scenario_root.display()
                ));
            }
            continue;
        }

        let checksums_path = safe_join(&scenario_root, "checksums.txt")?;
        let checksums = parse_checksum_manifest(
            &checksums_path,
            &format!("scenario {scenario_name} checksums"),
            errors,
        )?;
        let legacy_fetch_optional = checksums
            .as_ref()
            .is_some_and(|manifest| manifest.format == ChecksumFormat::LegacyV1);
        for name in SCENARIO_REQUIRED {
            if *name == "fetch-commands.json"
                && legacy_fetch_optional
                && !safe_join(&scenario_root, name)?.exists()
                && !safe_join(&scenario_root, "fetch-phase.json")?.exists()
            {
                continue;
            }
            let path = safe_join(&scenario_root, name)?;
            require_regular_file(
                &path,
                &format!("scenario {scenario_name} required file {name}"),
                errors,
            )?;
        }

        if let Some(manifest) = &checksums {
            if let Some(expected) = expected_format {
                if manifest.format != expected {
                    errors.push(format!(
                        "scenario {scenario_name} checksum format does not match run checksum format"
                    ));
                }
            }
            if manifest.format == ChecksumFormat::CurrentV2 {
                for current_name in [
                    "commands.json",
                    "test-attempts.json",
                    "image-resolve-phase.json",
                ] {
                    let path = safe_join(&scenario_root, current_name)?;
                    require_regular_file(
                        &path,
                        &format!("scenario {scenario_name} current-v2 file {current_name}"),
                        errors,
                    )?;
                }
            }
            verify_checksum_inventory(
                &scenario_root,
                InventoryScope::Scenario,
                manifest,
                errors,
                checked,
            )?;
        }
        verify_replay_attempts(&scenario_root, &scenario_name, errors)?;
    }
    Ok(())
}

fn verify_replay_attempts(
    scenario_root: &Path,
    scenario_name: &str,
    errors: &mut Vec<String>,
) -> Result<()> {
    let replays = safe_join(scenario_root, "replays")?;
    let metadata = match std::fs::symlink_metadata(&replays) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) {
        errors.push(format!(
            "scenario {scenario_name} replays is a symlink/reparse point"
        ));
        return Ok(());
    }
    if !metadata.is_dir() {
        errors.push(format!(
            "scenario {scenario_name} replays is not a directory"
        ));
        return Ok(());
    }

    let mut attempts = BTreeSet::new();
    for entry in std::fs::read_dir(&replays)? {
        let entry = entry?;
        let name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => {
                errors.push(format!(
                    "scenario {scenario_name} replay directory name is not UTF-8"
                ));
                continue;
            }
        };
        let number = match replay_attempt_number(&name) {
            Some(number) => number,
            None => {
                errors.push(format!(
                    "scenario {scenario_name} invalid replay attempt directory: {name}"
                ));
                continue;
            }
        };
        let path = entry.path();
        let metadata = safe_metadata_report(&path, errors)?;
        if !metadata.as_ref().is_some_and(std::fs::Metadata::is_dir) {
            if metadata.is_some() {
                errors.push(format!(
                    "scenario {scenario_name} replay attempt is not a directory: {name}"
                ));
            }
            continue;
        }
        attempts.insert(number);
        for required in REPLAY_REQUIRED {
            let required_path = safe_join(&path, required)?;
            require_regular_file(
                &required_path,
                &format!("scenario {scenario_name} replay {name} required file {required}"),
                errors,
            )?;
        }
    }

    for expected in 1..=attempts.len() as u32 {
        if !attempts.contains(&expected) {
            errors.push(format!(
                "scenario {scenario_name} replay attempts are not contiguous at attempt-{expected}"
            ));
        }
    }
    Ok(())
}

fn verify_replay_attempt_semantics(
    scenario_root: &Path,
    scenario_id: &str,
    scenario: &Scenario,
    result: &ExecutionResult,
    errors: &mut Vec<String>,
) -> Result<()> {
    let replays = safe_join(scenario_root, "replays")?;
    let summary = read_json_file::<TestAttemptsSummary>(
        &safe_join(scenario_root, "test-attempts.json")?,
        &format!("scenario {scenario_id} test-attempts.json"),
        errors,
    )?;
    let mut reports = Vec::new();
    if replays.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(&replays)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(replay_attempt_number)
                .unwrap_or(u32::MAX)
        });
        for entry in entries {
            let name = utf8_file_name(&entry)?;
            let Some(number) = replay_attempt_number(&name) else {
                continue;
            };
            let report_path = safe_join(&entry.path(), "result.json")?;
            if let Some(report) = read_json_file::<ReplayAttemptEvidence>(
                &report_path,
                &format!("scenario {scenario_id} replay {name} result.json"),
                errors,
            )? {
                if report.scenario_id != scenario_id || report.attempt != number as usize {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} identity mismatch"
                    ));
                }
                if report.finished_at < report.started_at {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} finished before it started"
                    ));
                }
                if report.original_exit != result.exit_code
                    || report.original_signature.as_deref()
                        != result
                            .failure
                            .as_ref()
                            .map(|failure| failure.normalized_hash.as_str())
                {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} does not bind original result"
                    ));
                }
                let recorded = canonical_image_digest_value(&report.recorded_digest);
                let resolved = canonical_image_digest_value(&report.resolved_digest);
                if recorded.is_err()
                    || resolved.is_err()
                    || recorded.ok() != resolved.ok()
                    || result.environment.image_digest.as_deref()
                        != Some(report.recorded_digest.as_str())
                {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} has invalid or divergent image digest"
                    ));
                }
                if report.engine != result.environment.engine.clone().unwrap_or_default()
                    || report.engine_version
                        != result
                            .environment
                            .engine_version
                            .clone()
                            .unwrap_or_default()
                    || report.image_tag != result.environment.tag()
                    || Some(report.fetch_timeout_seconds)
                        != result.environment.fetch_timeout_seconds
                    || Some(report.test_timeout_seconds) != result.environment.test_timeout_seconds
                {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} engine/environment identity mismatch"
                    ));
                }
                if report.dependency_manifest_sha256.as_ref()
                    != scenario
                        .resolved_dependencies
                        .as_ref()
                        .map(|set| &set.manifest_sha256)
                {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} dependency set identity mismatch"
                    ));
                }
                if report.phase == "test" && report.error.is_none() {
                    verify_workspace_preparation(
                        summary.as_ref().and_then(|s| s.workspace_isolation),
                        report.workspace_preparation.as_ref(),
                        &result.environment,
                        report.duration_ms,
                        scenario_id,
                        errors,
                    );
                } else if report.workspace_preparation.is_some() {
                    errors.push(format!("scenario {scenario_id} replay {name} has preparation without a completed test execution"));
                }
                let derived_exit_match =
                    report.replay_exit == result.exit_code && report.timed_out == result.timed_out;
                let derived_signature_match = report.replay_signature.as_deref()
                    == result
                        .failure
                        .as_ref()
                        .map(|failure| failure.normalized_hash.as_str());
                if report.phase == "test"
                    && (report.exit_match != Some(derived_exit_match)
                        || report.signature_match != Some(derived_signature_match))
                {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} comparison flags contradict recorded outputs"
                    ));
                }
                let expected_ok = report.phase == "test"
                    && report.error.is_none()
                    && derived_exit_match
                    && derived_signature_match;
                if report.ok != expected_ok {
                    errors.push(format!(
                        "scenario {scenario_id} replay {name} ok flag contradicts replay comparison"
                    ));
                }
                reports.push(report);
            }
        }
    }

    let latest_path = safe_join(scenario_root, "replay-result.json")?;
    match (reports.last(), latest_path.exists()) {
        (Some(expected), true) => {
            if let Some(latest) = read_json_file::<ReplayAttemptEvidence>(
                &latest_path,
                &format!("scenario {scenario_id} replay-result.json"),
                errors,
            )? {
                if &latest != expected {
                    errors.push(format!(
                        "scenario {scenario_id} replay-result.json is not the latest committed attempt"
                    ));
                }
            }
        }
        (Some(_), false) => errors.push(format!(
            "scenario {scenario_id} replay attempts exist without replay-result.json"
        )),
        (None, true) => errors.push(format!(
            "scenario {scenario_id} replay-result.json exists without a committed attempt"
        )),
        (None, false) => {}
    }
    Ok(())
}

fn parse_checksum_manifest(
    path: &Path,
    label: &str,
    errors: &mut Vec<String>,
) -> Result<Option<ChecksumManifest>> {
    if regular_file_metadata(path, label, errors)?.is_none() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)?;
    let first_nonempty = raw.lines().position(|line| !line.trim().is_empty());
    let format = match first_nonempty.and_then(|index| raw.lines().nth(index)) {
        Some(line) if line.trim() == CHECKSUM_FORMAT_V2 => ChecksumFormat::CurrentV2,
        _ => ChecksumFormat::LegacyV1,
    };

    let mut entries = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == CHECKSUM_FORMAT_V2 {
            if format != ChecksumFormat::CurrentV2 || Some(index) != first_nonempty {
                errors.push(format!(
                    "{label} line {line_number}: checksum format header is misplaced"
                ));
            }
            continue;
        }

        let fields: Vec<_> = trimmed.split_ascii_whitespace().collect();
        if fields.len() != 2 {
            errors.push(format!(
                "{label} line {line_number}: malformed checksum entry"
            ));
            continue;
        }

        let hash = match normalize_checksum(fields[0], format) {
            Some(hash) => hash,
            None => {
                errors.push(format!(
                    "{label} line {line_number}: malformed sha256 {:?}",
                    fields[0]
                ));
                continue;
            }
        };
        let relative = fields[1];
        if let Err(error) = validate_manifest_path(relative) {
            errors.push(format!(
                "{label} line {line_number}: invalid path {relative:?}: {error}"
            ));
            continue;
        }
        if relative.chars().any(char::is_whitespace) {
            errors.push(format!(
                "{label} line {line_number}: checksum path is not canonical"
            ));
            continue;
        }
        if entries.insert(relative.to_string(), hash).is_some() {
            errors.push(format!(
                "{label} line {line_number}: duplicate checksum path {relative}"
            ));
        }
    }

    Ok(Some(ChecksumManifest { format, entries }))
}

fn verify_checksum_inventory(
    root: &Path,
    scope: InventoryScope,
    manifest: &ChecksumManifest,
    errors: &mut Vec<String>,
    checked: &mut usize,
) -> Result<()> {
    let actual = match collect_inventory(root, scope) {
        Ok(actual) => actual,
        Err(error) => {
            errors.push(error.to_string());
            BTreeSet::new()
        }
    };
    let listed: BTreeSet<_> = manifest.entries.keys().cloned().collect();

    for (relative, expected) in &manifest.entries {
        if !inventory_path_allowed(scope, relative) {
            errors.push(format!(
                "checksum lists unrecognized {} file: {relative}",
                scope_name(scope)
            ));
            continue;
        }
        let path = safe_join(root, relative)?;
        if regular_file_metadata(&path, "checksum", errors)?.is_none() {
            continue;
        }
        let actual_hash = file_checksum(&path)?;
        if actual_hash != *expected {
            errors.push(format!(
                "checksum mutation detected in {} file: {relative}",
                scope_name(scope)
            ));
        } else {
            *checked += 1;
        }
    }

    for relative in actual.difference(&listed) {
        if manifest.format == ChecksumFormat::LegacyV1 && legacy_unlisted_allowed(scope, relative) {
            continue;
        }
        errors.push(format!("unlisted {} file: {relative}", scope_name(scope)));
    }
    for relative in listed.difference(&actual) {
        errors.push(format!(
            "checksum lists missing {} file: {relative}",
            scope_name(scope)
        ));
    }
    Ok(())
}

fn collect_inventory(root: &Path, scope: InventoryScope) -> Result<BTreeSet<String>> {
    ensure_directory_no_alias(root)?;
    match scope {
        InventoryScope::Run => collect_run_inventory(root),
        InventoryScope::Scenario => collect_scenario_inventory(root),
    }
}

fn collect_run_inventory(root: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = utf8_file_name(&entry)?;
        let metadata = safe_metadata(&path)?;

        if metadata.is_dir() {
            if name == "scenarios" {
                collect_scenario_checksum_bindings(&path, &mut files)?;
            } else if name != "workspace" {
                return Err(TcError::InvalidState(format!(
                    "unexpected run directory: {name}"
                )));
            }
            continue;
        }
        if !metadata.is_file() {
            return Err(TcError::InvalidState(format!(
                "unsupported run filesystem entry: {}",
                path.display()
            )));
        }
        if name == "checksums.txt" {
            continue;
        }
        validate_manifest_path(&name).map_err(TcError::InvalidState)?;
        if !inventory_path_allowed(InventoryScope::Run, &name) {
            return Err(TcError::InvalidState(format!(
                "unexpected run file: {name}"
            )));
        }
        files.insert(name);
    }
    Ok(files)
}

fn collect_scenario_checksum_bindings(
    scenarios_root: &Path,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    ensure_directory_no_alias(scenarios_root)?;
    for entry in std::fs::read_dir(scenarios_root)? {
        let entry = entry?;
        let scenario_id = utf8_file_name(&entry)?;
        validate_identifier(&scenario_id, "scenario directory").map_err(TcError::InvalidState)?;
        let scenario_root = entry.path();
        let metadata = safe_metadata(&scenario_root)?;
        if !metadata.is_dir() {
            return Err(TcError::InvalidState(format!(
                "scenario entry is not a directory: {}",
                scenario_root.display()
            )));
        }

        let checksum_path = safe_join(&scenario_root, "checksums.txt")?;
        match std::fs::symlink_metadata(&checksum_path) {
            Ok(metadata) if metadata_is_alias(&metadata) => {
                return Err(TcError::InvalidState(format!(
                    "scenario checksum manifest is a symlink/reparse point: {}",
                    checksum_path.display()
                )));
            }
            Ok(metadata) if metadata.is_file() => {
                files.insert(format!("scenarios/{scenario_id}/checksums.txt"));
            }
            Ok(_) => {
                return Err(TcError::InvalidState(format!(
                    "scenario checksum manifest is not a regular file: {}",
                    checksum_path.display()
                )));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn collect_scenario_inventory(root: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    walk_scenario_inventory(root, root, &mut files)?;
    Ok(files)
}

fn walk_scenario_inventory(
    root: &Path,
    current: &Path,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = safe_metadata(&path)?;
        let relative = relative_path(root, &path)?;
        validate_manifest_path(&relative).map_err(TcError::InvalidState)?;

        if metadata.is_dir() {
            if !scenario_directory_allowed(&relative) {
                return Err(TcError::InvalidState(format!(
                    "unexpected scenario directory: {relative}"
                )));
            }
            walk_scenario_inventory(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(TcError::InvalidState(format!(
                "unsupported scenario filesystem entry: {}",
                path.display()
            )));
        }
        if relative == "checksums.txt" {
            continue;
        }
        if !inventory_path_allowed(InventoryScope::Scenario, &relative) {
            return Err(TcError::InvalidState(format!(
                "unexpected scenario file: {relative}"
            )));
        }
        files.insert(relative);
    }
    Ok(())
}

fn collect_workspace_inventory(root: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    walk_workspace_inventory(root, root, &mut files)?;
    Ok(files)
}

fn walk_workspace_inventory(
    root: &Path,
    current: &Path,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let name = utf8_file_name(&entry)?;
        let metadata = safe_metadata(&path)?;
        if WORKSPACE_IGNORED.contains(&name.as_str()) {
            continue;
        }
        if metadata.is_dir() {
            walk_workspace_inventory(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = relative_path(root, &path)?;
            validate_manifest_path(&relative).map_err(TcError::InvalidState)?;
            files.insert(relative);
        } else {
            return Err(TcError::InvalidState(format!(
                "unsupported workspace filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn inventory_path_allowed(scope: InventoryScope, relative: &str) -> bool {
    match scope {
        InventoryScope::Run => {
            scenario_checksum_binding(relative)
                || (!relative.contains('/')
                    && relative != "checksums.txt"
                    && (RUN_REQUIRED.contains(&relative) || RUN_OPTIONAL.contains(&relative)))
        }
        InventoryScope::Scenario => {
            if !relative.contains('/') {
                return relative != "checksums.txt"
                    && (SCENARIO_REQUIRED.contains(&relative)
                        || SCENARIO_OPTIONAL.contains(&relative)
                        || attempt_log_number(relative).is_some());
            }
            let mut components = relative.split('/');
            matches!(
                (
                    components.next(),
                    components.next(),
                    components.next(),
                    components.next()
                ),
                (Some("replays"), Some(attempt), Some(file), None)
                    if replay_attempt_number(attempt).is_some()
                        && REPLAY_REQUIRED.contains(&file)
            )
        }
    }
}

fn scenario_directory_allowed(relative: &str) -> bool {
    if relative == "replays" {
        return true;
    }
    let mut components = relative.split('/');
    matches!(
        (components.next(), components.next(), components.next()),
        (Some("replays"), Some(attempt), None) if replay_attempt_number(attempt).is_some()
    )
}

fn legacy_unlisted_allowed(scope: InventoryScope, relative: &str) -> bool {
    match scope {
        InventoryScope::Run => {
            LEGACY_RUN_UNLISTED.contains(&relative) || scenario_checksum_binding(relative)
        }
        InventoryScope::Scenario => LEGACY_SCENARIO_UNLISTED.contains(&relative),
    }
}

fn scenario_checksum_binding(relative: &str) -> bool {
    let mut components = relative.split('/');
    matches!(
        (
            components.next(),
            components.next(),
            components.next(),
            components.next()
        ),
        (Some("scenarios"), Some(scenario_id), Some("checksums.txt"), None)
            if validate_identifier(scenario_id, "scenario_id").is_ok()
    )
}

fn normalize_checksum(raw: &str, format: ChecksumFormat) -> Option<String> {
    match format {
        ChecksumFormat::CurrentV2 => {
            validate_sha256(raw).ok()?;
            Some(raw.to_string())
        }
        ChecksumFormat::LegacyV1 => {
            let bare = raw.strip_prefix("sha256:").unwrap_or(raw);
            if bare.len() != 64 || !bare.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            Some(format!("sha256:{}", bare.to_ascii_lowercase()))
        }
    }
}

fn normalize_workspace_hash(raw: &str) -> Option<String> {
    let bare = raw
        .strip_prefix("sha256:sha256:")
        .or_else(|| raw.strip_prefix("sha256:"))
        .unwrap_or(raw);
    if bare.len() != 64 || !bare.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", bare.to_ascii_lowercase()))
}

fn attempt_log_number(name: &str) -> Option<u32> {
    let number = name
        .strip_prefix("stdout.attempt")
        .or_else(|| name.strip_prefix("stderr.attempt"))?
        .strip_suffix(".log")?;
    canonical_positive_number(number)
}

fn replay_attempt_number(name: &str) -> Option<u32> {
    canonical_positive_number(name.strip_prefix("attempt-")?)
}

fn canonical_positive_number(raw: &str) -> Option<u32> {
    if raw.is_empty()
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return None;
    }
    let number = raw.parse::<u32>().ok()?;
    (number > 0).then_some(number)
}

fn require_regular_file(path: &Path, label: &str, errors: &mut Vec<String>) -> Result<()> {
    let _ = regular_file_metadata(path, label, errors)?;
    Ok(())
}

fn regular_file_metadata(
    path: &Path,
    label: &str,
    errors: &mut Vec<String>,
) -> Result<Option<std::fs::Metadata>> {
    let path = match validate_existing_ancestors(path) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error.to_string());
            return Ok(None);
        }
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            errors.push(format!("{label} is missing: {}", path.display()));
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) {
        errors.push(format!(
            "{label} is a symlink/reparse point: {}",
            path.display()
        ));
        return Ok(None);
    }
    if !metadata.is_file() {
        errors.push(format!("{label} is not a regular file: {}", path.display()));
        return Ok(None);
    }
    Ok(Some(metadata))
}

fn safe_metadata_report(
    path: &Path,
    errors: &mut Vec<String>,
) -> Result<Option<std::fs::Metadata>> {
    let path = match validate_existing_ancestors(path) {
        Ok(path) => path,
        Err(error) => {
            errors.push(error.to_string());
            return Ok(None);
        }
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) {
        errors.push(format!(
            "refusing symlink/reparse point: {}",
            path.display()
        ));
        return Ok(None);
    }
    Ok(Some(metadata))
}

fn safe_metadata(path: &Path) -> Result<std::fs::Metadata> {
    let path = validate_existing_ancestors(path)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata_is_alias(&metadata) {
        return Err(TcError::InvalidState(format!(
            "refusing symlink/reparse point: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn ensure_directory_no_alias(path: &Path) -> Result<()> {
    let metadata = safe_metadata(path)?;
    if !metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "expected directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn utf8_file_name(entry: &std::fs::DirEntry) -> Result<String> {
    entry
        .file_name()
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| {
            TcError::InvalidState(format!(
                "filesystem entry name is not UTF-8: {}",
                entry.path().display()
            ))
        })
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    path.strip_prefix(root)
        .map_err(|_| {
            TcError::InvalidState(format!(
                "path escapes inventory root {}: {}",
                root.display(),
                path.display()
            ))
        })
        .and_then(|relative| {
            relative
                .to_str()
                .map(|value| value.replace('\\', "/"))
                .ok_or_else(|| {
                    TcError::InvalidState(format!(
                        "inventory path is not UTF-8: {}",
                        path.display()
                    ))
                })
        })
}

fn validate_single_component(name: &str) -> Result<()> {
    validate_identifier(name, "path component").map_err(TcError::InvalidState)
}

fn scope_name(scope: InventoryScope) -> &'static str {
    match scope {
        InventoryScope::Run => "run",
        InventoryScope::Scenario => "scenario",
    }
}

pub fn find_run_dir(cwd: &Path, run_id: &str) -> PathBuf {
    if validate_identifier(run_id, "run_id").is_err() {
        return PathBuf::from("__tomorrowci_invalid_run_identifier__");
    }
    let cwd = match validate_existing_ancestors(cwd) {
        Ok(cwd) => cwd,
        Err(_) => return PathBuf::from("__tomorrowci_unsafe_search_root__"),
    };
    let relative = format!(".tomorrowci/runs/{run_id}");
    let direct = match safe_join(&cwd, &relative) {
        Ok(path) => path,
        Err(_) => return PathBuf::from("__tomorrowci_unsafe_run_path__"),
    };
    if direct.exists() {
        return direct;
    }
    let fixture_relative = format!("fixtures/python-runtime-break/.tomorrowci/runs/{run_id}");
    let mut candidates = vec![direct.clone()];
    if let Ok(path) = safe_join(&cwd, &fixture_relative) {
        candidates.push(path);
    }
    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }
    direct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvidenceLayout;
    use tempfile::{tempdir, TempDir};

    fn strict_test_config() -> Config {
        let mut config = Config::default();
        config.execution.max_scenarios = 1;
        config.execution.timeout_seconds = 60;
        config.sandbox.memory_mb = 128;
        config.sandbox.cpus = 1.0;
        config.sandbox.pids_limit = 64;
        config.candidates.dependencies.latest_allowed = false;
        config
    }

    fn minimal_run_json(run_root: &Path) -> serde_json::Value {
        let config = strict_test_config();
        let config_hash = config.content_hash().unwrap();
        serde_json::json!({
            "evidence_schema_version": 2,
            "run_id": "r1",
            "tool_version": env!("CARGO_PKG_VERSION"),
            "started_at": "2026-08-09T00:00:00Z",
            "finished_at": "2026-08-09T00:00:01Z",
            "repository": {
                "source": "local:fixture",
                "path": run_root,
                "commit_sha": null,
                "is_disposable_copy": true
            },
            "config_hash": config_hash,
            "detection": {
                "ecosystem": "python",
                "manifests": [],
                "package_manager": "pip",
                "confidence": 1.0,
                "notes": []
            },
            "baseline": {
                "runtime": "3.9",
                "dependencies": "locked",
                "declared_by": "test"
            },
            "plan": {
                "plan_id": "plan",
                "scenarios": [],
                "selection_notes": [],
                "budget_max": 1
            },
            "results": [],
            "frontier": {
                "observed": false,
                "horizon_label": null,
                "first_failing_scenario": null,
                "last_passing_scenario": null,
                "changed_axes": [],
                "failure_signature": null,
                "grade": "INCONCLUSIVE",
                "replay_command": null,
                "notes": ["No observed breakage horizon: baseline is not BASELINE_PASS."]
            },
            "evidence_root": run_root,
            "identity": {
                "source_commit": null,
                "dirty_tree": null,
                "tool_version": env!("CARGO_PKG_VERSION"),
                "adapter_name": "python",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "config_hash": config_hash,
                "manifest_hashes": {},
                "container_engine": null,
                "container_engine_version": null,
                "started_at": "2026-08-09T00:00:00Z",
                "finished_at": "2026-08-09T00:00:01Z"
            }
        })
    }

    fn valid_run() -> (TempDir, PathBuf) {
        let temp = tempdir().unwrap();
        let layout = EvidenceLayout::create(temp.path(), "r1").unwrap();
        let workspace = layout.run_root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("source.txt"), "source\n").unwrap();
        write_workspace_manifest(&workspace, &layout.run_root.join("workspace-manifest.json"))
            .unwrap();
        let run_json = minimal_run_json(&layout.run_root);
        std::fs::write(
            layout.run_root.join("run.json"),
            serde_json::to_string_pretty(&run_json).unwrap(),
        )
        .unwrap();
        for name in RUN_REQUIRED {
            if matches!(
                *name,
                "run.json" | "workspace-manifest.json" | "checksums.txt"
            ) {
                continue;
            }
            let value = match *name {
                "repository.json" => run_json["repository"].clone(),
                "config.normalized.json" => serde_json::to_value(strict_test_config()).unwrap(),
                "candidates.json" | "plan-decisions.json" | "verdicts.json" => {
                    serde_json::json!([])
                }
                "plan.json" => run_json["plan"].clone(),
                "frontier.json" => run_json["frontier"].clone(),
                "metrics.json" => serde_json::json!({
                    "run_id": "r1",
                    "recorded_at": "2026-08-09T00:00:01Z",
                    "scenarios_total": 0,
                    "scenarios_pass": 0,
                    "scenarios_fail": 0,
                    "scenarios_flaky": 0,
                    "scenarios_blocked": 0,
                    "scenarios_unsupported": 0,
                    "scenarios_inconclusive": 0,
                    "baseline_ok": false,
                    "frontier_observed": false,
                    "total_duration_ms": 0,
                    "mean_duration_ms": 0.0,
                    "evidence_grade": "Observed",
                    "ecosystem": "Python",
                    "wall_ms": null,
                    "verdict_histogram": {}
                }),
                "claims.json" => serde_json::json!({"rows": []}),
                "report.json" => run_json.clone(),
                _ => {
                    std::fs::write(layout.run_root.join(name), "focused\n").unwrap();
                    continue;
                }
            };
            std::fs::write(
                layout.run_root.join(name),
                serde_json::to_string_pretty(&value).unwrap(),
            )
            .unwrap();
        }
        finalize_run_checksums(&layout.run_root).unwrap();
        let report = verify_run_root(&layout.run_root).unwrap();
        assert!(report.ok, "{:?}", report.errors);
        (temp, layout.run_root)
    }

    fn add_scenario(run_root: &Path, replay: bool) -> PathBuf {
        let digest = format!("sha256:{}", "a".repeat(64));
        let scenario_value = serde_json::json!({
            "id": "baseline",
            "is_baseline": true,
            "runtime": "3.9",
            "dependencies": "locked",
            "axes_changed": [],
            "candidates": [],
            "grade": "OBSERVED"
        });
        let result_value = serde_json::json!({
            "scenario_id": "baseline",
            "attempt": 1,
            "verdict": "BASELINE_PASS",
            "exit_code": 0,
            "duration_ms": 1,
            "timed_out": false,
            "failure": null,
            "environment": {
                "image_tag": "python:3.9",
                "image": "python:3.9",
                "image_digest": digest,
                "workdir": "/work",
                "env": {},
                "network_mode": "none",
                "memory_mb": 128,
                "cpus": 1.0,
                "pids_limit": 64,
                "user": null,
                "read_only_root": true,
                "scenario_state_root": null,
                "fetch_timeout_seconds": 60,
                "test_timeout_seconds": 60,
                "engine": "docker",
                "engine_version": "test"
            },
            "commands": []
        });

        let run_json_path = run_root.join("run.json");
        let mut run_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&run_json_path).unwrap()).unwrap();
        run_json["plan"]["plan_id"] = serde_json::json!("plan-1");
        run_json["plan"]["scenarios"] = serde_json::json!([scenario_value.clone()]);
        run_json["plan"]["selection_notes"] = serde_json::json!(["planned 1 scenarios (budget 1)"]);
        run_json["results"] = serde_json::json!([result_value.clone()]);
        let scenario_typed: Scenario = serde_json::from_value(scenario_value.clone()).unwrap();
        let result_typed: ExecutionResult = serde_json::from_value(result_value.clone()).unwrap();
        run_json["frontier"] = serde_json::to_value(compute_breakage_frontier(
            true,
            &[(scenario_typed, result_typed)],
            false,
            None,
        ))
        .unwrap();
        run_json["identity"]["container_engine"] = serde_json::json!("docker");
        run_json["identity"]["container_engine_version"] = serde_json::json!("test");
        std::fs::write(
            &run_json_path,
            serde_json::to_string_pretty(&run_json).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("verdicts.json"),
            serde_json::to_string_pretty(&serde_json::json!([result_value.clone()])).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("plan.json"),
            serde_json::to_string_pretty(&run_json["plan"]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("plan-decisions.json"),
            serde_json::to_string_pretty(&serde_json::json!([{
                "scenario_id": "baseline",
                "selected": true,
                "reason": "baseline must run first"
            }]))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("frontier.json"),
            serde_json::to_string_pretty(&run_json["frontier"]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("report.json"),
            serde_json::to_string_pretty(&run_json).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("metrics.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "run_id": "r1",
                "recorded_at": "2026-08-09T00:00:01Z",
                "scenarios_total": 1,
                "scenarios_pass": 1,
                "scenarios_fail": 0,
                "scenarios_flaky": 0,
                "scenarios_blocked": 0,
                "scenarios_unsupported": 0,
                "scenarios_inconclusive": 0,
                "baseline_ok": true,
                "frontier_observed": false,
                "total_duration_ms": 1,
                "mean_duration_ms": 1.0,
                "evidence_grade": "Observed",
                "ecosystem": "Python",
                "wall_ms": null,
                "verdict_histogram": {"BaselinePass": 1}
            }))
            .unwrap(),
        )
        .unwrap();

        let scenario = run_root.join("scenarios").join("baseline");
        std::fs::create_dir_all(&scenario).unwrap();
        let environment = result_value["environment"].clone();
        let replay_descriptor = serde_json::json!({
            "scenario_id": "baseline",
            "engine": "docker",
            "engine_version": "test",
            "image": "python:3.9",
            "image_digest": digest,
            "workdir": "/work",
            "user": null,
            "memory_mb": 128,
            "cpus": 1.0,
            "pids_limit": 64,
            "read_only_root": true,
            "fetch_network": "bridge",
            "test_network": "none",
            "fetch_timeout_seconds": 60,
            "test_timeout_seconds": 60,
            "fetch_argv": [],
            "test_argv": [],
            "expected_exit_code": 0,
            "expected_timed_out": false,
            "expected_failure_signature": null
        });
        let image_phase = serde_json::json!({
            "phase": "image-resolve", "ok": true, "exit_code": 0,
            "timed_out": false, "duration_ms": 1, "network": "n/a",
            "image": "python:3.9", "image_digest": digest, "argv": [],
            "started_at": "2026-08-09T00:00:00.100Z",
            "finished_at": "2026-08-09T00:00:00.200Z", "detail": "ok"
        });
        let test_phase = serde_json::json!({
            "phase": "test", "ok": true, "exit_code": 0,
            "timed_out": false, "duration_ms": 100, "network": "none",
            "image": "python:3.9", "image_digest": digest, "argv": [],
            "started_at": "2026-08-09T00:00:00.300Z",
            "finished_at": "2026-08-09T00:00:00.400Z", "detail": "ok"
        });
        let test_result = serde_json::json!({
            "exit_code": 0, "timed_out": false, "duration_ms": 1,
            "network_used": false,
            "started_at": "2026-08-09T00:00:00.300Z",
            "finished_at": "2026-08-09T00:00:00.400Z"
        });
        let test_attempts = serde_json::json!({
            "scenario_id": "baseline", "status": "completed", "error": null,
            "attempts": [{"attempt": 1,
                "started_at": "2026-08-09T00:00:00.300Z",
                "finished_at": "2026-08-09T00:00:00.400Z",
                "exit_code": 0, "timed_out": false,
                "duration_ms": 1, "failure": null}]
        });
        for (name, value) in [
            ("scenario.json", scenario_value.clone()),
            ("environment.json", environment),
            ("fetch-commands.json", serde_json::json!([])),
            ("test-commands.json", serde_json::json!([])),
            ("commands.json", serde_json::json!([])),
            ("result.json", result_value.clone()),
            ("replay.json", replay_descriptor),
            ("image-resolve-phase.json", image_phase),
            ("test-phase.json", test_phase),
            ("test-result.json", test_result),
            ("test-attempts.json", test_attempts),
        ] {
            std::fs::write(
                scenario.join(name),
                serde_json::to_string_pretty(&value).unwrap(),
            )
            .unwrap();
        }
        for name in [
            "stdout.log",
            "stderr.log",
            "stdout.attempt1.log",
            "stderr.attempt1.log",
            "replay.sh",
            "replay.ps1",
        ] {
            std::fs::write(scenario.join(name), "").unwrap();
        }
        if replay {
            let attempt = scenario.join("replays").join("attempt-1");
            std::fs::create_dir_all(&attempt).unwrap();
            let replay_result = serde_json::json!({
                "scenario_id": "baseline", "attempt": 1, "phase": "test", "ok": true,
                "started_at": "2026-08-09T00:00:02Z", "finished_at": "2026-08-09T00:00:03Z",
                "original_exit": 0, "fetch_exit": null, "replay_exit": 0,
                "timed_out": false, "duration_ms": 1, "original_signature": null,
                "replay_signature": null, "exit_match": true, "signature_match": true,
                "recorded_digest": digest, "resolved_digest": digest,
                "engine": "docker", "engine_version": "test", "image_tag": "python:3.9",
                "fetch_timeout_seconds": 60, "test_timeout_seconds": 60, "error": null
            });
            std::fs::write(
                attempt.join("result.json"),
                serde_json::to_string_pretty(&replay_result).unwrap(),
            )
            .unwrap();
            std::fs::write(
                scenario.join("replay-result.json"),
                serde_json::to_string_pretty(&replay_result).unwrap(),
            )
            .unwrap();
            std::fs::write(attempt.join("stdout.log"), "").unwrap();
            std::fs::write(attempt.join("stderr.log"), "").unwrap();
        }
        finalize_run_checksums(run_root).unwrap();
        let report = verify_run_root(run_root).unwrap();
        assert!(report.ok, "{:?}", report.errors);
        scenario
    }

    fn strip_header(path: &Path) {
        let raw = std::fs::read_to_string(path).unwrap();
        let rewritten = raw
            .lines()
            .filter(|line| line.trim() != CHECKSUM_FORMAT_V2)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(path, rewritten).unwrap();
    }

    #[test]
    fn verifier_rejects_missing_claims() {
        let directory = tempdir().unwrap();
        let layout = EvidenceLayout::create(directory.path(), "r1").unwrap();
        let report = verify_run_root(&layout.run_root).unwrap();
        assert!(!report.ok);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("claims.json")));
    }

    #[test]
    fn current_v2_valid_bundle_passes() {
        let (_temp, run_root) = valid_run();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report.ok, "{:?}", report.errors);
        assert_eq!(
            report.checksum_compatibility,
            ChecksumCompatibility::CurrentV2
        );
    }

    #[test]
    fn rejects_inconsistent_fresh_workspace_receipts() {
        for mutation in [
            "none",
            "missing",
            "writable-seed",
            "wrong-copy",
            "network",
            "image",
            "failed",
            "descriptor",
            "raw-mirror",
            "legacy-uplift",
            "replay-missing",
        ] {
            let (_temp, root) = valid_run();
            let scenario = add_scenario(&root, true);
            let preparation = serde_json::json!({
                "strategy": "fresh_prepared_copy_v1", "seed_mount": "/tomorrowci-seed",
                "seed_read_only": true, "destination_mount": "/work",
                "argv": tomorrowci_core::prepared_workspace_copy_argv(),
                "image_digest": format!("sha256:{}", "a".repeat(64)), "network": "none",
                "exit_code": 0, "timed_out": false, "duration_ms": 0, "stdout": "", "stderr": ""
            });
            let update = |name: &str, f: &dyn Fn(&mut serde_json::Value)| {
                let path = scenario.join(name);
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                f(&mut value);
                std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            };
            update("replay.json", &|v| {
                v["workspace_isolation"] = "fresh_prepared_copy_v1".into()
            });
            update("test-attempts.json", &|v| {
                v["workspace_isolation"] = "fresh_prepared_copy_v1".into();
                v["attempts"][0]["workspace_preparation"] = preparation.clone();
            });
            update("test-result.json", &|v| {
                v["workspace_preparation"] = preparation.clone()
            });
            for name in ["replay-result.json", "replays/attempt-1/result.json"] {
                update(name, &|v| v["workspace_preparation"] = preparation.clone());
            }
            match mutation {
                "none" => {}
                "descriptor" => update("replay.json", &|v| {
                    v["workspace_isolation"] = serde_json::Value::Null
                }),
                "raw-mirror" => update("test-result.json", &|v| {
                    v["workspace_preparation"] = serde_json::Value::Null
                }),
                "legacy-uplift" => {
                    update("replay.json", &|v| {
                        v["workspace_isolation"] = serde_json::Value::Null
                    });
                    update("test-attempts.json", &|v| {
                        v["workspace_isolation"] = serde_json::Value::Null
                    });
                }
                "replay-missing" => {
                    for name in ["replay-result.json", "replays/attempt-1/result.json"] {
                        update(name, &|v| {
                            v["workspace_preparation"] = serde_json::Value::Null
                        });
                    }
                }
                other => update("test-attempts.json", &|v| {
                    let p = &mut v["attempts"][0]["workspace_preparation"];
                    match other {
                        "missing" => *p = serde_json::Value::Null,
                        "writable-seed" => p["seed_read_only"] = false.into(),
                        "wrong-copy" => {
                            p["argv"] =
                                serde_json::json!(["cp", "-L", "/tomorrowci-seed/.", "/work"])
                        }
                        "network" => p["network"] = "bridge".into(),
                        "image" => p["image_digest"] = format!("sha256:{}", "b".repeat(64)).into(),
                        "failed" => p["exit_code"] = 1.into(),
                        _ => unreachable!(),
                    }
                }),
            }
            finalize_run_checksums(&root).unwrap();
            let report = verify_run_root(&root).unwrap();
            assert_eq!(
                report.ok,
                mutation == "none",
                "{mutation}: {:?}",
                report.errors
            );
        }
    }

    #[test]
    fn pre_schema_current_checksum_bundle_requires_explicit_migration() {
        let (_temp, run_root) = valid_run();
        let run_path = run_root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&run_path).unwrap()).unwrap();
        run["evidence_schema_version"] = serde_json::json!(0);
        std::fs::write(&run_path, serde_json::to_string_pretty(&run).unwrap()).unwrap();
        std::fs::write(
            run_root.join("report.json"),
            serde_json::to_string_pretty(&run).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&run_root).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(!report.ok);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("migration") && error.contains("schema")));
    }

    #[test]
    fn schema_two_is_readable_across_writer_version_changes() {
        let (_temp, run_root) = valid_run();
        let run_path = run_root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&run_path).unwrap()).unwrap();
        run["tool_version"] = serde_json::json!("9.1.0-beta.2");
        run["identity"]["tool_version"] = serde_json::json!("9.1.0-beta.2");
        run["identity"]["adapter_version"] = serde_json::json!("9.1.0-beta.2");
        std::fs::write(&run_path, serde_json::to_string_pretty(&run).unwrap()).unwrap();
        std::fs::write(
            run_root.join("report.json"),
            serde_json::to_string_pretty(&run).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&run_root).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report.ok, "{:?}", report.errors);
    }

    #[test]
    fn mutation_and_listed_missing_are_rejected() {
        let (_temp, run_root) = valid_run();
        std::fs::write(run_root.join("claims.json"), "mutated\n").unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("checksum mutation")));

        std::fs::remove_file(run_root.join("claims.json")).unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("lists missing")));
    }

    #[test]
    fn malformed_duplicate_and_traversal_entries_are_rejected() {
        let (_temp, run_root) = valid_run();
        let checksums = run_root.join("checksums.txt");
        let first_entry = std::fs::read_to_string(&checksums)
            .unwrap()
            .lines()
            .find(|line| !line.starts_with('#'))
            .unwrap()
            .to_string();
        let mut raw = std::fs::read_to_string(&checksums).unwrap();
        raw.push_str(&first_entry);
        raw.push('\n');
        raw.push_str("not-a-checksum\n");
        raw.push_str(&format!("sha256:{}  ../outside\n", "0".repeat(64)));
        std::fs::write(&checksums, raw).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("duplicate")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("malformed")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("invalid path")));
    }

    #[test]
    fn strict_inventory_rejects_unlisted_known_file() {
        let (_temp, run_root) = valid_run();
        std::fs::write(run_root.join("reduction.json"), "{}\n").unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unlisted run file: reduction.json")));
    }

    #[test]
    fn recursive_scenario_and_replay_mutations_are_rejected() {
        let (_temp, run_root) = valid_run();
        let scenario = add_scenario(&run_root, true);
        std::fs::write(scenario.join("replays/attempt-1/result.json"), "mutated\n").unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report.errors.iter().any(|error| {
            error.contains("checksum mutation") && error.contains("replays/attempt-1/result.json")
        }));
    }

    #[test]
    fn current_v2_header_cannot_be_downgraded_to_legacy() {
        let (_temp, run_root) = valid_run();
        strip_header(&run_root.join("checksums.txt"));

        let report = verify_run_root(&run_root).unwrap();
        assert!(!report.ok);
        assert!(report.errors.iter().any(|error| {
            error.contains("legacy-v1 checksum format is not permitted")
                && error.contains(LEGACY_TOOL_VERSION)
        }));
    }

    #[test]
    fn current_v2_requires_writer_guaranteed_scenario_files() {
        let (_temp, run_root) = valid_run();
        let scenario = add_scenario(&run_root, false);
        std::fs::remove_file(scenario.join("fetch-commands.json")).unwrap();
        std::fs::remove_file(scenario.join("commands.json")).unwrap();

        let scenario_checksums = scenario.join("checksums.txt");
        let raw = std::fs::read_to_string(&scenario_checksums).unwrap();
        let rewritten = raw
            .lines()
            .filter(|line| {
                !line.ends_with("  fetch-commands.json") && !line.ends_with("  commands.json")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&scenario_checksums, rewritten).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report.errors.iter().any(|error| {
            error.contains("required file fetch-commands.json") && error.contains("missing")
        }));
        assert!(report.errors.iter().any(|error| {
            error.contains("current-v2 file commands.json") && error.contains("missing")
        }));

        let error = finalize_run_checksums(&run_root).unwrap_err();
        assert!(error.to_string().contains("required file"));
    }

    #[test]
    fn run_manifest_binds_each_recursive_scenario_manifest() {
        let (_temp, run_root) = valid_run();
        let scenario = add_scenario(&run_root, false);
        let scenario_checksums = scenario.join("checksums.txt");
        let mut raw = std::fs::read_to_string(&scenario_checksums).unwrap();
        raw.push('\n');
        std::fs::write(&scenario_checksums, raw).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report.errors.iter().any(|error| {
            error.contains("checksum mutation")
                && error.contains("scenarios/baseline/checksums.txt")
        }));
    }

    #[test]
    fn scenario_results_and_verdicts_require_exact_closure() {
        {
            let (_temp, run_root) = valid_run();
            let scenario = add_scenario(&run_root, false);
            std::fs::remove_dir_all(scenario).unwrap();
            let report = verify_run_root(&run_root).unwrap();
            assert!(report.errors.iter().any(|error| {
                error.contains("scenario directories missing scenario present in run.json results")
            }));
        }

        {
            let (_temp, run_root) = valid_run();
            std::fs::create_dir_all(run_root.join("scenarios/orphan")).unwrap();
            let report = verify_run_root(&run_root).unwrap();
            assert!(report
                .errors
                .iter()
                .any(|error| { error.contains("scenario directories contains orphan scenario") }));
        }

        {
            let (_temp, run_root) = valid_run();
            let scenario = add_scenario(&run_root, false);
            let result_path = scenario.join("result.json");
            let mut result: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&result_path).unwrap()).unwrap();
            result["duration_ms"] = serde_json::json!(999);
            std::fs::write(&result_path, serde_json::to_string_pretty(&result).unwrap()).unwrap();
            let report = verify_run_root(&run_root).unwrap();
            assert!(report
                .errors
                .iter()
                .any(|error| { error.contains("result.json does not match run.json results") }));
            assert!(report
                .errors
                .iter()
                .any(|error| { error.contains("result.json does not match verdicts.json") }));
        }
    }

    #[test]
    fn baseline_pass_requires_a_result_for_every_planned_scenario() {
        let (_temp, run_root) = valid_run();
        add_scenario(&run_root, false);

        let run_path = run_root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&run_path).unwrap()).unwrap();
        run["plan"]["scenarios"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "future",
                "is_baseline": false,
                "runtime": "3.10",
                "dependencies": "locked",
                "axes_changed": ["runtime"],
                "candidates": ["future"],
                "grade": "OBSERVED"
            }));
        std::fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        std::fs::write(
            run_root.join("plan.json"),
            serde_json::to_vec_pretty(&run["plan"]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("report.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&run_root).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report.errors.iter().any(|error| {
            error.contains(
                "baseline passed but run.json results are missing planned scenario: future",
            )
        }));
    }

    #[test]
    fn run_lookup_and_verification_reject_path_components() {
        let directory = tempdir().unwrap();
        for run_id in [
            "",
            ".",
            "..",
            "../escape",
            "nested/run",
            r"nested\run",
            r"C:\escape",
            r"\\server\share",
        ] {
            assert_eq!(
                find_run_dir(directory.path(), run_id),
                PathBuf::from("__tomorrowci_invalid_run_identifier__"),
                "{run_id:?} must not participate in a filesystem join"
            );
            assert!(verify_run(directory.path(), run_id).is_err());
        }
    }

    #[test]
    fn legacy_v1_allows_only_documented_historical_omissions() {
        let (_temp, run_root) = valid_run();
        let scenario = add_scenario(&run_root, false);
        let run_json_path = run_root.join("run.json");
        let mut run_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&run_json_path).unwrap()).unwrap();
        run_json["tool_version"] = serde_json::json!(LEGACY_TOOL_VERSION);
        run_json["evidence_schema_version"] = serde_json::json!(0);
        run_json["identity"]["tool_version"] = serde_json::json!(LEGACY_TOOL_VERSION);
        std::fs::write(
            &run_json_path,
            serde_json::to_string_pretty(&run_json).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run_root.join("report.json"),
            serde_json::to_string_pretty(&run_json).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&run_root).unwrap();

        let scenario_checksums = scenario.join("checksums.txt");
        let raw = std::fs::read_to_string(&scenario_checksums).unwrap();
        let rewritten = raw
            .lines()
            .filter(|line| line.trim() != CHECKSUM_FORMAT_V2 && !line.ends_with("  commands.json"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&scenario_checksums, rewritten).unwrap();

        let root_checksums = run_root.join("checksums.txt");
        let raw = std::fs::read_to_string(&root_checksums).unwrap();
        let rewritten = raw
            .lines()
            .filter(|line| {
                line.trim() != CHECKSUM_FORMAT_V2
                    && !line.ends_with("  scenarios/baseline/checksums.txt")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&root_checksums, rewritten).unwrap();

        let report = verify_run_root(&run_root).unwrap();
        assert!(report.ok, "{:?}", report.errors);
        assert_eq!(
            report.checksum_compatibility,
            ChecksumCompatibility::LegacyV1ReadCompatible
        );

        std::fs::write(scenario.join("replay-result.json"), "{}\n").unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unlisted scenario file")));
    }

    #[test]
    fn legacy_workspace_double_prefix_is_normalized_for_read_compatibility() {
        let hex = "a".repeat(64);
        assert_eq!(
            normalize_workspace_hash(&format!("sha256:sha256:{hex}")),
            Some(format!("sha256:{hex}"))
        );
    }

    #[test]
    fn workspace_unlisted_and_mutated_files_are_rejected() {
        let (_temp, run_root) = valid_run();
        let workspace = run_root.join("workspace");
        std::fs::write(workspace.join("source.txt"), "changed\n").unwrap();
        std::fs::write(workspace.join("extra.txt"), "extra\n").unwrap();
        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("workspace-manifest hash mismatch")));
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("workspace contains unlisted")));
    }

    #[test]
    fn symlink_or_reparse_entries_are_rejected_when_supported() {
        let (_temp, run_root) = valid_run();
        let target = run_root.join("claims.json");
        let alias = run_root.join("reduction.json");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&target, &alias).is_err() {
            return;
        }

        let report = verify_run_root(&run_root).unwrap();
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("symlink/reparse")));
    }

    #[test]
    fn explicit_runtime_intent_cannot_be_replaced_by_consistent_candidate_metadata() {
        let baseline = tomorrowci_core::Baseline {
            runtime: "3.13".into(),
            dependencies: "locked".into(),
            declared_by: "config".into(),
        };
        let mut config = Config::default();
        config.candidates.runtime.versions = Some(vec!["3.14".into()]);
        let mut candidate = Candidate {
            id: "py314-locked".into(),
            axis: EnvironmentAxis::Runtime,
            label: "Python 3.14 + locked dependencies".into(),
            version: "3.14".into(),
            channel: "stable".into(),
            grade_if_executed: EvidenceGrade::Observed,
            order_key: "003.014".into(),
            dependency_set: None,
        };
        let mut errors = Vec::new();
        verify_explicit_runtime_candidates(
            &baseline,
            Ecosystem::Python,
            &config,
            &[candidate.clone()],
            &mut errors,
        );
        assert!(errors.is_empty(), "{errors:?}");
        // Even an internally consistent replacement must not satisfy the user's request.
        candidate.id = "py312-locked".into();
        candidate.version = "3.12".into();
        candidate.label = "Python 3.12 + locked dependencies".into();
        candidate.order_key = "003.012".into();
        verify_explicit_runtime_candidates(
            &baseline,
            Ecosystem::Python,
            &config,
            &[candidate.clone()],
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("differs from explicit configured version")));
        errors.clear();
        config.candidates.runtime.versions = Some(vec![]);
        verify_explicit_runtime_candidates(
            &baseline,
            Ecosystem::Python,
            &config,
            &[candidate],
            &mut errors,
        );
        assert!(errors
            .iter()
            .any(|error| error.contains("candidate count differs")));
    }

    #[test]
    fn dependency_runtime_mismatch_is_rejected_even_with_a_pinned_image() {
        let mut scenario = Scenario {
            id: "py312-locked".into(),
            is_baseline: false,
            runtime: "3.12".into(),
            dependencies: "baseline".into(),
            axes_changed: vec![EnvironmentAxis::Runtime],
            candidates: vec!["py312-locked".into()],
            grade: EvidenceGrade::Observed,
            resolved_dependencies: None,
        };
        let mut errors = Vec::new();
        verify_dependency_runtime(&scenario, "3.11", &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("mixed-runtime dependency evidence is unsupported"));
        scenario.runtime = "3.11".into();
        errors.clear();
        verify_dependency_runtime(&scenario, "3.11", &mut errors);
        assert!(errors.is_empty());
    }

    #[test]
    fn dependency_artifacts_and_exhaustive_probe_order_are_rederived() {
        let workspace = tempdir().unwrap();
        for source in ["contract-v1", "contract-v2", "noise-v1", "noise-v2"] {
            let directory = workspace.path().join("vendor").join(source);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("payload.txt"), format!("{source}\n")).unwrap();
        }
        let hash =
            |source: &str| sha256_tree_v1(&workspace.path().join("vendor").join(source)).unwrap();
        let experiment: DependencyExperimentManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "ecosystem": "python",
            "runtime": {
                "version": "3.11",
                "container_image": format!("python@sha256:{}", "a".repeat(64))
            },
            "content_hash_algorithm": "sha256-tree-v1",
            "baseline": { "set_id": "baseline" },
            "candidate": {
                "set_id": "candidate",
                "changes": [
                    {
                        "id": "breaking-api",
                        "name": "contract",
                        "before": { "version": "1", "source": "vendor/contract-v1", "content_sha256": hash("contract-v1") },
                        "after": { "version": "2", "source": "vendor/contract-v2", "content_sha256": hash("contract-v2") }
                    },
                    {
                        "id": "irrelevant-noise",
                        "name": "noise",
                        "before": { "version": "1", "source": "vendor/noise-v1", "content_sha256": hash("noise-v1") },
                        "after": { "version": "2", "source": "vendor/noise-v2", "content_sha256": hash("noise-v2") }
                    }
                ]
            }
        }))
        .unwrap();
        let declared = experiment.to_candidate_set("pip").unwrap();
        let mut errors = Vec::new();
        let probes = expected_dependency_probes(&experiment, &declared, &mut errors).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            probes.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec!["candidate", "ddmin-breaking-api", "ddmin-irrelevant-noise"]
        );
        verify_dependency_artifacts(workspace.path(), &experiment, &mut errors).unwrap();
        assert!(errors.is_empty(), "{errors:?}");

        std::fs::write(
            workspace.path().join("vendor/contract-v2/payload.txt"),
            "mutated\n",
        )
        .unwrap();
        verify_dependency_artifacts(workspace.path(), &experiment, &mut errors).unwrap();
        assert!(errors
            .iter()
            .any(|error| error.contains("content hash mismatch")));
    }

    fn wheel_experiment(workspace: &Path) -> DependencyExperimentManifest {
        std::fs::create_dir_all(workspace.join("wheels")).unwrap();
        let artifact = |name: &str, version: &str| {
            let source = format!("wheels/{name}-{version}.whl");
            let bytes = format!("wheel bytes for {name} {version}");
            std::fs::write(workspace.join(&source), bytes).unwrap();
            serde_json::json!({
                "version": version,
                "source": source,
                "content_sha256": sha256_file_v1(&workspace.join(&source)).unwrap()
            })
        };
        serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "ecosystem": "python",
            "runtime": { "version": "3.11", "container_image": format!("python@sha256:{}", "a".repeat(64)) },
            "content_hash_algorithm": "sha256-file-v1",
            "baseline": { "set_id": "baseline" },
            "candidate": {
                "set_id": "candidate",
                "changes": (["a", "b", "c"].iter().map(|name| serde_json::json!({
                    "id": name, "name": name,
                    "before": artifact(name, "1"), "after": artifact(name, "2")
                })).collect::<Vec<_>>())
            },
            "unchanged": [{ "id": "fixed", "name": "fixed", "artifact": artifact("fixed", "1") }]
        })).unwrap()
    }

    fn adaptive_schedule_fixture(
        workspace: &Path,
        subsets: &[&[&str]],
    ) -> (
        DependencyExperimentManifest,
        DependencyCandidateSet,
        Vec<Candidate>,
        RunManifest,
        Config,
    ) {
        let experiment = wheel_experiment(workspace);
        let declared = experiment.to_candidate_set("pip").unwrap();
        let original_ids: Vec<_> = declared
            .changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        let candidates: Vec<_> = subsets
            .iter()
            .enumerate()
            .map(|(index, subset)| {
                let subset_ids: Vec<String> = subset.iter().map(|id| (*id).into()).collect();
                let id = adaptive_dependency_probe_id(
                    &experiment.candidate.set_id,
                    &original_ids,
                    &subset_ids,
                )
                .unwrap();
                let changes: Vec<_> = declared
                    .changes
                    .iter()
                    .filter(|change| subset_ids.contains(&change.id))
                    .cloned()
                    .collect();
                let readable_id = format!("{}--{id}", experiment.candidate.set_id);
                let mut resolution = declared.resolution_for_changes(&changes).unwrap();
                resolution.set_id = readable_id.clone();
                let set = DependencyCandidateSet {
                    set_id: readable_id.clone(),
                    baseline: declared.baseline.clone(),
                    candidate: resolution,
                    changes,
                };
                set.validate().unwrap();
                Candidate {
                    id: id.clone(),
                    axis: EnvironmentAxis::Dependencies,
                    label: format!(
                        "3.11 dependency probe {id} ({})",
                        set.stable_identity().unwrap()
                    ),
                    version: readable_id,
                    channel: "content-addressed".into(),
                    grade_if_executed: EvidenceGrade::Observed,
                    order_key: format!("{index:04}"),
                    dependency_set: Some(set),
                }
            })
            .collect();
        let mut config = strict_test_config();
        config.execution.max_scenarios = 24;
        config.execution.reruns_on_failure = 3;
        config.candidates.runtime.max_versions = 0;
        let mut manifest: RunManifest =
            serde_json::from_value(minimal_run_json(workspace)).unwrap();
        manifest.baseline.runtime = "3.11".into();
        manifest.baseline.dependencies = declared.baseline.set_id.clone();
        manifest.plan = plan_scenarios(&manifest.baseline, &[], &candidates, &config).0;
        manifest.results = manifest.plan.scenarios.iter().map(|scenario| {
            let fails = !scenario.is_baseline && candidates.iter().find(|candidate| candidate.id == scenario.id).unwrap()
                .dependency_set.as_ref().unwrap().changes.iter().any(|change| change.id == "c");
            ExecutionResult {
                scenario_id: scenario.id.clone(), attempt: if fails { 3 } else { 1 },
                verdict: if scenario.is_baseline { Verdict::BaselinePass } else if fails { Verdict::FutureFail } else { Verdict::FuturePass },
                exit_code: Some(if fails { 1 } else { 0 }), duration_ms: 1, timed_out: false,
                failure: fails.then(|| FailureSignature {
                    kind: "test".into(), summary: "same concrete cause".into(),
                    normalized_hash: ContentHash::of_bytes(b"same concrete cause").as_str().into(), primary_frame: None,
                }),
                environment: serde_json::from_value(serde_json::json!({
                    "image": "python:3.11", "image_tag": "python:3.11", "image_digest": experiment.runtime.container_image,
                    "workdir": "/work", "env": {}, "network_mode": "none", "memory_mb": 128,
                    "cpus": 1.0, "pids_limit": 64, "user": null, "read_only_root": true
                })).unwrap(),
                commands: vec![],
            }
        }).collect();
        (experiment, declared, candidates, manifest, config)
    }

    fn adaptive_errors(
        experiment: &DependencyExperimentManifest,
        declared: &DependencyCandidateSet,
        candidates: &[Candidate],
        manifest: &RunManifest,
        config: &Config,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        expected_adaptive_dependency_probes(
            experiment,
            declared,
            &candidates.iter().collect::<Vec<_>>(),
            manifest,
            config,
            &mut errors,
        )
        .unwrap();
        errors
    }

    #[test]
    fn adaptive_probe_sequence_is_rederived_from_each_observation_prefix() {
        let workspace = tempdir().unwrap();
        let (experiment, declared, candidates, manifest, config) = adaptive_schedule_fixture(
            workspace.path(),
            &[&["a", "b", "c"], &["b", "c"], &["c"], &["a", "c"]],
        );
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config).is_empty()
        );

        let mut reordered_results = manifest.clone();
        reordered_results.results.swap(2, 3);
        assert!(adaptive_errors(
            &experiment,
            &declared,
            &candidates,
            &reordered_results,
            &config
        )
        .iter()
        .any(|error| error.contains("out of order")));

        // All these subsets really fail with the same hash, but that does not
        // authorize choosing them before the scheduler requests them.
        for forged in [
            vec![&["a", "b", "c"][..], &["c"], &["a", "c"]],
            vec![&["a", "b", "c"][..], &["a", "c"], &["c"], &["b", "c"]],
        ] {
            let (experiment, declared, candidates, manifest, config) =
                adaptive_schedule_fixture(workspace.path(), &forged);
            assert!(
                adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                    .iter()
                    .any(|error| error.contains("out of order"))
            );
        }
    }

    #[test]
    fn adaptive_missing_next_probe_requires_actual_budget_exhaustion() {
        let workspace = tempdir().unwrap();
        let (experiment, declared, candidates, mut manifest, mut config) =
            adaptive_schedule_fixture(workspace.path(), &[&["a", "b", "c"], &["b", "c"], &["c"]]);
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                .iter()
                .any(|error| error.contains("omits a required next probe"))
        );
        config.execution.max_scenarios = 4;
        manifest.plan = plan_scenarios(&manifest.baseline, &[], &candidates, &config).0;
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config).is_empty()
        );
        config.execution.max_scenarios = 5;
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                .iter()
                .any(|error| error.contains("budget differs"))
        );
    }

    #[test]
    fn adaptive_extra_probe_and_missing_execution_are_rejected() {
        let workspace = tempdir().unwrap();
        let (experiment, declared, candidates, mut manifest, config) = adaptive_schedule_fixture(
            workspace.path(),
            &[&["a", "b", "c"], &["b", "c"], &["c"], &["a", "c"], &["a"]],
        );
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                .iter()
                .any(|error| error.contains("after scheduling stopped"))
        );
        manifest.results.truncate(1);
        assert!(
            adaptive_errors(&experiment, &declared, &candidates[..1], &manifest, &config)
                .iter()
                .any(|error| error.contains("no executed result"))
        );
    }

    #[test]
    fn adaptive_baseline_failure_allows_only_unexecuted_full_seed() {
        let workspace = tempdir().unwrap();
        let (experiment, declared, candidates, mut manifest, mut config) =
            adaptive_schedule_fixture(workspace.path(), &[&["a", "b", "c"]]);
        manifest.results.truncate(1);
        manifest.results[0].verdict = Verdict::Blocked;
        manifest.results[0].attempt = 0;
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config).is_empty()
        );
        manifest.results.push(manifest.results[0].clone());
        manifest.results[1].scenario_id = candidates[0].id.clone();
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                .iter()
                .any(|error| error.contains("without an observed passing baseline"))
        );
        manifest.results.truncate(1);
        config.execution.reruns_on_failure = 2;
        assert!(
            adaptive_errors(&experiment, &declared, &candidates, &manifest, &config)
                .iter()
                .any(|error| error.contains("at least three failure attempts"))
        );
    }

    #[test]
    fn wheel_artifact_tampering_including_unchanged_closure_is_rejected() {
        for relative in ["wheels/a-2.whl", "wheels/fixed-1.whl"] {
            let workspace = tempdir().unwrap();
            let experiment = wheel_experiment(workspace.path());
            let mut errors = Vec::new();
            verify_dependency_artifacts(workspace.path(), &experiment, &mut errors).unwrap();
            assert!(errors.is_empty(), "{errors:?}");
            std::fs::write(workspace.path().join(relative), "altered wheel bytes").unwrap();
            verify_dependency_artifacts(workspace.path(), &experiment, &mut errors).unwrap();
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("content hash mismatch")),
                "{errors:?}"
            );
        }
    }

    #[test]
    fn fetch_and_replay_network_are_bound_to_the_concrete_dependency_contract() {
        let workspace = tempdir().unwrap();
        let (_, _, _, manifest, _) =
            adaptive_schedule_fixture(workspace.path(), &[&["a", "b", "c"]]);
        for expected_network in ["none", "bridge"] {
            let scenario_root = tempdir().unwrap();
            let mut scenario = manifest.plan.scenarios[0].clone();
            if expected_network == "bridge" {
                scenario.resolved_dependencies = None;
            }
            let result = &manifest.results[0];
            let environment = &result.environment;
            let fetch_commands = dependency_materialization_commands(&scenario)
                .unwrap()
                .unwrap_or_default();
            let argv: Vec<_> = fetch_commands
                .iter()
                .map(|command| command.argv.clone())
                .collect();
            let mut phase = PhaseEvidence {
                phase: "fetch".into(),
                ok: true,
                exit_code: Some(0),
                timed_out: false,
                duration_ms: 1,
                network: expected_network.into(),
                image: environment.tag().into(),
                image_digest: environment.image_digest.clone(),
                argv: argv.clone(),
                started_at: manifest.started_at,
                finished_at: manifest.finished_at.unwrap(),
                detail: "test".into(),
            };
            let mut raw = RawResultSummary {
                workspace_preparation: None,
                exit_code: Some(0),
                timed_out: false,
                duration_ms: 1,
                network_used: expected_network != "none",
                started_at: phase.started_at,
                finished_at: phase.finished_at,
            };
            let write_phase_and_raw = |phase: &PhaseEvidence, raw: &RawResultSummary| {
                std::fs::write(
                    scenario_root.path().join("fetch-phase.json"),
                    serde_json::to_vec(phase).unwrap(),
                )
                .unwrap();
                std::fs::write(
                    scenario_root.path().join("fetch-result.json"),
                    serde_json::to_vec(raw).unwrap(),
                )
                .unwrap();
            };
            write_phase_and_raw(&phase, &raw);
            let mut errors = Vec::new();
            verify_fetch_semantics(
                scenario_root.path(),
                &scenario,
                &fetch_commands,
                result,
                &manifest,
                None,
                &mut errors,
            )
            .unwrap();
            assert!(errors.is_empty(), "{errors:?}");

            phase.network = if expected_network == "none" {
                "bridge"
            } else {
                "none"
            }
            .into();
            raw.network_used = !raw.network_used;
            write_phase_and_raw(&phase, &raw);
            verify_fetch_semantics(
                scenario_root.path(),
                &scenario,
                &fetch_commands,
                result,
                &manifest,
                None,
                &mut errors,
            )
            .unwrap();
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("fetch phase does not bind")),
                "{errors:?}"
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("invalid network/time semantics")),
                "{errors:?}"
            );

            let mut replay = ReplayDescriptor {
                workspace_isolation: None,
                scenario_id: scenario.id.clone(),
                engine: environment.engine.clone(),
                engine_version: environment.engine_version.clone(),
                image: environment.tag().into(),
                image_digest: environment.image_digest.clone(),
                workdir: environment.workdir.clone(),
                user: environment.user.clone(),
                memory_mb: environment.memory_mb,
                cpus: environment.cpus,
                pids_limit: environment.pids_limit,
                read_only_root: environment.read_only_root,
                fetch_network: expected_network.into(),
                test_network: "none".into(),
                fetch_timeout_seconds: environment.fetch_timeout_seconds,
                test_timeout_seconds: environment.test_timeout_seconds,
                fetch_argv: argv,
                test_argv: vec![],
                expected_exit_code: result.exit_code,
                expected_timed_out: result.timed_out,
                expected_failure_signature: result.failure.clone(),
                resolved_dependencies: scenario.resolved_dependencies.clone(),
            };
            errors.clear();
            verify_replay_descriptor(
                &replay,
                &scenario,
                environment,
                result,
                &fetch_commands,
                &[],
                &mut errors,
            )
            .unwrap();
            assert!(errors.is_empty(), "{errors:?}");
            replay.fetch_network = phase.network;
            verify_replay_descriptor(
                &replay,
                &scenario,
                environment,
                result,
                &fetch_commands,
                &[],
                &mut errors,
            )
            .unwrap();
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("replay.json does not exactly bind")),
                "{errors:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn wheel_artifact_alias_is_rejected_even_when_target_hash_matches() {
        let workspace = tempdir().unwrap();
        let external = tempdir().unwrap();
        let experiment = wheel_experiment(workspace.path());
        let wheel = workspace.path().join("wheels/fixed-1.whl");
        let target = external.path().join("fixed-1.whl");
        std::fs::rename(&wheel, &target).unwrap();
        std::os::unix::fs::symlink(&target, &wheel).unwrap();
        let mut errors = Vec::new();
        verify_dependency_artifacts(workspace.path(), &experiment, &mut errors).unwrap();
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .any(|error| error.contains("symlink") || error.contains("alias")),
            "{errors:?}"
        );
    }

    #[test]
    fn dependency_materialization_command_mutation_is_rejected() {
        let dependency = tomorrowci_core::ResolvedDependency {
            id: "breaking-api".into(),
            name: "contract".into(),
            version: "2".into(),
            source: "vendor/contract-v2".into(),
            source_kind: tomorrowci_core::DependencySourceKind::VendoredTreeSha256V1,
            content_sha256: ContentHash::sha256("a".repeat(64)).unwrap(),
        };
        let mut set = ResolvedDependencySet {
            set_id: "candidate".into(),
            ecosystem: Ecosystem::Python,
            package_manager: "pip".into(),
            manifest_sha256: ContentHash::sha256("0".repeat(64)).unwrap(),
            dependencies: vec![dependency],
        };
        set.manifest_sha256 = set.expected_manifest_sha256().unwrap();
        let scenario = Scenario {
            id: "ddmin-breaking-api".into(),
            is_baseline: false,
            runtime: "3.11".into(),
            dependencies: "candidate".into(),
            axes_changed: vec![EnvironmentAxis::Dependencies],
            candidates: vec!["ddmin-breaking-api".into()],
            grade: EvidenceGrade::Observed,
            resolved_dependencies: Some(set),
        };
        let mut recorded = dependency_materialization_commands(&scenario)
            .unwrap()
            .unwrap();
        let mut errors = Vec::new();
        verify_dependency_materialization_contract(&scenario, &recorded, &mut errors).unwrap();
        assert!(errors.is_empty(), "{errors:?}");

        recorded.last_mut().unwrap().argv.pop();
        verify_dependency_materialization_contract(&scenario, &recorded, &mut errors).unwrap();
        assert!(errors
            .iter()
            .any(|error| error.contains("do not materialize its exact dependency set")));
    }
}
