//! Evidence bundle writer and replay manifest consumer.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tomorrowci_core::{
    redaction::redact_secrets, Baseline, BreakageFrontier, Candidate, CommandSpec, Config,
    EnvironmentAxis, EnvironmentSpec, EvidenceGrade, ExecutionPlan, ExecutionResult,
    FailureSignature, ProjectDetection, RawExecutionResult, RepositorySnapshot, RunManifest,
    RunStatus, Scenario, ScenarioKind, ScenarioVerdict, Verdict,
};
use tomorrowci_report::{
    render_html_report_with_version, render_json_report, render_sarif_report_with_version,
    ReportData,
};

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing evidence: {0}")]
    Missing(String),
    #[error("evidence bundle is not sealed with a versioned inventory: {0}")]
    UnsealedLegacy(String),
    #[error("unsupported evidence inventory version: {0}")]
    UnsupportedInventoryVersion(String),
    #[error("malformed evidence inventory at line {line}: {reason}")]
    MalformedInventory { line: usize, reason: String },
    #[error("unsafe evidence path: {0}")]
    UnsafePath(String),
    #[error("duplicate evidence path in inventory: {0}")]
    DuplicatePath(String),
    #[error("non-regular evidence entry: {0}")]
    NonRegularEntry(String),
    #[error("evidence file is not listed in the sealed inventory: {0}")]
    Unlisted(String),
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("invalid typed evidence in {path}: {source}")]
    InvalidJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("evidence identity mismatch for {field}: {detail}")]
    IdentityMismatch { field: String, detail: String },
    #[error("invalid evidence semantics for {field}: {detail}")]
    InvalidSemantics { field: String, detail: String },
    #[error("duplicate {kind} identity: {id}")]
    DuplicateIdentity { kind: String, id: String },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, EvidenceError>;

/// File containing the complete, recursive inventory for a sealed bundle.
pub const INVENTORY_FILE_NAME: &str = "checksums.txt";
/// Current on-disk evidence inventory schema version.
pub const INVENTORY_VERSION: u32 = 1;

const INVENTORY_HEADER_PREFIX: &str = "# tomorrowci-evidence-checksums-v";
const INVENTORY_HEADER_V1_PREFIX: &str = "# tomorrowci-evidence-checksums-v1 kind=";
const INVENTORY_HEADER_V1_SUFFIX: &str = " algorithm=sha256 scope=recursive sealed=true";
const MAX_INVENTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_DEPTH: usize = 64;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_VERIFIED_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TYPED_JSON_BYTES: usize = 16 * 1024 * 1024;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The layout whose required files are enforced by the inventory verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleKind {
    /// A complete TomorrowCI run bundle.
    Run,
    /// The evidence for one recorded scenario.
    Scenario,
    /// A generic bundle with no TomorrowCI-specific required filenames.
    Generic,
}

impl BundleKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Scenario => "scenario",
            Self::Generic => "generic",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "run" => Some(Self::Run),
            "scenario" => Some(Self::Scenario),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }

    fn required_paths(self) -> &'static [&'static str] {
        match self {
            // repository.json binds source and workspace identity; run.json binds the
            // run, tool, engine, and frontier identities. Reports and scenarios are
            // configuration/status dependent and remain exact-inventory protected
            // whenever present.
            Self::Run => &[
                "config.normalized.json",
                "frontier.json",
                "repository.json",
                "run.json",
                "verdicts.json",
            ],
            Self::Scenario => &[
                "commands.json",
                "environment.json",
                "replay-manifest.json",
                "replay.ps1",
                "replay.sh",
                "result.json",
                "scenario.json",
                "stderr.log",
                "stdout.log",
            ],
            Self::Generic => &[],
        }
    }
}

/// One canonical path and SHA-256 digest in a sealed inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub path: String,
    pub sha256: String,
}

/// Parsed representation of `checksums.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInventory {
    pub version: u32,
    pub kind: BundleKind,
    pub entries: Vec<InventoryEntry>,
}

/// Successful verification result. Success means the inventory and filesystem
/// contained exactly the same regular files and every digest matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub root: PathBuf,
    pub version: u32,
    pub kind: BundleKind,
    pub file_count: usize,
    inventory: BundleInventory,
}

impl VerifiedBundle {
    /// Read bytes from the exact inventory generation that produced this
    /// verification result.
    pub fn read_bytes(&self, relative: &str) -> Result<Vec<u8>> {
        validate_inventory_path(relative)?;
        let entry = self
            .inventory
            .entries
            .iter()
            .find(|entry| entry.path == relative)
            .ok_or_else(|| EvidenceError::Missing(format!("{relative} is not inventoried")))?;
        read_verified_bytes(&self.root, entry)
    }

    /// Parse typed JSON from bytes bound to this verified inventory generation.
    pub fn read_json<T: DeserializeOwned>(&self, relative: &str) -> Result<T> {
        let bytes = self.read_bytes(relative)?;
        if bytes.len() > MAX_TYPED_JSON_BYTES {
            return Err(EvidenceError::InvalidSemantics {
                field: relative.to_string(),
                detail: format!("typed JSON exceeds {MAX_TYPED_JSON_BYTES} bytes"),
            });
        }
        serde_json::from_slice(&bytes).map_err(|source| EvidenceError::InvalidJson {
            path: relative.to_string(),
            source,
        })
    }

    /// Return whether this verified inventory contains a path.
    pub fn contains(&self, relative: &str) -> bool {
        self.inventory
            .entries
            .iter()
            .any(|entry| entry.path == relative)
    }
}

pub struct EvidenceStore {
    pub root: PathBuf,
    pub run_id: String,
}

impl EvidenceStore {
    pub fn create(base: &Path, run_id: &str) -> Result<Self> {
        validate_single_component(run_id, "run id")?;
        fs::create_dir_all(base)?;
        ensure_directory(base)?;
        let runs = base.join("runs");
        if !runs.exists() {
            fs::create_dir(&runs)?;
        }
        ensure_directory(&runs)?;
        let root = base.join("runs").join(run_id);
        fs::create_dir(&root).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                EvidenceError::Other(format!(
                    "refusing to overwrite existing run directory: {}",
                    root.display()
                ))
            } else {
                EvidenceError::Io(error)
            }
        })?;
        ensure_directory(&root)?;
        let scenarios = root.join("scenarios");
        fs::create_dir(&scenarios)?;
        ensure_directory(&scenarios)?;
        Ok(Self {
            root,
            run_id: run_id.to_string(),
        })
    }

    pub fn open(base: &Path, run_id: &str) -> Result<Self> {
        validate_single_component(run_id, "run id")?;
        let root = base.join("runs").join(run_id);
        if !root.exists() {
            return Err(EvidenceError::Missing(format!(
                "run directory not found: {}",
                root.display()
            )));
        }
        ensure_directory(&root)?;
        Ok(Self {
            root,
            run_id: run_id.to_string(),
        })
    }

    pub fn write_json<T: Serialize + ?Sized>(&self, name: &str, value: &T) -> Result<PathBuf> {
        self.ensure_unsealed()?;
        validate_inventory_path(name)?;
        if name == INVENTORY_FILE_NAME {
            return Err(EvidenceError::UnsafePath(name.to_string()));
        }
        let path = self.root.join(name);
        let json = serde_json::to_string_pretty(value)?;
        persist_regular_file(&path, json.as_bytes())?;
        Ok(path)
    }

    pub fn write_run_manifest(&self, manifest: &RunManifest) -> Result<()> {
        self.write_json("run.json", &redact_run_manifest(manifest)?)?;
        Ok(())
    }

    pub fn write_repository(&self, repo: &RepositorySnapshot) -> Result<()> {
        self.write_json("repository.json", &redact_repository(repo))?;
        Ok(())
    }

    pub fn write_detection(&self, detection: &ProjectDetection) -> Result<()> {
        self.write_json("detection.json", &redact_detection(detection))?;
        Ok(())
    }

    pub fn write_detection_failure(&self, reason: &str) -> Result<()> {
        self.write_json(
            "detection-error.json",
            &DetectionFailure {
                reason: redact_secrets(reason),
            },
        )?;
        Ok(())
    }

    pub fn write_config(&self, config: &Config) -> Result<()> {
        self.write_json("config.normalized.json", config)?;
        Ok(())
    }

    pub fn write_plan(&self, plan: &ExecutionPlan) -> Result<()> {
        self.write_json("plan.json", &redact_plan(plan)?)?;
        Ok(())
    }

    pub fn write_candidates(&self, candidates: &serde_json::Value) -> Result<()> {
        let candidates: Vec<Candidate> = serde_json::from_value(candidates.clone())?;
        let candidates: Result<Vec<_>> = candidates.iter().map(redact_candidate).collect();
        self.write_json("candidates.json", &candidates?)?;
        Ok(())
    }

    pub fn write_verdicts(&self, verdicts: &[ScenarioVerdict]) -> Result<()> {
        let verdicts: Result<Vec<_>> = verdicts.iter().map(redact_verdict).collect();
        self.write_json("verdicts.json", &verdicts?)?;
        Ok(())
    }

    pub fn write_frontier(&self, frontier: &BreakageFrontier) -> Result<()> {
        self.write_json("frontier.json", &redact_frontier(frontier)?)?;
        Ok(())
    }

    /// Build the report model from the files that will be sealed, so reports
    /// cannot accidentally retain unredacted values that differ from the
    /// canonical run evidence.
    pub fn build_report_data(&self) -> Result<ReportData> {
        let run = read_unsealed_json(&self.root.join("run.json"), "run.json")?;
        let verdicts = read_unsealed_json(&self.root.join("verdicts.json"), "verdicts.json")?;
        let frontier = read_unsealed_json(&self.root.join("frontier.json"), "frontier.json")?;
        let plan = read_optional_unsealed_json(&self.root.join("plan.json"), "plan.json")?
            .unwrap_or_else(|| serde_json::json!({}));
        let candidates =
            read_optional_unsealed_json(&self.root.join("candidates.json"), "candidates.json")?
                .unwrap_or_else(|| serde_json::json!([]));
        Ok(ReportData {
            run,
            verdicts,
            frontier,
            plan,
            candidates,
        })
    }

    pub fn scenario_dir(&self, scenario_id: &str) -> PathBuf {
        self.root.join("scenarios").join(scenario_id)
    }

    pub fn write_scenario_bundle(
        &self,
        scenario: &Scenario,
        env: &EnvironmentSpec,
        commands: &[CommandSpec],
        raw: &RawExecutionResult,
        result: &ExecutionResult,
        failure: Option<&FailureSignature>,
    ) -> Result<PathBuf> {
        self.ensure_unsealed()?;
        validate_single_component(&scenario.id.0, "scenario id")?;
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

        let stdout = redact_secrets(&raw.stdout);
        let stderr = redact_secrets(&raw.stderr);
        // Cap log size (~2 MiB)
        let stdout = cap_bytes(&stdout, 2 * 1024 * 1024);
        let stderr = cap_bytes(&stderr, 2 * 1024 * 1024);
        persist_regular_file(&dir.join("stdout.log"), stdout.as_bytes())?;
        persist_regular_file(&dir.join("stderr.log"), stderr.as_bytes())?;
        write_json(&dir.join("result.json"), &result)?;
        if let Some(f) = &failure {
            write_json(&dir.join("failure-signature.json"), f)?;
        }

        let replay = ReplayManifest {
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
        write_json(&dir.join("replay-manifest.json"), &replay)?;

        // Static helpers cannot become an execution sink for recorded target text.
        let mut sh = String::from("#!/usr/bin/env bash\nset -euo pipefail\n# Generated by TomorrowCI — uses recorded manifest, not a new plan\n");
        // Never persist target-controlled interpolation in an executable helper.
        sh.clear();
        sh.push_str("#!/usr/bin/env bash\nset -euo pipefail\n# Generated by TomorrowCI; the CLI consumes replay-manifest.json.\necho 'Use: tomorrowci replay RUN_ID --scenario SCENARIO_ID'\n");
        persist_regular_file(&dir.join("replay.sh"), sh.as_bytes())?;

        let mut ps1 = String::from("# Generated by TomorrowCI\n");
        ps1.clear();
        ps1.push_str("# Generated by TomorrowCI; the CLI consumes replay-manifest.json.\nWrite-Host 'Use: tomorrowci replay RUN_ID --scenario SCENARIO_ID'\n");
        persist_regular_file(&dir.join("replay.ps1"), ps1.as_bytes())?;

        write_checksums(&dir, BundleKind::Scenario)?;
        Ok(dir)
    }

    pub fn load_replay_manifest(&self, scenario_id: &str) -> Result<ReplayManifest> {
        validate_single_component(scenario_id, "scenario id")?;
        let relative = format!("scenarios/{scenario_id}/replay-manifest.json");
        let path = self.root.join(&relative);
        if !path.exists() {
            return Err(EvidenceError::Missing(format!(
                "replay-manifest.json missing for scenario {scenario_id}"
            )));
        }
        self.load_verified_typed(&relative)
    }

    pub fn load_verdicts(&self) -> Result<Vec<ScenarioVerdict>> {
        self.load_verified_typed("verdicts.json")
    }

    pub fn load_frontier(&self) -> Result<BreakageFrontier> {
        self.load_verified_typed("frontier.json")
    }

    pub fn load_run(&self) -> Result<RunManifest> {
        self.load_verified_typed("run.json")
    }

    pub fn finalize_checksums(&self) -> Result<()> {
        self.ensure_unsealed()?;
        write_checksums(&self.root, BundleKind::Run)?;
        Ok(())
    }

    /// Verify this run's sealed recursive inventory without executing bundle content.
    pub fn verify(&self) -> Result<VerifiedBundle> {
        let verified = verify_bundle_internal(&self.root, Some(&self.run_id), None)?;
        if verified.kind != BundleKind::Run {
            return Err(EvidenceError::Other(format!(
                "evidence store requires a run bundle, found {}",
                verified.kind.as_str()
            )));
        }
        Ok(verified)
    }

    fn load_verified_typed<T: DeserializeOwned>(&self, relative: &str) -> Result<T> {
        self.verify()?.read_json(relative)
    }

    fn ensure_unsealed(&self) -> Result<()> {
        match fs::symlink_metadata(self.root.join(INVENTORY_FILE_NAME)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err(EvidenceError::Other(format!(
                "evidence run is already sealed and immutable: {}",
                self.root.display()
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayManifest {
    pub run_id: String,
    pub scenario_id: String,
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub commands: Vec<CommandSpec>,
    pub workdir: String,
    pub memory_mb: u64,
    pub cpus: f64,
    pub pids_limit: u64,
    pub timeout_seconds: u64,
    pub network_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionFailure {
    reason: String,
}

fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    persist_regular_file(path, json.as_bytes())?;
    Ok(())
}

fn read_unsealed_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || is_reparse_point(&metadata) {
        return Err(EvidenceError::NonRegularEntry(label.to_string()));
    }
    if metadata.len() > MAX_TYPED_JSON_BYTES as u64 {
        return Err(EvidenceError::InvalidSemantics {
            field: label.to_string(),
            detail: format!("typed JSON exceeds {MAX_TYPED_JSON_BYTES} bytes"),
        });
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_TYPED_JSON_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TYPED_JSON_BYTES {
        return Err(EvidenceError::InvalidSemantics {
            field: label.to_string(),
            detail: format!("typed JSON exceeds {MAX_TYPED_JSON_BYTES} bytes"),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| EvidenceError::InvalidJson {
        path: label.to_string(),
        source,
    })
}

fn read_optional_unsealed_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_unsealed_json(path, label).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn cap_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let half = max / 2;
    let mut head_end = half;
    while head_end > 0 && !s.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = s.len().saturating_sub(half);
    while tail_start < s.len() && !s.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!(
        "{}\n...[truncated {} bytes]...\n{}",
        &s[..head_end],
        tail_start.saturating_sub(head_end),
        &s[tail_start..]
    )
}

fn redact_environment(environment: &EnvironmentSpec) -> EnvironmentSpec {
    let mut redacted = environment.clone();
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.image_digest = redacted.image_digest.map(|value| redact_secrets(&value));
    redacted.workdir = redact_secrets(&redacted.workdir);
    redacted.user = redacted.user.map(|value| redact_secrets(&value));
    for value in redacted.env.values_mut() {
        *value = redact_secrets(value);
    }
    for mount in &mut redacted.mounts {
        mount.host_path = PathBuf::from(redact_secrets(&mount.host_path.to_string_lossy()));
        mount.container_path = redact_secrets(&mount.container_path);
    }
    redacted
}

fn redact_command(command: &CommandSpec) -> CommandSpec {
    let mut redacted = command.clone();
    redacted.program = redact_secrets(&redacted.program);
    redacted.args = redacted
        .args
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted.workdir = redact_secrets(&redacted.workdir);
    for value in redacted.env.values_mut() {
        *value = redact_secrets(value);
    }
    redacted
}

fn redact_execution_result(result: &ExecutionResult) -> ExecutionResult {
    let mut redacted = result.clone();
    redacted.stdout_path = redacted
        .stdout_path
        .map(|path| PathBuf::from(redact_secrets(&path.to_string_lossy())));
    redacted.stderr_path = redacted
        .stderr_path
        .map(|path| PathBuf::from(redact_secrets(&path.to_string_lossy())));
    redacted.stdout_preview = redact_secrets(&redacted.stdout_preview);
    redacted.stderr_preview = redact_secrets(&redacted.stderr_preview);
    redacted.blocked_reason = redacted.blocked_reason.map(|value| redact_secrets(&value));
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.image_digest = redacted.image_digest.map(|value| redact_secrets(&value));
    redacted.commands = redacted.commands.iter().map(redact_command).collect();
    redacted
}

fn redact_failure_signature(signature: &FailureSignature) -> FailureSignature {
    let mut redacted = signature.clone();
    redacted.kind = redact_secrets(&redacted.kind);
    redacted.summary = redact_secrets(&redacted.summary);
    redacted.primary_error = redacted.primary_error.map(|value| redact_secrets(&value));
    redacted.framework_hints = redacted
        .framework_hints
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted.fingerprint = FailureSignature::compute_fingerprint(
        &redacted.kind,
        redacted.primary_error.as_deref().unwrap_or_default(),
        &redacted.summary,
    );
    redacted
}

fn reject_secret_identity(value: &str, field: &str) -> Result<()> {
    validate_single_component(value, field)?;
    if redact_secrets(value) != value {
        return Err(EvidenceError::InvalidSemantics {
            field: field.to_string(),
            detail: "identity resembles a secret and cannot be persisted safely".into(),
        });
    }
    Ok(())
}

fn redact_repository(repository: &RepositorySnapshot) -> RepositorySnapshot {
    let mut redacted = repository.clone();
    redacted.source = redact_secrets(&redacted.source);
    redacted.path = PathBuf::from(redact_secrets(&redacted.path.to_string_lossy()));
    redacted.commit_sha = redacted.commit_sha.map(|value| redact_secrets(&value));
    redacted.branch = redacted.branch.map(|value| redact_secrets(&value));
    redacted.workspace_copy =
        PathBuf::from(redact_secrets(&redacted.workspace_copy.to_string_lossy()));
    redacted
}

fn redact_detection(detection: &ProjectDetection) -> ProjectDetection {
    let mut redacted = detection.clone();
    redacted.package_manager = redact_secrets(&redacted.package_manager);
    redacted.manifests = redacted
        .manifests
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted.notes = redacted
        .notes
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted.unsupported_reason = redacted
        .unsupported_reason
        .map(|value| redact_secrets(&value));
    redacted
}

fn redact_baseline(baseline: &Baseline) -> Baseline {
    let mut redacted = baseline.clone();
    redacted.runtime_label = redact_secrets(&redacted.runtime_label);
    redacted.runtime_version = redact_secrets(&redacted.runtime_version);
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.notes = redacted
        .notes
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted
}

fn redact_scenario(scenario: &Scenario) -> Result<Scenario> {
    reject_secret_identity(&scenario.id.0, "scenario id")?;
    let mut redacted = scenario.clone();
    redacted.label = redact_secrets(&redacted.label);
    redacted.runtime_version = redact_secrets(&redacted.runtime_version);
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.selection_reason = redact_secrets(&redacted.selection_reason);
    Ok(redacted)
}

fn redact_candidate(candidate: &Candidate) -> Result<Candidate> {
    reject_secret_identity(&candidate.id, "candidate id")?;
    let mut redacted = candidate.clone();
    redacted.label = redact_secrets(&redacted.label);
    redacted.runtime_version = redacted.runtime_version.map(|value| redact_secrets(&value));
    redacted.image_ref = redact_secrets(&redacted.image_ref);
    redacted.channel = redact_secrets(&redacted.channel);
    redacted.order_key = redact_secrets(&redacted.order_key);
    redacted.notes = redacted
        .notes
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    Ok(redacted)
}

fn redact_plan(plan: &ExecutionPlan) -> Result<ExecutionPlan> {
    reject_secret_identity(&plan.run_id.0, "plan run id")?;
    let mut redacted = plan.clone();
    redacted.scenarios = plan
        .scenarios
        .iter()
        .map(redact_scenario)
        .collect::<Result<Vec<_>>>()?;
    for decision in &mut redacted.decisions {
        if let Some(scenario_id) = decision.scenario_id.as_deref() {
            reject_secret_identity(scenario_id, "plan decision scenario id")?;
        }
        decision.action = redact_secrets(&decision.action);
        decision.reason = redact_secrets(&decision.reason);
    }
    for untested in &mut redacted.untested {
        untested.label = redact_secrets(&untested.label);
        untested.reason = redact_secrets(&untested.reason);
    }
    Ok(redacted)
}

fn redact_verdict(verdict: &ScenarioVerdict) -> Result<ScenarioVerdict> {
    reject_secret_identity(&verdict.scenario_id.0, "verdict scenario id")?;
    let mut redacted = verdict.clone();
    redacted.label = redact_secrets(&redacted.label);
    redacted.failure_signature = redacted
        .failure_signature
        .as_ref()
        .map(redact_failure_signature);
    if let Some(evidence) = &mut redacted.evidence {
        reject_secret_identity(&evidence.run_id.0, "evidence run id")?;
        reject_secret_identity(&evidence.scenario_id.0, "evidence scenario id")?;
        evidence.directory = PathBuf::from(redact_secrets(&evidence.directory.to_string_lossy()));
        evidence.replay_command = redact_secrets(&evidence.replay_command);
    }
    redacted.notes = redacted
        .notes
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    Ok(redacted)
}

fn redact_frontier(frontier: &BreakageFrontier) -> Result<BreakageFrontier> {
    if let Some(scenario_id) = frontier.scenario_id.as_ref() {
        reject_secret_identity(&scenario_id.0, "frontier scenario id")?;
    }
    let mut redacted = frontier.clone();
    redacted.horizon_label = redacted.horizon_label.map(|value| redact_secrets(&value));
    redacted.from_label = redacted.from_label.map(|value| redact_secrets(&value));
    redacted.to_label = redacted.to_label.map(|value| redact_secrets(&value));
    redacted.failure_signature = redacted
        .failure_signature
        .as_ref()
        .map(redact_failure_signature);
    redacted.replay_command = redacted.replay_command.map(|value| redact_secrets(&value));
    redacted.explanation = redact_secrets(&redacted.explanation);
    Ok(redacted)
}

fn redact_run_manifest(manifest: &RunManifest) -> Result<RunManifest> {
    reject_secret_identity(&manifest.run_id.0, "run id")?;
    let mut redacted = manifest.clone();
    redacted.tool_version = redact_secrets(&redacted.tool_version);
    redacted.repository = redact_repository(&redacted.repository);
    redacted.detection = redacted.detection.as_ref().map(redact_detection);
    redacted.baseline = redacted.baseline.as_ref().map(redact_baseline);
    redacted.config_hash = redact_secrets(&redacted.config_hash);
    redacted.sandbox_engine = redacted.sandbox_engine.map(|value| redact_secrets(&value));
    redacted.frontier = redacted
        .frontier
        .as_ref()
        .map(redact_frontier)
        .transpose()?;
    redacted.host.os = redact_secrets(&redacted.host.os);
    redacted.host.arch = redact_secrets(&redacted.host.arch);
    redacted.host.tomorrowci_version = redact_secrets(&redacted.host.tomorrowci_version);
    Ok(redacted)
}

impl BundleInventory {
    /// Parse the strict v1 inventory format. Unversioned historical checksum
    /// files are deliberately reported as unsealed rather than trusted.
    pub fn parse(contents: &str) -> Result<Self> {
        if contents.contains('\r') {
            return Err(EvidenceError::MalformedInventory {
                line: 1,
                reason: "carriage returns are not canonical".into(),
            });
        }
        if !contents.ends_with('\n') {
            return Err(EvidenceError::MalformedInventory {
                line: contents.lines().count().max(1),
                reason: "canonical inventory must end with LF".into(),
            });
        }

        let mut lines = contents.split_terminator('\n');
        let header = lines
            .next()
            .ok_or_else(|| EvidenceError::MalformedInventory {
                line: 1,
                reason: "missing version header".into(),
            })?;
        let kind = if let Some(value) = header
            .strip_prefix(INVENTORY_HEADER_V1_PREFIX)
            .and_then(|value| value.strip_suffix(INVENTORY_HEADER_V1_SUFFIX))
        {
            BundleKind::parse(value).ok_or_else(|| EvidenceError::MalformedInventory {
                line: 1,
                reason: format!("unknown bundle kind {value:?}"),
            })?
        } else if header.starts_with(INVENTORY_HEADER_PREFIX) {
            if header.starts_with(INVENTORY_HEADER_V1_PREFIX) {
                return Err(EvidenceError::MalformedInventory {
                    line: 1,
                    reason: "invalid v1 header".into(),
                });
            }
            return Err(EvidenceError::UnsupportedInventoryVersion(
                header.to_string(),
            ));
        } else {
            return Err(EvidenceError::UnsealedLegacy(header.to_string()));
        };

        let mut entries = Vec::new();
        let mut paths = BTreeSet::new();
        let mut portable_paths = BTreeSet::new();
        let mut previous_path: Option<String> = None;
        for (index, line) in lines.enumerate() {
            let line_number = index + 2;
            if line.is_empty() {
                return Err(EvidenceError::MalformedInventory {
                    line: line_number,
                    reason: "blank records are not allowed".into(),
                });
            }
            let bytes = line.as_bytes();
            if bytes.len() < 67 || bytes.get(64..66) != Some(b"  ") {
                return Err(EvidenceError::MalformedInventory {
                    line: line_number,
                    reason: "expected `<64 lowercase hex>  <path>`".into(),
                });
            }
            let digest = &bytes[..64];
            if !digest
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(EvidenceError::MalformedInventory {
                    line: line_number,
                    reason: "SHA-256 digest must be 64 lowercase hexadecimal characters".into(),
                });
            }
            let digest = line[..64].to_string();
            let path = &line[66..];
            validate_inventory_path(path)?;
            if path == INVENTORY_FILE_NAME {
                return Err(EvidenceError::UnsafePath(path.to_string()));
            }
            if !paths.insert(path.to_string()) {
                return Err(EvidenceError::DuplicatePath(path.to_string()));
            }
            if !portable_paths.insert(path.to_lowercase()) {
                return Err(EvidenceError::DuplicatePath(format!(
                    "portable case-fold collision: {path}"
                )));
            }
            if previous_path
                .as_deref()
                .is_some_and(|previous| previous >= path)
            {
                return Err(EvidenceError::MalformedInventory {
                    line: line_number,
                    reason: "paths must be in ascending canonical order".into(),
                });
            }
            previous_path = Some(path.to_string());
            entries.push(InventoryEntry {
                path: path.to_string(),
                sha256: digest,
            });
        }

        let inventory = Self {
            version: INVENTORY_VERSION,
            kind,
            entries,
        };
        inventory.enforce_required_paths()?;
        Ok(inventory)
    }

    /// Render a deterministic inventory. This validates caller-constructed
    /// values before producing bytes suitable for sealing.
    pub fn to_canonical_string(&self) -> Result<String> {
        if self.version != INVENTORY_VERSION {
            return Err(EvidenceError::UnsupportedInventoryVersion(
                self.version.to_string(),
            ));
        }
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let canonical = Self {
            version: self.version,
            kind: self.kind,
            entries,
        };
        canonical.enforce_required_paths()?;

        let mut seen = BTreeSet::new();
        let mut portable_seen = BTreeSet::new();
        let mut output = format!(
            "{INVENTORY_HEADER_V1_PREFIX}{}{INVENTORY_HEADER_V1_SUFFIX}\n",
            canonical.kind.as_str()
        );
        for entry in canonical.entries {
            validate_inventory_path(&entry.path)?;
            if entry.path == INVENTORY_FILE_NAME {
                return Err(EvidenceError::UnsafePath(entry.path));
            }
            if !seen.insert(entry.path.clone()) {
                return Err(EvidenceError::DuplicatePath(entry.path));
            }
            if !portable_seen.insert(entry.path.to_lowercase()) {
                return Err(EvidenceError::DuplicatePath(format!(
                    "portable case-fold collision: {}",
                    entry.path
                )));
            }
            if entry.sha256.len() != 64
                || !entry
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(EvidenceError::MalformedInventory {
                    line: 0,
                    reason: format!("invalid SHA-256 digest for {}", entry.path),
                });
            }
            writeln!(output, "{}  {}", entry.sha256, entry.path)
                .expect("writing to a String cannot fail");
        }
        Ok(output)
    }

    fn enforce_required_paths(&self) -> Result<()> {
        let paths: BTreeSet<&str> = self
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        for required in self.kind.required_paths() {
            if !paths.contains(required) {
                return Err(EvidenceError::Missing(format!(
                    "required {kind} evidence file is not inventoried: {required}",
                    kind = self.kind.as_str()
                )));
            }
        }
        Ok(())
    }
}

/// Recursively hash every regular file and seal the directory with a v1
/// inventory. The inventory file itself is excluded from its own digest set.
pub fn seal_bundle(dir: &Path, kind: BundleKind) -> Result<BundleInventory> {
    let files = collect_regular_files(dir)?;
    let mut entries = Vec::with_capacity(files.len());
    for (relative, path) in files {
        entries.push(InventoryEntry {
            path: relative,
            sha256: sha256_regular_file(&path)?,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let inventory = BundleInventory {
        version: INVENTORY_VERSION,
        kind,
        entries,
    };
    let contents = inventory.to_canonical_string()?;
    persist_inventory(dir, contents.as_bytes())?;

    // Read back through the independent verifier before reporting the bundle
    // as sealed. This also detects a concurrent late writer.
    verify_bundle(dir)?;
    Ok(inventory)
}

/// Parse a sealed inventory without verifying file contents. Most callers
/// should use [`verify_bundle`] instead.
pub fn read_inventory(dir: &Path) -> Result<BundleInventory> {
    let (_, inventory) = read_inventory_with_contents(dir)?;
    Ok(inventory)
}

/// Verify the complete recursive inventory and its fixed typed cross-file
/// invariants without executing bundle content.
pub fn verify_bundle(dir: &Path) -> Result<VerifiedBundle> {
    verify_bundle_internal(dir, None, None)
}

fn verify_bundle_internal(
    dir: &Path,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<VerifiedBundle> {
    ensure_directory(dir)?;
    let (inventory_contents, inventory) = read_inventory_with_contents(dir)?;
    let files = collect_regular_files(dir)?;
    let expected: BTreeSet<&str> = inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let actual: BTreeSet<&str> = files
        .iter()
        .map(|(relative, _)| relative.as_str())
        .collect();

    if let Some(missing) = expected.difference(&actual).next() {
        return Err(EvidenceError::Missing(format!(
            "inventoried file does not exist: {missing}"
        )));
    }
    if let Some(extra) = actual.difference(&expected).next() {
        return Err(EvidenceError::Unlisted((*extra).to_string()));
    }

    for entry in &inventory.entries {
        let path = dir.join(&entry.path);
        let actual_digest = sha256_regular_file(&path)?;
        if actual_digest != entry.sha256 {
            return Err(EvidenceError::ChecksumMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual_digest,
            });
        }
    }

    // A file added/deleted while hashing and an inventory swapped during the
    // check must not turn a racing bundle into a successful verification.
    let files_after = collect_regular_files(dir)?;
    let actual_after: BTreeSet<&str> = files_after
        .iter()
        .map(|(relative, _)| relative.as_str())
        .collect();
    if actual_after != actual {
        return Err(EvidenceError::Other(
            "evidence bundle changed during verification".into(),
        ));
    }
    let (inventory_contents_after, inventory_after) = read_inventory_with_contents(dir)?;
    if inventory_contents_after != inventory_contents || inventory_after != inventory {
        return Err(EvidenceError::Other(
            "evidence inventory changed during verification".into(),
        ));
    }

    verify_bundle_semantics(dir, &inventory, expected_run_id, expected_scenario_id)?;

    // Semantic parsing can take materially longer than hashing a small file.
    // Re-hash the complete inventory afterward so a bundle cannot pass with
    // bytes that changed between the integrity and semantic phases.
    let (inventory_contents_final, inventory_final) = read_inventory_with_contents(dir)?;
    if inventory_contents_final != inventory_contents || inventory_final != inventory {
        return Err(EvidenceError::Other(
            "evidence inventory changed during semantic verification".into(),
        ));
    }
    let files_final = collect_regular_files(dir)?;
    let actual_final: BTreeSet<&str> = files_final
        .iter()
        .map(|(relative, _)| relative.as_str())
        .collect();
    if actual_final != expected {
        return Err(EvidenceError::Other(
            "evidence bundle changed during semantic verification".into(),
        ));
    }
    for entry in &inventory.entries {
        let actual_digest = sha256_regular_file(&dir.join(&entry.path))?;
        if actual_digest != entry.sha256 {
            return Err(EvidenceError::ChecksumMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual_digest,
            });
        }
    }
    let files_post_hash = collect_regular_files(dir)?;
    let actual_post_hash: BTreeSet<&str> = files_post_hash
        .iter()
        .map(|(relative, _)| relative.as_str())
        .collect();
    if actual_post_hash != expected {
        return Err(EvidenceError::Other(
            "evidence bundle changed during final verification".into(),
        ));
    }
    let (inventory_contents_post_hash, inventory_post_hash) = read_inventory_with_contents(dir)?;
    if inventory_contents_post_hash != inventory_contents || inventory_post_hash != inventory {
        return Err(EvidenceError::Other(
            "evidence inventory changed during final verification".into(),
        ));
    }

    Ok(VerifiedBundle {
        root: dir.to_path_buf(),
        version: inventory.version,
        kind: inventory.kind,
        file_count: inventory.entries.len(),
        inventory,
    })
}

fn verify_bundle_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<()> {
    match inventory.kind {
        BundleKind::Generic => Ok(()),
        BundleKind::Run => verify_run_semantics(dir, inventory, expected_run_id),
        BundleKind::Scenario => {
            verify_scenario_semantics(dir, inventory, expected_run_id, expected_scenario_id)
        }
    }
}

fn verify_run_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
) -> Result<()> {
    let config: Config = read_typed_json(dir, inventory, "config.normalized.json")?;
    config
        .validate()
        .map_err(|error| EvidenceError::InvalidSemantics {
            field: "config.normalized.json".into(),
            detail: error.to_string(),
        })?;
    let run: RunManifest = read_typed_json(dir, inventory, "run.json")?;
    let repository: RepositorySnapshot = read_typed_json(dir, inventory, "repository.json")?;
    let verdicts: Vec<ScenarioVerdict> = read_typed_json(dir, inventory, "verdicts.json")?;
    let frontier: BreakageFrontier = read_typed_json(dir, inventory, "frontier.json")?;

    validate_single_component(&run.run_id.0, "run.json run id")?;
    if let Some(expected) = expected_run_id {
        ensure_identity("run.json.run_id", &run.run_id.0, expected)?;
    }
    let valid_tool_version = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || ".+-_".contains(character))
    };
    if !valid_tool_version(&run.tool_version) {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.tool_version".into(),
            detail: "must be a non-empty portable version identifier".into(),
        });
    }
    ensure_identity(
        "run.json.host.tomorrowci_version",
        &run.host.tomorrowci_version,
        &run.tool_version,
    )?;
    let config_hash = config
        .config_hash()
        .map_err(|error| EvidenceError::InvalidSemantics {
            field: "config.normalized.json".into(),
            detail: error.to_string(),
        })?;
    ensure_identity("run.json.config_hash", &run.config_hash, &config_hash)?;
    ensure_semantic_equality(
        "run.json.repository",
        &run.repository,
        "repository.json",
        &repository,
    )?;
    let run_frontier = run
        .frontier
        .as_ref()
        .ok_or_else(|| EvidenceError::InvalidSemantics {
            field: "run.json.frontier".into(),
            detail: "sealed runs must embed frontier.json".into(),
        })?;
    ensure_semantic_equality(
        "run.json.frontier",
        run_frontier,
        "frontier.json",
        &frontier,
    )?;

    let finished = run
        .finished_at
        .ok_or_else(|| EvidenceError::InvalidSemantics {
            field: "run.json.finished_at".into(),
            detail: "sealed runs must have a completion timestamp".into(),
        })?;
    if finished < run.started_at {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.finished_at".into(),
            detail: format!("completion {finished} precedes start {}", run.started_at),
        });
    }
    if !matches!(run.status, RunStatus::Completed | RunStatus::Blocked) {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.status".into(),
            detail: format!(
                "only COMPLETED or BLOCKED runs can be sealed as final evidence, found {:?}",
                run.status
            ),
        });
    }

    let mut verdict_by_id = BTreeMap::new();
    for verdict in &verdicts {
        validate_single_component(&verdict.scenario_id.0, "verdict scenario id")?;
        if let Some(signature) = &verdict.failure_signature {
            validate_failure_signature(
                &format!("verdicts.json[{}].failure_signature", verdict.scenario_id),
                signature,
            )?;
        }
        if verdict_by_id
            .insert(verdict.scenario_id.0.clone(), verdict)
            .is_some()
        {
            return Err(EvidenceError::DuplicateIdentity {
                kind: "verdict scenario".into(),
                id: verdict.scenario_id.0.clone(),
            });
        }
    }
    if let Some(signature) = &frontier.failure_signature {
        validate_failure_signature("frontier.json.failure_signature", signature)?;
    }
    let early_unsupported = run.scenario_count == 0
        && verdicts.len() == 1
        && verdicts[0].scenario_id.0 == "detect"
        && verdicts[0].verdict == Verdict::Unsupported
        && verdicts[0].evidence.is_none();
    let early_blocked = run.scenario_count == 0
        && verdicts.len() == 1
        && verdicts[0].scenario_id.0 == "sandbox"
        && verdicts[0].verdict == Verdict::Blocked
        && verdicts[0].evidence.is_none();
    let normal_run = !early_unsupported && !early_blocked;
    if early_unsupported || early_blocked {
        let verdict = &verdicts[0];
        let expected_label = if early_unsupported {
            "detection"
        } else {
            "sandbox"
        };
        if verdict.label != expected_label
            || verdict.attempts != 0
            || verdict.evidence_grade != EvidenceGrade::Inconclusive
            || verdict.failure_signature.is_some()
            || verdict.notes.is_empty()
        {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("verdicts.json[{}]", verdict.scenario_id),
                detail: "early final verdict must have its canonical label, zero attempts, INCONCLUSIVE grade, no signature, and a reason"
                    .into(),
            });
        }
    }
    if run.scenario_count != verdicts.len() && !early_unsupported && !early_blocked {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.scenario_count".into(),
            detail: format!(
                "declares {} scenarios but verdicts.json contains {}",
                run.scenario_count,
                verdicts.len()
            ),
        });
    }
    if early_blocked && run.status != RunStatus::Blocked {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.status".into(),
            detail: "sandbox-blocked evidence must have BLOCKED run status".into(),
        });
    }
    if early_unsupported && run.status != RunStatus::Completed {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.status".into(),
            detail: "detection-unsupported evidence must have COMPLETED run status".into(),
        });
    }
    if run.status == RunStatus::Blocked
        && !verdicts
            .iter()
            .any(|verdict| verdict.verdict == Verdict::Blocked)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.status".into(),
            detail: "BLOCKED run has no BLOCKED verdict".into(),
        });
    }
    if run.status == RunStatus::Completed
        && verdicts
            .iter()
            .any(|verdict| verdict.verdict == Verdict::Blocked)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "run.json.status".into(),
            detail: "COMPLETED run contains a BLOCKED verdict".into(),
        });
    }

    let recorded_detection = if inventory_has(inventory, "detection.json") {
        let detection: ProjectDetection = read_typed_json(dir, inventory, "detection.json")?;
        let embedded = run
            .detection
            .as_ref()
            .ok_or_else(|| EvidenceError::IdentityMismatch {
                field: "detection.json".into(),
                detail: "file exists but run.json.detection is null".into(),
            })?;
        ensure_semantic_equality("run.json.detection", embedded, "detection.json", &detection)?;
        Some(detection)
    } else {
        if run.detection.is_some() {
            return Err(EvidenceError::Missing(
                "run.json.detection has no detection.json".into(),
            ));
        }
        None
    };
    let detection_failure = if inventory_has(inventory, "detection-error.json") {
        let failure: DetectionFailure = read_typed_json(dir, inventory, "detection-error.json")?;
        if failure.reason.trim().is_empty() {
            return Err(EvidenceError::InvalidSemantics {
                field: "detection-error.json.reason".into(),
                detail: "detection failure reason must not be empty".into(),
            });
        }
        Some(failure)
    } else {
        None
    };
    if early_unsupported {
        match (&recorded_detection, &detection_failure) {
            (Some(detection), None) if !detection.supported => {}
            (None, Some(_)) => {}
            (Some(detection), None) if detection.supported => {
                return Err(EvidenceError::InvalidSemantics {
                    field: "detection.json.supported".into(),
                    detail: "UNSUPPORTED evidence cannot contain supported=true detection".into(),
                });
            }
            _ => {
                return Err(EvidenceError::InvalidSemantics {
                    field: "UNSUPPORTED detection evidence".into(),
                    detail:
                        "requires exactly one unsupported detection.json or detection-error.json"
                            .into(),
                });
            }
        }
    } else if detection_failure.is_some() {
        return Err(EvidenceError::InvalidSemantics {
            field: "detection-error.json".into(),
            detail: "only an early UNSUPPORTED run may contain detection failure evidence".into(),
        });
    }
    if early_blocked
        && recorded_detection
            .as_ref()
            .map_or(true, |detection| !detection.supported)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "detection.json".into(),
            detail: "sandbox BLOCKED evidence requires the prior supported detection".into(),
        });
    }

    let plan = if inventory_has(inventory, "plan.json") {
        let plan: ExecutionPlan = read_typed_json(dir, inventory, "plan.json")?;
        ensure_identity("plan.json.run_id", &plan.run_id.0, &run.run_id.0)?;
        let mut ids = BTreeSet::new();
        for scenario in &plan.scenarios {
            validate_single_component(&scenario.id.0, "plan scenario id")?;
            if !ids.insert(scenario.id.0.clone()) {
                return Err(EvidenceError::DuplicateIdentity {
                    kind: "plan scenario".into(),
                    id: scenario.id.0.clone(),
                });
            }
        }
        Some(plan)
    } else {
        None
    };
    let candidates = if inventory_has(inventory, "candidates.json") {
        Some(read_typed_json::<Vec<Candidate>>(
            dir,
            inventory,
            "candidates.json",
        )?)
    } else {
        None
    };

    if normal_run {
        if run.scenario_count == 0 || verdicts.is_empty() {
            return Err(EvidenceError::InvalidSemantics {
                field: "run.json.scenario_count".into(),
                detail: "a normal final run must contain at least one executed scenario".into(),
            });
        }
        let detection = recorded_detection.as_ref().ok_or_else(|| {
            EvidenceError::Missing("normal final run requires detection.json".into())
        })?;
        if !detection.supported {
            return Err(EvidenceError::InvalidSemantics {
                field: "detection.json.supported".into(),
                detail: "a normal executed run requires a supported project".into(),
            });
        }
        let baseline = run
            .baseline
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: "run.json.baseline".into(),
                detail: "a normal final run requires a baseline definition".into(),
            })?;
        if baseline.ecosystem != detection.ecosystem {
            return Err(EvidenceError::IdentityMismatch {
                field: "run.json.baseline.ecosystem".into(),
                detail: "does not match detection.json.ecosystem".into(),
            });
        }
        if run
            .sandbox_engine
            .as_deref()
            .map_or(true, |engine| engine.trim().is_empty())
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "run.json.sandbox_engine".into(),
                detail: "a normal final run requires the executing sandbox engine".into(),
            });
        }
        let plan = plan
            .as_ref()
            .ok_or_else(|| EvidenceError::Missing("normal final run requires plan.json".into()))?;
        let baseline_scenarios: Vec<_> = plan
            .scenarios
            .iter()
            .filter(|scenario| scenario.is_baseline)
            .collect();
        if baseline_scenarios.len() != 1 {
            return Err(EvidenceError::InvalidSemantics {
                field: "plan.json.scenarios".into(),
                detail: format!(
                    "normal final run requires exactly one baseline scenario, found {}",
                    baseline_scenarios.len()
                ),
            });
        }
        let baseline_scenario = baseline_scenarios[0];
        if baseline_scenario.ecosystem != baseline.ecosystem
            || baseline_scenario.runtime_version != baseline.runtime_version
            || baseline_scenario.dependency_mode != baseline.dependency_mode
            || baseline_scenario.image_ref != baseline.image_ref
        {
            return Err(EvidenceError::IdentityMismatch {
                field: "plan.json baseline scenario".into(),
                detail: "does not match run.json.baseline".into(),
            });
        }
        let candidates = candidates.as_ref().ok_or_else(|| {
            EvidenceError::Missing("normal final run requires candidates.json".into())
        })?;
        let mut candidate_ids = BTreeSet::new();
        for candidate in candidates {
            validate_single_component(&candidate.id, "candidate id")?;
            if !candidate_ids.insert(candidate.id.clone()) {
                return Err(EvidenceError::DuplicateIdentity {
                    kind: "candidate".into(),
                    id: candidate.id.clone(),
                });
            }
        }
        if plan.max_scenarios != config.execution.max_scenarios
            || plan.max_parallel != config.execution.max_parallel.max(1)
            || plan.scenarios.len() > plan.max_scenarios
            || run.scenario_count > plan.scenarios.len()
        {
            return Err(EvidenceError::IdentityMismatch {
                field: "plan.json limits".into(),
                detail: "max_scenarios/max_parallel or scenario counts do not match config/run"
                    .into(),
            });
        }
        if plan.scenarios.first().map(|scenario| scenario.id.clone())
            != Some(baseline_scenario.id.clone())
            || baseline_scenario.kind != ScenarioKind::Baseline
        {
            return Err(EvidenceError::InvalidSemantics {
                field: "plan.json.scenarios".into(),
                detail: "the single baseline scenario must be first and have BASELINE kind".into(),
            });
        }
        let planned_verdict_ids: Vec<_> = plan
            .scenarios
            .iter()
            .take(verdicts.len())
            .map(|scenario| &scenario.id)
            .collect();
        let recorded_verdict_ids: Vec<_> = verdicts
            .iter()
            .map(|verdict| &verdict.scenario_id)
            .collect();
        if planned_verdict_ids != recorded_verdict_ids {
            return Err(EvidenceError::IdentityMismatch {
                field: "verdicts.json order".into(),
                detail: "executed verdicts must be the ordered prefix of plan.json scenarios"
                    .into(),
            });
        }
        let baseline_verdict = verdict_by_id.get(&baseline_scenario.id.0).ok_or_else(|| {
            EvidenceError::IdentityMismatch {
                field: "verdicts.json".into(),
                detail: "normal run has no baseline verdict".into(),
            }
        })?;
        if baseline_verdict.verdict == Verdict::BaselinePass {
            if verdicts.len() != plan.scenarios.len() {
                return Err(EvidenceError::InvalidSemantics {
                    field: "verdicts.json".into(),
                    detail:
                        "a passing baseline requires a verdict for every final planned scenario"
                            .into(),
                });
            }
        } else if verdicts.len() != 1 {
            return Err(EvidenceError::InvalidSemantics {
                field: "verdicts.json".into(),
                detail: "future verdicts are forbidden when the baseline did not pass".into(),
            });
        }
        for scenario in &plan.scenarios {
            if scenario.ecosystem != detection.ecosystem {
                return Err(EvidenceError::IdentityMismatch {
                    field: format!("plan.json.scenarios[{}].ecosystem", scenario.id),
                    detail: "does not match detection.json.ecosystem".into(),
                });
            }
            if scenario.is_baseline != (scenario.kind == ScenarioKind::Baseline) {
                return Err(EvidenceError::InvalidSemantics {
                    field: format!("plan.json.scenarios[{}].kind", scenario.id),
                    detail: "baseline flag and scenario kind disagree".into(),
                });
            }
            match scenario.kind {
                ScenarioKind::SingleAxis => {
                    let candidate = candidates
                        .iter()
                        .find(|candidate| candidate.id == scenario.id.0)
                        .ok_or_else(|| EvidenceError::IdentityMismatch {
                            field: format!("plan.json.scenarios[{}]", scenario.id),
                            detail: "single-axis scenario has no matching candidate".into(),
                        })?;
                    let expected_runtime = candidate.runtime_version.as_deref().unwrap_or_default();
                    if scenario.label != candidate.label
                        || scenario.runtime_version != expected_runtime
                        || scenario.dependency_mode != candidate.dependency_mode
                        || scenario.image_ref != candidate.image_ref
                        || scenario.axes_changed.as_slice() != [candidate.axis.clone()]
                        || scenario.evidence_grade != candidate.evidence_grade
                    {
                        return Err(EvidenceError::IdentityMismatch {
                            field: format!("plan.json.scenarios[{}]", scenario.id),
                            detail: "does not match its candidates.json record".into(),
                        });
                    }
                }
                ScenarioKind::Combined => {
                    if scenario.is_baseline
                        || scenario.evidence_grade != EvidenceGrade::Simulated
                        || scenario.axes_changed.as_slice()
                            != [EnvironmentAxis::Runtime, EnvironmentAxis::Dependencies]
                        || scenario.selection_reason
                            != "pairwise combination after single-axis passes"
                    {
                        return Err(EvidenceError::InvalidSemantics {
                            field: format!("plan.json.scenarios[{}]", scenario.id),
                            detail: "combined scenario shape is not the canonical runtime+dependencies pair"
                                .into(),
                        });
                    }
                    let pair = candidates.iter().find_map(|runtime| {
                        if runtime.axis != EnvironmentAxis::Runtime {
                            return None;
                        }
                        candidates.iter().find_map(|dependency| {
                            if dependency.axis != EnvironmentAxis::Dependencies
                                || scenario.id.0
                                    != format!("combined-{}-{}", runtime.id, dependency.id)
                            {
                                return None;
                            }
                            Some((runtime, dependency))
                        })
                    });
                    let (runtime, dependency) =
                        pair.ok_or_else(|| EvidenceError::IdentityMismatch {
                            field: format!("plan.json.scenarios[{}]", scenario.id),
                            detail: "combined id does not bind to runtime/dependency candidates"
                                .into(),
                        })?;
                    let expected_runtime = runtime.runtime_version.as_deref().unwrap_or_default();
                    let expected_label =
                        format!("{expected_runtime} + {}", dependency.dependency_mode);
                    if scenario.runtime_version != expected_runtime
                        || scenario.dependency_mode != dependency.dependency_mode
                        || scenario.image_ref != runtime.image_ref
                        || scenario.label != expected_label
                    {
                        return Err(EvidenceError::IdentityMismatch {
                            field: format!("plan.json.scenarios[{}]", scenario.id),
                            detail: "combined scenario does not match its two candidate records"
                                .into(),
                        });
                    }
                }
                ScenarioKind::Baseline => {}
                ScenarioKind::Reduction | ScenarioKind::Replay => {
                    return Err(EvidenceError::InvalidSemantics {
                        field: format!("plan.json.scenarios[{}].kind", scenario.id),
                        detail: "normal scan evidence cannot contain reduction/replay plan entries"
                            .into(),
                    });
                }
            }
        }
    } else {
        if plan.is_some() || candidates.is_some() {
            return Err(EvidenceError::InvalidSemantics {
                field: "early final run layout".into(),
                detail: "zero-scenario UNSUPPORTED/BLOCKED runs cannot claim a plan or candidates"
                    .into(),
            });
        }
        if run.baseline.is_some() || run.sandbox_engine.is_some() {
            return Err(EvidenceError::InvalidSemantics {
                field: "early final run metadata".into(),
                detail: "zero-scenario UNSUPPORTED/BLOCKED runs cannot claim execution metadata"
                    .into(),
            });
        }
    }

    for (enabled, path) in [
        (config.report.html, "report.html"),
        (config.report.json, "report.json"),
        (config.report.sarif, "report.sarif"),
    ] {
        let present = inventory_has(inventory, path);
        if enabled && !present {
            return Err(EvidenceError::Missing(format!(
                "configured report is missing from sealed run: {path}"
            )));
        }
        if !enabled && present {
            return Err(EvidenceError::InvalidSemantics {
                field: path.into(),
                detail: "report is present although its config flag is disabled".into(),
            });
        }
    }

    let report_data = ReportData {
        run: run.clone(),
        verdicts: verdicts.clone(),
        frontier: frontier.clone(),
        plan: match &plan {
            Some(plan) => serde_json::to_value(plan)?,
            None => serde_json::json!({}),
        },
        candidates: match &candidates {
            Some(candidates) => serde_json::to_value(candidates)?,
            None => serde_json::json!([]),
        },
    };
    for (enabled, path) in [
        (config.report.html, "report.html"),
        (config.report.json, "report.json"),
        (config.report.sarif, "report.sarif"),
    ] {
        if !enabled {
            continue;
        }
        let expected = match path {
            "report.html" => render_html_report_with_version(&report_data, &run.tool_version)
                .map(|rendered| rendered.into_bytes()),
            "report.json" => render_json_report(&report_data),
            "report.sarif" => render_sarif_report_with_version(&report_data, &run.tool_version),
            _ => unreachable!("fixed report path"),
        }
        .map_err(|error| EvidenceError::InvalidSemantics {
            field: path.into(),
            detail: format!("could not deterministically render report: {error}"),
        })?;
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| EvidenceError::Missing(path.into()))?;
        let actual = read_verified_bytes(dir, entry)?;
        if actual != expected {
            return Err(EvidenceError::IdentityMismatch {
                field: path.into(),
                detail: "bytes do not match the deterministic verified evidence model".into(),
            });
        }
    }

    let scenario_ids = scenario_ids_from_inventory(inventory)?;
    for scenario_id in &scenario_ids {
        let scenario_dir = dir.join("scenarios").join(scenario_id);
        let verified =
            verify_bundle_internal(&scenario_dir, Some(&run.run_id.0), Some(scenario_id))?;
        if verified.kind != BundleKind::Scenario {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("scenarios/{scenario_id}/checksums.txt.kind"),
                detail: format!("expected scenario, found {}", verified.kind.as_str()),
            });
        }
        let verdict =
            verdict_by_id
                .get(scenario_id)
                .ok_or_else(|| EvidenceError::IdentityMismatch {
                    field: format!("scenarios/{scenario_id}"),
                    detail: "scenario bundle has no matching verdict".into(),
                })?;
        if verdict.evidence.is_none() {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("verdicts.json[{scenario_id}].evidence"),
                detail: "scenario bundle exists but verdict has no evidence reference".into(),
            });
        }
        let recorded_scenario: Scenario = read_typed_json(
            dir,
            inventory,
            &format!("scenarios/{scenario_id}/scenario.json"),
        )?;
        let recorded_result: ExecutionResult = read_typed_json(
            dir,
            inventory,
            &format!("scenarios/{scenario_id}/result.json"),
        )?;
        verify_verdict_result_consistency(verdict, &recorded_scenario, &recorded_result)?;
        let failure_path = format!("scenarios/{scenario_id}/failure-signature.json");
        if inventory_has(inventory, &failure_path) {
            let recorded: FailureSignature = read_typed_json(dir, inventory, &failure_path)?;
            validate_failure_signature(&failure_path, &recorded)?;
            let verdict_failure = verdict.failure_signature.as_ref().ok_or_else(|| {
                EvidenceError::IdentityMismatch {
                    field: format!("verdicts.json[{scenario_id}].failure_signature"),
                    detail: "scenario bundle records a failure signature but verdict does not"
                        .into(),
                }
            })?;
            ensure_semantic_equality(
                &failure_path,
                &recorded,
                "verdict failure signature",
                verdict_failure,
            )?;
        } else if verdict.failure_signature.is_some() {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("verdicts.json[{scenario_id}].failure_signature"),
                detail: "verdict signature has no scenario failure-signature.json".into(),
            });
        }
        if let Some(plan) = &plan {
            let planned = plan
                .scenarios
                .iter()
                .find(|scenario| scenario.id.0 == *scenario_id)
                .ok_or_else(|| EvidenceError::IdentityMismatch {
                    field: format!("scenarios/{scenario_id}/scenario.json"),
                    detail: "scenario is absent from plan.json".into(),
                })?;
            ensure_semantic_equality(
                &format!("scenarios/{scenario_id}/scenario.json"),
                &recorded_scenario,
                "plan.json scenario",
                planned,
            )?;
        }
    }

    for verdict in &verdicts {
        if normal_run
            && matches!(
                verdict.verdict,
                Verdict::Unsupported | Verdict::Inconclusive
            )
        {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("verdicts.json[{}].verdict", verdict.scenario_id),
                detail: "normal executed runs cannot contain UNSUPPORTED/INCONCLUSIVE verdicts"
                    .into(),
            });
        }
        if normal_run
            && verdict.verdict == Verdict::Blocked
            && (verdict.evidence_grade != EvidenceGrade::Inconclusive
                || verdict.evidence.is_some()
                || verdict.failure_signature.is_some()
                || verdict.notes.iter().all(|note| note.trim().is_empty()))
        {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("verdicts.json[{}]", verdict.scenario_id),
                detail: "BLOCKED requires inconclusive grade, no evidence/signature, and a nonempty reason"
                    .into(),
            });
        }
        if normal_run && verdict.verdict != Verdict::Blocked && verdict.evidence.is_none() {
            return Err(EvidenceError::IdentityMismatch {
                field: format!("verdicts.json[{}].evidence", verdict.scenario_id),
                detail: "executed non-BLOCKED verdict requires a sealed scenario bundle".into(),
            });
        }
        if let Some(evidence) = &verdict.evidence {
            ensure_identity(
                &format!("verdicts.json[{}].evidence.run_id", verdict.scenario_id),
                &evidence.run_id.0,
                &run.run_id.0,
            )?;
            ensure_identity(
                &format!(
                    "verdicts.json[{}].evidence.scenario_id",
                    verdict.scenario_id
                ),
                &evidence.scenario_id.0,
                &verdict.scenario_id.0,
            )?;
            if !scenario_ids.contains(&verdict.scenario_id.0) {
                return Err(EvidenceError::IdentityMismatch {
                    field: format!("verdicts.json[{}].evidence", verdict.scenario_id),
                    detail: "references a missing scenario bundle".into(),
                });
            }
            validate_evidence_directory(&evidence.directory, &verdict.scenario_id.0)?;
            let expected_replay = format!(
                "tomorrowci replay {} --scenario {}",
                run.run_id, verdict.scenario_id
            );
            ensure_identity(
                &format!(
                    "verdicts.json[{}].evidence.replay_command",
                    verdict.scenario_id
                ),
                &evidence.replay_command,
                &expected_replay,
            )?;
        }
        if let Some(plan) = &plan {
            let is_early = verdict.scenario_id.0 == "detect" || verdict.scenario_id.0 == "sandbox";
            if !is_early
                && !plan
                    .scenarios
                    .iter()
                    .any(|scenario| scenario.id == verdict.scenario_id)
            {
                return Err(EvidenceError::IdentityMismatch {
                    field: format!("verdicts.json[{}]", verdict.scenario_id),
                    detail: "verdict scenario is absent from plan.json".into(),
                });
            }
        }
    }

    if frontier.observed {
        let scenario_id =
            frontier
                .scenario_id
                .as_ref()
                .ok_or_else(|| EvidenceError::InvalidSemantics {
                    field: "frontier.json.scenario_id".into(),
                    detail: "an observed frontier must identify a scenario".into(),
                })?;
        let verdict =
            verdict_by_id
                .get(&scenario_id.0)
                .ok_or_else(|| EvidenceError::IdentityMismatch {
                    field: "frontier.json.scenario_id".into(),
                    detail: format!("{} has no matching verdict", scenario_id),
                })?;
        if verdict.verdict != Verdict::FutureFail {
            return Err(EvidenceError::InvalidSemantics {
                field: "frontier.json.scenario_id".into(),
                detail: format!("{} does not reference a FUTURE_FAIL verdict", scenario_id),
            });
        }
        if verdict.attempts < 2 || verdict.evidence.is_none() {
            return Err(EvidenceError::InvalidSemantics {
                field: "frontier.json.scenario_id".into(),
                detail: "an observed frontier requires a rerun FUTURE_FAIL with evidence".into(),
            });
        }
        let plan = plan.as_ref().ok_or_else(|| {
            EvidenceError::Missing("an observed frontier requires plan.json".into())
        })?;
        let baseline_scenario = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.is_baseline)
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: "plan.json.scenarios".into(),
                detail: "an observed frontier requires a baseline scenario".into(),
            })?;
        let baseline_verdict = verdict_by_id.get(&baseline_scenario.id.0).ok_or_else(|| {
            EvidenceError::IdentityMismatch {
                field: "frontier.json".into(),
                detail: "an observed frontier has no executed baseline verdict".into(),
            }
        })?;
        if baseline_verdict.verdict != Verdict::BaselinePass {
            return Err(EvidenceError::InvalidSemantics {
                field: "frontier.json".into(),
                detail: "an observed frontier requires a BASELINE_PASS".into(),
            });
        }
        let ordered_future: Vec<_> = verdicts
            .iter()
            .filter(|candidate| candidate.scenario_id != baseline_scenario.id)
            .collect();
        let first_fail_index = ordered_future
            .iter()
            .position(|candidate| candidate.verdict == Verdict::FutureFail)
            .ok_or_else(|| EvidenceError::InvalidSemantics {
                field: "frontier.json".into(),
                detail: "an observed frontier has no FUTURE_FAIL".into(),
            })?;
        if ordered_future[first_fail_index].scenario_id != *scenario_id {
            return Err(EvidenceError::IdentityMismatch {
                field: "frontier.json.scenario_id".into(),
                detail: "does not identify the first FUTURE_FAIL in verdict order".into(),
            });
        }
        let prior = if first_fail_index == 0 {
            baseline_verdict
        } else {
            ordered_future[first_fail_index - 1]
        };
        if !matches!(prior.verdict, Verdict::BaselinePass | Verdict::FuturePass) {
            return Err(EvidenceError::InvalidSemantics {
                field: "frontier.json.from_label".into(),
                detail: "the immediately prior environment did not pass".into(),
            });
        }
        let planned_failure = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.id == *scenario_id)
            .ok_or_else(|| EvidenceError::IdentityMismatch {
                field: "frontier.json.scenario_id".into(),
                detail: "scenario is absent from plan.json".into(),
            })?;
        ensure_optional_identity(
            "frontier.json.horizon_label",
            frontier.horizon_label.as_deref(),
            Some(verdict.label.as_str()),
        )?;
        ensure_optional_identity(
            "frontier.json.from_label",
            frontier.from_label.as_deref(),
            Some(prior.label.as_str()),
        )?;
        ensure_optional_identity(
            "frontier.json.to_label",
            frontier.to_label.as_deref(),
            Some(verdict.label.as_str()),
        )?;
        ensure_semantic_equality(
            "frontier.json.axis",
            &frontier.axis,
            "plan scenario first changed axis",
            &planned_failure.axes_changed.first().cloned(),
        )?;
        ensure_semantic_equality(
            "frontier.json.failure_signature",
            &frontier.failure_signature,
            "verdict failure signature",
            &verdict.failure_signature,
        )?;
        ensure_semantic_equality(
            "frontier.json.evidence_grade",
            &frontier.evidence_grade,
            "verdict evidence grade",
            &Some(verdict.evidence_grade),
        )?;
        let expected_replay = format!(
            "tomorrowci replay {} --scenario {}",
            run.run_id, verdict.scenario_id
        );
        ensure_optional_identity(
            "frontier.json.replay_command",
            frontier.replay_command.as_deref(),
            Some(&expected_replay),
        )?;
    } else if frontier.scenario_id.is_some()
        || frontier.horizon_label.is_some()
        || frontier.axis.is_some()
        || frontier.from_label.is_some()
        || frontier.to_label.is_some()
        || frontier.failure_signature.is_some()
        || frontier.evidence_grade.is_some()
        || frontier.replay_command.is_some()
    {
        return Err(EvidenceError::InvalidSemantics {
            field: "frontier.json".into(),
            detail: "an unobserved frontier cannot contain observed-claim fields".into(),
        });
    }
    if frontier.explanation.trim().is_empty() {
        return Err(EvidenceError::InvalidSemantics {
            field: "frontier.json.explanation".into(),
            detail: "frontier explanation must not be empty".into(),
        });
    }

    Ok(())
}

fn verify_scenario_semantics(
    dir: &Path,
    inventory: &BundleInventory,
    expected_run_id: Option<&str>,
    expected_scenario_id: Option<&str>,
) -> Result<()> {
    let scenario: Scenario = read_typed_json(dir, inventory, "scenario.json")?;
    let environment: EnvironmentSpec = read_typed_json(dir, inventory, "environment.json")?;
    let commands: Vec<CommandSpec> = read_typed_json(dir, inventory, "commands.json")?;
    let result: ExecutionResult = read_typed_json(dir, inventory, "result.json")?;
    let replay: ReplayManifest = read_typed_json(dir, inventory, "replay-manifest.json")?;
    let failure = if inventory_has(inventory, "failure-signature.json") {
        let signature: FailureSignature =
            read_typed_json(dir, inventory, "failure-signature.json")?;
        validate_failure_signature("failure-signature.json", &signature)?;
        Some(signature)
    } else {
        None
    };

    validate_single_component(&scenario.id.0, "scenario.json id")?;
    let directory_id = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| EvidenceError::InvalidSemantics {
            field: "scenario directory".into(),
            detail: format!("{} has no UTF-8 final component", dir.display()),
        })?;
    ensure_identity("scenario directory", directory_id, &scenario.id.0)?;
    if let Some(expected) = expected_scenario_id {
        ensure_identity("scenario.json.id", &scenario.id.0, expected)?;
    }
    if let Some(expected) = expected_run_id {
        ensure_identity("replay-manifest.json.run_id", &replay.run_id, expected)?;
    }
    validate_single_component(&replay.run_id, "replay run id")?;
    ensure_identity(
        "result.json.scenario_id",
        &result.scenario_id.0,
        &scenario.id.0,
    )?;
    ensure_identity(
        "replay-manifest.json.scenario_id",
        &replay.scenario_id,
        &scenario.id.0,
    )?;
    if result.attempt == 0 {
        return Err(EvidenceError::InvalidSemantics {
            field: "result.json.attempt".into(),
            detail: "attempt must be at least 1".into(),
        });
    }
    validate_image_identity(
        "environment.json",
        &environment.image_ref,
        environment.image_digest.as_deref(),
    )?;
    let result_passed = result.exit_code == Some(0)
        && result.signal.is_none()
        && !result.timed_out
        && result.blocked_reason.is_none();
    if !result_passed && failure.is_none() {
        return Err(EvidenceError::InvalidSemantics {
            field: "failure-signature.json".into(),
            detail: "a failing recorded execution requires a failure signature".into(),
        });
    }
    if let Some(signature) = &failure {
        if signature.evidence_grade != scenario.evidence_grade {
            return Err(EvidenceError::IdentityMismatch {
                field: "failure-signature.json.evidence_grade".into(),
                detail: format!(
                    "expected {:?}, found {:?}",
                    scenario.evidence_grade, signature.evidence_grade
                ),
            });
        }
    }

    ensure_identity(
        "scenario.json.image_ref",
        &scenario.image_ref,
        &environment.image_ref,
    )?;

    ensure_identity(
        "result.json.image_ref",
        &result.image_ref,
        &environment.image_ref,
    )?;
    ensure_optional_identity(
        "result.json.image_digest",
        result.image_digest.as_deref(),
        environment.image_digest.as_deref(),
    )?;
    ensure_identity(
        "replay-manifest.json.image_ref",
        &replay.image_ref,
        &environment.image_ref,
    )?;
    ensure_optional_identity(
        "replay-manifest.json.image_digest",
        replay.image_digest.as_deref(),
        environment.image_digest.as_deref(),
    )?;
    ensure_semantic_equality(
        "result.json.commands",
        &result.commands,
        "commands.json",
        &commands,
    )?;
    ensure_semantic_equality(
        "replay-manifest.json.commands",
        &replay.commands,
        "commands.json",
        &commands,
    )?;
    ensure_identity(
        "replay-manifest.json.workdir",
        &replay.workdir,
        &environment.workdir,
    )?;
    if replay.memory_mb != environment.memory_mb
        || replay.cpus.to_bits() != environment.cpus.to_bits()
        || replay.pids_limit != environment.pids_limit
        || replay.timeout_seconds != environment.timeout_seconds
    {
        return Err(EvidenceError::IdentityMismatch {
            field: "replay-manifest.json.resources".into(),
            detail: "memory/cpu/pids/timeout differ from environment.json".into(),
        });
    }
    let network_mode = format!("{:?}", environment.network_mode);
    ensure_identity(
        "replay-manifest.json.network_mode",
        &replay.network_mode,
        &network_mode,
    )?;

    Ok(())
}

fn verify_verdict_result_consistency(
    verdict: &ScenarioVerdict,
    scenario: &Scenario,
    result: &ExecutionResult,
) -> Result<()> {
    ensure_identity(
        &format!("verdicts.json[{}].label", verdict.scenario_id),
        &verdict.label,
        &scenario.label,
    )?;
    if verdict.attempts == 0 || result.attempt == 0 || result.attempt > verdict.attempts {
        return Err(EvidenceError::InvalidSemantics {
            field: format!("verdicts.json[{}].attempts", verdict.scenario_id),
            detail: format!(
                "recorded attempt {} is inconsistent with verdict attempts {}",
                result.attempt, verdict.attempts
            ),
        });
    }

    let allowed_kind = if scenario.is_baseline {
        matches!(
            verdict.verdict,
            Verdict::BaselinePass | Verdict::BaselineInvalid | Verdict::Flaky | Verdict::Blocked
        )
    } else {
        matches!(
            verdict.verdict,
            Verdict::FuturePass | Verdict::FutureFail | Verdict::Flaky | Verdict::Blocked
        )
    };
    if !allowed_kind {
        return Err(EvidenceError::InvalidSemantics {
            field: format!("verdicts.json[{}].verdict", verdict.scenario_id),
            detail: format!(
                "{:?} is inconsistent with scenario.is_baseline={}",
                verdict.verdict, scenario.is_baseline
            ),
        });
    }

    let expected_grade = if verdict.verdict == Verdict::Blocked {
        EvidenceGrade::Inconclusive
    } else {
        scenario.evidence_grade
    };
    if verdict.evidence_grade != expected_grade {
        return Err(EvidenceError::IdentityMismatch {
            field: format!("verdicts.json[{}].evidence_grade", verdict.scenario_id),
            detail: format!(
                "expected {:?}, found {:?}",
                expected_grade, verdict.evidence_grade
            ),
        });
    }
    if let Some(signature) = &verdict.failure_signature {
        if signature.evidence_grade != verdict.evidence_grade {
            return Err(EvidenceError::IdentityMismatch {
                field: format!(
                    "verdicts.json[{}].failure_signature.evidence_grade",
                    verdict.scenario_id
                ),
                detail: format!(
                    "expected {:?}, found {:?}",
                    verdict.evidence_grade, signature.evidence_grade
                ),
            });
        }
    }
    let result_passed = result.exit_code == Some(0)
        && result.signal.is_none()
        && !result.timed_out
        && result.blocked_reason.is_none();
    match verdict.verdict {
        Verdict::BaselinePass | Verdict::FuturePass => {
            if !result_passed || verdict.failure_signature.is_some() {
                return Err(EvidenceError::InvalidSemantics {
                    field: format!("verdicts.json[{}].verdict", verdict.scenario_id),
                    detail: "PASS verdict disagrees with the recorded execution result".into(),
                });
            }
        }
        Verdict::BaselineInvalid | Verdict::FutureFail => {
            if result_passed || verdict.failure_signature.is_none() {
                return Err(EvidenceError::InvalidSemantics {
                    field: format!("verdicts.json[{}].verdict", verdict.scenario_id),
                    detail:
                        "FAIL verdict disagrees with the recorded execution result or signature"
                            .into(),
                });
            }
        }
        Verdict::Flaky => {
            if verdict.attempts < 2 || verdict.failure_signature.is_none() {
                return Err(EvidenceError::InvalidSemantics {
                    field: format!("verdicts.json[{}].attempts", verdict.scenario_id),
                    detail: "FLAKY requires at least two outcomes and a retained failure signature"
                        .into(),
                });
            }
        }
        Verdict::Blocked => {}
        Verdict::Unsupported | Verdict::Inconclusive => unreachable!("filtered above"),
    }
    Ok(())
}

fn validate_image_identity(field: &str, image_ref: &str, digest: Option<&str>) -> Result<()> {
    if image_ref.trim().is_empty()
        || image_ref.len() > 2048
        || image_ref.chars().any(char::is_control)
    {
        return Err(EvidenceError::InvalidSemantics {
            field: format!("{field}.image_ref"),
            detail: "image reference must be nonempty, bounded, and control-free".into(),
        });
    }
    if let Some(digest) = digest {
        let hexadecimal =
            digest
                .strip_prefix("sha256:")
                .ok_or_else(|| EvidenceError::InvalidSemantics {
                    field: format!("{field}.image_digest"),
                    detail: "digest must use sha256:<64 lowercase hexadecimal characters>".into(),
                })?;
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvidenceError::InvalidSemantics {
                field: format!("{field}.image_digest"),
                detail: "digest must use sha256:<64 lowercase hexadecimal characters>".into(),
            });
        }
    }
    Ok(())
}

fn validate_failure_signature(field: &str, signature: &FailureSignature) -> Result<()> {
    let expected = FailureSignature::compute_fingerprint(
        &signature.kind,
        signature.primary_error.as_deref().unwrap_or_default(),
        &signature.summary,
    );
    if signature.fingerprint != expected {
        return Err(EvidenceError::IdentityMismatch {
            field: format!("{field}.fingerprint"),
            detail: format!(
                "does not match the canonical fingerprint of the stored signature fields (expected {expected})"
            ),
        });
    }
    Ok(())
}

fn read_typed_json<T: DeserializeOwned>(
    root: &Path,
    inventory: &BundleInventory,
    relative: &str,
) -> Result<T> {
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.path == relative)
        .ok_or_else(|| EvidenceError::Missing(format!("{relative} is not inventoried")))?;
    let bytes = read_verified_bytes(root, entry)?;
    if bytes.len() > MAX_TYPED_JSON_BYTES {
        return Err(EvidenceError::InvalidSemantics {
            field: relative.to_string(),
            detail: format!("typed JSON exceeds {MAX_TYPED_JSON_BYTES} bytes"),
        });
    }
    serde_json::from_slice(&bytes).map_err(|source| EvidenceError::InvalidJson {
        path: relative.to_string(),
        source,
    })
}

fn read_verified_bytes(root: &Path, entry: &InventoryEntry) -> Result<Vec<u8>> {
    let path = root.join(&entry.path);
    let metadata_before = fs::symlink_metadata(&path)?;
    ensure_regular_metadata(&metadata_before, &entry.path)?;
    let mut file = File::open(&path)?;
    let opened_metadata = file.metadata()?;
    ensure_regular_metadata(&opened_metadata, &entry.path)?;
    if opened_metadata.len() > MAX_VERIFIED_READ_BYTES {
        return Err(EvidenceError::InvalidSemantics {
            field: entry.path.clone(),
            detail: format!("verified read exceeds {MAX_VERIFIED_READ_BYTES} bytes"),
        });
    }
    let mut bytes = Vec::new();
    Read::take(&mut file, MAX_VERIFIED_READ_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_VERIFIED_READ_BYTES {
        return Err(EvidenceError::InvalidSemantics {
            field: entry.path.clone(),
            detail: format!("verified read exceeds {MAX_VERIFIED_READ_BYTES} bytes"),
        });
    }
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != entry.sha256 {
        return Err(EvidenceError::ChecksumMismatch {
            path: entry.path.clone(),
            expected: entry.sha256.clone(),
            actual,
        });
    }
    let metadata_after = fs::symlink_metadata(&path)?;
    ensure_regular_metadata(&metadata_after, &entry.path)?;
    if opened_metadata.len() != metadata_after.len()
        || opened_metadata.modified().ok() != metadata_after.modified().ok()
    {
        return Err(EvidenceError::Other(format!(
            "evidence file changed while reading verified bytes: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn inventory_has(inventory: &BundleInventory, path: &str) -> bool {
    inventory.entries.iter().any(|entry| entry.path == path)
}

fn scenario_ids_from_inventory(inventory: &BundleInventory) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for entry in &inventory.entries {
        let Some(relative) = entry.path.strip_prefix("scenarios/") else {
            continue;
        };
        let (id, nested) =
            relative
                .split_once('/')
                .ok_or_else(|| EvidenceError::InvalidSemantics {
                    field: entry.path.clone(),
                    detail: "files in scenarios/ must be below a scenario-id directory".into(),
                })?;
        validate_single_component(id, "scenario directory id")?;
        if nested.is_empty() {
            return Err(EvidenceError::InvalidSemantics {
                field: entry.path.clone(),
                detail: "scenario evidence path is empty".into(),
            });
        }
        ids.insert(id.to_string());
    }
    for id in &ids {
        let checksum = format!("scenarios/{id}/{INVENTORY_FILE_NAME}");
        if !inventory_has(inventory, &checksum) {
            return Err(EvidenceError::Missing(format!(
                "scenario {id} has no sealed {INVENTORY_FILE_NAME}"
            )));
        }
    }
    Ok(ids)
}

fn ensure_identity(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(EvidenceError::IdentityMismatch {
            field: field.to_string(),
            detail: format!("expected {expected:?}, found {actual:?}"),
        })
    }
}

fn ensure_optional_identity(
    field: &str,
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(EvidenceError::IdentityMismatch {
            field: field.to_string(),
            detail: format!("expected {expected:?}, found {actual:?}"),
        })
    }
}

fn ensure_semantic_equality<L: Serialize, R: Serialize>(
    left_label: &str,
    left: &L,
    right_label: &str,
    right: &R,
) -> Result<()> {
    let left_value = serde_json::to_value(left)?;
    let right_value = serde_json::to_value(right)?;
    if left_value == right_value {
        Ok(())
    } else {
        Err(EvidenceError::IdentityMismatch {
            field: left_label.to_string(),
            detail: format!("does not equal {right_label}"),
        })
    }
}

fn validate_evidence_directory(path: &Path, scenario_id: &str) -> Result<()> {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let suffix = format!("scenarios/{scenario_id}");
    if normalized == suffix || normalized.ends_with(&format!("/{suffix}")) {
        Ok(())
    } else {
        Err(EvidenceError::IdentityMismatch {
            field: "verdict evidence directory".into(),
            detail: format!("{} does not identify {suffix}", path.display()),
        })
    }
}

fn write_checksums(dir: &Path, kind: BundleKind) -> Result<()> {
    seal_bundle(dir, kind)?;
    Ok(())
}

fn read_inventory_with_contents(dir: &Path) -> Result<(String, BundleInventory)> {
    ensure_directory(dir)?;
    let path = dir.join(INVENTORY_FILE_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EvidenceError::Missing(format!("{} is missing", path.display()))
        } else {
            EvidenceError::Io(error)
        }
    })?;
    ensure_regular_metadata(&metadata, INVENTORY_FILE_NAME)?;
    // Bound attacker-controlled allocation while leaving room for very large
    // bundles (roughly 150k entries at the current record size).
    if metadata.len() > MAX_INVENTORY_BYTES {
        return Err(EvidenceError::MalformedInventory {
            line: 0,
            reason: "inventory exceeds 16 MiB".into(),
        });
    }
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    Read::take(&mut file, MAX_INVENTORY_BYTES + 1).read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_INVENTORY_BYTES {
        return Err(EvidenceError::MalformedInventory {
            line: 0,
            reason: "inventory exceeds 16 MiB".into(),
        });
    }
    let inventory = BundleInventory::parse(&contents)?;
    Ok((contents, inventory))
}

fn persist_regular_file(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        EvidenceError::UnsafePath(format!("file has no parent: {}", path.display()))
    })?;
    ensure_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| EvidenceError::UnsafePath(path.display().to_string()))?;
    let mut temporary = None;
    for _ in 0..100 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        EvidenceError::Other(format!(
            "could not allocate temporary file for {}",
            path.display()
        ))
    })?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    Ok(())
}

fn persist_inventory(dir: &Path, contents: &[u8]) -> Result<()> {
    ensure_directory(dir)?;
    let target = dir.join(INVENTORY_FILE_NAME);
    if let Ok(metadata) = fs::symlink_metadata(&target) {
        ensure_regular_metadata(&metadata, INVENTORY_FILE_NAME)?;
    }

    let mut temporary = None;
    for _ in 0..100 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = dir.join(format!(
            ".{INVENTORY_FILE_NAME}.tmp-{}-{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        EvidenceError::Other("could not allocate a temporary inventory file".into())
    })?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    drop(file);

    if let Err(error) = fs::rename(&temporary_path, &target) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    Ok(())
}

fn collect_regular_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    ensure_directory(dir)?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    let mut total_entries = 0_usize;
    collect_regular_files_from(
        dir,
        dir,
        "",
        0,
        &mut total_bytes,
        &mut total_entries,
        &mut files,
    )?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

fn collect_regular_files_from(
    root: &Path,
    current: &Path,
    relative_parent: &str,
    depth: usize,
    total_bytes: &mut u64,
    total_entries: &mut usize,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(current)? {
        *total_entries =
            total_entries
                .checked_add(1)
                .ok_or_else(|| EvidenceError::InvalidSemantics {
                    field: current.display().to_string(),
                    detail: "bundle entry count overflowed".into(),
                })?;
        if *total_entries > MAX_BUNDLE_FILES {
            return Err(EvidenceError::InvalidSemantics {
                field: current.display().to_string(),
                detail: format!("bundle contains more than {MAX_BUNDLE_FILES} entries"),
            });
        }
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            EvidenceError::UnsafePath(format!("non-UTF-8 entry below {}", root.display()))
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
                    detail: format!("bundle nesting exceeds {MAX_BUNDLE_DEPTH} directories"),
                });
            }
            collect_regular_files_from(
                root,
                &path,
                &relative,
                depth + 1,
                total_bytes,
                total_entries,
                files,
            )?;
        } else if metadata.is_file() {
            if relative != INVENTORY_FILE_NAME {
                if files.len() >= MAX_BUNDLE_FILES {
                    return Err(EvidenceError::InvalidSemantics {
                        field: relative,
                        detail: format!("bundle contains more than {MAX_BUNDLE_FILES} files"),
                    });
                }
                *total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    EvidenceError::InvalidSemantics {
                        field: relative.clone(),
                        detail: "bundle byte count overflowed".into(),
                    }
                })?;
                if *total_bytes > MAX_BUNDLE_BYTES {
                    return Err(EvidenceError::InvalidSemantics {
                        field: relative,
                        detail: format!("bundle exceeds {MAX_BUNDLE_BYTES} total bytes"),
                    });
                }
                files.push((relative, path));
            }
        } else {
            return Err(EvidenceError::NonRegularEntry(relative));
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EvidenceError::Missing(format!("bundle directory not found: {}", path.display()))
        } else {
            EvidenceError::Io(error)
        }
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(EvidenceError::NonRegularEntry(path.display().to_string()));
    }
    Ok(())
}

fn ensure_regular_metadata(metadata: &Metadata, display: &str) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(EvidenceError::NonRegularEntry(display.to_string()));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn validate_single_component(value: &str, label: &str) -> Result<()> {
    validate_inventory_path(value)?;
    if value.contains('/') {
        return Err(EvidenceError::UnsafePath(format!(
            "{label} must be one path component: {value}"
        )));
    }
    Ok(())
}

fn validate_inventory_path(path: &str) -> Result<()> {
    let unsafe_component = path.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.trim() != component
            || component.ends_with('.')
            || is_windows_reserved_component(component)
    });
    if path.is_empty()
        || path.trim() != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(char::is_control)
        || path.contains(':')
        || Path::new(path).is_absolute()
        || unsafe_component
    {
        return Err(EvidenceError::UnsafePath(path.to_string()));
    }
    Ok(())
}

fn is_windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .and_then(|suffix| suffix.parse::<u8>().ok())
            .is_some_and(|number| (1..=9).contains(&number))
        || stem
            .strip_prefix("LPT")
            .and_then(|suffix| suffix.parse::<u8>().ok())
            .is_some_and(|number| (1..=9).contains(&number))
}

fn sha256_regular_file(path: &Path) -> Result<String> {
    let metadata_before = fs::symlink_metadata(path)?;
    ensure_regular_metadata(&metadata_before, &path.display().to_string())?;
    let mut file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    ensure_regular_metadata(&opened_metadata, &path.display().to_string())?;

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let metadata_after = fs::symlink_metadata(path)?;
    ensure_regular_metadata(&metadata_after, &path.display().to_string())?;
    if opened_metadata.len() != metadata_after.len()
        || opened_metadata.modified().ok() != metadata_after.modified().ok()
    {
        return Err(EvidenceError::Other(format!(
            "evidence file changed while hashing: {}",
            path.display()
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    sha256_regular_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};
    use tomorrowci_core::{
        Candidate, CommandPhase, DependencyMode, Ecosystem, EnvironmentAxis, EvidenceGrade,
        EvidenceReference, HostInfo, NetworkMode, RunId, ScenarioId, ScenarioKind,
    };

    const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn generic_bundle() -> TempDir {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("nested/deeper")).unwrap();
        fs::write(dir.path().join("root.json"), b"root").unwrap();
        fs::write(dir.path().join("nested/deeper/result.json"), b"nested").unwrap();
        seal_bundle(dir.path(), BundleKind::Generic).unwrap();
        dir
    }

    fn inventory_text(kind: BundleKind, records: &[(&str, &str)]) -> String {
        let mut text = format!(
            "{INVENTORY_HEADER_V1_PREFIX}{}{INVENTORY_HEADER_V1_SUFFIX}\n",
            kind.as_str()
        );
        for (digest, path) in records {
            text.push_str(digest);
            text.push_str("  ");
            text.push_str(path);
            text.push('\n');
        }
        text
    }

    fn sample_scenario(id: &str) -> Scenario {
        Scenario {
            id: ScenarioId::new(id),
            kind: ScenarioKind::Baseline,
            ecosystem: Ecosystem::Python,
            label: "baseline".into(),
            runtime_version: "3.12".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.12-bookworm".into(),
            axes_changed: vec![],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: true,
            selection_reason: "fixture".into(),
        }
    }

    fn sample_command() -> CommandSpec {
        CommandSpec {
            phase: CommandPhase::Test,
            program: "python".into(),
            args: vec!["-m".into(), "pytest".into()],
            workdir: "/workspace".into(),
            network_required: false,
            env: Default::default(),
        }
    }

    fn valid_run_bundle(run_id: &str) -> (TempDir, EvidenceStore) {
        let dir = tempdir().unwrap();
        let store = EvidenceStore::create(dir.path(), run_id).unwrap();
        let workspace = dir.path().join("work/workspaces").join(run_id);
        fs::create_dir_all(&workspace).unwrap();
        let mut config = Config::default();
        config.report.html = false;
        config.report.json = false;
        config.execution.max_scenarios = 1;
        config.execution.max_parallel = 1;
        let repository = RepositorySnapshot {
            source: "fixture".into(),
            path: dir.path().join("source"),
            commit_sha: Some("0123456789abcdef".into()),
            branch: Some("main".into()),
            is_remote: false,
            workspace_copy: workspace,
            captured_at: chrono::Utc::now(),
        };
        let detection = ProjectDetection {
            ecosystem: Ecosystem::Python,
            package_manager: "pip".into(),
            manifests: vec!["pyproject.toml".into()],
            confidence: 1.0,
            notes: vec![],
            supported: true,
            unsupported_reason: None,
        };
        let baseline = tomorrowci_core::Baseline {
            ecosystem: Ecosystem::Python,
            runtime_label: "Python 3.12".into(),
            runtime_version: "3.12".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.12-bookworm".into(),
            notes: vec![],
        };
        let scenario = sample_scenario("baseline");
        let command = sample_command();
        let environment = EnvironmentSpec {
            image_ref: scenario.image_ref.clone(),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            workdir: "/workspace".into(),
            user: None,
            env: Default::default(),
            mounts: vec![],
            network_mode: NetworkMode::None,
            read_only_root: false,
            memory_mb: 1024,
            cpus: 1.0,
            pids_limit: 128,
            timeout_seconds: 60,
        };
        let raw = RawExecutionResult {
            exit_code: Some(0),
            signal: None,
            stdout: "ok".into(),
            stderr: String::new(),
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            error: None,
        };
        let result = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: 1,
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            stdout_path: None,
            stderr_path: None,
            stdout_preview: "ok".into(),
            stderr_preview: String::new(),
            blocked_reason: None,
            image_ref: environment.image_ref.clone(),
            image_digest: environment.image_digest.clone(),
            commands: vec![command.clone()],
        };
        store
            .write_scenario_bundle(
                &scenario,
                &environment,
                std::slice::from_ref(&command),
                &raw,
                &result,
                None,
            )
            .unwrap();
        let plan = ExecutionPlan {
            run_id: RunId(run_id.into()),
            scenarios: vec![scenario.clone()],
            max_scenarios: 1,
            max_parallel: 1,
            decisions: vec![],
            untested: vec![],
        };
        let evidence = EvidenceReference {
            run_id: RunId(run_id.into()),
            scenario_id: scenario.id.clone(),
            directory: store.scenario_dir(&scenario.id.0),
            replay_command: format!("tomorrowci replay {run_id} --scenario {}", scenario.id),
        };
        let verdict = ScenarioVerdict {
            scenario_id: scenario.id.clone(),
            label: scenario.label.clone(),
            verdict: Verdict::BaselinePass,
            evidence_grade: EvidenceGrade::Observed,
            attempts: 1,
            failure_signature: None,
            evidence: Some(evidence),
            notes: vec![],
        };
        let frontier = BreakageFrontier {
            observed: false,
            horizon_label: None,
            scenario_id: None,
            axis: None,
            from_label: None,
            to_label: None,
            failure_signature: None,
            evidence_grade: None,
            replay_command: None,
            explanation: "No observed breakage horizon.".into(),
        };
        let started = chrono::Utc::now();
        let run = RunManifest {
            run_id: RunId(run_id.into()),
            tool_version: "0.1.0".into(),
            started_at: started,
            finished_at: Some(started + chrono::Duration::seconds(1)),
            repository: repository.clone(),
            detection: Some(detection.clone()),
            baseline: Some(baseline),
            config_hash: config.config_hash().unwrap(),
            sandbox_engine: Some("test".into()),
            status: RunStatus::Completed,
            frontier: Some(frontier.clone()),
            scenario_count: 1,
            host: HostInfo::default(),
        };
        store.write_config(&config).unwrap();
        store.write_repository(&repository).unwrap();
        store.write_detection(&detection).unwrap();
        store.write_candidates(&serde_json::json!([])).unwrap();
        store.write_plan(&plan).unwrap();
        store.write_verdicts(&[verdict]).unwrap();
        store.write_frontier(&frontier).unwrap();
        store.write_run_manifest(&run).unwrap();
        store.finalize_checksums().unwrap();
        (dir, store)
    }

    fn rewrite_json_and_reseal(
        root: &Path,
        kind: BundleKind,
        relative: &str,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let path = root.join(relative);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut value);
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        seal_integrity_only(root, kind);
    }

    fn seal_integrity_only(root: &Path, kind: BundleKind) {
        let entries = collect_regular_files(root)
            .unwrap()
            .into_iter()
            .map(|(path, absolute)| InventoryEntry {
                path,
                sha256: sha256_regular_file(&absolute).unwrap(),
            })
            .collect();
        let inventory = BundleInventory {
            version: INVENTORY_VERSION,
            kind,
            entries,
        };
        persist_inventory(root, inventory.to_canonical_string().unwrap().as_bytes()).unwrap();
    }

    #[test]
    fn writes_and_loads_replay_manifest() {
        let (_dir, store) = valid_run_bundle("abc123");
        let m = store.load_replay_manifest("baseline").unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(m.image_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(m.scenario_id, "baseline");
        let verified = verify_bundle(&store.scenario_dir("baseline")).unwrap();
        assert_eq!(verified.kind, BundleKind::Scenario);
        assert_eq!(verified.file_count, 9);
        let verified_run = store.verify().unwrap();
        assert_eq!(verified_run.kind, BundleKind::Run);
        assert_eq!(verified_run.file_count, 18);
    }

    fn assert_semantic_failure(result: Result<VerifiedBundle>, expected: &str) {
        let error = result.expect_err("semantically mixed bundle was accepted");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }

    #[test]
    fn rejects_self_resealed_config_hash_repository_frontier_and_timestamps() {
        let (_dir, store) = valid_run_bundle("semantic-run");
        rewrite_json_and_reseal(
            &store.root,
            BundleKind::Run,
            "config.normalized.json",
            |value| value["execution"]["timeout_seconds"] = serde_json::json!(61),
        );
        assert_semantic_failure(verify_bundle(&store.root), "config_hash");

        let (_dir, store) = valid_run_bundle("semantic-repository");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "repository.json", |value| {
            value["source"] = serde_json::json!("mixed-source")
        });
        assert_semantic_failure(verify_bundle(&store.root), "repository");

        let (_dir, store) = valid_run_bundle("semantic-frontier");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "frontier.json", |value| {
            value["explanation"] = serde_json::json!("forged frontier")
        });
        assert_semantic_failure(verify_bundle(&store.root), "frontier");

        let (_dir, store) = valid_run_bundle("semantic-time");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["finished_at"] = serde_json::json!("2000-01-01T00:00:00Z")
        });
        assert_semantic_failure(verify_bundle(&store.root), "precedes start");

        let (_dir, store) = valid_run_bundle("semantic-tool-version");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["tool_version"] = serde_json::json!("</p><script>alert(1)</script>")
        });
        assert_semantic_failure(
            verify_bundle(&store.root),
            "must be a non-empty portable version identifier",
        );

        let (_dir, store) = valid_run_bundle("semantic-host-version");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["host"]["tomorrowci_version"] = serde_json::json!("9.9.9")
        });
        assert_semantic_failure(verify_bundle(&store.root), "host.tomorrowci_version");

        let (_dir, store) = valid_run_bundle("semantic-unknown-field");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["attacker_claim"] = serde_json::json!("ignored by a permissive parser")
        });
        assert_semantic_failure(verify_bundle(&store.root), "unknown field");
    }

    #[test]
    fn rejects_run_id_mixing_for_direct_paths_and_evidence_stores() {
        let (_dir, store) = valid_run_bundle("expected-run");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["run_id"] = serde_json::json!("mixed-run")
        });
        assert_semantic_failure(verify_bundle(&store.root), "plan.json.run_id");

        let (_dir, store) = valid_run_bundle("store-run");
        for (relative, pointer) in [
            ("run.json", "/run_id"),
            ("plan.json", "/run_id"),
            ("verdicts.json", "/0/evidence/run_id"),
        ] {
            rewrite_json_and_reseal(&store.root, BundleKind::Run, relative, |value| {
                *value.pointer_mut(pointer).unwrap() = serde_json::json!("other-run")
            });
        }
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(
            &scenario,
            BundleKind::Scenario,
            "replay-manifest.json",
            |value| value["run_id"] = serde_json::json!("other-run"),
        );
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            value[0]["evidence"]["replay_command"] =
                serde_json::json!("tomorrowci replay other-run --scenario baseline")
        });
        assert_semantic_failure(store.verify(), "run.json.run_id");
    }

    #[test]
    fn rejects_nested_scenario_result_and_replay_id_mixing() {
        let (_dir, store) = valid_run_bundle("scenario-id-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(&scenario, BundleKind::Scenario, "scenario.json", |value| {
            value["id"] = serde_json::json!("other-scenario")
        });
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(verify_bundle(&store.root), "scenario directory");

        let (_dir, store) = valid_run_bundle("result-id-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(&scenario, BundleKind::Scenario, "result.json", |value| {
            value["scenario_id"] = serde_json::json!("other-scenario")
        });
        assert_semantic_failure(verify_bundle(&scenario), "result.json.scenario_id");

        let (_dir, store) = valid_run_bundle("replay-id-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(
            &scenario,
            BundleKind::Scenario,
            "replay-manifest.json",
            |value| value["scenario_id"] = serde_json::json!("other-scenario"),
        );
        assert_semantic_failure(verify_bundle(&scenario), "replay-manifest.json.scenario_id");
    }

    #[test]
    fn rejects_scenario_image_digest_and_command_mixing() {
        let (_dir, store) = valid_run_bundle("image-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(
            &scenario,
            BundleKind::Scenario,
            "environment.json",
            |value| value["image_ref"] = serde_json::json!("python:attacker"),
        );
        assert_semantic_failure(verify_bundle(&scenario), "scenario.json.image_ref");

        let (_dir, store) = valid_run_bundle("digest-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(
            &scenario,
            BundleKind::Scenario,
            "environment.json",
            |value| value["image_digest"] = serde_json::json!(format!("sha256:{}", "b".repeat(64))),
        );
        assert_semantic_failure(verify_bundle(&scenario), "result.json.image_digest");

        let (_dir, store) = valid_run_bundle("commands-run");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(&scenario, BundleKind::Scenario, "commands.json", |value| {
            value[0]["program"] = serde_json::json!("attacker")
        });
        assert_semantic_failure(verify_bundle(&scenario), "result.json.commands");

        let (_dir, store) = valid_run_bundle("malformed-digest-run");
        let scenario = store.scenario_dir("baseline");
        for relative in ["environment.json", "result.json", "replay-manifest.json"] {
            rewrite_json_and_reseal(&scenario, BundleKind::Scenario, relative, |value| {
                value["image_digest"] = serde_json::json!("sha256:not-a-digest")
            });
        }
        assert_semantic_failure(
            verify_bundle(&scenario),
            "digest must use sha256:<64 lowercase hexadecimal characters>",
        );
    }

    #[test]
    fn rejects_completed_blocked_dangling_and_duplicate_verdicts() {
        let (_dir, store) = valid_run_bundle("completed-blocked");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            value[0]["verdict"] = serde_json::json!("BLOCKED")
        });
        assert_semantic_failure(
            verify_bundle(&store.root),
            "COMPLETED run contains a BLOCKED",
        );

        let (_dir, store) = valid_run_bundle("canonical-normal-blocked");
        fs::remove_dir_all(store.scenario_dir("baseline")).unwrap();
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            value[0]["verdict"] = serde_json::json!("BLOCKED");
            value[0]["evidence_grade"] = serde_json::json!("INCONCLUSIVE");
            value[0]["attempts"] = serde_json::json!(0);
            value[0]["failure_signature"] = serde_json::Value::Null;
            value[0]["evidence"] = serde_json::Value::Null;
            value[0]["notes"] = serde_json::json!(["sandbox execution failed"]);
        });
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["status"] = serde_json::json!("BLOCKED")
        });
        verify_bundle(&store.root).unwrap();

        let (_dir, store) = valid_run_bundle("forged-normal-blocked-evidence");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            value[0]["verdict"] = serde_json::json!("BLOCKED");
            value[0]["evidence_grade"] = serde_json::json!("INCONCLUSIVE");
            value[0]["notes"] = serde_json::json!(["claimed block"]);
        });
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "run.json", |value| {
            value["status"] = serde_json::json!("BLOCKED")
        });
        assert_semantic_failure(
            verify_bundle(&store.root),
            "BLOCKED requires inconclusive grade, no evidence/signature, and a nonempty reason",
        );

        let (_dir, store) = valid_run_bundle("dangling-reference");
        fs::remove_dir_all(store.scenario_dir("baseline")).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(verify_bundle(&store.root), "missing scenario bundle");

        let (_dir, store) = valid_run_bundle("missing-evidence-reference");
        fs::remove_dir_all(store.scenario_dir("baseline")).unwrap();
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            value[0]["evidence"] = serde_json::Value::Null;
        });
        assert_semantic_failure(
            verify_bundle(&store.root),
            "executed non-BLOCKED verdict requires a sealed scenario bundle",
        );

        let (_dir, store) = valid_run_bundle("duplicate-verdict");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "verdicts.json", |value| {
            let duplicate = value[0].clone();
            value.as_array_mut().unwrap().push(duplicate);
        });
        assert_semantic_failure(verify_bundle(&store.root), "duplicate verdict scenario");

        let (_dir, store) = valid_run_bundle("duplicate-plan");
        rewrite_json_and_reseal(&store.root, BundleKind::Run, "plan.json", |value| {
            let duplicate = value["scenarios"][0].clone();
            value["scenarios"].as_array_mut().unwrap().push(duplicate);
        });
        assert_semantic_failure(verify_bundle(&store.root), "duplicate plan scenario");
    }

    #[test]
    fn rejects_empty_completed_run_and_forged_pass_result() {
        let (_dir, store) = valid_run_bundle("empty-completed");
        fs::remove_dir_all(store.root.join("scenarios")).unwrap();
        for name in ["detection.json", "candidates.json", "plan.json"] {
            fs::remove_file(store.root.join(name)).unwrap();
        }
        fs::write(store.root.join("verdicts.json"), b"[]").unwrap();
        let run_path = store.root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_slice(&fs::read(&run_path).unwrap()).unwrap();
        run["detection"] = serde_json::Value::Null;
        run["baseline"] = serde_json::Value::Null;
        run["sandbox_engine"] = serde_json::Value::Null;
        run["scenario_count"] = serde_json::json!(0);
        fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(
            verify_bundle(&store.root),
            "normal final run must contain at least one executed scenario",
        );

        let (_dir, store) = valid_run_bundle("forged-pass");
        let scenario = store.scenario_dir("baseline");
        rewrite_json_and_reseal(&scenario, BundleKind::Scenario, "result.json", |value| {
            value["exit_code"] = serde_json::json!(1);
        });
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(
            verify_bundle(&store.root),
            "a failing recorded execution requires a failure signature",
        );
    }

    #[test]
    fn rejects_a_truncated_successful_plan_after_self_reseal() {
        let (_dir, store) = valid_run_bundle("truncated-plan");
        let config_path = store.root.join("config.normalized.json");
        let mut config: Config = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config.execution.max_scenarios = 2;
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let plan_path = store.root.join("plan.json");
        let mut plan: ExecutionPlan =
            serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        let candidate = Candidate {
            id: "py313-locked".into(),
            axis: EnvironmentAxis::Runtime,
            label: "Python 3.13 locked".into(),
            runtime_version: Some("3.13".into()),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.13-bookworm".into(),
            channel: "stable".into(),
            order_key: "3.13".into(),
            evidence_grade: EvidenceGrade::Observed,
            notes: vec![],
        };
        plan.max_scenarios = 2;
        plan.scenarios.push(Scenario {
            id: ScenarioId::new(&candidate.id),
            kind: ScenarioKind::SingleAxis,
            ecosystem: Ecosystem::Python,
            label: candidate.label.clone(),
            runtime_version: candidate.runtime_version.clone().unwrap(),
            dependency_mode: candidate.dependency_mode.clone(),
            image_ref: candidate.image_ref.clone(),
            axes_changed: vec![candidate.axis.clone()],
            evidence_grade: candidate.evidence_grade,
            is_baseline: false,
            selection_reason: "candidate on axis runtime".into(),
        });
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        fs::write(
            store.root.join("candidates.json"),
            serde_json::to_vec_pretty(&vec![candidate]).unwrap(),
        )
        .unwrap();

        let run_path = store.root.join("run.json");
        let mut run: RunManifest = serde_json::from_slice(&fs::read(&run_path).unwrap()).unwrap();
        run.config_hash = config.config_hash().unwrap();
        fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);

        assert_semantic_failure(
            verify_bundle(&store.root),
            "a passing baseline requires a verdict for every final planned scenario",
        );
    }

    #[test]
    fn accepts_canonical_baseline_failure_and_flaky_evidence() {
        let signature = FailureSignature {
            kind: "test".into(),
            summary: "baseline failed on one attempt".into(),
            primary_error: Some("assertion failed".into()),
            fingerprint: FailureSignature::compute_fingerprint(
                "test",
                "assertion failed",
                "baseline failed on one attempt",
            ),
            framework_hints: vec![],
            evidence_grade: EvidenceGrade::Observed,
        };

        let (_dir, store) = valid_run_bundle("baseline-invalid-valid");
        let scenario_dir = store.scenario_dir("baseline");
        rewrite_json_and_reseal(
            &scenario_dir,
            BundleKind::Scenario,
            "result.json",
            |value| value["exit_code"] = serde_json::json!(1),
        );
        fs::write(
            scenario_dir.join("failure-signature.json"),
            serde_json::to_vec_pretty(&signature).unwrap(),
        )
        .unwrap();
        seal_integrity_only(&scenario_dir, BundleKind::Scenario);
        let verdict_path = store.root.join("verdicts.json");
        let mut verdicts: Vec<ScenarioVerdict> =
            serde_json::from_slice(&fs::read(&verdict_path).unwrap()).unwrap();
        verdicts[0].verdict = Verdict::BaselineInvalid;
        verdicts[0].failure_signature = Some(signature.clone());
        fs::write(&verdict_path, serde_json::to_vec_pretty(&verdicts).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        verify_bundle(&store.root).unwrap();

        let (_dir, store) = valid_run_bundle("baseline-flaky-valid");
        let scenario_dir = store.scenario_dir("baseline");
        fs::write(
            scenario_dir.join("failure-signature.json"),
            serde_json::to_vec_pretty(&signature).unwrap(),
        )
        .unwrap();
        seal_integrity_only(&scenario_dir, BundleKind::Scenario);
        let verdict_path = store.root.join("verdicts.json");
        let mut verdicts: Vec<ScenarioVerdict> =
            serde_json::from_slice(&fs::read(&verdict_path).unwrap()).unwrap();
        verdicts[0].verdict = Verdict::Flaky;
        verdicts[0].attempts = 2;
        verdicts[0].failure_signature = Some(signature);
        fs::write(&verdict_path, serde_json::to_vec_pretty(&verdicts).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        verify_bundle(&store.root).unwrap();

        fs::remove_file(scenario_dir.join("failure-signature.json")).unwrap();
        seal_integrity_only(&scenario_dir, BundleKind::Scenario);
        verdicts[0].failure_signature = None;
        fs::write(&verdict_path, serde_json::to_vec_pretty(&verdicts).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(
            verify_bundle(&store.root),
            "FLAKY requires at least two outcomes and a retained failure signature",
        );
    }

    #[test]
    fn rejects_a_missing_configured_report() {
        let (_dir, store) = valid_run_bundle("missing-report");
        let config_path = store.root.join("config.normalized.json");
        let mut config: Config = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config.report.json = true;
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let run_path = store.root.join("run.json");
        let mut run: RunManifest = serde_json::from_slice(&fs::read(&run_path).unwrap()).unwrap();
        run.config_hash = config.config_hash().unwrap();
        fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);

        assert_semantic_failure(
            verify_bundle(&store.root),
            "configured report is missing from sealed run: report.json",
        );

        let (_dir, store) = valid_run_bundle("forged-report");
        let config_path = store.root.join("config.normalized.json");
        let mut config: Config = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config.report.json = true;
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let run_path = store.root.join("run.json");
        let mut run: RunManifest = serde_json::from_slice(&fs::read(&run_path).unwrap()).unwrap();
        run.config_hash = config.config_hash().unwrap();
        fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        fs::write(store.root.join("report.json"), b"{}").unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        assert_semantic_failure(
            verify_bundle(&store.root),
            "bytes do not match the deterministic verified evidence model",
        );
    }

    #[test]
    fn verified_reads_remain_bound_to_one_inventory_generation() {
        let (_dir, store) = valid_run_bundle("generation-bound");
        let verified = store.verify().unwrap();
        let mut run: RunManifest = verified.read_json("run.json").unwrap();
        let mut frontier: BreakageFrontier = verified.read_json("frontier.json").unwrap();

        frontier.explanation = "A later, independently valid generation.".into();
        run.frontier = Some(frontier.clone());
        fs::write(
            store.root.join("frontier.json"),
            serde_json::to_vec_pretty(&frontier).unwrap(),
        )
        .unwrap();
        fs::write(
            store.root.join("run.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
        seal_integrity_only(&store.root, BundleKind::Run);
        store.verify().unwrap();

        let error = verified
            .read_json::<BreakageFrontier>("frontier.json")
            .expect_err("an older verification consumed a newer generation");
        assert!(
            error.to_string().contains("checksum mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn evidence_store_refuses_writes_and_reseal_after_finalization() {
        let (_dir, store) = valid_run_bundle("immutable-after-seal");
        let write_error = store
            .write_json("late.json", &serde_json::json!({"late": true}))
            .expect_err("sealed EvidenceStore accepted a late writer");
        assert!(write_error
            .to_string()
            .contains("already sealed and immutable"));
        let seal_error = store
            .finalize_checksums()
            .expect_err("sealed EvidenceStore accepted a second finalization");
        assert!(seal_error
            .to_string()
            .contains("already sealed and immutable"));
    }

    #[test]
    fn seals_and_verifies_a_recursive_exact_inventory() {
        let dir = generic_bundle();
        let inventory = read_inventory(dir.path()).unwrap();
        assert_eq!(inventory.version, INVENTORY_VERSION);
        assert_eq!(inventory.kind, BundleKind::Generic);
        assert_eq!(
            inventory
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["nested/deeper/result.json", "root.json"]
        );

        let verified = verify_bundle(dir.path()).unwrap();
        assert_eq!(verified.file_count, 2);
        assert_eq!(verified.root, dir.path());
    }

    #[test]
    fn replaces_an_existing_inventory_without_an_unsealed_window() {
        let dir = generic_bundle();
        let before = fs::read(dir.path().join(INVENTORY_FILE_NAME)).unwrap();
        fs::write(dir.path().join("second.json"), b"second").unwrap();
        seal_bundle(dir.path(), BundleKind::Generic).unwrap();
        let after = fs::read(dir.path().join(INVENTORY_FILE_NAME)).unwrap();
        assert_ne!(before, after);
        assert_eq!(verify_bundle(dir.path()).unwrap().file_count, 3);
    }

    #[test]
    fn atomic_writer_does_not_follow_a_preseeded_hardlink() {
        let dir = tempdir().unwrap();
        let store = EvidenceStore::create(dir.path(), "hardlink-run").unwrap();
        let outside = dir.path().join("outside.json");
        fs::write(&outside, b"outside-must-not-change").unwrap();
        fs::hard_link(&outside, store.root.join("run.json")).unwrap();

        store
            .write_json("run.json", &serde_json::json!({"inside": true}))
            .unwrap();

        assert_eq!(fs::read(&outside).unwrap(), b"outside-must-not-change");
        assert_ne!(
            fs::read(store.root.join("run.json")).unwrap(),
            fs::read(&outside).unwrap()
        );
    }

    #[test]
    fn caps_large_unicode_logs_on_character_boundaries() {
        let input = "🙂".repeat(600_000);
        let capped = cap_bytes(&input, 2 * 1024 * 1024);
        assert!(capped.contains("...[truncated "));
        assert!(capped.starts_with('🙂'));
        assert!(capped.ends_with('🙂'));
    }

    #[test]
    fn scenario_writer_redacts_logs_previews_and_failure_signatures() {
        let dir = tempdir().unwrap();
        let store = EvidenceStore::create(dir.path(), "redaction-run").unwrap();
        let secret = "api_key=super-secret-value";
        let mut scenario = sample_scenario("baseline");
        scenario.label = format!("baseline {secret}");
        scenario.selection_reason = format!("fixture {secret}");
        let mut environment = EnvironmentSpec {
            image_ref: scenario.image_ref.clone(),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            workdir: "/workspace".into(),
            user: None,
            env: Default::default(),
            mounts: vec![],
            network_mode: NetworkMode::None,
            read_only_root: false,
            memory_mb: 1024,
            cpus: 1.0,
            pids_limit: 128,
            timeout_seconds: 60,
        };
        environment.env.insert("TOKEN".into(), secret.into());
        let mut command = sample_command();
        command
            .args
            .push(format!("value\nWrite-Host injected {secret}"));
        let raw = RawExecutionResult {
            exit_code: Some(1),
            signal: None,
            stdout: secret.into(),
            stderr: secret.into(),
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            error: Some(secret.into()),
        };
        let result = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: 1,
            exit_code: Some(1),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            stdout_path: None,
            stderr_path: None,
            stdout_preview: secret.into(),
            stderr_preview: secret.into(),
            blocked_reason: Some(secret.into()),
            image_ref: environment.image_ref.clone(),
            image_digest: environment.image_digest.clone(),
            commands: vec![command.clone()],
        };
        let failure = FailureSignature {
            kind: "blocked".into(),
            summary: secret.into(),
            primary_error: Some(secret.into()),
            fingerprint: "fingerprint".into(),
            framework_hints: vec![secret.into()],
            evidence_grade: EvidenceGrade::Observed,
        };
        let scenario_dir = store
            .write_scenario_bundle(
                &scenario,
                &environment,
                &[command],
                &raw,
                &result,
                Some(&failure),
            )
            .unwrap();
        verify_bundle(&scenario_dir).unwrap();
        for (relative, absolute) in collect_regular_files(&scenario_dir).unwrap() {
            let persisted = fs::read_to_string(absolute).unwrap();
            assert!(!persisted.contains("super-secret-value"), "{relative}");
        }
        for relative in [
            "stdout.log",
            "stderr.log",
            "result.json",
            "failure-signature.json",
        ] {
            let persisted = fs::read_to_string(scenario_dir.join(relative)).unwrap();
            assert!(persisted.contains("REDACTED"), "{relative}");
        }
        for helper in ["replay.sh", "replay.ps1"] {
            let persisted = fs::read_to_string(scenario_dir.join(helper)).unwrap();
            assert!(!persisted.contains("baseline"), "{helper}");
            assert!(!persisted.contains("Write-Host injected"), "{helper}");
        }
        rewrite_json_and_reseal(
            &scenario_dir,
            BundleKind::Scenario,
            "failure-signature.json",
            |value| value["fingerprint"] = serde_json::json!("forged"),
        );
        assert_semantic_failure(verify_bundle(&scenario_dir), ".fingerprint");
    }

    #[test]
    fn evidence_store_rejects_a_self_declared_generic_bundle() {
        let base = tempdir().unwrap();
        let store = EvidenceStore::create(base.path(), "run-kind-check").unwrap();
        fs::write(store.root.join("payload.json"), b"{}").unwrap();
        seal_bundle(&store.root, BundleKind::Generic).unwrap();

        assert!(matches!(
            store.verify(),
            Err(EvidenceError::Other(message))
                if message == "evidence store requires a run bundle, found generic"
        ));
    }

    #[test]
    fn rejects_mutated_file() {
        let dir = generic_bundle();
        fs::write(dir.path().join("root.json"), b"tampered").unwrap();
        assert!(matches!(
            verify_bundle(dir.path()),
            Err(EvidenceError::ChecksumMismatch { path, .. }) if path == "root.json"
        ));
    }

    #[test]
    fn rejects_deleted_file() {
        let dir = generic_bundle();
        fs::remove_file(dir.path().join("root.json")).unwrap();
        assert!(matches!(
            verify_bundle(dir.path()),
            Err(EvidenceError::Missing(message)) if message.contains("root.json")
        ));
    }

    #[test]
    fn rejects_unlisted_added_file() {
        let dir = generic_bundle();
        fs::write(dir.path().join("late-writer.json"), b"too late").unwrap();
        assert!(matches!(
            verify_bundle(dir.path()),
            Err(EvidenceError::Unlisted(path)) if path == "late-writer.json"
        ));
    }

    #[test]
    fn rejects_absolute_parent_backslash_and_noncanonical_paths() {
        for unsafe_path in [
            "/absolute.json",
            "C:/absolute.json",
            "../escape.json",
            "nested/../escape.json",
            "nested\\escape.json",
            "nested//escape.json",
            "./escape.json",
            "nested/trailing./file.json",
            "nested/trailing /file.json",
            "CON",
            "aux.json",
            "nested/LPT1/file.json",
        ] {
            let text = inventory_text(BundleKind::Generic, &[(ZERO_DIGEST, unsafe_path)]);
            assert!(
                matches!(
                    BundleInventory::parse(&text),
                    Err(EvidenceError::UnsafePath(path)) if path == unsafe_path
                ),
                "accepted unsafe path {unsafe_path:?}"
            );
        }
    }

    #[test]
    fn rejects_bundles_that_exceed_the_nesting_limit() {
        let dir = tempdir().unwrap();
        let mut current = dir.path().to_path_buf();
        for _ in 0..=MAX_BUNDLE_DEPTH {
            current.push("d");
            fs::create_dir(&current).unwrap();
        }
        fs::write(current.join("file.json"), b"{}").unwrap();
        let error = seal_bundle(dir.path(), BundleKind::Generic)
            .expect_err("overly deep bundle was accepted");
        assert!(
            error.to_string().contains("bundle nesting exceeds"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_control_characters_in_paths_and_ids() {
        for unsafe_value in ["escape\u{1b}.json", "line\nfeed", "tab\tvalue"] {
            assert!(matches!(
                validate_inventory_path(unsafe_value),
                Err(EvidenceError::UnsafePath(path)) if path == unsafe_value
            ));
            assert!(matches!(
                EvidenceStore::create(Path::new("."), unsafe_value),
                Err(EvidenceError::UnsafePath(path)) if path == unsafe_value
            ));
        }
    }

    #[test]
    fn rejects_duplicate_inventory_paths() {
        let text = inventory_text(
            BundleKind::Generic,
            &[(ZERO_DIGEST, "same.json"), (ZERO_DIGEST, "same.json")],
        );
        assert!(matches!(
            BundleInventory::parse(&text),
            Err(EvidenceError::DuplicatePath(path)) if path == "same.json"
        ));

        let portable_collision = inventory_text(
            BundleKind::Generic,
            &[(ZERO_DIGEST, "A.json"), (ZERO_DIGEST, "a.json")],
        );
        assert!(matches!(
            BundleInventory::parse(&portable_collision),
            Err(EvidenceError::DuplicatePath(path))
                if path.contains("portable case-fold collision")
        ));
    }

    #[test]
    fn rejects_malformed_checksums_and_unknown_versions() {
        let malformed = [
            inventory_text(BundleKind::Generic, &[("abc", "file.json")]),
            inventory_text(
                BundleKind::Generic,
                &[(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "file.json",
                )],
            ),
            format!(
                "{INVENTORY_HEADER_V1_PREFIX}generic{INVENTORY_HEADER_V1_SUFFIX}\n{ZERO_DIGEST} file.json\n"
            ),
            format!(
                "{INVENTORY_HEADER_V1_PREFIX}generic{INVENTORY_HEADER_V1_SUFFIX}\n\n"
            ),
            format!(
                "{INVENTORY_HEADER_V1_PREFIX}generic{INVENTORY_HEADER_V1_SUFFIX}\n{ZERO_DIGEST}  file.json"
            ),
        ];
        for text in malformed {
            assert!(matches!(
                BundleInventory::parse(&text),
                Err(EvidenceError::MalformedInventory { .. })
            ));
        }

        let version_two = "# tomorrowci-evidence-checksums-v2 kind=generic algorithm=sha256 scope=recursive sealed=true\n";
        assert!(matches!(
            BundleInventory::parse(version_two),
            Err(EvidenceError::UnsupportedInventoryVersion(_))
        ));
    }

    #[test]
    fn rejects_unversioned_legacy_checksums_as_unsealed() {
        let legacy = format!("{ZERO_DIGEST}  file.json\n");
        assert!(matches!(
            BundleInventory::parse(&legacy),
            Err(EvidenceError::UnsealedLegacy(_))
        ));
    }

    #[test]
    fn run_inventory_requires_core_identity_and_verdict_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("run.json"), b"{}").unwrap();
        assert!(matches!(
            seal_bundle(dir.path(), BundleKind::Run),
            Err(EvidenceError::Missing(message))
                if message.contains("config.normalized.json")
        ));
        assert!(!dir.path().join(INVENTORY_FILE_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_entries() {
        use std::os::unix::fs::symlink;

        let dir = generic_bundle();
        symlink(dir.path().join("root.json"), dir.path().join("linked.json")).unwrap();
        assert!(matches!(
            verify_bundle(dir.path()),
            Err(EvidenceError::NonRegularEntry(path)) if path == "linked.json"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_symlink_or_reparse_entries_where_supported() {
        use std::os::windows::fs::symlink_file;

        let dir = generic_bundle();
        let link = dir.path().join("linked.json");
        match symlink_file(dir.path().join("root.json"), &link) {
            Ok(()) => assert!(matches!(
                verify_bundle(dir.path()),
                Err(EvidenceError::NonRegularEntry(path)) if path == "linked.json"
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::Other
                ) =>
            {
                // Windows requires Developer Mode or SeCreateSymbolicLinkPrivilege.
            }
            Err(error) => panic!("could not create symlink: {error}"),
        }
    }
}
