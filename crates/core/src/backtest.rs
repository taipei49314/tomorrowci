//! Content-addressed historical registry-snapshot backtesting.
//!
//! A backtest is only conclusive when the source commit and a registry snapshot
//! for that commit's UTC calendar date are both available.  Snapshot payloads
//! are recursively inventoried and copied into the disposable source tree; a
//! missing snapshot never falls back to today's registry.

use crate::{canonical_sha256, Ecosystem};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const REGISTRY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const BACKTEST_PROOF_SCHEMA_VERSION: u32 = 2;
// Deliberately not below `.tomorrowci/`: workspace materialization excludes
// that evidence/output directory. This reserved source path must be copied and
// hashed into every scenario's source snapshot.
pub const WORKSPACE_SNAPSHOT_DIR: &str = ".tomorrowci-backtest/registry-snapshot";
pub const SNAPSHOT_MANIFEST_FILE: &str = "snapshot-manifest.json";
pub const SNAPSHOT_PAYLOAD_DIR: &str = "payload";
pub const DEFAULT_MAX_SNAPSHOT_FILES: usize = 20_000;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestRequest {
    pub target: String,
    pub at: NaiveDate,
    pub until: NaiveDate,
    /// Cap how many commits/points we materialize (budget).
    pub max_commits: usize,
    pub max_scenarios_per_point: usize,
    /// Registry root laid out as `<ecosystem>/<YYYY-MM-DD>/snapshot-manifest.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_registry: Option<PathBuf>,
    #[serde(default = "default_max_snapshot_files")]
    pub max_snapshot_files: usize,
    #[serde(default = "default_max_snapshot_bytes")]
    pub max_snapshot_bytes: u64,
}

pub const fn default_max_snapshot_files() -> usize {
    DEFAULT_MAX_SNAPSHOT_FILES
}

pub const fn default_max_snapshot_bytes() -> u64 {
    DEFAULT_MAX_SNAPSHOT_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestPoint {
    pub commit_sha: String,
    pub committed_at: Option<DateTime<Utc>>,
    pub run_id: Option<String>,
    pub frontier_observed: bool,
    pub horizon_label: Option<String>,
    pub status: BacktestPointStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<RegistrySnapshotBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<BacktestProofReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BacktestPointStatus {
    Ok,
    /// Required historical material was not supplied, so no claim was tested.
    Inconclusive,
    /// Supplied material was unsafe, inconsistent, or the sealed run was blocked.
    ScheduledRisk,
    Blocked,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestReport {
    pub request: BacktestRequest,
    pub points: Vec<BacktestPoint>,
    pub note: String,
}

impl BacktestReport {
    pub fn note() -> &'static str {
        "Backtest v0.2 runs historical source only when a strict, content-addressed registry \
         snapshot for the source commit's UTC date is present. Snapshot payloads execute \
         offline. Missing or invalid snapshots are INCONCLUSIVE/SCHEDULED_RISK; TomorrowCI \
         never substitutes today's registry or claims registry time travel."
    }

    /// Backward-compatible name retained for callers of the v0.1 skeleton API.
    #[deprecated(note = "use BacktestReport::note")]
    pub fn skeleton_note() -> &'static str {
        Self::note()
    }

    /// Backtests are green only when every sampled point produced a sealed proof.
    pub fn is_green(&self) -> bool {
        !self.points.is_empty()
            && self
                .points
                .iter()
                .all(|point| point.status == BacktestPointStatus::Ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryResolverMode {
    PythonWheelhouse,
    NpmOfflineCache,
    CargoVendor,
}

impl RegistryResolverMode {
    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            Self::PythonWheelhouse => Ecosystem::Python,
            Self::NpmOfflineCache => Ecosystem::Node,
            Self::CargoVendor => Ecosystem::Rust,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshotSource {
    pub url: String,
    /// Immutable upstream capture identity. v1 requires `sha256:<64 lowercase hex>`.
    pub immutable_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshotFile {
    /// Portable UTF-8 path below the fixed `payload/` directory.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshotManifest {
    pub schema_version: u32,
    /// Content address of every field below (including the exact file inventory).
    pub snapshot_id: String,
    pub ecosystem: Ecosystem,
    pub effective_at: DateTime<Utc>,
    pub captured_at: DateTime<Utc>,
    pub source: RegistrySnapshotSource,
    pub resolver_mode: RegistryResolverMode,
    pub files: Vec<RegistrySnapshotFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshotBinding {
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub ecosystem: Ecosystem,
    pub effective_at: DateTime<Utc>,
    pub captured_at: DateTime<Utc>,
    pub source: RegistrySnapshotSource,
    pub resolver_mode: RegistryResolverMode,
    pub file_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedRegistrySnapshot {
    pub manifest: RegistrySnapshotManifest,
    pub binding: RegistrySnapshotBinding,
    pub manifest_path: PathBuf,
    pub payload_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestRuntimeImage {
    pub image_ref: String,
    pub image_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestProof {
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub source_commit_sha: String,
    pub source_committed_at: DateTime<Utc>,
    pub snapshot: RegistrySnapshotBinding,
    /// Canonical SHA-256 of the sealed run's typed source manifest.
    pub source_manifest_sha256: String,
    pub normalized_config_sha256: String,
    /// Canonical SHA-256 identities of the typed run outcome witnesses.
    pub run_manifest_sha256: String,
    pub verdicts_sha256: String,
    pub frontier_sha256: String,
    pub outcome: BacktestProofOutcome,
    pub runtime_images: Vec<BacktestRuntimeImage>,
    pub run_id: String,
    pub sealed_run_inventory_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BacktestProofOutcome {
    Qualified,
    ScheduledRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestProofReference {
    pub directory: PathBuf,
    pub proof_sha256: String,
    pub sealed_inventory_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotFailureDisposition {
    Inconclusive,
    ScheduledRisk,
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("registry snapshot is missing: {0}")]
    Missing(String),
    #[error("registry snapshot manifest is invalid: {0}")]
    Manifest(String),
    #[error("registry snapshot date mismatch: {0}")]
    DateMismatch(String),
    #[error("registry snapshot ecosystem mismatch: {0}")]
    EcosystemMismatch(String),
    #[error("registry snapshot identity mismatch: {0}")]
    IdentityMismatch(String),
    #[error("registry snapshot payload is invalid: {0}")]
    Payload(String),
    #[error("registry snapshot exceeds resource cap: {0}")]
    ResourceCap(String),
    #[error("registry snapshot I/O failed: {0}")]
    Io(String),
}

impl SnapshotError {
    pub fn disposition(&self) -> SnapshotFailureDisposition {
        match self {
            Self::Missing(_) => SnapshotFailureDisposition::Inconclusive,
            Self::Manifest(_)
            | Self::DateMismatch(_)
            | Self::EcosystemMismatch(_)
            | Self::IdentityMismatch(_)
            | Self::Payload(_)
            | Self::ResourceCap(_)
            | Self::Io(_) => SnapshotFailureDisposition::ScheduledRisk,
        }
    }
}

/// Deterministic content address over the complete semantic manifest except its
/// own `snapshot_id` field. Length prefixes remove delimiter ambiguity.
pub fn registry_snapshot_id(manifest: &RegistrySnapshotManifest) -> String {
    fn field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let mut hasher = Sha256::new();
    field(&mut hasher, b"tomorrowci-registry-snapshot-v1");
    field(&mut hasher, manifest.schema_version.to_string().as_bytes());
    field(
        &mut hasher,
        match manifest.ecosystem {
            Ecosystem::Python => b"python",
            Ecosystem::Node => b"node",
            Ecosystem::Rust => b"rust",
        },
    );
    field(&mut hasher, manifest.effective_at.to_rfc3339().as_bytes());
    field(&mut hasher, manifest.captured_at.to_rfc3339().as_bytes());
    field(&mut hasher, manifest.source.url.as_bytes());
    field(&mut hasher, manifest.source.immutable_revision.as_bytes());
    field(
        &mut hasher,
        match manifest.resolver_mode {
            RegistryResolverMode::PythonWheelhouse => b"python_wheelhouse",
            RegistryResolverMode::NpmOfflineCache => b"npm_offline_cache",
            RegistryResolverMode::CargoVendor => b"cargo_vendor",
        },
    );
    for entry in &manifest.files {
        field(&mut hasher, entry.path.as_bytes());
        field(&mut hasher, entry.sha256.as_bytes());
        field(&mut hasher, entry.size.to_string().as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn expected_snapshot_manifest(
    registry: &Path,
    ecosystem: Ecosystem,
    date: NaiveDate,
) -> PathBuf {
    registry
        .join(ecosystem_slug(ecosystem))
        .join(date.format("%Y-%m-%d").to_string())
        .join(SNAPSHOT_MANIFEST_FILE)
}

pub fn verify_registry_snapshot(
    manifest_path: &Path,
    expected_ecosystem: Ecosystem,
    expected_date: Option<NaiveDate>,
    max_files: usize,
    max_bytes: u64,
) -> Result<VerifiedRegistrySnapshot, SnapshotError> {
    let manifest_metadata = std::fs::symlink_metadata(manifest_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SnapshotError::Missing(manifest_path.display().to_string())
        } else {
            SnapshotError::Io(format!("{}: {error}", manifest_path.display()))
        }
    })?;
    if manifest_metadata.file_type().is_symlink()
        || is_reparse_point(&manifest_metadata)
        || !manifest_metadata.is_file()
    {
        return Err(SnapshotError::Manifest(format!(
            "{} is not a regular file",
            manifest_path.display()
        )));
    }
    if manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(SnapshotError::ResourceCap(format!(
            "manifest is {} bytes (cap {MAX_MANIFEST_BYTES})",
            manifest_metadata.len()
        )));
    }
    let mut manifest_file = File::open(manifest_path)
        .map_err(|error| SnapshotError::Io(format!("{}: {error}", manifest_path.display())))?;
    let mut bytes = Vec::with_capacity(manifest_metadata.len() as usize);
    manifest_file
        .by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| SnapshotError::Io(format!("{}: {error}", manifest_path.display())))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(SnapshotError::ResourceCap(format!(
            "manifest exceeded {MAX_MANIFEST_BYTES} bytes while reading"
        )));
    }
    let manifest: RegistrySnapshotManifest = serde_json::from_slice(&bytes)
        .map_err(|error| SnapshotError::Manifest(error.to_string()))?;
    validate_manifest(&manifest, expected_ecosystem, expected_date)?;
    if manifest.files.len() > max_files {
        return Err(SnapshotError::ResourceCap(format!(
            "manifest lists {} files (cap {max_files})",
            manifest.files.len()
        )));
    }
    let declared_bytes = manifest.files.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.size).ok_or_else(|| {
            SnapshotError::ResourceCap("declared payload byte count overflowed".into())
        })
    })?;
    if declared_bytes > max_bytes {
        return Err(SnapshotError::ResourceCap(format!(
            "manifest declares {declared_bytes} bytes (cap {max_bytes})"
        )));
    }

    let parent = manifest_path
        .parent()
        .ok_or_else(|| SnapshotError::Manifest("manifest has no parent directory".into()))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| SnapshotError::Io(format!("{}: {error}", parent.display())))?;
    if parent_metadata.file_type().is_symlink()
        || is_reparse_point(&parent_metadata)
        || !parent_metadata.is_dir()
    {
        return Err(SnapshotError::Payload(format!(
            "snapshot root is not a regular directory: {}",
            parent.display()
        )));
    }
    for entry in std::fs::read_dir(parent)
        .map_err(|error| SnapshotError::Io(format!("{}: {error}", parent.display())))?
    {
        let entry = entry.map_err(|error| SnapshotError::Io(error.to_string()))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SnapshotError::Payload("snapshot root contains a non-UTF-8 path".into())
        })?;
        if name != SNAPSHOT_MANIFEST_FILE && name != SNAPSHOT_PAYLOAD_DIR {
            return Err(SnapshotError::Payload(format!(
                "snapshot root contains unlisted entry {name:?}"
            )));
        }
    }
    let payload_root = parent.join(SNAPSHOT_PAYLOAD_DIR);
    let actual = inventory_payload(&payload_root, max_files, max_bytes)?;
    let declared: BTreeMap<_, _> = manifest
        .files
        .iter()
        .map(|entry| (entry.path.clone(), (entry.sha256.clone(), entry.size)))
        .collect();
    if actual != declared {
        let missing: Vec<_> = declared
            .keys()
            .filter(|path| !actual.contains_key(*path))
            .collect();
        let extra: Vec<_> = actual
            .keys()
            .filter(|path| !declared.contains_key(*path))
            .collect();
        if !missing.is_empty() || !extra.is_empty() {
            return Err(SnapshotError::Payload(format!(
                "exact file set mismatch (missing={}, extra={})",
                missing.len(),
                extra.len()
            )));
        }
        return Err(SnapshotError::Payload(
            "file size or SHA-256 mismatch".into(),
        ));
    }

    let binding = RegistrySnapshotBinding {
        snapshot_id: manifest.snapshot_id.clone(),
        manifest_sha256: hex::encode(Sha256::digest(&bytes)),
        ecosystem: manifest.ecosystem,
        effective_at: manifest.effective_at,
        captured_at: manifest.captured_at,
        source: manifest.source.clone(),
        resolver_mode: manifest.resolver_mode.clone(),
        file_count: manifest.files.len(),
        total_bytes: declared_bytes,
    };
    Ok(VerifiedRegistrySnapshot {
        manifest,
        binding,
        manifest_path: manifest_path.to_path_buf(),
        payload_root,
    })
}

/// Re-verify a snapshot staged at the fixed container-visible workspace path.
pub fn workspace_registry_snapshot(
    workspace: &Path,
    ecosystem: Ecosystem,
) -> Result<Option<VerifiedRegistrySnapshot>, SnapshotError> {
    let root = workspace.join(WORKSPACE_SNAPSHOT_DIR);
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SnapshotError::Io(format!("{}: {error}", root.display()))),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || is_reparse_point(&metadata)
                || !metadata.is_dir() =>
        {
            return Err(SnapshotError::Payload(format!(
                "{} is not a regular directory",
                root.display()
            )))
        }
        Ok(_) => {}
    }
    verify_registry_snapshot(
        &root.join(SNAPSHOT_MANIFEST_FILE),
        ecosystem,
        None,
        DEFAULT_MAX_SNAPSHOT_FILES,
        DEFAULT_MAX_SNAPSHOT_BYTES,
    )
    .map(Some)
}

pub fn snapshot_container_payload() -> &'static str {
    "/workspace/.tomorrowci-backtest/registry-snapshot/payload"
}

pub fn canonical_proof_sha256(proof: &BacktestProof) -> Result<String, SnapshotError> {
    canonical_sha256(proof).map_err(|error| SnapshotError::Manifest(error.to_string()))
}

fn validate_manifest(
    manifest: &RegistrySnapshotManifest,
    expected_ecosystem: Ecosystem,
    expected_date: Option<NaiveDate>,
) -> Result<(), SnapshotError> {
    if manifest.schema_version != REGISTRY_SNAPSHOT_SCHEMA_VERSION {
        return Err(SnapshotError::Manifest(format!(
            "unsupported schema_version {}",
            manifest.schema_version
        )));
    }
    if manifest.ecosystem != expected_ecosystem {
        return Err(SnapshotError::EcosystemMismatch(format!(
            "expected {}, found {}",
            ecosystem_slug(expected_ecosystem),
            ecosystem_slug(manifest.ecosystem)
        )));
    }
    if manifest.resolver_mode.ecosystem() != manifest.ecosystem {
        return Err(SnapshotError::EcosystemMismatch(
            "resolver_mode does not match ecosystem".into(),
        ));
    }
    if let Some(date) = expected_date {
        if manifest.effective_at.date_naive() != date {
            return Err(SnapshotError::DateMismatch(format!(
                "expected {date}, found {}",
                manifest.effective_at.date_naive()
            )));
        }
    }
    if manifest.captured_at < manifest.effective_at {
        return Err(SnapshotError::Manifest(
            "captured_at precedes effective_at".into(),
        ));
    }
    let source_remainder = manifest
        .source
        .url
        .strip_prefix("https://")
        .unwrap_or_default();
    let source_authority = source_remainder.split('/').next().unwrap_or_default();
    if !manifest.source.url.starts_with("https://")
        || manifest.source.url.len() > 2048
        || source_remainder.is_empty()
        || manifest.source.url.chars().any(char::is_control)
        || manifest.source.url.chars().any(char::is_whitespace)
        || source_authority.is_empty()
        || source_authority.contains('@')
        || manifest.source.url.contains('?')
        || manifest.source.url.contains('#')
    {
        return Err(SnapshotError::Manifest(
            "source.url must be a bounded https URL".into(),
        ));
    }
    validate_sha256_identity(
        &manifest.source.immutable_revision,
        "source immutable_revision",
    )?;
    if manifest.files.is_empty() {
        return Err(SnapshotError::Manifest(
            "files inventory must not be empty".into(),
        ));
    }
    let mut previous: Option<&str> = None;
    let mut portable_paths = std::collections::BTreeSet::new();
    for entry in &manifest.files {
        validate_relative_path(&entry.path)?;
        validate_hex_sha256(&entry.sha256, "file sha256")?;
        if previous.is_some_and(|value| value >= entry.path.as_str()) {
            return Err(SnapshotError::Manifest(
                "files must be strictly sorted by unique path".into(),
            ));
        }
        if !portable_paths.insert(portable_path_identity(&entry.path)) {
            return Err(SnapshotError::Manifest(format!(
                "files contain case-fold-equivalent path {:?}",
                entry.path
            )));
        }
        previous = Some(&entry.path);
    }
    let expected_id = registry_snapshot_id(manifest);
    if manifest.snapshot_id != expected_id {
        return Err(SnapshotError::IdentityMismatch(format!(
            "expected {expected_id}, found {}",
            manifest.snapshot_id
        )));
    }
    Ok(())
}

fn validate_sha256_identity(value: &str, label: &str) -> Result<(), SnapshotError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| SnapshotError::Manifest(format!("{label} must start with sha256:")))?;
    validate_hex_sha256(digest, label)
}

fn validate_hex_sha256(value: &str, label: &str) -> Result<(), SnapshotError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::Manifest(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), SnapshotError> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|segment| segment.is_empty())
    {
        return Err(SnapshotError::Manifest(format!(
            "unsafe payload path {value:?}"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().to_str().is_none()
        })
    {
        return Err(SnapshotError::Manifest(format!(
            "unsafe payload path {value:?}"
        )));
    }
    for segment in value.split('/') {
        if segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.chars().any(|character| {
                character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
            })
            || is_dos_device_component(segment)
        {
            return Err(SnapshotError::Manifest(format!(
                "unsafe portable payload path {value:?}"
            )));
        }
    }
    Ok(())
}

fn portable_path_identity(value: &str) -> String {
    value
        .split('/')
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join("/")
}

fn is_dos_device_component(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.']);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn inventory_payload(
    root: &Path,
    max_files: usize,
    max_bytes: u64,
) -> Result<BTreeMap<String, (String, u64)>, SnapshotError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SnapshotError::Missing(root.display().to_string())
        } else {
            SnapshotError::Io(format!("{}: {error}", root.display()))
        }
    })?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(SnapshotError::Payload(format!(
            "{} is not a regular directory",
            root.display()
        )));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut out = BTreeMap::new();
    let mut portable_paths = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        let directory_metadata = std::fs::symlink_metadata(&directory)
            .map_err(|error| SnapshotError::Io(format!("{}: {error}", directory.display())))?;
        if directory_metadata.file_type().is_symlink()
            || is_reparse_point(&directory_metadata)
            || !directory_metadata.is_dir()
        {
            return Err(SnapshotError::Payload(format!(
                "payload traversal encountered a link, reparse point, or non-directory: {}",
                directory.display()
            )));
        }
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| SnapshotError::Io(format!("{}: {error}", directory.display())))?;
        for entry in entries {
            let entry = entry.map_err(|error| SnapshotError::Io(error.to_string()))?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| SnapshotError::Io(format!("{}: {error}", path.display())))?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(SnapshotError::Payload(format!(
                    "link or reparse point is forbidden: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(SnapshotError::Payload(format!(
                    "special file is forbidden: {}",
                    path.display()
                )));
            }
            if out.len() >= max_files {
                return Err(SnapshotError::ResourceCap(format!(
                    "payload exceeds {max_files} files"
                )));
            }
            total = total.checked_add(metadata.len()).ok_or_else(|| {
                SnapshotError::ResourceCap("payload byte count overflowed".into())
            })?;
            if total > max_bytes {
                return Err(SnapshotError::ResourceCap(format!(
                    "payload exceeds {max_bytes} bytes"
                )));
            }
            let relative = path.strip_prefix(root).map_err(|_| {
                SnapshotError::Payload(format!("path escaped payload root: {}", path.display()))
            })?;
            let relative = relative
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| SnapshotError::Payload("payload path is not UTF-8".into()))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            validate_relative_path(&relative)?;
            if !portable_paths.insert(portable_path_identity(&relative)) {
                return Err(SnapshotError::Payload(format!(
                    "payload contains case-fold-equivalent path {relative:?}"
                )));
            }
            let digest = hash_file_bounded(&path, metadata.len(), max_bytes)?;
            if out
                .insert(relative.clone(), (digest, metadata.len()))
                .is_some()
            {
                return Err(SnapshotError::Payload(format!(
                    "payload contains duplicate path {relative:?}"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn hash_file_bounded(
    path: &Path,
    expected_size: u64,
    max_bytes: u64,
) -> Result<String, SnapshotError> {
    if expected_size > max_bytes {
        return Err(SnapshotError::ResourceCap(format!(
            "{} exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| SnapshotError::Io(format!("{}: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read_total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| SnapshotError::Io(format!("{}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        read_total += read as u64;
        if read_total > expected_size || read_total > max_bytes {
            return Err(SnapshotError::Payload(format!(
                "{} changed while hashing",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    if read_total != expected_size {
        return Err(SnapshotError::Payload(format!(
            "{} changed while hashing",
            path.display()
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn ecosystem_slug(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Python => "python",
        Ecosystem::Node => "node",
        Ecosystem::Rust => "rust",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn manifest_for(path: &Path) -> RegistrySnapshotManifest {
        let bytes = std::fs::read(path).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        let mut manifest = RegistrySnapshotManifest {
            schema_version: REGISTRY_SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: String::new(),
            ecosystem: Ecosystem::Python,
            effective_at: Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
            captured_at: Utc.with_ymd_and_hms(2026, 1, 15, 13, 0, 0).unwrap(),
            source: RegistrySnapshotSource {
                url: "https://example.invalid/python/simple".into(),
                immutable_revision: format!("sha256:{digest}"),
            },
            resolver_mode: RegistryResolverMode::PythonWheelhouse,
            files: vec![RegistrySnapshotFile {
                path: "fixture.txt".into(),
                sha256: digest,
                size: bytes.len() as u64,
            }],
        };
        manifest.snapshot_id = registry_snapshot_id(&manifest);
        manifest
    }

    fn write_fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempdir().unwrap();
        let snapshot = root.path().join("python/2026-01-15");
        std::fs::create_dir_all(snapshot.join("payload")).unwrap();
        let payload = snapshot.join("payload/fixture.txt");
        std::fs::write(&payload, b"bounded fixture\n").unwrap();
        let manifest = manifest_for(&payload);
        let path = snapshot.join(SNAPSHOT_MANIFEST_FILE);
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        (root, path)
    }

    #[test]
    fn verifies_content_address_and_exact_recursive_set() {
        let (_root, path) = write_fixture();
        let verified = verify_registry_snapshot(
            &path,
            Ecosystem::Python,
            Some(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap()),
            2,
            1024,
        )
        .unwrap();
        assert_eq!(verified.binding.file_count, 1);
        std::fs::write(verified.payload_root.join("extra"), b"extra").unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 2, 1024),
            Err(SnapshotError::Payload(_))
        ));
    }

    #[test]
    fn rejects_date_ecosystem_identity_and_resource_mismatches() {
        let (_root, path) = write_fixture();
        assert!(matches!(
            verify_registry_snapshot(
                &path,
                Ecosystem::Python,
                Some(NaiveDate::from_ymd_opt(2026, 1, 16).unwrap()),
                2,
                1024
            ),
            Err(SnapshotError::DateMismatch(_))
        ));
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Node, None, 2, 1024),
            Err(SnapshotError::EcosystemMismatch(_))
        ));
        let mut manifest: RegistrySnapshotManifest =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        manifest.snapshot_id = format!("sha256:{}", "0".repeat(64));
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 2, 1024),
            Err(SnapshotError::IdentityMismatch(_))
        ));
        let (_root, path) = write_fixture();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 0, 1024),
            Err(SnapshotError::ResourceCap(_))
        ));
    }

    #[test]
    fn rejects_traversal_and_tampering() {
        let (_root, path) = write_fixture();
        let mut manifest: RegistrySnapshotManifest =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        manifest.files[0].path = "../outside".into();
        manifest.snapshot_id = registry_snapshot_id(&manifest);
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 2, 1024),
            Err(SnapshotError::Manifest(_))
        ));

        let (_root, path) = write_fixture();
        std::fs::write(
            path.parent().unwrap().join("payload/fixture.txt"),
            b"tampered",
        )
        .unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 2, 1024),
            Err(SnapshotError::Payload(_))
        ));
    }

    #[test]
    fn rejects_windows_ambiguous_and_case_fold_colliding_paths() {
        for path in [
            "CON",
            "con.txt",
            "CON .txt",
            "nested/AuX.json",
            "file.",
            "file ",
            "nested./file",
            "nested /file",
            "bad?/file",
            "bad</file",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "portable path was accepted: {path:?}"
            );
        }

        let (_root, path) = write_fixture();
        let mut manifest: RegistrySnapshotManifest =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut second = manifest.files[0].clone();
        manifest.files[0].path = "Fixture.txt".into();
        second.path = "fixture.txt".into();
        manifest.files = vec![manifest.files[0].clone(), second];
        manifest.snapshot_id = registry_snapshot_id(&manifest);
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 4, 2048),
            Err(SnapshotError::Manifest(_))
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn rejects_case_fold_collisions_in_actual_payload_traversal() {
        let root = tempdir().unwrap();
        let payload = root.path().join("payload");
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("Package.whl"), b"one").unwrap();
        std::fs::write(payload.join("package.whl"), b"two").unwrap();
        let error = inventory_payload(&payload, 4, 1024).unwrap_err();
        assert!(matches!(error, SnapshotError::Payload(_)));
        assert!(error.to_string().contains("case-fold-equivalent"));
    }

    #[test]
    fn bounded_repository_fixtures_verify_for_all_ecosystems() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/backtest-snapshots");
        for ecosystem in [Ecosystem::Python, Ecosystem::Node, Ecosystem::Rust] {
            let path = expected_snapshot_manifest(
                &root,
                ecosystem,
                NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            );
            let verified = verify_registry_snapshot(
                &path,
                ecosystem,
                Some(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap()),
                16,
                1024 * 1024,
            )
            .unwrap();
            assert!(verified.binding.file_count >= 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_payload_symlinks() {
        use std::os::unix::fs::symlink;
        let (_root, path) = write_fixture();
        let payload = path.parent().unwrap().join("payload/fixture.txt");
        std::fs::remove_file(&payload).unwrap();
        symlink("outside", payload).unwrap();
        assert!(matches!(
            verify_registry_snapshot(&path, Ecosystem::Python, None, 2, 1024),
            Err(SnapshotError::Payload(_))
        ));
    }
}
