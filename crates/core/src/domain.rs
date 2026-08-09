//! Typed domain model for TomorrowCI.
//!
//! Core promise: no forecast without an executable scenario; no breakage claim
//! without replayable evidence.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Unique run identifier (short hex from UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

impl RunId {
    pub fn new() -> Self {
        let id = uuid::Uuid::new_v4();
        Self(format!("{:x}", id.as_u128())[..12].to_string())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScenarioId(pub String);

impl ScenarioId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for ScenarioId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Supported ecosystems in v0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Python,
    Node,
    Rust,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Python => write!(f, "python"),
            Ecosystem::Node => write!(f, "node"),
            Ecosystem::Rust => write!(f, "rust"),
        }
    }
}

/// Evidence grade for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceGrade {
    /// Reproduced on a concrete released or preview environment.
    Observed,
    /// Reproduced under an explicit dependency or policy mutation.
    Simulated,
    /// Derived from a published lifecycle date, not an executed failure.
    ScheduledRisk,
    /// Evidence is insufficient or unstable.
    Inconclusive,
}

/// Typed verdict model — do not collapse every failure into FAIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    BaselinePass,
    BaselineInvalid,
    FuturePass,
    FutureFail,
    Flaky,
    Blocked,
    Unsupported,
    Inconclusive,
}

impl Verdict {
    pub fn is_pass(self) -> bool {
        matches!(self, Verdict::BaselinePass | Verdict::FuturePass)
    }

    pub fn is_fail(self) -> bool {
        matches!(self, Verdict::FutureFail | Verdict::BaselineInvalid)
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Verdict::BaselinePass | Verdict::FuturePass => "PASS",
            Verdict::BaselineInvalid | Verdict::FutureFail => "FAIL",
            Verdict::Flaky => "FLAKY",
            Verdict::Blocked => "BLOCKED",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Which environment axis a candidate mutates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentAxis {
    Runtime,
    Dependencies,
    BaseImage,
    Combined,
}

impl std::fmt::Display for EnvironmentAxis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentAxis::Runtime => write!(f, "runtime"),
            EnvironmentAxis::Dependencies => write!(f, "dependencies"),
            EnvironmentAxis::BaseImage => write!(f, "base_image"),
            EnvironmentAxis::Combined => write!(f, "combined"),
        }
    }
}

/// Dependency selection mode for a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyMode {
    Locked,
    LatestAllowed,
    PrereleaseAllowed,
}

impl std::fmt::Display for DependencyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyMode::Locked => write!(f, "locked"),
            DependencyMode::LatestAllowed => write!(f, "latest_allowed"),
            DependencyMode::PrereleaseAllowed => write!(f, "prerelease"),
        }
    }
}

/// Snapshot of the repository under test (never mutated).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySnapshot {
    pub source: String,
    pub path: PathBuf,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub is_remote: bool,
    pub workspace_copy: PathBuf,
    pub captured_at: DateTime<Utc>,
}

/// Detection result from an adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDetection {
    pub ecosystem: Ecosystem,
    pub package_manager: String,
    pub manifests: Vec<String>,
    pub confidence: f32,
    pub notes: Vec<String>,
    pub supported: bool,
    pub unsupported_reason: Option<String>,
}

/// Baseline environment definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub ecosystem: Ecosystem,
    pub runtime_label: String,
    pub runtime_version: String,
    pub dependency_mode: DependencyMode,
    pub image_ref: String,
    pub notes: Vec<String>,
}

/// A concrete future (or mutated) candidate environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub axis: EnvironmentAxis,
    pub label: String,
    pub runtime_version: Option<String>,
    pub dependency_mode: DependencyMode,
    pub image_ref: String,
    pub channel: String,
    pub order_key: String,
    pub evidence_grade: EvidenceGrade,
    pub notes: Vec<String>,
}

/// Full scenario to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: ScenarioId,
    pub kind: ScenarioKind,
    pub ecosystem: Ecosystem,
    pub label: String,
    pub runtime_version: String,
    pub dependency_mode: DependencyMode,
    pub image_ref: String,
    pub axes_changed: Vec<EnvironmentAxis>,
    pub evidence_grade: EvidenceGrade,
    pub is_baseline: bool,
    pub selection_reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    Baseline,
    SingleAxis,
    Combined,
    Reduction,
    Replay,
}

/// Ordered execution plan produced by the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub run_id: RunId,
    pub scenarios: Vec<Scenario>,
    pub max_scenarios: usize,
    /// Bound on concurrent future-scenario execution (baseline remains serial).
    #[serde(default = "default_max_parallel")]
    pub max_parallel: usize,
    pub decisions: Vec<PlanDecisionRecord>,
    pub untested: Vec<UntestedArea>,
}

fn default_max_parallel() -> usize {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDecisionRecord {
    pub scenario_id: Option<String>,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntestedArea {
    pub axis: EnvironmentAxis,
    pub label: String,
    pub reason: String,
}

/// A single command as an argument array (not a shell string).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub phase: CommandPhase,
    pub program: String,
    pub args: Vec<String>,
    pub workdir: String,
    pub network_required: bool,
    pub env: IndexMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandPhase {
    Fetch,
    Build,
    Test,
    Probe,
}

/// Environment specification materialized for the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSpec {
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub workdir: String,
    pub user: Option<String>,
    pub env: IndexMap<String, String>,
    pub mounts: Vec<MountSpec>,
    pub network_mode: NetworkMode,
    pub read_only_root: bool,
    pub memory_mb: u64,
    pub cpus: f64,
    pub pids_limit: u64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    None,
    FetchOnly,
    Full,
}

/// Raw runner output before normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawExecutionResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub network_used: bool,
    pub error: Option<String>,
}

/// Normalized execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub scenario_id: ScenarioId,
    pub attempt: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub network_used: bool,
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    pub stdout_preview: String,
    pub stderr_preview: String,
    pub blocked_reason: Option<String>,
    pub image_ref: String,
    pub image_digest: Option<String>,
    pub commands: Vec<CommandSpec>,
}

/// Normalized failure signature (not ad-hoc terminal parsing in verdict engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureSignature {
    pub kind: String,
    pub summary: String,
    pub primary_error: Option<String>,
    pub fingerprint: String,
    pub framework_hints: Vec<String>,
    pub evidence_grade: EvidenceGrade,
}

impl FailureSignature {
    pub fn compute_fingerprint(kind: &str, primary: &str, summary: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_bytes());
        hasher.update(b"|");
        hasher.update(primary.as_bytes());
        hasher.update(b"|");
        hasher.update(summary.as_bytes());
        hex::encode(hasher.finalize())[..16].to_string()
    }
}

/// Reference into the evidence directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub directory: PathBuf,
    pub replay_command: String,
}

/// Scenario-level classified outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioVerdict {
    pub scenario_id: ScenarioId,
    pub label: String,
    pub verdict: Verdict,
    pub evidence_grade: EvidenceGrade,
    pub attempts: u32,
    pub failure_signature: Option<FailureSignature>,
    pub evidence: Option<EvidenceReference>,
    pub notes: Vec<String>,
}

/// Minimal failure frontier (breakage horizon).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakageFrontier {
    pub observed: bool,
    pub horizon_label: Option<String>,
    pub scenario_id: Option<ScenarioId>,
    pub axis: Option<EnvironmentAxis>,
    pub from_label: Option<String>,
    pub to_label: Option<String>,
    pub failure_signature: Option<FailureSignature>,
    pub evidence_grade: Option<EvidenceGrade>,
    pub replay_command: Option<String>,
    pub explanation: String,
}

/// Top-level run manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub run_id: RunId,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub repository: RepositorySnapshot,
    pub detection: Option<ProjectDetection>,
    pub baseline: Option<Baseline>,
    pub config_hash: String,
    pub sandbox_engine: Option<String>,
    pub status: RunStatus,
    pub frontier: Option<BreakageFrontier>,
    pub scenario_count: usize,
    pub host: HostInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    Blocked,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub tomorrowci_version: String,
}

impl Default for HostInfo {
    fn default() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            tomorrowci_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Hash arbitrary serializable value for run identity.
pub fn hash_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())[..16].to_string()
}

/// Truncate logs for previews while preserving ends.
pub fn truncate_log(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let half = max_chars / 2;
    let start: String = s.chars().take(half).collect();
    let end: String = s
        .chars()
        .rev()
        .take(half)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}\n...[truncated]...\n{end}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_is_short_hex() {
        let id = RunId::new();
        assert_eq!(id.0.len(), 12);
        assert!(id.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_stable() {
        let a = FailureSignature::compute_fingerprint("ImportError", "MutableMapping", "sum");
        let b = FailureSignature::compute_fingerprint("ImportError", "MutableMapping", "sum");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn verdict_labels() {
        assert_eq!(Verdict::FutureFail.short_label(), "FAIL");
        assert_eq!(Verdict::Blocked.short_label(), "BLOCKED");
        assert!(!Verdict::Blocked.is_pass());
    }
}
