//! Typed domain models. Verdict engine consumes these — not ad-hoc terminal strings.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Python,
    Node,
    Rust,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentAxis {
    Runtime,
    Dependencies,
    PackageManager,
    BaseImage,
    Os,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceGrade {
    Observed,
    Simulated,
    ScheduledRisk,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn is_pass_like(self) -> bool {
        matches!(self, Self::BaselinePass | Self::FuturePass)
    }

    /// BLOCKED / UNSUPPORTED / INCONCLUSIVE must never become PASS.
    pub fn may_not_be_promoted_to_pass(self) -> bool {
        matches!(
            self,
            Self::Blocked | Self::Unsupported | Self::Inconclusive | Self::BaselineInvalid | Self::Flaky
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub source: String,
    pub path: PathBuf,
    pub commit_sha: Option<String>,
    pub is_disposable_copy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDetection {
    pub ecosystem: Ecosystem,
    pub manifests: Vec<String>,
    pub package_manager: String,
    pub confidence: f64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub runtime: String,
    pub dependencies: String,
    pub declared_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub axis: EnvironmentAxis,
    pub label: String,
    pub version: String,
    pub channel: String,
    pub grade_if_executed: EvidenceGrade,
    pub order_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub is_baseline: bool,
    pub runtime: String,
    pub dependencies: String,
    pub axes_changed: Vec<EnvironmentAxis>,
    pub candidates: Vec<String>,
    pub grade: EvidenceGrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub network: bool,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSpec {
    pub image: String,
    pub image_digest: Option<String>,
    pub workdir: String,
    pub env: IndexMap<String, String>,
    pub network_mode: String,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub user: Option<String>,
    pub read_only_root: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub plan_id: String,
    pub scenarios: Vec<Scenario>,
    pub selection_notes: Vec<String>,
    pub budget_max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawExecutionResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub network_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureSignature {
    pub kind: String,
    pub summary: String,
    pub normalized_hash: String,
    pub primary_frame: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub scenario_id: String,
    pub attempt: u32,
    pub verdict: Verdict,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub failure: Option<FailureSignature>,
    pub environment: EnvironmentSpec,
    pub commands: Vec<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub run_id: String,
    pub scenario_id: Option<String>,
    pub path: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakageFrontier {
    pub observed: bool,
    pub horizon_label: Option<String>,
    pub first_failing_scenario: Option<String>,
    pub last_passing_scenario: Option<String>,
    pub changed_axes: Vec<EnvironmentAxis>,
    pub failure_signature: Option<FailureSignature>,
    pub grade: EvidenceGrade,
    pub replay_command: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub repository: RepositorySnapshot,
    pub config_hash: String,
    pub detection: ProjectDetection,
    pub baseline: Baseline,
    pub plan: ExecutionPlan,
    pub results: Vec<ExecutionResult>,
    pub frontier: BreakageFrontier,
    pub evidence_root: PathBuf,
}
