//! Strict, self-contained domain model for exact replay evidence v2.
//!
//! The v2 records deliberately preserve execution metadata while keeping the
//! equivalence rule smaller: clocks, durations, raw-log identities, attempt
//! ordinals/kinds, and engine versions do not decide whether two attempts
//! reproduced the same outcome.

use crate::{CommandPhase, EvidenceGrade, NetworkMode, RunId, ScenarioId, ScenarioKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const REPLAY_SCHEMA_VERSION_V2: u32 = 2;
/// Schema for a detached receipt emitted by the public `replay` command.
pub const PUBLIC_REPLAY_RECEIPT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceIdentityKindV2 {
    GitCommit,
    DirtyWorktree,
    NonGit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFileEntryV2 {
    pub schema_version: u32,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotManifestV2 {
    pub schema_version: u32,
    pub run_id: RunId,
    pub source_id: String,
    pub identity_kind: SourceIdentityKindV2,
    pub repository_source: String,
    pub commit_sha: Option<String>,
    pub dirty: bool,
    pub tree_sha256: String,
    pub files: Vec<SourceFileEntryV2>,
    pub captured_at: DateTime<Utc>,
}

impl SourceSnapshotManifestV2 {
    /// Reject ambiguous source provenance before a snapshot can qualify replay.
    pub fn identity_is_coherent(&self) -> bool {
        if self.schema_version != REPLAY_SCHEMA_VERSION_V2
            || self
                .files
                .iter()
                .any(|file| file.schema_version != REPLAY_SCHEMA_VERSION_V2)
        {
            return false;
        }
        match self.identity_kind {
            SourceIdentityKindV2::GitCommit => self.commit_sha.is_some() && !self.dirty,
            SourceIdentityKindV2::DirtyWorktree => self.dirty,
            SourceIdentityKindV2::NonGit => self.commit_sha.is_none() && !self.dirty,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentityV2 {
    pub schema_version: u32,
    pub name: String,
    pub client_version: String,
    pub server_version: Option<String>,
    pub api_version: Option<String>,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCommandV2 {
    pub schema_version: u32,
    pub phase: CommandPhase,
    pub program: String,
    pub args: Vec<String>,
    pub workdir: String,
    pub network_required: bool,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactMountV2 {
    pub schema_version: u32,
    /// Logical source name (for example `workspace`), never a host temp path.
    pub source: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactEnvironmentV2 {
    pub schema_version: u32,
    pub workdir: String,
    pub user: Option<String>,
    pub env: BTreeMap<String, String>,
    pub mounts: Vec<ExactMountV2>,
    pub network_mode: NetworkMode,
    pub read_only_root: bool,
    pub memory_mb: u64,
    /// CPU limit in thousandths of a CPU, avoiding non-canonical floats.
    pub cpu_millis: u32,
    pub pids_limit: u64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReplayManifestV2 {
    pub schema_version: u32,
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub scenario_kind: ScenarioKind,
    pub source_manifest_sha256: String,
    pub config_sha256: String,
    pub scenario_sha256: String,
    pub image_ref: String,
    pub image_digest: String,
    pub commands: Vec<ReplayCommandV2>,
    pub environment: ExactEnvironmentV2,
    pub engine: EngineIdentityV2,
    pub created_at: DateTime<Utc>,
}

impl ExactReplayManifestV2 {
    pub fn schema_is_v2(&self) -> bool {
        self.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self.engine.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self
                .commands
                .iter()
                .all(|command| command.schema_version == REPLAY_SCHEMA_VERSION_V2)
            && self.environment.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self
                .environment
                .mounts
                .iter()
                .all(|mount| mount.schema_version == REPLAY_SCHEMA_VERSION_V2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptKindV2 {
    Original,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptOutcomeClassV2 {
    Passed,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptResultV2 {
    pub schema_version: u32,
    pub outcome_class: AttemptOutcomeClassV2,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub blocked_reason: Option<String>,
    pub network_used: bool,
    pub duration_ms: u64,
    /// Integrity metadata retained in the receipt but excluded from equivalence.
    pub stdout_sha256: Option<String>,
    /// Integrity metadata retained in the receipt but excluded from equivalence.
    pub stderr_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedFailureSignatureV2 {
    pub schema_version: u32,
    pub kind: String,
    pub summary: String,
    pub primary_error: Option<String>,
    pub fingerprint: String,
    pub framework_hints: Vec<String>,
    pub evidence_grade: EvidenceGrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub scenario_kind: ScenarioKind,
    pub source_manifest_sha256: String,
    pub config_sha256: String,
    pub replay_manifest_sha256: String,
    pub image_ref: String,
    pub image_digest: String,
    pub commands: Vec<ReplayCommandV2>,
    pub environment: ExactEnvironmentV2,
    pub engine: EngineIdentityV2,
    pub ordinal: u32,
    pub kind: AttemptKindV2,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub result: ExecutionAttemptResultV2,
    pub failure_signature: Option<NormalizedFailureSignatureV2>,
}

impl ExecutionAttemptV2 {
    pub fn schema_is_v2(&self) -> bool {
        self.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self.engine.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self.result.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self
                .failure_signature
                .as_ref()
                .is_none_or(|signature| signature.schema_version == REPLAY_SCHEMA_VERSION_V2)
            && self
                .commands
                .iter()
                .all(|command| command.schema_version == REPLAY_SCHEMA_VERSION_V2)
            && self.environment.schema_version == REPLAY_SCHEMA_VERSION_V2
            && self
                .environment
                .mounts
                .iter()
                .all(|mount| mount.schema_version == REPLAY_SCHEMA_VERSION_V2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptMismatchV2 {
    RunId,
    ScenarioId,
    OutcomeClass,
    ExitCode,
    Signal,
    TimedOut,
    BlockedReason,
    FailureFingerprint,
    ImageDigest,
    Commands,
    Environment,
    EngineIdentity,
    ConfigIdentity,
    SourceIdentity,
    ReplayIdentity,
}

/// Immutable, detached binding between one public replay execution and the
/// sealed run generation that authorized it.
///
/// The receipt bundle embeds the referenced inventory generations and the
/// minimal typed origin records.  A verifier therefore recomputes these fields
/// from sealed bytes instead of trusting CLI output or a workflow exit code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReplayReceiptV2 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub created_at: DateTime<Utc>,
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub original_run_inventory_sha256: String,
    pub original_scenario_inventory_sha256: String,
    pub original_attempt_inventory_sha256: String,
    /// Run-relative directory of the selected final original attempt.
    pub original_attempt_path: String,
    pub original_attempt_id: String,
    pub source_manifest_sha256: String,
    pub config_sha256: String,
    pub scenario_sha256: String,
    pub replay_manifest_sha256: String,
    pub original_attempt_sha256: String,
    pub replay_attempt_sha256: String,
    pub expected_engine: EngineIdentityV2,
    pub observed_engine: EngineIdentityV2,
    pub image_digest: String,
    pub original_result: ExecutionAttemptResultV2,
    pub replay_result: ExecutionAttemptResultV2,
    pub equivalent_to_original: bool,
    pub mismatches: Vec<AttemptMismatchV2>,
}

/// Non-persisted calculation result used to build qualification records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEquivalence {
    pub equivalent: bool,
    pub mismatches: Vec<AttemptMismatchV2>,
}

/// Compare only fields that define an exact replay outcome.
///
/// Attempt ids, kinds, ordinals, timestamps, durations, raw-log hashes, image
/// tags, engine versions, and diagnostic signature text are intentionally not
/// compared. Their enclosing attempt remains content-addressed, so they cannot
/// be changed without invalidating the receipt digest.
pub fn attempt_equivalence(
    original: &ExecutionAttemptV2,
    replay: &ExecutionAttemptV2,
) -> AttemptEquivalence {
    let mut mismatches = Vec::new();
    if original.run_id != replay.run_id {
        mismatches.push(AttemptMismatchV2::RunId);
    }
    if original.scenario_id != replay.scenario_id {
        mismatches.push(AttemptMismatchV2::ScenarioId);
    }
    if original.result.outcome_class != replay.result.outcome_class {
        mismatches.push(AttemptMismatchV2::OutcomeClass);
    }
    if original.result.exit_code != replay.result.exit_code {
        mismatches.push(AttemptMismatchV2::ExitCode);
    }
    if original.result.signal != replay.result.signal {
        mismatches.push(AttemptMismatchV2::Signal);
    }
    if original.result.timed_out != replay.result.timed_out {
        mismatches.push(AttemptMismatchV2::TimedOut);
    }
    if original.result.blocked_reason != replay.result.blocked_reason {
        mismatches.push(AttemptMismatchV2::BlockedReason);
    }
    if failure_fingerprint(original) != failure_fingerprint(replay) {
        mismatches.push(AttemptMismatchV2::FailureFingerprint);
    }
    if original.image_digest != replay.image_digest {
        mismatches.push(AttemptMismatchV2::ImageDigest);
    }
    if original.commands != replay.commands {
        mismatches.push(AttemptMismatchV2::Commands);
    }
    if original.environment != replay.environment {
        mismatches.push(AttemptMismatchV2::Environment);
    }
    if original.config_sha256 != replay.config_sha256 {
        mismatches.push(AttemptMismatchV2::ConfigIdentity);
    }
    if original.source_manifest_sha256 != replay.source_manifest_sha256 {
        mismatches.push(AttemptMismatchV2::SourceIdentity);
    }
    if original.replay_manifest_sha256 != replay.replay_manifest_sha256 {
        mismatches.push(AttemptMismatchV2::ReplayIdentity);
    }
    AttemptEquivalence {
        equivalent: mismatches.is_empty(),
        mismatches,
    }
}

fn failure_fingerprint(attempt: &ExecutionAttemptV2) -> Option<&str> {
    attempt
        .failure_signature
        .as_ref()
        .map(|signature| signature.fingerprint.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptReferenceV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub attempt_sha256: String,
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub source_manifest_sha256: String,
    pub config_sha256: String,
    pub replay_manifest_sha256: String,
    pub ordinal: u32,
    pub kind: AttemptKindV2,
}

impl AttemptReferenceV2 {
    pub fn from_attempt(attempt: &ExecutionAttemptV2) -> Result<Self, serde_json::Error> {
        Ok(Self {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            attempt_id: attempt.attempt_id.clone(),
            attempt_sha256: canonical_sha256(attempt)?,
            run_id: attempt.run_id.clone(),
            scenario_id: attempt.scenario_id.clone(),
            source_manifest_sha256: attempt.source_manifest_sha256.clone(),
            config_sha256: attempt.config_sha256.clone(),
            replay_manifest_sha256: attempt.replay_manifest_sha256.clone(),
            ordinal: attempt.ordinal,
            kind: attempt.kind,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAttemptEquivalenceV2 {
    pub schema_version: u32,
    pub replay_attempt_id: String,
    pub equivalent: bool,
    pub mismatches: Vec<AttemptMismatchV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayQualificationV2 {
    pub schema_version: u32,
    pub run_id: RunId,
    pub scenario_id: ScenarioId,
    pub source_manifest_sha256: String,
    pub config_sha256: String,
    pub replay_manifest_sha256: String,
    pub original_attempt: AttemptReferenceV2,
    pub replay_attempts: Vec<AttemptReferenceV2>,
    pub replay_equivalence: Vec<ReplayAttemptEquivalenceV2>,
    pub equivalent: bool,
    pub qualified_at: DateTime<Utc>,
}

impl ReplayQualificationV2 {
    /// Build a qualification artifact without hiding negative outcomes.
    pub fn evaluate(
        original: &ExecutionAttemptV2,
        replay_attempts: &[ExecutionAttemptV2],
        qualified_at: DateTime<Utc>,
    ) -> Result<Self, serde_json::Error> {
        let original_attempt = AttemptReferenceV2::from_attempt(original)?;
        let replay_references = replay_attempts
            .iter()
            .map(AttemptReferenceV2::from_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        let replay_equivalence = replay_attempts
            .iter()
            .map(|attempt| {
                let calculated = attempt_equivalence(original, attempt);
                ReplayAttemptEquivalenceV2 {
                    schema_version: REPLAY_SCHEMA_VERSION_V2,
                    replay_attempt_id: attempt.attempt_id.clone(),
                    equivalent: calculated.equivalent,
                    mismatches: calculated.mismatches,
                }
            })
            .collect::<Vec<_>>();
        let equivalent = replay_equivalence.iter().all(|record| record.equivalent);

        Ok(Self {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            run_id: original.run_id.clone(),
            scenario_id: original.scenario_id.clone(),
            source_manifest_sha256: original.source_manifest_sha256.clone(),
            config_sha256: original.config_sha256.clone(),
            replay_manifest_sha256: original.replay_manifest_sha256.clone(),
            original_attempt,
            replay_attempts: replay_references,
            replay_equivalence,
            equivalent,
            qualified_at,
        })
    }

    /// Phase-1 qualification requires two independent, consecutive replay
    /// attempts, each equivalent to the original and bound to one identity set.
    pub fn qualified(&self) -> bool {
        if self.schema_version != REPLAY_SCHEMA_VERSION_V2
            || !self.equivalent
            || self.original_attempt.schema_version != REPLAY_SCHEMA_VERSION_V2
            || self.original_attempt.kind != AttemptKindV2::Original
            || self.replay_attempts.len() < 2
            || self.replay_attempts.len() != self.replay_equivalence.len()
            || !reference_matches_qualification(&self.original_attempt, self)
        {
            return false;
        }

        self.replay_attempts
            .iter()
            .zip(&self.replay_equivalence)
            .enumerate()
            .all(|(index, (attempt, record))| {
                attempt.schema_version == REPLAY_SCHEMA_VERSION_V2
                    && attempt.kind == AttemptKindV2::Replay
                    && attempt.ordinal == index as u32 + 1
                    && attempt.attempt_id != self.original_attempt.attempt_id
                    && !self.replay_attempts[..index]
                        .iter()
                        .any(|prior| prior.attempt_id == attempt.attempt_id)
                    && reference_matches_qualification(attempt, self)
                    && record.schema_version == REPLAY_SCHEMA_VERSION_V2
                    && record.replay_attempt_id == attempt.attempt_id
                    && record.equivalent
                    && record.mismatches.is_empty()
            })
    }

    /// Recompute receipt digests and equivalence against the referenced
    /// attempts. Untrusted qualification JSON must pass this stronger gate.
    pub fn qualified_against(
        &self,
        original: &ExecutionAttemptV2,
        replay_attempts: &[ExecutionAttemptV2],
    ) -> bool {
        let Ok(original_reference) = AttemptReferenceV2::from_attempt(original) else {
            return false;
        };
        if !self.qualified()
            || !original.schema_is_v2()
            || replay_attempts.len() != self.replay_attempts.len()
            || original_reference != self.original_attempt
        {
            return false;
        }

        for ((attempt, reference), recorded) in replay_attempts
            .iter()
            .zip(&self.replay_attempts)
            .zip(&self.replay_equivalence)
        {
            let calculated = attempt_equivalence(original, attempt);
            let Ok(calculated_reference) = AttemptReferenceV2::from_attempt(attempt) else {
                return false;
            };
            if !attempt.schema_is_v2()
                || calculated_reference != *reference
                || !calculated.equivalent
                || calculated.mismatches != recorded.mismatches
            {
                return false;
            }
        }
        true
    }
}

fn reference_matches_qualification(
    attempt: &AttemptReferenceV2,
    qualification: &ReplayQualificationV2,
) -> bool {
    attempt.run_id == qualification.run_id
        && attempt.scenario_id == qualification.scenario_id
        && attempt.source_manifest_sha256 == qualification.source_manifest_sha256
        && attempt.config_sha256 == qualification.config_sha256
        && attempt.replay_manifest_sha256 == qualification.replay_manifest_sha256
}

/// Deterministic JSON bytes with recursively lexicographically sorted keys.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_canonical_value(&value, &mut out)?;
    Ok(out)
}

/// Full SHA-256 identity of [`canonical_json_bytes`], prefixed with `sha256:`.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = canonical_json_bytes(value)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn write_canonical_value(
    value: &serde_json::Value,
    out: &mut Vec<u8>,
) -> Result<(), serde_json::Error> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => out.extend(serde_json::to_vec(value)?),
        serde_json::Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_value(value, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(values) => {
            out.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key)?);
                out.push(b':');
                write_canonical_value(value, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn timestamp(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, second)
            .single()
            .unwrap()
    }

    fn command() -> ReplayCommandV2 {
        ReplayCommandV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            phase: CommandPhase::Test,
            program: "cargo".into(),
            args: vec!["test".into(), "--locked".into()],
            workdir: "/workspace".into(),
            network_required: false,
            env: BTreeMap::from([("CI".into(), "true".into())]),
        }
    }

    fn environment() -> ExactEnvironmentV2 {
        ExactEnvironmentV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            workdir: "/workspace".into(),
            user: Some("65532:65532".into()),
            env: BTreeMap::from([("TZ".into(), "UTC".into())]),
            mounts: vec![ExactMountV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                source: "workspace".into(),
                container_path: "/workspace".into(),
                read_only: true,
            }],
            network_mode: NetworkMode::None,
            read_only_root: true,
            memory_mb: 1024,
            cpu_millis: 1000,
            pids_limit: 128,
            timeout_seconds: 60,
        }
    }

    fn engine(version: &str) -> EngineIdentityV2 {
        EngineIdentityV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            name: "docker".into(),
            client_version: version.into(),
            server_version: Some(version.into()),
            api_version: Some("1.52".into()),
            os: "linux".into(),
            arch: "amd64".into(),
        }
    }

    fn attempt(kind: AttemptKindV2, ordinal: u32, attempt_id: &str) -> ExecutionAttemptV2 {
        ExecutionAttemptV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            attempt_id: attempt_id.into(),
            run_id: RunId("run-1".into()),
            scenario_id: ScenarioId("scenario-1".into()),
            scenario_kind: ScenarioKind::SingleAxis,
            source_manifest_sha256: format!("sha256:{}", "a".repeat(64)),
            config_sha256: format!("sha256:{}", "b".repeat(64)),
            replay_manifest_sha256: format!("sha256:{}", "c".repeat(64)),
            image_ref: "example.invalid/tool:tag".into(),
            image_digest: format!("sha256:{}", "d".repeat(64)),
            commands: vec![command()],
            environment: environment(),
            engine: engine("29.0.0"),
            ordinal,
            kind,
            started_at: timestamp(1),
            finished_at: timestamp(2),
            result: ExecutionAttemptResultV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                outcome_class: AttemptOutcomeClassV2::Failed,
                exit_code: Some(1),
                signal: None,
                timed_out: false,
                blocked_reason: None,
                network_used: false,
                duration_ms: 100,
                stdout_sha256: Some(format!("sha256:{}", "e".repeat(64))),
                stderr_sha256: Some(format!("sha256:{}", "f".repeat(64))),
            },
            failure_signature: Some(NormalizedFailureSignatureV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                kind: "assertion".into(),
                summary: "expected one, got two".into(),
                primary_error: Some("expected one, got two".into()),
                fingerprint: "normalized-fingerprint".into(),
                framework_hints: vec!["test".into()],
                evidence_grade: EvidenceGrade::Observed,
            }),
        }
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = serde_json::json!({"z": {"y": 2, "a": 1}, "a": true});
        let bytes = canonical_json_bytes(&value).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"a":true,"z":{"a":1,"y":2}}"#
        );
        assert_eq!(canonical_sha256(&value).unwrap().len(), 71);
    }

    #[test]
    fn equivalence_ignores_observational_attempt_metadata() {
        let original = attempt(AttemptKindV2::Original, 7, "original");
        let mut replay = original.clone();
        replay.attempt_id = "replay-1".into();
        replay.kind = AttemptKindV2::Replay;
        replay.ordinal = 1;
        replay.started_at = timestamp(10);
        replay.finished_at = timestamp(11);
        replay.result.duration_ms = 999;
        replay.result.stdout_sha256 = Some(format!("sha256:{}", "1".repeat(64)));
        replay.result.stderr_sha256 = Some(format!("sha256:{}", "2".repeat(64)));
        replay.image_ref = "example.invalid/tool:another-tag".into();
        replay.engine = engine("30.0.0");
        replay.failure_signature.as_mut().unwrap().summary = "different diagnostic text".into();

        assert_eq!(
            attempt_equivalence(&original, &replay),
            AttemptEquivalence {
                equivalent: true,
                mismatches: vec![],
            }
        );
    }

    #[test]
    fn equivalence_reports_every_authoritative_difference() {
        let original = attempt(AttemptKindV2::Original, 1, "original");
        let mut replay = attempt(AttemptKindV2::Replay, 1, "replay");
        replay.run_id = RunId("other-run".into());
        replay.scenario_id = ScenarioId("other-scenario".into());
        replay.result.outcome_class = AttemptOutcomeClassV2::Blocked;
        replay.result.exit_code = None;
        replay.result.signal = Some(9);
        replay.result.timed_out = true;
        replay.result.blocked_reason = Some("policy".into());
        replay.failure_signature.as_mut().unwrap().fingerprint = "other".into();
        replay.image_digest = format!("sha256:{}", "0".repeat(64));
        replay.commands[0].args.push("--all".into());
        replay.environment.read_only_root = false;
        replay.config_sha256 = "different-config".into();
        replay.source_manifest_sha256 = "different-source".into();
        replay.replay_manifest_sha256 = "different-replay".into();

        let result = attempt_equivalence(&original, &replay);
        assert!(!result.equivalent);
        assert_eq!(result.mismatches.len(), 14);
        for expected in [
            AttemptMismatchV2::RunId,
            AttemptMismatchV2::ScenarioId,
            AttemptMismatchV2::OutcomeClass,
            AttemptMismatchV2::ExitCode,
            AttemptMismatchV2::Signal,
            AttemptMismatchV2::TimedOut,
            AttemptMismatchV2::BlockedReason,
            AttemptMismatchV2::FailureFingerprint,
            AttemptMismatchV2::ImageDigest,
            AttemptMismatchV2::Commands,
            AttemptMismatchV2::Environment,
            AttemptMismatchV2::ConfigIdentity,
            AttemptMismatchV2::SourceIdentity,
            AttemptMismatchV2::ReplayIdentity,
        ] {
            assert!(
                result.mismatches.contains(&expected),
                "missing {expected:?}"
            );
        }
    }

    #[test]
    fn qualification_requires_two_consecutive_unique_equivalent_replays() {
        let original = attempt(AttemptKindV2::Original, 3, "original");
        let first = attempt(AttemptKindV2::Replay, 1, "replay-1");
        let second = attempt(AttemptKindV2::Replay, 2, "replay-2");
        let qualification = ReplayQualificationV2::evaluate(
            &original,
            &[first.clone(), second.clone()],
            timestamp(20),
        )
        .unwrap();
        assert!(qualification.equivalent);
        assert!(qualification.qualified());
        assert!(qualification.qualified_against(&original, &[first.clone(), second.clone()]));

        let one = ReplayQualificationV2::evaluate(&original, &[first], timestamp(20)).unwrap();
        assert!(!one.qualified());

        let mut duplicate_ordinal =
            ReplayQualificationV2::evaluate(&original, &[second.clone(), second], timestamp(20))
                .unwrap();
        duplicate_ordinal.replay_attempts[0].ordinal = 1;
        duplicate_ordinal.replay_attempts[1].ordinal = 1;
        assert!(!duplicate_ordinal.qualified());
    }

    #[test]
    fn qualification_preserves_negative_equivalence_and_identity_failures() {
        let original = attempt(AttemptKindV2::Original, 1, "original");
        let first = attempt(AttemptKindV2::Replay, 1, "replay-1");
        let mut second = attempt(AttemptKindV2::Replay, 2, "replay-2");
        second.failure_signature.as_mut().unwrap().fingerprint = "changed".into();
        let qualification =
            ReplayQualificationV2::evaluate(&original, &[first, second], timestamp(20)).unwrap();
        assert!(!qualification.equivalent);
        assert!(!qualification.qualified());
        assert_eq!(
            qualification.replay_equivalence[1].mismatches,
            vec![AttemptMismatchV2::FailureFingerprint]
        );

        let mut forged = ReplayQualificationV2::evaluate(
            &original,
            &[
                attempt(AttemptKindV2::Replay, 1, "replay-1"),
                attempt(AttemptKindV2::Replay, 2, "replay-2"),
            ],
            timestamp(20),
        )
        .unwrap();
        forged.replay_attempts[1].source_manifest_sha256 = "other-source".into();
        assert!(!forged.qualified());

        let replay_attempts = vec![
            attempt(AttemptKindV2::Replay, 1, "replay-1"),
            attempt(AttemptKindV2::Replay, 2, "replay-2"),
        ];
        let qualification =
            ReplayQualificationV2::evaluate(&original, &replay_attempts, timestamp(20)).unwrap();
        let mut mutated_receipts = replay_attempts;
        // Duration is excluded from outcome equivalence, but mutating a sealed
        // receipt must still fail its canonical reference identity.
        mutated_receipts[0].result.duration_ms += 1;
        assert!(!qualification.qualified_against(&original, &mutated_receipts));
    }

    #[test]
    fn persisted_v2_structs_reject_unknown_fields() {
        let attempt = attempt(AttemptKindV2::Original, 1, "original");
        let mut value = serde_json::to_value(&attempt).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<ExecutionAttemptV2>(value).is_err());

        let mut nested = serde_json::to_value(&attempt).unwrap();
        nested["result"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ExecutionAttemptV2>(nested).is_err());
    }

    #[test]
    fn source_identity_explicitly_distinguishes_dirty_and_non_git() {
        let base = SourceSnapshotManifestV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            run_id: RunId("run-1".into()),
            source_id: "source-1".into(),
            identity_kind: SourceIdentityKindV2::GitCommit,
            repository_source: "https://example.invalid/repo.git".into(),
            commit_sha: Some("abc123".into()),
            dirty: false,
            tree_sha256: format!("sha256:{}", "a".repeat(64)),
            files: vec![],
            captured_at: timestamp(1),
        };
        assert!(base.identity_is_coherent());

        let mut dirty = base.clone();
        dirty.identity_kind = SourceIdentityKindV2::DirtyWorktree;
        dirty.dirty = true;
        assert!(dirty.identity_is_coherent());

        let mut ambiguous = base;
        ambiguous.identity_kind = SourceIdentityKindV2::NonGit;
        assert!(!ambiguous.identity_is_coherent());
    }
}
