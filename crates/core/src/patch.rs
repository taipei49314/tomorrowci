//! Strict patch proposal and independently-verifiable Patch Lab proof model.
//!
//! Patch Lab accepts a deliberately small subset of unified diffs.  The
//! validated paths are later passed to `git apply` only inside a disposable
//! workspace.  Rejecting ambiguous Git metadata here is part of the security
//! boundary, not a convenience check.

use crate::{RunStatus, ScenarioKind, Verdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};
use thiserror::Error;

pub const PATCH_PROOF_SCHEMA_VERSION: u32 = 2;
pub const DEFAULT_MAX_PATCH_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_MAX_PATCH_FILES: usize = 128;
/// Upper bound for the changed-file bytes copied into an independently
/// verifiable PatchProof.  A whole-file witness is necessary because a hash
/// plus a partial unified diff is not enough to prove the resulting hash.
pub const DEFAULT_MAX_PATCH_WITNESS_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchDisposition {
    Proposal,
    Qualified,
    Blocked,
}

impl PatchDisposition {
    pub fn is_green(self) -> bool {
        self == Self::Qualified
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchChangeKind {
    Add,
    Modify,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFileChange {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub kind: PatchChangeKind,
    /// File mode asserted by an add/delete header.  Modifications must retain
    /// the mode and therefore leave both fields absent.
    pub old_executable: Option<bool>,
    pub new_executable: Option<bool>,
}

impl PatchFileChange {
    pub fn target_path(&self) -> &str {
        self.new_path
            .as_deref()
            .or(self.old_path.as_deref())
            .expect("a validated patch change always has a path")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedPatch {
    pub sha256: String,
    pub size_bytes: u64,
    pub changes: Vec<PatchFileChange>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PatchValidationError {
    #[error("patch is empty")]
    Empty,
    #[error("patch exceeds the {max_bytes}-byte cap: {actual_bytes} bytes")]
    TooLarge { max_bytes: u64, actual_bytes: u64 },
    #[error("patch is not UTF-8 text")]
    NotUtf8,
    #[error(
        "patch uses forbidden binary, submodule, symlink, rename, copy, or mode metadata: {0}"
    )]
    ForbiddenMetadata(String),
    #[error("patch structure is invalid: {0}")]
    InvalidFormat(String),
    #[error("unsafe patch path: {0}")]
    UnsafePath(String),
    #[error("patch changes more than {0} files")]
    TooManyFiles(usize),
    #[error("patch repeats target path: {0}")]
    DuplicatePath(String),
}

/// Validate and summarize an exact unified-diff byte stream.
///
/// Quoted Git paths are intentionally unsupported.  This avoids accepting an
/// escape syntax that could be interpreted differently by the validator and
/// `git apply`; callers should regenerate such patches with simple UTF-8 paths.
pub fn validate_unified_patch(
    bytes: &[u8],
    max_bytes: u64,
    max_files: usize,
) -> Result<ValidatedPatch, PatchValidationError> {
    if bytes.is_empty() {
        return Err(PatchValidationError::Empty);
    }
    if bytes.len() as u64 > max_bytes {
        return Err(PatchValidationError::TooLarge {
            max_bytes,
            actual_bytes: bytes.len() as u64,
        });
    }
    if bytes.contains(&0) {
        return Err(PatchValidationError::ForbiddenMetadata(
            "NUL/binary content".into(),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PatchValidationError::NotUtf8)?;
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current: Option<PendingChange> = None;

    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if is_forbidden_metadata(line) {
            return Err(PatchValidationError::ForbiddenMetadata(line.into()));
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(previous) = current.take() {
                finish_change(previous, max_files, &mut seen, &mut changes)?;
            }
            let mut fields = rest.split_whitespace();
            let old = fields.next();
            let new = fields.next();
            if old.is_none() || new.is_none() || fields.next().is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "quoted, spaced, or malformed diff --git path".into(),
                ));
            }
            let old = strip_git_prefix(old.unwrap(), "a/")?;
            let new = strip_git_prefix(new.unwrap(), "b/")?;
            if old != new {
                return Err(PatchValidationError::ForbiddenMetadata(
                    "renames and copies are not accepted".into(),
                ));
            }
            current = Some(PendingChange {
                diff_old: old,
                diff_new: new,
                header_old: None,
                header_new: None,
                new_file_executable: None,
                deleted_file_executable: None,
                saw_hunk: false,
            });
            continue;
        }

        let Some(change) = current.as_mut() else {
            if !line.is_empty() {
                return Err(PatchValidationError::InvalidFormat(
                    "content before first diff --git header".into(),
                ));
            }
            continue;
        };
        if let Some(mode) = line.strip_prefix("new file mode ") {
            if change.new_file_executable.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "duplicate new file mode header".into(),
                ));
            }
            change.new_file_executable = Some(parse_file_mode(mode)?);
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if change.deleted_file_executable.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "duplicate deleted file mode header".into(),
                ));
            }
            change.deleted_file_executable = Some(parse_file_mode(mode)?);
        } else if let Some(rest) = line.strip_prefix("--- ") {
            if change.header_old.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "duplicate --- header".into(),
                ));
            }
            change.header_old = Some(parse_file_header(rest, "a/")?);
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            if change.header_new.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "duplicate +++ header".into(),
                ));
            }
            change.header_new = Some(parse_file_header(rest, "b/")?);
        } else if line.starts_with("@@ ") {
            if change.header_old.is_none() || change.header_new.is_none() {
                return Err(PatchValidationError::InvalidFormat(
                    "hunk appears before file headers".into(),
                ));
            }
            change.saw_hunk = true;
        }
    }
    if let Some(previous) = current.take() {
        finish_change(previous, max_files, &mut seen, &mut changes)?;
    }
    if changes.is_empty() {
        return Err(PatchValidationError::InvalidFormat(
            "no file changes".into(),
        ));
    }
    Ok(ValidatedPatch {
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        size_bytes: bytes.len() as u64,
        changes,
    })
}

#[derive(Debug)]
struct PendingChange {
    diff_old: String,
    diff_new: String,
    header_old: Option<Option<String>>,
    header_new: Option<Option<String>>,
    new_file_executable: Option<bool>,
    deleted_file_executable: Option<bool>,
    saw_hunk: bool,
}

fn finish_change(
    change: PendingChange,
    max_files: usize,
    seen: &mut BTreeSet<String>,
    changes: &mut Vec<PatchFileChange>,
) -> Result<(), PatchValidationError> {
    let old = change
        .header_old
        .ok_or_else(|| PatchValidationError::InvalidFormat("missing --- file header".into()))?;
    let new = change
        .header_new
        .ok_or_else(|| PatchValidationError::InvalidFormat("missing +++ file header".into()))?;
    if !change.saw_hunk {
        return Err(PatchValidationError::InvalidFormat(
            "file change has no unified-diff hunk".into(),
        ));
    }
    match &old {
        Some(path) if path != &change.diff_old => {
            return Err(PatchValidationError::InvalidFormat(format!(
                "--- path {path} does not match diff path {}",
                change.diff_old
            )))
        }
        _ => {}
    }
    match &new {
        Some(path) if path != &change.diff_new => {
            return Err(PatchValidationError::InvalidFormat(format!(
                "+++ path {path} does not match diff path {}",
                change.diff_new
            )))
        }
        _ => {}
    }
    let (kind, old_executable, new_executable) = match (&old, &new) {
        (None, Some(_)) => {
            if change.deleted_file_executable.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "added file has a deleted file mode header".into(),
                ));
            }
            (
                PatchChangeKind::Add,
                None,
                Some(change.new_file_executable.unwrap_or(false)),
            )
        }
        (Some(_), None) => {
            if change.new_file_executable.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "deleted file has a new file mode header".into(),
                ));
            }
            (
                PatchChangeKind::Delete,
                Some(change.deleted_file_executable.unwrap_or(false)),
                None,
            )
        }
        (Some(_), Some(_)) => {
            if change.new_file_executable.is_some() || change.deleted_file_executable.is_some() {
                return Err(PatchValidationError::InvalidFormat(
                    "modified file cannot have add/delete mode metadata".into(),
                ));
            }
            (PatchChangeKind::Modify, None, None)
        }
        (None, None) => {
            return Err(PatchValidationError::InvalidFormat(
                "both file headers are /dev/null".into(),
            ))
        }
    };
    let target = new.as_ref().or(old.as_ref()).unwrap().clone();
    if !seen.insert(target.to_lowercase()) {
        return Err(PatchValidationError::DuplicatePath(target));
    }
    if changes.len() >= max_files {
        return Err(PatchValidationError::TooManyFiles(max_files));
    }
    changes.push(PatchFileChange {
        old_path: old,
        new_path: new,
        kind,
        old_executable,
        new_executable,
    });
    Ok(())
}

fn parse_file_mode(value: &str) -> Result<bool, PatchValidationError> {
    match value {
        "100644" => Ok(false),
        "100755" => Ok(true),
        _ => Err(PatchValidationError::ForbiddenMetadata(format!(
            "unsupported file mode {value}"
        ))),
    }
}

fn parse_file_header(
    value: &str,
    required_prefix: &str,
) -> Result<Option<String>, PatchValidationError> {
    if value == "/dev/null" {
        return Ok(None);
    }
    if value.contains('\t') || value.contains(' ') || value.starts_with('"') {
        return Err(PatchValidationError::InvalidFormat(
            "timestamps, quoted paths, and paths with spaces are not accepted".into(),
        ));
    }
    strip_git_prefix(value, required_prefix).map(Some)
}

fn strip_git_prefix(value: &str, prefix: &str) -> Result<String, PatchValidationError> {
    let path = value.strip_prefix(prefix).ok_or_else(|| {
        PatchValidationError::UnsafePath(format!("expected {prefix} prefix: {value}"))
    })?;
    validate_patch_path(path)?;
    Ok(path.to_string())
}

pub fn validate_patch_path(value: &str) -> Result<(), PatchValidationError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('-')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.contains("//")
        || value.chars().any(|ch| ch.is_control())
    {
        return Err(PatchValidationError::UnsafePath(value.into()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(PatchValidationError::UnsafePath(value.into()));
    }
    for component in value.split('/') {
        let raw_stem = component.split('.').next().unwrap_or(component);
        let superscript_reserved = raw_stem
            .strip_suffix(['\u{00b9}', '\u{00b2}', '\u{00b3}'])
            .is_some_and(|prefix| {
                prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
            });
        let portable_stem = raw_stem.to_ascii_uppercase();
        let windows_reserved = superscript_reserved
            || matches!(
                portable_stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || portable_stem.strip_prefix("COM").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
            || portable_stem.strip_prefix("LPT").is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.eq_ignore_ascii_case(".git")
            || component.eq_ignore_ascii_case(".tomorrowci")
            || component.eq_ignore_ascii_case("node_modules")
            || component.eq_ignore_ascii_case("target")
            || component.eq_ignore_ascii_case("__pycache__")
            || component.eq_ignore_ascii_case(".venv")
            || component.eq_ignore_ascii_case("venv")
            || component.ends_with('.')
            || component.ends_with(' ')
            || windows_reserved
        {
            return Err(PatchValidationError::UnsafePath(value.into()));
        }
    }
    Ok(())
}

fn is_forbidden_metadata(line: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "GIT binary patch",
        "Binary files ",
        "Submodule ",
        "old mode ",
        "new mode ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "similarity index ",
        "dissimilarity index ",
    ];
    FORBIDDEN.iter().any(|prefix| line.starts_with(prefix))
        || (line.starts_with("new file mode ")
            && line != "new file mode 100644"
            && line != "new file mode 100755")
        || (line.starts_with("deleted file mode ")
            && line != "deleted file mode 100644"
            && line != "deleted file mode 100755")
        || (line.starts_with("index ") && line.ends_with(" 160000"))
        || line == "new file mode 120000"
        || line == "deleted file mode 120000"
        || line == "new file mode 160000"
        || line == "deleted file mode 160000"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSourceBinding {
    pub run_id: String,
    pub run_inventory_sha256: String,
    pub source_manifest_sha256: String,
    pub source_tree_sha256: String,
    pub config_sha256: String,
    pub verdicts_sha256: String,
    pub run_status: RunStatus,
    pub scenario_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchReplayOutcome {
    Passed,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchReplayReceipt {
    pub scenario_id: String,
    pub scenario_kind: ScenarioKind,
    pub verdict: Verdict,
    pub scenario_inventory_sha256: Option<String>,
    pub exact_replay_manifest_sha256: Option<String>,
    /// Portable path below the PatchProof bundle containing a sealed v2
    /// replay-attempt bundle.  Absent only when execution was blocked before
    /// an attempt receipt could be written.
    pub replay_attempt_path: Option<String>,
    pub replay_attempt_inventory_sha256: Option<String>,
    pub outcome: PatchReplayOutcome,
    pub detail: String,
}

/// Verifier-derived identity of an observed broken scenario repaired by the
/// proposal.  The evidence verifier recomputes this from the two sealed run
/// bundles; these fields are never accepted as self-asserted evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchScenarioRepair {
    pub scenario_id: String,
    pub scenario_kind: ScenarioKind,
    pub original_verdict: Verdict,
    pub patched_verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProof {
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    pub original: PatchSourceBinding,
    pub original_had_observed_breakage: bool,
    pub patch: ValidatedPatch,
    pub patched: PatchSourceBinding,
    pub repaired_scenarios: Vec<PatchScenarioRepair>,
    pub replay_receipts: Vec<PatchReplayReceipt>,
    pub original_unchanged: bool,
    pub disposition: PatchDisposition,
    pub disposition_reason: String,
}

impl PatchProof {
    /// Recompute the only status that can be shown as a qualified patch.
    pub fn evaluate_disposition(&self) -> (PatchDisposition, String) {
        if !self.original_unchanged {
            return (
                PatchDisposition::Blocked,
                "original sealed source or run changed during Patch Lab".into(),
            );
        }
        if self.patched.run_status == RunStatus::Blocked {
            return (PatchDisposition::Blocked, "patched scan was blocked".into());
        }
        if self.original.config_sha256 != self.patched.config_sha256 {
            return (
                PatchDisposition::Blocked,
                "patched scan did not use the original normalized configuration".into(),
            );
        }
        if !self.original_had_observed_breakage {
            return (
                PatchDisposition::Proposal,
                "original run had no observed breakage to repair".into(),
            );
        }
        if self.original.source_tree_sha256 == self.patched.source_tree_sha256 {
            return (
                PatchDisposition::Proposal,
                "patch did not produce a different sealed source tree".into(),
            );
        }
        if self.patched.run_status != RunStatus::Completed {
            return (
                PatchDisposition::Proposal,
                "patched scan did not complete".into(),
            );
        }
        if self.repaired_scenarios.is_empty() {
            return (
                PatchDisposition::Proposal,
                "the observed broken scenario did not become passing under the same scenario identity"
                    .into(),
            );
        }
        let mut repaired_ids = BTreeSet::new();
        if self.repaired_scenarios.iter().any(|repair| {
            !repaired_ids.insert(repair.scenario_id.as_str())
                || !repair.original_verdict.is_fail()
                || !repair.patched_verdict.is_pass()
                || !self.replay_receipts.iter().any(|receipt| {
                    receipt.scenario_id == repair.scenario_id
                        && receipt.scenario_kind == repair.scenario_kind
                        && receipt.verdict == repair.patched_verdict
                })
        }) {
            return (
                PatchDisposition::Proposal,
                "repaired-scenario witness is incomplete or incoherent".into(),
            );
        }
        if self.replay_receipts.len() != self.patched.scenario_count {
            return (
                PatchDisposition::Proposal,
                "not every patched scenario has an exact replay receipt".into(),
            );
        }
        let has_baseline = self.replay_receipts.iter().any(|receipt| {
            receipt.scenario_kind == ScenarioKind::Baseline
                && receipt.verdict == Verdict::BaselinePass
        });
        let has_future = self.replay_receipts.iter().any(|receipt| {
            receipt.scenario_kind != ScenarioKind::Baseline
                && receipt.verdict == Verdict::FuturePass
        });
        if !has_baseline || !has_future {
            return (
                PatchDisposition::Proposal,
                "qualification requires a passing baseline and at least one passing future scenario"
                    .into(),
            );
        }
        if self.replay_receipts.iter().any(|receipt| {
            !receipt.verdict.is_pass()
                || receipt.outcome != PatchReplayOutcome::Passed
                || receipt.scenario_inventory_sha256.is_none()
                || receipt.exact_replay_manifest_sha256.is_none()
                || receipt.replay_attempt_path.is_none()
                || receipt.replay_attempt_inventory_sha256.is_none()
        }) {
            return (
                PatchDisposition::Proposal,
                "patched scan or exact replay was not successful for every scenario".into(),
            );
        }
        (
            PatchDisposition::Qualified,
            "the same observed broken scenario became passing; patched baseline and future scenarios passed and exact replayed from sealed evidence".into(),
        )
    }

    pub fn disposition_is_coherent(&self) -> bool {
        let (disposition, reason) = self.evaluate_disposition();
        self.schema_version == PATCH_PROOF_SCHEMA_VERSION
            && self.disposition == disposition
            && self.disposition_reason == reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n";

    #[test]
    fn accepts_strict_text_patch_and_binds_exact_bytes() {
        let patch = validate_unified_patch(GOOD.as_bytes(), 4096, 2).unwrap();
        assert_eq!(patch.changes.len(), 1);
        assert_eq!(patch.changes[0].kind, PatchChangeKind::Modify);
        assert!(patch.sha256.starts_with("sha256:"));
    }

    #[test]
    fn rejects_absolute_parent_and_protected_paths() {
        for path in [
            "../escape",
            "/escape",
            "C:/escape",
            ".git/config",
            ".tomorrowci/x",
            "COM\u{00b9}",
            "nested/lpt\u{00b2}.txt",
            "CONOUT$.log",
        ] {
            assert!(validate_patch_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_binary_symlink_submodule_and_rename_metadata() {
        for metadata in [
            "GIT binary patch",
            "new file mode 120000",
            "new file mode 160000",
            "rename from old",
        ] {
            let patch = GOOD.replace("--- a/src/lib.rs", &format!("{metadata}\n--- a/src/lib.rs"));
            assert!(matches!(
                validate_unified_patch(patch.as_bytes(), 4096, 2),
                Err(PatchValidationError::ForbiddenMetadata(_))
            ));
        }
    }

    #[test]
    fn rejects_size_cap_and_duplicate_target() {
        assert!(matches!(
            validate_unified_patch(GOOD.as_bytes(), 8, 2),
            Err(PatchValidationError::TooLarge { .. })
        ));
        let duplicate = format!("{GOOD}{GOOD}");
        assert!(matches!(
            validate_unified_patch(duplicate.as_bytes(), 8192, 2),
            Err(PatchValidationError::DuplicatePath(_))
        ));
    }

    #[test]
    fn add_and_delete_modes_are_part_of_the_patch_summary() {
        let added = b"diff --git a/bin/tool b/bin/tool\nnew file mode 100755\n--- /dev/null\n+++ b/bin/tool\n@@ -0,0 +1 @@\n+run\n";
        let patch = validate_unified_patch(added, 4096, 2).unwrap();
        assert_eq!(patch.changes[0].kind, PatchChangeKind::Add);
        assert_eq!(patch.changes[0].old_executable, None);
        assert_eq!(patch.changes[0].new_executable, Some(true));

        let deleted = b"diff --git a/bin/tool b/bin/tool\ndeleted file mode 100644\n--- a/bin/tool\n+++ /dev/null\n@@ -1 +0,0 @@\n-run\n";
        let patch = validate_unified_patch(deleted, 4096, 2).unwrap();
        assert_eq!(patch.changes[0].kind, PatchChangeKind::Delete);
        assert_eq!(patch.changes[0].old_executable, Some(false));
        assert_eq!(patch.changes[0].new_executable, None);
    }

    fn binding(run_id: &str, tree: &str) -> PatchSourceBinding {
        PatchSourceBinding {
            run_id: run_id.into(),
            run_inventory_sha256: format!("sha256:{:0>64}", run_id),
            source_manifest_sha256: format!("sha256:{:1>64}", run_id),
            source_tree_sha256: tree.into(),
            config_sha256: format!("sha256:{:2>64}", "config"),
            verdicts_sha256: format!("sha256:{:3>64}", run_id),
            run_status: RunStatus::Completed,
            scenario_count: 2,
        }
    }

    #[test]
    fn forged_qualified_disposition_is_not_coherent() {
        let patch = validate_unified_patch(GOOD.as_bytes(), 4096, 2).unwrap();
        let mut proof = PatchProof {
            schema_version: PATCH_PROOF_SCHEMA_VERSION,
            created_at: Utc::now(),
            original: binding("original", "sha256:original"),
            original_had_observed_breakage: true,
            patch,
            patched: binding("patched", "sha256:patched"),
            repaired_scenarios: vec![PatchScenarioRepair {
                scenario_id: "future".into(),
                scenario_kind: ScenarioKind::SingleAxis,
                original_verdict: Verdict::FutureFail,
                patched_verdict: Verdict::FuturePass,
            }],
            replay_receipts: vec![
                PatchReplayReceipt {
                    scenario_id: "baseline".into(),
                    scenario_kind: ScenarioKind::Baseline,
                    verdict: Verdict::BaselinePass,
                    scenario_inventory_sha256: Some("sha256:scenario-a".into()),
                    exact_replay_manifest_sha256: Some("sha256:manifest-a".into()),
                    replay_attempt_path: Some("replays/baseline/attempt-000001".into()),
                    replay_attempt_inventory_sha256: Some("sha256:attempt-a".into()),
                    outcome: PatchReplayOutcome::Passed,
                    detail: "passed".into(),
                },
                PatchReplayReceipt {
                    scenario_id: "future".into(),
                    scenario_kind: ScenarioKind::SingleAxis,
                    verdict: Verdict::FuturePass,
                    scenario_inventory_sha256: Some("sha256:scenario-b".into()),
                    exact_replay_manifest_sha256: Some("sha256:manifest-b".into()),
                    replay_attempt_path: Some("replays/future/attempt-000001".into()),
                    replay_attempt_inventory_sha256: Some("sha256:attempt-b".into()),
                    outcome: PatchReplayOutcome::Passed,
                    detail: "passed".into(),
                },
            ],
            original_unchanged: true,
            disposition: PatchDisposition::Proposal,
            disposition_reason: String::new(),
        };
        (proof.disposition, proof.disposition_reason) = proof.evaluate_disposition();
        assert!(proof.disposition_is_coherent());
        assert_eq!(proof.disposition, PatchDisposition::Qualified);

        // A self-resealed proof cannot retain QUALIFIED after its replay
        // outcome is mutated; the semantic verifier recomputes disposition.
        proof.replay_receipts[1].outcome = PatchReplayOutcome::Failed;
        assert!(!proof.disposition_is_coherent());
    }

    #[test]
    fn unrelated_successful_run_cannot_qualify_without_same_scenario_repair() {
        let patch = validate_unified_patch(GOOD.as_bytes(), 4096, 2).unwrap();
        let mut proof = PatchProof {
            schema_version: PATCH_PROOF_SCHEMA_VERSION,
            created_at: Utc::now(),
            original: binding("original", "sha256:original"),
            original_had_observed_breakage: true,
            patch,
            patched: binding("patched", "sha256:patched"),
            repaired_scenarios: Vec::new(),
            replay_receipts: vec![
                PatchReplayReceipt {
                    scenario_id: "baseline".into(),
                    scenario_kind: ScenarioKind::Baseline,
                    verdict: Verdict::BaselinePass,
                    scenario_inventory_sha256: Some("sha256:scenario-a".into()),
                    exact_replay_manifest_sha256: Some("sha256:manifest-a".into()),
                    replay_attempt_path: Some("replays/baseline/attempt-000001".into()),
                    replay_attempt_inventory_sha256: Some("sha256:attempt-a".into()),
                    outcome: PatchReplayOutcome::Passed,
                    detail: "passed".into(),
                },
                PatchReplayReceipt {
                    scenario_id: "unrelated-future".into(),
                    scenario_kind: ScenarioKind::SingleAxis,
                    verdict: Verdict::FuturePass,
                    scenario_inventory_sha256: Some("sha256:scenario-b".into()),
                    exact_replay_manifest_sha256: Some("sha256:manifest-b".into()),
                    replay_attempt_path: Some("replays/unrelated-future/attempt-000001".into()),
                    replay_attempt_inventory_sha256: Some("sha256:attempt-b".into()),
                    outcome: PatchReplayOutcome::Passed,
                    detail: "passed".into(),
                },
            ],
            original_unchanged: true,
            disposition: PatchDisposition::Proposal,
            disposition_reason: String::new(),
        };
        (proof.disposition, proof.disposition_reason) = proof.evaluate_disposition();
        assert_eq!(proof.disposition, PatchDisposition::Proposal);
        assert!(proof.disposition_reason.contains("same scenario identity"));
    }
}
