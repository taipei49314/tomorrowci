//! Claim-to-evidence ledger — every public claim maps to a measured status.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tomorrowci_core::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRow {
    pub claim: String,
    pub status: ClaimStatus,
    pub command: String,
    pub result: String,
    pub artifact: String,
    pub measured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaimLedger {
    pub rows: Vec<ClaimRow>,
}

impl ClaimLedger {
    pub fn push(
        &mut self,
        claim: impl Into<String>,
        status: ClaimStatus,
        command: impl Into<String>,
        result: impl Into<String>,
        artifact: impl Into<String>,
    ) {
        self.rows.push(ClaimRow {
            claim: claim.into(),
            status,
            command: command.into(),
            result: result.into(),
            artifact: artifact.into(),
            measured_at: Utc::now(),
        });
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn write_markdown(&self, path: &Path) -> Result<()> {
        let mut md = String::from("# Claim-to-evidence ledger\n\n");
        md.push_str("| Claim | Status | Command | Result | Artifact |\n");
        md.push_str("|---|---|---|---|---|\n");
        for r in &self.rows {
            md.push_str(&format!(
                "| {} | {:?} | `{}` | {} | {} |\n",
                r.claim,
                r.status,
                r.command.replace('|', "\\|"),
                r.result.replace('|', "\\|"),
                r.artifact
            ));
        }
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, md)?;
        Ok(())
    }

    pub fn all_pass_or_blocked_ok(&self) -> bool {
        !self.rows.iter().any(|r| r.status == ClaimStatus::Fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ledger_roundtrip() {
        let mut l = ClaimLedger::default();
        l.push("unit tests", ClaimStatus::Pass, "cargo test", "ok", "-");
        let d = tempdir().unwrap();
        let p = d.path().join("claims.json");
        l.write_json(&p).unwrap();
        assert!(p.exists());
    }
}
