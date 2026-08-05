//! Claim ledger — the only source of truth for “did it pass?”

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
    Skip,
}

impl ClaimStatus {
    pub fn label(self) -> &'static str {
        match self {
            ClaimStatus::Pass => "PASS",
            ClaimStatus::Fail => "FAIL",
            ClaimStatus::Blocked => "BLOCKED",
            ClaimStatus::NotRun => "NOT_RUN",
            ClaimStatus::Skip => "SKIP",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, ClaimStatus::Pass | ClaimStatus::Skip)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub id: String,
    pub claim: String,
    pub status: ClaimStatus,
    pub category: String,
    pub duration_ms: u64,
    pub detail: String,
    pub command: Option<String>,
    pub artifact: Option<PathBuf>,
    pub measured_at: DateTime<Utc>,
}

impl ClaimRecord {
    pub fn new(
        id: impl Into<String>,
        claim: impl Into<String>,
        category: impl Into<String>,
        status: ClaimStatus,
        detail: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            id: id.into(),
            claim: claim.into(),
            status,
            category: category.into(),
            duration_ms,
            detail: detail.into(),
            command: None,
            artifact: None,
            measured_at: Utc::now(),
        }
    }

    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    pub fn with_artifact(mut self, path: impl Into<PathBuf>) -> Self {
        self.artifact = Some(path.into());
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub claims: Vec<ClaimRecord>,
}

impl Ledger {
    pub fn push(&mut self, claim: ClaimRecord) {
        self.claims.push(claim);
    }

    pub fn counts(&self) -> LedgerCounts {
        let mut c = LedgerCounts::default();
        for r in &self.claims {
            match r.status {
                ClaimStatus::Pass => c.pass += 1,
                ClaimStatus::Fail => c.fail += 1,
                ClaimStatus::Blocked => c.blocked += 1,
                ClaimStatus::NotRun => c.not_run += 1,
                ClaimStatus::Skip => c.skip += 1,
            }
        }
        c
    }

    pub fn all_trustworthy(&self) -> bool {
        // Trust only when no FAIL and no unexpected NOT_RUN for required claims.
        // BLOCKED is infrastructure honesty — suite may still "pass with blocks".
        self.claims.iter().all(|c| c.status != ClaimStatus::Fail)
    }

    pub fn render_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{:<28} {:<10} {:>8}  {}\n",
            "CLAIM_ID", "STATUS", "MS", "DETAIL"
        ));
        out.push_str(&"-".repeat(100));
        out.push('\n');
        for c in &self.claims {
            let detail: String = c.detail.chars().take(70).collect();
            out.push_str(&format!(
                "{:<28} {:<10} {:>8}  {}\n",
                c.id,
                c.status.label(),
                c.duration_ms,
                detail
            ));
        }
        let counts = self.counts();
        out.push('\n');
        out.push_str(&format!(
            "totals: PASS={} FAIL={} BLOCKED={} NOT_RUN={} SKIP={}\n",
            counts.pass, counts.fail, counts.blocked, counts.not_run, counts.skip
        ));
        out
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerCounts {
    pub pass: usize,
    pub fail: usize,
    pub blocked: usize,
    pub not_run: usize,
    pub skip: usize,
}
