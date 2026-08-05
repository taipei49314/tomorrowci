//! Historical backtest domain (north-star M2 skeleton).
//!
//! Full historical package-index recreation is post-v0.1. This module defines
//! the typed request/result surface and commit sampling helpers that the CLI
//! and runner use without inventing unavailable historical environments.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestRequest {
    pub target: String,
    pub at: NaiveDate,
    pub until: NaiveDate,
    /// Cap how many commits/points we materialize (budget).
    pub max_commits: usize,
    pub max_scenarios_per_point: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestPoint {
    pub commit_sha: String,
    pub committed_at: Option<DateTime<Utc>>,
    pub run_id: Option<String>,
    pub frontier_observed: bool,
    pub horizon_label: Option<String>,
    pub status: BacktestPointStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BacktestPointStatus {
    Ok,
    Blocked,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestReport {
    pub request: BacktestRequest,
    pub points: Vec<BacktestPoint>,
    pub note: String,
}

impl BacktestReport {
    pub fn skeleton_note() -> &'static str {
        "Backtest v0.1 samples repository commits in [at, until] and runs TomorrowCI scan \
         on each disposable worktree. It does NOT recreate historical package indexes or \
         time-travel registries. Findings are OBSERVED only against current published \
         candidates applied to historical source trees. Full scientific backtesting is M2."
    }
}
