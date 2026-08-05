//! Fixture expectation contracts — what “correct behavior” means.

use serde::{Deserialize, Serialize};
use tomorrowci_core::Verdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureExpectation {
    pub id: String,
    pub path: String,
    pub description: String,
    /// Requires container engine; otherwise claims are BLOCKED not FAIL.
    #[serde(default = "default_true")]
    pub require_engine: bool,
    /// Expected baseline scenario verdict (if a baseline scenario exists).
    pub expect_baseline: Option<ExpectedVerdict>,
    /// Whether an observed breakage horizon is required.
    #[serde(default)]
    pub expect_horizon: bool,
    /// Whether horizon must be absent.
    #[serde(default)]
    pub expect_no_horizon: bool,
    /// Substring that horizon label should contain (when expect_horizon).
    pub horizon_contains: Option<String>,
    /// At least one scenario must have this verdict.
    pub expect_any_verdict: Option<ExpectedVerdict>,
    /// Failure signature summary substring (when a FUTURE_FAIL is expected).
    pub signature_contains: Option<String>,
    /// Minimum scenario count (excluding pure detect/sandbox blockers).
    #[serde(default)]
    pub min_scenarios: usize,
    /// Optional config relative to fixture root.
    pub config: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpectedVerdict {
    BaselinePass,
    BaselineInvalid,
    FuturePass,
    FutureFail,
    Flaky,
    Blocked,
    Unsupported,
    Inconclusive,
}

impl ExpectedVerdict {
    pub fn matches(self, v: Verdict) -> bool {
        matches!(
            (self, v),
            (ExpectedVerdict::BaselinePass, Verdict::BaselinePass)
                | (ExpectedVerdict::BaselineInvalid, Verdict::BaselineInvalid)
                | (ExpectedVerdict::FuturePass, Verdict::FuturePass)
                | (ExpectedVerdict::FutureFail, Verdict::FutureFail)
                | (ExpectedVerdict::Flaky, Verdict::Flaky)
                | (ExpectedVerdict::Blocked, Verdict::Blocked)
                | (ExpectedVerdict::Unsupported, Verdict::Unsupported)
                | (ExpectedVerdict::Inconclusive, Verdict::Inconclusive)
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            ExpectedVerdict::BaselinePass => "BASELINE_PASS",
            ExpectedVerdict::BaselineInvalid => "BASELINE_INVALID",
            ExpectedVerdict::FuturePass => "FUTURE_PASS",
            ExpectedVerdict::FutureFail => "FUTURE_FAIL",
            ExpectedVerdict::Flaky => "FLAKY",
            ExpectedVerdict::Blocked => "BLOCKED",
            ExpectedVerdict::Unsupported => "UNSUPPORTED",
            ExpectedVerdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

fn default_true() -> bool {
    true
}

/// Built-in catalog for v0.1 fixtures (north-star measurement set).
pub fn default_catalog() -> Vec<FixtureExpectation> {
    vec![
        FixtureExpectation {
            id: "python-runtime-break".into(),
            path: "fixtures/python-runtime-break".into(),
            description: "Runtime axis: 3.9 pass, 3.10+ ImportError MutableMapping".into(),
            require_engine: true,
            expect_baseline: Some(ExpectedVerdict::BaselinePass),
            expect_horizon: true,
            expect_no_horizon: false,
            horizon_contains: Some("3.10".into()),
            expect_any_verdict: Some(ExpectedVerdict::FutureFail),
            signature_contains: Some("MutableMapping".into()),
            min_scenarios: 2,
            config: Some(".tomorrowci.yml".into()),
        },
        FixtureExpectation {
            id: "baseline-fail".into(),
            path: "fixtures/baseline-fail".into(),
            description: "Invalid baseline must not authorize horizon".into(),
            require_engine: true,
            expect_baseline: Some(ExpectedVerdict::BaselineInvalid),
            expect_horizon: false,
            expect_no_horizon: true,
            horizon_contains: None,
            expect_any_verdict: None,
            signature_contains: None,
            min_scenarios: 1,
            config: None,
        },
        FixtureExpectation {
            id: "flaky-project".into(),
            path: "fixtures/flaky-project".into(),
            description: "Reruns produce FLAKY not FUTURE_FAIL".into(),
            require_engine: true,
            expect_baseline: None, // flaky baseline or future
            expect_horizon: false,
            expect_no_horizon: true,
            horizon_contains: None,
            expect_any_verdict: Some(ExpectedVerdict::Flaky),
            signature_contains: None,
            min_scenarios: 1,
            config: None,
        },
        FixtureExpectation {
            id: "python-dependency-break".into(),
            path: "fixtures/python-dependency-break".into(),
            description: "Dependency axis SIMULATED: locked pass, latest_allowed fails".into(),
            require_engine: true,
            expect_baseline: Some(ExpectedVerdict::BaselinePass),
            expect_horizon: true,
            expect_no_horizon: false,
            horizon_contains: Some("latest".into()),
            expect_any_verdict: Some(ExpectedVerdict::FutureFail),
            signature_contains: Some("legacycompat".into()),
            min_scenarios: 2,
            config: Some(".tomorrowci.yml".into()),
        },
        FixtureExpectation {
            id: "node-dependency-break".into(),
            path: "fixtures/node-dependency-break".into(),
            description: "Node locked pass; latest_allowed SIMULATED dep break".into(),
            require_engine: true,
            expect_baseline: Some(ExpectedVerdict::BaselinePass),
            expect_horizon: true,
            expect_no_horizon: false,
            horizon_contains: Some("latest".into()),
            expect_any_verdict: Some(ExpectedVerdict::FutureFail),
            signature_contains: Some("dependency".into()),
            min_scenarios: 2,
            config: Some(".tomorrowci.yml".into()),
        },
        FixtureExpectation {
            id: "rust-msrv-break".into(),
            path: "fixtures/rust-msrv-break".into(),
            description: "Rust 1.83 pass; 1.85+ fails ceiling gate (observed horizon)".into(),
            require_engine: true,
            expect_baseline: Some(ExpectedVerdict::BaselinePass),
            expect_horizon: true,
            expect_no_horizon: false,
            horizon_contains: Some("1.85".into()),
            expect_any_verdict: Some(ExpectedVerdict::FutureFail),
            signature_contains: Some("toolchain break".into()),
            min_scenarios: 2,
            config: Some(".tomorrowci.yml".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_six_fixtures() {
        assert_eq!(default_catalog().len(), 6);
    }

    #[test]
    fn expected_verdict_match() {
        assert!(ExpectedVerdict::FutureFail.matches(Verdict::FutureFail));
        assert!(!ExpectedVerdict::FutureFail.matches(Verdict::Flaky));
    }
}
