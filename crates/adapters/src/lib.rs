//! Ecosystem adapter contract. Adapters must not run unrestricted host shell.

use std::path::Path;
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, EnvironmentSpec, FailureSignature, ProjectDetection,
    RawExecutionResult, Result, Scenario, TcError,
};

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detection: ProjectDetection,
    pub supported: bool,
}

pub trait EcosystemAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, repo: &Path) -> DetectionResult;
    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline>;
    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>>;
    fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec>;
    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>>;
    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature;
}

/// Return UNSUPPORTED rather than guessing unsafe package managers.
pub fn unsupported_manager(manager: &str) -> TcError {
    TcError::Unsupported(format!(
        "package manager '{manager}' is not supported in v0.1; returning UNSUPPORTED"
    ))
}

pub fn path_exists(repo: &Path, name: &str) -> bool {
    repo.join(name).exists()
}
