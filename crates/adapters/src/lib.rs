//! Ecosystem adapter trait and registry.

use std::path::Path;
use thiserror::Error;
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, EnvironmentSpec, FailureSignature, ProjectDetection,
    RawExecutionResult, Scenario,
};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("detection failed: {0}")]
    Detection(String),
    #[error("materialize failed: {0}")]
    Materialize(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AdapterError>;

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detection: ProjectDetection,
}

/// Contract every ecosystem adapter must implement.
/// Adapters must not execute unrestricted host shell commands.
pub trait EcosystemAdapter: Send + Sync {
    fn name(&self) -> &'static str;

    fn detect(&self, repo: &Path) -> Result<DetectionResult>;

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline>;

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>>;

    fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec>;

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>>;

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature;
}

/// Detect which adapter applies (first confident match).
pub fn detect_ecosystem(
    repo: &Path,
    adapters: &[&dyn EcosystemAdapter],
    forced: Option<&str>,
) -> Result<(usize, DetectionResult)> {
    if let Some(name) = forced {
        if name != "auto" {
            for (i, a) in adapters.iter().enumerate() {
                if a.name() == name {
                    let d = a.detect(repo)?;
                    if !d.detection.supported {
                        return Err(AdapterError::Unsupported(
                            d.detection
                                .unsupported_reason
                                .unwrap_or_else(|| format!("{name} not supported here")),
                        ));
                    }
                    return Ok((i, d));
                }
            }
            return Err(AdapterError::Unsupported(format!(
                "unknown ecosystem '{name}'"
            )));
        }
    }

    let mut best: Option<(usize, DetectionResult)> = None;
    for (i, a) in adapters.iter().enumerate() {
        match a.detect(repo) {
            Ok(d) if d.detection.supported && d.detection.confidence > 0.5 => {
                if best
                    .as_ref()
                    .map(|(_, b)| d.detection.confidence > b.detection.confidence)
                    .unwrap_or(true)
                {
                    best = Some((i, d));
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    best.ok_or_else(|| {
        AdapterError::Unsupported(
            "no supported ecosystem detected (need pyproject.toml/requirements.txt, package.json, or Cargo.toml)"
                .into(),
        )
    })
}
