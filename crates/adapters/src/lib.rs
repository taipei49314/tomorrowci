//! Versioned ecosystem-adapter SDK and registry.

pub mod conformance;
mod contract;
pub mod safety;

pub use contract::{
    negotiate_adapter, AdapterApiVersion, AdapterCapability, AdapterContract, HostAdapterContract,
    NegotiatedCapabilities, ADAPTER_CONTRACT_SCHEMA_VERSION, HOST_ADAPTER_API_VERSION,
};

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
    #[error("adapter contract rejected: {0}")]
    Contract(String),
    #[error("adapter output rejected: {0}")]
    Unsafe(String),
    #[error("adapter conformance failed: {0}")]
    Conformance(String),
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
    /// Declare the versioned, data-only contract implemented by this adapter.
    ///
    /// The default preserves compatibility for the three built-in adapters. New
    /// external adapters should override this method explicitly so a source
    /// review can see the contract they intend to implement.
    fn contract(&self) -> AdapterContract {
        AdapterContract::v1()
    }

    fn name(&self) -> &'static str;

    fn detect(&self, repo: &Path) -> Result<DetectionResult>;

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline>;

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>>;

    fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec>;

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>>;

    /// Produce commands with access to the already-materialized disposable
    /// workspace. The default preserves the v1 adapter API; built-in adapters
    /// use this hook to opt into a verified offline registry snapshot.
    fn commands_in_workspace(
        &self,
        scenario: &Scenario,
        config: &Config,
        _workspace: &Path,
    ) -> Result<Vec<CommandSpec>> {
        self.commands(scenario, config)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature;
}

/// Detect which adapter applies (first confident match).
pub fn detect_ecosystem(
    repo: &Path,
    adapters: &[&dyn EcosystemAdapter],
    forced: Option<&str>,
) -> Result<(usize, DetectionResult)> {
    // Validate the complete registry before calling any adapter hook. An
    // incompatible or unknown capability is a registry error, not a reason to
    // silently fall through to another adapter.
    let host = HostAdapterContract::strict_v1();
    for adapter in adapters {
        negotiate_adapter(*adapter, &host)?;
    }

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
