//! Versioned `.tomorrowci.yml` config + validation.

use crate::error::{Result, TcError};
use crate::hash::canonical_json_hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

const KNOWN_TOP_LEVEL: &[&str] = &[
    "version",
    "project",
    "baseline",
    "candidates",
    "execution",
    "sandbox",
    "report",
    "policy",
    "x-", // extension namespace prefix handled separately
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub candidates: CandidatesConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default = "auto_str")]
    pub ecosystem: String,
    #[serde(default = "auto_str")]
    pub test_command: String,
    #[serde(default = "auto_str")]
    pub build_command: String,
}

fn auto_str() -> String {
    "auto".into()
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            ecosystem: auto_str(),
            test_command: auto_str(),
            build_command: auto_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    #[serde(default = "auto_str")]
    pub runtime: String,
    #[serde(default = "locked_str")]
    pub dependencies: String,
}

fn locked_str() -> String {
    "locked".into()
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            runtime: auto_str(),
            dependencies: locked_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatesConfig {
    #[serde(default)]
    pub runtime: RuntimeCandidates,
    #[serde(default)]
    pub dependencies: DependencyCandidates,
}

impl Default for CandidatesConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeCandidates::default(),
            dependencies: DependencyCandidates::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeCandidates {
    #[serde(default = "default_channels")]
    pub channels: Vec<String>,
    #[serde(default = "default_max_versions")]
    pub max_versions: u32,
}

fn default_channels() -> Vec<String> {
    vec!["stable".into(), "preview".into()]
}

fn default_max_versions() -> u32 {
    5
}

impl Default for RuntimeCandidates {
    fn default() -> Self {
        Self {
            channels: default_channels(),
            max_versions: default_max_versions(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCandidates {
    #[serde(default = "default_true")]
    pub latest_allowed: bool,
    #[serde(default)]
    pub prerelease: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DependencyCandidates {
    fn default() -> Self {
        Self {
            latest_allowed: true,
            prerelease: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_max_scenarios")]
    pub max_scenarios: u32,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_reruns")]
    pub reruns_on_failure: u32,
    #[serde(default = "default_parallel")]
    pub max_parallel: u32,
}

fn default_max_scenarios() -> u32 {
    24
}
fn default_timeout() -> u64 {
    900
}
fn default_reruns() -> u32 {
    2
}
fn default_parallel() -> u32 {
    2
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_scenarios: default_max_scenarios(),
            timeout_seconds: default_timeout(),
            reruns_on_failure: default_reruns(),
            max_parallel: default_parallel(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "auto_str")]
    pub engine: String,
    #[serde(default = "fetch_only")]
    pub network: String,
    #[serde(default = "default_mem")]
    pub memory_mb: u32,
    #[serde(default = "default_cpus")]
    pub cpus: f32,
    #[serde(default = "default_pids")]
    pub pids_limit: u32,
}

fn fetch_only() -> String {
    "fetch-only".into()
}
fn default_mem() -> u32 {
    4096
}
fn default_cpus() -> f32 {
    2.0
}
fn default_pids() -> u32 {
    512
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            engine: auto_str(),
            network: fetch_only(),
            memory_mb: default_mem(),
            cpus: default_cpus(),
            pids_limit: default_pids(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_true")]
    pub html: bool,
    #[serde(default = "default_true")]
    pub json: bool,
    #[serde(default)]
    pub sarif: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            html: true,
            json: true,
            sarif: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub fail_if: FailIfPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FailIfPolicy {
    #[serde(default)]
    pub baseline_invalid: bool,
    #[serde(default)]
    pub new_future_failure: bool,
    #[serde(default)]
    pub horizon_regression: bool,
    #[serde(default)]
    pub blocked_ratio_above: Option<f64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            project: ProjectConfig::default(),
            baseline: BaselineConfig::default(),
            candidates: CandidatesConfig::default(),
            execution: ExecutionConfig::default(),
            sandbox: SandboxConfig::default(),
            report: ReportConfig::default(),
            policy: None,
        }
    }
}

impl Config {
    pub fn load_str(raw: &str) -> Result<Self> {
        reject_unknown_top_level(raw)?;
        let cfg: Config = serde_yaml::from_str(raw).map_err(|e| TcError::Yaml(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Self::load_str(&raw)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(TcError::Config(format!(
                "unsupported config version {}; only version 1 is supported",
                self.version
            )));
        }
        if self.execution.max_scenarios == 0 {
            return Err(TcError::Config(
                "execution.max_scenarios must be >= 1".into(),
            ));
        }
        if self.execution.max_parallel == 0 {
            return Err(TcError::Config("execution.max_parallel must be >= 1".into()));
        }
        let eng = self.sandbox.engine.as_str();
        if !matches!(eng, "auto" | "docker" | "podman") {
            return Err(TcError::Config(format!(
                "sandbox.engine must be auto|docker|podman, got {eng}"
            )));
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<String> {
        canonical_json_hash(self).map_err(|e| TcError::Other(e.to_string()))
    }
}

fn reject_unknown_top_level(raw: &str) -> Result<()> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| TcError::Yaml(e.to_string()))?;
    let Some(map) = value.as_mapping() else {
        return Err(TcError::Config("config root must be a mapping".into()));
    };
    let known: BTreeSet<&str> = KNOWN_TOP_LEVEL
        .iter()
        .copied()
        .filter(|k| *k != "x-")
        .collect();
    for key in map.keys() {
        let Some(k) = key.as_str() else {
            return Err(TcError::Config("config keys must be strings".into()));
        };
        if k.starts_with("x-") || k.starts_with("x_") {
            continue; // forward-compatible extension namespace
        }
        if !known.contains(k) {
            return Err(TcError::Config(format!(
                "unknown top-level key '{k}'; known keys: version, project, baseline, candidates, execution, sandbox, report, policy (or x-* extensions)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_valid() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.content_hash().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn rejects_unknown_key() {
        let raw = r#"
version: 1
foobar: true
"#;
        let err = Config::load_str(raw).unwrap_err().to_string();
        assert!(err.contains("unknown top-level key"), "{err}");
    }

    #[test]
    fn allows_extension_namespace() {
        let raw = r#"
version: 1
x-experimental:
  foo: 1
"#;
        Config::load_str(raw).unwrap();
    }
}
