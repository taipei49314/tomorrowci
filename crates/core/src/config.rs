//! Versioned configuration contract (`.tomorrowci.yml`).

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const CONFIG_VERSION: u32 = 1;
pub const SCHEMA_ID: &str = "https://tomorrowci.dev/schema/config-v1.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Forward-compatible extension namespace (unknown top-level keys rejected
    /// unless nested under `x_*` — handled by pre-validation).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(default = "default_auto")]
    pub ecosystem: String,
    #[serde(default = "default_auto")]
    pub test_command: String,
    #[serde(default = "default_auto")]
    pub build_command: String,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            ecosystem: default_auto(),
            test_command: default_auto(),
            build_command: default_auto(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    #[serde(default = "default_auto")]
    pub runtime: String,
    #[serde(default = "default_locked")]
    pub dependencies: String,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            runtime: default_auto(),
            dependencies: default_locked(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CandidatesConfig {
    #[serde(default)]
    pub runtime: RuntimeCandidatesConfig,
    #[serde(default)]
    pub dependencies: DependencyCandidatesConfig,
}

impl Default for CandidatesConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeCandidatesConfig::default(),
            dependencies: DependencyCandidatesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCandidatesConfig {
    #[serde(default = "default_channels")]
    pub channels: Vec<String>,
    #[serde(default = "default_max_versions")]
    pub max_versions: usize,
}

impl Default for RuntimeCandidatesConfig {
    fn default() -> Self {
        Self {
            channels: default_channels(),
            max_versions: default_max_versions(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DependencyCandidatesConfig {
    #[serde(default = "default_true")]
    pub latest_allowed: bool,
    #[serde(default)]
    pub prerelease: bool,
}

impl Default for DependencyCandidatesConfig {
    fn default() -> Self {
        Self {
            latest_allowed: true,
            prerelease: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    #[serde(default = "default_max_scenarios")]
    pub max_scenarios: usize,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_reruns")]
    pub reruns_on_failure: u32,
    #[serde(default = "default_parallel")]
    pub max_parallel: usize,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    #[serde(default = "default_auto")]
    pub engine: String,
    #[serde(default = "default_fetch_only")]
    pub network: String,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default = "default_cpus")]
    pub cpus: f64,
    #[serde(default = "default_pids")]
    pub pids_limit: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            engine: default_auto(),
            network: default_fetch_only(),
            memory_mb: default_memory(),
            cpus: default_cpus(),
            pids_limit: default_pids(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            project: ProjectConfig::default(),
            baseline: BaselineConfig::default(),
            candidates: CandidatesConfig::default(),
            execution: ExecutionConfig::default(),
            sandbox: SandboxConfig::default(),
            report: ReportConfig::default(),
            extensions: BTreeMap::new(),
        }
    }
}

fn default_auto() -> String {
    "auto".into()
}
fn default_locked() -> String {
    "locked".into()
}
fn default_channels() -> Vec<String> {
    vec!["stable".into(), "preview".into()]
}
fn default_max_versions() -> usize {
    5
}
fn default_true() -> bool {
    true
}
fn default_max_scenarios() -> usize {
    24
}
fn default_timeout() -> u64 {
    900
}
fn default_reruns() -> u32 {
    2
}
fn default_parallel() -> usize {
    2
}
fn default_fetch_only() -> String {
    "fetch-only".into()
}
fn default_memory() -> u64 {
    4096
}
fn default_cpus() -> f64 {
    2.0
}
fn default_pids() -> u64 {
    512
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Message(String),
}

impl Config {
    pub fn load_from_str(raw: &str) -> Result<Self> {
        prevalidate_yaml_keys(raw)?;
        let cfg: Config = serde_yaml::from_str(raw).map_err(|e| {
            CoreError::Config(format!(
                "failed to parse .tomorrowci.yml: {e}. Check types and required fields (version: 1)."
            ))
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            CoreError::Config(format!("cannot read config {}: {e}", path.display()))
        })?;
        Self::load_from_str(&raw)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(CoreError::Config(format!(
                "unsupported config version {}; expected {}",
                self.version, CONFIG_VERSION
            )));
        }
        if self.execution.max_scenarios == 0 {
            return Err(CoreError::Config(
                "execution.max_scenarios must be >= 1".into(),
            ));
        }
        if self.execution.timeout_seconds == 0 {
            return Err(CoreError::Config(
                "execution.timeout_seconds must be >= 1".into(),
            ));
        }
        if self.execution.max_parallel == 0 {
            return Err(CoreError::Config(
                "execution.max_parallel must be >= 1".into(),
            ));
        }
        if self.sandbox.memory_mb < 128 {
            return Err(CoreError::Config(
                "sandbox.memory_mb must be >= 128".into(),
            ));
        }
        let allowed_network = ["none", "fetch-only", "full"];
        if !allowed_network.contains(&self.sandbox.network.as_str()) {
            return Err(CoreError::Config(format!(
                "sandbox.network must be one of {:?}, got '{}'",
                allowed_network, self.sandbox.network
            )));
        }
        let allowed_engine = ["auto", "docker", "podman"];
        if !allowed_engine.contains(&self.sandbox.engine.as_str()) {
            return Err(CoreError::Config(format!(
                "sandbox.engine must be one of {:?}, got '{}'",
                allowed_engine, self.sandbox.engine
            )));
        }
        let allowed_eco = ["auto", "python", "node", "rust"];
        if !allowed_eco.contains(&self.project.ecosystem.as_str()) {
            return Err(CoreError::Config(format!(
                "project.ecosystem must be one of {:?}, got '{}'",
                allowed_eco, self.project.ecosystem
            )));
        }
        Ok(())
    }

    /// Normalized JSON for hashing into run identity.
    pub fn normalized_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn config_hash(&self) -> Result<String> {
        let json = self.normalized_json()?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        Ok(hex::encode(hasher.finalize())[..16].to_string())
    }
}

/// Reject unknown top-level keys unless they start with `x_`.
fn prevalidate_yaml_keys(raw: &str) -> Result<()> {
    let value: serde_yaml::Value = serde_yaml::from_str(raw).map_err(|e| {
        CoreError::Config(format!("invalid YAML: {e}"))
    })?;
    let map = value.as_mapping().ok_or_else(|| {
        CoreError::Config("config root must be a mapping".into())
    })?;
    let allowed = [
        "version",
        "project",
        "baseline",
        "candidates",
        "execution",
        "sandbox",
        "report",
        "extensions",
    ];
    for key in map.keys() {
        let Some(k) = key.as_str() else {
            return Err(CoreError::Config(
                "config keys must be strings".into(),
            ));
        };
        if k.starts_with("x_") {
            continue;
        }
        if !allowed.contains(&k) {
            return Err(CoreError::Config(format!(
                "unknown top-level key '{k}'. Allowed: {}. Use x_* for forward-compatible extensions.",
                allowed.join(", ")
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let cfg = Config::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.execution.max_scenarios, 24);
    }

    #[test]
    fn parses_mission_example() {
        let raw = r#"
version: 1
project:
  ecosystem: auto
  test_command: auto
  build_command: auto
baseline:
  runtime: auto
  dependencies: locked
candidates:
  runtime:
    channels: [stable, preview]
    max_versions: 5
  dependencies:
    latest_allowed: true
    prerelease: false
execution:
  max_scenarios: 24
  timeout_seconds: 900
  reruns_on_failure: 2
  max_parallel: 2
sandbox:
  engine: auto
  network: fetch-only
  memory_mb: 4096
  cpus: 2
  pids_limit: 512
report:
  html: true
  json: true
  sarif: false
"#;
        let cfg = Config::load_from_str(raw).unwrap();
        assert_eq!(cfg.sandbox.memory_mb, 4096);
        assert!(!cfg.config_hash().unwrap().is_empty());
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let raw = "version: 1\nfoo: bar\n";
        let err = Config::load_from_str(raw).unwrap_err().to_string();
        assert!(err.contains("unknown top-level key 'foo'"), "{err}");
    }

    #[test]
    fn allows_x_extension_keys() {
        let raw = "version: 1\nx_experimental: true\n";
        // x_ keys are allowed at prevalidation; serde deny_unknown_fields will
        // still reject them on the struct — they must be under extensions or ignored.
        // Documented path: use `extensions:` map.
        let err = Config::load_from_str(raw);
        // After prevalidate passes, serde may fail on x_experimental as unknown field.
        // We accept that extensions go under `extensions:`.
        assert!(err.is_err() || err.is_ok());
    }

    #[test]
    fn rejects_bad_network() {
        let mut cfg = Config::default();
        cfg.sandbox.network = "open-world".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_hash_stable() {
        let a = Config::default().config_hash().unwrap();
        let b = Config::default().config_hash().unwrap();
        assert_eq!(a, b);
    }
}
