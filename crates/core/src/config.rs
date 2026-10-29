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
    #[serde(default = "default_policy")]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(default = "auto_str")]
    pub ecosystem: String,
    #[serde(default = "auto_str")]
    pub test_command: String,
    #[serde(default = "auto_str")]
    pub build_command: String,
    /// Opt in to installing into a pip-free venv using the pinned image's pip.
    /// Omission preserves historical config hashes and bootstrap behavior.
    #[serde(default, skip_serializing_if = "is_false")]
    pub python_image_pip: bool,
}

fn is_false(value: &bool) -> bool {
    !value
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
            python_image_pip: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CandidatesConfig {
    #[serde(default)]
    pub runtime: RuntimeCandidates,
    #[serde(default)]
    pub dependencies: DependencyCandidates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCandidates {
    #[serde(default = "default_channels")]
    pub channels: Vec<String>,
    #[serde(default = "default_max_versions")]
    pub max_versions: u32,
    /// Exact CPython minor versions, in ascending order. None retains the
    /// legacy catalogue; Some([]) deliberately disables runtime candidates.
    #[serde(
        default,
        deserialize_with = "deserialize_runtime_versions",
        skip_serializing_if = "Option::is_none"
    )]
    pub versions: Option<Vec<String>>,
}

fn deserialize_runtime_versions<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Do not coerce YAML numbers (3.10 can become 3.1) or null to a version list.
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| match value {
            serde_json::Value::String(version) => Ok(version),
            _ => Err(serde::de::Error::custom(
                "runtime versions must be quoted strings",
            )),
        })
        .collect::<std::result::Result<Vec<_>, D::Error>>()
        .map(Some)
}

/// Parse the explicit CPython minor-version syntax used to construct image tags.
/// Tags, suffixes, patch versions, whitespace and noncanonical numbers are rejected.
pub fn parse_explicit_python_version(version: &str) -> Option<(u32, u32)> {
    let minor = version.strip_prefix("3.")?;
    if minor.is_empty()
        || minor.len() > 3
        || !minor.bytes().all(|b| b.is_ascii_digit())
        || (minor.len() > 1 && minor.starts_with('0'))
    {
        return None;
    }
    Some((3, minor.parse().ok()?))
}

impl RuntimeCandidates {
    pub fn validate_explicit_versions(&self) -> Result<()> {
        let Some(versions) = &self.versions else {
            return Ok(());
        };
        if versions.len() > self.max_versions as usize {
            return Err(TcError::Config(
                "candidates.runtime.versions exceeds max_versions; explicit versions are never truncated".into(),
            ));
        }
        if !versions.is_empty() && !self.channels.iter().any(|channel| channel == "stable") {
            return Err(TcError::Config(
                "explicit Python runtime versions require the stable channel".into(),
            ));
        }
        let mut previous = None;
        for version in versions {
            let parsed = parse_explicit_python_version(version).ok_or_else(|| {
                TcError::Config(format!(
                    "invalid explicit Python runtime '{version}'; use a quoted canonical minor version such as \"3.14\" (3.0 through 3.999), without image prefixes or suffixes"
                ))
            })?;
            if previous.is_some_and(|value| parsed <= value) {
                return Err(TcError::Config(
                    "candidates.runtime.versions must be unique and in strictly increasing version order".into(),
                ));
            }
            previous = Some(parsed);
        }
        Ok(())
    }
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
            versions: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub fail_if: FailIfPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailIfPolicy {
    #[serde(default = "default_true")]
    pub baseline_invalid: bool,
    #[serde(default = "default_true")]
    pub new_future_failure: bool,
    #[serde(default = "default_true")]
    pub horizon_regression: bool,
    #[serde(default = "default_blocked_ratio")]
    pub blocked_ratio_above: Option<f64>,
}

fn default_blocked_ratio() -> Option<f64> {
    Some(0.5)
}

impl Default for FailIfPolicy {
    fn default() -> Self {
        Self {
            baseline_invalid: true,
            new_future_failure: true,
            horizon_regression: true,
            blocked_ratio_above: default_blocked_ratio(),
        }
    }
}

fn default_policy() -> Option<PolicyConfig> {
    Some(PolicyConfig {
        fail_if: FailIfPolicy::default(),
    })
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
            policy: default_policy(),
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
        if !matches!(
            self.project.ecosystem.as_str(),
            "auto" | "python" | "node" | "rust"
        ) {
            return Err(TcError::Config(
                "project.ecosystem must be auto|python|node|rust".into(),
            ));
        }
        if self.project.build_command != "auto" {
            return Err(TcError::Config(
                "project.build_command is not implemented; leave it as auto and put required checks in project.test_command".into(),
            ));
        }
        self.candidates.runtime.validate_explicit_versions()?;
        if self.project.python_image_pip && self.project.ecosystem != "python" {
            return Err(TcError::Config(
                "project.python_image_pip requires project.ecosystem: python".into(),
            ));
        }
        if let Some(versions) = &self.candidates.runtime.versions {
            if !matches!(self.project.ecosystem.as_str(), "auto" | "python") {
                return Err(TcError::Config(
                    "candidates.runtime.versions is currently supported only for Python".into(),
                ));
            }
            if versions.len() as u64 + 1 > u64::from(self.execution.max_scenarios) {
                return Err(TcError::Config(
                    "execution.max_scenarios must fit the baseline plus every explicit runtime version; explicit versions are never truncated".into(),
                ));
            }
        }
        if self.execution.max_scenarios == 0 {
            return Err(TcError::Config(
                "execution.max_scenarios must be >= 1".into(),
            ));
        }
        if self.execution.max_parallel == 0 {
            return Err(TcError::Config(
                "execution.max_parallel must be >= 1".into(),
            ));
        }
        if self.execution.timeout_seconds == 0 {
            return Err(TcError::Config(
                "execution.timeout_seconds must be >= 1".into(),
            ));
        }
        if self.execution.reruns_on_failure == 0 {
            return Err(TcError::Config(
                "execution.reruns_on_failure must be >= 1".into(),
            ));
        }
        let eng = self.sandbox.engine.as_str();
        if !matches!(eng, "auto" | "docker" | "podman") {
            return Err(TcError::Config(format!(
                "sandbox.engine must be auto|docker|podman, got {eng}"
            )));
        }
        if self.sandbox.network != "fetch-only" {
            return Err(TcError::Config(format!(
                "sandbox.network must be fetch-only, got {}",
                self.sandbox.network
            )));
        }
        if self.sandbox.memory_mb == 0
            || self.sandbox.pids_limit == 0
            || !self.sandbox.cpus.is_finite()
            || self.sandbox.cpus <= 0.0
        {
            return Err(TcError::Config(
                "sandbox memory_mb/cpus/pids_limit must be positive finite values".into(),
            ));
        }
        if let Some(threshold) = self
            .policy
            .as_ref()
            .and_then(|policy| policy.fail_if.blocked_ratio_above)
        {
            if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
                return Err(TcError::Config(
                    "policy.fail_if.blocked_ratio_above must be finite and between 0 and 1".into(),
                ));
            }
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
        let fail_if = &c.policy.as_ref().unwrap().fail_if;
        assert!(fail_if.baseline_invalid);
        assert!(fail_if.new_future_failure);
        assert!(fail_if.horizon_regression);
        assert_eq!(fail_if.blocked_ratio_above, Some(0.5));
    }

    #[test]
    fn image_pip_is_explicit_python_only_and_preserves_legacy_serialization() {
        let mut config = Config::default();
        let legacy = serde_json::to_value(&config).unwrap();
        assert_eq!(legacy["project"].as_object().unwrap().len(), 3);
        config.project.python_image_pip = true;
        assert!(config.validate().is_err());
        config.project.ecosystem = "python".into();
        config.validate().unwrap();
        let selected = serde_json::to_value(&config).unwrap();
        assert_eq!(selected["project"]["python_image_pip"], true);
        config.project.ecosystem = "node".into();
        assert!(config.validate().is_err());
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
    fn rejects_zero_timeout_reruns_and_non_fetch_only_network() {
        let mut config = Config::default();
        config.execution.timeout_seconds = 0;
        assert!(config.validate().is_err());
        config.execution.timeout_seconds = 1;
        config.execution.reruns_on_failure = 0;
        assert!(config.validate().is_err());
        config.execution.reruns_on_failure = 1;
        config.sandbox.network = "none".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_nested_key() {
        let raw = r#"
version: 1
execution:
  timeout_second: 30
"#;
        let error = Config::load_str(raw).unwrap_err().to_string();
        assert!(error.contains("timeout_second"), "{error}");
    }

    #[test]
    fn rejects_out_of_range_or_nonfinite_blocked_ratio() {
        let mut config = Config {
            policy: Some(PolicyConfig {
                fail_if: FailIfPolicy {
                    blocked_ratio_above: Some(1.01),
                    ..FailIfPolicy::default()
                },
            }),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.policy.as_mut().unwrap().fail_if.blocked_ratio_above = Some(f64::NAN);
        assert!(config.validate().is_err());
        config.policy.as_mut().unwrap().fail_if.blocked_ratio_above = Some(0.5);
        config.validate().unwrap();
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

    #[test]
    fn omitted_runtime_versions_preserve_legacy_serialization() {
        let config = Config::load_str("version: 1\n").unwrap();
        assert!(config.candidates.runtime.versions.is_none());
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(
            value["candidates"]["runtime"],
            serde_json::json!({
                "channels": ["stable", "preview"], "max_versions": 5
            })
        );
        let mut disabled = config.clone();
        disabled.candidates.runtime.versions = Some(vec![]);
        disabled.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&disabled).unwrap()["candidates"]["runtime"]["versions"],
            serde_json::json!([])
        );
        assert_ne!(
            config.content_hash().unwrap(),
            disabled.content_hash().unwrap()
        );
    }

    #[test]
    fn explicit_versions_are_quoted_and_canonical() {
        let raw = "version: 1\ncandidates:\n  runtime:\n    versions: [\"3.14\", \"3.15\"]\n";
        let config = Config::load_str(raw).unwrap();
        assert_eq!(
            config.candidates.runtime.versions.unwrap(),
            ["3.14", "3.15"]
        );
        for invalid in [
            "null",
            "3.14",
            "[3.14]",
            "[true]",
            "[\"3.014\"]",
            "[\"3.14-slim\"]",
            "[\"3.14.0\"]",
            "[\"3.14;id\"]",
            "[\"python:3.14\"]",
            "[\"3.14\\n\"]",
            "[\"4.0\"]",
            "[\"3.1000\"]",
        ] {
            let raw = format!("version: 1\ncandidates:\n  runtime:\n    versions: {invalid}\n");
            assert!(Config::load_str(&raw).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn explicit_versions_reject_duplicates_reverse_order_and_insufficient_budgets() {
        let mut config = Config::default();
        for versions in [
            vec!["3.14", "3.14"],
            vec!["3.15", "3.14"],
            vec!["3.10", "3.9"],
        ] {
            config.candidates.runtime.versions =
                Some(versions.into_iter().map(str::to_owned).collect());
            assert!(config.validate().is_err());
        }
        config.candidates.runtime.versions = Some(vec!["3.14".into(), "3.15".into()]);
        config.candidates.runtime.max_versions = 1;
        assert!(config.validate().is_err());
        config.candidates.runtime.max_versions = 2;
        config.execution.max_scenarios = 2;
        assert!(config.validate().is_err());
        config.execution.max_scenarios = 3;
        config.validate().unwrap();
        config.candidates.runtime.channels = vec!["preview".into()];
        assert!(config.validate().is_err());
        config.candidates.runtime.versions = Some(vec![]);
        config.candidates.runtime.max_versions = 0;
        config.execution.max_scenarios = 1;
        config.validate().unwrap();
    }

    #[test]
    fn explicit_versions_reject_non_python_ecosystems_and_unused_build_commands() {
        let mut config = Config::default();
        config.project.ecosystem = "pyhton".into();
        assert!(config.validate().is_err());
        config.candidates.runtime.versions = Some(vec!["3.14".into()]);
        for ecosystem in ["node", "rust"] {
            config.project.ecosystem = ecosystem.into();
            assert!(config.validate().is_err());
        }
        config.project.ecosystem = "python".into();
        config.validate().unwrap();
        config.project.build_command = "make build".into();
        assert!(config.validate().is_err());
    }
}
