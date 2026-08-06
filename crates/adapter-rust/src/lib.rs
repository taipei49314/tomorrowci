//! Rust adapter (cargo only).

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
};

pub struct RustAdapter;

impl EcosystemAdapter for RustAdapter {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has = path_exists(repo, "Cargo.toml");
        DetectionResult {
            supported: has,
            detection: ProjectDetection {
                ecosystem: if has {
                    Ecosystem::Rust
                } else {
                    Ecosystem::Unknown
                },
                manifests: if has {
                    vec!["Cargo.toml".into()]
                } else {
                    vec![]
                },
                package_manager: "cargo".into(),
                confidence: if has { 0.95 } else { 0.0 },
                notes: vec![],
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        Ok(Baseline {
            runtime: if config.baseline.runtime == "auto" {
                "stable".into()
            } else {
                config.baseline.runtime.clone()
            },
            dependencies: config.baseline.dependencies.clone(),
            declared_by: "config/auto".into(),
        })
    }

    fn candidates(&self, _baseline: &Baseline, _config: &Config) -> Result<Vec<Candidate>> {
        Ok(vec![
            Candidate {
                id: "rust-beta".into(),
                axis: EnvironmentAxis::Runtime,
                label: "Rust beta toolchain".into(),
                version: "beta".into(),
                channel: "beta".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: "0001".into(),
            },
            Candidate {
                id: "rust-nightly".into(),
                axis: EnvironmentAxis::Runtime,
                label: "Rust nightly toolchain".into(),
                version: "nightly".into(),
                channel: "nightly".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: "0002".into(),
            },
        ])
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        Ok(EnvironmentSpec {
            image: format!("rust:{}", scenario.runtime),
            image_digest: None,
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: None,
            read_only_root: false,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec!["cargo".into(), "test".into()]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        Ok(vec![CommandSpec {
            argv,
            cwd: Some("/work".into()),
            network: false,
            phase: "test".into(),
        }])
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        let blob = format!("{}\n{}", result.stdout, result.stderr);
        let kind = if blob.contains("error[E") {
            "CompileError"
        } else {
            "TestFailure"
        };
        FailureSignature {
            kind: kind.into(),
            summary: blob
                .lines()
                .find(|l| l.contains("error"))
                .unwrap_or(kind)
                .chars()
                .take(200)
                .collect(),
            normalized_hash: tomorrowci_core::sha256_str(kind),
            primary_frame: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_cargo() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("Cargo.toml"), "[package]\nname=\"x\"\nversion=\"0.1.0\"\n").unwrap();
        assert!(RustAdapter.detect(d.path()).supported);
    }
}
