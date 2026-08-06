//! Node adapter (npm only in v0.1). yarn/pnpm => UNSUPPORTED.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
    TcError,
};

pub struct NodeAdapter;

impl EcosystemAdapter for NodeAdapter {
    fn name(&self) -> &'static str {
        "node"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has_pkg = path_exists(repo, "package.json");
        let has_lock = path_exists(repo, "package-lock.json");
        // yarn.lock / pnpm-lock without npm lock => unsupported manager detection note
        let yarn = path_exists(repo, "yarn.lock");
        let pnpm = path_exists(repo, "pnpm-lock.yaml");
        let mut notes = Vec::new();
        if yarn && !has_lock {
            notes.push("yarn.lock present without package-lock.json => yarn is UNSUPPORTED in v0.1.".into());
        }
        if pnpm && !has_lock {
            notes.push("pnpm-lock.yaml present without package-lock.json => pnpm is UNSUPPORTED in v0.1.".into());
        }
        DetectionResult {
            supported: has_pkg && (has_lock || (!yarn && !pnpm)),
            detection: ProjectDetection {
                ecosystem: if has_pkg {
                    Ecosystem::Node
                } else {
                    Ecosystem::Unknown
                },
                manifests: {
                    let mut m = Vec::new();
                    if has_pkg {
                        m.push("package.json".into());
                    }
                    if has_lock {
                        m.push("package-lock.json".into());
                    }
                    m
                },
                package_manager: "npm".into(),
                confidence: if has_pkg { 0.85 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        Ok(Baseline {
            runtime: if config.baseline.runtime == "auto" {
                "node:20".into()
            } else {
                config.baseline.runtime.clone()
            },
            dependencies: config.baseline.dependencies.clone(),
            declared_by: "config/auto".into(),
        })
    }

    fn candidates(&self, _baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let max = config.candidates.runtime.max_versions as usize;
        Ok(["22", "23", "24"]
            .iter()
            .take(max)
            .enumerate()
            .map(|(i, v)| Candidate {
                id: format!("node{v}-locked"),
                axis: EnvironmentAxis::Runtime,
                label: format!("Node {v} + locked dependencies"),
                version: (*v).into(),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{:04}", i),
            })
            .collect())
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        Ok(EnvironmentSpec {
            image: format!("node:{}", scenario.runtime.trim_start_matches("node:")),
            image_digest: None,
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: Some("node".into()),
            read_only_root: true,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec!["npm".into(), "test".into()]
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
        let kind = if blob.contains("ERR!") {
            "NpmError"
        } else {
            "TestFailure"
        };
        FailureSignature {
            kind: kind.into(),
            summary: blob.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(kind).chars().take(200).collect(),
            normalized_hash: tomorrowci_core::sha256_str(kind),
            primary_frame: None,
        }
    }
}

pub fn check_manager(manager: &str) -> Result<()> {
    if manager == "npm" {
        Ok(())
    } else {
        Err(TcError::Unsupported(format!(
            "Node package manager '{manager}' is UNSUPPORTED (v0.1 supports npm only)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_package_json() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert!(NodeAdapter.detect(d.path()).detection.ecosystem == Ecosystem::Node);
    }

    #[test]
    fn yarn_unsupported() {
        assert!(check_manager("yarn").is_err());
    }
}
