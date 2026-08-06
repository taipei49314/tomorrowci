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
        let yarn = path_exists(repo, "yarn.lock");
        let pnpm = path_exists(repo, "pnpm-lock.yaml");
        let mut notes = Vec::new();
        if yarn && !has_lock {
            notes.push(
                "yarn.lock without package-lock.json => yarn UNSUPPORTED in v0.1.".into(),
            );
        }
        if pnpm && !has_lock {
            notes.push(
                "pnpm-lock.yaml without package-lock.json => pnpm UNSUPPORTED in v0.1.".into(),
            );
        }
        // Supported when package.json exists and we are not forced onto yarn/pnpm-only.
        let supported = has_pkg && !(yarn && !has_lock) && !(pnpm && !has_lock);
        DetectionResult {
            supported,
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
                confidence: if supported { 0.9 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        let runtime = if config.baseline.runtime == "auto" {
            "20".into()
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("node:")
                .to_string()
        };
        Ok(Baseline {
            runtime,
            dependencies: if config.baseline.dependencies == "auto" {
                "locked".into()
            } else {
                config.baseline.dependencies.clone()
            },
            declared_by: "config/auto".into(),
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let max = config.candidates.runtime.max_versions as usize;
        if max == 0 {
            return Ok(vec![]);
        }
        // Concrete Node.js major tags available on Docker Hub.
        let versions = ["18", "22", "24"];
        let mut out = Vec::new();
        for (i, v) in versions.iter().enumerate() {
            if out.len() >= max {
                break;
            }
            if *v == baseline.runtime.as_str() {
                continue;
            }
            out.push(Candidate {
                id: format!("node{v}-locked"),
                axis: EnvironmentAxis::Runtime,
                label: format!("Node {v} + locked dependencies"),
                version: (*v).into(),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{i:04}"),
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("node:");
        Ok(EnvironmentSpec {
            image: format!("node:{tag}"),
            image_digest: None,
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: Some("node".into()),
            read_only_root: false, // npm needs write for node_modules
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec!["npm".into(), "test".into(), "--".into(), "--reporter".into(), "tap".into()]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        // Prefer plain `npm test` for broadest fixture compatibility
        let argv = if config.project.test_command == "auto" {
            vec!["npm".into(), "test".into()]
        } else {
            argv
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
        let kind = if blob.contains("ERR_REQUIRE_ESM") {
            "ErrRequireEsm"
        } else if blob.contains("Cannot find module") {
            "ModuleNotFound"
        } else if blob.contains("ERR!") {
            "NpmError"
        } else {
            "TestFailure"
        };
        FailureSignature {
            kind: kind.into(),
            summary: blob
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or(kind)
                .chars()
                .take(200)
                .collect(),
            normalized_hash: tomorrowci_core::sha256_str(&format!("{kind}")),
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
        assert!(NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_only_unsupported() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert!(!NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_unsupported_manager() {
        assert!(check_manager("yarn").is_err());
    }
}
