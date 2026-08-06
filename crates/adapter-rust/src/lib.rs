//! Rust adapter (cargo only). Supports stable/beta/nightly and pinned versions.

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
        // Prefer fixture/app crates; monorepos with workspace still supported.
        DetectionResult {
            supported: has,
            detection: ProjectDetection {
                ecosystem: if has {
                    Ecosystem::Rust
                } else {
                    Ecosystem::Unknown
                },
                manifests: if has {
                    let mut m = vec!["Cargo.toml".into()];
                    if path_exists(repo, "Cargo.lock") {
                        m.push("Cargo.lock".into());
                    }
                    m
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
        let runtime = if config.baseline.runtime == "auto" {
            "1.83".into() // concrete recent stable pin for reproducibility
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("rust:")
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
        // Ordered concrete toolchains. Include an older MSRV pin for break fixtures.
        let versions = ["1.74", "beta", "nightly"];
        let mut out = Vec::new();
        for (i, v) in versions.iter().enumerate() {
            if out.len() >= max {
                break;
            }
            if *v == baseline.runtime.as_str() {
                continue;
            }
            out.push(Candidate {
                id: format!("rust-{}", v.replace('.', "")),
                axis: EnvironmentAxis::Runtime,
                label: format!("Rust {v} toolchain"),
                version: (*v).into(),
                channel: if v.chars().next().unwrap().is_ascii_digit() {
                    "stable".into()
                } else {
                    (*v).into()
                },
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{i:04}"),
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("rust:");
        let image = if tag.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            format!("rust:{tag}-bookworm")
        } else {
            format!("rust:{tag}-bookworm")
        };
        Ok(EnvironmentSpec {
            image,
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
            vec!["cargo".into(), "test".into(), "--".into(), "--nocapture".into()]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        let argv = if config.project.test_command == "auto" {
            vec!["cargo".into(), "test".into()]
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
        let kind = if blob.contains("error[E") {
            "CompileError"
        } else if blob.contains("package.rust-version") || blob.contains("rust-version") {
            "MsrvError"
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
        std::fs::write(
            d.path().join("Cargo.toml"),
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        assert!(RustAdapter.detect(d.path()).supported);
    }

    #[test]
    fn candidates_respect_max_zero() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.max_versions = 0;
        let b = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "t".into(),
        };
        assert!(RustAdapter.candidates(&b, &cfg).unwrap().is_empty());
    }
}
