//! Python adapter — detection + baseline stubs for M0; full runtime slice in M1.

use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
    TcError,
};
use indexmap::IndexMap;

pub struct PythonAdapter;

impl EcosystemAdapter for PythonAdapter {
    fn name(&self) -> &'static str {
        "python"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has_pyproject = path_exists(repo, "pyproject.toml");
        let has_req = path_exists(repo, "requirements.txt");
        let supported = has_pyproject || has_req;
        let mut manifests = Vec::new();
        if has_pyproject {
            manifests.push("pyproject.toml".into());
        }
        if has_req {
            manifests.push("requirements.txt".into());
        }
        DetectionResult {
            supported,
            detection: ProjectDetection {
                ecosystem: if supported {
                    Ecosystem::Python
                } else {
                    Ecosystem::Unknown
                },
                manifests,
                package_manager: "pip".into(), // v0.1 default; uv optional later
                confidence: if supported { 0.9 } else { 0.0 },
                notes: if supported {
                    vec!["Python project detected; package manager: pip (v0.1).".into()]
                } else {
                    vec!["No pyproject.toml or requirements.txt.".into()]
                },
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        let runtime = if config.baseline.runtime == "auto" {
            "3.9".into()
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("python:")
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
        // Concrete published CPython slim tags — never invent versions.
        let max = config.candidates.runtime.max_versions as usize;
        let mut out = Vec::new();
        let versions = ["3.10", "3.11", "3.12"];
        for (i, v) in versions.iter().take(max).enumerate() {
            if *v == baseline.runtime.as_str() {
                continue;
            }
            out.push(Candidate {
                id: format!("py{}-locked", v.replace('.', "")),
                axis: EnvironmentAxis::Runtime,
                label: format!("Python {v} + locked dependencies"),
                version: (*v).into(),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{:04}", i + 1),
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        Ok(EnvironmentSpec {
            image: format!("python:{}", scenario.runtime.trim_start_matches("python:")),
            image_digest: None, // resolved at execution time in M1
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: Some("65534:65534".into()),
            read_only_root: true,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let test = if config.project.test_command == "auto" {
            vec!["python".into(), "-m".into(), "pytest".into(), "-q".into()]
        } else {
            // shell-less: split on whitespace for M0
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        Ok(vec![CommandSpec {
            argv: test,
            cwd: Some("/work".into()),
            network: false,
            phase: "test".into(),
        }])
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        let blob = format!("{}\n{}", result.stdout, result.stderr);
        let kind = if blob.contains("ImportError") {
            "ImportError"
        } else if blob.contains("SyntaxError") {
            "SyntaxError"
        } else if result.timed_out {
            "Timeout"
        } else {
            "TestFailure"
        };
        let summary = blob
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or(kind)
            .chars()
            .take(200)
            .collect::<String>();
        let normalized_hash = tomorrowci_core::sha256_str(&format!("{kind}:{summary}"));
        FailureSignature {
            kind: kind.into(),
            summary,
            normalized_hash,
            primary_frame: None,
        }
    }
}

/// Explicit: poetry/pipenv not supported in v0.1.
pub fn check_manager_supported(manager: &str) -> Result<()> {
    match manager {
        "pip" | "uv" => Ok(()),
        other => Err(TcError::Unsupported(format!(
            "Python package manager '{other}' is UNSUPPORTED in v0.1 (supported: pip, uv)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_requirements() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let det = PythonAdapter.detect(d.path());
        assert!(det.supported);
        assert_eq!(det.detection.ecosystem, Ecosystem::Python);
    }

    #[test]
    fn poetry_unsupported() {
        assert!(check_manager_supported("poetry").is_err());
    }
}
