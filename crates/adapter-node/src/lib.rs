//! Node.js adapter — package manager: **npm** only.
//!
//! Yarn/pnpm lockfiles without package-lock.json → UNSUPPORTED.

use std::path::Path;
use tomorrowci_adapters::{AdapterError, DetectionResult, EcosystemAdapter, Result};
use tomorrowci_core::signature::normalize_failure;
use tomorrowci_core::{
    Baseline, Candidate, CommandPhase, CommandSpec, Config, DependencyMode, Ecosystem,
    EnvironmentAxis, EnvironmentSpec, EvidenceGrade, FailureSignature, IndexMap, NetworkMode,
    ProjectDetection, RawExecutionResult, Scenario, ScenarioId, ScenarioKind,
};

pub const NODE_STABLE_MAJORS: &[&str] = &["18", "20", "22", "24"];

pub struct NodeAdapter;

impl Default for NodeAdapter {
    fn default() -> Self {
        Self
    }
}

impl NodeAdapter {
    pub fn new() -> Self {
        Self
    }

    fn read_engines_node(repo: &Path) -> Option<String> {
        let raw = std::fs::read_to_string(repo.join("package.json")).ok()?;
        let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
        v.get("engines")
            .and_then(|e| e.get("node"))
            .and_then(|n| n.as_str())
            .map(|s| {
                // Extract first major digit sequence
                let digits: String = s.chars().filter(|c| c.is_ascii_digit()).take(2).collect();
                if digits.is_empty() {
                    "20".into()
                } else {
                    digits
                }
            })
    }
}

impl EcosystemAdapter for NodeAdapter {
    fn name(&self) -> &'static str {
        "node"
    }

    fn detect(&self, repo: &Path) -> Result<DetectionResult> {
        if !repo.join("package.json").exists() {
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Node,
                    package_manager: "npm".into(),
                    manifests: vec![],
                    confidence: 0.0,
                    notes: vec![],
                    supported: false,
                    unsupported_reason: Some("no package.json".into()),
                },
            });
        }

        let has_npm_lock = repo.join("package-lock.json").exists();
        let has_yarn = repo.join("yarn.lock").exists();
        let has_pnpm = repo.join("pnpm-lock.yaml").exists();

        if !has_npm_lock && (has_yarn || has_pnpm) {
            let pm = if has_yarn { "yarn" } else { "pnpm" };
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Node,
                    package_manager: pm.into(),
                    manifests: vec!["package.json".into()],
                    confidence: 0.9,
                    notes: vec![format!(
                        "{pm} is UNSUPPORTED in v0.1; npm + package-lock.json required"
                    )],
                    supported: false,
                    unsupported_reason: Some(format!(
                        "{pm} is unsupported; commit package-lock.json and use npm"
                    )),
                },
            });
        }

        let mut manifests = vec!["package.json".into()];
        if has_npm_lock {
            manifests.push("package-lock.json".into());
        }

        Ok(DetectionResult {
            detection: ProjectDetection {
                ecosystem: Ecosystem::Node,
                package_manager: "npm".into(),
                manifests,
                confidence: 0.95,
                notes: vec!["Node package manager for v0.1: npm".into()],
                supported: true,
                unsupported_reason: None,
            },
        })
    }

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline> {
        let ver = if config.baseline.runtime != "auto" {
            config.baseline.runtime.clone()
        } else {
            Self::read_engines_node(repo).unwrap_or_else(|| "20".into())
        };
        Ok(Baseline {
            ecosystem: Ecosystem::Node,
            runtime_label: format!("Node.js {ver}"),
            runtime_version: ver.clone(),
            dependency_mode: DependencyMode::Locked,
            image_ref: format!("node:{ver}-bookworm"),
            notes: vec!["baseline uses npm ci when package-lock.json present".into()],
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let mut out = Vec::new();
        let base: u32 = baseline.runtime_version.parse().unwrap_or(20);

        if config
            .candidates
            .runtime
            .channels
            .iter()
            .any(|c| c == "stable")
        {
            for ver in NODE_STABLE_MAJORS {
                let v: u32 = ver.parse().unwrap_or(0);
                if v > base {
                    out.push(Candidate {
                        id: format!("node{ver}-locked"),
                        axis: EnvironmentAxis::Runtime,
                        label: format!("Node.js {ver} + locked dependencies"),
                        runtime_version: Some((*ver).into()),
                        dependency_mode: DependencyMode::Locked,
                        image_ref: format!("node:{ver}-bookworm"),
                        channel: "stable".into(),
                        order_key: format!("{ver:0>2}"),
                        evidence_grade: EvidenceGrade::Observed,
                        notes: vec![],
                    });
                }
            }
        }

        if config.candidates.dependencies.latest_allowed {
            out.push(Candidate {
                id: format!("node{}-latest", baseline.runtime_version),
                axis: EnvironmentAxis::Dependencies,
                label: format!(
                    "Node.js {} + latest allowed dependencies",
                    baseline.runtime_version
                ),
                runtime_version: Some(baseline.runtime_version.clone()),
                dependency_mode: DependencyMode::LatestAllowed,
                image_ref: baseline.image_ref.clone(),
                channel: "stable".into(),
                order_key: format!("dep-{}", baseline.runtime_version),
                evidence_grade: EvidenceGrade::Simulated,
                notes: vec!["npm update within package.json ranges".into()],
            });
        }

        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        Ok(EnvironmentSpec {
            image_ref: if scenario.image_ref.is_empty() {
                format!("node:{}-bookworm", scenario.runtime_version)
            } else {
                scenario.image_ref.clone()
            },
            image_digest: None,
            workdir: "/workspace".into(),
            user: None,
            env: IndexMap::new(),
            mounts: vec![],
            network_mode: NetworkMode::FetchOnly,
            read_only_root: false,
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            timeout_seconds: 900,
        })
    }

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let mut cmds = Vec::new();
        match scenario.dependency_mode {
            DependencyMode::Locked => {
                cmds.push(CommandSpec {
                    phase: CommandPhase::Fetch,
                    program: "npm".into(),
                    args: vec!["ci".into()],
                    workdir: "/workspace".into(),
                    network_required: true,
                    env: IndexMap::new(),
                });
            }
            DependencyMode::LatestAllowed => {
                cmds.push(CommandSpec {
                    phase: CommandPhase::Fetch,
                    program: "npm".into(),
                    args: vec!["install".into()],
                    workdir: "/workspace".into(),
                    network_required: true,
                    env: IndexMap::new(),
                });
                cmds.push(CommandSpec {
                    phase: CommandPhase::Fetch,
                    program: "npm".into(),
                    args: vec!["update".into()],
                    workdir: "/workspace".into(),
                    network_required: true,
                    env: IndexMap::new(),
                });
            }
            DependencyMode::PrereleaseAllowed => {
                cmds.push(CommandSpec {
                    phase: CommandPhase::Fetch,
                    program: "npm".into(),
                    args: vec!["install".into(), "--include=dev".into()],
                    workdir: "/workspace".into(),
                    network_required: true,
                    env: IndexMap::new(),
                });
            }
        }

        if config.project.build_command != "auto" {
            let parts: Vec<_> = config
                .project
                .build_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if let Some((p, a)) = parts.split_first() {
                cmds.push(CommandSpec {
                    phase: CommandPhase::Build,
                    program: p.clone(),
                    args: a.to_vec(),
                    workdir: "/workspace".into(),
                    network_required: false,
                    env: IndexMap::new(),
                });
            }
        }

        let test_parts: Vec<String> = if config.project.test_command != "auto" {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        } else {
            vec![
                "npm".into(),
                "test".into(),
                "--".into(),
                "--watch=false".into(),
            ]
        };
        let (program, args) = test_parts
            .split_first()
            .ok_or_else(|| AdapterError::Other("empty test command".into()))?;
        let mut test_env = IndexMap::new();
        test_env.insert(
            "TOMORROWCI_DEP_MODE".into(),
            match scenario.dependency_mode {
                DependencyMode::Locked => "locked".into(),
                DependencyMode::LatestAllowed => "latest_allowed".into(),
                DependencyMode::PrereleaseAllowed => "prerelease".into(),
            },
        );
        cmds.push(CommandSpec {
            phase: CommandPhase::Test,
            program: program.clone(),
            args: args.to_vec(),
            workdir: "/workspace".into(),
            network_required: false,
            env: test_env,
        });
        Ok(cmds)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        normalize_failure(result, EvidenceGrade::Observed)
    }
}

pub fn baseline_scenario(b: &Baseline) -> Scenario {
    Scenario {
        id: ScenarioId::new("baseline"),
        kind: ScenarioKind::Baseline,
        ecosystem: Ecosystem::Node,
        label: format!("{} + locked dependencies", b.runtime_label),
        runtime_version: b.runtime_version.clone(),
        dependency_mode: DependencyMode::Locked,
        image_ref: b.image_ref.clone(),
        axes_changed: vec![],
        evidence_grade: EvidenceGrade::Observed,
        is_baseline: true,
        selection_reason: "repository baseline".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn yarn_only_unsupported() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        fs::write(d.path().join("yarn.lock"), "").unwrap();
        let a = NodeAdapter::new();
        let det = a.detect(d.path()).unwrap();
        assert!(!det.detection.supported);
    }

    #[test]
    fn npm_lock_supported() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        fs::write(
            d.path().join("package-lock.json"),
            r#"{"lockfileVersion":3}"#,
        )
        .unwrap();
        let a = NodeAdapter::new();
        assert!(a.detect(d.path()).unwrap().detection.supported);
    }
}
