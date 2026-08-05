//! Rust adapter — package manager: **cargo**.
//!
//! Toolchain candidates: stable, beta, nightly, and configured MSRV.

use std::path::Path;
use tomorrowci_adapters::{AdapterError, DetectionResult, EcosystemAdapter, Result};
use tomorrowci_core::signature::normalize_failure;
use tomorrowci_core::{
    Baseline, Candidate, CommandPhase, CommandSpec, Config, DependencyMode, Ecosystem,
    EnvironmentAxis, EnvironmentSpec, EvidenceGrade, FailureSignature, IndexMap, NetworkMode,
    ProjectDetection, RawExecutionResult, Scenario, ScenarioId, ScenarioKind,
};

pub struct RustAdapter;

impl Default for RustAdapter {
    fn default() -> Self {
        Self
    }
}

impl RustAdapter {
    pub fn new() -> Self {
        Self
    }

    fn read_msrv(repo: &Path) -> Option<String> {
        let raw = std::fs::read_to_string(repo.join("Cargo.toml")).ok()?;
        let val: toml::Value = raw.parse().ok()?;
        val.get("package")
            .and_then(|p| p.get("rust-version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                // rust-toolchain.toml
                let t = std::fs::read_to_string(repo.join("rust-toolchain.toml")).ok()?;
                let v: toml::Value = t.parse().ok()?;
                v.get("toolchain")
                    .and_then(|t| t.get("channel"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string())
            })
    }
}

impl EcosystemAdapter for RustAdapter {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> Result<DetectionResult> {
        if !repo.join("Cargo.toml").exists() {
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Rust,
                    package_manager: "cargo".into(),
                    manifests: vec![],
                    confidence: 0.0,
                    notes: vec![],
                    supported: false,
                    unsupported_reason: Some("no Cargo.toml".into()),
                },
            });
        }
        let mut manifests = vec!["Cargo.toml".into()];
        if repo.join("Cargo.lock").exists() {
            manifests.push("Cargo.lock".into());
        }
        Ok(DetectionResult {
            detection: ProjectDetection {
                ecosystem: Ecosystem::Rust,
                package_manager: "cargo".into(),
                manifests,
                confidence: 0.95,
                notes: vec!["Rust package manager for v0.1: cargo".into()],
                supported: true,
                unsupported_reason: None,
            },
        })
    }

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline> {
        let ver = if config.baseline.runtime != "auto" {
            config.baseline.runtime.clone()
        } else {
            Self::read_msrv(repo).unwrap_or_else(|| "1.75".into())
        };
        // Use rust Docker images: rust:<version> or rust:latest-bookworm for stable
        let image = if ver == "stable" || ver == "beta" || ver == "nightly" {
            format!("rust:{ver}-bookworm")
        } else {
            format!("rust:{ver}-bookworm")
        };
        Ok(Baseline {
            ecosystem: Ecosystem::Rust,
            runtime_label: format!("Rust {ver}"),
            runtime_version: ver,
            dependency_mode: DependencyMode::Locked,
            image_ref: image,
            notes: vec!["baseline uses cargo test with existing lockfile when present".into()],
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let mut out = Vec::new();
        let channels = &config.candidates.runtime.channels;

        // Always consider newer stable toolchains relative to MSRV baseline
        if channels.iter().any(|c| c == "stable") {
            for (tag, order) in [("1.80", "1.80"), ("1.83", "1.83"), ("1.85", "1.85"), ("stable", "1.99")]
            {
                if tag != baseline.runtime_version.as_str()
                    && version_like_gt(tag, &baseline.runtime_version)
                {
                    out.push(Candidate {
                        id: format!("rust{}-locked", tag.replace('.', "")),
                        axis: EnvironmentAxis::Runtime,
                        label: format!("Rust {tag} + locked dependencies"),
                        runtime_version: Some(tag.into()),
                        dependency_mode: DependencyMode::Locked,
                        image_ref: format!("rust:{tag}-bookworm"),
                        channel: "stable".into(),
                        order_key: order.into(),
                        evidence_grade: EvidenceGrade::Observed,
                        notes: vec![],
                    });
                }
            }
        }

        if channels.iter().any(|c| c == "preview" || c == "beta") {
            out.push(Candidate {
                id: "rustbeta-locked".into(),
                axis: EnvironmentAxis::Runtime,
                label: "Rust beta + locked dependencies".into(),
                runtime_version: Some("beta".into()),
                dependency_mode: DependencyMode::Locked,
                image_ref: "rust:beta-bookworm".into(),
                channel: "beta".into(),
                order_key: "2.00-beta".into(),
                evidence_grade: EvidenceGrade::Observed,
                notes: vec![],
            });
        }

        if channels.iter().any(|c| c == "preview" || c == "nightly") {
            out.push(Candidate {
                id: "rustnightly-locked".into(),
                axis: EnvironmentAxis::Runtime,
                label: "Rust nightly + locked dependencies".into(),
                runtime_version: Some("nightly".into()),
                dependency_mode: DependencyMode::Locked,
                image_ref: "rust:nightly-bookworm".into(),
                channel: "nightly".into(),
                order_key: "2.01-nightly".into(),
                evidence_grade: EvidenceGrade::Observed,
                notes: vec![],
            });
        }

        // MSRV break candidate: intentionally older than declared if testing forward
        // For "future" we also include a scenario that uses edition-breaking newer flags via stable.

        if config.candidates.dependencies.latest_allowed {
            out.push(Candidate {
                id: format!("rust{}-latest", baseline.runtime_version.replace('.', "")),
                axis: EnvironmentAxis::Dependencies,
                label: format!(
                    "Rust {} + latest allowed dependencies",
                    baseline.runtime_version
                ),
                runtime_version: Some(baseline.runtime_version.clone()),
                dependency_mode: DependencyMode::LatestAllowed,
                image_ref: baseline.image_ref.clone(),
                channel: "stable".into(),
                order_key: format!("dep-{}", baseline.runtime_version),
                evidence_grade: EvidenceGrade::Simulated,
                notes: vec!["cargo update".into()],
            });
        }

        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        Ok(EnvironmentSpec {
            image_ref: if scenario.image_ref.is_empty() {
                format!("rust:{}-bookworm", scenario.runtime_version)
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
                    program: "cargo".into(),
                    args: vec!["fetch".into(), "--locked".into()],
                    workdir: "/workspace".into(),
                    network_required: true,
                    env: IndexMap::new(),
                });
            }
            DependencyMode::LatestAllowed | DependencyMode::PrereleaseAllowed => {
                cmds.push(CommandSpec {
                    phase: CommandPhase::Fetch,
                    program: "cargo".into(),
                    args: vec!["update".into()],
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
            match scenario.dependency_mode {
                DependencyMode::Locked => {
                    vec!["cargo".into(), "test".into(), "--locked".into()]
                }
                _ => vec!["cargo".into(), "test".into()],
            }
        };
        let (program, args) = test_parts.split_first().ok_or_else(|| {
            AdapterError::Other("empty test command".into())
        })?;
        cmds.push(CommandSpec {
            phase: CommandPhase::Test,
            program: program.clone(),
            args: args.to_vec(),
            workdir: "/workspace".into(),
            network_required: false,
            env: IndexMap::new(),
        });
        Ok(cmds)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        normalize_failure(result, EvidenceGrade::Observed)
    }
}

fn version_like_gt(a: &str, b: &str) -> bool {
    if a == "stable" || a == "beta" || a == "nightly" {
        return true;
    }
    if b == "stable" || b == "beta" || b == "nightly" {
        return false;
    }
    let pa = parse_ver(a);
    let pb = parse_ver(b);
    pa > pb
}

fn parse_ver(v: &str) -> (u32, u32) {
    let mut p = v.split('.');
    (
        p.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        p.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    )
}

pub fn baseline_scenario(b: &Baseline) -> Scenario {
    Scenario {
        id: ScenarioId::new("baseline"),
        kind: ScenarioKind::Baseline,
        ecosystem: Ecosystem::Rust,
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
    fn detects_cargo() {
        let d = tempdir().unwrap();
        fs::write(
            d.path().join("Cargo.toml"),
            r#"[package]
name = "x"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        let a = RustAdapter::new();
        assert!(a.detect(d.path()).unwrap().detection.supported);
    }
}
