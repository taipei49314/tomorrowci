//! Minimal external-adapter example.
//!
//! This crate deliberately lives outside the built-in adapter crates and uses
//! only the public SDK. It models an alternate Rust project convention because
//! adapter API v1 has a closed `Ecosystem` schema (Python, Node, and Rust).

use std::path::Path;
use tomorrowci_adapters::{
    AdapterContract, AdapterError, DetectionResult, EcosystemAdapter, Result,
};
use tomorrowci_core::signature::normalize_failure;
use tomorrowci_core::{
    Baseline, Candidate, CommandPhase, CommandSpec, Config, DependencyMode, Ecosystem,
    EnvironmentSpec, EvidenceGrade, FailureSignature, IndexMap, NetworkMode, ProjectDetection,
    RawExecutionResult, Scenario,
};

pub struct ExampleAdapter;

impl EcosystemAdapter for ExampleAdapter {
    fn contract(&self) -> AdapterContract {
        AdapterContract::v1()
    }

    fn name(&self) -> &'static str {
        "example-rust"
    }

    fn detect(&self, repository: &Path) -> Result<DetectionResult> {
        let supported =
            repository.join("example.toml").is_file() && repository.join("Cargo.toml").is_file();
        Ok(DetectionResult {
            detection: ProjectDetection {
                ecosystem: Ecosystem::Rust,
                package_manager: "cargo".into(),
                manifests: if supported {
                    vec!["Cargo.toml".into(), "example.toml".into()]
                } else {
                    vec![]
                },
                confidence: if supported { 0.99 } else { 0.0 },
                notes: vec!["SDK example: example.toml opts into this adapter".into()],
                supported,
                unsupported_reason: (!supported)
                    .then(|| "example.toml and Cargo.toml are required".into()),
            },
        })
    }

    fn baseline(&self, _repository: &Path, config: &Config) -> Result<Baseline> {
        let version = if config.baseline.runtime == "auto" {
            "1.75".to_owned()
        } else {
            config.baseline.runtime.clone()
        };
        Ok(Baseline {
            ecosystem: Ecosystem::Rust,
            runtime_label: format!("Rust {version}"),
            runtime_version: version.clone(),
            dependency_mode: DependencyMode::Locked,
            image_ref: format!("rust:{version}-bookworm"),
            notes: vec!["example adapter baseline".into()],
        })
    }

    fn candidates(&self, baseline: &Baseline, _config: &Config) -> Result<Vec<Candidate>> {
        Ok(vec![Candidate {
            id: "example-rust-stable".into(),
            axis: tomorrowci_core::EnvironmentAxis::Runtime,
            label: "Rust stable + locked dependencies".into(),
            runtime_version: Some("stable".into()),
            dependency_mode: DependencyMode::Locked,
            image_ref: "rust:bookworm".into(),
            channel: "stable".into(),
            order_key: format!("{}-stable", baseline.runtime_version),
            evidence_grade: EvidenceGrade::Observed,
            notes: vec![],
        }])
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        if scenario.image_ref.trim().is_empty() {
            return Err(AdapterError::Materialize("scenario image is empty".into()));
        }
        Ok(EnvironmentSpec {
            image_ref: scenario.image_ref.clone(),
            image_digest: None,
            workdir: "/workspace".into(),
            user: None,
            env: IndexMap::new(),
            mounts: vec![],
            network_mode: NetworkMode::FetchOnly,
            read_only_root: false,
            memory_mb: 2048,
            cpus: 1.0,
            pids_limit: 256,
            timeout_seconds: 600,
        })
    }

    fn commands(&self, _scenario: &Scenario, _config: &Config) -> Result<Vec<CommandSpec>> {
        Ok(vec![
            CommandSpec {
                phase: CommandPhase::Fetch,
                program: "cargo".into(),
                args: vec!["fetch".into(), "--locked".into()],
                workdir: "/workspace".into(),
                network_required: true,
                env: IndexMap::new(),
            },
            CommandSpec {
                phase: CommandPhase::Test,
                program: "cargo".into(),
                args: vec!["test".into(), "--locked".into()],
                workdir: "/workspace".into(),
                network_required: false,
                env: IndexMap::new(),
            },
        ])
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        normalize_failure(result, EvidenceGrade::Observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tomorrowci_adapters::conformance::{assert_adapter_conforms, AdapterFixture};

    #[test]
    fn external_example_passes_the_public_conformance_suite() {
        let fixture = AdapterFixture::new("external-example", "example-rust", Ecosystem::Rust)
            .file("example.toml", "contract = 1\n")
            .file(
                "Cargo.toml",
                "[package]\nname = \"external-example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            );
        let report = assert_adapter_conforms(&ExampleAdapter, &fixture).unwrap();
        assert_eq!(report.adapter, "example-rust");
    }

    #[test]
    fn contract_is_stable_json() {
        let json = serde_json::to_string(&ExampleAdapter.contract()).unwrap();
        let decoded: AdapterContract = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, AdapterContract::v1());
    }
}
