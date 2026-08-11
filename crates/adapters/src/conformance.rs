//! Shared adapter conformance suite and disposable fixture kit.

use crate::safety::{validate_commands, validate_environment};
use crate::{
    negotiate_adapter, AdapterContract, AdapterError, EcosystemAdapter, HostAdapterContract, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use tomorrowci_core::{
    Config, Ecosystem, EvidenceGrade, RawExecutionResult, Scenario, ScenarioId, ScenarioKind,
};

#[derive(Debug, Clone)]
pub struct AdapterFixture {
    pub name: String,
    pub expected_adapter: String,
    pub expected_ecosystem: Ecosystem,
    files: BTreeMap<PathBuf, Vec<u8>>,
}

impl AdapterFixture {
    pub fn new(
        name: impl Into<String>,
        expected_adapter: impl Into<String>,
        expected_ecosystem: Ecosystem,
    ) -> Self {
        Self {
            name: name.into(),
            expected_adapter: expected_adapter.into(),
            expected_ecosystem,
            files: BTreeMap::new(),
        }
    }

    /// Add a UTF-8 fixture file. Paths are checked when materialized.
    pub fn file(mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }

    pub fn materialize(&self) -> Result<MaterializedFixture> {
        if self.files.is_empty() {
            return Err(AdapterError::Conformance(format!(
                "fixture '{}' has no files",
                self.name
            )));
        }
        let directory = tempfile::tempdir().map_err(|error| {
            AdapterError::Conformance(format!("cannot create fixture directory: {error}"))
        })?;
        for (relative, contents) in &self.files {
            validate_fixture_path(relative)?;
            let target = directory.path().join(relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    AdapterError::Conformance(format!(
                        "cannot create fixture path '{}': {error}",
                        relative.display()
                    ))
                })?;
            }
            std::fs::write(&target, contents).map_err(|error| {
                AdapterError::Conformance(format!(
                    "cannot write fixture file '{}': {error}",
                    relative.display()
                ))
            })?;
        }
        Ok(MaterializedFixture { directory })
    }
}

#[derive(Debug)]
pub struct MaterializedFixture {
    directory: TempDir,
}

impl MaterializedFixture {
    pub fn path(&self) -> &Path {
        self.directory.path()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub fixture: String,
    pub adapter: String,
    pub checks: Vec<String>,
}

/// Run the same full contract, lifecycle, schema-shape, and safety checks used
/// for TomorrowCI's built-in adapters.
pub fn assert_adapter_conforms(
    adapter: &dyn EcosystemAdapter,
    fixture: &AdapterFixture,
) -> Result<ConformanceReport> {
    let materialized = fixture.materialize()?;
    let repository = materialized.path();
    let mut checks = Vec::new();

    validate_adapter_name(adapter.name())?;
    if adapter.name() != fixture.expected_adapter {
        return Err(AdapterError::Conformance(format!(
            "fixture '{}' expected adapter '{}', got '{}'",
            fixture.name,
            fixture.expected_adapter,
            adapter.name()
        )));
    }
    checks.push("adapter-name".into());

    negotiate_adapter(adapter, &HostAdapterContract::strict_v1())?;
    let serialized = serde_json::to_string(&adapter.contract()).map_err(|error| {
        AdapterError::Conformance(format!("cannot serialize adapter contract: {error}"))
    })?;
    let round_trip: AdapterContract = serde_json::from_str(&serialized).map_err(|error| {
        AdapterError::Conformance(format!("cannot deserialize adapter contract: {error}"))
    })?;
    if adapter.contract() != round_trip {
        return Err(AdapterError::Conformance(
            "adapter contract changed during schema round trip".into(),
        ));
    }
    checks.push("contract-negotiation-and-schema".into());

    let detection = adapter.detect(repository)?;
    if !detection.detection.supported {
        return Err(AdapterError::Conformance(format!(
            "fixture '{}' was reported unsupported: {}",
            fixture.name,
            detection
                .detection
                .unsupported_reason
                .as_deref()
                .unwrap_or("no reason")
        )));
    }
    if detection.detection.ecosystem != fixture.expected_ecosystem {
        return Err(AdapterError::Conformance(format!(
            "fixture '{}' expected ecosystem {}, got {}",
            fixture.name, fixture.expected_ecosystem, detection.detection.ecosystem
        )));
    }
    if !(0.0..=1.0).contains(&detection.detection.confidence)
        || detection.detection.confidence <= 0.5
    {
        return Err(AdapterError::Conformance(format!(
            "supported fixture '{}' has invalid confidence {}",
            fixture.name, detection.detection.confidence
        )));
    }
    for manifest in &detection.detection.manifests {
        validate_fixture_path(Path::new(manifest))?;
        if !repository.join(manifest).is_file() {
            return Err(AdapterError::Conformance(format!(
                "adapter reported missing manifest '{manifest}'"
            )));
        }
    }
    checks.push("detection".into());

    let config = Config::default();
    let baseline = adapter.baseline(repository, &config)?;
    if baseline.ecosystem != detection.detection.ecosystem {
        return Err(AdapterError::Conformance(
            "baseline ecosystem does not match detection".into(),
        ));
    }
    require_nonempty("baseline runtime version", &baseline.runtime_version)?;
    require_nonempty("baseline image", &baseline.image_ref)?;
    checks.push("baseline".into());

    let candidates = adapter.candidates(&baseline, &config)?;
    let mut candidate_ids = BTreeSet::new();
    for candidate in &candidates {
        require_nonempty("candidate id", &candidate.id)?;
        require_nonempty("candidate image", &candidate.image_ref)?;
        require_nonempty("candidate order key", &candidate.order_key)?;
        if !candidate_ids.insert(&candidate.id) {
            return Err(AdapterError::Conformance(format!(
                "duplicate candidate id '{}'",
                candidate.id
            )));
        }
    }
    checks.push("candidate-planning".into());

    let scenario = Scenario {
        id: ScenarioId::new("adapter-conformance-baseline"),
        kind: ScenarioKind::Baseline,
        ecosystem: baseline.ecosystem,
        label: format!("{} conformance baseline", adapter.name()),
        runtime_version: baseline.runtime_version.clone(),
        dependency_mode: baseline.dependency_mode,
        image_ref: baseline.image_ref,
        axes_changed: vec![],
        evidence_grade: EvidenceGrade::Observed,
        is_baseline: true,
        selection_reason: "adapter SDK conformance fixture".into(),
    };
    let environment = adapter.materialize(&scenario, repository)?;
    validate_environment(&environment)?;
    checks.push("sandbox-materialization-safety".into());

    let commands = adapter.commands_in_workspace(&scenario, &config, repository)?;
    validate_commands(&commands)?;
    for command in &commands {
        if command.workdir != "/workspace" {
            return Err(AdapterError::Conformance(format!(
                "command workdir must be /workspace, found '{}'",
                command.workdir
            )));
        }
        for value in command.args.iter().chain(command.env.values()) {
            if value.contains(repository.to_string_lossy().as_ref()) {
                return Err(AdapterError::Conformance(
                    "command leaked the host workspace path".into(),
                ));
            }
            if value.contains("registry-snapshot")
                && !value.starts_with("/workspace/")
                && !value.contains("=\"/workspace/")
            {
                return Err(AdapterError::Conformance(
                    "registry snapshot references must use /workspace/... container paths".into(),
                ));
            }
        }
    }
    checks.push("workspace-command-spec-safety".into());

    let signature = adapter.normalize_failure(&RawExecutionResult {
        exit_code: Some(1),
        signal: None,
        stdout: String::new(),
        stderr: "adapter conformance synthetic failure".into(),
        duration_ms: 1,
        timed_out: false,
        network_used: false,
        error: None,
    });
    require_nonempty("failure kind", &signature.kind)?;
    require_nonempty("failure summary", &signature.summary)?;
    require_nonempty("failure fingerprint", &signature.fingerprint)?;
    checks.push("failure-normalization".into());

    Ok(ConformanceReport {
        fixture: fixture.name.clone(),
        adapter: adapter.name().into(),
        checks,
    })
}

fn validate_adapter_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !valid {
        return Err(AdapterError::Conformance(format!(
            "adapter name '{name}' must be a lowercase ASCII slug"
        )));
    }
    Ok(())
}

fn validate_fixture_path(path: &Path) -> Result<()> {
    let portable = path.as_os_str().to_string_lossy();
    if path.as_os_str().is_empty() || path.is_absolute() || portable.contains('\\') {
        return Err(AdapterError::Conformance(format!(
            "fixture path '{}' must be non-empty and relative",
            path.display()
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AdapterError::Conformance(format!(
            "fixture path '{}' is not a confined portable path",
            path.display()
        )));
    }
    Ok(())
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(AdapterError::Conformance(format!("{label} is empty")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_kit_rejects_traversal() {
        let fixture =
            AdapterFixture::new("hostile", "rust", Ecosystem::Rust).file("../outside", "nope");
        assert!(fixture.materialize().is_err());

        let windows_separator =
            AdapterFixture::new("hostile", "rust", Ecosystem::Rust).file("nested\\outside", "nope");
        assert!(windows_separator.materialize().is_err());
    }

    #[test]
    fn fixture_kit_materializes_nested_files() {
        let fixture = AdapterFixture::new("nested", "rust", Ecosystem::Rust)
            .file("src/lib.rs", "pub fn value() -> u8 { 1 }");
        let materialized = fixture.materialize().unwrap();
        assert!(materialized.path().join("src/lib.rs").is_file());
    }
}
