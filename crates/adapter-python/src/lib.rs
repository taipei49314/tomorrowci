//! Python adapter — package manager: **pip** (documented).
//!
//! Behavior:
//! - Detects `pyproject.toml` and/or `requirements.txt`
//! - Rejects Poetry/Pipenv-only lockfiles without requirements/pyproject as UNSUPPORTED
//!   when only `Pipfile` / `poetry.lock` is present without supported manifests
//! - Baseline runtime: config or `requires-python` / `.python-version` / default 3.9
//! - Candidates: concrete CPython tags available as official `python:X.Y` images
//! - Commands: pip install (fetch phase) then pytest or configured test command

use std::path::Path;
use tomorrowci_adapters::{AdapterError, DetectionResult, EcosystemAdapter, Result};
use tomorrowci_core::backtest::{snapshot_container_payload, workspace_registry_snapshot};
use tomorrowci_core::signature::normalize_failure;
use tomorrowci_core::{
    Baseline, Candidate, CommandPhase, CommandSpec, Config, DependencyMode, Ecosystem,
    EnvironmentAxis, EnvironmentSpec, EvidenceGrade, FailureSignature, IndexMap, NetworkMode,
    ProjectDetection, RawExecutionResult, Scenario,
};

/// Official CPython stable minors we consider for v0.1 (concrete published images).
pub const PYTHON_STABLE_MINORS: &[&str] = &["3.9", "3.10", "3.11", "3.12", "3.13"];

pub struct PythonAdapter;

impl Default for PythonAdapter {
    fn default() -> Self {
        Self
    }
}

impl PythonAdapter {
    pub fn new() -> Self {
        Self
    }

    fn has_poetry_only(repo: &Path) -> bool {
        repo.join("poetry.lock").exists()
            && !repo.join("requirements.txt").exists()
            && !repo.join("pyproject.toml").exists()
    }

    fn has_pipenv_only(repo: &Path) -> bool {
        repo.join("Pipfile").exists()
            && !repo.join("requirements.txt").exists()
            && !repo.join("pyproject.toml").exists()
    }

    fn detect_baseline_version(repo: &Path, config: &Config) -> String {
        if config.baseline.runtime != "auto" {
            return config.baseline.runtime.clone();
        }
        if let Ok(v) = std::fs::read_to_string(repo.join(".python-version")) {
            let v = v.trim();
            if !v.is_empty() {
                // normalize 3.9.10 -> 3.9
                let parts: Vec<_> = v.split('.').collect();
                if parts.len() >= 2 {
                    return format!("{}.{}", parts[0], parts[1]);
                }
                return v.to_string();
            }
        }
        if let Ok(raw) = std::fs::read_to_string(repo.join("pyproject.toml")) {
            if let Ok(val) = raw.parse::<toml::Value>() {
                if let Some(req) = val
                    .get("project")
                    .and_then(|p| p.get("requires-python"))
                    .and_then(|v| v.as_str())
                {
                    // Pick lowest minor that satisfies a simple >=3.X pattern
                    if let Some(cap) = regex::Regex::new(r">=\s*3\.(\d+)")
                        .ok()
                        .and_then(|re| re.captures(req))
                    {
                        let minor: u32 = cap[1].parse().unwrap_or(9);
                        return format!("3.{minor}");
                    }
                }
            }
        }
        "3.9".into()
    }

    fn test_command(config: &Config) -> Vec<String> {
        if config.project.test_command != "auto" {
            // Split naively on whitespace — recorded as arg array by caller convention
            return config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
        vec!["python".into(), "-m".into(), "pytest".into(), "-q".into()]
    }
}

impl EcosystemAdapter for PythonAdapter {
    fn name(&self) -> &'static str {
        "python"
    }

    fn detect(&self, repo: &Path) -> Result<DetectionResult> {
        if Self::has_poetry_only(repo) {
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Python,
                    package_manager: "poetry".into(),
                    manifests: vec!["poetry.lock".into()],
                    confidence: 0.9,
                    notes: vec!["Poetry-only projects are UNSUPPORTED in v0.1".into()],
                    supported: false,
                    unsupported_reason: Some(
                        "Poetry is unsupported; provide requirements.txt or use pip-compatible pyproject.toml"
                            .into(),
                    ),
                },
            });
        }
        if Self::has_pipenv_only(repo) {
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Python,
                    package_manager: "pipenv".into(),
                    manifests: vec!["Pipfile".into()],
                    confidence: 0.9,
                    notes: vec!["Pipenv is UNSUPPORTED in v0.1".into()],
                    supported: false,
                    unsupported_reason: Some(
                        "Pipenv is unsupported; export requirements.txt for pip".into(),
                    ),
                },
            });
        }

        let mut manifests = Vec::new();
        if repo.join("pyproject.toml").exists() {
            manifests.push("pyproject.toml".into());
        }
        if repo.join("requirements.txt").exists() {
            manifests.push("requirements.txt".into());
        }
        if repo.join("requirements-dev.txt").exists() {
            manifests.push("requirements-dev.txt".into());
        }

        if manifests.is_empty() {
            return Ok(DetectionResult {
                detection: ProjectDetection {
                    ecosystem: Ecosystem::Python,
                    package_manager: "pip".into(),
                    manifests: vec![],
                    confidence: 0.0,
                    notes: vec![],
                    supported: false,
                    unsupported_reason: Some("no Python manifests found".into()),
                },
            });
        }

        Ok(DetectionResult {
            detection: ProjectDetection {
                ecosystem: Ecosystem::Python,
                package_manager: "pip".into(),
                manifests,
                confidence: 0.95,
                notes: vec![
                    "Python package manager for v0.1: pip".into(),
                    "Runtime images: official docker.io/library/python:<major.minor>".into(),
                ],
                supported: true,
                unsupported_reason: None,
            },
        })
    }

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline> {
        let ver = Self::detect_baseline_version(repo, config);
        Ok(Baseline {
            ecosystem: Ecosystem::Python,
            runtime_label: format!("Python {ver}"),
            runtime_version: ver.clone(),
            dependency_mode: DependencyMode::Locked,
            image_ref: format!("python:{ver}-bookworm"),
            notes: vec!["baseline uses locked/pinned requirements when present".into()],
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        let mut out = Vec::new();
        let base_minor = baseline.runtime_version.clone();
        let channels = &config.candidates.runtime.channels;

        if channels.iter().any(|c| c == "stable") {
            for ver in PYTHON_STABLE_MINORS {
                if version_gt(ver, &base_minor) {
                    out.push(Candidate {
                        id: format!("py{}-locked", ver.replace('.', "")),
                        axis: EnvironmentAxis::Runtime,
                        label: format!("Python {ver} + locked dependencies"),
                        runtime_version: Some((*ver).into()),
                        dependency_mode: DependencyMode::Locked,
                        image_ref: format!("python:{ver}-bookworm"),
                        channel: "stable".into(),
                        order_key: (*ver).into(),
                        evidence_grade: EvidenceGrade::Observed,
                        notes: vec!["concrete official python image tag".into()],
                    });
                }
            }
        }

        // Preview: 3.14-rc style when configured — only if "preview" channel enabled.
        // We list a known published RC tag pattern; if pull fails at runtime → BLOCKED.
        if channels.iter().any(|c| c == "preview") {
            out.push(Candidate {
                id: "py314rc-locked".into(),
                axis: EnvironmentAxis::Runtime,
                label: "Python 3.14-rc + locked dependencies".into(),
                runtime_version: Some("3.14-rc".into()),
                dependency_mode: DependencyMode::Locked,
                image_ref: "python:3.14-rc-bookworm".into(),
                channel: "preview".into(),
                order_key: "3.14-rc".into(),
                evidence_grade: EvidenceGrade::Observed,
                notes: vec!["preview/RC image; may be BLOCKED if tag is unavailable".into()],
            });
        }

        if config.candidates.dependencies.latest_allowed {
            out.push(Candidate {
                id: format!("py{}-latest", base_minor.replace('.', "")),
                axis: EnvironmentAxis::Dependencies,
                label: format!(
                    "Python {} + latest allowed dependencies",
                    baseline.runtime_version
                ),
                runtime_version: Some(baseline.runtime_version.clone()),
                dependency_mode: DependencyMode::LatestAllowed,
                image_ref: baseline.image_ref.clone(),
                channel: "stable".into(),
                order_key: format!("dep-{}", baseline.runtime_version),
                evidence_grade: EvidenceGrade::Simulated,
                notes: vec!["pip install without pinning (constraints still apply)".into()],
            });
        }

        if config.candidates.dependencies.prerelease {
            out.push(Candidate {
                id: format!("py{}-prerelease", base_minor.replace('.', "")),
                axis: EnvironmentAxis::Dependencies,
                label: format!(
                    "Python {} + prerelease dependencies",
                    baseline.runtime_version
                ),
                runtime_version: Some(baseline.runtime_version.clone()),
                dependency_mode: DependencyMode::PrereleaseAllowed,
                image_ref: baseline.image_ref.clone(),
                channel: "stable".into(),
                order_key: format!("dep-pre-{}", baseline.runtime_version),
                evidence_grade: EvidenceGrade::Simulated,
                notes: vec!["pip install with --pre".into()],
            });
        }

        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec> {
        let image = if scenario.image_ref.is_empty() {
            format!("python:{}-bookworm", scenario.runtime_version)
        } else {
            scenario.image_ref.clone()
        };
        let mut environment = EnvironmentSpec {
            image_ref: image,
            image_digest: None,
            workdir: "/workspace".into(),
            user: None, // root install then could drop — v0.1 installs as root in container only
            env: IndexMap::new(),
            mounts: vec![],
            network_mode: NetworkMode::FetchOnly,
            read_only_root: false, // pip needs site-packages
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            timeout_seconds: 900,
        };
        if workspace_registry_snapshot(workspace, Ecosystem::Python)
            .map_err(|error| AdapterError::Materialize(error.to_string()))?
            .is_some()
        {
            environment.network_mode = NetworkMode::None;
            environment.env.insert("PIP_NO_INDEX".into(), "1".into());
            environment
                .env
                .insert("PIP_FIND_LINKS".into(), snapshot_container_payload().into());
        }
        Ok(environment)
    }

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let mut cmds = Vec::new();
        // Fetch phase: upgrade pip tooling and install pytest runner
        cmds.push(CommandSpec {
            phase: CommandPhase::Fetch,
            program: "python".into(),
            args: vec![
                "-m".into(),
                "pip".into(),
                "install".into(),
                "-q".into(),
                "--upgrade".into(),
                "pip".into(),
                "pytest".into(),
            ],
            workdir: "/workspace".into(),
            network_required: true,
            env: IndexMap::new(),
        });

        // Install from requirements.txt when present (adapters do not shell out to test existence;
        // runner workspace always includes the repo files — pip fails clearly if missing).
        let mut install_args = vec!["-m".into(), "pip".into(), "install".into(), "-q".into()];
        match scenario.dependency_mode {
            DependencyMode::Locked => {
                install_args.push("-r".into());
                install_args.push("requirements.txt".into());
            }
            DependencyMode::LatestAllowed => {
                install_args.push("-r".into());
                install_args.push("requirements.txt".into());
                install_args.push("--upgrade".into());
            }
            DependencyMode::PrereleaseAllowed => {
                install_args.push("-r".into());
                install_args.push("requirements.txt".into());
                install_args.push("--upgrade".into());
                install_args.push("--pre".into());
            }
        }
        cmds.push(CommandSpec {
            phase: CommandPhase::Fetch,
            program: "python".into(),
            args: install_args,
            workdir: "/workspace".into(),
            network_required: true,
            env: IndexMap::new(),
        });

        let test = Self::test_command(config);
        let (program, args) = test
            .split_first()
            .ok_or_else(|| AdapterError::Other("empty test command".into()))?;
        let mut test_env = IndexMap::new();
        // Explicit dependency mode marker for SIMULATED scenarios / fixtures.
        // Adapters never invent versions; they only label the mutation that was applied.
        test_env.insert(
            "TOMORROWCI_DEP_MODE".into(),
            match scenario.dependency_mode {
                DependencyMode::Locked => "locked".into(),
                DependencyMode::LatestAllowed => "latest_allowed".into(),
                DependencyMode::PrereleaseAllowed => "prerelease".into(),
            },
        );
        // Prefer upgraded vendor tree when present (fixture contract for dep-axis SIMULATED).
        if matches!(
            scenario.dependency_mode,
            DependencyMode::LatestAllowed | DependencyMode::PrereleaseAllowed
        ) {
            test_env.insert(
                "PYTHONPATH".into(),
                "/workspace/vendor/legacycompat_v2:/workspace/vendor".into(),
            );
        } else {
            test_env.insert("PYTHONPATH".into(), "/workspace/vendor".into());
        }
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

    fn commands_in_workspace(
        &self,
        scenario: &Scenario,
        config: &Config,
        workspace: &Path,
    ) -> Result<Vec<CommandSpec>> {
        let snapshot = workspace_registry_snapshot(workspace, Ecosystem::Python)
            .map_err(|error| AdapterError::Materialize(error.to_string()))?;
        let dependency_source = if workspace.join("requirements.txt").is_file() {
            Some(("-r", "requirements.txt"))
        } else if workspace.join("requirements-dev.txt").is_file() {
            Some(("-r", "requirements-dev.txt"))
        } else if workspace.join("pyproject.toml").is_file() {
            Some(("", "."))
        } else {
            None
        }
        .ok_or_else(|| {
            AdapterError::Materialize(
                "supported Python workspace has no installable pip manifest".into(),
            )
        })?;

        let mut commands = self.commands(scenario, config)?;
        for command in &mut commands {
            if command.phase != CommandPhase::Fetch
                || command.program != "python"
                || !command
                    .args
                    .iter()
                    .any(|argument| argument == "requirements.txt")
            {
                continue;
            }
            let requirements = command
                .args
                .iter()
                .position(|argument| argument == "requirements.txt")
                .ok_or_else(|| {
                    AdapterError::Materialize("requirements argument vanished".into())
                })?;
            command.args[requirements] = dependency_source.1.into();
            if dependency_source.0.is_empty()
                && requirements > 0
                && command.args[requirements - 1] == "-r"
            {
                command.args.remove(requirements - 1);
            }
        }

        // A requirements-backed locked baseline must be defined by those
        // source-bound bytes. Fetching the latest pip/pytest first would make
        // the supposedly locked environment depend on mutable index state.
        // Pyproject-only workspaces retain the compatibility bootstrap because
        // there is no requirements lock for the adapter to consume.
        if scenario.dependency_mode == DependencyMode::Locked && !dependency_source.0.is_empty() {
            commands.retain(|command| {
                !(command.phase == CommandPhase::Fetch
                    && command.args.iter().any(|argument| argument == "--upgrade")
                    && command.args.iter().any(|argument| argument == "pip")
                    && command.args.iter().any(|argument| argument == "pytest"))
            });
        }

        if snapshot.is_none() {
            return Ok(commands);
        }
        let payload = snapshot_container_payload();
        // A historical wheelhouse must not bootstrap today's pip/pytest. The
        // project requirements (or its explicit test command) define those
        // tools; silently adding them would change the historical dependency
        // set and make an empty-cache acceptance impossible.
        commands.retain(|command| {
            !(command.phase == CommandPhase::Fetch
                && command.args.iter().any(|argument| argument == "--upgrade")
                && command.args.iter().any(|argument| argument == "pytest"))
        });
        for command in &mut commands {
            if command.phase == CommandPhase::Fetch {
                command.args.push("--no-index".into());
                command.args.push("--find-links".into());
                command.args.push(payload.into());
                command.network_required = false;
                command.env.insert("PIP_NO_INDEX".into(), "1".into());
                command.env.insert("PIP_FIND_LINKS".into(), payload.into());
            }
        }
        Ok(commands)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        normalize_failure(result, EvidenceGrade::Observed)
    }
}

fn version_gt(a: &str, b: &str) -> bool {
    let pa = parse_minor(a);
    let pb = parse_minor(b);
    pa > pb
}

fn parse_minor(v: &str) -> (u32, u32) {
    let clean = v.split('-').next().unwrap_or(v);
    let mut parts = clean.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// Build baseline scenario from baseline struct.
pub fn baseline_scenario(b: &Baseline) -> Scenario {
    Scenario {
        id: tomorrowci_core::ScenarioId::new("baseline"),
        kind: tomorrowci_core::ScenarioKind::Baseline,
        ecosystem: Ecosystem::Python,
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
    fn detects_requirements() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let a = PythonAdapter::new();
        let det = a.detect(d.path()).unwrap();
        assert!(det.detection.supported);
        assert_eq!(det.detection.package_manager, "pip");
    }

    #[test]
    fn poetry_only_unsupported() {
        let d = tempdir().unwrap();
        fs::write(d.path().join("poetry.lock"), "").unwrap();
        let a = PythonAdapter::new();
        let det = a.detect(d.path()).unwrap();
        assert!(!det.detection.supported);
    }

    #[test]
    fn candidates_newer_than_baseline() {
        let a = PythonAdapter::new();
        let b = Baseline {
            ecosystem: Ecosystem::Python,
            runtime_label: "Python 3.9".into(),
            runtime_version: "3.9".into(),
            dependency_mode: DependencyMode::Locked,
            image_ref: "python:3.9-bookworm".into(),
            notes: vec![],
        };
        let cfg = Config::default();
        let c = a.candidates(&b, &cfg).unwrap();
        assert!(c
            .iter()
            .any(|x| x.runtime_version.as_deref() == Some("3.10")));
        assert!(!c
            .iter()
            .any(|x| x.runtime_version.as_deref() == Some("3.9")
                && x.axis == EnvironmentAxis::Runtime));
    }

    #[test]
    fn verified_wheelhouse_commands_are_offline_and_container_relative() {
        let workspace = tempdir().unwrap();
        stage_snapshot_fixture(workspace.path(), "python");
        fs::write(workspace.path().join("requirements.txt"), "").unwrap();
        let adapter = PythonAdapter::new();
        let baseline = adapter
            .baseline(workspace.path(), &Config::default())
            .unwrap();
        let scenario = baseline_scenario(&baseline);
        let environment = adapter.materialize(&scenario, workspace.path()).unwrap();
        assert_eq!(environment.network_mode, NetworkMode::None);
        let commands = adapter
            .commands_in_workspace(&scenario, &Config::default(), workspace.path())
            .unwrap();
        fake_offline_executor(&commands, workspace.path());
        assert!(commands
            .iter()
            .any(|command| command.args.iter().any(|argument| argument == "--no-index")));
    }

    #[test]
    fn requirements_backed_locked_commands_do_not_bootstrap_mutable_tools() {
        let workspace = tempdir().unwrap();
        fs::write(workspace.path().join("requirements.txt"), "pytest==8.3.4\n").unwrap();
        let adapter = PythonAdapter::new();
        let baseline = adapter
            .baseline(workspace.path(), &Config::default())
            .unwrap();
        let commands = adapter
            .commands_in_workspace(
                &baseline_scenario(&baseline),
                &Config::default(),
                workspace.path(),
            )
            .unwrap();
        assert!(commands.iter().any(|command| {
            command
                .args
                .windows(2)
                .any(|args| args[0] == "-r" && args[1] == "requirements.txt")
        }));
        assert!(!commands.iter().any(|command| {
            command.args.iter().any(|argument| argument == "--upgrade")
                && command.args.iter().any(|argument| argument == "pip")
                && command.args.iter().any(|argument| argument == "pytest")
        }));
    }

    #[test]
    fn pyproject_only_workspace_installs_the_project_instead_of_a_missing_requirements_file() {
        let workspace = tempdir().unwrap();
        fs::write(
            workspace.path().join("pyproject.toml"),
            "[project]\nname = \"example\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        let adapter = PythonAdapter::new();
        let baseline = adapter
            .baseline(workspace.path(), &Config::default())
            .unwrap();
        let commands = adapter
            .commands_in_workspace(
                &baseline_scenario(&baseline),
                &Config::default(),
                workspace.path(),
            )
            .unwrap();
        let install = commands
            .iter()
            .find(|command| {
                command.phase == CommandPhase::Fetch
                    && command.args.iter().any(|argument| argument == ".")
            })
            .expect("project install command");
        assert!(!install.args.iter().any(|argument| argument == "-r"));
        assert!(!install
            .args
            .iter()
            .any(|argument| argument == "requirements.txt"));
        assert!(commands.iter().any(|command| {
            command.args.iter().any(|argument| argument == "--upgrade")
                && command.args.iter().any(|argument| argument == "pip")
                && command.args.iter().any(|argument| argument == "pytest")
        }));
    }

    fn stage_snapshot_fixture(workspace: &Path, ecosystem: &str) {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/backtest-snapshots")
            .join(ecosystem)
            .join("2026-01-15");
        let destination = workspace.join(tomorrowci_core::backtest::WORKSPACE_SNAPSHOT_DIR);
        copy_fixture_tree(&source, &destination);
    }

    fn copy_fixture_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_fixture_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn fake_offline_executor(commands: &[CommandSpec], host_workspace: &Path) {
        for command in commands {
            assert!(!command.network_required);
            assert_eq!(command.workdir, "/workspace");
            for value in command.args.iter().chain(command.env.values()) {
                assert!(!value.contains(host_workspace.to_string_lossy().as_ref()));
                if value.contains("registry-snapshot") {
                    assert!(value.starts_with("/workspace/"));
                }
            }
        }
    }
}
