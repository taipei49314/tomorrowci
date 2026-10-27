//! Python adapter — pip-only live runtime forecasting path.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    parse_explicit_python_version, Baseline, Candidate, CommandSpec, Config, Ecosystem,
    EnvironmentAxis, EnvironmentSpec, EvidenceGrade, FailureSignature, ProjectDetection,
    RawExecutionResult, Result, Scenario, TcError,
};

pub struct PythonAdapter;

/// Parse `3.9`, `python:3.10`, `3.11-slim` → (major, minor).
pub fn parse_python_version(s: &str) -> Option<(u32, u32)> {
    let t = s
        .trim()
        .trim_start_matches("python:")
        .split('-')
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = t.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn version_order_key(major: u32, minor: u32) -> String {
    format!("{major:03}.{minor:03}")
}

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
        let notes = if supported {
            let mut n = vec!["Python project detected; package manager: pip only.".into()];
            if has_pyproject && !has_req {
                n.push(
                    "pyproject.toml without requirements.txt: install path is UNSUPPORTED for this milestone unless requirements.txt is present."
                        .into(),
                );
            }
            n
        } else {
            vec!["No pyproject.toml or requirements.txt.".into()]
        };
        DetectionResult {
            supported,
            detection: ProjectDetection {
                ecosystem: if supported {
                    Ecosystem::Python
                } else {
                    Ecosystem::Unknown
                },
                manifests,
                package_manager: "pip".into(),
                confidence: if supported { 0.9 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline> {
        if config
            .candidates
            .runtime
            .versions
            .as_ref()
            .is_some_and(|versions| !versions.is_empty())
            && config.baseline.runtime != "auto"
            && parse_explicit_python_version(&config.baseline.runtime).is_none()
        {
            return Err(TcError::Config(
                "explicit Python runtime candidates require a canonical baseline.runtime such as \"3.13\"; image tags and patch versions are not accepted".into(),
            ));
        }
        // Prefer explicit config; never silently invent unrelated projects' baselines.
        let runtime = if config.baseline.runtime == "auto" {
            // Read requires-python from pyproject if present; else fail closed to config requirement.
            if let Some(v) = read_requires_python_min(repo) {
                v
            } else {
                return Err(TcError::Config(
                    "baseline.runtime is 'auto' but no requires-python / config pin found; set baseline.runtime explicitly (e.g. \"3.9\")".into(),
                ));
            }
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("python:")
                .split('-')
                .next()
                .unwrap_or(&config.baseline.runtime)
                .to_string()
        };
        if parse_python_version(&runtime).is_none() {
            return Err(TcError::Config(format!(
                "invalid Python baseline runtime '{runtime}'"
            )));
        }
        Ok(Baseline {
            runtime,
            dependencies: if config.baseline.dependencies == "auto" {
                "locked".into()
            } else {
                config.baseline.dependencies.clone()
            },
            declared_by: if config.baseline.runtime == "auto" {
                "pyproject/requires-python".into()
            } else {
                "config".into()
            },
        })
    }

    fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>> {
        config.validate()?;
        let max = config.candidates.runtime.max_versions as usize;
        let base = parse_python_version(&baseline.runtime).ok_or_else(|| {
            TcError::Config(format!(
                "cannot order candidates: invalid baseline {}",
                baseline.runtime
            ))
        })?;

        // Omission retains the legacy catalogue. An explicit list is an exact
        // request, including an empty list; it is never filled in or truncated.
        let catalog = if let Some(versions) = &config.candidates.runtime.versions {
            if !versions.is_empty() && parse_explicit_python_version(&baseline.runtime).is_none() {
                return Err(TcError::Config(
                    "explicit Python runtime candidates require a canonical baseline.runtime such as \"3.13\"".into(),
                ));
            }
            versions
                .iter()
                .map(|version| {
                    let parsed = parse_explicit_python_version(version).ok_or_else(|| {
                        TcError::Config(format!("invalid explicit Python runtime '{version}'"))
                    })?;
                    if parsed <= base {
                        return Err(TcError::Config(format!(
                            "explicit runtime {version} must be strictly later than baseline {}",
                            baseline.runtime
                        )));
                    }
                    Ok(parsed)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![(3, 10), (3, 11), (3, 12), (3, 13)]
        };
        let mut out = Vec::new();
        for (maj, min) in catalog {
            if (maj, min) <= base {
                continue; // strictly later only
            }
            if out.len() >= max {
                break;
            }
            let v = format!("{maj}.{min}");
            out.push(Candidate {
                id: format!("py{}{}-locked", maj, min),
                axis: EnvironmentAxis::Runtime,
                label: format!("Python {v} + locked dependencies"),
                version: v,
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: version_order_key(maj, min),
                dependency_set: None,
            });
        }
        out.sort_by(|a, b| a.order_key.cmp(&b.order_key));
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let ver = scenario
            .runtime
            .trim_start_matches("python:")
            .split('-')
            .next()
            .unwrap_or(&scenario.runtime);
        let state = format!("/work/.tomorrowci/scenarios/{}", scenario.id);
        let venv = format!("{state}/venv");
        let exact_dependencies = scenario.resolved_dependencies.is_some();
        let image = format!("python:{ver}-slim");
        Ok(EnvironmentSpec {
            image_tag: image.clone(),
            image: image.clone(),
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let mut m = IndexMap::new();
                m.insert("PIP_CACHE_DIR".into(), format!("{state}/cache/pip"));
                if exact_dependencies {
                    m.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
                    m.insert("PYTHONPATH".into(), format!("{state}/deps"));
                } else {
                    m.insert("VIRTUAL_ENV".into(), venv.clone());
                    m.insert(
                        "PATH".into(),
                        format!("{venv}/bin:/usr/local/bin:/usr/bin:/bin"),
                    );
                }
                m
            },
            network_mode: "none".into(),
            memory_mb: 2048,
            cpus: 1.0,
            pids_limit: 256,
            user: Some("65534:65534".into()),
            read_only_root: true,
            scenario_state_root: Some(state),
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
        })
    }

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let py = if scenario.resolved_dependencies.is_some() {
            "python".into()
        } else {
            format!(
                "/work/.tomorrowci/scenarios/{}/venv/bin/python",
                scenario.id
            )
        };
        let test = if config.project.test_command == "auto" {
            vec![py, "-m".into(), "pytest".into(), "-q".into()]
        } else {
            let parts: Vec<String> = config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if parts.first().map(|s| s.as_str()) == Some("python") {
                let mut p = parts;
                p[0] = py;
                p
            } else {
                parts
            }
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
        let kind = if blob.contains("ImportError") || blob.contains("cannot import name") {
            "ImportError"
        } else if blob.contains("SyntaxError") {
            "SyntaxError"
        } else if result.timed_out {
            "Timeout"
        } else if blob.contains("ModuleNotFoundError") {
            "ModuleNotFoundError"
        } else {
            "TestFailure"
        };
        // Normalize: prefer stable ImportError line about MutableMapping when present
        let summary = blob
            .lines()
            .find(|l| {
                l.contains("MutableMapping") || l.contains("ImportError") || l.contains("Error")
            })
            .or_else(|| blob.lines().rev().find(|l| !l.trim().is_empty()))
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

/// Fetch phase: create a scenario-local venv, installing pip requirements when
/// the file contains more than blank/comment lines.
pub fn python_fetch_commands(
    workspace: &Path,
    upgrade: bool,
    scenario_id: &str,
) -> Result<Vec<CommandSpec>> {
    if !workspace.join("requirements.txt").exists() {
        return Err(TcError::Unsupported(
            "Python install path requires requirements.txt in this repair milestone (pip only); pyproject-only is UNSUPPORTED".into(),
        ));
    }
    let state = format!("/work/.tomorrowci/scenarios/{scenario_id}");
    let venv = format!("{state}/venv");
    let requirements = std::fs::read_to_string(workspace.join("requirements.txt"))?;
    let no_dependencies = requirements.lines().all(|line| {
        let line = line.trim();
        line.is_empty() || line.starts_with('#')
    });
    if no_dependencies {
        // A stdlib-only project needs an isolated interpreter, not ensurepip or
        // a package-index connection. Any requirements directive takes the
        // normal pip path below, including -r, constraints and index options.
        return Ok(vec![
            CommandSpec {
                argv: vec!["rm".into(), "-rf".into(), venv.clone()],
                cwd: Some("/work".into()),
                network: false,
                phase: "fetch".into(),
            },
            CommandSpec {
                argv: vec![
                    "python".into(),
                    "-m".into(),
                    "venv".into(),
                    "--without-pip".into(),
                    venv,
                ],
                cwd: Some("/work".into()),
                network: false,
                phase: "fetch".into(),
            },
        ]);
    }
    let cache = format!("{state}/cache/pip");
    let py = format!("{venv}/bin/python");
    let mut install = vec![
        py.clone(),
        "-m".into(),
        "pip".into(),
        "install".into(),
        "-q".into(),
        "--cache-dir".into(),
        cache,
        "-r".into(),
        "requirements.txt".into(),
    ];
    if upgrade {
        install.push("--upgrade".into());
    }
    Ok(vec![
        CommandSpec {
            argv: vec!["rm".into(), "-rf".into(), venv.clone()],
            cwd: Some("/work".into()),
            network: false,
            phase: "fetch".into(),
        },
        CommandSpec {
            argv: vec!["mkdir".into(), "-p".into(), format!("{state}/cache/pip")],
            cwd: Some("/work".into()),
            network: false,
            phase: "fetch".into(),
        },
        CommandSpec {
            argv: vec!["python".into(), "-m".into(), "venv".into(), venv],
            cwd: Some("/work".into()),
            network: false,
            phase: "fetch".into(),
        },
        CommandSpec {
            argv: install,
            cwd: Some("/work".into()),
            network: true,
            phase: "fetch".into(),
        },
    ])
}

fn read_requires_python_min(repo: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(repo.join("pyproject.toml")).ok()?;
    // minimal parse: requires-python = ">=3.9"
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with("requires-python") {
            if let Some(idx) = t.find('"') {
                let rest = &t[idx + 1..];
                if let Some(end) = rest.find('"') {
                    let spec = &rest[..end];
                    // take first X.Y mentioned
                    for token in spec.split(|c: char| !c.is_ascii_digit() && c != '.') {
                        if parse_python_version(token).is_some() {
                            return Some(token.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Explicit: only pip is supported in this repair milestone.
pub fn check_manager_supported(manager: &str) -> Result<()> {
    match manager {
        "pip" => Ok(()),
        "uv" => Err(TcError::Unsupported(
            "Python package manager 'uv' is NOT_RUN / UNSUPPORTED in this repair milestone (pip only)".into(),
        )),
        other => Err(TcError::Unsupported(format!(
            "Python package manager '{other}' is UNSUPPORTED (supported: pip)"
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

    #[test]
    fn uv_not_supported_claim() {
        assert!(check_manager_supported("uv").is_err());
    }

    #[test]
    fn empty_or_comment_only_requirements_need_no_pip_or_package_network() {
        let dir = tempdir().unwrap();
        for contents in [
            "",
            " \n\t\r\n",
            "# Standard library only\n  # no dependencies\r\n\n",
        ] {
            std::fs::write(dir.path().join("requirements.txt"), contents).unwrap();
            for upgrade in [false, true] {
                let commands = python_fetch_commands(dir.path(), upgrade, "baseline").unwrap();
                assert!(commands.iter().all(|command| !command.network));
                assert!(commands
                    .iter()
                    .all(|command| !command.argv.iter().any(|arg| arg == "pip")));
                let venv = commands
                    .iter()
                    .find(|command| command.argv.iter().any(|arg| arg == "venv"))
                    .unwrap();
                assert!(venv.argv.iter().any(|arg| arg == "--without-pip"));
                assert_eq!(
                    venv.argv.last().unwrap(),
                    "/work/.tomorrowci/scenarios/baseline/venv"
                );
            }
        }
    }

    #[test]
    fn actual_requirements_and_directives_preserve_pip_install() {
        let dir = tempdir().unwrap();
        for contents in [
            "pytest==8.0.0\n",
            "# tests\npytest==8.0.0 # pinned\n",
            "-r requirements-test.txt\n",
            "--find-links ./wheels\n",
            "-c constraints.txt\n",
        ] {
            std::fs::write(dir.path().join("requirements.txt"), contents).unwrap();
            for upgrade in [false, true] {
                let commands = python_fetch_commands(dir.path(), upgrade, "py314-locked").unwrap();
                assert!(commands
                    .iter()
                    .all(|command| !command.argv.iter().any(|arg| arg == "--without-pip")));
                let install = commands
                    .iter()
                    .find(|command| command.argv.iter().any(|arg| arg == "pip"))
                    .unwrap();
                assert!(install.network);
                assert!(install
                    .argv
                    .windows(2)
                    .any(|args| args == ["-r", "requirements.txt"]));
                assert_eq!(install.argv.iter().any(|arg| arg == "--upgrade"), upgrade);
            }
        }
    }

    #[test]
    fn unreadable_requirements_are_not_treated_as_dependency_free() {
        let dir = tempdir().unwrap();
        assert!(python_fetch_commands(dir.path(), false, "baseline").is_err());
        std::fs::write(dir.path().join("requirements.txt"), [0xff, 0xfe]).unwrap();
        assert!(python_fetch_commands(dir.path(), false, "baseline").is_err());
    }

    #[test]
    fn candidates_strictly_later_semantic() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let mut cfg = Config::default();
        cfg.baseline.runtime = "3.11".into();
        cfg.candidates.runtime.max_versions = 5;
        let base = PythonAdapter.baseline(d.path(), &cfg).unwrap();
        let c = PythonAdapter.candidates(&base, &cfg).unwrap();
        assert!(c
            .iter()
            .all(|x| parse_python_version(&x.version).unwrap() > (3, 11)));
        assert_eq!(c.first().map(|x| x.version.as_str()), Some("3.12"));
        // order keys semantic not lexical-only
        let keys: Vec<_> = c.iter().map(|x| x.order_key.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn no_hardcoded_silent_39_for_auto_without_pyproject() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("requirements.txt"), "pytest\n").unwrap();
        let mut cfg = Config::default();
        cfg.baseline.runtime = "auto".into();
        assert!(PythonAdapter.baseline(d.path(), &cfg).is_err());
    }

    fn explicit_config(versions: &[&str]) -> Config {
        let mut config = Config::default();
        config.project.ecosystem = "python".into();
        config.baseline.runtime = "3.13".into();
        config.candidates.runtime.versions = Some(versions.iter().map(|v| (*v).into()).collect());
        config.candidates.dependencies.latest_allowed = false;
        config.candidates.dependencies.prerelease = false;
        config
    }

    #[test]
    fn explicit_versions_extend_beyond_catalogue_without_guessing() {
        let dir = tempdir().unwrap();
        let config = explicit_config(&["3.14", "3.15"]);
        let baseline = PythonAdapter.baseline(dir.path(), &config).unwrap();
        let candidates = PythonAdapter.candidates(&baseline, &config).unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|c| c.version.as_str())
                .collect::<Vec<_>>(),
            ["3.14", "3.15"]
        );
        assert_eq!(candidates[0].id, "py314-locked");
        let (plan, _) = tomorrowci_core::plan_scenarios(&baseline, &candidates, &[], &config);
        assert_eq!(plan.scenarios.len(), 3);
        let env = PythonAdapter
            .materialize(&plan.scenarios[1], dir.path())
            .unwrap();
        assert_eq!(env.image_tag, "python:3.14-slim");
        // This unit test validates selection and image naming, not tag availability.
    }

    #[test]
    fn no_candidates_has_no_catalogue_or_latest_fallback() {
        let dir = tempdir().unwrap();
        let mut config = explicit_config(&[]);
        config.baseline.runtime = "3.11".into();
        let baseline = PythonAdapter.baseline(dir.path(), &config).unwrap();
        assert!(PythonAdapter
            .candidates(&baseline, &config)
            .unwrap()
            .is_empty());
        config.candidates.runtime.versions = None;
        config.baseline.runtime = "3.13".into();
        let baseline = PythonAdapter.baseline(dir.path(), &config).unwrap();
        assert!(PythonAdapter
            .candidates(&baseline, &config)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn explicit_versions_reject_same_or_earlier_runtime() {
        let dir = tempdir().unwrap();
        for versions in [vec!["3.13"], vec!["3.12", "3.14"]] {
            let config = explicit_config(&versions);
            let baseline = PythonAdapter.baseline(dir.path(), &config).unwrap();
            let error = PythonAdapter
                .candidates(&baseline, &config)
                .unwrap_err()
                .to_string();
            assert!(error.contains("strictly later"), "{error}");
        }
    }

    #[test]
    fn explicit_selection_rejects_ambiguous_baseline_and_direct_invalid_config() {
        let dir = tempdir().unwrap();
        for runtime in ["3.13.1", "python:3.13", "3.13-slim", "3.013", "3.13;id"] {
            let mut config = explicit_config(&["3.14"]);
            config.baseline.runtime = runtime.into();
            assert!(
                PythonAdapter.baseline(dir.path(), &config).is_err(),
                "accepted {runtime}"
            );
        }
        let valid = explicit_config(&["3.14"]);
        let baseline = PythonAdapter.baseline(dir.path(), &valid).unwrap();
        for versions in [
            vec!["3.15", "3.14"],
            vec!["3.14", "3.14"],
            vec!["3.14;id"],
            vec!["3.14/evil"],
            vec!["3.14\n"],
        ] {
            let config = explicit_config(&versions);
            assert!(PythonAdapter.candidates(&baseline, &config).is_err());
        }
        let mut config = valid;
        config.candidates.runtime.max_versions = 0;
        assert!(PythonAdapter.candidates(&baseline, &config).is_err());
        config.candidates.runtime.max_versions = 1;
        config.execution.max_scenarios = 1;
        assert!(PythonAdapter.candidates(&baseline, &config).is_err());
    }
}
