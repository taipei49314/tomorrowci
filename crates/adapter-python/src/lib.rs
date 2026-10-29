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
        if let Some(failure) = tomorrowci_core::python_coverage_failure(result) {
            return failure;
        }
        let blob = strip_python_ansi(&format!("{}\n{}", result.stdout, result.stderr));
        let (kind, summary, primary_frame, detail) = if result.timed_out {
            (
                "Timeout".into(),
                "execution timed out".into(),
                None,
                "execution timed out".into(),
            )
        } else {
            python_failure_identity(&blob)
        };
        // The namespace deliberately prevents old wrapper-only receipts from
        // authorizing a replay under this stronger diagnostic contract.
        let normalized_hash = tomorrowci_core::sha256_str(&format!(
            "python-failure-v2\n{kind}\n{}\n{detail}",
            primary_frame.as_deref().unwrap_or("")
        ));
        FailureSignature {
            kind,
            summary: summary.chars().take(200).collect(),
            normalized_hash,
            primary_frame,
        }
    }
}

fn strip_python_ansi(text: &str) -> String {
    let mut chars = text.chars().peekable();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for control in chars.by_ref() {
                    if ('@'..='~').contains(&control) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(control) = chars.next() {
                    if control == '\u{7}' {
                        break;
                    }
                    if control == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            Some(other) => {
                out.push('\u{1b}');
                out.push(other);
            }
            None => out.push('\u{1b}'),
        }
    }
    out
}

fn normalize_python_frame_path(raw: &str) -> String {
    let path = raw.replace('\\', "/");
    for root in ["/work/", "/workspace/"] {
        if let Some(relative) = path.strip_prefix(root) {
            return normalize_python_scenario_path(relative);
        }
    }
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate().skip(1) {
        let parent = parts[index - 1];
        if (parent.eq_ignore_ascii_case("tmp") || parent.eq_ignore_ascii_case("temp"))
            && (part.starts_with("run-") || part.starts_with("tomorrowci-replay-"))
            && index + 1 < parts.len()
        {
            return normalize_python_scenario_path(&parts[index + 1..].join("/"));
        }
    }
    // Unknown roots stay distinct rather than merging unrelated modules.
    normalize_python_scenario_path(path.trim_start_matches("./"))
}

fn normalize_python_scenario_path(path: &str) -> String {
    if let Some((scenario, relative)) = path
        .strip_prefix(".tomorrowci/scenarios/")
        .and_then(|rest| rest.split_once('/'))
    {
        if !scenario.is_empty() && (relative.starts_with("deps/") || relative.starts_with("venv/"))
        {
            return format!("<scenario-state>/{relative}");
        }
    }
    path.to_string()
}

fn normalize_python_embedded_paths(text: &str) -> String {
    let mut out = String::new();
    let mut start = 0;
    for (index, ch) in text.char_indices() {
        if matches!(ch, '\'' | '"' | '(' | ')') {
            let part = &text[start..index];
            let is_path = part.starts_with('/') || part.as_bytes().get(1) == Some(&b':');
            out.push_str(&if is_path {
                normalize_python_frame_path(part)
            } else {
                part.to_string()
            });
            out.push(ch);
            start = index + ch.len_utf8();
        }
    }
    out.push_str(&text[start..]);
    out
}

fn python_traceback_frame(line: &str) -> Option<String> {
    let rest = line.strip_prefix("File ")?;
    let quote = rest.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let (path, location) = rest[1..].split_once(quote)?;
    let location = location.strip_prefix(", line ")?;
    let line_number = location.split(',').next()?;
    if line_number.is_empty() || !line_number.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let path = normalize_python_frame_path(path);
    Some(match location.split_once(", in ") {
        Some((_, function)) => format!("{path}::{}", function.trim()),
        None => path,
    })
}

fn python_exception_kind(line: &str, allow_custom: bool) -> Option<&str> {
    let (name, has_message) = match line.split_once(':') {
        Some((name, _)) => (name, true),
        None => (line, false),
    };
    let short = name.rsplit('.').next()?;
    if short.is_empty()
        || !short.chars().next()?.is_ascii_uppercase()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.'))
        || matches!(short, "ERROR" | "FAIL" | "FAILED" | "Traceback" | "File")
    {
        return None;
    }
    if (allow_custom && has_message)
        || short.ends_with("Error")
        || short.ends_with("Exception")
        || matches!(
            short,
            "KeyboardInterrupt"
                | "SystemExit"
                | "StopIteration"
                | "GeneratorExit"
                | "ExceptionGroup"
                | "BaseExceptionGroup"
        )
    {
        Some(name)
    } else {
        None
    }
}

fn python_runner_noise(line: &str) -> bool {
    let words: Vec<_> = line.split_whitespace().collect();
    let unittest_timing = words.len() == 5
        && words[0] == "Ran"
        && words[1].chars().all(|ch| ch.is_ascii_digit())
        && matches!(words[2], "test" | "tests")
        && words[3] == "in"
        && words[4]
            .strip_suffix('s')
            .is_some_and(|n| n.parse::<f64>().is_ok());
    let pytest_summary = line.trim_matches('=').trim();
    let pytest_words: Vec<_> = pytest_summary.split_whitespace().collect();
    let pytest_timing = pytest_words.len() >= 4
        && pytest_words[0].chars().all(|ch| ch.is_ascii_digit())
        && matches!(
            pytest_words[1].trim_end_matches(','),
            "failed"
                | "passed"
                | "skipped"
                | "error"
                | "errors"
                | "xfailed"
                | "xpassed"
                | "deselected"
        )
        && pytest_words[pytest_words.len() - 2] == "in"
        && pytest_words
            .last()
            .and_then(|s| s.strip_suffix('s'))
            .is_some_and(|n| n.parse::<f64>().is_ok());
    unittest_timing
        || pytest_timing
        || pytest_summary == "short test summary info"
        || line == "OK"
        || line.starts_with("FAILED (")
        || line.starts_with("OK (")
        || line.starts_with("ERROR: ")
        || line.starts_with("FAIL: ")
        || (line.len() >= 10 && line.chars().all(|ch| ch == '-' || ch == '='))
        || (line.contains(") ... ")
            && [" ... ok", " ... ERROR", " ... FAIL", " ... skipped"]
                .iter()
                .any(|suffix| line.ends_with(suffix)))
}

fn python_pytest_location(line: &str) -> Option<String> {
    let (mut location, exception) = line.rsplit_once(": ")?;
    python_exception_kind(exception, false)?;
    let mut removed = 0;
    for _ in 0..2 {
        if let Some((path, number)) = location.rsplit_once(':') {
            if !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()) {
                location = path;
                removed += 1;
            }
        }
    }
    (removed > 0 && location.ends_with(".py")).then(|| normalize_python_frame_path(location))
}

fn python_pytest_test_id(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("FAILED ")
        .or_else(|| line.strip_prefix("ERROR "))?;
    let identity = rest
        .split_once(" - ")
        .map(|(identity, _)| identity)
        .unwrap_or(rest);
    let (file, test) = identity.split_once("::")?;
    (file.ends_with(".py") && !test.is_empty())
        .then(|| format!("{}::{test}", normalize_python_frame_path(file)))
}

fn normalize_python_object_addresses(line: &str) -> String {
    let mut normalized = String::new();
    let mut rest = line;
    while let Some(index) = rest.find(" at 0x") {
        normalized.push_str(&rest[..index]);
        let suffix = &rest[index + 6..];
        let hex_length = suffix
            .bytes()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if hex_length > 0 && suffix[hex_length..].starts_with('>') {
            normalized.push_str(" at <address>");
            rest = &suffix[hex_length..];
        } else {
            normalized.push_str(" at 0x");
            rest = suffix;
        }
    }
    normalized.push_str(rest);
    normalized
}

fn python_failure_identity(blob: &str) -> (String, String, Option<String>, String) {
    let mut detail = Vec::new();
    let mut fallback = Vec::new();
    let mut pending_frame = None;
    let mut primary_frame = None;
    let mut last_exception: Option<(String, String)> = None;
    let mut exception_continuation = false;
    let mut in_traceback = false;
    for raw in blob.lines() {
        let trimmed = raw.trim();
        // pytest prefixes exception diagnostics with "E   ". Keep their
        // assertion values and custom exception messages after removing it.
        let without_prefix = trimmed
            .strip_prefix("E ")
            .map(str::trim_start)
            .unwrap_or(trimmed);
        let normalized =
            normalize_python_object_addresses(&normalize_python_embedded_paths(without_prefix));
        let line = normalized.as_str();
        if line.is_empty() {
            continue;
        }
        if python_runner_noise(line) {
            exception_continuation = false;
            continue;
        }
        if let Some(test_id) = python_pytest_test_id(line) {
            let identity = format!("pytest test: {test_id}");
            fallback.push(identity.clone());
            if last_exception.is_some() {
                detail.push(identity);
                primary_frame = Some(test_id.clone());
            }
            pending_frame = Some(test_id);
            exception_continuation = false;
            continue;
        }
        if line == "Traceback (most recent call last):" {
            pending_frame = None;
            exception_continuation = false;
            in_traceback = true;
            continue;
        }
        if let Some(frame) = python_traceback_frame(line) {
            fallback.push(format!("source: {frame}"));
            pending_frame = Some(frame);
            exception_continuation = false;
            in_traceback = true;
            continue;
        }
        if let Some(frame) = python_pytest_location(line) {
            fallback.push(format!("source: {frame}"));
            if last_exception.is_some() {
                detail.push(format!("source: {frame}"));
                primary_frame = Some(frame.clone());
            }
            pending_frame = Some(frame);
            exception_continuation = false;
            continue;
        }
        if matches!(
            line,
            "During handling of the above exception, another exception occurred:"
                | "The above exception was the direct cause of the following exception:"
        ) {
            detail.push(line.to_string());
            pending_frame = None;
            exception_continuation = false;
            in_traceback = false;
            continue;
        }
        fallback.push(line.to_string());
        if in_traceback && raw.starts_with(char::is_whitespace) && !trimmed.starts_with("E ") {
            continue; // source excerpts and line/column carets are not exceptions
        }
        if let Some(kind) = python_exception_kind(line, in_traceback && !exception_continuation) {
            detail.push(format!(
                "source: {}\n{line}",
                pending_frame.as_deref().unwrap_or("")
            ));
            primary_frame = pending_frame.clone();
            last_exception = Some((kind.to_string(), line.to_string()));
            exception_continuation = true;
            in_traceback = false;
        } else if exception_continuation {
            // Multiline assertion values, exception notes and unfamiliar details
            // remain semantic. Never hash only a 200-character display prefix.
            detail.push(line.to_string());
        }
    }
    if let Some((kind, summary)) = last_exception {
        (kind, summary, primary_frame, detail.join("\n"))
    } else {
        let detail = fallback.join("\n");
        let summary = fallback
            .last()
            .cloned()
            .unwrap_or_else(|| "TestFailure".into());
        ("TestFailure".into(), summary, pending_frame, detail)
    }
}

/// Fetch phase: create a scenario-local venv, installing pip requirements when
/// the file contains more than blank/comment lines.
pub fn python_fetch_commands(
    workspace: &Path,
    upgrade: bool,
    scenario_id: &str,
) -> Result<Vec<CommandSpec>> {
    python_fetch_commands_with_image_pip(workspace, upgrade, scenario_id, false)
}

/// The opt-in path leaves pip/setuptools out of the test venv unless explicitly
/// required. The installer comes from the recorded Python image (pip >= 22.3).
pub fn python_fetch_commands_with_image_pip(
    workspace: &Path,
    upgrade: bool,
    scenario_id: &str,
    image_pip: bool,
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
    let mut install = if image_pip {
        // PATH points into the new venv, which deliberately has no pip. Select
        // the official Python image's interpreter explicitly for the installer.
        vec![
            "/usr/local/bin/python".into(),
            "-m".into(),
            "pip".into(),
            "--python".into(),
            py,
        ]
    } else {
        vec![py, "-m".into(), "pip".into()]
    };
    install.extend([
        "install".into(),
        "-q".into(),
        "--cache-dir".into(),
        cache,
        "-r".into(),
        "requirements.txt".into(),
    ]);
    if upgrade {
        install.push("--upgrade".into());
    }
    let mut create = vec!["python".into(), "-m".into(), "venv".into()];
    if image_pip {
        create.push("--without-pip".into());
    }
    create.push(venv.clone());
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
            argv: create,
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

    fn python_failure(stderr: &str) -> FailureSignature {
        PythonAdapter.normalize_failure(&RawExecutionResult {
            workspace_preparation: None,
            exit_code: Some(1),
            signal: None,
            duration_ms: 10,
            timed_out: false,
            stdout: String::new(),
            stderr: stderr.into(),
            network_used: false,
        })
    }

    fn unittest_import_failure(module: &str) -> String {
        format!(
            r#"dirtyjson.tests (unittest.loader._FailedTest) ... ERROR
======================================================================
ERROR: dirtyjson.tests (unittest.loader._FailedTest)
----------------------------------------------------------------------
ImportError: Failed to import test module: dirtyjson.tests
Traceback (most recent call last):
  File "/work/dirtyjson/attributed_containers.py", line 7, in <module>
    from collections import MutableMapping as DictMixin
ImportError: cannot import name 'MutableMapping' from 'collections'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/lib/python3.10/unittest/loader.py", line 470, in _find_test_path
    package = self._get_module_from_name(name)
  File "/work/dirtyjson/attributed_containers.py", line 11, in <module>
    from UserDict import DictMixin
ModuleNotFoundError: No module named '{module}'

----------------------------------------------------------------------
Ran 1 test in 0.000s

FAILED (errors=1)
"#
        )
    }

    #[test]
    fn unittest_import_wrappers_preserve_the_final_concrete_exception() {
        let first = python_failure(&unittest_import_failure("UserDict"));
        let second = python_failure(&unittest_import_failure("AnotherModule"));
        assert_eq!(first.kind, "ModuleNotFoundError");
        assert_eq!(
            first.summary,
            "ModuleNotFoundError: No module named 'UserDict'"
        );
        assert_eq!(
            first.primary_frame.as_deref(),
            Some("dirtyjson/attributed_containers.py::<module>")
        );
        assert_ne!(first.normalized_hash, second.normalized_hash);
        assert_ne!(
            first.normalized_hash,
            tomorrowci_core::sha256_str(
                "ImportError:ImportError: Failed to import test module: dirtyjson.tests"
            )
        );
    }

    #[test]
    fn chained_causes_remain_part_of_the_identity_even_with_the_same_final_exception() {
        let chain = |cause: &str| {
            format!(
            "Traceback (most recent call last):\n  File \"/work/loader.py\", line 8, in read\nValueError: {cause}\n\nThe above exception was the direct cause of the following exception:\n\nTraceback (most recent call last):\n  File \"/work/app.py\", line 9, in main\nRuntimeError: load failed"
        )
        };
        let first = python_failure(&chain("invalid number"));
        let second = python_failure(&chain("invalid encoding"));
        assert_eq!(first.summary, "RuntimeError: load failed");
        assert_eq!(first.summary, second.summary);
        assert_eq!(first.primary_frame.as_deref(), Some("app.py::main"));
        assert_ne!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn traceback_locations_ansi_and_unittest_timing_are_noise() {
        let first = python_failure("test_value (tests.Test.test_value) ... FAIL\nTraceback (most recent call last):\n  File \"/work/tests/test_value.py\", line 12, in test_value\n    self.assertEqual(actual, expected)\n\u{1b}[31mAssertionError: 1 != 2\u{1b}[0m\n\n----------------------------------------------------------------------\nRan 1 test in 0.001s\n\nFAILED (failures=1)");
        let second = python_failure("test_value (tests.Test.test_value) ... FAIL\nTraceback (most recent call last):\n  File \"C:\\temp\\tomorrowci-replay-456\\tests\\test_value.py\", line 99, column 3, in test_value\n    self.assertEqual(actual, expected)\nAssertionError: 1 != 2\n\n----------------------------------------------------------------------\nRan 1 test in 14.978s\n\nFAILED (failures=1)");
        assert_eq!(
            first.primary_frame.as_deref(),
            Some("tests/test_value.py::test_value")
        );
        assert_eq!(first.normalized_hash, second.normalized_hash);
        let third = python_failure("Traceback (most recent call last):\n  File \"/tmp/run-123/tests/test_value.py\", line 7, in test_value\nAssertionError: 1 != 2");
        assert_eq!(first.normalized_hash, third.normalized_hash);
    }

    #[test]
    fn same_exception_in_different_files_or_functions_is_distinct() {
        let diagnostic = |file: &str, function: &str| {
            format!(
            "Traceback (most recent call last):\n  File \"/work/{file}\", line 3, in {function}\nValueError: invalid input"
        )
        };
        let first = python_failure(&diagnostic("alpha.py", "parse"));
        assert_ne!(
            first.normalized_hash,
            python_failure(&diagnostic("beta.py", "parse")).normalized_hash
        );
        assert_ne!(
            first.normalized_hash,
            python_failure(&diagnostic("alpha.py", "load")).normalized_hash
        );
    }

    #[test]
    fn assertion_values_notes_and_long_messages_are_not_truncated_in_the_hash() {
        let first =
            python_failure("AssertionError: values differ\nExpected: [1, 2]\nActual: [1, 3]");
        let second =
            python_failure("AssertionError: values differ\nExpected: [1, 2]\nActual: [1, 4]");
        assert_eq!(first.kind, "AssertionError");
        assert_eq!(first.summary, "AssertionError: values differ");
        assert_ne!(first.normalized_hash, second.normalized_hash);
        let prefix = format!("AssertionError: {}", "x".repeat(220));
        let long_a = python_failure(&format!("{prefix} expected=42"));
        let long_b = python_failure(&format!("{prefix} expected=43"));
        assert_eq!(long_a.summary, long_b.summary);
        assert_ne!(long_a.normalized_hash, long_b.normalized_hash);
        assert_ne!(
            python_failure("E   AssertionError: assert 1 == 2").normalized_hash,
            python_failure("E   AssertionError: assert 3 == 2").normalized_hash
        );
    }

    #[test]
    fn object_addresses_are_noise_but_hex_assertion_values_are_semantic() {
        assert_eq!(
            python_failure("AssertionError: <Widget object at 0x7fff1234> is not ready")
                .normalized_hash,
            python_failure("AssertionError: <Widget object at 0xabcdef42> is not ready")
                .normalized_hash
        );
        assert_ne!(
            python_failure("AssertionError: expected 0x12").normalized_hash,
            python_failure("AssertionError: expected 0x13").normalized_hash
        );
    }

    #[test]
    fn pytest_assertions_ignore_only_location_numbers_and_runner_timing() {
        for exception in ["E   assert 3 == 4", "E   AssertionError: assert 3 == 4"] {
            let output = |line: u32, seconds: &str| {
                format!(
                "F                                                                        [100%]\n________________________________ test_function _________________________________\n\n    def test_function():\n>       assert 3 == 4\n{exception}\n\ntest_assert1.py:{line}: AssertionError\n=========================== short test summary info ============================\nFAILED test_assert1.py::test_function - assert 3 == 4\n============================== 1 failed in {seconds}s =============================="
            )
            };
            let first = python_failure(&output(6, "0.12"));
            let second = python_failure(&output(80, "4.91"));
            assert_eq!(first.normalized_hash, second.normalized_hash);
            assert_eq!(
                first.primary_frame.as_deref(),
                Some("test_assert1.py::test_function")
            );
            assert_ne!(
                first.normalized_hash,
                python_failure(&output(6, "0.12").replace("3 == 4", "3 == 5")).normalized_hash
            );
        }
        assert_eq!(
            python_failure("E   assert 1 == 2\n1 failed in 0.12s").normalized_hash,
            python_failure("E   assert 1 == 2\n1 failed in 9.87s").normalized_hash
        );
    }

    #[test]
    fn pytest_same_exception_in_different_tests_in_one_file_is_distinct() {
        let output = |test: &str| {
            format!(
            "E   AssertionError: wrong value\ntests/test_api.py:6: AssertionError\n=========================== short test summary info ============================\nFAILED tests/test_api.py::{test} - AssertionError: wrong value\n1 failed in 0.12s"
        )
        };
        let first = python_failure(&output("test_a"));
        let second = python_failure(&output("test_b"));
        assert_eq!(first.summary, second.summary);
        assert_eq!(
            first.primary_frame.as_deref(),
            Some("tests/test_api.py::test_a")
        );
        assert_ne!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn generated_scenario_roots_are_noise_in_frames_and_import_messages() {
        let output = |scenario: &str, package_file: &str, install_dir: &str| {
            format!(
            "Traceback (most recent call last):\n  File \"/work/.tomorrowci/scenarios/{scenario}/{install_dir}/{package_file}\", line 14, in load\nImportError: cannot import name 'value' from 'pkg' (/work/.tomorrowci/scenarios/{scenario}/{install_dir}/{package_file})"
        )
        };
        for install_dir in ["deps", "venv/lib/python3.13/site-packages"] {
            let first = python_failure(&output("full-candidate", "pkg/api.py", install_dir));
            let subset = python_failure(&output("ddmin-subset-2", "pkg/api.py", install_dir));
            assert_eq!(first.normalized_hash, subset.normalized_hash);
            assert_eq!(
                first.primary_frame,
                Some(format!("<scenario-state>/{install_dir}/pkg/api.py::load"))
            );
            assert_ne!(
                first.normalized_hash,
                python_failure(&output("full-candidate", "pkg/other.py", install_dir))
                    .normalized_hash
            );
        }
        assert_ne!(python_failure("Traceback (most recent call last):\n  File \"/opt/first/pkg.py\", line 2, in load\nValueError: bad data").normalized_hash, python_failure("Traceback (most recent call last):\n  File \"/opt/second/pkg.py\", line 2, in load\nValueError: bad data").normalized_hash);
    }

    #[test]
    fn unfamiliar_diagnostics_and_custom_exceptions_fail_closed() {
        assert_ne!(
            python_failure("loader stopped: invalid encoding").normalized_hash,
            python_failure("loader stopped: invalid number").normalized_hash
        );
        let custom = python_failure("Traceback (most recent call last):\n  File \"/work/app.py\", line 2, in main\npackage.CustomProblem: broken record");
        assert_eq!(custom.kind, "package.CustomProblem");
        assert_eq!(custom.summary, "package.CustomProblem: broken record");
    }

    #[test]
    fn timeout_is_not_reclassified_by_a_prior_logged_exception() {
        let signature = PythonAdapter.normalize_failure(&RawExecutionResult {
            workspace_preparation: None,
            exit_code: None,
            signal: None,
            duration_ms: 300_000,
            timed_out: true,
            stdout: String::new(),
            stderr: "ImportError: previous retry failed".into(),
            network_used: false,
        });
        assert_eq!(signature.kind, "Timeout");
        assert_eq!(signature.summary, "execution timed out");
        assert!(signature.primary_frame.is_none());
        assert_eq!(
            signature.normalized_hash,
            tomorrowci_core::sha256_str("python-failure-v2\nTimeout\n\nexecution timed out")
        );
    }

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
    fn image_pip_targets_the_fresh_venv_and_keeps_requirement_policy() {
        let dir = tempdir().unwrap();
        let requirements = "--require-hashes\n-r locked.txt\n";
        std::fs::write(dir.path().join("requirements.txt"), requirements).unwrap();
        for upgrade in [false, true] {
            let commands =
                python_fetch_commands_with_image_pip(dir.path(), upgrade, "baseline", true)
                    .unwrap();
            assert!(commands[2].argv.iter().any(|arg| arg == "--without-pip"));
            assert_eq!(
                &commands[3].argv[..5],
                [
                    "/usr/local/bin/python",
                    "-m",
                    "pip",
                    "--python",
                    "/work/.tomorrowci/scenarios/baseline/venv/bin/python",
                ]
            );
            assert!(commands[3]
                .argv
                .windows(2)
                .any(|args| args == ["-r", "requirements.txt"]));
            assert_eq!(
                commands[3].argv.iter().any(|arg| arg == "--upgrade"),
                upgrade
            );
            assert!(!commands[3]
                .argv
                .iter()
                .any(|arg| arg == "--system" || arg == "--break-system-packages"));
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("requirements.txt")).unwrap(),
            requirements
        );
        std::fs::write(dir.path().join("requirements.txt"), "# stdlib only\n").unwrap();
        let commands =
            python_fetch_commands_with_image_pip(dir.path(), false, "baseline", true).unwrap();
        assert!(commands.iter().all(|c| !c.network));
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
