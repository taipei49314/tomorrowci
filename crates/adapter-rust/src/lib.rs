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
        let stable_enabled = config
            .candidates
            .runtime
            .channels
            .iter()
            .any(|channel| channel == "stable");
        let preview_enabled = config
            .candidates
            .runtime
            .channels
            .iter()
            .any(|channel| channel == "preview" || channel == "nightly");

        // `rust:beta-bookworm` is not a published OCI reference. Keep the
        // declared-MSRV stable probe and the independently published nightly
        // preview image explicit instead of manufacturing an invalid tag.
        let versions = [("1.74", "stable"), ("nightly", "preview")];
        let mut out = Vec::new();
        for (i, (v, channel)) in versions.iter().enumerate() {
            if out.len() >= max {
                break;
            }
            if (*channel == "stable" && !stable_enabled)
                || (*channel == "preview" && !preview_enabled)
            {
                continue;
            }
            if *v == baseline.runtime.as_str() {
                continue;
            }
            out.push(Candidate {
                id: format!("rust-{}", v.replace('.', "")),
                axis: EnvironmentAxis::Runtime,
                label: format!("Rust {v} toolchain"),
                version: (*v).into(),
                channel: (*channel).into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{i:04}"),
                dependency_set: None,
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("rust:");
        let image = if tag == "nightly" {
            "rustlang/rust:nightly".into()
        } else {
            format!("rust:{tag}-bookworm")
        };
        Ok(EnvironmentSpec {
            image_tag: image.clone(),
            image: image.clone(),
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let state = format!("/work/.tomorrowci/scenarios/{}", scenario.id);
                let mut env = IndexMap::new();
                env.insert("CARGO_HOME".into(), format!("{state}/cargo"));
                env.insert("CARGO_TARGET_DIR".into(), format!("{state}/target"));
                env
            },
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: None,
            read_only_root: false,
            scenario_state_root: None,
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
        })
    }

    fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec![
                "cargo".into(),
                "test".into(),
                "--".into(),
                "--nocapture".into(),
            ]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        let argv = if config.project.test_command == "auto" {
            let mut argv = vec!["cargo".into(), "test".into()];
            if scenario.resolved_dependencies.is_some() {
                argv.extend(["--offline".into(), "--locked".into()]);
            }
            argv
        } else {
            argv
        };
        let mut commands = vec![
            CommandSpec {
                argv: vec!["rustc".into(), "--version".into(), "--verbose".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec!["cargo".into(), "--version".into(), "--verbose".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f Cargo.lock ]; then sha256sum Cargo.lock; else printf '%s\\n' 'Cargo.lock:ABSENT'; fi".into(),
                ],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
        ];
        commands.push(CommandSpec {
            argv,
            cwd: Some("/work".into()),
            network: false,
            phase: "test".into(),
        });
        Ok(commands)
    }

    fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature {
        let blob = strip_diagnostic_ansi(&format!("{}\n{}", result.stdout, result.stderr));
        let kind = if result.timed_out {
            "Timeout"
        } else if blob.contains("package.rust-version")
            || blob.contains("rust-version")
            || (blob.contains("requires rustc")
                && (blob.contains("cannot be built") || blob.contains("is not supported")))
        {
            "MsrvError"
        } else if blob.contains("error[E") {
            "CompileError"
        } else {
            "TestFailure"
        };
        let detail = if result.timed_out {
            "execution timed out".to_string()
        } else {
            rust_failure_detail(&blob)
        };
        let primary_frame = (!result.timed_out)
            .then(|| rust_primary_frame(&blob))
            .flatten();
        FailureSignature {
            kind: kind.into(),
            summary: detail.chars().take(200).collect(),
            // Compiler codes, messages and assertion values must agree, not just
            // the broad CompileError/TestFailure category. Version the contract
            // so historical coarse hashes cannot silently authorize a replay.
            normalized_hash: tomorrowci_core::sha256_str(&format!(
                "rust-failure-v2\n{kind}\n{}\n{detail}",
                primary_frame.as_deref().unwrap_or("")
            )),
            primary_frame,
        }
    }
}

fn strip_diagnostic_ansi(text: &str) -> String {
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

fn rust_error_header(line: &str) -> bool {
    line.starts_with("error:")
        || line.starts_with("error[")
        || (line.starts_with("thread '") && line.contains("panicked at"))
}

fn normalize_frame_path(raw: &str) -> String {
    let mut path = raw.trim().trim_start_matches("file://").replace('\\', "/");
    for _ in 0..2 {
        if let Some((file, number)) = path.rsplit_once(':') {
            if !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit()) {
                path = file.to_string();
            }
        }
    }
    for root in ["/work/", "/workspace/"] {
        if let Some(relative) = path.strip_prefix(root) {
            return normalize_relative_scenario_path(relative);
        }
    }
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate().skip(1) {
        let parent = parts[index - 1];
        let temporary_parent =
            parent.eq_ignore_ascii_case("tmp") || parent.eq_ignore_ascii_case("temp");
        if temporary_parent
            && (part.starts_with("run-") || part.starts_with("tomorrowci-replay-"))
            && index + 1 < parts.len()
        {
            return normalize_relative_scenario_path(&parts[index + 1..].join("/"));
        }
    }
    // Preserve an uncertain root rather than collapsing equally named modules.
    normalize_relative_scenario_path(path.trim_start_matches("./"))
}

fn is_generated_scenario_id(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn normalize_relative_scenario_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(".tomorrowci/scenarios/") {
        if let Some((scenario, relative)) = rest.split_once('/') {
            if is_generated_scenario_id(scenario) && !relative.is_empty() {
                return format!(".tomorrowci/scenarios/<scenario>/{relative}");
            }
        }
    }
    path.to_string()
}

/// Only the adapter-owned scenario directory varies across reduction runs.
/// Preserve package names, files and every path outside these exact roots.
fn normalize_generated_scenario_paths(text: &str) -> String {
    let mut normalized = text.to_string();
    for prefix in [
        "/work/.tomorrowci/scenarios/",
        "/workspace/.tomorrowci/scenarios/",
    ] {
        let mut output = String::with_capacity(normalized.len());
        let mut last = 0;
        for (start, _) in normalized.match_indices(prefix) {
            if start > 0
                && !normalized[..start].chars().next_back().is_some_and(|ch| {
                    ch.is_whitespace() || matches!(ch, '\'' | '"' | '(' | '[' | '=')
                })
            {
                continue;
            }
            let rest = &normalized[start + prefix.len()..];
            let Some((scenario, relative)) = rest.split_once('/') else {
                continue;
            };
            if !is_generated_scenario_id(scenario) || relative.is_empty() {
                continue;
            }
            output.push_str(&normalized[last..start]);
            output.push_str(".tomorrowci/scenarios/<scenario>/");
            last = start + prefix.len() + scenario.len() + 1;
        }
        output.push_str(&normalized[last..]);
        normalized = output;
    }
    normalized
}

fn rust_primary_frame(blob: &str) -> Option<String> {
    let lines: Vec<_> = blob.lines().map(str::trim).collect();
    let start = lines
        .iter()
        .position(|line| rust_error_header(line))
        .unwrap_or(0);
    for &line in &lines[start..] {
        if let Some(location) = line.strip_prefix("-->") {
            return Some(normalize_frame_path(location));
        }
        if line.starts_with("thread '") && line.ends_with(':') {
            if let Some((_, location)) = line.split_once("panicked at ") {
                return Some(normalize_frame_path(location.trim_end_matches(':')));
            }
        }
    }
    None
}

fn rust_failure_detail(blob: &str) -> String {
    let lines: Vec<_> = blob.lines().map(str::trim).collect();
    let start = lines
        .iter()
        .position(|line| rust_error_header(line))
        .unwrap_or(0);
    let mut details = Vec::new();
    let mut backtrace = false;
    for &line in &lines[start..] {
        if rust_error_header(line) {
            backtrace = false;
        }
        if line == "stack backtrace:" {
            backtrace = true;
            continue;
        }
        if backtrace
            || line.is_empty()
            || line.starts_with(":::")
            || line.starts_with("Compiling ")
            || line.starts_with("Checking ")
            || line.starts_with("Finished ")
            || line.starts_with("Running ")
            || line.starts_with("test result:")
            || line.starts_with("For more information about this error")
            || line.starts_with("note: run with `RUST_BACKTRACE")
        {
            continue;
        }
        if let Some(location) = line.strip_prefix("-->") {
            // Keep every diagnostic's module, not just its message. Line/column
            // and known disposable roots are noise; the relative file is not.
            details.push(format!("source: {}", normalize_frame_path(location)));
            continue;
        }
        if let Some(thread) = line.strip_prefix("thread '") {
            if let Some((name, rest)) = thread.split_once('\'') {
                if rest.contains("panicked at") && rest.ends_with(':') {
                    // PID and source location vary; thread/test identity does not.
                    details.push(format!("thread '{name}' panicked"));
                    continue;
                }
            }
        }
        let line = if let Some((gutter, content)) = line.split_once('|') {
            if !gutter.is_empty() && gutter.trim().chars().all(|c| c.is_ascii_digit()) {
                continue; // numbered source excerpt, not the compiler diagnostic
            }
            if gutter.trim().is_empty() {
                content.trim_start_matches([' ', '^'])
            } else {
                line
            }
        } else {
            line
        };
        if !line.is_empty() {
            details.push(line.to_string());
        }
    }
    // Retain all semantic payload, including expected/found types and left/right
    // assertion values. The 200-character display limit never truncates the hash.
    normalize_generated_scenario_paths(&details.join("\n"))
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

    #[test]
    fn stable_channel_does_not_manufacture_preview_tags() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.channels = vec!["stable".into()];
        cfg.candidates.runtime.max_versions = 3;
        let baseline = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidates = RustAdapter.candidates(&baseline, &cfg).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].version, "1.74");
        assert_eq!(candidates[0].channel, "stable");
    }

    #[test]
    fn preview_channel_uses_the_published_nightly_image() {
        let mut cfg = Config::default();
        cfg.candidates.runtime.channels = vec!["preview".into()];
        cfg.candidates.runtime.max_versions = 1;
        let baseline = Baseline {
            runtime: "1.83".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidate = RustAdapter.candidates(&baseline, &cfg).unwrap().remove(0);
        assert_eq!(candidate.version, "nightly");
        let scenario = Scenario {
            id: candidate.id,
            is_baseline: false,
            runtime: candidate.version,
            dependencies: "locked".into(),
            axes_changed: vec![EnvironmentAxis::Runtime],
            candidates: vec![],
            grade: EvidenceGrade::Observed,
            resolved_dependencies: None,
        };
        assert_eq!(
            RustAdapter
                .materialize(&scenario, Path::new("."))
                .unwrap()
                .image,
            "rustlang/rust:nightly"
        );
    }

    #[test]
    fn declared_msrv_failure_has_stable_signature() {
        let raw = RawExecutionResult {
            workspace_preparation: None,
            exit_code: Some(101),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: "error: package `rust-msrv-break v0.1.0 (/work)` cannot be built because it requires rustc 1.80 or newer, while the currently active rustc version is 1.74.1".into(),
            network_used: false,
        };

        let signature = RustAdapter.normalize_failure(&raw);
        assert_eq!(signature.kind, "MsrvError");
        assert_eq!(
            signature.normalized_hash,
            tomorrowci_core::sha256_str(&format!("rust-failure-v2\nMsrvError\n\n{}", raw.stderr))
        );
    }

    fn failure(stderr: &str) -> FailureSignature {
        RustAdapter.normalize_failure(&RawExecutionResult {
            workspace_preparation: None,
            exit_code: Some(101),
            signal: None,
            duration_ms: 10,
            timed_out: false,
            stdout: String::new(),
            stderr: stderr.into(),
            network_used: false,
        })
    }

    #[test]
    fn compiler_error_codes_and_messages_are_distinct() {
        let types = failure("error[E0308]: mismatched types");
        let missing = failure("error[E0425]: cannot find value `total` in this scope");
        assert_eq!(types.kind, missing.kind);
        assert_ne!(types.normalized_hash, missing.normalized_hash);
        assert_ne!(
            failure("error[E0425]: cannot find value `total` in this scope").normalized_hash,
            failure("error[E0425]: cannot find value `customer` in this scope").normalized_hash
        );
    }

    #[test]
    fn expected_and_found_types_are_part_of_the_failure() {
        let integer = failure("error[E0308]: mismatched types\n  --> /tmp/a/main.rs:10:2\n   |\n10 | let value: i32 = input;\n   |                  ^^^^^ expected `i32`, found `&str`");
        let boolean = failure("error[E0308]: mismatched types\n  --> /tmp/a/main.rs:10:2\n   |\n10 | let value: bool = input;\n   |                   ^^^^^ expected `bool`, found `&str`");
        assert_ne!(integer.normalized_hash, boolean.normalized_hash);
    }

    #[test]
    fn compiler_locations_ansi_and_build_timing_are_not_failure_identity() {
        let first = failure("\u{1b}[31merror[E0308]: mismatched types\u{1b}[0m\n  --> /tmp/run-123/src/main.rs:10:2\n   |\n10 | let value: i32 = input;\n   |                  ^^^^^ expected `i32`, found `&str`\nFinished test profile in 0.12s");
        let second = failure("error[E0308]: mismatched types\n  --> C:\\temp\\run-456\\src\\main.rs:99:4\n   |\n99 | let value: i32 = input;\n   |                   ^^^^^ expected `i32`, found `&str`\nFinished test profile in 9.87s");
        assert_eq!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn panic_assertion_values_survive_pid_and_backtrace_normalization() {
        let first = failure("thread 'balance_test' (123) panicked at /tmp/run-123/src/lib.rs:10:2:\nassertion `left == right` failed\n  left: 1\n right: 2\nstack backtrace:\n0: /tmp/run-123/src/lib.rs:10\n1: test::run");
        let same = failure("thread 'balance_test' (456) panicked at C:\\temp\\run-456\\src\\lib.rs:99:4:\nassertion `left == right` failed\n  left: 1\n right: 2\nstack backtrace:\n0: C:\\temp\\run-456\\src\\lib.rs:99\n1: test::run");
        let different = failure("thread 'balance_test' (123) panicked at /tmp/run-123/src/lib.rs:10:2:\nassertion `left == right` failed\n  left: 3\n right: 2");
        assert_eq!(first.normalized_hash, same.normalized_hash);
        assert_ne!(first.normalized_hash, different.normalized_hash);
    }

    #[test]
    fn legacy_inline_panic_messages_are_not_discarded() {
        assert_ne!(
            failure("thread 'main' panicked at 'alpha', src/main.rs:1:1").normalized_hash,
            failure("thread 'main' panicked at 'beta', src/main.rs:1:1").normalized_hash
        );
    }

    #[test]
    fn display_truncation_does_not_truncate_failure_identity() {
        let prefix = format!("error[E0001]: {}", "x".repeat(220));
        let first = failure(&format!("{prefix}alpha"));
        let second = failure(&format!("{prefix}beta"));
        assert_eq!(first.summary, second.summary);
        assert_ne!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn the_same_diagnostic_in_another_module_is_a_different_failure() {
        let billing = failure(
            "error[E0425]: cannot find value `total` in this scope\n --> /work/src/billing.rs:10:2",
        );
        let shipping = failure("error[E0425]: cannot find value `total` in this scope\n --> /work/src/shipping.rs:10:2");
        assert_eq!(billing.primary_frame.as_deref(), Some("src/billing.rs"));
        assert_ne!(billing.normalized_hash, shipping.normalized_hash);
    }

    #[test]
    fn unknown_absolute_roots_are_not_silently_merged() {
        assert_ne!(
            failure("error[E0425]: missing value\n --> /opt/billing/src/lib.rs:1:2")
                .normalized_hash,
            failure("error[E0425]: missing value\n --> /opt/shipping/src/lib.rs:1:2")
                .normalized_hash
        );
    }

    #[test]
    fn reduction_scenario_ids_do_not_change_dependency_error_identity() {
        let diagnostic = |root: &str, scenario: &str, file: &str| {
            failure(&format!(
                "error[E0425]: cannot find value `total` in this scope\n --> {root}/.tomorrowci/scenarios/{scenario}/cargo/registry/src/{file}:10:2\n note: dependency source '{root}/.tomorrowci/scenarios/{scenario}/cargo/registry/src/{file}'"
            ))
        };
        let full = diagnostic("/work", "deps-full", "alpha-1.0.0/src/lib.rs");
        let reduced = diagnostic("/workspace", "ddmin-2", "alpha-1.0.0/src/lib.rs");
        assert_eq!(full.normalized_hash, reduced.normalized_hash);
        assert_eq!(
            full.primary_frame.as_deref(),
            Some(".tomorrowci/scenarios/<scenario>/cargo/registry/src/alpha-1.0.0/src/lib.rs")
        );
        assert_ne!(
            full.normalized_hash,
            diagnostic("/work", "ddmin-2", "beta-1.0.0/src/lib.rs").normalized_hash
        );
        assert_ne!(
            full.normalized_hash,
            diagnostic("/work", "ddmin-2", "alpha-1.0.0/src/other.rs").normalized_hash
        );
        assert_ne!(
            diagnostic("/opt/work", "deps-full", "alpha-1.0.0/src/lib.rs").normalized_hash,
            diagnostic("/opt/work", "ddmin-2", "alpha-1.0.0/src/lib.rs").normalized_hash
        );
    }
}
