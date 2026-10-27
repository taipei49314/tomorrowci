//! Node adapter (npm only in v0.1). yarn/pnpm => UNSUPPORTED.

use indexmap::IndexMap;
use std::path::Path;
use tomorrowci_adapters::{path_exists, DetectionResult, EcosystemAdapter};
use tomorrowci_core::{
    Baseline, Candidate, CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec,
    EvidenceGrade, FailureSignature, ProjectDetection, RawExecutionResult, Result, Scenario,
    TcError,
};

pub struct NodeAdapter;

impl EcosystemAdapter for NodeAdapter {
    fn name(&self) -> &'static str {
        "node"
    }

    fn detect(&self, repo: &Path) -> DetectionResult {
        let has_pkg = path_exists(repo, "package.json");
        let has_lock = path_exists(repo, "package-lock.json");
        let yarn = path_exists(repo, "yarn.lock");
        let pnpm = path_exists(repo, "pnpm-lock.yaml");
        let mut notes = Vec::new();
        if yarn && !has_lock {
            notes.push("yarn.lock without package-lock.json => yarn UNSUPPORTED in v0.1.".into());
        }
        if pnpm && !has_lock {
            notes.push(
                "pnpm-lock.yaml without package-lock.json => pnpm UNSUPPORTED in v0.1.".into(),
            );
        }
        // Supported when package.json exists and we are not forced onto yarn/pnpm-only.
        let supported = has_pkg && !(yarn && !has_lock) && !(pnpm && !has_lock);
        DetectionResult {
            supported,
            detection: ProjectDetection {
                ecosystem: if has_pkg {
                    Ecosystem::Node
                } else {
                    Ecosystem::Unknown
                },
                manifests: {
                    let mut m = Vec::new();
                    if has_pkg {
                        m.push("package.json".into());
                    }
                    if has_lock {
                        m.push("package-lock.json".into());
                    }
                    m
                },
                package_manager: "npm".into(),
                confidence: if supported { 0.9 } else { 0.0 },
                notes,
            },
        }
    }

    fn baseline(&self, _repo: &Path, config: &Config) -> Result<Baseline> {
        let runtime = if config.baseline.runtime == "auto" {
            "20".into()
        } else {
            config
                .baseline
                .runtime
                .trim_start_matches("node:")
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
        let baseline_major = baseline
            .runtime
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                TcError::Config(format!(
                    "Node baseline runtime must begin with a numeric major version: {:?}",
                    baseline.runtime
                ))
            })?;

        // Concrete, monotonically newer Node.js major tags. A runtime horizon
        // must never be authorized by silently testing an older runtime first.
        let versions = [18_u32, 20, 22, 24];
        let mut out = Vec::new();
        for v in versions {
            if out.len() >= max {
                break;
            }
            if v <= baseline_major {
                continue;
            }
            out.push(Candidate {
                id: format!("node{v}-locked"),
                axis: EnvironmentAxis::Runtime,
                label: format!("Node {v} + locked dependencies"),
                version: v.to_string(),
                channel: "stable".into(),
                grade_if_executed: EvidenceGrade::Observed,
                order_key: format!("{v:04}"),
                dependency_set: None,
            });
        }
        Ok(out)
    }

    fn materialize(&self, scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
        let tag = scenario.runtime.trim_start_matches("node:");
        let image = format!("node:{tag}");
        Ok(EnvironmentSpec {
            image_tag: image.clone(),
            image,
            image_digest: None,
            workdir: "/work".into(),
            env: {
                let mut env = IndexMap::new();
                env.insert(
                    "NODE_PATH".into(),
                    format!(
                        "/work/.tomorrowci/scenarios/{}/node-project/node_modules",
                        scenario.id
                    ),
                );
                env
            },
            network_mode: "none".into(),
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            user: Some("node".into()),
            read_only_root: false, // npm needs write for node_modules
            scenario_state_root: None,
            fetch_timeout_seconds: None,
            test_timeout_seconds: None,
            engine: None,
            engine_version: None,
        })
    }

    fn commands(&self, _scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>> {
        let argv = if config.project.test_command == "auto" {
            vec![
                "npm".into(),
                "test".into(),
                "--".into(),
                "--reporter".into(),
                "tap".into(),
            ]
        } else {
            config
                .project
                .test_command
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        // Prefer plain `npm test` for broadest fixture compatibility
        let argv = if config.project.test_command == "auto" {
            vec!["npm".into(), "test".into()]
        } else {
            argv
        };
        let mut commands = vec![
            CommandSpec {
                argv: vec!["node".into(), "--version".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec!["npm".into(), "--version".into()],
                cwd: Some("/work".into()),
                network: false,
                phase: "test".into(),
            },
            CommandSpec {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f package-lock.json ]; then sha256sum package-lock.json; else printf '%s\\n' 'package-lock.json:ABSENT'; fi".into(),
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
        } else if blob.contains("createCipher is not a function") {
            "RemovedRuntimeApi"
        } else if blob.contains("ERR_OSSL_EVP_UNSUPPORTED") {
            "OpenSslUnsupported"
        } else if blob.contains("ERR_REQUIRE_ESM") {
            "ErrRequireEsm"
        } else if blob.contains("Cannot find module") {
            "ModuleNotFound"
        } else if blob.contains("ERR!") {
            "NpmError"
        } else {
            "TestFailure"
        };
        let detail = if result.timed_out {
            "execution timed out".to_string()
        } else {
            node_failure_detail(&blob)
        };
        let primary_frame = (!result.timed_out)
            .then(|| node_primary_frame(&blob))
            .flatten();
        FailureSignature {
            kind: kind.into(),
            summary: detail.chars().take(200).collect(),
            // Hash the complete diagnostic, not its display prefix or error class.
            // Old class-only fingerprints deliberately cannot authorize new replays.
            normalized_hash: tomorrowci_core::sha256_str(&format!(
                "node-failure-v2\n{kind}\n{}\n{detail}",
                primary_frame.as_deref().unwrap_or("")
            )),
            primary_frame,
        }
    }
}

/// Remove terminal decoration, preserving Unicode and the actual error text.
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
                // Unknown escapes are not grounds for discarding diagnostic bytes.
                out.push('\u{1b}');
                out.push(other);
            }
            None => out.push('\u{1b}'),
        }
    }
    out
}

fn node_error_header(line: &str) -> bool {
    let Some((prefix, _)) = line.split_once(':') else {
        return false;
    };
    prefix.ends_with("Error")
        || prefix
            .split_once(" [")
            .is_some_and(|(name, _)| name.ends_with("Error"))
        || prefix == "error" // node:test TAP diagnostic block
}

/// Strip only known execution roots and numeric line/column suffixes. An unknown
/// absolute root stays in the fingerprint: uncertain relocation must diverge,
/// rather than merging equally named files from different directories.
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
            return relative.to_string();
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
            return parts[index + 1..].join("/");
        }
    }
    path.trim_start_matches("./").to_string()
}

fn node_primary_frame(blob: &str) -> Option<String> {
    let mut internal_frame = None;
    let lines: Vec<_> = blob.lines().map(str::trim).collect();
    // Select the same diagnostic as node_failure_detail. An earlier debug trace
    // must not supply the frame for an unrelated exception emitted afterwards.
    let start = lines
        .iter()
        .position(|line| node_error_header(line))
        .unwrap_or(0);
    for &line in &lines[start..] {
        let Some(frame) = line.strip_prefix("at ") else {
            continue;
        };
        let (function, location) = match frame.split_once(" (") {
            Some((function, location)) if location.ends_with(')') => {
                (Some(function), location.trim_end_matches(')'))
            }
            _ => (None, frame),
        };
        let location = normalize_frame_path(location);
        let normalized = function.map_or_else(
            || location.clone(),
            |function| format!("{function} ({location})"),
        );
        if location.starts_with("node:") || location == "native" {
            internal_frame.get_or_insert(normalized);
        } else {
            return Some(normalized);
        }
    }
    internal_frame
}

fn node_failure_detail(blob: &str) -> String {
    let lines: Vec<_> = blob.lines().map(str::trim).collect();
    // Prefer the error over npm banners and the source excerpt above an exception.
    // If there is no recognized diagnostic, retain the output rather than reduce
    // every unfamiliar failure to a shared "TestFailure" fingerprint.
    let start = lines
        .iter()
        .position(|line| node_error_header(line))
        .unwrap_or(0);
    let details: Vec<_> = lines[start..]
        .iter()
        .copied()
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("at ")
                && !line.starts_with("Node.js v")
                && !line.starts_with("duration_ms:")
                && !line.starts_with("# duration_ms ")
                && !line.starts_with("npm ERR! A complete log")
                && !line.starts_with("npm error A complete log")
        })
        .collect();
    // Numbers, actual/expected values, module paths and error codes remain part
    // of the identity. The primary frame is separately hashed; only the remainder
    // of the stack and explicit timing metadata vanish here.
    details.join("\n")
}

pub fn check_manager(manager: &str) -> Result<()> {
    if manager == "npm" {
        Ok(())
    } else {
        Err(TcError::Unsupported(format!(
            "Node package manager '{manager}' is UNSUPPORTED (v0.1 supports npm only)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_package_json() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert!(NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_only_unsupported() {
        let d = tempdir().unwrap();
        std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert!(!NodeAdapter.detect(d.path()).supported);
    }

    #[test]
    fn yarn_unsupported_manager() {
        assert!(check_manager("yarn").is_err());
    }

    #[test]
    fn runtime_candidates_are_strictly_newer_than_baseline() {
        let mut config = Config::default();
        config.candidates.runtime.max_versions = 3;
        let baseline = Baseline {
            runtime: "20.20.2".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let candidates = NodeAdapter.candidates(&baseline, &config).unwrap();
        let versions: Vec<_> = candidates
            .iter()
            .map(|candidate| candidate.version.as_str())
            .collect();
        assert_eq!(versions, vec!["22", "24"]);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.id != "node18-locked"));
    }

    #[test]
    fn non_numeric_runtime_baseline_is_rejected() {
        let mut config = Config::default();
        config.candidates.runtime.max_versions = 1;
        let baseline = Baseline {
            runtime: "current".into(),
            dependencies: "locked".into(),
            declared_by: "test".into(),
        };

        let error = NodeAdapter
            .candidates(&baseline, &config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("numeric major version"), "{error}");
    }

    #[test]
    fn removed_runtime_api_has_a_semantic_stable_signature() {
        let raw = RawExecutionResult {
            exit_code: Some(1),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: String::new(),
            stderr: "TypeError: crypto.createCipher is not a function".into(),
            network_used: false,
        };

        let signature = NodeAdapter.normalize_failure(&raw);
        assert_eq!(signature.kind, "RemovedRuntimeApi");
        assert!(signature.summary.contains("createCipher is not a function"));
        assert_eq!(
            signature.normalized_hash,
            tomorrowci_core::sha256_str(
                "node-failure-v2\nRemovedRuntimeApi\n\nTypeError: crypto.createCipher is not a function"
            )
        );
    }

    fn failure(stderr: &str) -> FailureSignature {
        NodeAdapter.normalize_failure(&RawExecutionResult {
            exit_code: Some(1),
            signal: None,
            duration_ms: 10,
            timed_out: false,
            stdout: String::new(),
            stderr: stderr.into(),
            network_used: false,
        })
    }

    #[test]
    fn different_errors_with_the_same_exit_and_class_are_not_the_same_failure() {
        let missing_name = failure("TypeError: customer.name is undefined");
        let missing_total = failure("TypeError: invoice.total is undefined");
        assert_eq!(missing_name.kind, missing_total.kind);
        assert_ne!(missing_name.normalized_hash, missing_total.normalized_hash);
        assert_ne!(
            failure("Error: Cannot find module 'alpha'").normalized_hash,
            failure("Error: Cannot find module 'beta'").normalized_hash
        );
    }

    #[test]
    fn assertion_values_and_the_full_message_are_part_of_the_identity() {
        let first = failure("AssertionError [ERR_ASSERTION]: Expected values to be equal\nactual: 1\nexpected: 2\noperator: strictEqual");
        let second = failure("AssertionError [ERR_ASSERTION]: Expected values to be equal\nactual: 3\nexpected: 2\noperator: strictEqual");
        assert_ne!(first.normalized_hash, second.normalized_hash);
        let prefix = format!("Error: {}", "x".repeat(220));
        let first = failure(&format!("{prefix}alpha"));
        let second = failure(&format!("{prefix}beta"));
        assert_eq!(first.summary, second.summary);
        assert_ne!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn ansi_stack_paths_and_timing_do_not_change_the_failure() {
        let first = failure("npm test banner\n\u{1b}[31mTypeError: customer.name is undefined\u{1b}[0m\n    at run (/tmp/run-123/test.js:10:2)\nduration_ms: 13.1\nNode.js v22.1.0");
        let second = failure("another banner\nTypeError: customer.name is undefined\n    at run (C:\\temp\\run-456\\test.js:99:4)\nduration_ms: 74.9\nNode.js v22.1.0");
        assert_eq!(first.normalized_hash, second.normalized_hash);
    }

    #[test]
    fn unfamiliar_failure_output_is_not_discarded() {
        assert_ne!(
            failure("check failed: balance 10 != 20").normalized_hash,
            failure("check failed: balance 30 != 20").normalized_hash
        );
    }

    #[test]
    fn the_same_error_in_another_file_or_function_is_a_different_failure() {
        let billing =
            failure("AssertionError: total differs\n at checkTotal (/work/src/billing.js:10:2)");
        let shipping =
            failure("AssertionError: total differs\n at checkTotal (/work/src/shipping.js:10:2)");
        let other_function =
            failure("AssertionError: total differs\n at checkTax (/work/src/billing.js:10:2)");
        assert_eq!(
            billing.primary_frame.as_deref(),
            Some("checkTotal (src/billing.js)")
        );
        assert_ne!(billing.normalized_hash, shipping.normalized_hash);
        assert_ne!(billing.normalized_hash, other_function.normalized_hash);
    }

    #[test]
    fn unknown_absolute_roots_are_not_silently_merged() {
        assert_ne!(
            failure("Error: failed\n at check (/opt/billing/index.js:1:2)").normalized_hash,
            failure("Error: failed\n at check (/opt/shipping/index.js:1:2)").normalized_hash
        );
    }

    #[test]
    fn an_earlier_debug_trace_does_not_replace_the_actual_error_frame() {
        let normalize = |file: &str| {
            NodeAdapter.normalize_failure(&RawExecutionResult {
                exit_code: Some(1),
                signal: None,
                duration_ms: 10,
                timed_out: false,
                stdout: "Trace: debug\n at trace (/work/helper.js:1:1)".into(),
                stderr: format!("Error: failed\n at check (/work/src/{file}.js:10:2)"),
                network_used: false,
            })
        };
        let first = normalize("a");
        let second = normalize("b");
        assert_eq!(first.primary_frame.as_deref(), Some("check (src/a.js)"));
        assert_eq!(second.primary_frame.as_deref(), Some("check (src/b.js)"));
        assert_ne!(first.normalized_hash, second.normalized_hash);
    }
}
