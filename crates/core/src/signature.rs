//! Failure signature normalization from typed runner records.

use crate::domain::{EvidenceGrade, FailureSignature, RawExecutionResult};
use regex::Regex;
use std::sync::OnceLock;

fn import_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^(ImportError|ModuleNotFoundError):\s*(.+)$").unwrap())
}

fn rust_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"error(\[E\d+\])?:\s*(.+)").unwrap())
}

fn node_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(TypeError|ReferenceError|Error):\s*(.+)").unwrap())
}

/// Normalize raw execution output into a typed failure signature.
pub fn normalize_failure(result: &RawExecutionResult, grade: EvidenceGrade) -> FailureSignature {
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    let combined = strip_ansi(&combined);

    if result.timed_out {
        return FailureSignature {
            kind: "timeout".into(),
            summary: format!("execution timed out after {} ms", result.duration_ms),
            primary_error: Some("timeout".into()),
            fingerprint: FailureSignature::compute_fingerprint("timeout", "timeout", "timeout"),
            framework_hints: vec![],
            evidence_grade: grade,
        };
    }

    if let Some(err) = &result.error {
        let fp = FailureSignature::compute_fingerprint("blocked", err, err);
        return FailureSignature {
            kind: "blocked".into(),
            summary: err.clone(),
            primary_error: Some(err.clone()),
            fingerprint: fp,
            framework_hints: vec![],
            evidence_grade: EvidenceGrade::Inconclusive,
        };
    }

    if let Some(caps) = import_error_re().captures(&combined) {
        let kind = caps.get(1).map(|m| m.as_str()).unwrap_or("ImportError");
        let msg = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        let summary = format!("{kind}: {msg}");
        return FailureSignature {
            kind: kind.into(),
            summary: summary.clone(),
            primary_error: Some(summary.clone()),
            fingerprint: FailureSignature::compute_fingerprint(kind, msg, &summary),
            framework_hints: vec!["python".into()],
            evidence_grade: grade,
        };
    }

    // pytest / node assertion failures — keep the message, not only exit code
    if let Some(caps) = Regex::new(r"(?m)^E\s+AssertionError:\s*(.+)$")
        .ok()
        .and_then(|re| re.captures(&combined))
    {
        let msg = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        let summary = format!("AssertionError: {msg}");
        return FailureSignature {
            kind: "AssertionError".into(),
            summary: summary.clone(),
            primary_error: Some(summary.clone()),
            fingerprint: FailureSignature::compute_fingerprint("AssertionError", msg, &summary),
            framework_hints: vec!["pytest".into()],
            evidence_grade: grade,
        };
    }
    if combined.contains("AssertionError:") {
        let line = combined
            .lines()
            .find(|l| l.contains("AssertionError"))
            .unwrap_or("AssertionError")
            .trim();
        return FailureSignature {
            kind: "AssertionError".into(),
            summary: line.to_string(),
            primary_error: Some(line.to_string()),
            fingerprint: FailureSignature::compute_fingerprint("AssertionError", line, line),
            framework_hints: vec!["python".into()],
            evidence_grade: grade,
        };
    }
    if combined.contains("ERR_ASSERTION")
        || combined.contains("simulated dependency")
        || combined.contains("assert.fail")
    {
        // Prefer the assertion message line over stack frames like `node:assert:137`.
        let line = combined
            .lines()
            .map(str::trim)
            .find(|l| {
                l.contains("simulated dependency")
                    || (l.contains("AssertionError") && !l.starts_with("node:"))
                    || (l.contains("ERR_ASSERTION") && l.contains(':'))
            })
            .or_else(|| {
                combined.lines().map(str::trim).find(|l| {
                    !l.starts_with("node:")
                        && !l.starts_with("at ")
                        && (l.contains("fail") || l.contains("assert"))
                })
            })
            .unwrap_or("node assertion failed");
        return FailureSignature {
            kind: "AssertionError".into(),
            summary: line.to_string(),
            primary_error: Some(line.to_string()),
            fingerprint: FailureSignature::compute_fingerprint("AssertionError", line, line),
            framework_hints: vec!["node".into()],
            evidence_grade: grade,
        };
    }

    // Prefer rustc test panic messages over generic `error: test failed`.
    if let Some(line) = combined
        .lines()
        .map(str::trim)
        .find(|l| l.contains("toolchain break:") || l.starts_with("thread '") && l.contains("panicked"))
    {
        let summary = if line.contains("toolchain break:") {
            line.to_string()
        } else {
            combined
                .lines()
                .map(str::trim)
                .find(|l| l.contains("toolchain break:") || l.contains("panicked at"))
                .unwrap_or(line)
                .to_string()
        };
        // Also grab the next line if panic header
        let summary = if summary.contains("panicked at") {
            combined
                .lines()
                .map(str::trim)
                .find(|l| l.contains("toolchain break:") || l.contains("assertion failed"))
                .unwrap_or(&summary)
                .to_string()
        } else {
            summary
        };
        return FailureSignature {
            kind: "rust_test".into(),
            summary: summary.clone(),
            primary_error: Some(summary.clone()),
            fingerprint: FailureSignature::compute_fingerprint("rust_test", &summary, &summary),
            framework_hints: vec!["cargo-test".into()],
            evidence_grade: grade,
        };
    }
    if let Some(caps) = rust_error_re().captures(&combined) {
        let code = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let msg = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        // Skip uninformative cargo test wrappers when stdout has better detail
        if msg.starts_with("test failed") && combined.contains("toolchain break:") {
            let line = combined
                .lines()
                .map(str::trim)
                .find(|l| l.contains("toolchain break:"))
                .unwrap_or(msg);
            return FailureSignature {
                kind: "rust_test".into(),
                summary: line.to_string(),
                primary_error: Some(line.to_string()),
                fingerprint: FailureSignature::compute_fingerprint("rust_test", line, line),
                framework_hints: vec!["cargo-test".into()],
                evidence_grade: grade,
            };
        }
        let kind = format!("rust{code}");
        let summary = format!("rust{code}: {msg}");
        return FailureSignature {
            kind: kind.clone(),
            summary: summary.clone(),
            primary_error: Some(msg.into()),
            fingerprint: FailureSignature::compute_fingerprint(&kind, msg, &summary),
            framework_hints: vec!["rustc".into()],
            evidence_grade: grade,
        };
    }

    if let Some(caps) = node_error_re().captures(&combined) {
        let kind = caps.get(1).map(|m| m.as_str()).unwrap_or("Error");
        let msg = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        let summary = format!("{kind}: {msg}");
        return FailureSignature {
            kind: kind.into(),
            summary: summary.clone(),
            primary_error: Some(summary.clone()),
            fingerprint: FailureSignature::compute_fingerprint(kind, msg, &summary),
            framework_hints: vec!["node".into()],
            evidence_grade: grade,
        };
    }

    let exit = result
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "unknown".into());
    let summary = format!("process failed with exit code {exit}");
    let snippet: String = combined.chars().take(200).collect();
    FailureSignature {
        kind: "exit_nonzero".into(),
        summary: summary.clone(),
        primary_error: Some(snippet.clone()),
        fingerprint: FailureSignature::compute_fingerprint("exit_nonzero", &exit, &snippet),
        framework_hints: vec![],
        evidence_grade: grade,
    }
}

pub fn strip_ansi(s: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    re.replace_all(s, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_import_error() {
        let raw = RawExecutionResult {
            exit_code: Some(1),
            signal: None,
            stdout: String::new(),
            stderr: "ImportError: cannot import name 'MutableMapping'\n".into(),
            duration_ms: 10,
            timed_out: false,
            network_used: false,
            error: None,
        };
        let sig = normalize_failure(&raw, EvidenceGrade::Observed);
        assert_eq!(sig.kind, "ImportError");
        assert!(sig.summary.contains("MutableMapping"));
    }

    #[test]
    fn strips_ansi() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn timeout_signature() {
        let raw = RawExecutionResult {
            exit_code: None,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 900000,
            timed_out: true,
            network_used: false,
            error: None,
        };
        let sig = normalize_failure(&raw, EvidenceGrade::Observed);
        assert_eq!(sig.kind, "timeout");
    }
}
