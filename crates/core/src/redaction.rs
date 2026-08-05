//! Secret redaction for logs and reports.

use regex::Regex;
use std::sync::OnceLock;

fn default_patterns() -> &'static Vec<Regex> {
    static PATS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Regex::new(r#"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?([^\s'"]+)"#)
                .unwrap(),
            Regex::new(r"ghp_[A-Za-z0-9]{20,}").unwrap(),
            Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").unwrap(),
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            Regex::new(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
        ]
    })
}

/// Redact known secret patterns from a log string.
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_string();
    for re in default_patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                if caps.name("0").is_some() || caps.len() >= 1 {
                    if caps.len() >= 3 {
                        format!("{}=[REDACTED]", &caps[1])
                    } else {
                        "[REDACTED]".to_string()
                    }
                } else {
                    "[REDACTED]".to_string()
                }
            })
            .to_string();
    }
    // Second pass for token-like patterns without capture groups
    out = out.replace("-----BEGIN RSA PRIVATE KEY-----", "[REDACTED PRIVATE KEY]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_api_key() {
        let s = "api_key=sk-abc123secret";
        let r = redact_secrets(s);
        assert!(r.contains("REDACTED"), "{r}");
        assert!(!r.contains("sk-abc123secret"));
    }

    #[test]
    fn redacts_gh_token() {
        let s = "token ghp_abcdefghijklmnopqrstuvwxyz012345";
        let r = redact_secrets(s);
        assert!(r.contains("REDACTED") || !r.contains("ghp_abcdefghijklmnop"));
    }
}
