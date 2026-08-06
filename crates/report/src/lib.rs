//! Report generation. HTML must escape untrusted log content.

use serde_json::json;
use std::path::Path;
use tomorrowci_core::{Result, RunManifest, Verdict};

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn write_json_report(manifest: &RunManifest, out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(manifest)?)?;
    Ok(())
}

/// Minimal static HTML shell for M0 (real React UI in later milestone).
/// Must never inject raw logs without escaping.
pub fn write_html_report(manifest: &RunManifest, out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut rows = String::new();
    for r in &manifest.results {
        let label = match r.verdict {
            Verdict::BaselinePass | Verdict::FuturePass => "PASS",
            Verdict::FutureFail | Verdict::BaselineInvalid => "FAIL",
            Verdict::Flaky => "FLAKY",
            Verdict::Blocked => "BLOCKED",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td><span class=\"v\">{}</span></td><td>{}</td></tr>",
            escape_html(&r.scenario_id),
            label,
            r.duration_ms
        ));
    }
    let frontier = if manifest.frontier.observed {
        format!(
            "Observed breakage horizon: {}",
            escape_html(manifest.frontier.horizon_label.as_deref().unwrap_or("?"))
        )
    } else {
        "No observed breakage horizon within tested candidates.".into()
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>TomorrowCI Report {run}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0b1220; color: #e5eefc; }}
 h1 {{ color: #7dd3fc; }}
 .banner {{ background: #1e293b; padding: 1rem; border-radius: 8px; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
 th, td {{ border: 1px solid #334155; padding: 0.5rem; text-align: left; }}
 .v {{ font-weight: 700; }}
</style>
</head>
<body>
<main>
<h1>TomorrowCI</h1>
<p class="banner">Continuous Integration Against the Future.<br/>
Run <code>{run}</code><br/>
{frontier}<br/>
<em>Evidence grade labels only; no LLM root-cause claims.</em>
</p>
<table>
<thead><tr><th>Scenario</th><th>Verdict</th><th>Duration ms</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</main>
</body>
</html>
"#,
        run = escape_html(&manifest.run_id),
        frontier = frontier,
        rows = rows
    );
    std::fs::write(out, html)?;
    Ok(())
}

pub fn write_sarif_stub(manifest: &RunManifest, out: &Path) -> Result<()> {
    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": { "name": "TomorrowCI", "version": manifest.tool_version } },
            "results": manifest.results.iter().filter(|r| matches!(r.verdict, Verdict::FutureFail)).map(|r| json!({
                "ruleId": "future-fail",
                "level": "error",
                "message": { "text": format!("Scenario {} FUTURE_FAIL", r.scenario_id) }
            })).collect::<Vec<_>>()
        }]
    });
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_xss() {
        let s = escape_html("<script>alert(1)</script>");
        assert!(!s.contains("<script>"));
        assert!(s.contains("&lt;script&gt;"));
    }
}
