//! Report generation: JSON / SARIF / accessible HTML (no untrusted raw HTML).

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

/// Strip ANSI CSI sequences from untrusted logs before display.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for x in chars.by_ref() {
                    if x.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

pub fn sanitize_log(s: &str) -> String {
    escape_html(&strip_ansi(s))
}

pub fn write_json_report(manifest: &RunManifest, out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(manifest)?)?;
    Ok(())
}

pub fn write_github_job_summary(manifest: &RunManifest, out: &Path) -> Result<()> {
    let mut md = String::new();
    md.push_str("## TomorrowCI\n\n");
    md.push_str(&format!("- **Run:** `{}`\n", manifest.run_id));
    md.push_str(&format!(
        "- **Ecosystem:** {:?}\n",
        manifest.detection.ecosystem
    ));
    md.push_str(&format!(
        "- **Frontier observed:** {}\n",
        manifest.frontier.observed
    ));
    if let Some(ref h) = manifest.frontier.horizon_label {
        md.push_str(&format!("- **Horizon:** `{h}`\n"));
    }
    md.push_str("\n| Scenario | Verdict | ms |\n|---|---|---:|\n");
    for r in &manifest.results {
        md.push_str(&format!(
            "| `{}` | {:?} | {} |\n",
            r.scenario_id, r.verdict, r.duration_ms
        ));
    }
    md.push_str("\n_BLOCKED/UNSUPPORTED/INCONCLUSIVE are never treated as PASS._\n");
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, md)?;
    Ok(())
}

/// Accessible static HTML report generated from real run data.
pub fn write_html_report(manifest: &RunManifest, out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }

    let mut rows = String::new();
    for r in &manifest.results {
        let (label, badge) = verdict_badge(r.verdict);
        let sc = manifest
            .plan
            .scenarios
            .iter()
            .find(|s| s.id == r.scenario_id);
        let axes = sc
            .map(|s| format!("{:?}", s.axes_changed))
            .unwrap_or_else(|| "[]".into());
        rows.push_str(&format!(
            "<tr tabindex=\"0\"><td><code>{}</code></td><td><span class=\"badge {}\" aria-label=\"verdict {}\">{}</span></td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&r.scenario_id),
            badge,
            label,
            label,
            axes,
            r.duration_ms
        ));
    }

    // Simple matrix: runtime vs deps from scenarios
    let mut matrix = String::from("<table aria-label=\"Scenario matrix\"><thead><tr><th scope=\"col\">Scenario</th><th scope=\"col\">Runtime</th><th scope=\"col\">Deps</th><th scope=\"col\">State</th></tr></thead><tbody>");
    for r in &manifest.results {
        let sc = manifest.plan.scenarios.iter().find(|s| s.id == r.scenario_id);
        let (rt, deps) = sc
            .map(|s| (s.runtime.as_str(), s.dependencies.as_str()))
            .unwrap_or(("?", "?"));
        let (label, badge) = verdict_badge(r.verdict);
        matrix.push_str(&format!(
            "<tr><th scope=\"row\"><code>{}</code></th><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
            escape_html(&r.scenario_id),
            escape_html(rt),
            escape_html(deps),
            badge,
            label
        ));
    }
    matrix.push_str("</tbody></table>");

    let frontier = if manifest.frontier.observed {
        format!(
            "<strong>Observed breakage horizon:</strong> <code>{}</code> (grade {:?})",
            escape_html(manifest.frontier.horizon_label.as_deref().unwrap_or("?")),
            manifest.frontier.grade
        )
    } else {
        "No observed breakage horizon within tested candidates.".into()
    };

    let notes: String = manifest
        .frontier
        .notes
        .iter()
        .map(|n| format!("<li>{}</li>", escape_html(n)))
        .collect();

    let plan_notes: String = manifest
        .plan
        .selection_notes
        .iter()
        .map(|n| format!("<li>{}</li>", escape_html(n)))
        .collect();

    // Use replace (not format!) so CSS colors and #anchors are not parsed as format args.
    let html = HTML_TEMPLATE
        .replace("{{RUN}}", &escape_html(&manifest.run_id))
        .replace(
            "{{ECO}}",
            &escape_html(&format!("{:?}", manifest.detection.ecosystem)),
        )
        .replace("{{TOOL}}", &escape_html(&manifest.tool_version))
        .replace("{{FRONTIER}}", &frontier)
        .replace("{{MATRIX}}", &matrix)
        .replace("{{ROWS}}", &rows)
        .replace("{{PLAN_NOTES}}", &plan_notes)
        .replace("{{NOTES}}", &notes);
    std::fs::write(out, html)?;
    Ok(())
}

const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TomorrowCI Report {{RUN}}</title>
<style>
:root { color-scheme: dark; }
body { font-family: system-ui, sans-serif; margin: 0; background: #0b1220; color: #e5eefc; line-height: 1.5; }
a:focus, button:focus, tr:focus { outline: 3px solid #fbbf24; outline-offset: 2px; }
header, main, footer { max-width: 960px; margin: 0 auto; padding: 1.25rem; }
h1 { color: #7dd3fc; margin-bottom: 0.25rem; }
.banner { background: #1e293b; padding: 1rem; border-radius: 8px; border-left: 4px solid #38bdf8; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #334155; padding: 0.5rem; text-align: left; }
th { background: #1e293b; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700; font-size: 0.85rem; }
.badge.pass { background: #14532d; color: #bbf7d0; }
.badge.fail { background: #7f1d1d; color: #fecaca; }
.badge.flaky { background: #713f12; color: #fde68a; }
.badge.blocked { background: #334155; color: #e2e8f0; }
.badge.other { background: #312e81; color: #c7d2fe; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
nav a { color: #7dd3fc; margin-right: 1rem; }
</style>
</head>
<body>
<a class="sr-only" href="#main">Skip to main content</a>
<header>
  <h1>TomorrowCI</h1>
  <p>Continuous Integration Against the Future.</p>
  <nav aria-label="Report sections">
    <a href="#horizon">Horizon</a>
    <a href="#matrix">Matrix</a>
    <a href="#results">Results</a>
    <a href="#planner">Planner</a>
  </nav>
</header>
<main id="main">
  <section class="banner" aria-labelledby="run-meta">
    <h2 id="run-meta" class="sr-only">Run metadata</h2>
    <p>Run <code>{{RUN}}</code> · Ecosystem <code>{{ECO}}</code> · Tool <code>{{TOOL}}</code></p>
    <p id="horizon">{{FRONTIER}}</p>
    <p><em>Evidence grades only — no LLM root-cause claims. Color is not the only verdict cue (text badges).</em></p>
  </section>

  <section aria-labelledby="matrix-h" id="matrix">
    <h2 id="matrix-h">Scenario matrix</h2>
    {{MATRIX}}
  </section>

  <section aria-labelledby="results-h" id="results">
    <h2 id="results-h">Results</h2>
    <table>
      <thead>
        <tr>
          <th scope="col">Scenario</th>
          <th scope="col">Verdict</th>
          <th scope="col">Axes</th>
          <th scope="col">Duration ms</th>
        </tr>
      </thead>
      <tbody>
{{ROWS}}
      </tbody>
    </table>
  </section>

  <section aria-labelledby="planner-h" id="planner">
    <h2 id="planner-h">Planner notes</h2>
    <ul>{{PLAN_NOTES}}</ul>
    <h3>Frontier notes</h3>
    <ul>{{NOTES}}</ul>
  </section>
</main>
<footer>
  <p>Read-only report derived from evidence bundle. Rebuild with <code>tomorrowci report</code>.</p>
</footer>
</body>
</html>
"##;

fn verdict_badge(v: Verdict) -> (&'static str, &'static str) {
    match v {
        Verdict::BaselinePass | Verdict::FuturePass => ("PASS", "pass"),
        Verdict::BaselineInvalid | Verdict::FutureFail => ("FAIL", "fail"),
        Verdict::Flaky => ("FLAKY", "flaky"),
        Verdict::Blocked => ("BLOCKED", "blocked"),
        Verdict::Unsupported => ("UNSUPPORTED", "other"),
        Verdict::Inconclusive => ("INCONCLUSIVE", "other"),
    }
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

    #[test]
    fn sanitize_strips_ansi_and_escapes() {
        let raw = "\u{1b}[31m<script>\u{1b}[0m";
        let s = sanitize_log(raw);
        assert!(!s.contains('\u{1b}'));
        assert!(!s.contains("<script>"));
        assert!(s.contains("&lt;script&gt;"));
    }

    #[test]
    fn xss_in_scenario_id_escaped_in_report() {
        use chrono::Utc;
        use indexmap::IndexMap;
        use tomorrowci_core::*;
        let mut m = RunManifest {
            run_id: "r".into(),
            tool_version: "0.1.0".into(),
            started_at: Utc::now(),
            finished_at: None,
            repository: RepositorySnapshot {
                source: ".".into(),
                path: ".".into(),
                commit_sha: None,
                is_disposable_copy: true,
            },
            config_hash: "x".into(),
            detection: ProjectDetection {
                ecosystem: Ecosystem::Python,
                manifests: vec![],
                package_manager: "pip".into(),
                confidence: 1.0,
                notes: vec![],
            },
            baseline: Baseline {
                runtime: "3.9".into(),
                dependencies: "locked".into(),
                declared_by: "t".into(),
            },
            plan: ExecutionPlan {
                plan_id: "p".into(),
                scenarios: vec![],
                selection_notes: vec!["note".into()],
                budget_max: 1,
            },
            results: vec![ExecutionResult {
                scenario_id: "<img onerror=alert(1)>".into(),
                attempt: 1,
                verdict: Verdict::FutureFail,
                exit_code: Some(1),
                duration_ms: 1,
                timed_out: false,
                failure: None,
                environment: EnvironmentSpec {
                    image: "x".into(),
                    image_digest: None,
                    workdir: "/w".into(),
                    env: IndexMap::new(),
                    network_mode: "none".into(),
                    memory_mb: 1,
                    cpus: 1.0,
                    pids_limit: 1,
                    user: None,
                    read_only_root: true,
                },
                commands: vec![],
            }],
            frontier: BreakageFrontier {
                observed: false,
                horizon_label: None,
                first_failing_scenario: None,
                last_passing_scenario: None,
                changed_axes: vec![],
                failure_signature: None,
                grade: EvidenceGrade::Inconclusive,
                replay_command: None,
                notes: vec!["<b>x</b>".into()],
            },
            evidence_root: ".".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.html");
        write_html_report(&m, &p).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains("<img onerror"));
        assert!(body.contains("&lt;img"));
        assert!(body.contains("aria-label"));
        assert!(body.contains("prefers-reduced-motion"));
        assert!(body.contains("tabindex"));
        let _ = m;
    }
}
