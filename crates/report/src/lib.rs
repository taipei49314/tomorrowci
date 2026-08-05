//! Report generation: JSON, SARIF, and self-contained HTML.
//!
//! HTML embeds real run data (never mocked). XSS-safe via HTML escaping.

pub mod backtest_html;

use serde::Serialize;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tomorrowci_core::{
    safety::escape_html, BreakageFrontier, RunManifest, ScenarioVerdict, Verdict,
};

pub use backtest_html::write_backtest_html;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ReportError>;

#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub run: RunManifest,
    pub verdicts: Vec<ScenarioVerdict>,
    pub frontier: BreakageFrontier,
    pub plan: serde_json::Value,
    pub candidates: serde_json::Value,
}

pub fn write_json_report(path: &Path, data: &ReportData) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}

pub fn write_sarif_report(path: &Path, data: &ReportData) -> Result<()> {
    let mut results = Vec::new();
    for v in &data.verdicts {
        if matches!(v.verdict, Verdict::FutureFail | Verdict::BaselineInvalid) {
            let msg = v
                .failure_signature
                .as_ref()
                .map(|f| f.summary.clone())
                .unwrap_or_else(|| format!("{}: {:?}", v.label, v.verdict));
            results.push(serde_json::json!({
                "ruleId": "tomorrowci/future-fail",
                "level": "error",
                "message": { "text": msg },
                "properties": {
                    "scenarioId": v.scenario_id.0,
                    "verdict": format!("{:?}", v.verdict),
                    "evidenceGrade": format!("{:?}", v.evidence_grade),
                }
            }));
        }
    }
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TomorrowCI",
                    "informationUri": "https://github.com/tomorrowci/tomorrowci",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [{
                        "id": "tomorrowci/future-fail",
                        "shortDescription": { "text": "Future environment failure" },
                        "helpUri": "https://github.com/tomorrowci/tomorrowci/blob/main/docs/report-format.md"
                    }]
                }
            },
            "results": results
        }]
    });
    fs::write(path, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}

/// Generate accessible, self-contained HTML from real run data.
pub fn write_html_report(path: &Path, data: &ReportData) -> Result<()> {
    let json = serde_json::to_string(data)?;
    // Embed as JSON in script type application/json — escaped for script safety
    let json_safe = json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");

    let run_id = escape_html(&data.run.run_id.0);
    let repo = escape_html(&data.run.repository.source);
    let sha = escape_html(
        data.run
            .repository
            .commit_sha
            .as_deref()
            .unwrap_or("unknown"),
    );
    let horizon = if data.frontier.observed {
        escape_html(data.frontier.horizon_label.as_deref().unwrap_or("unknown"))
    } else {
        "No observed breakage horizon within tested candidates.".into()
    };

    let mut rows = String::new();
    for v in &data.verdicts {
        let badge = verdict_badge(v.verdict);
        let label = escape_html(&v.label);
        let grade = escape_html(&format!("{:?}", v.evidence_grade));
        let sig = v
            .failure_signature
            .as_ref()
            .map(|f| escape_html(&f.summary))
            .unwrap_or_else(|| "—".into());
        rows.push_str(&format!(
            r#"<tr>
              <td>{label}</td>
              <td><span class="badge {badge_class}" aria-label="{badge}">{badge}</span></td>
              <td>{grade}</td>
              <td><code>{sig}</code></td>
            </tr>"#,
            badge_class = badge_class(v.verdict),
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>TomorrowCI Report — {run_id}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #121a2b;
      --text: #e8eefc;
      --muted: #9db0d0;
      --pass: #1f9d55;
      --fail: #e53e3e;
      --flaky: #d69e2e;
      --blocked: #718096;
      --accent: #63b3ed;
      --border: #243049;
      --focus: #f6e05e;
    }}
    @media (prefers-reduced-motion: reduce) {{
      * {{ animation: none !important; transition: none !important; }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: ui-sans-serif, system-ui, Segoe UI, Roboto, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5;
    }}
    a {{ color: var(--accent); }}
    a:focus, button:focus, [tabindex]:focus {{ outline: 3px solid var(--focus); outline-offset: 2px; }}
    header, main, footer {{ max-width: 1100px; margin: 0 auto; padding: 1.25rem; }}
    header {{ border-bottom: 1px solid var(--border); }}
    h1 {{ font-size: 1.5rem; margin: 0 0 0.25rem; }}
    .muted {{ color: var(--muted); }}
    .panel {{
      background: var(--panel); border: 1px solid var(--border);
      border-radius: 12px; padding: 1rem; margin: 1rem 0;
    }}
    .grid {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .badge {{
      display: inline-block; min-width: 5.5rem; text-align: center;
      padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem;
      font-weight: 700; letter-spacing: 0.03em;
      border: 1px solid transparent;
    }}
    .badge-pass {{ background: rgba(31,157,85,0.15); color: #68d391; border-color: var(--pass); }}
    .badge-fail {{ background: rgba(229,62,62,0.15); color: #fc8181; border-color: var(--fail); }}
    .badge-flaky {{ background: rgba(214,158,46,0.15); color: #f6e05e; border-color: var(--flaky); }}
    .badge-blocked {{ background: rgba(113,128,150,0.15); color: #cbd5e0; border-color: var(--blocked); }}
    .timeline {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
    .chip {{
      border: 1px solid var(--border); border-radius: 8px; padding: 0.5rem 0.75rem;
      background: #0f1726; min-width: 8rem;
    }}
    .chip strong {{ display: block; font-size: 0.8rem; }}
    pre, code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    pre {{
      background: #0a0f18; border: 1px solid var(--border); border-radius: 8px;
      padding: 0.75rem; overflow: auto; max-height: 320px; white-space: pre-wrap;
    }}
    nav.toc ul {{ list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.75rem; }}
    nav.toc a {{ text-decoration: none; border-bottom: 1px dotted var(--accent); }}
    .sr-only {{
      position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
      overflow: hidden; clip: rect(0,0,0,0); border: 0;
    }}
  </style>
</head>
<body>
  <a class="sr-only" href="#main">Skip to content</a>
  <header>
    <p class="muted">TomorrowCI — Continuous Integration Against the Future</p>
    <h1>Run {run_id}</h1>
    <p>Repository: <strong>{repo}</strong> @ <code>{sha}</code></p>
    <nav class="toc" aria-label="Report sections">
      <ul>
        <li><a href="#horizon">Horizon</a></li>
        <li><a href="#matrix">Scenario matrix</a></li>
        <li><a href="#evidence">Failure evidence</a></li>
        <li><a href="#graph">Execution graph</a></li>
      </ul>
    </nav>
  </header>
  <main id="main">
    <section id="horizon" class="panel" aria-labelledby="horizon-title">
      <h2 id="horizon-title">Breakage horizon timeline</h2>
      <p><strong>Observed horizon:</strong> {horizon}</p>
      <p class="muted">{frontier_expl}</p>
      <div class="timeline" role="list" aria-label="Scenario timeline">
        {timeline}
      </div>
    </section>

    <section id="matrix" class="panel" aria-labelledby="matrix-title">
      <h2 id="matrix-title">Scenario matrix</h2>
      <table>
        <caption class="sr-only">Scenarios and verdicts</caption>
        <thead>
          <tr>
            <th scope="col">Scenario</th>
            <th scope="col">Verdict</th>
            <th scope="col">Evidence grade</th>
            <th scope="col">Signature</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </section>

    <section id="evidence" class="panel" aria-labelledby="evidence-title">
      <h2 id="evidence-title">Failure evidence</h2>
      <div class="grid">
        <div>
          <h3>Signature</h3>
          <pre>{fail_sig}</pre>
        </div>
        <div>
          <h3>Replay</h3>
          <pre>{replay}</pre>
          <p class="muted">Evidence grade and correlation only — not a proven root cause unless stated.</p>
        </div>
      </div>
    </section>

    <section id="graph" class="panel" aria-labelledby="graph-title">
      <h2 id="graph-title">Execution graph / planner decisions</h2>
      <pre id="plan-view"></pre>
    </section>
  </main>
  <footer class="muted">
    <p>Generated by TomorrowCI {version}. No telemetry. Local-first.</p>
  </footer>
  <script id="tomorrowci-data" type="application/json">{json_safe}</script>
  <script>
    (function() {{
      var el = document.getElementById('tomorrowci-data');
      var data = JSON.parse(el.textContent);
      var plan = document.getElementById('plan-view');
      plan.textContent = JSON.stringify(data.plan, null, 2);
    }})();
  </script>
</body>
</html>
"##,
        frontier_expl = escape_html(&data.frontier.explanation),
        timeline = build_timeline(&data.verdicts),
        fail_sig = escape_html(
            &data
                .frontier
                .failure_signature
                .as_ref()
                .map(|f| f.summary.clone())
                .or_else(|| {
                    data.verdicts
                        .iter()
                        .find(|v| v.verdict == Verdict::FutureFail)
                        .and_then(|v| v.failure_signature.as_ref().map(|f| f.summary.clone()))
                })
                .unwrap_or_else(|| "No failure signature".into())
        ),
        replay = escape_html(data.frontier.replay_command.as_deref().unwrap_or("n/a")),
        version = env!("CARGO_PKG_VERSION"),
    );

    fs::write(path, html)?;
    Ok(())
}

fn verdict_badge(v: Verdict) -> &'static str {
    v.short_label()
}

fn badge_class(v: Verdict) -> &'static str {
    match v {
        Verdict::BaselinePass | Verdict::FuturePass => "badge-pass",
        Verdict::BaselineInvalid | Verdict::FutureFail => "badge-fail",
        Verdict::Flaky => "badge-flaky",
        Verdict::Blocked | Verdict::Unsupported | Verdict::Inconclusive => "badge-blocked",
    }
}

fn build_timeline(verdicts: &[ScenarioVerdict]) -> String {
    let mut out = String::new();
    for v in verdicts {
        out.push_str(&format!(
            r#"<div class="chip" role="listitem">
              <strong>{}</strong>
              <span class="badge {}">{}</span>
              <span class="muted">{}</span>
            </div>"#,
            escape_html(&v.label),
            badge_class(v.verdict),
            verdict_badge(v.verdict),
            escape_html(&format!("{:?}", v.evidence_grade)),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;
    use tomorrowci_core::{
        EvidenceGrade, HostInfo, RepositorySnapshot, RunId, RunStatus, ScenarioId,
    };

    #[test]
    fn html_escapes_xss() {
        let d = tempdir().unwrap();
        let data = ReportData {
            run: RunManifest {
                run_id: RunId("test".into()),
                tool_version: "0.1.0".into(),
                started_at: Utc::now(),
                finished_at: None,
                repository: RepositorySnapshot {
                    source: "<script>alert(1)</script>".into(),
                    path: ".".into(),
                    commit_sha: Some("abc".into()),
                    branch: None,
                    is_remote: false,
                    workspace_copy: ".".into(),
                    captured_at: Utc::now(),
                },
                detection: None,
                baseline: None,
                config_hash: "x".into(),
                sandbox_engine: None,
                status: RunStatus::Completed,
                frontier: None,
                scenario_count: 0,
                host: HostInfo::default(),
            },
            verdicts: vec![ScenarioVerdict {
                scenario_id: ScenarioId::new("s"),
                label: "<img onerror=alert(1)>".into(),
                verdict: Verdict::FutureFail,
                evidence_grade: EvidenceGrade::Observed,
                attempts: 2,
                failure_signature: None,
                evidence: None,
                notes: vec![],
            }],
            frontier: BreakageFrontier {
                observed: false,
                horizon_label: None,
                scenario_id: None,
                axis: None,
                from_label: None,
                to_label: None,
                failure_signature: None,
                evidence_grade: None,
                replay_command: None,
                explanation: "<script>".into(),
            },
            plan: serde_json::json!({}),
            candidates: serde_json::json!([]),
        };
        let path = d.path().join("r.html");
        write_html_report(&path, &data).unwrap();
        let html = fs::read_to_string(path).unwrap();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;") || html.contains("\\u003c"));
    }
}
