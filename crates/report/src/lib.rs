//! Report generation: JSON / SARIF / accessible HTML (no untrusted raw HTML).

mod model;

pub use model::{ReportModel, REPORT_MODEL_SCHEMA};

use model::build_report_model;
use serde_json::json;
use std::path::Path;
use tomorrowci_core::{Result, RunManifest, TcError, Verdict};

const REPORT_UI_JS: &str = include_str!("../assets/report-ui.js");
const REPORT_UI_CSS: &str = include_str!("../assets/report-ui.css");

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
    let manifest_root = manifest.evidence_root.as_path();
    let replay_root = if manifest_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == manifest.run_id)
        && manifest_root.is_dir()
    {
        Some(manifest_root)
    } else {
        out.parent()
    };
    write_html_report_with_replay_root(manifest, replay_root, out)
}

/// Render from a caller-verified evidence root. Transactional report writers
/// use this form when their output lives in a staging directory.
pub fn write_html_report_from_verified_root(
    manifest: &RunManifest,
    verified_run_root: &Path,
    out: &Path,
) -> Result<()> {
    write_html_report_with_replay_root(manifest, Some(verified_run_root), out)
}

fn write_html_report_with_replay_root(
    manifest: &RunManifest,
    replay_root: Option<&Path>,
    out: &Path,
) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }

    let report_model = build_report_model(manifest, replay_root)?;

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
        let digest = r
            .environment
            .image_digest
            .as_deref()
            .unwrap_or("(no digest)");
        let sig = r
            .failure
            .as_ref()
            .map(|f| f.normalized_hash.as_str())
            .unwrap_or("—");
        rows.push_str(&format!(
            "<tr tabindex=\"0\"><td><code>{}</code></td><td><span class=\"badge {}\" aria-label=\"verdict {}\">{}</span></td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>\n",
            escape_html(&r.scenario_id),
            badge,
            label,
            label,
            axes,
            escape_html(&r.environment.image),
            escape_html(digest),
            r.duration_ms
        ));
        let _ = sig; // signature listed in frontier section
    }

    // Simple matrix: runtime vs deps from scenarios
    let mut matrix = String::from("<table aria-label=\"Scenario matrix\"><thead><tr><th scope=\"col\">Scenario</th><th scope=\"col\">Runtime</th><th scope=\"col\">Deps</th><th scope=\"col\">Image digest</th><th scope=\"col\">State</th></tr></thead><tbody>");
    for r in &manifest.results {
        let sc = manifest
            .plan
            .scenarios
            .iter()
            .find(|s| s.id == r.scenario_id);
        let (rt, deps) = sc
            .map(|s| (s.runtime.as_str(), s.dependencies.as_str()))
            .unwrap_or(("?", "?"));
        let (label, badge) = verdict_badge(r.verdict);
        let digest = r
            .environment
            .image_digest
            .as_deref()
            .unwrap_or("(no digest)");
        matrix.push_str(&format!(
            "<tr><th scope=\"row\"><code>{}</code></th><td>{}</td><td>{}</td><td><code>{}</code></td><td><span class=\"badge {}\">{}</span></td></tr>",
            escape_html(&r.scenario_id),
            escape_html(rt),
            escape_html(deps),
            escape_html(digest),
            badge,
            label
        ));
    }
    matrix.push_str("</tbody></table>");

    let sig_html = manifest
        .frontier
        .failure_signature
        .as_ref()
        .map(|f| {
            format!(
                "<span class=\"fallback-detail\">Failure signature: <code>{}</code> — {}</span><span class=\"fallback-detail\">Replay: <code>{}</code></span>",
                escape_html(&f.normalized_hash),
                escape_html(&f.summary),
                escape_html(manifest.frontier.replay_command.as_deref().unwrap_or("n/a"))
            )
        })
        .unwrap_or_default();
    let frontier = if manifest.frontier.observed {
        format!(
            "<strong>Observed breakage horizon:</strong> <code>{}</code> (grade {:?}){sig_html}",
            escape_html(manifest.frontier.horizon_label.as_deref().unwrap_or("?")),
            manifest.frontier.grade
        )
    } else {
        format!("No observed breakage horizon within tested candidates.{sig_html}")
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

    let replay_attempts = if report_model.replay_attempts.is_empty() {
        "<p class=\"empty-state\">No canonical replay attempt directory was present when this report was generated.</p>".to_owned()
    } else {
        let items: String = report_model
            .replay_attempts
            .iter()
            .map(|attempt| {
                format!(
                    "<li><div><code>{}</code><span>Attempt {}</span></div><a href=\"{}\">Open result.json</a></li>",
                    escape_html(&attempt.scenario_id),
                    attempt.attempt,
                    escape_html(&attempt.result_href)
                )
            })
            .collect();
        format!("<ol class=\"replay-list\">{items}</ol>")
    };

    let d = &report_model.denominator;
    let denominator = format!(
        "<dl class=\"denominator\" aria-label=\"Scenario denominator\"><div><dt>PASS</dt><dd>{}</dd></div><div><dt>FAIL</dt><dd>{}</dd></div><div><dt>FLAKY</dt><dd>{}</dd></div><div><dt>BLOCKED</dt><dd>{}</dd></div><div><dt>UNSUPPORTED</dt><dd>{}</dd></div><div><dt>INCONCLUSIVE</dt><dd>{}</dd></div><div><dt>NOT_RUN</dt><dd>{}</dd></div></dl>",
        d.pass, d.fail, d.flaky, d.blocked, d.unsupported, d.inconclusive, d.not_run
    );

    let report_model_json = safe_json_for_script(&report_model)?;

    let escaped_run = escape_html(&manifest.run_id);
    let escaped_ecosystem = escape_html(&format!("{:?}", manifest.detection.ecosystem));
    let escaped_tool = escape_html(&manifest.tool_version);
    let replay_count = report_model.replay_attempts.len().to_string();
    let html = render_html_template_once(&[
        ("{{REPORT_UI_CSS}}", REPORT_UI_CSS),
        ("{{REPORT_UI_JS}}", REPORT_UI_JS),
        ("{{REPORT_MODEL}}", &report_model_json),
        ("{{RUN}}", &escaped_run),
        ("{{ECO}}", &escaped_ecosystem),
        ("{{TOOL}}", &escaped_tool),
        ("{{FRONTIER}}", &frontier),
        ("{{MATRIX}}", &matrix),
        ("{{ROWS}}", &rows),
        ("{{DENOMINATOR}}", &denominator),
        ("{{REPLAY_ATTEMPTS}}", &replay_attempts),
        ("{{REPLAY_COUNT}}", &replay_count),
        ("{{PLAN_NOTES}}", &plan_notes),
        ("{{NOTES}}", &notes),
    ])?;
    std::fs::write(out, html)?;
    Ok(())
}

/// Replace placeholders found in the trusted template exactly once. Replacement
/// values are never scanned as template syntax, so untrusted report text such
/// as `{{ROWS}}` remains data instead of becoming markup or corrupting JSON.
fn render_html_template_once(replacements: &[(&str, &str)]) -> Result<String> {
    let mut rendered = String::with_capacity(HTML_TEMPLATE.len());
    let mut remaining = HTML_TEMPLATE;

    while let Some(start) = remaining.find("{{") {
        rendered.push_str(&remaining[..start]);
        let placeholder = &remaining[start..];
        let end = placeholder.find("}}").ok_or_else(|| {
            TcError::InvalidState("unterminated HTML report template placeholder".into())
        })? + 2;
        let placeholder = &placeholder[..end];
        let replacement = replacements
            .iter()
            .find_map(|(candidate, value)| (*candidate == placeholder).then_some(*value))
            .ok_or_else(|| {
                TcError::InvalidState(format!(
                    "unknown HTML report template placeholder: {placeholder}"
                ))
            })?;
        rendered.push_str(replacement);
        remaining = &remaining[start + end..];
    }
    rendered.push_str(remaining);
    Ok(rendered)
}

fn safe_json_for_script<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TomorrowCI Report {{RUN}}</title>
<style>{{REPORT_UI_CSS}}</style>
</head>
<body>
<div id="report-root"></div>
<noscript>
<style>#report-root { display: none; }</style>
<div id="no-js-report">
<a class="sr-only" href="#main">Skip to main content</a>
<header>
  <p><strong>TomorrowCI</strong> — Continuous Integration Against the Future.</p>
  <h1>Run <code>{{RUN}}</code></h1>
  <nav aria-label="Report sections">
    <a href="#horizon">Horizon</a>
    <a href="#matrix">Matrix</a>
    <a href="#results">Results</a>
    <a href="#replays">Replays</a>
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
    {{DENOMINATOR}}
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
          <th scope="col">Image</th>
          <th scope="col">Digest</th>
          <th scope="col">Duration ms</th>
        </tr>
      </thead>
      <tbody>
{{ROWS}}
      </tbody>
    </table>
  </section>

  <section aria-labelledby="replays-h" id="replays">
    <h2 id="replays-h">Replay attempts</h2>
    <p>{{REPLAY_COUNT}} recorded.</p>
    {{REPLAY_ATTEMPTS}}
  </section>

  <section aria-labelledby="planner-h" id="planner">
    <h2 id="planner-h">Planner notes</h2>
    <ul>{{PLAN_NOTES}}</ul>
    <h3>Frontier notes</h3>
    <ul>{{NOTES}}</ul>
  </section>

  <section aria-labelledby="evidence-h" id="evidence">
    <h2 id="evidence-h">Evidence links</h2>
    <p>Relative paths under the run evidence root (open next to this report):</p>
    <ul>
      <li><a href="run.json">run.json</a></li>
      <li><a href="frontier.json">frontier.json</a></li>
      <li><a href="checksums.txt">checksums.txt</a></li>
      <li><a href="workspace-manifest.json">workspace-manifest.json</a></li>
      <li><a href="scenarios/">scenarios/</a> (environment, fetch/test phase, failure-signature, replay)</li>
    </ul>
  </section>
</main>
<footer>
  <p>Read-only report derived from evidence bundle. Rebuild with <code>tomorrowci report</code>.</p>
</footer>
</div>
</noscript>
<script id="report-data" type="application/json">{{REPORT_MODEL}}</script>
<script>{{REPORT_UI_JS}}</script>
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
        Verdict::CoverageIncomplete => ("COVERAGE_INCOMPLETE", "other"),
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
    fn untrusted_report_text_is_escaped_and_placeholders_stay_literal() {
        use chrono::Utc;
        use indexmap::IndexMap;
        use tomorrowci_core::*;
        let mut m = RunManifest {
            evidence_schema_version: 2,
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
                scenario_id:
                    "</script><script data-xss>window.xss=1</script><img onerror=alert(1)>".into(),
                attempt: 1,
                verdict: Verdict::FutureFail,
                exit_code: Some(1),
                duration_ms: 1,
                timed_out: false,
                failure: Some(FailureSignature {
                    kind: "LiteralPlaceholder".into(),
                    summary: "literal {{ROWS}} marker".into(),
                    normalized_hash: format!("sha256:{}", "a".repeat(64)),
                    primary_frame: None,
                }),
                environment: EnvironmentSpec {
                    image_tag: "x".into(),
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
                    scenario_state_root: None,
                    fetch_timeout_seconds: None,
                    test_timeout_seconds: None,
                    engine: None,
                    engine_version: None,
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
            identity: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.html");
        write_html_report(&m, &p).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains("<img onerror"));
        assert!(!body.contains("<script data-xss>"));
        assert!(body.contains("&lt;img"));
        assert!(body.contains("\\u003c/script\\u003e"));
        assert!(body.contains("aria-label"));
        assert!(body.contains("prefers-reduced-motion"));
        assert!(body.contains("tabindex"));

        let embedded = body
            .split_once("<script id=\"report-data\" type=\"application/json\">")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let model: serde_json::Value = serde_json::from_str(embedded).unwrap();
        assert_eq!(model["schemaVersion"], REPORT_MODEL_SCHEMA);
        assert_eq!(model["denominator"]["fail"], 1);
        assert_eq!(model["denominator"]["notRun"], 0);
        assert_eq!(model["scenarios"][0]["verdict"], "FAIL");
        assert_eq!(
            model["scenarios"][0]["failureSummary"],
            "literal {{ROWS}} marker"
        );

        m.results[0].scenario_id = "candidate".into();
        let run_root = dir.path().join("bundle");
        for attempt in [2, 1] {
            let attempt_root = run_root
                .join("scenarios/candidate/replays")
                .join(format!("attempt-{attempt}"));
            std::fs::create_dir_all(&attempt_root).unwrap();
            std::fs::write(attempt_root.join("result.json"), "{}\n").unwrap();
        }
        std::fs::create_dir_all(run_root.join("scenarios/candidate/replays/attempt-03")).unwrap();
        let staged = dir.path().join("staging/report.html");
        write_html_report_from_verified_root(&m, &run_root, &staged).unwrap();
        let replay_body = std::fs::read_to_string(staged).unwrap();
        let embedded = replay_body
            .split_once("<script id=\"report-data\" type=\"application/json\">")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let model: serde_json::Value = serde_json::from_str(embedded).unwrap();
        assert_eq!(model["replayAttempts"].as_array().unwrap().len(), 2);
        assert_eq!(model["replayAttempts"][0]["attempt"], 1);
        assert_eq!(model["replayAttempts"][1]["attempt"], 2);
    }
}
