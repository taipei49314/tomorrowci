import { useEffect, useMemo, useState } from "react";
import type { ReportData, ScenarioVerdict, Verdict } from "./types";
import { VerdictBadge } from "./VerdictBadge";
import { escapeHtml } from "./escape";

declare global {
  interface Window {
    __TOMORROWCI_REPORT__?: ReportData;
  }
}

function runId(data: ReportData): string {
  const id = data.run.run_id;
  return typeof id === "string" ? id : id[0];
}

export function App({ initial }: { initial?: ReportData }) {
  const [data, setData] = useState<ReportData | null>(initial ?? null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initial) return;
    if (window.__TOMORROWCI_REPORT__) {
      setData(window.__TOMORROWCI_REPORT__);
      return;
    }
    fetch("./report.json")
      .then((r) => {
        if (!r.ok) throw new Error(`Failed to load report.json (${r.status})`);
        return r.json();
      })
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [initial]);

  const title = useMemo(() => (data ? `Run ${runId(data)}` : "TomorrowCI"), [data]);

  if (error) {
    return (
      <main>
        <h1>TomorrowCI Report</h1>
        <p role="alert">Could not load report data: {error}</p>
        <p className="muted">
          Open a CLI-generated report.html, or place report.json next to this app.
        </p>
      </main>
    );
  }
  if (!data) {
    return (
      <main>
        <h1>TomorrowCI Report</h1>
        <p className="muted">Loading…</p>
      </main>
    );
  }

  return (
    <main>
      <a className="sr-only" href="#matrix">
        Skip to matrix
      </a>
      <header>
        <p className="muted">TomorrowCI — Continuous Integration Against the Future</p>
        <h1>{title}</h1>
        <p>
          Repository: <strong>{data.run.repository.source}</strong> @{" "}
          <code>{data.run.repository.commit_sha ?? "unknown"}</code>
        </p>
      </header>

      <section className="panel" aria-labelledby="horizon-title">
        <h2 id="horizon-title">Breakage horizon</h2>
        <p>
          <strong>Observed horizon:</strong>{" "}
          {data.frontier.observed
            ? data.frontier.horizon_label ?? "unknown"
            : "No observed breakage horizon within tested candidates."}
        </p>
        <p className="muted">{data.frontier.explanation}</p>
        <div className="timeline" role="list" aria-label="Scenario timeline">
          {data.verdicts.map((v) => (
            <div className="chip" role="listitem" key={labelKey(v)}>
              <strong>{v.label}</strong> <VerdictBadge verdict={v.verdict} />
            </div>
          ))}
        </div>
      </section>

      <section className="panel" id="matrix" aria-labelledby="matrix-title">
        <h2 id="matrix-title">Scenario matrix</h2>
        <table>
          <caption className="sr-only">Scenarios and verdicts</caption>
          <thead>
            <tr>
              <th scope="col">Scenario</th>
              <th scope="col">Verdict</th>
              <th scope="col">Evidence grade</th>
              <th scope="col">Signature</th>
            </tr>
          </thead>
          <tbody>
            {data.verdicts.map((v) => (
              <tr key={labelKey(v)}>
                <td>{v.label}</td>
                <td>
                  <VerdictBadge verdict={v.verdict} />
                </td>
                <td>{String(v.evidence_grade)}</td>
                <td>
                  <code>{v.failure_signature?.summary ?? "—"}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel" aria-labelledby="evidence-title">
        <h2 id="evidence-title">Failure evidence</h2>
        <pre>{data.frontier.failure_signature?.summary ?? "No failure signature"}</pre>
        <p>
          Replay: <code>{data.frontier.replay_command ?? "n/a"}</code>
        </p>
        <p className="muted">
          Suspected cause is correlation only unless a higher evidence grade is stated.
        </p>
      </section>

      {/* escapeHtml used to prove XSS helper is exported for tests */}
      <span className="sr-only">{escapeHtml("<script>")}</span>
    </main>
  );
}

function labelKey(v: ScenarioVerdict): string {
  const id = v.scenario_id;
  return typeof id === "string" ? id : id[0] ?? v.label;
}

export function verdictClass(v: Verdict): string {
  if (v === "BASELINE_PASS" || v === "FUTURE_PASS") return "badge-pass";
  if (v === "BASELINE_INVALID" || v === "FUTURE_FAIL") return "badge-fail";
  if (v === "FLAKY") return "badge-flaky";
  return "badge-blocked";
}
