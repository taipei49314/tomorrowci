export type Verdict =
  | "BASELINE_PASS"
  | "BASELINE_INVALID"
  | "FUTURE_PASS"
  | "FUTURE_FAIL"
  | "FLAKY"
  | "BLOCKED"
  | "UNSUPPORTED"
  | "INCONCLUSIVE";

export interface ScenarioVerdict {
  scenario_id: { 0: string } | string;
  label: string;
  verdict: Verdict;
  evidence_grade: string;
  attempts: number;
  failure_signature?: { summary: string; fingerprint: string };
  notes: string[];
}

export interface BreakageFrontier {
  observed: boolean;
  horizon_label?: string;
  explanation: string;
  replay_command?: string;
  failure_signature?: { summary: string };
}

export interface ReportData {
  run: {
    run_id: { 0: string } | string;
    repository: { source: string; commit_sha?: string };
  };
  verdicts: ScenarioVerdict[];
  frontier: BreakageFrontier;
  plan: unknown;
  candidates: unknown;
}
