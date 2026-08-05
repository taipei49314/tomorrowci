import type { Verdict } from "./types";
import { verdictClass } from "./App";

const LABELS: Record<Verdict, string> = {
  BASELINE_PASS: "PASS",
  BASELINE_INVALID: "FAIL",
  FUTURE_PASS: "PASS",
  FUTURE_FAIL: "FAIL",
  FLAKY: "FLAKY",
  BLOCKED: "BLOCKED",
  UNSUPPORTED: "UNSUPPORTED",
  INCONCLUSIVE: "INCONCLUSIVE",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`badge ${verdictClass(verdict)}`} aria-label={LABELS[verdict]}>
      {LABELS[verdict]}
    </span>
  );
}
