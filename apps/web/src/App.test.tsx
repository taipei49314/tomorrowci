import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { escapeHtml } from "./escape";
import type { ReportData } from "./types";

const sample: ReportData = {
  run: {
    run_id: "deadbeef",
    repository: { source: "fixtures/python-runtime-break", commit_sha: "abc123" },
  },
  verdicts: [
    {
      scenario_id: "baseline",
      label: "Python 3.9 + locked",
      verdict: "BASELINE_PASS",
      evidence_grade: "OBSERVED",
      attempts: 1,
      notes: [],
    },
    {
      scenario_id: "py310",
      label: "Python 3.10 + locked",
      verdict: "FUTURE_FAIL",
      evidence_grade: "OBSERVED",
      attempts: 2,
      failure_signature: {
        summary: "ImportError: cannot import name 'MutableMapping'",
        fingerprint: "abc",
      },
      notes: [],
    },
  ],
  frontier: {
    observed: true,
    horizon_label: "Python 3.10 + locked",
    explanation: "Observed breakage horizon at Python 3.10",
    replay_command: "tomorrowci replay deadbeef --scenario py310",
    failure_signature: { summary: "ImportError: cannot import name 'MutableMapping'" },
  },
  plan: {},
  candidates: [],
};

describe("App", () => {
  it("renders horizon from real-shaped data", () => {
    render(<App initial={sample} />);
    expect(screen.getByText(/Observed breakage horizon/i)).toBeTruthy();
    expect(screen.getAllByText(/Python 3.10 \+ locked/).length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText("FAIL").length).toBeGreaterThan(0);
  });

  it("supports keyboard focus target on skip link", () => {
    render(<App initial={sample} />);
    const skip = screen.getByText(/Skip to matrix/i);
    expect(skip.getAttribute("href")).toBe("#matrix");
  });
});

describe("XSS", () => {
  it("escapes script tags", () => {
    expect(escapeHtml("<script>alert(1)</script>")).toBe(
      "&lt;script&gt;alert(1)&lt;/script&gt;"
    );
  });
});
