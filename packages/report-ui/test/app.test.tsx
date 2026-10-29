import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../src/App";
import { sampleModel } from "./sample-model";

describe("interactive report", () => {
  it("keeps incomplete coverage visible in the attention view", async () => {
    const user = userEvent.setup();
    const model = structuredClone(sampleModel);
    model.scenarios[1].verdict = "COVERAGE_INCOMPLETE";
    model.scenarios[1].tone = "other";
    model.scenarios[1].failureSummary = "Test coverage incomplete: skipped=1";
    model.denominator.fail = 0;
    model.denominator.inconclusive = 1;
    render(<App model={model} />);
    await user.click(screen.getByRole("button", { name: "Needs attention" }));
    expect(screen.getByLabelText("verdict COVERAGE_INCOMPLETE")).toBeTruthy();
    expect(screen.getByText("Test coverage incomplete: skipped=1")).toBeTruthy();
    expect(screen.queryByLabelText("verdict FAIL")).toBeNull();
  });
  it("filters without changing recorded verdicts or order", async () => {
    const user = userEvent.setup();
    render(<App model={sampleModel} />);

    expect(screen.getByText("Showing 3 of 3")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "baseline" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Needs attention" }));
    expect(screen.getByText("Showing 2 of 3")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "baseline" })).toBeNull();
    expect(screen.getByRole("heading", { name: "node22" })).toBeTruthy();
    expect(screen.getByLabelText("verdict BLOCKED")).toBeTruthy();
  });

  it("keeps filters keyboard reachable and untrusted text inert", async () => {
    const user = userEvent.setup();
    render(<App model={sampleModel} />);
    const all = screen.getByRole("button", { name: "All" });
    all.focus();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Needs attention" }));
    expect(document.querySelector("img[data-xss]")).toBeNull();
    expect(screen.getByText(/<img data-xss onerror=alert\(1\)> remains text/)).toBeTruthy();
  });

  it("shows replay attempts and non-pass denominator states explicitly", () => {
    render(<App model={sampleModel} />);
    expect(screen.getByRole("heading", { name: "Replay attempts" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open result.json" }).getAttribute("href"))
      .toBe("scenarios/node22/replays/attempt-1/result.json");
    expect(screen.getByText("BLOCKED", { selector: "dt" })).toBeTruthy();
    expect(screen.getByText("NOT_RUN", { selector: "dt" })).toBeTruthy();
  });
});
