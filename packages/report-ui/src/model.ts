export const REPORT_MODEL_SCHEMA = "tomorrowci.report/v1" as const;

export type ReportVerdict =
  | "PASS"
  | "FAIL"
  | "FLAKY"
  | "BLOCKED"
  | "UNSUPPORTED"
  | "INCONCLUSIVE"
  | "COVERAGE_INCOMPLETE"
  | "NOT_RUN";

export type ReportTone = "pass" | "fail" | "flaky" | "blocked" | "other";

export interface ReportLink {
  label: string;
  href: string;
  description: string;
}

export interface ScenarioLinks {
  scenario: string;
  environment: string;
  result: string;
  replayDescriptor: string;
  replays: string;
}

export interface ReportScenario {
  order: number;
  id: string;
  isBaseline: boolean;
  runtime: string;
  dependencies: string;
  axesChanged: string[];
  verdict: ReportVerdict;
  tone: ReportTone;
  durationMs: number | null;
  testAttempts: number;
  image: string | null;
  imageDigest: string | null;
  failureKind: string | null;
  failureSummary: string | null;
  links: ScenarioLinks;
}

export interface ReplayAttempt {
  scenarioId: string;
  attempt: number;
  resultHref: string;
}

export interface ReportModel {
  schemaVersion: typeof REPORT_MODEL_SCHEMA;
  evidenceSchemaVersion: number;
  run: {
    id: string;
    toolVersion: string;
    ecosystem: string;
    source: string;
    commitSha: string | null;
    configHash: string;
    startedAt: string;
    finishedAt: string | null;
  };
  baseline: {
    runtime: string;
    dependencies: string;
    declaredBy: string;
  };
  frontier: {
    observed: boolean;
    authorization: "AUTHORIZED_BY_VERIFIED_FRONTIER" | "NOT_AUTHORIZED";
    horizonLabel: string | null;
    firstFailingScenario: string | null;
    lastPassingScenario: string | null;
    grade: string;
    changedAxes: string[];
    failureHash: string | null;
    failureSummary: string | null;
    replayCommand: string | null;
    notes: string[];
  };
  scenarios: ReportScenario[];
  replayAttempts: ReplayAttempt[];
  denominator: {
    total: number;
    pass: number;
    fail: number;
    flaky: number;
    blocked: number;
    unsupported: number;
    inconclusive: number;
    notRun: number;
  };
  evidenceLinks: ReportLink[];
}

type JsonObject = Record<string, unknown>;

function object(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonObject;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

function optionalString(value: unknown, label: string): string | null {
  if (value === null) return null;
  return string(value, label);
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function optionalInteger(value: unknown, label: string): number | null {
  if (value === null) return null;
  return integer(value, label);
}

function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((item, index) => string(item, `${label}[${index}]`));
}

function hasActiveOrAbsolutePrefix(href: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("/") || href.includes("\\");
}

function relativeHref(value: unknown, label: string): string {
  const href = string(value, label);
  if (href.trim() !== href || hasActiveOrAbsolutePrefix(href)) {
    throw new Error(`${label} must be a relative evidence link`);
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(href);
  } catch {
    throw new Error(`${label} contains invalid percent encoding`);
  }
  if (decoded.trim() !== decoded || hasActiveOrAbsolutePrefix(decoded)) {
    throw new Error(`${label} must be a relative evidence link`);
  }
  if (
    decoded
      .split(/[/?#]/)
      .some((component) => component === "." || component === "..") ||
    /[\u0000-\u001f\u007f]/.test(decoded)
  ) {
    throw new Error(`${label} contains an unsafe path component`);
  }
  return href;
}

function reportVerdict(value: unknown, label: string): ReportVerdict {
  const verdict = string(value, label);
  const allowed: ReportVerdict[] = [
    "PASS",
    "FAIL",
    "FLAKY",
    "BLOCKED",
    "UNSUPPORTED",
    "INCONCLUSIVE",
    "COVERAGE_INCOMPLETE",
    "NOT_RUN",
  ];
  if (!allowed.includes(verdict as ReportVerdict)) throw new Error(`${label} is not a known verdict`);
  return verdict as ReportVerdict;
}

function reportTone(value: unknown, label: string): ReportTone {
  const tone = string(value, label);
  const allowed: ReportTone[] = ["pass", "fail", "flaky", "blocked", "other"];
  if (!allowed.includes(tone as ReportTone)) throw new Error(`${label} is not a known tone`);
  return tone as ReportTone;
}

function scenarioLinks(value: unknown, label: string): ScenarioLinks {
  const source = object(value, label);
  return {
    scenario: relativeHref(source.scenario, `${label}.scenario`),
    environment: relativeHref(source.environment, `${label}.environment`),
    result: relativeHref(source.result, `${label}.result`),
    replayDescriptor: relativeHref(source.replayDescriptor, `${label}.replayDescriptor`),
    replays: relativeHref(source.replays, `${label}.replays`),
  };
}

function scenario(value: unknown, index: number): ReportScenario {
  const source = object(value, `scenarios[${index}]`);
  return {
    order: integer(source.order, `scenarios[${index}].order`),
    id: string(source.id, `scenarios[${index}].id`),
    isBaseline: boolean(source.isBaseline, `scenarios[${index}].isBaseline`),
    runtime: string(source.runtime, `scenarios[${index}].runtime`),
    dependencies: string(source.dependencies, `scenarios[${index}].dependencies`),
    axesChanged: strings(source.axesChanged, `scenarios[${index}].axesChanged`),
    verdict: reportVerdict(source.verdict, `scenarios[${index}].verdict`),
    tone: reportTone(source.tone, `scenarios[${index}].tone`),
    durationMs: optionalInteger(source.durationMs, `scenarios[${index}].durationMs`),
    testAttempts: integer(source.testAttempts, `scenarios[${index}].testAttempts`),
    image: optionalString(source.image, `scenarios[${index}].image`),
    imageDigest: optionalString(source.imageDigest, `scenarios[${index}].imageDigest`),
    failureKind: optionalString(source.failureKind, `scenarios[${index}].failureKind`),
    failureSummary: optionalString(source.failureSummary, `scenarios[${index}].failureSummary`),
    links: scenarioLinks(source.links, `scenarios[${index}].links`),
  };
}

export function parseReportModel(value: unknown): ReportModel {
  const source = object(value, "report model");
  if (source.schemaVersion !== REPORT_MODEL_SCHEMA) {
    throw new Error(`unsupported report model schema: ${String(source.schemaVersion)}`);
  }
  const run = object(source.run, "run");
  const baseline = object(source.baseline, "baseline");
  const frontier = object(source.frontier, "frontier");
  const denominator = object(source.denominator, "denominator");
  const authorization = string(frontier.authorization, "frontier.authorization");
  if (authorization !== "AUTHORIZED_BY_VERIFIED_FRONTIER" && authorization !== "NOT_AUTHORIZED") {
    throw new Error("frontier.authorization is invalid");
  }
  if (!Array.isArray(source.scenarios)) throw new Error("scenarios must be an array");
  if (!Array.isArray(source.replayAttempts)) throw new Error("replayAttempts must be an array");
  if (!Array.isArray(source.evidenceLinks)) throw new Error("evidenceLinks must be an array");

  return {
    schemaVersion: REPORT_MODEL_SCHEMA,
    evidenceSchemaVersion: integer(source.evidenceSchemaVersion, "evidenceSchemaVersion"),
    run: {
      id: string(run.id, "run.id"),
      toolVersion: string(run.toolVersion, "run.toolVersion"),
      ecosystem: string(run.ecosystem, "run.ecosystem"),
      source: string(run.source, "run.source"),
      commitSha: optionalString(run.commitSha, "run.commitSha"),
      configHash: string(run.configHash, "run.configHash"),
      startedAt: string(run.startedAt, "run.startedAt"),
      finishedAt: optionalString(run.finishedAt, "run.finishedAt"),
    },
    baseline: {
      runtime: string(baseline.runtime, "baseline.runtime"),
      dependencies: string(baseline.dependencies, "baseline.dependencies"),
      declaredBy: string(baseline.declaredBy, "baseline.declaredBy"),
    },
    frontier: {
      observed: boolean(frontier.observed, "frontier.observed"),
      authorization,
      horizonLabel: optionalString(frontier.horizonLabel, "frontier.horizonLabel"),
      firstFailingScenario: optionalString(frontier.firstFailingScenario, "frontier.firstFailingScenario"),
      lastPassingScenario: optionalString(frontier.lastPassingScenario, "frontier.lastPassingScenario"),
      grade: string(frontier.grade, "frontier.grade"),
      changedAxes: strings(frontier.changedAxes, "frontier.changedAxes"),
      failureHash: optionalString(frontier.failureHash, "frontier.failureHash"),
      failureSummary: optionalString(frontier.failureSummary, "frontier.failureSummary"),
      replayCommand: optionalString(frontier.replayCommand, "frontier.replayCommand"),
      notes: strings(frontier.notes, "frontier.notes"),
    },
    scenarios: source.scenarios.map(scenario),
    replayAttempts: source.replayAttempts.map((value, index) => {
      const replay = object(value, `replayAttempts[${index}]`);
      return {
        scenarioId: string(replay.scenarioId, `replayAttempts[${index}].scenarioId`),
        attempt: integer(replay.attempt, `replayAttempts[${index}].attempt`),
        resultHref: relativeHref(replay.resultHref, `replayAttempts[${index}].resultHref`),
      };
    }),
    denominator: {
      total: integer(denominator.total, "denominator.total"),
      pass: integer(denominator.pass, "denominator.pass"),
      fail: integer(denominator.fail, "denominator.fail"),
      flaky: integer(denominator.flaky, "denominator.flaky"),
      blocked: integer(denominator.blocked, "denominator.blocked"),
      unsupported: integer(denominator.unsupported, "denominator.unsupported"),
      inconclusive: integer(denominator.inconclusive, "denominator.inconclusive"),
      notRun: integer(denominator.notRun, "denominator.notRun"),
    },
    evidenceLinks: source.evidenceLinks.map((value, index) => {
      const link = object(value, `evidenceLinks[${index}]`);
      return {
        label: string(link.label, `evidenceLinks[${index}].label`),
        href: relativeHref(link.href, `evidenceLinks[${index}].href`),
        description: string(link.description, `evidenceLinks[${index}].description`),
      };
    }),
  };
}
