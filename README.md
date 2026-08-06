# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI finds the earliest **concrete** future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits **replayable evidence**.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## What it is / is not

| TomorrowCI | Not TomorrowCI |
|---|---|
| Tests against real runtime/dependency candidates | A dependency update PR bot |
| OBSERVED / SIMULATED / SCHEDULED_RISK / INCONCLUSIVE grades | Invented future APIs |
| Sandboxed execution (Docker/Podman) | Default host execution of untrusted code |
| Typed verdicts (`BLOCKED` ≠ `PASS`) | Collapsing everything into FAIL/PASS |

## Status (Milestone 0)

| Area | Status |
|------|--------|
| Domain model + config schema | Implemented |
| Verdict / horizon authorization rules | Implemented + unit tested |
| Adapter detection (Python / Node / Rust) | Implemented (detect only) |
| Sandbox policy + doctor | Implemented |
| Full scenario execution | **NOT_RUN** — Milestone 1 |
| HTML React report | Scaffold only — Milestone 1/4 |
| GitHub Action dogfood | Skeleton — Milestone 4 |

## Quick start (Milestone 0)

```bash
cargo build -p tomorrowci-cli --release
./target/release/tomorrowci doctor
./target/release/tomorrowci scan .
./target/release/tomorrowci init-action
```

**Requirements for later execution milestones:** Docker or Podman. Target repository code is **never** run on the host by default.

## Configuration

See `.tomorrowci.yml` schema: `packages/schema/tomorrowci-config.schema.json`.

## License

Apache-2.0
