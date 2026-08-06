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

## Status (through Milestone 2)

| Area | Status |
|------|--------|
| Domain model + config + verdict/horizon rules | Done |
| Budget planner + ddmin reduction | Done |
| Flaky vs FUTURE_FAIL classification | Done |
| Python detect + full scan pipeline | Done |
| Docker/Podman sandbox executor | Done (daemon required for live runs) |
| Evidence bundle + HTML/JSON report + replay scripts | Done |
| Scripted pipeline tests (no Docker) | Done — PASS |
| Live Docker e2e on fixtures | **BLOCKED** if Docker Desktop daemon is down |
| Node/Rust full execution | Milestone 3 |
| React report UI + Action dogfood | Milestone 4 |

## Quick start

```bash
cargo build -p tomorrowci-cli --release
./target/release/tomorrowci doctor
./target/release/tomorrowci scan fixtures/python-runtime-break
cargo test --workspace
```

**Security:** target code is **never** executed on the host by default. Use Docker/Podman.

## Configuration

See `.tomorrowci.yml` schema: `packages/schema/tomorrowci-config.schema.json`.

## License

Apache-2.0
