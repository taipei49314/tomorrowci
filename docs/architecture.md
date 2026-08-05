# Architecture

```text
                    ┌─────────────┐
                    │  CLI (apps) │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   runner    │  detect → plan → execute → evidence → report
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
      ┌─────────┐    ┌──────────┐    ┌──────────┐
      │ adapters│    │ sandbox  │    │ evidence │
      │ py/node │    │docker/   │    │ + report │
      │ rust    │    │podman    │    └──────────┘
      └────┬────┘    └──────────┘
           ▼
      ┌─────────┐
      │  core   │  config, planner, ddmin, verdicts, signatures
      └─────────┘
```

## Core principles

1. **Typed domain model** — verdicts are enums; the engine never greps ad-hoc terminal text for pass/fail authorization.
2. **Adapters do not run host shells** — they emit `CommandSpec` argument arrays for the sandbox.
3. **Planner is budget-aware** — baseline first, ordered single-axis candidates, optional pairwise + ddmin.
4. **Replay consumes manifests** — never regenerates a new plan from live discovery.
5. **Security is structural** — host execution is not a default code path.

## Crate map

| Crate | Responsibility |
|---|---|
| `tomorrowci-core` | Domain types, config, planner, ddmin, verdicts, redaction, path safety |
| `tomorrowci-sandbox` | Engine detect, image digest, `docker/podman run` with limits |
| `tomorrowci-adapters` | `EcosystemAdapter` trait |
| `tomorrowci-adapter-*` | Python (pip), Node (npm), Rust (cargo) |
| `tomorrowci-runner` | End-to-end orchestration |
| `tomorrowci-evidence` | Run directory, checksums, replay manifests |
| `tomorrowci-report` | JSON / SARIF / accessible HTML |
| `tomorrowci` (CLI) | User commands |

## Scenario flow

1. Snapshot repository (clone or copy worktree).
2. Detect ecosystem; `UNSUPPORTED` exits cleanly.
3. Require container engine; else `BLOCKED`.
4. Build baseline + candidates; plan under `max_scenarios`.
5. Execute with fetch/test network split; rerun failures.
6. Authorize breakage frontier (strict rules).
7. Write evidence + HTML/JSON reports.
