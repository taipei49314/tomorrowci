# Measurement harness

**Principle:** build instruments first, then trust behavior.

```bash
tomorrowci measure bench
tomorrowci measure suite --engine auto
tomorrowci measure all --engine docker
tomorrowci measure all --engine podman
```

## Outputs (default `.tomorrowci/measure/`)

| File | Content |
|---|---|
| `bench-report.json` | Micro-bench distributions + methodology |
| `suite-report.json` | Per-fixture scan results + claims |
| `claim-ledger.json` | Flat PASS/FAIL/BLOCKED/NOT_RUN/SKIP ledger |
| `CLAIM_LEDGER.md` | Human table |
| `summary.json` | Combined north-star trust summary |

`suite-report.json` and `summary.json` retain `engine_requested`; each sealed
run independently retains the resolved engine identity. An explicit Docker or
Podman request never falls back to the other engine.

## Claim statuses

| Status | Meaning |
|---|---|
| PASS | Expectation met with executed evidence |
| FAIL | Expectation violated under runnable conditions |
| BLOCKED | Infrastructure prevented execution (not a green check) |
| NOT_RUN | Dependent claim not evaluated |
| SKIP | Explicitly out of scope |

`BLOCKED` is never converted to `PASS`.

## Methodology notes

- CLI startup bench measures process spawn of `tomorrowci --version`, not container work.
- Planner/config benches are in-process microbenchmarks on a warm runtime.
- Fixture suite requires Docker/Podman; absence → BLOCKED claims.
- Do not publish invented SLA numbers; publish measured p50/p95 with method text.
- Required CI runs the complete six-fixture contract once with Docker and once
  with an explicit live Podman selection, then verifies every sealed run
  bundle.
