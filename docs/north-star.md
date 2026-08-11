# North-star extensions (v0.2)

## Done in-tree (instrumented)

| Capability | Command | Status |
|---|---|---|
| Measurement harness | `tomorrowci measure all` | Live — PASS/FAIL/BLOCKED ledger |
| Bounded parallel scenarios | config `execution.max_parallel` | Live — baseline serial, futures bounded concurrently |
| Horizon compare (base→head) | `tomorrowci compare <base> <head>` | Live — regression exit 5 |
| Policy fail-if gate | `tomorrowci policy <run>` | Live — exit 6 on FAIL |
| Historical source + registry snapshot backtest | `tomorrowci backtest --at --until --snapshot-registry ...` | Live — exact-date, content-addressed, offline or non-green |
| Downloaded backtest proof readback | `tomorrowci backtest-verify <proof>` | Live — recursive seal + typed identity verification |
| Ecosystem weather map | `tomorrowci weather --manifest ...` | Live — predeclared denominator and verified v2 inputs |
| Patch laboratory | `tomorrowci patch propose/verify` | Live — disposable application and detached proof |
| Adapter contract/conformance SDK | `tomorrowci-adapters` | Live — capability, safety, and built-in conformance checks |

## Honest limits

### Historical backtest

- Samples exact **repository commits** in a date range and selects a strict
  registry snapshot for each commit's UTC date.
- Snapshot manifests and payloads are content-addressed, bounded, staged into
  the source snapshot, and consumed with ecosystem-specific offline settings.
- A missing, late, invalid, or identity-mismatched snapshot is
  `INCONCLUSIVE`/`SCHEDULED_RISK`; it never falls back to today's live registry.
- TomorrowCI verifies supplied bytes and their binding. It does not assert that
  an operator-supplied snapshot is a complete historical registry mirror or
  authenticate its publisher.
- A downloaded proof embeds the sealed v2 run and complete registry snapshot,
  but deliberately does not republish the historical repository bytes. Its
  source manifest can be checked for internal consistency; authenticating that
  manifest against the named public commit still requires trusted publication
  provenance or a separately supplied source checkout.

### Compare

- Compares **already executed** run frontiers by order keys extracted from labels.
- Does not re-scan; pair with two `scan` invocations (for example base branch vs PR).

### Weather map

- Describes only the explicitly selected, predeclared units and time window.
- Never converts missing, blocked, unsupported, inconclusive, or flaky units to
  PASS, and does not estimate ecosystem adoption or prevalence.

### Patch Lab

- A qualifying proof demonstrates the declared patch workflow against its bound
  source/run identities; it is not a general proof of correctness or safety.
- Proposals remain separate from ordinary verdicts and never rewrite the sealed
  original evidence.

## Remaining trust/reach gates

- Public cross-platform and Podman acceptance evidence for the exact candidate
- Independent external adopter/auditor evidence bound to that candidate
- Authenticated producer provenance beyond SHA-256 integrity
- Broader registry-snapshot publishers and adapter ecosystem coverage
