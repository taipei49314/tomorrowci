# TomorrowCI

> **Continuous Integration Against the Future.**

**One sentence:** TomorrowCI finds the earliest concrete future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits replayable evidence.

```text
Today’s green build is not evidence of tomorrow’s compatibility.
TomorrowCI turns future-facing compatibility into an executable, replayable claim.
```

[![CI](https://github.com/taipei49314/tomorrowci/actions/workflows/ci.yml/badge.svg)](https://github.com/taipei49314/tomorrowci/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](apps/cli)

**Public repo:** https://github.com/taipei49314/tomorrowci  
Related lab fixtures: [tomorrowci-lab](https://github.com/taipei49314/tomorrowci-lab)

---

## What it is (and is not)

| TomorrowCI is | TomorrowCI is not |
|---|---|
| A local-first scanner of **concrete** future runtimes & dependency sets | A Dependabot/Renovate clone |
| An evidence engine with **replay** | An LLM “will this break?” oracle |
| Secure-by-default (containers only) | A host-side test runner for untrusted code |

**No forecast without an executable scenario. No breakage claim without replayable evidence.**

### Evidence grades

| Grade | Meaning |
|---|---|
| **OBSERVED** | Reproduced on a concrete released or preview environment |
| **SIMULATED** | Reproduced under an explicit dependency/policy mutation |
| **SCHEDULED_RISK** | Derived from a published lifecycle date (not an executed failure) |
| **INCONCLUSIVE** | Insufficient or unstable evidence |

---

## Quick start

### Prerequisites

- Rust 1.75+ (`rustup`)
- Git
- **Docker** or **Podman** with a running daemon (required for `scan` / `replay`)
- For fixtures: images such as `python:3.9-bookworm`, `node:20-bookworm`, `rust:1.75-bookworm`

### Build

```bash
git clone https://github.com/taipei49314/tomorrowci.git
cd tomorrowci
cargo build -p tomorrowci --release
./target/release/tomorrowci doctor
```

### Measure then trust (recommended)

Build instruments first — never trust unverified green:

```bash
./target/release/tomorrowci measure all
# → .tomorrowci/measure/{bench,suite,claim-ledger,summary}.json + CLAIM_LEDGER.md
```

### Policy gate

```bash
tomorrowci policy <run-id>
tomorrowci policy <head-run-id> --base <base-run-id>
# exit 6 on FAIL — see docs/policy.md
```

### Compare horizons (PR / base vs head)

```bash
./target/release/tomorrowci scan . --evidence-root .tomorrowci   # note run-id A
# ... switch branch ...
./target/release/tomorrowci scan . --evidence-root .tomorrowci   # note run-id B
./target/release/tomorrowci compare <base-run-id> <head-run-id> --fail-on-regression
```

Earlier horizon on head = **regression** (exit 5 with `--fail-on-regression`).

### Backtest skeleton (commit sampling)

```bash
./target/release/tomorrowci backtest . --at 2025-01-01 --until 2026-08-01 --max-commits 5
```

Honest limit: applies **current** published candidates to historical source trees; does not time-travel package registries (see `docs/north-star.md`).

### Scan a repository

```bash
./target/release/tomorrowci scan .
./target/release/tomorrowci scan ./fixtures/python-runtime-break
./target/release/tomorrowci scan https://github.com/owner/repo
```

### Inspect, verify, explain, replay

```bash
./target/release/tomorrowci show <run-id>
./target/release/tomorrowci verify <run-id|run-path>
./target/release/tomorrowci explain <run-id>
./target/release/tomorrowci replay <run-id> --scenario <scenario-id>
./target/release/tomorrowci report <run-id> --format html
```

Evidence is written to `.tomorrowci/runs/<run-id>/` (JSON, logs, checksums,
HTML). New bundles use a v1 sealed, recursive SHA-256 inventory. `verify`
accepts either an explicit absolute/`./relative` bundle path or a run ID under
`<evidence-root>/runs/`. A bare selector is always a run ID, so an untrusted
directory in the current working directory cannot shadow it. A run ID must
resolve to a `run` bundle, and an explicit path is accepted only when the
verified bundle kind is also `run`; `scenario` and `generic` bundles cannot be
passed to this command. It exits `0` with a `PASS` line only when the exact
regular-file set, canonical paths, entry types, every digest, and the fixed
run/scenario cross-file identity checks verify. Verification failures exit `1`
(CLI usage errors exit `2`).

`verify` parses only the fixed inventory and typed evidence schemas; it never
executes replay scripts, recorded commands, target code, or containers. Legacy
unversioned checksum lists fail closed as `UnsealedLegacy`. A verification
`PASS` proves byte integrity and internal identity consistency relative to that
co-located inventory, not producer authenticity, claim correctness, or a
successful replay. It does not yet prove the two successful replay attempts
required to complete the Phase 1 acceptance criteria. See
[Report format](docs/report-format.md) for the exact contract.

Configured reports inside a sealed run are deterministically reconstructed
from that run's verified evidence model and compared byte for byte. Evidence
consumers retain the verified inventory generation and recheck bytes against
it when reading; bounded inventory, file-count, nesting, total-byte, individual
read, and typed-JSON limits fail closed. These checks detect observed changes
but do not create an atomic filesystem snapshot, so evidence directories must
not have concurrent writers while they are verified or consumed.

---

## Supported ecosystems (v0.1)

| Ecosystem | Manifests | Package manager | Notes |
|---|---|---|---|
| Python | `pyproject.toml`, `requirements.txt` | **pip** | Poetry/Pipenv-only → `UNSUPPORTED` |
| Node.js | `package.json`, `package-lock.json` | **npm** | Yarn/pnpm-only → `UNSUPPORTED` |
| Rust | `Cargo.toml`, `Cargo.lock` | **cargo** | stable / beta / nightly candidates |

Unsupported managers never silently fall back to unsafe guesses.

---

## Verdict model

```text
BASELINE_PASS       Baseline executed and passed
BASELINE_INVALID    Baseline failed — future comparisons not authorized
FUTURE_PASS         Candidate passed
FUTURE_FAIL         Candidate failed reproducibly
FLAKY               Inconsistent reruns
BLOCKED             Environment/execution could not complete
UNSUPPORTED         Outside supported contract
INCONCLUSIVE        Execution completed without causal evidence
```

A **breakage horizon** is emitted only when baseline passes, a first failure is rerun and stable, the prior candidate passed (or none exists), and replay + evidence exist. Otherwise:

> No observed breakage horizon within tested candidates.

`BLOCKED` / `UNSUPPORTED` / `INCONCLUSIVE` are **never** converted to `PASS`.

---

## Configuration

See [`.tomorrowci.yml` schema](packages/schema/config-v1.json) and the example:

```yaml
version: 1
project:
  ecosystem: auto
  test_command: auto
baseline:
  runtime: auto
  dependencies: locked
candidates:
  runtime:
    channels: [stable, preview]
    max_versions: 5
  dependencies:
    latest_allowed: true
    prerelease: false
execution:
  max_scenarios: 24
  timeout_seconds: 900
  reruns_on_failure: 2
sandbox:
  engine: auto          # docker | podman
  network: fetch-only   # fetch deps, then network=none for tests
```

---

## Security (honest summary)

- Target code runs **only** in Docker/Podman (no privileged mode, no docker.sock mounts).
- Disposable workspace copies — your repository is not mutated.
- Fetch phase may use network; test phase uses `network=none` by default.
- Host secrets and env are not forwarded (deny-list + allow-list).
- Residual risk: container escapes, malicious images, compromised registries — see [docs/threat-model.md](docs/threat-model.md).

**No telemetry by default. No required cloud account.**

---

## GitHub Action

```bash
./target/release/tomorrowci init-action
```

Generates a read-only workflow that builds TomorrowCI, runs doctor + fixture scans, uploads evidence artifacts, and writes a job summary. See [action/](action/).

---

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Measurement](docs/measurement.md)
- [North-star extensions](docs/north-star.md)
- [Adapter authoring](docs/adapter-authoring.md)
- [Report format](docs/report-format.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
