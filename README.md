# TomorrowCI

> **Continuous Integration Against the Future.**

**One sentence:** TomorrowCI finds the earliest concrete future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits replayable evidence.

```text
Today’s green build is not evidence of tomorrow’s compatibility.
TomorrowCI turns future-facing compatibility into an executable, replayable claim.
```

[![CI](https://github.com/taipei49314/tomorrowci/actions/workflows/ci.yml/badge.svg)](https://github.com/taipei49314/tomorrowci/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](apps/cli)

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

- Rust 1.85+ (`rustup`; enforced by CI against the locked dependency graph)
- Git
- **Docker** or **Podman** with a running daemon (required for `scan` / `replay`)
- For fixtures: images such as `python:3.9-bookworm`, `node:20-bookworm`, `rust:1.75-bookworm`

### Build

```bash
git clone https://github.com/taipei49314/tomorrowci.git
cd tomorrowci
cargo build --locked -p tomorrowci --release
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

### Historical backtest

```bash
./target/release/tomorrowci backtest . --at 2026-01-15 --until 2026-01-15 \
  --snapshot-registry fixtures/backtest-snapshots --max-commits 5
./target/release/tomorrowci backtest-verify .tomorrowci/backtests/<proof-id>
```

Backtests fail closed unless the selected historical commit has an exact,
content-addressed offline registry snapshot. `backtest-verify` performs a
non-executing recursive-seal and typed-identity readback of a downloaded proof;
it embeds the sealed run and registry snapshot, but not the historical source
bytes, and therefore establishes integrity and internal binding rather than
producer or source-commit authenticity. See
[Historical backtest](docs/historical-backtest.md).

### Scan a repository

```bash
./target/release/tomorrowci scan .
./target/release/tomorrowci scan ./fixtures/python-runtime-break
./target/release/tomorrowci scan https://github.com/owner/repo
```

Git source identity is fail-closed. Local commit/status metadata and remote
post-clone provenance are read only through bounded Git invocations that ignore
replacement refs, isolate ambient configuration and credentials, and override
repository fsmonitor and hook execution. A repository-configured executable
clean/process filter is `BLOCKED` before `status` can invoke it. On non-Unix
hosts, a tracked Git `100755` entry is also `BLOCKED` because its logical
executable mode cannot be faithfully represented; TomorrowCI does not label
that copy as an exact `GitCommit`. These checks do not provide an atomic
filesystem snapshot or defend against every malicious same-user pathname swap
during capture.

### Inspect, verify, explain, replay

```bash
./target/release/tomorrowci show <run-id>
./target/release/tomorrowci verify <run-id|run-path>
./target/release/tomorrowci explain <run-id>
./target/release/tomorrowci replay <run-id> --scenario <scenario-id>
./target/release/tomorrowci replay <run-id> --scenario <scenario-id> --workspace ./source
./target/release/tomorrowci verify .tomorrowci/replay-receipts/<run-id>/<scenario-id>/<receipt-id>
./target/release/tomorrowci replay-qualify --original-run .tomorrowci/runs/<run-id> <receipt-1> <receipt-2>
./target/release/tomorrowci report <run-id> --format html
```

Evidence is written to `.tomorrowci/runs/<run-id>/` (JSON, logs, checksums,
HTML). Current scans write v2 sealed, recursive SHA-256 inventories. The
verifier continues to accept v1 bundles for their legacy integrity and typed-
identity contract; historical unversioned checksum lists still fail closed as
`UnsealedLegacy`. `verify` accepts either an explicit absolute/`./relative`
bundle path or a run ID under `<evidence-root>/runs/`. A bare selector is always
a run ID, so an untrusted directory in the current working directory cannot
shadow it. A run ID must resolve to a `run` bundle. An explicit path may resolve
to a `run` bundle or a detached public replay receipt; `scenario`, generic, and
ordinary nested attempt bundles are rejected. A verified run exits `0` with a
`PASS` line. A receipt exits `0` with `PASS_INTERNAL`, which deliberately does
not assert that its embedded run inventory was ever a valid complete run.
Verification failures exit `1` (CLI usage errors exit `2`).

`verify` parses only the fixed inventory and typed evidence schemas; it never
executes replay scripts, recorded commands, target code, or containers. For a
v1 bundle, `PASS` proves byte integrity and internal identity consistency only.
For v2, it additionally checks the source snapshot, strict exact-replay
manifest, every preserved original attempt, nested replay-attempt bundles, and
the run/scenario qualification records. An observed frontier is accepted only
when the verifier recomputes receipt digests and confirms at least two
consecutive scan-time digest-pinned replays are equivalent to the selected
original attempt. `replay-qualify` separately requires exactly two distinct,
consecutive detached receipts plus the complete original run, verifies that run,
matches its inventory bytes and typed source/config/scenario/manifest/original
attempt to both receipts, and recomputes equivalence. Neither command
authenticates the producer or independently proves that the recorded execution
occurred.

The public `replay` command rechecks the sealed source tree and executes in a
fresh disposable workspace below a securely created system-temporary root, not
as a sibling inside the caller's source tree. Each accepted v2 invocation creates a new,
create-only `replay-attempt` receipt under
`<evidence-root>/replay-receipts/<run-id>/<scenario-id>/<receipt-id>/`; it never
appends to or reseals the original run. The terminal output includes one
`REPLAY_RECEIPT` JSON record with its path and sealed inventory digest. A
reproduced target failure is sealed before exit `3`, and a source, engine, or
execution block is sealed before exit `4`. Downloaded v2 evidence can use
`--workspace` with a different canonical checkout/copy only when its normalized
exact file set, tree digest, and sealed source identity all match. v1 evidence
still requires its recorded producer workspace. v2 supports the implicit
logical `/workspace` mount; additional explicit mounts fail closed as
`BLOCKED`, and general workdir/mount handling remains a sandbox boundary. See
[Report format](docs/report-format.md) for the exact contract.

Replay target failures use exit `3`, source/environment blocks use exit `4`,
and evidence/internal failures use exit `1`.

### Ecosystem weather map

```bash
./target/release/tomorrowci weather \
  --manifest ./weather-selection.json \
  --format json \
  --output .tomorrowci/weather-map.json
```

The manifest predeclares every selection unit and its denominator. Each named
run is verified before the evidence layer derives its inventory, source, and
typed-model digests; missing, blocked, unsupported, inconclusive, and flaky
units remain visible in the denominator. See
[Ecosystem weather map](docs/ecosystem-weather-map.md).

### Patch Lab

```bash
./target/release/tomorrowci patch propose <run-id> --source ./source --patch ./fix.patch
./target/release/tomorrowci patch verify --proof <proof-dir> \
  --original-run <original-run-dir> --patched-run <patched-run-dir>
```

Patch proposals run only in disposable copies. A verified qualifying proof
exits `0`; non-qualifying proposals exit `8`, blocked setup/safety exits `4`,
and malformed or unverifiable proof input exits `1`.

Configured reports inside a sealed run are deterministically reconstructed
from that run's verified evidence model and compared byte for byte. Evidence
consumers retain the verified inventory generation and recheck bytes against
it when reading; bounded inventory, file-count, nesting, total-byte, individual
read, and typed-JSON limits fail closed. These checks detect observed changes
but do not create an atomic filesystem snapshot, so evidence directories must
not have concurrent writers while they are verified or consumed.

---

## Supported ecosystems (v0.2)

This source tree reports version `0.2.0`. Release artifacts are published only
through the documented exact-candidate, independent-qualification, and
byte-identical promotion gates; consult GitHub Releases rather than inferring a
published tag from the source version.

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
  network: fetch-only   # upper bound: only an explicit Fetch command may connect
```

---

## Security (honest summary)

- Target code runs **only** in Docker/Podman (no privileged mode, no docker.sock mounts).
- Disposable workspace copies — your repository is not mutated.
- Before target commands start, the engine must confirm that the container has
  no attached network. A Fetch command connects only when its
  recorded `CommandSpec` requests network and the adapter environment plus
  `sandbox.network` both permit it; config can tighten, never expand, adapter
  policy. Engine connect/disconnect/status errors fail closed.
- Host secrets and env are not forwarded (deny-list + allow-list).
- Residual risk: container escapes, malicious images, compromised registries — see [docs/threat-model.md](docs/threat-model.md).

**No telemetry by default. No required cloud account.**

---

## GitHub Action

```bash
./target/release/tomorrowci init-action
```

Generates a read-only, repository-local workflow that uses `./action`, builds
TomorrowCI, scans, uploads evidence artifacts, and writes a job summary. It has
no job-level `continue-on-error`; advisory scan outcomes are handled explicitly
while internal errors fail. The generated file is safe only in a checkout that
actually contains TomorrowCI's `action/action.yml`; do not copy it alone into an
unrelated repository. See [action/](action/).

---

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Measurement](docs/measurement.md)
- [North-star extensions](docs/north-star.md)
- [Historical backtest](docs/historical-backtest.md)
- [Ecosystem weather map](docs/ecosystem-weather-map.md)
- [Patch Lab](docs/patch-lab.md)
- [Adapter SDK](docs/adapter-sdk.md)
- [Adapter authoring](docs/adapter-authoring.md)
- [Report format](docs/report-format.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
