# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI aims to find the earliest **concrete** future environment in which a
repository stops building or passing tests, isolate the smallest
breakage-inducing change, and emit **replayable evidence**. The currently
demonstrated public slices are the Python, Node, and Rust runtime paths plus a
bounded Linux Docker dependency-reduction path for pip, npm, and cargo; wider
product surfaces remain explicit qualification work.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**Current checkout: local recovery, 2026-10-28.** Start with the bounded
[Python Docker trial](docs/PYTHON_TRIAL.md): choose the baseline and candidate
versions explicitly, run your own tests, verify the evidence, then replay.
This checkout is not a new published release. The historical GitHub repositories
returned 404 during the recovery audit; the release links below are historical
references, not verified current download locations.

The recovery rejects mixed runtime/concrete-dependency experiments instead of
running a candidate under the baseline image. Python/Node/Rust failure fingerprints
now distinguish concrete diagnostics; rescan with this checkout before replaying
old failures whose fingerprints used the previous algorithm. See the trial guide
for limits, including known candidate coverage and dependency reproducibility.

For Python dependency upgrades, [import two exact pin snapshots](docs/PYTHON_DEPENDENCIES.md).
The wheel-backed v2 path preserves the full dependency closure, runs installations
and tests offline, and adaptively reduces 1–64 changed packages within the chosen
scenario budget. It proves an observed **1-minimal** failing subset when the
required addition/subtraction checks complete; it does not claim a globally
smallest set or treat a blocked installation as proof of causality. The original
vendored-tree v1 protocol remains available for historical fixtures.

### Historical qualification (not a validation of this checkout)

**TomorrowCI is an experimental pre-alpha architecture. The exact
[`v0.2.0-alpha.1`](https://github.com/taipei49314/tomorrowci-lab/releases/tag/v0.2.0-alpha.1)
candidate was distributed as an immutable, project-operated prerelease for
external testing; broader product qualification was incomplete.**

The prerelease contains the deterministic candidate built from exact source
`f83d43235c4d03ea9a95fc048d3edbd582e8f438`, plus bounded M2/M3 Linux Docker
observations, M4 engineering slices, and project-owned exact-SHA
Python/Node/Rust observations on hosted Linux Docker and Podman. Its frozen
manifest remains explicitly `CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED`: public
distribution is not a platform-support claim, independent adoption, external
authorization, protected formal promotion, or published GHCR image.

The current live baseline, historical tag identities, clean-download checks,
and honest blockers are recorded in
[`docs/qualification/BASELINE.md`](docs/qualification/BASELINE.md). The
run-bound current record is
[`docs/qualification/STATUS.md`](docs/qualification/STATUS.md); open work is
machine-readable in
[`docs/qualification/backlog.json`](docs/qualification/backlog.json).

| Area | Status | Notes |
|------|--------|--------|
| Live Python runtime vertical slice | **PASS** (demonstrated) | Real Docker path on public CI; see claim ledger |
| Action dogfood + consumer | **PASS** (alpha.2 demonstrated) | `uses: ./action`; public CI evidence in the claim ledger |
| Evidence integrity + exact replay | **PASS** (bounded alpha.2 scope) | `verify` plus two independent replay attempts passed |
| Historical release gate | **PASS** (alpha.2 scope) | Three platform archives, checksums, and CycloneDX SBOM were published for `v0.1.1-alpha.2` |
| Linux Docker dependency axis / observed ddmin | **PASS** (bounded M2 scope) | Native pip/npm/cargo fixtures; scan, verify, minimal replay x2, and downloaded-artifact read-back passed at exact master `456a36e...`; see [M2 qualification](docs/qualification/M2.md) |
| Linux Docker Node/Rust runtime slices | **PASS** (bounded M3 scope) | Node 20→22/24 and Rust 1.83→1.74 observations, fail-closed controls, verify, replay x2, and artifact read-back passed at exact master `a6af307...`; see [M3 qualification](docs/qualification/M3.md) |
| React/TypeScript interactive report | **PASS** (bounded engineering slice) | PR #5, merge `f6efabf...`, and exact-master CI exercised generated assets, types, unit tests, Chromium accessibility/responsive/XSS/no-JS gates, and Rust rendering |
| Exact-commit GitHub URL materialization | **PASS** (bounded engineering slice) | PR #5 added fail-closed exact-commit materialization; the later schema-v2 amendment adds manifest-derived index-only Git metadata for disposable scenarios without changing recorded source bytes |
| Four-platform + OCI candidate | **PASS** (candidate construction/read-back only) | Exact source `f83d432...`, candidate run `31678894284`, artifact `9172900020`; no support or formal promotion authority |
| Preregistered public targets (Python/Node/Rust × Docker/Podman) | **PASS** (bounded, project-owned observation) | Exact-source run `31679941755` completed all six pairs, replayed each candidate twice, and passed downloaded current-v2 read-back; earlier failed runs remain immutable history |
| Public `v0.2.0-alpha.1` distribution | **PASS** (external testing only) | Immutable GitHub prerelease `369814204`; 16 exact candidate assets passed anonymous HTTPS digest/read-back and Windows CLI smoke; no GHCR image |
| Broader platform qualification | **BLOCKED** | Hosted Linux Docker/Podman target observations and reproducible archives do not qualify Windows Docker Desktop, macOS Docker Desktop/Colima, or a wider clean-machine support matrix |
| Independent authorization and formal `0.2.0-alpha.1` promotion | **BLOCKED** | The external-testing prerelease is owner-operated; no genuine independent signed authorization, protected promotion, or GHCR publication has passed |

### Tags (audit history)

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | **REJECTED** product candidate — scripted acceptance; red CI |
| `v0.1.0-grok-session` | **REJECTED** historical parallel candidate — same peeled commit as `v0.1.0`; GitHub release metadata corrected without moving the tag or assets |
| `v0.1.1-alpha.1` | **REJECTED acceptance candidate** / live-path demonstration — Python slice real; evidence envelope + release gate incomplete ([audit note](docs/audits/v0.1.1-alpha.1-rejection.md)) |
| `v0.1.1-alpha.2` | **PUBLISHED MEASURED LAB RELEASE** — Python live path, verify, replay ×2, Action dogfood, and release assets passed; Node/Rust live and the other `NOT_RUN` rows remain unclaimed |
| `v0.2.0-alpha.1` | **PROJECT-OPERATED EXTERNAL-TESTING PRERELEASE** — exact immutable candidate assets and anonymous public read-back passed; formal independent authorization, platform qualification, and GHCR remain blocked |

Full historical matrix: [docs/CLAIM_TO_EVIDENCE.md](docs/CLAIM_TO_EVIDENCE.md).
The historical “Latest” selection of the rejected `v0.1.0-grok-session` was
metadata behavior, not an acceptance claim.

## Quick start

**Prerequisites:** Rust toolchain and **Docker daemon** for the current narrow
trial. Start in the supplied source checkout; see [the trial guide](docs/PYTHON_TRIAL.md)
to scan your own repository. Historical platform qualifications remain separate.

```bash
cargo build -p tomorrowci-cli --release --locked

./target/release/tomorrowci doctor
./target/release/tomorrowci trust
./target/release/tomorrowci scan fixtures/python-runtime-break \
  --config fixtures/python-runtime-break/.tomorrowci.yml
cd fixtures/python-runtime-break
../../target/release/tomorrowci verify <run-id>
```

Without a container daemon, `scan` returns **BLOCKED** (not a silent host run).

## Tree immutability contract

**Target source files under the scanned path are not modified by scenario execution.**  
Evidence is written under `<scan-root>/.tomorrowci/runs/` (and is **excluded** from the immutability claim). Disposable workspace copies are used for container mounts.

## CLI

```bash
tomorrowci doctor
tomorrowci trust
tomorrowci scan <path> [--config .tomorrowci.yml]
tomorrowci verify <run-id>
tomorrowci show <run-id>
tomorrowci replay <run-id> --scenario <id>
tomorrowci explain <run-id>
tomorrowci report <run-id> --format html|json|sarif|summary
tomorrowci metrics <run-id>
tomorrowci compare --base <id> --head <id> [--gate]
tomorrowci init-action
```

## License

Apache-2.0 — see [LICENSE](LICENSE)
