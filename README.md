# TomorrowCI

**Check one Python upgrade with your existing tests, then inspect and rerun the result.**

Choose one baseline and one later Python minor version. TomorrowCI runs the
selected tests in Linux Docker containers and keeps the source, configuration,
logs and scenario records together. It reports observed results for those
inputs; it does not certify future compatibility or discover the first failing
Python version automatically.

**Start with the [Python upgrade walkthrough](docs/PYTHON_UPGRADE.md).**
The current entry point needs a Rust source build, a running Linux Docker
daemon and an explicit test/dependency setup. These are real setup costs.
Whether this saves developer effort over adding a version to an existing CI
matrix is **not yet measured**. The [comparison kit](docs/PYTHON_UPGRADE_COMPARISON.md)
defines the same task for both approaches and includes a normal matrix example.

The broader research direction, "Continuous Integration Against the Future,"
also includes Python/Node/Rust runtime paths and bounded pip/npm/cargo
dependency reduction. Those existing capabilities and historical observations
remain below; this first-use workflow focuses on one Python upgrade.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**Public source recovery, 2026-10-30.** Start with the bounded
[Python Docker trial](docs/PYTHON_TRIAL.md): choose the baseline and candidate
versions explicitly, run your own tests, verify the evidence, then replay.
The canonical source repository is [`taipei49314/tomorrowci`](https://github.com/taipei49314/tomorrowci).
This is source distribution, not a new binary release or platform qualification.
Historical release links below refer to the retired repositories; their tags,
release assets and workflows have not been republished as current releases.

Try the [Pydub audioop regression](docs/PYTHON_TRIAL.md#known-upstream-regression-pydub-and-audioop):
eight fixed PCM tests pass on Python 3.11 and fail on 3.14 before a conditional
dependency fix; the identical tests then pass on both versions with matching
replays. This reproduces an existing upstream issue, not a new discovery or a
claim that the entire Pydub suite passes. The example includes the exact source
SHA, dependency hash, patch and preparation command.

Recent project-operated Linux-container observations also cover Mistune's
1,327 tests and pyparsing's 1,958 selected tests on Python 3.11/3.14. Packaging's
selected baseline executed 53,613 passing tests and skipped two version-specific
tests, so its candidate was not run and the observation remains coverage-incomplete.
These local observations are not independent adoption or full platform support.

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

A minimal failure is not yet a repair. [Validate a Python rollback](docs/python-dependency-rollback.md)
with a separate full-complement run and fresh replay before publishing hashed
repair pins. The verifier binds both runs, unchanged source/tests, the exact
retained upgrades and every recorded repair replay.

The [natural batch rehearsal](docs/PYTHON_ROLLBACK_REHEARSAL_20261105.md) compares
one real dependency repair with a local matrix plus AI and depsect. The repair
and replay pass; lower effort is not established, and native uv lock output
remains missing.

For explicit Python trial subsets, the optional [coverage adapter](docs/PYTHON_TRIAL_COVERAGE.md)
checks checkout import origins and records framework test counts. It rejects
zero-test and skipped-feature successes while preserving original test failures.
It also documents baseline-only observations when no natural update is available.
New container test attempts each use a fresh prepared workspace copy; replay
preserves that contract, and historical shared-workspace evidence stays labelled
by its original contract. See the trial guide for limits and receipt semantics.

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
git clone https://github.com/taipei49314/tomorrowci.git
cd tomorrowci
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
tomorrowci rollback <run-id> --out rollback-evidence
tomorrowci verify-rollback <run-id> --out rollback-evidence
tomorrowci explain <run-id>
tomorrowci report <run-id> --format html|json|sarif|summary
tomorrowci metrics <run-id>
tomorrowci compare --base <id> --head <id> [--gate]
tomorrowci init-action
```

## License

Apache-2.0 — see [LICENSE](LICENSE)
