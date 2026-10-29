# Try one Python runtime upgrade on your own repository

This alpha answers a bounded question: does the test command that passes on your
baseline Python also pass on the exact later Python versions you select? Start
with one baseline and one candidate, using Docker and pip. A completed scan is
an observation of those tests and environments; it does not certify future
compatibility or prove that a failure was caused by CPython itself.

## Prepare the source checkout and target

Use the supplied TomorrowCI source checkout. A public release download is not a
prerequisite for this local trial. Record its `git rev-parse HEAD` and any local
changes with your result; an older qualification receipt does not validate a
newer executable.

You need a Rust toolchain compatible with the checked-in lockfile and a running
Docker daemon that can run Linux containers. From the TomorrowCI checkout:

```sh
cargo build -p tomorrowci-cli --release --locked
./target/release/tomorrowci doctor
```

On Windows PowerShell use `.\target\release\tomorrowci.exe`. Keep the absolute
path to that executable for the commands below. `doctor` reports container
availability; it does not establish that a target passes. The scan requests
Docker explicitly and never falls back to running target tests on the host.

For your target repository:

1. Start with a real test command already used by the project. The example below
   assumes `python -m unittest discover -s tests -q` discovers and runs actual
   tests. Confirm the test count in the captured output: zero discovered tests
   can exit successfully and do not establish useful coverage.
2. Put the project's pip requirements in a root `requirements.txt`, including
   test dependencies when needed. Prefer the pinned requirements used by your
   CI. An empty or comment-only file works for a standard-library-only project:
   TomorrowCI creates a venv with `--without-pip` and skips package installation
   and package fetching. Docker may still need to fetch the runtime image.
   Any actual requirement or directive such as `-r` or `--find-links` retains
   the normal pip install path. This alpha does not install a pyproject-only,
   Poetry or uv project. If your project needs an
   installation/build step, prepare a supported requirements-based setup first;
   `build_command` accepts only `auto` and does not run a custom build.
3. Choose the baseline you actually support and a later published CPython minor
   version you want to test. Verify the corresponding official Python slim image
   is available for your Docker platform. TomorrowCI does not discover or guess
   a `latest` version. The `3.13` / `3.14` pair below is an explicit example,
   not a claim that it has been tested against your repository.

The test phase has no network access. Tests that require external services need
a project-specific offline setup before this workflow is useful.

For an explicit subset that should execute without skips, use the optional
[strict coverage adapter](PYTHON_TRIAL_COVERAGE.md). It preserves original
assertions, checks source import origins, and emits structured test counts.

## Configure one runtime comparison

Create `.tomorrowci.yml` at the target repository root:

```yaml
version: 1
project:
  ecosystem: python
  test_command: python -m unittest discover -s tests -q
baseline:
  runtime: "3.13"
  dependencies: locked
candidates:
  runtime:
    channels: [stable]
    versions: ["3.14"]
    max_versions: 1
  dependencies:
    latest_allowed: false
    prerelease: false
execution:
  max_scenarios: 2
  timeout_seconds: 300
  reruns_on_failure: 2
  max_parallel: 1
sandbox:
  engine: docker
  network: fetch-only
  memory_mb: 2048
  cpus: 1
  pids_limit: 256
report:
  html: true
  json: true
```

For pytest projects, use `python -m pytest -q` and include pytest in the
requirements. Commands are split into arguments, not interpreted by a shell:
avoid shell operators, redirection, quoted arguments containing spaces and
environment-variable assignments. Use a repository-owned Python test entry
point when orchestration is needed.

`dependencies: locked` does not generate a lockfile or freeze an unpinned
requirements file. Each runtime installs the supplied requirements through pip;
version markers, wheels and transitive resolution can differ between runtimes.
Keep that distinction when investigating a failure.

The optional `runtime.versions` field has exact semantics:

- Values are quoted canonical CPython minor versions such as `"3.14"`. Only
  `3.0` through `3.999` syntax is accepted; this is a syntax range, not an
  availability catalogue. Image prefixes, patch numbers, suffixes, leading
  zeroes and whitespace are rejected. The image tag is `python:<version>-slim`
  and execution records its resolved digest.
- Every version must be later than the canonical baseline, unique and listed
  in increasing numeric order. At least the `stable` channel must be enabled.
- The entire explicit list must fit `max_versions`, and the baseline plus that
  list must fit `max_scenarios`. Insufficient budgets are errors, not silent
  truncation. Failure reruns do not add distinct planned scenarios.
- `versions: []` deliberately selects no runtime candidates. Omitting the field
  preserves the old catalogue ending at Python 3.13; a 3.13+ baseline therefore
  needs an explicit later candidate. A baseline-only run is `NO_CANDIDATES`
  coverage, not a successful runtime-upgrade comparison.
- This field currently supports Python only. Node and Rust do not consume it.

Keep concrete dependency experiments separate. A repository containing
`.tomorrowci-dependencies.json` pins one runtime image; combining that
manifest with runtime candidates is unsupported. Use a separate checkout for
this runtime trial. For a separate dependency experiment, disable runtime
candidates with `versions: []` (or omit `versions` and set `max_versions: 0`).

## Run, inspect and replay

Change into the target repository. Replace `/absolute/path/to/tomorrowci` with
the built executable path; in PowerShell invoke a quoted executable path with
`& "C:\path\to\tomorrowci.exe"`.

```sh
/absolute/path/to/tomorrowci scan . --config .tomorrowci.yml
/absolute/path/to/tomorrowci verify <run-id>
/absolute/path/to/tomorrowci show <run-id>
/absolute/path/to/tomorrowci replay <run-id> --scenario py314-locked
```

Use the run ID printed by `scan`. Evidence is retained under
`.tomorrowci/runs/<run-id>/`, including `report.html`, `report.json`, `run.json`,
the recorded workspace and each scenario's logs, test attempts and environment.
Check that both `baseline` and `py314-locked` were planned and actually tested.
`verify` checks evidence integrity; it does not execute the tests again.

The first install needs access to image and package registries. Missing images,
failed installs, daemon problems and timeouts must be investigated from the
phase records; they are not evidence of an upstream runtime regression.

Interpret the verdict together with the recorded tests:

| Result | What you can conclude |
| --- | --- |
| `BASELINE_PASS` and `FUTURE_PASS` (terminal `PASS`) | The baseline and selected candidate passed the configured tests in this run. Untested versions and behavior remain unknown. |
| `FUTURE_FAIL` (terminal `FAIL`) | The candidate failed after a valid baseline. Inspect the repeated failure signature, logs and observed frontier; gaps between selected versions were not tested. |
| `BASELINE_INVALID` | The control did not pass, so the run cannot attribute a new failure to the later environment. |
| `BLOCKED`, `UNSUPPORTED`, `INCONCLUSIVE`, `FLAKY` | The run did not establish a reliable compatibility conclusion for the affected scenario. |
| `NO_CANDIDATES` coverage | Only the baseline was selected; there is no runtime comparison. |

Replay is deliberately strict. It requires intact evidence, the recorded source
snapshot, recorded image digest, and the same container engine name and version.
It re-executes the recorded scenario and compares its outcome. Copying only
`report.html` is enough to read a report, but not to replay it. Moving the entire
run to another machine does not guarantee replay: platform/image availability,
engine version and pip fetch requirements can still block execution. A Docker
upgrade can therefore leave evidence verifiable while replay is blocked.

New container scans use `fresh_prepared_copy_v1`: after dependency preparation,
each test attempt receives a new copy of the prepared workspace. A separate
network-disabled preparation container reads the seed read-only; the test
container cannot see that seed mount. Source files, installed dependencies and
generated files modified by one test attempt therefore do not carry into the
next. Copying preserves container-local symlinks and does not re-download
dependencies between retries. Preparation time shares the test timeout budget;
preparation errors are `BLOCKED`, not project test failures.

Attempt and replay receipts record the copy contract, image, network policy and
preparation result. `verify` checks consistency across those records. This is
auditable execution evidence, not independent cryptographic attestation that a
container executed. Historical receipts without the isolation field remain
historical shared-workspace observations and are not upgraded to the new claim.
Generated replay scripts for new receipts delegate to the CLI so the same
preparation and receipt path is used; set `TOMORROWCI_BINARY` to the matching
executable when it is not on PATH.

This recovery also changes failure fingerprints to preserve concrete exception
causes and source identity. Use a fresh scan from this checkout before replay;
old failure fingerprints are not silently treated as equivalent to the new ones.

For a useful first issue or review, retain the complete run directory, the exact
TomorrowCI source identity, the target source identity, the chosen configuration,
and the original test output. A naturally failing third-party test plus a passing
fix/replay is stronger evidence than a purpose-built demonstration fixture.
