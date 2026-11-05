# Check one Python upgrade

Answer one question: **do the tests that work on my current Python also work
on the later version I selected?** Keep the result so it can be inspected and
rerun. This is an experimental source-based workflow, not a compatibility
certificate.

## 1. Choose the existing test job

Use a clean, committed Python repository and the test scope you already run.
Write down its commit, baseline and candidate Python minor versions, dependency
file and test arguments before running either version.

The short path supports unittest or pytest, pip requirements, and tests that
can run offline in Linux containers. Python versions are explicit, such as
`3.12` and `3.14`; check their official images are available. A `src` layout
uses `--source-root src`. The source package must be imported from the checkout.

If the job needs Poetry/uv-only setup, custom build commands, external services,
directory links or submodules, record that setup gap first. Do not replace the
real job with a tiny passing subset just to finish the trial. A declared subset
can answer a narrower question, and must be identified as such in the result.
The optional strict coverage runner used below rejects zero tests and skips;
if normal platform skips are required, read the
[coverage contract](PYTHON_TRIAL_COVERAGE.md) before choosing a scope.

## 2. Prepare an isolated trial

You need Git, Python, a compatible Rust toolchain and a running Docker daemon
for Linux containers. From the TomorrowCI source checkout:

```sh
cargo build -p tomorrowci-cli --release --locked
./target/release/tomorrowci doctor
```

Record the TomorrowCI commit too. On PowerShell the executable is
`.\target\release\tomorrowci.exe`. Save its absolute path for later commands.
Tool installation, build and Docker setup belong in first-use cost; a successful
`doctor` is not a successful upgrade test.

Example for an existing pytest job (replace the paths, versions, package and
test arguments with your project's actual values):

```sh
python scripts/prepare_python_trial.py /path/to/clean/repo --output /path/to/new/trial --baseline 3.12 --candidate 3.14 --framework pytest --source-root src --source-package example --requirements /path/to/test-requirements.txt -- -q tests
```

Include pytest and the project's test dependencies in the requirements. For a
standard-library-only unittest job use `--framework unittest --stdlib-only`
instead of `--framework pytest --requirements ...`, and pass its existing
arguments after `--`, for example `discover -s tests -v`.

The helper copies source at the selected commit, writes the trial configuration
and prints the next command. It does not run target code or resolve dependencies
on the host. `PREPARED_NOT_EXECUTED` means preparation only. The original source
is unchanged; the output directory must be new. Requirements are copied, not
automatically locked. Keep any local requirement paths checkout-relative.

## 3. Run and read the result

Change to the new trial directory, then use the absolute executable path:

```sh
/absolute/path/to/tomorrowci scan . --config .tomorrowci.yml
/absolute/path/to/tomorrowci verify <run-id>
/absolute/path/to/tomorrowci show <run-id>
```

Replace `<run-id>` with the ID printed by `scan`. In PowerShell invoke a quoted
path with `& "C:\path\to\tomorrowci.exe"`. Inspect the retained test output and
report under `.tomorrowci/runs/<run-id>/`; `verify` checks record consistency,
not that your chosen tests establish compatibility.

Before drawing a conclusion, check which tests each version actually ran,
from which checkout, and whether the planned scope was reached. Record test,
failure, error and skip counts, including zero when collection could not start.
Distinguish these outcomes:

| Observation | Useful conclusion |
|---|---|
| Baseline and candidate complete the planned tests successfully | This selected test scope passed on both observed environments |
| Baseline is valid; candidate reaches the tests and fails | A test failure was observed in the candidate environment; investigate its log |
| Baseline is valid; candidate reproducibly fails to import/collect the same test job after setup | The candidate environment cannot start the intended suite; retain the source-linked traceback and say which tests never ran |
| Installation or infrastructure fails, the command/source is wrong, or coverage is otherwise missing | No adequate test-upgrade conclusion yet; retain and address the setup/coverage problem |

A failing candidate can be a successful investigation. An install failure is
not proof that CPython broke your code. Runtime-dependent dependency resolution
can differ, even when both versions receive the same requirements file.
An import/collection failure needs inspection to separate a real candidate
environment failure from a missing declared dependency or an incorrect command.
Keep TomorrowCI's original verdict, including `BLOCKED` or `INCONCLUSIVE`; a
useful diagnosis does not promote that tool verdict to PASS or full coverage.

## 4. Rerun one recorded scenario

```sh
/absolute/path/to/tomorrowci replay <run-id> --scenario <scenario-id>
```

Choose the scenario ID from that run's report (for example `py314-locked`),
and compare its actual environment and test result with the original. Retain
the complete run directory, original test logs, source identities and dependency
input. Replay has the [recorded preparation contract](PYTHON_TRIAL.md#run-inspect-and-replay);
unpinned or unavailable dependencies can prevent an exact reconstruction.

For a worked known failure use the [Pydub audioop example](PYTHON_TRIAL.md#known-upstream-regression-pydub-and-audioop).
For all options and limitations use [the reference](PYTHON_TRIAL.md).

**Already have a CI matrix?** Keep using it unless this workflow earns its setup
cost. The [comparison kit](PYTHON_UPGRADE_COMPARISON.md) measures preparation,
interpretation and same-commit rerun separately. No effort advantage is claimed
yet.
