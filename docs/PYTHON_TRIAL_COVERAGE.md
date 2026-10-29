# Check that a Python trial actually ran its tests

An exit code of zero is insufficient for a useful compatibility observation.
`unittest` can succeed after discovering no tests. Pytest's `importorskip` can
skip a feature when its dependency is missing. The optional strict trial adapter
records framework callbacks and rejects empty or skipped coverage.

Current scans classify a valid adapter summary with framework exit 0, process
exit 6 and a concrete coverage gap as `COVERAGE_INCOMPLETE`. CLI and HTML show
the gate reason. It counts under inconclusive metrics, returns CLI exit 2,
cannot authorize a breakage horizon or dependency minimality, and produces no
SARIF functional-regression finding. A coverage-invalid baseline stops the
candidate scan. A failed assertion remains a functional failure even with skips.
Missing, malformed, duplicate or contradictory summaries do not authorize this
classification. The cooperative summary is not independent test attestation.
Historical receipts retain their original verdict and remain verifiable;
rerun to obtain the new classification, without rewriting old evidence.

Copy `scripts/python_trial_runner.py` into the **disposable target checkout** as
`.tomorrowci-trial.py`. Record the copied file's SHA-256 with the trial profile.
Run it through TomorrowCI's container test command, not directly on the host for
an unfamiliar target. Original project assertions and test files stay intact.

For a standard-library project with a top-level `example` package:

```yaml
project:
  ecosystem: python
  test_command: python .tomorrowci-trial.py --framework unittest --source-package example -- discover -s tests -v
```

For a pytest project with a `src/example` package:

```yaml
project:
  ecosystem: python
  test_command: python .tomorrowci-trial.py --framework pytest --source-root src --source-package example -- -q tests/test_api.py
```

Include pytest and all selected test dependencies in the frozen dependency set.
`--source-root` adds the selected checkout directory to the import path before
test discovery. Repeat `--source-package` to check additional source modules.
Every named module must resolve to a concrete file inside that source root.
After the framework finishes, it must also have been loaded by the tests with
the same origin: `source_origins` records preflight resolution and
`observed_source_origins` records the loaded modules. An unused source package
or an installed same-named replacement is rejected. This check does not certify
all transitive imports or package installation/entry-point behavior.

The adapter emits exactly one line starting with
`TOMORROWCI_TRIAL_SUMMARY=` followed by JSON. It records selected/executed counts,
skip and failure counts, hashes of selected and executed test IDs, relative source origins,
the framework exit code, and the coverage gate outcome. Unittest's synthetic
`_FailedTest` on an import error is not counted as an executed project test.
Pytest collection skips/errors and empty-reason XPASS are recorded too.

For unittest suites containing `doctest.DocTestCase`, the adapter separately
records `doctest_skip_directives`: selected examples whose effective options
declare `SKIP`. Older Python versions do not consistently expose these as
unittest skips, so the strict policy rejects the declarations even when the
framework reports success with zero skipped test cases. This is a count of
declared examples, not proof of their execution, and is not added to the
framework's test-case skip count. A per-example `-SKIP` overrides a suite-wide
`SKIP`. Arbitrary custom runners and doctest invocations hidden inside ordinary
test bodies are outside this inspection's scope.

The strict policy rejects zero executed tests, skips, expected failures,
unexpected successes, collection errors, and incomplete execution of the selected
tests (including failfast). This deliberately narrow policy is suitable for
explicit trial subsets that are expected to execute fully. It has no option to
silently permit missing dependencies or skips. Declare a different scope openly
if a project's ordinary suite requires platform-conditional skips.

Original framework failures remain nonzero. An otherwise successful framework
run that violates coverage returns 6. Adapter setup/argument errors return 7.
These are trial failures requiring diagnosis, not automatically evidence of an
upstream runtime or dependency regression. A failed assertion can still have
valid coverage: read `framework_exit_code` and the TomorrowCI verdict alongside
`coverage_valid`.

The adapter is an opt-in convenience for cooperative test suites. Tests run in
the same interpreter and can interfere with hooks or print misleading output;
this is not independent attestation against hostile tests. The trial driver
must reject absent/duplicate summary lines, preserve raw logs, and still use
`tomorrowci verify` plus actual replays. A summary does not replace either.

## Projects without an existing lock

Prefer a traceable existing dependency snapshot. If none exists, resolve the
project's declared requirements in the selected container, record that this is a
new baseline, and freeze the full closure and wheel hashes. Select update policy
before seeing target test outcomes. If before and after resolve identically,
record `NO_CANDIDATES` rather than manufacturing a downgrade.

The wheel v2 importer requires at least one actual update. For a baseline-only
observation, the runtime path can consume a root `requirements.txt` containing
the complete exact pins, `--require-hashes`, `--no-index`, and `--find-links`
pointing to a saved workspace-relative wheelhouse. Disable runtime candidates
with `versions: []` and `max_versions: 0`. This is a baseline observation only,
not successful upgrade coverage. This runtime path's FETCH container still has
the normal fetch network policy; local wheels and pip flags are not a claim
that its container networking is disabled. TEST remains network-disabled.

Keep the test command, selected source revision, source-origin checks, and
coverage policy identical throughout each comparison. Preserve incomplete,
blocked, flaky, and failing observations alongside passing ones.
