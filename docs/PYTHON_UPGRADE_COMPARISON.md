# Does one Python upgrade take less developer effort?

Status: **One agent-operated passing-case rehearsal completed; human pilot NOT_RUN.**
See the [2026-11-05 rehearsal](PYTHON_UPGRADE_REHEARSAL_20261105.md) for the
unchanged full-suite case, both candidate reruns, friction and measurement limits.
Scope: one Python repository, one baseline, one later minor version and the
existing test job. This study is a product decision aid, not a release gate.

## Question and primary baseline

Does TomorrowCI reduce **active developer minutes** for obtaining an accurate
upgrade conclusion and rerunning it, compared with **adding one version to the
repository's existing GitHub Actions Python matrix**?

The existing-CI task is primary. Starting a new workflow is a separate,
greenfield stratum; do not pool its results with existing-CI edits. A matrix
that needs only a one-line edit is a valid and important competitor.

Use normal matrix features: an existing workflow or official template,
`setup-python`, dependency caching, parallel jobs, job logs, artifacts and
GitHub's native rerun. Set `fail-fast: false` so both versions have results.
Do not require the participant to recreate TomorrowCI's hashes, manifests or
report format. A [copyable matrix example](../examples/python-upgrade-comparison/github-matrix.yml)
is supplied for projects without a suitable template; adapt its dependency
and test steps to the actual job. It is not installed in this repository's CI.

Both arms may use documentation, existing scripts and the same assistance
policy. Record AI/human help, corrections and preparation carried over from
another arm. Do not charge matrix users for inventing the test command while
giving TomorrowCI users a preconfigured answer.

## Freeze a small task card before observing results

Copy [case.md](../examples/python-upgrade-comparison/case.md). Record:

- operator type (human non-author, human author, or agent), prior tool and repo
  familiarity, start state, arm order and help policy;
- target commit and any declared source overlays, baseline/candidate minor
  versions, dependency input, actual test command, source/import roots and
  planned test IDs or scope, with the same allowed skips in both arms;
- TomorrowCI source/binary identity, matrix workflow identity, host/OS, cache
  state, existing tool installations and execution budget;
- the plan's commit and the stopping rule. Changes after an attempt starts
  become a new version; keep the failed/unsupported attempt in the record.

Use independent clean workspaces for the arms. The baseline Python must have
been known to run the selected tests, but each arm must demonstrate it again.
The workflow commit can differ between arms; record it separately from target
source identity and ensure tested source/dependency/test bytes match.

Normal Actions `setup-python` and TomorrowCI's Linux Docker environments differ.
Record actual Python patch versions, OS, dependency versions and container
digest where applicable. A disagreement needs investigation; do not attribute
it to Python alone or count a faster, different test scope as a win. This is a
comparison of real workflows, not a controlled execution-speed benchmark.

## Three common tasks; exact reconstruction is separate

| Phase | Completion requirement for either arm |
|---|---|
| A — configure and obtain a result | Baseline executes the planned scope on the selected source. Candidate either executes that scope or has a reproducible, reviewed import/collection/test-start failure in that same job after setup. Preserve original results and logs, including tests that never ran. |
| B — interpret and hand off | Write the source/version/scope, baseline result, candidate result, counts/skips and a log reference for the failure or success. Separate setup/collection failure from a completed test result. A reviewer can verify the conclusion from those records. |
| C — same-commit rerun | Starting from the saved result, identify and rerun the requested candidate scenario, then compare its result with the original. Native GitHub **Re-run jobs** is sufficient. |

Successful A+B+C is the primary completed task. A supported, correctly diagnosed
candidate test failure counts as completion. A candidate test-start failure can
also count if a reviewer can verify the intended source/job, successful setup,
valid baseline and repeated candidate traceback. Label it `candidate_start_failure`
and state `tests_not_executed` for the unrun scope; it proves neither full test
coverage nor that CPython alone caused the problem. A wrong command, missing
declared prerequisite, unexplained empty suite, skipped required test, failed
installation or tool `UNSUPPORTED` does not count. Keep the tool's original
verdict, including `BLOCKED`/`INCONCLUSIVE`, separate from study task completion;
the study never promotes it to PASS. For unresolved cases record a truthful
incomplete conclusion, but do not count a completed upgrade comparison.
Do not reduce the scope after a tool rejects it. A new, smaller scope is a new
case, and the original remains in the denominator.

Optional D asks for the same source, image and dependency bytes in a fresh
environment. Score D separately, only when that is an actual user need.
GitHub rerun keeps the original event's SHA/ref but does not freeze every
environment input. TomorrowCI's runtime trial also does not turn unpinned
requirements into a dependency lock. Record missing/unavailable inputs and
unsupported reconstruction honestly on both sides. D cannot rescue a claim
that the basic A+B+C workflow is cheaper.

## Record effort without confusing it with machine speed

Use one row per phase in [observations.csv](../examples/python-upgrade-comparison/observations.csv).
Record tool installation/build as phase `SETUP`, including the first user's
Rust/Docker requirements. Do not replace missing measurements with zero.

- **Active seconds:** reading, deciding, typing, editing, searching logs,
  troubleshooting, checking and requesting help. Observe with a timer or
  consented screen recording; retain the observation reference.
- **Wait seconds:** queue, pull, build, install and test time when the operator
  is not working on the task. If troubleshooting occurs while a job runs, that
  interval is active, not also wait. Breaks are separate; the operator does
  not work on the other arm while a timed arm is waiting.
- **Elapsed seconds:** wall time from phase start to finish, including breaks.
  Record start/end times as well. For parallel jobs measure the critical-path
  wait, not the sum of every worker's duration.
- **Help and retries:** keep failures, edits, resubmissions and assistance in
  the relevant phase. An assisted finish is labelled assisted.

Per arm: `first_use_active = SETUP + A + B + C` active seconds.
Also report `A+B`, `C`, and `A+B+C excluding SETUP` separately. The last measure
is only a setup-excluded view, not a measured repeat-user session. Do not hide
installation cost or manufacture an amortization claim from assumed reuse.

For completed pairs: `saving_seconds = matrix_active - tomorrowci_active`;
`saving_percent = 100 * saving_seconds / matrix_active` when the denominator
is positive. Summarize paired differences, not a ratio of unrelated medians.
Publish each pair, order and start state alongside the median.

Stop each arm after **45 active minutes or 90 elapsed minutes**, whichever
comes first, including SETUP. Retain elapsed/active time and the reason for
an unfinished task. These pilot budgets can be changed before the study starts,
not after seeing a losing arm. Never drop timeouts or report successful-pair
timing without the completion counts for all attempted pairs.

## Run in two stages

1. **Engineering rehearsal:** one real repo's unchanged test job, plus the
   existing [Pydub example](PYTHON_TRIAL.md#known-upstream-regression-pydub-and-audioop)
   for failure interpretation. Pydub is a known eight-test example with source
   overlays; it is not blind diagnosis, full-suite coverage or a novel finding.
   Reverse arm order between cases and document what information is already
   known. Agent-operated rehearsal records actual steps, failures and machine
   times; it cannot supply human active-time or independent-user evidence.
2. **Directional user pilot:** six non-author Python developers, one real
   repository each with a working CI test job; use at least three distinct
   repositories. Each performs both arms from clean workspaces; assign three
   matrix-first and three TomorrowCI-first before starting. Record familiarity
   and shared knowledge; counterbalancing reduces, but does not remove,
   learning effects. Show first-arm results separately. Known training cases
   do not enter the primary sample. Declines and pre-screen exclusions are
   recorded with reasons; supported-looking failures stay in the denominator.

No invitations, participant collection or hosted workload is started by these
files. The first stage should expose confusing instructions before spending
someone else's time. If human users are unavailable, leave stage 2 NOT_RUN.

## Proposed decision rule, fixed before the pilot

These are pragmatic investment thresholds, not statistical significance or
new product-release rules. Report disagreement and small-sample uncertainty.

- Continue investing in the broad first-use workflow only if at least **5/6**
  TomorrowCI tasks finish accurately without author rescue, its completion
  count is no lower than matrix, there are no falsely reassuring conclusions,
  and at least five pairs complete accurately in both arms.
- Among those paired completions, require a median first-use active saving of
  **at least 5 minutes** and a median paired saving of **at least 30%**. Show all
  six outcomes and each order group; an order group reversing the direction
  means further study, not a win. Missing data or fewer qualifying pairs is
  inconclusive; never relax the threshold afterward.
- If only B/C or optional D saves effort, describe that narrower use case and
  test it next. Do not advertise easier initial matrix setup.
- If matrix is as easy or easier, or TomorrowCI preparation repeatedly fails,
  stop expanding language/platform coverage. Address the observed setup cost
  or reconsider this workflow before another study.

Six users provide a directional product signal, not a general developer-time
claim. A larger independent sample is needed for a broad savings statement.

## Existing evidence and baseline references

The [image-pip observation](../examples/benchmarks/python-image-pip.json) measured
two TomorrowCI preparation modes on one project-operated Pydub fixture. Its
88.57% scan-time reduction has no matrix arm and no human active-time measure.
Keep it as runtime evidence; do not relabel it as the result of this study.

- [GitHub matrix strategies](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations)
- [GitHub rerun semantics](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
- [setup-python and dependency caching](https://github.com/actions/setup-python)

An engineering rehearsal, a human pilot, published package qualification and
independent adoption are separate claims. One passing-case rehearsal is recorded;
known-failure interpretation, the human pilot and effort advantages remain unmeasured.
