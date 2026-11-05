# Python upgrade comparison task card

This is a blank form, not a measurement. Leave unknown fields blank and label
them missing in the result. Follow [the protocol](../../docs/PYTHON_UPGRADE_COMPARISON.md).

## Before either arm

- Case / participant pseudonym:
- Operator: human non-author / human author / agent
- Repo and tool familiarity:
- Starting point: existing CI / greenfield (separate analysis)
- Arm order and assignment method:
- Allowed help (same policy for both arms):
- Protocol commit:
- Target repository and immutable commit:
- Source overlays, if any (give both arms the same tested bytes):
- Baseline / candidate Python minor versions:
- Dependency input path and identity:
- Existing test command / import root / source packages:
- Planned scope / test IDs / allowed skips:
- Existing baseline evidence:
- TomorrowCI commit and executable identity:
- Matrix workflow commit (separate from tested target commit):
- Host / OS / installed tools / cache state for each arm:
- Previously completed/shared preparation:
- Time limits (default 45 active / 90 elapsed minutes per arm):
- Optional exact-environment reconstruction needed? Why?

## After each arm (keep two separate copies)

- Arm: matrix / tomorrowci
- Status: completed / assisted / incomplete / unsupported / timed_out / not_run
- Actual source, Python patch versions, OS, dependency versions and image digest:
- Baseline test / failure / error / skip counts and log reference:
- Candidate test / failure / error / skip counts and log reference:
- Original tool/job verdict (never overwrite it with study completion):
- Observation: tests_passed / tests_failed / candidate_start_failure / setup_failure / coverage_incomplete
- For candidate_start_failure: reviewed repeated traceback, setup evidence and tests_not_executed scope:
- Did both versions run the planned scope from the intended source?
- Upgrade conclusion and the exact evidence supporting it:
- Same-commit rerun reference and comparison with the original:
- Missing/unavailable inputs for optional exact reconstruction:
- Raw timing/observation reference (observations.csv or consented recording):
- Setup issues, corrections, help and prior-answer contamination:
- Stop reason if unfinished:
- Independent conclusion check (reviewer, result and disagreements):

## Pair assessment

- Are target source/dependencies/test scope comparable? Explain any difference:
- Completion counts (include failed and unsupported attempts):
- Active seconds including SETUP for matrix / TomorrowCI:
- Paired saving seconds / percent (only if both accurately complete):
- A+B / C / optional D reported separately:
- Elapsed and waiting time, host/cache differences:
- Narrow conclusion supported by this pair:
- Limitations; a single pair is not general user evidence:
