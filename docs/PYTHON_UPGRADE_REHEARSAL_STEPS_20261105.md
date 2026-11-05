# Ordered Python steps: Mistune follow-up — 2026-11-05

**The same passing case now needs no handwritten case-specific wrapper or
TomorrowCI config. Its four initial step results and candidate replay comparison
are readable directly in the terminal.** This removes observed TomorrowCI
friction; it does not establish lower human effort than native CI matrix.

This follows the [original rehearsal](PYTHON_UPGRADE_REHEARSAL_20261105.md).
The new source workflow is described in [Python upgrade](PYTHON_UPGRADE.md).

## What changed

Repeat `--test-step` for the original job's Python commands. The helper generates
the ordered plan, driver, config and preparation profile in a new trial checkout.
It does not infer dependencies or lock them. Steps share a scenario workspace
but run in fresh Python processes. A failing step stops later steps, which are
recorded as NOT_RUN; retries and replays use the existing fresh workspace path.
The original strict `--framework` entry remains available separately.

`scan`, `show`, HTML and job summaries distinguish the passing upgrade observation
from the unchanged breakage-frontier grade. They show ordered argv, completion,
exit, framework-reported counts, log locations and replay commands. Missing,
ambiguous, oversized or inconsistent records show UNKNOWN, not zero or PASS.
The current display reader limits each log to 1 MiB. Counts remain cooperative
diagnostics; no verdict, strict coverage gate or evidence hash contract changed.

Replay prints its step results, advisory count comparison, original/replay log
locations, preparation/test phase times and total wall time. Known status/exit
differences remain DIFFERENT even if later step counts are unavailable. Replay
divergence retains the diagnostic summary and a failing exit. The authoritative
replay gate still compares exit and failure signature, not test IDs.

## Frozen inputs and comparability

- Product source: `c6ca78575c631347ee29ad8bf9fced8d5e4de3b5`.
- Executable SHA-256: `b3e256efb26d8e85ac838495695e14eca89832e55d1b80d482b7bfdfaadea7be`.
- Target: [Mistune v3.0.2](https://github.com/lepture/mistune/tree/f997c86335d8a5d8435aac08b66ed3cba9381b51),
  upstream `f997c86335d8a5d8435aac08b66ed3cba9381b51`.
- All 124 upstream tracked files are byte-identical in the original source,
  previous trial and new trial. The generated overlay differs from the previous
  `9d62cfc5ba79cfe321bfe78efcf963285fb432fb` overlay; whole trees are not identical.
- Both full-suite commands remain `python -m pytest` and
  `python -m pytest --cov=mistune --cov-report=xml`. They use the module form of
  upstream's `pytest` entry point, as in both original comparison arms.
  Assertions, test selection, imports and warning policy are unchanged.
- Same shared requirements SHA-256:
  `ae457e34fdc411340c148f9ed3db8e5f4a7b4576940e036bdccef34663be0ee6`.
  These are the previous rehearsal's current wheel-hashed test dependencies,
  not a historical upstream lock. Codecov upload and other OS/runtime legs remain
  outside scope.
- Same selected Python minors, exact container digests, default venv mode,
  sequential scenarios, 1 CPU, 2048 MiB, pids 256 and 300-second phase limits.
  Helper default failure reruns are 3 versus the previous config's 2; both actual
  scenarios completed on attempt 1, so neither failure-rerun budget was used.
- Case frozen at `2026-11-05T13:26:11Z`, before target execution. Previous success
  was already known: this is a non-blind engineering regression, not a fresh
  discovery or non-author user study.
- Host `LAPTOP-01AGNPJU`, `HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL`;
  host Python 3.11.9, Rust 1.98.0, Docker 29.7.2 Linux containers.

The single preparation invocation was:

```sh
python scripts/prepare_python_trial.py <clean-mistune> --output <new-trial> --baseline 3.11 --candidate 3.14 --requirements <same-requirements.txt> --test-step "python -m pytest" --test-step "python -m pytest --cov=mistune --cov-report=xml"
```

## Actual results

New run `398f12b8d759` completed with BASELINE_PASS and FUTURE_PASS.

| Observation | Python | Full suite | Suite with coverage |
|---|---|---:|---:|
| Baseline, attempt 1 | 3.11.18 | 941 passed | 941 passed |
| Candidate, attempt 1 | 3.14.10 | 941 passed | 941 passed |
| Candidate replay, attempt 1 | 3.14.10 | 941 passed | 941 passed |

All six step exits are 0, with zero failures/errors/skips/xfails/xpasses/deselected
reported. Raw logs confirm 941 collected each time. Repeated execution does not
represent 1,882 unique tests. No complete test-ID set was captured.

The initial interpretation was saved from scan/show before raw target-log audit.
Those views already contain all four original counts and commands. HTML and
generated job summary contain the same details. Replay exposes two counts and
MATCH for commands, statuses, exits and framework counts. Later raw-log audit
confirmed the displayed data. The unchanged frontier grade is INCONCLUSIVE
because no breakage frontier was observed; the per-version results remain PASS.

Evidence verification passed before replay (188 files), after replay and summary
generation (192 files). The new binary also verified the old run `113e1ff1d441`
(190 files), without modifying it.

## Which work disappeared

| Task | Previous TomorrowCI | New TomorrowCI | Recorded native matrix |
|---|---|---|---|
| Preserve two commands | Handwrite wrapper and config | One helper call; neither file hand-authored | Already supports two native test steps |
| Read scope and result | PASS rows; open raw logs for step counts; interpret generic frontier grade | Four counts, commands and exits in scan/show; distinct upgrade observation | Job/step state visible; exact counts in pytest logs |
| Compare candidate replay | Exit/signature gate; count comparison by reading logs | Same gate plus displayed advisory step/count comparison and full wall time | Native candidate-job rerun; count comparison through logs |

The **2 to 0** change counts handwritten case-specific wrapper/config files,
not generated files or all setup tasks. It is a before/after TomorrowCI measure,
not a two-file advantage over matrix. The generated config, driver, plan,
profile and requirements still exist. Users still choose the source, versions,
commands and dependencies and prepare the toolchain, Docker and checkout.

## Machine observations, not effort savings

| Measurement | Previous TomorrowCI | New TomorrowCI | Previous matrix |
|---|---:|---:|---:|
| Initial scan / run span | 341.031 s | 228.078 s | 24 s |
| Candidate replay / attempt span | 138.485 s | 97.515 s | 23 s |

New helper execution took 1.109 s, incremental release build 11.843 s, doctor
0.828 s, and show 1.360 s. These exclude human authoring and first-install cost.
The replay output reports 97.507 s total wall time (excluding CLI startup),
51.343 s preparation/fetch phase and 41.005 s test phase. The existing test-phase
definition includes 26.510 s of workspace copying; the two test subprocesses'
step times sum to 13.979 s. It is not pure pytest time. Phase times do not
include all verification/coordination overhead and do not sum to total wall time.

The new run reused tools, images and previously prepared requirements. No
execution optimization was introduced or controlled speed benefit established.
The earlier GitHub runs used different hardware, OS, baseline Python patch,
parallelism and caches. The native matrix reference is
[run 42029043134](https://github.com/taipei49314/tomorrowci/actions/runs/42029043134);
it was not rerun this round. Actions had been restored to disabled after that
bounded experiment and was not enabled or changed here.

## Validation and remaining claim boundary

53 Python tests, including the legacy strict runner, and 217 Rust workspace
tests passed. Clippy with warnings denied, formatting, text encoding and pinned
Actions checks passed. Tests cover stop-on-failure, NOT_RUN, incomplete and
ambiguous counts, changed replay results, preserved unresolved verdicts, relocated
evidence roots and HTML escaping. The live Mistune run exercises the successful
container path; a live known-failure user exercise and non-author pilot remain
NOT_RUN. This is not complete cross-platform or release qualification.

An additional agent reviewed the code and retained evidence; this is internal
review, not external adoption evidence. Human active time, saved minutes and
saved percentage remain null. The concrete result is reduced manual connection
work and directly available interpretation data. Whether that is enough to beat
an existing CI matrix still needs the unchanged
[non-author comparison protocol](PYTHON_UPGRADE_COMPARISON.md).
