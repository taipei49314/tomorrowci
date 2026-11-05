# Python upgrade engineering rehearsal — 2026-11-05

**Both arms completed one passing historical-repository case and one candidate
rerun. No reduction in active developer effort has been established.** This was
an agent-operated rehearsal, not a non-author user study or release qualification.

## Frozen case and scope

- Target: [Mistune v3.0.2](https://github.com/lepture/mistune/tree/f997c86335d8a5d8435aac08b66ed3cba9381b51),
  upstream `f997c86335d8a5d8435aac08b66ed3cba9381b51`.
- Selected Python minors: 3.11 baseline, 3.14 candidate. Current Mistune already
  supports later versions; this does not report a current upstream defect.
- Preserve both original full-suite commands, using the module entry point:
  `python -m pytest` and `python -m pytest --cov=mistune --cov-report=xml`.
  Original assertions, selection, source roots and warning policy are unchanged.
  Codecov upload and other runtime/OS legs are outside this two-version case.
- Both arms use the same newly pinned, wheel-hashed test dependencies. This is
  common experimental preparation, not a historical upstream lock or a cost
  assigned only to the matrix arm.
- Common [inputs](../examples/python-upgrade-comparison/mistune-v3.0.2/README.md)
  produce Git tree `10bf899d05ddded8583c9d70b786acf12793bc69`.
  TomorrowCI target overlay commit: `9d62cfc5ba79cfe321bfe78efcf963285fb432fb`.
- TomorrowCI tool source: `270545d93ebc10c9bac288af0802c2498ec32f9a`.
  Product code is unchanged from master `c9b4206524bf1f5c547e2964c1c6b58a29a84603`.
  Executable SHA-256: `69f56c846b24980c06eb3a97910b86ad1256bb1f96ff04d03b546f282558a024`.
- Matrix workflow source: `57bd149d5aa10fd7e926fb00e0c646b49463285d`,
  [run 42029043134](https://github.com/taipei49314/tomorrowci/actions/runs/42029043134).
  It runs a pinned Mistune checkout in TomorrowCI's Actions repository. This is
  a port of the existing test job, not a timed one-line edit in upstream CI.

## Observed results

| Observation | TomorrowCI | Native GitHub Actions matrix |
|---|---|---|
| Baseline | Python 3.11.18; 941 passed in each of two stages | Python 3.11.17; 941 passed in each of two stages |
| Candidate | Python 3.14.10; 941 passed in each of two stages | Python 3.14.10; 941 passed in each of two stages |
| Candidate rerun | 941 passed in each of two stages | 941 passed in each of two stages |

All twelve stage summaries report 941 passes and no nonpass counts. No complete
test-ID set was captured. Matrix attempt 2 carries forward the original baseline
result: its API ID changes but its original timestamps remain. Only 3.14 ran anew.
Both attempts use the same workflow SHA and verified target tree/input hashes.

TomorrowCI run `113e1ff1d441` records `BASELINE_PASS` and `FUTURE_PASS`, with no
observed breakage frontier and frontier grade `INCONCLUSIVE`. These original
values remain unchanged. `verify` passed before replay (186 checked files) and
after replay (190). Candidate replay returned matching exit and failure signature;
the two-stage counts were checked separately in its raw log.

## Preparation, interpretation and rerun

| Phase | Observed TomorrowCI friction | Matrix comparison |
|---|---|---|
| Preparation | Build/doctor, isolated checkout, handwritten config and a fail-fast wrapper to preserve both CI commands. The short helper cannot directly represent this multi-step job. | Preserve two native test steps, choose versions and push. Extra checkout/hash steps in this harness are experimental controls, not normal matrix requirements. |
| Interpretation | Two scenario PASS rows end with `Evidence grade: Inconclusive`; interpreting this requires separating frontier absence from the upgrade observation. `show` omits counts and the two-stage scope, so raw logs remain necessary. | Job/step success is visible directly; exact counts still require pytest step logs. |
| Rerun | One `replay RUN --scenario py314-locked` command. Exit/signature comparison is automatic; scope/count comparison still requires logs. | Select the candidate job, then native **Re-run this job** and **Re-run jobs**. Same SHA, successful pip-cache restore. |
| Handoff | Source/config/image identities, results, replay descriptor and verification are grouped locally. | Native run and step logs already support the basic task. Exact reconstruction was not imposed on the matrix arm. |

The local evidence bundle is a visible functional difference. Whether it offsets
the additional preparation and interpretation is unproven. Basic rerunning is
already straightforward in either arm. Failure diagnosis and optional exact
reconstruction task D were **NOT_RUN**.

## Machine time only

| Measurement | Seconds | Boundary |
|---|---:|---|
| TomorrowCI build | 40.766 | Existing Rust toolchain/registry; fresh release target |
| TomorrowCI scan | 341.031 | Whole observed CLI process |
| TomorrowCI candidate replay | 138.485 | Whole observed CLI process |
| Matrix initial attempt | 24 | API run start/creation to metadata update |
| Matrix initial attempt including push | 31.003 | Post-enablement push-command start to metadata update |
| Matrix candidate rerun | 23 | API attempt start to metadata update |

Initial matrix jobs were parallel (15 and 21 seconds); do not sum their durations.
The new candidate job took 18 seconds, ending one second before the attempt's
final metadata update. Matrix spans exclude workflow authoring, settings work,
403 troubleshooting and log retrieval. TomorrowCI replay's printed 45,081 ms
duration covers only part of the 138.485-second process and is not total cost.

TomorrowCI ran on `LAPTOP-01AGNPJU`, labelled
`HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL`, using Windows/WSL2 Linux Docker 29.7.2,
1 CPU, sequential scenarios, default venv preparation and pre-existing Python
images. GitHub ran hosted Ubuntu 26.04 jobs in parallel with setup-python and
pip caching. Baseline patch versions and runner image builds differ. These are
descriptive observations, not a controlled speed benchmark. No optimized
image-pip rerun replaced the original result. Full first-install cost is unknown.
Human active time, saved minutes and saved percentage are all **null**, not zero.

## Preserved environmental friction

Actions was initially disabled; the first push produced no run. The user then
explicitly authorized temporary enablement with GitHub-owned external actions
(the GitHub setting also allows owner-owned actions), retaining read-only token
defaults, followed by restoration. A comment-only workflow commit retriggered
the experiment without changing target inputs.

The CLI token returned 403 for administration and job-rerun requests; the actual
rerun used the native UI without token permission expansion. One parallel `gh`
log download failed with a ZIP-cache error. Direct API log retrieval initially
refused escape sequences, then succeeded when raw bytes were explicitly allowed
into the evidence file. The shared dependency download also exposed an observer
stdout-encoding issue after successful download. All unsuccessful attempts are
retained; none required changing target tests or hiding a failed test run.

After both attempts and evidence retrieval, the saved settings page confirmed
**Disable actions**, with the policy-updated acknowledgement. Main was not merged
and no release or runner change was made. The Actions page may be unavailable
while disabled; raw run/job metadata and logs were saved separately.

## Product decision

Do not claim that this workflow is easier than adding a version to existing CI.
First make three improvements reviewable: preserve existing multi-step commands
without manual glue; separate upgrade results from frontier grades and expose
scope/logs; show complete rerun timing and the actual comparison boundaries.
Then repeat this case, add the separately labelled known-failure exercise, and
run the [non-author pilot](PYTHON_UPGRADE_COMPARISON.md). The original human-effort
thresholds are unchanged; this rehearsal does not satisfy them.

A read-only agent independently checked the saved logs, source identities,
counts, timing definitions, baseline carry-forward and restored setting. This is
team evidence review, not independent external adoption or human-user evidence.
