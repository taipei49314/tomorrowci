# TomorrowCI measure suite

- engine: true (docker 29.6.2 at C:\Program Files\Docker\Docker\resources\bin\docker.exe)
- trustworthy: true

| Claim | Status | ms | Detail |
|---|---|---:|---|
| `infra.container_engine` | PASS | 0 | docker 29.6.2 at C:\Program Files\Docker\Docker\resources\bin\docker.exe |
| `fixture.python-runtime-break.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/python-runtime-break |
| `fixture.python-runtime-break.scan` | PASS | 87506 | run_id=4e18b2ac852a scenarios=5 |
| `fixture.python-runtime-break.min_scenarios` | PASS | 0 | got 5 |
| `fixture.python-runtime-break.baseline` | PASS | 0 | BaselinePass (want BASELINE_PASS) |
| `fixture.python-runtime-break.horizon` | PASS | 0 | observed=true label=Some("Python 3.10 + locked dependencies") |
| `fixture.python-runtime-break.verdict` | PASS | 0 | verdicts=["PASS", "FAIL", "FAIL", "FAIL", "FAIL"] |
| `fixture.python-runtime-break.signature` | PASS | 0 | Error: cannot import name 'MutableMapping' from 'collections' (/usr/local/lib/python3.10/collections/__init__.py)
Error: |
| `fixture.python-runtime-break.evidence` | PASS | 0 | .tomorrowci\runs\4e18b2ac852a |
| `fixture.baseline-fail.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/baseline-fail |
| `fixture.baseline-fail.scan` | PASS | 19778 | run_id=efd8c840db3f scenarios=1 |
| `fixture.baseline-fail.min_scenarios` | PASS | 0 | got 1 |
| `fixture.baseline-fail.baseline` | PASS | 0 | BaselineInvalid (want BASELINE_INVALID) |
| `fixture.baseline-fail.no_horizon` | PASS | 0 | observed=false — Baseline did not pass; future comparisons are not authorized. No observed breakage horizon. |
| `fixture.baseline-fail.evidence` | PASS | 0 | .tomorrowci\runs\efd8c840db3f |
| `fixture.flaky-project.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/flaky-project |
| `fixture.flaky-project.scan` | PASS | 19934 | run_id=6997ce5c317a scenarios=1 |
| `fixture.flaky-project.min_scenarios` | PASS | 0 | got 1 |
| `fixture.flaky-project.no_horizon` | PASS | 0 | observed=false — Baseline did not pass; future comparisons are not authorized. No observed breakage horizon. |
| `fixture.flaky-project.verdict` | PASS | 0 | verdicts=["FLAKY"] |
| `fixture.flaky-project.evidence` | PASS | 0 | .tomorrowci\runs\6997ce5c317a |
| `fixture.python-dependency-break.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/python-dependency-break |
| `fixture.python-dependency-break.scan` | PASS | 54250 | run_id=b7a5998e8ae9 scenarios=4 |
| `fixture.python-dependency-break.min_scenarios` | PASS | 0 | got 4 |
| `fixture.python-dependency-break.baseline` | PASS | 0 | BaselinePass (want BASELINE_PASS) |
| `fixture.python-dependency-break.horizon` | PASS | 0 | observed=true label=Some("Python 3.11 + latest allowed dependencies") |
| `fixture.python-dependency-break.verdict` | PASS | 0 | verdicts=["PASS", "PASS", "FAIL", "FAIL"] |
| `fixture.python-dependency-break.signature` | PASS | 0 | AssertionError: legacycompat 2.x removed old_function contract (mode=latest_allowed, version=2, path=/workspace/vendor/l |
| `fixture.python-dependency-break.evidence` | PASS | 0 | .tomorrowci\runs\b7a5998e8ae9 |
| `fixture.node-dependency-break.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/node-dependency-break |
| `fixture.node-dependency-break.scan` | PASS | 22046 | run_id=11b12b2b2948 scenarios=6 |
| `fixture.node-dependency-break.min_scenarios` | PASS | 0 | got 6 |
| `fixture.node-dependency-break.baseline` | PASS | 0 | BaselinePass (want BASELINE_PASS) |
| `fixture.node-dependency-break.horizon` | PASS | 0 | observed=true label=Some("Node.js 20 + latest allowed dependencies") |
| `fixture.node-dependency-break.verdict` | PASS | 0 | verdicts=["PASS", "PASS", "PASS", "FAIL", "FAIL", "FAIL"] |
| `fixture.node-dependency-break.signature` | PASS | 0 | AssertionError [ERR_ASSERTION]: simulated dependency API break under latest_allowed mode
AssertionError [ERR_ASSERTION]: |
| `fixture.node-dependency-break.evidence` | PASS | 0 | .tomorrowci\runs\11b12b2b2948 |
| `fixture.rust-msrv-break.exists` | PASS | 0 | C:\Users\1\Desktop\tomorrowci\fixtures/rust-msrv-break |
| `fixture.rust-msrv-break.scan` | PASS | 26562 | run_id=e2d4454041a2 scenarios=3 |
| `fixture.rust-msrv-break.min_scenarios` | PASS | 0 | got 3 |
| `fixture.rust-msrv-break.baseline` | PASS | 0 | BaselinePass (want BASELINE_PASS) |
| `fixture.rust-msrv-break.horizon` | PASS | 0 | observed=true label=Some("Rust 1.85 + locked dependencies") |
| `fixture.rust-msrv-break.verdict` | PASS | 0 | verdicts=["PASS", "FAIL", "FAIL"] |
| `fixture.rust-msrv-break.signature` | PASS | 0 | toolchain break: fixture supports rustc <= 1.84, got release=1.85.1 (major=1 minor=85)
toolchain break: fixture supports |
| `fixture.rust-msrv-break.evidence` | PASS | 0 | .tomorrowci\runs\e2d4454041a2 |
