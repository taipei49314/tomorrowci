# Terminal demo (text recording)

Captured from a real Milestone 5 verification session.

```text
$ cargo run -p tomorrowci-cli -- trust
TomorrowCI trust audit
overall: Pass
[Pass] T1_SAFE_DEFAULTS — SecurityPolicy rejects privileged/docker.sock/host mutation
[Pass] T2_NO_HOST_EXEC — Host execution of target code is refused by default
[Pass] T3_NO_PRIVILEGED — Privileged containers are rejected
[Pass] T4_NO_DOCKER_SOCK — docker.sock mount into target is rejected
[Blocked] T5_ENGINE_HONEST — No sandbox engine (daemon down) — not silent host run
[Pass] T6_NO_VERDICT_PROMOTE — BLOCKED/UNSUPPORTED/INCONCLUSIVE cannot be PASS
[Pass] T8_GIT — git available
status: PASS

$ cargo run -p tomorrowci-gen-demo
wrote demo to examples/reports/python-runtime-break
metrics: eco=Python total=4 pass=1 fail=3 flaky=0 blocked=0 frontier=true

$ cargo run -p tomorrowci-cli -- doctor
docker: false | selected_engine: NONE (sandbox BLOCKED)
host_execution_of_targets: FORBIDDEN by default
```

Live container e2e requires Docker Desktop daemon. Without it, execution is
**BLOCKED** (honest), while detection, trust, planner tests, and demo reports remain valid.
