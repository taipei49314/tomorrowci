# Validate a Python dependency rollback

An observed `PROVEN_MINIMAL` reduction identifies a set that reproduces the
original failure. It does not prove that rolling that set back repairs the full
upgrade. A second independent failure or a dependency conflict can remain.

After a wheel-backed Python dependency scan:

```sh
tomorrowci rollback RUN_ID --out rollback-evidence
tomorrowci verify-rollback RUN_ID --out rollback-evidence
```

Run both commands from the original diagnosis workspace so `RUN_ID` resolves to
its `.tomorrowci/runs` directory. The output must be a new directory, outside the
diagnosis evidence. The original run is preserved byte for byte.

`rollback` derives the full after set minus exactly the diagnosed updates. All
other upgrades are retained. It copies the verified source, wheel bytes and test
configuration into a separate experiment and runs the original baseline and
the repaired candidate in Docker. A passing candidate is freshly replayed.
Only verified command success followed by a passing replay produces
`VERIFIED_COMMANDS_PASS` and these files:

- `requirements.before.txt`: full baseline closure with wheel hashes.
- `requirements.after.txt`: full upgrade closure with wheel hashes.
- `requirements.rollback.txt`: verified repair closure with wheel hashes.
- `requirements.patch`: the full-after to repaired-pins difference.

The output also retains `rollback-request.json`, `rollback-result.json`, the
copied source and the new `.tomorrowci/runs/RUN_ID` raw evidence. The requirements
are installation inputs for the verified wheelhouse, not an automatically
rewritten Poetry/uv lockfile. Keep both original and rollback evidence when
sharing the repair. `verify-rollback` accepts relocated evidence and re-derives
the complement, source/configuration equality and exact repair files. Every
recorded candidate replay must reproduce success; a later contradictory replay
invalidates the repair verification.

Current scope: local Python v2 wheel experiments, one fixed runtime, same-name
dependency updates, an observed minimal diagnosis and a baseline that passed on
its first attempt. Remote synthetic-Git trials are refused. A rollback that
retains no updates reports `NO_RETAINED_UPDATES` and does not publish repair
pins. Failed/blocked/flaky/incomplete validation never authorizes a repair.

The claim covers the original selected commands for this precise dependency
closure and runtime. It does not prove compatibility outside that scope, equal
test IDs, or a globally minimal repair. Existing strict test-coverage contracts
remain unchanged.

The [2026-11-05 natural batch rehearsal](PYTHON_ROLLBACK_REHEARSAL_20261105.md)
compares this workflow with a local matrix plus AI and depsect. It verifies one
repair, while recording native uv integration and unmeasured effort as gaps.
This checkout also binds unambiguous pytest failure blocks to test IDs before
normalizing parallel output order. Rescan older failures before comparing or
replaying evidence produced with the earlier fingerprint algorithm.

## Live regression

```sh
python scripts/test_python_rollback_live.py \
  --binary target/debug/tomorrowci \
  --work-dir /new/rollback-regression \
  --image python@sha256:YOUR_PINNED_PYTHON_311_IMAGE_DIGEST
```

The standard-library host harness writes synthetic wheels; all target code runs
inside Docker. It preserves raw scan, rollback, verification and tamper-test
receipts. Controls cover a valid repair retaining another update, a second
independent failure, an installation conflict, an empty retained set and an
incomplete diagnosis. Unit tests additionally cover baseline flakiness, later
contradictory replay, publication failure and Windows path aliases.
