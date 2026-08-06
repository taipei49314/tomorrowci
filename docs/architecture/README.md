# Architecture (draft)

```text
CLI → core (config, plan, verdict)
    → adapters (python | node | rust)
    → sandbox (docker/podman)
    → runner (timeouts, retries)
    → evidence (bundle + checksums)
    → report (json/sarif/html)
```

## Principles

1. Typed domain records before classification — no ad-hoc terminal grepping in the verdict engine.
2. Baseline must `BASELINE_PASS` before any breakage horizon is authorized.
3. `BLOCKED` / `UNSUPPORTED` / `INCONCLUSIVE` never become `PASS`.
4. Adapters do not execute unrestricted host shells.
5. Evidence digests and replay manifests are first-class.

## Milestone map

- M0: contracts, detection, config, doctor
- M1: Python runtime vertical slice (sandbox + evidence + replay + report)
- M2: dependency axis + ddmin
- M3: Node + Rust adapters full execution
- M4: Action + polished UI
- M5: public release candidate
