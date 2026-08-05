# Policy gate

Deterministic fail-if rules over completed run evidence. Verdict classification stays separate from policy.

```bash
tomorrowci policy <run-id>
tomorrowci policy <head-run-id> --base <base-run-id>
tomorrowci policy <run-id> --policy .tomorrowci-policy.yml --out policy.json
```

Exit code **6** when decision is `FAIL`.

## Default rules

```yaml
fail_if:
  baseline_invalid: true
  new_future_failure: false
  horizon_regression: true   # requires --base
  blocked_ratio_above: 0.50  # null to disable
```

| Rule | Meaning |
|---|---|
| `baseline_invalid` | Baseline did not pass |
| `new_future_failure` | Any `FUTURE_FAIL` scenario |
| `horizon_regression` | Head horizon earlier / new vs base |
| `blocked_ratio_above` | Share of BLOCKED/UNSUPPORTED/INCONCLUSIVE |

**Never:** `BLOCKED` / `UNSUPPORTED` / `INCONCLUSIVE` are converted to `PASS`. A high blocked ratio may cause policy **FAIL** if configured — that is a gate, not a green claim.

## Example gate mode

```yaml
fail_if:
  baseline_invalid: true
  new_future_failure: true
  horizon_regression: true
  blocked_ratio_above: 0.25
```
