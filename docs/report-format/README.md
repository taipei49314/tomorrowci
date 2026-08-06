# Report format

## Evidence directory

```text
.tomorrowci/runs/<run-id>/
  run.json              # RunManifest
  metrics.json          # ScanMetrics
  claims.json           # Claim ledger fragment
  job-summary.md        # GitHub Actions summary
  report.html           # Accessible static report
  report.json
  frontier.json
  plan.json
  scenarios/<id>/...
```

## RunManifest (JSON)

See `crates/core` types: `RunManifest`, `ExecutionResult`, `BreakageFrontier`.

## HTML

- Generated from real `RunManifest` data (no mock dashboard)
- Untrusted strings HTML-escaped; ANSI stripped
- Text badges + aria labels (color not sole cue)
- Keyboard focus outlines; skip link; reduced-motion CSS

## SARIF

Optional `report.sarif.json` for FUTURE_FAIL results (minimal SARIF 2.1.0).
