# Report format

## Evidence directory

```text
.tomorrowci/runs/<run-id>/
  run.json
  repository.json
  config.normalized.json
  plan.json
  candidates.json
  verdicts.json
  frontier.json
  report.html
  report.json
  checksums.txt
  scenarios/<scenario-id>/
    scenario.json
    environment.json
    commands.json
    stdout.log
    stderr.log
    result.json
    failure-signature.json
    replay-manifest.json
    replay.sh
    replay.ps1
    checksums.txt
```

## HTML

Self-contained file generated from **real** run JSON. Views:

1. Horizon timeline  
2. Scenario matrix  
3. Failure evidence + replay  
4. Planner/execution graph  

Accessibility: semantic landmarks, table headers, visible focus, text badges (not color alone), `prefers-reduced-motion`.

## SARIF

Optional `report.sarif` maps `FUTURE_FAIL` / `BASELINE_INVALID` to SARIF results (`tomorrowci/future-fail`).
