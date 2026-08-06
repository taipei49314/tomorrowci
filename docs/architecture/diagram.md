# Architecture diagram

```mermaid
flowchart TB
  CLI[tomorrowci CLI] --> CORE[core: config planner verdict]
  CLI --> METRICS[metrics: trust + scan metrics]
  CORE --> ADAPTERS[adapters: python node rust]
  ADAPTERS --> RUNNER[runner: orchestrate]
  RUNNER --> SANDBOX[sandbox: docker/podman]
  RUNNER --> EVIDENCE[evidence bundle]
  EVIDENCE --> REPORT[report: html json sarif summary]
  ACTION[GitHub Action] --> CLI
```

## Trust boundary

```text
[ Developer host ] --CLI--> [ TomorrowCI trusted code ]
                                |
                                v
                         [ Container engine TCB ]
                                |
                                v
                         [ Untrusted target + packages ]
```
