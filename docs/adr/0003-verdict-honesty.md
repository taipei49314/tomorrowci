# ADR 0003: Verdict honesty and evidence grades

## Status

Accepted

## Context

Collapsing every outcome into PASS/FAIL creates false confidence about future
compatibility.

## Decision

- Typed verdicts: BASELINE_*, FUTURE_*, FLAKY, BLOCKED, UNSUPPORTED, INCONCLUSIVE
- Breakage horizon only after baseline pass + confirmed FUTURE_FAIL reruns
- Evidence grades: OBSERVED / SIMULATED / SCHEDULED_RISK / INCONCLUSIVE
- Never promote BLOCKED/UNSUPPORTED/INCONCLUSIVE to PASS
- No LLM-only root-cause claims in the deterministic engine

## Consequences

+ Users can trust report semantics  
+ Policy gates can fail on regressions without treating infra gaps as green  
