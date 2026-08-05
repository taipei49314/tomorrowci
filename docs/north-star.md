# North-star extensions (post / toward v0.1+)

## Done in-tree (instrumented)

| Capability | Command | Status |
|---|---|---|
| Measurement harness | `tomorrowci measure all` | Live — PASS/FAIL/BLOCKED ledger |
| Bounded parallel scenarios | config `execution.max_parallel` | Live — baseline serial, futures `buffer_unordered` |
| Horizon compare (base→head) | `tomorrowci compare <base> <head>` | Live — regression exit 5 |
| Policy fail-if gate | `tomorrowci policy <run>` | Live — exit 6 on FAIL |
| Backtest skeleton | `tomorrowci backtest --at --until` | Live — commit sampling only |

## Honest limits

### Backtest (M2 skeleton)

- Samples **repository commits** in a date range and runs current TomorrowCI candidates on each tree.
- Does **not** recreate historical package indexes or registry state as of that date.
- Evidence grade for package-time-travel claims remains out of scope until full M2.

### Compare

- Compares **already executed** run frontiers by order keys extracted from labels.
- Does not re-scan; pair with two `scan` invocations (e.g. base branch vs PR).

## Next

- Full historical package index reconstruction
- Ecosystem weather map aggregation
- Patch laboratory (separate from verdict path)
- Adapter SDK plugins
