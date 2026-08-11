# Ecosystem weather map

`tomorrowci weather` produces a descriptive cross-ecosystem summary from
sealed v2 run bundles. It does not execute target code, rediscover candidates,
or accept a caller-authored claim that a run was verified.

```bash
tomorrowci --evidence-root .tomorrowci weather \
  --manifest weather-selection.json \
  --format json \
  --output .tomorrowci/weather-map.json

tomorrowci --evidence-root .tomorrowci weather \
  --manifest weather-selection.json \
  --format human \
  --output .tomorrowci/weather-map.txt
```

Both files are atomically written outside every selected sealed run. JSON and
human output render the same `WeatherMap`; the human renderer does not maintain
an independent count or coverage calculation.

## Selection manifest

The JSON manifest is strict: unknown or missing fields fail. A selector may
name a run ID below `--evidence-root`, or an explicit absolute / `./relative`
run-bundle path.

```json
{
  "schema_version": 1,
  "selection_policy": {
    "id": "pre-registered-2026-08",
    "description": "Repositories fixed before outcomes were inspected",
    "population": "The explicitly listed units, not an ecosystem-wide sample",
    "inclusion_criteria": ["one immutable source revision per selected unit"],
    "exclusion_criteria": ["no replacement after observing an outcome"],
    "declared_denominator": 3,
    "selected_units": [
      {
        "id": "python-project",
        "ecosystem": "python",
        "source_kind": "EXTERNAL_REPOSITORY",
        "source": "https://github.com/example/python-project",
        "commit_sha": "0123456789abcdef0123456789abcdef01234567"
      },
      {
        "id": "node-project",
        "ecosystem": "node",
        "source_kind": "EXTERNAL_REPOSITORY",
        "source": "https://github.com/example/node-project",
        "commit_sha": "89abcdef0123456789abcdef0123456789abcdef"
      },
      {
        "id": "rust-fixture",
        "ecosystem": "rust",
        "source_kind": "PROJECT_FIXTURE",
        "source": "fixtures/rust-msrv-break",
        "commit_sha": null
      }
    ]
  },
  "time_window": {
    "starts_at": "2026-08-01T00:00:00Z",
    "ends_at": "2026-09-01T00:00:00Z"
  },
  "runs": [
    {
      "selection_unit_id": "python-project",
      "run": "python-run-id",
      "selection_policy_id": "pre-registered-2026-08",
      "time_window": {
        "starts_at": "2026-08-01T00:00:00Z",
        "ends_at": "2026-09-01T00:00:00Z"
      }
    }
  ]
}
```

`declared_denominator` must exactly equal the complete `selected_units` set.
It may be greater than the number of supplied runs: selected units with no
verified run remain `UNOBSERVED`. Removing their outcome does not improve
coverage.

## Verification and identity boundary

For every selector, the CLI first runs the normal exact-inventory verifier.
Only `kind=run`, inventory v2-or-later bundles proceed. It then reads
`run.json`, `verdicts.json`, and `source-manifest.json` through the retained
`VerifiedBundle` generation. The output binds each accepted observation to:

- run ID and selected-unit ID;
- source, ecosystem, and exact commit where declared;
- canonical inventory SHA-256 and inventory version;
- source-manifest SHA-256;
- SHA-256 of the exact typed run/verdict models;
- completion time inside one common `[starts_at, ends_at)` window.

An unsealed/mutated bundle, duplicate run or inventory, duplicate selection
unit, mixed policy/window, source mismatch, or typed-model substitution fails
the entire aggregation.

The Rust trust boundary is `tomorrowci_evidence::aggregate_verified_weather_map`.
It accepts opaque `VerifiedBundle` generations and derives every digest and the
VERIFIED state itself. The core `aggregate_preverified_weather_map` function is
only a deterministic reducer for already-authenticated typed models; its
serializable identity structs are report data and are not proof of verification.

## Denominator, coverage, and uncertainty

The top-level and per-ecosystem counts always sum to their declared
denominators:

```text
PASS + FAIL + FLAKY + BLOCKED + UNSUPPORTED + INCONCLUSIVE + UNOBSERVED
  = denominator
```

`verified_units` includes verified `BLOCKED` and `UNSUPPORTED` observations;
those statuses remain explicit and are never converted to PASS.
`resolved_units` includes only PASS and FAIL. Coverage uses integer basis
points to avoid platform-dependent floating-point rendering.

The inference boundary is always `SELECTED_UNITS_ONLY`, and
`adoption_or_prevalence_permitted` is always false. In particular, project
fixtures are executable test cases; they are not evidence of adoption or
ecosystem prevalence.
