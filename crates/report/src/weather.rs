//! Deterministic JSON and human renderers for the canonical weather-map model.

use crate::Result;
use std::fmt::Write as FmtWrite;
use std::path::Path;
use tomorrowci_core::redaction::sanitize_terminal;
use tomorrowci_core::weather::{WeatherMap, WeatherOutcomeCounts};

pub fn render_weather_json(map: &WeatherMap) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(map)?)
}

pub fn write_weather_json(path: &Path, map: &WeatherMap) -> Result<()> {
    super::atomic_write(path, &render_weather_json(map)?)
}

/// Render the same typed [`WeatherMap`] used for JSON. No counts or coverage
/// values are recomputed in the renderer.
pub fn render_weather_human(map: &WeatherMap) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "TomorrowCI ecosystem weather map");
    let _ = writeln!(output, "schema: {}", map.schema_version);
    let _ = writeln!(
        output,
        "window: {} (inclusive) to {} (exclusive)",
        map.time_window.starts_at.to_rfc3339(),
        map.time_window.ends_at.to_rfc3339()
    );
    let _ = writeln!(
        output,
        "selection policy: {} — {}",
        one_line(&map.selection_policy.id),
        one_line(&map.selection_policy.description)
    );
    let _ = writeln!(
        output,
        "population: {}",
        one_line(&map.selection_policy.population)
    );
    let _ = writeln!(output, "denominator: {}", map.denominator);
    let _ = writeln!(
        output,
        "coverage: verified={}/{} ({} bp), resolved={}/{} ({} bp), unobserved={}",
        map.coverage.verified_units,
        map.coverage.denominator,
        map.coverage.verified_basis_points,
        map.coverage.resolved_units,
        map.coverage.denominator,
        map.coverage.resolved_basis_points,
        map.coverage.unobserved_units
    );
    let _ = writeln!(output, "outcomes: {}", format_outcomes(&map.outcomes));
    let _ = writeln!(output);
    let _ = writeln!(output, "Ecosystems (fixed order)");
    for entry in &map.ecosystems {
        let _ = writeln!(
            output,
            "- {}: denominator={}, verified={}/{} ({} bp), resolved={}/{} ({} bp); {}",
            entry.ecosystem,
            entry.denominator,
            entry.coverage.verified_units,
            entry.coverage.denominator,
            entry.coverage.verified_basis_points,
            entry.coverage.resolved_units,
            entry.coverage.denominator,
            entry.coverage.resolved_basis_points,
            format_outcomes(&entry.outcomes)
        );
    }

    let _ = writeln!(output);
    let _ = writeln!(output, "Verified run identities");
    if map.runs.is_empty() {
        let _ = writeln!(output, "- (none)");
    } else {
        for run in &map.runs {
            let commit = run.commit_sha.as_deref().unwrap_or("uncommitted-snapshot");
            let _ = writeln!(
                output,
                "- {}/{}: {} {} run={} source={}@{} inventory=v{}:{} source_manifest={} model={} completed={}",
                run.ecosystem,
                one_line(&run.selection_unit_id),
                format!("{:?}", run.outcome).to_ascii_uppercase(),
                format!("{:?}", run.source_kind).to_ascii_uppercase(),
                one_line(&run.run_id.0),
                one_line(&run.source),
                one_line(commit),
                run.inventory_version,
                run.inventory_sha256,
                run.source_manifest_sha256,
                run.typed_model_sha256,
                run.completed_at.to_rfc3339()
            );
        }
    }

    let _ = writeln!(output);
    let _ = writeln!(output, "Uncertainty and inference boundary");
    let _ = writeln!(output, "- scope: {:?}", map.inference_boundary.scope);
    let _ = writeln!(
        output,
        "- adoption/prevalence inference permitted: {}",
        map.inference_boundary.adoption_or_prevalence_permitted
    );
    let _ = writeln!(
        output,
        "- reason: {}",
        one_line(&map.inference_boundary.reason)
    );
    for limitation in &map.uncertainty.limitations {
        let _ = writeln!(output, "- limitation: {}", one_line(limitation));
    }
    output
}

pub fn write_weather_human(path: &Path, map: &WeatherMap) -> Result<()> {
    super::atomic_write(path, render_weather_human(map).as_bytes())
}

fn format_outcomes(outcomes: &WeatherOutcomeCounts) -> String {
    format!(
        "PASS={}, FAIL={}, FLAKY={}, BLOCKED={}, UNSUPPORTED={}, INCONCLUSIVE={}, UNOBSERVED={} (total={})",
        outcomes.pass,
        outcomes.fail,
        outcomes.flaky,
        outcomes.blocked,
        outcomes.unsupported,
        outcomes.inconclusive,
        outcomes.unobserved,
        outcomes.total()
    )
}

fn one_line(value: &str) -> String {
    sanitize_terminal(value)
        .replace('\n', "\\n")
        .replace('\u{2028}', "\\u{2028}")
        .replace('\u{2029}', "\\u{2029}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use tempfile::tempdir;
    use tomorrowci_core::weather::{
        EcosystemWeather, WeatherCoverage, WeatherInferenceBoundary, WeatherInferenceScope,
        WeatherOutcome, WeatherRunSummary, WeatherSelectionPolicy, WeatherSelectionUnit,
        WeatherSourceKind, WeatherTimeWindow, WeatherUncertainty, WEATHER_MAP_SCHEMA_VERSION,
    };
    use tomorrowci_core::{Ecosystem, RunId};

    fn counts() -> WeatherOutcomeCounts {
        WeatherOutcomeCounts {
            pass: 0,
            fail: 0,
            flaky: 0,
            blocked: 1,
            unsupported: 1,
            inconclusive: 0,
            unobserved: 1,
        }
    }

    fn coverage(denominator: u64, verified: u64) -> WeatherCoverage {
        WeatherCoverage {
            denominator,
            verified_units: verified,
            unobserved_units: denominator - verified,
            resolved_units: 0,
            verified_basis_points: if denominator == 0 { 0 } else { 6_666 },
            resolved_basis_points: 0,
        }
    }

    fn map() -> WeatherMap {
        let starts_at = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        let ends_at = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        WeatherMap {
            schema_version: WEATHER_MAP_SCHEMA_VERSION,
            selection_policy: WeatherSelectionPolicy {
                id: "policy\u{1b}[2J".into(),
                description: "pre-registered\nnot outcome selected".into(),
                population: "three selected units".into(),
                inclusion_criteria: vec!["before outcomes".into()],
                exclusion_criteria: vec![],
                declared_denominator: 3,
                selected_units: vec![WeatherSelectionUnit {
                    id: "fixture-python".into(),
                    ecosystem: Ecosystem::Python,
                    source_kind: WeatherSourceKind::ProjectFixture,
                    source: "fixture".into(),
                    commit_sha: None,
                }],
            },
            time_window: WeatherTimeWindow { starts_at, ends_at },
            denominator: 3,
            outcomes: counts(),
            coverage: coverage(3, 2),
            uncertainty: WeatherUncertainty {
                unobserved_units: 1,
                blocked_units: 1,
                unsupported_units: 1,
                inconclusive_units: 0,
                flaky_units: 0,
                includes_project_fixtures: true,
                limitations: vec!["fixtures are not adoption\nprevalence".into()],
            },
            inference_boundary: WeatherInferenceBoundary {
                scope: WeatherInferenceScope::SelectedUnitsOnly,
                adoption_or_prevalence_permitted: false,
                reason: "selected units only".into(),
            },
            ecosystems: vec![EcosystemWeather {
                ecosystem: Ecosystem::Python,
                denominator: 1,
                outcomes: WeatherOutcomeCounts {
                    blocked: 1,
                    ..WeatherOutcomeCounts::default()
                },
                coverage: WeatherCoverage {
                    denominator: 1,
                    verified_units: 1,
                    unobserved_units: 0,
                    resolved_units: 0,
                    verified_basis_points: 10_000,
                    resolved_basis_points: 0,
                },
            }],
            runs: vec![WeatherRunSummary {
                selection_unit_id: "fixture-python".into(),
                run_id: RunId("run-one".into()),
                ecosystem: Ecosystem::Python,
                source_kind: WeatherSourceKind::ProjectFixture,
                source: "fixture\nspoof".into(),
                commit_sha: None,
                completed_at: starts_at,
                outcome: WeatherOutcome::Blocked,
                inventory_version: 2,
                inventory_sha256: "a".repeat(64),
                source_manifest_sha256: "b".repeat(64),
                typed_model_sha256: "c".repeat(64),
            }],
        }
    }

    #[test]
    fn json_is_the_canonical_typed_model() {
        let map = map();
        let bytes = render_weather_json(&map).unwrap();
        let reparsed: WeatherMap = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reparsed, map);
    }

    #[test]
    fn human_report_uses_model_counts_and_sanitizes_control_text() {
        let rendered = render_weather_human(&map());
        assert!(rendered.contains("denominator: 3"));
        assert!(rendered.contains("BLOCKED=1"));
        assert!(rendered.contains("UNSUPPORTED=1"));
        assert!(rendered.contains("UNOBSERVED=1"));
        assert!(rendered.contains("adoption/prevalence inference permitted: false"));
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("fixture\\nspoof"));
    }

    #[test]
    fn writes_both_formats_without_divergent_models() {
        let dir = tempdir().unwrap();
        let map = map();
        let json = dir.path().join("weather.json");
        let human = dir.path().join("weather.txt");
        write_weather_json(&json, &map).unwrap();
        write_weather_human(&human, &map).unwrap();
        let reparsed: WeatherMap = serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
        assert_eq!(reparsed, map);
        assert!(std::fs::read_to_string(human)
            .unwrap()
            .contains("denominator: 3"));
    }
}
