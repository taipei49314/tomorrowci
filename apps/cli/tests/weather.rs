use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;
use tomorrowci_core::{
    Ecosystem, RunManifest, WeatherMap, WeatherSelectionPolicy, WeatherSelectionUnit,
    WeatherSourceKind, WeatherTimeWindow, WEATHER_MAP_SCHEMA_VERSION,
};
use tomorrowci_evidence::{verify_bundle, BundleKind};

fn tomorrowci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
}

fn assert_failure(output: Output, expected: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected failure: stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains(expected),
        "missing {expected:?}: stdout={stdout:?} stderr={stderr:?}"
    );
}

fn make_blocked_v2_run(root: &Path) -> (PathBuf, String, RunManifest) {
    let target = root.join("python-fixture");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("requirements.txt"), b"pytest==8.0.0\n").unwrap();
    let evidence = root.join("evidence");
    let work = root.join("work");
    let empty_path = root.join("empty-path");
    fs::create_dir(&empty_path).unwrap();

    let output = tomorrowci()
        .current_dir(root)
        .arg("--evidence-root")
        .arg(&evidence)
        .arg("--work-root")
        .arg(&work)
        .arg("scan")
        .arg(&target)
        .env("PATH", &empty_path)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "scan should produce honest BLOCKED evidence without an engine: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run_paths = fs::read_dir(evidence.join("runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(run_paths.len(), 1);
    let run_path = run_paths[0].clone();
    let verified = verify_bundle(&run_path).unwrap();
    assert_eq!(verified.version, 2);
    assert_eq!(verified.kind, BundleKind::Run);
    let run: RunManifest = verified.read_json("run.json").unwrap();
    assert_eq!(run.status, tomorrowci_core::RunStatus::Blocked);
    (evidence, run.run_id.0.clone(), run)
}

fn selection_unit(id: &str, run: &RunManifest) -> WeatherSelectionUnit {
    WeatherSelectionUnit {
        id: id.into(),
        ecosystem: Ecosystem::Python,
        source_kind: WeatherSourceKind::ProjectFixture,
        source: run.repository.source.clone(),
        commit_sha: run.repository.commit_sha.clone(),
    }
}

fn policy(units: Vec<WeatherSelectionUnit>, denominator: u64) -> WeatherSelectionPolicy {
    WeatherSelectionPolicy {
        id: "binary-integration-policy".into(),
        description: "Pre-declared binary integration cohort".into(),
        population: "Explicit selected test units".into(),
        inclusion_criteria: vec!["selected before weather aggregation".into()],
        exclusion_criteria: vec!["no outcome replacement".into()],
        declared_denominator: denominator,
        selected_units: units,
    }
}

fn selector(unit: &str, run: &str, window: &WeatherTimeWindow) -> serde_json::Value {
    serde_json::json!({
        "selection_unit_id": unit,
        "run": run,
        "selection_policy_id": "binary-integration-policy",
        "time_window": window,
    })
}

fn manifest(
    selection_policy: WeatherSelectionPolicy,
    window: &WeatherTimeWindow,
    runs: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": WEATHER_MAP_SCHEMA_VERSION,
        "selection_policy": selection_policy,
        "time_window": window,
        "runs": runs,
    })
}

fn invoke_weather(evidence: &Path, manifest_path: &Path, output: &Path) -> Output {
    tomorrowci()
        .arg("--evidence-root")
        .arg(evidence)
        .arg("weather")
        .arg("--manifest")
        .arg(manifest_path)
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn real_weather_cli_verifies_runs_and_rejects_untrusted_or_biased_inputs() {
    let temp = tempdir().unwrap();
    let (evidence, run_id, run) = make_blocked_v2_run(temp.path());
    let run_path = evidence.join("runs").join(&run_id);
    let run_before = fs::read(run_path.join("run.json")).unwrap();
    let finished = run.finished_at.unwrap();
    let window = WeatherTimeWindow {
        starts_at: run.started_at - chrono::Duration::seconds(1),
        ends_at: finished + chrono::Duration::seconds(1),
    };
    let selected = selection_unit("python-fixture", &run);

    // Positive path: a real verified v2 run drives both the typed JSON and the
    // human renderer. The output is preseeded as a hardlink to prove atomic
    // replacement cannot truncate sealed evidence.
    let valid_manifest = temp.path().join("weather-valid.json");
    fs::write(
        &valid_manifest,
        serde_json::to_vec_pretty(&manifest(
            policy(vec![selected.clone()], 1),
            &window,
            vec![selector("python-fixture", &run_id, &window)],
        ))
        .unwrap(),
    )
    .unwrap();
    let output_path = temp.path().join("weather-output.json");
    fs::hard_link(run_path.join("run.json"), &output_path).unwrap();
    let output = invoke_weather(&evidence, &valid_manifest, &output_path);
    assert!(
        output.status.success(),
        "weather failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let map: WeatherMap = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(map.denominator, 1);
    assert_eq!(map.outcomes.blocked, 1);
    assert_eq!(map.outcomes.unsupported, 0);
    assert_eq!(map.outcomes.total(), 1);
    assert_eq!(map.coverage.verified_units, 1);
    assert!(!map.inference_boundary.adoption_or_prevalence_permitted);
    assert_eq!(fs::read(run_path.join("run.json")).unwrap(), run_before);
    verify_bundle(&run_path).unwrap();

    // An unsealed directory cannot become a weather observation by appearing
    // in a caller-authored manifest.
    let unsealed = temp.path().join("unsealed-run");
    fs::create_dir(&unsealed).unwrap();
    fs::write(unsealed.join("run.json"), b"{}\n").unwrap();
    let unverified_manifest = temp.path().join("weather-unverified.json");
    fs::write(
        &unverified_manifest,
        serde_json::to_vec_pretty(&manifest(
            policy(vec![selected.clone()], 1),
            &window,
            vec![selector(
                "python-fixture",
                unsealed.to_str().unwrap(),
                &window,
            )],
        ))
        .unwrap(),
    )
    .unwrap();
    let unverified_output = temp.path().join("unverified-output.json");
    assert_failure(
        invoke_weather(&evidence, &unverified_manifest, &unverified_output),
        "checksums.txt is missing",
    );
    assert!(!unverified_output.exists());

    // Reusing one verified run under two denominator units is rejected.
    let second = selection_unit("python-fixture-copy", &run);
    let duplicate_manifest = temp.path().join("weather-duplicate.json");
    fs::write(
        &duplicate_manifest,
        serde_json::to_vec_pretty(&manifest(
            policy(vec![selected.clone(), second], 2),
            &window,
            vec![
                selector("python-fixture", &run_id, &window),
                selector("python-fixture-copy", &run_id, &window),
            ],
        ))
        .unwrap(),
    )
    .unwrap();
    assert_failure(
        invoke_weather(
            &evidence,
            &duplicate_manifest,
            &temp.path().join("duplicate-output.json"),
        ),
        "duplicate run id",
    );

    // A selector cannot smuggle a run into a different cohort window.
    let mixed_window = WeatherTimeWindow {
        starts_at: window.starts_at,
        ends_at: window.ends_at + chrono::Duration::days(1),
    };
    let mixed_manifest = temp.path().join("weather-mixed-window.json");
    fs::write(
        &mixed_manifest,
        serde_json::to_vec_pretty(&manifest(
            policy(vec![selected.clone()], 1),
            &window,
            vec![selector("python-fixture", &run_id, &mixed_window)],
        ))
        .unwrap(),
    )
    .unwrap();
    assert_failure(
        invoke_weather(
            &evidence,
            &mixed_manifest,
            &temp.path().join("mixed-output.json"),
        ),
        "different time window",
    );

    // The independent declared denominator must equal the complete selected
    // unit set, so a producer cannot quietly shrink it to improve coverage.
    let dropped_manifest = temp.path().join("weather-dropped-denominator.json");
    fs::write(
        &dropped_manifest,
        serde_json::to_vec_pretty(&manifest(
            policy(vec![selected], 0),
            &window,
            vec![selector("python-fixture", &run_id, &window)],
        ))
        .unwrap(),
    )
    .unwrap();
    assert_failure(
        invoke_weather(
            &evidence,
            &dropped_manifest,
            &temp.path().join("dropped-output.json"),
        ),
        "denominator 0 does not equal its 1 selected units",
    );
}
