//! M1/M2 pipeline tests using scripted executor (no Docker required).

use std::collections::HashMap;
use tempfile::tempdir;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{Config, EnvironmentAxis, Verdict};
use tomorrowci_runner::{scan_with_executor, ScriptedExecutor};

fn write_py_fixture(root: &std::path::Path) {
    std::fs::write(
        root.join("requirements.txt"),
        "pytest==7.4.4\n",
    )
    .unwrap();
    std::fs::write(
        root.join("app.py"),
        "from collections import MutableMapping\ndef ok():\n    return True\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("tests/test_app.py"),
        "import app\ndef test_ok():\n    assert app.ok()\n",
    )
    .unwrap();
}

#[test]
fn python_runtime_break_horizon_scripted() {
    let d = tempdir().unwrap();
    write_py_fixture(d.path());
    let adapter = PythonAdapter;
    let det = adapter.detect(d.path());
    assert!(det.supported);

    let mut cfg = Config::default();
    cfg.baseline.runtime = "3.9".into();
    cfg.baseline.dependencies = "locked".into();
    cfg.candidates.runtime.max_versions = 3;
    cfg.candidates.dependencies.latest_allowed = false;
    cfg.execution.reruns_on_failure = 2;
    cfg.execution.max_scenarios = 6;

    // baseline pass; py310/311/312 fail consistently
    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![0]);
    map.insert("py310-locked".into(), vec![1, 1]);
    map.insert("py311-locked".into(), vec![1, 1]);
    map.insert("py312-locked".into(), vec![1, 1]);
    let exec = ScriptedExecutor::new(map).with_stderr(
        "ImportError: cannot import name 'MutableMapping' from 'collections'",
    );

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    assert!(
        out.manifest.frontier.observed,
        "summary:\n{}",
        out.terminal_summary
    );
    assert_eq!(
        out.manifest.frontier.horizon_label.as_deref(),
        Some("3.10")
    );
    assert!(out.evidence_root.join("report.html").exists());
    assert!(out.evidence_root.join("run.json").exists());
    assert!(out.terminal_summary.contains("Observed breakage horizon"));
    assert!(out.terminal_summary.contains("ImportError") || out.manifest.frontier.failure_signature.is_some());
}

#[test]
fn baseline_invalid_blocks_horizon() {
    let d = tempdir().unwrap();
    write_py_fixture(d.path());
    let adapter = PythonAdapter;
    let det = adapter.detect(d.path());
    let mut cfg = Config::default();
    cfg.baseline.runtime = "3.9".into();
    cfg.candidates.dependencies.latest_allowed = false;
    cfg.execution.max_scenarios = 4;

    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![1]); // fail baseline
    map.insert("py310-locked".into(), vec![1]);
    let exec = ScriptedExecutor::new(map);

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    assert!(!out.manifest.frontier.observed);
    assert!(out
        .manifest
        .results
        .iter()
        .any(|r| r.verdict == Verdict::BaselineInvalid));
}

#[test]
fn flaky_not_future_fail() {
    let d = tempdir().unwrap();
    write_py_fixture(d.path());
    let adapter = PythonAdapter;
    let det = adapter.detect(d.path());
    let mut cfg = Config::default();
    cfg.baseline.runtime = "3.9".into();
    cfg.candidates.dependencies.latest_allowed = false;
    cfg.execution.reruns_on_failure = 3;
    cfg.execution.max_scenarios = 4;

    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![0]);
    // alternating fail/pass => FLAKY
    map.insert("py310-locked".into(), vec![1, 0, 1]);
    let exec = ScriptedExecutor::new(map);

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    let py310 = out
        .manifest
        .results
        .iter()
        .find(|r| r.scenario_id == "py310-locked")
        .unwrap();
    assert_eq!(py310.verdict, Verdict::Flaky);
    // horizon must not treat flaky as confirmed FUTURE_FAIL without consistent fails
    // (first fail not all-fail => not confirmed)
}

#[test]
fn dependency_axis_and_ddmin_reduction() {
    let d = tempdir().unwrap();
    write_py_fixture(d.path());
    let adapter = PythonAdapter;
    let det = adapter.detect(d.path());
    let mut cfg = Config::default();
    cfg.baseline.runtime = "3.9".into();
    cfg.candidates.runtime.max_versions = 1; // one runtime cand
    cfg.candidates.dependencies.latest_allowed = true;
    cfg.execution.max_scenarios = 10;
    cfg.execution.reruns_on_failure = 2;

    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![0]);
    map.insert("py310-locked".into(), vec![0, 0]); // runtime alone passes
    map.insert("deps-latest-allowed".into(), vec![1, 1]); // deps alone fails
    map.insert("combo-py310-locked-deps-latest-allowed".into(), vec![1, 1]);
    let exec = ScriptedExecutor::new(map)
        .with_stderr("RuntimeError: simulated dependency API break");

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    assert!(out.evidence_root.join("reduction.json").exists() || out.manifest.results.iter().any(|r| r.scenario_id.starts_with("deps-")));
    let dep = out
        .manifest
        .results
        .iter()
        .find(|r| r.scenario_id == "deps-latest-allowed");
    assert!(dep.is_some());
    assert_eq!(dep.unwrap().verdict, Verdict::FutureFail);
    // reduction file should prefer Dependencies axis
    if out.evidence_root.join("reduction.json").exists() {
        let raw = std::fs::read_to_string(out.evidence_root.join("reduction.json")).unwrap();
        assert!(raw.contains("Dependencies") || raw.contains("dependencies"));
    }
    let _ = EnvironmentAxis::Dependencies;
}
