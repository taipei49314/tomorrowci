//! M3 Node + Rust pipeline tests (scripted executor; no Docker required).

use std::collections::HashMap;
use tempfile::tempdir;
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{Config, Verdict};
use tomorrowci_runner::{scan_with_executor, ScriptedExecutor};

#[test]
fn node_runtime_break_horizon() {
    let d = tempdir().unwrap();
    std::fs::write(
        d.path().join("package.json"),
        r#"{"name":"n","scripts":{"test":"node --test"},"type":"commonjs"}"#,
    )
    .unwrap();
    std::fs::write(d.path().join("index.js"), "exports.x=1\n").unwrap();
    std::fs::create_dir_all(d.path().join("test")).unwrap();
    std::fs::write(d.path().join("test/a.test.js"), "require('node:test')\n").unwrap();

    let adapter = NodeAdapter;
    let det = adapter.detect(d.path());
    assert!(det.supported);

    let mut cfg = Config::default();
    cfg.baseline.runtime = "20".into();
    cfg.baseline.dependencies = "locked".into();
    cfg.candidates.runtime.max_versions = 2;
    cfg.candidates.dependencies.latest_allowed = false;
    cfg.execution.reruns_on_failure = 2;
    cfg.execution.max_scenarios = 6;

    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![0]);
    map.insert("node18-locked".into(), vec![1, 1]); // first ordered cand after skip 20
    map.insert("node22-locked".into(), vec![0, 0]);
    // candidates order: 18, 22, 24 — 20 skipped as baseline
    let exec = ScriptedExecutor::new(map)
        .with_stderr("TypeError: arr.toSorted is not a function");

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    assert!(
        out.manifest.frontier.observed,
        "{}",
        out.terminal_summary
    );
    assert_eq!(out.manifest.detection.ecosystem, tomorrowci_core::Ecosystem::Node);
    assert!(out.evidence_root.join("report.html").exists());
    assert!(out.terminal_summary.contains("Observed breakage horizon"));
}

#[test]
fn rust_msrv_break_horizon() {
    let d = tempdir().unwrap();
    std::fs::write(
        d.path().join("Cargo.toml"),
        "[package]\nname=\"r\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(d.path().join("src")).unwrap();
    std::fs::write(d.path().join("src/lib.rs"), "pub fn x()->i32{1}\n#[test] fn t(){assert_eq!(x(),1)}\n")
        .unwrap();

    let adapter = RustAdapter;
    let det = adapter.detect(d.path());
    assert!(det.supported);

    let mut cfg = Config::default();
    cfg.baseline.runtime = "1.83".into();
    cfg.candidates.runtime.max_versions = 2;
    cfg.candidates.dependencies.latest_allowed = false;
    cfg.execution.reruns_on_failure = 2;
    cfg.execution.max_scenarios = 6;

    // candidates: 1.74, beta (nightly may be truncated by max)
    let mut map = HashMap::new();
    map.insert("baseline".into(), vec![0]);
    map.insert("rust-174".into(), vec![1, 1]);
    map.insert("rust-beta".into(), vec![0, 0]);
    let exec = ScriptedExecutor::new(map).with_stderr(
        "error[E0658]: use of unstable library feature `lazy_cell` (MSRV)",
    );

    let out = scan_with_executor(d.path(), &adapter, cfg, &exec, det.detection).unwrap();
    assert!(
        out.manifest.frontier.observed,
        "{}",
        out.terminal_summary
    );
    assert_eq!(
        out.manifest.frontier.horizon_label.as_deref(),
        Some("1.74")
    );
    let fail = out
        .manifest
        .results
        .iter()
        .find(|r| r.scenario_id == "rust-174")
        .unwrap();
    assert_eq!(fail.verdict, Verdict::FutureFail);
}

#[test]
fn scan_local_auto_detects_node_without_execution_when_no_docker() {
    // Detection path only — ensures Node is not left as NOT_RUN stub in CLI routing.
    let d = tempdir().unwrap();
    std::fs::write(d.path().join("package.json"), r#"{"name":"x"}"#).unwrap();
    assert!(NodeAdapter.detect(d.path()).supported);
}
