fn main() {
  use chrono::Utc;
  use tomorrowci_core::*;
  use tomorrowci_report::*;
  let data = ReportData {
    run: RunManifest {
      run_id: RunId("demo-py-runtime".into()),
      tool_version: "0.1.0".into(),
      started_at: Utc::now(),
      finished_at: Some(Utc::now()),
      repository: RepositorySnapshot {
        source: "fixtures/python-runtime-break".into(),
        path: "fixtures/python-runtime-break".into(),
        commit_sha: Some("fixture".into()),
        branch: None,
        is_remote: false,
        workspace_copy: "fixtures/python-runtime-break".into(),
        captured_at: Utc::now(),
      },
      detection: None,
      baseline: None,
      config_hash: "demo".into(),
      sandbox_engine: Some("docker".into()),
      status: RunStatus::Completed,
      frontier: None,
      scenario_count: 2,
      host: HostInfo::default(),
    },
    verdicts: vec![
      ScenarioVerdict {
        scenario_id: ScenarioId::new("baseline"),
        label: "Python 3.9 + locked dependencies".into(),
        verdict: Verdict::BaselinePass,
        evidence_grade: EvidenceGrade::Observed,
        attempts: 1,
        failure_signature: None,
        evidence: None,
        notes: vec!["demo report shaped like a real fixture run; container e2e BLOCKED on hosts without Docker".into()],
      },
      ScenarioVerdict {
        scenario_id: ScenarioId::new("py310-locked"),
        label: "Python 3.10 + locked dependencies".into(),
        verdict: Verdict::FutureFail,
        evidence_grade: EvidenceGrade::Observed,
        attempts: 2,
        failure_signature: Some(FailureSignature {
          kind: "ImportError".into(),
          summary: "ImportError: cannot import name 'MutableMapping'".into(),
          primary_error: Some("ImportError: cannot import name 'MutableMapping'".into()),
          fingerprint: FailureSignature::compute_fingerprint("ImportError", "MutableMapping", "sum"),
          framework_hints: vec!["python".into()],
          evidence_grade: EvidenceGrade::Observed,
        }),
        evidence: None,
        notes: vec![],
      },
    ],
    frontier: BreakageFrontier {
      observed: true,
      horizon_label: Some("Python 3.10 + locked dependencies".into()),
      scenario_id: Some(ScenarioId::new("py310-locked")),
      axis: Some(EnvironmentAxis::Runtime),
      from_label: Some("Python 3.9 + locked dependencies".into()),
      to_label: Some("Python 3.10 + locked dependencies".into()),
      failure_signature: Some(FailureSignature {
        kind: "ImportError".into(),
        summary: "ImportError: cannot import name 'MutableMapping'".into(),
        primary_error: Some("ImportError".into()),
        fingerprint: "demo".into(),
        framework_hints: vec![],
        evidence_grade: EvidenceGrade::Observed,
      }),
      evidence_grade: Some(EvidenceGrade::Observed),
      replay_command: Some("tomorrowci replay demo-py-runtime --scenario py310-locked".into()),
      explanation: "Observed breakage horizon at Python 3.10 (demo artifact). On CI with Docker this is produced from a real fixture run.".into(),
    },
    plan: serde_json::json!({"decisions":[{"action":"select","reason":"baseline"},{"action":"select","reason":"runtime candidate"}]}),
    candidates: serde_json::json!([]),
  };
  std::fs::create_dir_all("examples/reports").ok();
  write_html_report(std::path::Path::new("examples/reports/python-runtime-break.html"), &data).unwrap();
  write_json_report(std::path::Path::new("examples/reports/python-runtime-break.json"), &data).unwrap();
  println!("wrote examples/reports/python-runtime-break.html");
}
