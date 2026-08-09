use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;
use tomorrowci_core::{
    Baseline, BreakageFrontier, CommandPhase, CommandSpec, Config, DependencyMode, Ecosystem,
    EnvironmentSpec, EvidenceGrade, EvidenceReference, ExecutionPlan, ExecutionResult, HostInfo,
    NetworkMode, ProjectDetection, RawExecutionResult, RepositorySnapshot, RunId, RunManifest,
    RunStatus, Scenario, ScenarioId, ScenarioKind, ScenarioVerdict, Verdict,
};
use tomorrowci_evidence::{seal_bundle, verify_bundle, BundleKind, EvidenceStore};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn tomorrowci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
}

fn build_fake_docker(root: &Path) -> PathBuf {
    const SOURCE: &str = r#"
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let Some(path) = env::var_os("TOMORROWCI_FAKE_DOCKER_LOG") {
        let mut log = OpenOptions::new().create(true).append(true).open(path).unwrap();
        writeln!(log, "{}", args.join("\t")).unwrap();
    }

    let mode = env::var("TOMORROWCI_FAKE_DOCKER_MODE").unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("29.0.0");
        }
        Some("--version") => {
            println!("Docker version 29.0.0, fake");
        }
        Some("info") => {
            println!("fake-daemon");
        }
        Some("image") if args.get(1).map(String::as_str) == Some("inspect") => {
            if mode == "digest-unavailable" {
                eprintln!("missing exact digest api_key=digest-secret");
                process::exit(1);
            }
            if args.iter().any(|arg| arg == "--format") {
                println!("fixture@sha256:{}", "a".repeat(64));
            }
        }
        Some("pull") => {
            if mode == "digest-unavailable" {
                eprintln!("pull rejected api_key=pull-secret");
                process::exit(1);
            }
        }
        Some("exec") => {
            if mode == "target-nonzero" {
                eprintln!("\x1b[2J\rtarget failed api_key=target-secret");
                process::exit(23);
            }
            println!("ok");
        }
        _ => {}
    }
}
"#;

    let bin_dir = root.join("fake-bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let source = root.join("fake-docker.rs");
    fs::write(&source, SOURCE).unwrap();
    let binary = bin_dir.join(format!("docker{}", std::env::consts::EXE_SUFFIX));
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("--edition=2021")
        .arg(&source)
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "failed to compile fake docker: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    bin_dir
}

fn path_with_fake_engine(bin_dir: &Path) -> OsString {
    let mut entries = vec![bin_dir.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(entries).unwrap()
}

fn replay_command(
    evidence_root: &Path,
    work_root: &Path,
    fake_bin: &Path,
    fake_log: &Path,
    run_id: &str,
    mode: &str,
) -> Command {
    let mut command = tomorrowci();
    command
        .arg("--evidence-root")
        .arg(evidence_root)
        .arg("--work-root")
        .arg(work_root)
        .args(["replay", run_id, "--scenario", "baseline"])
        .env("PATH", path_with_fake_engine(fake_bin))
        .env("TOMORROWCI_FAKE_DOCKER_LOG", fake_log)
        .env("TOMORROWCI_FAKE_DOCKER_MODE", mode);
    command
}

fn make_bundle(path: &Path) {
    let run_id = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("direct-bundle");
    make_reportable_bundle(path, run_id);
}

fn make_reportable_bundle(path: &Path, run_id: &str) {
    make_reportable_bundle_for_replay(
        path,
        run_id,
        path.join("workspace"),
        Some(format!("sha256:{}", "a".repeat(64))),
    );
}

fn make_reportable_bundle_for_replay(
    path: &Path,
    run_id: &str,
    workspace_copy: PathBuf,
    image_digest: Option<String>,
) {
    fs::create_dir_all(path.join("scenarios")).unwrap();
    let store = EvidenceStore {
        root: path.to_path_buf(),
        run_id: run_id.into(),
    };
    let mut config = Config::default();
    config.report.html = false;
    config.report.json = false;
    config.execution.max_scenarios = 1;
    config.execution.max_parallel = 1;
    let captured_at = chrono::DateTime::parse_from_rfc3339("2026-08-09T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let repository = RepositorySnapshot {
        source: "fixture".into(),
        path: path.join("source"),
        commit_sha: Some("0123456789abcdef".into()),
        branch: Some("main".into()),
        is_remote: false,
        workspace_copy,
        captured_at,
    };
    let detection = ProjectDetection {
        ecosystem: Ecosystem::Python,
        package_manager: "pip".into(),
        manifests: vec!["pyproject.toml".into()],
        confidence: 1.0,
        notes: vec![],
        supported: true,
        unsupported_reason: None,
    };
    let baseline = Baseline {
        ecosystem: Ecosystem::Python,
        runtime_label: "Python 3.12".into(),
        runtime_version: "3.12".into(),
        dependency_mode: DependencyMode::Locked,
        image_ref: "python:3.12-bookworm".into(),
        notes: vec![],
    };
    let scenario = Scenario {
        id: ScenarioId::new("baseline"),
        kind: ScenarioKind::Baseline,
        ecosystem: Ecosystem::Python,
        label: "baseline".into(),
        runtime_version: baseline.runtime_version.clone(),
        dependency_mode: baseline.dependency_mode.clone(),
        image_ref: baseline.image_ref.clone(),
        axes_changed: vec![],
        evidence_grade: EvidenceGrade::Observed,
        is_baseline: true,
        selection_reason: "CLI verification fixture".into(),
    };
    let command = CommandSpec {
        phase: CommandPhase::Test,
        program: "python".into(),
        args: vec!["-m".into(), "pytest".into()],
        workdir: "/workspace".into(),
        network_required: false,
        env: Default::default(),
    };
    let environment = EnvironmentSpec {
        image_ref: scenario.image_ref.clone(),
        image_digest,
        workdir: "/workspace".into(),
        user: None,
        env: Default::default(),
        mounts: vec![],
        network_mode: NetworkMode::None,
        read_only_root: false,
        memory_mb: 1024,
        cpus: 1.0,
        pids_limit: 128,
        timeout_seconds: 60,
    };
    let raw = RawExecutionResult {
        exit_code: Some(0),
        signal: None,
        stdout: "ok".into(),
        stderr: String::new(),
        duration_ms: 1,
        timed_out: false,
        network_used: false,
        error: None,
    };
    let result = ExecutionResult {
        scenario_id: scenario.id.clone(),
        attempt: 1,
        exit_code: Some(0),
        signal: None,
        duration_ms: 1,
        timed_out: false,
        network_used: false,
        stdout_path: None,
        stderr_path: None,
        stdout_preview: "ok".into(),
        stderr_preview: String::new(),
        blocked_reason: None,
        image_ref: environment.image_ref.clone(),
        image_digest: environment.image_digest.clone(),
        commands: vec![command.clone()],
    };
    store
        .write_scenario_bundle(
            &scenario,
            &environment,
            std::slice::from_ref(&command),
            &raw,
            &result,
            None,
        )
        .unwrap();
    let plan = ExecutionPlan {
        run_id: RunId(run_id.into()),
        scenarios: vec![scenario.clone()],
        max_scenarios: 1,
        max_parallel: 1,
        decisions: vec![],
        untested: vec![],
    };
    let verdict = ScenarioVerdict {
        scenario_id: scenario.id.clone(),
        label: scenario.label.clone(),
        verdict: Verdict::BaselinePass,
        evidence_grade: scenario.evidence_grade,
        attempts: 1,
        failure_signature: None,
        evidence: Some(EvidenceReference {
            run_id: RunId(run_id.into()),
            scenario_id: scenario.id.clone(),
            directory: store.scenario_dir(&scenario.id.0),
            replay_command: format!("tomorrowci replay {run_id} --scenario {}", scenario.id),
        }),
        notes: vec![],
    };
    let frontier = BreakageFrontier {
        observed: false,
        horizon_label: None,
        scenario_id: None,
        axis: None,
        from_label: None,
        to_label: None,
        failure_signature: None,
        evidence_grade: None,
        replay_command: None,
        explanation: "No observed breakage horizon.".into(),
    };
    let run = RunManifest {
        run_id: RunId(run_id.into()),
        tool_version: "0.1.0".into(),
        started_at: captured_at,
        finished_at: Some(captured_at + chrono::Duration::minutes(1)),
        repository: repository.clone(),
        detection: Some(detection.clone()),
        baseline: Some(baseline),
        config_hash: config.config_hash().unwrap(),
        sandbox_engine: Some("docker".into()),
        status: RunStatus::Completed,
        frontier: Some(frontier.clone()),
        scenario_count: 1,
        host: HostInfo::default(),
    };
    store.write_config(&config).unwrap();
    store.write_repository(&repository).unwrap();
    store.write_detection(&detection).unwrap();
    store.write_candidates(&serde_json::json!([])).unwrap();
    store.write_plan(&plan).unwrap();
    store.write_verdicts(&[verdict]).unwrap();
    store.write_frontier(&frontier).unwrap();
    store.write_run_manifest(&run).unwrap();
    store.finalize_checksums().unwrap();
}

fn assert_pass(output: Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected success, status={} stdout={stdout:?} stderr={stderr:?}",
        output.status
    );
    assert!(stdout.starts_with("PASS "), "unexpected stdout: {stdout:?}");
    assert!(
        stdout.contains("version=1"),
        "unexpected stdout: {stdout:?}"
    );
    assert!(stdout.contains("kind=run"), "unexpected stdout: {stdout:?}");
    assert!(
        stdout.contains("file_count=18"),
        "unexpected stdout: {stdout:?}"
    );
    assert!(stdout.contains("root="), "unexpected stdout: {stdout:?}");
    stdout
}

fn assert_fail(output: Output, expected: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected failure, stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "verification failures must use exit 1: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stdout.starts_with("PASS "),
        "failure printed PASS: {stdout:?}"
    );
    assert!(
        stderr.contains(expected),
        "stderr did not contain {expected:?}: {stderr:?}"
    );
}

#[test]
fn verifies_existing_path_and_run_id() {
    let temp = tempdir().unwrap();

    let direct = temp.path().join("direct-bundle");
    make_bundle(&direct);
    let mut direct_command = tomorrowci();
    let direct_output = direct_command
        .current_dir(temp.path())
        .args(["verify", "./direct-bundle"])
        .output()
        .unwrap();
    assert_pass(direct_output);

    let evidence_root = temp.path().join("evidence");
    let run = evidence_root.join("runs").join("run-123");
    make_bundle(&run);
    fs::create_dir(temp.path().join("run-123")).unwrap();
    fs::write(
        temp.path().join("run-123/checksums.txt"),
        b"untrusted current-directory shadow\n",
    )
    .unwrap();
    let mut id_command = tomorrowci();
    let id_output = id_command
        .current_dir(temp.path())
        .arg("--evidence-root")
        .arg(&evidence_root)
        .args(["verify", "run-123"])
        .output()
        .unwrap();
    let stdout = assert_pass(id_output);
    assert!(
        stdout.contains("run-123"),
        "resolved run root missing from stdout: {stdout:?}"
    );

    let dotted_run = evidence_root.join("runs").join(".run");
    make_reportable_bundle(&dotted_run, ".run");
    fs::create_dir(temp.path().join(".run")).unwrap();
    fs::write(
        temp.path().join(".run/checksums.txt"),
        b"untrusted dotted current-directory shadow\n",
    )
    .unwrap();
    let mut dotted_id_command = tomorrowci();
    assert_pass(
        dotted_id_command
            .current_dir(temp.path())
            .arg("--evidence-root")
            .arg(&evidence_root)
            .args(["verify", ".run"])
            .output()
            .unwrap(),
    );

    let mut explicit_shadow = tomorrowci();
    assert_fail(
        explicit_shadow
            .current_dir(temp.path())
            .args(["verify", "./run-123"])
            .output()
            .unwrap(),
        "not sealed with a versioned inventory",
    );
}

#[test]
fn rejects_mutated_bundle() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("bundle");
    make_bundle(&bundle);
    fs::write(bundle.join("run.json"), b"{\"trusted\":false}\n").unwrap();

    let mut command = tomorrowci();
    assert_fail(
        command.arg("verify").arg(&bundle).output().unwrap(),
        "checksum mismatch",
    );
}

#[test]
fn rejects_self_resealed_semantic_forgery_through_the_real_cli() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("semantic-forgery");
    make_bundle(&bundle);
    let run_path = bundle.join("run.json");
    let mut run: serde_json::Value = serde_json::from_slice(&fs::read(&run_path).unwrap()).unwrap();
    run["tool_version"] = serde_json::json!("</p><script>alert(1)</script>");
    fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
    seal_bundle(&bundle, BundleKind::Run)
        .expect_err("semantic forgery unexpectedly resealed as valid");

    let mut command = tomorrowci();
    assert_fail(
        command.arg("verify").arg(&bundle).output().unwrap(),
        "must be a non-empty portable version identifier",
    );
}

#[test]
fn real_cli_sanitizes_hostile_errors_and_uses_non_green_unsupported_exit() {
    let temp = tempdir().unwrap();
    let hostile = "missing\u{1b}[2J\rapi_key=super-secret-value";
    let mut hostile_command = tomorrowci();
    let output = hostile_command
        .current_dir(temp.path())
        .arg("--evidence-root")
        .arg(temp.path().join("hostile-evidence"))
        .args(["verify", hostile])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stdout.starts_with("PASS "));
    assert!(!stderr.contains('\u{1b}'), "stderr={stderr:?}");
    assert!(!stderr.contains('\r'), "stderr={stderr:?}");
    assert!(!stderr.contains("super-secret-value"), "stderr={stderr:?}");
    assert!(stderr.contains("REDACTED"), "stderr={stderr:?}");

    let target = temp.path().join("unsupported-project");
    fs::create_dir(&target).unwrap();
    let mut unsupported_command = tomorrowci();
    let output = unsupported_command
        .current_dir(temp.path())
        .arg("--evidence-root")
        .arg(temp.path().join("scan-evidence"))
        .arg("--work-root")
        .arg(temp.path().join("scan-work"))
        .arg("scan")
        .arg(&target)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(4),
        "unsupported scan must be non-green: stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("UNSUPPORTED"), "stdout={stdout:?}");
}

#[test]
fn real_replay_cli_is_non_green_for_target_and_digest_failures_and_keeps_run_sealed() {
    let temp = tempdir().unwrap();
    let fake_bin = build_fake_docker(temp.path());
    let digest = Some(format!("sha256:{}", "a".repeat(64)));

    let target_evidence = temp.path().join("target-evidence");
    let target_work = temp.path().join("target-work");
    let target_run_id = "target-nonzero";
    let target_workspace = target_work.join("workspaces").join(target_run_id);
    fs::create_dir_all(&target_workspace).unwrap();
    make_reportable_bundle_for_replay(
        &target_evidence.join("runs").join(target_run_id),
        target_run_id,
        target_workspace,
        digest.clone(),
    );
    let target_output = replay_command(
        &target_evidence,
        &target_work,
        &fake_bin,
        &temp.path().join("target-docker.log"),
        target_run_id,
        "target-nonzero",
    )
    .output()
    .unwrap();
    let target_stdout = String::from_utf8_lossy(&target_output.stdout);
    let target_stderr = String::from_utf8_lossy(&target_output.stderr);
    assert!(
        !target_output.status.success(),
        "target exit 23 must be non-green: stdout={target_stdout:?} stderr={target_stderr:?}"
    );
    assert!(!target_stdout.contains("target-secret"));
    assert!(!target_stderr.contains("target-secret"));
    assert!(!target_stdout.contains('\u{1b}'));
    assert!(!target_stderr.contains('\u{1b}'));

    let digest_evidence = temp.path().join("digest-evidence");
    let digest_work = temp.path().join("digest-work");
    let digest_run_id = "digest-unavailable";
    let digest_workspace = digest_work.join("workspaces").join(digest_run_id);
    fs::create_dir_all(&digest_workspace).unwrap();
    make_reportable_bundle_for_replay(
        &digest_evidence.join("runs").join(digest_run_id),
        digest_run_id,
        digest_workspace,
        digest.clone(),
    );
    let digest_log = temp.path().join("digest-docker.log");
    let digest_output = replay_command(
        &digest_evidence,
        &digest_work,
        &fake_bin,
        &digest_log,
        digest_run_id,
        "digest-unavailable",
    )
    .output()
    .unwrap();
    let digest_stdout = String::from_utf8_lossy(&digest_output.stdout);
    let digest_stderr = String::from_utf8_lossy(&digest_output.stderr);
    assert_eq!(
        digest_output.status.code(),
        Some(4),
        "missing exact digest must be BLOCKED: stdout={digest_stdout:?} stderr={digest_stderr:?}"
    );
    assert!(!digest_stdout.contains("digest-secret"));
    assert!(!digest_stderr.contains("digest-secret"));
    assert!(!digest_stdout.contains("pull-secret"));
    assert!(!digest_stderr.contains("pull-secret"));
    let digest_invocations = fs::read_to_string(&digest_log).unwrap();
    for invocation in digest_invocations
        .lines()
        .filter(|line| line.starts_with("image\tinspect\t") || line.starts_with("pull\t"))
    {
        assert!(
            invocation.contains("@sha256:"),
            "replay fell back to a mutable image tag: {invocation:?}"
        );
    }

    let flow_evidence = temp.path().join("flow-evidence");
    let flow_work = temp.path().join("flow-work");
    let flow_run_id = "selector-flow";
    let flow_workspace = flow_work.join("workspaces").join(flow_run_id);
    fs::create_dir_all(&flow_workspace).unwrap();
    make_reportable_bundle_for_replay(
        &flow_evidence.join("runs").join(flow_run_id),
        flow_run_id,
        flow_workspace,
        digest,
    );

    let mut before = tomorrowci();
    assert_pass(
        before
            .arg("--evidence-root")
            .arg(&flow_evidence)
            .args(["verify", flow_run_id])
            .output()
            .unwrap(),
    );

    let first_replay = replay_command(
        &flow_evidence,
        &flow_work,
        &fake_bin,
        &temp.path().join("flow-docker.log"),
        flow_run_id,
        "success",
    )
    .output()
    .unwrap();
    assert_ne!(
        first_replay.status.code(),
        Some(4),
        "equivalent first replay was blocked: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&first_replay.stdout),
        String::from_utf8_lossy(&first_replay.stderr)
    );

    let second_replay = replay_command(
        &flow_evidence,
        &flow_work,
        &fake_bin,
        &temp.path().join("flow-docker.log"),
        flow_run_id,
        "success",
    )
    .output()
    .unwrap();
    assert!(
        second_replay.status.success(),
        "second equivalent replay must qualify: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&second_replay.stdout),
        String::from_utf8_lossy(&second_replay.stderr)
    );

    let mut after = tomorrowci();
    assert_pass(
        after
            .arg("--evidence-root")
            .arg(&flow_evidence)
            .args(["verify", flow_run_id])
            .output()
            .unwrap(),
    );
}

#[test]
fn rejects_missing_inventoried_file_and_missing_run() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("bundle");
    make_bundle(&bundle);
    fs::remove_file(bundle.join("verdicts.json")).unwrap();

    let mut missing_file_command = tomorrowci();
    assert_fail(
        missing_file_command
            .arg("verify")
            .arg(&bundle)
            .output()
            .unwrap(),
        "inventoried file does not exist",
    );

    let evidence_root = temp.path().join("evidence");
    let mut missing_run_command = tomorrowci();
    assert_fail(
        missing_run_command
            .arg("--evidence-root")
            .arg(&evidence_root)
            .args(["verify", "not-a-run"])
            .output()
            .unwrap(),
        "run directory not found",
    );
}

#[test]
fn rejects_unlisted_extra_file() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("bundle");
    make_bundle(&bundle);
    fs::write(bundle.join("late-writer.json"), b"{}\n").unwrap();

    let mut command = tomorrowci();
    assert_fail(
        command.arg("verify").arg(&bundle).output().unwrap(),
        "not listed in the sealed inventory",
    );
}

#[test]
fn rejects_generic_and_scenario_bundles_as_run_paths() {
    let temp = tempdir().unwrap();
    let generic = temp.path().join("generic");
    fs::create_dir(&generic).unwrap();
    fs::write(generic.join("data.txt"), b"data").unwrap();
    seal_bundle(&generic, BundleKind::Generic).unwrap();
    let mut generic_command = tomorrowci();
    assert_fail(
        generic_command
            .arg("verify")
            .arg(&generic)
            .output()
            .unwrap(),
        "verify requires a run bundle, found generic",
    );

    let run = temp.path().join("run");
    make_bundle(&run);
    let mut scenario_command = tomorrowci();
    assert_fail(
        scenario_command
            .arg("verify")
            .arg(run.join("scenarios/baseline"))
            .output()
            .unwrap(),
        "verify requires a run bundle, found scenario",
    );
}

#[test]
fn rejects_unsafe_inventory_and_run_id_traversal() {
    let temp = tempdir().unwrap();
    let bundle = temp.path().join("unsafe-bundle");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(
        bundle.join("checksums.txt"),
        format!(
            "# tomorrowci-evidence-checksums-v1 kind=generic algorithm=sha256 scope=recursive sealed=true\n{ZERO_DIGEST}  ../outside.json\n"
        ),
    )
    .unwrap();

    let mut unsafe_inventory_command = tomorrowci();
    assert_fail(
        unsafe_inventory_command
            .arg("verify")
            .arg(&bundle)
            .output()
            .unwrap(),
        "unsafe evidence path",
    );

    let working_dir = temp.path().join("working");
    fs::create_dir(&working_dir).unwrap();
    let evidence_root = temp.path().join("evidence");
    let mut traversal_command = tomorrowci();
    assert_fail(
        traversal_command
            .current_dir(&working_dir)
            .arg("--evidence-root")
            .arg(&evidence_root)
            .args(["verify", "../outside"])
            .output()
            .unwrap(),
        "bundle directory not found",
    );
}

#[test]
fn report_verifies_before_reading_and_writes_outside_the_sealed_bundle() {
    let temp = tempdir().unwrap();
    let evidence_root = temp.path().join("evidence");

    let internal_run = evidence_root.join("runs").join("internal-report");
    make_reportable_bundle(&internal_run, "internal-report");
    let mut internal_command = tomorrowci();
    let internal_output = internal_command
        .arg("--evidence-root")
        .arg(&evidence_root)
        .args(["report", "internal-report", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        internal_output.status.success(),
        "internal report failed: {}",
        String::from_utf8_lossy(&internal_output.stderr)
    );
    assert!(evidence_root.join("reports/internal-report.json").is_file());
    assert_eq!(verify_bundle(&internal_run).unwrap().file_count, 18);

    let external_run = evidence_root.join("runs").join("external-report");
    make_reportable_bundle(&external_run, "external-report");
    let inventory_before = fs::read(external_run.join("checksums.txt")).unwrap();
    let run_before = fs::read(external_run.join("run.json")).unwrap();
    let external_report = temp.path().join("external-report.json");
    fs::hard_link(external_run.join("run.json"), &external_report).unwrap();
    let mut external_command = tomorrowci();
    let external_output = external_command
        .arg("--evidence-root")
        .arg(&evidence_root)
        .args(["report", "external-report", "--format", "json", "--output"])
        .arg(&external_report)
        .output()
        .unwrap();
    assert!(
        external_output.status.success(),
        "external report failed: {}",
        String::from_utf8_lossy(&external_output.stderr)
    );
    assert!(external_report.is_file());
    assert_eq!(fs::read(external_run.join("run.json")).unwrap(), run_before);
    assert_eq!(
        fs::read(external_run.join("checksums.txt")).unwrap(),
        inventory_before
    );
    verify_bundle(&external_run).unwrap();

    fs::write(external_run.join("run.json"), b"tampered\n").unwrap();
    let rejected_report = temp.path().join("must-not-exist.json");
    let mut rejected_command = tomorrowci();
    assert_fail(
        rejected_command
            .arg("--evidence-root")
            .arg(&evidence_root)
            .args(["report", "external-report", "--format", "json", "--output"])
            .arg(&rejected_report)
            .output()
            .unwrap(),
        "checksum mismatch",
    );
    assert!(!rejected_report.exists());
}

#[test]
fn report_rejects_core_nested_and_parent_directory_outputs_without_mutation() {
    let temp = tempdir().unwrap();
    let evidence_root = temp.path().join("evidence");
    let run = evidence_root.join("runs").join("immutable-report");
    make_reportable_bundle(&run, "immutable-report");
    let inventory_before = fs::read(run.join("checksums.txt")).unwrap();
    let run_before = fs::read(run.join("run.json")).unwrap();
    let nested_before = fs::read(run.join("scenarios/baseline/result.json")).unwrap();

    for output in [
        run.join("run.json"),
        run.join("scenarios/baseline/result.json"),
    ] {
        let mut command = tomorrowci();
        assert_fail(
            command
                .arg("--evidence-root")
                .arg(&evidence_root)
                .args(["report", "immutable-report", "--format", "json", "--output"])
                .arg(output)
                .output()
                .unwrap(),
            "outside sealed run bundle",
        );
    }

    let parent_path = run.join("missing").join("..").join("late-writer.json");
    let mut parent_command = tomorrowci();
    assert_fail(
        parent_command
            .arg("--evidence-root")
            .arg(&evidence_root)
            .args(["report", "immutable-report", "--format", "json", "--output"])
            .arg(parent_path)
            .output()
            .unwrap(),
        "must not contain parent-directory components",
    );

    assert_eq!(
        fs::read(run.join("checksums.txt")).unwrap(),
        inventory_before
    );
    assert_eq!(fs::read(run.join("run.json")).unwrap(), run_before);
    assert_eq!(
        fs::read(run.join("scenarios/baseline/result.json")).unwrap(),
        nested_before
    );
    verify_bundle(&run).unwrap();
}
