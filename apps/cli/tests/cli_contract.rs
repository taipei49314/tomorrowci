use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::tempdir;
use tomorrowci_core::{
    Ecosystem, RunManifest, WeatherSelectionPolicy, WeatherSelectionUnit, WeatherSourceKind,
    WeatherTimeWindow, WEATHER_MAP_SCHEMA_VERSION,
};
use tomorrowci_evidence::{seal_bundle, verify_bundle, BundleKind};

fn tomorrowci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_fake_docker(root: &Path) -> PathBuf {
    const SOURCE: &str = r#"
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

fn network_state_path(name: &str) -> Option<PathBuf> {
    env::var_os("TOMORROWCI_FAKE_DOCKER_STATE")
        .map(PathBuf::from)
        .map(|path| path.join(name))
}

fn set_network_state(name: &str, value: &str) {
    if let Some(path) = network_state_path(name) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mode = env::var("TOMORROWCI_FAKE_DOCKER_MODE").unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("version") => println!("29.0.0"),
        Some("--version") => println!("Docker version 29.0.0, fake"),
        Some("info") => println!("linux"),
        Some("image") if args.get(1).map(String::as_str) == Some("inspect") => {
            if args.iter().any(|arg| arg == "--format") {
                println!("fixture@sha256:{}", "a".repeat(64));
            }
        }
        Some("create") => {
            let name = args
                .iter()
                .position(|arg| arg == "--name")
                .and_then(|index| args.get(index + 1))
                .unwrap();
            set_network_state(name, "connected");
            println!("fixture-container");
        }
        Some("inspect") => {
            let name = args.last().unwrap();
            let connected = network_state_path(name)
                .and_then(|path| fs::read_to_string(path).ok())
                .is_some_and(|value| value == "connected");
            if connected {
                println!("{{\"bridge\":{{}}}}");
            } else {
                println!("{{}}");
            }
        }
        Some("network") if args.get(1).map(String::as_str) == Some("disconnect") => {
            set_network_state(args.last().unwrap(), "offline");
        }
        Some("network") if args.get(1).map(String::as_str) == Some("connect") => {
            set_network_state(args.last().unwrap(), "connected");
        }
        Some("start") | Some("kill") => {}
        Some("rm") => {
            if let Some(path) = network_state_path(args.last().unwrap()) {
                let _ = fs::remove_file(path);
            }
        }
        Some("exec") => {
            if mode == "target-nonzero" {
                eprintln!("fixture target failure");
                process::exit(23);
            }
            println!("ok");
        }
        _ => {}
    }
}
"#;
    let bin = root.join("fake-bin");
    fs::create_dir_all(&bin).unwrap();
    let source = root.join("fake-docker.rs");
    fs::write(&source, SOURCE).unwrap();
    let executable = bin.join(format!("docker{}", std::env::consts::EXE_SUFFIX));
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("--edition=2021")
        .arg(source)
        .args(["-C", "debuginfo=0", "-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fake docker compile failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    bin
}

fn fake_path(fake_bin: &Path) -> OsString {
    let mut entries = vec![fake_bin.to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&path));
    }
    std::env::join_paths(entries).unwrap()
}

fn with_fake_engine(command: &mut Command, fake_bin: &Path, mode: &str) {
    command
        .env("PATH", fake_path(fake_bin))
        .env(
            "TOMORROWCI_FAKE_DOCKER_STATE",
            fake_bin.join("network-states"),
        )
        .env("TOMORROWCI_FAKE_DOCKER_MODE", mode);
}

fn assert_exit(output: &Output, expected: i32, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{label}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn only_run_id(evidence: &Path) -> String {
    let ids = fs::read_dir(evidence.join("runs"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        ids.len(),
        1,
        "expected one run under {}",
        evidence.display()
    );
    ids[0].clone()
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn assert_backtest_readback_rejected(proof: &Path, label: &str) {
    let output = tomorrowci()
        .arg("backtest-verify")
        .arg(proof)
        .output()
        .unwrap();
    assert_exit(&output, 1, label);
}

fn create_historical_repo(root: &Path) -> PathBuf {
    let repository = root.join("historical-source");
    fs::create_dir(&repository).unwrap();
    fs::write(repository.join("requirements.txt"), b"\n").unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["config", "user.name", "TomorrowCI Test"],
        vec!["config", "user.email", "test@example.invalid"],
        vec!["add", "requirements.txt"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(output.status.success());
    }
    let output = Command::new("git")
        .args(["commit", "--quiet", "-m", "historical fixture"])
        .current_dir(&repository)
        .env("GIT_AUTHOR_DATE", "2026-01-15T12:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-15T12:00:00Z")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git commit failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    repository
}

#[test]
fn real_binary_readme_surface_contract_emits_defined_exits_and_artifacts() {
    let temp = tempdir().unwrap();
    let fake_bin = build_fake_docker(temp.path());
    let project = temp.path().join("source");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("requirements.txt"), b"\n").unwrap();
    let evidence = temp.path().join("evidence");
    let work = temp.path().join("work");

    let help = tomorrowci().arg("--help").output().unwrap();
    assert_exit(&help, 0, "root help");
    let help = String::from_utf8_lossy(&help.stdout);
    for surface in [
        "scan",
        "show",
        "verify",
        "replay",
        "explain",
        "report",
        "doctor",
        "init-action",
        "measure",
        "compare",
        "policy",
        "backtest",
        "backtest-verify",
        "weather",
        "patch",
    ] {
        assert!(help.contains(surface), "root help omitted {surface}");
    }
    for args in [
        vec!["measure", "bench", "--help"],
        vec!["measure", "suite", "--help"],
        vec!["measure", "all", "--help"],
        vec!["patch", "propose", "--help"],
        vec!["patch", "verify", "--help"],
    ] {
        let output = tomorrowci().args(args).output().unwrap();
        assert_exit(&output, 0, "nested help");
    }

    let mut scan = tomorrowci();
    scan.arg("--evidence-root")
        .arg(&evidence)
        .arg("--work-root")
        .arg(&work)
        .arg("scan")
        .arg(&project);
    with_fake_engine(&mut scan, &fake_bin, "success");
    let scan = scan.output().unwrap();
    assert_exit(&scan, 0, "scan");
    let run_id = only_run_id(&evidence);
    let run_path = evidence.join("runs").join(&run_id);
    let verified = verify_bundle(&run_path).unwrap();
    let run: RunManifest = verified.read_json("run.json").unwrap();

    for (label, args) in [
        ("show", vec!["show", run_id.as_str()]),
        ("verify", vec!["verify", run_id.as_str()]),
        ("explain", vec!["explain", run_id.as_str()]),
    ] {
        let output = tomorrowci()
            .arg("--evidence-root")
            .arg(&evidence)
            .args(args)
            .output()
            .unwrap();
        assert_exit(&output, 0, label);
    }

    for ordinal in 1..=2 {
        let mut replay = tomorrowci();
        replay
            .arg("--evidence-root")
            .arg(&evidence)
            .args(["replay", &run_id, "--scenario", "baseline", "--workspace"])
            .arg(&project);
        with_fake_engine(&mut replay, &fake_bin, "success");
        let output = replay.output().unwrap();
        assert_exit(&output, 0, &format!("replay {ordinal}"));
    }
    verify_bundle(&run_path).unwrap();

    let report = temp.path().join("report.json");
    let output = tomorrowci()
        .arg("--evidence-root")
        .arg(&evidence)
        .args(["report", &run_id, "--format", "json", "--output"])
        .arg(&report)
        .output()
        .unwrap();
    assert_exit(&output, 0, "report");
    assert!(report.is_file());

    let mut doctor = tomorrowci();
    doctor.arg("doctor");
    with_fake_engine(&mut doctor, &fake_bin, "success");
    let doctor = doctor.output().unwrap();
    assert_exit(&doctor, 0, "doctor");

    let generated = temp.path().join("tomorrowci.yml");
    let output = tomorrowci()
        .args(["init-action", "--output"])
        .arg(&generated)
        .output()
        .unwrap();
    assert_exit(&output, 0, "init-action");
    let workflow = fs::read_to_string(&generated).unwrap();
    assert!(workflow.contains("uses: ./action"));
    assert!(!workflow.contains("    continue-on-error:"));
    assert!(workflow.contains("Repository-local boundary"));

    let output = tomorrowci()
        .arg("--evidence-root")
        .arg(&evidence)
        .args(["compare", &run_id, &run_id])
        .output()
        .unwrap();
    assert_exit(&output, 0, "compare");
    assert!(evidence
        .join(format!("compare-{run_id}-{run_id}.json"))
        .is_file());

    let policy_out = temp.path().join("policy.json");
    let output = tomorrowci()
        .arg("--evidence-root")
        .arg(&evidence)
        .args(["policy", &run_id, "--out"])
        .arg(&policy_out)
        .output()
        .unwrap();
    assert_exit(&output, 0, "policy");
    assert!(policy_out.is_file());

    let finished = run.finished_at.unwrap();
    let window = WeatherTimeWindow {
        starts_at: run.started_at - chrono::Duration::seconds(1),
        ends_at: finished + chrono::Duration::seconds(1),
    };
    let selection_policy = WeatherSelectionPolicy {
        id: "contract-policy".into(),
        description: "real binary contract".into(),
        population: "one preselected fixture".into(),
        inclusion_criteria: vec!["selected before aggregation".into()],
        exclusion_criteria: vec![],
        declared_denominator: 1,
        selected_units: vec![WeatherSelectionUnit {
            id: "contract-source".into(),
            ecosystem: Ecosystem::Python,
            source_kind: WeatherSourceKind::ProjectFixture,
            source: run.repository.source.clone(),
            commit_sha: run.repository.commit_sha.clone(),
        }],
    };
    let weather_manifest = temp.path().join("weather-manifest.json");
    fs::write(
        &weather_manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": WEATHER_MAP_SCHEMA_VERSION,
            "selection_policy": selection_policy,
            "time_window": window,
            "runs": [{
                "selection_unit_id": "contract-source",
                "run": run_id,
                "selection_policy_id": "contract-policy",
                "time_window": window,
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    let weather_out = temp.path().join("weather.json");
    let output = tomorrowci()
        .arg("--evidence-root")
        .arg(&evidence)
        .args(["weather", "--manifest"])
        .arg(&weather_manifest)
        .args(["--format", "json", "--output"])
        .arg(&weather_out)
        .output()
        .unwrap();
    assert_exit(&output, 0, "weather");
    assert!(weather_out.is_file());

    let bench_out = temp.path().join("measure-bench");
    let output = tomorrowci()
        .current_dir(repo_root())
        .args(["measure", "bench", "--out"])
        .arg(&bench_out)
        .output()
        .unwrap();
    assert_exit(&output, 0, "measure bench");
    assert!(bench_out.join("bench-report.json").is_file());

    for (surface, output_dir) in [
        ("suite", temp.path().join("measure-suite")),
        ("all", temp.path().join("measure-all")),
    ] {
        let mut command = tomorrowci();
        command
            .current_dir(repo_root())
            .arg("--evidence-root")
            .arg(temp.path().join(format!("{surface}-evidence")))
            .arg("--work-root")
            .arg(temp.path().join(format!("{surface}-work")))
            .args([
                "measure",
                surface,
                "--only",
                "baseline-fail",
                "--engine",
                "docker",
                "--out",
            ])
            .arg(&output_dir);
        with_fake_engine(&mut command, &fake_bin, "target-nonzero");
        let output = command.output().unwrap();
        assert_exit(&output, 0, &format!("measure {surface}"));
        assert!(output_dir.join("suite-report.json").is_file());
        if surface == "all" {
            assert!(output_dir.join("summary.json").is_file());
            assert!(output_dir.join("claim-ledger.json").is_file());
        }
    }

    let historical = create_historical_repo(temp.path());
    let missing_report = temp.path().join("backtest-missing.json");
    let mut missing = tomorrowci();
    missing
        .arg("--evidence-root")
        .arg(temp.path().join("backtest-missing-evidence"))
        .arg("--work-root")
        .arg(temp.path().join("backtest-missing-work"))
        .arg("backtest")
        .arg(&historical)
        .args([
            "--at",
            "2026-01-15",
            "--until",
            "2026-01-15",
            "--max-commits",
            "1",
            "--max-scenarios",
            "1",
            "--out",
        ])
        .arg(&missing_report);
    with_fake_engine(&mut missing, &fake_bin, "success");
    let missing = missing.output().unwrap();
    assert_exit(&missing, 7, "backtest missing snapshot");
    assert!(missing_report.is_file());
    assert!(missing_report.with_extension("html").is_file());

    let backtest_evidence = temp.path().join("backtest-evidence");
    let backtest_report = temp.path().join("backtest-valid.json");
    let snapshot_registry = repo_root().join("fixtures/backtest-snapshots");
    let mut valid = tomorrowci();
    valid
        .arg("--evidence-root")
        .arg(&backtest_evidence)
        .arg("--work-root")
        .arg(temp.path().join("backtest-valid-work"))
        .arg("backtest")
        .arg(&historical)
        .args([
            "--at",
            "2026-01-15",
            "--until",
            "2026-01-15",
            "--max-commits",
            "1",
            "--max-scenarios",
            "1",
            "--snapshot-registry",
        ])
        .arg(&snapshot_registry)
        .args([
            "--max-snapshot-files",
            "16",
            "--max-snapshot-bytes",
            "1048576",
            "--out",
        ])
        .arg(&backtest_report);
    with_fake_engine(&mut valid, &fake_bin, "success");
    let valid = valid.output().unwrap();
    assert_exit(&valid, 0, "backtest valid snapshot");
    assert!(backtest_report.is_file());
    let proof_dir = fs::read_dir(backtest_evidence.join("backtests"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let readback = tomorrowci()
        .arg("backtest-verify")
        .arg(&proof_dir)
        .output()
        .unwrap();
    assert_exit(&readback, 0, "backtest proof readback");

    for (label, relative) in [
        ("backtest mutated run witness", "witness/run/run.json"),
        (
            "backtest mutated config witness",
            "witness/run/config.normalized.json",
        ),
        (
            "backtest mutated verdict witness",
            "witness/run/verdicts.json",
        ),
    ] {
        let forged = temp.path().join(label.replace(' ', "-"));
        copy_tree(&proof_dir, &forged);
        fs::write(forged.join(relative), b"{}\n").unwrap();
        // The attacker can reseal the generic outer envelope, but cannot make
        // the independently sealed, typed run witness accept changed bytes.
        seal_bundle(&forged, BundleKind::Generic).unwrap();
        assert_backtest_readback_rejected(&forged, label);
    }

    for (label, field, value) in [
        (
            "backtest wrong run binding",
            "run_id",
            serde_json::json!("ffffffffffff"),
        ),
        (
            "backtest wrong config binding",
            "normalized_config_sha256",
            serde_json::json!("0".repeat(64)),
        ),
        (
            "backtest wrong verdict binding",
            "verdicts_sha256",
            serde_json::json!(format!("sha256:{}", "0".repeat(64))),
        ),
        (
            "backtest wrong source binding",
            "source",
            serde_json::json!("C:/forged-source"),
        ),
        (
            "backtest wrong commit binding",
            "source_commit_sha",
            serde_json::json!("0".repeat(40)),
        ),
    ] {
        let forged = temp.path().join(label.replace(' ', "-"));
        copy_tree(&proof_dir, &forged);
        let proof_path = forged.join("backtest-proof.json");
        let mut proof: serde_json::Value =
            serde_json::from_slice(&fs::read(&proof_path).unwrap()).unwrap();
        proof[field] = value;
        fs::write(&proof_path, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();
        seal_bundle(&forged, BundleKind::Generic).unwrap();
        assert_backtest_readback_rejected(&forged, label);
    }

    let snapshot_payload = Path::new("witness/registry-snapshot")
        .join("payload/tomorrowci_snapshot_dep-1.0.0-py3-none-any.whl");
    let missing_snapshot = temp.path().join("backtest-missing-snapshot-witness");
    copy_tree(&proof_dir, &missing_snapshot);
    fs::remove_file(missing_snapshot.join(&snapshot_payload)).unwrap();
    seal_bundle(&missing_snapshot, BundleKind::Generic).unwrap();
    assert_backtest_readback_rejected(&missing_snapshot, "backtest missing snapshot payload");

    let mutated_snapshot = temp.path().join("backtest-mutated-snapshot-witness");
    copy_tree(&proof_dir, &mutated_snapshot);
    fs::write(
        mutated_snapshot.join(&snapshot_payload),
        b"self-resealed forgery",
    )
    .unwrap();
    seal_bundle(&mutated_snapshot, BundleKind::Generic).unwrap();
    assert_backtest_readback_rejected(&mutated_snapshot, "backtest mutated snapshot payload");

    let invalid_patch = temp.path().join("invalid.patch");
    fs::write(
        &invalid_patch,
        b"diff --git a/../escape b/../escape\n--- a/../escape\n+++ b/../escape\n@@ -0,0 +1 @@\n+bad\n",
    )
    .unwrap();
    let output = tomorrowci()
        .arg("--evidence-root")
        .arg(&evidence)
        .arg("--work-root")
        .arg(&work)
        .args(["patch", "propose", &run_id, "--source"])
        .arg(&project)
        .arg("--patch")
        .arg(&invalid_patch)
        .output()
        .unwrap();
    assert_exit(&output, 4, "patch safety rejection");
    assert!(!evidence.join("patches").exists());

    // A safe, still-green change is intentionally only a Proposal because the
    // original run had no observed breakage. It nevertheless exercises the
    // full container scan, exact replay, detached proof seal, and downloaded
    // proof verifier through the real binary.
    let valid_patch = temp.path().join("proposal.patch");
    fs::write(
        &valid_patch,
        b"diff --git a/requirements.txt b/requirements.txt\n--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-\n+# patch-lab contract\n",
    )
    .unwrap();
    let original_inventory = fs::read(run_path.join("checksums.txt")).unwrap();
    let mut propose = tomorrowci();
    propose
        .arg("--evidence-root")
        .arg(&evidence)
        .arg("--work-root")
        .arg(&work)
        .args(["patch", "propose", &run_id, "--source"])
        .arg(&project)
        .arg("--patch")
        .arg(&valid_patch);
    with_fake_engine(&mut propose, &fake_bin, "success");
    let propose = propose.output().unwrap();
    assert_exit(&propose, 8, "patch non-qualifying proposal");
    assert!(
        String::from_utf8_lossy(&propose.stdout).contains("Patch Lab Proposal"),
        "unexpected proposal output: {:?}",
        String::from_utf8_lossy(&propose.stdout)
    );
    assert_eq!(
        fs::read(run_path.join("checksums.txt")).unwrap(),
        original_inventory,
        "Patch Lab changed the original run"
    );
    let proof_dir = fs::read_dir(evidence.join("patches"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(proof_dir.join("patch-proof.json").is_file());
    assert!(proof_dir.join("proposal.patch").is_file());
    let proof: serde_json::Value =
        serde_json::from_slice(&fs::read(proof_dir.join("patch-proof.json")).unwrap()).unwrap();
    let patched_run_id = proof["patched"]["run_id"].as_str().unwrap();
    let patched_run = evidence.join("runs").join(patched_run_id);
    let readback = tomorrowci()
        .args(["patch", "verify", "--proof"])
        .arg(&proof_dir)
        .arg("--original-run")
        .arg(&run_path)
        .arg("--patched-run")
        .arg(&patched_run)
        .output()
        .unwrap();
    assert_exit(&readback, 8, "patch proposal readback");
    assert!(
        String::from_utf8_lossy(&readback.stdout).starts_with("PASS disposition=Proposal"),
        "unexpected PatchProof readback: {:?}",
        String::from_utf8_lossy(&readback.stdout)
    );
    verify_bundle(&run_path).unwrap();
}
