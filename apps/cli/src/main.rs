//! TomorrowCI CLI — Continuous Integration Against the Future.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::path::{Component, Path, PathBuf};
use tomorrowci_core::{
    compare_horizons, evaluate_policy_gate, Config, EvidenceGrade, HorizonDelta, Verdict,
};
use tomorrowci_evidence::{
    finalize_run_checksums, find_run_dir, validate_identifier, verify_run_root,
    ChecksumCompatibility,
};
use tomorrowci_metrics::{run_trust_audit, ClaimLedger, ClaimStatus, ScanMetrics, TrustVerdict};
use tomorrowci_report::{
    write_github_job_summary, write_html_report_from_verified_root, write_json_report,
    write_sarif_stub,
};
use tomorrowci_runner::{
    load_and_explain, replay_scenario, scan_local, scan_remote_github, ScanOptions, ScanOutcome,
};
use tomorrowci_sandbox::{detect_engines, SecurityPolicy};

#[derive(Parser, Debug)]
#[command(
    name = "tomorrowci",
    version,
    about = "Continuous Integration Against the Future."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a local path or an exact GitHub commit (Python/Node/Rust)
    Scan {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Required immutable 40-hex commit for remote GitHub scans
        #[arg(long)]
        commit: Option<String>,
    },
    Show {
        run_id: String,
    },
    /// Verify evidence integrity for a run
    Verify {
        run_id: String,
    },
    Replay {
        run_id: String,
        #[arg(long)]
        scenario: String,
    },
    Explain {
        run_id: String,
    },
    Report {
        run_id: String,
        #[arg(long, default_value = "json")]
        format: String,
    },
    Doctor,
    /// Trust-behavior audit (security invariants — no target code execution)
    Trust {
        #[arg(long)]
        json: bool,
    },
    /// Compare base vs head run frontiers (PR horizon delta)
    Compare {
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        gate: bool,
    },
    /// Print metrics.json for a run
    Metrics {
        run_id: String,
    },
    #[command(name = "init-action")]
    InitAction {
        #[arg(long, default_value = ".github/workflows/tomorrowci.yml")]
        out: PathBuf,
    },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => cmd_doctor(),
        Commands::Trust { json } => cmd_trust(json),
        Commands::Scan {
            target,
            config,
            commit,
        } => cmd_scan(&target, config.as_deref(), commit.as_deref()),
        Commands::Show { run_id } => cmd_show(&run_id),
        Commands::Verify { run_id } => cmd_verify(&run_id),
        Commands::Replay { run_id, scenario } => {
            validate_cli_identifier(&run_id, "run_id")?;
            validate_cli_identifier(&scenario, "scenario_id")?;
            let cwd = std::env::current_dir()?;
            // Prefer run under cwd; also resolve fixture-local runs
            let root = find_run_dir(&cwd, &run_id);
            let repo = root
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .unwrap_or(&cwd);
            print!("{}", replay_scenario(repo, &run_id, &scenario)?);
            Ok(())
        }
        Commands::Explain { run_id } => {
            let cwd = std::env::current_dir()?;
            print!("{}", load_and_explain(&cwd, &run_id)?);
            Ok(())
        }
        Commands::Report { run_id, format } => cmd_report(&run_id, &format),
        Commands::Compare { base, head, gate } => cmd_compare(&base, &head, gate),
        Commands::Metrics { run_id } => cmd_metrics(&run_id),
        Commands::InitAction { out } => cmd_init_action(&out),
    }
}

fn cmd_doctor() -> Result<()> {
    println!("TomorrowCI doctor");
    println!("tool_version: {}", env!("CARGO_PKG_VERSION"));
    let engines = detect_engines();
    println!("docker: {}", engines.docker);
    println!("podman: {}", engines.podman);
    println!(
        "selected_engine: {}",
        engines
            .selected
            .map(|e| format!("{e:?}"))
            .unwrap_or_else(|| "NONE (sandbox BLOCKED)".into())
    );
    for n in &engines.notes {
        println!("note: {n}");
    }
    SecurityPolicy::default()
        .validate_safe_defaults()
        .context("security policy")?;
    println!("security_defaults: OK");
    println!("host_execution_of_targets: FORBIDDEN by default");
    println!(
        "status: {}",
        if engines.selected.is_some() {
            "READY"
        } else {
            "BLOCKED for container execution"
        }
    );
    Ok(())
}

fn cmd_trust(json: bool) -> Result<()> {
    let report = run_trust_audit()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("TomorrowCI trust audit");
        println!("overall: {:?}", report.overall);
        for p in &report.probes {
            println!("[{:?}] {} — {}", p.verdict, p.id, p.title);
            println!("         {}", p.detail);
        }
        if report.overall == TrustVerdict::Fail {
            bail!("trust audit FAILED");
        }
        println!("status: PASS (Blocked probes are infra-only, not trust failures)");
    }
    if report.failed() {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_scan(target: &str, config_path: Option<&Path>, commit: Option<&str>) -> Result<()> {
    if target.starts_with("http://") || target.starts_with("https://") {
        let commit = commit.context(
            "remote GitHub scans require --commit <40-lowercase-hex>; moving refs are forbidden",
        )?;
        let explicit_config = config_path.map(Config::load_file).transpose()?;
        let cwd = std::env::current_dir()?;
        let result = scan_remote_github(target, commit, &cwd, explicit_config);
        let eco = result
            .as_ref()
            .ok()
            .map(|outcome| ecosystem_name(outcome.manifest.detection.ecosystem))
            .unwrap_or("remote");
        if eco != "remote" {
            println!("ecosystem: {eco}");
            println!("detection: PASS");
        }
        return finish_scan(
            result,
            eco,
            format!("tomorrowci scan {target} --commit {commit}"),
        );
    }
    if commit.is_some() {
        bail!("--commit is only valid for an HTTPS GitHub remote target");
    }
    let root = local_scan_root(Path::new(target))?;
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    let cfg = load_config(&root, config_path)?;

    let result = scan_local(
        &root,
        ScanOptions {
            config: cfg,
            allow_scripted: false,
        },
    );
    let eco = result
        .as_ref()
        .ok()
        .map(|outcome| ecosystem_name(outcome.manifest.detection.ecosystem))
        .unwrap_or("local");
    if eco != "local" {
        println!("ecosystem: {eco}");
        println!("detection: PASS");
    }

    finish_scan(result, eco, format!("tomorrowci scan {}", root.display()))
}

fn ecosystem_name(ecosystem: tomorrowci_core::Ecosystem) -> &'static str {
    match ecosystem {
        tomorrowci_core::Ecosystem::Python => "python",
        tomorrowci_core::Ecosystem::Node => "node",
        tomorrowci_core::Ecosystem::Rust => "rust",
        tomorrowci_core::Ecosystem::Unknown => "unknown",
    }
}

fn local_scan_root(target: &Path) -> Result<PathBuf> {
    // Accept the documented `scan .` / `scan ./project` without resolving
    // aliases before the evidence layer can reject them. Parent traversal and
    // drive-relative paths still pass through its strict ancestor checks.
    let without_dot: PathBuf = target
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect();
    let path = if without_dot.as_os_str().is_empty() {
        std::env::current_dir()?
    } else {
        without_dot
    };
    Ok(tomorrowci_evidence::validate_existing_ancestors(&path)?)
}

fn finish_scan(
    result: tomorrowci_core::Result<ScanOutcome>,
    eco: &str,
    claim_command: String,
) -> Result<()> {
    match result {
        Ok(out) => {
            println!("{}", out.terminal_summary);
            println!(
                "report: {}",
                out.evidence_root.join("report.html").display()
            );
            println!(
                "metrics: {}",
                out.evidence_root.join("metrics.json").display()
            );
            let mut claims = ClaimLedger::default();
            let any_blocked = out.manifest.results.iter().any(|r| {
                matches!(
                    r.verdict,
                    Verdict::Blocked
                        | Verdict::Unsupported
                        | Verdict::Inconclusive
                        | Verdict::BaselineInvalid
                        | Verdict::Flaky
                )
            });
            let status = if any_blocked {
                ClaimStatus::Blocked
            } else {
                ClaimStatus::Pass
            };
            claims.push(
                format!("{eco} scan completed"),
                status,
                claim_command,
                out.metrics.summary_line(),
                out.evidence_root.display().to_string(),
            );
            claims.write_json(&out.evidence_root.join("claims.json"))?;
            // Re-finalize checksums after claims.json is written, then fail closed.
            finalize_and_verify_run(&out.evidence_root)?;
            println!("run_id: {}", out.manifest.run_id);
            // Never promote BLOCKED to success: non-zero exit for infra/construction blocks
            if any_blocked {
                println!("verdict: BLOCKED");
                std::process::exit(2);
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("BLOCKED")
                || msg.contains("blocked:")
                || msg.contains("sandbox")
                || msg.contains("Docker")
                || msg.contains("Podman")
                || msg.contains("daemon")
            {
                println!("verdict: BLOCKED");
                println!("{msg}");
                std::process::exit(2);
            } else if msg.contains("UNSUPPORTED") || msg.contains("unsupported:") {
                println!("verdict: UNSUPPORTED");
                println!("{msg}");
                std::process::exit(3);
            } else {
                Err(e.into())
            }
        }
    }
}

fn load_config(root: &Path, config_path: Option<&Path>) -> Result<Config> {
    if let Some(p) = config_path {
        Ok(Config::load_file(p)?)
    } else if root.join(".tomorrowci.yml").exists() {
        Ok(Config::load_file(&root.join(".tomorrowci.yml"))?)
    } else {
        Ok(Config::default())
    }
}

fn cmd_show(run_id: &str) -> Result<()> {
    validate_cli_identifier(run_id, "run_id")?;
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let verified = load_verified_manifest(&root, "show", false)?;
    let m = &verified.manifest;
    println!("run: {}", m.run_id);
    for r in &m.results {
        println!("  {} => {:?}", r.scenario_id, r.verdict);
    }
    println!("frontier.observed: {}", m.frontier.observed);
    Ok(())
}

fn cmd_verify(run_id: &str) -> Result<()> {
    validate_cli_identifier(run_id, "run_id")?;
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let rep = verify_run_root(&root)?;
    println!("{}", serde_json::to_string_pretty(&rep)?);
    if !rep.ok {
        bail!("evidence verify FAILED: {} errors", rep.errors.len());
    }
    println!("verify: PASS");
    Ok(())
}

fn cmd_report(run_id: &str, format: &str) -> Result<()> {
    validate_cli_identifier(run_id, "run_id")?;
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let output = render_report_transactionally(&root, format)?;
    println!("wrote {}", output.display());
    Ok(())
}

fn cmd_compare(base: &str, head: &str, gate: bool) -> Result<()> {
    validate_cli_identifier(base, "base run_id")?;
    validate_cli_identifier(head, "head run_id")?;
    let cwd = std::env::current_dir()?;
    let base_root = cwd.join(".tomorrowci/runs").join(base);
    let head_root = cwd.join(".tomorrowci/runs").join(head);
    let (base_m, head_m, head_config) = load_compare_manifests(&base_root, &head_root, gate)?;
    let cmp = compare_horizons(&base_m.frontier, &head_m.frontier);
    println!(
        "evidence_grade: base={:?} head={:?}",
        base_m.frontier.grade, head_m.frontier.grade
    );
    println!("{}", serde_json::to_string_pretty(&cmp)?);

    if gate {
        require_observed_gate_inputs(&base_m, &head_m)?;
        let baseline_invalid = head_m
            .results
            .iter()
            .any(|r| r.verdict == Verdict::BaselineInvalid);
        let new_future_failure = head_m
            .results
            .iter()
            .any(|r| r.verdict == Verdict::FutureFail)
            && !base_m
                .results
                .iter()
                .any(|r| r.verdict == Verdict::FutureFail);
        let horizon_regression = cmp.delta == HorizonDelta::Regression;
        let blocked = head_m
            .results
            .iter()
            .filter(|r| r.verdict == Verdict::Blocked)
            .count() as f64;
        let total = head_m.results.len().max(1) as f64;
        let policy = head_config
            .policy
            .as_ref()
            .map(|policy| policy.fail_if.clone())
            .ok_or_else(|| {
                anyhow::anyhow!("compare gate requires an explicit or normalized default policy")
            })?;
        if !policy.baseline_invalid
            && !policy.new_future_failure
            && !policy.horizon_regression
            && policy.blocked_ratio_above.is_none()
        {
            bail!("compare gate refuses a policy with no enabled failure rules");
        }
        let g = evaluate_policy_gate(
            baseline_invalid,
            new_future_failure,
            horizon_regression,
            blocked / total,
            policy.blocked_ratio_above,
            policy.baseline_invalid,
            policy.new_future_failure,
            policy.horizon_regression,
        );
        println!("policy_gate: {}", serde_json::to_string_pretty(&g)?);
        if g.fail {
            std::process::exit(3);
        }
    }
    Ok(())
}

fn require_observed_gate_inputs(
    base: &tomorrowci_core::RunManifest,
    head: &tomorrowci_core::RunManifest,
) -> Result<()> {
    for (label, manifest) in [("base", base), ("head", head)] {
        if manifest.results.is_empty() {
            bail!("compare gate requires executed {label} scenario evidence");
        }
        if manifest.results.iter().any(|result| {
            manifest
                .plan
                .scenarios
                .iter()
                .find(|scenario| scenario.id == result.scenario_id)
                .is_none_or(|scenario| scenario.grade != EvidenceGrade::Observed)
        }) {
            bail!("compare gate rejects non-OBSERVED {label} scenario evidence");
        }
        let baseline_result = manifest
            .plan
            .scenarios
            .iter()
            .find(|scenario| scenario.is_baseline)
            .and_then(|scenario| {
                manifest
                    .results
                    .iter()
                    .find(|result| result.scenario_id == scenario.id)
            })
            .ok_or_else(|| {
                anyhow::anyhow!("compare gate requires an executed {label} baseline scenario")
            })?;
        if !matches!(
            baseline_result.verdict,
            Verdict::BaselinePass | Verdict::BaselineInvalid
        ) {
            bail!(
                "compare gate requires a completed {label} baseline classification; got {:?}",
                baseline_result.verdict
            );
        }
        if let Some(result) = manifest.results.iter().find(|result| {
            matches!(
                result.verdict,
                Verdict::Unsupported | Verdict::Inconclusive | Verdict::Flaky
            )
        }) {
            bail!(
                "compare gate rejects unresolved {label} scenario {} with verdict {:?}",
                result.scenario_id,
                result.verdict
            );
        }
        let expected_frontier_grade = if manifest.frontier.observed {
            EvidenceGrade::Observed
        } else {
            EvidenceGrade::Inconclusive
        };
        if manifest.frontier.grade != expected_frontier_grade {
            bail!(
                "compare gate rejects non-authoritative {label} frontier grade {:?}; expected {:?}",
                manifest.frontier.grade,
                expected_frontier_grade
            );
        }
    }
    Ok(())
}

fn cmd_metrics(run_id: &str) -> Result<()> {
    validate_cli_identifier(run_id, "run_id")?;
    let cwd = std::env::current_dir()?;
    let root = find_run_dir(&cwd, run_id);
    let verified = load_verified_manifest(&root, "metrics", false)?;
    let p = root.join("metrics.json");
    if p.exists() {
        print!("{}", std::fs::read_to_string(p)?);
        return Ok(());
    }
    // recompute from run.json
    let metrics = ScanMetrics::from_manifest(&verified.manifest, None);
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

fn cmd_init_action(out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(out, include_str!("../../../action/workflow-template.yml"))?;
    println!("wrote {}", out.display());
    Ok(())
}

fn validate_cli_identifier(value: &str, label: &str) -> Result<()> {
    validate_identifier(value, label).map_err(anyhow::Error::msg)
}

struct RunOperationLock {
    path: PathBuf,
    _file: std::fs::File,
}

impl RunOperationLock {
    fn acquire(run_root: &Path, operation: &str) -> Result<Self> {
        tomorrowci_evidence::validate_existing_ancestors(run_root)
            .with_context(|| format!("{operation}: unsafe run path"))?;
        let run_id = run_root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow::anyhow!("{operation}: run directory name is not UTF-8"))?;
        validate_cli_identifier(run_id, "run_id")?;
        let parent = run_root
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{operation}: run root has no parent"))?;
        let path = parent.join(format!(".{run_id}.operation.lock"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "{operation}: could not acquire exclusive run operation lock {}",
                    path.display()
                )
            })?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for RunOperationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct VerifiedManifest {
    manifest: tomorrowci_core::RunManifest,
    config: Option<Config>,
    _lock: RunOperationLock,
}

fn load_verified_manifest(
    run_root: &Path,
    operation: &str,
    require_current: bool,
) -> Result<VerifiedManifest> {
    verify_run_for_operation(run_root, &format!("{operation} pre-lock"), require_current)?;
    let lock = RunOperationLock::acquire(run_root, operation)?;
    verify_run_for_operation(run_root, operation, require_current)?;
    let run_path = run_root.join("run.json");
    let before =
        std::fs::read(&run_path).with_context(|| format!("{operation}: read verified run.json"))?;
    let manifest = serde_json::from_slice(&before)
        .with_context(|| format!("{operation}: parse verified run.json"))?;
    let config_path = run_root.join("config.normalized.json");
    let config_before = if require_current {
        Some(
            std::fs::read(&config_path)
                .with_context(|| format!("{operation}: read verified normalized config"))?,
        )
    } else {
        None
    };
    let config = config_before
        .as_deref()
        .map(serde_json::from_slice::<Config>)
        .transpose()
        .with_context(|| format!("{operation}: parse verified normalized config"))?;
    verify_run_for_operation(run_root, &format!("{operation} post-load"), require_current)?;
    let after = std::fs::read(&run_path)
        .with_context(|| format!("{operation}: re-read verified run.json"))?;
    if before != after {
        bail!("{operation}: run.json changed during trusted read");
    }
    if let Some(config_before) = &config_before {
        let config_after = std::fs::read(&config_path)
            .with_context(|| format!("{operation}: re-read verified normalized config"))?;
        if config_before != &config_after {
            bail!("{operation}: config.normalized.json changed during trusted read");
        }
    }
    Ok(VerifiedManifest {
        manifest,
        config,
        _lock: lock,
    })
}

fn verify_run_for_operation(run_root: &Path, operation: &str, require_current: bool) -> Result<()> {
    let verification = verify_run_root(run_root)
        .with_context(|| format!("{operation}: evidence verification could not complete"))?;
    if !verification.ok {
        bail!(
            "{operation}: evidence verification FAILED: {}",
            verification.errors.join("; ")
        );
    }
    if require_current && verification.checksum_compatibility != ChecksumCompatibility::CurrentV2 {
        bail!(
            "{operation}: legacy evidence is read-compatible only and cannot authorize this operation"
        );
    }
    Ok(())
}

fn load_compare_manifests(
    base_root: &Path,
    head_root: &Path,
    _gate: bool,
) -> Result<(
    tomorrowci_core::RunManifest,
    tomorrowci_core::RunManifest,
    Config,
)> {
    // Every comparison is a trusted decision input. Keep both locks alive until
    // both stable, twice-verified manifests have been captured.
    if base_root == head_root {
        let verified = load_verified_manifest(base_root, "compare base/head", true)?;
        let config = verified
            .config
            .clone()
            .ok_or_else(|| anyhow::anyhow!("compare: verified config is missing"))?;
        return Ok((verified.manifest.clone(), verified.manifest, config));
    }
    let (first_root, first_label, second_root, second_label, swapped) =
        if base_root.as_os_str() <= head_root.as_os_str() {
            (base_root, "compare base", head_root, "compare head", false)
        } else {
            (head_root, "compare head", base_root, "compare base", true)
        };
    let first = load_verified_manifest(first_root, first_label, true)?;
    let second = load_verified_manifest(second_root, second_label, true)?;
    if swapped {
        let head_config = first
            .config
            .ok_or_else(|| anyhow::anyhow!("compare head: verified config is missing"))?;
        Ok((second.manifest, first.manifest, head_config))
    } else {
        let head_config = second
            .config
            .ok_or_else(|| anyhow::anyhow!("compare head: verified config is missing"))?;
        Ok((first.manifest, second.manifest, head_config))
    }
}

fn report_file_name(format: &str) -> &'static str {
    match format {
        "html" => "report.html",
        "sarif" => "report.sarif.json",
        "summary" => "job-summary.md",
        _ => "report.json",
    }
}

fn write_report_format(
    manifest: &tomorrowci_core::RunManifest,
    verified_run_root: &Path,
    format: &str,
    output: &Path,
) -> Result<()> {
    match format {
        "html" => write_html_report_from_verified_root(manifest, verified_run_root, output)?,
        "sarif" => write_sarif_stub(manifest, output)?,
        "summary" => write_github_job_summary(manifest, output)?,
        _ => write_json_report(manifest, output)?,
    }
    Ok(())
}

fn snapshot_checksum_files(run_root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut snapshots = vec![(
        run_root.join("checksums.txt"),
        std::fs::read(run_root.join("checksums.txt"))?,
    )];
    let scenarios = run_root.join("scenarios");
    if scenarios.exists() {
        for entry in std::fs::read_dir(scenarios)? {
            let entry = entry?;
            if entry.path().is_dir() {
                let checksums = entry.path().join("checksums.txt");
                if checksums.exists() {
                    snapshots.push((checksums.clone(), std::fs::read(checksums)?));
                }
            }
        }
    }
    Ok(snapshots)
}

fn rollback_report(
    run_root: &Path,
    destination: &Path,
    previous: Option<&[u8]>,
    checksum_snapshots: &[(PathBuf, Vec<u8>)],
) -> Result<()> {
    if let Some(previous) = previous {
        std::fs::write(destination, previous)?;
    } else if destination.exists() {
        std::fs::remove_file(destination)?;
    }
    for (path, contents) in checksum_snapshots {
        std::fs::write(path, contents)?;
    }
    verify_run_for_operation(run_root, "report rollback", true)
}

fn verify_only_report_changed(run_root: &Path, file_name: &str) -> Result<()> {
    let verification = verify_run_root(run_root)?;
    if verification.ok {
        return Ok(());
    }
    let allowed = [
        format!("checksum mutation detected in run file: {file_name}"),
        format!("unlisted run file: {file_name}"),
    ];
    let unexpected: Vec<_> = verification
        .errors
        .iter()
        .filter(|error| !allowed.contains(error))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        bail!(
            "report transaction observed unrelated evidence mutation: {}",
            unexpected.join("; ")
        );
    }
    Ok(())
}

fn render_report_transactionally(run_root: &Path, format: &str) -> Result<PathBuf> {
    let verified = load_verified_manifest(run_root, "report", true)?;
    let manifest = &verified.manifest;
    let file_name = report_file_name(format);
    let destination = run_root.join(file_name);

    let staging_root = std::env::temp_dir().join(format!(
        "tomorrowci-report-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&staging_root)?;
    let staged = staging_root.join(file_name);
    let render_result = write_report_format(manifest, run_root, format, &staged);
    if let Err(error) = render_result {
        let cleanup = std::fs::remove_dir_all(&staging_root);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(anyhow::anyhow!(
                "report render failed: {error:#}; staging cleanup failed: {cleanup_error}"
            )),
        };
    }

    let rendered = std::fs::read(&staged)?;
    let previous = if destination.exists() {
        Some(std::fs::read(&destination)?)
    } else {
        None
    };
    let checksum_snapshots = snapshot_checksum_files(run_root)?;
    let transaction = (|| -> Result<()> {
        std::fs::write(&destination, &rendered)?;
        verify_only_report_changed(run_root, file_name)?;
        finalize_and_verify_run(run_root)
    })();

    if let Err(error) = transaction {
        let rollback = rollback_report(
            run_root,
            &destination,
            previous.as_deref(),
            &checksum_snapshots,
        );
        let cleanup = std::fs::remove_dir_all(&staging_root);
        return match (rollback, cleanup) {
            (Ok(()), Ok(())) => Err(error),
            (rollback, cleanup) => Err(anyhow::anyhow!(
                "report transaction failed: {error:#}; rollback={}; cleanup={}",
                rollback
                    .err()
                    .map(|failure| format!("FAILED ({failure:#})"))
                    .unwrap_or_else(|| "ok".into()),
                cleanup
                    .err()
                    .map(|failure| format!("FAILED ({failure})"))
                    .unwrap_or_else(|| "ok".into())
            )),
        };
    }

    std::fs::remove_dir_all(&staging_root).context("remove committed report staging directory")?;
    Ok(destination)
}

fn finalize_and_verify_run(run_root: &Path) -> Result<()> {
    finalize_run_checksums(run_root)?;
    let verification = verify_run_root(run_root)?;
    if !verification.ok {
        bail!(
            "evidence verify FAILED after finalization: {}",
            verification.errors.join("; ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_run(repo: &Path, run_id: &str) -> PathBuf {
        use tomorrowci_core::{
            Baseline, BreakageFrontier, Config, Ecosystem, EvidenceGrade, ExecutionPlan,
            ProjectDetection, RepositorySnapshot, RunIdentity, RunManifest,
        };

        let layout = tomorrowci_evidence::EvidenceLayout::create(repo, run_id).unwrap();
        let workspace = layout.run_root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        tomorrowci_evidence::write_workspace_manifest(
            &workspace,
            &layout.run_root.join("workspace-manifest.json"),
        )
        .unwrap();

        let frontier = BreakageFrontier {
            observed: false,
            horizon_label: None,
            first_failing_scenario: None,
            last_passing_scenario: None,
            changed_axes: Vec::new(),
            failure_signature: None,
            grade: EvidenceGrade::Inconclusive,
            replay_command: None,
            notes: vec!["No observed breakage horizon: baseline is not BASELINE_PASS.".into()],
        };
        let config = Config::default();
        let config_hash = config.content_hash().unwrap();
        let started_at = chrono::Utc::now();
        let finished_at = chrono::Utc::now();
        let identity = RunIdentity {
            source_commit: None,
            dirty_tree: None,
            tool_version: env!("CARGO_PKG_VERSION").into(),
            adapter_name: "python".into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
            config_hash: config_hash.clone(),
            manifest_hashes: Default::default(),
            container_engine: None,
            container_engine_version: None,
            started_at,
            finished_at: Some(finished_at),
        };
        let manifest = RunManifest {
            evidence_schema_version: 2,
            run_id: run_id.into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            started_at,
            finished_at: Some(finished_at),
            repository: RepositorySnapshot {
                source: format!("local:{}", repo.display()),
                path: repo.to_path_buf(),
                commit_sha: None,
                is_disposable_copy: true,
            },
            config_hash,
            detection: ProjectDetection {
                ecosystem: Ecosystem::Python,
                manifests: Vec::new(),
                package_manager: "pip".into(),
                confidence: 1.0,
                notes: Vec::new(),
            },
            baseline: Baseline {
                runtime: "3.11".into(),
                dependencies: "locked".into(),
                declared_by: "focused test".into(),
            },
            plan: ExecutionPlan {
                plan_id: "focused-plan".into(),
                scenarios: Vec::new(),
                selection_notes: Vec::new(),
                budget_max: 0,
            },
            results: Vec::new(),
            frontier: frontier.clone(),
            evidence_root: layout.run_root.clone(),
            identity: Some(identity),
        };

        tomorrowci_evidence::write_run_manifest(&layout, &manifest).unwrap();
        layout
            .write_json("repository.json", &manifest.repository)
            .unwrap();
        layout
            .write_json("config.normalized.json", &config)
            .unwrap();
        layout
            .write_json("candidates.json", &serde_json::json!([]))
            .unwrap();
        layout.write_json("plan.json", &manifest.plan).unwrap();
        layout
            .write_json("plan-decisions.json", &serde_json::json!([]))
            .unwrap();
        layout
            .write_json("verdicts.json", &manifest.results)
            .unwrap();
        layout.write_json("frontier.json", &frontier).unwrap();
        let metrics = ScanMetrics::from_manifest(&manifest, None);
        layout.write_json("metrics.json", &metrics).unwrap();
        layout
            .write_json("claims.json", &serde_json::json!({ "rows": [] }))
            .unwrap();
        write_json_report(&manifest, &layout.run_root.join("report.json")).unwrap();
        tomorrowci_report::write_html_report(&manifest, &layout.run_root.join("report.html"))
            .unwrap();
        write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md")).unwrap();
        std::fs::write(layout.run_root.join("summary.txt"), "focused summary\n").unwrap();
        finalize_and_verify_run(&layout.run_root).unwrap();
        layout.run_root
    }

    fn add_observed_passing_baseline(manifest: &mut tomorrowci_core::RunManifest) {
        use tomorrowci_core::{EnvironmentSpec, ExecutionResult, Scenario};

        let scenario_id = "baseline".to_string();
        manifest.plan.scenarios.push(Scenario {
            id: scenario_id.clone(),
            is_baseline: true,
            runtime: "3.11".into(),
            dependencies: "locked".into(),
            axes_changed: Vec::new(),
            candidates: Vec::new(),
            grade: EvidenceGrade::Observed,
            resolved_dependencies: None,
        });
        manifest.results.push(ExecutionResult {
            scenario_id,
            attempt: 1,
            verdict: Verdict::BaselinePass,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            failure: None,
            environment: EnvironmentSpec {
                image_tag: "python:3.11".into(),
                image: "python:3.11".into(),
                image_digest: Some(format!("python@sha256:{}", "1".repeat(64))),
                workdir: "/work".into(),
                env: Default::default(),
                network_mode: "none".into(),
                memory_mb: 1024,
                cpus: 1.0,
                pids_limit: 128,
                user: Some("65532:65532".into()),
                read_only_root: true,
                scenario_state_root: Some("/work/.tomorrowci/scenarios/baseline".into()),
                fetch_timeout_seconds: Some(30),
                test_timeout_seconds: Some(30),
                engine: Some("docker".into()),
                engine_version: Some("focused".into()),
            },
            commands: Vec::new(),
        });
        manifest.frontier.observed = false;
        manifest.frontier.grade = EvidenceGrade::Inconclusive;
    }

    #[test]
    fn finalization_errors_propagate() {
        let root = std::env::temp_dir().join(format!("tomorrowci-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("unexpected-evidence.bin"), b"not allowed\n").unwrap();

        let error = finalize_and_verify_run(&root).unwrap_err();
        assert!(error.to_string().contains("unexpected-evidence.bin"));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_report_format_preserves_a_strictly_verifiable_inventory() {
        let repo =
            std::env::temp_dir().join(format!("tomorrowci-cli-reports-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "reports");

        for format in ["json", "html", "summary", "sarif"] {
            let output = render_report_transactionally(&root, format).unwrap();
            assert!(output.is_file(), "missing {format} output");
            let verification = verify_run_root(&root).unwrap();
            assert!(
                verification.ok,
                "format={format}: {:?}",
                verification.errors
            );
        }

        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn html_report_dispatch_uses_current_run_root_for_replays() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-report-root-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "report-root");
        let mut manifest: tomorrowci_core::RunManifest =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        add_observed_passing_baseline(&mut manifest);
        manifest.evidence_root = repo.join("stale-original-location");

        let attempt_root = root.join("scenarios/baseline/replays/attempt-1");
        std::fs::create_dir_all(&attempt_root).unwrap();
        std::fs::write(attempt_root.join("result.json"), b"{}\n").unwrap();

        let output = repo.join("staging/report.html");
        write_report_format(&manifest, &root, "html", &output).unwrap();
        let body = std::fs::read_to_string(output).unwrap();
        let embedded = body
            .split_once("<script id=\"report-data\" type=\"application/json\">")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let model: serde_json::Value = serde_json::from_str(embedded).unwrap();
        assert_eq!(model["replayAttempts"].as_array().unwrap().len(), 1);
        assert_eq!(model["replayAttempts"][0]["scenarioId"], "baseline");
        assert_eq!(model["replayAttempts"][0]["attempt"], 1);

        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn report_rejects_tampered_input_before_writing() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-tampered-report-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "tampered-report");
        let report_before = std::fs::read(root.join("report.html")).unwrap();
        std::fs::write(root.join("frontier.json"), b"{\"tampered\":true}\n").unwrap();

        let error = render_report_transactionally(&root, "html").unwrap_err();
        assert!(error.to_string().contains("report"));
        assert!(error.to_string().contains("verification FAILED"));
        assert_eq!(
            std::fs::read(root.join("report.html")).unwrap(),
            report_before
        );

        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn every_compare_verifies_both_inputs_before_loading_manifests() {
        let repo =
            std::env::temp_dir().join(format!("tomorrowci-cli-compare-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&repo).unwrap();
        let base = create_valid_run(&repo, "base");
        let head = create_valid_run(&repo, "head");
        std::fs::write(base.join("frontier.json"), b"{\"tampered\":true}\n").unwrap();

        for gate in [false, true] {
            let error = load_compare_manifests(&base, &head, gate).unwrap_err();
            assert!(error.to_string().contains("compare base"));
            assert!(error.to_string().contains("verification FAILED"));
        }

        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn compare_gate_rejects_simulated_current_evidence() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-simulated-gate-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "simulated");
        let mut manifest: tomorrowci_core::RunManifest =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        add_observed_passing_baseline(&mut manifest);
        manifest.frontier.grade = EvidenceGrade::Simulated;
        assert!(require_observed_gate_inputs(&manifest, &manifest)
            .unwrap_err()
            .to_string()
            .contains("non-authoritative"));
        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn compare_gate_accepts_observed_all_pass_without_a_breakage_horizon() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-observed-all-pass-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "observed-all-pass");
        let mut manifest: tomorrowci_core::RunManifest =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        add_observed_passing_baseline(&mut manifest);

        require_observed_gate_inputs(&manifest, &manifest).unwrap();
        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn compare_gate_rejects_unsupported_baseline() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-unsupported-baseline-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "unsupported-baseline");
        let mut manifest: tomorrowci_core::RunManifest =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        add_observed_passing_baseline(&mut manifest);
        manifest.results[0].verdict = Verdict::Unsupported;

        let error = require_observed_gate_inputs(&manifest, &manifest).unwrap_err();
        assert!(error.to_string().contains("baseline classification"));
        assert!(error.to_string().contains("Unsupported"));
        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn compare_gate_rejects_inconclusive_future_result() {
        let repo = std::env::temp_dir().join(format!(
            "tomorrowci-cli-inconclusive-future-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "inconclusive-future");
        let mut manifest: tomorrowci_core::RunManifest =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        add_observed_passing_baseline(&mut manifest);
        let mut future = manifest.plan.scenarios[0].clone();
        future.id = "future".into();
        future.is_baseline = false;
        future.axes_changed = vec![tomorrowci_core::EnvironmentAxis::Runtime];
        let mut result = manifest.results[0].clone();
        result.scenario_id = future.id.clone();
        result.verdict = Verdict::Inconclusive;
        result.exit_code = Some(1);
        manifest.plan.scenarios.push(future);
        manifest.results.push(result);

        let error = require_observed_gate_inputs(&manifest, &manifest).unwrap_err();
        assert!(error.to_string().contains("unresolved"));
        assert!(error.to_string().contains("Inconclusive"));
        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn legacy_is_readable_but_cannot_authorize_compare_or_report() {
        let repo =
            std::env::temp_dir().join(format!("tomorrowci-cli-legacy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&repo).unwrap();
        let root = create_valid_run(&repo, "legacy");

        let run_path = root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&run_path).unwrap()).unwrap();
        run["evidence_schema_version"] = serde_json::json!(0);
        run["tool_version"] = serde_json::json!("0.1.1-alpha.2");
        run["identity"]["tool_version"] = serde_json::json!("0.1.1-alpha.2");
        run["identity"]["adapter_version"] = serde_json::json!("0.1.1-alpha.2");
        std::fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        std::fs::write(
            root.join("report.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
        finalize_run_checksums(&root).unwrap();
        let checksums = std::fs::read_to_string(root.join("checksums.txt")).unwrap();
        std::fs::write(
            root.join("checksums.txt"),
            checksums
                .lines()
                .filter(|line| line.trim() != tomorrowci_evidence::CHECKSUM_FORMAT_V2)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();

        let readable = verify_run_root(&root).unwrap();
        assert!(readable.ok, "{:?}", readable.errors);
        assert_eq!(
            readable.checksum_compatibility,
            ChecksumCompatibility::LegacyV1ReadCompatible
        );
        verify_run_for_operation(&root, "show", false).unwrap();
        load_verified_manifest(&root, "metrics", false).unwrap();
        let error = verify_run_for_operation(&root, "compare", true).unwrap_err();
        assert!(error.to_string().contains("read-compatible only"));
        assert!(render_report_transactionally(&root, "html").is_err());

        std::fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn remote_scan_requires_an_exact_commit_before_network_access() {
        let error = cmd_scan("https://github.com/example/project", None, None).unwrap_err();
        assert!(error.to_string().contains("require --commit"));
        assert!(error.to_string().contains("moving refs are forbidden"));
    }

    #[test]
    fn local_scan_rejects_remote_commit_authority() {
        let error = cmd_scan(".", None, Some(&"a".repeat(40))).unwrap_err();
        assert!(error.to_string().contains("only valid"));
    }

    #[test]
    fn scan_dot_is_accepted_without_weakening_ancestor_validation() {
        assert_eq!(
            local_scan_root(Path::new(".")).unwrap(),
            std::env::current_dir().unwrap()
        );
        assert_eq!(
            local_scan_root(Path::new("./.")).unwrap(),
            std::env::current_dir().unwrap()
        );
        assert!(local_scan_root(Path::new("../outside")).is_err());
        #[cfg(windows)]
        assert!(local_scan_root(Path::new("C:relative")).is_err());
    }

    #[test]
    fn scan_dot_prefix_does_not_resolve_an_alias_before_validation() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("real");
        let alias = parent.path().join("alias");
        std::fs::create_dir(&target).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_dir(&target, &alias).is_err() {
            return; // Capability-dependent; no claim that Windows symlinks were exercised.
        }
        assert!(local_scan_root(&parent.path().join(".").join("alias")).is_err());
    }
}
