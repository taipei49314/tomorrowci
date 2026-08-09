//! TomorrowCI CLI — Continuous Integration Against the Future.

use clap::{Parser, Subcommand, ValueEnum};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tomorrowci_core::backtest::BacktestRequest;
use tomorrowci_core::policy::PolicyConfig;
use tomorrowci_core::redaction::{redact_secrets, sanitize_terminal};
use tomorrowci_core::Config;
use tomorrowci_evidence::{verify_bundle, BundleKind, EvidenceStore};
use tomorrowci_measure::{
    default_catalog, run_benches, run_fixture_suite, ClaimStatus, SuiteOptions,
};
use tomorrowci_runner::{
    backtest_repo, compare_runs, doctor, explain_run, format_compare, format_policy_report,
    policy_check_run, replay, scan, show_run, ScanRequest, TOOL_VERSION,
};

#[derive(Parser, Debug)]
#[command(
    name = "tomorrowci",
    version = TOOL_VERSION,
    about = "Find the earliest concrete future environment that breaks a repository — with replayable evidence.",
    long_about = "TomorrowCI is not a dependency update bot and not an LLM wrapper.\n\
No forecast without an executable scenario. No breakage claim without replayable evidence."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Evidence root directory (default: ./.tomorrowci)
    #[arg(long, global = true, default_value = ".tomorrowci")]
    evidence_root: PathBuf,

    /// Working directory for clones/workspaces (default: under evidence root)
    #[arg(long, global = true)]
    work_root: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a repository against future runtime/dependency environments
    Scan {
        /// Local path or https://github.com/owner/repo URL
        target: String,
        /// Path to .tomorrowci.yml
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show scenarios and verdicts for a run
    Show { run_id: String },
    /// Verify a sealed evidence bundle without executing its contents
    Verify {
        /// Run id, or an explicit absolute/./relative bundle path
        run: String,
    },
    /// Replay one exact scenario from recorded evidence
    Replay {
        run_id: String,
        #[arg(long)]
        scenario: String,
    },
    /// Explain the evidence-backed minimal failure frontier
    Explain { run_id: String },
    /// Export reports
    Report {
        run_id: String,
        #[arg(long, value_enum, default_value = "html")]
        format: ReportFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Diagnose local requirements without modifying the host
    Doctor,
    /// Generate a safe GitHub Actions workflow
    InitAction {
        #[arg(long, default_value = ".github/workflows/tomorrowci.yml")]
        output: PathBuf,
    },
    /// Measurement harness: instruments before trust (fixtures + benches + ledger)
    Measure {
        #[command(subcommand)]
        cmd: MeasureCmd,
    },
    /// Compare breakage horizons of two completed runs (base → head)
    Compare {
        /// Base run id (e.g. main branch scan)
        base: String,
        /// Head run id (e.g. PR scan)
        head: String,
        /// Exit 5 when head regresses the horizon earlier
        #[arg(long)]
        fail_on_regression: bool,
    },
    /// Evaluate fail-if policy against a completed run (optional base for regression)
    Policy {
        /// Run id to evaluate (head)
        run_id: String,
        /// Optional base run id for horizon_regression rule
        #[arg(long)]
        base: Option<String>,
        /// Policy YAML (default: built-in advisory-safe defaults)
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Write JSON report path
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Historical commit sampling backtest (M2 skeleton — honest limitations)
    Backtest {
        /// Local git repository path
        target: String,
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        at: String,
        /// End date (YYYY-MM-DD)
        #[arg(long)]
        until: String,
        /// Max commits to sample
        #[arg(long, default_value_t = 5)]
        max_commits: usize,
        /// Max scenarios per commit scan
        #[arg(long, default_value_t = 8)]
        max_scenarios: usize,
        /// Write report JSON here
        #[arg(long, default_value = ".tomorrowci/backtest-report.json")]
        out: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum MeasureCmd {
    /// Run fixture expectation suite and emit claim ledger
    Suite {
        /// Only these fixture ids (comma-separated)
        #[arg(long)]
        only: Option<String>,
        /// Output directory for measure report JSON
        #[arg(long, default_value = ".tomorrowci/measure")]
        out: PathBuf,
    },
    /// Micro-benchmarks with recorded methodology (no invented SLAs)
    Bench {
        #[arg(long, default_value = ".tomorrowci/measure")]
        out: PathBuf,
    },
    /// Run benches then full fixture suite (north-star trust loop)
    All {
        #[arg(long, default_value = ".tomorrowci/measure")]
        out: PathBuf,
        #[arg(long)]
        only: Option<String>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum ReportFormat {
    Html,
    Json,
    Sarif,
}

static OUTPUT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let message = sanitize_terminal(&redact_secrets(&format!("{error:#}")));
        eprintln!("Error: {message}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let evidence_root = cli.evidence_root;
    let work_root = cli.work_root.unwrap_or_else(|| evidence_root.join("work"));

    match cli.command {
        Commands::Scan { target, config } => {
            let cfg = load_config(config.as_deref())?;
            let outcome = scan(ScanRequest {
                target,
                config: cfg,
                config_path: config,
                output_root: evidence_root,
                work_root,
            })
            .await?;
            print!("{}", outcome.terminal_summary);
            if let Some(code) = scan_exit_code(
                &outcome.verdicts,
                outcome.manifest.status,
                outcome.frontier.observed,
            ) {
                std::process::exit(code);
            }
        }
        Commands::Show { run_id } => {
            print!("{}", show_run(&evidence_root, &run_id)?);
        }
        Commands::Verify { run } => {
            let candidate = PathBuf::from(&run);
            let verified = if is_explicit_bundle_path(&run, &candidate) {
                verify_bundle(&candidate)?
            } else {
                EvidenceStore::open(&evidence_root, &run)?.verify()?
            };
            if verified.kind != BundleKind::Run {
                anyhow::bail!(
                    "verify requires a run bundle, found {}",
                    bundle_kind_label(verified.kind)
                );
            }
            println!(
                "PASS version={} kind={} file_count={} root={}",
                verified.version,
                bundle_kind_label(verified.kind),
                verified.file_count,
                serde_json::to_string(&verified.root.to_string_lossy())?
            );
        }
        Commands::Replay { run_id, scenario } => {
            let trusted_workspace = work_root.join("workspaces").join(&run_id);
            let msg = replay(&evidence_root, &run_id, &scenario, Some(&trusted_workspace)).await?;
            println!("{msg}");
        }
        Commands::Explain { run_id } => {
            print!("{}", explain_run(&evidence_root, &run_id)?);
        }
        Commands::Report {
            run_id,
            format,
            output,
        } => {
            let store = EvidenceStore::open(&evidence_root, &run_id)?;
            let verified = store.verify()?;
            let dest = output.unwrap_or_else(|| {
                let extension = match &format {
                    ReportFormat::Html => "html",
                    ReportFormat::Json => "json",
                    ReportFormat::Sarif => "sarif",
                };
                evidence_root
                    .join("reports")
                    .join(format!("{run_id}.{extension}"))
            });
            if path_would_be_within(&dest, &store.root)? {
                anyhow::bail!(
                    "report output must be outside sealed run bundle {}",
                    store.root.display()
                );
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if path_would_be_within(&dest, &store.root)? {
                anyhow::bail!(
                    "report output resolved inside sealed run bundle {}",
                    store.root.display()
                );
            }
            let run = verified.read_json("run.json")?;
            let verdicts = verified.read_json("verdicts.json")?;
            let frontier = verified.read_json("frontier.json")?;
            let plan = if verified.contains("plan.json") {
                verified.read_json("plan.json")?
            } else {
                serde_json::json!({})
            };
            let candidates = if verified.contains("candidates.json") {
                verified.read_json("candidates.json")?
            } else {
                serde_json::json!([])
            };
            let data = tomorrowci_report::ReportData {
                run,
                verdicts,
                frontier,
                plan,
                candidates,
            };
            match format {
                ReportFormat::Html => tomorrowci_report::write_html_report(&dest, &data)?,
                ReportFormat::Json => tomorrowci_report::write_json_report(&dest, &data)?,
                ReportFormat::Sarif => tomorrowci_report::write_sarif_report(&dest, &data)?,
            }
            println!("Wrote {}", dest.display());
        }
        Commands::Doctor => {
            let report = doctor();
            println!("TomorrowCI doctor v{TOOL_VERSION}\n");
            for (name, check) in [
                ("rustc", &report.rustc),
                ("cargo", &report.cargo),
                ("git", &report.git),
                ("python", &report.python),
                ("node", &report.node),
                ("npm", &report.npm),
            ] {
                println!(
                    "{name:10} [{status}] {detail}",
                    status = check.status,
                    detail = check.detail
                );
            }
            println!(
                "{:10} [{}] {}",
                "sandbox",
                report.sandbox.status,
                report.sandbox.details.join("; ")
            );
            println!();
            for n in report.notes {
                println!("- {n}");
            }
            if report.sandbox.status != "ok" {
                std::process::exit(4);
            }
        }
        Commands::InitAction { output } => {
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write_output(&output, GITHUB_ACTION_WORKFLOW.as_bytes())?;
            println!("Wrote safe GitHub Actions workflow to {}", output.display());
            println!(
                "Default permissions: contents: read only. No secrets forwarded to untrusted code."
            );
        }
        Commands::Policy {
            run_id,
            base,
            policy,
            out,
        } => {
            let pol = if let Some(p) = policy {
                let raw = std::fs::read_to_string(&p)?;
                serde_yaml::from_str::<PolicyConfig>(&raw)?
            } else {
                PolicyConfig::default()
            };
            let report = policy_check_run(&evidence_root, &run_id, &pol, base.as_deref())?;
            print!("{}", format_policy_report(&report));
            let dest = out.unwrap_or_else(|| evidence_root.join(format!("policy-{run_id}.json")));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write_output(&dest, serde_json::to_string_pretty(&report)?.as_bytes())?;
            println!("Wrote {}", dest.display());
            if report.decision == tomorrowci_core::PolicyDecision::Fail {
                std::process::exit(6);
            }
        }
        Commands::Compare {
            base,
            head,
            fail_on_regression,
        } => {
            let cmp = compare_runs(&evidence_root, &base, &head)?;
            print!("{}", format_compare(&cmp, &base, &head));
            let path = evidence_root.join(format!("compare-{}-{}.json", base, head));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write_output(&path, serde_json::to_string_pretty(&cmp)?.as_bytes())?;
            println!("Wrote {}", path.display());
            if fail_on_regression && cmp.is_regression {
                std::process::exit(5);
            }
        }
        Commands::Backtest {
            target,
            at,
            until,
            max_commits,
            max_scenarios,
            out,
        } => {
            let at = chrono::NaiveDate::parse_from_str(&at, "%Y-%m-%d")
                .map_err(|e| anyhow::anyhow!("--at date: {e}"))?;
            let until = chrono::NaiveDate::parse_from_str(&until, "%Y-%m-%d")
                .map_err(|e| anyhow::anyhow!("--until date: {e}"))?;
            let report = backtest_repo(
                BacktestRequest {
                    target,
                    at,
                    until,
                    max_commits,
                    max_scenarios_per_point: max_scenarios,
                },
                evidence_root,
                work_root,
            )
            .await?;
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            atomic_write_output(&out, serde_json::to_string_pretty(&report)?.as_bytes())?;
            let html_path = out.with_extension("html");
            if let Err(e) = tomorrowci_report::write_backtest_html(&html_path, &report) {
                eprintln!("warning: backtest html: {e}");
            } else {
                println!("Wrote {}", html_path.display());
            }
            println!("{}", report.note);
            println!("points={}", report.points.len());
            for p in &report.points {
                println!(
                    "  {} {:?} horizon={:?} run={:?}",
                    &p.commit_sha[..8.min(p.commit_sha.len())],
                    p.status,
                    p.horizon_label,
                    p.run_id
                );
            }
            println!("Wrote {}", out.display());
        }
        Commands::Measure { cmd } => match cmd {
            MeasureCmd::Suite { only, out } => {
                let report = run_measure_suite(&evidence_root, &work_root, only, &out).await?;
                print!("{}", report.ledger.render_table());
                println!(
                    "\ntrustworthy(no FAIL)={} engine={} report={}",
                    report.trustworthy,
                    report.engine_available,
                    out.join("suite-report.json").display()
                );
                if report.ledger.counts().fail > 0 {
                    std::process::exit(1);
                }
                if !report.engine_available {
                    std::process::exit(4);
                }
            }
            MeasureCmd::Bench { out } => {
                let root = std::env::current_dir()?;
                let report = run_benches(&root);
                std::fs::create_dir_all(&out)?;
                let path = out.join("bench-report.json");
                atomic_write_output(&path, serde_json::to_string_pretty(&report)?.as_bytes())?;
                print!("{}", report.ledger.render_table());
                println!("\n{}\nreport={}", report.note, path.display());
                if report.ledger.counts().fail > 0 {
                    std::process::exit(1);
                }
            }
            MeasureCmd::All { out, only } => {
                let root = std::env::current_dir()?;
                std::fs::create_dir_all(&out)?;
                let benches = run_benches(&root);
                atomic_write_output(
                    &out.join("bench-report.json"),
                    serde_json::to_string_pretty(&benches)?.as_bytes(),
                )?;
                println!("=== Benches ===");
                print!("{}", benches.ledger.render_table());
                println!("\n=== Fixture suite ===");
                let suite = run_measure_suite(&evidence_root, &work_root, only, &out).await?;
                print!("{}", suite.ledger.render_table());
                // Combined ledger
                let mut combined = benches.ledger;
                for c in suite.ledger.claims {
                    combined.push(c);
                }
                let combined_path = out.join("claim-ledger.json");
                atomic_write_output(
                    &combined_path,
                    serde_json::to_string_pretty(&combined)?.as_bytes(),
                )?;
                let summary = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "tool_version": TOOL_VERSION,
                    "trustworthy": combined.all_trustworthy() && suite.engine_available,
                    "counts": combined.counts(),
                    "engine_available": suite.engine_available,
                    "bench_report": out.join("bench-report.json"),
                    "suite_report": out.join("suite-report.json"),
                    "ledger": combined_path,
                });
                atomic_write_output(
                    &out.join("summary.json"),
                    serde_json::to_string_pretty(&summary)?.as_bytes(),
                )?;
                println!("\n=== Combined ===\n{}", combined.render_table());
                println!("summary={}", out.join("summary.json").display());
                if combined.counts().fail > 0 {
                    std::process::exit(1);
                }
                if !suite.engine_available {
                    std::process::exit(4);
                }
            }
        },
    }

    Ok(())
}

fn atomic_write_output(path: &std::path::Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("output filename is not UTF-8: {}", path.display()))?;
    let mut temporary = None;
    for _ in 0..100 {
        let sequence = OUTPUT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.tmp-{}-{sequence}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| {
        anyhow::anyhow!("could not allocate temporary output for {}", path.display())
    })?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary_path, path) {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    Ok(())
}

fn scan_exit_code(
    verdicts: &[tomorrowci_core::ScenarioVerdict],
    status: tomorrowci_core::RunStatus,
    frontier_observed: bool,
) -> Option<i32> {
    use tomorrowci_core::Verdict;
    if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::BaselineInvalid)
    {
        return Some(2);
    }
    if frontier_observed {
        return Some(3);
    }
    if status == tomorrowci_core::RunStatus::Blocked
        || verdicts.iter().any(|verdict| {
            matches!(
                verdict.verdict,
                Verdict::FutureFail
                    | Verdict::Flaky
                    | Verdict::Blocked
                    | Verdict::Unsupported
                    | Verdict::Inconclusive
            )
        })
    {
        return Some(4);
    }
    None
}

async fn run_measure_suite(
    evidence_root: &std::path::Path,
    work_root: &std::path::Path,
    only: Option<String>,
    out: &std::path::Path,
) -> anyhow::Result<tomorrowci_measure::MeasureReport> {
    let root = std::env::current_dir()?;
    let only = only.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });
    let report = run_fixture_suite(SuiteOptions {
        repo_root: root,
        evidence_root: evidence_root.to_path_buf(),
        work_root: work_root.to_path_buf(),
        only,
        catalog: default_catalog(),
    })
    .await;
    std::fs::create_dir_all(out)?;
    atomic_write_output(
        &out.join("suite-report.json"),
        serde_json::to_string_pretty(&report)?.as_bytes(),
    )?;
    atomic_write_output(
        &out.join("claim-ledger.json"),
        serde_json::to_string_pretty(&report.ledger)?.as_bytes(),
    )?;
    // Human markdown
    let mut md = String::from("# TomorrowCI measure suite\n\n");
    md.push_str(&format!(
        "- engine: {} ({})\n- trustworthy: {}\n\n",
        report.engine_available, report.engine_detail, report.trustworthy
    ));
    md.push_str("| Claim | Status | ms | Detail |\n|---|---|---:|---|\n");
    for c in &report.ledger.claims {
        md.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            c.id,
            c.status.label(),
            c.duration_ms,
            c.detail.replace('|', "\\|")
        ));
    }
    atomic_write_output(&out.join("CLAIM_LEDGER.md"), md.as_bytes())?;
    let _ = ClaimStatus::Pass; // keep import used if optimized
    Ok(report)
}

fn load_config(path: Option<&std::path::Path>) -> anyhow::Result<Config> {
    if let Some(p) = path {
        return Ok(Config::load_from_path(p)?);
    }
    let default = PathBuf::from(".tomorrowci.yml");
    if default.exists() {
        Ok(Config::load_from_path(&default)?)
    } else {
        Ok(Config::default())
    }
}

fn bundle_kind_label(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Run => "run",
        BundleKind::Scenario => "scenario",
        BundleKind::Generic => "generic",
    }
}

fn is_explicit_bundle_path(selector: &str, path: &std::path::Path) -> bool {
    path.is_absolute()
        || selector == "."
        || selector == ".."
        || selector.contains('/')
        || selector.contains('\\')
}

fn path_would_be_within(path: &std::path::Path, root: &std::path::Path) -> anyhow::Result<bool> {
    let canonical_root = std::fs::canonicalize(root)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        anyhow::bail!("report output must not contain parent-directory components");
    }

    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("report output has no existing ancestor"))?;
        missing.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| anyhow::anyhow!("report output has no existing ancestor"))?;
    }
    let mut resolved = std::fs::canonicalize(ancestor)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved.starts_with(canonical_root))
}

const GITHUB_ACTION_WORKFLOW: &str = r###"# Generated by `tomorrowci init-action`
# Pins third-party actions by commit SHA. Default permissions: read-only.
name: TomorrowCI

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  tomorrowci:
    runs-on: ubuntu-latest
    # Advisory by default; set fail-on-regression: true to gate on horizon moves.
    continue-on-error: true
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - name: TomorrowCI (composite)
        uses: ./action
        with:
          target: .
          advisory: "true"
          base-ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || '' }}
          fail-on-regression: "false"
"###;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tomorrowci_core::{EvidenceGrade, ScenarioId, ScenarioVerdict, Verdict};

    fn verdict(kind: Verdict) -> ScenarioVerdict {
        ScenarioVerdict {
            scenario_id: ScenarioId::new("fixture"),
            label: "fixture".into(),
            verdict: kind,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: 0,
            failure_signature: None,
            evidence: None,
            notes: vec![],
        }
    }

    #[test]
    fn unsupported_and_inconclusive_scans_are_never_green() {
        assert_eq!(
            scan_exit_code(
                &[verdict(Verdict::Unsupported)],
                tomorrowci_core::RunStatus::Completed,
                false
            ),
            Some(4)
        );
        assert_eq!(
            scan_exit_code(
                &[verdict(Verdict::Inconclusive)],
                tomorrowci_core::RunStatus::Completed,
                false
            ),
            Some(4)
        );
        assert_eq!(
            scan_exit_code(
                &[verdict(Verdict::BaselinePass)],
                tomorrowci_core::RunStatus::Completed,
                false
            ),
            None
        );
    }

    #[test]
    fn atomic_cli_output_does_not_truncate_a_hardlink_alias() {
        let dir = tempdir().unwrap();
        let sealed = dir.path().join("run.json");
        let output = dir.path().join("policy.json");
        std::fs::write(&sealed, b"sealed").unwrap();
        std::fs::hard_link(&sealed, &output).unwrap();

        atomic_write_output(&output, b"derived").unwrap();

        assert_eq!(std::fs::read(&sealed).unwrap(), b"sealed");
        assert_eq!(std::fs::read(&output).unwrap(), b"derived");
    }
}
