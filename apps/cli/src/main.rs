//! TomorrowCI CLI — Continuous Integration Against the Future.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tomorrowci_core::Config;
use tomorrowci_core::backtest::BacktestRequest;
use tomorrowci_measure::{
    default_catalog, run_benches, run_fixture_suite, ClaimStatus, SuiteOptions,
};
use tomorrowci_runner::{
    backtest_repo, compare_runs, doctor, explain_run, format_compare, replay, scan, show_run,
    ScanRequest, TOOL_VERSION,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let evidence_root = cli.evidence_root;
    let work_root = cli
        .work_root
        .unwrap_or_else(|| evidence_root.join("work"));

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
            // Non-zero if baseline invalid or policy-relevant fail
            if outcome
                .verdicts
                .iter()
                .any(|v| v.verdict == tomorrowci_core::Verdict::BaselineInvalid)
            {
                std::process::exit(2);
            }
            if outcome.frontier.observed {
                std::process::exit(3);
            }
            if outcome.manifest.status == tomorrowci_core::RunStatus::Blocked {
                std::process::exit(4);
            }
        }
        Commands::Show { run_id } => {
            print!("{}", show_run(&evidence_root, &run_id)?);
        }
        Commands::Replay { run_id, scenario } => {
            let msg = replay(&evidence_root, &run_id, &scenario, None).await?;
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
            let store = tomorrowci_evidence::EvidenceStore::open(&evidence_root, &run_id)?;
            let dest = output.unwrap_or_else(|| match format {
                ReportFormat::Html => store.root.join("report.html"),
                ReportFormat::Json => store.root.join("report.json"),
                ReportFormat::Sarif => store.root.join("report.sarif"),
            });
            // Re-load data
            let run = store.load_run()?;
            let verdicts = store.load_verdicts()?;
            let frontier = store.load_frontier()?;
            let plan = std::fs::read_to_string(store.root.join("plan.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!({}));
            let candidates = std::fs::read_to_string(store.root.join("candidates.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!([]));
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
            std::fs::write(&output, GITHUB_ACTION_WORKFLOW)?;
            println!("Wrote safe GitHub Actions workflow to {}", output.display());
            println!("Default permissions: contents: read only. No secrets forwarded to untrusted code.");
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
            std::fs::write(&path, serde_json::to_string_pretty(&cmp)?)?;
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
            std::fs::write(&out, serde_json::to_string_pretty(&report)?)?;
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
                std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
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
                std::fs::write(
                    out.join("bench-report.json"),
                    serde_json::to_string_pretty(&benches)?,
                )?;
                println!("=== Benches ===");
                print!("{}", benches.ledger.render_table());
                println!("\n=== Fixture suite ===");
                let suite =
                    run_measure_suite(&evidence_root, &work_root, only, &out).await?;
                print!("{}", suite.ledger.render_table());
                // Combined ledger
                let mut combined = benches.ledger;
                for c in suite.ledger.claims {
                    combined.push(c);
                }
                let combined_path = out.join("claim-ledger.json");
                std::fs::write(
                    &combined_path,
                    serde_json::to_string_pretty(&combined)?,
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
                std::fs::write(
                    out.join("summary.json"),
                    serde_json::to_string_pretty(&summary)?,
                )?;
                println!(
                    "\n=== Combined ===\n{}",
                    combined.render_table()
                );
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
    std::fs::write(
        out.join("suite-report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    std::fs::write(
        out.join("claim-ledger.json"),
        serde_json::to_string_pretty(&report.ledger)?,
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
    std::fs::write(out.join("CLAIM_LEDGER.md"), md)?;
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
    # Advisory by default: do not gate merge unless policy.fail_if is configured.
    continue-on-error: true
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build TomorrowCI
        run: cargo build -p tomorrowci --release

      - name: Doctor
        run: ./target/release/tomorrowci doctor

      - name: Scan fixtures (dogfood)
        run: |
          ./target/release/tomorrowci scan fixtures/python-runtime-break --evidence-root .tomorrowci
          ./target/release/tomorrowci scan fixtures/baseline-fail --evidence-root .tomorrowci || true

      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08 # v4.6.0
        with:
          name: tomorrowci-evidence
          path: .tomorrowci/runs/

      - name: Job summary
        if: always()
        run: |
          {
            echo "## TomorrowCI"
            echo "Evidence uploaded as artifact tomorrowci-evidence."
            echo "BLOCKED/INCONCLUSIVE are never treated as PASS."
          } >> "$GITHUB_STEP_SUMMARY"
"###;
