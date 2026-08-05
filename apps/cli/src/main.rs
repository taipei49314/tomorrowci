//! TomorrowCI CLI — Continuous Integration Against the Future.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tomorrowci_core::Config;
use tomorrowci_runner::{
    doctor, explain_run, replay, scan, show_run, ScanRequest, TOOL_VERSION,
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
    }

    Ok(())
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
