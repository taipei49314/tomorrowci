//! TomorrowCI CLI — Continuous Integration Against the Future.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{Config, Ecosystem};
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
    /// Scan a repository or GitHub URL (full execution in Milestone 1+)
    Scan {
        /// Local path or https://github.com/owner/repo
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show scenarios and verdicts for a run
    Show { run_id: String },
    /// Replay one recorded scenario from evidence
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
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Diagnose local prerequisites without modifying the host
    Doctor,
    /// Generate a safe GitHub Actions workflow skeleton
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
        Commands::Scan { target, config } => cmd_scan(&target, config.as_deref()),
        Commands::Show { run_id } => {
            println!("show {run_id}: not fully implemented until Milestone 1 (evidence runs)");
            Ok(())
        }
        Commands::Replay { run_id, scenario } => {
            println!(
                "replay {run_id} scenario {scenario}: requires recorded evidence (Milestone 1)"
            );
            Ok(())
        }
        Commands::Explain { run_id } => {
            println!("explain {run_id}: requires run evidence (Milestone 1)");
            Ok(())
        }
        Commands::Report { run_id, format } => {
            println!("report {run_id} format={format}: requires run evidence (Milestone 1)");
            Ok(())
        }
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
    println!("security_defaults: OK (no privileged, no docker.sock, no host target exec)");
    println!("host_execution_of_targets: FORBIDDEN by default");
    println!(
        "status: {}",
        if engines.selected.is_some() {
            "READY for sandbox work"
        } else {
            "BLOCKED for execution; detection/config still work"
        }
    );
    Ok(())
}

fn cmd_scan(target: &str, config_path: Option<&std::path::Path>) -> Result<()> {
    if target.starts_with("https://") || target.starts_with("http://") {
        println!("GitHub URL scan is planned; cloning into disposable workspace (Milestone 1).");
        println!("target: {target}");
        println!("status: NOT_RUN (clone+sandbox not wired in Milestone 0)");
        return Ok(());
    }
    let root = PathBuf::from(target);
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    let cfg = if let Some(p) = config_path {
        Config::load_file(p).context("load config")?
    } else if root.join(".tomorrowci.yml").exists() {
        Config::load_file(&root.join(".tomorrowci.yml"))?
    } else {
        Config::default()
    };
    println!("TomorrowCI scan (Milestone 0 — detect only, no target execution on host)");
    println!("path: {}", root.display());
    println!("config_hash: {}", cfg.content_hash()?);

    let py = PythonAdapter.detect(&root);
    let node = NodeAdapter.detect(&root);
    let rust = RustAdapter.detect(&root);

    let chosen = if py.supported {
        ("python", py.detection)
    } else if node.supported {
        ("node", node.detection)
    } else if rust.supported {
        ("rust", rust.detection)
    } else {
        println!("ecosystem: UNKNOWN");
        println!("verdict: UNSUPPORTED");
        println!("note: no supported manifests found (need pyproject/requirements, package.json, or Cargo.toml)");
        return Ok(());
    };

    println!("ecosystem: {} ({:?})", chosen.0, chosen.1.ecosystem);
    println!("package_manager: {}", chosen.1.package_manager);
    println!("manifests: {}", chosen.1.manifests.join(", "));
    for n in &chosen.1.notes {
        println!("note: {n}");
    }
    if matches!(chosen.1.ecosystem, Ecosystem::Unknown) {
        println!("verdict: UNSUPPORTED");
    } else {
        println!("detection: PASS");
        println!("execution: NOT_RUN (Milestone 1 wires sandbox scenarios)");
        println!("promise: no forecast without executable scenario; no host target execution");
    }
    Ok(())
}

fn cmd_init_action(out: &std::path::Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    // Pin placeholder SHAs must be replaced before production use — documented honestly.
    let yml = r#"# Generated by `tomorrowci init-action`
# Pins: replace action SHAs with immutable commit SHAs before production use.
name: tomorrowci
on:
  pull_request:
  push:
    branches: [main, master]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run TomorrowCI
        run: |
          echo "Install tomorrowci binary / use container image once published."
          echo "This workflow is a safe skeleton from Milestone 0."
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tomorrowci-evidence
          path: .tomorrowci/runs/
"#;
    std::fs::write(out, yml)?;
    println!("wrote {}", out.display());
    println!("note: workflow is a skeleton; dogfood against real action comes in Milestone 4.");
    Ok(())
}
