//! TomorrowCI CLI — Continuous Integration Against the Future.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::Config;
use tomorrowci_evidence::load_run_manifest;
use tomorrowci_report::{write_html_report, write_json_report, write_sarif_stub};
use tomorrowci_runner::{load_and_explain, replay_scenario, scan_local, ScanOptions};
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
    /// Scan a repository (Python full slice in M1/M2; detect-only for others)
    Scan {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Show { run_id: String },
    Replay {
        run_id: String,
        #[arg(long)]
        scenario: String,
    },
    Explain { run_id: String },
    Report {
        run_id: String,
        #[arg(long, default_value = "json")]
        format: String,
    },
    Doctor,
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
        Commands::Show { run_id } => cmd_show(&run_id),
        Commands::Replay { run_id, scenario } => {
            let cwd = std::env::current_dir()?;
            print!("{}", replay_scenario(&cwd, &run_id, &scenario)?);
            Ok(())
        }
        Commands::Explain { run_id } => {
            let cwd = std::env::current_dir()?;
            print!("{}", load_and_explain(&cwd, &run_id)?);
            Ok(())
        }
        Commands::Report { run_id, format } => cmd_report(&run_id, &format),
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
            "BLOCKED for container execution; unit/scripted tests still valid"
        }
    );
    Ok(())
}

fn cmd_scan(target: &str, config_path: Option<&Path>) -> Result<()> {
    if target.starts_with("http://") || target.starts_with("https://") {
        bail!("remote GitHub clone scan: Milestone 1 local path only for now (NOT_RUN remote)");
    }
    let root = PathBuf::from(target);
    if !root.exists() {
        bail!("path does not exist: {}", root.display());
    }
    let cfg = load_config(&root, config_path)?;

    let py = PythonAdapter.detect(&root);
    let node = NodeAdapter.detect(&root);
    let rust = RustAdapter.detect(&root);

    if py.supported {
        println!("ecosystem: python");
        match scan_local(
            &root,
            ScanOptions {
                config: cfg,
                allow_scripted: false,
            },
        ) {
            Ok(out) => {
                println!("{}", out.terminal_summary);
                println!("report: {}", out.evidence_root.join("report.html").display());
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("BLOCKED") || msg.contains("sandbox") || msg.contains("Docker") {
                    println!("verdict: BLOCKED");
                    println!("{msg}");
                    println!("detection still works; start Docker Desktop to execute scenarios.");
                    // still print detection
                    Ok(())
                } else {
                    Err(e.into())
                }
            }
        }
    } else if node.supported {
        println!("ecosystem: node ({:?})", node.detection.ecosystem);
        println!("detection: PASS");
        println!("execution: NOT_RUN (Node full execution is Milestone 3)");
        Ok(())
    } else if rust.supported {
        println!("ecosystem: rust");
        println!("detection: PASS");
        println!("execution: NOT_RUN (Rust full execution is Milestone 3)");
        Ok(())
    } else {
        println!("verdict: UNSUPPORTED");
        Ok(())
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
    let cwd = std::env::current_dir()?;
    let m = load_run_manifest(&cwd.join(".tomorrowci/runs").join(run_id))?;
    println!("run: {}", m.run_id);
    for r in &m.results {
        println!("  {} => {:?}", r.scenario_id, r.verdict);
    }
    println!("frontier.observed: {}", m.frontier.observed);
    Ok(())
}

fn cmd_report(run_id: &str, format: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = cwd.join(".tomorrowci/runs").join(run_id);
    let m = load_run_manifest(&root)?;
    match format {
        "html" => {
            let p = root.join("report.html");
            write_html_report(&m, &p)?;
            println!("wrote {}", p.display());
        }
        "sarif" => {
            let p = root.join("report.sarif.json");
            write_sarif_stub(&m, &p)?;
            println!("wrote {}", p.display());
        }
        _ => {
            let p = root.join("report.json");
            write_json_report(&m, &p)?;
            println!("wrote {}", p.display());
        }
    }
    Ok(())
}

fn cmd_init_action(out: &Path) -> Result<()> {
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(
        out,
        r#"# Generated by tomorrowci init-action
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
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Build TomorrowCI
        run: cargo build -p tomorrowci-cli --release
      - name: Scan fixture
        run: ./target/release/tomorrowci scan fixtures/python-runtime-break || true
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tomorrowci-evidence
          path: .tomorrowci/runs/
"#,
    )?;
    println!("wrote {}", out.display());
    Ok(())
}
