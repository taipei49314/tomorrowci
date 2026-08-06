//! Full scan orchestration for Python / Node / Rust (M1–M3).

use crate::engine::{ContainerExecutor, ExecutionContext, ScenarioExecutor};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::PythonAdapter;
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{
    classify_from_reruns, compute_breakage_frontier, ddmin_axes, plan_scenarios, Baseline,
    CommandSpec, Config, Ecosystem, EnvironmentAxis, EnvironmentSpec, EvidenceGrade,
    ExecutionResult, ProjectDetection, RepositorySnapshot, Result, RunManifest, Scenario, TcError,
    Verdict,
};
use tomorrowci_evidence::{write_checksums, write_run_manifest, EvidenceLayout};
use tomorrowci_report::{write_html_report, write_json_report};
use tomorrowci_sandbox::make_disposable_copy;
use chrono::Utc;
use uuid::Uuid;

pub struct ScanOptions {
    pub config: Config,
    pub allow_scripted: bool,
}

pub struct ScanOutcome {
    pub manifest: RunManifest,
    pub evidence_root: PathBuf,
    pub terminal_summary: String,
}

/// Auto-detect ecosystem and run a full local scan.
pub fn scan_local(repo: &Path, opts: ScanOptions) -> Result<ScanOutcome> {
    let py = PythonAdapter.detect(repo);
    if py.supported {
        return scan_with_adapter(repo, &PythonAdapter, opts, py.detection);
    }
    let node = NodeAdapter.detect(repo);
    if node.supported {
        return scan_with_adapter(repo, &NodeAdapter, opts, node.detection);
    }
    let rust = RustAdapter.detect(repo);
    if rust.supported {
        return scan_with_adapter(repo, &RustAdapter, opts, rust.detection);
    }
    Err(TcError::Unsupported(
        "no supported ecosystem detected (need Python, Node/npm, or Rust/cargo manifests)".into(),
    ))
}

pub fn scan_with_adapter(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    opts: ScanOptions,
    detection: ProjectDetection,
) -> Result<ScanOutcome> {
    let config = opts.config;
    let run_id = Uuid::new_v4().to_string().replace('-', "")[..12].to_string();
    let layout = EvidenceLayout::create(repo, &run_id)?;

    // Disposable workspace — never mutate user repo
    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;

    let baseline = adapter.baseline(repo, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dep_cands = dependency_candidates(&baseline, &config);

    let (plan, decisions) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;
    layout.write_json("plan-decisions.json", &decisions)?;
    layout.write_json("candidates.json", &rt_cands)?;
    layout.write_json(
        "repository.json",
        &RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
    )?;
    layout.write_json("config.normalized.json", &config)?;

    let executor: Box<dyn ScenarioExecutor> = match ContainerExecutor::detect() {
        Ok(e) => Box::new(e),
        Err(e) if opts.allow_scripted => {
            // Only for explicit test harness — never default product path.
            return Err(TcError::Blocked(format!(
                "sandbox unavailable ({e}); set scripted harness in tests only"
            )));
        }
        Err(e) => return Err(e),
    };

    let mut results: Vec<ExecutionResult> = Vec::new();
    let mut ordered_for_frontier: Vec<(Scenario, ExecutionResult)> = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail_scenario: Option<String> = None;

    let eco = detection.ecosystem;

    for scenario in &plan.scenarios {
        let mut env = adapter.materialize(scenario, &work)?;
        env.image = normalize_image(eco, &scenario.runtime);
        env.memory_mb = config.sandbox.memory_mb;
        env.cpus = config.sandbox.cpus;
        env.pids_limit = config.sandbox.pids_limit;

        let digest = executor.ensure_image(&env.image).ok().flatten();
        env.image_digest = digest;

        let commands = build_scenario_commands(adapter, scenario, &config, &work)?;

        // Fetch phase (network) then test phase (network none). Always fetch for
        // language ecosystems that need installed deps; upgrade only when latest-allowed.
        let fetch_cmds = fetch_commands(eco, scenario);

        let sc_dir = layout.ensure_scenario(&scenario.id)?;
        layout_write_scenario_meta(&sc_dir, scenario, &env, &commands)?;

        // Execute with reruns on failure
        let reruns = if scenario.is_baseline {
            1
        } else {
            config.execution.reruns_on_failure.max(1)
        };

        let mut attempt_pass: Vec<bool> = Vec::new();
        let mut last_raw = None;

        for attempt in 1..=reruns {
            if let Some(ref fcmds) = fetch_cmds {
                let _ = executor.execute(&ExecutionContext {
                    workspace: &work,
                    scenario,
                    environment: &env,
                    commands: fcmds,
                    timeout: Duration::from_secs(config.execution.timeout_seconds.min(300)),
                    network: "bridge",
                });
            }

            let raw = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: &commands,
                timeout: Duration::from_secs(config.execution.timeout_seconds),
                network: "none",
            })?;

            let pass = raw.exit_code == Some(0) && !raw.timed_out;
            attempt_pass.push(pass);
            std::fs::write(sc_dir.join(format!("stdout.attempt{attempt}.log")), &raw.stdout)?;
            std::fs::write(sc_dir.join(format!("stderr.attempt{attempt}.log")), &raw.stderr)?;
            last_raw = Some(raw);
            if pass && scenario.is_baseline {
                break;
            }
            if pass && !scenario.is_baseline && attempt == 1 {
                // single pass enough if first attempt passes? still honor reruns only on fail
                break;
            }
        }

        let raw = last_raw.unwrap();
        let verdict = if scenario.is_baseline {
            if attempt_pass.iter().any(|p| *p) {
                baseline_ok = true;
                Verdict::BaselinePass
            } else {
                baseline_ok = false;
                Verdict::BaselineInvalid
            }
        } else {
            classify_from_reruns(&attempt_pass)
        };

        // If baseline invalid, stop further scenarios
        let failure = if !matches!(verdict, Verdict::BaselinePass | Verdict::FuturePass) {
            Some(adapter.normalize_failure(&raw))
        } else {
            None
        };

        let exec = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: attempt_pass.len() as u32,
            verdict,
            exit_code: raw.exit_code,
            duration_ms: raw.duration_ms,
            timed_out: raw.timed_out,
            failure: failure.clone(),
            environment: env.clone(),
            commands: commands.clone(),
        };

        // write result artifacts
        std::fs::write(sc_dir.join("stdout.log"), &raw.stdout)?;
        std::fs::write(sc_dir.join("stderr.log"), &raw.stderr)?;
        std::fs::write(
            sc_dir.join("result.json"),
            serde_json::to_string_pretty(&exec)?,
        )?;
        if let Some(ref f) = failure {
            std::fs::write(
                sc_dir.join("failure-signature.json"),
                serde_json::to_string_pretty(f)?,
            )?;
        }
        write_replay_scripts(&sc_dir, &env, &commands, &scenario.id)?;
        let checksums = vec![
            (
                "stdout.log".into(),
                tomorrowci_core::sha256_str(&raw.stdout),
            ),
            (
                "stderr.log".into(),
                tomorrowci_core::sha256_str(&raw.stderr),
            ),
        ];
        write_checksums(&sc_dir, &checksums)?;

        ordered_for_frontier.push((scenario.clone(), exec.clone()));
        results.push(exec);

        if matches!(verdict, Verdict::FutureFail) && first_fail_scenario.is_none() {
            first_fail_scenario = Some(scenario.id.clone());
            // confirmed if all reruns failed
            confirmed_first_fail = attempt_pass.iter().all(|p| !*p) && !attempt_pass.is_empty();
        }

        if matches!(verdict, Verdict::BaselineInvalid) {
            break; // no future comparisons authorized
        }
    }

    // ddmin on combined failure if present
    let mut frontier_notes = Vec::new();
    if let Some(combo) = results.iter().find(|r| {
        r.scenario_id.starts_with("combo-") && matches!(r.verdict, Verdict::FutureFail)
    }) {
        let axes = ordered_for_frontier
            .iter()
            .find(|(s, _)| s.id == combo.scenario_id)
            .map(|(s, _)| s.axes_changed.clone())
            .unwrap_or_default();
        // Use observed single-axis outcomes as oracle for which axes fail alone
        let minimal = ddmin_axes(&axes, |subset| {
            // fails if any axis in subset failed alone in single-axis runs
            subset.iter().any(|ax| {
                results.iter().any(|r| {
                    let sc = plan.scenarios.iter().find(|s| s.id == r.scenario_id);
                    sc.map(|s| {
                        s.axes_changed == vec![*ax]
                            && matches!(r.verdict, Verdict::FutureFail)
                    })
                    .unwrap_or(false)
                })
            })
        });
        frontier_notes.push(format!("ddmin reduced axes to: {minimal:?}"));
        layout.write_json(
            "reduction.json",
            &serde_json::json!({
                "combo": combo.scenario_id,
                "minimal_axes": minimal,
            }),
        )?;
    }

    let replay_cmd = first_fail_scenario
        .as_ref()
        .map(|s| format!("tomorrowci replay {run_id} --scenario {s}"));

    let mut frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered_for_frontier,
        confirmed_first_fail,
        replay_cmd.clone(),
    );
    frontier.notes.extend(frontier_notes);

    layout.write_json("verdicts.json", &results)?;
    layout.write_json("frontier.json", &frontier)?;

    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        repository: RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results: results.clone(),
        frontier: frontier.clone(),
        evidence_root: layout.run_root.clone(),
    };
    write_run_manifest(&layout, &manifest)?;
    write_json_report(&manifest, &layout.run_root.join("report.json"))?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;

    let terminal_summary = render_terminal_summary(&manifest);
    std::fs::write(layout.run_root.join("summary.txt"), &terminal_summary)?;

    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
    })
}

/// Test-only scan with injected executor (scripted).
pub fn scan_with_executor(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    config: Config,
    executor: &dyn ScenarioExecutor,
    detection: ProjectDetection,
) -> Result<ScanOutcome> {
    // Duplicate simplified path using provided executor — used by tests.
    let run_id = format!("test{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
    let layout = EvidenceLayout::create(repo, &run_id)?;
    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;

    let baseline = adapter.baseline(repo, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dep_cands = dependency_candidates(&baseline, &config);
    let (plan, _) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;

    let mut results = Vec::new();
    let mut ordered = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail = None;

    for scenario in &plan.scenarios {
        let mut env = adapter.materialize(scenario, &work)?;
        env.image_digest = executor.ensure_image(&env.image)?;
        let commands = build_scenario_commands(adapter, scenario, &config, &work)?;
        let sc_dir = layout.ensure_scenario(&scenario.id)?;

        let reruns = if scenario.is_baseline {
            1
        } else {
            config.execution.reruns_on_failure.max(1)
        };
        let mut attempts = Vec::new();
        let mut last_raw = None;
        for _ in 0..reruns {
            let raw = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: &commands,
                timeout: Duration::from_secs(30),
                network: "none",
            })?;
            attempts.push(raw.exit_code == Some(0) && !raw.timed_out);
            last_raw = Some(raw);
            if *attempts.last().unwrap_or(&false) {
                break;
            }
        }
        let raw = last_raw.unwrap();
        let verdict = if scenario.is_baseline {
            if attempts.iter().any(|p| *p) {
                baseline_ok = true;
                Verdict::BaselinePass
            } else {
                Verdict::BaselineInvalid
            }
        } else {
            classify_from_reruns(&attempts)
        };
        let failure = if !verdict.is_pass_like() {
            Some(adapter.normalize_failure(&raw))
        } else {
            None
        };
        let exec = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: attempts.len() as u32,
            verdict,
            exit_code: raw.exit_code,
            duration_ms: raw.duration_ms,
            timed_out: raw.timed_out,
            failure,
            environment: env,
            commands,
        };
        std::fs::write(sc_dir.join("result.json"), serde_json::to_string_pretty(&exec)?)?;
        if matches!(verdict, Verdict::FutureFail) && first_fail.is_none() {
            first_fail = Some(scenario.id.clone());
            confirmed_first_fail = attempts.iter().all(|p| !*p);
        }
        ordered.push((scenario.clone(), exec.clone()));
        results.push(exec);
        if matches!(verdict, Verdict::BaselineInvalid) {
            break;
        }
    }

    // ddmin note for combo
    if let Some(combo) = results.iter().find(|r| r.scenario_id.starts_with("combo-")) {
        let axes = ordered
            .iter()
            .find(|(s, _)| s.id == combo.scenario_id)
            .map(|(s, _)| s.axes_changed.clone())
            .unwrap_or_default();
        let minimal = ddmin_axes(&axes, |subset| {
            subset.iter().any(|ax| {
                ordered.iter().any(|(s, r)| {
                    s.axes_changed == vec![*ax] && matches!(r.verdict, Verdict::FutureFail)
                })
            })
        });
        layout.write_json(
            "reduction.json",
            &serde_json::json!({ "minimal_axes": minimal }),
        )?;
    }

    let frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered,
        confirmed_first_fail,
        first_fail
            .as_ref()
            .map(|s| format!("tomorrowci replay {run_id} --scenario {s}")),
    );

    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        repository: RepositorySnapshot {
            source: repo.display().to_string(),
            path: repo.to_path_buf(),
            commit_sha: git_head(repo),
            is_disposable_copy: true,
        },
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results,
        frontier,
        evidence_root: layout.run_root.clone(),
    };
    write_run_manifest(&layout, &manifest)?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    let terminal_summary = render_terminal_summary(&manifest);
    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
    })
}

fn dependency_candidates(baseline: &Baseline, config: &Config) -> Vec<tomorrowci_core::Candidate> {
    let mut out = Vec::new();
    if config.candidates.dependencies.latest_allowed {
        out.push(tomorrowci_core::Candidate {
            id: "deps-latest-allowed".into(),
            axis: EnvironmentAxis::Dependencies,
            label: format!("{} + latest allowed dependencies", baseline.runtime),
            version: "latest-allowed".into(),
            channel: "stable".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0001".into(),
        });
    }
    if config.candidates.dependencies.prerelease {
        out.push(tomorrowci_core::Candidate {
            id: "deps-prerelease".into(),
            axis: EnvironmentAxis::Dependencies,
            label: "prerelease dependencies".into(),
            version: "prerelease".into(),
            channel: "preview".into(),
            grade_if_executed: EvidenceGrade::Simulated,
            order_key: "0002".into(),
        });
    }
    out
}

fn normalize_image(eco: Ecosystem, runtime: &str) -> String {
    match eco {
        Ecosystem::Python => {
            if runtime.starts_with("python:") {
                runtime.to_string()
            } else if runtime
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                format!("python:{runtime}-slim")
            } else {
                format!("python:{runtime}")
            }
        }
        Ecosystem::Node => {
            if runtime.starts_with("node:") {
                runtime.to_string()
            } else {
                format!("node:{}", runtime.trim_start_matches("node:"))
            }
        }
        Ecosystem::Rust => {
            // Prefer concrete bookworm tags for MSRV pins like 1.74
            if runtime.starts_with("rust:") {
                runtime.to_string()
            } else if runtime
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                format!("rust:{runtime}-bookworm")
            } else {
                // stable | beta | nightly
                format!("rust:{runtime}-bookworm")
            }
        }
        Ecosystem::Unknown => runtime.to_string(),
    }
}

fn fetch_commands(eco: Ecosystem, scenario: &Scenario) -> Option<Vec<CommandSpec>> {
    let upgrade = scenario.dependencies == "latest-allowed"
        || scenario.dependencies == "prerelease";
    match eco {
        Ecosystem::Python => {
            let mut argv = vec![
                "pip".into(),
                "install".into(),
                "-q".into(),
                "-r".into(),
                "requirements.txt".into(),
            ];
            if upgrade {
                argv.push("--upgrade".into());
            }
            Some(vec![CommandSpec {
                argv,
                cwd: Some("/work".into()),
                network: true,
                phase: "fetch".into(),
            }])
        }
        Ecosystem::Node => {
            let argv: Vec<String> = if upgrade {
                vec![
                    "npm".into(),
                    "install".into(),
                    "--no-audit".into(),
                    "--no-fund".into(),
                ]
            } else {
                vec![
                    "sh".into(),
                    "-c".into(),
                    "if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi".into(),
                ]
            };
            Some(vec![CommandSpec {
                argv,
                cwd: Some("/work".into()),
                network: true,
                phase: "fetch".into(),
            }])
        }
        Ecosystem::Rust => {
            // Networked resolve once; tests run offline afterward
            Some(vec![CommandSpec {
                argv: vec!["cargo".into(), "fetch".into()],
                cwd: Some("/work".into()),
                network: true,
                phase: "fetch".into(),
            }])
        }
        Ecosystem::Unknown => None,
    }
}

fn build_scenario_commands(
    adapter: &dyn EcosystemAdapter,
    scenario: &Scenario,
    config: &Config,
    _work: &Path,
) -> Result<Vec<CommandSpec>> {
    // Prefer fixture marker scripts if present will be handled inside container via pytest
    adapter.commands(scenario, config)
}

fn layout_write_scenario_meta(
    sc_dir: &Path,
    scenario: &Scenario,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
) -> Result<()> {
    std::fs::write(
        sc_dir.join("scenario.json"),
        serde_json::to_string_pretty(scenario)?,
    )?;
    std::fs::write(
        sc_dir.join("environment.json"),
        serde_json::to_string_pretty(env)?,
    )?;
    std::fs::write(
        sc_dir.join("commands.json"),
        serde_json::to_string_pretty(commands)?,
    )?;
    Ok(())
}

fn write_replay_scripts(
    sc_dir: &Path,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
    scenario_id: &str,
) -> Result<()> {
    let cmd = commands
        .iter()
        .map(|c| c.argv.join(" "))
        .collect::<Vec<_>>()
        .join(" && ");
    let sh = format!(
        "#!/usr/bin/env bash\n# Replay scenario {scenario_id}\nset -euo pipefail\ndocker run --rm --network none -v \"$PWD\":/work -w /work {} sh -c '{}'\n",
        env.image, cmd.replace('\'', "'\\''")
    );
    std::fs::write(sc_dir.join("replay.sh"), sh)?;
    let ps1 = format!(
        "# Replay scenario {scenario_id}\ndocker run --rm --network none -v \"${{PWD}}:/work\" -w /work {} sh -c \"{}\"\n",
        env.image,
        cmd.replace('"', "\\\"")
    );
    std::fs::write(sc_dir.join("replay.ps1"), ps1)?;
    Ok(())
}

fn git_head(repo: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

pub fn render_terminal_summary(m: &RunManifest) -> String {
    let mut out = String::new();
    out.push_str(&format!("TomorrowCI run {}\n", m.run_id));
    out.push_str(&format!(
        "Repository: {} @ {}\n",
        m.repository.source,
        m.repository.commit_sha.as_deref().unwrap_or("unknown")
    ));
    for r in &m.results {
        let sc = m.plan.scenarios.iter().find(|s| s.id == r.scenario_id);
        let label = sc
            .map(|s| {
                let eco = format!("{:?}", m.detection.ecosystem);
                if s.is_baseline {
                    format!("Baseline: {} + {}", s.runtime, s.dependencies)
                } else {
                    format!("{eco} {} + {} deps", s.runtime, s.dependencies)
                }
            })
            .unwrap_or_else(|| r.scenario_id.clone());
        let v = match r.verdict {
            Verdict::BaselinePass | Verdict::FuturePass => "PASS",
            Verdict::BaselineInvalid | Verdict::FutureFail => "FAIL",
            Verdict::Flaky => "FLAKY",
            Verdict::Blocked => "BLOCKED",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        };
        out.push_str(&format!("{label:-50} {v}\n"));
    }
    out.push('\n');
    if m.frontier.observed {
        out.push_str(&format!(
            "Observed breakage horizon: {}\n",
            m.frontier.horizon_label.as_deref().unwrap_or("?")
        ));
        out.push_str(&format!(
            "Minimal changed axis: {:?}\n",
            m.frontier.changed_axes
        ));
        if let Some(ref sig) = m.frontier.failure_signature {
            out.push_str(&format!(
                "Stable failure signature: {} — {}\n",
                sig.kind, sig.summary
            ));
        }
        if let Some(ref cmd) = m.frontier.replay_command {
            out.push_str(&format!("Reproduce: {cmd}\n"));
        }
    } else {
        out.push_str("No observed breakage horizon within tested candidates.\n");
        for n in &m.frontier.notes {
            out.push_str(&format!("note: {n}\n"));
        }
    }
    out.push_str(&format!("Evidence: {}\n", m.evidence_root.display()));
    out.push_str(&format!("Evidence grade: {:?}\n", m.frontier.grade));
    out
}

pub fn load_and_explain(repo: &Path, run_id: &str) -> Result<String> {
    let root = repo.join(".tomorrowci/runs").join(run_id);
    let m = tomorrowci_evidence::load_run_manifest(&root)?;
    Ok(render_terminal_summary(&m))
}

pub fn replay_scenario(repo: &Path, run_id: &str, scenario_id: &str) -> Result<String> {
    let root = repo.join(".tomorrowci/runs").join(run_id);
    let m = tomorrowci_evidence::load_run_manifest(&root)?;
    let sc_dir = root.join("scenarios").join(scenario_id);
    if !sc_dir.join("result.json").exists() {
        return Err(TcError::Blocked(format!(
            "scenario evidence missing for {scenario_id}"
        )));
    }
    // Consume recorded manifest — do not replan
    let env: EnvironmentSpec = serde_json::from_str(&std::fs::read_to_string(
        sc_dir.join("environment.json"),
    )?)?;
    let commands: Vec<CommandSpec> =
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("commands.json"))?)?;
    let scenario = m
        .plan
        .scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .cloned()
        .ok_or_else(|| TcError::Other("scenario not in manifest".into()))?;

    let executor = ContainerExecutor::detect()?;
    let work = root.join("workspace");
    if !work.exists() {
        return Err(TcError::Blocked(
            "workspace copy missing for replay; external artifact unavailable".into(),
        ));
    }
    // Ensure image still resolvable
    let digest = executor.ensure_image(&env.image);
    if digest.is_err() {
        return Err(TcError::Blocked(format!(
            "image {} no longer obtainable for replay",
            env.image
        )));
    }
    let raw = executor.execute(&ExecutionContext {
        workspace: &work,
        scenario: &scenario,
        environment: &env,
        commands: &commands,
        timeout: Duration::from_secs(900),
        network: "none",
    })?;
    Ok(format!(
        "replay {scenario_id}: exit={:?} timed_out={} duration_ms={}\n",
        raw.exit_code, raw.timed_out, raw.duration_ms
    ))
}
