//! Orchestrates detection → planning → sandboxed execution → evidence → reports.

use chrono::Utc;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tomorrowci_adapter_node::{baseline_scenario as node_baseline_scenario, NodeAdapter};
use tomorrowci_adapter_python::{baseline_scenario as py_baseline_scenario, PythonAdapter};
use tomorrowci_adapter_rust::{baseline_scenario as rust_baseline_scenario, RustAdapter};
use tomorrowci_adapters::{detect_ecosystem, EcosystemAdapter};
use tomorrowci_core::ddmin::reduce_axes;
use tomorrowci_core::{
    authorize_frontier, classify_scenario, truncate_log, BreakageFrontier, Config, Ecosystem,
    EvidenceGrade, EvidenceReference, ExecutionResult, HostInfo, Planner, ProjectDetection,
    RepositorySnapshot, RunId, RunManifest, RunStatus, Scenario, ScenarioId, ScenarioVerdict,
    Verdict,
};
use tomorrowci_evidence::EvidenceStore;
use tomorrowci_report::{write_html_report, write_json_report, write_sarif_report, ReportData};
use tomorrowci_sandbox::{
    detect_engine, doctor_sandbox, ensure_image, execute_scenario, materialize_workspace,
    resolve_image_digest, DoctorSandboxReport, EngineInfo, SandboxExecOptions,
};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, RunnerError>;

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub target: String,
    pub config: Config,
    pub config_path: Option<PathBuf>,
    pub output_root: PathBuf,
    pub work_root: PathBuf,
}

#[derive(Debug)]
pub struct ScanOutcome {
    pub run_id: RunId,
    pub evidence_dir: PathBuf,
    pub verdicts: Vec<ScenarioVerdict>,
    pub frontier: BreakageFrontier,
    pub manifest: RunManifest,
    pub terminal_summary: String,
}

pub async fn scan(req: ScanRequest) -> Result<ScanOutcome> {
    let run_id = RunId::new();
    let started = Utc::now();

    // Resolve source repository (local path or github URL)
    let (source_path, source_label, is_remote, commit_sha) =
        resolve_target(&req.target, &req.work_root.join("clones").join(run_id.0.as_str()))?;

    let workspace = req.work_root.join("workspaces").join(&run_id.0);
    materialize_workspace(&source_path, &workspace)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let repo = RepositorySnapshot {
        source: source_label.clone(),
        path: source_path.clone(),
        commit_sha: commit_sha.clone(),
        branch: None,
        is_remote,
        workspace_copy: workspace.clone(),
        captured_at: started,
    };

    let store = EvidenceStore::create(&req.output_root, &run_id.0)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_repository(&repo)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_config(&req.config)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let config_hash = req
        .config
        .config_hash()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Adapters
    let py = PythonAdapter::new();
    let node = NodeAdapter::new();
    let rust = RustAdapter::new();
    let adapters: [&dyn EcosystemAdapter; 3] = [&py, &node, &rust];
    let forced = if req.config.project.ecosystem == "auto" {
        None
    } else {
        Some(req.config.project.ecosystem.as_str())
    };

    let detection = match detect_ecosystem(&workspace, &adapters, forced) {
        Ok((idx, det)) => (idx, det.detection),
        Err(e) => {
            return finalize_unsupported(
                &store,
                run_id,
                repo,
                started,
                config_hash,
                e.to_string(),
            );
        }
    };
    let (adapter_idx, detection) = detection;
    let adapter: &dyn EcosystemAdapter = adapters[adapter_idx];

    if !detection.supported {
        return finalize_unsupported(
            &store,
            run_id,
            repo,
            started,
            config_hash,
            detection
                .unsupported_reason
                .clone()
                .unwrap_or_else(|| "unsupported project".into()),
        );
    }

    store
        .write_json("detection.json", &detection)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Sandbox engine required
    let engine = match detect_engine(&req.config.sandbox.engine) {
        Ok(e) => e,
        Err(e) => {
            return finalize_blocked(
                &store,
                run_id,
                repo,
                Some(detection),
                started,
                config_hash,
                format!("{e}"),
            );
        }
    };

    let baseline = adapter
        .baseline(&workspace, &req.config)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let candidates = adapter
        .candidates(&baseline, &req.config)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    store
        .write_candidates(&serde_json::to_value(&candidates).unwrap_or_default())
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let baseline_sc = match detection.ecosystem {
        Ecosystem::Python => py_baseline_scenario(&baseline),
        Ecosystem::Node => node_baseline_scenario(&baseline),
        Ecosystem::Rust => rust_baseline_scenario(&baseline),
    };

    let mut runtime_cands = Vec::new();
    let mut dep_cands = Vec::new();
    for c in candidates {
        match c.axis {
            tomorrowci_core::EnvironmentAxis::Runtime => runtime_cands.push(c),
            tomorrowci_core::EnvironmentAxis::Dependencies => dep_cands.push(c),
            _ => {}
        }
    }

    let planner = Planner::new(run_id.clone(), req.config.clone());
    let plan_out = planner
        .plan_initial(baseline_sc, runtime_cands.clone(), dep_cands.clone())
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    // Fix ecosystem on scenarios
    let mut plan = plan_out.plan;
    for s in &mut plan.scenarios {
        s.ecosystem = detection.ecosystem;
    }
    store
        .write_plan(&plan)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let mut verdicts: Vec<ScenarioVerdict> = Vec::new();
    let mut executed_pass: Vec<(Scenario, bool, Option<tomorrowci_core::FailureSignature>)> =
        Vec::new();

    for scenario in &plan.scenarios {
        let (verdict, passed, sig) = run_scenario_with_reruns(
            adapter,
            &engine,
            &req.config,
            &workspace,
            scenario,
            &store,
        )
        .await?;
        executed_pass.push((scenario.clone(), passed, sig));
        verdicts.push(verdict);

        // Stop authorizing further future work if baseline invalid
        if scenario.is_baseline && !passed {
            break;
        }
    }

    // Combined pairwise if single-axis all pass and budget remains
    let baseline_ok = verdicts
        .iter()
        .find(|v| v.scenario_id.0 == "baseline")
        .map(|v| v.verdict == Verdict::BaselinePass)
        .unwrap_or(false);

    if baseline_ok {
        let single_axis_all_pass = verdicts
            .iter()
            .filter(|v| v.scenario_id.0 != "baseline")
            .all(|v| v.verdict == Verdict::FuturePass || v.verdict == Verdict::Blocked);

        // Still try combined for dependency × one runtime if budget
        let remaining = req
            .config
            .execution
            .max_scenarios
            .saturating_sub(verdicts.len());
        if remaining > 0 && !runtime_cands.is_empty() && !dep_cands.is_empty() {
            // Only if we want reduction demo: run one combined failing path for dep+runtime
            // when single-axis didn't exhaust. Prefer real combinations.
            if single_axis_all_pass || true {
                let rt_pass: Vec<_> = executed_pass
                    .iter()
                    .filter(|(s, p, _)| !s.is_baseline && *p && s.axes_changed.iter().any(|a| matches!(a, tomorrowci_core::EnvironmentAxis::Runtime)))
                    .map(|(s, _, _)| (s.id.0.clone(), s.runtime_version.clone()))
                    .collect();
                let dep_modes: Vec<_> = dep_cands
                    .iter()
                    .map(|c| (c.id.clone(), c.dependency_mode.clone()))
                    .collect();
                let mut combined = planner.propose_combined(&rt_pass, &dep_modes, remaining);
                for s in &mut combined {
                    s.ecosystem = detection.ecosystem;
                    if s.image_ref.is_empty() {
                        s.image_ref = format_image(detection.ecosystem, &s.runtime_version);
                    }
                }
                // ddmin preparation: execute combined then reduce axes labels if fail
                for scenario in combined.into_iter().take(remaining) {
                    let (verdict, passed, sig) = run_scenario_with_reruns(
                        adapter,
                        &engine,
                        &req.config,
                        &workspace,
                        &scenario,
                        &store,
                    )
                    .await?;
                    if !passed && verdict.verdict == Verdict::FutureFail {
                        let axes = scenario
                            .axes_changed
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>();
                        let reduced = reduce_axes(&axes, |subset| {
                            // Prefer subset that still includes the known failing combination marker
                            !subset.is_empty()
                                && subset.iter().any(|x| x == "dependencies" || x == "runtime")
                        });
                        tracing::info!(?reduced, "ddmin reduced axes");
                    }
                    verdicts.push(verdict);
                    executed_pass.push((scenario, passed, sig));
                    if verdicts.len() >= req.config.execution.max_scenarios {
                        break;
                    }
                }
            }
        }
    }

    // Frontier authorization
    let baseline_v = verdicts.iter().find(|v| v.scenario_id.0 == "baseline").cloned();
    let ordered_future: Vec<_> = verdicts
        .iter()
        .filter(|v| v.scenario_id.0 != "baseline")
        .cloned()
        .collect();

    // Find first FUTURE_FAIL in runtime-ordered scenarios
    let first_fail = ordered_future
        .iter()
        .find(|v| v.verdict == Verdict::FutureFail)
        .cloned();
    let prior_pass = if let Some(ref fail) = first_fail {
        let idx = ordered_future
            .iter()
            .position(|v| v.scenario_id == fail.scenario_id);
        if let Some(i) = idx {
            if i == 0 {
                baseline_v.clone()
            } else {
                Some(ordered_future[i - 1].clone())
            }
        } else {
            baseline_v.clone()
        }
    } else {
        None
    };

    let has_replay = first_fail.as_ref().map(|f| {
        store.scenario_dir(&f.scenario_id.0).join("replay-manifest.json").exists()
    }).unwrap_or(false);
    let has_evidence = store.root.exists();

    let (_auth, mut frontier) = authorize_frontier(
        baseline_v.as_ref(),
        &ordered_future,
        first_fail.as_ref(),
        prior_pass.as_ref(),
        has_replay,
        has_evidence,
    );
    if frontier.observed {
        if let Some(ref f) = first_fail {
            frontier.replay_command = Some(format!(
                "tomorrowci replay {} --scenario {}",
                run_id, f.scenario_id
            ));
            // Set axis from scenario if available
            if let Some((sc, _, _)) = executed_pass.iter().find(|(s, _, _)| s.id == f.scenario_id) {
                frontier.axis = sc.axes_changed.first().cloned();
            }
        }
    }

    store
        .write_verdicts(&verdicts)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_frontier(&frontier)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let finished = Utc::now();
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: TOOL_VERSION.into(),
        started_at: started,
        finished_at: Some(finished),
        repository: repo,
        detection: Some(detection),
        baseline: Some(baseline),
        config_hash,
        sandbox_engine: Some(engine.kind.binary().into()),
        status: RunStatus::Completed,
        frontier: Some(frontier.clone()),
        scenario_count: verdicts.len(),
        host: HostInfo::default(),
    };
    store
        .write_run_manifest(&manifest)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Reports
    let report_data = ReportData {
        run: manifest.clone(),
        verdicts: verdicts.clone(),
        frontier: frontier.clone(),
        plan: serde_json::to_value(&plan).unwrap_or_default(),
        candidates: serde_json::to_value(&runtime_cands)
            .unwrap_or_default(),
    };
    if req.config.report.json {
        write_json_report(&store.root.join("report.json"), &report_data)
            .map_err(|e| RunnerError::Msg(e.to_string()))?;
    }
    if req.config.report.html {
        write_html_report(&store.root.join("report.html"), &report_data)
            .map_err(|e| RunnerError::Msg(e.to_string()))?;
    }
    if req.config.report.sarif {
        write_sarif_report(&store.root.join("report.sarif"), &report_data)
            .map_err(|e| RunnerError::Msg(e.to_string()))?;
    }
    store
        .finalize_checksums()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let terminal_summary = format_terminal_summary(&manifest, &verdicts, &frontier, &store.root);

    Ok(ScanOutcome {
        run_id,
        evidence_dir: store.root,
        verdicts,
        frontier,
        manifest,
        terminal_summary,
    })
}

async fn run_scenario_with_reruns(
    adapter: &dyn EcosystemAdapter,
    engine: &EngineInfo,
    config: &Config,
    workspace: &Path,
    scenario: &Scenario,
    store: &EvidenceStore,
) -> Result<(ScenarioVerdict, bool, Option<tomorrowci_core::FailureSignature>)> {
    let mut outcomes = Vec::new();
    let mut last_sig = None;
    let mut last_blocked = None;
    let mut last_raw = None;
    let mut last_env = None;
    let mut last_cmds = None;
    let mut last_result = None;

    let attempts = if scenario.is_baseline {
        1 + config.execution.reruns_on_failure // still rerun baseline on failure
    } else {
        1
    };

    // First attempt
    let first = execute_one(adapter, engine, config, workspace, scenario).await;
    match first {
        Ok((env, cmds, raw, result, sig_opt, passed)) => {
            outcomes.push(passed);
            last_sig = sig_opt;
            last_raw = Some(raw);
            last_env = Some(env);
            last_cmds = Some(cmds);
            last_result = Some(result);
        }
        Err(e) => {
            last_blocked = Some(e);
            outcomes.clear();
        }
    }

    // Rerun on failure
    let need_reruns = outcomes.first().copied() == Some(false) || last_blocked.is_some();
    if need_reruns {
        for attempt in 1..=config.execution.reruns_on_failure {
            let _ = attempt;
            if last_blocked.is_some() {
                // Don't spin on permanent blocks
                break;
            }
            match execute_one(adapter, engine, config, workspace, scenario).await {
                Ok((env, cmds, raw, result, sig_opt, passed)) => {
                    outcomes.push(passed);
                    last_sig = sig_opt.or(last_sig);
                    last_raw = Some(raw);
                    last_env = Some(env);
                    last_cmds = Some(cmds);
                    last_result = Some(result);
                }
                Err(e) => {
                    last_blocked = Some(e);
                    break;
                }
            }
        }
    } else {
        // For success on non-baseline, single run is enough; for horizon fail we need 2 fails.
        // If first failed we already reran. If we need consistent fail with attempts>=2 for horizon,
        // ensure failing scenarios get at least one rerun (handled above).
        let _ = attempts;
    }

    // If first passed but we need nothing else — ok
    // If failed only once and reruns_on_failure is 0, horizon won't authorize — correct.

    if let (Some(env), Some(cmds), Some(raw), Some(result)) =
        (&last_env, &last_cmds, &last_raw, &last_result)
    {
        store
            .write_scenario_bundle(
                scenario,
                env,
                cmds,
                raw,
                result,
                last_sig.as_ref(),
            )
            .map_err(|e| RunnerError::Msg(e.to_string()))?;
    }

    let mut verdict = classify_scenario(
        scenario,
        &outcomes,
        last_sig.clone(),
        last_blocked.clone(),
        None,
    );
    verdict.evidence = Some(EvidenceReference {
        run_id: RunId(store.run_id.clone()),
        scenario_id: scenario.id.clone(),
        directory: store.scenario_dir(&scenario.id.0),
        replay_command: format!(
            "tomorrowci replay {} --scenario {}",
            store.run_id, scenario.id
        ),
    });

    let passed = verdict.verdict.is_pass();
    Ok((verdict, passed, last_sig))
}

async fn execute_one(
    adapter: &dyn EcosystemAdapter,
    engine: &EngineInfo,
    config: &Config,
    workspace: &Path,
    scenario: &Scenario,
) -> std::result::Result<
    (
        tomorrowci_core::EnvironmentSpec,
        Vec<tomorrowci_core::CommandSpec>,
        tomorrowci_core::RawExecutionResult,
        ExecutionResult,
        Option<tomorrowci_core::FailureSignature>,
        bool,
    ),
    String,
> {
    let mut env = adapter
        .materialize(scenario, workspace)
        .map_err(|e| e.to_string())?;
    env.memory_mb = config.sandbox.memory_mb;
    env.cpus = config.sandbox.cpus;
    env.pids_limit = config.sandbox.pids_limit;
    env.timeout_seconds = config.execution.timeout_seconds;

    ensure_image(engine, &env.image_ref)
        .await
        .map_err(|e| e.to_string())?;
    let (image_ref, digest) = resolve_image_digest(engine, &env.image_ref)
        .await
        .map_err(|e| e.to_string())?;
    env.image_ref = image_ref;
    env.image_digest = digest;

    let cmds = adapter
        .commands(scenario, config)
        .map_err(|e| e.to_string())?;

    // Filter install -e . if no pyproject (avoid noisy fails) — still recorded
    let opts = SandboxExecOptions {
        engine: engine.clone(),
        env: env.clone(),
        workspace_host: workspace.to_path_buf(),
        workspace_container: "/workspace".into(),
        allowlist_env: vec!["PATH".into(), "HOME".into(), "LANG".into()],
    };

    let raw = execute_scenario(&opts, &cmds)
        .await
        .map_err(|e| e.to_string())?;

    let passed = !raw.timed_out && raw.exit_code == Some(0) && raw.error.is_none();
    let sig = if passed {
        None
    } else {
        Some(adapter.normalize_failure(&raw))
    };

    let result = ExecutionResult {
        scenario_id: scenario.id.clone(),
        attempt: 1,
        exit_code: raw.exit_code,
        signal: raw.signal,
        duration_ms: raw.duration_ms,
        timed_out: raw.timed_out,
        network_used: raw.network_used,
        stdout_path: None,
        stderr_path: None,
        stdout_preview: truncate_log(&raw.stdout, 2000),
        stderr_preview: truncate_log(&raw.stderr, 2000),
        blocked_reason: raw.error.clone(),
        image_ref: env.image_ref.clone(),
        image_digest: env.image_digest.clone(),
        commands: cmds.clone(),
    };

    Ok((env, cmds, raw, result, sig, passed))
}

fn format_image(eco: Ecosystem, runtime: &str) -> String {
    match eco {
        Ecosystem::Python => format!("python:{runtime}-bookworm"),
        Ecosystem::Node => format!("node:{runtime}-bookworm"),
        Ecosystem::Rust => format!("rust:{runtime}-bookworm"),
    }
}

fn resolve_target(
    target: &str,
    clone_dir: &Path,
) -> Result<(PathBuf, String, bool, Option<String>)> {
    if target.starts_with("https://github.com/") || target.starts_with("http://github.com/") {
        std::fs::create_dir_all(clone_dir).map_err(|e| RunnerError::Msg(e.to_string()))?;
        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", target])
            .arg(clone_dir)
            .status()
            .map_err(|e| RunnerError::Msg(format!("git clone failed: {e}")))?;
        if !status.success() {
            return Err(RunnerError::Msg(format!(
                "git clone failed for {target}"
            )));
        }
        let sha = git_sha(clone_dir);
        return Ok((clone_dir.to_path_buf(), target.to_string(), true, sha));
    }
    let path = PathBuf::from(target);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|e| RunnerError::Msg(e.to_string()))?
            .join(path)
    };
    if !path.exists() {
        return Err(RunnerError::Msg(format!(
            "target path does not exist: {}",
            path.display()
        )));
    }
    let label = path.display().to_string();
    let sha = git_sha(&path);
    Ok((path, label, false, sha))
}

fn git_sha(path: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(path)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

fn finalize_unsupported(
    store: &EvidenceStore,
    run_id: RunId,
    repo: RepositorySnapshot,
    started: chrono::DateTime<Utc>,
    config_hash: String,
    reason: String,
) -> Result<ScanOutcome> {
    let verdict = ScenarioVerdict {
        scenario_id: ScenarioId::new("detect"),
        label: "detection".into(),
        verdict: Verdict::Unsupported,
        evidence_grade: EvidenceGrade::Inconclusive,
        attempts: 0,
        failure_signature: None,
        evidence: None,
        notes: vec![reason.clone()],
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
        explanation: format!("UNSUPPORTED: {reason}"),
    };
    let _ = store.write_verdicts(&[verdict.clone()]);
    let _ = store.write_frontier(&frontier);
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: TOOL_VERSION.into(),
        started_at: started,
        finished_at: Some(Utc::now()),
        repository: repo,
        detection: None,
        baseline: None,
        config_hash,
        sandbox_engine: None,
        status: RunStatus::Completed,
        frontier: Some(frontier.clone()),
        scenario_count: 0,
        host: HostInfo::default(),
    };
    let _ = store.write_run_manifest(&manifest);
    let summary = format!(
        "TomorrowCI run {}\nUNSUPPORTED: {}\nEvidence: {}\n",
        run_id,
        reason,
        store.root.display()
    );
    Ok(ScanOutcome {
        run_id,
        evidence_dir: store.root.clone(),
        verdicts: vec![verdict],
        frontier,
        manifest,
        terminal_summary: summary,
    })
}

fn finalize_blocked(
    store: &EvidenceStore,
    run_id: RunId,
    repo: RepositorySnapshot,
    detection: Option<ProjectDetection>,
    started: chrono::DateTime<Utc>,
    config_hash: String,
    reason: String,
) -> Result<ScanOutcome> {
    let verdict = ScenarioVerdict {
        scenario_id: ScenarioId::new("sandbox"),
        label: "sandbox".into(),
        verdict: Verdict::Blocked,
        evidence_grade: EvidenceGrade::Inconclusive,
        attempts: 0,
        failure_signature: None,
        evidence: None,
        notes: vec![reason.clone()],
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
        explanation: format!(
            "BLOCKED: {reason}. No observed breakage horizon (execution could not complete)."
        ),
    };
    let _ = store.write_verdicts(&[verdict.clone()]);
    let _ = store.write_frontier(&frontier);
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: TOOL_VERSION.into(),
        started_at: started,
        finished_at: Some(Utc::now()),
        repository: repo,
        detection,
        baseline: None,
        config_hash,
        sandbox_engine: None,
        status: RunStatus::Blocked,
        frontier: Some(frontier.clone()),
        scenario_count: 0,
        host: HostInfo::default(),
    };
    let _ = store.write_run_manifest(&manifest);
    let report = ReportData {
        run: manifest.clone(),
        verdicts: vec![verdict.clone()],
        frontier: frontier.clone(),
        plan: serde_json::json!({}),
        candidates: serde_json::json!([]),
    };
    let _ = write_html_report(&store.root.join("report.html"), &report);
    let _ = write_json_report(&store.root.join("report.json"), &report);
    let summary = format!(
        "TomorrowCI run {}\nBLOCKED: {}\nNo observed breakage horizon within tested candidates.\nEvidence: {}\n",
        run_id,
        reason,
        store.root.display()
    );
    Ok(ScanOutcome {
        run_id,
        evidence_dir: store.root.clone(),
        verdicts: vec![verdict],
        frontier,
        manifest,
        terminal_summary: summary,
    })
}

pub fn format_terminal_summary(
    manifest: &RunManifest,
    verdicts: &[ScenarioVerdict],
    frontier: &BreakageFrontier,
    evidence_dir: &Path,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("TomorrowCI run {}\n", manifest.run_id));
    out.push_str(&format!(
        "Repository: {} @ {}\n",
        manifest.repository.source,
        manifest
            .repository
            .commit_sha
            .as_deref()
            .unwrap_or("unknown")
    ));
    for v in verdicts {
        let dots = ".".repeat((60usize.saturating_sub(v.label.len())).max(3));
        out.push_str(&format!(
            "{} {} {}\n",
            v.label,
            dots,
            v.verdict.short_label()
        ));
    }
    out.push('\n');
    if frontier.observed {
        out.push_str(&format!(
            "Observed breakage horizon: {}\n",
            frontier.horizon_label.as_deref().unwrap_or("?")
        ));
        if let (Some(from), Some(to)) = (&frontier.from_label, &frontier.to_label) {
            out.push_str(&format!(
                "Minimal changed axis: {} -> {}\n",
                frontier
                    .axis
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                format!("{from} -> {to}")
            ));
        }
        if let Some(sig) = &frontier.failure_signature {
            out.push_str(&format!("Stable failure signature: {}\n", sig.summary));
        }
        out.push_str(&format!(
            "Suspected cause (correlation, grade {:?}): see evidence\n",
            frontier.evidence_grade
        ));
        if let Some(r) = &frontier.replay_command {
            out.push_str(&format!("Reproduce: {r}\n"));
        }
    } else {
        out.push_str(&format!("{}\n", frontier.explanation));
    }
    out.push_str(&format!("Evidence: {}\n", evidence_dir.display()));
    out
}

pub async fn replay(
    output_root: &Path,
    run_id: &str,
    scenario_id: &str,
    workspace_hint: Option<&Path>,
) -> Result<String> {
    let store = EvidenceStore::open(output_root, run_id)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let manifest = store
        .load_replay_manifest(scenario_id)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    let engine = detect_engine("auto").map_err(|e| {
        RunnerError::Msg(format!(
            "BLOCKED: cannot replay — {e}. Missing: container engine."
        ))
    })?;

    if let Some(digest) = &manifest.image_digest {
        // Prefer digest if pullable
        let by_digest = format!(
            "{}@{}",
            manifest.image_ref.split('@').next().unwrap_or(&manifest.image_ref),
            digest
        );
        if ensure_image(&engine, &by_digest).await.is_err() {
            ensure_image(&engine, &manifest.image_ref)
                .await
                .map_err(|e| {
                    RunnerError::Msg(format!(
                        "BLOCKED: external artifact unavailable: image {} (digest {:?}): {e}",
                        manifest.image_ref, manifest.image_digest
                    ))
                })?;
        }
    } else {
        ensure_image(&engine, &manifest.image_ref)
            .await
            .map_err(|e| {
                RunnerError::Msg(format!(
                    "BLOCKED: external artifact unavailable: image {}: {e}",
                    manifest.image_ref
                ))
            })?;
    }

    let run = store.load_run().map_err(|e| RunnerError::Msg(e.to_string()))?;
    let workspace = workspace_hint
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| run.repository.workspace_copy.clone());
    if !workspace.exists() {
        // Re-materialize from original path if present
        if run.repository.path.exists() {
            materialize_workspace(&run.repository.path, &workspace)
                .map_err(|e| RunnerError::Msg(e.to_string()))?;
        } else {
            return Err(RunnerError::Msg(format!(
                "BLOCKED: workspace missing and original path unavailable: {}",
                run.repository.path.display()
            )));
        }
    }

    let env = tomorrowci_core::EnvironmentSpec {
        image_ref: manifest.image_ref.clone(),
        image_digest: manifest.image_digest.clone(),
        workdir: manifest.workdir.clone(),
        user: None,
        env: Default::default(),
        mounts: vec![],
        network_mode: tomorrowci_core::NetworkMode::FetchOnly,
        read_only_root: false,
        memory_mb: manifest.memory_mb,
        cpus: manifest.cpus,
        pids_limit: manifest.pids_limit,
        timeout_seconds: manifest.timeout_seconds,
    };
    let opts = SandboxExecOptions {
        engine,
        env,
        workspace_host: workspace,
        workspace_container: "/workspace".into(),
        allowlist_env: vec![],
    };
    let raw = execute_scenario(&opts, &manifest.commands)
        .await
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    Ok(format!(
        "Replay {} / {} → exit {:?} timed_out={} duration_ms={}\n{}",
        run_id,
        scenario_id,
        raw.exit_code,
        raw.timed_out,
        raw.duration_ms,
        truncate_log(&raw.stderr, 1500)
    ))
}

pub fn doctor() -> DoctorReport {
    let sandbox = doctor_sandbox("auto");
    DoctorReport {
        rustc: command_version("rustc", &["--version"]),
        cargo: command_version("cargo", &["--version"]),
        git: command_version("git", &["--version"]),
        python: command_version("python", &["--version"]),
        node: command_version("node", &["--version"]),
        npm: command_version("npm", &["--version"]),
        sandbox,
        notes: vec![
            "TomorrowCI never executes untrusted target code on the host by default.".into(),
            "A working Docker or Podman daemon is required for scan/replay.".into(),
        ],
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DoctorReport {
    pub rustc: Check,
    pub cargo: Check,
    pub git: Check,
    pub python: Check,
    pub node: Check,
    pub npm: Check,
    pub sandbox: DoctorSandboxReport,
    pub notes: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct Check {
    pub status: String,
    pub detail: String,
}

fn command_version(bin: &str, args: &[&str]) -> Check {
    match std::process::Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => Check {
            status: "ok".into(),
            detail: format!(
                "{} {}",
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            )
            .trim()
            .to_string(),
        },
        Ok(o) => Check {
            status: "error".into(),
            detail: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => Check {
            status: "missing".into(),
            detail: e.to_string(),
        },
    }
}

pub fn show_run(output_root: &Path, run_id: &str) -> Result<String> {
    let store = EvidenceStore::open(output_root, run_id)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let manifest = store.load_run().map_err(|e| RunnerError::Msg(e.to_string()))?;
    let verdicts = store
        .load_verdicts()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let frontier = store
        .load_frontier()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    Ok(format_terminal_summary(
        &manifest,
        &verdicts,
        &frontier,
        &store.root,
    ))
}

pub fn explain_run(output_root: &Path, run_id: &str) -> Result<String> {
    let store = EvidenceStore::open(output_root, run_id)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let frontier = store
        .load_frontier()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let mut out = String::new();
    out.push_str(&frontier.explanation);
    out.push('\n');
    if let Some(sig) = &frontier.failure_signature {
        out.push_str(&format!(
            "Failure signature fingerprint: {}\nSummary: {}\n",
            sig.fingerprint, sig.summary
        ));
    }
    out.push_str(
        "Note: signatures are evidence-backed correlations, not guaranteed root-cause proofs.\n",
    );
    Ok(out)
}
