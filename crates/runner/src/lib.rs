//! Orchestrates detection → planning → sandboxed execution → evidence → reports.

use chrono::{DateTime, NaiveDate, Utc};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tomorrowci_adapter_node::{baseline_scenario as node_baseline_scenario, NodeAdapter};
use tomorrowci_adapter_python::{baseline_scenario as py_baseline_scenario, PythonAdapter};
use tomorrowci_adapter_rust::{baseline_scenario as rust_baseline_scenario, RustAdapter};
use tomorrowci_adapters::{detect_ecosystem, EcosystemAdapter};
use tomorrowci_core::backtest::{
    BacktestPoint, BacktestPointStatus, BacktestReport, BacktestRequest,
};
use tomorrowci_core::compare::{compare_horizons, HorizonCompare};
use tomorrowci_core::ddmin::reduce_axes;
use tomorrowci_core::policy::{evaluate_policy, PolicyConfig, PolicyReport};
use tomorrowci_core::{
    authorize_frontier, canonical_sha256, classify_scenario,
    redaction::{redact_secrets, sanitize_terminal},
    truncate_log, AttemptKindV2, AttemptOutcomeClassV2, BreakageFrontier, CommandSpec, Config,
    Ecosystem, EngineIdentityV2, EnvironmentSpec, EvidenceGrade, EvidenceReference,
    ExactEnvironmentV2, ExactReplayManifestV2, ExecutionAttemptResultV2, ExecutionAttemptV2,
    ExecutionResult, FailureSignature, HostInfo, NormalizedFailureSignatureV2, Planner,
    ProjectDetection, RawExecutionResult, ReplayCommandV2, ReplayQualificationV2,
    RepositorySnapshot, RunId, RunManifest, RunStatus, Scenario, ScenarioId, ScenarioVerdict,
    SourceIdentityKindV2, SourceSnapshotManifestV2, Verdict, REPLAY_SCHEMA_VERSION_V2,
};
use tomorrowci_evidence::{
    capture_source_snapshot_v2, AttemptEvidenceV2, EvidenceStore, VerifiedBundle,
};
use tomorrowci_report::{write_html_report, write_json_report, write_sarif_report};
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

#[derive(Debug, Clone)]
struct ReplayContextV2 {
    run_id: RunId,
    source_manifest_sha256: String,
    config_sha256: String,
}

pub async fn scan(req: ScanRequest) -> Result<ScanOutcome> {
    let run_id = RunId::new();
    let started = Utc::now();

    // Resolve source repository (local path or github URL)
    let (source_path, source_label, is_remote, commit_sha) = resolve_target(
        &req.target,
        &req.work_root.join("clones").join(run_id.0.as_str()),
    )?;

    let workspace = req.work_root.join("workspaces").join(&run_id.0);
    materialize_workspace(&source_path, &workspace).map_err(|e| RunnerError::Msg(e.to_string()))?;

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
    let source_dirty = commit_sha.is_some() && git_worktree_dirty(&source_path);
    let source_identity = match (&commit_sha, source_dirty) {
        (Some(_), false) => SourceIdentityKindV2::GitCommit,
        (Some(_), true) => SourceIdentityKindV2::DirtyWorktree,
        (None, _) => SourceIdentityKindV2::NonGit,
    };
    let source_manifest = capture_source_snapshot_v2(
        &run_id,
        &workspace,
        &source_label,
        commit_sha.clone(),
        source_identity,
        source_dirty,
        started,
    )
    .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_source_manifest_v2(&source_manifest)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    // Required even for an early UNSUPPORTED/BLOCKED v2 run; normal scans
    // overwrite it with every positive and negative qualification record.
    store
        .write_replay_qualifications_v2(&[])
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let replay_context = ReplayContextV2 {
        run_id: run_id.clone(),
        source_manifest_sha256: canonical_sha256(&source_manifest)
            .map_err(|e| RunnerError::Msg(e.to_string()))?,
        config_sha256: canonical_sha256(&req.config)
            .map_err(|e| RunnerError::Msg(e.to_string()))?,
    };

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
                FinalizationContext {
                    store: &store,
                    run_id,
                    repo,
                    started,
                    config: &req.config,
                    config_hash,
                },
                None,
                e.to_string(),
            );
        }
    };
    let (adapter_idx, detection) = detection;
    let adapter: &dyn EcosystemAdapter = adapters[adapter_idx];

    if !detection.supported {
        return finalize_unsupported(
            FinalizationContext {
                store: &store,
                run_id,
                repo,
                started,
                config: &req.config,
                config_hash,
            },
            Some(detection.clone()),
            detection
                .unsupported_reason
                .clone()
                .unwrap_or_else(|| "unsupported project".into()),
        );
    }

    store
        .write_detection(&detection)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Sandbox engine required
    let engine = match detect_engine(&req.config.sandbox.engine) {
        Ok(e) => e,
        Err(e) => {
            return finalize_blocked(
                FinalizationContext {
                    store: &store,
                    run_id,
                    repo,
                    started,
                    config: &req.config,
                    config_hash,
                },
                detection,
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
    let candidates_json = serde_json::to_value(&candidates).unwrap_or_default();

    store
        .write_candidates(&candidates_json)
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
    let mut replay_qualifications = Vec::new();

    // Baseline always first (serial) — future work is unauthorized without it.
    let (baseline_scenarios, future_scenarios): (Vec<_>, Vec<_>) =
        plan.scenarios.iter().cloned().partition(|s| s.is_baseline);

    for scenario in &baseline_scenarios {
        let (verdict, passed, sig, qualification) = run_scenario_with_reruns(
            adapter,
            &engine,
            &req.config,
            &workspace,
            scenario,
            &store,
            &replay_context,
        )
        .await?;
        executed_pass.push((scenario.clone(), passed, sig));
        if let Some(qualification) = qualification {
            replay_qualifications.push(qualification);
        }
        verdicts.push(verdict);
        if !passed {
            // No parallel futures when baseline fails.
            break;
        }
    }

    let baseline_ok = verdicts
        .iter()
        .find(|v| v.scenario_id.0 == "baseline")
        .map(|v| v.verdict == Verdict::BaselinePass)
        .unwrap_or(false);

    if baseline_ok && !future_scenarios.is_empty() {
        let max_p = req.config.execution.max_parallel.max(1);
        tracing::info!(
            max_parallel = max_p,
            n = future_scenarios.len(),
            "running future scenarios"
        );
        let results = run_scenarios_bounded(
            adapter,
            &engine,
            &req.config,
            &workspace,
            &store,
            &replay_context,
            &future_scenarios,
            max_p,
        )
        .await?;
        // Preserve plan order for deterministic terminal output.
        for scenario in &future_scenarios {
            if let Some((verdict, passed, sig, qualification)) = results.get(&scenario.id.0) {
                executed_pass.push((scenario.clone(), *passed, sig.clone()));
                verdicts.push(verdict.clone());
                if let Some(qualification) = qualification {
                    replay_qualifications.push(qualification.clone());
                }
            }
        }
    }

    // Combined pairwise if budget remains
    if baseline_ok {
        let remaining = req
            .config
            .execution
            .max_scenarios
            .saturating_sub(verdicts.len());
        if remaining > 0 && !runtime_cands.is_empty() && !dep_cands.is_empty() {
            let rt_pass: Vec<_> = executed_pass
                .iter()
                .filter(|(s, p, _)| {
                    !s.is_baseline
                        && *p
                        && s.axes_changed
                            .iter()
                            .any(|a| matches!(a, tomorrowci_core::EnvironmentAxis::Runtime))
                })
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
            let combined: Vec<_> = combined.into_iter().take(remaining).collect();
            if !combined.is_empty() {
                plan.scenarios.extend(combined.iter().cloned());
                let max_p = req.config.execution.max_parallel.max(1);
                let results = run_scenarios_bounded(
                    adapter,
                    &engine,
                    &req.config,
                    &workspace,
                    &store,
                    &replay_context,
                    &combined,
                    max_p,
                )
                .await?;
                for scenario in &combined {
                    if let Some((verdict, passed, sig, qualification)) = results.get(&scenario.id.0)
                    {
                        if !passed && verdict.verdict == Verdict::FutureFail {
                            let axes = scenario
                                .axes_changed
                                .iter()
                                .map(|a| a.to_string())
                                .collect::<Vec<_>>();
                            let reduced = reduce_axes(&axes, |subset| {
                                !subset.is_empty()
                                    && subset.iter().any(|x| x == "dependencies" || x == "runtime")
                            });
                            tracing::info!(?reduced, "ddmin reduced axes");
                        }
                        executed_pass.push((scenario.clone(), *passed, sig.clone()));
                        verdicts.push(verdict.clone());
                        if let Some(qualification) = qualification {
                            replay_qualifications.push(qualification.clone());
                        }
                    }
                }
            }
        }
    }

    // Combined scenarios are proposed after the initial plan is persisted.
    // Rewrite the final executed plan before verdicts and checksum sealing.
    store
        .write_plan(&plan)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let qualification_records = replay_qualifications
        .iter()
        .map(|qualification| qualification.record.clone())
        .collect::<Vec<_>>();
    store
        .write_replay_qualifications_v2(&qualification_records)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Frontier authorization
    let baseline_v = verdicts
        .iter()
        .find(|v| v.scenario_id.0 == "baseline")
        .cloned();
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

    let has_replay = first_fail
        .as_ref()
        .map(|failure| {
            replay_qualifications.iter().any(|qualification| {
                qualification.record.scenario_id == failure.scenario_id
                    && qualification.qualified_against
            })
        })
        .unwrap_or(false);
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
    let status = final_run_status(&verdicts);
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
        status,
        frontier: Some(frontier.clone()),
        scenario_count: verdicts.len(),
        host: HostInfo::default(),
    };
    store
        .write_run_manifest(&manifest)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;

    // Reports
    write_configured_reports(&store, &req.config)?;
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

type ScenarioOutcome = (
    ScenarioVerdict,
    bool,
    Option<tomorrowci_core::FailureSignature>,
    Option<ScenarioQualification>,
);

#[derive(Debug, Clone)]
struct ScenarioQualification {
    record: ReplayQualificationV2,
    qualified_against: bool,
}
type ScenarioOutcomeMap = std::collections::HashMap<String, ScenarioOutcome>;

/// Run scenarios with bounded concurrency. Results keyed by scenario id.
/// Ordering of execution is not guaranteed; callers should re-sort by plan order.
#[allow(clippy::too_many_arguments)]
async fn run_scenarios_bounded(
    adapter: &dyn EcosystemAdapter,
    engine: &EngineInfo,
    config: &Config,
    workspace: &Path,
    store: &EvidenceStore,
    replay_context: &ReplayContextV2,
    scenarios: &[Scenario],
    max_parallel: usize,
) -> Result<ScenarioOutcomeMap> {
    use futures::stream::{self, StreamExt};
    let limit = max_parallel.max(1);
    let results: Vec<Result<(String, ScenarioOutcome)>> = stream::iter(scenarios.iter())
        .map(|scenario| async move {
            let (verdict, passed, sig, qualification) = run_scenario_with_reruns(
                adapter,
                engine,
                config,
                workspace,
                scenario,
                store,
                replay_context,
            )
            .await?;
            Ok((scenario.id.0.clone(), (verdict, passed, sig, qualification)))
        })
        .buffer_unordered(limit)
        .collect()
        .await;

    let mut map = ScenarioOutcomeMap::new();
    for r in results {
        let (id, triple) = r?;
        map.insert(id, triple);
    }
    Ok(map)
}

async fn run_scenario_with_reruns(
    adapter: &dyn EcosystemAdapter,
    engine: &EngineInfo,
    config: &Config,
    workspace: &Path,
    scenario: &Scenario,
    store: &EvidenceStore,
    replay_context: &ReplayContextV2,
) -> Result<(
    ScenarioVerdict,
    bool,
    Option<tomorrowci_core::FailureSignature>,
    Option<ScenarioQualification>,
)> {
    let mut outcomes = Vec::new();
    let mut last_sig = None;
    let mut last_blocked = None;
    let mut original_attempts = Vec::new();
    let mut replay_manifest = None;

    // First attempt
    let first = execute_one(adapter, engine, config, workspace, scenario, 1).await;
    match first {
        Ok(attempt) => {
            log_attempt_provenance(&attempt.provenance);
            outcomes.push(attempt.completed.passed);
            last_sig = attempt.completed.signature.clone();
            replay_manifest = Some(build_exact_replay_manifest_v2(
                replay_context,
                scenario,
                &attempt.completed.environment,
                &attempt.completed.commands,
                engine,
                attempt.provenance.started_at,
            )?);
            original_attempts.push(attempt);
        }
        Err(failure) => {
            log_attempt_provenance(&failure.provenance);
            last_blocked = Some(redact_secrets(&failure.message));
            outcomes.clear();
        }
    }

    // Rerun on failure
    let need_reruns = outcomes.first().copied() == Some(false) || last_blocked.is_some();
    if need_reruns {
        for rerun_index in 0..config.execution.reruns_on_failure {
            if last_blocked.is_some() {
                // Don't spin on permanent blocks
                break;
            }
            let ordinal = rerun_index + 2;
            let Some(recorded) = original_attempts.last() else {
                last_blocked = Some("rerun has no recorded first attempt".into());
                break;
            };
            let environment = recorded.completed.environment.clone();
            let commands = recorded.completed.commands.clone();
            match execute_recorded_attempt(
                engine,
                workspace,
                scenario,
                &environment,
                &commands,
                ordinal,
                AttemptKindV2::Original,
            )
            .await
            {
                Ok(mut attempt) => {
                    log_attempt_provenance(&attempt.provenance);
                    if !attempt.completed.passed {
                        let mut signature = adapter.normalize_failure(&attempt.completed.raw);
                        signature.evidence_grade = scenario.evidence_grade;
                        attempt.completed.signature = Some(redact_failure_signature(&signature));
                    }
                    outcomes.push(attempt.completed.passed);
                    last_sig = attempt.completed.signature.clone().or(last_sig);
                    original_attempts.push(attempt);
                }
                Err(failure) => {
                    log_attempt_provenance(&failure.provenance);
                    last_blocked = Some(redact_secrets(&failure.message));
                    break;
                }
            }
        }
    }

    let mut verdict = classify_scenario(
        scenario,
        &outcomes,
        last_sig.clone(),
        last_blocked.clone(),
        None,
    );

    // A stable FUTURE_FAIL must replay the already-recorded exact manifest in
    // two independent disposable workspaces before it can authorize a horizon.
    // Negative attempts are retained just as carefully as positive attempts.
    let mut replay_attempts = Vec::new();
    if verdict.verdict == Verdict::FutureFail && last_blocked.is_none() {
        if let (Some(recorded), Some(manifest)) =
            (original_attempts.last(), replay_manifest.as_ref())
        {
            for ordinal in 1..=2 {
                match execute_recorded_attempt(
                    engine,
                    workspace,
                    scenario,
                    &recorded.completed.environment,
                    &recorded.completed.commands,
                    ordinal,
                    AttemptKindV2::Replay,
                )
                .await
                {
                    Ok(mut attempt) => {
                        log_attempt_provenance(&attempt.provenance);
                        if !attempt.completed.passed {
                            let mut signature = adapter.normalize_failure(&attempt.completed.raw);
                            signature.evidence_grade = scenario.evidence_grade;
                            attempt.completed.signature =
                                Some(redact_failure_signature(&signature));
                        }
                        replay_attempts.push(attempt_evidence_v2(
                            replay_context,
                            scenario,
                            manifest,
                            &attempt,
                        )?);
                    }
                    Err(failure) => {
                        log_attempt_provenance(&failure.provenance);
                        replay_attempts.push(attempt_failure_evidence_v2(
                            replay_context,
                            scenario,
                            manifest,
                            &failure,
                        )?);
                    }
                }
            }
        }
    }

    // A later execution-level block means a prior result is not the final
    // classified outcome. BLOCKED verdicts intentionally carry no scenario
    // evidence under the strict run semantics.
    let mut qualification = None;
    let has_bundle = if may_publish_final_attempt(last_blocked.as_deref()) {
        if let (Some(attempt), Some(manifest)) =
            (original_attempts.last(), replay_manifest.as_ref())
        {
            let mut attempt_evidence = original_attempts
                .iter()
                .map(|attempt| attempt_evidence_v2(replay_context, scenario, manifest, attempt))
                .collect::<Result<Vec<_>>>()?;
            attempt_evidence.extend(replay_attempts);
            let original_receipts = attempt_evidence
                .iter()
                .filter(|evidence| evidence.attempt.kind == AttemptKindV2::Original)
                .map(|evidence| evidence.attempt.clone())
                .collect::<Vec<_>>();
            let replay_receipts = attempt_evidence
                .iter()
                .filter(|evidence| evidence.attempt.kind == AttemptKindV2::Replay)
                .map(|evidence| evidence.attempt.clone())
                .collect::<Vec<_>>();
            let (_, persisted) = store
                .write_scenario_bundle_v2(
                    scenario,
                    &attempt.completed.environment,
                    &attempt.completed.commands,
                    &attempt.completed.raw,
                    &attempt.completed.result,
                    last_sig.as_ref(),
                    manifest,
                    &attempt_evidence,
                )
                .map_err(|e| RunnerError::Msg(e.to_string()))?;
            if let Some(record) = persisted {
                let qualified_against = original_receipts
                    .last()
                    .is_some_and(|original| record.qualified_against(original, &replay_receipts));
                qualification = Some(ScenarioQualification {
                    record,
                    qualified_against,
                });
            }
            true
        } else {
            false
        }
    } else {
        false
    };

    verdict.evidence = has_bundle.then(|| EvidenceReference {
        run_id: RunId(store.run_id.clone()),
        scenario_id: scenario.id.clone(),
        directory: store.scenario_dir(&scenario.id.0),
        replay_command: format!(
            "tomorrowci replay {} --scenario {}",
            store.run_id, scenario.id
        ),
    });

    let passed = verdict.verdict.is_pass();
    Ok((verdict, passed, last_sig, qualification))
}

fn may_publish_final_attempt(blocked_reason: Option<&str>) -> bool {
    blocked_reason.is_none()
}

#[derive(Debug, Clone)]
struct AttemptProvenance {
    ordinal: u32,
    kind: AttemptKindV2,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    engine_kind: String,
    engine_version: String,
}

#[derive(Debug)]
struct ExecutedAttempt {
    provenance: AttemptProvenance,
    completed: CompletedAttempt,
}

#[derive(Debug)]
struct CompletedAttempt {
    environment: EnvironmentSpec,
    commands: Vec<CommandSpec>,
    raw: RawExecutionResult,
    result: ExecutionResult,
    signature: Option<FailureSignature>,
    passed: bool,
}

#[derive(Debug)]
struct AttemptFailure {
    provenance: AttemptProvenance,
    message: String,
}

fn log_attempt_provenance(provenance: &AttemptProvenance) {
    tracing::debug!(
        attempt = provenance.ordinal,
        kind = ?provenance.kind,
        started_at = %provenance.started_at,
        finished_at = %provenance.finished_at,
        engine = %provenance.engine_kind,
        engine_version = %provenance.engine_version,
        "scenario attempt finished"
    );
}

async fn execute_one(
    adapter: &dyn EcosystemAdapter,
    engine: &EngineInfo,
    config: &Config,
    workspace: &Path,
    scenario: &Scenario,
    ordinal: u32,
) -> std::result::Result<ExecutedAttempt, AttemptFailure> {
    let mut env = adapter
        .materialize(scenario, workspace)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    env.memory_mb = config.sandbox.memory_mb;
    env.cpus = config.sandbox.cpus;
    env.pids_limit = config.sandbox.pids_limit;
    env.timeout_seconds = config.execution.timeout_seconds;

    ensure_image(engine, &env.image_ref)
        .await
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    let (image_ref, digest) = resolve_image_digest(engine, &env.image_ref)
        .await
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    env.image_ref = image_ref;
    env.image_digest = digest;
    environment_with_exact_image(&env)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e))?;

    let commands = adapter
        .commands(scenario, config)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    let mut attempt = execute_recorded_attempt(
        engine,
        workspace,
        scenario,
        &env,
        &commands,
        ordinal,
        AttemptKindV2::Original,
    )
    .await?;
    if !attempt.completed.passed {
        let mut signature = adapter.normalize_failure(&attempt.completed.raw);
        signature.evidence_grade = scenario.evidence_grade;
        attempt.completed.signature = Some(redact_failure_signature(&signature));
    }
    Ok(attempt)
}

async fn execute_recorded_attempt(
    engine: &EngineInfo,
    workspace: &Path,
    scenario: &Scenario,
    environment: &EnvironmentSpec,
    commands: &[CommandSpec],
    ordinal: u32,
    kind: AttemptKindV2,
) -> std::result::Result<ExecutedAttempt, AttemptFailure> {
    let started_at = Utc::now();
    let execution = async {
        let attempt_workspace = disposable_workspace(workspace)?;
        let execution_env = environment_with_exact_image(environment)?;
        ensure_image(engine, &execution_env.image_ref)
            .await
            .map_err(|e| format!("BLOCKED: exact image unavailable: {e}"))?;

        // Filter install -e . if no pyproject (avoid noisy fails) — still recorded
        let opts = SandboxExecOptions {
            engine: engine.clone(),
            env: execution_env,
            workspace_host: attempt_workspace.path().to_path_buf(),
            workspace_container: "/workspace".into(),
            allowlist_env: vec![],
        };

        let raw = execute_scenario(&opts, commands)
            .await
            .map_err(|e| e.to_string())?;

        let passed = replay_target_succeeded(&raw);
        let result = build_execution_result(scenario, ordinal, environment, commands, &raw);

        Ok(CompletedAttempt {
            environment: environment.clone(),
            commands: commands.to_vec(),
            raw,
            result,
            signature: None,
            passed,
        })
    }
    .await;
    let provenance = AttemptProvenance {
        ordinal,
        kind,
        started_at,
        finished_at: Utc::now(),
        engine_kind: engine.kind.binary().into(),
        engine_version: engine.version.clone(),
    };
    execution
        .map(|completed| ExecutedAttempt {
            provenance: provenance.clone(),
            completed,
        })
        .map_err(|message| AttemptFailure {
            provenance,
            message,
        })
}

fn attempt_failure(
    engine: &EngineInfo,
    ordinal: u32,
    kind: AttemptKindV2,
    message: String,
) -> AttemptFailure {
    let now = Utc::now();
    AttemptFailure {
        provenance: AttemptProvenance {
            ordinal,
            kind,
            started_at: now,
            finished_at: now,
            engine_kind: engine.kind.binary().into(),
            engine_version: engine.version.clone(),
        },
        message,
    }
}

fn build_exact_replay_manifest_v2(
    context: &ReplayContextV2,
    scenario: &Scenario,
    environment: &EnvironmentSpec,
    commands: &[CommandSpec],
    engine: &EngineInfo,
    created_at: DateTime<Utc>,
) -> Result<ExactReplayManifestV2> {
    // External host mounts do not have source snapshot identities in v2. Do
    // not publish an "exact" manifest that could silently bind different host
    // content during replay.
    if !environment.mounts.is_empty() {
        return Err(RunnerError::Msg(
            "BLOCKED: exact replay cannot bind external host mounts without source identities"
                .into(),
        ));
    }
    let image_digest = environment.image_digest.clone().ok_or_else(|| {
        RunnerError::Msg("BLOCKED: exact replay manifest requires an image digest".into())
    })?;
    digest_qualified_image_ref(&environment.image_ref, Some(&image_digest))
        .map_err(RunnerError::Msg)?;

    let cpu_value = environment.cpus * 1000.0;
    if !cpu_value.is_finite()
        || cpu_value <= 0.0
        || cpu_value > u32::MAX as f64
        || (cpu_value - cpu_value.round()).abs() > f64::EPSILON
    {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: CPU limit cannot be represented exactly in replay manifest: {}",
            environment.cpus
        )));
    }

    let replay_commands = commands
        .iter()
        .map(|command| ReplayCommandV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            phase: command.phase,
            program: command.program.clone(),
            args: command.args.clone(),
            workdir: command.workdir.clone(),
            network_required: command.network_required,
            env: command
                .env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
        })
        .collect::<Vec<_>>();
    let exact_environment = ExactEnvironmentV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        workdir: environment.workdir.clone(),
        user: environment.user.clone(),
        env: environment
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
        // The implicit primary workspace mount is carried by the sandbox
        // options, not EnvironmentSpec.mounts. Only explicit mounts belong in
        // this exact field (and are rejected above until source-bound).
        mounts: vec![],
        network_mode: environment.network_mode,
        read_only_root: environment.read_only_root,
        memory_mb: environment.memory_mb,
        cpu_millis: cpu_value.round() as u32,
        pids_limit: environment.pids_limit,
        timeout_seconds: environment.timeout_seconds,
    };
    Ok(ExactReplayManifestV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        run_id: context.run_id.clone(),
        scenario_id: scenario.id.clone(),
        scenario_kind: scenario.kind,
        source_manifest_sha256: context.source_manifest_sha256.clone(),
        config_sha256: context.config_sha256.clone(),
        scenario_sha256: canonical_sha256(scenario).map_err(|e| RunnerError::Msg(e.to_string()))?,
        image_ref: environment.image_ref.clone(),
        image_digest,
        commands: replay_commands,
        environment: exact_environment,
        engine: engine_identity_v2(engine),
        created_at,
    })
}

fn engine_identity_v2(engine: &EngineInfo) -> EngineIdentityV2 {
    EngineIdentityV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        name: engine.kind.binary().into(),
        client_version: engine.version.clone(),
        server_version: Some(engine.version.clone()),
        api_version: None,
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
    }
}

fn attempt_evidence_v2(
    context: &ReplayContextV2,
    scenario: &Scenario,
    manifest: &ExactReplayManifestV2,
    attempt: &ExecutedAttempt,
) -> Result<AttemptEvidenceV2> {
    let stdout = cap_attempt_log(&redact_secrets(&attempt.completed.raw.stdout));
    let stderr = cap_attempt_log(&redact_secrets(&attempt.completed.raw.stderr));
    let outcome_class = if attempt.completed.raw.error.is_some() {
        AttemptOutcomeClassV2::Blocked
    } else if attempt.completed.passed {
        AttemptOutcomeClassV2::Passed
    } else {
        AttemptOutcomeClassV2::Failed
    };
    let failure_signature = attempt
        .completed
        .signature
        .as_ref()
        .map(normalized_failure_signature_v2);
    let replay_manifest_sha256 =
        canonical_sha256(manifest).map_err(|e| RunnerError::Msg(e.to_string()))?;
    Ok(AttemptEvidenceV2 {
        attempt: ExecutionAttemptV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            attempt_id: RunId::new().0,
            run_id: context.run_id.clone(),
            scenario_id: scenario.id.clone(),
            scenario_kind: scenario.kind,
            source_manifest_sha256: context.source_manifest_sha256.clone(),
            config_sha256: context.config_sha256.clone(),
            replay_manifest_sha256,
            image_ref: manifest.image_ref.clone(),
            image_digest: manifest.image_digest.clone(),
            commands: manifest.commands.clone(),
            environment: manifest.environment.clone(),
            engine: manifest.engine.clone(),
            ordinal: attempt.provenance.ordinal,
            kind: attempt.provenance.kind,
            started_at: attempt.provenance.started_at,
            finished_at: attempt.provenance.finished_at,
            result: ExecutionAttemptResultV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                outcome_class,
                exit_code: attempt.completed.raw.exit_code,
                signal: attempt.completed.raw.signal,
                timed_out: attempt.completed.raw.timed_out,
                blocked_reason: attempt.completed.raw.error.as_deref().map(redact_secrets),
                network_used: attempt.completed.raw.network_used,
                duration_ms: attempt.completed.raw.duration_ms,
                stdout_sha256: Some(prefixed_sha256(stdout.as_bytes())),
                stderr_sha256: Some(prefixed_sha256(stderr.as_bytes())),
            },
            failure_signature,
        },
        stdout,
        stderr,
    })
}

fn attempt_failure_evidence_v2(
    context: &ReplayContextV2,
    scenario: &Scenario,
    manifest: &ExactReplayManifestV2,
    failure: &AttemptFailure,
) -> Result<AttemptEvidenceV2> {
    let stdout = String::new();
    let stderr = cap_attempt_log(&redact_secrets(&failure.message));
    let duration_ms = failure
        .provenance
        .finished_at
        .signed_duration_since(failure.provenance.started_at)
        .num_milliseconds()
        .max(0) as u64;
    Ok(AttemptEvidenceV2 {
        attempt: ExecutionAttemptV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            attempt_id: RunId::new().0,
            run_id: context.run_id.clone(),
            scenario_id: scenario.id.clone(),
            scenario_kind: scenario.kind,
            source_manifest_sha256: context.source_manifest_sha256.clone(),
            config_sha256: context.config_sha256.clone(),
            replay_manifest_sha256: canonical_sha256(manifest)
                .map_err(|e| RunnerError::Msg(e.to_string()))?,
            image_ref: manifest.image_ref.clone(),
            image_digest: manifest.image_digest.clone(),
            commands: manifest.commands.clone(),
            environment: manifest.environment.clone(),
            engine: manifest.engine.clone(),
            ordinal: failure.provenance.ordinal,
            kind: failure.provenance.kind,
            started_at: failure.provenance.started_at,
            finished_at: failure.provenance.finished_at,
            result: ExecutionAttemptResultV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                outcome_class: AttemptOutcomeClassV2::Blocked,
                exit_code: None,
                signal: None,
                timed_out: false,
                blocked_reason: Some(redact_secrets(&failure.message)),
                network_used: false,
                duration_ms,
                stdout_sha256: Some(prefixed_sha256(stdout.as_bytes())),
                stderr_sha256: Some(prefixed_sha256(stderr.as_bytes())),
            },
            failure_signature: None,
        },
        stdout,
        stderr,
    })
}

fn normalized_failure_signature_v2(signature: &FailureSignature) -> NormalizedFailureSignatureV2 {
    NormalizedFailureSignatureV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        kind: signature.kind.clone(),
        summary: signature.summary.clone(),
        primary_error: signature.primary_error.clone(),
        fingerprint: signature.fingerprint.clone(),
        framework_hints: signature.framework_hints.clone(),
        evidence_grade: signature.evidence_grade,
    }
}

fn cap_attempt_log(value: &str) -> String {
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    if value.len() <= MAX_BYTES {
        return value.to_string();
    }
    let half = MAX_BYTES / 2;
    let mut head_end = half;
    while head_end > 0 && !value.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = value.len().saturating_sub(half);
    while tail_start < value.len() && !value.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!(
        "{}\n...[truncated {} bytes]...\n{}",
        &value[..head_end],
        tail_start.saturating_sub(head_end),
        &value[tail_start..]
    )
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn build_execution_result(
    scenario: &Scenario,
    ordinal: u32,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
    raw: &RawExecutionResult,
) -> ExecutionResult {
    ExecutionResult {
        scenario_id: scenario.id.clone(),
        attempt: ordinal,
        exit_code: raw.exit_code,
        signal: raw.signal,
        duration_ms: raw.duration_ms,
        timed_out: raw.timed_out,
        network_used: raw.network_used,
        stdout_path: None,
        stderr_path: None,
        stdout_preview: truncate_log(&redact_secrets(&raw.stdout), 2000),
        stderr_preview: truncate_log(&redact_secrets(&raw.stderr), 2000),
        blocked_reason: raw.error.as_deref().map(redact_secrets),
        image_ref: env.image_ref.clone(),
        image_digest: env.image_digest.clone(),
        commands: commands.to_vec(),
    }
}

fn disposable_workspace(source: &Path) -> std::result::Result<tempfile::TempDir, String> {
    let parent = source
        .parent()
        .ok_or_else(|| "BLOCKED: workspace has no trusted parent directory".to_string())?;
    let workspace = tempfile::Builder::new()
        .prefix(".tomorrowci-attempt-")
        .tempdir_in(parent)
        .map_err(|e| format!("BLOCKED: cannot create disposable workspace: {e}"))?;
    materialize_workspace(source, workspace.path())
        .map_err(|e| format!("BLOCKED: cannot materialize disposable workspace: {e}"))?;
    Ok(workspace)
}

fn environment_with_exact_image(
    env: &EnvironmentSpec,
) -> std::result::Result<EnvironmentSpec, String> {
    let mut exact = env.clone();
    exact.image_ref = digest_qualified_image_ref(&env.image_ref, env.image_digest.as_deref())?;
    Ok(exact)
}

fn digest_qualified_image_ref(
    image_ref: &str,
    image_digest: Option<&str>,
) -> std::result::Result<String, String> {
    let digest = image_digest.ok_or_else(|| {
        format!(
            "BLOCKED: immutable digest is unavailable for image {}",
            terminal_text(image_ref)
        )
    })?;
    let digest_hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        format!(
            "BLOCKED: invalid immutable image digest for {}",
            terminal_text(image_ref)
        )
    })?;
    if digest_hex.len() != 64
        || !digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "BLOCKED: invalid immutable image digest for {}",
            terminal_text(image_ref)
        ));
    }

    let repository = match image_ref.split_once('@') {
        Some((repository, embedded_digest)) => {
            if embedded_digest != digest {
                return Err(format!(
                    "BLOCKED: recorded image digest does not match image reference {}",
                    terminal_text(image_ref)
                ));
            }
            repository
        }
        None => image_ref,
    };
    if repository.is_empty() || repository.contains('@') {
        return Err(format!(
            "BLOCKED: invalid image reference {}",
            terminal_text(image_ref)
        ));
    }
    Ok(format!("{repository}@{digest}"))
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
            return Err(RunnerError::Msg(format!("git clone failed for {target}")));
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

fn git_worktree_dirty(path: &Path) -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(path)
        .output()
        .map(|output| !output.status.success() || !output.stdout.is_empty())
        // If provenance cannot be inspected, never mislabel the captured tree
        // as a clean commit. The content-addressed snapshot remains exact.
        .unwrap_or(true)
}

struct FinalizationContext<'a> {
    store: &'a EvidenceStore,
    run_id: RunId,
    repo: RepositorySnapshot,
    started: chrono::DateTime<Utc>,
    config: &'a Config,
    config_hash: String,
}

fn finalize_unsupported(
    context: FinalizationContext<'_>,
    detection: Option<ProjectDetection>,
    reason: String,
) -> Result<ScanOutcome> {
    let FinalizationContext {
        store,
        run_id,
        repo,
        started,
        config,
        config_hash,
    } = context;
    let reason = redact_secrets(&reason);
    if let Some(detection) = &detection {
        store
            .write_detection(detection)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
    } else {
        store
            .write_detection_failure(&reason)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
    }
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
    store
        .write_verdicts(std::slice::from_ref(&verdict))
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_frontier(&frontier)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
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
        status: RunStatus::Completed,
        frontier: Some(frontier.clone()),
        scenario_count: 0,
        host: HostInfo::default(),
    };
    store
        .write_run_manifest(&manifest)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    write_configured_reports(store, config)?;
    store
        .finalize_checksums()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let summary = format!(
        "TomorrowCI run {}\nUNSUPPORTED: {}\nEvidence: {}\n",
        terminal_text(&run_id.to_string()),
        terminal_text(&reason),
        terminal_text(&store.root.to_string_lossy())
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
    context: FinalizationContext<'_>,
    detection: ProjectDetection,
    reason: String,
) -> Result<ScanOutcome> {
    let FinalizationContext {
        store,
        run_id,
        repo,
        started,
        config,
        config_hash,
    } = context;
    let reason = redact_secrets(&reason);
    store
        .write_detection(&detection)
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
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
    store
        .write_verdicts(std::slice::from_ref(&verdict))
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    store
        .write_frontier(&frontier)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let manifest = RunManifest {
        run_id: run_id.clone(),
        tool_version: TOOL_VERSION.into(),
        started_at: started,
        finished_at: Some(Utc::now()),
        repository: repo,
        detection: Some(detection),
        baseline: None,
        config_hash,
        sandbox_engine: None,
        status: RunStatus::Blocked,
        frontier: Some(frontier.clone()),
        scenario_count: 0,
        host: HostInfo::default(),
    };
    store
        .write_run_manifest(&manifest)
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    write_configured_reports(store, config)?;
    store
        .finalize_checksums()
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let summary = format!(
        "TomorrowCI run {}\nBLOCKED: {}\nNo observed breakage horizon within tested candidates.\nEvidence: {}\n",
        terminal_text(&run_id.to_string()),
        terminal_text(&reason),
        terminal_text(&store.root.to_string_lossy())
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

fn write_configured_reports(store: &EvidenceStore, config: &Config) -> Result<()> {
    let report = store
        .build_report_data()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    if config.report.json {
        write_json_report(&store.root.join("report.json"), &report)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
    }
    if config.report.html {
        write_html_report(&store.root.join("report.html"), &report)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
    }
    if config.report.sarif {
        write_sarif_report(&store.root.join("report.sarif"), &report)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
    }
    Ok(())
}

pub fn format_terminal_summary(
    manifest: &RunManifest,
    verdicts: &[ScenarioVerdict],
    frontier: &BreakageFrontier,
    evidence_dir: &Path,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "TomorrowCI run {}\n",
        terminal_text(&manifest.run_id.0)
    ));
    out.push_str(&format!(
        "Repository: {} @ {}\n",
        terminal_text(&manifest.repository.source),
        terminal_text(
            manifest
                .repository
                .commit_sha
                .as_deref()
                .unwrap_or("unknown")
        )
    ));
    for v in verdicts {
        let label = terminal_text(&v.label);
        let dots = ".".repeat((60usize.saturating_sub(label.chars().count())).max(3));
        out.push_str(&format!("{} {} {}\n", label, dots, v.verdict.short_label()));
    }
    out.push('\n');
    if frontier.observed {
        out.push_str(&format!(
            "Observed breakage horizon: {}\n",
            terminal_text(frontier.horizon_label.as_deref().unwrap_or("?"))
        ));
        if let (Some(from), Some(to)) = (&frontier.from_label, &frontier.to_label) {
            let axis = frontier
                .axis
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".into());
            let axis_msg = format!("{axis}: {} -> {}", terminal_text(from), terminal_text(to));
            out.push_str(&format!("Minimal changed axis: {axis_msg}\n"));
        }
        if let Some(sig) = &frontier.failure_signature {
            out.push_str(&format!(
                "Stable failure signature: {}\n",
                terminal_text(&sig.summary)
            ));
        }
        out.push_str(&format!(
            "Suspected cause (correlation, grade {:?}): see evidence\n",
            frontier.evidence_grade
        ));
        if let Some(r) = &frontier.replay_command {
            out.push_str(&format!("Reproduce: {}\n", terminal_text(r)));
        }
    } else {
        out.push_str(&format!("{}\n", terminal_text(&frontier.explanation)));
    }
    out.push_str(&format!(
        "Evidence: {}\n",
        terminal_text(&evidence_dir.to_string_lossy())
    ));
    out
}

pub async fn replay(
    output_root: &Path,
    run_id: &str,
    scenario_id: &str,
    workspace_hint: Option<&Path>,
) -> Result<String> {
    let (_store, verified) = open_verified_store(output_root, run_id)?;
    let environment: EnvironmentSpec = verified
        .read_json(&format!("scenarios/{scenario_id}/environment.json"))
        .map_err(|e| RunnerError::Msg(terminal_text(&e.to_string())))?;
    let commands: Vec<CommandSpec> = verified
        .read_json(&format!("scenarios/{scenario_id}/commands.json"))
        .map_err(|e| RunnerError::Msg(terminal_text(&e.to_string())))?;
    let scenario: Scenario = verified
        .read_json(&format!("scenarios/{scenario_id}/scenario.json"))
        .map_err(|e| RunnerError::Msg(terminal_text(&e.to_string())))?;
    let run: RunManifest = verified
        .read_json("run.json")
        .map_err(|e| RunnerError::Msg(terminal_text(&e.to_string())))?;
    let workspace = if let Some(hint) = workspace_hint {
        hint.canonicalize().map_err(|error| {
            RunnerError::Msg(format!(
                "BLOCKED: trusted replay workspace is unavailable: {}: {error}",
                terminal_text(&hint.to_string_lossy())
            ))
        })?
    } else {
        let expected = output_root.join("work").join("workspaces").join(run_id);
        let expected = expected.canonicalize().map_err(|error| {
            RunnerError::Msg(format!(
                "BLOCKED: trusted replay workspace is unavailable: {}: {error}",
                terminal_text(&expected.to_string_lossy())
            ))
        })?;
        expected
    };
    let recorded = run
        .repository
        .workspace_copy
        .canonicalize()
        .map_err(|error| {
            RunnerError::Msg(format!(
                "BLOCKED: recorded workspace cannot be trusted: {}: {error}",
                terminal_text(&run.repository.workspace_copy.to_string_lossy())
            ))
        })?;
    if recorded != workspace {
        return Err(RunnerError::Msg(format!(
            "BLOCKED: recorded workspace is outside the trusted replay root: {}",
            terminal_text(&run.repository.workspace_copy.to_string_lossy())
        )));
    }
    if verified.contains("source-manifest.json") {
        let source: SourceSnapshotManifestV2 = verified
            .read_json("source-manifest.json")
            .map_err(|e| RunnerError::Msg(terminal_text(&e.to_string())))?;
        let actual = capture_source_snapshot_v2(
            &source.run_id,
            &workspace,
            &source.repository_source,
            source.commit_sha.clone(),
            source.identity_kind,
            source.dirty,
            source.captured_at,
        )
        .map_err(|e| RunnerError::Msg(format!("BLOCKED: source snapshot mismatch: {e}")))?;
        if actual.files != source.files || actual.tree_sha256 != source.tree_sha256 {
            return Err(RunnerError::Msg(
                "BLOCKED: source snapshot mismatch; recorded replay workspace has changed".into(),
            ));
        }
    }

    let engine = detect_engine("auto").map_err(|e| {
        RunnerError::Msg(format!(
            "BLOCKED: cannot replay — {e}. Missing: container engine."
        ))
    })?;

    let attempt = execute_recorded_attempt(
        &engine,
        &workspace,
        &scenario,
        &environment,
        &commands,
        1,
        AttemptKindV2::Replay,
    )
    .await
    .map_err(|failure| RunnerError::Msg(terminal_text(&failure.message)))?;
    log_attempt_provenance(&attempt.provenance);
    replay_summary(run_id, scenario_id, &attempt.completed.raw)
}

fn replay_summary(run_id: &str, scenario_id: &str, raw: &RawExecutionResult) -> Result<String> {
    let summary = format!(
        "Replay {} / {} → exit {:?} timed_out={} duration_ms={}\n{}",
        terminal_text(run_id),
        terminal_text(scenario_id),
        raw.exit_code,
        raw.timed_out,
        raw.duration_ms,
        truncate_log(&terminal_text(&raw.stderr), 1500)
    );
    if replay_target_succeeded(raw) {
        Ok(summary)
    } else {
        Err(RunnerError::Msg(format!("REPLAY_FAILED: {summary}")))
    }
}

fn replay_target_succeeded(raw: &RawExecutionResult) -> bool {
    raw.exit_code == Some(0) && !raw.timed_out && raw.error.is_none()
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
    let (store, verified) = open_verified_store(output_root, run_id)?;
    let manifest: RunManifest = verified
        .read_json("run.json")
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let verdicts: Vec<ScenarioVerdict> = verified
        .read_json("verdicts.json")
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let frontier: BreakageFrontier = verified
        .read_json("frontier.json")
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    Ok(format_terminal_summary(
        &manifest,
        &verdicts,
        &frontier,
        &store.root,
    ))
}

pub fn explain_run(output_root: &Path, run_id: &str) -> Result<String> {
    let (_store, verified) = open_verified_store(output_root, run_id)?;
    let frontier: BreakageFrontier = verified
        .read_json("frontier.json")
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let mut out = String::new();
    out.push_str(&terminal_text(&frontier.explanation));
    out.push('\n');
    if let Some(sig) = &frontier.failure_signature {
        out.push_str(&format!(
            "Failure signature fingerprint: {}\nSummary: {}\n",
            terminal_text(&sig.fingerprint),
            terminal_text(&sig.summary)
        ));
    }
    out.push_str(
        "Note: signatures are evidence-backed correlations, not guaranteed root-cause proofs.\n",
    );
    Ok(out)
}

/// Load verdicts for a run and evaluate policy (optional base compare).
pub fn policy_check_run(
    output_root: &Path,
    run_id: &str,
    policy: &PolicyConfig,
    base_run_id: Option<&str>,
) -> Result<PolicyReport> {
    let (_store, verified) = open_verified_store(output_root, run_id)?;
    let verdicts: Vec<ScenarioVerdict> = verified
        .read_json("verdicts.json")
        .map_err(|e| RunnerError::Msg(e.to_string()))?;
    let compare = if let Some(base) = base_run_id {
        Some(compare_runs(output_root, base, run_id)?)
    } else {
        None
    };
    Ok(evaluate_policy(policy, &verdicts, compare.as_ref()))
}

pub fn format_policy_report(report: &PolicyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("TomorrowCI policy: {:?}\n", report.decision));
    out.push_str(&format!(
        "stats: scenarios={} baseline_invalid={} future_fail={} blocked_like={} ratio={:.2} horizon_regression={}\n",
        report.stats.scenario_count,
        report.stats.baseline_invalid,
        report.stats.future_fail_count,
        report.stats.blocked_like_count,
        report.stats.blocked_ratio,
        report.stats.horizon_regression
    ));
    if report.violations.is_empty() {
        out.push_str("No policy violations.\n");
    } else {
        out.push_str("Violations:\n");
        for v in &report.violations {
            out.push_str(&format!(
                "  - {}: {}\n",
                terminal_text(&v.rule),
                terminal_text(&v.detail)
            ));
        }
    }
    out.push_str(
        "Note: BLOCKED/UNSUPPORTED/INCONCLUSIVE are never converted to PASS; high blocked ratio may FAIL if configured.\n",
    );
    out
}

/// Compare two completed runs' frontiers (base → head).
pub fn compare_runs(
    output_root: &Path,
    base_run_id: &str,
    head_run_id: &str,
) -> Result<HorizonCompare> {
    let (_base_store, base_verified) = open_verified_store(output_root, base_run_id)
        .map_err(|e| RunnerError::Msg(format!("base run: {e}")))?;
    let (_head_store, head_verified) = open_verified_store(output_root, head_run_id)
        .map_err(|e| RunnerError::Msg(format!("head run: {e}")))?;
    let base_f: BreakageFrontier = base_verified
        .read_json("frontier.json")
        .map_err(|e| RunnerError::Msg(format!("base frontier: {e}")))?;
    let head_f: BreakageFrontier = head_verified
        .read_json("frontier.json")
        .map_err(|e| RunnerError::Msg(format!("head frontier: {e}")))?;
    Ok(compare_horizons(&base_f, &head_f))
}

fn final_run_status(verdicts: &[ScenarioVerdict]) -> RunStatus {
    if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Blocked)
    {
        RunStatus::Blocked
    } else {
        RunStatus::Completed
    }
}

fn open_verified_store(
    output_root: &Path,
    run_id: &str,
) -> Result<(EvidenceStore, VerifiedBundle)> {
    let store =
        EvidenceStore::open(output_root, run_id).map_err(|e| RunnerError::Msg(e.to_string()))?;
    let verified = store.verify().map_err(|e| {
        RunnerError::Msg(format!(
            "evidence verification failed for run {run_id}: {e}"
        ))
    })?;
    Ok((store, verified))
}

pub fn format_compare(cmp: &HorizonCompare, base_id: &str, head_id: &str) -> String {
    let mut out = String::new();
    let base_label = if cmp.base_observed {
        terminal_text(cmp.base_label.as_deref().unwrap_or("?"))
    } else {
        "(none)".into()
    };
    let head_label = if cmp.head_observed {
        terminal_text(cmp.head_label.as_deref().unwrap_or("?"))
    } else {
        "(none)".into()
    };
    out.push_str(&format!(
        "TomorrowCI compare  base={}  head={}\n",
        terminal_text(base_id),
        terminal_text(head_id)
    ));
    out.push_str(&format!("Movement: {:?}\n", cmp.movement));
    out.push_str(&format!("Base horizon: {base_label}\n"));
    out.push_str(&format!("Head horizon: {head_label}\n"));
    out.push_str(&format!("{}\n", terminal_text(&cmp.explanation)));
    if cmp.is_regression {
        out.push_str("Policy signal: HORIZON_REGRESSION\n");
    }
    out
}

/// Sample commits in [at, until] and scan each (honest M2 skeleton).
pub async fn backtest_repo(
    req: BacktestRequest,
    evidence_root: PathBuf,
    work_root: PathBuf,
) -> Result<BacktestReport> {
    let mut points = Vec::new();
    let target_path = PathBuf::from(&req.target);
    if !target_path.exists() {
        return Err(RunnerError::Msg(format!(
            "backtest target missing: {}",
            target_path.display()
        )));
    }

    let commits = list_commits_in_range(&target_path, req.at, req.until, req.max_commits)?;
    if commits.is_empty() {
        points.push(BacktestPoint {
            commit_sha: String::new(),
            committed_at: None,
            run_id: None,
            frontier_observed: false,
            horizon_label: None,
            status: BacktestPointStatus::Skipped,
            detail: format!("no commits found in {}..{} (git log)", req.at, req.until),
        });
        return Ok(BacktestReport {
            request: req,
            points,
            note: BacktestReport::skeleton_note().into(),
        });
    }

    for (sha, committed_at) in commits {
        let worktree = work_root.join("backtest").join(&sha[..12.min(sha.len())]);
        if let Err(e) = materialize_commit_worktree(&target_path, &sha, &worktree) {
            points.push(BacktestPoint {
                commit_sha: sha,
                committed_at,
                run_id: None,
                frontier_observed: false,
                horizon_label: None,
                status: BacktestPointStatus::Blocked,
                detail: e,
            });
            continue;
        }

        let mut cfg = Config::default();
        cfg.execution.max_scenarios = req.max_scenarios_per_point.max(1);
        cfg.execution.reruns_on_failure = 1;
        cfg.candidates.runtime.max_versions = 3;

        match scan(ScanRequest {
            target: worktree.display().to_string(),
            config: cfg,
            config_path: None,
            output_root: evidence_root.clone(),
            work_root: work_root.join("backtest-workspaces"),
        })
        .await
        {
            Ok(out) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at,
                    run_id: Some(out.run_id.0.clone()),
                    frontier_observed: out.frontier.observed,
                    horizon_label: out.frontier.horizon_label.clone(),
                    status: if out.manifest.status == RunStatus::Blocked {
                        BacktestPointStatus::Blocked
                    } else {
                        BacktestPointStatus::Ok
                    },
                    detail: out.frontier.explanation,
                });
            }
            Err(e) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at,
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::Failed,
                    detail: e.to_string(),
                });
            }
        }
    }

    Ok(BacktestReport {
        request: req,
        points,
        note: BacktestReport::skeleton_note().into(),
    })
}

fn list_commits_in_range(
    repo: &Path,
    at: NaiveDate,
    until: NaiveDate,
    max: usize,
) -> Result<Vec<(String, Option<chrono::DateTime<Utc>>)>> {
    let after = format!("{at} 00:00:00");
    let before = format!("{until} 23:59:59");
    let out = std::process::Command::new("git")
        .args([
            "log",
            "--format=%H %cI",
            &format!("--after={after}"),
            &format!("--before={before}"),
            "-n",
            &max.to_string(),
        ])
        .current_dir(repo)
        .output()
        .map_err(|e| RunnerError::Msg(format!("git log: {e}")))?;
    if !out.status.success() {
        return Err(RunnerError::Msg(format!(
            "git log failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut parts = line.split_whitespace();
        let Some(sha) = parts.next() else { continue };
        let ts = parts.next().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        rows.push((sha.to_string(), ts));
    }
    // Oldest first for timeline readability
    rows.reverse();
    Ok(rows)
}

fn materialize_commit_worktree(
    repo: &Path,
    sha: &str,
    dest: &Path,
) -> std::result::Result<(), String> {
    if dest.exists() {
        let _ = std::fs::remove_dir_all(dest);
    }
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    // Export tree without .git via archive
    let archive = std::process::Command::new("git")
        .args(["archive", sha])
        .current_dir(repo)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("git archive spawn: {e}"))?;
    // Prefer tar extraction via git archive | tar -x
    let tar = std::process::Command::new("tar")
        .args(["-x", "-C"])
        .arg(dest)
        .stdin(
            archive
                .stdout
                .ok_or_else(|| "git archive stdout".to_string())?,
        )
        .output();
    match tar {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            // Windows fallback: git checkout-index via worktree
            let _ = o;
            let wt = std::process::Command::new("git")
                .args(["worktree", "add", "--detach"])
                .arg(dest)
                .arg(sha)
                .current_dir(repo)
                .output()
                .map_err(|e| e.to_string())?;
            if wt.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "git worktree add failed: {}",
                    String::from_utf8_lossy(&wt.stderr)
                ))
            }
        }
        Err(_) => {
            let wt = std::process::Command::new("git")
                .args(["worktree", "add", "--detach"])
                .arg(dest)
                .arg(sha)
                .current_dir(repo)
                .output()
                .map_err(|e| e.to_string())?;
            if wt.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "git worktree add failed: {}",
                    String::from_utf8_lossy(&wt.stderr)
                ))
            }
        }
    }
}

fn redact_failure_signature(signature: &FailureSignature) -> FailureSignature {
    let mut redacted = signature.clone();
    redacted.kind = redact_secrets(&redacted.kind);
    redacted.summary = redact_secrets(&redacted.summary);
    redacted.primary_error = redacted.primary_error.map(|value| redact_secrets(&value));
    redacted.framework_hints = redacted
        .framework_hints
        .into_iter()
        .map(|value| redact_secrets(&value))
        .collect();
    redacted.fingerprint = FailureSignature::compute_fingerprint(
        &redacted.kind,
        redacted.primary_error.as_deref().unwrap_or_default(),
        &redacted.summary,
    );
    redacted
}

fn terminal_text(value: &str) -> String {
    sanitize_terminal(&redact_secrets(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn stub_store(root: &Path, run_id: &str) -> EvidenceStore {
        let store = EvidenceStore::create(root, run_id).unwrap();
        let mut config = Config::default();
        config.report.html = false;
        config.report.json = false;
        config.execution.max_scenarios = 1;
        config.execution.max_parallel = 1;
        let repository = repository_snapshot(root);
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
        let started = Utc::now();
        let run = RunManifest {
            run_id: RunId(run_id.into()),
            tool_version: TOOL_VERSION.into(),
            started_at: started,
            finished_at: Some(started),
            repository: repository.clone(),
            detection: None,
            baseline: None,
            config_hash: config.config_hash().unwrap(),
            sandbox_engine: None,
            status: RunStatus::Completed,
            frontier: Some(frontier.clone()),
            scenario_count: 0,
            host: HostInfo::default(),
        };
        let verdict = ScenarioVerdict {
            scenario_id: ScenarioId::new("detect"),
            label: "detection".into(),
            verdict: Verdict::Unsupported,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: 0,
            failure_signature: None,
            evidence: None,
            notes: vec!["unsupported fixture".into()],
        };
        store.write_config(&config).unwrap();
        store.write_repository(&repository).unwrap();
        store
            .write_detection_failure("unsupported fixture")
            .unwrap();
        store.write_frontier(&frontier).unwrap();
        store.write_verdicts(&[verdict]).unwrap();
        store.write_run_manifest(&run).unwrap();
        store
    }

    fn assert_verification_failed<T>(result: Result<T>) {
        let error = match result {
            Ok(_) => panic!("tampered evidence was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("evidence verification failed"),
            "unexpected error: {error}"
        );
    }

    fn repository_snapshot(root: &Path) -> RepositorySnapshot {
        RepositorySnapshot {
            source: "fixture".into(),
            path: root.to_path_buf(),
            commit_sha: Some("0123456789abcdef".into()),
            branch: None,
            is_remote: false,
            workspace_copy: root.join("workspace"),
            captured_at: Utc::now(),
        }
    }

    fn replay_store(root: &Path, run_id: &str) -> EvidenceStore {
        let store = stub_store(root, run_id);
        std::fs::remove_file(store.root.join("detection-error.json")).unwrap();
        let trusted_workspace = root.join("work/workspaces").join(run_id);
        std::fs::create_dir_all(&trusted_workspace).unwrap();
        let mut run: RunManifest =
            serde_json::from_slice(&std::fs::read(store.root.join("run.json")).unwrap()).unwrap();
        run.repository.workspace_copy = trusted_workspace;
        let scenario = Scenario {
            id: ScenarioId::new("scenario-1"),
            kind: tomorrowci_core::ScenarioKind::Baseline,
            ecosystem: Ecosystem::Python,
            label: "baseline".into(),
            runtime_version: "3.12".into(),
            dependency_mode: tomorrowci_core::DependencyMode::Locked,
            image_ref: "python:3.12-bookworm".into(),
            axes_changed: vec![],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: true,
            selection_reason: "fixture".into(),
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
        let baseline = tomorrowci_core::Baseline {
            ecosystem: Ecosystem::Python,
            runtime_label: "Python 3.12".into(),
            runtime_version: scenario.runtime_version.clone(),
            dependency_mode: scenario.dependency_mode.clone(),
            image_ref: scenario.image_ref.clone(),
            notes: vec![],
        };
        let command = tomorrowci_core::CommandSpec {
            phase: tomorrowci_core::CommandPhase::Test,
            program: "python".into(),
            args: vec!["-m".into(), "pytest".into()],
            workdir: "/workspace".into(),
            network_required: false,
            env: Default::default(),
        };
        let environment = tomorrowci_core::EnvironmentSpec {
            image_ref: scenario.image_ref.clone(),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            workdir: "/workspace".into(),
            user: None,
            env: Default::default(),
            mounts: vec![],
            network_mode: tomorrowci_core::NetworkMode::None,
            read_only_root: false,
            memory_mb: 1024,
            cpus: 1.0,
            pids_limit: 128,
            timeout_seconds: 60,
        };
        let raw = tomorrowci_core::RawExecutionResult {
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
            .write_scenario_bundle(&scenario, &environment, &[command], &raw, &result, None)
            .unwrap();
        let verdict = ScenarioVerdict {
            scenario_id: scenario.id.clone(),
            label: scenario.label.clone(),
            verdict: Verdict::BaselinePass,
            evidence_grade: EvidenceGrade::Observed,
            attempts: 1,
            failure_signature: None,
            evidence: Some(EvidenceReference {
                run_id: run.run_id.clone(),
                scenario_id: scenario.id.clone(),
                directory: store.scenario_dir(&scenario.id.0),
                replay_command: format!("tomorrowci replay {run_id} --scenario {}", scenario.id),
            }),
            notes: vec![],
        };
        let plan = tomorrowci_core::ExecutionPlan {
            run_id: run.run_id.clone(),
            scenarios: vec![scenario],
            max_scenarios: 1,
            max_parallel: 1,
            decisions: vec![],
            untested: vec![],
        };
        run.scenario_count = 1;
        run.detection = Some(detection.clone());
        run.baseline = Some(baseline);
        run.sandbox_engine = Some("docker".into());
        store.write_repository(&run.repository).unwrap();
        store.write_detection(&detection).unwrap();
        store.write_candidates(&serde_json::json!([])).unwrap();
        store.write_plan(&plan).unwrap();
        store.write_verdicts(&[verdict]).unwrap();
        store.write_run_manifest(&run).unwrap();
        store.finalize_checksums().unwrap();
        store
    }

    #[test]
    fn bundle_consumers_reject_tampered_evidence_before_loading_it() {
        let root = tempdir().unwrap();

        let show = stub_store(root.path(), "show");
        show.finalize_checksums().unwrap();
        std::fs::write(show.root.join("run.json"), b"tampered").unwrap();
        assert_verification_failed(show_run(root.path(), "show"));

        let explain = stub_store(root.path(), "explain");
        explain.finalize_checksums().unwrap();
        std::fs::write(explain.root.join("frontier.json"), b"tampered").unwrap();
        assert_verification_failed(explain_run(root.path(), "explain"));

        let policy = stub_store(root.path(), "policy");
        policy.finalize_checksums().unwrap();
        std::fs::write(policy.root.join("verdicts.json"), b"tampered").unwrap();
        assert_verification_failed(policy_check_run(
            root.path(),
            "policy",
            &PolicyConfig::default(),
            None,
        ));

        let base = stub_store(root.path(), "base");
        base.finalize_checksums().unwrap();
        let head = stub_store(root.path(), "head");
        head.finalize_checksums().unwrap();
        std::fs::write(base.root.join("frontier.json"), b"tampered").unwrap();
        assert_verification_failed(compare_runs(root.path(), "base", "head"));
    }

    #[tokio::test]
    async fn replay_rejects_tampering_before_engine_or_workspace_lookup() {
        let root = tempdir().unwrap();
        let store = replay_store(root.path(), "replay");
        let scenario = store.scenario_dir("scenario-1");
        std::fs::write(
            scenario.join("replay-manifest.json"),
            br#"{"image_ref":"attacker-controlled"}"#,
        )
        .unwrap();

        assert_verification_failed(replay(root.path(), "replay", "scenario-1", None).await);
    }

    #[tokio::test]
    async fn replay_rejects_self_resealed_bundle_workspace_before_engine_lookup() {
        let root = tempdir().unwrap();
        let store = replay_store(root.path(), "host-path");
        let untrusted = root.path().join("attacker-selected-host-directory");
        std::fs::create_dir_all(&untrusted).unwrap();

        let repository_path = store.root.join("repository.json");
        let mut repository: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&repository_path).unwrap()).unwrap();
        repository["workspace_copy"] = serde_json::json!(untrusted);
        std::fs::write(
            &repository_path,
            serde_json::to_vec_pretty(&repository).unwrap(),
        )
        .unwrap();
        let run_path = store.root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&run_path).unwrap()).unwrap();
        run["repository"] = repository;
        std::fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        tomorrowci_evidence::seal_bundle(&store.root, tomorrowci_evidence::BundleKind::Run)
            .unwrap();

        let error = replay(root.path(), "host-path", "scenario-1", None)
            .await
            .expect_err("untrusted host workspace was accepted")
            .to_string();
        assert!(
            error.contains("outside the trusted replay root"),
            "unexpected error: {error}"
        );
    }

    fn exact_test_scenario() -> Scenario {
        Scenario {
            id: ScenarioId::new("exact-attempt"),
            kind: tomorrowci_core::ScenarioKind::Replay,
            ecosystem: Ecosystem::Python,
            label: "exact attempt".into(),
            runtime_version: "3.12".into(),
            dependency_mode: tomorrowci_core::DependencyMode::Locked,
            image_ref: "python:3.12-bookworm".into(),
            axes_changed: vec![],
            evidence_grade: EvidenceGrade::Observed,
            is_baseline: false,
            selection_reason: "test".into(),
        }
    }

    fn exact_test_environment() -> EnvironmentSpec {
        let mut env = EnvironmentSpec {
            image_ref: "python:3.12-bookworm".into(),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            workdir: "/workspace/project".into(),
            user: Some("1000:1000".into()),
            env: Default::default(),
            mounts: vec![tomorrowci_core::MountSpec {
                host_path: PathBuf::from("fixture-cache"),
                container_path: "/cache".into(),
                read_only: true,
            }],
            network_mode: tomorrowci_core::NetworkMode::None,
            read_only_root: true,
            memory_mb: 768,
            cpus: 1.5,
            pids_limit: 64,
            timeout_seconds: 45,
        };
        env.env.insert("LANG".into(), "C.UTF-8".into());
        env
    }

    #[test]
    fn exact_image_binding_requires_one_matching_lowercase_sha256_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            digest_qualified_image_ref("python:3.12-bookworm", Some(&digest)).unwrap(),
            format!("python:3.12-bookworm@{digest}")
        );
        assert_eq!(
            digest_qualified_image_ref(
                &format!("registry.example/python:3.12@{digest}"),
                Some(&digest)
            )
            .unwrap(),
            format!("registry.example/python:3.12@{digest}")
        );

        for error in [
            digest_qualified_image_ref("python:3.12", None).unwrap_err(),
            digest_qualified_image_ref("python:3.12", Some("sha256:ABC")).unwrap_err(),
            digest_qualified_image_ref(
                &format!("python:3.12@sha256:{}", "b".repeat(64)),
                Some(&digest),
            )
            .unwrap_err(),
        ] {
            assert!(error.starts_with("BLOCKED:"), "unexpected error: {error}");
        }
    }

    #[test]
    fn exact_image_environment_preserves_every_recorded_execution_field() {
        let recorded = exact_test_environment();
        let exact = environment_with_exact_image(&recorded).unwrap();
        assert_eq!(
            exact.image_ref,
            format!("python:3.12-bookworm@sha256:{}", "a".repeat(64))
        );
        assert_eq!(exact.image_digest, recorded.image_digest);
        assert_eq!(exact.workdir, recorded.workdir);
        assert_eq!(exact.user, recorded.user);
        assert_eq!(exact.env, recorded.env);
        assert_eq!(
            serde_json::to_value(&exact.mounts).unwrap(),
            serde_json::to_value(&recorded.mounts).unwrap()
        );
        assert_eq!(exact.network_mode, recorded.network_mode);
        assert_eq!(exact.read_only_root, recorded.read_only_root);
        assert_eq!(exact.memory_mb, recorded.memory_mb);
        assert_eq!(exact.cpus.to_bits(), recorded.cpus.to_bits());
        assert_eq!(exact.pids_limit, recorded.pids_limit);
        assert_eq!(exact.timeout_seconds, recorded.timeout_seconds);
    }

    #[test]
    fn normalized_execution_result_keeps_the_real_attempt_ordinal() {
        let scenario = exact_test_scenario();
        let environment = exact_test_environment();
        let commands = vec![tomorrowci_core::CommandSpec {
            phase: tomorrowci_core::CommandPhase::Test,
            program: "python".into(),
            args: vec!["-m".into(), "pytest".into()],
            workdir: "/workspace/project".into(),
            network_required: false,
            env: Default::default(),
        }];
        let raw = RawExecutionResult {
            exit_code: Some(0),
            signal: None,
            stdout: "ok".into(),
            stderr: String::new(),
            duration_ms: 42,
            timed_out: false,
            network_used: false,
            error: None,
        };
        let result = build_execution_result(&scenario, 3, &environment, &commands, &raw);
        assert_eq!(result.attempt, 3);
        assert_eq!(result.image_ref, environment.image_ref);
        assert_eq!(result.image_digest, environment.image_digest);
        assert_eq!(result.commands.len(), 1);
    }

    #[test]
    fn every_disposable_attempt_starts_clean_and_is_removed_after_use() {
        let root = tempdir().unwrap();
        let source = root.path().join("recorded-workspace");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("state.txt"), "recorded").unwrap();

        let first_path;
        {
            let first = disposable_workspace(&source).unwrap();
            first_path = first.path().to_path_buf();
            assert_eq!(
                std::fs::read_to_string(first.path().join("state.txt")).unwrap(),
                "recorded"
            );
            std::fs::write(first.path().join("state.txt"), "mutated").unwrap();
        }
        assert!(!first_path.exists());
        assert_eq!(
            std::fs::read_to_string(source.join("state.txt")).unwrap(),
            "recorded"
        );

        let second = disposable_workspace(&source).unwrap();
        assert_eq!(
            std::fs::read_to_string(second.path().join("state.txt")).unwrap(),
            "recorded"
        );
    }

    #[test]
    fn replay_target_failure_is_never_a_successful_runner_result() {
        let mut raw = RawExecutionResult {
            exit_code: Some(0),
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            error: None,
        };
        assert!(replay_summary("run", "scenario", &raw).is_ok());

        raw.exit_code = Some(7);
        assert!(replay_summary("run", "scenario", &raw)
            .unwrap_err()
            .to_string()
            .starts_with("REPLAY_FAILED:"));
        raw.exit_code = Some(0);
        raw.timed_out = true;
        assert!(replay_summary("run", "scenario", &raw).is_err());
        raw.timed_out = false;
        raw.error = Some("engine lost target process".into());
        assert!(replay_summary("run", "scenario", &raw).is_err());
    }

    #[test]
    fn attempt_failures_retain_ordinal_kind_and_engine_identity() {
        let engine = EngineInfo {
            kind: tomorrowci_sandbox::EngineKind::Docker,
            path: PathBuf::from("docker"),
            version: "29.0.0".into(),
        };
        let failure = attempt_failure(&engine, 4, AttemptKindV2::Replay, "BLOCKED: fixture".into());
        assert_eq!(failure.provenance.ordinal, 4);
        assert_eq!(failure.provenance.kind, AttemptKindV2::Replay);
        assert_eq!(failure.provenance.engine_kind, "docker");
        assert_eq!(failure.provenance.engine_version, "29.0.0");
        assert!(failure.provenance.finished_at >= failure.provenance.started_at);
    }

    #[test]
    fn blocked_verdict_makes_the_run_status_blocked() {
        let blocked = ScenarioVerdict {
            scenario_id: ScenarioId::new("scenario"),
            label: "scenario".into(),
            verdict: Verdict::Blocked,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: 0,
            failure_signature: None,
            evidence: None,
            notes: vec![],
        };
        assert_eq!(final_run_status(&[blocked]), RunStatus::Blocked);
        assert_eq!(final_run_status(&[]), RunStatus::Completed);
    }

    #[test]
    fn failure_then_rerun_block_does_not_publish_the_prior_attempt() {
        assert!(may_publish_final_attempt(None));
        assert!(!may_publish_final_attempt(Some(
            "rerun could not start after a recorded failure"
        )));
    }

    #[test]
    fn derived_failure_signatures_are_redacted_before_verdicts_and_reports() {
        let secret = "api_key=super-secret-value";
        let signature = FailureSignature {
            kind: "blocked".into(),
            summary: secret.into(),
            primary_error: Some(secret.into()),
            fingerprint: "fingerprint".into(),
            framework_hints: vec![secret.into()],
            evidence_grade: EvidenceGrade::Inconclusive,
        };
        let redacted = redact_failure_signature(&signature);
        let encoded = serde_json::to_string(&redacted).unwrap();
        assert!(!encoded.contains("super-secret-value"));
        assert!(encoded.contains("REDACTED"));
        assert_ne!(redacted.fingerprint, "fingerprint");
        assert_eq!(
            redacted.fingerprint,
            FailureSignature::compute_fingerprint(
                &redacted.kind,
                redacted.primary_error.as_deref().unwrap_or_default(),
                &redacted.summary,
            )
        );
    }

    #[test]
    fn terminal_renderers_never_emit_secrets_or_control_sequences() {
        let hostile = "\u{1b}[2J\rapi_key=super-secret-value";
        let root = tempdir().unwrap();
        let store = stub_store(root.path(), "terminal-safe");
        let mut manifest: RunManifest =
            serde_json::from_slice(&std::fs::read(store.root.join("run.json")).unwrap()).unwrap();
        let mut verdicts: Vec<ScenarioVerdict> =
            serde_json::from_slice(&std::fs::read(store.root.join("verdicts.json")).unwrap())
                .unwrap();
        let mut frontier: BreakageFrontier =
            serde_json::from_slice(&std::fs::read(store.root.join("frontier.json")).unwrap())
                .unwrap();
        manifest.repository.source = hostile.into();
        verdicts[0].label = hostile.into();
        frontier.explanation = hostile.into();

        let summary = format_terminal_summary(&manifest, &verdicts, &frontier, &store.root);
        assert!(!summary.contains('\u{1b}'));
        assert!(!summary.contains('\r'));
        assert!(!summary.contains("super-secret-value"));

        let compare = HorizonCompare {
            movement: tomorrowci_core::HorizonMovement::Unchanged,
            base_observed: true,
            head_observed: true,
            base_label: Some(hostile.into()),
            head_label: Some(hostile.into()),
            base_order_key: None,
            head_order_key: None,
            explanation: hostile.into(),
            is_regression: false,
        };
        let compare_output = format_compare(&compare, hostile, hostile);
        assert!(!compare_output.contains('\u{1b}'));
        assert!(!compare_output.contains('\r'));
        assert!(!compare_output.contains("super-secret-value"));

        let policy = tomorrowci_core::PolicyReport {
            decision: tomorrowci_core::PolicyDecision::Fail,
            violations: vec![tomorrowci_core::policy::PolicyViolation {
                rule: hostile.into(),
                detail: hostile.into(),
            }],
            stats: tomorrowci_core::policy::PolicyStats {
                scenario_count: 1,
                baseline_invalid: false,
                future_fail_count: 0,
                blocked_like_count: 1,
                blocked_ratio: 1.0,
                horizon_regression: false,
            },
            policy: PolicyConfig::default(),
        };
        let policy_output = format_policy_report(&policy);
        assert!(!policy_output.contains('\u{1b}'));
        assert!(!policy_output.contains('\r'));
        assert!(!policy_output.contains("super-secret-value"));
    }

    #[test]
    fn early_finalizers_seal_complete_bundles_and_keep_honest_statuses() {
        let root = tempdir().unwrap();
        let config = Config::default();
        let config_hash = config.config_hash().unwrap();
        let hostile_reason = "\u{1b}[2J\rapi_key=super-secret-value";

        let unsupported_store =
            EvidenceStore::create(root.path(), "unsupported-finalizer").unwrap();
        let unsupported_repo = repository_snapshot(root.path());
        unsupported_store
            .write_repository(&unsupported_repo)
            .unwrap();
        unsupported_store.write_config(&config).unwrap();
        let unsupported_detection = ProjectDetection {
            ecosystem: Ecosystem::Python,
            package_manager: "pip".into(),
            manifests: vec![],
            confidence: 1.0,
            notes: vec![],
            supported: false,
            unsupported_reason: Some("unsupported fixture".into()),
        };
        let unsupported = finalize_unsupported(
            FinalizationContext {
                store: &unsupported_store,
                run_id: RunId("unsupported-finalizer".into()),
                repo: unsupported_repo,
                started: Utc::now(),
                config: &config,
                config_hash: config_hash.clone(),
            },
            Some(unsupported_detection),
            hostile_reason.into(),
        )
        .unwrap();
        unsupported_store.verify().unwrap();
        assert_eq!(unsupported.manifest.status, RunStatus::Completed);
        assert_eq!(unsupported.verdicts[0].verdict, Verdict::Unsupported);
        assert!(!unsupported.terminal_summary.contains('\u{1b}'));
        assert!(!unsupported.terminal_summary.contains('\r'));
        assert!(!unsupported.terminal_summary.contains("super-secret-value"));

        std::fs::remove_file(unsupported_store.root.join("detection.json")).unwrap();
        let run_path = unsupported_store.root.join("run.json");
        let mut run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&run_path).unwrap()).unwrap();
        run["detection"] = serde_json::Value::Null;
        std::fs::write(&run_path, serde_json::to_vec_pretty(&run).unwrap()).unwrap();
        let error = tomorrowci_evidence::seal_bundle(
            &unsupported_store.root,
            tomorrowci_evidence::BundleKind::Run,
        )
        .expect_err("deleted unsupported detection was accepted")
        .to_string();
        assert!(
            error.contains(
                "requires exactly one unsupported detection.json or detection-error.json"
            ),
            "unexpected error: {error}"
        );

        let detection_error_store =
            EvidenceStore::create(root.path(), "detection-error-finalizer").unwrap();
        let detection_error_repo = repository_snapshot(root.path());
        detection_error_store
            .write_repository(&detection_error_repo)
            .unwrap();
        detection_error_store.write_config(&config).unwrap();
        finalize_unsupported(
            FinalizationContext {
                store: &detection_error_store,
                run_id: RunId("detection-error-finalizer".into()),
                repo: detection_error_repo,
                started: Utc::now(),
                config: &config,
                config_hash: config_hash.clone(),
            },
            None,
            "adapter detection failed".into(),
        )
        .unwrap();
        detection_error_store.verify().unwrap();
        assert!(detection_error_store
            .root
            .join("detection-error.json")
            .is_file());

        let blocked_store = EvidenceStore::create(root.path(), "blocked-finalizer").unwrap();
        let blocked_repo = repository_snapshot(root.path());
        blocked_store.write_repository(&blocked_repo).unwrap();
        blocked_store.write_config(&config).unwrap();
        let supported_detection = ProjectDetection {
            ecosystem: Ecosystem::Python,
            package_manager: "pip".into(),
            manifests: vec!["pyproject.toml".into()],
            confidence: 1.0,
            notes: vec![],
            supported: true,
            unsupported_reason: None,
        };
        let blocked = finalize_blocked(
            FinalizationContext {
                store: &blocked_store,
                run_id: RunId("blocked-finalizer".into()),
                repo: blocked_repo,
                started: Utc::now(),
                config: &config,
                config_hash,
            },
            supported_detection,
            hostile_reason.into(),
        )
        .unwrap();
        blocked_store.verify().unwrap();
        assert_eq!(blocked.manifest.status, RunStatus::Blocked);
        assert_eq!(blocked.verdicts[0].verdict, Verdict::Blocked);
        assert!(!blocked.terminal_summary.contains('\u{1b}'));
        assert!(!blocked.terminal_summary.contains('\r'));
        assert!(!blocked.terminal_summary.contains("super-secret-value"));
    }
}
