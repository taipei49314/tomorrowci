//! Orchestrates detection → planning → sandboxed execution → evidence → reports.

mod patch;
mod remote;

pub use patch::{patch_lab, PatchLabOutcome, PatchLabRequest};

use chrono::{DateTime, NaiveDate, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
use tomorrowci_adapter_node::{baseline_scenario as node_baseline_scenario, NodeAdapter};
use tomorrowci_adapter_python::{baseline_scenario as py_baseline_scenario, PythonAdapter};
use tomorrowci_adapter_rust::{baseline_scenario as rust_baseline_scenario, RustAdapter};
use tomorrowci_adapters::{
    detect_ecosystem,
    safety::{validate_commands, validate_environment},
    EcosystemAdapter,
};
use tomorrowci_core::backtest::{
    canonical_proof_sha256, expected_snapshot_manifest, verify_registry_snapshot, BacktestPoint,
    BacktestPointStatus, BacktestProof, BacktestProofOutcome, BacktestProofReference,
    BacktestReport, BacktestRequest, BacktestRuntimeImage, SnapshotFailureDisposition,
    VerifiedRegistrySnapshot, BACKTEST_PROOF_SCHEMA_VERSION, SNAPSHOT_MANIFEST_FILE,
    SNAPSHOT_PAYLOAD_DIR, WORKSPACE_SNAPSHOT_DIR,
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
    ExecutionResult, FailureSignature, HostInfo, NetworkMode, NormalizedFailureSignatureV2,
    Planner, ProjectDetection, RawExecutionResult, ReplayCommandV2, ReplayQualificationV2,
    RepositorySnapshot, RunId, RunManifest, RunStatus, Scenario, ScenarioId, ScenarioVerdict,
    SourceIdentityKindV2, SourceSnapshotManifestV2, Verdict, REPLAY_SCHEMA_VERSION_V2,
};
use tomorrowci_evidence::{
    capture_source_snapshot_v2, load_public_replay_origin_v2, next_public_replay_ordinal_v2,
    write_public_replay_receipt_v2, AttemptEvidenceV2, EvidenceStore, PublicReplayOriginV2,
    SealedPublicReplayReceiptV2, VerifiedBundle,
};
use tomorrowci_report::{write_html_report, write_json_report, write_sarif_report};
use tomorrowci_sandbox::{
    detect_engine, doctor_sandbox, ensure_image, execute_scenario, materialize_workspace,
    resolve_image_digest, validate_network_policy, DoctorSandboxReport, EngineInfo,
    SandboxExecOptions,
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

/// Backtest-only provenance supplied after an exact commit tree has been
/// materialized and the verified registry snapshot has been staged. Normal
/// scans always derive their source identity directly from the target.
#[derive(Debug, Clone)]
struct PinnedBacktestSource {
    repository_source: String,
    commit_sha: String,
    /// Canonical identity of the complete staged tree that `scan` must copy.
    expected_tree_sha256: String,
}

#[derive(Debug, Clone)]
struct ReplayContextV2 {
    run_id: RunId,
    source_manifest_sha256: String,
    config_sha256: String,
}

pub async fn scan(req: ScanRequest) -> Result<ScanOutcome> {
    scan_with_pinned_source(req, None).await
}

async fn scan_with_pinned_source(
    req: ScanRequest,
    pinned: Option<PinnedBacktestSource>,
) -> Result<ScanOutcome> {
    let run_id = RunId::new();
    let started = Utc::now();

    // Resolve source repository (local path or github URL)
    let (source_path, resolved_source_label, is_remote, resolved_commit_sha, resolved_source_dirty) =
        resolve_target(
            &req.target,
            &req.work_root.join("clones").join(run_id.0.as_str()),
        )?;

    let (source_label, commit_sha, source_dirty, source_identity) = match pinned.as_ref() {
        Some(binding) => {
            if is_remote
                || !is_lower_hex(&binding.commit_sha, 40) && !is_lower_hex(&binding.commit_sha, 64)
                || !is_sha256_identity(&binding.expected_tree_sha256)
            {
                return Err(RunnerError::Msg(
                    "invalid pinned historical source binding".into(),
                ));
            }
            (
                binding.repository_source.clone(),
                Some(binding.commit_sha.clone()),
                true,
                SourceIdentityKindV2::DirtyWorktree,
            )
        }
        None => {
            let dirty = resolved_commit_sha.is_some() && resolved_source_dirty;
            let identity = match (&resolved_commit_sha, dirty) {
                (Some(_), false) => SourceIdentityKindV2::GitCommit,
                (Some(_), true) => SourceIdentityKindV2::DirtyWorktree,
                (None, _) => SourceIdentityKindV2::NonGit,
            };
            (resolved_source_label, resolved_commit_sha, dirty, identity)
        }
    };

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
    if let Some(binding) = pinned.as_ref() {
        if source_manifest.tree_sha256 != binding.expected_tree_sha256
            || source_manifest.commit_sha.as_deref() != Some(binding.commit_sha.as_str())
            || source_manifest.identity_kind != SourceIdentityKindV2::DirtyWorktree
            || !source_manifest.dirty
        {
            return Err(RunnerError::Msg(
                "pinned historical source changed before scan capture".into(),
            ));
        }
    }
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
    let original_workspace = disposable_workspace(workspace);

    // First attempt
    let first = match original_workspace.as_ref() {
        Ok(original_workspace) => {
            execute_one(
                adapter,
                engine,
                config,
                original_workspace.path(),
                scenario,
                1,
            )
            .await
        }
        Err(message) => Err(attempt_failure(
            engine,
            1,
            AttemptKindV2::Original,
            message.clone(),
        )),
    };
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
            let original_workspace = original_workspace
                .as_ref()
                .expect("a recorded first attempt requires an original workspace");
            match execute_recorded_attempt_in_workspace(
                engine,
                original_workspace.path(),
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
    env.network_mode = effective_network_mode(env.network_mode, &config.sandbox.network)
        .map_err(|message| attempt_failure(engine, ordinal, AttemptKindV2::Original, message))?;
    validate_environment(&env)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;

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
        .commands_in_workspace(scenario, config, workspace)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    validate_commands(&commands)
        .map_err(|e| attempt_failure(engine, ordinal, AttemptKindV2::Original, e.to_string()))?;
    let mut attempt = execute_recorded_attempt_in_workspace(
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
    let attempt_workspace = disposable_workspace(workspace)
        .map_err(|message| attempt_failure(engine, ordinal, kind, message))?;
    execute_recorded_attempt_in_workspace(
        engine,
        attempt_workspace.path(),
        scenario,
        environment,
        commands,
        ordinal,
        kind,
    )
    .await
}

async fn execute_recorded_attempt_in_workspace(
    engine: &EngineInfo,
    attempt_workspace: &Path,
    scenario: &Scenario,
    environment: &EnvironmentSpec,
    commands: &[CommandSpec],
    ordinal: u32,
    kind: AttemptKindV2,
) -> std::result::Result<ExecutedAttempt, AttemptFailure> {
    validate_recorded_execution(environment, commands)
        .map_err(|message| attempt_failure(engine, ordinal, kind, message))?;
    let started_at = Utc::now();
    let execution = async {
        let execution_env = environment_with_exact_image(environment)?;
        ensure_image(engine, &execution_env.image_ref)
            .await
            .map_err(|e| format!("BLOCKED: exact image unavailable: {e}"))?;

        // Filter install -e . if no pyproject (avoid noisy fails) — still recorded
        let opts = SandboxExecOptions {
            engine: engine.clone(),
            env: execution_env,
            workspace_host: attempt_workspace.to_path_buf(),
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

fn validate_recorded_execution(
    environment: &EnvironmentSpec,
    commands: &[CommandSpec],
) -> std::result::Result<(), String> {
    validate_environment(environment)
        .map_err(|error| format!("BLOCKED: unsafe recorded environment: {error}"))?;
    validate_commands(commands)
        .map_err(|error| format!("BLOCKED: unsafe recorded commands: {error}"))?;
    validate_network_policy(environment, commands)
        .map_err(|error| format!("BLOCKED: unsafe recorded network policy: {error}"))?;
    Ok(())
}

/// Apply configuration as an upper bound without weakening an adapter's
/// stricter recorded environment (notably historical snapshot adapters, which
/// deliberately emit `None`). Network access therefore requires agreement
/// between config, EnvironmentSpec, and each CommandSpec.
fn effective_network_mode(
    adapter_mode: NetworkMode,
    configured: &str,
) -> std::result::Result<NetworkMode, String> {
    if adapter_mode == NetworkMode::Full {
        return Err("BLOCKED: adapter requested prohibited full-time network access".into());
    }
    match configured {
        "none" => Ok(NetworkMode::None),
        "fetch-only" => Ok(match adapter_mode {
            NetworkMode::None => NetworkMode::None,
            NetworkMode::FetchOnly => NetworkMode::FetchOnly,
            NetworkMode::Full => unreachable!("rejected above"),
        }),
        "full" => Ok(adapter_mode),
        other => Err(format!(
            "BLOCKED: unsupported sandbox.network value '{}'",
            terminal_text(other)
        )),
    }
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

struct DisposableWorkspace {
    _private_root: tempfile::TempDir,
    workspace: PathBuf,
}

impl DisposableWorkspace {
    fn path(&self) -> &Path {
        &self.workspace
    }
}

fn disposable_workspace(source: &Path) -> std::result::Result<DisposableWorkspace, String> {
    let private_root = tempfile::Builder::new()
        .prefix(".tomorrowci-attempt-")
        .tempdir()
        .map_err(|e| format!("BLOCKED: cannot create disposable workspace: {e}"))?;
    // `materialize_workspace` builds a destination from scratch. Keep the
    // TempDir's securely created root intact and materialize only a child, so
    // deleting/recreating the destination never discards the private root's
    // exclusive ownership boundary.
    let workspace = private_root.path().join("workspace");
    materialize_workspace(source, &workspace)
        .map_err(|e| format!("BLOCKED: cannot materialize disposable workspace: {e}"))?;
    Ok(DisposableWorkspace {
        _private_root: private_root,
        workspace,
    })
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
) -> Result<(PathBuf, String, bool, Option<String>, bool)> {
    if remote::looks_like_remote_target(target) {
        let repository = remote::clone_github_repository(target, clone_dir)?;
        return Ok((
            repository.path,
            repository.canonical_origin,
            true,
            Some(repository.commit_sha),
            false,
        ));
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
    let (sha, dirty) = inspect_local_git_source(&path)?;
    Ok((path, label, false, sha, dirty))
}

fn inspect_local_git_source(path: &Path) -> Result<(Option<String>, bool)> {
    let has_git_metadata = path
        .ancestors()
        .any(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok());
    let control = tempfile::tempdir().map_err(|_| {
        RunnerError::Msg("BLOCKED: local Git control directory could not be created".into())
    })?;
    let hooks = control.path().join("empty-hooks");
    std::fs::create_dir(&hooks).map_err(|_| {
        RunnerError::Msg("BLOCKED: local Git hooks directory could not be created".into())
    })?;

    let commit = match run_local_source_git_output(
        path,
        &hooks,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        HISTORICAL_GIT_MAX_IDENTITY_BYTES,
        "inspect local Git commit",
    ) {
        Ok(output) => parse_local_git_commit(&output)?,
        Err(_) if !has_git_metadata => return Ok((None, false)),
        Err(error) => return Err(RunnerError::Msg(error)),
    };

    let local_config = run_local_source_git_output(
        path,
        &hooks,
        &["config", "--null", "--name-only", "--list"],
        HISTORICAL_GIT_MAX_INDEX_BYTES,
        "inspect local Git executable configuration",
    )
    .map_err(RunnerError::Msg)?;
    reject_executable_local_git_config(&local_config)?;

    #[cfg(not(unix))]
    {
        let index = run_local_source_git_output(
            path,
            &hooks,
            &["ls-files", "--stage", "-z"],
            HISTORICAL_GIT_MAX_INDEX_BYTES,
            "inspect local Git index modes",
        )
        .map_err(RunnerError::Msg)?;
        reject_unrepresentable_local_git_modes(&index)?;
    }

    let status = run_local_source_git_output(
        path,
        &hooks,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
        HISTORICAL_GIT_MAX_INDEX_BYTES,
        "inspect local Git worktree",
    )
    .map_err(RunnerError::Msg)?;
    Ok((Some(commit), !status.is_empty()))
}

fn run_local_source_git_output(
    path: &Path,
    hooks: &Path,
    args: &[&str],
    max_stdout: usize,
    operation: &str,
) -> std::result::Result<Vec<u8>, String> {
    let mut command = historical_git_command(path);
    // The final command-scope value wins over any target-controlled local
    // configuration. `status` therefore cannot invoke a fsmonitor hook, and
    // no Git hook path inherited from the repository can execute on the host.
    command
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks.display()))
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .args(["-c", "core.fileMode=true"])
        .args(args);
    let mut output = run_bounded_command(
        command,
        None,
        max_stdout as u64,
        HISTORICAL_GIT_MAX_STDERR_BYTES as u64,
        HISTORICAL_GIT_TIMEOUT,
        operation,
    )?;
    let mut bytes = Vec::new();
    output
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .and_then(|_| output.as_file_mut().read_to_end(&mut bytes))
        .map_err(|_| format!("BLOCKED: local Git output could not be read for {operation}"))?;
    Ok(bytes)
}

fn parse_local_git_commit(output: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| RunnerError::Msg("BLOCKED: local Git commit is not UTF-8".into()))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if !is_lower_hex(text, 40) && !is_lower_hex(text, 64) {
        return Err(RunnerError::Msg(
            "BLOCKED: local Git did not resolve an exact commit identity".into(),
        ));
    }
    Ok(text.to_string())
}

fn reject_executable_local_git_config(config_keys: &[u8]) -> Result<()> {
    for key in config_keys.split(|byte| *byte == 0) {
        if key.is_empty() {
            continue;
        }
        let key = std::str::from_utf8(key).map_err(|_| {
            RunnerError::Msg("BLOCKED: local Git configuration key is not UTF-8".into())
        })?;
        let key = key.to_ascii_lowercase();
        if key.starts_with("filter.") && (key.ends_with(".clean") || key.ends_with(".process")) {
            return Err(RunnerError::Msg(
                "BLOCKED: local Git configuration contains an executable content filter".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_unrepresentable_local_git_modes(index: &[u8]) -> Result<()> {
    if index.is_empty() {
        return Ok(());
    }
    if index.last() != Some(&0) {
        return Err(RunnerError::Msg(
            "BLOCKED: local Git index output is malformed".into(),
        ));
    }
    for record in index[..index.len() - 1].split(|byte| *byte == 0) {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                RunnerError::Msg("BLOCKED: local Git index output is malformed".into())
            })?;
        let metadata = std::str::from_utf8(&record[..tab]).map_err(|_| {
            RunnerError::Msg("BLOCKED: local Git index identity is malformed".into())
        })?;
        let mut fields = metadata.split_ascii_whitespace();
        let mode = fields.next().unwrap_or_default();
        let object = fields.next().unwrap_or_default();
        let stage = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || !matches!(stage, "0" | "1" | "2" | "3")
            || !is_lower_hex(object, 40) && !is_lower_hex(object, 64)
        {
            return Err(RunnerError::Msg(
                "BLOCKED: local Git index identity is malformed".into(),
            ));
        }
        if mode == "100755" {
            return Err(RunnerError::Msg(
                "BLOCKED: local executable Git mode 100755 cannot be preserved on this host".into(),
            ));
        }
    }
    Ok(())
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
    let origin = load_public_replay_origin_v2(&verified, scenario_id).map_err(|error| {
        RunnerError::Msg(format!(
            "BLOCKED: public replay requires a sealed v2 origin: {}",
            terminal_text(&error.to_string())
        ))
    })?;
    let ordinal =
        next_public_replay_ordinal_v2(output_root, run_id, scenario_id).map_err(|error| {
            RunnerError::Msg(format!(
                "BLOCKED: public replay receipt sequence is not trustworthy: {}",
                terminal_text(&error.to_string())
            ))
        })?;
    let context = ReplayContextV2 {
        run_id: origin.manifest.run_id.clone(),
        source_manifest_sha256: canonical_sha256(&origin.source)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        config_sha256: canonical_sha256(&origin.config)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
    };
    let unavailable_engine = unavailable_engine_identity();
    let selected_workspace = if let Some(hint) = workspace_hint {
        match hint.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                let message = format!(
                    "BLOCKED: trusted replay workspace is unavailable: {}: {error}",
                    terminal_text(&hint.to_string_lossy())
                );
                return Err(record_blocked_public_replay(
                    output_root,
                    &origin,
                    &context,
                    ordinal,
                    &unavailable_engine,
                    &message,
                ));
            }
        }
    } else {
        let expected = output_root.join("work").join("workspaces").join(run_id);
        match expected.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                let message = format!(
                    "BLOCKED: trusted replay workspace is unavailable: {}: {error}",
                    terminal_text(&expected.to_string_lossy())
                );
                return Err(record_blocked_public_replay(
                    output_root,
                    &origin,
                    &context,
                    ordinal,
                    &unavailable_engine,
                    &message,
                ));
            }
        }
    };
    // v2 source identity is content-addressed, so a downloaded evidence bundle
    // can be replayed against a different canonical checkout/copy. Normalize
    // the caller's source with the same materialization boundary used by scan,
    // verify the complete sealed snapshot, and execute only from that private
    // verified copy. This avoids both recorded-host-path coupling and a
    // verify-then-recopy race against the caller-owned directory.
    let normalized_workspace = match disposable_workspace(&selected_workspace) {
        Ok(workspace) => workspace,
        Err(message) => {
            return Err(record_blocked_public_replay(
                output_root,
                &origin,
                &context,
                ordinal,
                &unavailable_engine,
                &message,
            ));
        }
    };
    let workspace = normalized_workspace.path();
    let actual = match capture_source_snapshot_v2(
        &origin.source.run_id,
        workspace,
        &origin.source.repository_source,
        origin.source.commit_sha.clone(),
        origin.source.identity_kind,
        origin.source.dirty,
        origin.source.captured_at,
    ) {
        Ok(actual) => actual,
        Err(error) => {
            let message = format!("BLOCKED: source snapshot mismatch: {error}");
            return Err(record_blocked_public_replay(
                output_root,
                &origin,
                &context,
                ordinal,
                &unavailable_engine,
                &message,
            ));
        }
    };
    if actual != origin.source {
        return Err(record_blocked_public_replay(
            output_root,
            &origin,
            &context,
            ordinal,
            &unavailable_engine,
            "BLOCKED: source snapshot mismatch; replay workspace does not match the sealed v2 file set, tree, and source identity",
        ));
    }

    // Public replay is not an engine-selection operation. The sealed exact
    // manifest chooses Docker or Podman; probing `auto` here could silently
    // prefer Docker on a host that has both even when the run was sealed by
    // Podman. Detection and the full identity check below therefore use the
    // sealed engine name as a fail-closed selector.
    let engine = match detect_engine(&origin.manifest.engine.name) {
        Ok(engine) => engine,
        Err(error) => {
            let message = format!("BLOCKED: cannot replay: {error}. Missing: container engine.");
            return Err(record_blocked_public_replay(
                output_root,
                &origin,
                &context,
                ordinal,
                &unavailable_engine,
                &message,
            ));
        }
    };

    let observed_engine = engine_identity_v2(&engine);
    if observed_engine != origin.manifest.engine {
        return Err(record_blocked_public_replay(
            output_root,
            &origin,
            &context,
            ordinal,
            &observed_engine,
            "BLOCKED: current engine identity differs from the sealed exact replay manifest",
        ));
    }

    let execution = execute_recorded_attempt(
        &engine,
        workspace,
        &origin.scenario_record,
        &origin.environment,
        &origin.commands,
        ordinal,
        AttemptKindV2::Replay,
    )
    .await;
    match execution {
        Ok(mut attempt) => {
            log_attempt_provenance(&attempt.provenance);
            if !attempt.completed.passed {
                let mut signature = normalize_replay_failure(
                    origin.scenario_record.ecosystem,
                    &attempt.completed.raw,
                );
                signature.evidence_grade = origin.scenario_record.evidence_grade;
                attempt.completed.signature = Some(redact_failure_signature(&signature));
            }
            let evidence = attempt_evidence_v2(
                &context,
                &origin.scenario_record,
                &origin.manifest,
                &attempt,
            )?;
            let sealed = seal_public_replay(output_root, &origin, &evidence, &observed_engine)?;
            replay_summary(
                run_id,
                scenario_id,
                &attempt.completed.raw,
                &receipt_terminal_line(&sealed)?,
            )
        }
        Err(failure) => {
            log_attempt_provenance(&failure.provenance);
            let evidence = attempt_failure_evidence_v2(
                &context,
                &origin.scenario_record,
                &origin.manifest,
                &failure,
            )?;
            let sealed = seal_public_replay(output_root, &origin, &evidence, &observed_engine)?;
            Err(RunnerError::Msg(format!(
                "BLOCKED: {}\n{}",
                terminal_text(&failure.message),
                receipt_terminal_line(&sealed)?
            )))
        }
    }
}

fn replay_summary(
    run_id: &str,
    scenario_id: &str,
    raw: &RawExecutionResult,
    receipt: &str,
) -> Result<String> {
    let summary = format!(
        "Replay {} / {} → exit {:?} timed_out={} duration_ms={}\n{}",
        terminal_text(run_id),
        terminal_text(scenario_id),
        raw.exit_code,
        raw.timed_out,
        raw.duration_ms,
        truncate_log(&terminal_text(&raw.stderr), 1500)
    );
    let summary = format!("{summary}\n{receipt}");
    if replay_target_succeeded(raw) {
        Ok(summary)
    } else {
        Err(RunnerError::Msg(format!("REPLAY_FAILED: {summary}")))
    }
}

fn normalize_replay_failure(ecosystem: Ecosystem, raw: &RawExecutionResult) -> FailureSignature {
    match ecosystem {
        Ecosystem::Python => PythonAdapter::new().normalize_failure(raw),
        Ecosystem::Node => NodeAdapter::new().normalize_failure(raw),
        Ecosystem::Rust => RustAdapter::new().normalize_failure(raw),
    }
}

fn unavailable_engine_identity() -> EngineIdentityV2 {
    EngineIdentityV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        name: "unavailable".into(),
        client_version: "unavailable".into(),
        server_version: None,
        api_version: None,
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
    }
}

fn record_blocked_public_replay(
    output_root: &Path,
    origin: &PublicReplayOriginV2,
    context: &ReplayContextV2,
    ordinal: u32,
    observed_engine: &EngineIdentityV2,
    message: &str,
) -> RunnerError {
    let now = Utc::now();
    let failure = AttemptFailure {
        provenance: AttemptProvenance {
            ordinal,
            kind: AttemptKindV2::Replay,
            started_at: now,
            finished_at: now,
            engine_kind: observed_engine.name.clone(),
            engine_version: observed_engine.client_version.clone(),
        },
        message: message.to_string(),
    };
    let recorded =
        attempt_failure_evidence_v2(context, &origin.scenario_record, &origin.manifest, &failure)
            .and_then(|evidence| {
                seal_public_replay(output_root, origin, &evidence, observed_engine)
            });
    match recorded.and_then(|sealed| receipt_terminal_line(&sealed)) {
        Ok(line) => RunnerError::Msg(format!("{}\n{line}", terminal_text(message))),
        Err(error) => RunnerError::Msg(format!(
            "{}\nReplay receipt sealing failed closed: {}",
            terminal_text(message),
            terminal_text(&error.to_string())
        )),
    }
}

fn seal_public_replay(
    output_root: &Path,
    origin: &PublicReplayOriginV2,
    evidence: &AttemptEvidenceV2,
    observed_engine: &EngineIdentityV2,
) -> Result<SealedPublicReplayReceiptV2> {
    write_public_replay_receipt_v2(output_root, origin, evidence, observed_engine).map_err(
        |error| {
            RunnerError::Msg(format!(
                "BLOCKED: could not seal public replay receipt: {}",
                terminal_text(&error.to_string())
            ))
        },
    )
}

fn receipt_terminal_line(receipt: &SealedPublicReplayReceiptV2) -> Result<String> {
    let path =
        std::fs::canonicalize(&receipt.bundle.root).unwrap_or_else(|_| receipt.bundle.root.clone());
    let digest = receipt
        .bundle
        .inventory_sha256()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let attempt: ExecutionAttemptV2 = receipt
        .bundle
        .read_json("attempt.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "path": path,
        "inventory_sha256": format!("sha256:{digest}"),
        "receipt_id": receipt.receipt.receipt_id,
        "ordinal": attempt.ordinal,
        "equivalent_to_original": receipt.receipt.equivalent_to_original,
    }))
    .map(|json| format!("REPLAY_RECEIPT {json}"))
    .map_err(|error| RunnerError::Msg(error.to_string()))
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
    match std::process::Command::new(command_program(bin))
        .args(args)
        .output()
    {
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

fn command_program(bin: &str) -> &str {
    if cfg!(windows) && bin.eq_ignore_ascii_case("npm") {
        "npm.cmd"
    } else {
        bin
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

/// Sample commits in [at, until] and run each against its exact-date,
/// content-addressed registry snapshot. There is deliberately no live-registry
/// fallback: absence is a typed INCONCLUSIVE result.
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

    if req.at > req.until {
        return Err(RunnerError::Msg(
            "backtest --at must not be after --until".into(),
        ));
    }
    if req.max_commits == 0 || req.max_scenarios_per_point == 0 {
        return Err(RunnerError::Msg(
            "backtest resource caps must be greater than zero".into(),
        ));
    }
    if req.max_snapshot_files == 0 || req.max_snapshot_bytes == 0 {
        return Err(RunnerError::Msg(
            "backtest snapshot resource caps must be greater than zero".into(),
        ));
    }

    let commits = list_commits_in_range(&target_path, req.at, req.until, req.max_commits)?;
    if commits.is_empty() {
        points.push(BacktestPoint {
            commit_sha: String::new(),
            committed_at: None,
            run_id: None,
            frontier_observed: false,
            horizon_label: None,
            status: BacktestPointStatus::Inconclusive,
            detail: format!("no commits found in {}..{} (git log)", req.at, req.until),
            snapshot: None,
            proof: None,
        });
        return Ok(BacktestReport {
            request: req,
            points,
            note: BacktestReport::note().into(),
        });
    }

    for (sha, committed_at) in commits {
        // Every commit gets an unguessable, private session directory. Existing
        // ancestors are inspected component-by-component before creation. As
        // with all pathname-based portable Rust APIs, a hostile same-user
        // process racing path replacement is outside this local-work-root
        // boundary; callers must place `work_root` in a trusted directory.
        let session = match create_private_historical_session(&work_root) {
            Ok(session) => session,
            Err(detail) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at,
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::Blocked,
                    detail,
                    snapshot: None,
                    proof: None,
                });
                continue;
            }
        };
        let worktree = session.path().join("source");
        let materialized = match materialize_commit_worktree(&target_path, &sha, &worktree) {
            Ok(materialized) => materialized,
            Err(detail) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at,
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::Blocked,
                    detail,
                    snapshot: None,
                    proof: None,
                });
                continue;
            }
        };

        let Some(commit_time) = committed_at else {
            points.push(BacktestPoint {
                commit_sha: sha,
                committed_at: None,
                run_id: None,
                frontier_observed: false,
                horizon_label: None,
                status: BacktestPointStatus::Inconclusive,
                detail: "commit timestamp is unavailable; exact-date snapshot cannot be selected"
                    .into(),
                snapshot: None,
                proof: None,
            });
            continue;
        };

        let ecosystem = match detect_backtest_ecosystem(&worktree) {
            Ok(ecosystem) => ecosystem,
            Err(detail) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at: Some(commit_time),
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::Inconclusive,
                    detail,
                    snapshot: None,
                    proof: None,
                });
                continue;
            }
        };

        let Some(snapshot_registry) = req.snapshot_registry.as_deref() else {
            points.push(BacktestPoint {
                commit_sha: sha,
                committed_at: Some(commit_time),
                run_id: None,
                frontier_observed: false,
                horizon_label: None,
                status: BacktestPointStatus::Inconclusive,
                detail: format!(
                    "registry snapshot missing for {} {} (pass --snapshot-registry); no live-registry fallback",
                    ecosystem,
                    commit_time.date_naive()
                ),
                snapshot: None,
                proof: None,
            });
            continue;
        };
        let manifest_path =
            expected_snapshot_manifest(snapshot_registry, ecosystem, commit_time.date_naive());
        let verified = match verify_registry_snapshot(
            &manifest_path,
            ecosystem,
            Some(commit_time.date_naive()),
            req.max_snapshot_files,
            req.max_snapshot_bytes,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                let status = match error.disposition() {
                    SnapshotFailureDisposition::Inconclusive => BacktestPointStatus::Inconclusive,
                    SnapshotFailureDisposition::ScheduledRisk => BacktestPointStatus::ScheduledRisk,
                };
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at: Some(commit_time),
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status,
                    detail: format!("{error}; no live-registry fallback"),
                    snapshot: None,
                    proof: None,
                });
                continue;
            }
        };
        if verified.manifest.effective_at > commit_time {
            points.push(BacktestPoint {
                commit_sha: sha,
                committed_at: Some(commit_time),
                run_id: None,
                frontier_observed: false,
                horizon_label: None,
                status: BacktestPointStatus::ScheduledRisk,
                detail: format!(
                    "registry snapshot effective_at {} is after source commit {}; no registry time travel",
                    verified.manifest.effective_at, commit_time
                ),
                snapshot: Some(verified.binding),
                proof: None,
            });
            continue;
        }
        let staged = match stage_verified_snapshot(
            &verified,
            &worktree,
            commit_time.date_naive(),
            req.max_snapshot_files,
            req.max_snapshot_bytes,
        ) {
            Ok(staged) => staged,
            Err(detail) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at: Some(commit_time),
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::ScheduledRisk,
                    detail,
                    snapshot: Some(verified.binding),
                    proof: None,
                });
                continue;
            }
        };

        let commit_config = worktree.join(".tomorrowci.yml");
        let mut cfg = if commit_config.exists() {
            match Config::load_from_path(&commit_config) {
                Ok(config) => config,
                Err(error) => {
                    points.push(BacktestPoint {
                        commit_sha: sha,
                        committed_at: Some(commit_time),
                        run_id: None,
                        frontier_observed: false,
                        horizon_label: None,
                        status: BacktestPointStatus::ScheduledRisk,
                        detail: format!("historical .tomorrowci.yml is invalid: {error}"),
                        snapshot: Some(staged.binding),
                        proof: None,
                    });
                    continue;
                }
            }
        } else {
            Config::default()
        };
        cfg.execution.max_scenarios = req.max_scenarios_per_point.max(1);
        cfg.execution.reruns_on_failure = 1;
        cfg.candidates.runtime.max_versions = 3;

        // The run manifest retains the historical short config id for format
        // compatibility. A detached BacktestProof promises a full SHA-256,
        // so bind the complete normalized JSON rather than that short id.
        let normalized_config = cfg
            .normalized_json()
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let config_sha256 = hex::encode(Sha256::digest(normalized_config.as_bytes()));
        let staged_source_tree_sha256 =
            match verify_staged_historical_source(&worktree, &materialized, &staged) {
                Ok(identity) => identity,
                Err(detail) => {
                    points.push(BacktestPoint {
                        commit_sha: sha,
                        committed_at: Some(commit_time),
                        run_id: None,
                        frontier_observed: false,
                        horizon_label: None,
                        status: BacktestPointStatus::Blocked,
                        detail,
                        snapshot: Some(staged.binding),
                        proof: None,
                    });
                    continue;
                }
            };
        match scan_with_pinned_source(
            ScanRequest {
                target: worktree.display().to_string(),
                config: cfg.clone(),
                config_path: None,
                output_root: evidence_root.clone(),
                work_root: work_root.join("backtest-workspaces"),
            },
            Some(PinnedBacktestSource {
                repository_source: req.target.clone(),
                commit_sha: materialized.commit_sha.clone(),
                expected_tree_sha256: staged_source_tree_sha256,
            }),
        )
        .await
        {
            Ok(out) => {
                let baseline_passed = out
                    .verdicts
                    .iter()
                    .any(|verdict| verdict.verdict == Verdict::BaselinePass);
                let verdicts_evaluable = out.verdicts.iter().all(|verdict| {
                    matches!(
                        verdict.verdict,
                        Verdict::BaselinePass | Verdict::FuturePass | Verdict::FutureFail
                    )
                });
                let proof = create_backtest_proof(CreateBacktestProofRequest {
                    evidence_root: &evidence_root,
                    source: &req.target,
                    source_commit_sha: &sha,
                    source_committed_at: commit_time,
                    snapshot: &staged,
                    materialized: &materialized,
                    config_sha256: &config_sha256,
                    outcome: &out,
                });
                let (status, detail, proof) = match proof {
                    Ok(proof)
                        if out.manifest.status == RunStatus::Completed
                            && baseline_passed
                            && verdicts_evaluable => (
                        BacktestPointStatus::Ok,
                        format!(
                            "offline snapshot {} and sealed no-network receipts verified; {}",
                            staged.binding.snapshot_id, out.frontier.explanation
                        ),
                        Some(proof),
                    ),
                    Ok(proof) => (
                        BacktestPointStatus::ScheduledRisk,
                        format!(
                            "offline snapshot run is sealed but not evaluable (status={:?}, baseline_passed={}, verdicts_evaluable={}): {}",
                            out.manifest.status,
                            baseline_passed,
                            verdicts_evaluable,
                            out.frontier.explanation
                        ),
                        Some(proof),
                    ),
                    Err(error) => (
                        BacktestPointStatus::ScheduledRisk,
                        format!("backtest proof could not be sealed: {error}"),
                        None,
                    ),
                };
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at: Some(commit_time),
                    run_id: Some(out.run_id.0.clone()),
                    frontier_observed: out.frontier.observed,
                    horizon_label: out.frontier.horizon_label.clone(),
                    status,
                    detail,
                    snapshot: Some(staged.binding),
                    proof,
                });
            }
            Err(e) => {
                points.push(BacktestPoint {
                    commit_sha: sha,
                    committed_at: Some(commit_time),
                    run_id: None,
                    frontier_observed: false,
                    horizon_label: None,
                    status: BacktestPointStatus::Failed,
                    detail: e.to_string(),
                    snapshot: Some(staged.binding),
                    proof: None,
                });
            }
        }
    }

    Ok(BacktestReport {
        request: req,
        points,
        note: BacktestReport::note().into(),
    })
}

fn detect_backtest_ecosystem(worktree: &Path) -> std::result::Result<Ecosystem, String> {
    let python = PythonAdapter::new();
    let node = NodeAdapter::new();
    let rust = RustAdapter::new();
    let adapters: [&dyn EcosystemAdapter; 3] = [&python, &node, &rust];
    detect_ecosystem(worktree, &adapters, None)
        .map(|(_, detection)| detection.detection.ecosystem)
        .map_err(|error| format!("cannot select registry snapshot: {error}"))
}

fn stage_verified_snapshot(
    snapshot: &VerifiedRegistrySnapshot,
    worktree: &Path,
    expected_date: NaiveDate,
    max_files: usize,
    max_bytes: u64,
) -> std::result::Result<VerifiedRegistrySnapshot, String> {
    let destination = worktree.join(WORKSPACE_SNAPSHOT_DIR);
    if std::fs::symlink_metadata(&destination).is_ok() {
        return Err(format!(
            "SCHEDULED_RISK: source tree already contains reserved snapshot path {}",
            destination.display()
        ));
    }
    std::fs::create_dir_all(destination.join(SNAPSHOT_PAYLOAD_DIR))
        .map_err(|error| format!("SCHEDULED_RISK: create staged snapshot: {error}"))?;
    let manifest_bytes = std::fs::read(&snapshot.manifest_path)
        .map_err(|error| format!("SCHEDULED_RISK: read verified manifest: {error}"))?;
    std::fs::write(destination.join(SNAPSHOT_MANIFEST_FILE), manifest_bytes)
        .map_err(|error| format!("SCHEDULED_RISK: write staged manifest: {error}"))?;
    set_historical_executable(&destination.join(SNAPSHOT_MANIFEST_FILE), false)
        .map_err(|error| format!("SCHEDULED_RISK: normalize staged manifest mode: {error}"))?;
    for entry in &snapshot.manifest.files {
        let source = snapshot.payload_root.join(&entry.path);
        let target = destination.join(SNAPSHOT_PAYLOAD_DIR).join(&entry.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("SCHEDULED_RISK: stage payload: {error}"))?;
        }
        std::fs::copy(&source, &target)
            .map_err(|error| format!("SCHEDULED_RISK: stage payload: {error}"))?;
        set_historical_executable(&target, false)
            .map_err(|error| format!("SCHEDULED_RISK: normalize staged payload mode: {error}"))?;
    }
    verify_registry_snapshot(
        &destination.join(SNAPSHOT_MANIFEST_FILE),
        snapshot.manifest.ecosystem,
        Some(expected_date),
        max_files,
        max_bytes,
    )
    .map_err(|error| format!("SCHEDULED_RISK: staged snapshot verification failed: {error}"))
}

struct CreateBacktestProofRequest<'a> {
    evidence_root: &'a Path,
    source: &'a str,
    source_commit_sha: &'a str,
    source_committed_at: DateTime<Utc>,
    snapshot: &'a VerifiedRegistrySnapshot,
    materialized: &'a MaterializedCommit,
    config_sha256: &'a str,
    outcome: &'a ScanOutcome,
}

fn create_backtest_proof(req: CreateBacktestProofRequest<'_>) -> Result<BacktestProofReference> {
    let CreateBacktestProofRequest {
        evidence_root,
        source,
        source_commit_sha,
        source_committed_at,
        snapshot,
        materialized,
        config_sha256,
        outcome,
    } = req;
    let verified_run = tomorrowci_evidence::verify_bundle(&outcome.evidence_dir)
        .map_err(|error| RunnerError::Msg(format!("verify sealed run: {error}")))?;
    if verified_run.kind != tomorrowci_evidence::BundleKind::Run
        || verified_run.version != tomorrowci_evidence::INVENTORY_VERSION_V2
    {
        return Err(RunnerError::Msg(
            "backtest proof requires a typed v2 sealed run witness".into(),
        ));
    }
    let sealed_run_inventory_sha256 = verified_run
        .inventory_sha256()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let run: RunManifest = verified_run
        .read_json("run.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let source_manifest: SourceSnapshotManifestV2 = verified_run
        .read_json("source-manifest.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let config: Config = verified_run
        .read_json("config.normalized.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let verdicts: Vec<ScenarioVerdict> = verified_run
        .read_json("verdicts.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let frontier: BreakageFrontier = verified_run
        .read_json("frontier.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    ensure_backtest_run_strictly_offline(&verified_run, &verdicts)?;
    let witness_config_sha256 = normalized_config_sha256(&config)?;
    if witness_config_sha256 != config_sha256 {
        return Err(RunnerError::Msg(
            "effective backtest config does not match the sealed run config".into(),
        ));
    }
    let runtime_images = runtime_images_from_run(&verified_run, &verdicts, run.scenario_count)?;
    let proof_outcome = backtest_proof_outcome(&run, &verdicts);
    let proof = BacktestProof {
        schema_version: BACKTEST_PROOF_SCHEMA_VERSION,
        created_at: Utc::now(),
        source: redact_secrets(source),
        source_commit_sha: source_commit_sha.to_string(),
        source_committed_at,
        snapshot: snapshot.binding.clone(),
        source_manifest_sha256: canonical_sha256(&source_manifest)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        normalized_config_sha256: config_sha256.to_string(),
        run_manifest_sha256: canonical_sha256(&run)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        verdicts_sha256: canonical_sha256(&verdicts)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        frontier_sha256: canonical_sha256(&frontier)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        outcome: proof_outcome,
        runtime_images,
        run_id: outcome.run_id.0.clone(),
        sealed_run_inventory_sha256,
    };
    let proof_sha256 =
        canonical_proof_sha256(&proof).map_err(|error| RunnerError::Msg(error.to_string()))?;
    let proof_hex = proof_sha256
        .strip_prefix("sha256:")
        .ok_or_else(|| RunnerError::Msg("backtest proof digest is not SHA-256".into()))?;
    let directory_name = format!(
        "{}-{}",
        &source_commit_sha[..12.min(source_commit_sha.len())],
        &proof_hex[..16]
    );
    let directory = create_backtest_proof_directory(evidence_root, &directory_name)?;
    let proof_path = directory.join("backtest-proof.json");
    let witness = directory.join("witness");
    std::fs::create_dir(&witness)
        .map_err(|error| RunnerError::Msg(format!("create proof witness: {error}")))?;
    let run_witness = witness.join("run");
    let snapshot_witness = witness.join("registry-snapshot");
    let git_source_binding_path = witness.join("git-source-binding.json");
    copy_regular_tree(&outcome.evidence_dir, &run_witness)?;
    tomorrowci_evidence::verify_bundle(&run_witness)
        .map_err(|error| RunnerError::Msg(format!("verify copied run witness: {error}")))?;
    let snapshot_root = snapshot
        .manifest_path
        .parent()
        .ok_or_else(|| RunnerError::Msg("verified snapshot manifest has no parent".into()))?;
    copy_regular_tree(snapshot_root, &snapshot_witness)?;
    let git_source_binding = HistoricalGitSourceBinding {
        schema_version: HISTORICAL_GIT_SOURCE_BINDING_SCHEMA_VERSION,
        source_commit_sha: materialized.commit_sha.clone(),
        source_git_tree_oid: materialized.tree_oid.clone(),
        commit_source_manifest_sha256: materialized.source_tree_sha256.clone(),
    };
    write_new_file(
        &git_source_binding_path,
        &serde_json::to_vec_pretty(&git_source_binding)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
    )
    .map_err(|error| RunnerError::Msg(format!("write Git source binding: {error}")))?;

    let bytes =
        serde_json::to_vec_pretty(&proof).map_err(|error| RunnerError::Msg(error.to_string()))?;
    write_new_file(&proof_path, &bytes)
        .map_err(|error| RunnerError::Msg(format!("write backtest proof: {error}")))?;
    tomorrowci_evidence::seal_bundle(&directory, tomorrowci_evidence::BundleKind::Generic)
        .map_err(|error| RunnerError::Msg(format!("seal backtest proof: {error}")))?;
    let verified_proof = tomorrowci_evidence::verify_bundle(&directory)
        .map_err(|error| RunnerError::Msg(format!("verify backtest proof: {error}")))?;
    let sealed_inventory_sha256 = verified_proof
        .inventory_sha256()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let reference = BacktestProofReference {
        directory,
        proof_sha256,
        sealed_inventory_sha256,
    };
    verify_backtest_proof(&reference)?;
    Ok(reference)
}

/// Strict readback for the detached proof that links an immutable run to the
/// historical source and registry snapshot used to produce it.
pub fn verify_backtest_proof(reference: &BacktestProofReference) -> Result<BacktestProof> {
    let verified = tomorrowci_evidence::verify_bundle(&reference.directory)
        .map_err(|error| RunnerError::Msg(format!("verify backtest proof: {error}")))?;
    if verified.kind != tomorrowci_evidence::BundleKind::Generic {
        return Err(RunnerError::Msg(
            "backtest proof must be a sealed generic bundle".into(),
        ));
    }
    let inventory_sha256 = verified
        .inventory_sha256()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    if inventory_sha256 != reference.sealed_inventory_sha256 {
        return Err(RunnerError::Msg(
            "backtest proof sealed inventory identity mismatch".into(),
        ));
    }
    let proof: BacktestProof = verified
        .read_json("backtest-proof.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    if proof.schema_version != BACKTEST_PROOF_SCHEMA_VERSION {
        return Err(RunnerError::Msg(format!(
            "unsupported backtest proof schema {}",
            proof.schema_version
        )));
    }
    let proof_sha256 =
        canonical_proof_sha256(&proof).map_err(|error| RunnerError::Msg(error.to_string()))?;
    if proof_sha256 != reference.proof_sha256 {
        return Err(RunnerError::Msg(
            "backtest proof content identity mismatch".into(),
        ));
    }
    if proof.source.trim().is_empty()
        || proof.source.len() > 4096
        || proof.source.chars().any(char::is_control)
        || !(is_lower_hex(&proof.source_commit_sha, 40)
            || is_lower_hex(&proof.source_commit_sha, 64))
        || !is_lower_hex(&proof.run_id, 12)
        || !is_lower_hex(&proof.normalized_config_sha256, 64)
        || !is_lower_hex(&proof.sealed_run_inventory_sha256, 64)
        || !is_sha256_identity(&proof.source_manifest_sha256)
        || !is_sha256_identity(&proof.run_manifest_sha256)
        || !is_sha256_identity(&proof.verdicts_sha256)
        || !is_sha256_identity(&proof.frontier_sha256)
        || !is_sha256_identity(&proof.snapshot.snapshot_id)
        || !is_lower_hex(&proof.snapshot.manifest_sha256, 64)
        || !is_sha256_identity(&proof.snapshot.source.immutable_revision)
        || proof.snapshot.effective_at.date_naive() != proof.source_committed_at.date_naive()
        || proof.snapshot.effective_at > proof.source_committed_at
        || proof.snapshot.captured_at < proof.snapshot.effective_at
        || proof.created_at < proof.source_committed_at
        || proof.created_at < proof.snapshot.captured_at
        || proof.snapshot.resolver_mode.ecosystem() != proof.snapshot.ecosystem
        || !proof.snapshot.source.url.starts_with("https://")
        || proof.snapshot.source.url.chars().any(char::is_control)
        || proof.snapshot.source.url.chars().any(char::is_whitespace)
        || proof.snapshot.file_count == 0
    {
        return Err(RunnerError::Msg(
            "backtest proof contains an invalid source, snapshot, time, or digest identity".into(),
        ));
    }
    let mut previous_image: Option<(&str, &str)> = None;
    if proof.runtime_images.is_empty()
        || proof.runtime_images.iter().any(|image| {
            let current = (image.image_ref.as_str(), image.image_digest.as_str());
            let unordered = previous_image.is_some_and(|previous| previous >= current);
            previous_image = Some(current);
            image.image_ref.trim().is_empty()
                || !is_sha256_identity(&image.image_digest)
                || unordered
        })
    {
        return Err(RunnerError::Msg(
            "backtest proof requires exact runtime image identities".into(),
        ));
    }
    verify_backtest_proof_witnesses(&verified, &proof)?;
    Ok(proof)
}

fn verify_backtest_proof_witnesses(
    proof_bundle: &tomorrowci_evidence::VerifiedBundle,
    proof: &BacktestProof,
) -> Result<()> {
    const RUN_WITNESS: &str = "witness/run";
    for required in [
        "witness/git-source-binding.json",
        "witness/run/checksums.txt",
        "witness/run/run.json",
        "witness/run/source-manifest.json",
        "witness/run/config.normalized.json",
        "witness/run/verdicts.json",
        "witness/run/frontier.json",
        "witness/registry-snapshot/snapshot-manifest.json",
    ] {
        if !proof_bundle.contains(required) {
            return Err(RunnerError::Msg(format!(
                "backtest proof is missing required witness {required}"
            )));
        }
    }

    let run_root = proof_bundle.root.join(RUN_WITNESS);
    let verified_run = tomorrowci_evidence::verify_bundle(&run_root)
        .map_err(|error| RunnerError::Msg(format!("verify embedded run witness: {error}")))?;
    if verified_run.kind != tomorrowci_evidence::BundleKind::Run
        || verified_run.version != tomorrowci_evidence::INVENTORY_VERSION_V2
    {
        return Err(RunnerError::Msg(
            "embedded backtest run witness must be a sealed v2 run".into(),
        ));
    }
    let run_inventory_sha256 = verified_run
        .inventory_sha256()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    if run_inventory_sha256 != proof.sealed_run_inventory_sha256 {
        return Err(RunnerError::Msg(
            "backtest proof run inventory binding mismatch".into(),
        ));
    }

    let run: RunManifest = verified_run
        .read_json("run.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let repository: RepositorySnapshot = verified_run
        .read_json("repository.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let source_manifest: SourceSnapshotManifestV2 = verified_run
        .read_json("source-manifest.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let config: Config = verified_run
        .read_json("config.normalized.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let verdicts: Vec<ScenarioVerdict> = verified_run
        .read_json("verdicts.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let frontier: BreakageFrontier = verified_run
        .read_json("frontier.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    ensure_backtest_run_strictly_offline(&verified_run, &verdicts)?;
    let git_source_binding: HistoricalGitSourceBinding = proof_bundle
        .read_json("witness/git-source-binding.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;

    if run.run_id.0 != proof.run_id
        || repository.source != proof.source
        || source_manifest.repository_source != proof.source
        || repository.commit_sha.as_deref() != Some(proof.source_commit_sha.as_str())
        || source_manifest.commit_sha.as_deref() != Some(proof.source_commit_sha.as_str())
        || canonical_sha256(&source_manifest)
            .map_err(|error| RunnerError::Msg(error.to_string()))?
            != proof.source_manifest_sha256
        || normalized_config_sha256(&config)? != proof.normalized_config_sha256
        || canonical_sha256(&run).map_err(|error| RunnerError::Msg(error.to_string()))?
            != proof.run_manifest_sha256
        || canonical_sha256(&verdicts).map_err(|error| RunnerError::Msg(error.to_string()))?
            != proof.verdicts_sha256
        || canonical_sha256(&frontier).map_err(|error| RunnerError::Msg(error.to_string()))?
            != proof.frontier_sha256
        || backtest_proof_outcome(&run, &verdicts) != proof.outcome
        || run.started_at < proof.source_committed_at
        || run
            .finished_at
            .is_some_and(|finished| proof.created_at < finished)
        || run
            .detection
            .as_ref()
            .is_some_and(|detection| detection.ecosystem != proof.snapshot.ecosystem)
        || !valid_historical_git_source_binding(
            &git_source_binding,
            &proof.source_commit_sha,
            &source_manifest,
        )
    {
        return Err(RunnerError::Msg(
            "backtest proof run, source, config, verdict, frontier, or outcome binding mismatch"
                .into(),
        ));
    }

    let expected_images = runtime_images_from_run(&verified_run, &verdicts, run.scenario_count)?;
    if expected_images != proof.runtime_images {
        return Err(RunnerError::Msg(
            "backtest proof runtime image binding mismatch".into(),
        ));
    }

    let snapshot_manifest = proof_bundle
        .root
        .join("witness/registry-snapshot")
        .join(SNAPSHOT_MANIFEST_FILE);
    let verified_snapshot = verify_registry_snapshot(
        &snapshot_manifest,
        proof.snapshot.ecosystem,
        Some(proof.source_committed_at.date_naive()),
        proof.snapshot.file_count,
        proof.snapshot.total_bytes,
    )
    .map_err(|error| RunnerError::Msg(format!("verify embedded registry snapshot: {error}")))?;
    if verified_snapshot.binding != proof.snapshot {
        return Err(RunnerError::Msg(
            "embedded registry snapshot binding mismatch".into(),
        ));
    }
    verify_snapshot_source_binding(&source_manifest, &verified_snapshot)?;
    Ok(())
}

fn normalized_config_sha256(config: &Config) -> Result<String> {
    let normalized = config
        .normalized_json()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(normalized.as_bytes())))
}

fn backtest_proof_outcome(run: &RunManifest, verdicts: &[ScenarioVerdict]) -> BacktestProofOutcome {
    let baseline_passed = verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::BaselinePass);
    let verdicts_evaluable = verdicts.iter().all(|verdict| {
        matches!(
            verdict.verdict,
            Verdict::BaselinePass | Verdict::FuturePass | Verdict::FutureFail
        )
    });
    if run.status == RunStatus::Completed && baseline_passed && verdicts_evaluable {
        BacktestProofOutcome::Qualified
    } else {
        BacktestProofOutcome::ScheduledRisk
    }
}

fn runtime_images_from_run(
    verified_run: &tomorrowci_evidence::VerifiedBundle,
    verdicts: &[ScenarioVerdict],
    scenario_count: usize,
) -> Result<Vec<BacktestRuntimeImage>> {
    let mut images = BTreeMap::<(String, String), BacktestRuntimeImage>::new();
    for verdict in verdicts {
        if verdict.evidence.is_none() {
            continue;
        }
        let result_path = format!("scenarios/{}/result.json", verdict.scenario_id.0);
        let result: ExecutionResult = verified_run
            .read_json(&result_path)
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let digest = result.image_digest.ok_or_else(|| {
            RunnerError::Msg(format!(
                "sealed scenario {} has no runtime image digest",
                verdict.scenario_id.0
            ))
        })?;
        images.insert(
            (result.image_ref.clone(), digest.clone()),
            BacktestRuntimeImage {
                image_ref: result.image_ref,
                image_digest: digest,
            },
        );
    }
    if images.is_empty() && scenario_count > 0 {
        return Err(RunnerError::Msg(
            "sealed run did not expose any exact runtime image identity".into(),
        ));
    }
    Ok(images.into_values().collect())
}

fn ensure_backtest_run_strictly_offline(
    verified_run: &tomorrowci_evidence::VerifiedBundle,
    verdicts: &[ScenarioVerdict],
) -> Result<()> {
    for verdict in verdicts {
        if verdict.evidence.is_none() || verdict.attempts == 0 {
            return Err(RunnerError::Msg(format!(
                "backtest scenario {} has no executed evidence",
                verdict.scenario_id.0
            )));
        }
        let prefix = format!("scenarios/{}", verdict.scenario_id.0);
        let environment: EnvironmentSpec = verified_run
            .read_json(&format!("{prefix}/environment.json"))
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let commands: Vec<CommandSpec> = verified_run
            .read_json(&format!("{prefix}/commands.json"))
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        let result: ExecutionResult = verified_run
            .read_json(&format!("{prefix}/result.json"))
            .map_err(|error| RunnerError::Msg(error.to_string()))?;
        if environment.network_mode != NetworkMode::None
            || commands.iter().any(|command| command.network_required)
            || result.network_used
        {
            return Err(RunnerError::Msg(format!(
                "backtest scenario {} is not provably offline",
                verdict.scenario_id.0
            )));
        }

        for ordinal in 1..=verdict.attempts {
            let path = format!("{prefix}/attempts/attempt-{ordinal:06}/attempt.json");
            let attempt: ExecutionAttemptV2 = verified_run
                .read_json(&path)
                .map_err(|error| RunnerError::Msg(error.to_string()))?;
            ensure_backtest_attempt_strictly_offline(&attempt)?;
        }

        let qualification_path = format!("{prefix}/replay-qualification.json");
        if verified_run.contains(&qualification_path) {
            let qualification: ReplayQualificationV2 = verified_run
                .read_json(&qualification_path)
                .map_err(|error| RunnerError::Msg(error.to_string()))?;
            for reference in &qualification.replay_attempts {
                let path = format!(
                    "{prefix}/replays/attempt-{:06}/attempt.json",
                    reference.ordinal
                );
                let attempt: ExecutionAttemptV2 = verified_run
                    .read_json(&path)
                    .map_err(|error| RunnerError::Msg(error.to_string()))?;
                ensure_backtest_attempt_strictly_offline(&attempt)?;
            }
        }
    }
    Ok(())
}

fn ensure_backtest_attempt_strictly_offline(attempt: &ExecutionAttemptV2) -> Result<()> {
    if attempt.environment.network_mode != NetworkMode::None
        || attempt
            .commands
            .iter()
            .any(|command| command.network_required)
        || attempt.result.network_used
    {
        return Err(RunnerError::Msg(format!(
            "backtest attempt {} is not provably offline",
            terminal_text(&attempt.attempt_id)
        )));
    }
    Ok(())
}

/// A standalone downloaded backtest proof after both its recursive seal and
/// typed semantic identities have been recomputed. The returned reference is
/// derived from the bytes that were actually verified; callers may retain it
/// as the detached identity for later comparisons.
#[derive(Debug, Clone)]
pub struct VerifiedBacktestProof {
    pub proof: BacktestProof,
    pub reference: BacktestProofReference,
}

/// Verify a downloaded backtest proof directory without treating its generic
/// bundle as a run. This establishes integrity and internal identity, not
/// producer authenticity.
pub fn verify_backtest_proof_bundle(directory: &Path) -> Result<VerifiedBacktestProof> {
    let verified = tomorrowci_evidence::verify_bundle(directory)
        .map_err(|error| RunnerError::Msg(format!("verify backtest proof: {error}")))?;
    if verified.kind != tomorrowci_evidence::BundleKind::Generic {
        return Err(RunnerError::Msg(
            "backtest proof must be a sealed generic bundle".into(),
        ));
    }
    let proof: BacktestProof = verified
        .read_json("backtest-proof.json")
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    let reference = BacktestProofReference {
        directory: verified.root.clone(),
        proof_sha256: canonical_proof_sha256(&proof)
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
        sealed_inventory_sha256: verified
            .inventory_sha256()
            .map_err(|error| RunnerError::Msg(error.to_string()))?,
    };
    let proof = verify_backtest_proof(&reference)?;
    Ok(VerifiedBacktestProof { proof, reference })
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata = std::fs::symlink_metadata(source)
        .map_err(|error| RunnerError::Msg(format!("inspect {}: {error}", source.display())))?;
    if !source_metadata.is_dir()
        || source_metadata.file_type().is_symlink()
        || runner_reparse_point(&source_metadata)
    {
        return Err(RunnerError::Msg(format!(
            "proof witness source must be a plain directory: {}",
            source.display()
        )));
    }
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(RunnerError::Msg(format!(
            "proof witness destination already exists: {}",
            destination.display()
        )));
    }
    std::fs::create_dir(destination)
        .map_err(|error| RunnerError::Msg(format!("create {}: {error}", destination.display())))?;
    copy_regular_tree_contents(source, destination, 0)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()
}

fn create_backtest_proof_directory(evidence_root: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\']) || name.chars().any(char::is_control) {
        return Err(RunnerError::Msg(
            "invalid backtest proof directory name".into(),
        ));
    }
    let backtests_root = evidence_root.join("backtests");
    create_plain_directory_chain(&backtests_root).map_err(RunnerError::Msg)?;
    let directory = backtests_root.join(name);
    std::fs::create_dir(&directory)
        .map_err(|error| RunnerError::Msg(format!("create backtest proof: {error}")))?;
    ensure_plain_historical_directory(&directory).map_err(RunnerError::Msg)?;
    Ok(directory)
}

fn copy_regular_tree_contents(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(RunnerError::Msg(
            "proof witness directory nesting exceeds 64".into(),
        ));
    }
    let mut entries = std::fs::read_dir(source)
        .map_err(|error| RunnerError::Msg(format!("read {}: {error}", source.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| RunnerError::Msg(error.to_string()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path).map_err(|error| {
            RunnerError::Msg(format!("inspect {}: {error}", source_path.display()))
        })?;
        if metadata.file_type().is_symlink() || runner_reparse_point(&metadata) {
            return Err(RunnerError::Msg(format!(
                "proof witness contains a link or reparse point: {}",
                source_path.display()
            )));
        }
        if metadata.is_dir() {
            std::fs::create_dir(&destination_path).map_err(|error| {
                RunnerError::Msg(format!("create {}: {error}", destination_path.display()))
            })?;
            copy_regular_tree_contents(&source_path, &destination_path, depth + 1)?;
        } else if metadata.is_file() {
            copy_file_new(&source_path, &destination_path)?;
        } else {
            return Err(RunnerError::Msg(format!(
                "proof witness contains a special file: {}",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn copy_file_new(source: &Path, destination: &Path) -> Result<()> {
    let mut input = std::fs::File::open(source)
        .map_err(|error| RunnerError::Msg(format!("open {}: {error}", source.display())))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| RunnerError::Msg(format!("create {}: {error}", destination.display())))?;
    std::io::copy(&mut input, &mut output).map_err(|error| {
        RunnerError::Msg(format!(
            "copy {} to {}: {error}",
            source.display(),
            destination.display()
        ))
    })?;
    output
        .flush()
        .map_err(|error| RunnerError::Msg(format!("flush {}: {error}", destination.display())))?;
    Ok(())
}

#[cfg(windows)]
fn runner_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn runner_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn is_sha256_identity(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn list_commits_in_range(
    repo: &Path,
    at: NaiveDate,
    until: NaiveDate,
    max: usize,
) -> Result<Vec<(String, Option<chrono::DateTime<Utc>>)>> {
    let after = format!("{at} 00:00:00");
    let before = format!("{until} 23:59:59");
    let max_arg = max.to_string();
    let output_cap = max
        .saturating_mul(128)
        .saturating_add(1024)
        .min(16 * 1024 * 1024);
    let out = run_historical_git_output(
        repo,
        &[
            "log",
            "--no-decorate",
            "--format=%H %cI",
            &format!("--after={after}"),
            &format!("--before={before}"),
            "-n",
            &max_arg,
            "--",
        ],
        output_cap,
        "enumerate historical commits",
    )
    .map_err(RunnerError::Msg)?;
    let output = std::str::from_utf8(&out)
        .map_err(|_| RunnerError::Msg("historical git log output is not UTF-8".into()))?;
    let mut rows = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(sha) = parts.next() else { continue };
        let timestamp = parts.next();
        if parts.next().is_some() || !(is_lower_hex(sha, 40) || is_lower_hex(sha, 64)) {
            return Err(RunnerError::Msg(
                "historical git log returned malformed commit metadata".into(),
            ));
        }
        let ts = timestamp
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|date| date.with_timezone(&Utc));
        if ts.is_none() {
            return Err(RunnerError::Msg(
                "historical git log returned an invalid commit timestamp".into(),
            ));
        }
        rows.push((sha.to_string(), ts));
    }
    // Oldest first for timeline readability
    rows.reverse();
    Ok(rows)
}

const HISTORICAL_SOURCE_MAX_FILES: usize = 10_000;
const HISTORICAL_SOURCE_MAX_ENTRIES: usize = 10_000;
const HISTORICAL_SOURCE_MAX_DEPTH: usize = 64;
const HISTORICAL_SOURCE_MAX_PATH_BYTES: usize = 4_096;
const HISTORICAL_SOURCE_MAX_COMPONENT_BYTES: usize = 255;
const HISTORICAL_SOURCE_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const HISTORICAL_SOURCE_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HISTORICAL_GIT_MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
const HISTORICAL_GIT_MAX_IDENTITY_BYTES: usize = 4 * 1024;
const HISTORICAL_GIT_MAX_STDERR_BYTES: usize = 8 * 1024;
const HISTORICAL_GIT_FSCK_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const HISTORICAL_GIT_TIMEOUT: Duration = Duration::from_secs(120);
const HISTORICAL_GIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const HISTORICAL_GIT_SOURCE_BINDING_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoricalTreeEntry {
    mode: &'static str,
    oid: String,
    path: String,
    size_bytes: u64,
}

#[derive(Debug)]
struct MaterializedCommit {
    commit_sha: String,
    tree_oid: String,
    source_files: Vec<tomorrowci_core::SourceFileEntryV2>,
    source_tree_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalGitSourceBinding {
    schema_version: u32,
    source_commit_sha: String,
    source_git_tree_oid: String,
    commit_source_manifest_sha256: String,
}

fn create_private_historical_session(
    work_root: &Path,
) -> std::result::Result<tempfile::TempDir, String> {
    let base = work_root.join("backtest-sessions");
    create_plain_directory_chain(&base)?;
    let session = tempfile::Builder::new()
        .prefix("commit-")
        .tempdir_in(&base)
        .map_err(|_| "BLOCKED: private historical session could not be created".to_string())?;
    ensure_plain_historical_directory(session.path())?;
    set_private_historical_directory(session.path())?;
    Ok(session)
}

fn create_plain_directory_chain(path: &Path) -> std::result::Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "BLOCKED: historical work root could not be resolved".to_string())?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                current.push(component.as_os_str());
            }
            std::path::Component::Normal(value) => {
                current.push(value);
                match std::fs::symlink_metadata(&current) {
                    Ok(_) => ensure_plain_historical_directory(&current)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir(&current).map_err(|_| {
                            "BLOCKED: historical work-root component could not be created"
                                .to_string()
                        })?;
                        ensure_plain_historical_directory(&current)?;
                    }
                    Err(_) => {
                        return Err(
                            "BLOCKED: historical work-root component could not be inspected".into(),
                        )
                    }
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err("BLOCKED: historical work root contains parent traversal".into())
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_historical_directory(path: &Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "BLOCKED: private historical session permissions could not be set".into())
}

#[cfg(not(unix))]
fn set_private_historical_directory(_path: &Path) -> std::result::Result<(), String> {
    Ok(())
}

/// Materialize an exact commit without checkout, archive attributes, filters,
/// hooks, submodules, or platform tar behavior. Only ordinary Git blobs with
/// portable paths and modes are accepted.
fn materialize_commit_worktree(
    repo: &Path,
    sha: &str,
    dest: &Path,
) -> std::result::Result<MaterializedCommit, String> {
    if !(is_lower_hex(sha, 40) || is_lower_hex(sha, 64)) {
        return Err("BLOCKED: historical source is not an exact lowercase commit SHA".into());
    }
    if std::fs::symlink_metadata(dest).is_ok() {
        return Err(format!(
            "BLOCKED: historical materialization destination already exists: {}",
            dest.display()
        ));
    }

    let commit_expression = format!("{sha}^{{commit}}");
    let resolved = historical_git_text(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &commit_expression,
        ],
        HISTORICAL_GIT_MAX_IDENTITY_BYTES,
        "resolve exact commit",
    )?;
    if resolved != sha {
        return Err("BLOCKED: historical source did not resolve to the requested commit".into());
    }
    let tree_expression = format!("{sha}^{{tree}}");
    let tree_oid = historical_git_text(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &tree_expression,
        ],
        HISTORICAL_GIT_MAX_IDENTITY_BYTES,
        "resolve exact commit tree",
    )?;
    if !(is_lower_hex(&tree_oid, 40) || is_lower_hex(&tree_oid, 64)) || tree_oid.len() != sha.len()
    {
        return Err("BLOCKED: historical commit tree has an invalid object identity".into());
    }

    // Validate object hashes and graph integrity before trusting ls-tree or
    // cat-file output. Only this exact commit is supplied as a traversal head;
    // the process is subject to the same output and wall-clock limits.
    run_historical_git_output(
        repo,
        &[
            "fsck",
            "--strict",
            "--no-reflogs",
            "--no-dangling",
            "--no-progress",
            sha,
        ],
        HISTORICAL_GIT_FSCK_MAX_OUTPUT_BYTES,
        "verify exact commit object graph",
    )?;

    let listing = run_historical_git_output(
        repo,
        &["ls-tree", "-r", "-z", "--full-tree", "--long", sha, "--"],
        HISTORICAL_GIT_MAX_INDEX_BYTES,
        "enumerate exact commit tree",
    )?;
    let entries = parse_historical_tree(&listing, sha.len())?;

    let parent = dest
        .parent()
        .ok_or_else(|| "BLOCKED: historical destination has no parent".to_string())?;
    create_plain_directory_chain(parent)?;
    ensure_plain_historical_directory(parent)?;
    std::fs::create_dir(dest)
        .map_err(|_| "BLOCKED: historical destination could not be created".to_string())?;
    ensure_plain_historical_directory(dest)?;

    let source_files = write_historical_blobs(repo, dest, &entries)?;
    let source_tree_sha256 = canonical_sha256(&source_files)
        .map_err(|_| "BLOCKED: historical source identity could not be computed".to_string())?;
    let materialized = MaterializedCommit {
        commit_sha: sha.to_string(),
        tree_oid,
        source_files,
        source_tree_sha256,
    };
    verify_materialized_commit_source(dest, &materialized)?;
    Ok(materialized)
}

fn parse_historical_tree(
    listing: &[u8],
    object_id_length: usize,
) -> std::result::Result<Vec<HistoricalTreeEntry>, String> {
    if !listing.is_empty() && listing.last() != Some(&0) {
        return Err("BLOCKED: historical Git tree listing is not NUL terminated".into());
    }
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    let mut portable_paths = BTreeMap::<String, (String, bool)>::new();
    let mut distinct_entries = BTreeSet::<String>::new();

    for record in listing.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        if entries.len() >= HISTORICAL_SOURCE_MAX_FILES {
            return Err(format!(
                "BLOCKED: historical source exceeds {HISTORICAL_SOURCE_MAX_FILES} files"
            ));
        }
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| "BLOCKED: malformed historical Git tree entry".to_string())?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| "BLOCKED: malformed historical Git tree header".to_string())?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| "BLOCKED: historical source contains a non-UTF-8 path".to_string())?;
        validate_historical_path(path, &mut portable_paths, &mut distinct_entries)?;

        let mut fields = header.split_ascii_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| "BLOCKED: historical Git tree mode is missing".to_string())?;
        let object_type = fields
            .next()
            .ok_or_else(|| "BLOCKED: historical Git tree object type is missing".to_string())?;
        let oid = fields
            .next()
            .ok_or_else(|| "BLOCKED: historical Git tree object ID is missing".to_string())?;
        let size = fields
            .next()
            .ok_or_else(|| "BLOCKED: historical Git tree blob size is missing".to_string())?;
        if fields.next().is_some() {
            return Err("BLOCKED: malformed historical Git tree header".into());
        }
        match mode {
            "120000" => {
                return Err(format!(
                    "BLOCKED: historical source contains a symlink: {path}"
                ))
            }
            "160000" => {
                return Err(format!(
                    "BLOCKED: historical source contains a gitlink/submodule: {path}"
                ))
            }
            "100755" if !cfg!(unix) => {
                return Err(format!(
                    "BLOCKED: executable Git mode 100755 cannot be preserved on this host: {path}"
                ))
            }
            "100644" | "100755" if object_type == "blob" => {}
            _ => {
                return Err(format!(
                    "BLOCKED: historical source contains unsupported mode/type {mode} {object_type}: {path}"
                ))
            }
        }
        if oid.len() != object_id_length || !is_lower_hex(oid, object_id_length) {
            return Err(format!(
                "BLOCKED: historical source blob has an invalid object ID: {path}"
            ));
        }
        let size_bytes = size
            .parse::<u64>()
            .map_err(|_| format!("BLOCKED: historical source blob size is invalid: {path}"))?;
        if size_bytes > HISTORICAL_SOURCE_MAX_FILE_BYTES {
            return Err(format!(
                "BLOCKED: historical source file exceeds {HISTORICAL_SOURCE_MAX_FILE_BYTES} bytes: {path}"
            ));
        }
        total_bytes = total_bytes
            .checked_add(size_bytes)
            .ok_or_else(|| "BLOCKED: historical source byte count overflowed".to_string())?;
        if total_bytes > HISTORICAL_SOURCE_MAX_TOTAL_BYTES {
            return Err(format!(
                "BLOCKED: historical source exceeds {HISTORICAL_SOURCE_MAX_TOTAL_BYTES} bytes"
            ));
        }
        entries.push(HistoricalTreeEntry {
            mode: if mode == "100755" { "100755" } else { "100644" },
            oid: oid.to_string(),
            path: path.to_string(),
            size_bytes,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn validate_historical_path(
    path: &str,
    portable_paths: &mut BTreeMap<String, (String, bool)>,
    distinct_entries: &mut BTreeSet<String>,
) -> std::result::Result<(), String> {
    if path.is_empty()
        || !path.is_ascii()
        || path.len() > HISTORICAL_SOURCE_MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'))
    {
        return Err(format!(
            "BLOCKED: historical source contains an unsafe or non-portable path: {path:?}"
        ));
    }

    let components = path.split('/').collect::<Vec<_>>();
    if components.len() > HISTORICAL_SOURCE_MAX_DEPTH {
        return Err(format!(
            "BLOCKED: historical source path exceeds {HISTORICAL_SOURCE_MAX_DEPTH} components: {path}"
        ));
    }
    let mut prefix = String::new();
    for (index, component) in components.iter().enumerate() {
        if component.is_empty()
            || *component == "."
            || *component == ".."
            || component.len() > HISTORICAL_SOURCE_MAX_COMPONENT_BYTES
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.eq_ignore_ascii_case(".git")
            || is_dos_device_name(component)
        {
            return Err(format!(
                "BLOCKED: historical source contains an unsafe or non-portable path: {path:?}"
            ));
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let is_file = index + 1 == components.len();
        let folded = prefix
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if let Some((original, existing_is_file)) = portable_paths.get(&folded) {
            if original != &prefix || *existing_is_file != is_file {
                return Err(format!(
                    "BLOCKED: historical source contains a case-fold or file/directory collision: {original:?} versus {prefix:?}"
                ));
            }
        } else {
            portable_paths.insert(folded, (prefix.clone(), is_file));
        }
        distinct_entries.insert(prefix.clone());
        if distinct_entries.len() > HISTORICAL_SOURCE_MAX_ENTRIES {
            return Err(format!(
                "BLOCKED: historical source exceeds {HISTORICAL_SOURCE_MAX_ENTRIES} path entries"
            ));
        }
    }
    Ok(())
}

fn is_dos_device_name(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or_default();
    if base
        .strip_suffix(['\u{00b9}', '\u{00b2}', '\u{00b3}'])
        .is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")
        })
    {
        return true;
    }
    let upper = base.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && matches!(upper.as_bytes()[3], b'1'..=b'9')
}

fn write_historical_blobs(
    repo: &Path,
    dest: &Path,
    entries: &[HistoricalTreeEntry],
) -> std::result::Result<Vec<tomorrowci_core::SourceFileEntryV2>, String> {
    let mut requests = Vec::with_capacity(entries.len().saturating_mul(65));
    let mut max_output = 0_u64;
    for entry in entries {
        requests.extend_from_slice(entry.oid.as_bytes());
        requests.push(b'\n');
        max_output = max_output
            .checked_add(entry.size_bytes)
            .and_then(|value| value.checked_add(entry.oid.len() as u64 + 64))
            .ok_or_else(|| "BLOCKED: historical Git blob output cap overflowed".to_string())?;
    }
    let mut command = historical_git_command(repo);
    command.args(["cat-file", "--batch"]);
    let mut output_file = run_bounded_command(
        command,
        Some(&requests),
        max_output.max(1),
        HISTORICAL_GIT_MAX_STDERR_BYTES as u64,
        HISTORICAL_GIT_TIMEOUT,
        "read exact historical Git blobs",
    )?;
    output_file
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|_| "BLOCKED: historical Git blob output could not be opened".to_string())?;
    let mut output = BufReader::new(output_file.as_file_mut());

    let result = (|| {
        let mut source_files = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut header = Vec::new();
            output
                .read_until(b'\n', &mut header)
                .map_err(|_| "BLOCKED: historical Git blob header could not be read".to_string())?;
            if header.len() > 256 || header.last() != Some(&b'\n') {
                return Err("BLOCKED: malformed historical Git blob header".into());
            }
            header.pop();
            let header = std::str::from_utf8(&header)
                .map_err(|_| "BLOCKED: malformed historical Git blob header".to_string())?;
            let mut fields = header.split_ascii_whitespace();
            let returned_oid = fields.next().unwrap_or_default();
            let object_type = fields.next().unwrap_or_default();
            let returned_size = fields.next().and_then(|value| value.parse::<u64>().ok());
            if fields.next().is_some()
                || returned_oid != entry.oid
                || object_type != "blob"
                || returned_size != Some(entry.size_bytes)
            {
                return Err(format!(
                    "BLOCKED: historical Git blob identity mismatch: {}",
                    entry.path
                ));
            }

            let target = dest.join(Path::new(&entry.path));
            let parent = target.parent().ok_or_else(|| {
                "BLOCKED: historical source file has no destination parent".to_string()
            })?;
            create_plain_historical_directories(dest, parent)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|_| {
                    format!(
                        "BLOCKED: historical source file could not be created: {}",
                        entry.path
                    )
                })?;
            let mut digest = Sha256::new();
            let mut remaining = entry.size_bytes;
            let mut buffer = [0_u8; 64 * 1024];
            while remaining > 0 {
                let amount = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| "BLOCKED: historical blob size is invalid".to_string())?;
                output.read_exact(&mut buffer[..amount]).map_err(|_| {
                    format!("BLOCKED: historical Git blob was truncated: {}", entry.path)
                })?;
                file.write_all(&buffer[..amount]).map_err(|_| {
                    format!(
                        "BLOCKED: historical source file could not be written: {}",
                        entry.path
                    )
                })?;
                digest.update(&buffer[..amount]);
                remaining -= amount as u64;
            }
            let mut terminator = [0_u8; 1];
            output.read_exact(&mut terminator).map_err(|_| {
                format!(
                    "BLOCKED: historical Git blob terminator is missing: {}",
                    entry.path
                )
            })?;
            if terminator != *b"\n" {
                return Err(format!(
                    "BLOCKED: historical Git blob terminator is invalid: {}",
                    entry.path
                ));
            }
            file.flush().map_err(|_| {
                format!(
                    "BLOCKED: historical source file could not be flushed: {}",
                    entry.path
                )
            })?;
            drop(file);
            set_historical_executable(&target, entry.mode == "100755")?;
            ensure_plain_historical_file(&target)?;
            source_files.push(tomorrowci_core::SourceFileEntryV2 {
                schema_version: REPLAY_SCHEMA_VERSION_V2,
                path: entry.path.clone(),
                sha256: format!("sha256:{}", hex::encode(digest.finalize())),
                size_bytes: entry.size_bytes,
                executable: entry.mode == "100755",
            });
        }
        let mut trailing = [0_u8; 1];
        if output
            .read(&mut trailing)
            .map_err(|_| "BLOCKED: historical Git blob output could not be finalized".to_string())?
            != 0
        {
            return Err("BLOCKED: historical Git blob reader returned trailing output".into());
        }
        Ok(source_files)
    })();

    drop(output);
    result
}

fn verify_materialized_commit_source(
    root: &Path,
    materialized: &MaterializedCommit,
) -> std::result::Result<(), String> {
    if !(is_lower_hex(&materialized.tree_oid, 40) || is_lower_hex(&materialized.tree_oid, 64))
        || materialized.tree_oid.len() != materialized.commit_sha.len()
    {
        return Err("BLOCKED: historical commit tree identity is invalid".into());
    }
    let (files, tree_sha256) = capture_historical_source(root)?;
    if files != materialized.source_files || tree_sha256 != materialized.source_tree_sha256 {
        return Err(
            "BLOCKED: materialized source bytes or modes differ from exact commit tree".into(),
        );
    }
    Ok(())
}

fn verify_staged_historical_source(
    root: &Path,
    materialized: &MaterializedCommit,
    snapshot: &VerifiedRegistrySnapshot,
) -> std::result::Result<String, String> {
    let reverified = verify_registry_snapshot(
        &snapshot.manifest_path,
        snapshot.manifest.ecosystem,
        Some(snapshot.manifest.effective_at.date_naive()),
        snapshot.binding.file_count,
        snapshot.binding.total_bytes,
    )
    .map_err(|error| format!("BLOCKED: staged snapshot changed before scan: {error}"))?;
    if reverified.binding != snapshot.binding {
        return Err("BLOCKED: staged snapshot binding changed before scan".into());
    }
    let mut expected = materialized.source_files.clone();
    if expected.iter().any(|file| {
        file.path == WORKSPACE_SNAPSHOT_DIR
            || file.path.starts_with(&format!("{WORKSPACE_SNAPSHOT_DIR}/"))
    }) {
        return Err("BLOCKED: exact commit occupies the reserved snapshot path".into());
    }
    expected.extend(expected_snapshot_source_files(&reverified)?);
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    let (actual_files, tree_sha256) = capture_historical_source(root)?;
    if actual_files != expected {
        return Err(
            "BLOCKED: staged historical source differs from exact commit plus snapshot inventory"
                .into(),
        );
    }
    Ok(tree_sha256)
}

fn expected_snapshot_source_files(
    snapshot: &VerifiedRegistrySnapshot,
) -> std::result::Result<Vec<tomorrowci_core::SourceFileEntryV2>, String> {
    let manifest_metadata = std::fs::symlink_metadata(&snapshot.manifest_path)
        .map_err(|_| "BLOCKED: staged snapshot manifest could not be inspected".to_string())?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || runner_reparse_point(&manifest_metadata)
    {
        return Err("BLOCKED: staged snapshot manifest is not a regular file".into());
    }
    let mut files = vec![tomorrowci_core::SourceFileEntryV2 {
        schema_version: REPLAY_SCHEMA_VERSION_V2,
        path: format!("{WORKSPACE_SNAPSHOT_DIR}/{SNAPSHOT_MANIFEST_FILE}"),
        sha256: format!("sha256:{}", snapshot.binding.manifest_sha256),
        size_bytes: manifest_metadata.len(),
        executable: false,
    }];
    for entry in &snapshot.manifest.files {
        if !entry.path.is_ascii() {
            return Err("BLOCKED: staged snapshot contains a non-ASCII portable path".into());
        }
        files.push(tomorrowci_core::SourceFileEntryV2 {
            schema_version: REPLAY_SCHEMA_VERSION_V2,
            path: format!(
                "{WORKSPACE_SNAPSHOT_DIR}/{SNAPSHOT_PAYLOAD_DIR}/{}",
                entry.path
            ),
            sha256: format!("sha256:{}", entry.sha256),
            size_bytes: entry.size,
            executable: false,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn verify_snapshot_source_binding(
    source: &SourceSnapshotManifestV2,
    snapshot: &VerifiedRegistrySnapshot,
) -> Result<()> {
    let prefix = format!("{WORKSPACE_SNAPSHOT_DIR}/");
    let actual = source
        .files
        .iter()
        .filter(|file| file.path.starts_with(&prefix))
        .cloned()
        .collect::<Vec<_>>();
    let expected = expected_snapshot_source_files(snapshot).map_err(RunnerError::Msg)?;
    if actual != expected {
        return Err(RunnerError::Msg(
            "backtest run source snapshot does not match the embedded registry snapshot".into(),
        ));
    }
    Ok(())
}

fn valid_historical_git_source_binding(
    binding: &HistoricalGitSourceBinding,
    expected_commit_sha: &str,
    source: &SourceSnapshotManifestV2,
) -> bool {
    let prefix = format!("{WORKSPACE_SNAPSHOT_DIR}/");
    let commit_files = source
        .files
        .iter()
        .filter(|file| !file.path.starts_with(&prefix))
        .cloned()
        .collect::<Vec<_>>();
    binding.schema_version == HISTORICAL_GIT_SOURCE_BINDING_SCHEMA_VERSION
        && binding.source_commit_sha == expected_commit_sha
        && binding.source_git_tree_oid.len() == expected_commit_sha.len()
        && (is_lower_hex(&binding.source_git_tree_oid, 40)
            || is_lower_hex(&binding.source_git_tree_oid, 64))
        && is_sha256_identity(&binding.commit_source_manifest_sha256)
        && canonical_sha256(&commit_files)
            .is_ok_and(|identity| identity == binding.commit_source_manifest_sha256)
}

fn capture_historical_source(
    root: &Path,
) -> std::result::Result<(Vec<tomorrowci_core::SourceFileEntryV2>, String), String> {
    let manifest = capture_source_snapshot_v2(
        &RunId("historical-source-verification".into()),
        root,
        "historical-source-verification",
        None,
        SourceIdentityKindV2::NonGit,
        false,
        Utc::now(),
    )
    .map_err(|error| format!("BLOCKED: historical source verification failed: {error}"))?;
    Ok((manifest.files, manifest.tree_sha256))
}

fn create_plain_historical_directories(
    root: &Path,
    directory: &Path,
) -> std::result::Result<(), String> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| "BLOCKED: historical destination escaped its root".to_string())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err("BLOCKED: historical destination path is unsafe".into());
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(_) => ensure_plain_historical_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|_| {
                    "BLOCKED: historical destination directory could not be created".to_string()
                })?;
                ensure_plain_historical_directory(&current)?;
            }
            Err(_) => {
                return Err(
                    "BLOCKED: historical destination directory could not be inspected".into(),
                )
            }
        }
    }
    Ok(())
}

fn ensure_plain_historical_directory(path: &Path) -> std::result::Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "BLOCKED: historical destination could not be inspected".to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || runner_reparse_point(&metadata) {
        return Err("BLOCKED: historical destination is not a plain directory".into());
    }
    Ok(())
}

fn ensure_plain_historical_file(path: &Path) -> std::result::Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "BLOCKED: historical source file could not be inspected".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || runner_reparse_point(&metadata) {
        return Err("BLOCKED: historical source did not materialize as a regular file".into());
    }
    Ok(())
}

#[cfg(unix)]
fn set_historical_executable(path: &Path, executable: bool) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| "BLOCKED: historical source mode could not be applied".to_string())
}

#[cfg(not(unix))]
fn set_historical_executable(_path: &Path, _executable: bool) -> std::result::Result<(), String> {
    Ok(())
}

fn historical_git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    for name in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_SSL_NO_VERIFY",
        "GIT_TEMPLATE_DIR",
        "GIT_TRACE",
        "GIT_TRACE2",
        "GIT_TRACE2_EVENT",
        "GIT_TRACE2_PERF",
        "GIT_TRACE_CURL",
        "GIT_TRACE_PACKET",
        "GIT_TRACE_PERFORMANCE",
        "GIT_TRACE_SETUP",
        "GIT_WORK_TREE",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "NETRC",
        "SSH_ASKPASS",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(name);
    }
    for index in 0..64 {
        command.env_remove(format!("GIT_CONFIG_KEY_{index}"));
        command.env_remove(format!("GIT_CONFIG_VALUE_{index}"));
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", historical_null_device())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GCM_INTERACTIVE", "Never")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .current_dir(repo)
        .arg("--no-replace-objects")
        .args(["-c", "credential.helper="])
        .args(["-c", "core.askPass="])
        .arg("-c")
        .arg(format!("core.hooksPath={}", historical_null_device()))
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .arg("-c")
        .arg(format!("fsck.skipList={}", historical_null_device()))
        .args(["-c", "filter.lfs.smudge="])
        .args(["-c", "filter.lfs.required=false"])
        .args(["-c", "protocol.ext.allow=never"])
        .args(["-c", "protocol.file.allow=never"]);
    command
}

fn run_historical_git_output(
    repo: &Path,
    args: &[&str],
    max_stdout: usize,
    operation: &str,
) -> std::result::Result<Vec<u8>, String> {
    let mut command = historical_git_command(repo);
    command.args(args);
    let mut output = run_bounded_command(
        command,
        None,
        max_stdout as u64,
        HISTORICAL_GIT_MAX_STDERR_BYTES as u64,
        HISTORICAL_GIT_TIMEOUT,
        operation,
    )?;
    let mut bytes = Vec::new();
    output
        .as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .and_then(|_| output.as_file_mut().read_to_end(&mut bytes))
        .map_err(|_| format!("BLOCKED: historical Git output could not be read for {operation}"))?;
    Ok(bytes)
}

fn run_bounded_command(
    mut command: Command,
    input: Option<&[u8]>,
    max_stdout: u64,
    max_stderr: u64,
    timeout: Duration,
    operation: &str,
) -> std::result::Result<tempfile::NamedTempFile, String> {
    if timeout.is_zero() || max_stdout == 0 || max_stderr == 0 {
        return Err(format!("BLOCKED: invalid process limits for {operation}"));
    }
    let stdout = tempfile::NamedTempFile::new()
        .map_err(|_| format!("BLOCKED: output file could not be created for {operation}"))?;
    let stderr = tempfile::NamedTempFile::new()
        .map_err(|_| format!("BLOCKED: error file could not be created for {operation}"))?;
    let stdout_writer = stdout
        .reopen()
        .map_err(|_| format!("BLOCKED: output file could not be opened for {operation}"))?;
    let stderr_writer = stderr
        .reopen()
        .map_err(|_| format!("BLOCKED: error file could not be opened for {operation}"))?;
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::from(stdout_writer))
        .stderr(Stdio::from(stderr_writer));
    let mut child = command
        .spawn()
        .map_err(|_| format!("BLOCKED: process could not start for {operation}"))?;
    if let Some(bytes) = input {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| format!("BLOCKED: process input unavailable for {operation}"))
            .and_then(|mut stdin| {
                stdin
                    .write_all(bytes)
                    .map_err(|_| format!("BLOCKED: process input failed for {operation}"))
            });
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }

    let started = Instant::now();
    loop {
        let stdout_size = stdout
            .as_file()
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(max_stdout + 1);
        let stderr_size = stderr
            .as_file()
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(max_stderr + 1);
        if stdout_size > max_stdout || stderr_size > max_stderr {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "BLOCKED: process output exceeded cap for {operation}"
            ));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "BLOCKED: process timed out while attempting to {operation}"
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(format!("BLOCKED: process failed to {operation}"));
                }
                // Recheck after process handles have closed and all bytes are visible.
                let stdout_size = stdout
                    .as_file()
                    .metadata()
                    .map_err(|_| format!("BLOCKED: output unavailable for {operation}"))?
                    .len();
                let stderr_size = stderr
                    .as_file()
                    .metadata()
                    .map_err(|_| format!("BLOCKED: errors unavailable for {operation}"))?
                    .len();
                if stdout_size > max_stdout || stderr_size > max_stderr {
                    return Err(format!(
                        "BLOCKED: process output exceeded cap for {operation}"
                    ));
                }
                return Ok(stdout);
            }
            Ok(None) => std::thread::sleep(HISTORICAL_GIT_POLL_INTERVAL),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("BLOCKED: process status failed for {operation}"));
            }
        }
    }
}

fn historical_git_text(
    repo: &Path,
    args: &[&str],
    max_stdout: usize,
    operation: &str,
) -> std::result::Result<String, String> {
    let output = run_historical_git_output(repo, args, max_stdout, operation)?;
    let text = std::str::from_utf8(&output)
        .map_err(|_| format!("BLOCKED: historical Git returned invalid text for {operation}"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty()
        || text.contains('\n')
        || text.contains('\r')
        || text.chars().any(char::is_control)
    {
        return Err(format!(
            "BLOCKED: historical Git returned an invalid identity for {operation}"
        ));
    }
    Ok(text.to_string())
}

#[cfg(windows)]
fn historical_null_device() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn historical_null_device() -> &'static str {
    "/dev/null"
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

    #[tokio::test]
    async fn backtest_without_snapshot_is_inconclusive_before_engine_lookup() {
        let root = tempdir().unwrap();
        let repository = root.path().join("repository");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::write(repository.join("requirements.txt"), b"\n").unwrap();
        for args in [vec!["init"], vec!["add", "."]] {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(&repository)
                .output()
                .unwrap();
            assert!(output.status.success());
        }
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=TomorrowCI Test",
                "-c",
                "user.email=tomorrowci@example.invalid",
                "commit",
                "-m",
                "fixture",
            ])
            .env("GIT_AUTHOR_DATE", "2026-01-15T12:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-15T12:00:00Z")
            .current_dir(&repository)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let date = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let report = backtest_repo(
            BacktestRequest {
                target: repository.display().to_string(),
                at: date,
                until: date,
                max_commits: 1,
                max_scenarios_per_point: 1,
                snapshot_registry: None,
                max_snapshot_files: 2,
                max_snapshot_bytes: 1024,
            },
            root.path().join("evidence"),
            root.path().join("work"),
        )
        .await
        .unwrap();
        assert_eq!(report.points.len(), 1);
        assert_eq!(report.points[0].status, BacktestPointStatus::Inconclusive);
        assert!(report.points[0].run_id.is_none());
        assert!(!report.is_green());
    }

    #[test]
    fn staged_snapshot_survives_disposable_workspace_materialization() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        std::fs::create_dir_all(&source).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/backtest-snapshots/python/2026-01-15/snapshot-manifest.json");
        let verified = verify_registry_snapshot(
            &fixture,
            Ecosystem::Python,
            Some(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap()),
            16,
            1024 * 1024,
        )
        .unwrap();
        stage_verified_snapshot(
            &verified,
            &source,
            NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            16,
            1024 * 1024,
        )
        .unwrap();

        materialize_workspace(&source, &destination).unwrap();
        let copied =
            tomorrowci_core::backtest::workspace_registry_snapshot(&destination, Ecosystem::Python)
                .unwrap()
                .expect("staged snapshot was excluded from disposable workspace");
        assert_eq!(copied.binding.snapshot_id, verified.binding.snapshot_id);
    }

    #[test]
    fn detached_backtest_proof_is_strict_and_bound_to_its_seal() {
        let root = tempdir().unwrap();
        let directory = root.path().join("proof");
        std::fs::create_dir_all(&directory).unwrap();
        let source_committed_at = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let proof = BacktestProof {
            schema_version: BACKTEST_PROOF_SCHEMA_VERSION,
            created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T15:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            source: "https://example.invalid/repository".into(),
            source_commit_sha: "a".repeat(40),
            source_committed_at,
            snapshot: tomorrowci_core::backtest::RegistrySnapshotBinding {
                snapshot_id: format!("sha256:{}", "b".repeat(64)),
                manifest_sha256: "c".repeat(64),
                ecosystem: Ecosystem::Python,
                effective_at: source_committed_at,
                captured_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T13:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                source: tomorrowci_core::backtest::RegistrySnapshotSource {
                    url: "https://pypi.org/simple/".into(),
                    immutable_revision: format!("sha256:{}", "d".repeat(64)),
                },
                resolver_mode: tomorrowci_core::backtest::RegistryResolverMode::PythonWheelhouse,
                file_count: 1,
                total_bytes: 1,
            },
            source_manifest_sha256: format!("sha256:{}", "2".repeat(64)),
            normalized_config_sha256: "e".repeat(64),
            run_manifest_sha256: format!("sha256:{}", "3".repeat(64)),
            verdicts_sha256: format!("sha256:{}", "4".repeat(64)),
            frontier_sha256: format!("sha256:{}", "5".repeat(64)),
            outcome: BacktestProofOutcome::Qualified,
            runtime_images: vec![BacktestRuntimeImage {
                image_ref: "python:3.12-bookworm".into(),
                image_digest: format!("sha256:{}", "f".repeat(64)),
            }],
            run_id: "0123456789ab".into(),
            sealed_run_inventory_sha256: "1".repeat(64),
        };
        std::fs::write(
            directory.join("backtest-proof.json"),
            serde_json::to_vec_pretty(&proof).unwrap(),
        )
        .unwrap();
        tomorrowci_evidence::seal_bundle(&directory, tomorrowci_evidence::BundleKind::Generic)
            .unwrap();
        let verified = tomorrowci_evidence::verify_bundle(&directory).unwrap();
        let reference = BacktestProofReference {
            directory,
            proof_sha256: canonical_proof_sha256(&proof).unwrap(),
            sealed_inventory_sha256: verified.inventory_sha256().unwrap(),
        };
        let error = verify_backtest_proof(&reference).unwrap_err().to_string();
        assert!(error.contains("missing required witness"), "{error}");
        let mut wrong = reference;
        wrong.proof_sha256 = "0".repeat(64);
        assert!(verify_backtest_proof(&wrong).is_err());
    }

    #[test]
    fn target_resolution_never_treats_disallowed_remote_syntax_as_local() {
        let root = tempdir().unwrap();
        for target in [
            "http://github.com/owner/repo",
            "ssh://github.com/owner/repo",
            "git@github.com:owner/repo",
            "https://github.com/owner/repo/extra",
            "https://github.com/owner/repo?ref=main",
        ] {
            let clone_dir = root.path().join("clone");
            let error = resolve_target(target, &clone_dir).unwrap_err().to_string();
            assert!(error.starts_with("BLOCKED:"), "unexpected error: {error}");
            assert!(!clone_dir.exists());
        }
    }

    #[test]
    fn doctor_uses_the_platform_npm_launcher() {
        let expected = if cfg!(windows) { "npm.cmd" } else { "npm" };
        assert_eq!(command_program("npm"), expected);
        assert_eq!(command_program("node"), "node");
    }

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
    async fn replay_rejects_self_resealed_v1_bundle_before_engine_lookup() {
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
            error.contains("public replay requires a sealed v2 origin"),
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
    fn recorded_execution_reapplies_adapter_safety_before_sandbox_use() {
        let mut environment = exact_test_environment();
        environment.mounts.clear();
        let command = tomorrowci_core::CommandSpec {
            phase: tomorrowci_core::CommandPhase::Test,
            program: "python".into(),
            args: vec!["-m".into(), "pytest".into()],
            workdir: "/workspace/project".into(),
            network_required: false,
            env: Default::default(),
        };
        validate_recorded_execution(&environment, std::slice::from_ref(&command)).unwrap();

        let mut full_network = environment.clone();
        full_network.network_mode = tomorrowci_core::NetworkMode::Full;
        assert!(
            validate_recorded_execution(&full_network, std::slice::from_ref(&command))
                .unwrap_err()
                .starts_with("BLOCKED:")
        );

        let mut mounted = environment.clone();
        mounted.mounts.push(tomorrowci_core::MountSpec {
            host_path: PathBuf::from("attacker-controlled"),
            container_path: "/host".into(),
            read_only: false,
        });
        assert!(validate_recorded_execution(&mounted, std::slice::from_ref(&command)).is_err());

        let mut secret = command.clone();
        secret.env.insert("API_TOKEN".into(), "secret".into());
        assert!(validate_recorded_execution(&environment, &[secret]).is_err());

        let mut shell = command;
        shell.program = "sh".into();
        shell.args = vec!["-c".into(), "hostile".into()];
        assert!(validate_recorded_execution(&environment, &[shell]).is_err());
    }

    #[test]
    fn configured_network_is_applied_as_a_non_expanding_upper_bound() {
        assert_eq!(
            effective_network_mode(tomorrowci_core::NetworkMode::FetchOnly, "none").unwrap(),
            tomorrowci_core::NetworkMode::None
        );
        assert_eq!(
            effective_network_mode(tomorrowci_core::NetworkMode::None, "fetch-only").unwrap(),
            tomorrowci_core::NetworkMode::None
        );
        assert_eq!(
            effective_network_mode(tomorrowci_core::NetworkMode::FetchOnly, "full").unwrap(),
            tomorrowci_core::NetworkMode::FetchOnly
        );
        assert!(effective_network_mode(tomorrowci_core::NetworkMode::Full, "full").is_err());
        assert!(
            effective_network_mode(tomorrowci_core::NetworkMode::FetchOnly, "forged")
                .unwrap_err()
                .starts_with("BLOCKED:")
        );
    }

    #[test]
    fn forged_recorded_fetch_cannot_bypass_environment_none() {
        let mut environment = exact_test_environment();
        environment.mounts.clear();
        let command = tomorrowci_core::CommandSpec {
            phase: tomorrowci_core::CommandPhase::Fetch,
            program: "python".into(),
            args: vec!["-m".into(), "pip".into(), "install".into()],
            workdir: "/workspace/project".into(),
            network_required: true,
            env: Default::default(),
        };
        let error = validate_recorded_execution(&environment, &[command]).unwrap_err();
        assert!(error.contains("unsafe recorded network policy"), "{error}");
    }

    #[test]
    fn forged_backtest_receipt_cannot_claim_offline_qualification() {
        let scenario = exact_test_scenario();
        let mut environment = exact_test_environment();
        environment.mounts.clear();
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
            duration_ms: 1,
            timed_out: false,
            network_used: false,
            error: None,
        };
        let result = build_execution_result(&scenario, 1, &environment, &commands, &raw);
        let engine = EngineInfo {
            kind: tomorrowci_sandbox::EngineKind::Docker,
            path: PathBuf::from("docker"),
            version: "test".into(),
        };
        let context = ReplayContextV2 {
            run_id: RunId("0123456789ab".into()),
            source_manifest_sha256: format!("sha256:{}", "b".repeat(64)),
            config_sha256: format!("sha256:{}", "c".repeat(64)),
        };
        let manifest = build_exact_replay_manifest_v2(
            &context,
            &scenario,
            &environment,
            &commands,
            &engine,
            Utc::now(),
        )
        .unwrap();
        let executed = ExecutedAttempt {
            provenance: AttemptProvenance {
                ordinal: 1,
                kind: AttemptKindV2::Original,
                started_at: Utc::now(),
                finished_at: Utc::now(),
                engine_kind: "docker".into(),
                engine_version: "test".into(),
            },
            completed: CompletedAttempt {
                environment,
                commands,
                raw,
                result,
                signature: None,
                passed: true,
            },
        };
        let receipt = attempt_evidence_v2(&context, &scenario, &manifest, &executed)
            .unwrap()
            .attempt;
        ensure_backtest_attempt_strictly_offline(&receipt).unwrap();

        let mut forged_result = receipt.clone();
        forged_result.result.network_used = true;
        assert!(ensure_backtest_attempt_strictly_offline(&forged_result).is_err());

        let mut forged_environment = receipt.clone();
        forged_environment.environment.network_mode = tomorrowci_core::NetworkMode::FetchOnly;
        assert!(ensure_backtest_attempt_strictly_offline(&forged_environment).is_err());

        let mut forged_command = receipt;
        forged_command.commands[0].network_required = true;
        assert!(ensure_backtest_attempt_strictly_offline(&forged_command).is_err());
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
    fn disposable_attempts_use_private_system_roots_and_leave_source_parent_exact() {
        let root = tempdir().unwrap();
        let source = root.path().join("recorded-workspace");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("state.txt"), "recorded").unwrap();
        let parent_entries_before = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        let first_path;
        {
            let first = disposable_workspace(&source).unwrap();
            first_path = first.path().to_path_buf();
            assert!(!first.path().starts_with(root.path()));
            assert_eq!(first.path(), first._private_root.path().join("workspace"));
            assert!(first._private_root.path().is_dir());
            let parent_entries_during = std::fs::read_dir(root.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(parent_entries_during, parent_entries_before);
            assert_eq!(
                std::fs::read_to_string(first.path().join("state.txt")).unwrap(),
                "recorded"
            );
            std::fs::write(first.path().join("state.txt"), "mutated").unwrap();
        }
        assert!(!first_path.exists());
        let parent_entries_after = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(parent_entries_after, parent_entries_before);
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
    fn original_rerun_series_shares_state_but_fresh_replay_does_not() {
        let root = tempdir().unwrap();
        let recorded = root.path().join("recorded-workspace");
        std::fs::create_dir_all(&recorded).unwrap();
        std::fs::write(recorded.join("source.txt"), "recorded").unwrap();

        let original_series = disposable_workspace(&recorded).unwrap();
        let counter = original_series.path().join("rerun-counter");
        std::fs::write(&counter, "1").unwrap();

        // A later original rerun executes in this same isolated workspace and
        // can therefore expose state-dependent flakiness.
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "1");
        std::fs::write(&counter, "2").unwrap();
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "2");

        // The sealed recording is not mutated, and qualification/public
        // replays still start from independent copies of that recording.
        assert!(!recorded.join("rerun-counter").exists());
        let replay = disposable_workspace(&recorded).unwrap();
        assert!(!replay.path().join("rerun-counter").exists());
        assert_eq!(
            std::fs::read_to_string(replay.path().join("source.txt")).unwrap(),
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
        assert!(replay_summary("run", "scenario", &raw, "receipt").is_ok());

        raw.exit_code = Some(7);
        assert!(replay_summary("run", "scenario", &raw, "receipt")
            .unwrap_err()
            .to_string()
            .starts_with("REPLAY_FAILED:"));
        raw.exit_code = Some(0);
        raw.timed_out = true;
        assert!(replay_summary("run", "scenario", &raw, "receipt").is_err());
        raw.timed_out = false;
        raw.error = Some("engine lost target process".into());
        assert!(replay_summary("run", "scenario", &raw, "receipt").is_err());
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

#[cfg(test)]
mod historical_source_tests {
    use super::*;
    use std::process::Stdio;
    use tempfile::tempdir;

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn init_repo(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "core.autocrlf", "false"]);
        git(root, &["config", "user.name", "TomorrowCI Test"]);
        git(
            root,
            &["config", "user.email", "tomorrowci@example.invalid"],
        );
    }

    fn commit_all(repo: &Path, message: &str) -> String {
        git(repo, &["add", "--all"]);
        git(repo, &["commit", "-q", "-m", message]);
        git(repo, &["rev-parse", "HEAD"])
    }

    fn write_git_stdin(repo: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn hash_blob(repo: &Path, bytes: &[u8]) -> String {
        String::from_utf8(write_git_stdin(
            repo,
            &["hash-object", "-w", "--stdin"],
            bytes,
        ))
        .unwrap()
        .trim()
        .to_string()
    }

    fn commit_tree(repo: &Path, records: &[u8]) -> String {
        let tree = String::from_utf8(write_git_stdin(repo, &["mktree", "-z"], records))
            .unwrap()
            .trim()
            .to_string();
        git(repo, &["commit-tree", &tree, "-m", "synthetic tree"])
    }

    fn tree_record(mode: &str, object_type: &str, oid: &str, path: &[u8]) -> Vec<u8> {
        let mut record = format!("{mode} {object_type} {oid}\t").into_bytes();
        record.extend_from_slice(path);
        record.push(0);
        record
    }

    #[test]
    fn plumbing_ignores_export_attributes_and_replace_refs() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(
            repo.join(".gitattributes"),
            b"ignored.txt export-ignore\nsubst.txt export-subst\n",
        )
        .unwrap();
        std::fs::write(repo.join("ignored.txt"), b"must remain\n").unwrap();
        std::fs::write(repo.join("subst.txt"), b"$Format:%H$\n").unwrap();
        let first = commit_all(&repo, "exact source");

        std::fs::write(repo.join("ignored.txt"), b"replacement bytes\n").unwrap();
        let replacement = commit_all(&repo, "replacement");
        git(&repo, &["replace", &first, &replacement]);

        let destination = root.path().join("materialized");
        let binding = materialize_commit_worktree(&repo, &first, &destination).unwrap();
        assert_eq!(binding.commit_sha, first);
        assert!(is_lower_hex(&binding.tree_oid, first.len()));
        assert_eq!(
            std::fs::read(destination.join("ignored.txt")).unwrap(),
            b"must remain\n"
        );
        assert_eq!(
            std::fs::read(destination.join("subst.txt")).unwrap(),
            b"$Format:%H$\n"
        );
        verify_materialized_commit_source(&destination, &binding).unwrap();
    }

    #[test]
    fn symlink_and_gitlink_modes_are_rejected_before_writing() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("base.txt"), b"base").unwrap();
        let base_commit = commit_all(&repo, "base");
        let blob = hash_blob(&repo, b"target");

        let symlink_commit = commit_tree(&repo, &tree_record("120000", "blob", &blob, b"link"));
        let error = materialize_commit_worktree(
            &repo,
            &symlink_commit,
            &root.path().join("symlink-output"),
        )
        .unwrap_err();
        assert!(error.contains("symlink"), "{error}");

        let gitlink_commit = commit_tree(
            &repo,
            &tree_record("160000", "commit", &base_commit, b"dependency"),
        );
        let error = materialize_commit_worktree(
            &repo,
            &gitlink_commit,
            &root.path().join("gitlink-output"),
        )
        .unwrap_err();
        assert!(error.contains("gitlink/submodule"), "{error}");
    }

    #[test]
    fn non_utf8_dos_trailing_and_case_fold_paths_are_rejected() {
        let oid = "a".repeat(40);
        let listing = |path: &[u8]| {
            let mut bytes = format!("100644 blob {oid} 1\t").into_bytes();
            bytes.extend_from_slice(path);
            bytes.push(0);
            bytes
        };
        assert!(parse_historical_tree(&listing(b"bad\xffname"), 40)
            .unwrap_err()
            .contains("non-UTF-8"));
        for path in ["CON.txt", "directory/trailing. ", "bad:name"] {
            assert!(parse_historical_tree(&listing(path.as_bytes()), 40)
                .unwrap_err()
                .contains("path"));
        }

        let mut collision = listing(b"Readme");
        collision.extend_from_slice(&listing(b"README"));
        assert!(parse_historical_tree(&collision, 40)
            .unwrap_err()
            .contains("case-fold"));
        assert!(parse_historical_tree(&listing("σ.txt".as_bytes()), 40)
            .unwrap_err()
            .contains("path"));
        assert!(is_dos_device_name("cOm\u{00b9}.txt"));
    }

    #[cfg(not(unix))]
    #[test]
    fn executable_git_mode_fails_closed_when_host_cannot_preserve_it() {
        let oid = "c".repeat(40);
        let listing = format!("100755 blob {oid} 0\tscript\0");
        assert!(parse_historical_tree(listing.as_bytes(), 40)
            .unwrap_err()
            .contains("cannot be preserved"));
    }

    #[cfg(not(unix))]
    #[test]
    fn local_scan_rejects_real_git_executable_mode_on_non_unix() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("script"), b"echo exact\n").unwrap();
        git(&repo, &["add", "--", "script"]);
        git(&repo, &["update-index", "--chmod=+x", "--", "script"]);
        git(&repo, &["commit", "-q", "-m", "executable"]);
        let index = write_git_stdin(&repo, &["ls-files", "--stage", "-z"], b"");
        assert!(index.starts_with(b"100755 "));

        let error = inspect_local_git_source(&repo).unwrap_err().to_string();
        assert!(error.contains("100755 cannot be preserved"), "{error}");
    }

    #[test]
    fn local_git_status_disables_repository_fsmonitor_hook() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("tracked.txt"), b"exact\n").unwrap();
        let commit = commit_all(&repo, "fixture");
        let sentinel = root.path().join("fsmonitor-invoked");

        #[cfg(unix)]
        let hook = {
            use std::os::unix::fs::PermissionsExt;
            let hook = root.path().join("fsmonitor-probe");
            std::fs::write(
                &hook,
                format!(
                    "#!/bin/sh\nprintf invoked > '{}'\nexit 0\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
            hook
        };
        #[cfg(windows)]
        let hook = {
            let hook = root.path().join("fsmonitor-probe.cmd");
            std::fs::write(
                &hook,
                format!(
                    "@echo off\r\n>\"{}\" echo invoked\r\nexit /b 0\r\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            hook
        };
        let hook_config = hook.to_string_lossy().replace('\\', "/");
        git(&repo, &["config", "core.fsmonitor", &hook_config]);
        let baseline = Command::new("git")
            .args(["status", "--porcelain=v1"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(baseline.status.success());
        assert!(
            sentinel.is_file(),
            "real Git did not exercise the fsmonitor fixture"
        );
        std::fs::remove_file(&sentinel).unwrap();

        let (actual, dirty) = inspect_local_git_source(&repo).unwrap();
        assert_eq!(actual.as_deref(), Some(commit.as_str()));
        assert!(!dirty);
        assert!(
            !sentinel.exists(),
            "isolated local Git inspection executed repository fsmonitor"
        );
    }

    #[test]
    fn local_git_status_rejects_repository_content_filter_before_execution() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join(".gitattributes"), b"tracked.txt filter=probe\n").unwrap();
        std::fs::write(repo.join("tracked.txt"), b"exact\n").unwrap();
        commit_all(&repo, "fixture");
        let sentinel = root.path().join("filter-invoked");

        #[cfg(unix)]
        let filter = {
            use std::os::unix::fs::PermissionsExt;
            let filter = root.path().join("filter-probe");
            std::fs::write(
                &filter,
                format!(
                    "#!/bin/sh\nprintf invoked > '{}'\ncat\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&filter, std::fs::Permissions::from_mode(0o700)).unwrap();
            filter
        };
        #[cfg(windows)]
        let filter = {
            let filter = root.path().join("filter-probe.cmd");
            std::fs::write(
                &filter,
                format!(
                    "@echo off\r\n>\"{}\" echo invoked\r\nmore\r\n",
                    sentinel.display()
                ),
            )
            .unwrap();
            filter
        };
        let filter_config = filter.to_string_lossy().replace('\\', "/");
        git(&repo, &["config", "filter.probe.clean", &filter_config]);

        let error = inspect_local_git_source(&repo).unwrap_err().to_string();
        assert!(error.contains("executable content filter"), "{error}");
        assert!(
            !sentinel.exists(),
            "isolated local Git inspection executed repository content filter"
        );
    }

    #[test]
    fn local_git_status_ignores_replace_refs() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("tracked.txt"), b"first\n").unwrap();
        let first = commit_all(&repo, "first");
        std::fs::write(repo.join("tracked.txt"), b"replacement\n").unwrap();
        let replacement = commit_all(&repo, "replacement");
        git(&repo, &["replace", &first, &replacement]);
        git(&repo, &["--no-replace-objects", "reset", "--hard", &first]);

        let ambient = Command::new("git")
            .args(["status", "--porcelain=v1"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(ambient.status.success());
        assert!(
            !ambient.stdout.is_empty(),
            "real Git did not exercise the replace-ref fixture"
        );

        let (actual, dirty) = inspect_local_git_source(&repo).unwrap();
        assert_eq!(actual.as_deref(), Some(first.as_str()));
        assert!(!dirty);
    }

    #[test]
    fn file_count_per_file_and_total_caps_fail_closed() {
        let oid = "b".repeat(40);
        let oversized = format!(
            "100644 blob {oid} {}\tlarge.bin\0",
            HISTORICAL_SOURCE_MAX_FILE_BYTES + 1
        );
        assert!(parse_historical_tree(oversized.as_bytes(), 40)
            .unwrap_err()
            .contains("file exceeds"));

        let each = HISTORICAL_SOURCE_MAX_FILE_BYTES;
        let mut total = Vec::new();
        for index in 0..=(HISTORICAL_SOURCE_MAX_TOTAL_BYTES / each) {
            total.extend_from_slice(format!("100644 blob {oid} {each}\tf{index:04}\0").as_bytes());
        }
        assert!(parse_historical_tree(&total, 40)
            .unwrap_err()
            .contains("source exceeds"));

        let mut files = Vec::new();
        for index in 0..=HISTORICAL_SOURCE_MAX_FILES {
            files.extend_from_slice(format!("100644 blob {oid} 0\tf{index:05}\0").as_bytes());
        }
        assert!(parse_historical_tree(&files, 40)
            .unwrap_err()
            .contains("files"));
    }

    #[test]
    fn commit_files_must_remain_exact_and_only_reserved_snapshot_bytes_may_be_added() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("source.txt"), b"pinned bytes\n").unwrap();
        let commit = commit_all(&repo, "pinned");
        let destination = root.path().join("materialized");
        let binding = materialize_commit_worktree(&repo, &commit, &destination).unwrap();

        std::fs::write(destination.join("source.txt"), b"mutated\n").unwrap();
        assert!(verify_materialized_commit_source(&destination, &binding)
            .unwrap_err()
            .contains("differ"));
        std::fs::write(destination.join("source.txt"), b"pinned bytes\n").unwrap();

        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/backtest-snapshots/python/2026-01-15/snapshot-manifest.json");
        let verified = verify_registry_snapshot(
            &fixture,
            Ecosystem::Python,
            Some(NaiveDate::from_ymd_opt(2026, 1, 15).unwrap()),
            16,
            1024 * 1024,
        )
        .unwrap();
        let staged = stage_verified_snapshot(
            &verified,
            &destination,
            NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            16,
            1024 * 1024,
        )
        .unwrap();
        let staged_identity =
            verify_staged_historical_source(&destination, &binding, &staged).unwrap();
        assert!(is_sha256_identity(&staged_identity));

        let source_manifest = capture_source_snapshot_v2(
            &RunId("snapshot-cross-binding".into()),
            &destination,
            "fixture",
            Some(commit.clone()),
            SourceIdentityKindV2::DirtyWorktree,
            true,
            Utc::now(),
        )
        .unwrap();
        verify_snapshot_source_binding(&source_manifest, &staged).unwrap();
        let git_binding = HistoricalGitSourceBinding {
            schema_version: HISTORICAL_GIT_SOURCE_BINDING_SCHEMA_VERSION,
            source_commit_sha: commit.clone(),
            source_git_tree_oid: binding.tree_oid.clone(),
            commit_source_manifest_sha256: binding.source_tree_sha256.clone(),
        };
        assert!(valid_historical_git_source_binding(
            &git_binding,
            &commit,
            &source_manifest
        ));

        let payload = destination
            .join(WORKSPACE_SNAPSHOT_DIR)
            .join(SNAPSHOT_PAYLOAD_DIR)
            .join(&staged.manifest.files[0].path);
        let original_payload = std::fs::read(&payload).unwrap();
        std::fs::write(&payload, b"mutated snapshot bytes").unwrap();
        assert!(
            verify_staged_historical_source(&destination, &binding, &staged)
                .unwrap_err()
                .contains("snapshot changed")
        );
        std::fs::write(&payload, original_payload).unwrap();

        std::fs::write(destination.join("outside.txt"), b"unexpected\n").unwrap();
        assert!(
            verify_staged_historical_source(&destination, &binding, &staged)
                .unwrap_err()
                .contains("differs")
        );
    }

    #[test]
    fn destination_must_not_preexist() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("file.txt"), b"data").unwrap();
        let commit = commit_all(&repo, "fixture");
        let destination = root.path().join("existing");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("sentinel"), b"preserve").unwrap();
        assert!(materialize_commit_worktree(&repo, &commit, &destination)
            .unwrap_err()
            .contains("already exists"));
        assert_eq!(
            std::fs::read(destination.join("sentinel")).unwrap(),
            b"preserve"
        );
    }

    #[test]
    fn commit_enumeration_ignores_replace_ref_timestamps() {
        let root = tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("file.txt"), b"first").unwrap();
        git(&repo, &["add", "--all"]);
        let output = Command::new("git")
            .args(["commit", "-q", "-m", "dated"])
            .env("GIT_AUTHOR_DATE", "2026-01-15T12:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-15T12:00:00Z")
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(output.status.success());
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        let replacement = Command::new("git")
            .args(["commit-tree", &tree, "-m", "replacement"])
            .env("GIT_AUTHOR_NAME", "TomorrowCI Test")
            .env("GIT_AUTHOR_EMAIL", "tomorrowci@example.invalid")
            .env("GIT_COMMITTER_NAME", "TomorrowCI Test")
            .env("GIT_COMMITTER_EMAIL", "tomorrowci@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-02-20T12:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-02-20T12:00:00Z")
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(replacement.status.success());
        let replacement = String::from_utf8(replacement.stdout).unwrap();
        git(&repo, &["replace", &commit, replacement.trim()]);

        let date = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let commits = list_commits_in_range(&repo, date, date, 1).unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, commit);
        assert_eq!(commits[0].1.unwrap().date_naive(), date);
    }

    #[test]
    fn bounded_process_child() {
        match std::env::var("TOMORROWCI_BOUNDED_CHILD").as_deref() {
            Ok("overflow") => {
                std::io::stdout()
                    .write_all(&vec![b'x'; 128 * 1024])
                    .unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(10));
            }
            Ok("timeout") => std::thread::sleep(Duration::from_secs(10)),
            _ => {}
        }
    }

    #[test]
    fn bounded_process_kills_on_timeout_and_output_overflow() {
        let helper = "historical_source_tests::bounded_process_child";
        let mut overflow = Command::new(std::env::current_exe().unwrap());
        overflow
            .args(["--exact", helper, "--nocapture"])
            .env("TOMORROWCI_BOUNDED_CHILD", "overflow");
        let started = Instant::now();
        let error = run_bounded_command(
            overflow,
            None,
            1024,
            1024 * 1024,
            Duration::from_secs(2),
            "test overflow",
        )
        .unwrap_err();
        assert!(error.contains("exceeded cap"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));

        let mut timeout = Command::new(std::env::current_exe().unwrap());
        timeout
            .args(["--exact", helper, "--nocapture"])
            .env("TOMORROWCI_BOUNDED_CHILD", "timeout");
        let started = Instant::now();
        let error = run_bounded_command(
            timeout,
            None,
            1024 * 1024,
            1024 * 1024,
            Duration::from_millis(150),
            "test timeout",
        )
        .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn proof_destinations_and_leaf_writes_never_reuse_preseeded_paths() {
        let root = tempdir().unwrap();
        let evidence = root.path().join("evidence");
        let directory = create_backtest_proof_directory(&evidence, "proof-id").unwrap();
        std::fs::write(directory.join("sentinel"), b"preserve").unwrap();
        assert!(create_backtest_proof_directory(&evidence, "proof-id").is_err());
        assert_eq!(
            std::fs::read(directory.join("sentinel")).unwrap(),
            b"preserve"
        );

        let victim = root.path().join("victim");
        let preseed = root.path().join("preseed");
        std::fs::write(&victim, b"original").unwrap();
        std::fs::hard_link(&victim, &preseed).unwrap();
        assert!(write_new_file(&preseed, b"replacement").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_ancestor_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let linked = root.path().join("linked");
        symlink(&outside, &linked).unwrap();
        assert!(create_private_historical_session(&linked)
            .unwrap_err()
            .contains("plain directory"));
    }
}
