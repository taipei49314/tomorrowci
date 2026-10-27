//! Full scan orchestration with explicit scenario lifecycle:
//! IMAGE_RESOLVE → WORKSPACE_PREPARE → FETCH → TEST → CLASSIFY → EVIDENCE_FINALIZE

use crate::dependency::{
    concrete_dependency_fetch_commands, derive_observed_dependency_reduction,
    load_dependency_experiment, DependencyExperiment,
};
use crate::engine::{ContainerExecutor, ExecutionContext, ScenarioExecutor};
use crate::synthetic_git::{
    configure_synthetic_git_environment, install_synthetic_git_index, prepare_synthetic_git_index,
    PreparedSyntheticGitIndex,
};
use chrono::Utc;
use indexmap::IndexMap;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tomorrowci_adapter_node::NodeAdapter;
use tomorrowci_adapter_python::{python_fetch_commands, PythonAdapter};
use tomorrowci_adapter_rust::RustAdapter;
use tomorrowci_adapters::EcosystemAdapter;
use tomorrowci_core::{
    classify_candidate_attempts, classify_from_reruns, compute_breakage_frontier, plan_scenarios,
    validate_image_digest, Baseline, CommandSpec, Config, Ecosystem, EnvironmentAxis,
    EnvironmentSpec, EvidenceGrade, ExecutionPlan, ExecutionResult, FailureSignature,
    ProjectDetection, RawExecutionResult, RemoteSourceRecord, RepositorySnapshot, Result,
    RunIdentity, RunManifest, Scenario, TcError, TestAttemptRecord, TestAttemptsSummary,
    TestExecutionStatus, Verdict,
};
use tomorrowci_evidence::{
    metadata_is_alias, validate_existing_ancestors, validate_identifier, write_checksums,
    write_run_manifest, write_workspace_manifest, ChecksumCompatibility, EvidenceLayout,
    WorkspaceManifest,
};
use tomorrowci_metrics::{ClaimLedger, ClaimStatus, ScanMetrics};
use tomorrowci_report::{write_github_job_summary, write_html_report, write_json_report};
use tomorrowci_sandbox::{make_disposable_copy, prepare_scenario_state, shell_join};
use uuid::Uuid;

pub struct ScanOptions {
    pub config: Config,
    pub allow_scripted: bool,
}

pub struct ScanOutcome {
    pub manifest: RunManifest,
    pub evidence_root: PathBuf,
    pub terminal_summary: String,
    pub metrics: ScanMetrics,
}

#[derive(Debug, Clone, Serialize)]
struct PhaseResult {
    phase: String,
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network: String,
    image: String,
    image_digest: Option<String>,
    argv: Vec<Vec<String>>,
    started_at: String,
    finished_at: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct SourceIdentity {
    repository: RepositorySnapshot,
    dirty_tree: Option<bool>,
}

/// Auto-detect ecosystem and run a full local scan.
pub fn scan_local(repo: &Path, opts: ScanOptions) -> Result<ScanOutcome> {
    scan_local_into(repo, repo, opts, false)
}

/// Scan `repo` while retaining evidence under a separate trusted root. Remote
/// materialization uses this so its temporary Git checkout can be deleted
/// without deleting the immutable recorded workspace or replay evidence.
pub(crate) fn scan_local_into(
    repo: &Path,
    evidence_repo: &Path,
    opts: ScanOptions,
    synthesize_git_index: bool,
) -> Result<ScanOutcome> {
    opts.config.validate()?;
    let requested = opts.config.project.ecosystem.as_str();
    let py = PythonAdapter.detect(repo);
    if py.supported && matches!(requested, "auto" | "python") {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &PythonAdapter,
            opts,
            py.detection,
            synthesize_git_index,
            None,
        );
    }
    let node = NodeAdapter.detect(repo);
    if node.supported && matches!(requested, "auto" | "node") {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &NodeAdapter,
            opts,
            node.detection,
            synthesize_git_index,
            None,
        );
    }
    let rust = RustAdapter.detect(repo);
    if rust.supported && matches!(requested, "auto" | "rust") {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &RustAdapter,
            opts,
            rust.detection,
            synthesize_git_index,
            None,
        );
    }
    Err(TcError::Unsupported(format!(
        "no supported {requested} ecosystem detected (need matching Python, Node/npm, or Rust/cargo manifests)"
    )))
}

fn scan_with_adapter(
    repo: &Path,
    evidence_repo: &Path,
    adapter: &dyn EcosystemAdapter,
    opts: ScanOptions,
    detection: ProjectDetection,
    synthesize_git_index: bool,
    executor_override: Option<&dyn ScenarioExecutor>,
) -> Result<ScanOutcome> {
    let config = opts.config;
    config.validate()?;
    if config.candidates.runtime.versions.is_some() && detection.ecosystem != Ecosystem::Python {
        return Err(TcError::Unsupported(
            "candidates.runtime.versions is currently supported only for Python; the selected adapter cannot ignore an explicit candidate list".into(),
        ));
    }
    let detected = adapter.detect(repo);
    if !detected.supported
        || serde_json::to_value(&detected.detection)? != serde_json::to_value(&detection)?
        || adapter.name()
            != match detection.ecosystem {
                Ecosystem::Python => "python",
                Ecosystem::Node => "node",
                Ecosystem::Rust => "rust",
                Ecosystem::Unknown => "unknown",
            }
    {
        return Err(TcError::InvalidState(
            "supplied detection does not exactly match the selected adapter and source tree".into(),
        ));
    }
    let wall_start = Instant::now();
    let run_started = Utc::now();
    let source_before = capture_source_identity(repo)?;
    let run_id = Uuid::new_v4().to_string().replace('-', "")[..12].to_string();
    let layout = EvidenceLayout::create(evidence_repo, &run_id)?;

    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;
    let workspace_manifest_path = layout.run_root.join("workspace-manifest.json");
    let workspace_manifest = write_workspace_manifest(&work, &workspace_manifest_path)?;
    let synthetic_git_index = if synthesize_git_index {
        Some(prepare_synthetic_git_index(
            &work,
            &workspace_manifest,
            &tomorrowci_evidence::file_checksum(&workspace_manifest_path)?,
        )?)
    } else {
        None
    };
    verify_source_copy_stable(repo, &layout, &workspace_manifest, &source_before)?;
    let source_after = capture_source_identity(repo)?;
    let source_identity = merge_source_identity(source_before, source_after)?;

    let captured_detection = adapter.detect(&work).detection;
    if serde_json::to_value(&captured_detection)? != serde_json::to_value(&detection)? {
        return Err(TcError::Blocked(
            "project detection changed while the immutable workspace snapshot was captured".into(),
        ));
    }
    let detection = captured_detection;

    // Target source files are not modified; evidence is under .tomorrowci/runs (excluded).
    let mut baseline = adapter.baseline(&work, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dependency_experiment =
        load_dependency_experiment(&work, detection.ecosystem, &baseline.runtime)?;
    if let Some(experiment) = &dependency_experiment {
        // Schema v1 pins a single runtime image. Applying that image to a
        // different runtime would report an experiment we never executed.
        if !rt_cands.is_empty() {
            return Err(TcError::Unsupported(
                "concrete dependency experiments pin one runtime image; run runtime candidates separately, or set candidates.runtime.max_versions to 0 for this dependency experiment".into(),
            ));
        }
        baseline.dependencies = experiment.baseline.set_id.clone();
    }
    let dep_cands = dependency_candidates(&baseline, &config, dependency_experiment.as_ref())?;

    let (plan, decisions) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;
    layout.write_json("plan-decisions.json", &decisions)?;
    let all_candidates: Vec<_> = rt_cands.iter().chain(dep_cands.iter()).cloned().collect();
    layout.write_json("candidates.json", &all_candidates)?;
    layout.write_json("repository.json", &source_identity.repository)?;
    layout.write_json("config.normalized.json", &config)?;
    if let Some(experiment) = &dependency_experiment {
        layout.write_json("dependency-experiment.json", &experiment.manifest)?;
    }

    let engine_resolve_started = Utc::now();
    let engine = if executor_override.is_none() {
        Some(ContainerExecutor::detect_requested(&config.sandbox.engine))
    } else {
        None
    };
    let engine_resolve_finished = Utc::now();
    let detected_executor = match engine {
        Some(Ok(executor)) => Some(executor),
        Some(Err(e)) => {
            let detail = if opts.allow_scripted {
                format!("sandbox unavailable ({e}); scripted executors are test-only")
            } else {
                format!("sandbox unavailable: {e}")
            };
            return finalize_no_engine_blocked_run(
                repo,
                adapter,
                &config,
                &detection,
                &baseline,
                &plan,
                &layout,
                &work,
                &run_id,
                run_started,
                wall_start,
                engine_resolve_started,
                engine_resolve_finished,
                &detail,
                &source_identity,
                synthesize_git_index,
            );
        }
        None => None,
    };
    let executor: &dyn ScenarioExecutor = executor_override.unwrap_or_else(|| {
        detected_executor
            .as_ref()
            .expect("container executor was detected when no test override was supplied")
    });

    let mut results: Vec<ExecutionResult> = Vec::new();
    let mut ordered_for_frontier: Vec<(Scenario, ExecutionResult)> = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail_scenario: Option<String> = None;

    let eco = detection.ecosystem;
    let is_scripted = executor.name() == "scripted";

    for scenario in &plan.scenarios {
        // Every scenario executes against a fresh copy of the immutable recorded
        // workspace. Dependency installers and build tools must never leak state
        // into a later candidate or mutate the replay authority snapshot.
        let scenario_workspace = DisposableWorkspace::capture(&work)?;
        if let Some(prepared) = &synthetic_git_index {
            install_synthetic_git_index(scenario_workspace.path(), prepared)?;
        }
        prepare_scenario_state(scenario_workspace.path())?;
        scenario_workspace.prepare_runtime(eco)?;
        prepare_dependency_materialization_root(scenario_workspace.path(), scenario)?;
        let scenario_work = scenario_workspace.path();

        let mut env = adapter.materialize(scenario, scenario_work)?;
        if synthetic_git_index.is_some() {
            configure_synthetic_git_environment(&mut env)?;
        }
        let tag = normalize_image(eco, &scenario.runtime);
        env.image_tag = tag.clone();
        env.image = tag; // legacy alias of tag only — never store digest here
        env.memory_mb = config.sandbox.memory_mb;
        env.cpus = config.sandbox.cpus;
        env.pids_limit = config.sandbox.pids_limit;
        env.fetch_timeout_seconds = Some(config.execution.timeout_seconds.min(600));
        env.test_timeout_seconds = Some(config.execution.timeout_seconds);
        env.engine = Some(executor.engine_label());
        env.engine_version = executor.engine_version();

        let sc_dir = layout.ensure_scenario(&scenario.id)?;
        // True scenario-specific mounted state
        let sc_state = scenario_work
            .join(".tomorrowci")
            .join("scenarios")
            .join(&scenario.id);
        std::fs::create_dir_all(sc_state.join("venv"))?;
        std::fs::create_dir_all(sc_state.join("cache").join("pip"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::Permissions::from_mode(0o777);
            let _ = std::fs::set_permissions(&sc_state, mode.clone());
            let _ = std::fs::set_permissions(sc_state.join("venv"), mode.clone());
            let _ = std::fs::set_permissions(sc_state.join("cache"), mode.clone());
            let _ = std::fs::set_permissions(sc_state.join("cache").join("pip"), mode);
        }

        // IMAGE_RESOLVE — pull/resolve by tag; record digest separately
        // Command construction is pure planning evidence. Record it even when
        // immutable image resolution later blocks execution.
        let test_commands = build_scenario_commands(adapter, scenario, &config, scenario_work)?;
        let planned_fetch_commands =
            build_fetch_commands(eco, scenario, scenario_work, is_scripted);

        let image_started = Utc::now();
        let image_request = dependency_experiment
            .as_ref()
            .filter(|_| scenario.resolved_dependencies.is_some())
            .map(|experiment| experiment.manifest.runtime.container_image.as_str())
            .unwrap_or_else(|| env.tag());
        let digest = match executor.ensure_image(image_request).and_then(|digest| {
            validate_image_digest(&digest).map_err(TcError::InvalidState)?;
            Ok(digest)
        }) {
            Ok(d) => d,
            Err(e) => {
                let image_finished = Utc::now();
                let fetch_commands = planned_fetch_commands
                    .as_ref()
                    .ok()
                    .and_then(|commands| commands.as_ref())
                    .cloned()
                    .unwrap_or_default();
                let mut all_commands = fetch_commands.clone();
                all_commands.extend(test_commands.clone());
                let blocked = blocked_result(scenario, &env, &all_commands, &e.to_string());
                write_phase(
                    &sc_dir,
                    "image-resolve",
                    false,
                    None,
                    false,
                    elapsed_ms(image_started, image_finished),
                    "n/a",
                    env.tag(),
                    None,
                    &[],
                    &e.to_string(),
                    Some(image_started),
                    Some(image_finished),
                )?;
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    &fetch_commands,
                    &test_commands,
                    None,
                    None,
                    &blocked,
                    executor.engine_label(),
                    blocked.failure.as_ref(),
                    &not_run_summary(scenario, "image resolution failed"),
                )?;
                results.push(blocked.clone());
                ordered_for_frontier.push((scenario.clone(), blocked));
                if scenario.is_baseline {
                    break;
                }
                continue;
            }
        };
        let image_finished = Utc::now();
        env.image_digest = Some(digest.clone());
        write_phase(
            &sc_dir,
            "image-resolve",
            true,
            Some(0),
            false,
            elapsed_ms(image_started, image_finished),
            "n/a",
            env.tag(),
            Some(digest),
            &[],
            "immutable image digest resolved",
            Some(image_started),
            Some(image_finished),
        )?;

        let fetch_cmds = match planned_fetch_commands {
            Ok(c) => c,
            Err(TcError::Unsupported(msg)) => {
                let mut r = blocked_result(scenario, &env, &test_commands, &msg);
                r.verdict = Verdict::Unsupported;
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    &[],
                    &test_commands,
                    None,
                    None,
                    &r,
                    executor.engine_label(),
                    r.failure.as_ref(),
                    &not_run_summary(scenario, &msg),
                )?;
                let stop_after_result = baseline_requires_early_stop(scenario, &r);
                results.push(r.clone());
                ordered_for_frontier.push((scenario.clone(), r));
                if stop_after_result {
                    break;
                }
                continue;
            }
            Err(e) => return Err(e),
        };

        layout_write_scenario_meta(&sc_dir, scenario, &env, &test_commands)?;
        std::fs::write(
            sc_dir.join("fetch-commands.json"),
            serde_json::to_string_pretty(&fetch_cmds)?,
        )?;
        std::fs::write(
            sc_dir.join("test-commands.json"),
            serde_json::to_string_pretty(&test_commands)?,
        )?;

        // FETCH
        let mut fetch_raw: Option<RawExecutionResult> = None;
        if let Some(ref fcmds) = fetch_cmds {
            let fetch_start = Utc::now();
            let fetch_timeout = Duration::from_secs(env.fetch_timeout_seconds.unwrap_or(600));
            let fr = match executor.execute(&ExecutionContext {
                workspace: scenario_work,
                scenario,
                environment: &env,
                commands: fcmds,
                timeout: fetch_timeout,
                network: "bridge",
            }) {
                Ok(r) => r,
                Err(e) => {
                    let fetch_finished = Utc::now();
                    let mut all_commands = fcmds.clone();
                    all_commands.extend(test_commands.clone());
                    let blocked = blocked_result(scenario, &env, &all_commands, &e.to_string());
                    write_phase(
                        &sc_dir,
                        "fetch",
                        false,
                        None,
                        false,
                        elapsed_ms(fetch_start, fetch_finished),
                        "bridge",
                        env.tag(),
                        env.image_digest.clone(),
                        fcmds,
                        &e.to_string(),
                        Some(fetch_start),
                        Some(fetch_finished),
                    )?;
                    persist_scenario_artifacts(
                        &sc_dir,
                        scenario,
                        &env,
                        fcmds,
                        &test_commands,
                        None,
                        None,
                        &blocked,
                        executor.engine_label(),
                        blocked.failure.as_ref(),
                        &not_run_summary(scenario, &format!("fetch execution failed: {e}")),
                    )?;
                    results.push(blocked.clone());
                    ordered_for_frontier.push((scenario.clone(), blocked));
                    if scenario.is_baseline {
                        break;
                    }
                    continue;
                }
            };
            let fetch_finished = Utc::now();
            let fetch_ok = fr.exit_code == Some(0) && !fr.timed_out;
            write_raw_logs(&sc_dir, "fetch", &fr)?;
            write_phase(
                &sc_dir,
                "fetch",
                fetch_ok,
                fr.exit_code,
                fr.timed_out,
                fr.duration_ms,
                "bridge",
                env.tag(),
                env.image_digest.clone(),
                fcmds,
                if fetch_ok { "ok" } else { "fetch failed" },
                Some(fetch_start),
                Some(fetch_finished),
            )?;
            std::fs::write(
                sc_dir.join("fetch-result.json"),
                serde_json::to_string_pretty(&fr_json(&fr, fetch_start, Some(fetch_finished)))?,
            )?;
            if !fetch_ok {
                let mut all_commands = fcmds.clone();
                all_commands.extend(test_commands.clone());
                let mut blocked = blocked_result(
                    scenario,
                    &env,
                    &all_commands,
                    "dependency fetch failed; test phase not executed",
                );
                blocked.exit_code = fr.exit_code;
                blocked.duration_ms = fr.duration_ms;
                blocked.timed_out = fr.timed_out;
                blocked.failure = Some(adapter.normalize_failure(&fr));
                persist_scenario_artifacts(
                    &sc_dir,
                    scenario,
                    &env,
                    fcmds,
                    &test_commands,
                    Some(&fr),
                    None,
                    &blocked,
                    executor.engine_label(),
                    blocked.failure.as_ref(),
                    &not_run_summary(scenario, "dependency fetch failed"),
                )?;
                results.push(blocked.clone());
                ordered_for_frontier.push((scenario.clone(), blocked));
                if scenario.is_baseline {
                    baseline_ok = false;
                    break;
                }
                continue;
            }
            fetch_raw = Some(fr);
        }

        // TEST with reruns
        let reruns = if scenario.is_baseline {
            1
        } else {
            config.execution.reruns_on_failure.max(1)
        };

        let mut attempt_pass: Vec<bool> = Vec::new();
        let mut attempt_records: Vec<TestAttemptRecord> = Vec::new();
        let mut last_raw = None;
        let mut test_execution_error = None;

        let test_timeout = Duration::from_secs(env.test_timeout_seconds.unwrap_or(900));
        let mut test_phase_started = None;
        let mut final_attempt_started = None;
        let mut final_attempt_finished = None;
        for attempt in 1..=reruns {
            let attempt_started = Utc::now();
            test_phase_started.get_or_insert(attempt_started);
            let raw = match executor.execute(&ExecutionContext {
                workspace: scenario_work,
                scenario,
                environment: &env,
                commands: &test_commands,
                timeout: test_timeout,
                network: "none",
            }) {
                Ok(raw) => raw,
                Err(error) => {
                    final_attempt_started = Some(attempt_started);
                    final_attempt_finished = Some(Utc::now());
                    test_execution_error = Some(error.to_string());
                    break;
                }
            };
            let attempt_finished = Utc::now();

            let pass = raw.exit_code == Some(0) && !raw.timed_out;
            attempt_pass.push(pass);
            let attempt_failure = (!pass).then(|| adapter.normalize_failure(&raw));
            attempt_records.push(TestAttemptRecord {
                attempt,
                started_at: attempt_started,
                finished_at: attempt_finished,
                exit_code: raw.exit_code,
                timed_out: raw.timed_out,
                duration_ms: raw.duration_ms,
                failure: attempt_failure,
            });
            std::fs::write(
                sc_dir.join(format!("stdout.attempt{attempt}.log")),
                &raw.stdout,
            )?;
            std::fs::write(
                sc_dir.join(format!("stderr.attempt{attempt}.log")),
                &raw.stderr,
            )?;
            final_attempt_started = Some(attempt_started);
            final_attempt_finished = Some(attempt_finished);
            last_raw = Some(raw);
            if pass {
                break;
            }
        }
        let test_started = test_phase_started
            .ok_or_else(|| TcError::InvalidState("test attempt did not start".into()))?;
        let test_finished = final_attempt_finished
            .ok_or_else(|| TcError::InvalidState("test attempt did not finish".into()))?;

        if let Some(error) = test_execution_error {
            let mut all_commands = fetch_cmds.clone().unwrap_or_default();
            all_commands.extend(test_commands.clone());
            let mut blocked = blocked_result(scenario, &env, &all_commands, &error);
            blocked.attempt = attempt_records.len() as u32;
            write_phase(
                &sc_dir,
                "test",
                false,
                None,
                false,
                elapsed_ms(test_started, test_finished),
                "none",
                env.tag(),
                env.image_digest.clone(),
                &test_commands,
                &error,
                Some(test_started),
                Some(test_finished),
            )?;
            let summary = TestAttemptsSummary {
                scenario_id: scenario.id.clone(),
                status: TestExecutionStatus::ExecutionError,
                attempts: attempt_records,
                error: Some(error),
            };
            persist_scenario_artifacts(
                &sc_dir,
                scenario,
                &env,
                fetch_cmds.as_deref().unwrap_or(&[]),
                &test_commands,
                fetch_raw.as_ref(),
                last_raw.as_ref(),
                &blocked,
                executor.engine_label(),
                blocked.failure.as_ref(),
                &summary,
            )?;
            results.push(blocked.clone());
            ordered_for_frontier.push((scenario.clone(), blocked));
            if scenario.is_baseline {
                break;
            }
            continue;
        }

        let raw = last_raw.ok_or_else(|| TcError::InvalidState("no test attempts".into()))?;
        write_phase(
            &sc_dir,
            "test",
            raw.exit_code == Some(0) && !raw.timed_out,
            raw.exit_code,
            raw.timed_out,
            elapsed_ms(test_started, test_finished),
            "none",
            env.tag(),
            env.image_digest.clone(),
            &test_commands,
            "test complete",
            Some(test_started),
            Some(test_finished),
        )?;
        std::fs::write(
            sc_dir.join("test-result.json"),
            serde_json::to_string_pretty(&fr_json(
                &raw,
                final_attempt_started.expect("completed attempt has start time"),
                final_attempt_finished,
            ))?,
        )?;

        let verdict = if scenario.is_baseline {
            if attempt_pass.iter().any(|p| *p) {
                baseline_ok = true;
                Verdict::BaselinePass
            } else {
                baseline_ok = false;
                Verdict::BaselineInvalid
            }
        } else {
            classify_candidate_attempts(&attempt_records)
        };

        let failure = match verdict {
            Verdict::BaselinePass | Verdict::FuturePass => None,
            Verdict::Flaky => attempt_records
                .iter()
                .rev()
                .find_map(|attempt| attempt.failure.clone()),
            _ => attempt_records
                .last()
                .and_then(|attempt| attempt.failure.clone()),
        };

        let mut all_cmds = fetch_cmds.clone().unwrap_or_default();
        all_cmds.extend(test_commands.clone());

        let exec = ExecutionResult {
            scenario_id: scenario.id.clone(),
            attempt: attempt_pass.len() as u32,
            verdict,
            exit_code: raw.exit_code,
            duration_ms: raw.duration_ms,
            timed_out: raw.timed_out,
            failure: failure.clone(),
            environment: env.clone(),
            commands: all_cmds,
        };

        persist_scenario_artifacts(
            &sc_dir,
            scenario,
            &env,
            fetch_cmds.as_deref().unwrap_or(&[]),
            &test_commands,
            fetch_raw.as_ref(),
            Some(&raw),
            &exec,
            executor.engine_label(),
            failure.as_ref(),
            &TestAttemptsSummary {
                scenario_id: scenario.id.clone(),
                status: TestExecutionStatus::Completed,
                attempts: attempt_records,
                error: None,
            },
        )?;

        ordered_for_frontier.push((scenario.clone(), exec.clone()));
        results.push(exec);

        if matches!(verdict, Verdict::FutureFail) && first_fail_scenario.is_none() {
            first_fail_scenario = Some(scenario.id.clone());
            confirmed_first_fail = attempt_pass.iter().all(|p| !*p) && attempt_pass.len() >= 2;
        }

        if matches!(verdict, Verdict::BaselineInvalid) {
            break;
        }
    }

    let dependency_reduction = dependency_experiment
        .as_ref()
        .map(|experiment| {
            derive_observed_dependency_reduction(
                &run_id,
                &layout.run_root,
                experiment,
                &plan,
                &results,
            )
        })
        .transpose()?;
    if let Some(reduction) = &dependency_reduction {
        layout.write_json("reduction.json", reduction)?;
    }
    let minimal_replay_scenario = dependency_reduction.as_ref().and_then(|reduction| {
        if reduction.status != tomorrowci_core::DependencyReductionStatus::ProvenMinimal {
            return None;
        }
        let minimal_ids: Vec<_> = reduction
            .minimal_changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        dependency_experiment
            .as_ref()?
            .probes
            .iter()
            .find_map(|probe| (probe.change_ids == minimal_ids).then(|| probe.id.clone()))
    });

    let replay_target = minimal_replay_scenario
        .as_ref()
        .or(first_fail_scenario.as_ref());
    let replay_cmd = replay_target.map(|s| format!("tomorrowci replay {run_id} --scenario {s}"));

    let mut frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered_for_frontier,
        confirmed_first_fail,
        replay_cmd.clone(),
    );
    if let Some(scenario_id) = minimal_replay_scenario {
        frontier.notes.push(format!(
            "dependency reduction proved 1-minimal at scenario {scenario_id}"
        ));
    }
    if is_scripted {
        frontier
            .notes
            .push("executor=scripted — NOT acceptance evidence for live adapter".into());
    }

    layout.write_json("verdicts.json", &results)?;
    layout.write_json("frontier.json", &frontier)?;

    let run_finished = Utc::now();
    let manifest_hashes = manifest_hashes_for_detection(work.as_path(), &detection)?;
    let identity = RunIdentity {
        source_commit: source_identity.repository.commit_sha.clone(),
        dirty_tree: source_identity.dirty_tree,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        adapter_name: adapter.name().into(),
        adapter_version: env!("CARGO_PKG_VERSION").into(),
        config_hash: config.content_hash()?,
        manifest_hashes,
        container_engine: Some(executor.engine_label()),
        container_engine_version: executor.engine_version(),
        started_at: run_started,
        finished_at: Some(run_finished),
    };
    let manifest = RunManifest {
        evidence_schema_version: 2,
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: run_started,
        finished_at: Some(run_finished),
        repository: source_identity.repository.clone(),
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results: results.clone(),
        frontier: frontier.clone(),
        evidence_root: layout.run_root.clone(),
        identity: Some(identity),
    };
    write_run_manifest(&layout, &manifest)?;
    write_json_report(&manifest, &layout.run_root.join("report.json"))?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md"))?;

    let metrics =
        ScanMetrics::from_manifest(&manifest, Some(wall_start.elapsed().as_millis() as u64));
    metrics.write_json(&layout.run_root.join("metrics.json"))?;

    let mut terminal_summary = render_terminal_summary(&manifest);
    terminal_summary.push_str(&metrics.summary_line());
    terminal_summary.push('\n');
    std::fs::write(layout.run_root.join("summary.txt"), &terminal_summary)?;

    if !layout.run_root.join("claims.json").exists() {
        std::fs::write(
            layout.run_root.join("claims.json"),
            serde_json::to_string_pretty(&ClaimLedger::default())?,
        )?;
    }
    tomorrowci_evidence::finalize_run_checksums(&layout.run_root)?;

    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
        metrics,
    })
}

#[allow(clippy::too_many_arguments)]
fn finalize_no_engine_blocked_run(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    config: &Config,
    detection: &ProjectDetection,
    baseline: &Baseline,
    plan: &ExecutionPlan,
    layout: &EvidenceLayout,
    work: &Path,
    run_id: &str,
    run_started: chrono::DateTime<Utc>,
    wall_start: Instant,
    image_resolve_started: chrono::DateTime<Utc>,
    image_resolve_finished: chrono::DateTime<Utc>,
    detail: &str,
    source_identity: &SourceIdentity,
    synthesize_git_index: bool,
) -> Result<ScanOutcome> {
    let scenario = plan.scenarios.first().ok_or_else(|| {
        TcError::InvalidState("cannot record BLOCKED scan without a planned scenario".into())
    })?;

    let mut env = adapter.materialize(scenario, work)?;
    if synthesize_git_index {
        configure_synthetic_git_environment(&mut env)?;
    }
    let image_tag = normalize_image(detection.ecosystem, &scenario.runtime);
    env.image_tag = image_tag.clone();
    env.image = image_tag;
    env.image_digest = None;
    env.memory_mb = config.sandbox.memory_mb;
    env.cpus = config.sandbox.cpus;
    env.pids_limit = config.sandbox.pids_limit;
    env.fetch_timeout_seconds = Some(config.execution.timeout_seconds.min(600));
    env.test_timeout_seconds = Some(config.execution.timeout_seconds);
    env.engine = None;
    env.engine_version = None;

    let mut blocked_detail = detail.to_string();
    let test_commands = match build_scenario_commands(adapter, scenario, config, work) {
        Ok(commands) => commands,
        Err(error) => {
            blocked_detail.push_str(&format!("; test command construction also failed: {error}"));
            Vec::new()
        }
    };
    let fetch_commands = match build_fetch_commands(detection.ecosystem, scenario, work, false) {
        Ok(commands) => commands.unwrap_or_default(),
        Err(error) => {
            blocked_detail.push_str(&format!(
                "; fetch command construction also failed: {error}"
            ));
            Vec::new()
        }
    };

    let mut all_commands = fetch_commands.clone();
    all_commands.extend(test_commands.clone());
    let blocked = blocked_result(scenario, &env, &all_commands, &blocked_detail);
    let scenario_dir = layout.ensure_scenario(&scenario.id)?;
    write_phase(
        &scenario_dir,
        "image-resolve",
        false,
        None,
        false,
        elapsed_ms(image_resolve_started, image_resolve_finished),
        "n/a",
        env.tag(),
        None,
        &[],
        &blocked_detail,
        Some(image_resolve_started),
        Some(image_resolve_finished),
    )?;
    persist_scenario_artifacts(
        &scenario_dir,
        scenario,
        &env,
        &fetch_commands,
        &test_commands,
        None,
        None,
        &blocked,
        "unavailable".into(),
        blocked.failure.as_ref(),
        &not_run_summary(scenario, &blocked_detail),
    )?;

    let frontier =
        compute_breakage_frontier(false, &[(scenario.clone(), blocked.clone())], false, None);
    let results = vec![blocked];
    layout.write_json("verdicts.json", &results)?;
    layout.write_json("frontier.json", &frontier)?;

    let finished_at = Utc::now();
    let manifest_hashes = manifest_hashes_for_detection(work, detection)?;
    let identity = RunIdentity {
        source_commit: source_identity.repository.commit_sha.clone(),
        dirty_tree: source_identity.dirty_tree,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        adapter_name: adapter.name().into(),
        adapter_version: env!("CARGO_PKG_VERSION").into(),
        config_hash: config.content_hash()?,
        manifest_hashes,
        container_engine: None,
        container_engine_version: None,
        started_at: run_started,
        finished_at: Some(finished_at),
    };
    let manifest = RunManifest {
        evidence_schema_version: 2,
        run_id: run_id.into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: run_started,
        finished_at: Some(finished_at),
        repository: source_identity.repository.clone(),
        config_hash: config.content_hash()?,
        detection: detection.clone(),
        baseline: baseline.clone(),
        plan: plan.clone(),
        results,
        frontier,
        evidence_root: layout.run_root.clone(),
        identity: Some(identity),
    };

    write_run_manifest(layout, &manifest)?;
    write_json_report(&manifest, &layout.run_root.join("report.json"))?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md"))?;

    let metrics =
        ScanMetrics::from_manifest(&manifest, Some(wall_start.elapsed().as_millis() as u64));
    metrics.write_json(&layout.run_root.join("metrics.json"))?;
    let mut terminal_summary = render_terminal_summary(&manifest);
    terminal_summary.push_str(&metrics.summary_line());
    terminal_summary.push('\n');
    std::fs::write(layout.run_root.join("summary.txt"), &terminal_summary)?;

    let mut claims = ClaimLedger::default();
    claims.push(
        format!("{} scan completed", adapter.name()),
        ClaimStatus::Blocked,
        format!("tomorrowci scan {}", repo.display()),
        blocked_detail,
        layout.run_root.display().to_string(),
    );
    claims.write_json(&layout.run_root.join("claims.json"))?;

    tomorrowci_evidence::finalize_run_checksums(&layout.run_root)?;
    let verification = tomorrowci_evidence::verify_run_root(&layout.run_root)?;
    if !verification.ok {
        return Err(TcError::InvalidState(format!(
            "BLOCKED evidence finalization failed verification: {}",
            verification.errors.join("; ")
        )));
    }

    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root.clone(),
        terminal_summary,
        metrics,
    })
}

fn capture_source_identity(repo: &Path) -> Result<SourceIdentity> {
    let canonical = std::fs::canonicalize(repo)?;
    let local_source = format!("local:{}", canonical.display());
    let inside_output = std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo)
        .output()
        .map_err(|error| {
            TcError::Blocked(format!(
                "git could not be started to establish source identity: {error}"
            ))
        })?;
    let is_git = if inside_output.status.success() {
        String::from_utf8_lossy(&inside_output.stdout).trim() == "true"
    } else {
        let stderr = String::from_utf8_lossy(&inside_output.stderr);
        if stderr.contains("not a git repository") {
            false
        } else {
            return Err(TcError::Blocked(format!(
                "git source identity check failed: {}",
                stderr.trim()
            )));
        }
    };

    let commit_output = is_git.then(|| {
        std::process::Command::new("git")
            .args(["rev-parse", "--verify", "HEAD"])
            .current_dir(repo)
            .output()
    });
    let commit_sha = match commit_output {
        Some(Ok(output)) if output.status.success() => {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if matches!(value.len(), 40 | 64)
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !value.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                Some(value)
            } else {
                return Err(TcError::InvalidState(format!(
                    "git returned a noncanonical source commit: {value:?}"
                )));
            }
        }
        Some(Ok(output)) => {
            return Err(TcError::Blocked(format!(
                "git could not resolve the exact source commit: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Some(Err(error)) => {
            return Err(TcError::Blocked(format!(
                "git commit identity command failed: {error}"
            )));
        }
        None => None,
    };

    let (source, dirty_tree) = if commit_sha.is_some() {
        let origin = std::process::Command::new("git")
            .args(["config", "--get", "remote.origin.url"])
            .current_dir(repo)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .and_then(|value| canonical_git_origin(&value, repo))
            .unwrap_or(local_source);
        let dirty_output = std::process::Command::new("git")
            .args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--",
                ".",
                ":(exclude).tomorrowci",
                ":(exclude)target",
                ":(exclude)node_modules",
                ":(exclude)__pycache__",
                ":(exclude).venv",
                ":(exclude)venv",
                ":(exclude).pytest_cache",
                ":(exclude).mypy_cache",
                ":(exclude).ruff_cache",
                ":(exclude).tox",
                ":(exclude).nox",
            ])
            .current_dir(repo)
            .output()
            .map_err(|error| {
                TcError::Blocked(format!(
                    "git status could not establish source state: {error}"
                ))
            })?;
        if !dirty_output.status.success() {
            return Err(TcError::Blocked(format!(
                "git status could not establish source state: {}",
                String::from_utf8_lossy(&dirty_output.stderr).trim()
            )));
        }
        (origin, Some(!dirty_output.stdout.is_empty()))
    } else {
        (local_source, None)
    };

    Ok(SourceIdentity {
        repository: RepositorySnapshot {
            source,
            path: canonical,
            commit_sha,
            is_disposable_copy: true,
        },
        dirty_tree,
    })
}

fn canonical_git_origin(raw: &str, repo: &Path) -> Option<String> {
    if raw.is_empty() || raw.contains(['\r', '\n', '\0']) {
        return None;
    }
    if let Some((scheme, rest)) = raw.split_once("://") {
        if !scheme
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+-".contains(&byte))
        {
            return None;
        }
        let rest = rest.split(['?', '#']).next()?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        if host.is_empty() {
            return None;
        }
        let path = trim_git_origin_suffix(path);
        return Some(if path.is_empty() {
            format!("origin:{scheme}://{}", host.to_ascii_lowercase())
        } else {
            format!("origin:{scheme}://{}/{}", host.to_ascii_lowercase(), path)
        });
    }
    if let Some((authority, path)) = raw.split_once(':') {
        if authority.contains('@') && !path.is_empty() {
            let host = authority.rsplit_once('@')?.1.to_ascii_lowercase();
            return Some(format!(
                "origin:ssh://{host}/{}",
                trim_git_origin_suffix(path)
            ));
        }
    }
    let path = Path::new(raw);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    };
    std::fs::canonicalize(absolute)
        .ok()
        .map(|path| format!("origin-local:{}", path.display()))
}

fn trim_git_origin_suffix(value: &str) -> &str {
    value.trim_end_matches('/').trim_end_matches(".git")
}

fn merge_source_identity(before: SourceIdentity, after: SourceIdentity) -> Result<SourceIdentity> {
    if before.repository.source != after.repository.source
        || before.repository.path != after.repository.path
        || before.repository.commit_sha != after.repository.commit_sha
    {
        return Err(TcError::Blocked(
            "source identity changed while the disposable workspace was captured".into(),
        ));
    }
    let dirty_tree = match (before.dirty_tree, after.dirty_tree) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    };
    Ok(SourceIdentity {
        repository: before.repository,
        dirty_tree,
    })
}

fn verify_source_copy_stable(
    repo: &Path,
    layout: &EvidenceLayout,
    copied: &WorkspaceManifest,
    source_before: &SourceIdentity,
) -> Result<()> {
    let comparison_path = layout.run_root.join(".source-workspace-manifest.tmp");
    let source_manifest = write_workspace_manifest(repo, &comparison_path)?;
    std::fs::remove_file(&comparison_path)?;
    if &source_manifest != copied {
        return Err(TcError::Blocked(
            "source bytes changed while the disposable workspace was captured".into(),
        ));
    }
    let source_after_copy = capture_source_identity(repo)?;
    if source_before.repository.commit_sha != source_after_copy.repository.commit_sha {
        return Err(TcError::Blocked(
            "source commit changed while the disposable workspace was captured".into(),
        ));
    }
    Ok(())
}

fn manifest_hashes_for_detection(
    workspace: &Path,
    detection: &ProjectDetection,
) -> Result<IndexMap<String, String>> {
    let mut hashes = IndexMap::new();
    for relative in &detection.manifests {
        tomorrowci_evidence::validate_manifest_path(relative).map_err(TcError::InvalidState)?;
        let path = workspace.join(relative);
        if !path.is_file() {
            return Err(TcError::InvalidState(format!(
                "detected manifest is missing from disposable workspace: {relative}"
            )));
        }
        let hash = tomorrowci_evidence::file_checksum(&path)?;
        if hashes.insert(relative.clone(), hash).is_some() {
            return Err(TcError::InvalidState(format!(
                "duplicate detected manifest: {relative}"
            )));
        }
    }
    Ok(hashes)
}

#[cfg(test)]
pub(crate) fn scan_local_with_executor_into(
    repo: &Path,
    evidence_repo: &Path,
    config: Config,
    executor: &dyn ScenarioExecutor,
) -> Result<ScanOutcome> {
    let opts = ScanOptions {
        config,
        allow_scripted: true,
    };
    let py = PythonAdapter.detect(repo);
    if py.supported {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &PythonAdapter,
            opts,
            py.detection,
            true,
            Some(executor),
        );
    }
    let node = NodeAdapter.detect(repo);
    if node.supported {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &NodeAdapter,
            opts,
            node.detection,
            true,
            Some(executor),
        );
    }
    let rust = RustAdapter.detect(repo);
    if rust.supported {
        return scan_with_adapter(
            repo,
            evidence_repo,
            &RustAdapter,
            opts,
            rust.detection,
            true,
            Some(executor),
        );
    }
    Err(TcError::Unsupported(
        "no supported ecosystem detected (need Python, Node/npm, or Rust/cargo manifests)".into(),
    ))
}

/// Test-only scan with injected executor (scripted).
pub fn scan_with_executor(
    repo: &Path,
    adapter: &dyn EcosystemAdapter,
    config: Config,
    executor: &dyn ScenarioExecutor,
    detection: ProjectDetection,
) -> Result<ScanOutcome> {
    let wall_start = Instant::now();
    let run_started = Utc::now();
    let source_identity = capture_source_identity(repo)?;
    let run_id = format!("test{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
    let layout = EvidenceLayout::create(repo, &run_id)?;
    let work = layout.run_root.join("workspace");
    make_disposable_copy(repo, &work)?;
    prepare_scenario_state(&work)?;

    let baseline = adapter.baseline(repo, &config)?;
    let rt_cands = adapter.candidates(&baseline, &config)?;
    let dep_cands = dependency_candidates(&baseline, &config, None)?;
    let (plan, _) = plan_scenarios(&baseline, &rt_cands, &dep_cands, &config);
    layout.write_json("plan.json", &plan)?;

    let mut results = Vec::new();
    let mut ordered = Vec::new();
    let mut baseline_ok = false;
    let mut confirmed_first_fail = false;
    let mut first_fail = None;
    let eco = detection.ecosystem;

    for scenario in &plan.scenarios {
        let mut env = adapter.materialize(scenario, &work)?;
        let tag = normalize_image(eco, &scenario.runtime);
        env.image_tag = tag.clone();
        env.image = tag;
        env.image_digest = Some(executor.ensure_image(env.tag())?);
        let commands = build_scenario_commands(adapter, scenario, &config, &work)?;
        let fetch_cmds = build_fetch_commands(eco, scenario, &work, true)
            .ok()
            .flatten();
        let sc_dir = layout.ensure_scenario(&scenario.id)?;

        if let Some(ref fcmds) = fetch_cmds {
            let _ = executor.execute(&ExecutionContext {
                workspace: &work,
                scenario,
                environment: &env,
                commands: fcmds,
                timeout: Duration::from_secs(30),
                network: "bridge",
            })?;
        }

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
        std::fs::write(
            sc_dir.join("result.json"),
            serde_json::to_string_pretty(&exec)?,
        )?;
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

    let frontier = compute_breakage_frontier(
        baseline_ok,
        &ordered,
        confirmed_first_fail,
        first_fail
            .as_ref()
            .map(|s| format!("tomorrowci replay {run_id} --scenario {s}")),
    );

    let manifest = RunManifest {
        evidence_schema_version: 2,
        run_id: run_id.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        started_at: run_started,
        finished_at: Some(Utc::now()),
        repository: source_identity.repository,
        config_hash: config.content_hash()?,
        detection,
        baseline,
        plan,
        results,
        frontier,
        evidence_root: layout.run_root.clone(),
        identity: None,
    };
    write_run_manifest(&layout, &manifest)?;
    write_html_report(&manifest, &layout.run_root.join("report.html"))?;
    write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md"))?;
    let metrics =
        ScanMetrics::from_manifest(&manifest, Some(wall_start.elapsed().as_millis() as u64));
    metrics.write_json(&layout.run_root.join("metrics.json"))?;
    let mut terminal_summary = render_terminal_summary(&manifest);
    terminal_summary.push_str(&metrics.summary_line());
    terminal_summary.push('\n');
    Ok(ScanOutcome {
        manifest,
        evidence_root: layout.run_root,
        terminal_summary,
        metrics,
    })
}

fn dependency_candidates(
    baseline: &Baseline,
    config: &Config,
    experiment: Option<&DependencyExperiment>,
) -> Result<Vec<tomorrowci_core::Candidate>> {
    if let Some(experiment) = experiment {
        let candidates = experiment
            .probes
            .iter()
            .enumerate()
            .map(|(index, probe)| {
                let identity = probe
                    .dependency_set
                    .stable_identity()
                    .map_err(|error| TcError::InvalidState(error.to_string()))?;
                Ok(tomorrowci_core::Candidate {
                    id: probe.id.clone(),
                    axis: EnvironmentAxis::Dependencies,
                    label: format!(
                        "{} dependency probe {} ({})",
                        baseline.runtime, probe.id, identity
                    ),
                    version: probe.dependency_set.candidate.set_id.clone(),
                    channel: "content-addressed".into(),
                    grade_if_executed: EvidenceGrade::Observed,
                    order_key: format!("{index:04}"),
                    dependency_set: Some(probe.dependency_set.clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(candidates);
    }

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
            dependency_set: None,
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
            dependency_set: None,
        });
    }
    Ok(out)
}

fn normalize_image(eco: Ecosystem, runtime: &str) -> String {
    match eco {
        Ecosystem::Python => {
            if runtime.contains("python:") {
                if runtime.contains('-') {
                    runtime.to_string()
                } else {
                    format!("{runtime}-slim")
                }
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
            if runtime == "nightly" || runtime == "rust:nightly" {
                "rustlang/rust:nightly".into()
            } else if runtime.starts_with("rust:") {
                runtime.to_string()
            } else {
                format!("rust:{runtime}-bookworm")
            }
        }
        Ecosystem::Unknown => runtime.to_string(),
    }
}

fn build_fetch_commands(
    eco: Ecosystem,
    scenario: &Scenario,
    work: &Path,
    scripted: bool,
) -> Result<Option<Vec<CommandSpec>>> {
    if let Some(commands) = concrete_dependency_fetch_commands(eco, scenario)? {
        return Ok(Some(commands));
    }
    let upgrade =
        scenario.dependencies == "latest-allowed" || scenario.dependencies == "prerelease";
    match eco {
        Ecosystem::Python => {
            if scripted {
                // Keep scripted harness free of host filesystem requirements for venv paths
                return Ok(Some(vec![CommandSpec {
                    argv: vec!["true".into()],
                    cwd: Some("/work".into()),
                    network: true,
                    phase: "fetch".into(),
                }]));
            }
            Ok(Some(python_fetch_commands(work, upgrade, &scenario.id)?))
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
            Ok(Some(vec![CommandSpec {
                argv,
                cwd: Some("/work".into()),
                network: true,
                phase: "fetch".into(),
            }]))
        }
        Ecosystem::Rust => Ok(Some(vec![CommandSpec {
            argv: vec!["cargo".into(), "fetch".into()],
            cwd: Some("/work".into()),
            network: true,
            phase: "fetch".into(),
        }])),
        Ecosystem::Unknown => Ok(None),
    }
}

fn build_scenario_commands(
    adapter: &dyn EcosystemAdapter,
    scenario: &Scenario,
    config: &Config,
    _work: &Path,
) -> Result<Vec<CommandSpec>> {
    adapter.commands(scenario, config)
}

fn blocked_result(
    scenario: &Scenario,
    env: &EnvironmentSpec,
    commands: &[CommandSpec],
    detail: &str,
) -> ExecutionResult {
    ExecutionResult {
        scenario_id: scenario.id.clone(),
        attempt: 0,
        verdict: Verdict::Blocked,
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        failure: Some(FailureSignature {
            kind: "Blocked".into(),
            summary: detail.chars().take(200).collect(),
            normalized_hash: tomorrowci_core::sha256_str(detail),
            primary_frame: None,
        }),
        environment: env.clone(),
        commands: commands.to_vec(),
    }
}

fn baseline_requires_early_stop(scenario: &Scenario, result: &ExecutionResult) -> bool {
    scenario.is_baseline && result.verdict != Verdict::BaselinePass
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

#[allow(clippy::too_many_arguments)]
fn write_phase(
    sc_dir: &Path,
    phase: &str,
    ok: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    network: &str,
    image_tag: &str,
    image_digest: Option<String>,
    commands: &[CommandSpec],
    detail: &str,
    started: Option<chrono::DateTime<Utc>>,
    finished: Option<chrono::DateTime<Utc>>,
) -> Result<()> {
    let started = started.unwrap_or_else(Utc::now);
    let finished = finished.unwrap_or_else(Utc::now);
    let pr = PhaseResult {
        phase: phase.into(),
        ok,
        exit_code,
        timed_out,
        duration_ms,
        network: network.into(),
        image: image_tag.into(),
        image_digest,
        argv: commands.iter().map(|c| c.argv.clone()).collect(),
        started_at: started.to_rfc3339(),
        finished_at: finished.to_rfc3339(),
        detail: detail.into(),
    };
    std::fs::write(
        sc_dir.join(format!("{phase}-phase.json")),
        serde_json::to_string_pretty(&pr)?,
    )?;
    Ok(())
}

fn write_raw_logs(sc_dir: &Path, prefix: &str, raw: &RawExecutionResult) -> Result<()> {
    std::fs::write(sc_dir.join(format!("{prefix}-stdout.log")), &raw.stdout)?;
    std::fs::write(sc_dir.join(format!("{prefix}-stderr.log")), &raw.stderr)?;
    Ok(())
}

fn fr_json(
    raw: &RawExecutionResult,
    started: chrono::DateTime<Utc>,
    finished: Option<chrono::DateTime<Utc>>,
) -> serde_json::Value {
    let finished = finished.unwrap_or_else(Utc::now);
    serde_json::json!({
        "exit_code": raw.exit_code,
        "timed_out": raw.timed_out,
        "duration_ms": raw.duration_ms,
        "network_used": raw.network_used,
        "started_at": started.to_rfc3339(),
        "finished_at": finished.to_rfc3339(),
    })
}

fn elapsed_ms(started: chrono::DateTime<Utc>, finished: chrono::DateTime<Utc>) -> u64 {
    finished
        .signed_duration_since(started)
        .num_milliseconds()
        .max(0) as u64
}

fn not_run_summary(scenario: &Scenario, reason: &str) -> TestAttemptsSummary {
    TestAttemptsSummary {
        scenario_id: scenario.id.clone(),
        status: TestExecutionStatus::NotRun,
        attempts: Vec::new(),
        error: Some(reason.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_scenario_artifacts(
    sc_dir: &Path,
    scenario: &Scenario,
    env: &EnvironmentSpec,
    fetch_cmds: &[CommandSpec],
    test_cmds: &[CommandSpec],
    fetch_raw: Option<&RawExecutionResult>,
    test_raw: Option<&RawExecutionResult>,
    exec: &ExecutionResult,
    engine: String,
    failure: Option<&FailureSignature>,
    test_attempts: &TestAttemptsSummary,
) -> Result<()> {
    let mut combined_commands = fetch_cmds.to_vec();
    combined_commands.extend(test_cmds.to_vec());
    layout_write_scenario_meta(sc_dir, scenario, env, &combined_commands)?;
    std::fs::write(
        sc_dir.join("fetch-commands.json"),
        serde_json::to_string_pretty(fetch_cmds)?,
    )?;
    std::fs::write(
        sc_dir.join("test-commands.json"),
        serde_json::to_string_pretty(test_cmds)?,
    )?;
    std::fs::write(
        sc_dir.join("result.json"),
        serde_json::to_string_pretty(exec)?,
    )?;
    std::fs::write(
        sc_dir.join("test-attempts.json"),
        serde_json::to_string_pretty(test_attempts)?,
    )?;
    if let Some(dependencies) = &scenario.resolved_dependencies {
        std::fs::write(
            sc_dir.join("resolved-dependencies.json"),
            serde_json::to_string_pretty(dependencies)?,
        )?;
    }
    if let Some(raw) = test_raw {
        std::fs::write(sc_dir.join("stdout.log"), &raw.stdout)?;
        std::fs::write(sc_dir.join("stderr.log"), &raw.stderr)?;
    } else {
        std::fs::write(sc_dir.join("stdout.log"), [])?;
        std::fs::write(sc_dir.join("stderr.log"), [])?;
    }
    if let Some(f) = failure {
        std::fs::write(
            sc_dir.join("failure-signature.json"),
            serde_json::to_string_pretty(f)?,
        )?;
    } else if sc_dir.join("failure-signature.json").exists() {
        std::fs::remove_file(sc_dir.join("failure-signature.json"))?;
    }
    let replay = serde_json::json!({
        "scenario_id": scenario.id,
        "engine": env.engine,
        "engine_version": env.engine_version,
        "image": env.tag(),
        "image_digest": env.image_digest,
        "workdir": env.workdir,
        "user": env.user,
        "memory_mb": env.memory_mb,
        "cpus": env.cpus,
        "pids_limit": env.pids_limit,
        "read_only_root": env.read_only_root,
        "fetch_network": "bridge",
        "test_network": "none",
        "fetch_timeout_seconds": env.fetch_timeout_seconds,
        "test_timeout_seconds": env.test_timeout_seconds,
        "fetch_argv": fetch_cmds.iter().map(|c| c.argv.clone()).collect::<Vec<_>>(),
        "test_argv": test_cmds.iter().map(|c| c.argv.clone()).collect::<Vec<_>>(),
        "expected_exit_code": exec.exit_code,
        "expected_timed_out": exec.timed_out,
        "expected_failure_signature": failure,
        "resolved_dependencies": scenario.resolved_dependencies,
    });
    std::fs::write(
        sc_dir.join("replay.json"),
        serde_json::to_string_pretty(&replay)?,
    )?;
    write_replay_scripts(sc_dir, env, fetch_cmds, test_cmds, &scenario.id, &engine)?;

    let mut checksums = Vec::new();
    for name in [
        "scenario.json",
        "environment.json",
        "fetch-commands.json",
        "test-commands.json",
        "commands.json",
        "test-attempts.json",
        "resolved-dependencies.json",
        "image-resolve-phase.json",
        "fetch-phase.json",
        "test-phase.json",
        "result.json",
        "stdout.log",
        "stderr.log",
        "failure-signature.json",
        "replay.json",
        "replay.sh",
        "replay.ps1",
        "fetch-result.json",
        "test-result.json",
    ] {
        let p = sc_dir.join(name);
        if p.exists() {
            checksums.push((name.into(), tomorrowci_evidence::file_checksum(&p)?));
        }
    }
    if let Some(raw) = fetch_raw {
        let _ = raw; // already on disk if written
    }
    write_checksums(sc_dir, &checksums)?;
    Ok(())
}

fn write_replay_scripts(
    sc_dir: &Path,
    env: &EnvironmentSpec,
    fetch_cmds: &[CommandSpec],
    test_cmds: &[CommandSpec],
    scenario_id: &str,
    engine: &str,
) -> Result<()> {
    let bin = if engine == "podman" {
        "podman"
    } else {
        "docker"
    };
    let image = env
        .image_digest
        .clone()
        .filter(|d| d.contains("sha256:") || d.starts_with("sha256:"))
        .unwrap_or_else(|| env.image.clone());
    let user = env
        .user
        .as_ref()
        .map(|u| format!(" --user {u}"))
        .unwrap_or_default();
    let fetch = fetch_cmds
        .iter()
        .map(|c| shell_join(&c.argv))
        .collect::<Vec<_>>()
        .join(" && ");
    let test = test_cmds
        .iter()
        .map(|c| shell_join(&c.argv))
        .collect::<Vec<_>>()
        .join(" && ");
    let mem = env.memory_mb;
    let cpus = env.cpus;
    let pids = env.pids_limit;
    let ro = if env.read_only_root {
        " --read-only --tmpfs /tmp:rw,exec,nosuid,size=256m"
    } else {
        ""
    };
    let sh = format!(
        r#"#!/usr/bin/env bash
# Replay scenario {scenario_id} — digest-pinned; workspace must be recorded copy
set -euo pipefail
IMG={image:?}
WORK="${{TOMORROWCI_WORKSPACE:-$PWD}}"
{bin} run --rm --network bridge --memory {mem}m --cpus {cpus} --pids-limit {pids} \
  --security-opt no-new-privileges --cap-drop ALL{user}{ro} \
  -v "$WORK":/work -w /work "$IMG" sh -c {fetch:?}
{bin} run --rm --network none --memory {mem}m --cpus {cpus} --pids-limit {pids} \
  --security-opt no-new-privileges --cap-drop ALL{user}{ro} \
  -v "$WORK":/work -w /work "$IMG" sh -c {test:?}
"#
    );
    std::fs::write(sc_dir.join("replay.sh"), sh)?;
    let ps1 = format!(
        r#"# Replay scenario {scenario_id}
$Img = {image:?}
$Work = if ($env:TOMORROWCI_WORKSPACE) {{ $env:TOMORROWCI_WORKSPACE }} else {{ $PWD }}
{bin} run --rm --network bridge --memory {mem}m --cpus {cpus} --pids-limit {pids} --security-opt no-new-privileges --cap-drop ALL{user}{ro} -v "${{Work}}:/work" -w /work $Img sh -c {fetch:?}
{bin} run --rm --network none --memory {mem}m --cpus {cpus} --pids-limit {pids} --security-opt no-new-privileges --cap-drop ALL{user}{ro} -v "${{Work}}:/work" -w /work $Img sh -c {test:?}
"#
    );
    std::fs::write(sc_dir.join("replay.ps1"), ps1)?;
    Ok(())
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
        if let Some(ref d) = r.environment.image_digest {
            out.push_str(&format!("  digest: {d}\n"));
        }
    }
    out.push('\n');
    let planned_candidates = m.plan.scenarios.iter().filter(|s| !s.is_baseline).count();
    let tested_candidates = m
        .results
        .iter()
        .filter(|r| {
            r.attempt > 0
                && m.plan
                    .scenarios
                    .iter()
                    .any(|s| s.id == r.scenario_id && !s.is_baseline)
        })
        .count();
    out.push_str(&format!(
        "Candidate coverage: {tested_candidates} tested / {planned_candidates} planned.\n"
    ));
    if planned_candidates == 0 {
        out.push_str("NO_CANDIDATES: no candidate scenarios were planned; future compatibility was not evaluated.\n");
    }
    out.push_str("Scope: observed results for these candidates only; passing does not establish compatibility with untested versions.\n");
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
    validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
    let root = tomorrowci_evidence::find_run_dir(repo, run_id);
    verify_evidence_for_operation(&root, false)?;
    let _lock = EvidenceOperationLock::acquire(&root, "explain")?;
    let m = load_stable_verified_manifest(&root, false)?;
    Ok(render_terminal_summary(&m))
}

fn verify_replay_evidence(root: &Path) -> Result<()> {
    verify_evidence_for_operation(root, true)
}

fn verify_evidence_for_operation(root: &Path, require_current: bool) -> Result<()> {
    let report = tomorrowci_evidence::verify_run_root(root).map_err(|error| {
        TcError::Blocked(format!(
            "evidence integrity verification could not complete: {error}"
        ))
    })?;
    if !report.ok {
        return Err(TcError::Blocked(format!(
            "evidence integrity verification failed: {}",
            report.errors.join("; ")
        )));
    }
    if require_current && report.checksum_compatibility != ChecksumCompatibility::CurrentV2 {
        return Err(TcError::Blocked(
            "legacy evidence is read-compatible only and cannot authorize replay".into(),
        ));
    }
    Ok(())
}

struct EvidenceOperationLock {
    path: PathBuf,
    _file: std::fs::File,
}

impl EvidenceOperationLock {
    fn acquire(root: &Path, operation: &str) -> Result<Self> {
        tomorrowci_evidence::validate_existing_ancestors(root)
            .map_err(|error| TcError::Blocked(format!("{operation}: unsafe run path: {error}")))?;
        let run_id = root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| TcError::InvalidState("run directory name is not UTF-8".into()))?;
        validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
        let parent = root
            .parent()
            .ok_or_else(|| TcError::InvalidState("run root has no parent".into()))?;
        let path = parent.join(format!(".{run_id}.operation.lock"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                TcError::Blocked(format!(
                    "{operation}: could not acquire exclusive evidence lock {}: {error}",
                    path.display()
                ))
            })?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for EvidenceOperationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn load_stable_verified_manifest(root: &Path, require_current: bool) -> Result<RunManifest> {
    verify_evidence_for_operation(root, require_current)?;
    let run_path = root.join("run.json");
    let before = std::fs::read(&run_path)?;
    let manifest = serde_json::from_slice(&before)?;
    verify_evidence_for_operation(root, require_current)?;
    let after = std::fs::read(&run_path)?;
    if before != after {
        return Err(TcError::Blocked(
            "run.json changed during trusted evidence read".into(),
        ));
    }
    Ok(manifest)
}

fn prepare_dependency_materialization_root(workspace: &Path, scenario: &Scenario) -> Result<()> {
    let is_rust = scenario
        .resolved_dependencies
        .as_ref()
        .is_some_and(|set| set.ecosystem == Ecosystem::Rust);
    if !is_rust {
        return Ok(());
    }
    let root = workspace.join("vendor").join("tomorrowci-selected");
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) => {
            if metadata_is_alias(&metadata) || !metadata.is_dir() {
                return Err(TcError::Blocked(format!(
                    "Rust dependency materialization root is not a plain directory: {}",
                    root.display()
                )));
            }
            if std::fs::read_dir(&root)?.next().transpose()?.is_some() {
                return Err(TcError::Blocked(format!(
                    "Rust dependency materialization root must be absent or empty: {}",
                    root.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&root)?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777))?;
        // Cargo rewrites Cargo.lock via a temporary file in the project root.
        // This is a disposable scenario snapshot, never the recorded evidence
        // workspace, so granting the sandbox UID write access is safe here.
        std::fs::set_permissions(workspace, std::fs::Permissions::from_mode(0o777))?;
        let lock = workspace.join("Cargo.lock");
        if lock.is_file() {
            std::fs::set_permissions(lock, std::fs::Permissions::from_mode(0o666))?;
        }
    }
    Ok(())
}

fn prepare_node_runtime_workspace(workspace: &Path) -> Result<()> {
    let workspace = validate_existing_ancestors(workspace)?;

    // The official Node images run this adapter as the unprivileged `node`
    // account. Project test suites can install packages below existing nested
    // package roots, so every plain directory in this disposable scenario copy
    // must be writable. This preparation step does not rewrite regular-file
    // bytes or modes, and the recorded authority is never passed here. Aliases
    // and special filesystem entries fail closed.
    let mut directories = collect_plain_workspace_directories(&workspace)?;
    let modules = workspace.join("node_modules");
    match std::fs::symlink_metadata(&modules) {
        Ok(metadata) => {
            if metadata_is_alias(&metadata) || !metadata.is_dir() {
                return Err(TcError::InvalidState(format!(
                    "Node dependency root is not a plain directory: {}",
                    modules.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&modules)?;
            directories.push(modules.clone());
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        directories.sort_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });

        // Open and validate every directory before changing any mode. fchmod on
        // the stable handles cannot follow a path swapped to an outside alias.
        let mut handles = Vec::with_capacity(directories.len());
        for directory in directories {
            let directory = validate_existing_ancestors(&directory)?;
            let expected = std::fs::symlink_metadata(&directory)?;
            if metadata_is_alias(&expected) || !expected.is_dir() {
                return Err(TcError::InvalidState(format!(
                    "Node disposable workspace directory changed during preparation: {}",
                    directory.display()
                )));
            }

            let handle = std::fs::File::open(&directory)?;
            let opened = handle.metadata()?;
            if !opened.is_dir() || expected.dev() != opened.dev() || expected.ino() != opened.ino()
            {
                return Err(TcError::InvalidState(format!(
                    "Node disposable workspace directory changed while opening: {}",
                    directory.display()
                )));
            }
            handles.push((directory, handle));
        }
        for (_, handle) in handles {
            handle.set_permissions(std::fs::Permissions::from_mode(0o777))?;
        }
    }
    Ok(())
}

fn collect_plain_workspace_directories(workspace: &Path) -> Result<Vec<PathBuf>> {
    let workspace = validate_existing_ancestors(workspace)?;
    let metadata = std::fs::symlink_metadata(&workspace)?;
    if metadata_is_alias(&metadata) || !metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "Node disposable workspace is not a plain directory: {}",
            workspace.display()
        )));
    }

    let mut pending = vec![workspace];
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&directory)?;
        if metadata_is_alias(&metadata) || !metadata.is_dir() {
            return Err(TcError::InvalidState(format!(
                "Node disposable workspace directory is not plain: {}",
                directory.display()
            )));
        }
        directories.push(directory.clone());

        let mut entries = std::fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata_is_alias(&metadata) {
                return Err(TcError::InvalidState(format!(
                    "refusing symlink/reparse point in Node disposable workspace: {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if !metadata.is_file() {
                return Err(TcError::InvalidState(format!(
                    "unsupported entry in Node disposable workspace: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(directories)
}

struct DisposableWorkspace {
    path: PathBuf,
}

impl DisposableWorkspace {
    fn capture(recorded_workspace: &Path) -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("tomorrowci-replay-{}", Uuid::new_v4().simple()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&root)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&root)?;

        let path = root.join("workspace");
        let disposable = Self { path };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        let source_manifest =
            write_workspace_manifest(recorded_workspace, &root.join("source-manifest.json"))?;
        make_disposable_copy(recorded_workspace, disposable.path())?;
        let copied_manifest =
            write_workspace_manifest(disposable.path(), &root.join("copy-manifest.json"))?;
        if source_manifest != copied_manifest {
            return Err(TcError::Blocked(
                "recorded workspace changed while replay snapshot was captured".into(),
            ));
        }
        Ok(disposable)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn prepare_runtime(&self, ecosystem: Ecosystem) -> Result<()> {
        if ecosystem == Ecosystem::Node {
            prepare_node_runtime_workspace(self.path())?;
        }
        Ok(())
    }
}

impl Drop for DisposableWorkspace {
    fn drop(&mut self) {
        if let Some(root) = self.path.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn inspect_replay_attempts(sc_dir: &Path) -> Result<usize> {
    let replays = sc_dir.join("replays");
    let metadata = match std::fs::symlink_metadata(&replays) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(error) => return Err(error.into()),
    };
    if metadata_is_alias(&metadata) || !metadata.is_dir() {
        return Err(TcError::InvalidState(format!(
            "replay attempt root is not a plain directory: {}",
            replays.display()
        )));
    }

    let mut attempts = Vec::new();
    for entry in std::fs::read_dir(&replays)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata_is_alias(&metadata) || !metadata.is_dir() {
            return Err(TcError::InvalidState(format!(
                "replay attempt entry is not a plain directory: {}",
                path.display()
            )));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            TcError::InvalidState(format!(
                "replay attempt directory name is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        let number = name
            .strip_prefix("attempt-")
            .and_then(|raw| raw.parse::<usize>().ok())
            .filter(|number| *number > 0)
            .ok_or_else(|| {
                TcError::InvalidState(format!("invalid replay attempt directory name: {name:?}"))
            })?;
        if name != format!("attempt-{number}") {
            return Err(TcError::InvalidState(format!(
                "non-canonical replay attempt directory name: {name:?}"
            )));
        }
        for required in ["result.json", "stdout.log", "stderr.log"] {
            let required_path = path.join(required);
            let metadata = std::fs::symlink_metadata(&required_path).map_err(|error| {
                TcError::InvalidState(format!(
                    "incomplete replay {name}: required file {} is unavailable: {error}",
                    required_path.display()
                ))
            })?;
            if metadata_is_alias(&metadata) || !metadata.is_file() {
                return Err(TcError::InvalidState(format!(
                    "invalid replay {name}: required entry is not a plain file: {}",
                    required_path.display()
                )));
            }
        }
        attempts.push(number);
    }

    attempts.sort_unstable();
    for (index, actual) in attempts.iter().enumerate() {
        let expected = index + 1;
        if *actual != expected {
            return Err(TcError::InvalidState(format!(
                "replay attempts must be contiguous and append-only: expected attempt-{expected}, found attempt-{actual}"
            )));
        }
    }
    attempts
        .len()
        .checked_add(1)
        .ok_or_else(|| TcError::InvalidState("replay attempt number overflow".into()))
}

struct ReplayAttemptTransaction {
    number: usize,
    staging_dir: PathBuf,
    committed_dir: PathBuf,
}

impl ReplayAttemptTransaction {
    fn commit(self, report: &serde_json::Value, stdout: &[u8], stderr: &[u8]) -> Result<PathBuf> {
        std::fs::write(
            self.staging_dir.join("result.json"),
            serde_json::to_string_pretty(report)?,
        )?;
        std::fs::write(self.staging_dir.join("stdout.log"), stdout)?;
        std::fs::write(self.staging_dir.join("stderr.log"), stderr)?;

        if self.committed_dir.exists() {
            return Err(TcError::InvalidState(format!(
                "replay attempt collision detected before commit: {}",
                self.committed_dir.display()
            )));
        }
        std::fs::rename(&self.staging_dir, &self.committed_dir).map_err(|error| {
            TcError::InvalidState(format!(
                "could not atomically commit replay attempt {} (complete staging preserved at {}): {error}",
                self.number,
                self.staging_dir.display()
            ))
        })?;
        Ok(self.committed_dir.clone())
    }
}

impl Drop for ReplayAttemptTransaction {
    fn drop(&mut self) {
        if self.staging_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.staging_dir);
        }
    }
}

fn reserve_replay_attempt(sc_dir: &Path) -> Result<ReplayAttemptTransaction> {
    let attempt_number = inspect_replay_attempts(sc_dir)?;
    let replays = sc_dir.join("replays");
    if !replays.exists() {
        std::fs::create_dir(&replays).map_err(|error| {
            TcError::InvalidState(format!(
                "could not create replay attempt root without collision ({}): {error}",
                replays.display()
            ))
        })?;
    }
    let committed_dir = replays.join(format!("attempt-{attempt_number}"));
    if committed_dir.exists() {
        return Err(TcError::InvalidState(format!(
            "replay attempt collision detected before execution: {}",
            committed_dir.display()
        )));
    }
    let staging_dir = replays.join(format!(".attempt-{attempt_number}.staging"));
    std::fs::create_dir(&staging_dir).map_err(|error| {
        TcError::InvalidState(format!(
            "could not reserve replay attempt without collision ({}): {error}",
            staging_dir.display()
        ))
    })?;
    Ok(ReplayAttemptTransaction {
        number: attempt_number,
        staging_dir,
        committed_dir,
    })
}

fn normalize_replay_failure(ecosystem: Ecosystem, raw: &RawExecutionResult) -> FailureSignature {
    match ecosystem {
        Ecosystem::Python => PythonAdapter.normalize_failure(raw),
        Ecosystem::Node => NodeAdapter.normalize_failure(raw),
        Ecosystem::Rust => RustAdapter.normalize_failure(raw),
        Ecosystem::Unknown => {
            let blob = format!("{}\n{}", raw.stdout, raw.stderr);
            FailureSignature {
                kind: "UnknownEcosystemFailure".into(),
                summary: blob
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("unknown failure")
                    .chars()
                    .take(200)
                    .collect(),
                normalized_hash: tomorrowci_core::sha256_str(&blob),
                primary_frame: None,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn replay_attempt_report(
    scenario_id: &str,
    attempt: usize,
    phase: &str,
    ok: bool,
    started: chrono::DateTime<Utc>,
    finished: chrono::DateTime<Utc>,
    original: &ExecutionResult,
    fetch: Option<&RawExecutionResult>,
    replay: Option<&RawExecutionResult>,
    new_signature: Option<&FailureSignature>,
    recorded_digest: &str,
    resolved_digest: &str,
    environment: &EnvironmentSpec,
    dependency_manifest_sha256: Option<&tomorrowci_core::ContentHash>,
    exit_match: Option<bool>,
    signature_match: Option<bool>,
    error: Option<&str>,
) -> serde_json::Value {
    let latest = replay.or(fetch);
    serde_json::json!({
        "scenario_id": scenario_id,
        "attempt": attempt,
        "phase": phase,
        "ok": ok,
        "started_at": started.to_rfc3339(),
        "finished_at": finished.to_rfc3339(),
        "original_exit": original.exit_code,
        "fetch_exit": fetch.and_then(|raw| raw.exit_code),
        "replay_exit": replay.and_then(|raw| raw.exit_code),
        "timed_out": latest.map(|raw| raw.timed_out).unwrap_or(false),
        "duration_ms": latest.map(|raw| raw.duration_ms).unwrap_or(0),
        "original_signature": original.failure.as_ref().map(|failure| &failure.normalized_hash),
        "replay_signature": new_signature.map(|failure| &failure.normalized_hash),
        "exit_match": exit_match,
        "signature_match": signature_match,
        "recorded_digest": recorded_digest,
        "resolved_digest": resolved_digest,
        "engine": environment.engine.as_deref(),
        "engine_version": environment.engine_version.as_deref(),
        "image_tag": environment.tag(),
        "fetch_timeout_seconds": environment.fetch_timeout_seconds,
        "test_timeout_seconds": environment.test_timeout_seconds,
        "dependency_manifest_sha256": dependency_manifest_sha256,
        "error": error,
    })
}

fn complete_replay_attempt(
    root: &Path,
    scenario_dir: &Path,
    transaction: ReplayAttemptTransaction,
    report: &serde_json::Value,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<()> {
    let replay_result = scenario_dir.join("replay-result.json");
    let root_checksums = root.join("checksums.txt");
    let scenario_checksums = scenario_dir.join("checksums.txt");
    let previous_replay_result = read_optional_file(&replay_result)?;
    let previous_root_checksums = std::fs::read(&root_checksums)?;
    let previous_scenario_checksums = std::fs::read(&scenario_checksums)?;

    let committed = transaction.commit(report, stdout, stderr)?;
    let finalize = (|| -> Result<()> {
        std::fs::write(&replay_result, serde_json::to_string_pretty(report)?)?;
        tomorrowci_evidence::finalize_run_checksums(root)?;
        verify_replay_evidence(root)
    })();
    if let Err(error) = finalize {
        let rollback = (|| -> Result<()> {
            if committed.exists() {
                std::fs::remove_dir_all(&committed)?;
            }
            restore_optional_file(&replay_result, previous_replay_result.as_deref())?;
            std::fs::write(&scenario_checksums, &previous_scenario_checksums)?;
            std::fs::write(&root_checksums, &previous_root_checksums)?;
            verify_replay_evidence(root)
        })();
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(TcError::InvalidState(format!(
                "replay post-commit verification failed ({error}); rollback also failed ({rollback_error})"
            ))),
        };
    }
    Ok(())
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn restore_optional_file(path: &Path, contents: Option<&[u8]>) -> Result<()> {
    match contents {
        Some(contents) => std::fs::write(path, contents)?,
        None if path.exists() => std::fs::remove_file(path)?,
        None => {}
    }
    Ok(())
}

/// Exact replay: recorded digest, fetch+test, compare exit + failure signature.
pub fn replay_scenario(repo: &Path, run_id: &str, scenario_id: &str) -> Result<String> {
    validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
    validate_identifier(scenario_id, "scenario_id").map_err(TcError::InvalidState)?;
    let root = repo.join(".tomorrowci/runs").join(run_id);
    verify_replay_evidence(&root)?;
    let _lock = EvidenceOperationLock::acquire(&root, "replay")?;
    verify_replay_evidence(&root)?;
    let environment_path = root
        .join("scenarios")
        .join(scenario_id)
        .join("environment.json");
    let before = std::fs::read(&environment_path)?;
    let environment: EnvironmentSpec = serde_json::from_slice(&before)?;
    verify_replay_evidence(&root)?;
    if before != std::fs::read(&environment_path)? {
        return Err(TcError::Blocked(
            "environment.json changed while selecting the recorded replay engine".into(),
        ));
    }
    let recorded_engine = environment.engine.as_deref().ok_or_else(|| {
        TcError::Blocked("recorded replay environment has no authoritative engine".into())
    })?;
    let executor = ContainerExecutor::detect_requested(recorded_engine)?;
    replay_scenario_with_verified_evidence(&root, scenario_id, &executor)
}

#[cfg(test)]
pub(crate) fn replay_scenario_with_executor(
    repo: &Path,
    run_id: &str,
    scenario_id: &str,
    executor: &dyn ScenarioExecutor,
) -> Result<String> {
    validate_identifier(run_id, "run_id").map_err(TcError::InvalidState)?;
    validate_identifier(scenario_id, "scenario_id").map_err(TcError::InvalidState)?;
    let root = repo.join(".tomorrowci/runs").join(run_id);
    verify_replay_evidence(&root)?;
    let _lock = EvidenceOperationLock::acquire(&root, "replay test")?;
    verify_replay_evidence(&root)?;
    replay_scenario_with_verified_evidence(&root, scenario_id, executor)
}

fn replay_scenario_with_verified_evidence(
    root: &Path,
    scenario_id: &str,
    executor: &dyn ScenarioExecutor,
) -> Result<String> {
    validate_identifier(scenario_id, "scenario_id").map_err(TcError::InvalidState)?;
    let m = load_stable_verified_manifest(root, true)?;
    let sc_dir = root.join("scenarios").join(scenario_id);
    if !sc_dir.join("result.json").exists() {
        return Err(TcError::Blocked(format!(
            "scenario evidence missing for {scenario_id}"
        )));
    }

    let original: ExecutionResult =
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("result.json"))?)?;
    let env: EnvironmentSpec =
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("environment.json"))?)?;
    let fetch_cmds: Vec<CommandSpec> = if sc_dir.join("fetch-commands.json").exists() {
        serde_json::from_str(&std::fs::read_to_string(
            sc_dir.join("fetch-commands.json"),
        )?)?
    } else {
        Vec::new()
    };
    let test_cmds: Vec<CommandSpec> = if sc_dir.join("test-commands.json").exists() {
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("test-commands.json"))?)?
    } else {
        serde_json::from_str(&std::fs::read_to_string(sc_dir.join("commands.json"))?)?
    };
    let scenario = m
        .plan
        .scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .cloned()
        .ok_or_else(|| TcError::Other("scenario not in manifest".into()))?;

    let recorded_digest = env.image_digest.clone().ok_or_else(|| {
        TcError::Blocked("recorded image digest missing; cannot exact-replay".into())
    })?;
    let recorded_digest_value = tomorrowci_core::canonical_image_digest_value(&recorded_digest)
        .map_err(|error| TcError::Blocked(format!("recorded image digest is invalid: {error}")))?;

    let actual_engine = executor.engine_label();
    let actual_engine_version = executor.engine_version().ok_or_else(|| {
        TcError::Blocked("replay executor did not expose an exact engine version".into())
    })?;
    if env.engine.as_deref() != Some(actual_engine.as_str())
        || env.engine_version.as_deref() != Some(actual_engine_version.as_str())
    {
        return Err(TcError::Blocked(format!(
            "replay engine identity changed: recorded={:?}/{:?} actual={actual_engine}/{actual_engine_version}",
            env.engine, env.engine_version
        )));
    }
    let fetch_seconds = env
        .fetch_timeout_seconds
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            TcError::Blocked("recorded fetch timeout missing; cannot exact-replay".into())
        })?;
    let test_seconds = env
        .test_timeout_seconds
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            TcError::Blocked("recorded test timeout missing; cannot exact-replay".into())
        })?;

    let work = root.join("workspace");
    if !work.exists() {
        return Err(TcError::Blocked(
            "workspace snapshot missing for replay; external artifact unavailable".into(),
        ));
    }
    let replay_synthetic_git_index = prepared_synthetic_git_index_for_replay(root, &work)?;

    // Reject malformed/gapped history before any external image resolution or target execution.
    inspect_replay_attempts(&sc_dir)?;

    // Resolve and require same digest
    let resolved = executor.ensure_image(&recorded_digest)?;
    let resolved_digest_value = tomorrowci_core::canonical_image_digest_value(&resolved)
        .map_err(|error| TcError::Blocked(format!("resolved image digest is invalid: {error}")))?;
    if resolved_digest_value != recorded_digest_value {
        return Err(TcError::Blocked(format!(
            "image digest changed: recorded={recorded_digest} resolved={resolved}"
        )));
    }

    // Keep image_tag as tag; digest only in image_digest
    let mut env_run = env.clone();
    env_run.image_digest = Some(recorded_digest.clone());
    env_run.image = env.tag().to_string();
    env_run.image_tag = env.tag().to_string();

    let fetch_to = Duration::from_secs(fetch_seconds);
    let test_to = Duration::from_secs(test_seconds);

    let replay_workspace = DisposableWorkspace::capture(&work)?;
    if let Some(prepared) = &replay_synthetic_git_index {
        install_synthetic_git_index(replay_workspace.path(), prepared)?;
    }
    prepare_scenario_state(replay_workspace.path())?;
    replay_workspace.prepare_runtime(m.detection.ecosystem)?;
    prepare_dependency_materialization_root(replay_workspace.path(), &scenario)?;
    verify_replay_evidence(root)?;

    // The staging directory is an atomic reservation/lock. No target command may
    // execute unless this succeeds, and concurrent replays collide here first.
    let transaction = reserve_replay_attempt(&sc_dir)?;
    let attempt_n = transaction.number;
    let started = Utc::now();
    let mut fetch_raw = None;
    if !fetch_cmds.is_empty() {
        let fetch_result = executor.execute(&ExecutionContext {
            workspace: replay_workspace.path(),
            scenario: &scenario,
            environment: &env_run,
            commands: &fetch_cmds,
            timeout: fetch_to,
            network: "bridge",
        });
        let fr = match fetch_result {
            Ok(raw) => raw,
            Err(error) => {
                let finished = Utc::now();
                let error_message = error.to_string();
                let report = replay_attempt_report(
                    scenario_id,
                    attempt_n,
                    "fetch",
                    false,
                    started,
                    finished,
                    &original,
                    None,
                    None,
                    None,
                    &recorded_digest,
                    &resolved,
                    &env_run,
                    scenario
                        .resolved_dependencies
                        .as_ref()
                        .map(|set| &set.manifest_sha256),
                    None,
                    None,
                    Some(&error_message),
                );
                complete_replay_attempt(
                    root,
                    &sc_dir,
                    transaction,
                    &report,
                    &[],
                    error_message.as_bytes(),
                )?;
                return Err(error);
            }
        };
        if fr.exit_code != Some(0) || fr.timed_out {
            let finished = Utc::now();
            let detail = format!(
                "replay fetch failed exit={:?} stderr={}",
                fr.exit_code,
                fr.stderr.chars().take(400).collect::<String>()
            );
            let report = replay_attempt_report(
                scenario_id,
                attempt_n,
                "fetch",
                false,
                started,
                finished,
                &original,
                Some(&fr),
                None,
                None,
                &recorded_digest,
                &resolved,
                &env_run,
                scenario
                    .resolved_dependencies
                    .as_ref()
                    .map(|set| &set.manifest_sha256),
                None,
                None,
                Some(&detail),
            );
            complete_replay_attempt(
                root,
                &sc_dir,
                transaction,
                &report,
                fr.stdout.as_bytes(),
                fr.stderr.as_bytes(),
            )?;
            return Err(TcError::Blocked(format!(
                "replay fetch failed exit={:?} stderr={}",
                fr.exit_code,
                fr.stderr.chars().take(400).collect::<String>()
            )));
        }
        fetch_raw = Some(fr);
    }

    let test_result = executor.execute(&ExecutionContext {
        workspace: replay_workspace.path(),
        scenario: &scenario,
        environment: &env_run,
        commands: &test_cmds,
        timeout: test_to,
        network: "none",
    });
    let raw = match test_result {
        Ok(raw) => raw,
        Err(error) => {
            let finished = Utc::now();
            let error_message = error.to_string();
            let report = replay_attempt_report(
                scenario_id,
                attempt_n,
                "test",
                false,
                started,
                finished,
                &original,
                fetch_raw.as_ref(),
                None,
                None,
                &recorded_digest,
                &resolved,
                &env_run,
                scenario
                    .resolved_dependencies
                    .as_ref()
                    .map(|set| &set.manifest_sha256),
                None,
                None,
                Some(&error_message),
            );
            let stdout = fetch_raw
                .as_ref()
                .map(|fetch| fetch.stdout.as_bytes())
                .unwrap_or_default();
            let mut stderr = fetch_raw
                .as_ref()
                .map(|fetch| fetch.stderr.clone())
                .unwrap_or_default();
            if !stderr.is_empty() {
                stderr.push('\n');
            }
            stderr.push_str(&error_message);
            complete_replay_attempt(
                root,
                &sc_dir,
                transaction,
                &report,
                stdout,
                stderr.as_bytes(),
            )?;
            return Err(error);
        }
    };
    let finished = Utc::now();

    let new_sig = if raw.exit_code != Some(0) || raw.timed_out {
        Some(normalize_replay_failure(m.detection.ecosystem, &raw))
    } else {
        None
    };

    let exit_match = raw.exit_code == original.exit_code && raw.timed_out == original.timed_out;
    let sig_match = match (&original.failure, &new_sig) {
        (Some(a), Some(b)) => a.normalized_hash == b.normalized_hash,
        (None, None) => true,
        _ => false,
    };

    let ok = exit_match && sig_match;
    let report = replay_attempt_report(
        scenario_id,
        attempt_n,
        "test",
        ok,
        started,
        finished,
        &original,
        fetch_raw.as_ref(),
        Some(&raw),
        new_sig.as_ref(),
        &recorded_digest,
        &resolved,
        &env_run,
        scenario
            .resolved_dependencies
            .as_ref()
            .map(|set| &set.manifest_sha256),
        Some(exit_match),
        Some(sig_match),
        None,
    );
    let mut stdout = fetch_raw
        .as_ref()
        .map(|fetch| fetch.stdout.clone())
        .unwrap_or_default();
    if !stdout.is_empty() && !raw.stdout.is_empty() {
        stdout.push('\n');
    }
    stdout.push_str(&raw.stdout);
    let mut stderr = fetch_raw
        .as_ref()
        .map(|fetch| fetch.stderr.clone())
        .unwrap_or_default();
    if !stderr.is_empty() && !raw.stderr.is_empty() {
        stderr.push('\n');
    }
    stderr.push_str(&raw.stderr);
    complete_replay_attempt(
        root,
        &sc_dir,
        transaction,
        &report,
        stdout.as_bytes(),
        stderr.as_bytes(),
    )?;

    let mut out = format!(
        "replay {scenario_id}: exit={:?} timed_out={} duration_ms={}\n",
        raw.exit_code, raw.timed_out, raw.duration_ms
    );
    out.push_str(&format!(
        "original_exit={:?} signature_match={sig_match} exit_match={exit_match}\n",
        original.exit_code
    ));
    if let Some(ref s) = new_sig {
        out.push_str(&format!("replay_signature={}\n", s.normalized_hash));
    }
    if let Some(ref s) = original.failure {
        out.push_str(&format!("original_signature={}\n", s.normalized_hash));
    }
    if !ok {
        return Err(TcError::Other(format!(
            "replay divergence for {scenario_id}: exit_match={exit_match} sig_match={sig_match}"
        )));
    }
    out.push_str("replay: PASS (exit + failure signature match)\n");
    Ok(out)
}

fn prepared_synthetic_git_index_for_replay(
    run_root: &Path,
    workspace: &Path,
) -> Result<Option<PreparedSyntheticGitIndex>> {
    let remote_path = run_root.join("remote-source.json");
    let before = match std::fs::read(&remote_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let remote: RemoteSourceRecord = serde_json::from_slice(&before)?;
    let Some(expected) = remote.synthetic_git_index else {
        if remote.schema_version == 1 {
            return Err(TcError::Blocked(
                "legacy remote-source schema v1 is verify-only; exact replay requires the schema v2 synthetic Git contract"
                    .into(),
            ));
        }
        return Err(TcError::Blocked(
            "remote replay has no synthetic Git index contract".into(),
        ));
    };
    if remote.schema_version != 2 {
        return Err(TcError::Blocked(
            "synthetic Git index is not valid for this remote-source schema".into(),
        ));
    }
    let workspace_manifest_path = run_root.join("workspace-manifest.json");
    let manifest: WorkspaceManifest =
        serde_json::from_slice(&std::fs::read(&workspace_manifest_path)?)?;
    let prepared = prepare_synthetic_git_index(
        workspace,
        &manifest,
        &tomorrowci_evidence::file_checksum(&workspace_manifest_path)?,
    )?;
    if prepared.record != expected {
        return Err(TcError::Blocked(
            "replay synthetic Git index differs from checksummed remote evidence".into(),
        ));
    }
    verify_replay_evidence(run_root)?;
    if before != std::fs::read(&remote_path)? {
        return Err(TcError::Blocked(
            "remote-source evidence changed while preparing replay Git metadata".into(),
        ));
    }
    Ok(Some(prepared))
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn write_python_fixture(root: &Path) {
        std::fs::write(root.join("requirements.txt"), "pytest==7.4.4\n").unwrap();
        std::fs::write(root.join("app.py"), "def ok():\n    return True\n").unwrap();
        std::fs::create_dir(root.join("tests")).unwrap();
        std::fs::write(
            root.join("tests/test_app.py"),
            "from app import ok\ndef test_ok():\n    assert ok()\n",
        )
        .unwrap();
    }

    #[test]
    fn pyproject_only_unsupported_baseline_requires_early_stop() {
        let repo = tempdir().unwrap();
        std::fs::write(
            repo.path().join("pyproject.toml"),
            "[project]\nname = \"focused\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\n",
        )
        .unwrap();
        let adapter = PythonAdapter;
        let detection = adapter.detect(repo.path());
        assert!(detection.supported);
        let mut config = Config::default();
        config.baseline.runtime = "3.9".into();
        config.candidates.dependencies.latest_allowed = false;
        let baseline = adapter.baseline(repo.path(), &config).unwrap();
        let (plan, _) = plan_scenarios(&baseline, &[], &[], &config);
        let scenario = &plan.scenarios[0];
        let environment = adapter.materialize(scenario, repo.path()).unwrap();
        let commands = adapter.commands(scenario, &config).unwrap();

        let message = match build_fetch_commands(Ecosystem::Python, scenario, repo.path(), false)
            .unwrap_err()
        {
            TcError::Unsupported(message) => message,
            error => panic!("expected unsupported fetch contract, got {error}"),
        };
        let mut result = blocked_result(scenario, &environment, &commands, &message);
        result.verdict = Verdict::Unsupported;
        assert!(baseline_requires_early_stop(scenario, &result));
    }

    #[test]
    fn replay_workspace_prepares_container_writable_state() {
        let source = tempdir().unwrap();
        std::fs::write(source.path().join("source.txt"), "focused\n").unwrap();
        let nested = source
            .path()
            .join("test/project-setups/javascript-commonjs");
        std::fs::create_dir_all(&nested).unwrap();
        let nested_source = nested.join("package.json");
        std::fs::write(&nested_source, "{}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();
            std::fs::set_permissions(&nested_source, std::fs::Permissions::from_mode(0o444))
                .unwrap();
        }
        let replay = DisposableWorkspace::capture(source.path()).unwrap();
        let state = prepare_scenario_state(replay.path()).unwrap();
        replay.prepare_runtime(Ecosystem::Node).unwrap();

        assert!(state.join("venv").is_dir());
        assert!(state.join("cache/pip").is_dir());
        assert!(replay.path().join("node_modules").is_dir());
        assert_eq!(
            std::fs::read_to_string(
                replay
                    .path()
                    .join("test/project-setups/javascript-commonjs/package.json")
            )
            .unwrap(),
            "{}\n"
        );
        assert!(!source.path().join("node_modules").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(replay.path().parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
                0o777
            );
            assert_eq!(
                std::fs::metadata(
                    replay
                        .path()
                        .join("test/project-setups/javascript-commonjs")
                )
                .unwrap()
                .permissions()
                .mode()
                    & 0o777,
                0o777
            );
            assert_eq!(
                std::fs::metadata(
                    replay
                        .path()
                        .join("test/project-setups/javascript-commonjs/package.json")
                )
                .unwrap()
                .permissions()
                .mode()
                    & 0o777,
                0o444
            );
            assert_eq!(
                std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
                0o555
            );
            assert_eq!(
                std::fs::metadata(&nested_source)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o444
            );
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&nested_source, std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
    }

    #[test]
    fn non_node_runtime_workspace_is_unchanged() {
        let source = tempdir().unwrap();
        std::fs::write(source.path().join("source.txt"), "focused\n").unwrap();
        let disposable = DisposableWorkspace::capture(source.path()).unwrap();
        let before = std::fs::read(disposable.path().join("source.txt")).unwrap();
        #[cfg(unix)]
        let before_mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(disposable.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };

        disposable.prepare_runtime(Ecosystem::Python).unwrap();

        assert_eq!(
            std::fs::read(disposable.path().join("source.txt")).unwrap(),
            before
        );
        assert!(!disposable.path().join("node_modules").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(disposable.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                before_mode
            );
        }
    }

    #[test]
    fn node_runtime_workspace_prepares_all_nested_directories_without_changing_files() {
        let workspace = tempdir().unwrap();
        let nested = workspace
            .path()
            .join("test/project-setups/javascript-commonjs/deeper");
        std::fs::create_dir_all(&nested).unwrap();
        let source = nested.join("package.json");
        std::fs::write(&source, "{\"private\":true}\n").unwrap();
        let before = std::fs::read(&source).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o440)).unwrap();
        }

        prepare_node_runtime_workspace(workspace.path()).unwrap();
        prepare_node_runtime_workspace(workspace.path()).unwrap();

        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert!(workspace.path().join("node_modules").is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [
                workspace.path().to_path_buf(),
                workspace.path().join("test"),
                workspace.path().join("test/project-setups"),
                workspace
                    .path()
                    .join("test/project-setups/javascript-commonjs"),
                nested,
                workspace.path().join("node_modules"),
            ] {
                assert_eq!(
                    std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                    0o777,
                    "{}",
                    directory.display()
                );
            }
            assert_eq!(
                std::fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                0o440
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn node_runtime_workspace_rejects_alias_before_changing_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let root_mode = std::fs::metadata(workspace.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        symlink(outside.path(), workspace.path().join("nested-alias")).unwrap();

        let error = prepare_node_runtime_workspace(workspace.path()).unwrap_err();
        assert!(error.to_string().contains("symlink/reparse point"));
        assert!(!workspace.path().join("node_modules").exists());
        assert_eq!(
            std::fs::metadata(workspace.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            root_mode
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_runtime_workspace_rejects_alias_ancestor_without_touching_outside_tree() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let holder = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_workspace = outside.path().join("workspace");
        std::fs::create_dir(&outside_workspace).unwrap();
        std::fs::set_permissions(&outside_workspace, std::fs::Permissions::from_mode(0o555))
            .unwrap();
        symlink(outside.path(), holder.path().join("alias")).unwrap();

        let aliased_workspace = holder.path().join("alias/workspace");
        let error = prepare_node_runtime_workspace(&aliased_workspace).unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing path with symlink/reparse ancestor"));
        assert!(!outside_workspace.join("node_modules").exists());
        assert_eq!(
            std::fs::metadata(&outside_workspace)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
    }

    #[test]
    fn node_runtime_workspace_rejects_preexisting_node_modules_file() {
        let workspace = tempdir().unwrap();
        let modules = workspace.path().join("node_modules");
        std::fs::write(&modules, "not a directory\n").unwrap();

        let error = prepare_node_runtime_workspace(workspace.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("Node dependency root is not a plain directory"));
        assert_eq!(
            std::fs::read_to_string(modules).unwrap(),
            "not a directory\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_runtime_workspace_rejects_special_entry_before_changing_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let workspace = tempdir().unwrap();
        let socket = workspace.path().join("target.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let error = prepare_node_runtime_workspace(workspace.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported entry in Node disposable workspace"));
        assert!(!workspace.path().join("node_modules").exists());
        assert_eq!(
            std::fs::metadata(workspace.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );

        std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_completed_attempt(root: &Path, number: usize) {
        let attempt = root.join(format!("attempt-{number}"));
        std::fs::create_dir(&attempt).unwrap();
        for name in ["result.json", "stdout.log", "stderr.log"] {
            std::fs::write(attempt.join(name), b"{}\n").unwrap();
        }
    }

    fn create_blocked_bundle(repo: &Path, run_id: &str) -> ScanOutcome {
        create_blocked_bundle_with_synthetic_git(repo, run_id, false)
    }

    fn create_blocked_bundle_with_synthetic_git(
        repo: &Path,
        run_id: &str,
        synthesize_git_index: bool,
    ) -> ScanOutcome {
        let adapter = PythonAdapter;
        let source_identity = capture_source_identity(repo).unwrap();
        let detection = adapter.detect(repo).detection;
        let mut config = Config::default();
        config.baseline.runtime = "3.11".into();
        config.baseline.dependencies = "locked".into();
        let baseline = adapter.baseline(repo, &config).unwrap();
        let candidates = adapter.candidates(&baseline, &config).unwrap();
        let dependency_candidates = dependency_candidates(&baseline, &config, None).unwrap();
        let (plan, decisions) =
            plan_scenarios(&baseline, &candidates, &dependency_candidates, &config);

        let layout = EvidenceLayout::create(repo, run_id).unwrap();
        let work = layout.run_root.join("workspace");
        make_disposable_copy(repo, &work).unwrap();
        write_workspace_manifest(&work, &layout.run_root.join("workspace-manifest.json")).unwrap();
        layout.write_json("plan.json", &plan).unwrap();
        layout
            .write_json("plan-decisions.json", &decisions)
            .unwrap();
        layout.write_json("candidates.json", &candidates).unwrap();
        layout
            .write_json("repository.json", &source_identity.repository)
            .unwrap();
        layout
            .write_json("config.normalized.json", &config)
            .unwrap();

        let run_started = Utc::now();
        let image_resolve_started = Utc::now();
        let image_resolve_finished = Utc::now();
        finalize_no_engine_blocked_run(
            repo,
            &adapter,
            &config,
            &detection,
            &baseline,
            &plan,
            &layout,
            &work,
            run_id,
            run_started,
            Instant::now(),
            image_resolve_started,
            image_resolve_finished,
            "sandbox unavailable: focused test has no engine",
            &source_identity,
            synthesize_git_index,
        )
        .unwrap()
    }

    fn make_replayable_bundle(repo: &Path, run_id: &str) -> String {
        let outcome = create_blocked_bundle(repo, run_id);
        let mut manifest = outcome.manifest;
        let layout = EvidenceLayout {
            run_root: outcome.evidence_root.clone(),
        };
        let mut config: Config = serde_json::from_slice(
            &std::fs::read(layout.run_root.join("config.normalized.json")).unwrap(),
        )
        .unwrap();
        config.execution.max_scenarios = 1;
        config.candidates.runtime.max_versions = 0;
        config.candidates.dependencies.latest_allowed = false;
        config.candidates.dependencies.prerelease = false;
        let candidates: Vec<tomorrowci_core::Candidate> = Vec::new();
        let (plan, decisions) = plan_scenarios(&manifest.baseline, &candidates, &[], &config);
        manifest.plan = plan;
        let config_hash = config.content_hash().unwrap();
        manifest.config_hash = config_hash.clone();
        manifest.identity.as_mut().unwrap().config_hash = config_hash;
        layout
            .write_json("config.normalized.json", &config)
            .unwrap();
        layout.write_json("candidates.json", &candidates).unwrap();
        layout.write_json("plan.json", &manifest.plan).unwrap();
        layout
            .write_json("plan-decisions.json", &decisions)
            .unwrap();
        let scenario = manifest.plan.scenarios[0].clone();
        let scenario_dir = outcome.evidence_root.join("scenarios").join(&scenario.id);
        let fetch_commands: Vec<CommandSpec> = serde_json::from_str(
            &std::fs::read_to_string(scenario_dir.join("fetch-commands.json")).unwrap(),
        )
        .unwrap();
        let test_commands: Vec<CommandSpec> = serde_json::from_str(
            &std::fs::read_to_string(scenario_dir.join("test-commands.json")).unwrap(),
        )
        .unwrap();
        let mut result = manifest.results[0].clone();
        result.attempt = 1;
        result.verdict = Verdict::BaselinePass;
        result.exit_code = Some(0);
        result.duration_ms = 1;
        result.timed_out = false;
        result.failure = None;
        result.environment.image_digest = Some(TEST_DIGEST.into());
        result.environment.engine = Some("docker".into());
        result.environment.engine_version = Some("test-engine-v1".into());
        let mut all_commands = fetch_commands.clone();
        all_commands.extend(test_commands.clone());
        result.commands = all_commands;

        let image_started = Utc::now();
        let image_finished = Utc::now();
        write_phase(
            &scenario_dir,
            "image-resolve",
            true,
            Some(0),
            false,
            elapsed_ms(image_started, image_finished),
            "n/a",
            result.environment.tag(),
            Some(TEST_DIGEST.into()),
            &[],
            "focused image resolution",
            Some(image_started),
            Some(image_finished),
        )
        .unwrap();
        let mut fetch_raw = raw_result(0, "fetch ok", "");
        fetch_raw.network_used = true;
        let fetch_started = Utc::now();
        let fetch_finished = Utc::now();
        write_raw_logs(&scenario_dir, "fetch", &fetch_raw).unwrap();
        write_phase(
            &scenario_dir,
            "fetch",
            true,
            Some(0),
            false,
            1,
            "bridge",
            result.environment.tag(),
            Some(TEST_DIGEST.into()),
            &fetch_commands,
            "focused fetch",
            Some(fetch_started),
            Some(fetch_finished),
        )
        .unwrap();
        std::fs::write(
            scenario_dir.join("fetch-result.json"),
            serde_json::to_string_pretty(&fr_json(&fetch_raw, fetch_started, Some(fetch_finished)))
                .unwrap(),
        )
        .unwrap();
        let test_raw = raw_result(0, "test ok", "");
        let test_started = Utc::now();
        let test_finished = Utc::now();
        std::fs::write(scenario_dir.join("stdout.attempt1.log"), &test_raw.stdout).unwrap();
        std::fs::write(scenario_dir.join("stderr.attempt1.log"), &test_raw.stderr).unwrap();
        write_phase(
            &scenario_dir,
            "test",
            true,
            Some(0),
            false,
            elapsed_ms(test_started, test_finished),
            "none",
            result.environment.tag(),
            Some(TEST_DIGEST.into()),
            &test_commands,
            "focused test",
            Some(test_started),
            Some(test_finished),
        )
        .unwrap();
        std::fs::write(
            scenario_dir.join("test-result.json"),
            serde_json::to_string_pretty(&fr_json(&test_raw, test_started, Some(test_finished)))
                .unwrap(),
        )
        .unwrap();
        let attempts = TestAttemptsSummary {
            scenario_id: scenario.id.clone(),
            status: TestExecutionStatus::Completed,
            attempts: vec![TestAttemptRecord {
                attempt: 1,
                started_at: test_started,
                finished_at: test_finished,
                exit_code: Some(0),
                timed_out: false,
                duration_ms: 1,
                failure: None,
            }],
            error: None,
        };
        persist_scenario_artifacts(
            &scenario_dir,
            &scenario,
            &result.environment,
            &fetch_commands,
            &test_commands,
            Some(&fetch_raw),
            Some(&test_raw),
            &result,
            "docker".into(),
            None,
            &attempts,
        )
        .unwrap();
        manifest.results = vec![result.clone()];
        manifest.frontier = compute_breakage_frontier(true, &[(scenario, result)], false, None);
        let finished = Utc::now();
        manifest.finished_at = Some(finished);
        let identity = manifest.identity.as_mut().unwrap();
        identity.container_engine = Some("docker".into());
        identity.container_engine_version = Some("test-engine-v1".into());
        identity.finished_at = Some(finished);
        write_run_manifest(&layout, &manifest).unwrap();
        layout
            .write_json("verdicts.json", &manifest.results)
            .unwrap();
        layout
            .write_json("frontier.json", &manifest.frontier)
            .unwrap();
        write_json_report(&manifest, &layout.run_root.join("report.json")).unwrap();
        write_html_report(&manifest, &layout.run_root.join("report.html")).unwrap();
        write_github_job_summary(&manifest, &layout.run_root.join("job-summary.md")).unwrap();
        ScanMetrics::from_manifest(&manifest, None)
            .write_json(&layout.run_root.join("metrics.json"))
            .unwrap();
        ClaimLedger::default()
            .write_json(&layout.run_root.join("claims.json"))
            .unwrap();
        std::fs::write(
            layout.run_root.join("summary.txt"),
            render_terminal_summary(&manifest),
        )
        .unwrap();
        tomorrowci_evidence::finalize_run_checksums(&layout.run_root).unwrap();
        let verification = tomorrowci_evidence::verify_run_root(&layout.run_root).unwrap();
        assert!(verification.ok, "{:?}", verification.errors);
        manifest.plan.scenarios[0].id.clone()
    }

    fn raw_result(code: i32, stdout: &str, stderr: &str) -> RawExecutionResult {
        RawExecutionResult {
            exit_code: Some(code),
            signal: None,
            duration_ms: 1,
            timed_out: false,
            stdout: stdout.into(),
            stderr: stderr.into(),
            network_used: false,
        }
    }

    struct PassingReplayExecutor;

    impl ScenarioExecutor for PassingReplayExecutor {
        fn name(&self) -> &str {
            "docker"
        }

        fn ensure_image(&self, _image: &str) -> Result<String> {
            Ok(TEST_DIGEST.into())
        }

        fn engine_version(&self) -> Option<String> {
            Some("test-engine-v1".into())
        }

        fn execute(&self, context: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
            if context.network == "bridge" {
                Ok(raw_result(0, "fetch ok", ""))
            } else {
                Ok(raw_result(0, "test ok", ""))
            }
        }
    }

    struct FetchFailureExecutor;

    impl ScenarioExecutor for FetchFailureExecutor {
        fn name(&self) -> &str {
            "docker"
        }

        fn ensure_image(&self, _image: &str) -> Result<String> {
            Ok(TEST_DIGEST.into())
        }

        fn engine_version(&self) -> Option<String> {
            Some("test-engine-v1".into())
        }

        fn execute(&self, context: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
            if context.network == "bridge" {
                Ok(raw_result(23, "", "registry unavailable"))
            } else {
                panic!("test phase must not execute after a failed fetch")
            }
        }
    }

    struct WorkspaceMutatingExecutor;

    impl ScenarioExecutor for WorkspaceMutatingExecutor {
        fn name(&self) -> &str {
            "docker"
        }

        fn ensure_image(&self, _image: &str) -> Result<String> {
            Ok(TEST_DIGEST.into())
        }

        fn engine_version(&self) -> Option<String> {
            Some("test-engine-v1".into())
        }

        fn execute(&self, context: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
            if context.network == "bridge" {
                return Ok(raw_result(0, "fetch ok", ""));
            }
            std::fs::write(context.workspace.join("app.py"), "# replay mutation\n")?;
            Ok(raw_result(0, "test ok", ""))
        }
    }

    #[test]
    fn replay_rejects_any_verifier_failure_before_engine_detection() {
        let repo = tempdir().unwrap();
        let run_root = repo.path().join(".tomorrowci/runs/tampered");
        std::fs::create_dir_all(&run_root).unwrap();

        let error = replay_scenario(repo.path(), "tampered", "baseline").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("evidence integrity verification failed"));
        assert!(message.contains("required run file"));
    }

    #[test]
    fn replay_attempts_are_contiguous_canonical_and_append_only() {
        let dir = tempdir().unwrap();
        let scenario = dir.path().join("scenario");
        let replays = scenario.join("replays");
        std::fs::create_dir_all(&replays).unwrap();
        write_completed_attempt(&replays, 1);
        write_completed_attempt(&replays, 2);

        assert_eq!(inspect_replay_attempts(&scenario).unwrap(), 3);
        let transaction = reserve_replay_attempt(&scenario).unwrap();
        assert_eq!(transaction.number, 3);
        assert_eq!(
            transaction.staging_dir.file_name().unwrap(),
            ".attempt-3.staging"
        );
        assert!(transaction.staging_dir.is_dir());

        // The reservation is also a lock: a concurrent replay fails before execution.
        assert!(reserve_replay_attempt(&scenario).is_err());
        assert!(inspect_replay_attempts(&scenario).is_err());
    }

    #[test]
    fn replay_attempts_reject_gaps_and_noncanonical_names() {
        let dir = tempdir().unwrap();
        let scenario = dir.path().join("scenario");
        let replays = scenario.join("replays");
        std::fs::create_dir_all(&replays).unwrap();
        write_completed_attempt(&replays, 1);
        write_completed_attempt(&replays, 3);
        assert!(inspect_replay_attempts(&scenario)
            .unwrap_err()
            .to_string()
            .contains("contiguous"));

        std::fs::remove_dir_all(replays.join("attempt-3")).unwrap();
        write_completed_attempt(&replays, 2);
        std::fs::create_dir(replays.join("attempt-03")).unwrap();
        assert!(inspect_replay_attempts(&scenario)
            .unwrap_err()
            .to_string()
            .contains("non-canonical"));
    }

    #[test]
    fn no_engine_blocked_bundle_is_complete_and_verifiable() {
        let repo = tempdir().unwrap();
        write_python_fixture(repo.path());
        let outcome = create_blocked_bundle(repo.path(), "blockedrun");

        assert_eq!(outcome.manifest.results.len(), 1);
        assert_eq!(outcome.manifest.results[0].verdict, Verdict::Blocked);
        assert!(outcome.manifest.results[0].environment.engine.is_none());
        assert!(outcome.manifest.results[0]
            .environment
            .image_digest
            .is_none());
        assert!(outcome.terminal_summary.contains("BLOCKED"));
        let verification = tomorrowci_evidence::verify_run_root(&outcome.evidence_root).unwrap();
        assert!(verification.ok, "{:?}", verification.errors);
    }

    #[test]
    fn no_engine_remote_bundle_binds_synthetic_git_contract() {
        let repo = tempdir().unwrap();
        write_python_fixture(repo.path());
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(repo.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.name", "TomorrowCI Test"]);
        git(&["config", "user.email", "test@example.invalid"]);
        git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/example/blocked",
        ]);
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "fixture"]);
        let commit = git(&["rev-parse", "HEAD"]);

        let outcome = create_blocked_bundle_with_synthetic_git(repo.path(), "remoteblocked", true);
        let environment = &outcome.manifest.results[0].environment;
        for (key, value) in tomorrowci_core::SYNTHETIC_GIT_ENV {
            assert_eq!(environment.env.get(*key).map(String::as_str), Some(*value));
        }
        assert!(environment
            .env
            .keys()
            .filter(|key| key.starts_with("GIT_"))
            .all(|key| tomorrowci_core::SYNTHETIC_GIT_ENV
                .iter()
                .any(|(allowed, _)| key == allowed)));
        assert!(!outcome.evidence_root.join("workspace/.git").exists());

        let manifest_path = outcome.evidence_root.join("workspace-manifest.json");
        let manifest: WorkspaceManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let manifest_sha256 = tomorrowci_evidence::file_checksum(&manifest_path).unwrap();
        let prepared = prepare_synthetic_git_index(
            &outcome.evidence_root.join("workspace"),
            &manifest,
            &manifest_sha256,
        )
        .unwrap();
        let snapshot_total_bytes = manifest.files.values().map(|entry| entry.size).sum();
        let remote = RemoteSourceRecord {
            schema_version: 2,
            requested_url: "https://github.com/example/blocked".into(),
            canonical_origin: "origin:https://github.com/example/blocked".into(),
            requested_commit: commit.clone(),
            resolved_commit: commit,
            clean_tree: true,
            moving_ref_allowed: false,
            redirects_allowed: false,
            credentials_allowed: false,
            submodules_allowed: false,
            lfs_allowed: false,
            clone_timeout_seconds: 120,
            max_files: 10_000,
            max_file_bytes: 25 * 1024 * 1024,
            max_total_bytes: 100 * 1024 * 1024,
            max_clone_disk_bytes: 256 * 1024 * 1024,
            snapshot_file_count: manifest.files.len() as u64,
            snapshot_total_bytes,
            workspace_manifest_sha256: manifest_sha256,
            synthetic_git_index: Some(prepared.record),
        };
        std::fs::write(
            outcome.evidence_root.join("remote-source.json"),
            serde_json::to_vec_pretty(&remote).unwrap(),
        )
        .unwrap();
        tomorrowci_evidence::finalize_run_checksums(&outcome.evidence_root).unwrap();
        let verification = tomorrowci_evidence::verify_run_root(&outcome.evidence_root).unwrap();
        assert!(verification.ok, "{:?}", verification.errors);
        assert_eq!(
            verification.checksum_compatibility,
            ChecksumCompatibility::CurrentV2
        );
    }

    #[test]
    fn failed_fetch_commits_complete_attempt_and_does_not_poison_retry() {
        let repo = tempdir().unwrap();
        write_python_fixture(repo.path());
        let run_id = "fetchfailure";
        let scenario_id = make_replayable_bundle(repo.path(), run_id);

        let error =
            replay_scenario_with_executor(repo.path(), run_id, &scenario_id, &FetchFailureExecutor)
                .unwrap_err();
        assert!(error.to_string().contains("replay fetch failed"));
        let scenario_dir = repo
            .path()
            .join(".tomorrowci/runs")
            .join(run_id)
            .join("scenarios")
            .join(&scenario_id);
        assert_eq!(inspect_replay_attempts(&scenario_dir).unwrap(), 2);
        let failed: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(scenario_dir.join("replays/attempt-1/result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(failed["phase"], "fetch");
        assert_eq!(failed["ok"], false);

        let output = replay_scenario_with_executor(
            repo.path(),
            run_id,
            &scenario_id,
            &PassingReplayExecutor,
        )
        .unwrap();
        assert!(output.contains("replay: PASS"));
        assert_eq!(inspect_replay_attempts(&scenario_dir).unwrap(), 3);
    }

    #[test]
    fn replay_executes_only_in_disposable_workspace_and_preserves_evidence_snapshot() {
        let repo = tempdir().unwrap();
        write_python_fixture(repo.path());
        let run_id = "mutating";
        let scenario_id = make_replayable_bundle(repo.path(), run_id);

        let output = replay_scenario_with_executor(
            repo.path(),
            run_id,
            &scenario_id,
            &WorkspaceMutatingExecutor,
        )
        .unwrap();
        assert!(output.contains("replay: PASS"));
        let run_root = repo.path().join(".tomorrowci/runs").join(run_id);
        assert!(std::fs::read_to_string(run_root.join("workspace/app.py"))
            .unwrap()
            .contains("def ok"));
        let attempt = run_root
            .join("scenarios")
            .join(&scenario_id)
            .join("replays/attempt-1");
        for required in ["result.json", "stdout.log", "stderr.log"] {
            assert!(attempt.join(required).is_file());
        }
        let verification = tomorrowci_evidence::verify_run_root(&run_root).unwrap();
        assert!(verification.ok, "{:?}", verification.errors);
    }

    #[test]
    fn replay_uses_recorded_node_and_rust_failure_normalizers() {
        let node = raw_result(1, "", "Error [ERR_REQUIRE_ESM]: require() of ES Module");
        let rust = raw_result(1, "", "error[E0308]: mismatched types");

        assert_eq!(
            normalize_replay_failure(Ecosystem::Node, &node).kind,
            "ErrRequireEsm"
        );
        assert_eq!(
            normalize_replay_failure(Ecosystem::Rust, &rust).kind,
            "CompileError"
        );
    }
}
