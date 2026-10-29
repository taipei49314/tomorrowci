//! Pluggable scenario executors (Docker real; scripted for tests).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use tomorrowci_core::{
    prepared_workspace_copy_argv, CommandSpec, EnvironmentSpec, RawExecutionResult, Result,
    Scenario, TcError, WorkspaceIsolation, WorkspacePreparation,
};
use tomorrowci_sandbox::{
    detect_requested_engine, engine_version as sandbox_engine_version, env_spec_to_map,
    resolve_or_pull_digest, run_in_container, RunRequest, SandboxEngine,
};

pub struct ExecutionContext<'a> {
    pub workspace: &'a Path,
    /// A prepared seed to copy offline into the fresh, empty workspace before tests.
    pub prepared_workspace: Option<&'a Path>,
    pub scenario: &'a Scenario,
    pub environment: &'a EnvironmentSpec,
    pub commands: &'a [CommandSpec],
    pub timeout: Duration,
    /// "none" for test; "bridge" for fetch phase
    pub network: &'a str,
}

pub trait ScenarioExecutor: Send + Sync {
    fn name(&self) -> &str;
    /// Resolve immutable digest; failure must surface as BLOCKED to callers.
    fn ensure_image(&self, image: &str) -> Result<String>;
    fn engine_label(&self) -> String {
        self.name().to_string()
    }
    /// Exact engine build identity recorded with executable evidence.
    fn engine_version(&self) -> Option<String> {
        None
    }
    fn isolates_test_attempts(&self) -> bool {
        false
    }
    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult>;
}

/// Real Docker/Podman executor.
pub struct ContainerExecutor {
    pub engine: SandboxEngine,
}

impl ContainerExecutor {
    pub fn detect() -> Result<Self> {
        Self::detect_requested("auto")
    }

    /// Detect exactly the configured engine. A requested Docker/Podman engine
    /// is never silently replaced by the other implementation.
    pub fn detect_requested(requested: &str) -> Result<Self> {
        let engine = detect_requested_engine(requested)?;
        Ok(Self { engine })
    }
}

impl ScenarioExecutor for ContainerExecutor {
    fn name(&self) -> &str {
        "container"
    }

    fn engine_label(&self) -> String {
        match self.engine {
            SandboxEngine::Docker => "docker".into(),
            SandboxEngine::Podman => "podman".into(),
        }
    }

    fn ensure_image(&self, image: &str) -> Result<String> {
        resolve_or_pull_digest(self.engine, image)
    }

    fn engine_version(&self) -> Option<String> {
        sandbox_engine_version(self.engine)
    }

    fn isolates_test_attempts(&self) -> bool {
        true
    }

    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
        let image = ctx.environment.run_image_ref();
        let mut req = RunRequest {
            engine: self.engine,
            image,
            workspace_host: ctx.workspace.to_path_buf(),
            prepared_seed_host: None,
            workdir: ctx.environment.workdir.clone(),
            commands: ctx.commands.to_vec(),
            env: env_spec_to_map(ctx.environment),
            memory_mb: ctx.environment.memory_mb.max(256),
            cpus: if ctx.environment.cpus <= 0.0 {
                1.0
            } else {
                ctx.environment.cpus
            },
            pids_limit: ctx.environment.pids_limit.max(64),
            network: ctx.network.into(),
            timeout: ctx.timeout,
            read_only_root: ctx.environment.read_only_root,
            user: ctx.environment.user.clone(),
            use_shell: true, // multi-step fetch uses &&
        };
        let Some(seed) = ctx.prepared_workspace else {
            return run_in_container(&req);
        };
        if ctx.network != "none" || ctx.commands.iter().any(|command| command.phase != "test") {
            return Err(TcError::InvalidState(
                "fresh prepared workspaces are only valid for offline tests".into(),
            ));
        }
        let mut preparation = req.clone();
        preparation.prepared_seed_host = Some(seed.to_path_buf());
        preparation.env.clear();
        preparation.commands = vec![CommandSpec {
            argv: prepared_workspace_copy_argv(),
            cwd: Some("/work".into()),
            network: false,
            phase: "workspace-prepare".into(),
        }];
        let started = std::time::Instant::now();
        let prepared = run_in_container(&preparation)?;
        if prepared.exit_code != Some(0) || prepared.timed_out {
            return Err(TcError::Blocked(format!(
                "offline test workspace preparation failed: exit={:?}, timed_out={}, stdout={}, stderr={}",
                prepared.exit_code, prepared.timed_out, prepared.stdout, prepared.stderr
            )));
        }
        req.timeout = ctx
            .timeout
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                TcError::Blocked("test timeout exhausted while preparing fresh workspace".into())
            })?;
        // The target container receives only the new copy; never the seed mount.
        let mut result = run_in_container(&req)?;
        result.duration_ms = started.elapsed().as_millis() as u64;
        result.workspace_preparation = Some(WorkspacePreparation {
            strategy: WorkspaceIsolation::FreshPreparedCopyV1,
            seed_mount: "/tomorrowci-seed".into(),
            seed_read_only: true,
            destination_mount: "/work".into(),
            argv: prepared_workspace_copy_argv(),
            image_digest: req.image,
            network: "none".into(),
            exit_code: prepared.exit_code,
            timed_out: prepared.timed_out,
            duration_ms: prepared.duration_ms,
            stdout: prepared.stdout,
            stderr: prepared.stderr,
        });
        Ok(result)
    }
}

/// Scripted executor for unit/integration tests without Docker.
pub struct ScriptedExecutor {
    /// scenario_id -> sequence of (exit_code) per attempt
    outcomes: Mutex<HashMap<String, Vec<i32>>>,
    pub stderr_template: String,
}

impl ScriptedExecutor {
    pub fn new(map: HashMap<String, Vec<i32>>) -> Self {
        Self {
            outcomes: Mutex::new(map),
            stderr_template: String::new(),
        }
    }

    pub fn with_stderr(mut self, s: impl Into<String>) -> Self {
        self.stderr_template = s.into();
        self
    }
}

impl ScenarioExecutor for ScriptedExecutor {
    fn name(&self) -> &str {
        "scripted"
    }

    fn ensure_image(&self, _image: &str) -> Result<String> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }

    fn engine_version(&self) -> Option<String> {
        Some("scripted-test-v1".into())
    }

    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
        // Fetch phase always succeeds in scripted harness (construction is not under test)
        if ctx.commands.iter().all(|c| c.phase == "fetch") {
            return Ok(RawExecutionResult {
                workspace_preparation: None,
                exit_code: Some(0),
                signal: None,
                duration_ms: 1,
                timed_out: false,
                stdout: "scripted-fetch-ok\n".into(),
                stderr: String::new(),
                network_used: ctx.network != "none",
            });
        }
        let mut guard = self.outcomes.lock().unwrap();
        let q = guard.entry(ctx.scenario.id.clone()).or_default();
        let code = if q.is_empty() { 0 } else { q.remove(0) };
        let fail = code != 0;
        let stderr = if fail {
            if self.stderr_template.is_empty() {
                format!(
                    "ImportError: cannot import name 'MutableMapping' (scenario {})",
                    ctx.scenario.id
                )
            } else {
                self.stderr_template.clone()
            }
        } else {
            "ok\n".into()
        };
        Ok(RawExecutionResult {
            workspace_preparation: None,
            exit_code: Some(code),
            signal: None,
            duration_ms: 5,
            timed_out: false,
            stdout: if fail {
                String::new()
            } else {
                "passed\n".into()
            },
            stderr,
            network_used: ctx.network != "none",
        })
    }
}
