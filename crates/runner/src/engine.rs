//! Pluggable scenario executors (Docker real; scripted for tests).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use tomorrowci_core::{
    CommandSpec, EnvironmentSpec, RawExecutionResult, Result, Scenario, TcError,
};
use tomorrowci_sandbox::{
    detect_engines, env_spec_to_map, pull_image, resolve_image_digest, run_in_container,
    RunRequest, SandboxEngine,
};

pub struct ExecutionContext<'a> {
    pub workspace: &'a Path,
    pub scenario: &'a Scenario,
    pub environment: &'a EnvironmentSpec,
    pub commands: &'a [CommandSpec],
    pub timeout: Duration,
    /// "none" for test; "bridge" for fetch phase
    pub network: &'a str,
}

pub trait ScenarioExecutor: Send + Sync {
    fn name(&self) -> &str;
    fn ensure_image(&self, image: &str) -> Result<Option<String>>;
    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult>;
}

/// Real Docker/Podman executor.
pub struct ContainerExecutor {
    pub engine: SandboxEngine,
}

impl ContainerExecutor {
    pub fn detect() -> Result<Self> {
        let avail = detect_engines();
        let engine = avail.selected.ok_or_else(|| {
            TcError::Blocked(avail.notes.join("; "))
        })?;
        Ok(Self { engine })
    }
}

impl ScenarioExecutor for ContainerExecutor {
    fn name(&self) -> &str {
        "container"
    }

    fn ensure_image(&self, image: &str) -> Result<Option<String>> {
        // Try resolve first; pull if missing
        if let Some(d) = resolve_image_digest(self.engine, image) {
            return Ok(Some(d));
        }
        pull_image(self.engine, image)?;
        Ok(resolve_image_digest(self.engine, image))
    }

    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
        let req = RunRequest {
            engine: self.engine,
            image: ctx.environment.image.clone(),
            workspace_host: ctx.workspace.to_path_buf(),
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
        };
        run_in_container(&req)
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

    fn ensure_image(&self, _image: &str) -> Result<Option<String>> {
        Ok(Some("sha256:scripted-test-digest".into()))
    }

    fn execute(&self, ctx: &ExecutionContext<'_>) -> Result<RawExecutionResult> {
        let mut guard = self.outcomes.lock().unwrap();
        let q = guard.entry(ctx.scenario.id.clone()).or_default();
        let code = if q.is_empty() { 0 } else { q.remove(0) };
        let fail = code != 0;
        let stderr = if fail {
            if self.stderr_template.is_empty() {
                format!("ImportError: cannot import name 'MutableMapping' (scenario {})", ctx.scenario.id)
            } else {
                self.stderr_template.clone()
            }
        } else {
            "ok\n".into()
        };
        Ok(RawExecutionResult {
            exit_code: Some(code),
            signal: None,
            duration_ms: 5,
            timed_out: false,
            stdout: if fail { String::new() } else { "passed\n".into() },
            stderr,
            network_used: ctx.network != "none",
        })
    }
}
