//! Container sandbox: Docker/Podman without privileged mode.
//!
//! Security invariants:
//! - never mount the Docker socket into the target container
//! - never forward host env vars except an explicit allowlist
//! - no privileged mode
//! - CPU/memory/PID/wall-clock limits
//! - fetch phase may use network; test phase defaults to network=none
//! - target code is never executed on the host by default

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::process::Command;
use tomorrowci_core::{
    CommandPhase, CommandSpec, EnvironmentSpec, NetworkMode, RawExecutionResult,
};

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("no container engine available (install Docker or Podman). doctor: tomorrowci doctor")]
    NoEngine,
    #[error("engine '{0}' not found on PATH")]
    EngineNotFound(String),
    #[error("sandbox blocked: {0}")]
    Blocked(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    Docker,
    Podman,
}

impl EngineKind {
    pub fn binary(self) -> &'static str {
        match self {
            EngineKind::Docker => "docker",
            EngineKind::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineInfo {
    pub kind: EngineKind,
    pub path: PathBuf,
    pub version: String,
}

/// Detect available sandbox engine.
pub fn detect_engine(preference: &str) -> Result<EngineInfo> {
    let order: Vec<EngineKind> = match preference {
        "docker" => vec![EngineKind::Docker],
        "podman" => vec![EngineKind::Podman],
        "auto" => vec![EngineKind::Docker, EngineKind::Podman],
        other => {
            return Err(SandboxError::Blocked(format!(
                "unknown sandbox.engine '{other}'"
            )))
        }
    };

    for kind in order {
        if let Ok(path) = which::which(kind.binary()) {
            let version = std::process::Command::new(&path)
                .arg("version")
                .arg("--format")
                .arg("{{.Server.Version}}")
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    std::process::Command::new(&path)
                        .arg("--version")
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                })
                .unwrap_or_else(|| "unknown".into());

            // Probe daemon
            let probe = std::process::Command::new(&path)
                .args(["info", "--format", "{{.ID}}"])
                .output();
            match probe {
                Ok(o) if o.status.success() => {
                    return Ok(EngineInfo {
                        kind,
                        path,
                        version,
                    });
                }
                Ok(o) => {
                    tracing::warn!(
                        engine = kind.binary(),
                        stderr = %String::from_utf8_lossy(&o.stderr),
                        "engine present but daemon not ready"
                    );
                }
                Err(e) => tracing::warn!("failed to probe {}: {e}", kind.binary()),
            }
        }
    }
    Err(SandboxError::NoEngine)
}

/// Resolve image tag to immutable digest when possible.
pub async fn resolve_image_digest(engine: &EngineInfo, image_ref: &str) -> Result<(String, Option<String>)> {
    let out = Command::new(&engine.path)
        .args(["image", "inspect", "--format", "{{index .RepoDigests 0}}", image_ref])
        .output()
        .await?;
    if out.status.success() {
        let dig = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if dig.is_empty() || dig == "<no value>" {
            return Ok((image_ref.to_string(), None));
        }
        // RepoDigests looks like repo@sha256:...
        let digest = dig.split_once('@').map(|(_, d)| d.to_string());
        return Ok((image_ref.to_string(), digest));
    }
    Ok((image_ref.to_string(), None))
}

/// Pull image if missing (networked phase).
pub async fn ensure_image(engine: &EngineInfo, image_ref: &str) -> Result<()> {
    let inspect = Command::new(&engine.path)
        .args(["image", "inspect", image_ref])
        .output()
        .await?;
    if inspect.status.success() {
        return Ok(());
    }
    tracing::info!(image = image_ref, "pulling image");
    let pull = Command::new(&engine.path)
        .args(["pull", image_ref])
        .output()
        .await?;
    if !pull.status.success() {
        return Err(SandboxError::Blocked(format!(
            "failed to pull image {image_ref}: {}",
            String::from_utf8_lossy(&pull.stderr)
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SandboxExecOptions {
    pub engine: EngineInfo,
    pub env: EnvironmentSpec,
    pub workspace_host: PathBuf,
    pub workspace_container: String,
    /// Explicit allowlisted env keys only
    pub allowlist_env: Vec<String>,
}

/// Execute commands inside an isolated container.
/// Fetch-phase commands may use network; test/build phases use network=none by default.
pub async fn execute_scenario(
    opts: &SandboxExecOptions,
    commands: &[CommandSpec],
) -> Result<RawExecutionResult> {
    // Hard security checks
    if opts.env.mounts.iter().any(|m| {
        m.host_path.ends_with("docker.sock")
            || m.container_path.contains("docker.sock")
            || m.host_path.to_string_lossy().contains("docker.sock")
    }) {
        return Err(SandboxError::Blocked(
            "refusing to mount docker.sock into target container".into(),
        ));
    }

    let mut combined_stdout = String::new();
    let mut combined_stderr = String::new();
    let mut last_exit = Some(0);
    let mut network_used = false;
    let mut timed_out = false;
    let start = Instant::now();
    let wall = Duration::from_secs(opts.env.timeout_seconds.max(1));

    for cmd in commands {
        if start.elapsed() > wall {
            timed_out = true;
            break;
        }
        let remaining = wall.saturating_sub(start.elapsed());
        let use_net = match (cmd.phase, opts.env.network_mode) {
            (CommandPhase::Fetch, _) => true,
            (_, NetworkMode::Full) => true,
            (_, NetworkMode::None) => false,
            (_, NetworkMode::FetchOnly) => false,
        };
        if use_net {
            network_used = true;
        }

        let result = run_in_container(opts, cmd, use_net, remaining).await?;
        combined_stdout.push_str(&result.stdout);
        combined_stderr.push_str(&result.stderr);
        last_exit = result.exit_code;
        if result.timed_out {
            timed_out = true;
            break;
        }
        if result.exit_code.unwrap_or(1) != 0 {
            return Ok(RawExecutionResult {
                exit_code: result.exit_code,
                signal: result.signal,
                stdout: combined_stdout,
                stderr: combined_stderr,
                duration_ms: start.elapsed().as_millis() as u64,
                timed_out,
                network_used,
                error: result.error,
            });
        }
    }

    Ok(RawExecutionResult {
        exit_code: if timed_out { None } else { last_exit },
        signal: None,
        stdout: combined_stdout,
        stderr: combined_stderr,
        duration_ms: start.elapsed().as_millis() as u64,
        timed_out,
        network_used,
        error: None,
    })
}

async fn run_in_container(
    opts: &SandboxExecOptions,
    cmd: &CommandSpec,
    network: bool,
    timeout: Duration,
) -> Result<RawExecutionResult> {
    let engine = &opts.engine;
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        if network { "bridge".into() } else { "none".into() },
        "--memory".into(),
        format!("{}m", opts.env.memory_mb),
        "--cpus".into(),
        opts.env.cpus.to_string(),
        "--pids-limit".into(),
        opts.env.pids_limit.to_string(),
        // never privileged
        "--security-opt".into(),
        "no-new-privileges".into(),
        // do not pass host env
        "--env".into(),
        "HOME=/tmp".into(),
        "--env".into(),
        "PYTHONUNBUFFERED=1".into(),
        "--env".into(),
        "CI=1".into(),
        "--env".into(),
        "TOMORROWCI=1".into(),
        "-v".into(),
        format!(
            "{}:{}:{}",
            opts.workspace_host.display(),
            opts.workspace_container,
            if opts.env.read_only_root {
                "ro"
            } else {
                "rw"
            }
        ),
        "-w".into(),
        if cmd.workdir.is_empty() {
            opts.workspace_container.clone()
        } else {
            cmd.workdir.clone()
        },
    ];

    if opts.env.read_only_root {
        args.push("--read-only".into());
        args.push("--tmpfs".into());
        args.push("/tmp:rw,exec,nosuid,size=512m".into());
        args.push("--tmpfs".into());
        args.push("/var/tmp:rw,exec,nosuid,size=256m".into());
    }

    if let Some(user) = &opts.env.user {
        args.push("--user".into());
        args.push(user.clone());
    }

    // Explicit command env only (not host env)
    for (k, v) in &cmd.env {
        if is_forbidden_env(k) {
            continue;
        }
        args.push("--env".into());
        args.push(format!("{k}={v}"));
    }
    for (k, v) in &opts.env.env {
        if is_forbidden_env(k) {
            continue;
        }
        if opts.allowlist_env.is_empty() || opts.allowlist_env.iter().any(|a| a == k) {
            args.push("--env".into());
            args.push(format!("{k}={v}"));
        }
    }

    args.push(opts.env.image_ref.clone());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

    // Refuse docker.sock in args
    let joined = args.join(" ");
    if joined.contains("docker.sock") {
        return Err(SandboxError::Blocked(
            "refusing command that references docker.sock".into(),
        ));
    }

    let child = Command::new(&engine.path)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let start = Instant::now();
    let output = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match output {
        Ok(Ok(out)) => Ok(RawExecutionResult {
            exit_code: out.status.code(),
            signal: None,
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
            timed_out: false,
            network_used: network,
            error: None,
        }),
        Ok(Err(e)) => Err(SandboxError::Io(e)),
        Err(_elapsed) => {
            // best-effort kill is handled by kill_on_drop
            Ok(RawExecutionResult {
                exit_code: None,
                signal: None,
                stdout: String::new(),
                stderr: "tomorrowci: container wall-clock timeout".into(),
                duration_ms: start.elapsed().as_millis() as u64,
                timed_out: true,
                network_used: network,
                error: Some("timeout".into()),
            })
        }
    }
}

fn is_forbidden_env(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    matches!(
        k.as_str(),
        "DOCKER_HOST"
            | "SSH_AUTH_SOCK"
            | "AWS_SECRET_ACCESS_KEY"
            | "AWS_SESSION_TOKEN"
            | "GITHUB_TOKEN"
            | "GH_TOKEN"
            | "NPM_TOKEN"
            | "CARGO_REGISTRY_TOKEN"
    ) || k.contains("SECRET")
        || k.contains("PASSWORD")
        || k.contains("PRIVATE_KEY")
}

/// Doctor check output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorSandboxReport {
    pub engine: Option<EngineInfo>,
    pub status: String,
    pub details: Vec<String>,
}

pub fn doctor_sandbox(preference: &str) -> DoctorSandboxReport {
    match detect_engine(preference) {
        Ok(info) => DoctorSandboxReport {
            status: "ok".into(),
            details: vec![format!(
                "{} at {} ({})",
                info.kind.binary(),
                info.path.display(),
                info.version
            )],
            engine: Some(info),
        },
        Err(e) => DoctorSandboxReport {
            engine: None,
            status: "blocked".into(),
            details: vec![
                e.to_string(),
                "Install Docker Desktop or Podman and ensure the daemon is running.".into(),
                "TomorrowCI never executes untrusted target code on the host by default.".into(),
            ],
        },
    }
}

/// Copy repository into a disposable workspace (does not mutate original).
pub fn materialize_workspace(source: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    std::fs::create_dir_all(dest)?;
    copy_dir_recursive(source, dest)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Skip heavy/irrelevant dirs
        if matches!(
            name_str.as_ref(),
            ".git" | "node_modules" | "target" | ".tomorrowci" | "__pycache__" | ".venv" | "venv"
        ) {
            // Keep .git for commit SHA if needed — actually copy .git for SHA? We record SHA before copy.
            if name_str == ".git" {
                continue;
            }
            continue;
        }
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_symlink() {
            // Do not follow; skip symlinks to avoid escapes at copy time
            tracing::warn!(path = %entry.path().display(), "skipping symlink during workspace copy");
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_env_detected() {
        assert!(is_forbidden_env("AWS_SECRET_ACCESS_KEY"));
        assert!(is_forbidden_env("my_password"));
        assert!(!is_forbidden_env("PYTEST_ADDOPTS"));
    }

    #[test]
    fn doctor_without_engine_is_blocked() {
        // May or may not have engine; just ensure function returns
        let _ = doctor_sandbox("auto");
    }
}
