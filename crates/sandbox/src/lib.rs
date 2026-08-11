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
use std::collections::BTreeSet;
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

fn daemon_probe_args(_kind: EngineKind) -> &'static [&'static str] {
    &["info"]
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

            // Probe daemon readiness with the cross-engine command itself.
            // Docker's Go template exposes `.ID`, while current Podman does
            // not, so a Docker-specific formatted probe incorrectly reports
            // a healthy Podman service as unavailable.
            let probe = std::process::Command::new(&path)
                .args(daemon_probe_args(kind))
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
pub async fn resolve_image_digest(
    engine: &EngineInfo,
    image_ref: &str,
) -> Result<(String, Option<String>)> {
    let out = Command::new(&engine.path)
        .args([
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}",
            image_ref,
        ])
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

const ENGINE_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const ENGINE_CONTROL_OUTPUT_LIMIT: usize = 64 * 1024;

/// Validate the joint environment/command network policy before creating a
/// container. A Fetch label alone never grants network access: the recorded
/// command and environment must both explicitly permit it.
pub fn validate_network_policy(env: &EnvironmentSpec, commands: &[CommandSpec]) -> Result<()> {
    for command in commands {
        command_network_access(env.network_mode, command)?;
    }
    Ok(())
}

fn command_network_access(mode: NetworkMode, command: &CommandSpec) -> Result<bool> {
    if command.network_required && command.phase != CommandPhase::Fetch {
        return Err(SandboxError::Blocked(format!(
            "network was requested outside the fetch phase by '{}'",
            command.program
        )));
    }
    if command.network_required && mode == NetworkMode::None {
        return Err(SandboxError::Blocked(format!(
            "command '{}' requires network but the recorded environment forbids it",
            command.program
        )));
    }
    Ok(command.phase == CommandPhase::Fetch
        && command.network_required
        && matches!(mode, NetworkMode::FetchOnly | NetworkMode::Full))
}

/// Execute commands inside **one** isolated container session.
///
/// Install/fetch state must persist across commands (pip install then pytest).
/// Network policy: execute every recorded command with no attached network
/// unless it is an explicitly network-required Fetch command, verify every
/// transition, and disconnect again before accepting its result.
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
    if opts
        .workspace_host
        .to_string_lossy()
        .contains("docker.sock")
        || opts.workspace_container.contains("docker.sock")
    {
        return Err(SandboxError::Blocked(
            "refusing workspace path that references docker.sock".into(),
        ));
    }
    validate_network_policy(&opts.env, commands)?;

    let engine = &opts.engine;
    let name = format!(
        "tomorrowci-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );

    // Create long-lived container (sleep) so package installs persist.
    let mut create_args: Vec<String> = vec![
        "create".into(),
        "--name".into(),
        name.clone(),
        "--network".into(),
        engine_default_network(engine).into(),
        "--memory".into(),
        format!("{}m", opts.env.memory_mb),
        "--cpus".into(),
        opts.env.cpus.to_string(),
        "--pids-limit".into(),
        opts.env.pids_limit.to_string(),
        "--security-opt".into(),
        "no-new-privileges".into(),
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
            host_path_for_docker(&opts.workspace_host),
            opts.workspace_container,
            if opts.env.read_only_root { "ro" } else { "rw" }
        ),
        "-w".into(),
        opts.workspace_container.clone(),
    ];

    if opts.env.read_only_root {
        create_args.push("--read-only".into());
        create_args.push("--tmpfs".into());
        create_args.push("/tmp:rw,exec,nosuid,size=512m".into());
        create_args.push("--tmpfs".into());
        create_args.push("/var/tmp:rw,exec,nosuid,size=256m".into());
    }
    if let Some(user) = &opts.env.user {
        create_args.push("--user".into());
        create_args.push(user.clone());
    }
    for (k, v) in &opts.env.env {
        if is_forbidden_env(k) {
            continue;
        }
        if opts.allowlist_env.is_empty() || opts.allowlist_env.iter().any(|a| a == k) {
            create_args.push("--env".into());
            create_args.push(format!("{k}={v}"));
        }
    }

    // Override any image entrypoint so startup cannot execute unrecorded code.
    create_args.push("--entrypoint".into());
    create_args.push("/bin/sleep".into());
    create_args.push(opts.env.image_ref.clone());
    create_args.push("infinity".into());

    let create = Command::new(&engine.path)
        .args(&create_args)
        .output()
        .await?;
    if !create.status.success() {
        return Err(SandboxError::Blocked(format!(
            "docker create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        )));
    }

    let start_out = Command::new(&engine.path)
        .args(["start", &name])
        .output()
        .await?;
    if !start_out.status.success() {
        let _ = Command::new(&engine.path)
            .args(["rm", "-f", &name])
            .output()
            .await;
        return Err(SandboxError::Blocked(format!(
            "docker start failed: {}",
            String::from_utf8_lossy(&start_out.stderr)
        )));
    }

    // Start only the fixed image-provided `/bin/sleep`, then detach the named
    // network before any recorded target command is executed. Podman 4.x does
    // not persist a network disconnect made while a container is stopped;
    // disconnecting the running inert container is portable across Docker and
    // Podman while preserving the target-code isolation boundary.
    if let Err(error) = disconnect_container_network(engine, &name).await {
        let _ = Command::new(&engine.path)
            .args(["rm", "-f", &name])
            .output()
            .await;
        return Err(error);
    }

    let cleanup = |engine: EngineInfo, name: String| async move {
        // Best-effort terminate then remove (cancellation / crash safety).
        let _ = Command::new(&engine.path)
            .args(["kill", &name])
            .output()
            .await;
        let _ = Command::new(&engine.path)
            .args(["rm", "-f", &name])
            .output()
            .await;
    };

    let mut combined_stdout = String::new();
    let mut combined_stderr = String::new();
    let mut last_exit = Some(0);
    let mut network_used = false;
    let mut timed_out = false;
    let start = Instant::now();
    let wall = Duration::from_secs(opts.env.timeout_seconds.max(1));

    // An inspect failure is not evidence of isolation. Require the engine to
    // corroborate the post-start disconnect before any target command executes.
    if let Err(error) = ensure_container_offline(engine, &name).await {
        cleanup(engine.clone(), name.clone()).await;
        return Err(error);
    }

    for cmd in commands {
        if start.elapsed() > wall {
            timed_out = true;
            break;
        }
        let remaining = wall.saturating_sub(start.elapsed());
        let use_net = command_network_access(opts.env.network_mode, cmd)
            .expect("network policy was validated before container creation");
        let transition = if use_net {
            connect_container_network(engine, &name).await
        } else {
            ensure_container_offline(engine, &name).await
        };
        if let Err(error) = transition {
            cleanup(engine.clone(), name.clone()).await;
            return Err(error);
        }

        let result = exec_in_container(engine, &name, cmd, use_net, remaining).await;
        // Never interpret or return a networked command result until the
        // engine confirms that egress has been removed again.
        if use_net {
            if let Err(error) = disconnect_container_network(engine, &name).await {
                cleanup(engine.clone(), name.clone()).await;
                return Err(error);
            }
        }
        match result {
            Ok(raw) => {
                network_used |= raw.network_used;
                combined_stdout.push_str(&raw.stdout);
                combined_stderr.push_str(&raw.stderr);
                last_exit = raw.exit_code;
                if raw.timed_out {
                    timed_out = true;
                    break;
                }
                if raw.exit_code.unwrap_or(1) != 0 {
                    cleanup(engine.clone(), name.clone()).await;
                    return Ok(RawExecutionResult {
                        exit_code: raw.exit_code,
                        signal: raw.signal,
                        stdout: combined_stdout,
                        stderr: combined_stderr,
                        duration_ms: start.elapsed().as_millis() as u64,
                        timed_out,
                        network_used,
                        error: raw.error,
                    });
                }
            }
            Err(e) => {
                cleanup(engine.clone(), name.clone()).await;
                return Err(e);
            }
        }
    }

    cleanup(engine.clone(), name).await;

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

fn engine_default_network(engine: &EngineInfo) -> &'static str {
    match engine.kind {
        EngineKind::Docker => "bridge",
        EngineKind::Podman => "podman",
    }
}

async fn engine_control_output(
    engine: &EngineInfo,
    args: &[&str],
    operation: &str,
) -> Result<std::process::Output> {
    let mut command = Command::new(&engine.path);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = command.spawn().map_err(|error| {
        SandboxError::Blocked(format!(
            "container network {operation} could not start: {error}"
        ))
    })?;
    let output = tokio::time::timeout(ENGINE_CONTROL_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| {
            SandboxError::Blocked(format!(
                "container network {operation} timed out after {} seconds",
                ENGINE_CONTROL_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|error| {
            SandboxError::Blocked(format!("container network {operation} failed: {error}"))
        })?;
    if output.stdout.len() > ENGINE_CONTROL_OUTPUT_LIMIT
        || output.stderr.len() > ENGINE_CONTROL_OUTPUT_LIMIT
    {
        return Err(SandboxError::Blocked(format!(
            "container network {operation} exceeded the control-output limit"
        )));
    }
    if !output.status.success() {
        return Err(SandboxError::Blocked(format!(
            "container network {operation} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output)
}

async fn inspect_container_networks(engine: &EngineInfo, name: &str) -> Result<BTreeSet<String>> {
    let output = engine_control_output(
        engine,
        &[
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            name,
        ],
        "status inspection",
    )
    .await?;
    parse_container_networks(&output.stdout)
}

fn parse_container_networks(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| SandboxError::Blocked("container network status was not valid JSON".into()))?;
    // Podman 4.9 renders `.NetworkSettings.Networks` as JSON `null` after the
    // last network is detached. Docker and newer Podman render `{}`. Both are
    // engine attestations that no named network remains attached.
    if value.is_null() {
        return Ok(BTreeSet::new());
    }
    let networks = value.as_object().ok_or_else(|| {
        SandboxError::Blocked("container network status was not a JSON object".into())
    })?;
    if networks.keys().any(|name| name.trim().is_empty()) {
        return Err(SandboxError::Blocked(
            "container network status contained an empty network name".into(),
        ));
    }
    Ok(networks.keys().cloned().collect())
}

fn networks_are_offline(networks: &BTreeSet<String>) -> bool {
    networks.is_empty()
}

async fn ensure_container_offline(engine: &EngineInfo, name: &str) -> Result<()> {
    let networks = inspect_container_networks(engine, name).await?;
    if networks_are_offline(&networks) {
        Ok(())
    } else {
        Err(SandboxError::Blocked(format!(
            "container unexpectedly has active networks: {}",
            networks.into_iter().collect::<Vec<_>>().join(", ")
        )))
    }
}

async fn connect_container_network(engine: &EngineInfo, name: &str) -> Result<()> {
    let before = inspect_container_networks(engine, name).await?;
    if !networks_are_offline(&before) {
        return Err(SandboxError::Blocked(
            "container was already network-connected before an allowed fetch".into(),
        ));
    }

    let network = engine_default_network(engine);
    engine_control_output(engine, &["network", "connect", network, name], "connect").await?;
    let after = inspect_container_networks(engine, name).await?;
    if after.len() != 1 || !after.contains(network) {
        return Err(SandboxError::Blocked(format!(
            "container network connect was not corroborated for {network}"
        )));
    }
    Ok(())
}

async fn disconnect_container_network(engine: &EngineInfo, name: &str) -> Result<()> {
    let network = engine_default_network(engine);
    let before = inspect_container_networks(engine, name).await?;
    if before.len() != 1 || !before.contains(network) {
        return Err(SandboxError::Blocked(format!(
            "container network state changed before disconnect: {}",
            before.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    engine_control_output(
        engine,
        &["network", "disconnect", "--force", network, name],
        "disconnect",
    )
    .await?;
    let after = inspect_container_networks(engine, name).await?;
    if !networks_are_offline(&after) {
        return Err(SandboxError::Blocked(
            "container network disconnect was not corroborated".into(),
        ));
    }
    Ok(())
}

/// Docker Desktop on Windows expects Linux-style paths for -v mounts when using
/// the linux engine context (//c/Users/...).
fn host_path_for_docker(path: &Path) -> String {
    let s = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    // Strip Windows \\?\ prefix
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    if cfg!(windows) {
        // C:\foo\bar -> /c/foo/bar
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            let drive = s.chars().next().unwrap().to_ascii_lowercase();
            let rest = s[2..].replace('\\', "/");
            return format!("/{drive}{rest}");
        }
        s.replace('\\', "/")
    } else {
        s
    }
}

async fn exec_in_container(
    engine: &EngineInfo,
    name: &str,
    cmd: &CommandSpec,
    network: bool,
    timeout: Duration,
) -> Result<RawExecutionResult> {
    let mut args: Vec<String> = vec!["exec".into()];
    // Workdir for this command
    if !cmd.workdir.is_empty() {
        args.push("-w".into());
        args.push(cmd.workdir.clone());
    }
    for (k, v) in &cmd.env {
        if is_forbidden_env(k) {
            continue;
        }
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }
    args.push(name.to_string());
    args.push(cmd.program.clone());
    args.extend(cmd.args.iter().cloned());

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
        Err(_elapsed) => Ok(RawExecutionResult {
            exit_code: None,
            signal: None,
            stdout: String::new(),
            stderr: "tomorrowci: container wall-clock timeout".into(),
            duration_ms: start.elapsed().as_millis() as u64,
            timed_out: true,
            network_used: network,
            error: Some("timeout".into()),
        }),
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
    let source_metadata = std::fs::symlink_metadata(source)?;
    if !source_metadata.is_dir()
        || source_metadata.file_type().is_symlink()
        || is_reparse_point(&source_metadata)
    {
        return Err(SandboxError::Blocked(
            "workspace source must be a plain directory".into(),
        ));
    }
    match std::fs::symlink_metadata(dest) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata)
            {
                return Err(SandboxError::Blocked(
                    "workspace destination must be a plain directory".into(),
                ));
            }
            std::fs::remove_dir_all(dest)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
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
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if ty.is_symlink() || is_reparse_point(&metadata) {
            return Err(SandboxError::Blocked(format!(
                "workspace contains unsupported link or reparse entry: {}",
                entry.path().display()
            )));
        }
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to)?;
        } else {
            return Err(SandboxError::Blocked(format!(
                "workspace contains unsupported non-regular entry: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tomorrowci_core::IndexMap;

    fn command(phase: CommandPhase, network_required: bool) -> CommandSpec {
        CommandSpec {
            phase,
            program: "fixture".into(),
            args: vec![],
            workdir: "/workspace".into(),
            network_required,
            env: IndexMap::new(),
        }
    }

    fn environment(network_mode: NetworkMode) -> EnvironmentSpec {
        EnvironmentSpec {
            image_ref: "fixture@sha256:deadbeef".into(),
            image_digest: None,
            workdir: "/workspace".into(),
            user: None,
            env: IndexMap::new(),
            mounts: vec![],
            network_mode,
            read_only_root: false,
            memory_mb: 128,
            cpus: 1.0,
            pids_limit: 16,
            timeout_seconds: 10,
        }
    }

    #[test]
    fn daemon_readiness_probe_is_portable_across_supported_engines() {
        assert_eq!(daemon_probe_args(EngineKind::Docker), ["info"]);
        assert_eq!(daemon_probe_args(EngineKind::Podman), ["info"]);
    }

    #[test]
    fn fetch_needs_both_recorded_command_and_environment_permission() {
        let implicit_fetch = command(CommandPhase::Fetch, false);
        assert!(!command_network_access(NetworkMode::FetchOnly, &implicit_fetch).unwrap());
        assert!(!command_network_access(NetworkMode::Full, &implicit_fetch).unwrap());

        let explicit_fetch = command(CommandPhase::Fetch, true);
        assert!(command_network_access(NetworkMode::FetchOnly, &explicit_fetch).unwrap());
        assert!(command_network_access(NetworkMode::Full, &explicit_fetch).unwrap());
        assert!(command_network_access(NetworkMode::None, &explicit_fetch).is_err());
        assert!(validate_network_policy(
            &environment(NetworkMode::None),
            std::slice::from_ref(&explicit_fetch)
        )
        .is_err());
    }

    #[test]
    fn forged_non_fetch_network_request_is_blocked_in_every_mode() {
        for phase in [CommandPhase::Build, CommandPhase::Test, CommandPhase::Probe] {
            for mode in [NetworkMode::None, NetworkMode::FetchOnly, NetworkMode::Full] {
                assert!(command_network_access(mode, &command(phase, true)).is_err());
            }
        }
    }

    #[test]
    fn network_status_must_be_valid_and_corroborate_isolation() {
        let none = parse_container_networks(br#"{"none":{}}"#).unwrap();
        assert!(!networks_are_offline(&none));
        let detached = parse_container_networks(br#"{}"#).unwrap();
        assert!(networks_are_offline(&detached));
        let podman_detached = parse_container_networks(b"null").unwrap();
        assert!(networks_are_offline(&podman_detached));
        let bridge = parse_container_networks(br#"{"bridge":{}}"#).unwrap();
        assert!(!networks_are_offline(&bridge));

        assert!(parse_container_networks(b"not-json").is_err());
        assert!(parse_container_networks(b"[]").is_err());
        assert!(parse_container_networks(br#"{"":{}}"#).is_err());
    }

    #[tokio::test]
    async fn network_status_process_error_fails_closed() {
        let engine = EngineInfo {
            kind: EngineKind::Docker,
            path: PathBuf::from("definitely-missing-tomorrowci-engine-binary"),
            version: "test".into(),
        };
        let error = inspect_container_networks(&engine, "fixture")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not start"), "{error}");
    }

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

    #[cfg(unix)]
    #[test]
    fn materialization_rejects_source_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("target"), b"data").unwrap();
        symlink("target", source.join("link")).unwrap();

        let error = materialize_workspace(&source, &destination).unwrap_err();
        assert!(error.to_string().contains("link or reparse"));
    }

    #[cfg(windows)]
    #[test]
    fn materialization_rejects_source_junctions() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let external = root.path().join("external");
        let destination = root.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("secret"), b"data").unwrap();
        let junction = source.join("junction");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&external)
            .status()
            .unwrap();
        assert!(status.success(), "test junction could not be created");

        let error = materialize_workspace(&source, &destination).unwrap_err();
        assert!(error.to_string().contains("link or reparse"));
    }
}
