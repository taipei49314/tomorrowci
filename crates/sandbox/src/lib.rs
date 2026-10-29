//! Sandbox: Docker/Podman isolation. Never run target code on host by default.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tomorrowci_core::{
    validate_image_digest, CommandSpec, EnvironmentSpec, RawExecutionResult, Result, TcError,
};
use uuid::Uuid;

/// Maximum stdout bytes retained in memory for one container invocation.
///
/// The pipe is still drained after this limit; excess bytes are counted and
/// represented by a deterministic truncation marker in persisted output.
pub const MAX_CONTAINER_STDOUT_BYTES: usize = 512 * 1024;

/// Maximum stderr bytes retained in memory for one container invocation.
///
/// The pipe is still drained after this limit; excess bytes are counted and
/// represented by a deterministic truncation marker in persisted output.
pub const MAX_CONTAINER_STDERR_BYTES: usize = 512 * 1024;

/// A stuck engine cleanup command must not hold the runner indefinitely.
pub const CONTAINER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEngine {
    Docker,
    Podman,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAvailability {
    pub docker: bool,
    pub podman: bool,
    pub selected: Option<SandboxEngine>,
    pub engine_version: Option<String>,
    pub notes: Vec<String>,
}

pub fn detect_engines() -> SandboxAvailability {
    let docker = engine_alive("docker");
    let podman = engine_alive("podman");
    let mut notes = Vec::new();
    let selected = if docker {
        notes.push("Docker daemon responsive.".into());
        Some(SandboxEngine::Docker)
    } else if podman {
        notes.push("Podman responsive.".into());
        Some(SandboxEngine::Podman)
    } else {
        notes.push(
            "Neither Docker nor Podman daemon available; sandbox execution is BLOCKED.".into(),
        );
        if which_exists("docker") {
            notes.push("docker CLI found but daemon not responding.".into());
        }
        None
    };
    let engine_version = selected.and_then(engine_version);
    SandboxAvailability {
        docker,
        podman,
        selected,
        engine_version,
        notes,
    }
}

fn which_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn engine_alive(bin: &str) -> bool {
    Command::new(bin)
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Query the exact selected engine's server/build version.
pub fn engine_version(engine: SandboxEngine) -> Option<String> {
    let bin = engine_bin(engine);
    let out = Command::new(bin)
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let out2 = Command::new(bin).args(["--version"]).output().ok()?;
    Some(String::from_utf8_lossy(&out2.stdout).trim().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityPolicy {
    pub privileged: bool,
    pub mount_docker_socket: bool,
    pub forward_host_env: bool,
    pub network_during_test: bool,
    pub mutate_user_repo: bool,
}

impl SecurityPolicy {
    pub fn validate_safe_defaults(&self) -> Result<()> {
        if self.privileged {
            return Err(TcError::InvalidState(
                "privileged containers are forbidden".into(),
            ));
        }
        if self.mount_docker_socket {
            return Err(TcError::InvalidState(
                "mounting docker.sock into target is forbidden".into(),
            ));
        }
        if self.mutate_user_repo {
            return Err(TcError::InvalidState(
                "mutating the user repository is forbidden".into(),
            ));
        }
        Ok(())
    }
}

pub fn refuse_host_execution() -> Result<()> {
    Err(TcError::Blocked(
        "target code must not execute on the host by default; use Docker/Podman sandbox".into(),
    ))
}

/// Copy repo into disposable workspace (does not mutate original).
pub fn make_disposable_copy(src: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        let _ = std::fs::remove_dir_all(dest);
    }
    copy_dir_filtered(src, dest)?;
    Ok(())
}

fn copy_dir_filtered(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if matches!(
            name_s.as_ref(),
            "target"
                | "node_modules"
                | ".git"
                | ".tomorrowci"
                | "__pycache__"
                | ".venv"
                | "venv"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
                | ".tox"
                | ".nox"
        ) {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        let metadata = std::fs::symlink_metadata(&from)?;
        if metadata_is_alias(&metadata) {
            return Err(TcError::InvalidState(format!(
                "refusing source symlink/reparse point while copying workspace: {}",
                from.display()
            )));
        }
        if metadata.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else if metadata.is_file() {
            std::fs::copy(&from, &to)?;
        } else {
            return Err(TcError::InvalidState(format!(
                "unsupported source filesystem entry while copying workspace: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

/// Detect the configured engine without silently falling back to a different
/// engine. `auto` retains Docker-first auto-detection for compatibility.
pub fn detect_requested_engine(requested: &str) -> Result<SandboxEngine> {
    let availability = detect_engines();
    select_requested_engine(requested, &availability)
}

fn select_requested_engine(
    requested: &str,
    availability: &SandboxAvailability,
) -> Result<SandboxEngine> {
    match requested {
        "auto" => availability
            .selected
            .ok_or_else(|| TcError::Blocked(availability.notes.join("; "))),
        "docker" if availability.docker => Ok(SandboxEngine::Docker),
        "podman" if availability.podman => Ok(SandboxEngine::Podman),
        "docker" => Err(TcError::Blocked(
            "sandbox.engine requested docker, but the Docker daemon is unavailable; refusing to fall back to Podman"
                .into(),
        )),
        "podman" => Err(TcError::Blocked(
            "sandbox.engine requested podman, but the Podman daemon is unavailable; refusing to fall back to Docker"
                .into(),
        )),
        other => Err(TcError::Config(format!(
            "sandbox.engine must be auto|docker|podman, got {other}"
        ))),
    }
}

fn metadata_is_alias(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

/// Prepare scenario-local writable state under the disposable workspace.
pub fn prepare_scenario_state(workspace: &Path) -> Result<PathBuf> {
    let root = workspace.join(".tomorrowci");
    let venv = root.join("venv");
    let cache = root.join("cache").join("pip");
    std::fs::create_dir_all(&venv)?;
    std::fs::create_dir_all(&cache)?;
    // Ensure non-root container user can write (best-effort on Windows mounts).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o777);
        let _ = std::fs::set_permissions(&root, mode.clone());
        let _ = std::fs::set_permissions(&venv, mode.clone());
        let _ = std::fs::set_permissions(workspace.join(".tomorrowci/cache"), mode.clone());
        let _ = std::fs::set_permissions(&cache, mode);
    }
    Ok(root)
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub engine: SandboxEngine,
    /// Prefer immutable ref `image@sha256:...` when available.
    pub image: String,
    pub workspace_host: PathBuf,
    /// Only the trusted preparation command may mount this seed read-only.
    pub prepared_seed_host: Option<PathBuf>,
    pub workdir: String,
    pub commands: Vec<CommandSpec>,
    pub env: HashMap<String, String>,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub network: String,
    pub timeout: Duration,
    pub read_only_root: bool,
    pub user: Option<String>,
    /// When true, record only argv execution via `sh -c` with proven escaping.
    pub use_shell: bool,
}

/// Pull image if needed and return an immutable digest ref (`repo@sha256:...` or `sha256:...`).
pub fn resolve_or_pull_digest(engine: SandboxEngine, image: &str) -> Result<String> {
    if let Some(d) = resolve_image_digest(engine, image) {
        return Ok(d);
    }
    pull_image(engine, image)?;
    resolve_image_digest(engine, image).ok_or_else(|| {
        TcError::Blocked(format!(
            "image {image} pulled but immutable digest could not be resolved"
        ))
    })
}

pub fn resolve_image_digest(engine: SandboxEngine, image: &str) -> Option<String> {
    let bin = engine_bin(engine);
    // Already a digest-pinned ref
    if image.contains("@sha256:") {
        return validate_image_digest(image)
            .is_ok()
            .then(|| image.to_string());
    }
    let out = Command::new(bin)
        .args([
            "image",
            "inspect",
            "--format",
            "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}",
            image,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "<no value>" {
        return None;
    }
    // Normalize Id-only to sha256:...
    if s.starts_with("sha256:") || s.contains("@sha256:") {
        validate_image_digest(&s).is_ok().then_some(s)
    } else if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let normalized = format!("sha256:{}", s.to_ascii_lowercase());
        validate_image_digest(&normalized)
            .is_ok()
            .then_some(normalized)
    } else {
        None
    }
}

pub fn pull_image(engine: SandboxEngine, image: &str) -> Result<()> {
    let bin = engine_bin(engine);
    let st = Command::new(bin)
        .args(["pull", image])
        .status()
        .map_err(|e| TcError::Blocked(format!("failed to spawn {bin} pull: {e}")))?;
    if !st.success() {
        return Err(TcError::Blocked(format!("failed to pull image {image}")));
    }
    Ok(())
}

fn engine_bin(engine: SandboxEngine) -> &'static str {
    match engine {
        SandboxEngine::Docker => "docker",
        SandboxEngine::Podman => "podman",
    }
}

fn mount_source(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(rest) = rendered.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = rendered.strip_prefix(r"\\?\") {
            return rest.to_string();
        }
    }
    rendered.into_owned()
}

#[derive(Debug, PartialEq, Eq)]
struct BoundedStreamCapture {
    retained: Vec<u8>,
    discarded_bytes: u64,
}

impl BoundedStreamCapture {
    fn render(&self, limit: usize) -> String {
        let mut rendered = String::from_utf8_lossy(&self.retained).into_owned();
        if self.discarded_bytes > 0 {
            rendered.push_str(&format!(
                "\n...[truncated after {limit} bytes; discarded {} bytes]...\n",
                self.discarded_bytes
            ));
        }
        rendered
    }
}

/// Retain at most `limit` bytes while continuing to read until EOF. Continuing
/// to drain is required because stopping at the retention limit can deadlock a
/// child whose pipe buffer becomes full.
fn drain_stream_bounded<R: Read>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<BoundedStreamCapture> {
    let mut retained = Vec::with_capacity(limit.min(STREAM_READ_CHUNK_BYTES));
    let mut discarded_bytes = 0_u64;
    let mut chunk = [0_u8; STREAM_READ_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&chunk[..keep]);
        discarded_bytes = discarded_bytes.saturating_add((read - keep) as u64);
    }
    Ok(BoundedStreamCapture {
        retained,
        discarded_bytes,
    })
}

fn spawn_bounded_drain<R>(
    reader: R,
    limit: usize,
) -> mpsc::Receiver<std::io::Result<BoundedStreamCapture>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(drain_stream_bounded(reader, limit));
    });
    receiver
}

fn receive_bounded_capture(
    receiver: mpsc::Receiver<std::io::Result<BoundedStreamCapture>>,
    stream_name: &str,
) -> Result<BoundedStreamCapture> {
    receiver
        .recv_timeout(PIPE_DRAIN_TIMEOUT)
        .map_err(|error| {
            TcError::Blocked(format!(
                "timed out draining container {stream_name} after process exit: {error}"
            ))
        })?
        .map_err(|error| {
            TcError::Blocked(format!("failed draining container {stream_name}: {error}"))
        })
}

#[derive(Debug)]
struct CleanupProcessOutput {
    status: ExitStatus,
    timed_out: bool,
    stdout: BoundedStreamCapture,
    stderr: BoundedStreamCapture,
}

/// Execute the exact-container cleanup process with an independent deadline.
/// The child is killed and reaped when it exceeds the deadline.
fn run_cleanup_process(mut command: Command, timeout: Duration) -> Result<CleanupProcessOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| TcError::Blocked(format!("container cleanup spawn failed: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .expect("cleanup stdout must be piped before spawn");
    let stderr = child
        .stderr
        .take()
        .expect("cleanup stderr must be piped before spawn");
    let stdout_receiver = spawn_bounded_drain(stdout, MAX_CONTAINER_STDOUT_BYTES);
    let stderr_receiver = spawn_bounded_drain(stderr, MAX_CONTAINER_STDERR_BYTES);

    let timed_out = wait_with_timeout(&mut child, timeout)?;
    let status = child_status_with_timeout(&mut child, PIPE_DRAIN_TIMEOUT, "cleanup process")?;
    let stdout = receive_bounded_capture(stdout_receiver, "cleanup stdout")?;
    let stderr = receive_bounded_capture(stderr_receiver, "cleanup stderr")?;
    Ok(CleanupProcessOutput {
        status,
        timed_out,
        stdout,
        stderr,
    })
}

fn cleanup_exact_container(engine: SandboxEngine, container_name: &str) -> Result<()> {
    let bin = engine_bin(engine);
    let mut command = Command::new(bin);
    command.args(["rm", "-f", container_name]);
    let output = run_cleanup_process(command, CONTAINER_CLEANUP_TIMEOUT)?;
    let stderr = redact_secrets(&output.stderr.render(MAX_CONTAINER_STDERR_BYTES));
    let stdout = redact_secrets(&output.stdout.render(MAX_CONTAINER_STDOUT_BYTES));
    if output.timed_out {
        return Err(TcError::Blocked(format!(
            "timed-out container cleanup command exceeded {} seconds and was killed; container {container_name} may still be running",
            CONTAINER_CLEANUP_TIMEOUT.as_secs()
        )));
    }
    if !output.status.success() {
        return Err(TcError::Blocked(format!(
            "timed-out container cleanup failed for {container_name}: status={}; stderr={}; stdout={}",
            output.status,
            stderr.trim().chars().take(400).collect::<String>(),
            stdout.trim().chars().take(400).collect::<String>()
        )));
    }
    Ok(())
}

/// Run commands inside a container. Network should be "none" for test phase.
pub fn run_in_container(req: &RunRequest) -> Result<RawExecutionResult> {
    SecurityPolicy::default().validate_safe_defaults()?;
    let bin = engine_bin(req.engine);
    let workspace =
        std::fs::canonicalize(&req.workspace_host).unwrap_or_else(|_| req.workspace_host.clone());
    let mount = format!("{}:{}:rw", mount_source(&workspace), req.workdir);
    let container_name = format!("tomorrowci-{}", Uuid::new_v4().simple());

    let mut docker_args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        container_name.clone(),
        "--network".into(),
        req.network.clone(),
        "--memory".into(),
        format!("{}m", req.memory_mb),
        "--cpus".into(),
        req.cpus.to_string(),
        "--pids-limit".into(),
        req.pids_limit.to_string(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "-v".into(),
        mount,
        "-w".into(),
        req.workdir.clone(),
    ];
    if let Some(seed) = &req.prepared_seed_host {
        let seed = validate_prepared_seed(req, seed, &workspace)?;
        docker_args.extend([
            "-v".into(),
            format!("{}:/tomorrowci-seed:ro", mount_source(&seed)),
        ]);
    }
    if req.read_only_root {
        docker_args.push("--read-only".into());
        docker_args.push("--tmpfs".into());
        docker_args.push("/tmp:rw,exec,nosuid,size=256m".into());
        // venv creation needs write under /work which is mounted rw
    }
    if let Some(user) = &req.user {
        docker_args.push("--user".into());
        docker_args.push(user.clone());
    }
    for (k, v) in &req.env {
        if is_forbidden_env(k) {
            continue;
        }
        docker_args.push("-e".into());
        docker_args.push(format!("{k}={v}"));
    }
    docker_args.push(req.image.clone());

    if req.use_shell
        || req.commands.len() > 1
        || req
            .commands
            .iter()
            .any(|c| c.argv.len() > 1 && needs_shell(&c.argv))
    {
        let shell_cmd = req
            .commands
            .iter()
            .map(|c| shell_join(&c.argv))
            .collect::<Vec<_>>()
            .join(" && ");
        docker_args.push("sh".into());
        docker_args.push("-c".into());
        docker_args.push(shell_cmd);
    } else if let Some(cmd) = req.commands.first() {
        // Direct argv — recorded argv matches executed argv
        for a in &cmd.argv {
            docker_args.push(a.clone());
        }
    } else {
        return Err(TcError::InvalidState("no commands to execute".into()));
    }

    let start = Instant::now();
    let mut child = Command::new(bin)
        .args(&docker_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| TcError::Blocked(format!("container spawn failed: {e}")))?;

    let stdout_pipe = child
        .stdout
        .take()
        .expect("container stdout must be piped before spawn");
    let stderr_pipe = child
        .stderr
        .take()
        .expect("container stderr must be piped before spawn");
    let stdout_receiver = spawn_bounded_drain(stdout_pipe, MAX_CONTAINER_STDOUT_BYTES);
    let stderr_receiver = spawn_bounded_drain(stderr_pipe, MAX_CONTAINER_STDERR_BYTES);

    let timed_out = wait_with_timeout(&mut child, req.timeout)?;
    let cleanup_error = if timed_out {
        cleanup_exact_container(req.engine, &container_name)
            .err()
            .map(|error| error.to_string())
    } else {
        None
    };
    let status = child_status_with_timeout(&mut child, PIPE_DRAIN_TIMEOUT, "container client")?;

    let stdout_capture = receive_bounded_capture(stdout_receiver, "stdout")?;
    let stderr_capture = receive_bounded_capture(stderr_receiver, "stderr")?;

    let duration_ms = start.elapsed().as_millis() as u64;
    let stdout = redact_secrets(&stdout_capture.render(MAX_CONTAINER_STDOUT_BYTES));
    let stderr = redact_secrets(&stderr_capture.render(MAX_CONTAINER_STDERR_BYTES));
    if let Some(error) = cleanup_error {
        return Err(TcError::Blocked(format!(
            "{error}; timed-out container may still be running; stderr={}",
            stderr.chars().take(400).collect::<String>()
        )));
    }

    Ok(RawExecutionResult {
        workspace_preparation: None,
        exit_code: if timed_out { None } else { status.code() },
        signal: None,
        duration_ms,
        timed_out,
        stdout,
        stderr,
        network_used: req.network != "none",
    })
}

fn validate_prepared_seed(req: &RunRequest, seed: &Path, workspace: &Path) -> Result<PathBuf> {
    if req.network != "none"
        || req.workdir != "/work"
        || req.commands.len() != 1
        || req.commands[0].phase != "workspace-prepare"
        || req.commands[0].argv != tomorrowci_core::prepared_workspace_copy_argv()
        || req.commands[0].network
        || req.commands[0].cwd.as_deref() != Some("/work")
    {
        return Err(TcError::InvalidState(
            "invalid offline prepared-workspace copy contract".into(),
        ));
    }
    for path in [seed, workspace] {
        for ancestor in path.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            if metadata_is_alias(&metadata) || !metadata.is_dir() {
                return Err(TcError::InvalidState(
                    "prepared workspace roots must have plain directory ancestors".into(),
                ));
            }
        }
    }
    let seed = std::fs::canonicalize(seed)?;
    let workspace = std::fs::canonicalize(workspace)?;
    if seed.starts_with(&workspace) || workspace.starts_with(&seed) {
        return Err(TcError::InvalidState(
            "prepared seed and test destination must not overlap".into(),
        ));
    }
    if std::fs::read_dir(&workspace)?.next().is_some() {
        return Err(TcError::InvalidState(
            "prepared test destination must be empty".into(),
        ));
    }
    Ok(seed)
}

fn needs_shell(argv: &[String]) -> bool {
    // Prefer shell only when metacharacters require a shell pipeline
    argv.iter()
        .any(|a| a.contains('|') || a.contains('>') || a.contains('<') || a.contains('&'))
}

fn wait_with_timeout(child: &mut std::process::Child, timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return Ok(true);
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TcError::Blocked(format!("try_wait: {e}"))),
        }
    }
}

fn child_status_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    process_name: &str,
) -> Result<ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                return Err(TcError::Blocked(format!(
                    "{process_name} did not exit within {} seconds after termination",
                    timeout.as_secs()
                )));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                return Err(TcError::Blocked(format!(
                    "failed checking {process_name} status: {error}"
                )))
            }
        }
    }
}

/// POSIX-style single-quote shell joining so recorded argv and shell form stay aligned.
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn shell_quote(a: &str) -> String {
    // Always single-quote; escape embedded single quotes with '\''
    format!("'{}'", a.replace('\'', "'\\''"))
}

fn is_forbidden_env(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    u.contains("SECRET")
        || u.contains("TOKEN")
        || u.contains("PASSWORD")
        || u.starts_with("AWS_")
        || u == "SSH_AUTH_SOCK"
}

pub fn redact_secrets(s: &str) -> String {
    // Simple pattern redaction for persisted logs
    let mut out = s.to_string();
    for pat in [
        "password=",
        "PASSWORD=",
        "token=",
        "TOKEN=",
        "secret=",
        "SECRET=",
    ] {
        if let Some(idx) = out.find(pat) {
            let rest = &out[idx + pat.len()..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            out = format!(
                "{}{}***REDACTED***{}",
                &out[..idx + pat.len()],
                "",
                &rest[end..]
            );
        }
    }
    out
}

/// Truncate without slicing inside a UTF-8 code point.
pub fn truncate_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n...[truncated {} bytes]...\n",
        &s[..end],
        s.len().saturating_sub(end)
    )
}

pub fn env_spec_to_map(spec: &EnvironmentSpec) -> HashMap<String, String> {
    spec.env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Cap number of artifact files recorded under a scenario directory.
pub const MAX_SCENARIO_ARTIFACTS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_defaults() {
        SecurityPolicy::default().validate_safe_defaults().unwrap();
    }

    #[test]
    fn host_execution_refused() {
        assert!(refuse_host_execution().is_err());
    }

    #[test]
    fn disposable_copy_skips_git() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(src.join(".git")).unwrap();
        std::fs::write(src.join("a.py"), "x").unwrap();
        std::fs::write(src.join(".git/x"), "no").unwrap();
        for ignored in [
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".nox",
        ] {
            std::fs::create_dir_all(src.join(ignored)).unwrap();
            std::fs::write(src.join(ignored).join("unbound"), "no").unwrap();
        }
        let dest = d.path().join("dest");
        make_disposable_copy(&src, &dest).unwrap();
        assert!(dest.join("a.py").exists());
        assert!(!dest.join(".git").exists());
        for ignored in [
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".nox",
        ] {
            assert!(!dest.join(ignored).exists(), "copied ignored {ignored}");
        }
    }

    #[test]
    fn requested_engine_never_falls_back_to_another_available_engine() {
        let podman_only = SandboxAvailability {
            docker: false,
            podman: true,
            selected: Some(SandboxEngine::Podman),
            engine_version: Some("podman-test".into()),
            notes: vec!["Podman responsive.".into()],
        };
        assert_eq!(
            select_requested_engine("podman", &podman_only).unwrap(),
            SandboxEngine::Podman
        );
        assert_eq!(
            select_requested_engine("auto", &podman_only).unwrap(),
            SandboxEngine::Podman
        );
        let error = select_requested_engine("docker", &podman_only).unwrap_err();
        assert!(error.to_string().contains("refusing to fall back"));

        let both = SandboxAvailability {
            docker: true,
            podman: true,
            selected: Some(SandboxEngine::Docker),
            engine_version: Some("docker-test".into()),
            notes: vec![],
        };
        assert_eq!(
            select_requested_engine("podman", &both).unwrap(),
            SandboxEngine::Podman
        );
    }

    #[test]
    fn oversized_streams_are_fully_drained_but_retained_memory_is_bounded() {
        for limit in [MAX_CONTAINER_STDOUT_BYTES, MAX_CONTAINER_STDERR_BYTES] {
            let excess = 31_337;
            let input = vec![b'x'; limit + excess];
            let capture = drain_stream_bounded(std::io::Cursor::new(input), limit).unwrap();
            assert_eq!(capture.retained.len(), limit);
            assert_eq!(capture.discarded_bytes, excess as u64);
            let rendered = capture.render(limit);
            assert!(rendered.ends_with(&format!(
                "\n...[truncated after {limit} bytes; discarded {excess} bytes]...\n"
            )));
        }
    }

    #[cfg(unix)]
    fn deliberately_slow_cleanup_command() -> Command {
        let mut command = Command::new("sleep");
        command.arg("5");
        command
    }

    #[cfg(windows)]
    fn deliberately_slow_cleanup_command() -> Command {
        let mut command = Command::new("ping");
        command.args(["-n", "6", "127.0.0.1"]);
        command
    }

    #[test]
    fn cleanup_process_timeout_kills_and_returns_within_a_bound() {
        let started = Instant::now();
        let output = run_cleanup_process(
            deliberately_slow_cleanup_command(),
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(output.timed_out);
        assert!(!output.status.success());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "cleanup timeout path took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn utf8_truncate_never_panics() {
        let s = "hello 😀 world 世界";
        let t = truncate_log(s, 8);
        assert!(t.contains("truncated") || t.len() <= s.len());
        // mid-emoji boundary
        let emoji = "aa😀bb";
        let _ = truncate_log(emoji, 3);
        let _ = truncate_log(emoji, 4);
        let _ = truncate_log(emoji, 5);
    }

    #[test]
    fn shell_quote_metacharacters() {
        let q = shell_quote("a b;$(echo hi)");
        assert!(q.starts_with('\''));
        assert!(
            shell_join(&["echo".into(), "hello world".into(), "x;y".into()])
                .contains("'hello world'")
        );
    }

    #[test]
    fn redact_password() {
        let s = redact_secrets("export password=supersecret rest");
        assert!(s.contains("***REDACTED***"));
        assert!(!s.contains("supersecret"));
    }

    #[test]
    fn preparation_rejects_overlap_dirty_destinations_and_target_commands() {
        let seed = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let mut request = RunRequest {
            engine: SandboxEngine::Docker,
            image: format!("sha256:{}", "a".repeat(64)),
            workspace_host: destination.path().into(),
            prepared_seed_host: Some(seed.path().into()),
            workdir: "/work".into(),
            commands: vec![CommandSpec {
                argv: tomorrowci_core::prepared_workspace_copy_argv(),
                cwd: Some("/work".into()),
                network: false,
                phase: "workspace-prepare".into(),
            }],
            env: HashMap::new(),
            memory_mb: 256,
            cpus: 1.0,
            pids_limit: 64,
            network: "none".into(),
            timeout: Duration::from_secs(60),
            read_only_root: true,
            user: Some("65534:65534".into()),
            use_shell: true,
        };
        assert!(validate_prepared_seed(&request, seed.path(), destination.path()).is_ok());
        assert!(validate_prepared_seed(&request, seed.path(), seed.path()).is_err());
        let child = seed.path().join("child");
        std::fs::create_dir(&child).unwrap();
        assert!(validate_prepared_seed(&request, seed.path(), &child).is_err());
        std::fs::write(destination.path().join("old-attempt"), "mutation").unwrap();
        assert!(validate_prepared_seed(&request, seed.path(), destination.path()).is_err());
        std::fs::remove_file(destination.path().join("old-attempt")).unwrap();
        request.network = "bridge".into();
        assert!(validate_prepared_seed(&request, seed.path(), destination.path()).is_err());
        request.network = "none".into();
        request.commands[0].argv = vec!["python".into(), "untrusted.py".into()];
        assert!(validate_prepared_seed(&request, seed.path(), destination.path()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn docker_mount_source_strips_windows_verbatim_prefixes() {
        assert_eq!(
            mount_source(Path::new(r"\\?\C:\work\repo")),
            r"C:\work\repo"
        );
        assert_eq!(
            mount_source(Path::new(r"\\?\UNC\server\share\repo")),
            r"\\server\share\repo"
        );
    }
}
