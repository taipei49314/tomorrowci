//! Sandbox: Docker/Podman isolation. Never run target code on host by default.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tomorrowci_core::{
    CommandSpec, EnvironmentSpec, RawExecutionResult, Result, TcError,
};

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
    SandboxAvailability {
        docker,
        podman,
        selected,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub privileged: bool,
    pub mount_docker_socket: bool,
    pub forward_host_env: bool,
    pub network_during_test: bool,
    pub mutate_user_repo: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            privileged: false,
            mount_docker_socket: false,
            forward_host_env: false,
            network_during_test: false,
            mutate_user_repo: false,
        }
    }
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
        // skip heavy/irrelevant
        if matches!(
            name_s.as_ref(),
            "target" | "node_modules" | ".git" | ".tomorrowci" | "__pycache__" | ".venv" | "venv"
        ) {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        if from.is_symlink() {
            // refuse following symlinks out of tree
            continue;
        }
        if from.is_dir() {
            copy_dir_filtered(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub engine: SandboxEngine,
    pub image: String,
    pub workspace_host: PathBuf,
    pub workdir: String,
    pub commands: Vec<CommandSpec>,
    pub env: HashMap<String, String>,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub network: String, // "none" | "bridge" for fetch phase
    pub timeout: Duration,
    pub read_only_root: bool,
    pub user: Option<String>,
}

pub fn resolve_image_digest(engine: SandboxEngine, image: &str) -> Option<String> {
    let bin = engine_bin(engine);
    let out = Command::new(bin)
        .args(["image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "<no value>" {
        // fallback image id
        let out2 = Command::new(bin)
            .args(["image", "inspect", "--format", "{{.Id}}", image])
            .output()
            .ok()?;
        let id = String::from_utf8_lossy(&out2.stdout).trim().to_string();
        if id.is_empty() {
            None
        } else {
            Some(id)
        }
    } else {
        Some(s)
    }
}

pub fn pull_image(engine: SandboxEngine, image: &str) -> Result<()> {
    let bin = engine_bin(engine);
    let st = Command::new(bin)
        .args(["pull", image])
        .status()
        .map_err(|e| TcError::Blocked(format!("failed to spawn {bin} pull: {e}")))?;
    if !st.success() {
        return Err(TcError::Blocked(format!(
            "failed to pull image {image}"
        )));
    }
    Ok(())
}

fn engine_bin(engine: SandboxEngine) -> &'static str {
    match engine {
        SandboxEngine::Docker => "docker",
        SandboxEngine::Podman => "podman",
    }
}

/// Run commands inside a container. Network should be "none" for test phase.
pub fn run_in_container(req: &RunRequest) -> Result<RawExecutionResult> {
    SecurityPolicy::default().validate_safe_defaults()?;
    let bin = engine_bin(req.engine);
    let workspace = std::fs::canonicalize(&req.workspace_host)
        .unwrap_or_else(|_| req.workspace_host.clone());
    // Windows Docker Desktop needs path conversion sometimes — pass as-is; Docker handles.
    let mount = format!("{}:{}:rw", workspace.display(), req.workdir);

    let mut docker_args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        req.network.clone(),
        "--memory".into(),
        format!("{}m", req.memory_mb),
        "--cpus".into(),
        req.cpus.to_string(),
        "--pids-limit".into(),
        req.pids_limit.to_string(),
        "-v".into(),
        mount,
        "-w".into(),
        req.workdir.clone(),
    ];
    if req.read_only_root {
        docker_args.push("--read-only".into());
        docker_args.push("--tmpfs".into());
        docker_args.push("/tmp:rw,exec,nosuid,size=256m".into());
    }
    if let Some(user) = &req.user {
        docker_args.push("--user".into());
        docker_args.push(user.clone());
    }
    // never privileged, never docker.sock
    for (k, v) in &req.env {
        if is_forbidden_env(k) {
            continue;
        }
        docker_args.push("-e".into());
        docker_args.push(format!("{k}={v}"));
    }
    docker_args.push(req.image.clone());

    // Join commands with && in sh -c for multi-step; argv recorded separately in evidence.
    let shell_cmd = req
        .commands
        .iter()
        .map(|c| shell_join(&c.argv))
        .collect::<Vec<_>>()
        .join(" && ");
    docker_args.push("sh".into());
    docker_args.push("-c".into());
    docker_args.push(shell_cmd);

    let start = Instant::now();
    let mut child = Command::new(bin)
        .args(&docker_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| TcError::Blocked(format!("docker spawn failed: {e}")))?;

    // Simple timeout via thread + kill
    let timeout = req.timeout;
    let timed_out = wait_with_timeout(&mut child, timeout)?;
    let output = child
        .wait_with_output()
        .map_err(|e| TcError::Blocked(format!("wait failed: {e}")))?;

    let duration_ms = start.elapsed().as_millis() as u64;
    let stdout = truncate_log(&String::from_utf8_lossy(&output.stdout), 512 * 1024);
    let stderr = truncate_log(&String::from_utf8_lossy(&output.stderr), 512 * 1024);

    Ok(RawExecutionResult {
        exit_code: if timed_out {
            None
        } else {
            output.status.code()
        },
        signal: None,
        duration_ms,
        timed_out,
        stdout,
        stderr,
        network_used: req.network != "none",
    })
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<bool> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(true);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TcError::Blocked(format!("try_wait: {e}"))),
        }
    }
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('"') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_forbidden_env(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    u.contains("SECRET")
        || u.contains("TOKEN")
        || u.contains("PASSWORD")
        || u.starts_with("AWS_")
        || u == "SSH_AUTH_SOCK"
}

fn truncate_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}\n...[truncated {} bytes]...\n", &s[..max], s.len() - max)
    }
}

pub fn env_spec_to_map(spec: &EnvironmentSpec) -> HashMap<String, String> {
    spec.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

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
        let dest = d.path().join("dest");
        make_disposable_copy(&src, &dest).unwrap();
        assert!(dest.join("a.py").exists());
        assert!(!dest.join(".git").exists());
    }
}
