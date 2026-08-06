//! Sandbox engine selection and security policy.
//! Default: never run target code on the host.

use serde::{Deserialize, Serialize};
use std::process::Command;
use tomorrowci_core::{Result, TcError};

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
    let docker = command_ok("docker", &["version"]);
    let podman = command_ok("podman", &["version"]);
    let mut notes = Vec::new();
    let selected = if docker {
        Some(SandboxEngine::Docker)
    } else if podman {
        Some(SandboxEngine::Podman)
    } else {
        notes.push(
            "Neither Docker nor Podman available; sandbox execution is BLOCKED.".into(),
        );
        None
    };
    if docker {
        notes.push("Docker available.".into());
    }
    if podman {
        notes.push("Podman available.".into());
    }
    SandboxAvailability {
        docker,
        podman,
        selected,
        notes,
    }
}

fn command_ok(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Security invariants that every execution path must honor.
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

/// Host execution of untrusted target code is forbidden by default.
pub fn refuse_host_execution() -> Result<()> {
    Err(TcError::Blocked(
        "target code must not execute on the host by default; use Docker/Podman sandbox".into(),
    ))
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
}
