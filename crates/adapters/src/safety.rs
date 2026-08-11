//! Fail-closed validation for adapter-produced data.

use crate::{AdapterError, Result};
use tomorrowci_core::{CommandPhase, CommandSpec, EnvironmentSpec, NetworkMode};

const SHELL_PROGRAMS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

const ENGINE_CLIENTS: &[&str] = &[
    "docker",
    "docker.exe",
    "podman",
    "podman.exe",
    "nerdctl",
    "ctr",
];

/// Validate the sandbox environment emitted by an adapter.
pub fn validate_environment(environment: &EnvironmentSpec) -> Result<()> {
    if environment.image_ref.trim().is_empty() {
        return Err(AdapterError::Unsafe("empty sandbox image reference".into()));
    }
    if environment.network_mode == NetworkMode::Full {
        return Err(AdapterError::Unsafe(
            "full-time network access is outside the adapter capability contract".into(),
        ));
    }
    if !environment.mounts.is_empty() {
        return Err(AdapterError::Unsafe(
            "explicit host mounts are outside the adapter capability contract".into(),
        ));
    }
    validate_env("sandbox", environment.env.iter())?;
    reject_engine_reference("sandbox image", &environment.image_ref)?;
    reject_engine_reference("sandbox workdir", &environment.workdir)?;
    Ok(())
}

/// Validate command specifications before a sandbox host accepts them.
pub fn validate_commands(commands: &[CommandSpec]) -> Result<()> {
    if commands.is_empty() {
        return Err(AdapterError::Unsafe(
            "adapter emitted no commands for a scenario".into(),
        ));
    }

    for command in commands {
        let program = basename(&command.program).to_ascii_lowercase();
        if SHELL_PROGRAMS.contains(&program.as_str()) {
            return Err(AdapterError::Unsafe(format!(
                "shell trampoline '{}' is forbidden; emit a program and argument array",
                command.program
            )));
        }
        if ENGINE_CLIENTS.contains(&program.as_str()) {
            return Err(AdapterError::Unsafe(format!(
                "container-engine client '{}' is forbidden in adapter commands",
                command.program
            )));
        }
        if command.program.trim().is_empty() {
            return Err(AdapterError::Unsafe("empty command program".into()));
        }
        if command.network_required && command.phase != CommandPhase::Fetch {
            return Err(AdapterError::Unsafe(format!(
                "network is only permitted during fetch; '{}' requested it during {:?}",
                command.program, command.phase
            )));
        }

        reject_engine_reference("command program", &command.program)?;
        reject_engine_reference("command workdir", &command.workdir)?;
        for argument in &command.args {
            reject_engine_reference("command argument", argument)?;
        }
        validate_env("command", command.env.iter())?;
    }
    Ok(())
}

fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

fn validate_env<'a>(
    scope: &str,
    environment: impl Iterator<Item = (&'a String, &'a String)>,
) -> Result<()> {
    for (key, value) in environment {
        let uppercase = key.to_ascii_uppercase();
        let secret_like = [
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PASSWD",
            "API_KEY",
            "APIKEY",
            "CREDENTIAL",
            "PRIVATE_KEY",
            "ACCESS_KEY",
        ]
        .iter()
        .any(|marker| uppercase.contains(marker));
        if secret_like {
            return Err(AdapterError::Unsafe(format!(
                "{scope} environment key '{key}' is secret-like"
            )));
        }
        if matches!(uppercase.as_str(), "DOCKER_HOST" | "CONTAINER_HOST") {
            return Err(AdapterError::Unsafe(format!(
                "{scope} environment key '{key}' exposes a container engine"
            )));
        }
        reject_engine_reference(&format!("{scope} environment value"), value)?;
    }
    Ok(())
}

fn reject_engine_reference(context: &str, value: &str) -> Result<()> {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    let forbidden = [
        "docker.sock",
        "podman.sock",
        "containerd.sock",
        "/run/podman/",
        "docker_engine",
    ];
    if forbidden.iter().any(|needle| normalized.contains(needle)) {
        return Err(AdapterError::Unsafe(format!(
            "{context} references a container-engine socket"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tomorrowci_core::{IndexMap, MountSpec};

    fn safe_environment() -> EnvironmentSpec {
        EnvironmentSpec {
            image_ref: "rust:1.97-bookworm".into(),
            image_digest: None,
            workdir: "/workspace".into(),
            user: None,
            env: IndexMap::new(),
            mounts: vec![],
            network_mode: NetworkMode::FetchOnly,
            read_only_root: false,
            memory_mb: 1024,
            cpus: 1.0,
            pids_limit: 128,
            timeout_seconds: 60,
        }
    }

    fn safe_command() -> CommandSpec {
        CommandSpec {
            phase: CommandPhase::Test,
            program: "cargo".into(),
            args: vec!["test".into()],
            workdir: "/workspace".into(),
            network_required: false,
            env: IndexMap::new(),
        }
    }

    #[test]
    fn accepts_data_only_sandbox_plan() {
        validate_environment(&safe_environment()).unwrap();
        validate_commands(&[safe_command()]).unwrap();
    }

    #[test]
    fn rejects_shell_engine_socket_mount_and_secrets() {
        let mut shell = safe_command();
        shell.program = "bash".into();
        assert!(validate_commands(&[shell]).is_err());

        let mut socket = safe_command();
        socket.args.push("/var/run/docker.sock".into());
        assert!(validate_commands(&[socket]).is_err());

        let mut secret = safe_command();
        secret.env.insert("API_TOKEN".into(), "value".into());
        assert!(validate_commands(&[secret]).is_err());

        let mut mounted = safe_environment();
        mounted.mounts.push(MountSpec {
            host_path: "C:/source".into(),
            container_path: "/source".into(),
            read_only: true,
        });
        assert!(validate_environment(&mounted).is_err());
    }

    #[test]
    fn rejects_non_fetch_network_and_full_network() {
        let mut command = safe_command();
        command.network_required = true;
        assert!(validate_commands(&[command]).is_err());

        let mut environment = safe_environment();
        environment.network_mode = NetworkMode::Full;
        assert!(validate_environment(&environment).is_err());
    }
}
