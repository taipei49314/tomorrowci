//! Scenario runner: timeouts, retries, ordered results.
//! M0: scaffolding only — real container exec lands with Python vertical slice.

use tomorrowci_core::{ExecutionResult, Result, Scenario, TcError, Verdict};
use tomorrowci_sandbox::detect_engines;

/// Ensure sandbox is available before planning execution.
pub fn require_sandbox() -> Result<()> {
    let avail = detect_engines();
    if avail.selected.is_none() {
        return Err(TcError::Blocked(
            "no container engine (Docker/Podman); scenario execution BLOCKED".into(),
        ));
    }
    Ok(())
}

/// Placeholder: real execution in Milestone 1.
pub fn execute_scenario_placeholder(scenario: &Scenario) -> Result<ExecutionResult> {
    let _ = require_sandbox();
    Err(TcError::Blocked(format!(
        "scenario execution not implemented yet for '{}'; Milestone 1 will wire sandbox runs",
        scenario.id
    )))
}

pub fn empty_result(scenario_id: &str, verdict: Verdict) -> ExecutionResult {
    use indexmap::IndexMap;
    use tomorrowci_core::EnvironmentSpec;
    ExecutionResult {
        scenario_id: scenario_id.into(),
        attempt: 1,
        verdict,
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        failure: None,
        environment: EnvironmentSpec {
            image: "unset".into(),
            image_digest: None,
            workdir: "/work".into(),
            env: IndexMap::new(),
            network_mode: "none".into(),
            memory_mb: 0,
            cpus: 0.0,
            pids_limit: 0,
            user: None,
            read_only_root: true,
        },
        commands: vec![],
    }
}
