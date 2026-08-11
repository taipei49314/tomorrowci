use crate::{AdapterError, EcosystemAdapter, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Wire-schema version for [`AdapterContract`].
pub const ADAPTER_CONTRACT_SCHEMA_VERSION: u32 = 1;

/// Newer minor versions are rejected until this host knows their schema and
/// semantics. This intentionally favors a closed failure over optimistic
/// compatibility at a security boundary.
pub const HOST_ADAPTER_API_VERSION: AdapterApiVersion = AdapterApiVersion { major: 1, minor: 0 };

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterApiVersion {
    pub major: u16,
    pub minor: u16,
}

impl std::fmt::Display for AdapterApiVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

/// Capabilities exposed by the data-only adapter API.
///
/// Host shell execution, container-engine sockets, and host-secret access are
/// deliberately not representable as safe capabilities. Their reserved string
/// identifiers are recognized by negotiation and rejected as forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterCapability {
    DetectProject,
    ResolveBaseline,
    PlanCandidates,
    MaterializeSandbox,
    EmitCommandSpecs,
    NormalizeFailure,
}

impl AdapterCapability {
    pub const ALL: [Self; 6] = [
        Self::DetectProject,
        Self::ResolveBaseline,
        Self::PlanCandidates,
        Self::MaterializeSandbox,
        Self::EmitCommandSpecs,
        Self::NormalizeFailure,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DetectProject => "detect-project",
            Self::ResolveBaseline => "resolve-baseline",
            Self::PlanCandidates => "plan-candidates",
            Self::MaterializeSandbox => "materialize-sandbox",
            Self::EmitCommandSpecs => "emit-command-specs",
            Self::NormalizeFailure => "normalize-failure",
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "detect-project" => Ok(Self::DetectProject),
            "resolve-baseline" => Ok(Self::ResolveBaseline),
            "plan-candidates" => Ok(Self::PlanCandidates),
            "materialize-sandbox" => Ok(Self::MaterializeSandbox),
            "emit-command-specs" => Ok(Self::EmitCommandSpecs),
            "normalize-failure" => Ok(Self::NormalizeFailure),
            "host-shell" | "engine-socket" | "host-secrets" => Err(AdapterError::Contract(
                format!("forbidden capability '{raw}'"),
            )),
            _ => Err(AdapterError::Contract(format!(
                "unknown capability '{raw}'"
            ))),
        }
    }
}

impl std::fmt::Display for AdapterCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Serializable declaration made by an adapter.
///
/// Capability identifiers remain strings on the wire so a newer/hostile
/// adapter cannot make an old host deserialize an unknown value as a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterContract {
    pub schema_version: u32,
    pub api_version: AdapterApiVersion,
    pub capabilities: Vec<String>,
}

impl AdapterContract {
    pub fn v1() -> Self {
        Self {
            schema_version: ADAPTER_CONTRACT_SCHEMA_VERSION,
            api_version: HOST_ADAPTER_API_VERSION,
            capabilities: AdapterCapability::ALL
                .into_iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
        }
    }
}

/// The host side of capability negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAdapterContract {
    pub schema_version: u32,
    pub api_version: AdapterApiVersion,
    pub required_capabilities: BTreeSet<AdapterCapability>,
}

impl HostAdapterContract {
    pub fn strict_v1() -> Self {
        Self {
            schema_version: ADAPTER_CONTRACT_SCHEMA_VERSION,
            api_version: HOST_ADAPTER_API_VERSION,
            required_capabilities: AdapterCapability::ALL.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    pub api_version: AdapterApiVersion,
    pub capabilities: BTreeSet<AdapterCapability>,
}

/// Negotiate an adapter against a host contract, failing closed on every
/// unknown, forbidden, duplicate, missing, or newer capability declaration.
pub fn negotiate_adapter(
    adapter: &dyn EcosystemAdapter,
    host: &HostAdapterContract,
) -> Result<NegotiatedCapabilities> {
    let declared = adapter.contract();
    if declared.schema_version != host.schema_version {
        return Err(AdapterError::Contract(format!(
            "adapter '{}' declares schema {}, host requires {}",
            adapter.name(),
            declared.schema_version,
            host.schema_version
        )));
    }
    if declared.api_version.major != host.api_version.major {
        return Err(AdapterError::Contract(format!(
            "adapter '{}' API {}, host requires major {}",
            adapter.name(),
            declared.api_version,
            host.api_version.major
        )));
    }
    if declared.api_version.minor > host.api_version.minor {
        return Err(AdapterError::Contract(format!(
            "adapter '{}' API {} is newer than host API {}",
            adapter.name(),
            declared.api_version,
            host.api_version
        )));
    }

    let mut capabilities = BTreeSet::new();
    for raw in &declared.capabilities {
        let capability = AdapterCapability::parse(raw)?;
        if !capabilities.insert(capability) {
            return Err(AdapterError::Contract(format!(
                "adapter '{}' declares duplicate capability '{raw}'",
                adapter.name()
            )));
        }
    }

    let missing: Vec<_> = host
        .required_capabilities
        .difference(&capabilities)
        .map(|capability| capability.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(AdapterError::Contract(format!(
            "adapter '{}' is missing required capabilities: {}",
            adapter.name(),
            missing.join(", ")
        )));
    }

    Ok(NegotiatedCapabilities {
        api_version: declared.api_version,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionResult, EcosystemAdapter};
    use std::path::Path;
    use tomorrowci_core::{
        Baseline, Candidate, CommandSpec, Config, EnvironmentSpec, FailureSignature,
        RawExecutionResult, Scenario,
    };

    struct ContractOnlyAdapter(AdapterContract);

    impl EcosystemAdapter for ContractOnlyAdapter {
        fn contract(&self) -> AdapterContract {
            self.0.clone()
        }

        fn name(&self) -> &'static str {
            "contract-test"
        }

        fn detect(&self, _repo: &Path) -> Result<DetectionResult> {
            unreachable!()
        }

        fn baseline(&self, _repo: &Path, _config: &Config) -> Result<Baseline> {
            unreachable!()
        }

        fn candidates(&self, _baseline: &Baseline, _config: &Config) -> Result<Vec<Candidate>> {
            unreachable!()
        }

        fn materialize(&self, _scenario: &Scenario, _workspace: &Path) -> Result<EnvironmentSpec> {
            unreachable!()
        }

        fn commands(&self, _scenario: &Scenario, _config: &Config) -> Result<Vec<CommandSpec>> {
            unreachable!()
        }

        fn normalize_failure(&self, _result: &RawExecutionResult) -> FailureSignature {
            unreachable!()
        }
    }

    #[test]
    fn v1_contract_negotiates() {
        let adapter = ContractOnlyAdapter(AdapterContract::v1());
        let negotiated = negotiate_adapter(&adapter, &HostAdapterContract::strict_v1()).unwrap();
        assert_eq!(negotiated.api_version, HOST_ADAPTER_API_VERSION);
        assert_eq!(negotiated.capabilities.len(), AdapterCapability::ALL.len());
    }

    #[test]
    fn unknown_and_forbidden_capabilities_fail_closed() {
        for capability in [
            "future-magic",
            "host-shell",
            "engine-socket",
            "host-secrets",
        ] {
            let mut contract = AdapterContract::v1();
            contract.capabilities.push(capability.to_owned());
            let error = negotiate_adapter(
                &ContractOnlyAdapter(contract),
                &HostAdapterContract::strict_v1(),
            )
            .unwrap_err();
            assert!(error.to_string().contains(capability));
        }
    }

    #[test]
    fn registry_rejects_unknown_capability_before_detection() {
        let mut contract = AdapterContract::v1();
        contract.capabilities.push("future-magic".to_owned());
        let adapter = ContractOnlyAdapter(contract);
        let error = crate::detect_ecosystem(Path::new("."), &[&adapter], None).unwrap_err();
        assert!(error.to_string().contains("future-magic"));
    }

    #[test]
    fn incompatible_schema_and_versions_fail_closed() {
        let mut schema = AdapterContract::v1();
        schema.schema_version += 1;
        assert!(negotiate_adapter(
            &ContractOnlyAdapter(schema),
            &HostAdapterContract::strict_v1()
        )
        .is_err());

        let mut major = AdapterContract::v1();
        major.api_version.major += 1;
        assert!(negotiate_adapter(
            &ContractOnlyAdapter(major),
            &HostAdapterContract::strict_v1()
        )
        .is_err());

        let mut minor = AdapterContract::v1();
        minor.api_version.minor += 1;
        assert!(negotiate_adapter(
            &ContractOnlyAdapter(minor),
            &HostAdapterContract::strict_v1()
        )
        .is_err());
    }

    #[test]
    fn missing_and_duplicate_capabilities_fail_closed() {
        let mut missing = AdapterContract::v1();
        missing.capabilities.pop();
        assert!(negotiate_adapter(
            &ContractOnlyAdapter(missing),
            &HostAdapterContract::strict_v1()
        )
        .is_err());

        let mut duplicate = AdapterContract::v1();
        duplicate.capabilities.push("detect-project".to_owned());
        assert!(negotiate_adapter(
            &ContractOnlyAdapter(duplicate),
            &HostAdapterContract::strict_v1()
        )
        .is_err());
    }

    #[test]
    fn contract_schema_rejects_unknown_fields() {
        let raw = r#"{
            "schema_version": 1,
            "api_version": {"major": 1, "minor": 0},
            "capabilities": [],
            "host_shell": true
        }"#;
        assert!(serde_json::from_str::<AdapterContract>(raw).is_err());
    }
}
