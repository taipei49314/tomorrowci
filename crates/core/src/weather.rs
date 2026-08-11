//! Ecosystem weather-map aggregation over source-bound, verified run models.
//!
//! The weather map is deliberately descriptive. Its denominator is the
//! pre-declared selection-unit set, not the number of convenient outcomes.
//! Missing evidence, BLOCKED, and UNSUPPORTED units therefore remain visible.

use crate::{Ecosystem, RunId, RunManifest, RunStatus, ScenarioVerdict, Verdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const WEATHER_MAP_SCHEMA_VERSION: u32 = 1;
pub const MIN_WEATHER_INVENTORY_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherTimeWindow {
    /// Inclusive lower bound for a run's completion time.
    pub starts_at: DateTime<Utc>,
    /// Exclusive upper bound for a run's completion time.
    pub ends_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WeatherSourceKind {
    ProjectFixture,
    ProjectRepository,
    ExternalRepository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherSelectionUnit {
    /// Stable identifier declared before observing the run outcome.
    pub id: String,
    pub ecosystem: Ecosystem,
    pub source_kind: WeatherSourceKind,
    /// Must exactly equal `run.json.repository.source`.
    pub source: String,
    /// Required for external repositories and compared with the verified run.
    pub commit_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherSelectionPolicy {
    pub id: String,
    pub description: String,
    pub population: String,
    pub inclusion_criteria: Vec<String>,
    pub exclusion_criteria: Vec<String>,
    /// Independent declared count. It must equal `selected_units.len()` so a
    /// producer cannot silently lower the denominator while retaining runs.
    pub declared_denominator: u64,
    pub selected_units: Vec<WeatherSelectionUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WeatherVerificationState {
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WeatherBundleKind {
    Run,
    Scenario,
    ReplayAttempt,
    Generic,
}

/// Preverified identity data consumed by the deterministic weather reducer.
///
/// `inventory_sha256` binds the sealed inventory bytes,
/// `source_manifest_sha256` binds the v2 source snapshot manifest, and
/// `typed_model_sha256` binds the exact typed `run.json` + `verdicts.json`
/// values supplied to the reducer. This struct is serializable output data,
/// not an authenticity capability. Filesystem callers must enter through
/// `tomorrowci_evidence::aggregate_verified_weather_map`, which constructs it
/// from an opaque verified-bundle generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherVerificationIdentity {
    pub state: WeatherVerificationState,
    pub bundle_kind: WeatherBundleKind,
    pub inventory_version: u32,
    pub inventory_sha256: String,
    pub source_manifest_sha256: String,
    pub typed_model_sha256: String,
    pub run_id: RunId,
    pub verified_file_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherCohortIdentity {
    pub selection_policy_id: String,
    pub time_window: WeatherTimeWindow,
}

/// Preverified aggregation model. The core crate validates its internal
/// identities and cohort semantics but does not verify filesystem evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherRunInput {
    pub selection_unit_id: String,
    pub cohort: WeatherCohortIdentity,
    pub verification: WeatherVerificationIdentity,
    pub run: RunManifest,
    pub verdicts: Vec<ScenarioVerdict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherMapRequest {
    pub schema_version: u32,
    pub selection_policy: WeatherSelectionPolicy,
    pub time_window: WeatherTimeWindow,
    pub runs: Vec<WeatherRunInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WeatherOutcome {
    Pass,
    Fail,
    Flaky,
    Blocked,
    Unsupported,
    Inconclusive,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherOutcomeCounts {
    pub pass: u64,
    pub fail: u64,
    pub flaky: u64,
    pub blocked: u64,
    pub unsupported: u64,
    pub inconclusive: u64,
    /// Selected units for which no verified run was supplied.
    pub unobserved: u64,
}

impl WeatherOutcomeCounts {
    pub fn total(&self) -> u64 {
        self.pass
            + self.fail
            + self.flaky
            + self.blocked
            + self.unsupported
            + self.inconclusive
            + self.unobserved
    }

    fn add(&mut self, outcome: WeatherOutcome) {
        match outcome {
            WeatherOutcome::Pass => self.pass += 1,
            WeatherOutcome::Fail => self.fail += 1,
            WeatherOutcome::Flaky => self.flaky += 1,
            WeatherOutcome::Blocked => self.blocked += 1,
            WeatherOutcome::Unsupported => self.unsupported += 1,
            WeatherOutcome::Inconclusive => self.inconclusive += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherCoverage {
    pub denominator: u64,
    /// Every supplied observation has passed the evidence verification gate.
    /// BLOCKED and UNSUPPORTED observations are included here.
    pub verified_units: u64,
    pub unobserved_units: u64,
    /// PASS and FAIL only; FLAKY is intentionally not called resolved.
    pub resolved_units: u64,
    pub verified_basis_points: u16,
    pub resolved_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemWeather {
    pub ecosystem: Ecosystem,
    pub denominator: u64,
    pub outcomes: WeatherOutcomeCounts,
    pub coverage: WeatherCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WeatherInferenceScope {
    SelectedUnitsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherInferenceBoundary {
    pub scope: WeatherInferenceScope,
    /// Always false. A weather map is descriptive evidence, never an adoption
    /// or ecosystem-prevalence estimator.
    pub adoption_or_prevalence_permitted: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherUncertainty {
    pub unobserved_units: u64,
    pub blocked_units: u64,
    pub unsupported_units: u64,
    pub inconclusive_units: u64,
    pub flaky_units: u64,
    pub includes_project_fixtures: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherRunSummary {
    pub selection_unit_id: String,
    pub run_id: RunId,
    pub ecosystem: Ecosystem,
    pub source_kind: WeatherSourceKind,
    pub source: String,
    pub commit_sha: Option<String>,
    pub completed_at: DateTime<Utc>,
    pub outcome: WeatherOutcome,
    pub inventory_version: u32,
    pub inventory_sha256: String,
    pub source_manifest_sha256: String,
    pub typed_model_sha256: String,
}

/// Canonical typed model consumed by both JSON and human renderers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeatherMap {
    pub schema_version: u32,
    pub selection_policy: WeatherSelectionPolicy,
    pub time_window: WeatherTimeWindow,
    pub denominator: u64,
    pub outcomes: WeatherOutcomeCounts,
    pub coverage: WeatherCoverage,
    pub uncertainty: WeatherUncertainty,
    pub inference_boundary: WeatherInferenceBoundary,
    /// Always Python, Node, Rust in this order, including zero-denominator rows.
    pub ecosystems: Vec<EcosystemWeather>,
    /// Deterministically ordered by ecosystem, selection unit, then run ID.
    pub runs: Vec<WeatherRunSummary>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WeatherMapError {
    #[error("unsupported weather-map schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("invalid time window: starts_at must precede ends_at")]
    InvalidTimeWindow,
    #[error("selection policy field {0} must not be empty")]
    EmptySelectionField(&'static str),
    #[error("selection policy denominator {declared} does not equal its {actual} selected units")]
    DenominatorMismatch { declared: u64, actual: u64 },
    #[error("duplicate selection unit: {0}")]
    DuplicateSelectionUnit(String),
    #[error("invalid selection unit {unit}: {detail}")]
    InvalidSelectionUnit { unit: String, detail: String },
    #[error("run for unknown selection unit: {0}")]
    UnknownSelectionUnit(String),
    #[error("duplicate run id: {0}")]
    DuplicateRunId(String),
    #[error("duplicate verified inventory digest: {0}")]
    DuplicateInventory(String),
    #[error("more than one run supplied for selection unit: {0}")]
    DuplicateObservation(String),
    #[error("run {0} is not verified")]
    UnverifiedRun(String),
    #[error("run {run_id} has invalid verification identity: {detail}")]
    InvalidVerificationIdentity { run_id: String, detail: String },
    #[error("run {run_id} belongs to selection policy {actual}, expected {expected}")]
    MixedSelectionPolicy {
        run_id: String,
        expected: String,
        actual: String,
    },
    #[error("run {0} belongs to a different time window")]
    MixedTimeWindow(String),
    #[error("run {run_id} identity mismatch: {detail}")]
    IdentityMismatch { run_id: String, detail: String },
    #[error("run {run_id} completed outside the selected time window")]
    OutsideTimeWindow { run_id: String },
    #[error("run {run_id} is not a final verified model: {detail}")]
    InvalidRunModel { run_id: String, detail: String },
    #[error("could not serialize typed run model: {0}")]
    ModelSerialization(String),
}

/// Hash the exact typed values used by weather aggregation. Evidence adapters
/// should compute this only from `VerifiedBundle::read_json` results.
pub fn weather_typed_model_sha256(
    run: &RunManifest,
    verdicts: &[ScenarioVerdict],
) -> Result<String, WeatherMapError> {
    #[derive(Serialize)]
    struct TypedModel<'a> {
        run: &'a RunManifest,
        verdicts: &'a [ScenarioVerdict],
    }

    let bytes = serde_json::to_vec(&TypedModel { run, verdicts })
        .map_err(|error| WeatherMapError::ModelSerialization(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Deterministically reduce models that have already crossed an evidence
/// verification boundary. This is not a filesystem verifier; product callers
/// should use `tomorrowci_evidence::aggregate_verified_weather_map`.
pub fn aggregate_preverified_weather_map(
    request: WeatherMapRequest,
) -> Result<WeatherMap, WeatherMapError> {
    validate_request_header(&request)?;

    let mut units = BTreeMap::new();
    let mut ecosystem_denominators = [0_u64; 3];
    for unit in &request.selection_policy.selected_units {
        validate_selection_unit(unit)?;
        if units.insert(unit.id.clone(), unit).is_some() {
            return Err(WeatherMapError::DuplicateSelectionUnit(unit.id.clone()));
        }
        ecosystem_denominators[ecosystem_rank(unit.ecosystem)] += 1;
    }

    let mut run_ids = BTreeSet::new();
    let mut inventory_digests = BTreeSet::new();
    let mut observed_units = BTreeSet::new();
    let mut summaries = Vec::with_capacity(request.runs.len());

    for input in &request.runs {
        let run_id = input.run.run_id.0.clone();
        if input.cohort.selection_policy_id != request.selection_policy.id {
            return Err(WeatherMapError::MixedSelectionPolicy {
                run_id,
                expected: request.selection_policy.id.clone(),
                actual: input.cohort.selection_policy_id.clone(),
            });
        }
        if input.cohort.time_window != request.time_window {
            return Err(WeatherMapError::MixedTimeWindow(run_id));
        }
        let unit = units.get(&input.selection_unit_id).ok_or_else(|| {
            WeatherMapError::UnknownSelectionUnit(input.selection_unit_id.clone())
        })?;
        if !observed_units.insert(input.selection_unit_id.clone()) {
            return Err(WeatherMapError::DuplicateObservation(
                input.selection_unit_id.clone(),
            ));
        }
        validate_verification(input)?;
        if !run_ids.insert(input.run.run_id.0.clone()) {
            return Err(WeatherMapError::DuplicateRunId(input.run.run_id.0.clone()));
        }
        if !inventory_digests.insert(input.verification.inventory_sha256.clone()) {
            return Err(WeatherMapError::DuplicateInventory(
                input.verification.inventory_sha256.clone(),
            ));
        }

        let (ecosystem, completed_at, outcome) =
            validate_run_model(input, unit, &request.time_window)?;
        summaries.push(WeatherRunSummary {
            selection_unit_id: input.selection_unit_id.clone(),
            run_id: input.run.run_id.clone(),
            ecosystem,
            source_kind: unit.source_kind,
            source: input.run.repository.source.clone(),
            commit_sha: input.run.repository.commit_sha.clone(),
            completed_at,
            outcome,
            inventory_version: input.verification.inventory_version,
            inventory_sha256: input.verification.inventory_sha256.clone(),
            source_manifest_sha256: input.verification.source_manifest_sha256.clone(),
            typed_model_sha256: input.verification.typed_model_sha256.clone(),
        });
    }

    summaries.sort_by(|left, right| {
        ecosystem_rank(left.ecosystem)
            .cmp(&ecosystem_rank(right.ecosystem))
            .then_with(|| left.selection_unit_id.cmp(&right.selection_unit_id))
            .then_with(|| left.run_id.0.cmp(&right.run_id.0))
    });

    let denominator = request.selection_policy.declared_denominator;
    let mut outcomes = WeatherOutcomeCounts {
        unobserved: denominator - summaries.len() as u64,
        ..WeatherOutcomeCounts::default()
    };
    let mut ecosystem_outcomes: [WeatherOutcomeCounts; 3] =
        std::array::from_fn(|index| WeatherOutcomeCounts {
            unobserved: ecosystem_denominators[index],
            ..WeatherOutcomeCounts::default()
        });
    for summary in &summaries {
        outcomes.add(summary.outcome);
        let ecosystem_counts = &mut ecosystem_outcomes[ecosystem_rank(summary.ecosystem)];
        ecosystem_counts.unobserved -= 1;
        ecosystem_counts.add(summary.outcome);
    }

    debug_assert_eq!(outcomes.total(), denominator);
    let coverage = coverage_for(denominator, &outcomes);
    let ecosystems = [Ecosystem::Python, Ecosystem::Node, Ecosystem::Rust]
        .into_iter()
        .enumerate()
        .map(|(index, ecosystem)| EcosystemWeather {
            ecosystem,
            denominator: ecosystem_denominators[index],
            coverage: coverage_for(ecosystem_denominators[index], &ecosystem_outcomes[index]),
            outcomes: ecosystem_outcomes[index].clone(),
        })
        .collect();

    let includes_project_fixtures = request
        .selection_policy
        .selected_units
        .iter()
        .any(|unit| unit.source_kind == WeatherSourceKind::ProjectFixture);
    let mut limitations = vec![
        "This map describes only the declared selected units; it does not estimate ecosystem adoption or prevalence."
            .to_string(),
    ];
    if outcomes.unobserved > 0 {
        limitations.push(format!(
            "{} selected unit(s) have no verified run in the window.",
            outcomes.unobserved
        ));
    }
    if outcomes.blocked > 0 {
        limitations.push(format!(
            "{} BLOCKED unit(s) remain in the denominator and are not successful observations.",
            outcomes.blocked
        ));
    }
    if outcomes.unsupported > 0 {
        limitations.push(format!(
            "{} UNSUPPORTED unit(s) remain in the denominator and are not successful observations.",
            outcomes.unsupported
        ));
    }
    if includes_project_fixtures {
        limitations.push(
            "Project fixtures are test cases, not evidence of adoption or ecosystem prevalence."
                .to_string(),
        );
    }

    let mut selection_policy = request.selection_policy;
    selection_policy.selected_units.sort_by(|left, right| {
        ecosystem_rank(left.ecosystem)
            .cmp(&ecosystem_rank(right.ecosystem))
            .then_with(|| left.id.cmp(&right.id))
    });
    selection_policy.inclusion_criteria.sort();
    selection_policy.exclusion_criteria.sort();

    Ok(WeatherMap {
        schema_version: WEATHER_MAP_SCHEMA_VERSION,
        selection_policy,
        time_window: request.time_window,
        denominator,
        outcomes: outcomes.clone(),
        coverage,
        uncertainty: WeatherUncertainty {
            unobserved_units: outcomes.unobserved,
            blocked_units: outcomes.blocked,
            unsupported_units: outcomes.unsupported,
            inconclusive_units: outcomes.inconclusive,
            flaky_units: outcomes.flaky,
            includes_project_fixtures,
            limitations,
        },
        inference_boundary: WeatherInferenceBoundary {
            scope: WeatherInferenceScope::SelectedUnitsOnly,
            adoption_or_prevalence_permitted: false,
            reason: "Verified outcomes support a descriptive selected-unit summary only; selection and fixtures do not establish adoption prevalence."
                .to_string(),
        },
        ecosystems,
        runs: summaries,
    })
}

fn validate_request_header(request: &WeatherMapRequest) -> Result<(), WeatherMapError> {
    if request.schema_version != WEATHER_MAP_SCHEMA_VERSION {
        return Err(WeatherMapError::UnsupportedSchemaVersion(
            request.schema_version,
        ));
    }
    if request.time_window.starts_at >= request.time_window.ends_at {
        return Err(WeatherMapError::InvalidTimeWindow);
    }
    for (name, value) in [
        ("id", request.selection_policy.id.as_str()),
        ("description", request.selection_policy.description.as_str()),
        ("population", request.selection_policy.population.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(WeatherMapError::EmptySelectionField(name));
        }
    }
    let actual = request.selection_policy.selected_units.len() as u64;
    if request.selection_policy.declared_denominator != actual {
        return Err(WeatherMapError::DenominatorMismatch {
            declared: request.selection_policy.declared_denominator,
            actual,
        });
    }
    Ok(())
}

fn validate_selection_unit(unit: &WeatherSelectionUnit) -> Result<(), WeatherMapError> {
    if unit.id.trim().is_empty() {
        return Err(WeatherMapError::InvalidSelectionUnit {
            unit: unit.id.clone(),
            detail: "id must not be empty".into(),
        });
    }
    if unit.source.trim().is_empty() {
        return Err(WeatherMapError::InvalidSelectionUnit {
            unit: unit.id.clone(),
            detail: "source must not be empty".into(),
        });
    }
    let external_commit_missing = match unit.commit_sha.as_deref() {
        Some(commit) => commit.is_empty(),
        None => true,
    };
    if unit.source_kind == WeatherSourceKind::ExternalRepository && external_commit_missing {
        return Err(WeatherMapError::InvalidSelectionUnit {
            unit: unit.id.clone(),
            detail: "external repositories require an exact commit SHA".into(),
        });
    }
    if let Some(commit) = &unit.commit_sha {
        if !is_git_sha(commit) {
            return Err(WeatherMapError::InvalidSelectionUnit {
                unit: unit.id.clone(),
                detail: "commit SHA must be 40 or 64 lowercase hexadecimal characters".into(),
            });
        }
    }
    Ok(())
}

fn validate_verification(input: &WeatherRunInput) -> Result<(), WeatherMapError> {
    let run_id = input.run.run_id.0.clone();
    if input.verification.state != WeatherVerificationState::Verified {
        return Err(WeatherMapError::UnverifiedRun(run_id));
    }
    if input.verification.bundle_kind != WeatherBundleKind::Run {
        return Err(WeatherMapError::InvalidVerificationIdentity {
            run_id,
            detail: "only verified run bundles can be aggregated".into(),
        });
    }
    if input.verification.inventory_version < MIN_WEATHER_INVENTORY_VERSION {
        return Err(WeatherMapError::InvalidVerificationIdentity {
            run_id,
            detail: format!(
                "inventory v{} lacks the required v{} source identity",
                input.verification.inventory_version, MIN_WEATHER_INVENTORY_VERSION
            ),
        });
    }
    if input.verification.verified_file_count == 0 {
        return Err(WeatherMapError::InvalidVerificationIdentity {
            run_id,
            detail: "verified file count must be nonzero".into(),
        });
    }
    for (name, digest) in [
        (
            "inventory_sha256",
            input.verification.inventory_sha256.as_str(),
        ),
        (
            "source_manifest_sha256",
            input.verification.source_manifest_sha256.as_str(),
        ),
        (
            "typed_model_sha256",
            input.verification.typed_model_sha256.as_str(),
        ),
    ] {
        if !is_sha256(digest) {
            return Err(WeatherMapError::InvalidVerificationIdentity {
                run_id,
                detail: format!("{name} must be 64 lowercase hexadecimal characters"),
            });
        }
    }
    if input.verification.run_id != input.run.run_id {
        return Err(WeatherMapError::IdentityMismatch {
            run_id,
            detail: "verification run_id does not match run.json".into(),
        });
    }
    let actual = weather_typed_model_sha256(&input.run, &input.verdicts)?;
    if actual != input.verification.typed_model_sha256 {
        return Err(WeatherMapError::IdentityMismatch {
            run_id,
            detail: "typed run/verdict model digest does not match verified identity".into(),
        });
    }
    Ok(())
}

fn validate_run_model(
    input: &WeatherRunInput,
    unit: &WeatherSelectionUnit,
    window: &WeatherTimeWindow,
) -> Result<(Ecosystem, DateTime<Utc>, WeatherOutcome), WeatherMapError> {
    let run = &input.run;
    let run_id = run.run_id.0.clone();
    let detection = run
        .detection
        .as_ref()
        .ok_or_else(|| WeatherMapError::InvalidRunModel {
            run_id: run_id.clone(),
            detail: "verified weather runs require a detection model".into(),
        })?;
    if detection.ecosystem != unit.ecosystem {
        return Err(WeatherMapError::IdentityMismatch {
            run_id,
            detail: "detected ecosystem does not match selected unit".into(),
        });
    }
    if run.repository.source != unit.source {
        return Err(WeatherMapError::IdentityMismatch {
            run_id,
            detail: "repository source does not match selected unit".into(),
        });
    }
    if let Some(expected) = &unit.commit_sha {
        if run.repository.commit_sha.as_ref() != Some(expected) {
            return Err(WeatherMapError::IdentityMismatch {
                run_id,
                detail: "repository commit does not match selected unit".into(),
            });
        }
    }
    if let Some(baseline) = &run.baseline {
        if baseline.ecosystem != detection.ecosystem {
            return Err(WeatherMapError::IdentityMismatch {
                run_id,
                detail: "baseline ecosystem does not match detection".into(),
            });
        }
    }

    let completed_at = run
        .finished_at
        .ok_or_else(|| WeatherMapError::InvalidRunModel {
            run_id: run_id.clone(),
            detail: "final run is missing finished_at".into(),
        })?;
    if completed_at < run.started_at {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "finished_at precedes started_at".into(),
        });
    }
    if completed_at < window.starts_at || completed_at >= window.ends_at {
        return Err(WeatherMapError::OutsideTimeWindow { run_id });
    }
    if !matches!(run.status, RunStatus::Completed | RunStatus::Blocked) {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "run status must be COMPLETED or BLOCKED".into(),
        });
    }
    if input.verdicts.is_empty() {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "verdicts must not be empty".into(),
        });
    }
    let mut scenario_ids = BTreeSet::new();
    for verdict in &input.verdicts {
        if !scenario_ids.insert(verdict.scenario_id.0.as_str()) {
            return Err(WeatherMapError::InvalidRunModel {
                run_id,
                detail: format!("duplicate verdict scenario {}", verdict.scenario_id),
            });
        }
    }

    let early_unsupported = run.scenario_count == 0
        && input.verdicts.len() == 1
        && input.verdicts[0].scenario_id.0 == "detect"
        && input.verdicts[0].verdict == Verdict::Unsupported;
    let early_blocked = run.scenario_count == 0
        && input.verdicts.len() == 1
        && input.verdicts[0].scenario_id.0 == "sandbox"
        && input.verdicts[0].verdict == Verdict::Blocked;
    if !early_unsupported && !early_blocked && run.scenario_count != input.verdicts.len() {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "scenario_count does not match verdict count".into(),
        });
    }

    let contains_blocked = input
        .verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Blocked);
    let contains_unsupported = input
        .verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Unsupported);
    if contains_unsupported && (!early_unsupported || detection.supported) {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "UNSUPPORTED must be the canonical unsupported detection outcome".into(),
        });
    }
    if !contains_unsupported && !detection.supported {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "unsupported detection is missing an UNSUPPORTED verdict".into(),
        });
    }
    if contains_blocked != (run.status == RunStatus::Blocked) {
        return Err(WeatherMapError::InvalidRunModel {
            run_id,
            detail: "BLOCKED verdict and run status disagree".into(),
        });
    }

    let outcome = classify_run_outcome(&input.verdicts);
    Ok((detection.ecosystem, completed_at, outcome))
}

fn classify_run_outcome(verdicts: &[ScenarioVerdict]) -> WeatherOutcome {
    if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Unsupported)
    {
        WeatherOutcome::Unsupported
    } else if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Blocked)
    {
        WeatherOutcome::Blocked
    } else if verdicts.iter().any(|verdict| verdict.verdict.is_fail()) {
        WeatherOutcome::Fail
    } else if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Flaky)
    {
        WeatherOutcome::Flaky
    } else if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Inconclusive)
    {
        WeatherOutcome::Inconclusive
    } else {
        WeatherOutcome::Pass
    }
}

fn coverage_for(denominator: u64, outcomes: &WeatherOutcomeCounts) -> WeatherCoverage {
    let verified_units = denominator - outcomes.unobserved;
    let resolved_units = outcomes.pass + outcomes.fail;
    WeatherCoverage {
        denominator,
        verified_units,
        unobserved_units: outcomes.unobserved,
        resolved_units,
        verified_basis_points: ratio_basis_points(verified_units, denominator),
        resolved_basis_points: ratio_basis_points(resolved_units, denominator),
    }
}

fn ratio_basis_points(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    (((numerator as u128) * 10_000) / denominator as u128) as u16
}

fn ecosystem_rank(ecosystem: Ecosystem) -> usize {
    match ecosystem {
        Ecosystem::Python => 0,
        Ecosystem::Node => 1,
        Ecosystem::Rust => 2,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceGrade, HostInfo, ProjectDetection, RepositorySnapshot, ScenarioId};
    use chrono::TimeZone;

    fn window() -> WeatherTimeWindow {
        WeatherTimeWindow {
            starts_at: Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap(),
            ends_at: Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap(),
        }
    }

    fn unit(id: &str, ecosystem: Ecosystem, kind: WeatherSourceKind) -> WeatherSelectionUnit {
        WeatherSelectionUnit {
            id: id.into(),
            ecosystem,
            source_kind: kind,
            source: format!("https://example.invalid/{id}"),
            commit_sha: (kind == WeatherSourceKind::ExternalRepository).then(|| "a".repeat(40)),
        }
    }

    fn policy(units: Vec<WeatherSelectionUnit>) -> WeatherSelectionPolicy {
        WeatherSelectionPolicy {
            id: "pre-registered-2026-08".into(),
            description: "Pre-registered cross-ecosystem sample".into(),
            population: "Selected public repositories and explicit project fixtures".into(),
            inclusion_criteria: vec!["selected before outcomes".into()],
            exclusion_criteria: vec!["no outcome replacement".into()],
            declared_denominator: units.len() as u64,
            selected_units: units,
        }
    }

    fn input(unit: &WeatherSelectionUnit, run_id: &str, verdict: Verdict) -> WeatherRunInput {
        let completed = Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap();
        let (status, scenario_id, supported, scenario_count) = match verdict {
            Verdict::Blocked => (RunStatus::Blocked, "sandbox", true, 0),
            Verdict::Unsupported => (RunStatus::Completed, "detect", false, 0),
            _ => (RunStatus::Completed, "baseline", true, 1),
        };
        let run = RunManifest {
            run_id: RunId(run_id.into()),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            started_at: completed - chrono::Duration::minutes(2),
            finished_at: Some(completed),
            repository: RepositorySnapshot {
                source: unit.source.clone(),
                path: ".".into(),
                commit_sha: unit.commit_sha.clone(),
                branch: None,
                is_remote: unit.source_kind == WeatherSourceKind::ExternalRepository,
                workspace_copy: ".".into(),
                captured_at: completed - chrono::Duration::minutes(3),
            },
            detection: Some(ProjectDetection {
                ecosystem: unit.ecosystem,
                package_manager: "test".into(),
                manifests: vec!["manifest".into()],
                confidence: 1.0,
                notes: vec![],
                supported,
                unsupported_reason: (!supported).then(|| "unsupported manager".into()),
            }),
            baseline: None,
            config_hash: "config".into(),
            sandbox_engine: None,
            status,
            frontier: None,
            scenario_count,
            host: HostInfo::default(),
        };
        let verdicts = vec![ScenarioVerdict {
            scenario_id: ScenarioId::new(scenario_id),
            label: scenario_id.into(),
            verdict,
            evidence_grade: EvidenceGrade::Inconclusive,
            attempts: 0,
            failure_signature: None,
            evidence: None,
            notes: vec!["test evidence".into()],
        }];
        let typed_model_sha256 = weather_typed_model_sha256(&run, &verdicts).unwrap();
        WeatherRunInput {
            selection_unit_id: unit.id.clone(),
            cohort: WeatherCohortIdentity {
                selection_policy_id: "pre-registered-2026-08".into(),
                time_window: window(),
            },
            verification: WeatherVerificationIdentity {
                state: WeatherVerificationState::Verified,
                bundle_kind: WeatherBundleKind::Run,
                inventory_version: MIN_WEATHER_INVENTORY_VERSION,
                inventory_sha256: format!("{:064x}", run_id.len() + 1),
                source_manifest_sha256: format!("{:064x}", run_id.len() + 101),
                typed_model_sha256,
                run_id: run.run_id.clone(),
                verified_file_count: 20,
            },
            run,
            verdicts,
        }
    }

    fn request(units: Vec<WeatherSelectionUnit>, runs: Vec<WeatherRunInput>) -> WeatherMapRequest {
        WeatherMapRequest {
            schema_version: WEATHER_MAP_SCHEMA_VERSION,
            selection_policy: policy(units),
            time_window: window(),
            runs,
        }
    }

    #[test]
    fn blocked_unsupported_and_unobserved_stay_in_denominator() {
        let python = unit(
            "fixture-python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let node = unit(
            "external-node",
            Ecosystem::Node,
            WeatherSourceKind::ExternalRepository,
        );
        let rust = unit(
            "external-rust",
            Ecosystem::Rust,
            WeatherSourceKind::ExternalRepository,
        );
        let map = aggregate_preverified_weather_map(request(
            vec![python.clone(), node.clone(), rust],
            vec![
                input(&node, "node-run", Verdict::Unsupported),
                input(&python, "python-run", Verdict::Blocked),
            ],
        ))
        .unwrap();

        assert_eq!(map.denominator, 3);
        assert_eq!(map.outcomes.blocked, 1);
        assert_eq!(map.outcomes.unsupported, 1);
        assert_eq!(map.outcomes.unobserved, 1);
        assert_eq!(map.outcomes.total(), map.denominator);
        assert_eq!(map.coverage.verified_units, 2);
        assert!(map.uncertainty.includes_project_fixtures);
        assert!(!map.inference_boundary.adoption_or_prevalence_permitted);
        assert_eq!(
            map.ecosystems
                .iter()
                .map(|entry| entry.ecosystem)
                .collect::<Vec<_>>(),
            vec![Ecosystem::Python, Ecosystem::Node, Ecosystem::Rust]
        );
        assert_eq!(map.runs[0].selection_unit_id, "fixture-python");
        assert_eq!(map.runs[1].selection_unit_id, "external-node");
    }

    #[test]
    fn rejects_unverified_run() {
        let selected = unit(
            "python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let mut run = input(&selected, "run-one", Verdict::BaselinePass);
        run.verification.state = WeatherVerificationState::Unverified;
        assert!(matches!(
            aggregate_preverified_weather_map(request(vec![selected], vec![run])),
            Err(WeatherMapError::UnverifiedRun(id)) if id == "run-one"
        ));
    }

    #[test]
    fn rejects_duplicate_run_identity() {
        let python = unit(
            "python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let node = unit("node", Ecosystem::Node, WeatherSourceKind::ProjectFixture);
        let first = input(&python, "same-run", Verdict::BaselinePass);
        let mut duplicate = input(&node, "same-run", Verdict::BaselinePass);
        duplicate.verification.inventory_sha256 = first.verification.inventory_sha256.clone();
        assert!(matches!(
            aggregate_preverified_weather_map(request(vec![python, node], vec![first, duplicate])),
            Err(WeatherMapError::DuplicateRunId(id)) if id == "same-run"
        ));
    }

    #[test]
    fn rejects_mixed_time_windows() {
        let selected = unit(
            "python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let mut run = input(&selected, "run-one", Verdict::BaselinePass);
        run.cohort.time_window.ends_at += chrono::Duration::days(1);
        assert!(matches!(
            aggregate_preverified_weather_map(request(vec![selected], vec![run])),
            Err(WeatherMapError::MixedTimeWindow(id)) if id == "run-one"
        ));
    }

    #[test]
    fn rejects_denominator_dropping() {
        let python = unit(
            "python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let node = unit("node", Ecosystem::Node, WeatherSourceKind::ProjectFixture);
        let mut request = request(vec![python, node], vec![]);
        request.selection_policy.declared_denominator = 1;
        assert_eq!(
            aggregate_preverified_weather_map(request),
            Err(WeatherMapError::DenominatorMismatch {
                declared: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn rejects_typed_model_substitution_after_verification() {
        let selected = unit(
            "python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let mut run = input(&selected, "run-one", Verdict::BaselinePass);
        run.verdicts[0].verdict = Verdict::FutureFail;
        assert!(matches!(
            aggregate_preverified_weather_map(request(vec![selected], vec![run])),
            Err(WeatherMapError::IdentityMismatch { detail, .. })
                if detail.contains("typed run/verdict model digest")
        ));
    }

    #[test]
    fn strict_serde_rejects_unknown_fields() {
        let value = serde_json::json!({
            "starts_at": "2026-08-01T00:00:00Z",
            "ends_at": "2026-09-01T00:00:00Z",
            "surprise": true
        });
        assert!(serde_json::from_value::<WeatherTimeWindow>(value).is_err());
    }

    #[test]
    fn aggregation_is_deterministic_across_input_order() {
        let python = unit(
            "z-python",
            Ecosystem::Python,
            WeatherSourceKind::ProjectFixture,
        );
        let node = unit(
            "a-node",
            Ecosystem::Node,
            WeatherSourceKind::ExternalRepository,
        );
        let left = aggregate_preverified_weather_map(request(
            vec![python.clone(), node.clone()],
            vec![
                input(&node, "node-run", Verdict::FutureFail),
                input(&python, "python-run", Verdict::BaselinePass),
            ],
        ))
        .unwrap();
        let right = aggregate_preverified_weather_map(request(
            vec![node.clone(), python.clone()],
            vec![
                input(&python, "python-run", Verdict::BaselinePass),
                input(&node, "node-run", Verdict::FutureFail),
            ],
        ))
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(
            serde_json::to_vec(&left).unwrap(),
            serde_json::to_vec(&right).unwrap()
        );
    }
}
