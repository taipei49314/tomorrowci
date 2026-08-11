//! Evidence-authenticated construction of ecosystem weather maps.

use sha2::{Digest, Sha256};
use tomorrowci_core::{
    aggregate_preverified_weather_map, weather_typed_model_sha256, ScenarioVerdict,
    SourceSnapshotManifestV2, WeatherBundleKind, WeatherCohortIdentity, WeatherMap,
    WeatherMapRequest, WeatherRunInput, WeatherSelectionPolicy, WeatherTimeWindow,
    WeatherVerificationIdentity, WeatherVerificationState, MIN_WEATHER_INVENTORY_VERSION,
};

use crate::{BundleKind, EvidenceError, Result, VerifiedBundle};

/// Opaque observation whose bundle has passed the evidence verifier.
#[derive(Debug, Clone)]
pub struct VerifiedWeatherRun {
    selection_unit_id: String,
    cohort: WeatherCohortIdentity,
    bundle: VerifiedBundle,
}

impl VerifiedWeatherRun {
    pub fn new(
        selection_unit_id: String,
        cohort: WeatherCohortIdentity,
        bundle: VerifiedBundle,
    ) -> Self {
        Self {
            selection_unit_id,
            cohort,
            bundle,
        }
    }

    pub fn bundle_root(&self) -> &std::path::Path {
        &self.bundle.root
    }
}

/// Construct identities from retained verified generations and aggregate one
/// descriptive map. No caller-authored VERIFIED flag or digest is accepted.
pub fn aggregate_verified_weather_map(
    schema_version: u32,
    selection_policy: WeatherSelectionPolicy,
    time_window: WeatherTimeWindow,
    observations: Vec<VerifiedWeatherRun>,
) -> Result<WeatherMap> {
    let mut runs = Vec::with_capacity(observations.len());
    for observation in observations {
        let verified = observation.bundle;
        if verified.kind != BundleKind::Run {
            return Err(EvidenceError::InvalidSemantics {
                field: "weather.bundle.kind".into(),
                detail: "weather aggregation accepts verified run bundles only".into(),
            });
        }
        if verified.version < MIN_WEATHER_INVENTORY_VERSION {
            return Err(EvidenceError::InvalidSemantics {
                field: "weather.bundle.version".into(),
                detail: format!(
                    "inventory v{} lacks the v{} source identity",
                    verified.version, MIN_WEATHER_INVENTORY_VERSION
                ),
            });
        }

        let run: tomorrowci_core::RunManifest = verified.read_json("run.json")?;
        let verdicts: Vec<ScenarioVerdict> = verified.read_json("verdicts.json")?;
        let _: SourceSnapshotManifestV2 = verified.read_json("source-manifest.json")?;
        let source_manifest_bytes = verified.read_bytes("source-manifest.json")?;
        let source_manifest_sha256 = hex::encode(Sha256::digest(&source_manifest_bytes));
        let inventory_sha256 = verified.inventory_sha256()?;
        let typed_model_sha256 = weather_typed_model_sha256(&run, &verdicts).map_err(|error| {
            EvidenceError::InvalidSemantics {
                field: "weather.typed_model".into(),
                detail: error.to_string(),
            }
        })?;
        let verified_file_count =
            u64::try_from(verified.file_count).map_err(|_| EvidenceError::InvalidSemantics {
                field: "weather.bundle.file_count".into(),
                detail: "verified file count does not fit u64".into(),
            })?;

        runs.push(WeatherRunInput {
            selection_unit_id: observation.selection_unit_id,
            cohort: observation.cohort,
            verification: WeatherVerificationIdentity {
                state: WeatherVerificationState::Verified,
                bundle_kind: WeatherBundleKind::Run,
                inventory_version: verified.version,
                inventory_sha256,
                source_manifest_sha256,
                typed_model_sha256,
                run_id: run.run_id.clone(),
                verified_file_count,
            },
            run,
            verdicts,
        });
    }

    aggregate_preverified_weather_map(WeatherMapRequest {
        schema_version,
        selection_policy,
        time_window,
        runs,
    })
    .map_err(|error| EvidenceError::InvalidSemantics {
        field: "weather.map".into(),
        detail: error.to_string(),
    })
}
