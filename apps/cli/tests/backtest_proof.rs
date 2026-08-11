use std::fs;
use std::process::Command;

use tempfile::tempdir;
use tomorrowci_core::backtest::{
    BacktestProof, BacktestProofOutcome, BacktestRuntimeImage, RegistryResolverMode,
    RegistrySnapshotBinding, RegistrySnapshotSource, BACKTEST_PROOF_SCHEMA_VERSION,
};
use tomorrowci_core::Ecosystem;
use tomorrowci_evidence::{seal_bundle, BundleKind};

fn tomorrowci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tomorrowci"))
}

fn valid_proof() -> BacktestProof {
    let source_committed_at = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    BacktestProof {
        schema_version: BACKTEST_PROOF_SCHEMA_VERSION,
        created_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T15:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        source: "https://example.invalid/repository".into(),
        source_commit_sha: "a".repeat(40),
        source_committed_at,
        snapshot: RegistrySnapshotBinding {
            snapshot_id: format!("sha256:{}", "b".repeat(64)),
            manifest_sha256: "c".repeat(64),
            ecosystem: Ecosystem::Python,
            effective_at: source_committed_at,
            captured_at: chrono::DateTime::parse_from_rfc3339("2026-01-15T13:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            source: RegistrySnapshotSource {
                url: "https://pypi.org/simple/".into(),
                immutable_revision: format!("sha256:{}", "d".repeat(64)),
            },
            resolver_mode: RegistryResolverMode::PythonWheelhouse,
            file_count: 1,
            total_bytes: 1,
        },
        source_manifest_sha256: format!("sha256:{}", "2".repeat(64)),
        normalized_config_sha256: "e".repeat(64),
        run_manifest_sha256: format!("sha256:{}", "3".repeat(64)),
        verdicts_sha256: format!("sha256:{}", "4".repeat(64)),
        frontier_sha256: format!("sha256:{}", "5".repeat(64)),
        outcome: BacktestProofOutcome::Qualified,
        runtime_images: vec![BacktestRuntimeImage {
            image_ref: "python:3.12-bookworm".into(),
            image_digest: format!("sha256:{}", "f".repeat(64)),
        }],
        run_id: "0123456789ab".into(),
        sealed_run_inventory_sha256: "1".repeat(64),
    }
}

#[test]
fn arbitrary_self_resealed_json_is_not_a_backtest_proof() {
    let temp = tempdir().unwrap();
    let proof_dir = temp.path().join("proof");
    fs::create_dir(&proof_dir).unwrap();
    fs::write(
        proof_dir.join("backtest-proof.json"),
        serde_json::to_vec_pretty(&valid_proof()).unwrap(),
    )
    .unwrap();
    seal_bundle(&proof_dir, BundleKind::Generic).unwrap();

    let output = tomorrowci()
        .args(["backtest-verify"])
        .arg(&proof_dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("missing required witness"),
        "self-resealed JSON was not rejected at the witness boundary: stdout={stdout:?} stderr={stderr:?}"
    );

    fs::write(
        proof_dir.join("backtest-proof.json"),
        serde_json::to_vec_pretty(&serde_json::json!({"tampered": true})).unwrap(),
    )
    .unwrap();
    let mutation = tomorrowci()
        .args(["backtest-verify"])
        .arg(&proof_dir)
        .output()
        .unwrap();
    assert_eq!(mutation.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&mutation.stderr).contains("checksum mismatch"),
        "unexpected mutation error: {:?}",
        String::from_utf8_lossy(&mutation.stderr)
    );
}
