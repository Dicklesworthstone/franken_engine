#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::observability_publication_bundle::{
    BEAD_ID, ObservabilityMode, ObservabilityPublicationPolicyArtifact,
    SupportBundleObservabilityAttestationArtifact, write_observability_publication_bundle,
};

fn unique_dir(label: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_observability_publication_bundle_{label}_{}_{}",
        std::process::id(),
        timestamp
    ))
}

#[test]
fn write_observability_publication_bundle_emits_expected_artifacts() {
    let out_dir = unique_dir("artifacts");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");

    assert!(artifacts.observability_budget_sentinel_report_path.exists());
    assert!(artifacts.observability_on_supremacy_matrix_path.exists());
    assert!(artifacts.observability_claim_delta_report_path.exists());
    assert!(artifacts.telemetry_demotion_receipts_path.exists());
    assert!(artifacts.observability_publication_policy_path.exists());
    assert!(
        artifacts
            .support_bundle_observability_attestation_path
            .exists()
    );
    assert!(!artifacts.bundle_hash.is_empty());

    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_publication_policy_path).expect("read policy"),
    )
    .expect("parse policy");
    assert_eq!(policy.bead_id, BEAD_ID);
    assert_eq!(policy.default_shipped_mode, ObservabilityMode::Budgeted);
    assert!(
        !policy.suppressed_claims.is_empty(),
        "expected at least one fail-closed suppressed claim"
    );

    let attestation: SupportBundleObservabilityAttestationArtifact = serde_json::from_slice(
        &fs::read(&artifacts.support_bundle_observability_attestation_path)
            .expect("read attestation"),
    )
    .expect("parse attestation");
    assert_eq!(
        attestation.shipped_capture_mode,
        ObservabilityMode::Budgeted
    );
    assert!(
        !attestation.operator_summary.is_empty(),
        "expected operator summary lines"
    );
    assert_eq!(attestation.attested, artifacts.attested);
}

#[test]
fn write_observability_publication_bundle_is_deterministic() {
    let first_dir = unique_dir("first");
    let second_dir = unique_dir("second");

    let first =
        write_observability_publication_bundle(&first_dir).expect("write first publication bundle");
    let second = write_observability_publication_bundle(&second_dir)
        .expect("write second publication bundle");

    assert_eq!(first.bundle_hash, second.bundle_hash);
    assert_eq!(first.attested, second.attested);
    assert_eq!(first.suppressed_claim_count, second.suppressed_claim_count);
    assert_eq!(first.artifact_hashes, second.artifact_hashes);
}
