#![forbid(unsafe_code)]

//! Enrichment integration tests for the observability_publication_bundle module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::observability_publication_bundle::{
    BEAD_ID, BUDGET_SENTINEL_SCHEMA_VERSION, CLAIM_DELTA_SCHEMA_VERSION, COMPONENT,
    DEMOTION_RECEIPTS_SCHEMA_VERSION, ObservabilityBudgetSentinelReportArtifact,
    ObservabilityClaimDeltaReportArtifact, ObservabilityMode,
    ObservabilityOnSupremacyMatrixArtifact, ObservabilityPublicationPolicyArtifact,
    ObservabilityWorkloadClass, POLICY_ID, PUBLICATION_POLICY_SCHEMA_VERSION,
    SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION, SUPREMACY_MATRIX_SCHEMA_VERSION,
    SupportBundleObservabilityAttestationArtifact, TelemetryDemotionReceiptsArtifact,
    write_observability_publication_bundle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_bundle_to_tempdir() -> (
    std::path::PathBuf,
    frankenengine_engine::observability_publication_bundle::ObservabilityPublicationArtifacts,
) {
    let idx = DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "pearl_obs_bundle_enrichment_{}_{}",
        std::process::id(),
        idx
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let artifacts = write_observability_publication_bundle(&dir).unwrap();
    (dir, artifacts)
}

// ---------------------------------------------------------------------------
// ObservabilityWorkloadClass — Copy / BTreeSet / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_class_copy_semantics() {
    let a = ObservabilityWorkloadClass::DispatchSensitive;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_class_btreeset_dedup_3() {
    let mut set = BTreeSet::new();
    for c in ObservabilityWorkloadClass::ALL {
        set.insert(c);
    }
    set.insert(ObservabilityWorkloadClass::DispatchSensitive);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_workload_class_clone_independence() {
    let a = ObservabilityWorkloadClass::HostcallSensitive;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_class_debug_all_unique() {
    let dbgs: BTreeSet<String> = ObservabilityWorkloadClass::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn enrichment_workload_class_workload_id_all_unique() {
    let ids: BTreeSet<&str> = ObservabilityWorkloadClass::ALL
        .iter()
        .map(|v| v.workload_id())
        .collect();
    assert_eq!(ids.len(), 3);
}

#[test]
fn enrichment_workload_class_telemetry_domain_all_unique() {
    let domains: BTreeSet<&str> = ObservabilityWorkloadClass::ALL
        .iter()
        .map(|v| v.telemetry_domain())
        .collect();
    assert_eq!(domains.len(), 3);
}

#[test]
fn enrichment_workload_class_display_matches_workload_id() {
    for c in ObservabilityWorkloadClass::ALL {
        assert_eq!(format!("{}", c), c.workload_id());
    }
}

#[test]
fn enrichment_workload_class_default_is_dispatch_sensitive() {
    let d = ObservabilityWorkloadClass::default();
    assert_eq!(d, ObservabilityWorkloadClass::DispatchSensitive);
}

#[test]
fn enrichment_workload_class_serde_roundtrip_all() {
    for c in ObservabilityWorkloadClass::ALL {
        let json = serde_json::to_string(&c).unwrap();
        let rt: ObservabilityWorkloadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

// ---------------------------------------------------------------------------
// ObservabilityMode — Copy / BTreeSet / Clone / Debug / as_str / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observability_mode_copy_semantics() {
    let a = ObservabilityMode::Off;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_observability_mode_btreeset_dedup_3() {
    let mut set = BTreeSet::new();
    for m in ObservabilityMode::ALL {
        set.insert(m);
    }
    set.insert(ObservabilityMode::Off);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_observability_mode_clone_independence() {
    let a = ObservabilityMode::Budgeted;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_observability_mode_debug_all_unique() {
    let dbgs: BTreeSet<String> = ObservabilityMode::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn enrichment_observability_mode_as_str_all_unique() {
    let strs: BTreeSet<&str> = ObservabilityMode::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_observability_mode_display_matches_as_str() {
    for m in ObservabilityMode::ALL {
        assert_eq!(format!("{}", m), m.as_str());
    }
}

#[test]
fn enrichment_observability_mode_default_is_off() {
    let d = ObservabilityMode::default();
    assert_eq!(d, ObservabilityMode::Off);
}

#[test]
fn enrichment_observability_mode_serde_roundtrip_all() {
    for m in ObservabilityMode::ALL {
        let json = serde_json::to_string(&m).unwrap();
        let rt: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, rt);
    }
}

// ---------------------------------------------------------------------------
// Constants — exact values and uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(COMPONENT, "observability_publication_bundle");
    assert_eq!(BEAD_ID, "bd-1lsy.11.20.3");
    assert_eq!(POLICY_ID, "policy-rgc-observability-publication-v1");
}

#[test]
fn enrichment_schema_versions_all_nonempty() {
    for sv in &[
        BUDGET_SENTINEL_SCHEMA_VERSION,
        DEMOTION_RECEIPTS_SCHEMA_VERSION,
        SUPREMACY_MATRIX_SCHEMA_VERSION,
        CLAIM_DELTA_SCHEMA_VERSION,
        PUBLICATION_POLICY_SCHEMA_VERSION,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION,
    ] {
        assert!(!sv.is_empty());
    }
}

#[test]
fn enrichment_schema_versions_all_unique() {
    let versions: BTreeSet<&str> = [
        BUDGET_SENTINEL_SCHEMA_VERSION,
        DEMOTION_RECEIPTS_SCHEMA_VERSION,
        SUPREMACY_MATRIX_SCHEMA_VERSION,
        CLAIM_DELTA_SCHEMA_VERSION,
        PUBLICATION_POLICY_SCHEMA_VERSION,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(versions.len(), 6);
}

// ---------------------------------------------------------------------------
// write_observability_publication_bundle — artifacts / determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_bundle_produces_6_artifact_hashes() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    assert_eq!(artifacts.artifact_hashes.len(), 6);
}

#[test]
fn enrichment_bundle_hash_nonempty() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    assert!(!artifacts.bundle_hash.is_empty());
}

#[test]
fn enrichment_bundle_artifact_hash_keys_end_with_json() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    for key in artifacts.artifact_hashes.keys() {
        assert!(key.ends_with(".json"), "key should end with .json: {}", key);
    }
}

#[test]
fn enrichment_bundle_determinism() {
    let (_dir1, a1) = write_bundle_to_tempdir();
    let (_dir2, a2) = write_bundle_to_tempdir();
    assert_eq!(a1.bundle_hash, a2.bundle_hash);
    assert_eq!(a1.attested, a2.attested);
}

#[test]
fn enrichment_bundle_all_artifact_paths_exist() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
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
}

// ---------------------------------------------------------------------------
// Budget Sentinel Report — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_sentinel_report_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.observability_budget_sentinel_report_path).unwrap();
    let report: ObservabilityBudgetSentinelReportArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(report.schema_version, BUDGET_SENTINEL_SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
}

// ---------------------------------------------------------------------------
// Supremacy Matrix — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_supremacy_matrix_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_on_supremacy_matrix_path).unwrap();
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(matrix.schema_version, SUPREMACY_MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.component, COMPONENT);
    assert_eq!(matrix.bead_id, BEAD_ID);
}

#[test]
fn enrichment_supremacy_matrix_has_9_cells() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_on_supremacy_matrix_path).unwrap();
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(matrix.cells.len(), 9);
}

#[test]
fn enrichment_supremacy_matrix_green_fraction_in_range() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_on_supremacy_matrix_path).unwrap();
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_str(&data).unwrap();
    assert!(matrix.green_fraction_millionths <= 1_000_000);
}

// ---------------------------------------------------------------------------
// Claim Delta Report — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_claim_delta_report_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_claim_delta_report_path).unwrap();
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(report.schema_version, CLAIM_DELTA_SCHEMA_VERSION);
}

#[test]
fn enrichment_claim_delta_report_9_surfaces_6_deltas() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_claim_delta_report_path).unwrap();
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(report.claim_surfaces.len(), 9);
    assert_eq!(report.deltas.len(), 6);
}

// ---------------------------------------------------------------------------
// Demotion Receipts — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_demotion_receipts_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.telemetry_demotion_receipts_path).unwrap();
    let receipts: TelemetryDemotionReceiptsArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(receipts.schema_version, DEMOTION_RECEIPTS_SCHEMA_VERSION);
    assert_eq!(receipts.component, COMPONENT);
    assert_eq!(receipts.bead_id, BEAD_ID);
    assert_eq!(receipts.policy_id, POLICY_ID);
}

// ---------------------------------------------------------------------------
// Publication Policy — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publication_policy_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_publication_policy_path).unwrap();
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(policy.schema_version, PUBLICATION_POLICY_SCHEMA_VERSION);
    assert_eq!(policy.component, COMPONENT);
    assert_eq!(policy.bead_id, BEAD_ID);
}

#[test]
fn enrichment_publication_policy_required_artifacts_6() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_publication_policy_path).unwrap();
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(policy.required_artifacts.len(), 6);
    for name in &policy.required_artifacts {
        assert!(
            name.ends_with(".json"),
            "artifact should end with .json: {}",
            name
        );
    }
}

// ---------------------------------------------------------------------------
// Attestation — parse and validate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attestation_schema_version() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.support_bundle_observability_attestation_path).unwrap();
    let att: SupportBundleObservabilityAttestationArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(
        att.schema_version,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION
    );
    assert_eq!(att.component, COMPONENT);
    assert_eq!(att.bead_id, BEAD_ID);
}

#[test]
fn enrichment_attestation_hashes_all_nonempty() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.support_bundle_observability_attestation_path).unwrap();
    let att: SupportBundleObservabilityAttestationArtifact = serde_json::from_str(&data).unwrap();
    assert!(!att.quality_report_hash.is_empty());
    assert!(!att.supremacy_matrix_hash.is_empty());
    assert!(!att.claim_delta_hash.is_empty());
    assert!(!att.demotion_receipts_hash.is_empty());
    assert!(!att.publication_policy_hash.is_empty());
}

#[test]
fn enrichment_attestation_all_5_hashes_unique() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.support_bundle_observability_attestation_path).unwrap();
    let att: SupportBundleObservabilityAttestationArtifact = serde_json::from_str(&data).unwrap();
    let hashes: BTreeSet<&str> = [
        att.quality_report_hash.as_str(),
        att.supremacy_matrix_hash.as_str(),
        att.claim_delta_hash.as_str(),
        att.demotion_receipts_hash.as_str(),
        att.publication_policy_hash.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(hashes.len(), 5);
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_suppressed_count_matches_attestation() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.support_bundle_observability_attestation_path).unwrap();
    let att: SupportBundleObservabilityAttestationArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(
        att.suppressed_claim_count as usize,
        artifacts.suppressed_claim_count
    );
}

#[test]
fn enrichment_cross_cutting_attested_matches_artifacts() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data =
        std::fs::read_to_string(&artifacts.support_bundle_observability_attestation_path).unwrap();
    let att: SupportBundleObservabilityAttestationArtifact = serde_json::from_str(&data).unwrap();
    assert_eq!(att.attested, artifacts.attested);
}

#[test]
fn enrichment_cross_cutting_matrix_cells_cover_all_workloads_and_modes() {
    let (_dir, artifacts) = write_bundle_to_tempdir();
    let data = std::fs::read_to_string(&artifacts.observability_on_supremacy_matrix_path).unwrap();
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_str(&data).unwrap();
    let workload_ids: BTreeSet<&str> = matrix
        .cells
        .iter()
        .map(|c| c.workload_id.as_str())
        .collect();
    assert_eq!(workload_ids.len(), 3);
    let modes: BTreeSet<ObservabilityMode> = matrix.cells.iter().map(|c| c.mode).collect();
    assert_eq!(modes.len(), 3);
}
