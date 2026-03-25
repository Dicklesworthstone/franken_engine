#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::observability_publication_bundle::{
    BEAD_ID, ObservabilityMode, ObservabilityPublicationPolicyArtifact,
    SupportBundleObservabilityAttestationArtifact, write_observability_publication_bundle,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ObservabilityPublicationPolicyDocContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    audited_inputs: Vec<String>,
    required_readme_fragments: Vec<String>,
    required_doc_fragments: Vec<String>,
    source_fragment_checks: Vec<SourceFragmentCheck>,
    workload_classes: Vec<String>,
    observability_modes: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunnerContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SourceFragmentCheck {
    path: String,
    fragment: String,
}

#[derive(Debug, Deserialize)]
struct GateRunnerContract {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root parent")
        .parent()
        .expect("repo root parent")
        .to_path_buf()
}

fn read_repo_text(path: &str) -> String {
    let full_path = repo_root().join(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", full_path.display()))
}

fn parse_doc_contract() -> ObservabilityPublicationPolicyDocContract {
    let path = repo_root().join("docs/rgc_observability_publication_policy_v1.json");
    serde_json::from_slice(
        &fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
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

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn constants_component_is_non_empty() {
    use frankenengine_engine::observability_publication_bundle::COMPONENT;
    assert!(!COMPONENT.is_empty());
}

#[test]
fn constants_bead_id_is_non_empty() {
    assert!(!BEAD_ID.is_empty());
}

#[test]
fn constants_policy_id_is_non_empty() {
    use frankenengine_engine::observability_publication_bundle::POLICY_ID;
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn constants_schema_versions_are_non_empty() {
    use frankenengine_engine::observability_publication_bundle::{
        BUDGET_SENTINEL_SCHEMA_VERSION, CLAIM_DELTA_SCHEMA_VERSION,
        DEMOTION_RECEIPTS_SCHEMA_VERSION, PUBLICATION_POLICY_SCHEMA_VERSION,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION, SUPREMACY_MATRIX_SCHEMA_VERSION,
    };
    for version in [
        BUDGET_SENTINEL_SCHEMA_VERSION,
        DEMOTION_RECEIPTS_SCHEMA_VERSION,
        SUPREMACY_MATRIX_SCHEMA_VERSION,
        CLAIM_DELTA_SCHEMA_VERSION,
        PUBLICATION_POLICY_SCHEMA_VERSION,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION,
    ] {
        assert!(!version.is_empty(), "schema version must not be empty");
    }
}

#[test]
fn constants_schema_versions_are_all_distinct() {
    use frankenengine_engine::observability_publication_bundle::{
        BUDGET_SENTINEL_SCHEMA_VERSION, CLAIM_DELTA_SCHEMA_VERSION,
        DEMOTION_RECEIPTS_SCHEMA_VERSION, PUBLICATION_POLICY_SCHEMA_VERSION,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION, SUPREMACY_MATRIX_SCHEMA_VERSION,
    };
    use std::collections::BTreeSet;
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
    assert_eq!(versions.len(), 6, "all 6 schema versions must be distinct");
}

// ---------------------------------------------------------------------------
// ObservabilityWorkloadClass
// ---------------------------------------------------------------------------

#[test]
fn workload_class_all_has_three_variants() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    assert_eq!(ObservabilityWorkloadClass::ALL.len(), 3);
}

#[test]
fn workload_class_workload_ids_are_distinct() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    use std::collections::BTreeSet;
    let ids: BTreeSet<&str> = ObservabilityWorkloadClass::ALL
        .iter()
        .map(|variant| variant.workload_id())
        .collect();
    assert_eq!(ids.len(), 3);
}

#[test]
fn workload_class_telemetry_domains_are_distinct() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    use std::collections::BTreeSet;
    let domains: BTreeSet<&str> = ObservabilityWorkloadClass::ALL
        .iter()
        .map(|variant| variant.telemetry_domain())
        .collect();
    assert_eq!(domains.len(), 3);
}

#[test]
fn workload_class_display_non_empty() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    for variant in ObservabilityWorkloadClass::ALL {
        let display = format!("{variant}");
        assert!(!display.is_empty());
    }
}

#[test]
fn workload_class_clone_independence() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    let original = ObservabilityWorkloadClass::HostcallSensitive;
    let cloned = original;
    assert_eq!(original, cloned);
    assert_eq!(original.workload_id(), cloned.workload_id());
}

#[test]
fn workload_class_serde_roundtrip() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    for variant in ObservabilityWorkloadClass::ALL {
        let json = serde_json::to_string(&variant).expect("serialize workload class");
        let deserialized: ObservabilityWorkloadClass =
            serde_json::from_str(&json).expect("deserialize workload class");
        assert_eq!(variant, deserialized);
    }
}

#[test]
fn workload_class_display_matches_workload_id() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityWorkloadClass;
    for variant in ObservabilityWorkloadClass::ALL {
        assert_eq!(format!("{variant}"), variant.workload_id());
    }
}

// ---------------------------------------------------------------------------
// ObservabilityMode
// ---------------------------------------------------------------------------

#[test]
fn mode_all_has_three_variants() {
    assert_eq!(ObservabilityMode::ALL.len(), 3);
}

#[test]
fn mode_as_str_values_are_distinct() {
    use std::collections::BTreeSet;
    let strs: BTreeSet<&str> = ObservabilityMode::ALL
        .iter()
        .map(|mode| mode.as_str())
        .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn mode_display_non_empty() {
    for mode in ObservabilityMode::ALL {
        let display = format!("{mode}");
        assert!(!display.is_empty());
    }
}

#[test]
fn mode_default_is_off() {
    assert_eq!(ObservabilityMode::default(), ObservabilityMode::Off);
}

#[test]
fn mode_clone_preserves_equality() {
    let original = ObservabilityMode::ExactShadow;
    let cloned = original;
    assert_eq!(original, cloned);
}

#[test]
fn mode_serde_roundtrip() {
    for mode in ObservabilityMode::ALL {
        let json = serde_json::to_string(&mode).expect("serialize mode");
        let deserialized: ObservabilityMode =
            serde_json::from_str(&json).expect("deserialize mode");
        assert_eq!(mode, deserialized);
    }
}

#[test]
fn mode_display_matches_as_str() {
    for mode in ObservabilityMode::ALL {
        assert_eq!(format!("{mode}"), mode.as_str());
    }
}

// ---------------------------------------------------------------------------
// write_observability_publication_bundle: artifact_hashes
// ---------------------------------------------------------------------------

#[test]
fn bundle_artifact_hashes_has_six_entries() {
    let out_dir = unique_dir("artifact_hashes_count");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    assert_eq!(artifacts.artifact_hashes.len(), 6);
}

#[test]
fn bundle_hash_is_valid_hex() {
    let out_dir = unique_dir("bundle_hash_hex");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    assert!(!artifacts.bundle_hash.is_empty());
    assert!(
        artifacts.bundle_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "bundle_hash must be valid hex"
    );
}

#[test]
fn bundle_artifact_hash_values_are_valid_hex() {
    let out_dir = unique_dir("artifact_hash_values_hex");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    for (key, hash) in &artifacts.artifact_hashes {
        assert!(!hash.is_empty(), "hash for {key} must not be empty");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash for {key} must be valid hex"
        );
    }
}

#[test]
fn bundle_artifact_hash_keys_are_json_filenames() {
    let out_dir = unique_dir("artifact_hash_keys");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    for key in artifacts.artifact_hashes.keys() {
        assert!(
            key.ends_with(".json"),
            "artifact hash key {key} must end with .json"
        );
    }
}

// ---------------------------------------------------------------------------
// write_observability_publication_bundle: per-artifact JSON parsing
// ---------------------------------------------------------------------------

#[test]
fn budget_sentinel_report_artifact_parses_with_correct_schema() {
    use frankenengine_engine::observability_publication_bundle::{
        BUDGET_SENTINEL_SCHEMA_VERSION, COMPONENT, ObservabilityBudgetSentinelReportArtifact,
    };
    let out_dir = unique_dir("budget_sentinel_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityBudgetSentinelReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_budget_sentinel_report_path).expect("read budget"),
    )
    .expect("parse budget report");
    assert_eq!(report.schema_version, BUDGET_SENTINEL_SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
}

#[test]
fn budget_sentinel_report_gate_pass_is_bool() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityBudgetSentinelReportArtifact;
    let out_dir = unique_dir("budget_gate_pass");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityBudgetSentinelReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_budget_sentinel_report_path).expect("read budget"),
    )
    .expect("parse budget report");
    // gate_pass is a bool -- we just verify parsing succeeded and the field is accessible
    let _ = report.gate_pass;
}

#[test]
fn budget_sentinel_report_policy_id_matches_constant() {
    use frankenengine_engine::observability_publication_bundle::{
        ObservabilityBudgetSentinelReportArtifact, POLICY_ID,
    };
    let out_dir = unique_dir("budget_policy_id");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityBudgetSentinelReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_budget_sentinel_report_path).expect("read budget"),
    )
    .expect("parse budget report");
    assert_eq!(report.policy_id, POLICY_ID);
}

// ---------------------------------------------------------------------------
// Supremacy matrix artifact
// ---------------------------------------------------------------------------

#[test]
fn supremacy_matrix_artifact_has_nine_cells() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityOnSupremacyMatrixArtifact;
    let out_dir = unique_dir("supremacy_cells");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_on_supremacy_matrix_path).expect("read matrix"),
    )
    .expect("parse supremacy matrix");
    // 3 workload classes * 3 modes = 9 cells
    assert_eq!(matrix.cells.len(), 9);
}

#[test]
fn supremacy_matrix_green_fraction_within_range() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityOnSupremacyMatrixArtifact;
    let out_dir = unique_dir("supremacy_green_fraction");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_on_supremacy_matrix_path).expect("read matrix"),
    )
    .expect("parse supremacy matrix");
    assert!(
        matrix.green_fraction_millionths <= 1_000_000,
        "green_fraction_millionths must be <= 1_000_000"
    );
}

#[test]
fn supremacy_matrix_schema_version_matches() {
    use frankenengine_engine::observability_publication_bundle::{
        ObservabilityOnSupremacyMatrixArtifact, SUPREMACY_MATRIX_SCHEMA_VERSION,
    };
    let out_dir = unique_dir("supremacy_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_on_supremacy_matrix_path).expect("read matrix"),
    )
    .expect("parse supremacy matrix");
    assert_eq!(matrix.schema_version, SUPREMACY_MATRIX_SCHEMA_VERSION);
}

#[test]
fn supremacy_matrix_report_hash_non_empty() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityOnSupremacyMatrixArtifact;
    let out_dir = unique_dir("supremacy_report_hash");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let matrix: ObservabilityOnSupremacyMatrixArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_on_supremacy_matrix_path).expect("read matrix"),
    )
    .expect("parse supremacy matrix");
    assert!(!matrix.report_hash.is_empty());
    assert!(!matrix.report_id.is_empty());
}

// ---------------------------------------------------------------------------
// Claim delta report
// ---------------------------------------------------------------------------

#[test]
fn claim_delta_report_has_nine_surfaces() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityClaimDeltaReportArtifact;
    let out_dir = unique_dir("claim_delta_surfaces");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_claim_delta_report_path).expect("read claim delta"),
    )
    .expect("parse claim delta report");
    assert_eq!(report.claim_surfaces.len(), 9);
}

#[test]
fn claim_delta_report_has_six_deltas() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityClaimDeltaReportArtifact;
    let out_dir = unique_dir("claim_delta_deltas");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_claim_delta_report_path).expect("read claim delta"),
    )
    .expect("parse claim delta report");
    // 3 workloads * 2 deltas each (off->budgeted, budgeted->exact_shadow) = 6
    assert_eq!(report.deltas.len(), 6);
}

#[test]
fn claim_delta_report_schema_version_matches() {
    use frankenengine_engine::observability_publication_bundle::{
        CLAIM_DELTA_SCHEMA_VERSION, ObservabilityClaimDeltaReportArtifact,
    };
    let out_dir = unique_dir("claim_delta_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_claim_delta_report_path).expect("read claim delta"),
    )
    .expect("parse claim delta report");
    assert_eq!(report.schema_version, CLAIM_DELTA_SCHEMA_VERSION);
    assert_eq!(
        report.component,
        frankenengine_engine::observability_publication_bundle::COMPONENT
    );
    assert_eq!(report.bead_id, BEAD_ID);
}

#[test]
fn claim_delta_report_hot_path_summary_present() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityClaimDeltaReportArtifact;
    let out_dir = unique_dir("claim_delta_hot_path");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let report: ObservabilityClaimDeltaReportArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_claim_delta_report_path).expect("read claim delta"),
    )
    .expect("parse claim delta report");
    assert!(!report.hot_path_summary.manifest_id.is_empty());
    assert!(!report.hot_path_summary.manifest_hash.is_empty());
}

// ---------------------------------------------------------------------------
// Demotion receipts
// ---------------------------------------------------------------------------

#[test]
fn demotion_receipts_schema_version_matches() {
    use frankenengine_engine::observability_publication_bundle::{
        DEMOTION_RECEIPTS_SCHEMA_VERSION, TelemetryDemotionReceiptsArtifact,
    };
    let out_dir = unique_dir("demotion_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let receipts: TelemetryDemotionReceiptsArtifact = serde_json::from_slice(
        &fs::read(&artifacts.telemetry_demotion_receipts_path).expect("read demotion"),
    )
    .expect("parse demotion receipts");
    assert_eq!(receipts.schema_version, DEMOTION_RECEIPTS_SCHEMA_VERSION);
}

#[test]
fn demotion_receipts_counts_are_consistent() {
    use frankenengine_engine::observability_publication_bundle::TelemetryDemotionReceiptsArtifact;
    let out_dir = unique_dir("demotion_counts");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let receipts: TelemetryDemotionReceiptsArtifact = serde_json::from_slice(
        &fs::read(&artifacts.telemetry_demotion_receipts_path).expect("read demotion"),
    )
    .expect("parse demotion receipts");
    assert_eq!(receipts.receipt_count, receipts.receipts.len() as u64);
    assert_eq!(
        receipts.trigger_count,
        receipts.trigger_artifacts.len() as u64
    );
}

#[test]
fn demotion_receipts_component_and_bead_id() {
    use frankenengine_engine::observability_publication_bundle::{
        COMPONENT, POLICY_ID, TelemetryDemotionReceiptsArtifact,
    };
    let out_dir = unique_dir("demotion_component");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let receipts: TelemetryDemotionReceiptsArtifact = serde_json::from_slice(
        &fs::read(&artifacts.telemetry_demotion_receipts_path).expect("read demotion"),
    )
    .expect("parse demotion receipts");
    assert_eq!(receipts.component, COMPONENT);
    assert_eq!(receipts.bead_id, BEAD_ID);
    assert_eq!(receipts.policy_id, POLICY_ID);
}

// ---------------------------------------------------------------------------
// Publication policy artifact
// ---------------------------------------------------------------------------

#[test]
fn publication_policy_publication_gate_pass_is_bool() {
    let out_dir = unique_dir("policy_gate_pass");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_publication_policy_path).expect("read policy"),
    )
    .expect("parse policy");
    // publication_gate_pass is deterministically false because suppressed_claims is non-empty
    // (Off-mode cells are always suppressed)
    let _ = policy.publication_gate_pass;
}

#[test]
fn publication_policy_fail_closed_conditions_non_empty() {
    let out_dir = unique_dir("policy_fail_closed");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_publication_policy_path).expect("read policy"),
    )
    .expect("parse policy");
    assert!(
        !policy.fail_closed_conditions.is_empty(),
        "expected at least one fail-closed condition"
    );
}

#[test]
fn publication_policy_required_artifacts_has_six_entries() {
    let out_dir = unique_dir("policy_required_artifacts");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_publication_policy_path).expect("read policy"),
    )
    .expect("parse policy");
    assert_eq!(policy.required_artifacts.len(), 6);
    for artifact_name in &policy.required_artifacts {
        assert!(
            artifact_name.ends_with(".json"),
            "required artifact {artifact_name} must end with .json"
        );
    }
}

#[test]
fn publication_policy_schema_version_matches() {
    use frankenengine_engine::observability_publication_bundle::PUBLICATION_POLICY_SCHEMA_VERSION;
    let out_dir = unique_dir("policy_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let policy: ObservabilityPublicationPolicyArtifact = serde_json::from_slice(
        &fs::read(&artifacts.observability_publication_policy_path).expect("read policy"),
    )
    .expect("parse policy");
    assert_eq!(policy.schema_version, PUBLICATION_POLICY_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Support bundle attestation artifact
// ---------------------------------------------------------------------------

#[test]
fn attestation_schema_version_matches() {
    use frankenengine_engine::observability_publication_bundle::SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION;
    let out_dir = unique_dir("attestation_schema");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let attestation: SupportBundleObservabilityAttestationArtifact = serde_json::from_slice(
        &fs::read(&artifacts.support_bundle_observability_attestation_path)
            .expect("read attestation"),
    )
    .expect("parse attestation");
    assert_eq!(
        attestation.schema_version,
        SUPPORT_BUNDLE_ATTESTATION_SCHEMA_VERSION
    );
}

#[test]
fn attestation_hash_fields_are_non_empty_hex() {
    let out_dir = unique_dir("attestation_hashes");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let attestation: SupportBundleObservabilityAttestationArtifact = serde_json::from_slice(
        &fs::read(&artifacts.support_bundle_observability_attestation_path)
            .expect("read attestation"),
    )
    .expect("parse attestation");
    for (label, hash) in [
        ("quality_report_hash", &attestation.quality_report_hash),
        ("supremacy_matrix_hash", &attestation.supremacy_matrix_hash),
        ("claim_delta_hash", &attestation.claim_delta_hash),
        (
            "demotion_receipts_hash",
            &attestation.demotion_receipts_hash,
        ),
        (
            "publication_policy_hash",
            &attestation.publication_policy_hash,
        ),
    ] {
        assert!(!hash.is_empty(), "{label} must not be empty");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "{label} must be valid hex"
        );
    }
}

#[test]
fn attestation_suppressed_claim_count_matches_artifacts() {
    let out_dir = unique_dir("attestation_suppressed");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let attestation: SupportBundleObservabilityAttestationArtifact = serde_json::from_slice(
        &fs::read(&artifacts.support_bundle_observability_attestation_path)
            .expect("read attestation"),
    )
    .expect("parse attestation");
    assert_eq!(
        attestation.suppressed_claim_count as usize,
        artifacts.suppressed_claim_count
    );
}

#[test]
fn attestation_quality_and_hot_path_fields_non_empty() {
    let out_dir = unique_dir("attestation_fields");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    let attestation: SupportBundleObservabilityAttestationArtifact = serde_json::from_slice(
        &fs::read(&artifacts.support_bundle_observability_attestation_path)
            .expect("read attestation"),
    )
    .expect("parse attestation");
    assert!(!attestation.quality_overall_regime.is_empty());
    assert!(!attestation.hot_path_overall_mode.is_empty());
}

// ---------------------------------------------------------------------------
// Error type Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_busy_contains_path() {
    use frankenengine_engine::observability_publication_bundle::ObservabilityPublicationBundleError;
    let err = ObservabilityPublicationBundleError::Busy {
        path: "/tmp/test.lock".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/test.lock"));
}

// ---------------------------------------------------------------------------
// Out-dir is recorded in artifacts
// ---------------------------------------------------------------------------

#[test]
fn artifacts_out_dir_matches_input() {
    let out_dir = unique_dir("out_dir_match");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    assert_eq!(artifacts.out_dir, out_dir);
}

// ---------------------------------------------------------------------------
// All six artifact files exist as children of out_dir
// ---------------------------------------------------------------------------

#[test]
fn all_artifact_paths_are_under_out_dir() {
    let out_dir = unique_dir("paths_under_out_dir");
    let artifacts =
        write_observability_publication_bundle(&out_dir).expect("write publication bundle");
    for path in [
        &artifacts.observability_budget_sentinel_report_path,
        &artifacts.observability_on_supremacy_matrix_path,
        &artifacts.observability_claim_delta_report_path,
        &artifacts.telemetry_demotion_receipts_path,
        &artifacts.observability_publication_policy_path,
        &artifacts.support_bundle_observability_attestation_path,
    ] {
        assert!(
            path.starts_with(&out_dir),
            "artifact path {} must be under out_dir {}",
            path.display(),
            out_dir.display()
        );
    }
}

#[test]
fn rgc_066c_doc_contract_core_fields_are_expected() {
    let contract = parse_doc_contract();

    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-observability-publication-policy-contract.v1"
    );
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, BEAD_ID);
    assert_eq!(
        contract.policy_id,
        "policy-rgc-observability-publication-v1"
    );
    assert_eq!(
        contract.workload_classes,
        vec![
            "dispatch_sensitive".to_string(),
            "hostcall_sensitive".to_string(),
            "startup_sensitive".to_string()
        ]
    );
    assert_eq!(
        contract.observability_modes,
        vec![
            "off".to_string(),
            "budgeted".to_string(),
            "exact_shadow".to_string()
        ]
    );
    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_observability_publication_policy.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_observability_publication_policy_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "ci");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "rgc.observability-publication-policy.gate.run-manifest.v1"
    );
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids",
        "step_logs/",
        "observability_budget_sentinel_report.json",
        "observability_on_supremacy_matrix.json",
        "observability_claim_delta_report.json",
        "telemetry_demotion_receipts.json",
        "observability_publication_policy.json",
        "support_bundle_observability_attestation.json",
    ] {
        assert!(
            contract
                .required_artifacts
                .iter()
                .any(|entry| entry == artifact),
            "missing required artifact contract entry: {artifact}"
        );
    }
}

#[test]
fn rgc_066c_doc_contract_audited_inputs_are_unique_and_exist() {
    let contract = parse_doc_contract();
    let root = repo_root();
    let mut seen = std::collections::BTreeSet::new();
    for input in &contract.audited_inputs {
        assert!(
            seen.insert(input.clone()),
            "duplicate audited input in doc contract: {input}"
        );
        let path = root.join(input);
        assert!(
            path.exists(),
            "audited input must exist: {}",
            path.display()
        );
    }
}

#[test]
fn rgc_066c_readme_section_documents_gate_commands_and_artifacts() {
    let contract = parse_doc_contract();
    let readme = read_repo_text("README.md");
    for fragment in &contract.required_readme_fragments {
        assert!(
            readme.contains(fragment),
            "README.md must contain required fragment: {fragment}"
        );
    }
}

#[test]
fn rgc_066c_markdown_doc_contains_required_fragments() {
    let contract = parse_doc_contract();
    let doc = read_repo_text("docs/RGC_OBSERVABILITY_PUBLICATION_POLICY_V1.md");
    for fragment in &contract.required_doc_fragments {
        assert!(
            doc.contains(fragment),
            "RGC observability publication policy doc must contain fragment: {fragment}"
        );
    }
}

#[test]
fn rgc_066c_source_fragment_checks_match_repo_sources() {
    let contract = parse_doc_contract();
    let root = repo_root();
    for check in &contract.source_fragment_checks {
        let path = root.join(&check.path);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        assert!(
            source.contains(&check.fragment),
            "source file {} must contain fragment: {}",
            check.path,
            check.fragment
        );
    }
}

#[test]
fn rgc_066c_contract_operator_verification_mentions_preserved_replay() {
    let contract = parse_doc_contract();

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("step_logs/step-01.log")),
        "operator verification should surface the first step log"
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains(
                "RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP>"
            )
        }),
        "operator verification should use preserved exact-run-dir replay"
    );
}

#[test]
fn rgc_066c_replay_wrapper_uses_latest_complete_bundle() {
    let script = read_repo_text("scripts/e2e/rgc_observability_publication_policy_replay.sh");

    for required_fragment in [
        "explicit_run_dir=\"${RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR:-}\"",
        "latest_complete_run_dir()",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "rgc observability publication policy replay explicit run directory is incomplete: ${explicit_run_dir}",
        "latest manifest: ${latest_run_dir}/run_manifest.json",
        "latest trace ids: ${latest_run_dir}/trace_ids",
        "latest events: ${latest_run_dir}/events.jsonl",
        "latest commands: ${latest_run_dir}/commands.txt",
        "latest first step log: ${latest_run_dir}/step_logs/step-01.log",
        "latest publication policy: ${latest_run_dir}/observability_publication_policy.json",
    ] {
        assert!(
            script.contains(required_fragment),
            "observability publication replay wrapper missing fragment: {required_fragment}"
        );
    }
}

#[test]
fn rgc_066c_gate_runner_uses_interceptable_rch_exec() {
    let script = read_repo_text("scripts/run_rgc_observability_publication_policy.sh");

    assert!(
        script.contains(
            "rch exec -q -- env RUSTUP_TOOLCHAIN=\"${toolchain}\" CARGO_TARGET_DIR=\"${target_dir}\" \"$@\""
        ),
        "gate runner should use direct env-prefixed cargo commands so rch can intercept them"
    );
    assert!(
        !script.contains("rch exec -q -- bash -lc"),
        "gate runner must avoid shell-wrapped rch exec commands that bypass interception"
    );
}
