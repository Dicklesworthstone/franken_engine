#![forbid(unsafe_code)]

//! Enrichment integration tests for the `asupersync_contract_matrix` module.
//!
//! Exercises the public API from outside the crate: surface enumeration,
//! compatibility disposition classification, failure code catalog,
//! contract matrix building against the real asupersync root, bundle
//! artifact emission, serde round-trips, Display formatting, content
//! hashing, and edge cases (missing manifests, version drift combinations,
//! frankenlab scenario inventory).

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

use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::asupersync_contract_matrix::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("franken_engine_asupersync_enrichment");
    path.push(name);
    path.push(Uuid::now_v7().to_string());
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write file");
}

fn write_standard_root(root: &Path) {
    write_root_with_options(root, "0.2.7", "0.2.7", true);
}

fn write_root_with_options(
    root: &Path,
    decision_kernel_ver: &str,
    decision_evidence_ver: &str,
    with_examples: bool,
) {
    write_file(
        &root.join("franken_kernel/Cargo.toml"),
        r#"[package]
name = "franken-kernel"
version = "0.2.7"
edition = "2024"
"#,
    );
    write_file(
        &root.join("franken_decision/Cargo.toml"),
        &format!(
            r#"[package]
name = "franken-decision"
version = "0.2.7"
edition = "2024"

[dependencies]
franken-kernel = {{ version = "{decision_kernel_ver}", path = "../franken_kernel" }}
franken-evidence = {{ version = "{decision_evidence_ver}", path = "../franken_evidence" }}
"#
        ),
    );
    write_file(
        &root.join("franken_evidence/Cargo.toml"),
        r#"[package]
name = "franken-evidence"
version = "0.2.7"
edition = "2024"
"#,
    );
    write_file(
        &root.join("frankenlab/Cargo.toml"),
        r#"[package]
name = "frankenlab"
version = "0.2.7"
edition = "2024"

[dependencies]
asupersync = { version = "0.2.7", path = ".." }
"#,
    );
    write_file(&root.join("frankenlab/src/main.rs"), "fn main() {}\n");
    if with_examples {
        write_file(
            &root.join("frankenlab/examples/scenarios/01_race_condition.yaml"),
            "scenario: race\n",
        );
        write_file(
            &root.join("frankenlab/examples/scenarios/02_obligation_leak.yaml"),
            "scenario: obligation\n",
        );
        write_file(
            &root.join("frankenlab/examples/scenarios/03_saga_partition.yaml"),
            "scenario: partition\n",
        );
    }
}

// ---------------------------------------------------------------------------
// AsupersyncSurface enum tests
// ---------------------------------------------------------------------------

#[test]
fn surface_all_returns_four_variants() {
    let all = AsupersyncSurface::all();
    assert_eq!(all.len(), 4);
}

#[test]
fn surface_all_ordering_is_canonical() {
    let all = AsupersyncSurface::all();
    assert_eq!(all[0], AsupersyncSurface::KernelContext);
    assert_eq!(all[1], AsupersyncSurface::DecisionContract);
    assert_eq!(all[2], AsupersyncSurface::EvidenceLedger);
    assert_eq!(all[3], AsupersyncSurface::FrankenlabCli);
}

#[test]
fn surface_as_str_round_trips_with_display() {
    for surface in AsupersyncSurface::all() {
        assert_eq!(surface.as_str(), format!("{surface}"));
    }
}

#[test]
fn surface_as_str_values_are_snake_case() {
    assert_eq!(AsupersyncSurface::KernelContext.as_str(), "kernel_context");
    assert_eq!(
        AsupersyncSurface::DecisionContract.as_str(),
        "decision_contract"
    );
    assert_eq!(
        AsupersyncSurface::EvidenceLedger.as_str(),
        "evidence_ledger"
    );
    assert_eq!(AsupersyncSurface::FrankenlabCli.as_str(), "frankenlab_cli");
}

#[test]
fn surface_serde_roundtrip_all_variants() {
    for surface in AsupersyncSurface::all() {
        let json = serde_json::to_string(surface).unwrap();
        let back: AsupersyncSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*surface, back);
    }
}

#[test]
fn surface_clone_and_copy() {
    let s = AsupersyncSurface::KernelContext;
    let cloned = s.clone();
    let copied = s;
    assert_eq!(s, cloned);
    assert_eq!(s, copied);
}

#[test]
fn surface_ord_is_consistent_with_eq() {
    let a = AsupersyncSurface::KernelContext;
    let b = AsupersyncSurface::DecisionContract;
    assert_ne!(a, b);
    assert!(a != b);
}

// ---------------------------------------------------------------------------
// CompatibilityDisposition enum tests
// ---------------------------------------------------------------------------

#[test]
fn disposition_as_str_values() {
    assert_eq!(CompatibilityDisposition::Compatible.as_str(), "compatible");
    assert_eq!(
        CompatibilityDisposition::VersionDrift.as_str(),
        "version_drift"
    );
    assert_eq!(
        CompatibilityDisposition::MissingCapability.as_str(),
        "missing_capability"
    );
    assert_eq!(
        CompatibilityDisposition::BridgeIncompatible.as_str(),
        "bridge_incompatible"
    );
}

#[test]
fn disposition_display_matches_as_str() {
    let dispositions = [
        CompatibilityDisposition::Compatible,
        CompatibilityDisposition::VersionDrift,
        CompatibilityDisposition::MissingCapability,
        CompatibilityDisposition::BridgeIncompatible,
    ];
    for d in &dispositions {
        assert_eq!(d.as_str(), format!("{d}"));
    }
}

#[test]
fn disposition_serde_roundtrip() {
    let dispositions = [
        CompatibilityDisposition::Compatible,
        CompatibilityDisposition::VersionDrift,
        CompatibilityDisposition::MissingCapability,
        CompatibilityDisposition::BridgeIncompatible,
    ];
    for d in &dispositions {
        let json = serde_json::to_string(d).unwrap();
        let back: CompatibilityDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ---------------------------------------------------------------------------
// ContractFailureCode enum tests
// ---------------------------------------------------------------------------

#[test]
fn failure_code_all_returns_nine_variants() {
    let all = ContractFailureCode::all();
    assert_eq!(all.len(), 9);
}

#[test]
fn failure_code_as_str_nonempty() {
    for code in ContractFailureCode::all() {
        assert!(!code.as_str().is_empty(), "empty as_str for {code:?}");
    }
}

#[test]
fn failure_code_description_nonempty() {
    for code in ContractFailureCode::all() {
        assert!(
            !code.description().is_empty(),
            "empty description for {code:?}"
        );
    }
}

#[test]
fn failure_code_remediation_nonempty() {
    for code in ContractFailureCode::all() {
        assert!(
            !code.remediation().is_empty(),
            "empty remediation for {code:?}"
        );
    }
}

#[test]
fn failure_code_display_matches_as_str() {
    for code in ContractFailureCode::all() {
        assert_eq!(code.as_str(), format!("{code}"));
    }
}

#[test]
fn failure_code_serde_roundtrip() {
    for code in ContractFailureCode::all() {
        let json = serde_json::to_string(code).unwrap();
        let back: ContractFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

#[test]
fn failure_code_severity_is_assigned() {
    for code in ContractFailureCode::all() {
        let _severity = code.severity();
    }
}

#[test]
fn failure_code_required_response_is_assigned() {
    for code in ContractFailureCode::all() {
        let _response = code.required_response();
    }
}

// ---------------------------------------------------------------------------
// canonical_failure_code_catalog tests
// ---------------------------------------------------------------------------

#[test]
fn canonical_catalog_schema_version() {
    let catalog = canonical_failure_code_catalog();
    assert_eq!(catalog.schema_version, FAILURE_CODE_SCHEMA_VERSION);
}

#[test]
fn canonical_catalog_bead_id() {
    let catalog = canonical_failure_code_catalog();
    assert_eq!(catalog.bead_id, BEAD_ID);
}

#[test]
fn canonical_catalog_has_all_failure_codes() {
    let catalog = canonical_failure_code_catalog();
    assert_eq!(
        catalog.failure_codes.len(),
        ContractFailureCode::all().len()
    );
}

#[test]
fn canonical_catalog_failure_codes_match_enum() {
    let catalog = canonical_failure_code_catalog();
    let catalog_codes: Vec<ContractFailureCode> =
        catalog.failure_codes.iter().map(|fd| fd.code).collect();
    for code in ContractFailureCode::all() {
        assert!(
            catalog_codes.contains(code),
            "catalog missing code {code:?}"
        );
    }
}

#[test]
fn canonical_catalog_descriptors_consistent() {
    let catalog = canonical_failure_code_catalog();
    for fd in &catalog.failure_codes {
        assert_eq!(fd.description, fd.code.description());
        assert_eq!(fd.remediation, fd.code.remediation());
        assert_eq!(fd.severity, fd.code.severity());
        assert_eq!(fd.required_response, fd.code.required_response());
    }
}

#[test]
fn canonical_catalog_serde_roundtrip() {
    let catalog = canonical_failure_code_catalog();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: VersionDriftFailureCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

// ---------------------------------------------------------------------------
// build_asupersync_contract_matrix against real root
// ---------------------------------------------------------------------------

#[test]
fn real_root_matrix_schema_version() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.schema_version, SCHEMA_VERSION);
}

#[test]
fn real_root_matrix_bead_id() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.bead_id, BEAD_ID);
}

#[test]
fn real_root_matrix_has_four_releases() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.releases.len(), 4);
}

#[test]
fn real_root_matrix_releases_cover_all_surfaces() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for surface in AsupersyncSurface::all() {
        assert!(
            matrix.releases.iter().any(|r| r.surface == *surface),
            "missing release for surface {surface}"
        );
    }
}

#[test]
fn real_root_matrix_cells_cover_all_surfaces() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for surface in AsupersyncSurface::all() {
        assert!(
            matrix
                .compatibility_cells
                .iter()
                .any(|c| c.surface == *surface),
            "missing cell for surface {surface}"
        );
    }
}

#[test]
fn real_root_matrix_expected_release_cell_nonempty() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert!(!matrix.expected_release_cell.is_empty());
}

#[test]
fn real_root_matrix_report_hash_nonempty() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert!(!matrix.report_hash.is_empty());
}

#[test]
fn real_root_matrix_generated_at_matches_input() {
    let root = default_asupersync_root();
    let ts = 1_700_123_456_789;
    let matrix =
        build_asupersync_contract_matrix_with_generated_at(&root, ts, SecurityEpoch::GENESIS)
            .expect("build matrix");
    assert_eq!(matrix.generated_at_unix_ms, ts);
}

#[test]
fn real_root_matrix_is_deterministic_for_same_inputs() {
    let root = default_asupersync_root();
    let ts = 1_700_000_000_000;
    let epoch = SecurityEpoch::GENESIS;
    let m1 =
        build_asupersync_contract_matrix_with_generated_at(&root, ts, epoch).expect("build m1");
    let m2 =
        build_asupersync_contract_matrix_with_generated_at(&root, ts, epoch).expect("build m2");
    assert_eq!(m1.report_hash, m2.report_hash);
    assert_eq!(m1.compatible_surface_count, m2.compatible_surface_count);
    assert_eq!(m1.incompatible_surface_count, m2.incompatible_surface_count);
}

#[test]
fn real_root_matrix_serde_roundtrip() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let json = serde_json::to_string(&matrix).unwrap();
    let back: AsupersyncContractCompatMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

#[test]
fn real_root_matrix_compatible_count_consistent_with_cells() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let actual_compat = matrix
        .compatibility_cells
        .iter()
        .filter(|c| c.disposition == CompatibilityDisposition::Compatible)
        .count();
    assert_eq!(matrix.compatible_surface_count, actual_compat);
}

#[test]
fn real_root_matrix_incompatible_count_consistent_with_cells() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let actual_incompat = matrix
        .compatibility_cells
        .iter()
        .filter(|c| c.disposition != CompatibilityDisposition::Compatible)
        .count();
    assert_eq!(matrix.incompatible_surface_count, actual_incompat);
}

// ---------------------------------------------------------------------------
// build_asupersync_contract_matrix against fake roots
// ---------------------------------------------------------------------------

#[test]
fn fake_root_compatible_when_all_versions_match() {
    let root = unique_dir("compatible");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.compatibility_cells.len(), 4);
    for cell in &matrix.compatibility_cells {
        assert_eq!(
            cell.disposition,
            CompatibilityDisposition::Compatible,
            "surface {} not compatible",
            cell.surface
        );
        assert!(cell.diagnostic_codes.is_empty());
    }
}

#[test]
fn fake_root_decision_kernel_drift_detected() {
    let root = unique_dir("kernel_drift");
    write_root_with_options(&root, "0.3.0", "0.2.7", true);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let decision_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::DecisionContract)
        .expect("decision cell");
    assert!(
        decision_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::DecisionKernelVersionDrift)
    );
    assert_eq!(
        decision_cell.disposition,
        CompatibilityDisposition::VersionDrift
    );
}

#[test]
fn fake_root_decision_evidence_drift_detected() {
    let root = unique_dir("evidence_drift");
    write_root_with_options(&root, "0.2.7", "0.3.0", true);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let decision_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::DecisionContract)
        .expect("decision cell");
    assert!(
        decision_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::DecisionEvidenceVersionDrift)
    );
}

#[test]
fn fake_root_both_drifts_detected_simultaneously() {
    let root = unique_dir("both_drift");
    write_root_with_options(&root, "0.3.0", "0.3.0", true);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let decision_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::DecisionContract)
        .expect("decision cell");
    assert!(
        decision_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::DecisionKernelVersionDrift)
    );
    assert!(
        decision_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::DecisionEvidenceVersionDrift)
    );
}

#[test]
fn fake_root_missing_examples_detected() {
    let root = unique_dir("no_examples");
    write_root_with_options(&root, "0.2.7", "0.2.7", false);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab cell");
    assert!(
        frankenlab_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::FrankenlabExampleScenariosMissing)
    );
    assert_eq!(
        frankenlab_cell.disposition,
        CompatibilityDisposition::MissingCapability
    );
}

#[test]
fn fake_root_missing_examples_plus_drift() {
    let root = unique_dir("drift_and_missing");
    write_root_with_options(&root, "0.3.0", "0.2.7", false);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");

    let decision_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::DecisionContract)
        .expect("decision cell");
    assert_eq!(
        decision_cell.disposition,
        CompatibilityDisposition::VersionDrift
    );

    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab cell");
    assert_eq!(
        frankenlab_cell.disposition,
        CompatibilityDisposition::MissingCapability
    );
}

#[test]
fn fake_root_kernel_cell_compatible() {
    let root = unique_dir("kernel_compat");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let kernel_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::KernelContext)
        .expect("kernel cell");
    assert_eq!(
        kernel_cell.disposition,
        CompatibilityDisposition::Compatible
    );
}

#[test]
fn fake_root_evidence_cell_compatible() {
    let root = unique_dir("evidence_compat");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let evidence_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::EvidenceLedger)
        .expect("evidence cell");
    assert_eq!(
        evidence_cell.disposition,
        CompatibilityDisposition::Compatible
    );
}

#[test]
fn fake_root_releases_have_correct_package_names() {
    let root = unique_dir("pkg_names");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let kernel_rel = matrix
        .releases
        .iter()
        .find(|r| r.surface == AsupersyncSurface::KernelContext)
        .expect("kernel release");
    assert_eq!(kernel_rel.package_name, "franken-kernel");

    let decision_rel = matrix
        .releases
        .iter()
        .find(|r| r.surface == AsupersyncSurface::DecisionContract)
        .expect("decision release");
    assert_eq!(decision_rel.package_name, "franken-decision");

    let evidence_rel = matrix
        .releases
        .iter()
        .find(|r| r.surface == AsupersyncSurface::EvidenceLedger)
        .expect("evidence release");
    assert_eq!(evidence_rel.package_name, "franken-evidence");

    let frankenlab_rel = matrix
        .releases
        .iter()
        .find(|r| r.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab release");
    assert_eq!(frankenlab_rel.package_name, "frankenlab");
}

#[test]
fn fake_root_releases_have_version_0_2_7() {
    let root = unique_dir("ver_027");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for release in &matrix.releases {
        assert_eq!(
            release.release_id, "0.2.7",
            "unexpected version for surface {}",
            release.surface
        );
    }
}

#[test]
fn fake_root_releases_have_manifest_hashes() {
    let root = unique_dir("manifest_hashes");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for release in &matrix.releases {
        assert!(
            !release.manifest_hash.is_empty(),
            "empty hash for surface {}",
            release.surface
        );
    }
}

#[test]
fn fake_root_decision_release_has_dependency_versions() {
    let root = unique_dir("dep_versions");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let decision_rel = matrix
        .releases
        .iter()
        .find(|r| r.surface == AsupersyncSurface::DecisionContract)
        .expect("decision release");
    assert!(
        !decision_rel.dependency_versions.is_empty(),
        "decision should have dependency versions"
    );
}

#[test]
fn fake_root_cells_have_trace_ids() {
    let root = unique_dir("trace_ids");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for cell in &matrix.compatibility_cells {
        assert!(
            !cell.trace_id.is_empty(),
            "empty trace_id for surface {}",
            cell.surface
        );
    }
}

#[test]
fn fake_root_cells_have_version_cells() {
    let root = unique_dir("version_cells");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for cell in &matrix.compatibility_cells {
        assert!(
            !cell.version_cell.is_empty(),
            "empty version_cell for surface {}",
            cell.surface
        );
    }
}

// ---------------------------------------------------------------------------
// Missing manifest error paths
// ---------------------------------------------------------------------------

#[test]
fn missing_root_returns_error() {
    let root = unique_dir("nonexistent_root");
    let missing = root.join("totally_missing");
    let result = build_asupersync_contract_matrix_with_generated_at(
        &missing,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Bundle artifact emission tests
// ---------------------------------------------------------------------------

#[test]
fn bundle_emits_all_required_artifacts() {
    let out_dir = unique_dir("bundle_full");
    let root = default_asupersync_root();
    let args = vec![
        "test_binary".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    assert!(artifacts.compat_matrix_path.exists());
    assert!(artifacts.failure_codes_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.summary_path.exists());
    assert!(artifacts.env_path.exists());
    assert!(artifacts.repro_lock_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.step_logs_dir.exists());
}

#[test]
fn bundle_compat_matrix_is_valid_json() {
    let out_dir = unique_dir("bundle_json");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let content = fs::read_to_string(&artifacts.compat_matrix_path).expect("read matrix");
    let _parsed: serde_json::Value = serde_json::from_str(&content).expect("parse json");
}

#[test]
fn bundle_failure_codes_is_valid_json() {
    let out_dir = unique_dir("bundle_codes_json");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let content = fs::read_to_string(&artifacts.failure_codes_path).expect("read codes");
    let _parsed: serde_json::Value = serde_json::from_str(&content).expect("parse json");
}

#[test]
fn bundle_events_contain_surface_verification() {
    let out_dir = unique_dir("bundle_events");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    assert!(events.contains("surface_verification"));
}

#[test]
fn bundle_commands_contain_rch() {
    let out_dir = unique_dir("bundle_commands");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let commands = fs::read_to_string(&artifacts.commands_path).expect("read commands");
    assert!(commands.contains("rch exec"));
}

#[test]
fn bundle_summary_contains_markdown() {
    let out_dir = unique_dir("bundle_summary");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let summary = fs::read_to_string(&artifacts.summary_path).expect("read summary");
    assert!(summary.contains('#'));
}

#[test]
fn bundle_report_hash_nonempty() {
    let out_dir = unique_dir("bundle_hash");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");
    assert!(!artifacts.report_hash.is_empty());
}

#[test]
fn bundle_compatible_surface_count_is_four() {
    let out_dir = unique_dir("bundle_count");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");
    assert_eq!(artifacts.compatible_surface_count, 4);
}

// ---------------------------------------------------------------------------
// default_asupersync_root tests
// ---------------------------------------------------------------------------

#[test]
fn default_root_path_matches_constant() {
    let root = default_asupersync_root();
    assert_eq!(root, PathBuf::from(DEFAULT_ASUPERSYNC_ROOT));
}

// ---------------------------------------------------------------------------
// Constants tests
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn failure_code_schema_version_format() {
    assert!(FAILURE_CODE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(FAILURE_CODE_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn bead_id_is_expected() {
    assert_eq!(BEAD_ID, "bd-3nr.1.5.1");
}

#[test]
fn component_name_is_expected() {
    assert_eq!(COMPONENT, "asupersync_contract_matrix");
}

// ---------------------------------------------------------------------------
// UpstreamReleaseIdentifier serde tests
// ---------------------------------------------------------------------------

#[test]
fn upstream_release_identifier_serde_roundtrip() {
    let root = unique_dir("release_serde");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for release in &matrix.releases {
        let json = serde_json::to_string(release).unwrap();
        let back: UpstreamReleaseIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(*release, back);
    }
}

// ---------------------------------------------------------------------------
// CompatibilityCell serde tests
// ---------------------------------------------------------------------------

#[test]
fn compatibility_cell_serde_roundtrip() {
    let root = unique_dir("cell_serde");
    write_standard_root(&root);
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    for cell in &matrix.compatibility_cells {
        let json = serde_json::to_string(cell).unwrap();
        let back: CompatibilityCell = serde_json::from_str(&json).unwrap();
        assert_eq!(*cell, back);
    }
}

// ---------------------------------------------------------------------------
// Error display tests
// ---------------------------------------------------------------------------

#[test]
fn error_io_display() {
    let err = AsupersyncContractMatrixError::Io {
        path: PathBuf::from("/tmp/test"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/test"));
    assert!(display.contains("not found"));
}

#[test]
fn error_manifest_parse_display() {
    let err = AsupersyncContractMatrixError::ManifestParse {
        path: PathBuf::from("/tmp/Cargo.toml"),
        reason: "bad toml".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/Cargo.toml"));
    assert!(display.contains("bad toml"));
}

#[test]
fn error_missing_field_display() {
    let err = AsupersyncContractMatrixError::MissingField {
        path: PathBuf::from("/tmp/Cargo.toml"),
        field: "version",
    };
    let display = format!("{err}");
    assert!(display.contains("version"));
    assert!(display.contains("/tmp/Cargo.toml"));
}

// ---------------------------------------------------------------------------
// FailureCodeDescriptor serde tests
// ---------------------------------------------------------------------------

#[test]
fn failure_code_descriptor_serde_roundtrip() {
    let catalog = canonical_failure_code_catalog();
    for fd in &catalog.failure_codes {
        let json = serde_json::to_string(fd).unwrap();
        let back: FailureCodeDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(*fd, back);
    }
}

// ---------------------------------------------------------------------------
// ContractEvent serde tests
// ---------------------------------------------------------------------------

#[test]
fn contract_event_serde_roundtrip() {
    let out_dir = unique_dir("event_serde");
    let root = default_asupersync_root();
    let args = vec!["test".to_string()];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &root, &args).expect("write bundle");

    let events_str = fs::read_to_string(&artifacts.events_path).expect("read events");
    for line in events_str.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: ContractEvent = serde_json::from_str(line).expect("parse event line");
        let json = serde_json::to_string(&event).unwrap();
        let back: ContractEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn fake_root_matrix_hash_deterministic() {
    let root = unique_dir("det_hash");
    write_standard_root(&root);
    let m1 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("m1");
    let m2 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("m2");
    assert_eq!(m1.report_hash, m2.report_hash);
}

#[test]
fn different_timestamps_produce_different_hashes() {
    let root = unique_dir("diff_ts");
    write_standard_root(&root);
    let m1 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("m1");
    let m2 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_001,
        SecurityEpoch::GENESIS,
    )
    .expect("m2");
    assert_ne!(m1.report_hash, m2.report_hash);
}

#[test]
fn different_epochs_produce_different_hashes() {
    let root = unique_dir("diff_epoch");
    write_standard_root(&root);
    let m1 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("m1");
    let m2 = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::from_raw(5),
    )
    .expect("m2");
    assert_ne!(m1.report_hash, m2.report_hash);
}
