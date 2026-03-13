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

use frankenengine_engine::asupersync_contract_matrix::{
    AsupersyncSurface, BEAD_ID, COMPONENT, CompatibilityDisposition, ContractFailureCode,
    DEFAULT_ASUPERSYNC_ROOT, FAILURE_CODE_SCHEMA_VERSION, SCHEMA_VERSION,
    build_asupersync_contract_matrix, build_asupersync_contract_matrix_with_generated_at,
    canonical_failure_code_catalog, default_asupersync_root, write_asupersync_contract_bundle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use uuid::Uuid;

fn unique_temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("franken_engine_asupersync_contract_matrix");
    path.push(name);
    path.push(Uuid::now_v7().to_string());
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, contents).expect("write test file");
}

fn write_fake_asupersync_root(root: &Path, decision_kernel_version: &str, with_examples: bool) {
    write_fake_asupersync_root_with_frankenlab(
        root,
        decision_kernel_version,
        with_examples,
        "0.2.7",
        "0.2.7",
        "src/main.rs",
    );
}

fn write_fake_asupersync_root_with_frankenlab(
    root: &Path,
    decision_kernel_version: &str,
    with_examples: bool,
    frankenlab_package_version: &str,
    frankenlab_asupersync_version: &str,
    frankenlab_cli_path: &str,
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
franken-kernel = {{ version = "{decision_kernel_version}", path = "../franken_kernel" }}
franken-evidence = {{ version = "0.2.7", path = "../franken_evidence" }}
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
        &format!(
            r#"[package]
name = "frankenlab"
version = "{frankenlab_package_version}"
edition = "2024"

[[bin]]
name = "frankenlab"
path = "{frankenlab_cli_path}"

[dependencies]
asupersync = {{ version = "{frankenlab_asupersync_version}", path = ".." }}
"#
        ),
    );
    write_file(
        &root.join("frankenlab").join(frankenlab_cli_path),
        "fn main() {}\n",
    );
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

#[test]
fn actual_asupersync_root_builds_four_compatible_surfaces() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_123_456,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.compatibility_cells.len(), 4);
    assert_eq!(matrix.releases.len(), 4);
    assert!(!matrix.expected_release_cell.is_empty());
    assert!(
        matrix
            .compatibility_cells
            .iter()
            .all(|cell| { matches!(cell.disposition, CompatibilityDisposition::Compatible) })
    );
}

#[test]
fn decision_kernel_version_drift_is_reported_from_fake_root() {
    let root = unique_temp_dir("fake_root_drift");
    write_fake_asupersync_root(&root, "0.2.8", true);

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_123_456,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let decision_cell = matrix
        .compatibility_cells
        .iter()
        .find(|cell| cell.surface == AsupersyncSurface::DecisionContract)
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
fn frankenlab_missing_examples_is_reported_from_fake_root() {
    let root = unique_temp_dir("fake_root_missing_examples");
    write_fake_asupersync_root(&root, "0.2.7", false);

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_123_456,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|cell| cell.surface == AsupersyncSurface::FrankenlabCli)
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
fn frankenlab_dependency_is_compared_to_release_cell_not_local_package_version() {
    let root = unique_temp_dir("fake_root_frankenlab_release_drift_only");
    write_fake_asupersync_root_with_frankenlab(
        &root,
        "0.2.7",
        true,
        "0.2.8",
        "0.2.7",
        "src/main.rs",
    );

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_123_456,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|cell| cell.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab cell");
    assert!(
        frankenlab_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::AsupersyncReleaseCellDrift)
    );
    assert!(
        !frankenlab_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::FrankenlabAsupersyncVersionDrift)
    );
}

#[test]
fn frankenlab_manifest_bin_path_satisfies_cli_probe() {
    let root = unique_temp_dir("fake_root_manifest_bin_path");
    write_fake_asupersync_root_with_frankenlab(
        &root,
        "0.2.7",
        true,
        "0.2.7",
        "0.2.7",
        "src/bin/frankenlab.rs",
    );

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_123_456,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|cell| cell.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab cell");
    assert!(
        !frankenlab_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::FrankenlabCliMissing)
    );
}

#[test]
fn bundle_writer_emits_required_artifacts_and_rch_commands() {
    let out_dir = unique_temp_dir("bundle_output");
    let args = vec![
        "franken_asupersync_contract_matrix".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &default_asupersync_root(), &args)
        .expect("write bundle");

    for path in [
        &artifacts.compat_matrix_path,
        &artifacts.failure_codes_path,
        &artifacts.run_manifest_path,
        &artifacts.events_path,
        &artifacts.commands_path,
        &artifacts.summary_path,
        &artifacts.env_path,
        &artifacts.repro_lock_path,
        &artifacts.trace_ids_path,
    ] {
        assert!(path.exists(), "missing artifact {}", path.display());
    }
    assert!(artifacts.step_logs_dir.exists());

    let commands = fs::read_to_string(&artifacts.commands_path).expect("read commands");
    assert!(commands.contains("rch exec --"));
    assert!(commands.contains("run_asupersync_contract_matrix.sh"));
    assert!(commands.contains("asupersync_contract_matrix_enrichment_integration"));

    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    assert!(events.contains("\"event\":\"surface_verification\""));
}

// ---------------------------------------------------------------------------
// Enrichment tests: enum introspection, catalog validation, schema constants
// ---------------------------------------------------------------------------

#[test]
fn surface_all_returns_exactly_four_variants() {
    let all = AsupersyncSurface::all();
    assert_eq!(all.len(), 4);
    let expected = [
        AsupersyncSurface::KernelContext,
        AsupersyncSurface::DecisionContract,
        AsupersyncSurface::EvidenceLedger,
        AsupersyncSurface::FrankenlabCli,
    ];
    for variant in &expected {
        assert!(all.contains(variant), "missing surface variant {variant}");
    }
}

#[test]
fn surface_as_str_round_trips_display() {
    for surface in AsupersyncSurface::all() {
        let s = surface.as_str();
        assert!(!s.is_empty(), "as_str must not be empty");
        assert_eq!(format!("{surface}"), s, "Display must match as_str");
    }
}

#[test]
fn disposition_as_str_is_nonempty_for_all_variants() {
    let variants = [
        CompatibilityDisposition::Compatible,
        CompatibilityDisposition::VersionDrift,
        CompatibilityDisposition::MissingCapability,
        CompatibilityDisposition::BridgeIncompatible,
    ];
    for d in &variants {
        assert!(!d.as_str().is_empty());
        assert_eq!(format!("{d}"), d.as_str());
    }
}

#[test]
fn failure_code_all_returns_nine_variants() {
    let all = ContractFailureCode::all();
    assert_eq!(all.len(), 9);
    for code in all {
        assert!(!code.as_str().is_empty());
        assert!(!code.description().is_empty());
        assert!(!code.remediation().is_empty());
    }
}

#[test]
fn failure_code_display_matches_as_str() {
    for code in ContractFailureCode::all() {
        assert_eq!(format!("{code}"), code.as_str());
    }
}

#[test]
fn canonical_catalog_covers_all_failure_codes() {
    let catalog = canonical_failure_code_catalog();
    assert_eq!(catalog.schema_version, FAILURE_CODE_SCHEMA_VERSION);
    assert_eq!(catalog.bead_id, BEAD_ID);
    assert_eq!(
        catalog.failure_codes.len(),
        ContractFailureCode::all().len()
    );
    for code in ContractFailureCode::all() {
        assert!(
            catalog.failure_codes.iter().any(|fd| fd.code == *code),
            "catalog missing failure code {code}"
        );
    }
}

#[test]
fn canonical_catalog_descriptors_are_self_consistent() {
    let catalog = canonical_failure_code_catalog();
    for fd in &catalog.failure_codes {
        assert_eq!(fd.description, fd.code.description());
        assert_eq!(fd.remediation, fd.code.remediation());
        assert_eq!(fd.severity, fd.code.severity());
        assert_eq!(fd.required_response, fd.code.required_response());
    }
}

#[test]
fn schema_version_constants_are_nonempty_and_prefixed() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(FAILURE_CODE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!DEFAULT_ASUPERSYNC_ROOT.is_empty());
}

#[test]
fn matrix_schema_and_bead_id_match_constants() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    assert_eq!(matrix.schema_version, SCHEMA_VERSION);
    assert_eq!(matrix.bead_id, BEAD_ID);
    assert_eq!(matrix.asupersync_root, root.display().to_string());
}

#[test]
fn matrix_surface_counts_reflect_dispositions() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build matrix");
    let compatible = matrix
        .compatibility_cells
        .iter()
        .filter(|c| c.disposition == CompatibilityDisposition::Compatible)
        .count();
    let incompatible = matrix.compatibility_cells.len() - compatible;
    assert_eq!(matrix.compatible_surface_count, compatible);
    assert_eq!(matrix.incompatible_surface_count, incompatible);
}

#[test]
fn matrix_report_hash_is_deterministic_for_same_inputs() {
    let root = default_asupersync_root();
    let ts = 1_700_000_000_000_u64;
    let m1 = build_asupersync_contract_matrix_with_generated_at(&root, ts, SecurityEpoch::GENESIS)
        .expect("build 1");
    let m2 = build_asupersync_contract_matrix_with_generated_at(&root, ts, SecurityEpoch::GENESIS)
        .expect("build 2");
    assert_eq!(m1.report_hash, m2.report_hash);
    assert!(!m1.report_hash.is_empty());
}

#[test]
fn matrix_generated_at_timestamp_and_epoch_are_stored() {
    let root = default_asupersync_root();
    let ts = 1_700_123_456_789_u64;
    let epoch = SecurityEpoch::from_raw(42);
    let matrix =
        build_asupersync_contract_matrix_with_generated_at(&root, ts, epoch).expect("build");
    assert_eq!(matrix.generated_at_unix_ms, ts);
    assert_eq!(matrix.epoch, epoch.as_u64());
}

#[test]
fn build_without_generated_at_uses_genesis_epoch() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix(&root).expect("build default");
    assert_eq!(matrix.epoch, SecurityEpoch::GENESIS.as_u64());
    assert!(matrix.generated_at_unix_ms > 0);
}

#[test]
fn each_cell_has_nonempty_trace_id_and_version_cell() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build");
    for cell in &matrix.compatibility_cells {
        assert!(
            !cell.trace_id.is_empty(),
            "cell for {} missing trace_id",
            cell.surface
        );
        assert!(
            !cell.version_cell.is_empty(),
            "cell for {} missing version_cell",
            cell.surface
        );
        assert!(!cell.package_name.is_empty());
        assert!(!cell.crate_name.is_empty());
        assert!(!cell.manifest_path.is_empty());
        assert!(!cell.release_id.is_empty());
    }
}

#[test]
fn each_release_has_nonempty_identifiers() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build");
    for release in &matrix.releases {
        assert!(!release.package_name.is_empty());
        assert!(!release.crate_name.is_empty());
        assert!(!release.manifest_path.is_empty());
        assert!(!release.release_id.is_empty());
        assert!(!release.manifest_hash.is_empty());
    }
}

#[test]
fn matrix_serializes_to_valid_json_and_deserializes_back() {
    let root = default_asupersync_root();
    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build");
    let json = serde_json::to_string(&matrix).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    assert_eq!(parsed["bead_id"], BEAD_ID);
    assert_eq!(parsed["compatibility_cells"].as_array().unwrap().len(), 4);
}

#[test]
fn catalog_serializes_to_valid_json() {
    let catalog = canonical_failure_code_catalog();
    let json = serde_json::to_string(&catalog).expect("serialize catalog");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(
        parsed["failure_codes"].as_array().unwrap().len(),
        ContractFailureCode::all().len()
    );
}

#[test]
fn frankenlab_asupersync_version_drift_detected() {
    let root = unique_temp_dir("fake_root_asupersync_ver_drift");
    write_fake_asupersync_root_with_frankenlab(
        &root,
        "0.2.7",
        true,
        "0.2.7",
        "0.3.0",
        "src/main.rs",
    );

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build");
    let frankenlab_cell = matrix
        .compatibility_cells
        .iter()
        .find(|c| c.surface == AsupersyncSurface::FrankenlabCli)
        .expect("frankenlab cell");
    assert!(
        frankenlab_cell
            .diagnostic_codes
            .contains(&ContractFailureCode::FrankenlabAsupersyncVersionDrift)
    );
}

#[test]
fn fully_compatible_fake_root_has_all_compatible_dispositions() {
    let root = unique_temp_dir("fake_root_all_compat");
    write_fake_asupersync_root(&root, "0.2.7", true);

    let matrix = build_asupersync_contract_matrix_with_generated_at(
        &root,
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    )
    .expect("build");
    assert_eq!(matrix.compatible_surface_count, 4);
    assert_eq!(matrix.incompatible_surface_count, 0);
    for cell in &matrix.compatibility_cells {
        assert_eq!(cell.disposition, CompatibilityDisposition::Compatible);
        assert!(cell.diagnostic_codes.is_empty());
    }
}

#[test]
fn nonexistent_root_returns_io_error() {
    let result = build_asupersync_contract_matrix_with_generated_at(
        Path::new("/nonexistent/asupersync/root/that/does/not/exist"),
        1_700_000_000_000,
        SecurityEpoch::GENESIS,
    );
    assert!(result.is_err());
}

#[test]
fn bundle_artifacts_report_hash_matches_matrix() {
    let out_dir = unique_temp_dir("bundle_hash_check");
    let args = vec![
        "franken_asupersync_contract_matrix".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &default_asupersync_root(), &args)
        .expect("write bundle");
    assert!(!artifacts.report_hash.is_empty());
    assert_eq!(artifacts.compatible_surface_count, 4);
}

#[test]
fn bundle_trace_ids_file_has_expected_line_count() {
    let out_dir = unique_temp_dir("bundle_traces");
    let args = vec![
        "franken_asupersync_contract_matrix".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &default_asupersync_root(), &args)
        .expect("write bundle");
    let trace_ids = fs::read_to_string(&artifacts.trace_ids_path).expect("read trace_ids");
    assert!(
        trace_ids.lines().count() >= 4,
        "should have at least one trace per surface"
    );
}

#[test]
fn bundle_events_are_valid_json_lines() {
    let out_dir = unique_temp_dir("bundle_events_json");
    let args = vec![
        "franken_asupersync_contract_matrix".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
    ];
    let artifacts = write_asupersync_contract_bundle(&out_dir, &default_asupersync_root(), &args)
        .expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read events");
    for line in events.lines() {
        let event: serde_json::Value =
            serde_json::from_str(line).expect("each event must be valid JSON");
        assert_eq!(event["component"], COMPONENT);
    }
}
