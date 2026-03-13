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
    AsupersyncSurface, CompatibilityDisposition, ContractFailureCode,
    build_asupersync_contract_matrix_with_generated_at, default_asupersync_root,
    write_asupersync_contract_bundle,
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
