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

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::asupersync_contract_matrix::DEFAULT_ASUPERSYNC_ROOT;
use frankenengine_engine::cross_repo_contract::integration_point_inventory;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_repo_text(relative_path: &str) -> String {
    let path = repo_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_contract() -> Value {
    serde_json::from_str(&read_repo_text("docs/cross_repo_integration_suite_v1.json"))
        .expect("cross-repo integration suite contract should parse")
}

#[test]
fn cross_repo_integration_suite_doc_contains_required_sections() {
    let doc = read_repo_text("docs/CROSS_REPO_INTEGRATION_SUITE.md");
    let required_sections = [
        "# Cross-Repo Integration Suite (`bd-1mgd`)",
        "## Scope",
        "## Covered Boundaries",
        "## Suite Composition",
        "## Degraded-Mode and Drift Expectations",
        "## Machine-Readable Contract",
        "## RCH-Only Operator Commands",
        "## Reproducibility Artifacts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "cross-repo integration suite doc missing section: {section}"
        );
    }

    assert!(doc.contains("./scripts/run_cross_repo_integration_suite.sh ci"));
    assert!(doc.contains("./scripts/e2e/cross_repo_integration_suite_replay.sh"));
    assert!(doc.contains("docs/cross_repo_integration_suite_v1.json"));
}

#[test]
fn cross_repo_integration_suite_contract_is_machine_readable() {
    let value = load_contract();

    assert_eq!(
        value["schema_version"].as_str(),
        Some("franken-engine.cross-repo-integration-suite.contract.v1")
    );
    assert_eq!(value["bead_id"].as_str(), Some("bd-1mgd"));
    assert_eq!(
        value["component"].as_str(),
        Some("cross_repo_integration_suite")
    );
    assert_eq!(
        value["suite_script"].as_str(),
        Some("./scripts/run_cross_repo_integration_suite.sh")
    );
    assert_eq!(
        value["replay_script"].as_str(),
        Some("./scripts/e2e/cross_repo_integration_suite_replay.sh")
    );
    assert_eq!(
        value["artifact_root"].as_str(),
        Some("artifacts/cross_repo_integration_suite")
    );

    let structured_log_fields = value["structured_log_fields"]
        .as_array()
        .expect("structured_log_fields should be array")
        .iter()
        .filter_map(|field| field.as_str())
        .collect::<BTreeSet<_>>();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            structured_log_fields.contains(field),
            "missing structured log field {field}"
        );
    }
}

#[test]
fn cross_repo_integration_suite_contract_boundaries_have_existing_targets() {
    let value = load_contract();
    let boundaries = value["boundaries"]
        .as_array()
        .expect("boundaries should be an array");

    let ids = boundaries
        .iter()
        .filter_map(|boundary| boundary["boundary"].as_str())
        .collect::<BTreeSet<_>>();
    for boundary in [
        "asupersync",
        "frankentui",
        "frankensqlite",
        "fastapi_rust",
        "sqlmodel_rust",
    ] {
        assert!(ids.contains(boundary), "missing boundary {boundary}");
    }

    for boundary in boundaries {
        let test_targets = boundary["test_targets"]
            .as_array()
            .expect("boundary test_targets should be array");
        assert!(
            !test_targets.is_empty(),
            "boundary must declare at least one target"
        );
        for target in test_targets {
            let target_name = target.as_str().expect("test target should be string");
            let target_path = repo_root()
                .join("crates/franken-engine/tests")
                .join(format!("{target_name}.rs"));
            assert!(
                target_path.is_file(),
                "missing target file {}",
                target_path.display()
            );
        }
    }

    let asupersync = boundaries
        .iter()
        .find(|boundary| boundary["boundary"].as_str() == Some("asupersync"))
        .expect("asupersync boundary exists");
    assert_eq!(
        asupersync["repo_path"].as_str(),
        Some(DEFAULT_ASUPERSYNC_ROOT)
    );
    let suite_commands = asupersync["suite_commands"]
        .as_array()
        .expect("suite_commands should be array");
    assert!(
        suite_commands.iter().any(|command| {
            command
                .as_str()
                .is_some_and(|command| command.contains("run_asupersync_contract_matrix.sh"))
        }),
        "asupersync boundary must reference the matrix bundle command"
    );
}

#[test]
fn cross_repo_integration_suite_contract_aligns_with_runtime_inventory() {
    let inventory = integration_point_inventory();
    for boundary in [
        "frankentui",
        "frankensqlite",
        "fastapi_rust",
        "sqlmodel_rust",
    ] {
        assert!(
            inventory.contains_key(boundary),
            "runtime inventory missing boundary {boundary}"
        );
    }

    let value = load_contract();
    let shared_targets = value["shared_contract_targets"]
        .as_array()
        .expect("shared_contract_targets should be array")
        .iter()
        .filter_map(|target| target.as_str())
        .collect::<BTreeSet<_>>();
    for target in [
        "cross_repo_integration_suite",
        "cross_repo_contract_integration",
        "cross_repo_contract_enrichment_integration",
        "cross_repo_contract_edge_cases",
        "sibling_integration_benchmark_gate_integration",
    ] {
        assert!(
            shared_targets.contains(target),
            "missing shared target {target}"
        );
        let target_path = repo_root()
            .join("crates/franken-engine/tests")
            .join(format!("{target}.rs"));
        assert!(
            target_path.is_file(),
            "missing shared target file {}",
            target_path.display()
        );
    }
}

#[test]
fn cross_repo_integration_suite_readme_entry_present() {
    let readme = read_repo_text("README.md");

    assert!(
        readme.contains("## Cross-Repo Integration Suite"),
        "README missing cross-repo integration suite heading"
    );
    assert!(
        readme.contains("./scripts/run_cross_repo_integration_suite.sh ci"),
        "README missing cross-repo integration suite command"
    );
    assert!(
        readme.contains("./scripts/e2e/cross_repo_integration_suite_replay.sh"),
        "README missing cross-repo integration replay command"
    );
}

#[test]
fn cross_repo_integration_suite_runner_and_replay_scripts_reference_expected_commands() {
    let runner = read_repo_text("scripts/run_cross_repo_integration_suite.sh");
    let replay = read_repo_text("scripts/e2e/cross_repo_integration_suite_replay.sh");

    for fragment in [
        "rch exec --",
        "cross_repo_contract_integration",
        "cross_repo_contract_enrichment_integration",
        "cross_repo_contract_edge_cases",
        "asupersync_contract_matrix_integration",
        "asupersync_contract_matrix_enrichment_integration",
        "frankentui_adapter_integration",
        "frankentui_adapter_enrichment_integration",
        "storage_adapter_integration",
        "storage_adapter_enrichment_integration",
        "service_endpoint_template_integration",
        "sibling_integration_benchmark_gate_integration",
        "sqlmodel_rust_boundary",
        "run_asupersync_contract_matrix.sh",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
    ] {
        assert!(
            runner.contains(fragment),
            "runner missing required fragment: {fragment}"
        );
    }

    assert!(replay.contains("run_cross_repo_integration_suite.sh"));
    assert!(replay.contains("mode=\"${1:-ci}\""));
}

#[test]
fn cross_repo_integration_suite_operator_verification_commands_are_present() {
    let value = load_contract();
    let operator_verification = value["operator_verification"]
        .as_array()
        .expect("operator_verification should be array")
        .iter()
        .filter_map(|command| command.as_str())
        .collect::<Vec<_>>();

    assert!(operator_verification
        .iter()
        .any(|command| command.contains("./scripts/run_cross_repo_integration_suite.sh ci")));
    assert!(operator_verification
        .iter()
        .any(|command| command.contains("./scripts/e2e/cross_repo_integration_suite_replay.sh")));
    assert!(operator_verification
        .iter()
        .any(|command| command.contains("run_manifest.json")));
    assert!(operator_verification
        .iter()
        .any(|command| command.contains("events.jsonl")));
    assert!(operator_verification
        .iter()
        .any(|command| command.contains("commands.txt")));
}
