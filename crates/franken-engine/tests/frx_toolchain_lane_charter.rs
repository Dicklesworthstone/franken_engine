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

use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_toolchain_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Toolchain/Ecosystem Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Supported Integration Profiles",
        "## Migration and Rollout Controls",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "toolchain lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "conservative compatibility mode",
        "compatibility class",
        "Rollout toggles (`file`, `component`, `route`, `policy`)",
        "safe defaults",
        "block promotion",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "toolchain lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_toolchain_lane_contract_is_machine_readable_and_fail_safe() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.toolchain.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.6"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.6"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.6"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("conservative_compatibility")
    );
    assert_eq!(
        value["failure_policy"]["auto_route_on_instability"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_on_persistent_instability"].as_bool(),
        Some(true)
    );

    let rollout_axes =
        value["ownership"]["incremental_adoption_controls"]["supported_rollout_axes"]
            .as_array()
            .expect("supported_rollout_axes must be an array");
    let expected_axes = ["file", "component", "route", "policy"];
    for axis in expected_axes {
        assert!(
            rollout_axes
                .iter()
                .any(|entry| entry.as_str() == Some(axis)),
            "rollout axis missing: {axis}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_toolchain_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["toolchain_lane_charter"].as_str(),
        Some("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["toolchain_lane_contract"].as_str(),
        Some("docs/frx_toolchain_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn toolchain_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn toolchain_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn toolchain_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.6"));
}

#[test]
fn toolchain_contract_has_rollout_axes() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let axes = value["ownership"]["incremental_adoption_controls"]["supported_rollout_axes"]
        .as_array()
        .expect("rollout axes");
    assert!(!axes.is_empty());
}

#[test]
fn toolchain_contract_failure_mode_is_conservative_compatibility() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("conservative_compatibility")
    );
}

#[test]
fn toolchain_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn toolchain_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn toolchain_contract_has_ownership_section() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["ownership"].is_object());
}

#[test]
fn toolchain_charter_mentions_compatibility() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("compatibility"));
}

#[test]
fn toolchain_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn toolchain_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn toolchain_contract_has_failure_policy_mode() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["failure_policy"].is_object());
    assert!(
        !value["failure_policy"]["mode"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
}

#[test]
fn toolchain_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn toolchain_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn toolchain_contract_has_release_gate_contract() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["release_gate_contract"].is_object());
}

#[test]
fn toolchain_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn toolchain_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn toolchain_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn toolchain_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn toolchain_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn toolchain_charter_mentions_ecosystem() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("ecosystem"));
}

// ---------- enrichment: deeper structural and edge-case checks ----------

#[test]
fn toolchain_contract_release_gate_requires_promotion_green_or_waiver() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["release_gate_contract"]["promotion_requires_green_or_explicit_waiver"].as_bool(),
        Some(true),
        "release gate must require green or explicit waiver for promotion"
    );
    assert_eq!(
        value["release_gate_contract"]["rollback_path_required"].as_bool(),
        Some(true),
        "release gate must require rollback path"
    );
}

#[test]
fn toolchain_contract_logging_fields_include_core_observability_set() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    let field_set: std::collections::BTreeSet<&str> =
        fields.iter().filter_map(|v| v.as_str()).collect();
    for required in ["trace_id", "decision_id", "component", "event", "outcome"] {
        assert!(
            field_set.contains(required),
            "logging_contract missing required field: {required}"
        );
    }
}

#[test]
fn toolchain_contract_status_is_active() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["status"].as_str(),
        Some("active"),
        "toolchain contract status must be active"
    );
}

#[test]
fn toolchain_contract_auto_route_on_instability_is_enabled() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["auto_route_on_instability"].as_bool(),
        Some(true),
        "failure policy must auto-route on instability"
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_on_persistent_instability"].as_bool(),
        Some(true),
        "failure policy must block promotion on persistent instability"
    );
}

#[test]
fn toolchain_contract_serde_roundtrip_via_value_preserves_all_keys() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let serialized = serde_json::to_string_pretty(&value).expect("serialize");
    let reparsed: Value = serde_json::from_str(&serialized).expect("reparse");
    let original_keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let reparsed_keys: Vec<&str> = reparsed
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        original_keys, reparsed_keys,
        "serde roundtrip must preserve all top-level keys"
    );
    assert_eq!(value, reparsed);
}

// ---------- enrichment: additional structural and semantic checks ----------

#[test]
fn toolchain_contract_has_incremental_adoption_controls_section() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["ownership"]["incremental_adoption_controls"].is_object(),
        "contract must have ownership.incremental_adoption_controls section"
    );
}

#[test]
fn toolchain_contract_rollout_axes_include_all_required_axes() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let axes = value["ownership"]["incremental_adoption_controls"]["supported_rollout_axes"]
        .as_array()
        .expect("rollout axes array");
    let axis_set: std::collections::BTreeSet<&str> =
        axes.iter().filter_map(|v| v.as_str()).collect();
    for required in ["file", "component", "route", "policy"] {
        assert!(
            axis_set.contains(required),
            "rollout axis missing: {required}"
        );
    }
}

#[test]
fn toolchain_charter_doc_references_interface_contracts_section() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(
        doc.contains("## Interface Contracts"),
        "charter must have an Interface Contracts section"
    );
}

#[test]
fn toolchain_charter_mentions_rollout_toggles() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(
        doc.contains("Rollout toggles"),
        "charter must mention rollout toggles"
    );
}

#[test]
fn toolchain_contract_failure_policy_blocks_promotion_on_persistent_instability() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["block_promotion_on_persistent_instability"].as_bool(),
        Some(true),
        "failure_policy must block promotion on persistent instability"
    );
}
