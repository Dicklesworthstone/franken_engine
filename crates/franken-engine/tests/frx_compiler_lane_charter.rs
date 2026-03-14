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
fn frx_compiler_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Compiler/FRIR Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## FRIR Schema Governance",
        "## Pass Witness Obligations",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "compiler lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "SWC/OXC parity obligations",
        "Deterministic FRIR artifacts",
        "Missing or malformed witness metadata blocks activation.",
        "fail-closed",
        "deterministic fallback",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "compiler lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_compiler_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.compiler.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.2"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.2"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.2"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_verification_or_fallback_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_reuse_scan_outcome"].as_bool(),
        Some(true)
    );

    let witness_fields = value["outputs"]["pass_witness_bundle"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_witness_fields = [
        "pass_id",
        "input_hash",
        "output_hash",
        "invariant_results",
        "budget_summary",
        "replay_linkage",
    ];
    for field in expected_witness_fields {
        assert!(
            witness_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "pass witness field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_compiler_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["compiler_lane_charter"].as_str(),
        Some("docs/FRX_COMPILER_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["compiler_lane_contract"].as_str(),
        Some("docs/frx_compiler_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn compiler_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn compiler_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn compiler_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.2"));
}

#[test]
fn compiler_contract_has_outputs_with_pass_witness() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["pass_witness_bundle"].is_object());
}

#[test]
fn compiler_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn compiler_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn compiler_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn compiler_contract_has_failure_policy_mode() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
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
fn compiler_charter_mentions_frir() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRIR"));
}

#[test]
fn compiler_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn compiler_charter_mentions_swc_oxc() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("SWC/OXC"));
}

#[test]
fn compiler_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn compiler_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn compiler_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn compiler_contract_has_consumer_interfaces() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["consumer_interfaces"].is_object() || value["consumer_interfaces"].is_array());
}

#[test]
fn compiler_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn compiler_contract_json_is_an_object() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn compiler_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn compiler_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn compiler_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn compiler_contract_schema_version_is_nonempty() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn compiler_contract_serde_roundtrip_preserves_all_fields() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let serialized = serde_json::to_string(&value).expect("re-serialize");
    let roundtripped: Value = serde_json::from_str(&serialized).expect("re-parse");
    assert_eq!(value, roundtripped, "serde roundtrip must be lossless");
}

#[test]
fn compiler_contract_activation_gate_all_blocks_are_true() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let gate = &value["activation_gate"];
    for key in [
        "block_on_missing_verification_or_fallback_metadata",
        "block_on_missing_reuse_scan_outcome",
    ] {
        assert_eq!(
            gate[key].as_bool(),
            Some(true),
            "activation_gate.{key} must be true for fail-closed semantics"
        );
    }
}

#[test]
fn compiler_contract_pass_witness_fields_are_non_empty_strings() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let fields = value["outputs"]["pass_witness_bundle"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(fields.len() >= 6, "at least 6 witness fields required");
    for field in fields {
        let s = field.as_str().expect("field must be string");
        assert!(!s.trim().is_empty(), "witness field must not be empty");
    }
}

#[test]
fn compiler_charter_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "charter must not contain unresolved TODO/FIXME/XXX markers"
    );
}

#[test]
fn compiler_charter_interface_contracts_section_references_peer_lanes() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");

    let section_idx = doc
        .find("## Interface Contracts")
        .expect("section must exist");
    let section_text = &doc[section_idx..];
    // Interface Contracts must reference at least one upstream/downstream lane
    assert!(
        section_text.contains("Runtime")
            || section_text.contains("Verification")
            || section_text.contains("Toolchain")
            || section_text.contains("Adoption"),
        "Interface Contracts must reference at least one peer lane"
    );
}

// ---------- enrichment: deeper structural and cross-field checks ----------

#[test]
fn compiler_contract_lane_name_is_nonempty() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let name = value["lane"]["name"]
        .as_str()
        .expect("lane.name must be a string");
    assert!(!name.trim().is_empty(), "lane.name must not be empty");
}

#[test]
fn compiler_contract_inputs_section_exists_and_is_nonempty() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let inputs = &value["inputs"];
    assert!(
        inputs.is_object() || inputs.is_array(),
        "inputs must be an object or array"
    );
    if let Some(obj) = inputs.as_object() {
        assert!(!obj.is_empty(), "inputs object must not be empty");
    }
}

#[test]
fn compiler_charter_doc_mentions_deterministic_fallback() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(
        doc.contains("deterministic fallback"),
        "charter must mention deterministic fallback"
    );
}

#[test]
fn compiler_contract_logging_contract_has_required_fields_array() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("logging_contract.required_fields must be an array");
    assert!(
        !fields.is_empty(),
        "logging_contract.required_fields must not be empty"
    );
    for field in fields {
        assert!(
            field.as_str().is_some_and(|s| !s.trim().is_empty()),
            "each logging_contract required_field must be a non-empty string"
        );
    }
}

#[test]
fn compiler_contract_failure_policy_is_fail_closed_mode() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed"),
        "compiler lane failure_policy mode must be fail_closed"
    );
    // failure_policy should have an error_code
    let error_code = value["failure_policy"]["error_code"].as_str().unwrap_or("");
    assert!(
        !error_code.trim().is_empty(),
        "failure_policy.error_code must not be empty"
    );
}

// ---------------------------------------------------------------------------
// Enrichment batch 2: deeper structural and cross-field invariants
// ---------------------------------------------------------------------------

#[test]
fn compiler_charter_word_count_at_least_three_hundred() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 300,
        "charter should have at least 300 words, got {}",
        word_count
    );
}

#[test]
fn compiler_charter_h2_count_at_least_eight() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let h2_count = doc.lines().filter(|l| l.starts_with("## ")).count();
    assert!(
        h2_count >= 8,
        "charter should have at least 8 H2 sections, got {}",
        h2_count
    );
}

#[test]
fn compiler_contract_has_at_least_eight_top_level_keys() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let obj = value.as_object().expect("top-level must be object");
    assert!(
        obj.len() >= 8,
        "contract should have at least 8 top-level keys, got {}",
        obj.len()
    );
}

#[test]
fn compiler_charter_mentions_rollback_or_recovery() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let lower = doc.to_ascii_lowercase();
    assert!(
        lower.contains("rollback") || lower.contains("recovery") || lower.contains("revert"),
        "charter should mention rollback, recovery, or revert"
    );
}

#[test]
fn compiler_contract_primary_bead_starts_with_bd() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(
        pb.starts_with("bd-"),
        "primary_bead must start with bd-, got '{}'",
        pb
    );
}

#[test]
fn compiler_contract_schema_version_starts_with_frx() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(
        sv.starts_with("frx."),
        "schema_version must start with frx., got '{}'",
        sv
    );
}

#[test]
fn compiler_contract_generated_by_starts_with_bd() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gb = value["generated_by"]
        .as_str()
        .expect("generated_by must be string");
    assert!(
        gb.starts_with("bd-"),
        "generated_by must start with bd-, got '{}'",
        gb
    );
}

#[test]
fn compiler_charter_deterministic_double_read() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b, "charter must be deterministic on double read");
}

#[test]
fn compiler_contract_json_size_reasonable() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    assert!(
        raw.len() > 200,
        "contract JSON should be > 200 bytes, got {}",
        raw.len()
    );
    assert!(
        raw.len() < 100_000,
        "contract JSON should be < 100KB, got {}",
        raw.len()
    );
}

#[test]
fn compiler_charter_line_count_at_least_eighty() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let line_count = doc.lines().count();
    assert!(
        line_count >= 80,
        "charter should have at least 80 lines, got {}",
        line_count
    );
}

#[test]
fn compiler_contract_logging_component_nonempty() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let component = value["logging_contract"]["component"]
        .as_str()
        .unwrap_or("");
    assert!(
        !component.trim().is_empty(),
        "logging_contract.component must not be empty"
    );
}

#[test]
fn compiler_contract_outputs_has_at_least_one_key() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let outputs = value["outputs"]
        .as_object()
        .expect("outputs must be object");
    assert!(!outputs.is_empty(), "outputs must have at least one key");
}

#[test]
fn compiler_charter_mentions_budget_or_cost() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let lower = doc.to_ascii_lowercase();
    assert!(
        lower.contains("budget") || lower.contains("cost"),
        "charter should mention budget or cost concepts"
    );
}

#[test]
fn compiler_contract_lane_id_starts_with_frx() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let lane_id = value["lane"]["id"]
        .as_str()
        .expect("lane.id must be string");
    assert!(
        lane_id.starts_with("FRX-"),
        "lane.id must start with FRX-, got '{}'",
        lane_id
    );
}

#[test]
fn compiler_contract_generated_at_utc_contains_t_separator() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(
        ts.contains('T'),
        "generated_at_utc must contain T separator: '{}'",
        ts
    );
}
