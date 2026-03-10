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
fn frx_track_b_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track B Compiler/FRIR Spine Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Canonical Binder Contract",
        "## FRIR Lowering and Witness Contract",
        "## Optimization Budget and Isomorphism Guard",
        "## Promotion Blocking and Rollback",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track B charter missing section: {section}"
        );
    }

    let required_clauses = [
        "canonical binder representation",
        "FRIR schema version stability",
        "witness bundle linkage",
        "isomorphism checks",
        "fail closed",
        "replay command",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "track B charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_b_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-b.compiler-frir-spine.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.2"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.2"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.2"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_witness_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_failed_isomorphism_check"].as_bool(),
        Some(true)
    );

    let witness_fields = value["outputs"]["witness_bundle_contract"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_witness_fields = [
        "pass_id",
        "input_hash",
        "output_hash",
        "invariant_results",
        "budget_summary",
        "replay_linkage",
        "producer_track",
    ];

    for field in expected_witness_fields {
        assert!(
            witness_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "witness field missing: {field}"
        );
    }
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- doc content ----------

#[test]
fn track_b_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read track B charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn track_b_charter_doc_references_fail_closed_and_replay() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read track B charter doc");
    assert!(doc.contains("fail closed"));
    assert!(doc.contains("replay command"));
}

// ---------- JSON contract fields ----------

#[test]
fn track_b_contract_has_track_section() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read track B JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track B JSON");
    assert!(value["track"].is_object());
    assert!(value["track"]["id"].is_string());
}

#[test]
fn track_b_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read track B JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track B JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn track_b_contract_has_outputs_section() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read track B JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track B JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["witness_bundle_contract"].is_object());
}

#[test]
fn track_b_contract_failure_policy_is_fail_closed() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read track B JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track B JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn track_b_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read track B JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn track_b_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn track_b_charter_mentions_binder() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("binder"));
}

#[test]
fn track_b_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["primary_bead"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_b_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_b_contract_has_failure_policy() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
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
fn track_b_charter_mentions_frir() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("FRIR"));
}

#[test]
fn track_b_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_b_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn track_b_contract_has_ownership_section() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["ownership"].is_object());
}

#[test]
fn track_b_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn track_b_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn track_b_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn track_b_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    assert!(path.exists());
}

#[test]
fn track_b_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    assert!(path.exists());
}

#[test]
fn track_b_charter_mentions_compiler() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("compiler"));
}

// ---------- enrichment: deeper structural and edge-case checks ----------

#[test]
fn track_b_activation_gate_blocks_on_all_critical_conditions() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = &value["activation_gate"];
    for condition in [
        "block_on_missing_witness_linkage",
        "block_on_schema_incompatibility",
        "block_on_failed_isomorphism_check",
        "block_on_missing_replay_metadata",
    ] {
        assert_eq!(
            gate[condition].as_bool(),
            Some(true),
            "activation_gate.{condition} must be true"
        );
    }
}

#[test]
fn track_b_failure_policy_rollback_emits_replay_and_rationale() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let rollback = &value["failure_policy"]["rollback_policy"];
    assert_eq!(
        rollback["emit_replay_command"].as_bool(),
        Some(true),
        "rollback policy must emit replay command"
    );
    assert_eq!(
        rollback["emit_rationale_event"].as_bool(),
        Some(true),
        "rollback policy must emit rationale event"
    );
}

#[test]
fn track_b_frir_artifact_contract_is_deterministic_and_has_required_fields() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let frir = &value["outputs"]["frir_artifact_contract"];
    assert_eq!(
        frir["deterministic"].as_bool(),
        Some(true),
        "FRIR artifact contract must be deterministic"
    );
    let fields = frir["required_fields"]
        .as_array()
        .expect("frir required_fields array");
    let field_set: std::collections::BTreeSet<&str> =
        fields.iter().filter_map(|v| v.as_str()).collect();
    for required in [
        "frir_schema_version",
        "artifact_hash",
        "producer_track",
        "trace_id",
    ] {
        assert!(
            field_set.contains(required),
            "FRIR artifact contract missing required field: {required}"
        );
    }
}

#[test]
fn track_b_diagnostics_contract_is_deterministic_and_has_required_fields() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let diag = &value["outputs"]["diagnostics_contract"];
    assert_eq!(
        diag["deterministic"].as_bool(),
        Some(true),
        "diagnostics contract must be deterministic"
    );
    let fields = diag["required_fields"]
        .as_array()
        .expect("diagnostics required_fields array");
    let field_set: std::collections::BTreeSet<&str> =
        fields.iter().filter_map(|v| v.as_str()).collect();
    for required in [
        "diagnostic_code",
        "severity",
        "component",
        "event",
        "outcome",
    ] {
        assert!(
            field_set.contains(required),
            "diagnostics contract missing required field: {required}"
        );
    }
}

#[test]
fn track_b_contract_serde_roundtrip_via_value_preserves_all_keys() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
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

// ---------- enrichment: additional structural and policy checks ----------

#[test]
fn track_b_contract_has_status_active() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["status"].as_str(),
        Some("active"),
        "track B contract status must be active"
    );
}

#[test]
fn track_b_witness_bundle_has_required_count() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["witness_bundle_contract"]["required_fields"]
        .as_array()
        .expect("witness required_fields");
    assert!(
        fields.len() >= 7,
        "witness bundle must have at least 7 required fields, got {}",
        fields.len()
    );
}

#[test]
fn track_b_contract_logging_contract_has_required_fields() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("logging required_fields");
    let field_set: std::collections::BTreeSet<&str> =
        fields.iter().filter_map(|v| v.as_str()).collect();
    for required in ["trace_id", "component", "event", "outcome"] {
        assert!(
            field_set.contains(required),
            "logging_contract missing field: {required}"
        );
    }
}

#[test]
fn track_b_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"),
        "track B charter must reference program constitution"
    );
}

#[test]
fn track_b_charter_doc_mentions_isomorphism() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("isomorphism"),
        "track B charter must mention isomorphism checks"
    );
}
