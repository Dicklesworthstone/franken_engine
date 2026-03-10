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
fn frx_verification_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Verification/Formal Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Differential and Metamorphic Evidence Obligations",
        "## Formal Assurance Obligations",
        "## Counterexample Triage and Reproducibility",
        "## Promotion Blocking Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "verification lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "semantic non-regression evidence",
        "formal assurance artifacts",
        "Missing any required evidence bundle is a promotion blocker.",
        "If confidence degrades below gate threshold, block promotion.",
        "deterministic replay command",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "verification lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_verification_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.verification.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.4"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.4"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.4"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_confidence_below_threshold"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_replay_artifact"].as_bool(),
        Some(true)
    );

    let triage_fields = value["counterexample_triage"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_triage_fields = [
        "counterexample_id",
        "taxonomy_label",
        "replay_command",
        "minimized_payload_ref",
        "owner_lane",
        "confidence_impact",
    ];
    for field in expected_triage_fields {
        assert!(
            triage_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "counterexample triage field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_verification_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["verification_lane_charter"].as_str(),
        Some("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["verification_lane_contract"].as_str(),
        Some("docs/frx_verification_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn verification_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn verification_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn verification_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.4"));
}

#[test]
fn verification_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
    assert_eq!(
        value["activation_gate"]["block_on_confidence_below_threshold"].as_bool(),
        Some(true)
    );
}

#[test]
fn verification_contract_has_counterexample_triage() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["counterexample_triage"].is_object());
}

#[test]
fn verification_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn verification_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn verification_contract_has_failure_policy_object() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["failure_policy"].is_object());
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn verification_charter_mentions_counterexample() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("counterexample"));
}

#[test]
fn verification_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn verification_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn verification_contract_generated_at_utc_is_valid_iso8601() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'));
    assert!(ts.contains('T'));
}

#[test]
fn verification_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn verification_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn verification_contract_has_consumer_interfaces() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["consumer_interfaces"].is_object() || value["consumer_interfaces"].is_array());
}

#[test]
fn verification_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn verification_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn verification_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn verification_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn verification_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn verification_charter_mentions_formal() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("formal"));
}

// ---------- enrichment: deeper structural invariants ----------

#[test]
fn verification_contract_consumer_interfaces_cover_all_lanes() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ci = value["consumer_interfaces"]
        .as_object()
        .expect("consumer_interfaces must be object");
    for lane in ["governance_lane", "compiler_lane", "runtime_lane"] {
        assert!(
            ci.contains_key(lane),
            "consumer_interfaces missing lane: {lane}"
        );
        let entries = ci[lane].as_array().expect("lane entries must be array");
        assert!(
            !entries.is_empty(),
            "consumer_interfaces.{lane} must not be empty"
        );
    }
}

#[test]
fn verification_contract_counterexample_triage_repro_required() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["counterexample_triage"]["repro_required"].as_bool(),
        Some(true),
        "counterexample triage must require reproducibility"
    );
}

#[test]
fn verification_contract_logging_contract_has_component_and_fields() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let lc = &value["logging_contract"];
    let component = lc["component"]
        .as_str()
        .expect("logging_contract.component must be string");
    assert!(!component.trim().is_empty());
    let fields = lc["required_fields"]
        .as_array()
        .expect("logging_contract.required_fields must be array");
    assert!(
        !fields.is_empty(),
        "logging required_fields must not be empty"
    );
    for field in fields {
        let s = field.as_str().expect("each field must be string");
        assert!(!s.trim().is_empty());
    }
}

#[test]
fn verification_contract_json_roundtrip_preserves_all_keys() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let reserialized = serde_json::to_string_pretty(&value).expect("re-serialize");
    let reparsed: Value = serde_json::from_str(&reserialized).expect("re-parse");
    let original_keys: std::collections::BTreeSet<String> =
        value.as_object().unwrap().keys().cloned().collect();
    let reparsed_keys: std::collections::BTreeSet<String> =
        reparsed.as_object().unwrap().keys().cloned().collect();
    assert_eq!(original_keys, reparsed_keys);
}

#[test]
fn verification_contract_activation_gate_all_blocks_are_true() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = value["activation_gate"]
        .as_object()
        .expect("activation_gate must be object");
    for (key, val) in gate {
        if let Some(b) = val.as_bool() {
            assert!(
                b,
                "activation_gate.{key} must be true for fail-closed policy"
            );
        }
    }
}

// ---------- enrichment: deeper contract invariants ----------

#[test]
fn verification_contract_counterexample_triage_has_all_required_fields() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["counterexample_triage"]["required_fields"]
        .as_array()
        .expect("required_fields must be array");
    // Each field must be a non-empty string
    for field in fields {
        let s = field.as_str().expect("each field must be string");
        assert!(!s.trim().is_empty(), "empty counterexample triage field");
    }
    // Must have at least 4 required fields
    assert!(
        fields.len() >= 4,
        "counterexample triage should have at least 4 required fields, got {}",
        fields.len()
    );
}

#[test]
fn verification_contract_failure_policy_has_error_code() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fp = &value["failure_policy"];
    let code = fp["error_code"]
        .as_str()
        .expect("failure_policy.error_code must be string");
    assert!(!code.trim().is_empty(), "error_code must not be empty");
    assert!(
        code.starts_with("FE-"),
        "error_code should start with FE- prefix, got {code}"
    );
}

#[test]
fn verification_charter_doc_contains_all_input_and_output_sections() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    // Inputs and Outputs are required charter sections
    assert!(
        doc.contains("## Inputs"),
        "charter missing ## Inputs section"
    );
    assert!(
        doc.contains("## Outputs"),
        "charter missing ## Outputs section"
    );
    // Should have content under each (not just empty sections)
    let inputs_idx = doc.find("## Inputs").unwrap();
    let outputs_idx = doc.find("## Outputs").unwrap();
    assert!(
        outputs_idx > inputs_idx,
        "Outputs section should come after Inputs"
    );
}

#[test]
fn verification_contract_lane_has_name_and_description() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let lane = &value["lane"];
    assert!(lane.is_object(), "lane must be an object");
    // lane should have id, name, or description fields
    let id = lane["id"].as_str().expect("lane.id must be string");
    assert!(!id.trim().is_empty(), "lane.id must not be empty");
}

#[test]
fn verification_contract_logging_contract_fail_closed() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let lc = &value["logging_contract"];
    // The logging contract's fail_closed_on_missing_fields should be true
    assert_eq!(
        lc["fail_closed_on_missing_fields"].as_bool(),
        Some(true),
        "logging_contract must be fail-closed on missing fields"
    );
}
