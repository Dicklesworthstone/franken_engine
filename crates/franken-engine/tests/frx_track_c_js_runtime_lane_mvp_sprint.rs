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
fn frx_track_c_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track C JS Runtime Lane MVP Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Deterministic Scheduler and Lifecycle Contract",
        "## Trace Emission and Replay Linkage Contract",
        "## Failover and Fallback Hook Contract",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track C charter missing section: {section}"
        );
    }

    let required_clauses = [
        "deterministic scheduler ordering",
        "direct dom patch batches",
        "trace linkage fields",
        "failover hook points",
        "fallback activation",
        "fail-closed",
    ];

    let doc_lower = doc.to_ascii_lowercase();
    for clause in required_clauses {
        assert!(
            doc_lower.contains(clause),
            "track C charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_c_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-c.js-runtime-lane-mvp-sprint.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.3"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.3"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.3"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_trace_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_failover_hooks"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_nondeterministic_scheduler_observation"].as_bool(),
        Some(true)
    );

    let trace_fields = value["outputs"]["lane_trace_bundle"]["required_fields"]
        .as_array()
        .expect("lane trace bundle fields must be an array");

    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "flush_summary_id",
        "replay_linkage",
    ] {
        assert!(
            trace_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "lane trace field missing: {field}"
        );
    }
}

#[test]
fn frx_track_c_js_lane_source_contains_required_runtime_surfaces() {
    let path = repo_root().join("crates/franken-engine/src/js_runtime_lane.rs");
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_snippets = [
        "pub struct UpdateScheduler",
        "pub struct JsRuntimeLane",
        "pub enum LaneState",
        "pub struct FlushSummary",
        "pub fn derive_id(&self) -> EngineObjectId",
    ];

    for snippet in required_snippets {
        assert!(
            source.contains(snippet),
            "js runtime lane missing required surface: {snippet}"
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
fn track_c_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track C charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn track_c_charter_references_deterministic_scheduler() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track C charter doc");
    let doc_lower = doc.to_ascii_lowercase();
    assert!(doc_lower.contains("deterministic scheduler"));
}

// ---------- JSON contract fields ----------

#[test]
fn track_c_contract_has_track_section() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read track C JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track C JSON");
    assert!(value["track"].is_object());
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.3"));
}

#[test]
fn track_c_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read track C JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track C JSON");
    assert!(value["activation_gate"].is_object());
    assert_eq!(
        value["activation_gate"]["block_on_missing_trace_linkage"].as_bool(),
        Some(true)
    );
}

#[test]
fn track_c_contract_has_outputs_section() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read track C JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track C JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["lane_trace_bundle"].is_object());
}

#[test]
fn track_c_contract_failure_policy_is_fail_closed() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read track C JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse track C JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn track_c_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read track C JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

// ---------- source file checks ----------

#[test]
fn js_runtime_lane_source_has_update_scheduler() {
    let path = repo_root().join("crates/franken-engine/src/js_runtime_lane.rs");
    let source = fs::read_to_string(&path).expect("read js_runtime_lane.rs");
    assert!(source.contains("pub struct UpdateScheduler"));
}

#[test]
fn js_runtime_lane_source_has_lane_state_enum() {
    let path = repo_root().join("crates/franken-engine/src/js_runtime_lane.rs");
    let source = fs::read_to_string(&path).expect("read js_runtime_lane.rs");
    assert!(source.contains("pub enum LaneState"));
}

#[test]
fn track_c_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn track_c_charter_mentions_failover() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    let lower = doc.to_ascii_lowercase();
    assert!(lower.contains("failover"));
}

#[test]
fn track_c_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["primary_bead"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_c_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"].as_str().expect("schema_version");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_c_charter_mentions_js_runtime() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("JS Runtime"));
}

#[test]
fn track_c_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_c_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn track_c_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn track_c_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn track_c_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    assert!(path.exists());
}

#[test]
fn track_c_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    assert!(path.exists());
}

#[test]
fn track_c_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

// ---------- enrichment: deeper structural invariants ----------

#[test]
fn track_c_contract_logging_contract_required_fields_are_nonempty_strings() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("logging_contract.required_fields must be array");
    assert!(!fields.is_empty(), "required_fields must not be empty");
    for field in fields {
        let s = field.as_str().expect("each field must be a string");
        assert!(!s.trim().is_empty(), "field must not be blank");
    }
}

#[test]
fn track_c_contract_failover_hook_required_fields_present() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let hook = &value["outputs"]["failover_hook_contract"];
    assert!(
        hook["required"].as_bool() == Some(true),
        "failover_hook_contract must be required"
    );
    let fields = hook["required_fields"]
        .as_array()
        .expect("failover_hook_contract.required_fields");
    for expected in ["hook_id", "trigger_condition", "fallback_mode"] {
        assert!(
            fields.iter().any(|v| v.as_str() == Some(expected)),
            "failover_hook_contract missing field: {expected}"
        );
    }
}

#[test]
fn track_c_contract_promotion_evidence_pointer_fields_present() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pointer = &value["outputs"]["promotion_evidence_pointer"];
    assert!(
        pointer["required"].as_bool() == Some(true),
        "promotion_evidence_pointer must be required"
    );
    let fields = pointer["required_fields"]
        .as_array()
        .expect("promotion_evidence_pointer.required_fields");
    for expected in [
        "bead_id",
        "artifact_root",
        "manifest_path",
        "replay_command",
    ] {
        assert!(
            fields.iter().any(|v| v.as_str() == Some(expected)),
            "promotion_evidence_pointer missing field: {expected}"
        );
    }
}

#[test]
fn track_c_contract_json_roundtrip_preserves_all_keys() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    // Re-serialize and re-parse, verifying the full key set is stable
    let reserialized = serde_json::to_string_pretty(&value).expect("re-serialize");
    let reparsed: Value = serde_json::from_str(&reserialized).expect("re-parse");
    let original_keys: std::collections::BTreeSet<String> =
        value.as_object().unwrap().keys().cloned().collect();
    let reparsed_keys: std::collections::BTreeSet<String> =
        reparsed.as_object().unwrap().keys().cloned().collect();
    assert_eq!(original_keys, reparsed_keys);
}

#[test]
fn track_c_contract_status_is_active() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(value["status"].as_str(), Some("active"));
}

// ---------- enrichment: additional structural and semantic checks ----------

#[test]
fn track_c_contract_has_ownership_section() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["ownership"].is_object(),
        "track C contract must have ownership section"
    );
}

#[test]
fn track_c_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"),
        "track C charter must reference program constitution"
    );
}

#[test]
fn track_c_contract_activation_gate_blocks_nondeterministic_scheduler() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["activation_gate"]["block_on_nondeterministic_scheduler_observation"].as_bool(),
        Some(true),
        "activation gate must block on nondeterministic scheduler observations"
    );
}

#[test]
fn track_c_charter_mentions_dom_patch() {
    let path = repo_root().join("docs/FRX_TRACK_C_JS_RUNTIME_LANE_MVP_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        lower.contains("dom patch"),
        "track C charter must mention DOM patch batches"
    );
}

#[test]
fn track_c_contract_failure_policy_has_error_code() {
    let path = repo_root().join("docs/frx_track_c_js_runtime_lane_mvp_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let error_code = value["failure_policy"]["error_code"]
        .as_str()
        .expect("failure_policy.error_code must be a string");
    assert!(
        error_code.starts_with("FE-FRX-"),
        "error_code must start with FE-FRX-, got {error_code}"
    );
}
