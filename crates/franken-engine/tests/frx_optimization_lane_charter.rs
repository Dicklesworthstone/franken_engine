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
fn frx_optimization_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Optimization/Performance Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Profile-First Evidence Discipline",
        "## One-Lever and Isomorphism Proof Discipline",
        "## Regression and Rollback Gates",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "optimization lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "profile-driven performance improvement",
        "one-lever optimization discipline",
        "isomorphism proof note",
        "tail-latency budget gate",
        "Any unproven optimization is blocked from merge and promotion.",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "optimization lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_optimization_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.optimization.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.5"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.5"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.5"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["require_profile_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["require_rollback_plan"].as_bool(),
        Some(true)
    );

    let ranking_fields = value["outputs"]["optimization_campaign_ranking"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_ranking_fields = [
        "campaign_id",
        "expected_value",
        "relevance_score",
        "risk_score",
        "confidence",
    ];
    for field in expected_ranking_fields {
        assert!(
            ranking_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "optimization campaign ranking field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_optimization_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["optimization_lane_charter"].as_str(),
        Some("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["optimization_lane_contract"].as_str(),
        Some("docs/frx_optimization_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn optimization_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn optimization_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn optimization_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.5"));
}

#[test]
fn optimization_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
    assert_eq!(
        value["activation_gate"]["require_profile_evidence"].as_bool(),
        Some(true)
    );
}

#[test]
fn optimization_contract_has_campaign_ranking_output() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"]["optimization_campaign_ranking"].is_object());
}

#[test]
fn optimization_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn optimization_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn optimization_contract_has_failure_policy_object() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
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
fn optimization_charter_mentions_profile() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("profile"));
}

#[test]
fn optimization_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn optimization_charter_mentions_tail_latency() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("tail-latency"));
}

#[test]
fn optimization_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn optimization_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn optimization_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn optimization_contract_has_consumer_interfaces() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["consumer_interfaces"].is_object() || value["consumer_interfaces"].is_array());
}

#[test]
fn optimization_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn optimization_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn optimization_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn optimization_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn optimization_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn optimization_charter_mentions_regression() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("regression"));
}

// ---------- enrichment: deeper structural and cross-field checks ----------

#[test]
fn optimization_contract_activation_gate_blocks_all_regressions() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = &value["activation_gate"];
    for field in [
        "block_on_tail_latency_regression",
        "block_on_memory_regression",
        "block_on_responsiveness_regression",
    ] {
        assert_eq!(
            gate[field].as_bool(),
            Some(true),
            "activation_gate.{field} must be true to block regressions"
        );
    }
}

#[test]
fn optimization_contract_serde_roundtrip_via_value() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let reserialized = serde_json::to_string_pretty(&value).expect("re-serialize");
    let reparsed: Value = serde_json::from_str(&reserialized).expect("re-parse");
    assert_eq!(value, reparsed, "serde roundtrip must preserve all data");
}

#[test]
fn optimization_contract_failure_policy_rejects_unproven_optimizations() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fp = &value["failure_policy"];
    assert_eq!(
        fp["on_unproven_optimization"].as_str(),
        Some("block_merge_and_promotion"),
        "unproven optimizations must be blocked from merge and promotion"
    );
    assert_eq!(
        fp["on_missing_rollback_plan"].as_str(),
        Some("reject_candidate"),
        "missing rollback plan must reject the candidate"
    );
}

#[test]
fn optimization_contract_outputs_have_replay_command_field() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let before_after = &value["outputs"]["before_after_artifacts"]["required_fields"];
    let fields = before_after
        .as_array()
        .expect("before_after required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("replay_command")),
        "before_after_artifacts must include replay_command for reproducibility"
    );
}

#[test]
fn optimization_contract_consumer_interfaces_cover_all_downstream_lanes() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ci = &value["consumer_interfaces"];
    assert!(ci.is_object(), "consumer_interfaces must be an object");
    let obj = ci.as_object().expect("consumer_interfaces object");
    // must supply interfaces to at least release, verification, and runtime lanes
    for lane in ["release_lane", "verification_lane", "runtime_lane"] {
        assert!(
            obj.contains_key(lane),
            "consumer_interfaces missing downstream lane: {lane}"
        );
        let items = obj[lane]
            .as_array()
            .unwrap_or_else(|| panic!("consumer_interfaces.{lane} must be an array"));
        assert!(
            !items.is_empty(),
            "consumer_interfaces.{lane} must not be empty"
        );
    }
}

// ---------- enrichment: additional edge-case tests ----------

#[test]
fn optimization_contract_all_top_level_keys_are_present() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let obj = value.as_object().expect("top-level must be object");
    let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    for required_key in [
        "schema_version",
        "generated_by",
        "generated_at_utc",
        "lane",
        "primary_bead",
        "failure_policy",
        "activation_gate",
        "outputs",
    ] {
        assert!(
            keys.contains(required_key),
            "optimization contract missing top-level key: {required_key}"
        );
    }
}

#[test]
fn optimization_charter_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "optimization charter must not contain unresolved TODO/FIXME/XXX markers"
    );
}

#[test]
fn optimization_contract_campaign_ranking_fields_are_nonempty() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["optimization_campaign_ranking"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.len() >= 5,
        "optimization campaign ranking should have at least 5 required fields"
    );
    for field in fields {
        assert!(
            field.as_str().is_some_and(|s| !s.trim().is_empty()),
            "each campaign ranking field must be a non-empty string"
        );
    }
}

#[test]
fn optimization_contract_logging_contract_has_required_fields() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("logging_contract.required_fields array");
    assert!(
        !fields.is_empty(),
        "logging_contract.required_fields must not be empty"
    );
    for field in fields {
        assert!(
            field.as_str().is_some_and(|s| !s.trim().is_empty()),
            "each logging required_field must be a non-empty string"
        );
    }
}

#[test]
fn optimization_charter_mentions_isomorphism() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(
        doc.contains("isomorphism"),
        "optimization charter must reference isomorphism proof discipline"
    );
}
