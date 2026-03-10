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
fn frx_track_d_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track D WASM Lane + Hybrid Router Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## WASM Scheduler and ABI Contract",
        "## Hybrid Router Calibration and Safety Override Contract",
        "## Deterministic Replay and Failover Contract",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track D charter missing section: {section}"
        );
    }

    let required_clauses = [
        "wasm scheduler determinism",
        "abi overhead budget",
        "hybrid router calibration",
        "conservative override",
        "fallback events",
        "replay linkage",
        "fail closed",
        "verification and governance signoff artifacts",
    ];

    let doc_lower = doc.to_ascii_lowercase();
    for clause in required_clauses {
        assert!(
            doc_lower.contains(clause),
            "track D charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_d_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-d.wasm-lane-hybrid-router.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.4"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.4"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.4"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_calibration_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_failover_replay_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["requires_verification_and_governance_signoff"].as_bool(),
        Some(true)
    );

    let required_fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("router required fields must be an array");

    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "lane_choice",
        "calibration_snapshot_id",
        "override_reason",
        "failover_event_id",
        "abi_overhead_us",
    ] {
        assert!(
            required_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "router decision field missing: {field}"
        );
    }
}

#[test]
fn frx_track_d_runtime_sources_expose_required_surfaces() {
    let wasm_path = repo_root().join("crates/franken-engine/src/wasm_runtime_lane.rs");
    let wasm = fs::read_to_string(&wasm_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", wasm_path.display()));

    for snippet in [
        "pub struct WasmRuntimeLane",
        "pub enum SafeModeReason",
        "pub struct WasmFlushResult",
        "pub fn flush(&mut self) -> WasmFlushResult",
        "pub fn derive_id(&self) -> EngineObjectId",
    ] {
        assert!(
            wasm.contains(snippet),
            "wasm runtime lane missing required surface: {snippet}"
        );
    }

    let router_path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    let router = fs::read_to_string(&router_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", router_path.display()));

    for snippet in [
        "pub struct HybridLaneRouter",
        "pub struct RoutingDecisionTrace",
        "pub enum DemotionReason",
        "pub fn observe(",
        "pub fn manual_demote(&mut self) -> Result<(), RouterError>",
    ] {
        assert!(
            router.contains(snippet),
            "hybrid lane router missing required surface: {snippet}"
        );
    }
}

#[test]
fn frx_track_d_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Track D WASM Lane + Hybrid Router Sprint Gate"),
        "README missing track D gate heading"
    );
    assert!(
        readme.contains("./scripts/run_frx_track_d_wasm_lane_hybrid_router_sprint_suite.sh ci"),
        "README missing track D gate command"
    );
    assert!(
        readme.contains("./scripts/e2e/frx_track_d_wasm_lane_hybrid_router_sprint_replay.sh"),
        "README missing track D replay command"
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn track_d_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track D doc");
    assert!(!doc.is_empty());
}

// ---------- JSON contract ----------

#[test]
fn track_d_contract_has_track_section() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["track"].is_object());
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.4"));
}

#[test]
fn track_d_contract_has_outputs_section() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["router_decision_artifact"].is_object());
}

#[test]
fn track_d_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn track_d_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn track_d_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn track_d_charter_mentions_wasm() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("wasm"));
}

#[test]
fn track_d_contract_has_failure_policy() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["failure_policy"].is_object());
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn track_d_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn track_d_charter_mentions_hybrid_router() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("Hybrid Router"));
}

#[test]
fn track_d_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_d_charter_mentions_abi_overhead() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("abi overhead"));
}

#[test]
fn track_d_charter_mentions_deterministic_replay() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("Deterministic Replay"));
}

#[test]
fn track_d_contract_has_nonempty_primary_bead() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let primary_bead = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!primary_bead.trim().is_empty());
}

#[test]
fn track_d_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gen_by = value["generated_by"]
        .as_str()
        .expect("generated_by must be string");
    assert!(!gen_by.trim().is_empty());
}

#[test]
fn track_d_charter_references_wasm_lane() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("wasm lane"));
}

#[test]
fn track_d_charter_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn track_d_contract_has_nonempty_schema_version() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_d_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse a");
    let b: Value = serde_json::from_str(&raw).expect("parse b");
    assert_eq!(a, b);
}

// ---------- JSON contract field coverage ----------

#[test]
fn track_d_contract_outputs_router_decision_fields_are_nonempty_strings() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(!fields.is_empty());
    for field in fields {
        let s = field.as_str().expect("field must be string");
        assert!(!s.trim().is_empty(), "required field must be nonempty");
    }
}

#[test]
fn track_d_contract_activation_gate_has_boolean_fields() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = &value["activation_gate"];
    assert!(gate["block_on_missing_calibration_evidence"].is_boolean());
    assert!(gate["block_on_missing_failover_replay_linkage"].is_boolean());
    assert!(gate["requires_verification_and_governance_signoff"].is_boolean());
}

#[test]
fn track_d_charter_mentions_fail_closed() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("fail closed"),
        "charter must mention fail closed policy"
    );
}

#[test]
fn track_d_charter_mentions_calibration() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("calibration"),
        "charter must mention calibration"
    );
}

#[test]
fn track_d_contract_top_level_keys_are_present() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    for key in [
        "schema_version",
        "generated_by",
        "primary_bead",
        "track",
        "failure_policy",
        "activation_gate",
        "outputs",
    ] {
        assert!(
            !value[key].is_null(),
            "top-level key `{key}` must be present in contract JSON"
        );
    }
}

#[test]
fn track_d_charter_doc_has_more_than_10_headings() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let heading_count = doc.lines().filter(|line| line.starts_with('#')).count();
    assert!(
        heading_count >= 10,
        "charter doc should have at least 10 headings, found {heading_count}"
    );
}

#[test]
fn track_d_charter_mentions_fallback_events() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("fallback events"),
        "charter must mention fallback events"
    );
}

#[test]
fn track_d_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    assert!(path.exists(), "track D charter doc must exist");
}

#[test]
fn track_d_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    assert!(path.exists(), "track D contract JSON must exist");
}

#[test]
fn track_d_contract_track_name_is_nonempty() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let name = value["track"]["name"]
        .as_str()
        .expect("track.name must be a string");
    assert!(!name.trim().is_empty(), "track.name must not be empty");
}
