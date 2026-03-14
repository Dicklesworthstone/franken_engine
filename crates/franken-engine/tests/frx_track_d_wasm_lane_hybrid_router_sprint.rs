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

// ---------- Additional coverage: charter doc content ----------

#[test]
fn track_d_charter_mentions_conservative_override() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("conservative override"),
        "charter must mention conservative override"
    );
}

#[test]
fn track_d_charter_mentions_replay_linkage() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("replay linkage"),
        "charter must mention replay linkage"
    );
}

#[test]
fn track_d_charter_mentions_wasm_scheduler_determinism() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase()
            .contains("wasm scheduler determinism"),
        "charter must mention wasm scheduler determinism"
    );
}

#[test]
fn track_d_charter_mentions_verification_and_governance_signoff() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase()
            .contains("verification and governance signoff artifacts"),
        "charter must mention verification and governance signoff artifacts"
    );
}

#[test]
fn track_d_charter_mentions_hybrid_router_calibration() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase()
            .contains("hybrid router calibration"),
        "charter must mention hybrid router calibration"
    );
}

#[test]
fn track_d_charter_interface_contracts_section_exists() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("## Interface Contracts"),
        "charter must have Interface Contracts section"
    );
}

#[test]
fn track_d_charter_doc_size_is_reasonable() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    // Must be at least 1 KB to constitute a meaningful charter
    assert!(
        doc.len() >= 1_024,
        "charter doc must be at least 1 KB, got {} bytes",
        doc.len()
    );
}

#[test]
fn track_d_charter_inputs_section_exists() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("## Inputs"),
        "charter must have Inputs section"
    );
}

#[test]
fn track_d_charter_outputs_section_exists() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("## Outputs"),
        "charter must have Outputs section"
    );
}

#[test]
fn track_d_charter_responsibilities_section_exists() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("## Responsibilities"),
        "charter must have Responsibilities section"
    );
}

// ---------- Additional coverage: JSON contract structure ----------

#[test]
fn track_d_contract_failure_policy_mode_is_fail_closed() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed"),
        "failure_policy.mode must be fail_closed"
    );
}

#[test]
fn track_d_contract_generated_by_matches_primary_bead() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let generated_by = value["generated_by"].as_str().expect("generated_by");
    let primary_bead = value["primary_bead"].as_str().expect("primary_bead");
    assert_eq!(
        generated_by, primary_bead,
        "generated_by and primary_bead must match"
    );
}

#[test]
fn track_d_contract_schema_version_contains_track_d() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"].as_str().expect("schema_version");
    assert!(
        sv.contains("track-d") || sv.contains("wasm-lane"),
        "schema_version must reference track-d or wasm-lane, got: {sv}"
    );
}

#[test]
fn track_d_contract_track_id_is_frx_11_4() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["track"]["id"].as_str(),
        Some("FRX-11.4"),
        "track.id must be FRX-11.4"
    );
}

#[test]
fn track_d_contract_activation_gate_block_on_missing_calibration_evidence() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["activation_gate"]["block_on_missing_calibration_evidence"].as_bool(),
        Some(true),
        "block_on_missing_calibration_evidence must be true"
    );
}

#[test]
fn track_d_contract_activation_gate_block_on_missing_failover_replay_linkage() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["activation_gate"]["block_on_missing_failover_replay_linkage"].as_bool(),
        Some(true),
        "block_on_missing_failover_replay_linkage must be true"
    );
}

#[test]
fn track_d_contract_activation_gate_requires_governance_signoff() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["activation_gate"]["requires_verification_and_governance_signoff"].as_bool(),
        Some(true),
        "requires_verification_and_governance_signoff must be true"
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_abi_overhead_us() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("abi_overhead_us")),
        "router decision must include abi_overhead_us field"
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_lane_choice() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("lane_choice")),
        "router decision must include lane_choice field"
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_calibration_snapshot_id() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields
            .iter()
            .any(|f| f.as_str() == Some("calibration_snapshot_id")),
        "router decision must include calibration_snapshot_id field"
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_override_reason() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("override_reason")),
        "router decision must include override_reason field"
    );
}

#[test]
fn track_d_contract_generated_at_utc_is_nonempty() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(!ts.trim().is_empty(), "generated_at_utc must not be empty");
}

#[test]
fn track_d_contract_parses_to_object_at_root() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object(), "contract JSON root must be an object");
}

#[test]
fn track_d_contract_router_decision_field_count_at_least_eight() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.len() >= 8,
        "router_decision_artifact must have at least 8 required fields, found {}",
        fields.len()
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_trace_id() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("trace_id")),
        "router decision must include trace_id field"
    );
}

#[test]
fn track_d_contract_router_decision_fields_contain_decision_id() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        fields.iter().any(|f| f.as_str() == Some("decision_id")),
        "router decision must include decision_id field"
    );
}

// ---------- Additional: source file surface checks ----------

#[test]
fn track_d_wasm_lane_source_file_exists() {
    let path = repo_root().join("crates/franken-engine/src/wasm_runtime_lane.rs");
    assert!(path.exists(), "wasm_runtime_lane.rs source file must exist");
}

#[test]
fn track_d_hybrid_router_source_file_exists() {
    let path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    assert!(
        path.exists(),
        "hybrid_lane_router.rs source file must exist"
    );
}

#[test]
fn track_d_wasm_lane_source_mentions_wasm_budget() {
    let path = repo_root().join("crates/franken-engine/src/wasm_runtime_lane.rs");
    let src = fs::read_to_string(&path).expect("read wasm_runtime_lane.rs");
    assert!(
        src.contains("pub struct WasmBudget"),
        "wasm_runtime_lane.rs must define WasmBudget"
    );
}

#[test]
fn track_d_wasm_lane_source_mentions_bounded_queue() {
    let path = repo_root().join("crates/franken-engine/src/wasm_runtime_lane.rs");
    let src = fs::read_to_string(&path).expect("read wasm_runtime_lane.rs");
    assert!(
        src.contains("pub struct BoundedQueue"),
        "wasm_runtime_lane.rs must define BoundedQueue"
    );
}

#[test]
fn track_d_hybrid_router_source_mentions_lane_choice() {
    let path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    let src = fs::read_to_string(&path).expect("read hybrid_lane_router.rs");
    assert!(
        src.contains("pub enum LaneChoice"),
        "hybrid_lane_router.rs must define LaneChoice"
    );
}

#[test]
fn track_d_hybrid_router_source_mentions_demotion_reason() {
    let path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    let src = fs::read_to_string(&path).expect("read hybrid_lane_router.rs");
    assert!(
        src.contains("pub enum DemotionReason"),
        "hybrid_lane_router.rs must define DemotionReason"
    );
}

#[test]
fn track_d_hybrid_router_source_mentions_routing_policy() {
    let path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    let src = fs::read_to_string(&path).expect("read hybrid_lane_router.rs");
    assert!(
        src.contains("pub enum RoutingPolicy"),
        "hybrid_lane_router.rs must define RoutingPolicy"
    );
}
