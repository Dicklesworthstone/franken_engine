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
fn frx_adoption_release_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Adoption/Release Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Stage-Gate and Artifact Prerequisites",
        "## Rollback and Oncall Readiness",
        "## Claim Publication Integrity",
        "## Failure and Promotion Halt Policy",
        "## Interface Contracts",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "adoption/release lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "pilot rollout strategy",
        "stage-gate discipline",
        "rollback drills",
        "oncall readiness",
        "complete reproducibility bundles",
        "claim-to-artifact linkage",
        "halt promotion and enforce remediation",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "adoption/release lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_adoption_release_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.adoption-release.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.8"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.8"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.8"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("promotion_halt")
    );
    assert_eq!(
        value["failure_policy"]["halt_promotion_on_stage_gate_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["halt_promotion_on_rollback_readiness_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_claim_publication_on_incomplete_repro_bundle"].as_bool(),
        Some(true)
    );

    let stages = value["ownership"]["stage_gate_authority"]["stages"]
        .as_array()
        .expect("stages must be an array");
    for stage in ["alpha", "beta", "ga"] {
        assert!(
            stages.iter().any(|entry| entry.as_str() == Some(stage)),
            "stage missing: {stage}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_adoption_release_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["adoption_lane_charter"].as_str(),
        Some("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["adoption_lane_contract"].as_str(),
        Some("docs/frx_adoption_release_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn adoption_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn adoption_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn adoption_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.8"));
}

#[test]
fn adoption_contract_has_ownership_section() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["ownership"].is_object());
    assert!(value["ownership"]["stage_gate_authority"].is_object());
}

#[test]
fn adoption_contract_stages_include_alpha_beta_ga() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let stages = value["ownership"]["stage_gate_authority"]["stages"]
        .as_array()
        .expect("stages array");
    let stage_strs: Vec<&str> = stages.iter().filter_map(|s| s.as_str()).collect();
    assert!(stage_strs.contains(&"alpha"));
    assert!(stage_strs.contains(&"beta"));
    assert!(stage_strs.contains(&"ga"));
}

#[test]
fn adoption_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn adoption_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn adoption_contract_has_failure_policy_object() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
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
fn adoption_charter_mentions_rollback() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("rollback"));
}

#[test]
fn adoption_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn adoption_charter_mentions_claim_publication() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("claim"));
    assert!(doc.contains("publication"));
}

#[test]
fn adoption_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn adoption_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn adoption_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn adoption_contract_has_release_gate_contract() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["release_gate_contract"].is_object());
}

#[test]
fn adoption_contract_json_parses_as_object() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn adoption_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50, "charter should be substantial");
}

#[test]
fn adoption_contract_schema_version_is_nonempty_string() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn adoption_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn adoption_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn adoption_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn adoption_contract_serde_roundtrip_preserves_all_top_level_keys() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let serialized = serde_json::to_string_pretty(&value).expect("re-serialize");
    let roundtripped: Value = serde_json::from_str(&serialized).expect("re-parse");

    let orig_keys: Vec<&str> = value
        .as_object()
        .expect("top-level object")
        .keys()
        .map(String::as_str)
        .collect();
    let rt_keys: Vec<&str> = roundtripped
        .as_object()
        .expect("top-level object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        orig_keys, rt_keys,
        "serde roundtrip must preserve all top-level keys"
    );
    assert_eq!(value, roundtripped, "serde roundtrip must be lossless");
}

#[test]
fn adoption_contract_failure_policy_all_booleans_are_true() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let fp = &value["failure_policy"];
    for key in [
        "halt_promotion_on_stage_gate_failure",
        "halt_promotion_on_rollback_readiness_failure",
        "block_claim_publication_on_incomplete_repro_bundle",
    ] {
        assert_eq!(
            fp[key].as_bool(),
            Some(true),
            "failure_policy.{key} must be true for fail-closed semantics"
        );
    }
}

#[test]
fn adoption_charter_interface_contracts_section_references_known_lanes() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");

    // Interface Contracts section should cross-reference at least one other lane
    let interface_idx = doc
        .find("## Interface Contracts")
        .expect("section must exist");
    let interface_section = &doc[interface_idx..];
    assert!(
        interface_section.contains("Compiler")
            || interface_section.contains("Verification")
            || interface_section.contains("Toolchain")
            || interface_section.contains("Optimization"),
        "Interface Contracts section must reference at least one peer lane"
    );
}

#[test]
fn adoption_contract_stages_are_ordered_alpha_beta_ga() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let stages: Vec<&str> = value["ownership"]["stage_gate_authority"]["stages"]
        .as_array()
        .expect("stages array")
        .iter()
        .filter_map(|s| s.as_str())
        .collect();

    let alpha_pos = stages.iter().position(|&s| s == "alpha");
    let beta_pos = stages.iter().position(|&s| s == "beta");
    let ga_pos = stages.iter().position(|&s| s == "ga");

    assert!(
        alpha_pos < beta_pos,
        "alpha must precede beta in stage order"
    );
    assert!(beta_pos < ga_pos, "beta must precede ga in stage order");
}

#[test]
fn adoption_charter_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "charter must not contain unresolved TODO/FIXME/XXX markers"
    );
}
