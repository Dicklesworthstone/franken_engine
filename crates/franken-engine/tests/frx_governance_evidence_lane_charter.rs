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
fn frx_governance_evidence_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Governance/Evidence Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Policy-as-Data Integrity and Signing",
        "## Evidence Ledger and Explainability Surfaces",
        "## Failure and Deterministic Safe Mode Policy",
        "## Interface Contracts",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "governance/evidence lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "policy-as-data integrity",
        "evidence-ledger correctness",
        "machine-readable evidence ID",
        "disable adaptive behavior",
        "conservative deterministic mode",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "governance/evidence lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_governance_evidence_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.governance-evidence.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.7"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.7"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.7"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("conservative_deterministic")
    );
    assert_eq!(
        value["failure_policy"]["disable_adaptive_behavior_on_integrity_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["incident_artifact_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_until_revalidated"].as_bool(),
        Some(true)
    );

    let required_logging_fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    for field in ["trace_id", "decision_id", "policy_id", "evidence_id"] {
        assert!(
            required_logging_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "required logging field missing: {field}"
        );
    }

    let required_query_fields = value["outputs"]["evidence_ledger"]["required_query_fields"]
        .as_array()
        .expect("required_query_fields must be an array");
    for field in ["trace_id", "decision_id", "policy_id", "evidence_id"] {
        assert!(
            required_query_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "required evidence ledger query field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_governance_evidence_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["governance_lane_charter"].as_str(),
        Some("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["governance_lane_contract"].as_str(),
        Some("docs/frx_governance_evidence_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn governance_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn governance_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn governance_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.7"));
}

#[test]
fn governance_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn governance_contract_has_evidence_ledger_output() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"]["evidence_ledger"].is_object());
}

#[test]
fn governance_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn governance_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn governance_contract_has_failure_policy_object() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_charter_mentions_evidence() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("evidence"));
}

#[test]
fn governance_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn governance_charter_mentions_policy_as_data() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("policy-as-data"));
}

#[test]
fn governance_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn governance_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn governance_contract_has_release_gate_contract() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["release_gate_contract"].is_object());
}

#[test]
fn governance_contract_has_inputs_section() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["inputs"].is_object() || value["inputs"].is_array());
}

#[test]
fn governance_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn governance_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn governance_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn governance_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn governance_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn governance_contract_schema_version_is_nonempty() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version string");
    assert!(!sv.trim().is_empty());
}

// ---------- enrichment: deeper structural and cross-field checks ----------

#[test]
fn governance_contract_ownership_section_has_required_subsections() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ownership = &value["ownership"];
    assert!(ownership.is_object(), "ownership must be an object");
    for subsection in [
        "schema_governance",
        "policy_signing_and_verification",
        "explainability_surfaces",
    ] {
        assert!(
            ownership[subsection].is_object(),
            "ownership missing subsection: {subsection}"
        );
    }
    // policy signing must be fail-closed on errors
    assert_eq!(
        ownership["policy_signing_and_verification"]["fail_closed_on_signature_or_digest_error"]
            .as_bool(),
        Some(true),
        "policy signing must fail closed on signature/digest errors"
    );
}

#[test]
fn governance_contract_serde_roundtrip_via_value() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let reserialized = serde_json::to_string(&value).expect("re-serialize");
    let reparsed: Value = serde_json::from_str(&reserialized).expect("re-parse");
    assert_eq!(value, reparsed, "serde roundtrip must preserve all data");
}

#[test]
fn governance_contract_release_gate_all_booleans_true() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = &value["release_gate_contract"];
    assert!(gate.is_object());
    // all release gate predicates must be true (fail-closed)
    for (key, val) in gate.as_object().expect("release_gate_contract object") {
        assert_eq!(
            val.as_bool(),
            Some(true),
            "release_gate_contract.{key} must be true for fail-closed semantics"
        );
    }
}

#[test]
fn governance_contract_logging_fields_are_superset_of_evidence_ledger_query_fields() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let logging_fields: std::collections::BTreeSet<&str> =
        value["logging_contract"]["required_fields"]
            .as_array()
            .expect("logging required_fields array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

    let query_fields: std::collections::BTreeSet<&str> =
        value["outputs"]["evidence_ledger"]["required_query_fields"]
            .as_array()
            .expect("evidence ledger query fields array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

    // every query field must also appear in logging fields so evidence can be reconstructed from logs
    for qf in &query_fields {
        assert!(
            logging_fields.contains(qf),
            "evidence ledger query field '{qf}' missing from logging contract required_fields"
        );
    }
}

#[test]
fn governance_contract_outputs_policy_conformance_report_has_required_fields() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pcr = &value["outputs"]["policy_conformance_report"];
    assert!(pcr.is_object(), "policy_conformance_report must exist");
    assert_eq!(pcr["required"].as_bool(), Some(true));
    let fields = pcr["required_fields"]
        .as_array()
        .expect("required_fields array");
    for expected in ["policy_id", "outcome", "signature_status"] {
        assert!(
            fields.iter().any(|f| f.as_str() == Some(expected)),
            "policy_conformance_report missing field: {expected}"
        );
    }
}

// ---------- enrichment: deeper edge-case and structural tests ----------

#[test]
fn governance_charter_doc_references_explainability_surfaces() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(
        doc.contains("explainability"),
        "governance charter must reference explainability surfaces"
    );
}

#[test]
fn governance_contract_failure_policy_requires_incident_artifact() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["incident_artifact_required"].as_bool(),
        Some(true),
        "failure_policy must require incident artifact"
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_until_revalidated"].as_bool(),
        Some(true),
        "failure_policy must block promotion until revalidated"
    );
}

#[test]
fn governance_contract_all_top_level_keys_are_present() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
        "logging_contract",
        "outputs",
    ] {
        assert!(
            keys.contains(required_key),
            "governance contract missing top-level key: {required_key}"
        );
    }
}

#[test]
fn governance_charter_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "governance charter must not contain unresolved TODO/FIXME/XXX markers"
    );
}

#[test]
fn governance_contract_logging_required_fields_are_nonempty_strings() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("required_fields array");
    assert!(
        !fields.is_empty(),
        "logging required_fields must not be empty"
    );
    for field in fields {
        assert!(
            field.as_str().is_some_and(|s| !s.trim().is_empty()),
            "each logging required_field must be a non-empty string"
        );
    }
}

// ---------------------------------------------------------------------------
// Enrichment batch 3: deeper structural and cross-field invariants
// ---------------------------------------------------------------------------

#[test]
fn governance_charter_word_count_at_least_three_hundred() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 300,
        "charter should have at least 300 words, got {}",
        word_count
    );
}

#[test]
fn governance_charter_h2_count_at_least_eight() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let h2_count = doc.lines().filter(|l| l.starts_with("## ")).count();
    assert!(
        h2_count >= 8,
        "charter should have at least 8 H2 sections, got {}",
        h2_count
    );
}

#[test]
fn governance_contract_has_at_least_ten_top_level_keys() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let obj = value.as_object().expect("top-level must be object");
    assert!(
        obj.len() >= 10,
        "contract should have at least 10 top-level keys, got {}",
        obj.len()
    );
}

#[test]
fn governance_charter_mentions_signing_or_signature() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let lower = doc.to_ascii_lowercase();
    assert!(
        lower.contains("signing") || lower.contains("signature"),
        "charter should mention signing or signature concepts"
    );
}

#[test]
fn governance_contract_lane_name_nonempty() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let name = value["lane"]["name"]
        .as_str()
        .expect("lane.name must be string");
    assert!(!name.trim().is_empty(), "lane.name must not be empty");
}

#[test]
fn governance_contract_primary_bead_starts_with_bd() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_contract_schema_version_starts_with_frx() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_contract_generated_by_starts_with_bd() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_charter_deterministic_double_read() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b, "charter must be deterministic on double read");
}

#[test]
fn governance_contract_json_size_reasonable() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_charter_line_count_at_least_eighty() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    let line_count = doc.lines().count();
    assert!(
        line_count >= 80,
        "charter should have at least 80 lines, got {}",
        line_count
    );
}

#[test]
fn governance_charter_mentions_integrity() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter");
    assert!(doc.contains("integrity"), "charter must mention integrity");
}

#[test]
fn governance_contract_outputs_has_at_least_two_subsections() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let outputs = value["outputs"]
        .as_object()
        .expect("outputs must be object");
    assert!(
        outputs.len() >= 2,
        "outputs must have at least 2 subsections, got {}",
        outputs.len()
    );
}

#[test]
fn governance_contract_lane_id_starts_with_frx() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
fn governance_contract_generated_at_utc_contains_t_separator() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
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
