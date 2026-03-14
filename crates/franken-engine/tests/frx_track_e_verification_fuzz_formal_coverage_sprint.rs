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
fn frx_track_e_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track E Verification/Fuzz/Formal Coverage Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Confidence Trajectory and Metrics Contract",
        "## Promotion Gate and Escalation Behavior",
        "## Counterexample Reproduction and Ownership Routing",
        "## Formal/Model-Check Stewardship",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track E charter missing section: {section}"
        );
    }

    let required_clauses = [
        "confidence trajectory over time",
        "promotion gatekeeper",
        "blocking reports",
        "minimized reproductions",
        "ownership routing",
        "metamorphic relations",
        "schedule perturbation harnesses",
        "formal/model-checking artifacts",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "track E charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_e_contract_is_machine_readable_and_fail_closed() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-e.verification-fuzz-formal-coverage.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.5"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.5"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.5"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_critical_unresolved_counterexample"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_confidence_regression"].as_bool(),
        Some(true)
    );

    let blocking_report_fields = value["outputs"]["blocking_report"]["required_fields"]
        .as_array()
        .expect("blocking report fields must be an array");

    for field in [
        "counterexample_id",
        "owner_track",
        "minimized_reproduction_id",
        "replay_command",
    ] {
        assert!(
            blocking_report_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "blocking report field missing: {field}"
        );
    }
}

#[test]
fn frx_track_e_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Track E Verification/Fuzz/Formal Coverage Sprint Gate"),
        "README missing track E gate heading"
    );
    assert!(
        readme.contains(
            "./scripts/run_frx_track_e_verification_fuzz_formal_coverage_sprint_suite.sh ci"
        ),
        "README missing track E gate command"
    );
    assert!(
        readme.contains(
            "./scripts/e2e/frx_track_e_verification_fuzz_formal_coverage_sprint_replay.sh"
        ),
        "README missing track E replay command"
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc content ----------

#[test]
fn track_e_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track E doc");
    assert!(!doc.is_empty());
}

#[test]
fn track_e_charter_references_fail_closed() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track E doc");
    assert!(doc.contains("counterexample"));
}

// ---------- JSON contract fields ----------

#[test]
fn track_e_contract_has_track_section() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["track"].is_object());
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.5"));
}

#[test]
fn track_e_contract_has_activation_gate() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn track_e_contract_has_outputs_section() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["blocking_report"].is_object());
}

#[test]
fn track_e_contract_failure_policy_is_fail_closed() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn track_e_contract_json_is_deterministic() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn track_e_contract_has_generated_at_utc() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn track_e_contract_has_failure_policy_object() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
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
fn track_e_charter_mentions_fuzz() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("fuzz"));
}

#[test]
fn track_e_contract_has_primary_bead() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["primary_bead"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_e_charter_mentions_metamorphic() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("metamorphic"));
}

#[test]
fn track_e_contract_blocking_report_has_required_fields_array() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["outputs"]["blocking_report"]["required_fields"]
        .as_array()
        .expect("required_fields must be array");
    assert!(!fields.is_empty());
}

#[test]
fn track_e_contract_has_schema_version() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"].as_str().expect("schema_version");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_e_contract_has_generated_by() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_e_charter_mentions_formal_verification() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("Formal"));
}

#[test]
fn track_e_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let line_count = doc.lines().count();
    assert!(
        line_count > 50,
        "doc should have >50 lines, got {line_count}"
    );
}

#[test]
fn track_e_contract_deterministic_double_parse() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let a: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    let b: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    assert_eq!(a, b);
}

#[test]
fn track_e_contract_is_a_json_object() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let value: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    assert!(value.is_object());
}

#[test]
fn track_e_contract_logging_contract_has_required_fields() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let logging = &value["logging_contract"];
    assert!(logging.is_object(), "logging_contract must be an object");
    assert!(
        !logging["component"].as_str().unwrap_or("").is_empty(),
        "logging_contract.component must be non-empty"
    );
    let fields = logging["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    for expected in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
    ] {
        assert!(
            fields.iter().any(|f| f.as_str() == Some(expected)),
            "logging_contract missing field: {expected}"
        );
    }
}

#[test]
fn track_e_contract_ownership_sections_are_required() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let ownership = &value["ownership"];
    assert!(ownership.is_object(), "ownership must be an object");
    for section in [
        "lockstep_oracle_coverage",
        "metamorphic_and_schedule_campaigns",
        "formal_modelcheck_stewardship",
    ] {
        assert!(
            ownership[section].is_object(),
            "ownership missing section: {section}"
        );
        assert_eq!(
            ownership[section]["required"].as_bool(),
            Some(true),
            "ownership.{section}.required must be true"
        );
    }
}

#[test]
fn track_e_contract_inputs_are_nonempty_strings() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    let inputs = value["inputs"].as_array().expect("inputs must be an array");
    assert!(!inputs.is_empty(), "inputs must not be empty");
    for input in inputs {
        assert!(
            input.as_str().is_some_and(|s| !s.trim().is_empty()),
            "each input must be a non-empty string"
        );
    }
}

#[test]
fn track_e_contract_outputs_promotion_gate_decision_exists() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");

    assert!(
        value["outputs"]["promotion_gate_decision"].is_object(),
        "outputs.promotion_gate_decision must exist"
    );
    assert!(
        value["outputs"]["confidence_trajectory_bundle"].is_object(),
        "outputs.confidence_trajectory_bundle must exist"
    );
}

#[test]
fn track_e_contract_activation_gate_requires_ownership_routing() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["activation_gate"]["requires_ownership_routing"].as_bool(),
        Some(true)
    );
}

#[test]
fn track_e_contract_track_name_is_nonempty() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let name = value["track"]["name"]
        .as_str()
        .expect("track.name must be a string");
    assert!(!name.trim().is_empty(), "track.name must not be empty");
}

#[test]
fn track_e_charter_doc_contains_interface_contracts_and_escalation() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("Interface Contracts"));
    assert!(doc.contains("Escalation"));
}

#[test]
fn track_e_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    assert!(path.exists(), "track E charter doc must exist");
}

#[test]
fn track_e_contract_json_file_exists() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    assert!(path.exists(), "track E contract JSON must exist");
}

#[test]
fn track_e_charter_word_count_exceeds_minimum() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 100,
        "charter doc should have >= 100 words, got {word_count}"
    );
}

// ===== PearlTower enrichment session 2026-03-14 =====

#[test]
fn track_e_contract_deterministic_double_parse_v2() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn track_e_contract_json_pretty_roundtrip_stable() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    let pretty = serde_json::to_string_pretty(&value).expect("pretty");
    let reparsed: Value = serde_json::from_str(&pretty).expect("reparse");
    assert_eq!(value, reparsed);
}

#[test]
fn track_e_contract_has_track_id() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    let track_id = value["track"]["id"].as_str().expect("track.id");
    assert!(!track_id.trim().is_empty());
}

#[test]
fn track_e_contract_bead_id_is_hierarchical() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    let bead_id = value["bead_id"].as_str().expect("bead_id");
    assert!(
        bead_id.starts_with("bd-"),
        "bead_id must start with bd-: {bead_id}"
    );
}

#[test]
fn track_e_contract_outputs_blocking_reports_exists() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    assert!(
        value["outputs"]["blocking_reports"].is_object()
            || value["outputs"]["blocking_reports"].is_array(),
        "outputs.blocking_reports must exist"
    );
}

#[test]
fn track_e_contract_activation_gate_has_required_fields() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    let gate = &value["activation_gate"];
    assert!(gate.is_object(), "activation_gate must be an object");
}

#[test]
fn track_e_contract_responsibilities_are_nonempty() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    if let Some(responsibilities) = value["responsibilities"].as_array() {
        assert!(!responsibilities.is_empty());
        for r in responsibilities {
            assert!(
                r.as_str().is_some_and(|s| !s.trim().is_empty()),
                "each responsibility must be a non-empty string"
            );
        }
    }
}

#[test]
fn track_e_contract_operator_verification_commands_are_nonempty() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    if let Some(cmds) = value["operator_verification"].as_array() {
        assert!(!cmds.is_empty());
        for cmd in cmds {
            assert!(
                cmd.as_str().is_some_and(|s| !s.trim().is_empty()),
                "operator verification command must be nonempty"
            );
        }
    }
}

#[test]
fn enrichment_charter_mentions_counterexample() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("counterexample") || doc.contains("Counterexample"),
        "charter must mention counterexample handling"
    );
}

#[test]
fn enrichment_charter_mentions_metamorphic() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("metamorphic"),
        "charter must mention metamorphic relations"
    );
}

#[test]
fn enrichment_contract_schema_version_has_frx_prefix() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    let sv = value["schema_version"].as_str().expect("schema_version");
    assert!(
        sv.starts_with("frx."),
        "schema_version must start with frx.: {sv}"
    );
}

#[test]
fn enrichment_contract_json_is_nonempty_and_valid() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    assert!(raw.len() > 100, "contract JSON must be substantial");
    let _: Value = serde_json::from_str(&raw).expect("must be valid JSON");
}

#[test]
fn enrichment_confidence_trajectory_bundle_exists() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse");
    assert!(
        value["outputs"]["confidence_trajectory_bundle"].is_object(),
        "outputs.confidence_trajectory_bundle must exist"
    );
}
