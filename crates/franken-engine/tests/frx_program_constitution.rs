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
fn frx_program_constitution_contains_required_sections() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Program Constitution v1",
        "## Purpose",
        "## Objective Function",
        "## Compatibility Scope and Non-Goals",
        "## Testable Constitutional Invariants",
        "## Loss Matrix, Calibration, and Fallback Linkage",
        "## Program Metrics (North-Star + Guardrails)",
        "## Downstream Workstream Contract",
        "## Program-Wide Test Gate",
        "## Change Control",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "program constitution missing section: {section}"
        );
    }

    let required_clauses = [
        "frx.program.constitution.v1",
        "FRX-CI-001",
        "FRX-CI-005",
        "deterministic safe mode",
        "fail-closed",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "program constitution missing clause: {clause}"
        );
    }
}

#[test]
fn frx_objective_function_contract_is_machine_readable() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.objective_function.v1")
    );
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.1"));
    assert_eq!(
        value["constitution_ref"].as_str(),
        Some("docs/FRX_PROGRAM_CONSTITUTION_V1.md")
    );

    let dimensions = value["objective"]["dimensions"]
        .as_array()
        .expect("objective.dimensions must be an array");
    let expected_dimensions = ["compatibility", "deterministic_reliability", "performance"];
    for dim in expected_dimensions {
        assert!(
            dimensions.iter().any(|entry| entry.as_str() == Some(dim)),
            "objective dimension missing: {dim}"
        );
    }

    let required_decision_links = [
        (
            "loss_matrix_source",
            "crates/franken-engine/src/expected_loss_selector.rs",
        ),
        (
            "calibration_source",
            "crates/franken-engine/src/runtime_decision_theory.rs",
        ),
        (
            "fallback_policy_source",
            "crates/franken-engine/src/safe_mode_fallback.rs",
        ),
    ];
    for (field, expected) in required_decision_links {
        assert_eq!(
            value["decision_model"][field].as_str(),
            Some(expected),
            "unexpected {field}"
        );
    }
}

#[test]
fn frx_freeze_manifest_and_lane_charters_reference_program_constitution() {
    let freeze_manifest_path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let freeze_manifest_raw = fs::read_to_string(&freeze_manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", freeze_manifest_path.display()));
    let freeze_manifest: Value = serde_json::from_str(&freeze_manifest_raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", freeze_manifest_path.display()));

    assert_eq!(
        freeze_manifest["artifacts"]["program_constitution"].as_str(),
        Some("docs/FRX_PROGRAM_CONSTITUTION_V1.md")
    );
    assert_eq!(
        freeze_manifest["artifacts"]["objective_function_contract"].as_str(),
        Some("docs/frx_objective_function_v1.json")
    );

    let compiler_charter_path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let compiler_charter = fs::read_to_string(&compiler_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", compiler_charter_path.display()));
    assert!(
        compiler_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "compiler lane charter must reference program constitution"
    );

    let semantics_charter_path = repo_root().join("docs/FRX_SEMANTICS_LANE_CHARTER_V1.md");
    let semantics_charter = fs::read_to_string(&semantics_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", semantics_charter_path.display()));
    assert!(
        semantics_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "semantics lane charter must reference program constitution"
    );

    let verification_charter_path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let verification_charter =
        fs::read_to_string(&verification_charter_path).unwrap_or_else(|err| {
            panic!(
                "failed to read {}: {err}",
                verification_charter_path.display()
            )
        });
    assert!(
        verification_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "verification lane charter must reference program constitution"
    );

    let optimization_charter_path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let optimization_charter =
        fs::read_to_string(&optimization_charter_path).unwrap_or_else(|err| {
            panic!(
                "failed to read {}: {err}",
                optimization_charter_path.display()
            )
        });
    assert!(
        optimization_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "optimization lane charter must reference program constitution"
    );

    let toolchain_charter_path =
        repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let toolchain_charter = fs::read_to_string(&toolchain_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", toolchain_charter_path.display()));
    assert!(
        toolchain_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "toolchain lane charter must reference program constitution"
    );

    let governance_charter_path =
        repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let governance_charter = fs::read_to_string(&governance_charter_path).unwrap_or_else(|err| {
        panic!(
            "failed to read {}: {err}",
            governance_charter_path.display()
        )
    });
    assert!(
        governance_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "governance/evidence lane charter must reference program constitution"
    );

    let adoption_charter_path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let adoption_charter = fs::read_to_string(&adoption_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adoption_charter_path.display()));
    assert!(
        adoption_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "adoption/release lane charter must reference program constitution"
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- doc content ----------

#[test]
fn constitution_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read constitution doc");
    assert!(!doc.is_empty());
}

#[test]
fn constitution_doc_references_invariants() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read constitution doc");
    assert!(doc.contains("FRX-CI-001"));
    assert!(doc.contains("FRX-CI-005"));
}

// ---------- objective function JSON ----------

#[test]
fn objective_function_json_has_decision_model() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["decision_model"].is_object());
}

#[test]
fn objective_function_json_is_deterministic() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

// ---------- freeze manifest ----------

#[test]
fn freeze_manifest_has_schema_version() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["schema_version"].is_string());
}

#[test]
fn freeze_manifest_artifacts_are_nonempty() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let artifacts = value["artifacts"].as_object().expect("artifacts object");
    assert!(!artifacts.is_empty());
}

#[test]
fn objective_function_has_objective_dimensions() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let dims = value["objective"]["dimensions"]
        .as_array()
        .expect("dimensions array");
    assert!(!dims.is_empty());
}

#[test]
fn objective_function_has_constitution_ref() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let cr = value["constitution_ref"]
        .as_str()
        .expect("constitution_ref");
    assert!(!cr.is_empty());
}

#[test]
fn constitution_doc_mentions_safe_mode() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.contains("safe mode"));
}

#[test]
fn objective_function_has_schema_version() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn freeze_manifest_json_is_deterministic() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn constitution_doc_mentions_deterministic() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("deterministic"));
}

#[test]
fn objective_function_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn objective_function_has_testable_invariants() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let invariants = value["testable_invariants"]
        .as_array()
        .expect("testable_invariants array");
    assert!(!invariants.is_empty());
}

#[test]
fn objective_function_has_primary_bead() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["primary_bead"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn constitution_doc_has_more_than_100_lines() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 100);
}

#[test]
fn objective_function_json_is_an_object() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn objective_function_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn constitution_doc_file_exists() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    assert!(path.exists());
}

#[test]
fn objective_function_json_file_exists() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    assert!(path.exists());
}

#[test]
fn freeze_manifest_json_file_exists() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    assert!(path.exists());
}

// ---------- enrichment: deeper structural checks ----------

#[test]
fn objective_function_non_goals_are_declared_and_nonempty() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let non_goals = value["non_goals"]
        .as_array()
        .expect("non_goals must be an array");
    assert!(
        non_goals.len() >= 2,
        "at least 2 non-goals must be declared"
    );
    for ng in non_goals {
        let s = ng.as_str().expect("non-goal must be a string");
        assert!(!s.trim().is_empty(), "non-goal entry must not be blank");
    }
}

#[test]
fn objective_function_hard_constraints_include_fail_closed() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let hc = value["objective"]["hard_constraints"]
        .as_array()
        .expect("hard_constraints must be an array");
    assert!(
        hc.iter()
            .any(|c| c.as_str().is_some_and(|s| s.contains("fail_closed"))),
        "hard_constraints must include a fail-closed constraint"
    );
    assert!(
        hc.iter().any(|c| c
            .as_str()
            .is_some_and(|s| s.contains("deterministic_safe_mode"))),
        "hard_constraints must include deterministic safe mode constraint"
    );
}

#[test]
fn objective_function_status_is_active() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["status"].as_str(),
        Some("active"),
        "objective function status must be active"
    );
}

#[test]
fn freeze_manifest_downstream_reference_required_is_true() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["downstream_reference_required"].as_bool(),
        Some(true),
        "freeze manifest must require downstream references"
    );
}

#[test]
fn objective_function_serde_roundtrip_via_value_preserves_all_keys() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
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

// ---------- enrichment: deeper cross-document and constraint checks ----------

#[test]
fn constitution_doc_mentions_loss_matrix() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("loss matrix"),
        "constitution doc must mention loss matrix"
    );
}

#[test]
fn objective_function_dimensions_are_all_nonempty_strings() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let dims = value["objective"]["dimensions"]
        .as_array()
        .expect("dimensions array");
    for dim in dims {
        let s = dim.as_str().expect("dimension must be a string");
        assert!(!s.trim().is_empty(), "dimension entry must not be blank");
    }
}

#[test]
fn freeze_manifest_has_generated_at_utc_ending_with_z() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(
        ts.ends_with('Z'),
        "freeze manifest generated_at_utc must end with Z"
    );
}

#[test]
fn objective_function_testable_invariants_include_ci_codes() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let invariants = value["testable_invariants"]
        .as_array()
        .expect("testable_invariants");
    let invariant_strs: Vec<&str> = invariants.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        invariant_strs.iter().any(|s| s.contains("FRX-CI-001")),
        "testable_invariants must reference FRX-CI-001"
    );
}

#[test]
fn constitution_doc_references_compatibility() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("compatibility"),
        "constitution doc must mention compatibility"
    );
}
