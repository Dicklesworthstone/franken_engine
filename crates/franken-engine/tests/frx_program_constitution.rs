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

// ---------- enrichment: constitution invariant cross-referencing ----------

#[test]
fn constitution_doc_references_all_five_ci_codes() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    for i in 1..=5 {
        let code = format!("FRX-CI-00{i}");
        assert!(doc.contains(&code), "constitution must reference {code}");
    }
}

#[test]
fn objective_function_all_invariant_ids_are_unique() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let invariants = value["testable_invariants"]
        .as_array()
        .expect("testable_invariants array");
    let mut ids = std::collections::BTreeSet::new();
    for inv in invariants {
        let id = inv["id"].as_str().expect("invariant id must be string");
        assert!(ids.insert(id), "duplicate invariant id: {id}");
    }
}

#[test]
fn objective_function_all_invariant_entries_have_name_and_verification_ref() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let invariants = value["testable_invariants"]
        .as_array()
        .expect("testable_invariants array");
    for inv in invariants {
        let id = inv["id"].as_str().unwrap_or("?");
        let name = inv["name"].as_str().expect("invariant name must be string");
        let vref = inv["verification_ref"]
            .as_str()
            .expect("invariant verification_ref must be string");
        assert!(!name.trim().is_empty(), "invariant {id} name is blank");
        assert!(
            !vref.trim().is_empty(),
            "invariant {id} verification_ref is blank"
        );
    }
}

#[test]
fn objective_function_metrics_have_north_star_and_guardrails() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let metrics = value["metrics"].as_object().expect("metrics object");
    assert!(
        metrics.contains_key("north_star"),
        "metrics must have north_star"
    );
    assert!(
        metrics.contains_key("guardrails"),
        "metrics must have guardrails"
    );
    let ns = value["metrics"]["north_star"]
        .as_array()
        .expect("north_star array");
    assert!(!ns.is_empty(), "north_star metrics must not be empty");
    let guardrails = value["metrics"]["guardrails"]
        .as_array()
        .expect("guardrails array");
    assert!(
        !guardrails.is_empty(),
        "guardrail metrics must not be empty"
    );
}

#[test]
fn objective_function_north_star_metrics_have_direction_maximize() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ns = value["metrics"]["north_star"]
        .as_array()
        .expect("north_star array");
    for metric in ns {
        let id = metric["id"].as_str().unwrap_or("?");
        let direction = metric["direction"]
            .as_str()
            .expect("direction must be string");
        assert_eq!(
            direction, "maximize",
            "north_star metric {id} must have direction=maximize"
        );
    }
}

#[test]
fn objective_function_guardrail_metrics_have_direction_minimize() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let guardrails = value["metrics"]["guardrails"]
        .as_array()
        .expect("guardrails array");
    for metric in guardrails {
        let id = metric["id"].as_str().unwrap_or("?");
        let direction = metric["direction"]
            .as_str()
            .expect("direction must be string");
        assert_eq!(
            direction, "minimize",
            "guardrail metric {id} must have direction=minimize"
        );
    }
}

#[test]
fn objective_function_downstream_reference_policy_is_present_and_complete() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let policy = value["downstream_reference_policy"]
        .as_object()
        .expect("downstream_reference_policy must be an object");
    assert!(
        policy.contains_key("constitution_ref_mandatory"),
        "downstream_reference_policy must have constitution_ref_mandatory"
    );
    assert_eq!(
        value["downstream_reference_policy"]["constitution_ref_mandatory"].as_bool(),
        Some(true),
        "constitution_ref_mandatory must be true"
    );
    let req_fields = value["downstream_reference_policy"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    assert!(
        req_fields.len() >= 4,
        "at least 4 required downstream log fields must be declared"
    );
}

#[test]
fn freeze_manifest_promotion_block_rule_is_present() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let rule = value["promotion_block_rule"]
        .as_object()
        .expect("promotion_block_rule must be an object");
    assert!(
        rule.contains_key("rule_id"),
        "promotion_block_rule must have rule_id"
    );
    assert!(
        rule.contains_key("condition"),
        "promotion_block_rule must have condition"
    );
    assert!(
        rule.contains_key("action"),
        "promotion_block_rule must have action"
    );
    let action = value["promotion_block_rule"]["action"]
        .as_str()
        .expect("action must be string");
    assert!(
        !action.trim().is_empty(),
        "promotion_block_rule action must not be blank"
    );
}

#[test]
fn freeze_manifest_milestone_is_c0() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["milestone"].as_str(),
        Some("C0"),
        "freeze manifest milestone must be C0"
    );
}

#[test]
fn freeze_manifest_artifacts_include_all_lane_charters() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let artifacts = value["artifacts"].as_object().expect("artifacts object");
    let required_charter_keys = [
        "semantics_lane_charter",
        "compiler_lane_charter",
        "verification_lane_charter",
        "optimization_lane_charter",
        "toolchain_lane_charter",
        "governance_lane_charter",
        "adoption_lane_charter",
    ];
    for key in required_charter_keys {
        assert!(
            artifacts.contains_key(key),
            "freeze manifest artifacts must include {key}"
        );
        let val = artifacts[key].as_str().expect("{key} must be a string");
        assert!(
            val.ends_with(".md"),
            "charter artifact {key} must point to a .md file, got: {val}"
        );
    }
}

#[test]
fn forbidden_regressions_json_is_parseable_and_has_entries() {
    let path = repo_root().join("docs/frx_forbidden_regressions_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let entries = value["entries"]
        .as_array()
        .expect("entries must be an array");
    assert!(
        entries.len() >= 4,
        "at least 4 forbidden regression entries must be declared"
    );
}

#[test]
fn forbidden_regressions_all_entries_have_required_fields() {
    let path = repo_root().join("docs/frx_forbidden_regressions_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let entries = value["entries"]
        .as_array()
        .expect("entries must be an array");
    let required = ["id", "invariant", "description", "severity", "detection"];
    for entry in entries {
        let id = entry["id"].as_str().unwrap_or("?");
        for field in required {
            let val = entry[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} must be a string in {id}"));
            assert!(
                !val.trim().is_empty(),
                "field {field} must not be blank in entry {id}"
            );
        }
    }
}

#[test]
fn forbidden_regressions_all_entry_ids_are_unique() {
    let path = repo_root().join("docs/frx_forbidden_regressions_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let entries = value["entries"]
        .as_array()
        .expect("entries must be an array");
    let mut ids = std::collections::BTreeSet::new();
    for entry in entries {
        let id = entry["id"].as_str().expect("id must be string");
        assert!(ids.insert(id), "duplicate forbidden regression id: {id}");
    }
}

#[test]
fn forbidden_regressions_critical_entries_exist() {
    let path = repo_root().join("docs/frx_forbidden_regressions_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let entries = value["entries"]
        .as_array()
        .expect("entries must be an array");
    assert!(
        entries
            .iter()
            .any(|e| e["severity"].as_str() == Some("critical")),
        "at least one forbidden regression entry must have severity=critical"
    );
}

#[test]
fn compile_vs_fallback_json_has_schema_version_and_rules() {
    let path = repo_root().join("docs/frx_compile_vs_fallback_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty(), "schema_version must not be blank");
    let rules = value["rules"].as_array().expect("rules must be an array");
    assert!(
        rules.len() >= 3,
        "at least 3 compile-vs-fallback rules must be declared"
    );
}

#[test]
fn compile_vs_fallback_rules_all_have_required_fields() {
    let path = repo_root().join("docs/frx_compile_vs_fallback_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let rules = value["rules"].as_array().expect("rules must be an array");
    for rule in rules {
        let id = rule["rule_id"].as_str().unwrap_or("?");
        for field in ["rule_id", "condition", "decision", "action"] {
            let val = rule[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} must be a string in {id}"));
            assert!(
                !val.trim().is_empty(),
                "{field} must not be blank in rule {id}"
            );
        }
    }
}

#[test]
fn compile_vs_fallback_has_required_evidence_fields() {
    let path = repo_root().join("docs/frx_compile_vs_fallback_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["required_evidence_fields"]
        .as_array()
        .expect("required_evidence_fields must be an array");
    assert!(
        fields.len() >= 4,
        "at least 4 required evidence fields must be declared"
    );
    let field_strs: Vec<&str> = fields.iter().filter_map(|f| f.as_str()).collect();
    for required in ["trace_id", "decision_id", "policy_id"] {
        assert!(
            field_strs.contains(&required),
            "required_evidence_fields must include {required}"
        );
    }
}

#[test]
fn constitution_doc_mentions_governance_and_change_control() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.to_ascii_lowercase().contains("change control"),
        "constitution doc must include Change Control section"
    );
    assert!(
        doc.to_ascii_lowercase().contains("governance"),
        "constitution doc must mention governance"
    );
}

#[test]
fn objective_function_constitution_version_matches_program_constitution() {
    let obj_path = repo_root().join("docs/frx_objective_function_v1.json");
    let obj_raw = fs::read_to_string(&obj_path).expect("read objective JSON");
    let obj_value: Value = serde_json::from_str(&obj_raw).expect("parse objective JSON");
    let constitution_version = obj_value["constitution_version"]
        .as_str()
        .expect("constitution_version must be present in objective function JSON");
    let doc_path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&doc_path).expect("read constitution doc");
    assert!(
        doc.contains(constitution_version),
        "program constitution must embed its own version string '{constitution_version}'"
    );
}

#[test]
fn freeze_manifest_serde_roundtrip_preserves_structure() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let serialized = serde_json::to_string(&value).expect("serialize");
    let reparsed: Value = serde_json::from_str(&serialized).expect("reparse");
    assert_eq!(
        value, reparsed,
        "freeze manifest serde roundtrip must be identity"
    );
}

#[test]
fn objective_function_objective_target_is_maximize() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["objective"]["target"].as_str(),
        Some("maximize"),
        "objective target must be 'maximize'"
    );
}

#[test]
fn objective_function_hard_constraints_no_constitutional_invariant_violation() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let hc = value["objective"]["hard_constraints"]
        .as_array()
        .expect("hard_constraints array");
    assert!(
        hc.iter().any(|c| c
            .as_str()
            .is_some_and(|s| s.contains("no_constitutional_invariant"))),
        "hard_constraints must prohibit constitutional invariant violations"
    );
}

#[test]
fn freeze_manifest_all_artifact_values_are_nonempty_strings() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let artifacts = value["artifacts"].as_object().expect("artifacts object");
    for (key, val) in artifacts {
        let s = val
            .as_str()
            .unwrap_or_else(|| panic!("artifact {key} must be a string"));
        assert!(
            !s.trim().is_empty(),
            "artifact {key} value must not be blank"
        );
    }
}
