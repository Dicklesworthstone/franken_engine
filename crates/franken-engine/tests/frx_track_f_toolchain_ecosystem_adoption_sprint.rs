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
fn frx_track_f_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track F Toolchain/Ecosystem/Adoption Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Bundler and Source-Map Fidelity Contract",
        "## Ecosystem Compatibility and Migration Diagnostics Contract",
        "## Pilot/Canary Evidence Contract",
        "## Fallback Routing and Promotion-Block Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track F charter missing section: {section}"
        );
    }

    let lower = doc.to_ascii_lowercase();
    for clause in [
        "bundler adapters",
        "source-map fidelity",
        "ecosystem compatibility",
        "migration diagnostics",
        "pilot",
        "canary",
        "fallback routing",
        "block promotion",
        "fail-closed",
    ] {
        assert!(
            lower.contains(clause),
            "track F charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_f_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-f.toolchain-ecosystem-adoption-sprint.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.7.1"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.7.1"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-07.1"));

    assert_eq!(
        value["activation_gate"]["block_on_missing_bundler_adapter_coverage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_source_map_fidelity_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_untriaged_compatibility_regressions"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_pilot_canary_bundle"].as_bool(),
        Some(true)
    );

    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["failure_policy"]["fallback_mode"].as_str(),
        Some("conservative_compatibility")
    );
    assert_eq!(
        value["failure_policy"]["error_code"].as_str(),
        Some("FE-FRX-07-1-GATE-0001")
    );
    assert_eq!(
        value["failure_policy"]["promotion_block_on_repeated_class_regressions"].as_bool(),
        Some(true)
    );

    let dashboard_fields = value["outputs"]["integration_readiness_dashboard"]["required_fields"]
        .as_array()
        .expect("integration_readiness_dashboard.required_fields must be an array");
    for field in [
        "profile_id",
        "bundler",
        "compatibility_class",
        "confidence_grade",
        "fallback_route",
    ] {
        assert!(
            dashboard_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "dashboard field missing: {field}"
        );
    }
}

#[test]
fn frx_track_f_runtime_surfaces_exist_for_adoption_track() {
    let module_compat_path =
        repo_root().join("crates/franken-engine/src/module_compatibility_matrix.rs");
    let module_compat = fs::read_to_string(&module_compat_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", module_compat_path.display()));
    for snippet in [
        "pub struct ModuleCompatibilityMatrix",
        "pub enum CompatibilityRuntime",
        "pub enum CompatibilityMode",
    ] {
        assert!(
            module_compat.contains(snippet),
            "module_compatibility_matrix missing surface: {snippet}"
        );
    }

    let migration_kit_path = repo_root().join("crates/franken-engine/src/migration_kit.rs");
    let migration_kit = fs::read_to_string(&migration_kit_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", migration_kit_path.display()));
    for snippet in [
        "pub struct MigrationManifest",
        "pub struct CompatibilityReport",
        "pub struct BehaviorValidationReport",
        "pub enum MigrationKitError",
    ] {
        assert!(
            migration_kit.contains(snippet),
            "migration_kit missing surface: {snippet}"
        );
    }

    let migration_compat_path =
        repo_root().join("crates/franken-engine/src/migration_compatibility.rs");
    let migration_compat = fs::read_to_string(&migration_compat_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", migration_compat_path.display()));
    for snippet in [
        "pub struct MigrationCompatibilityChecker",
        "pub struct MigrationRegistry",
        "pub struct MigrationError",
    ] {
        assert!(
            migration_compat.contains(snippet),
            "migration_compatibility missing surface: {snippet}"
        );
    }

    let safe_mode_path = repo_root().join("crates/franken-engine/src/safe_mode_fallback.rs");
    let safe_mode = fs::read_to_string(&safe_mode_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", safe_mode_path.display()));
    for snippet in [
        "pub struct SafeModeManager",
        "pub enum FailureType",
        "pub struct SafeModeEvent",
    ] {
        assert!(
            safe_mode.contains(snippet),
            "safe_mode_fallback missing surface: {snippet}"
        );
    }
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn track_f_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track F doc");
    assert!(!doc.is_empty());
}

#[test]
fn track_f_charter_references_bundler_and_sourcemap() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read track F doc");
    let lower = doc.to_ascii_lowercase();
    assert!(lower.contains("bundler"));
    assert!(lower.contains("source-map"));
}

// ---------- JSON contract fields ----------

#[test]
fn track_f_contract_has_track_section() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["track"].is_object());
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-07.1"));
}

#[test]
fn track_f_contract_has_outputs_section() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"].is_object());
}

#[test]
fn track_f_contract_has_error_code() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["error_code"].as_str(),
        Some("FE-FRX-07-1-GATE-0001")
    );
}

#[test]
fn track_f_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn track_f_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc");
    assert!(ts.ends_with('Z'));
}

#[test]
fn track_f_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn track_f_contract_has_failure_policy_mode() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
}

#[test]
fn track_f_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn track_f_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn track_f_charter_mentions_ecosystem() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("ecosystem"));
}

#[test]
fn track_f_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn track_f_contract_has_scope_section() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["scope"].is_object() || value["scope"].is_array());
}

#[test]
fn track_f_contract_has_operator_verification() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ov = value["operator_verification"]
        .as_array()
        .expect("operator_verification must be array");
    assert!(!ov.is_empty());
}

#[test]
fn track_f_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn track_f_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn track_f_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn track_f_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    assert!(path.exists());
}

#[test]
fn track_f_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    assert!(path.exists());
}

#[test]
fn track_f_charter_mentions_adoption() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.to_ascii_lowercase().contains("adoption"));
}

// ---------- enrichment: deeper structural invariants ----------

#[test]
fn track_f_contract_scope_requires_track_b_and_c_baselines() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["scope"]["requires_track_b_baseline"].as_bool(),
        Some(true),
        "scope must require track B baseline"
    );
    assert_eq!(
        value["scope"]["requires_track_c_baseline"].as_bool(),
        Some(true),
        "scope must require track C baseline"
    );
    assert_eq!(
        value["scope"]["execution_window"].as_str(),
        Some("alpha_to_ga")
    );
}

#[test]
fn track_f_contract_operator_verification_scripts_are_non_empty() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ov = value["operator_verification"]
        .as_array()
        .expect("operator_verification must be array");
    assert!(
        ov.len() >= 2,
        "at least 2 operator verification scripts expected"
    );
    for entry in ov {
        let s = entry.as_str().expect("each entry must be a string");
        assert!(
            !s.trim().is_empty(),
            "operator verification entry must not be blank"
        );
    }
}

#[test]
fn track_f_contract_outputs_pilot_canary_evidence_section() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["outputs"]["pilot_canary_evidence"].is_object(),
        "outputs must contain pilot_canary_evidence"
    );
}

#[test]
fn track_f_contract_json_roundtrip_preserves_all_keys() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
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
fn track_f_contract_activation_gate_all_blocks_are_true() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let gate = value["activation_gate"]
        .as_object()
        .expect("activation_gate must be object");
    // Every boolean key in the gate must be true (fail-closed invariant)
    for (key, val) in gate {
        if let Some(b) = val.as_bool() {
            assert!(
                b,
                "activation_gate.{key} must be true for fail-closed policy"
            );
        }
    }
}

// ---------- enrichment: additional structural and runtime surface checks ----------

#[test]
fn track_f_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["logging_contract"].is_object(),
        "track F contract must have logging_contract section"
    );
}

#[test]
fn track_f_contract_logging_required_fields_include_core_set() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("logging required_fields array");
    let field_set: std::collections::BTreeSet<&str> =
        fields.iter().filter_map(|v| v.as_str()).collect();
    for required in ["trace_id", "component", "event", "outcome"] {
        assert!(
            field_set.contains(required),
            "logging_contract missing required field: {required}"
        );
    }
}

#[test]
fn track_f_contract_failure_policy_fallback_mode_is_conservative() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["failure_policy"]["fallback_mode"].as_str(),
        Some("conservative_compatibility"),
        "fallback_mode must be conservative_compatibility"
    );
}

#[test]
fn track_f_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(
        doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"),
        "track F charter must reference program constitution"
    );
}

#[test]
fn track_f_contract_status_is_active() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert_eq!(
        value["status"].as_str(),
        Some("active"),
        "track F contract status must be active"
    );
}
