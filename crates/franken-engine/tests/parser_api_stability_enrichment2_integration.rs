#![forbid(unsafe_code)]
//! Second enrichment integration test suite for `parser_api_stability`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser_api_stability::{
    API_STABILITY_CONTRACT_VERSION, API_STABILITY_SCHEMA_VERSION, ApiStabilityManifest,
    ApiSurfaceEntry, CheckVerdict, CompatibilityCheckResult, CompatibilityReport, EvolutionRule,
    GoldenVersionVector, IntegrationLogEntry, IntegrationOutcome, MINIMUM_COMPATIBLE_AST_CONTRACT,
    MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA, MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT,
    MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT, MigrationAssessment, assess_migration,
    is_version_compatible, parse_module, parse_script, parse_with_audit,
    parse_with_full_provenance, run_compatibility_checks,
};

// ---------------------------------------------------------------------------
// EvolutionRule completeness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evolution_rule_serde_all_variants_distinct_json() {
    let variants = [
        EvolutionRule::AdditiveOnly,
        EvolutionRule::Frozen,
        EvolutionRule::Internal,
    ];
    let jsons: BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(jsons.len(), variants.len());
}

#[test]
fn enrichment_evolution_rule_clone_independence() {
    let a = EvolutionRule::Frozen;
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// CheckVerdict completeness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_check_verdict_all_variants_serde_roundtrip() {
    for v in [
        CheckVerdict::Pass,
        CheckVerdict::Fail,
        CheckVerdict::Skipped,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CheckVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_check_verdict_display_distinct() {
    let variants = [
        CheckVerdict::Pass,
        CheckVerdict::Fail,
        CheckVerdict::Skipped,
    ];
    let dbg: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbg.len(), variants.len());
}

// ---------------------------------------------------------------------------
// IntegrationOutcome completeness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_integration_outcome_all_variants_serde() {
    for o in [
        IntegrationOutcome::Success,
        IntegrationOutcome::ParseFailure,
        IntegrationOutcome::MaterializationFailure,
        IntegrationOutcome::VersionMismatch,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: IntegrationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn enrichment_integration_outcome_display_all_distinct() {
    let all = [
        IntegrationOutcome::Success,
        IntegrationOutcome::ParseFailure,
        IntegrationOutcome::MaterializationFailure,
        IntegrationOutcome::VersionMismatch,
    ];
    let set: BTreeSet<String> = all.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(set.len(), all.len());
}

// ---------------------------------------------------------------------------
// Constants non-empty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contract_version_const_non_empty() {
    assert!(!API_STABILITY_CONTRACT_VERSION.is_empty());
}

#[test]
fn enrichment_schema_version_const_non_empty() {
    assert!(!API_STABILITY_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_minimum_compatible_consts_non_empty() {
    assert!(!MINIMUM_COMPATIBLE_AST_CONTRACT.is_empty());
    assert!(!MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT.is_empty());
    assert!(!MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT.is_empty());
    assert!(!MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA.is_empty());
}

// ---------------------------------------------------------------------------
// ApiStabilityManifest deep coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_entry_all_known_ids() {
    let m = ApiStabilityManifest::current();
    let expected_ids = [
        "ast.contract",
        "ast.schema",
        "event_ir.contract",
        "event_ir.schema",
        "materializer.contract",
        "materializer.schema",
        "diagnostics.taxonomy",
        "diagnostics.schema",
    ];
    for id in expected_ids {
        assert!(m.entry(id).is_some(), "missing surface entry for {id}");
    }
}

#[test]
fn enrichment_manifest_surface_ids_unique() {
    let m = ApiStabilityManifest::current();
    let ids: BTreeSet<&str> = m.entries.iter().map(|e| e.surface_id.as_str()).collect();
    assert_eq!(ids.len(), m.entries.len());
}

#[test]
fn enrichment_manifest_descriptions_non_empty() {
    let m = ApiStabilityManifest::current();
    for entry in &m.entries {
        assert!(
            !entry.description.is_empty(),
            "empty description for {}",
            entry.surface_id
        );
    }
}

#[test]
fn enrichment_manifest_canonical_value_contains_contract_version() {
    let m = ApiStabilityManifest::current();
    let cv = m.canonical_value();
    let encoded = format!("{cv:?}");
    assert!(encoded.contains("contract_version"));
}

#[test]
fn enrichment_manifest_canonical_hash_prefix() {
    let m = ApiStabilityManifest::current();
    let hash = m.canonical_hash();
    assert!(hash.starts_with("sha256:"));
    assert!(hash.len() > 10);
}

#[test]
fn enrichment_manifest_serde_roundtrip_preserves_surface_count() {
    let m = ApiStabilityManifest::current();
    let json = serde_json::to_string(&m).unwrap();
    let back: ApiStabilityManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m.surface_count(), back.surface_count());
}

// ---------------------------------------------------------------------------
// GoldenVersionVector
// ---------------------------------------------------------------------------

#[test]
fn enrichment_golden_v1_serde_roundtrip() {
    let g = GoldenVersionVector::v1();
    let json = serde_json::to_string(&g).unwrap();
    let back: GoldenVersionVector = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn enrichment_golden_v1_check_detects_multiple_drift() {
    let mut g = GoldenVersionVector::v1();
    g.ast_contract = "wrong".into();
    g.event_ir_contract = "wrong".into();
    let mismatches = g.check_against_live();
    assert!(mismatches.len() >= 2);
}

#[test]
fn enrichment_golden_v1_no_empty_fields() {
    let g = GoldenVersionVector::v1();
    assert!(!g.ast_hash_algorithm.is_empty());
    assert!(!g.ast_hash_prefix.is_empty());
    assert!(!g.event_ir_hash_algorithm.is_empty());
    assert!(!g.event_ir_hash_prefix.is_empty());
    assert!(!g.event_ir_policy_id.is_empty());
    assert!(!g.event_ir_component.is_empty());
    assert!(!g.event_ir_trace_prefix.is_empty());
    assert!(!g.event_ir_decision_prefix.is_empty());
    assert!(!g.materializer_node_id_prefix.is_empty());
    assert!(!g.diagnostic_hash_algorithm.is_empty());
    assert!(!g.diagnostic_hash_prefix.is_empty());
}

// ---------------------------------------------------------------------------
// CompatibilityReport
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compatibility_report_results_non_empty() {
    let report = run_compatibility_checks();
    assert!(!report.results.is_empty());
}

#[test]
fn enrichment_compatibility_report_check_ids_unique() {
    let report = run_compatibility_checks();
    let ids: BTreeSet<&str> = report.results.iter().map(|r| r.check_id.as_str()).collect();
    assert_eq!(ids.len(), report.results.len());
}

#[test]
fn enrichment_compatibility_report_canonical_hash_prefix() {
    let report = run_compatibility_checks();
    let hash = report.canonical_hash();
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn enrichment_compatibility_report_serde_roundtrip() {
    let report = run_compatibility_checks();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompatibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_compatibility_report_contract_version_matches() {
    let report = run_compatibility_checks();
    assert_eq!(report.contract_version, API_STABILITY_CONTRACT_VERSION);
    assert_eq!(report.schema_version, API_STABILITY_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Parse helpers edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_parse_script_returns_script_goal() {
    let tree = parse_script("1;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
}

#[test]
fn enrichment_parse_module_returns_module_goal() {
    let tree = parse_module("export default 1;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn enrichment_parse_with_audit_events_monotonic_sequence() {
    let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
    for (i, event) in ir.events.iter().enumerate() {
        assert_eq!(event.sequence, i as u64);
    }
}

#[test]
fn enrichment_parse_with_full_provenance_triple_determinism() {
    let (r1, ir1, m1) = parse_with_full_provenance("42;", ParseGoal::Script);
    let (r2, ir2, m2) = parse_with_full_provenance("42;", ParseGoal::Script);
    assert_eq!(r1.unwrap().canonical_hash(), r2.unwrap().canonical_hash());
    assert_eq!(ir1.canonical_hash(), ir2.canonical_hash());
    assert_eq!(m1.unwrap().canonical_hash(), m2.unwrap().canonical_hash());
}

// ---------------------------------------------------------------------------
// Migration assessment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_assess_migration_all_known_surfaces() {
    let surfaces = [
        "ast.contract",
        "ast.schema",
        "event_ir.contract",
        "event_ir.schema",
        "materializer.contract",
        "materializer.schema",
        "diagnostics.taxonomy",
        "diagnostics.schema",
    ];
    for surface in surfaces {
        let m = ApiStabilityManifest::current();
        let entry = m.entry(surface).unwrap();
        let assessment = assess_migration(surface, &entry.current_version).unwrap();
        assert!(assessment.compatible);
        assert!(!assessment.needs_migration);
    }
}

#[test]
fn enrichment_assess_migration_serde_roundtrip() {
    let a = assess_migration("ast.contract", MINIMUM_COMPATIBLE_AST_CONTRACT).unwrap();
    let json = serde_json::to_string(&a).unwrap();
    let back: MigrationAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_is_version_compatible_false_for_old_artifact() {
    // A very old version string (before v1) should be incompatible
    assert!(!is_version_compatible(
        "ast.contract",
        "franken-engine.parser-ast.contract.v0"
    ));
}

#[test]
fn enrichment_is_version_compatible_true_for_current() {
    let m = ApiStabilityManifest::current();
    for entry in &m.entries {
        assert!(
            is_version_compatible(&entry.surface_id, &entry.current_version),
            "current version should be compatible for {}",
            entry.surface_id
        );
    }
}

// ---------------------------------------------------------------------------
// ApiSurfaceEntry serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_api_surface_entry_clone_eq() {
    let entry = ApiSurfaceEntry {
        surface_id: "test".into(),
        description: "desc".into(),
        evolution_rule: EvolutionRule::Internal,
        current_version: "v1".into(),
        minimum_compatible_version: "v1".into(),
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_api_surface_entry_json_fields() {
    let entry = ApiSurfaceEntry {
        surface_id: "s".into(),
        description: "d".into(),
        evolution_rule: EvolutionRule::Frozen,
        current_version: "v1".into(),
        minimum_compatible_version: "v0".into(),
    };
    let val: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("surface_id"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("evolution_rule"));
    assert!(obj.contains_key("current_version"));
    assert!(obj.contains_key("minimum_compatible_version"));
    assert_eq!(obj.len(), 5);
}

// ---------------------------------------------------------------------------
// CompatibilityCheckResult serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compatibility_check_result_serde_roundtrip() {
    let r = CompatibilityCheckResult {
        check_id: "test_check".into(),
        description: "test desc".into(),
        verdict: CheckVerdict::Skipped,
        detail: "skipped for testing".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CompatibilityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_compatibility_check_result_json_fields() {
    let r = CompatibilityCheckResult {
        check_id: "c".into(),
        description: "d".into(),
        verdict: CheckVerdict::Pass,
        detail: "ok".into(),
    };
    let val: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("check_id"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("verdict"));
    assert!(obj.contains_key("detail"));
}

// ---------------------------------------------------------------------------
// Integration log entry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_integration_log_success_canonical_value_has_keys() {
    let (result, ir) = parse_with_audit("42;", ParseGoal::Script);
    let tree = result.unwrap();
    let log = IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &ir);
    let cv = log.canonical_value();
    let encoded = format!("{cv:?}");
    assert!(encoded.contains("operation"));
    assert!(encoded.contains("source_label"));
    assert!(encoded.contains("outcome"));
}

#[test]
fn enrichment_integration_log_failure_has_diagnostic_code() {
    let err = parse_script("").unwrap_err();
    let log = IntegrationLogEntry::from_parse_failure("bad.js", ParseGoal::Script, &err);
    assert!(log.diagnostic_code.is_some());
    assert!(log.ast_hash.is_none());
    assert!(log.event_count.is_none());
}

#[test]
fn enrichment_integration_log_serde_roundtrip_failure() {
    let err = parse_script("").unwrap_err();
    let log = IntegrationLogEntry::from_parse_failure("test.js", ParseGoal::Script, &err);
    let json = serde_json::to_string(&log).unwrap();
    let back: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}
