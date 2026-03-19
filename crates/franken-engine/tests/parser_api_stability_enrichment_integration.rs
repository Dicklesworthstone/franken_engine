#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_api_stability` module.
//!
//! Covers: manifest construction, surface lookup, canonical hashing, golden version vectors,
//! compatibility checks, parse helpers, integration log entries, migration assessment,
//! version compatibility, serde round-trips, edge cases, and cross-concern patterns.

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

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser_api_stability::{
    API_STABILITY_CONTRACT_VERSION, API_STABILITY_SCHEMA_VERSION, ApiStabilityManifest,
    ApiSurfaceEntry, CheckVerdict, CompatibilityCheckResult, CompatibilityReport, EvolutionRule,
    GoldenVersionVector, IntegrationLogEntry, IntegrationOutcome, MINIMUM_COMPATIBLE_AST_CONTRACT,
    MigrationAssessment, assess_migration, is_version_compatible, parse_module, parse_script,
    parse_with_audit, parse_with_full_provenance, run_compatibility_checks,
};

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn enrichment_contract_version_stable_format() {
    assert!(API_STABILITY_CONTRACT_VERSION.contains("parser-api-stability"));
    assert!(API_STABILITY_CONTRACT_VERSION.contains("contract"));
}

#[test]
fn enrichment_schema_version_stable_format() {
    assert!(API_STABILITY_SCHEMA_VERSION.contains("parser-api-stability"));
    assert!(API_STABILITY_SCHEMA_VERSION.contains("schema"));
}

#[test]
fn enrichment_minimum_compatible_ast_contract_nonempty() {
    assert!(!MINIMUM_COMPATIBLE_AST_CONTRACT.is_empty());
}

// ===========================================================================
// 2. EvolutionRule
// ===========================================================================

#[test]
fn enrichment_evolution_rule_all_variants_serde() {
    for rule in [
        EvolutionRule::AdditiveOnly,
        EvolutionRule::Frozen,
        EvolutionRule::Internal,
    ] {
        let json = serde_json::to_string(&rule).unwrap();
        let back: EvolutionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }
}

#[test]
fn enrichment_evolution_rule_debug_format() {
    let s = format!("{:?}", EvolutionRule::AdditiveOnly);
    assert!(s.contains("AdditiveOnly"));
}

// ===========================================================================
// 3. ApiSurfaceEntry
// ===========================================================================

#[test]
fn enrichment_surface_entry_serde_roundtrip() {
    let entry = ApiSurfaceEntry {
        surface_id: "test.surface".into(),
        description: "A test surface".into(),
        evolution_rule: EvolutionRule::Frozen,
        current_version: "v1".into(),
        minimum_compatible_version: "v1".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ApiSurfaceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// 4. ApiStabilityManifest
// ===========================================================================

#[test]
fn enrichment_manifest_current_surface_count_is_8() {
    let m = ApiStabilityManifest::current();
    assert_eq!(m.surface_count(), 8);
}

#[test]
fn enrichment_manifest_all_surface_ids_unique() {
    let m = ApiStabilityManifest::current();
    let mut ids: Vec<&str> = m.entries.iter().map(|e| e.surface_id.as_str()).collect();
    let len_before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), len_before);
}

#[test]
fn enrichment_manifest_lookup_known_surfaces() {
    let m = ApiStabilityManifest::current();
    let known = [
        "ast.contract",
        "ast.schema",
        "event_ir.contract",
        "event_ir.schema",
        "materializer.contract",
        "materializer.schema",
        "diagnostics.taxonomy",
        "diagnostics.schema",
    ];
    for id in &known {
        assert!(m.entry(id).is_some(), "missing surface: {}", id);
    }
}

#[test]
fn enrichment_manifest_lookup_missing_returns_none() {
    let m = ApiStabilityManifest::current();
    assert!(m.entry("does.not.exist").is_none());
}

#[test]
fn enrichment_manifest_canonical_hash_non_empty() {
    let m = ApiStabilityManifest::current();
    let hash = m.canonical_hash();
    assert!(hash.starts_with("sha256:"));
    assert!(hash.len() > 10);
}

#[test]
fn enrichment_manifest_canonical_hash_deterministic() {
    let h1 = ApiStabilityManifest::current().canonical_hash();
    let h2 = ApiStabilityManifest::current().canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let m = ApiStabilityManifest::current();
    let json = serde_json::to_string(&m).unwrap();
    let back: ApiStabilityManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_manifest_frozen_surfaces_invariant() {
    let m = ApiStabilityManifest::current();
    for entry in &m.entries {
        if entry.evolution_rule == EvolutionRule::Frozen {
            assert_eq!(
                entry.current_version, entry.minimum_compatible_version,
                "frozen surface {} min compat must equal current",
                entry.surface_id
            );
        }
    }
}

#[test]
fn enrichment_manifest_canonical_value_has_entries() {
    let m = ApiStabilityManifest::current();
    let cv = m.canonical_value();
    let debug = format!("{:?}", cv);
    assert!(debug.contains("entries"));
}

// ===========================================================================
// 5. CheckVerdict
// ===========================================================================

#[test]
fn enrichment_check_verdict_serde_all() {
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

// ===========================================================================
// 6. CompatibilityReport
// ===========================================================================

#[test]
fn enrichment_compatibility_report_all_pass() {
    let report = run_compatibility_checks();
    assert!(report.all_passed());
    assert_eq!(report.fail_count(), 0);
    assert!(report.pass_count() > 0);
}

#[test]
fn enrichment_compatibility_report_check_count() {
    let report = run_compatibility_checks();
    assert_eq!(report.results.len(), 12);
}

#[test]
fn enrichment_compatibility_report_canonical_hash_deterministic() {
    let h1 = run_compatibility_checks().canonical_hash();
    let h2 = run_compatibility_checks().canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_compatibility_report_serde_roundtrip() {
    let report = run_compatibility_checks();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompatibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_compatibility_report_pass_fail_counts() {
    let report = run_compatibility_checks();
    assert_eq!(
        report.pass_count() + report.fail_count(),
        report
            .results
            .iter()
            .filter(|r| r.verdict != CheckVerdict::Skipped)
            .count()
    );
}

#[test]
fn enrichment_compatibility_check_result_serde() {
    let check = CompatibilityCheckResult {
        check_id: "test_check".into(),
        description: "Test check".into(),
        verdict: CheckVerdict::Pass,
        detail: "ok".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: CompatibilityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

// ===========================================================================
// 7. GoldenVersionVector
// ===========================================================================

#[test]
fn enrichment_golden_v1_all_fields_non_empty() {
    let g = GoldenVersionVector::v1();
    assert!(!g.ast_contract.is_empty());
    assert!(!g.ast_schema.is_empty());
    assert!(!g.ast_hash_algorithm.is_empty());
    assert!(!g.ast_hash_prefix.is_empty());
    assert!(!g.event_ir_contract.is_empty());
    assert!(!g.event_ir_schema.is_empty());
    assert!(!g.event_ir_hash_algorithm.is_empty());
    assert!(!g.event_ir_hash_prefix.is_empty());
    assert!(!g.event_ir_policy_id.is_empty());
    assert!(!g.event_ir_component.is_empty());
    assert!(!g.event_ir_trace_prefix.is_empty());
    assert!(!g.event_ir_decision_prefix.is_empty());
    assert!(!g.materializer_contract.is_empty());
    assert!(!g.materializer_schema.is_empty());
    assert!(!g.materializer_node_id_prefix.is_empty());
    assert!(!g.diagnostic_taxonomy.is_empty());
    assert!(!g.diagnostic_schema.is_empty());
    assert!(!g.diagnostic_hash_algorithm.is_empty());
    assert!(!g.diagnostic_hash_prefix.is_empty());
}

#[test]
fn enrichment_golden_v1_matches_live() {
    let g = GoldenVersionVector::v1();
    let mismatches = g.check_against_live();
    assert!(mismatches.is_empty(), "mismatches: {:?}", mismatches);
}

#[test]
fn enrichment_golden_v1_detects_drift_in_multiple_fields() {
    let mut g = GoldenVersionVector::v1();
    g.ast_contract = "wrong".into();
    g.event_ir_schema = "wrong".into();
    let mismatches = g.check_against_live();
    assert_eq!(mismatches.len(), 2);
}

#[test]
fn enrichment_golden_v1_serde_roundtrip() {
    let g = GoldenVersionVector::v1();
    let json = serde_json::to_string(&g).unwrap();
    let back: GoldenVersionVector = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

// ===========================================================================
// 8. parse_script / parse_module
// ===========================================================================

#[test]
fn enrichment_parse_script_simple_literal() {
    let tree = parse_script("42;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert!(!tree.body.is_empty());
}

#[test]
fn enrichment_parse_script_variable_declaration() {
    let tree = parse_script("var x = 1;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn enrichment_parse_module_import() {
    let tree = parse_module("import x from 'y';").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn enrichment_parse_module_export() {
    let tree = parse_module("export default 42;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

// ===========================================================================
// 9. parse_with_audit
// ===========================================================================

#[test]
fn enrichment_parse_with_audit_produces_events() {
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    assert!(!event_ir.events.is_empty());
}

#[test]
fn enrichment_parse_with_audit_module() {
    let (result, event_ir) = parse_with_audit("import a from 'b';", ParseGoal::Module);
    assert!(result.is_ok());
    assert!(!event_ir.events.is_empty());
}

// ===========================================================================
// 10. parse_with_full_provenance
// ===========================================================================

#[test]
fn enrichment_parse_with_full_provenance_all_outputs() {
    let (parse_result, event_ir, mat_result) =
        parse_with_full_provenance("var y = 2;", ParseGoal::Script);
    assert!(parse_result.is_ok());
    assert!(!event_ir.events.is_empty());
    assert!(mat_result.is_ok());
}

#[test]
fn enrichment_parse_with_full_provenance_module() {
    let (parse_result, event_ir, mat_result) =
        parse_with_full_provenance("export default null;", ParseGoal::Module);
    assert!(parse_result.is_ok());
    assert!(!event_ir.events.is_empty());
    assert!(mat_result.is_ok());
}

// ===========================================================================
// 11. is_version_compatible
// ===========================================================================

#[test]
fn enrichment_version_compatible_current_contract() {
    let m = ApiStabilityManifest::current();
    for entry in &m.entries {
        assert!(is_version_compatible(
            &entry.surface_id,
            &entry.current_version
        ));
    }
}

#[test]
fn enrichment_version_compatible_unknown_surface() {
    assert!(!is_version_compatible("no.such.surface", "v1"));
}

#[test]
fn enrichment_version_compatible_old_version() {
    // An extremely old version string should generally fail
    let result = is_version_compatible("ast.contract", "a.v0");
    // Depends on the comparison, but version below minimum should fail
    assert!(!result);
}

// ===========================================================================
// 12. assess_migration
// ===========================================================================

#[test]
fn enrichment_assess_migration_current_version_no_migration() {
    let m = ApiStabilityManifest::current();
    let entry = m.entry("ast.contract").unwrap();
    let assessment = assess_migration("ast.contract", &entry.current_version).unwrap();
    assert!(assessment.compatible);
    assert!(!assessment.needs_migration);
}

#[test]
fn enrichment_assess_migration_unknown_surface() {
    assert!(assess_migration("unknown.surface", "v1").is_none());
}

#[test]
fn enrichment_assess_migration_serde_roundtrip() {
    let m = ApiStabilityManifest::current();
    let entry = m.entry("ast.contract").unwrap();
    let assessment = assess_migration("ast.contract", &entry.current_version).unwrap();
    let json = serde_json::to_string(&assessment).unwrap();
    let back: MigrationAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(assessment, back);
}

// ===========================================================================
// 13. IntegrationLogEntry / IntegrationOutcome
// ===========================================================================

#[test]
fn enrichment_integration_outcome_serde_all() {
    for outcome in [
        IntegrationOutcome::Success,
        IntegrationOutcome::ParseFailure,
        IntegrationOutcome::MaterializationFailure,
        IntegrationOutcome::VersionMismatch,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: IntegrationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

#[test]
fn enrichment_integration_log_entry_from_parse_success() {
    let (result, event_ir) = parse_with_audit("var z = 3;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &event_ir);
    assert_eq!(entry.operation, "parse");
    assert_eq!(entry.source_label, "test.js");
    assert_eq!(entry.goal, ParseGoal::Script);
    assert_eq!(entry.outcome, IntegrationOutcome::Success);
    assert!(entry.ast_hash.is_some());
    assert!(entry.event_count.is_some());
}

#[test]
fn enrichment_integration_log_entry_serde_roundtrip() {
    let (result, event_ir) = parse_with_audit("1;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("a.js", ParseGoal::Script, &tree, &event_ir);
    let json = serde_json::to_string(&entry).unwrap();
    let back: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_integration_log_entry_canonical_value_has_goal() {
    let (result, event_ir) = parse_with_audit("2;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("b.js", ParseGoal::Script, &tree, &event_ir);
    let cv = entry.canonical_value();
    let debug = format!("{:?}", cv);
    assert!(debug.contains("goal"));
}
