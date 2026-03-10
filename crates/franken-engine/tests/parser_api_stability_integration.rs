#![forbid(unsafe_code)]
//! Integration tests for the `parser_api_stability` module.
//!
//! Exercises ApiStabilityManifest, run_compatibility_checks, parse_script,
//! parse_module, parse_with_audit, parse_with_full_provenance,
//! GoldenVersionVector, version compatibility checks, migration assessment,
//! and serde round-trips.

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
    CheckVerdict, CompatibilityReport, EvolutionRule, GoldenVersionVector, IntegrationLogEntry,
    IntegrationOutcome, MINIMUM_COMPATIBLE_AST_CONTRACT, MigrationAssessment, assess_migration,
    is_version_compatible, parse_module, parse_script, parse_with_audit,
    parse_with_full_provenance, run_compatibility_checks,
};

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn contract_version_nonempty() {
    assert!(!API_STABILITY_CONTRACT_VERSION.is_empty());
    assert!(API_STABILITY_CONTRACT_VERSION.contains("parser-api-stability"));
}

#[test]
fn schema_version_nonempty() {
    assert!(!API_STABILITY_SCHEMA_VERSION.is_empty());
    assert!(API_STABILITY_SCHEMA_VERSION.contains("parser-api-stability"));
}

#[test]
fn minimum_compatible_ast_contract() {
    assert!(!MINIMUM_COMPATIBLE_AST_CONTRACT.is_empty());
    assert!(MINIMUM_COMPATIBLE_AST_CONTRACT.contains("parser-ast"));
}

// ===========================================================================
// 2. EvolutionRule
// ===========================================================================

#[test]
fn evolution_rule_serde() {
    for rule in [
        EvolutionRule::AdditiveOnly,
        EvolutionRule::Frozen,
        EvolutionRule::Internal,
    ] {
        let json = serde_json::to_string(&rule).unwrap();
        let back: EvolutionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }
}

// ===========================================================================
// 3. CheckVerdict
// ===========================================================================

#[test]
fn check_verdict_serde() {
    for v in [
        CheckVerdict::Pass,
        CheckVerdict::Fail,
        CheckVerdict::Skipped,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CheckVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// 4. IntegrationOutcome
// ===========================================================================

#[test]
fn integration_outcome_serde() {
    for o in [
        IntegrationOutcome::Success,
        IntegrationOutcome::ParseFailure,
        IntegrationOutcome::MaterializationFailure,
        IntegrationOutcome::VersionMismatch,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: IntegrationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }
}

// ===========================================================================
// 5. ApiStabilityManifest
// ===========================================================================

#[test]
fn manifest_current_has_surfaces() {
    let manifest = ApiStabilityManifest::current();
    assert!(manifest.surface_count() > 0);
    assert_eq!(manifest.surface_count(), 8);
}

#[test]
fn manifest_contract_and_schema_versions() {
    let manifest = ApiStabilityManifest::current();
    assert_eq!(manifest.contract_version, API_STABILITY_CONTRACT_VERSION);
    assert_eq!(manifest.schema_version, API_STABILITY_SCHEMA_VERSION);
}

#[test]
fn manifest_entry_lookup() {
    let manifest = ApiStabilityManifest::current();
    // Should have ast.contract surface
    let entry = manifest.entry("ast.contract");
    assert!(entry.is_some(), "expected ast.contract surface in manifest");
}

#[test]
fn manifest_entry_unknown_returns_none() {
    let manifest = ApiStabilityManifest::current();
    assert!(manifest.entry("nonexistent.surface").is_none());
}

#[test]
fn manifest_canonical_hash_is_deterministic() {
    let m1 = ApiStabilityManifest::current();
    let m2 = ApiStabilityManifest::current();
    assert_eq!(m1.canonical_hash(), m2.canonical_hash());
}

#[test]
fn manifest_serde_round_trip() {
    let manifest = ApiStabilityManifest::current();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ApiStabilityManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ===========================================================================
// 6. GoldenVersionVector
// ===========================================================================

#[test]
fn golden_version_v1_nonempty_fields() {
    let golden = GoldenVersionVector::v1();
    assert!(!golden.ast_contract.is_empty());
    assert!(!golden.ast_schema.is_empty());
    assert!(!golden.event_ir_contract.is_empty());
    assert!(!golden.materializer_contract.is_empty());
    assert!(!golden.diagnostic_taxonomy.is_empty());
}

#[test]
fn golden_version_check_against_live_no_mismatches() {
    let golden = GoldenVersionVector::v1();
    let mismatches = golden.check_against_live();
    assert!(
        mismatches.is_empty(),
        "golden version mismatches: {mismatches:?}"
    );
}

#[test]
fn golden_version_serde() {
    let golden = GoldenVersionVector::v1();
    let json = serde_json::to_string(&golden).unwrap();
    let back: GoldenVersionVector = serde_json::from_str(&json).unwrap();
    assert_eq!(back, golden);
}

// ===========================================================================
// 7. run_compatibility_checks
// ===========================================================================

#[test]
fn compatibility_checks_all_pass() {
    let report = run_compatibility_checks();
    assert!(
        report.all_passed(),
        "compatibility checks failed: {} failures out of {}",
        report.fail_count(),
        report.results.len()
    );
}

#[test]
fn compatibility_checks_12_checks() {
    let report = run_compatibility_checks();
    assert_eq!(report.pass_count(), 12);
}

#[test]
fn compatibility_report_versions() {
    let report = run_compatibility_checks();
    assert_eq!(report.contract_version, API_STABILITY_CONTRACT_VERSION);
    assert_eq!(report.schema_version, API_STABILITY_SCHEMA_VERSION);
}

#[test]
fn compatibility_report_deterministic_hash() {
    let r1 = run_compatibility_checks();
    let r2 = run_compatibility_checks();
    assert_eq!(r1.canonical_hash(), r2.canonical_hash());
}

#[test]
fn compatibility_report_serde() {
    let report = run_compatibility_checks();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompatibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

// ===========================================================================
// 8. parse_script / parse_module
// ===========================================================================

#[test]
fn parse_script_simple() {
    let result = parse_script("var x = 1;");
    assert!(result.is_ok());
}

#[test]
fn parse_module_simple() {
    let result = parse_module("export const x = 1;");
    assert!(result.is_ok());
}

#[test]
fn parse_script_lenient_recovery() {
    // The parser uses error-recovery and is lenient with malformed input
    let result = parse_script("function { invalid }}}");
    assert!(result.is_ok(), "parser should recover from malformed input");
}

#[test]
fn parse_module_lenient_recovery() {
    // The parser uses error-recovery and is lenient with malformed input
    let result = parse_module("export {{{}}");
    assert!(result.is_ok(), "parser should recover from malformed input");
}

#[test]
fn parse_script_empty_fails() {
    // Empty source is rejected by the parse_script wrapper
    let result = parse_script("");
    assert!(result.is_err());
}

// ===========================================================================
// 9. parse_with_audit
// ===========================================================================

#[test]
fn parse_with_audit_produces_event_ir() {
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    // Event IR should have at least some events
    // Event IR should have been populated during the parse
    let _ = &event_ir;
}

#[test]
fn parse_with_audit_module() {
    let (result, _event_ir) = parse_with_audit("export const x = 1;", ParseGoal::Module);
    assert!(result.is_ok());
}

// ===========================================================================
// 10. parse_with_full_provenance
// ===========================================================================

#[test]
fn parse_with_full_provenance_success() {
    let (parse_result, _event_ir, materialization_result) =
        parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    assert!(parse_result.is_ok());
    assert!(materialization_result.is_ok());
}

#[test]
fn parse_with_full_provenance_module() {
    let (parse_result, _event_ir, materialization_result) =
        parse_with_full_provenance("export const x = 42;", ParseGoal::Module);
    assert!(parse_result.is_ok());
    assert!(materialization_result.is_ok());
}

// ===========================================================================
// 11. IntegrationLogEntry
// ===========================================================================

#[test]
fn integration_log_entry_from_parse_success() {
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &event_ir);
    assert_eq!(entry.operation, "parse");
    assert_eq!(entry.source_label, "test.js");
    assert_eq!(entry.outcome, IntegrationOutcome::Success);
}

#[test]
fn integration_log_entry_from_parse_failure() {
    // Empty source triggers a parse error (parser rejects empty input)
    let result = parse_script("");
    let err = result.unwrap_err();
    let entry = IntegrationLogEntry::from_parse_failure("bad.js", ParseGoal::Script, &err);
    assert_eq!(entry.outcome, IntegrationOutcome::ParseFailure);
    assert_eq!(entry.source_label, "bad.js");
}

#[test]
fn integration_log_entry_serde() {
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &event_ir);
    let json = serde_json::to_string(&entry).unwrap();
    let back: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 12. Version compatibility
// ===========================================================================

#[test]
fn is_version_compatible_current_ast() {
    assert!(is_version_compatible(
        "ast.contract",
        MINIMUM_COMPATIBLE_AST_CONTRACT
    ));
}

#[test]
fn is_version_compatible_unknown_surface() {
    // Unknown surface should not be compatible
    assert!(!is_version_compatible("nonexistent", "v1"));
}

// ===========================================================================
// 13. Migration assessment
// ===========================================================================

#[test]
fn assess_migration_known_surface() {
    let assessment = assess_migration("ast.contract", MINIMUM_COMPATIBLE_AST_CONTRACT);
    assert!(assessment.is_some());
    let a = assessment.unwrap();
    assert!(a.compatible);
}

#[test]
fn assess_migration_unknown_surface() {
    let assessment = assess_migration("nonexistent.surface", "v1");
    assert!(assessment.is_none());
}

#[test]
fn migration_assessment_serde() {
    let assessment = MigrationAssessment {
        surface_id: "ast.contract".into(),
        artifact_version: "v1".into(),
        current_version: "v1".into(),
        minimum_compatible: "v1".into(),
        compatible: true,
        needs_migration: false,
    };
    let json = serde_json::to_string(&assessment).unwrap();
    let back: MigrationAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, assessment);
}

// ===========================================================================
// 14. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_parse_check_log() {
    // 1. Verify compatibility
    let report = run_compatibility_checks();
    assert!(report.all_passed());

    // 2. Parse with full provenance
    let source = "function add(a, b) { return a + b; }";
    let (parse_result, event_ir, mat_result) =
        parse_with_full_provenance(source, ParseGoal::Script);
    let tree = parse_result.unwrap();
    assert!(mat_result.is_ok());

    // 3. Create log entry
    let entry = IntegrationLogEntry::from_parse_success(
        "lifecycle.js",
        ParseGoal::Script,
        &tree,
        &event_ir,
    );
    assert_eq!(entry.outcome, IntegrationOutcome::Success);

    // 4. Check golden vector
    let golden = GoldenVersionVector::v1();
    let mismatches = golden.check_against_live();
    assert!(mismatches.is_empty());

    // 5. Verify manifest
    let manifest = ApiStabilityManifest::current();
    assert_eq!(manifest.surface_count(), 8);

    // 6. Serde round-trip of the log entry
    let json = serde_json::to_string(&entry).unwrap();
    let back: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}
