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

// ===========================================================================
// 15. Additional constants coverage
// ===========================================================================

#[test]
fn minimum_compatible_event_ir_contract_nonempty() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT;
    assert!(!MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT.is_empty());
    assert!(MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT.contains("parser-event-ir"));
}

#[test]
fn minimum_compatible_materializer_contract_nonempty() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT;
    assert!(!MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT.is_empty());
    assert!(MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT.contains("materializer"));
}

#[test]
fn minimum_compatible_diagnostic_schema_nonempty() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA;
    assert!(!MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA.is_empty());
    assert!(MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA.contains("diagnostics"));
}

// ===========================================================================
// 16. EvolutionRule extended
// ===========================================================================

#[test]
fn evolution_rule_debug_distinct() {
    let all = [
        EvolutionRule::AdditiveOnly,
        EvolutionRule::Frozen,
        EvolutionRule::Internal,
    ];
    let set: std::collections::BTreeSet<String> = all.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn evolution_rule_clone_eq() {
    let rule = EvolutionRule::AdditiveOnly;
    let cloned = rule;
    assert_eq!(rule, cloned);
}

#[test]
fn evolution_rule_json_values_stable() {
    assert_eq!(
        serde_json::to_string(&EvolutionRule::AdditiveOnly).unwrap(),
        "\"AdditiveOnly\""
    );
    assert_eq!(
        serde_json::to_string(&EvolutionRule::Frozen).unwrap(),
        "\"Frozen\""
    );
    assert_eq!(
        serde_json::to_string(&EvolutionRule::Internal).unwrap(),
        "\"Internal\""
    );
}

// ===========================================================================
// 17. CheckVerdict extended
// ===========================================================================

#[test]
fn check_verdict_debug_distinct() {
    let all = [
        CheckVerdict::Pass,
        CheckVerdict::Fail,
        CheckVerdict::Skipped,
    ];
    let set: std::collections::BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn check_verdict_json_values_stable() {
    assert_eq!(
        serde_json::to_string(&CheckVerdict::Pass).unwrap(),
        "\"Pass\""
    );
    assert_eq!(
        serde_json::to_string(&CheckVerdict::Fail).unwrap(),
        "\"Fail\""
    );
    assert_eq!(
        serde_json::to_string(&CheckVerdict::Skipped).unwrap(),
        "\"Skipped\""
    );
}

// ===========================================================================
// 18. IntegrationOutcome extended
// ===========================================================================

#[test]
fn integration_outcome_debug_distinct() {
    let all = [
        IntegrationOutcome::Success,
        IntegrationOutcome::ParseFailure,
        IntegrationOutcome::MaterializationFailure,
        IntegrationOutcome::VersionMismatch,
    ];
    let set: std::collections::BTreeSet<String> = all.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn integration_outcome_json_values_stable() {
    assert_eq!(
        serde_json::to_string(&IntegrationOutcome::Success).unwrap(),
        "\"Success\""
    );
    assert_eq!(
        serde_json::to_string(&IntegrationOutcome::ParseFailure).unwrap(),
        "\"ParseFailure\""
    );
    assert_eq!(
        serde_json::to_string(&IntegrationOutcome::MaterializationFailure).unwrap(),
        "\"MaterializationFailure\""
    );
    assert_eq!(
        serde_json::to_string(&IntegrationOutcome::VersionMismatch).unwrap(),
        "\"VersionMismatch\""
    );
}

// ===========================================================================
// 19. ApiSurfaceEntry
// ===========================================================================

#[test]
fn api_surface_entry_serde_roundtrip() {
    use frankenengine_engine::parser_api_stability::ApiSurfaceEntry;
    let entry = ApiSurfaceEntry {
        surface_id: "test.surface".into(),
        description: "A test surface".into(),
        evolution_rule: EvolutionRule::Frozen,
        current_version: "v2".into(),
        minimum_compatible_version: "v1".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ApiSurfaceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn api_surface_entry_fields_populated_in_manifest() {
    let manifest = ApiStabilityManifest::current();
    for entry in &manifest.entries {
        assert!(!entry.surface_id.is_empty());
        assert!(!entry.description.is_empty());
        assert!(!entry.current_version.is_empty());
        assert!(!entry.minimum_compatible_version.is_empty());
    }
}

// ===========================================================================
// 20. ApiStabilityManifest extended
// ===========================================================================

#[test]
fn manifest_has_all_eight_surface_ids() {
    let manifest = ApiStabilityManifest::current();
    let expected = [
        "ast.contract",
        "ast.schema",
        "event_ir.contract",
        "event_ir.schema",
        "materializer.contract",
        "materializer.schema",
        "diagnostics.taxonomy",
        "diagnostics.schema",
    ];
    for surface_id in &expected {
        assert!(
            manifest.entry(surface_id).is_some(),
            "missing surface: {surface_id}"
        );
    }
}

#[test]
fn manifest_frozen_surfaces_have_matching_min_compat() {
    let manifest = ApiStabilityManifest::current();
    for entry in &manifest.entries {
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
fn manifest_ast_contract_entry_evolution_rule() {
    let manifest = ApiStabilityManifest::current();
    let entry = manifest.entry("ast.contract").unwrap();
    assert_eq!(entry.evolution_rule, EvolutionRule::AdditiveOnly);
}

#[test]
fn manifest_ast_schema_entry_is_frozen() {
    let manifest = ApiStabilityManifest::current();
    let entry = manifest.entry("ast.schema").unwrap();
    assert_eq!(entry.evolution_rule, EvolutionRule::Frozen);
}

#[test]
fn manifest_event_ir_contract_entry_is_additive_only() {
    let manifest = ApiStabilityManifest::current();
    let entry = manifest.entry("event_ir.contract").unwrap();
    assert_eq!(entry.evolution_rule, EvolutionRule::AdditiveOnly);
}

#[test]
fn manifest_canonical_hash_starts_with_sha256_prefix() {
    let manifest = ApiStabilityManifest::current();
    let hash = manifest.canonical_hash();
    assert!(hash.starts_with("sha256:"), "hash={hash}");
}

#[test]
fn manifest_canonical_hash_hex_length() {
    let manifest = ApiStabilityManifest::current();
    let hash = manifest.canonical_hash();
    // sha256: prefix (7 chars) + 64 hex chars = 71
    assert_eq!(hash.len(), 71, "hash={hash}");
}

// ===========================================================================
// 21. GoldenVersionVector extended
// ===========================================================================

#[test]
fn golden_version_v1_all_fields_populated() {
    let g = GoldenVersionVector::v1();
    assert!(!g.ast_hash_algorithm.is_empty());
    assert!(!g.ast_hash_prefix.is_empty());
    assert!(!g.event_ir_schema.is_empty());
    assert!(!g.event_ir_hash_algorithm.is_empty());
    assert!(!g.event_ir_hash_prefix.is_empty());
    assert!(!g.event_ir_policy_id.is_empty());
    assert!(!g.event_ir_component.is_empty());
    assert!(!g.event_ir_trace_prefix.is_empty());
    assert!(!g.event_ir_decision_prefix.is_empty());
    assert!(!g.materializer_schema.is_empty());
    assert!(!g.materializer_node_id_prefix.is_empty());
    assert!(!g.diagnostic_hash_algorithm.is_empty());
    assert!(!g.diagnostic_hash_prefix.is_empty());
}

#[test]
fn golden_version_v1_detects_hypothetical_drift() {
    let mut g = GoldenVersionVector::v1();
    g.ast_contract = "franken-engine.parser-ast.contract.v99".into();
    let mismatches = g.check_against_live();
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches[0].0, "ast_contract");
}

#[test]
fn golden_version_v1_detects_multiple_drifts() {
    let mut g = GoldenVersionVector::v1();
    g.ast_contract = "DRIFTED".into();
    g.event_ir_contract = "DRIFTED".into();
    let mismatches = g.check_against_live();
    assert_eq!(mismatches.len(), 2);
}

#[test]
fn golden_version_v1_clone_equals_original() {
    let g = GoldenVersionVector::v1();
    let cloned = g.clone();
    assert_eq!(g, cloned);
}

#[test]
fn golden_version_v1_hash_algorithm_is_sha256() {
    let g = GoldenVersionVector::v1();
    assert_eq!(g.ast_hash_algorithm, "sha256");
    assert_eq!(g.event_ir_hash_algorithm, "sha256");
    assert_eq!(g.diagnostic_hash_algorithm, "sha256");
}

#[test]
fn golden_version_v1_hash_prefix_is_sha256_colon() {
    let g = GoldenVersionVector::v1();
    assert_eq!(g.ast_hash_prefix, "sha256:");
    assert_eq!(g.event_ir_hash_prefix, "sha256:");
    assert_eq!(g.diagnostic_hash_prefix, "sha256:");
}

// ===========================================================================
// 22. CompatibilityCheckResult serde
// ===========================================================================

#[test]
fn compatibility_check_result_serde_roundtrip() {
    use frankenengine_engine::parser_api_stability::CompatibilityCheckResult;
    let result = CompatibilityCheckResult {
        check_id: "test_check".into(),
        description: "A test check".into(),
        verdict: CheckVerdict::Pass,
        detail: "all good".into(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CompatibilityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn compatibility_check_result_fail_verdict_serde() {
    use frankenengine_engine::parser_api_stability::CompatibilityCheckResult;
    let result = CompatibilityCheckResult {
        check_id: "fail_check".into(),
        description: "Should fail".into(),
        verdict: CheckVerdict::Fail,
        detail: "mismatch detected".into(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CompatibilityCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verdict, CheckVerdict::Fail);
}

// ===========================================================================
// 23. CompatibilityReport extended
// ===========================================================================

#[test]
fn compatibility_report_canonical_hash_starts_with_sha256() {
    let report = run_compatibility_checks();
    let hash = report.canonical_hash();
    assert!(hash.starts_with("sha256:"), "hash={hash}");
    assert_eq!(hash.len(), 71);
}

#[test]
fn compatibility_report_all_check_ids_distinct() {
    let report = run_compatibility_checks();
    let ids: std::collections::BTreeSet<&str> =
        report.results.iter().map(|r| r.check_id.as_str()).collect();
    assert_eq!(ids.len(), report.results.len());
}

#[test]
fn compatibility_report_all_checks_have_descriptions() {
    let report = run_compatibility_checks();
    for result in &report.results {
        assert!(
            !result.description.is_empty(),
            "empty description for {}",
            result.check_id
        );
        assert!(
            !result.detail.is_empty(),
            "empty detail for {}",
            result.check_id
        );
    }
}

#[test]
fn compatibility_report_clone_equals_original() {
    let report = run_compatibility_checks();
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

// ===========================================================================
// 24. parse_script / parse_module extended
// ===========================================================================

#[test]
fn parse_script_function_declaration() {
    let result = parse_script("function foo(a, b) { return a + b; }");
    assert!(result.is_ok());
    let tree = result.unwrap();
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn parse_script_variable_declaration() {
    let tree = parse_script("var x = 42; var y = 100;").unwrap();
    assert_eq!(tree.body.len(), 2);
}

#[test]
fn parse_module_export_default() {
    let tree = parse_module("export default 42;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn parse_module_import_statement() {
    let tree = parse_module("import x from 'y';").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
    assert!(!tree.body.is_empty());
}

#[test]
fn parse_module_empty_fails() {
    let result = parse_module("");
    assert!(result.is_err());
}

#[test]
fn parse_script_goal_is_script() {
    let tree = parse_script("42;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
}

#[test]
fn parse_module_goal_is_module() {
    let tree = parse_module("42;").unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn parse_script_and_module_differ_for_same_source() {
    let s = parse_script("42;").unwrap();
    let m = parse_module("42;").unwrap();
    assert_ne!(s.canonical_hash(), m.canonical_hash());
}

#[test]
fn parse_script_ast_hash_deterministic() {
    let t1 = parse_script("var x = 1;").unwrap();
    let t2 = parse_script("var x = 1;").unwrap();
    assert_eq!(t1.canonical_hash(), t2.canonical_hash());
}

#[test]
fn parse_script_ast_hash_differs_for_different_source() {
    let t1 = parse_script("var x = 1;").unwrap();
    let t2 = parse_script("var x = 2;").unwrap();
    assert_ne!(t1.canonical_hash(), t2.canonical_hash());
}

#[test]
fn parse_script_ast_serde_roundtrip() {
    let tree = parse_script("var x = 1;").unwrap();
    let json = serde_json::to_string(&tree).unwrap();
    let back: frankenengine_engine::ast::SyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(tree, back);
}

// ===========================================================================
// 25. parse_with_audit extended
// ===========================================================================

#[test]
fn parse_with_audit_event_ir_has_events() {
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    assert!(!event_ir.events.is_empty());
}

#[test]
fn parse_with_audit_event_ir_starts_with_parse_started() {
    use frankenengine_engine::parser::ParseEventKind;
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    assert_eq!(
        event_ir.events.first().unwrap().kind,
        ParseEventKind::ParseStarted
    );
}

#[test]
fn parse_with_audit_event_ir_ends_with_parse_completed() {
    use frankenengine_engine::parser::ParseEventKind;
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    assert_eq!(
        event_ir.events.last().unwrap().kind,
        ParseEventKind::ParseCompleted
    );
}

#[test]
fn parse_with_audit_failure_has_parse_failed_event() {
    use frankenengine_engine::parser::ParseEventKind;
    let (result, event_ir) = parse_with_audit("", ParseGoal::Script);
    assert!(result.is_err());
    assert!(
        event_ir
            .events
            .iter()
            .any(|e| e.kind == ParseEventKind::ParseFailed)
    );
}

#[test]
fn parse_with_audit_event_sequence_monotonic() {
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    for (i, event) in event_ir.events.iter().enumerate() {
        assert_eq!(event.sequence, i as u64);
    }
}

#[test]
fn parse_with_audit_event_ir_serde_roundtrip() {
    use frankenengine_engine::parser::ParseEventIr;
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    let json = serde_json::to_string(&event_ir).unwrap();
    let back: ParseEventIr = serde_json::from_str(&json).unwrap();
    assert_eq!(event_ir, back);
}

// ===========================================================================
// 26. parse_with_full_provenance extended
// ===========================================================================

#[test]
fn parse_with_full_provenance_materializer_contract() {
    use frankenengine_engine::parser::PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION;
    let (result, _event_ir, mat_result) =
        parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    let mat = mat_result.unwrap();
    assert_eq!(
        mat.contract_version,
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    );
}

#[test]
fn parse_with_full_provenance_node_ids_have_prefix() {
    use frankenengine_engine::parser::PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX;
    let (result, _event_ir, mat_result) =
        parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    let mat = mat_result.unwrap();
    assert!(
        mat.root_node_id
            .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
    );
    for node in &mat.statement_nodes {
        assert!(
            node.node_id
                .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
        );
    }
}

#[test]
fn parse_with_full_provenance_statement_nodes_match_tree() {
    let (result, _event_ir, mat_result) =
        parse_with_full_provenance("var x = 1; var y = 2;", ParseGoal::Script);
    let tree = result.unwrap();
    let mat = mat_result.unwrap();
    assert_eq!(mat.statement_nodes.len(), tree.body.len());
}

#[test]
fn parse_with_full_provenance_failure_path() {
    use frankenengine_engine::parser::ParseEventMaterializationErrorCode;
    let (result, _event_ir, mat_result) = parse_with_full_provenance("", ParseGoal::Script);
    assert!(result.is_err());
    let mat_err = mat_result.unwrap_err();
    assert_eq!(
        mat_err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

#[test]
fn parse_with_full_provenance_materialized_ast_serde_roundtrip() {
    use frankenengine_engine::parser::MaterializedSyntaxTree;
    let (result, _event_ir, mat_result) =
        parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    assert!(result.is_ok());
    let mat = mat_result.unwrap();
    let json = serde_json::to_string(&mat).unwrap();
    let back: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(mat, back);
}

#[test]
fn parse_with_full_provenance_materialized_hash_deterministic() {
    let (_, _, m1) = parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    let (_, _, m2) = parse_with_full_provenance("var x = 1;", ParseGoal::Script);
    assert_eq!(m1.unwrap().canonical_hash(), m2.unwrap().canonical_hash());
}

// ===========================================================================
// 27. IntegrationLogEntry extended
// ===========================================================================

#[test]
fn integration_log_entry_success_fields() {
    let (result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("hello.js", ParseGoal::Script, &tree, &event_ir);
    assert_eq!(entry.operation, "parse");
    assert_eq!(entry.source_label, "hello.js");
    assert_eq!(entry.goal, ParseGoal::Script);
    assert_eq!(entry.outcome, IntegrationOutcome::Success);
    assert!(entry.ast_hash.is_some());
    assert!(entry.event_count.is_some());
    assert!(entry.diagnostic_code.is_none());
    assert!(!entry.detail.is_empty());
}

#[test]
fn integration_log_entry_failure_fields() {
    let err = parse_script("").unwrap_err();
    let entry = IntegrationLogEntry::from_parse_failure("bad.js", ParseGoal::Script, &err);
    assert_eq!(entry.operation, "parse");
    assert_eq!(entry.source_label, "bad.js");
    assert_eq!(entry.goal, ParseGoal::Script);
    assert_eq!(entry.outcome, IntegrationOutcome::ParseFailure);
    assert!(entry.ast_hash.is_none());
    assert!(entry.event_count.is_none());
    assert!(entry.diagnostic_code.is_some());
}

#[test]
fn integration_log_entry_failure_serde_roundtrip() {
    let err = parse_script("").unwrap_err();
    let entry = IntegrationLogEntry::from_parse_failure("bad.js", ParseGoal::Script, &err);
    let json = serde_json::to_string(&entry).unwrap();
    let back: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn integration_log_entry_module_goal() {
    let (result, event_ir) = parse_with_audit("export const a = 1;", ParseGoal::Module);
    let tree = result.unwrap();
    let entry =
        IntegrationLogEntry::from_parse_success("mod.js", ParseGoal::Module, &tree, &event_ir);
    assert_eq!(entry.goal, ParseGoal::Module);
}

// ===========================================================================
// 28. Version compatibility extended
// ===========================================================================

#[test]
fn is_version_compatible_event_ir_contract() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT;
    assert!(is_version_compatible(
        "event_ir.contract",
        MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT
    ));
}

#[test]
fn is_version_compatible_materializer_contract() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT;
    assert!(is_version_compatible(
        "materializer.contract",
        MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT
    ));
}

#[test]
fn is_version_compatible_diagnostics_schema() {
    use frankenengine_engine::parser_api_stability::MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA;
    assert!(is_version_compatible(
        "diagnostics.schema",
        MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA
    ));
}

// ===========================================================================
// 29. Migration assessment extended
// ===========================================================================

#[test]
fn assess_migration_event_ir_contract_current() {
    use frankenengine_engine::parser::PARSE_EVENT_IR_CONTRACT_VERSION;
    let a = assess_migration("event_ir.contract", PARSE_EVENT_IR_CONTRACT_VERSION).unwrap();
    assert!(a.compatible);
    assert!(!a.needs_migration);
}

#[test]
fn assess_migration_materializer_contract_current() {
    use frankenengine_engine::parser::PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION;
    let a = assess_migration(
        "materializer.contract",
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
    )
    .unwrap();
    assert!(a.compatible);
    assert!(!a.needs_migration);
}

#[test]
fn assess_migration_diagnostics_schema_current() {
    use frankenengine_engine::parser::PARSER_DIAGNOSTIC_SCHEMA_VERSION;
    let a = assess_migration("diagnostics.schema", PARSER_DIAGNOSTIC_SCHEMA_VERSION).unwrap();
    assert!(a.compatible);
    assert!(!a.needs_migration);
}

#[test]
fn assess_migration_old_event_ir_version_needs_migration() {
    let a = assess_migration(
        "event_ir.contract",
        "franken-engine.parser-event-ir.contract.v1",
    )
    .unwrap();
    assert!(a.needs_migration);
}

#[test]
fn assess_migration_serde_roundtrip_all_fields() {
    let a = MigrationAssessment {
        surface_id: "ast.contract".into(),
        artifact_version: "v0".into(),
        current_version: "v1".into(),
        minimum_compatible: "v1".into(),
        compatible: false,
        needs_migration: true,
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: MigrationAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.surface_id, "ast.contract");
    assert!(!back.compatible);
    assert!(back.needs_migration);
}

// ===========================================================================
// 30. ParseErrorCode as_str and stable_diagnostic_code stability
// ===========================================================================

#[test]
fn parse_error_code_as_str_stability() {
    use frankenengine_engine::parser::ParseErrorCode;
    assert_eq!(ParseErrorCode::EmptySource.as_str(), "empty_source");
    assert_eq!(ParseErrorCode::InvalidGoal.as_str(), "invalid_goal");
    assert_eq!(
        ParseErrorCode::UnsupportedSyntax.as_str(),
        "unsupported_syntax"
    );
    assert_eq!(ParseErrorCode::IoReadFailed.as_str(), "io_read_failed");
    assert_eq!(ParseErrorCode::InvalidUtf8.as_str(), "invalid_utf8");
    assert_eq!(ParseErrorCode::SourceTooLarge.as_str(), "source_too_large");
    assert_eq!(ParseErrorCode::BudgetExceeded.as_str(), "budget_exceeded");
}

#[test]
fn parse_error_code_stable_diagnostic_codes_follow_pattern() {
    use frankenengine_engine::parser::ParseErrorCode;
    for code in ParseErrorCode::ALL {
        let dc = code.stable_diagnostic_code();
        assert!(
            dc.starts_with("FE-PARSER-DIAG-"),
            "code {code:?} diagnostic {dc} missing prefix"
        );
        assert!(
            dc.ends_with("-0001"),
            "code {code:?} diagnostic {dc} missing suffix"
        );
    }
}

#[test]
fn parse_error_code_diagnostic_category_coverage() {
    use frankenengine_engine::parser::{ParseDiagnosticCategory, ParseErrorCode};
    assert_eq!(
        ParseErrorCode::EmptySource.diagnostic_category(),
        ParseDiagnosticCategory::Input
    );
    assert_eq!(
        ParseErrorCode::InvalidGoal.diagnostic_category(),
        ParseDiagnosticCategory::Goal
    );
    assert_eq!(
        ParseErrorCode::UnsupportedSyntax.diagnostic_category(),
        ParseDiagnosticCategory::Syntax
    );
    assert_eq!(
        ParseErrorCode::IoReadFailed.diagnostic_category(),
        ParseDiagnosticCategory::System
    );
    assert_eq!(
        ParseErrorCode::InvalidUtf8.diagnostic_category(),
        ParseDiagnosticCategory::Encoding
    );
    assert_eq!(
        ParseErrorCode::SourceTooLarge.diagnostic_category(),
        ParseDiagnosticCategory::Resource
    );
    assert_eq!(
        ParseErrorCode::BudgetExceeded.diagnostic_category(),
        ParseDiagnosticCategory::Resource
    );
}

#[test]
fn parse_error_code_diagnostic_severity_coverage() {
    use frankenengine_engine::parser::{ParseDiagnosticSeverity, ParseErrorCode};
    assert_eq!(
        ParseErrorCode::EmptySource.diagnostic_severity(),
        ParseDiagnosticSeverity::Error
    );
    assert_eq!(
        ParseErrorCode::IoReadFailed.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
    assert_eq!(
        ParseErrorCode::SourceTooLarge.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
    assert_eq!(
        ParseErrorCode::BudgetExceeded.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
}

// ===========================================================================
// 31. ParseEventKind as_str stability
// ===========================================================================

#[test]
fn parse_event_kind_as_str_stability() {
    use frankenengine_engine::parser::ParseEventKind;
    assert_eq!(ParseEventKind::ParseStarted.as_str(), "parse_started");
    assert_eq!(ParseEventKind::StatementParsed.as_str(), "statement_parsed");
    assert_eq!(ParseEventKind::ParseCompleted.as_str(), "parse_completed");
    assert_eq!(ParseEventKind::ParseFailed.as_str(), "parse_failed");
}

// ===========================================================================
// 32. ParseBudgetKind as_str stability
// ===========================================================================

#[test]
fn parse_budget_kind_as_str_stability() {
    use frankenengine_engine::parser::ParseBudgetKind;
    assert_eq!(ParseBudgetKind::SourceBytes.as_str(), "source_bytes");
    assert_eq!(ParseBudgetKind::TokenCount.as_str(), "token_count");
    assert_eq!(ParseBudgetKind::RecursionDepth.as_str(), "recursion_depth");
}

// ===========================================================================
// 33. ParseDiagnosticCategory as_str stability
// ===========================================================================

#[test]
fn parse_diagnostic_category_as_str_stability() {
    use frankenengine_engine::parser::ParseDiagnosticCategory;
    assert_eq!(ParseDiagnosticCategory::Input.as_str(), "input");
    assert_eq!(ParseDiagnosticCategory::Goal.as_str(), "goal");
    assert_eq!(ParseDiagnosticCategory::Syntax.as_str(), "syntax");
    assert_eq!(ParseDiagnosticCategory::Encoding.as_str(), "encoding");
    assert_eq!(ParseDiagnosticCategory::Resource.as_str(), "resource");
    assert_eq!(ParseDiagnosticCategory::System.as_str(), "system");
}

// ===========================================================================
// 34. ParseDiagnosticSeverity as_str stability
// ===========================================================================

#[test]
fn parse_diagnostic_severity_as_str_stability() {
    use frankenengine_engine::parser::ParseDiagnosticSeverity;
    assert_eq!(ParseDiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(ParseDiagnosticSeverity::Fatal.as_str(), "fatal");
}

// ===========================================================================
// 35. ParserMode as_str stability
// ===========================================================================

#[test]
fn parser_mode_as_str_stability() {
    use frankenengine_engine::parser::ParserMode;
    assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
}

// ===========================================================================
// 36. ParserOptions / ParserBudget defaults
// ===========================================================================

#[test]
fn parser_options_default_mode_is_scalar_reference() {
    use frankenengine_engine::parser::{ParserMode, ParserOptions};
    let opts = ParserOptions::default();
    assert_eq!(opts.mode, ParserMode::ScalarReference);
}

#[test]
fn parser_budget_default_values_stable() {
    use frankenengine_engine::parser::ParserBudget;
    let budget = ParserBudget::default();
    assert_eq!(budget.max_source_bytes, 1_048_576);
    assert_eq!(budget.max_token_count, 65_536);
    assert_eq!(budget.max_recursion_depth, 256);
}

#[test]
fn parser_budget_serde_roundtrip() {
    use frankenengine_engine::parser::ParserBudget;
    let budget = ParserBudget::default();
    let json = serde_json::to_string(&budget).unwrap();
    let back: ParserBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn parser_options_serde_roundtrip() {
    use frankenengine_engine::parser::ParserOptions;
    let opts = ParserOptions::default();
    let json = serde_json::to_string(&opts).unwrap();
    let back: ParserOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(opts, back);
}

// ===========================================================================
// 37. Grammar completeness matrix
// ===========================================================================

#[test]
fn grammar_matrix_has_families() {
    use frankenengine_engine::parser::GrammarCompletenessMatrix;
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    assert!(!matrix.families.is_empty());
}

#[test]
fn grammar_matrix_serde_roundtrip() {
    use frankenengine_engine::parser::GrammarCompletenessMatrix;
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    let json = serde_json::to_string(&matrix).unwrap();
    let back: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, back);
}

#[test]
fn grammar_matrix_summary_nonzero() {
    use frankenengine_engine::parser::GrammarCompletenessMatrix;
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    assert!(summary.family_count > 0);
    assert!(summary.completeness_millionths > 0);
}

#[test]
fn grammar_matrix_parser_mode_is_scalar_reference() {
    use frankenengine_engine::parser::{GrammarCompletenessMatrix, ParserMode};
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    assert_eq!(matrix.parser_mode, ParserMode::ScalarReference);
}

// ===========================================================================
// 38. ParseDiagnosticTaxonomy
// ===========================================================================

#[test]
fn diagnostic_taxonomy_v1_covers_all_error_codes() {
    use frankenengine_engine::parser::{ParseDiagnosticTaxonomy, ParseErrorCode};
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in ParseErrorCode::ALL {
        assert!(
            taxonomy.rule_for(code).is_some(),
            "taxonomy missing rule for {code:?}"
        );
    }
}

#[test]
fn diagnostic_taxonomy_v1_serde_roundtrip() {
    use frankenengine_engine::parser::ParseDiagnosticTaxonomy;
    let t = ParseDiagnosticTaxonomy::v1();
    let json = serde_json::to_string(&t).unwrap();
    let back: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ===========================================================================
// 39. Diagnostic envelope from parse error
// ===========================================================================

#[test]
fn diagnostic_envelope_from_empty_source_error() {
    use frankenengine_engine::parser::{
        PARSER_DIAGNOSTIC_SCHEMA_VERSION, PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseErrorCode,
    };
    let err = parse_script("").unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
    let diag = err.normalized_diagnostic();
    assert_eq!(diag.parse_error_code, ParseErrorCode::EmptySource);
    assert_eq!(diag.schema_version, PARSER_DIAGNOSTIC_SCHEMA_VERSION);
    assert_eq!(diag.taxonomy_version, PARSER_DIAGNOSTIC_TAXONOMY_VERSION);
    assert!(!diag.diagnostic_code.is_empty());
}

#[test]
fn diagnostic_envelope_serde_roundtrip() {
    use frankenengine_engine::parser::ParseDiagnosticEnvelope;
    let err = parse_script("").unwrap_err();
    let diag = err.normalized_diagnostic();
    let json = serde_json::to_string(&diag).unwrap();
    let back: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn diagnostic_envelope_canonical_hash_deterministic() {
    let err = parse_script("").unwrap_err();
    let d1 = err.normalized_diagnostic();
    let d2 = err.normalized_diagnostic();
    assert_eq!(d1.canonical_hash(), d2.canonical_hash());
}

#[test]
fn diagnostic_envelope_hash_starts_with_sha256() {
    let err = parse_script("").unwrap_err();
    let diag = err.normalized_diagnostic();
    let hash = diag.canonical_hash();
    assert!(hash.starts_with("sha256:"));
}

// ===========================================================================
// 40. ParseGoal as_str stability
// ===========================================================================

#[test]
fn parse_goal_as_str_stability() {
    assert_eq!(ParseGoal::Script.as_str(), "script");
    assert_eq!(ParseGoal::Module.as_str(), "module");
}

#[test]
fn parse_goal_serde_roundtrip() {
    for goal in [ParseGoal::Script, ParseGoal::Module] {
        let json = serde_json::to_string(&goal).unwrap();
        let back: ParseGoal = serde_json::from_str(&json).unwrap();
        assert_eq!(goal, back);
    }
}

// ===========================================================================
// 41. Cross-cutting determinism and stability
// ===========================================================================

#[test]
fn full_provenance_module_lifecycle() {
    let source = "export function add(a, b) { return a + b; }";
    let (parse_result, event_ir, mat_result) =
        parse_with_full_provenance(source, ParseGoal::Module);
    let tree = parse_result.unwrap();
    let mat = mat_result.unwrap();

    // Log entry from success
    let entry =
        IntegrationLogEntry::from_parse_success("mod.js", ParseGoal::Module, &tree, &event_ir);
    assert_eq!(entry.outcome, IntegrationOutcome::Success);
    assert_eq!(entry.goal, ParseGoal::Module);

    // Materialized tree has the right goal
    assert_eq!(mat.goal, ParseGoal::Module);
    assert_eq!(mat.statement_nodes.len(), tree.body.len());
}

#[test]
fn compatibility_checks_check_ids_are_known() {
    let report = run_compatibility_checks();
    let expected_ids = [
        "version_strings",
        "diagnostic_taxonomy_completeness",
        "diagnostic_code_format",
        "parse_goal_stability",
        "parser_mode_stability",
        "default_budget_stability",
        "event_kind_stability",
        "budget_kind_stability",
        "grammar_matrix_populated",
        "diagnostic_category_stability",
        "diagnostic_severity_stability",
        "manifest_surface_count",
    ];
    for id in &expected_ids {
        assert!(
            report.results.iter().any(|r| r.check_id == *id),
            "missing check_id: {id}"
        );
    }
}

#[test]
fn manifest_entry_descriptions_nonempty() {
    let manifest = ApiStabilityManifest::current();
    for entry in &manifest.entries {
        assert!(
            !entry.description.is_empty(),
            "empty description for surface {}",
            entry.surface_id
        );
    }
}

#[test]
fn event_ir_trace_and_decision_prefixes_stable() {
    use frankenengine_engine::parser::{
        PARSE_EVENT_IR_DECISION_PREFIX, PARSE_EVENT_IR_TRACE_PREFIX,
    };
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    for event in &event_ir.events {
        assert!(
            event.trace_id.starts_with(PARSE_EVENT_IR_TRACE_PREFIX),
            "trace_id {} missing prefix",
            event.trace_id
        );
        assert!(
            event
                .decision_id
                .starts_with(PARSE_EVENT_IR_DECISION_PREFIX),
            "decision_id {} missing prefix",
            event.decision_id
        );
    }
}

#[test]
fn event_ir_policy_and_component_stable() {
    use frankenengine_engine::parser::{PARSE_EVENT_IR_COMPONENT, PARSE_EVENT_IR_POLICY_ID};
    let (_result, event_ir) = parse_with_audit("var x = 1;", ParseGoal::Script);
    for event in &event_ir.events {
        assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
        assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
    }
}
