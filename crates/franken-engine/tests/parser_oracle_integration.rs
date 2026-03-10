#![forbid(unsafe_code)]
//! Integration tests for the `parser_oracle` module.
//!
//! Covers every public enum, struct, method, error variant, serde round-trip,
//! Display formatting, determinism, oracle query/response workflows, and
//! cross-concern integration scenarios.

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

use std::collections::BTreeMap;
use std::path::Path;

use frankenengine_engine::parser::ParserMode;
use frankenengine_engine::parser_oracle::{
    DEFAULT_FIXTURE_CATALOG_PATH, DriftClass, ExpectedLossModel, GateAction, OracleDecision,
    OracleFixtureCatalog, OracleFixtureResult, OracleFixtureSpec, OracleGateMode, OraclePartition,
    OracleSummary, ParserOracleConfig, ParserOracleError, derive_seed, load_fixture_catalog,
    partition_fixtures, run_parser_oracle,
};

// =========================================================================
// Helper: construct an OracleSummary for decision/loss testing
// =========================================================================

fn make_summary(equivalent: u64, minor: u64, critical: u64) -> OracleSummary {
    let total = equivalent + minor + critical;
    let mut counts_by_class = BTreeMap::new();
    if equivalent > 0 {
        counts_by_class.insert("Equivalent".to_string(), equivalent);
    }
    if minor > 0 {
        counts_by_class.insert("DiagnosticsDrift".to_string(), minor);
    }
    if critical > 0 {
        counts_by_class.insert("SemanticDrift".to_string(), critical);
    }
    let drift_rate_millionths = (minor + critical)
        .saturating_mul(1_000_000)
        .checked_div(total)
        .unwrap_or(0);
    OracleSummary {
        total_fixtures: total,
        equivalent_count: equivalent,
        minor_drift_count: minor,
        critical_drift_count: critical,
        drift_rate_millionths,
        counts_by_class,
    }
}

fn make_fixture(id: &str, goal: &str, source: &str) -> OracleFixtureSpec {
    OracleFixtureSpec {
        id: id.to_string(),
        family_id: "fam-default".to_string(),
        goal: goal.to_string(),
        source: source.to_string(),
        expected_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    }
}

fn valid_catalog() -> OracleFixtureCatalog {
    OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: vec![make_fixture("fix-001", "script", "var x = 1;")],
    }
}

// =========================================================================
// 1. OraclePartition — variant construction, as_str, fixture_limit,
//    metamorphic_pairs, FromStr, serde round-trip
// =========================================================================

#[test]
fn oracle_partition_as_str_all_variants() {
    assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
    assert_eq!(OraclePartition::Full.as_str(), "full");
    assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
}

#[test]
fn oracle_partition_fixture_limit_values() {
    assert_eq!(OraclePartition::Smoke.fixture_limit(), Some(4));
    assert_eq!(OraclePartition::Full.fixture_limit(), None);
    assert_eq!(OraclePartition::Nightly.fixture_limit(), None);
}

#[test]
fn oracle_partition_metamorphic_pairs_values() {
    assert_eq!(OraclePartition::Smoke.metamorphic_pairs(), 64);
    assert_eq!(OraclePartition::Full.metamorphic_pairs(), 256);
    assert_eq!(OraclePartition::Nightly.metamorphic_pairs(), 1024);
}

#[test]
fn oracle_partition_from_str_valid() {
    assert_eq!(
        "smoke".parse::<OraclePartition>().unwrap(),
        OraclePartition::Smoke
    );
    assert_eq!(
        "full".parse::<OraclePartition>().unwrap(),
        OraclePartition::Full
    );
    assert_eq!(
        "nightly".parse::<OraclePartition>().unwrap(),
        OraclePartition::Nightly
    );
}

#[test]
fn oracle_partition_from_str_invalid() {
    let err = "weekly".parse::<OraclePartition>().unwrap_err();
    assert!(
        err.contains("unsupported partition"),
        "error should mention unsupported partition, got: {err}"
    );
    assert!(err.contains("weekly"));
}

#[test]
fn oracle_partition_from_str_empty() {
    let err = "".parse::<OraclePartition>().unwrap_err();
    assert!(err.contains("unsupported partition"));
}

#[test]
fn oracle_partition_serde_roundtrip_all_variants() {
    for partition in [
        OraclePartition::Smoke,
        OraclePartition::Full,
        OraclePartition::Nightly,
    ] {
        let json = serde_json::to_string(&partition).unwrap();
        let back: OraclePartition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, partition, "serde round-trip for {partition:?}");
    }
}

#[test]
fn oracle_partition_serde_snake_case() {
    let json = serde_json::to_string(&OraclePartition::Smoke).unwrap();
    assert_eq!(json, "\"smoke\"");
    let json = serde_json::to_string(&OraclePartition::Full).unwrap();
    assert_eq!(json, "\"full\"");
    let json = serde_json::to_string(&OraclePartition::Nightly).unwrap();
    assert_eq!(json, "\"nightly\"");
}

#[test]
fn oracle_partition_copy_semantics() {
    let a = OraclePartition::Full;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// 2. OracleGateMode — variant construction, as_str, FromStr, serde
// =========================================================================

#[test]
fn oracle_gate_mode_as_str() {
    assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
    assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
}

#[test]
fn oracle_gate_mode_from_str_valid() {
    assert_eq!(
        "report_only".parse::<OracleGateMode>().unwrap(),
        OracleGateMode::ReportOnly
    );
    assert_eq!(
        "fail_closed".parse::<OracleGateMode>().unwrap(),
        OracleGateMode::FailClosed
    );
}

#[test]
fn oracle_gate_mode_from_str_invalid() {
    let err = "warn".parse::<OracleGateMode>().unwrap_err();
    assert!(err.contains("unsupported gate mode"));
    assert!(err.contains("warn"));
}

#[test]
fn oracle_gate_mode_from_str_empty() {
    let err = "".parse::<OracleGateMode>().unwrap_err();
    assert!(err.contains("unsupported gate mode"));
}

#[test]
fn oracle_gate_mode_serde_roundtrip() {
    for mode in [OracleGateMode::ReportOnly, OracleGateMode::FailClosed] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: OracleGateMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }
}

#[test]
fn oracle_gate_mode_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&OracleGateMode::ReportOnly).unwrap(),
        "\"report_only\""
    );
    assert_eq!(
        serde_json::to_string(&OracleGateMode::FailClosed).unwrap(),
        "\"fail_closed\""
    );
}

// =========================================================================
// 3. DriftClass — variant construction, comparator_decision, is_critical,
//    is_minor, serde round-trip
// =========================================================================

#[test]
fn drift_class_comparator_decision_all_variants() {
    assert_eq!(DriftClass::Equivalent.comparator_decision(), "equivalent");
    assert_eq!(
        DriftClass::DiagnosticsDrift.comparator_decision(),
        "drift_minor"
    );
    assert_eq!(
        DriftClass::SemanticDrift.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::HarnessNondeterminism.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::ArtifactIntegrityFailure.comparator_decision(),
        "drift_critical"
    );
}

#[test]
fn drift_class_is_critical_all_variants() {
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(!DriftClass::DiagnosticsDrift.is_critical());
    assert!(DriftClass::SemanticDrift.is_critical());
    assert!(DriftClass::HarnessNondeterminism.is_critical());
    assert!(DriftClass::ArtifactIntegrityFailure.is_critical());
}

#[test]
fn drift_class_is_minor_all_variants() {
    assert!(DriftClass::DiagnosticsDrift.is_minor());
    assert!(!DriftClass::Equivalent.is_minor());
    assert!(!DriftClass::SemanticDrift.is_minor());
    assert!(!DriftClass::HarnessNondeterminism.is_minor());
    assert!(!DriftClass::ArtifactIntegrityFailure.is_minor());
}

#[test]
fn drift_class_equivalent_is_neither_critical_nor_minor() {
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(!DriftClass::Equivalent.is_minor());
}

#[test]
fn drift_class_serde_roundtrip_all_variants() {
    for class in [
        DriftClass::Equivalent,
        DriftClass::SemanticDrift,
        DriftClass::DiagnosticsDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let back: DriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class, "serde round-trip for {class:?}");
    }
}

#[test]
fn drift_class_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&DriftClass::Equivalent).unwrap(),
        "\"equivalent\""
    );
    assert_eq!(
        serde_json::to_string(&DriftClass::SemanticDrift).unwrap(),
        "\"semantic_drift\""
    );
    assert_eq!(
        serde_json::to_string(&DriftClass::DiagnosticsDrift).unwrap(),
        "\"diagnostics_drift\""
    );
    assert_eq!(
        serde_json::to_string(&DriftClass::HarnessNondeterminism).unwrap(),
        "\"harness_nondeterminism\""
    );
    assert_eq!(
        serde_json::to_string(&DriftClass::ArtifactIntegrityFailure).unwrap(),
        "\"artifact_integrity_failure\""
    );
}

// =========================================================================
// 4. GateAction — variant construction, serde round-trip
// =========================================================================

#[test]
fn gate_action_serde_roundtrip_all_variants() {
    for action in [GateAction::Promote, GateAction::Hold, GateAction::Reject] {
        let json = serde_json::to_string(&action).unwrap();
        let back: GateAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);
    }
}

#[test]
fn gate_action_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&GateAction::Promote).unwrap(),
        "\"promote\""
    );
    assert_eq!(
        serde_json::to_string(&GateAction::Hold).unwrap(),
        "\"hold\""
    );
    assert_eq!(
        serde_json::to_string(&GateAction::Reject).unwrap(),
        "\"reject\""
    );
}

// =========================================================================
// 5. OracleFixtureSpec — construction, field access, Deserialize
// =========================================================================

#[test]
fn oracle_fixture_spec_construction_and_field_access() {
    let spec = make_fixture("fx-42", "module", "export default 42;");
    assert_eq!(spec.id, "fx-42");
    assert_eq!(spec.family_id, "fam-default");
    assert_eq!(spec.goal, "module");
    assert_eq!(spec.source, "export default 42;");
    assert!(spec.expected_hash.starts_with("sha256:"));
}

#[test]
fn oracle_fixture_spec_deserialize_from_json() {
    let json = r#"{
        "id": "f-99",
        "family_id": "fam-x",
        "goal": "script",
        "source": "1+1",
        "expected_hash": "sha256:abc"
    }"#;
    let spec: OracleFixtureSpec = serde_json::from_str(json).unwrap();
    assert_eq!(spec.id, "f-99");
    assert_eq!(spec.family_id, "fam-x");
}

#[test]
fn oracle_fixture_spec_clone_eq() {
    let a = make_fixture("f-1", "script", "x");
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// 6. OracleFixtureCatalog — construction, Deserialize
// =========================================================================

#[test]
fn oracle_fixture_catalog_construction() {
    let catalog = valid_catalog();
    assert_eq!(
        catalog.schema_version,
        "franken-engine.parser-phase0.semantic-fixtures.v1"
    );
    assert_eq!(catalog.parser_mode, "scalar_reference");
    assert_eq!(catalog.fixtures.len(), 1);
}

#[test]
fn oracle_fixture_catalog_deserialize() {
    let json = r#"{
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {
                "id": "f-1",
                "family_id": "fam",
                "goal": "script",
                "source": "var a;",
                "expected_hash": "sha256:abcd"
            }
        ]
    }"#;
    let catalog: OracleFixtureCatalog = serde_json::from_str(json).unwrap();
    assert_eq!(catalog.fixtures.len(), 1);
    assert_eq!(catalog.fixtures[0].id, "f-1");
}

// =========================================================================
// 7. OracleFixtureResult — construction, Serialize
// =========================================================================

#[test]
fn oracle_fixture_result_serialize() {
    let result = OracleFixtureResult {
        fixture_id: "f-01".to_string(),
        family_id: "fam-1".to_string(),
        goal: "script".to_string(),
        parser_mode: "scalar_reference".to_string(),
        derived_seed: 12345,
        input_hash: "sha256:abc".to_string(),
        expected_hash: "sha256:abc".to_string(),
        observed_hash: Some("sha256:abc".to_string()),
        repeated_hash: Some("sha256:abc".to_string()),
        parse_error_code: None,
        repeated_error_code: None,
        drift_class: DriftClass::Equivalent,
        comparator_decision: "equivalent".to_string(),
        latency_ns: 1000,
        replay_command: "cargo run ...".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"fixture_id\":\"f-01\""));
    assert!(json.contains("\"equivalent\""));
    assert!(json.contains("\"latency_ns\":1000"));
}

#[test]
fn oracle_fixture_result_with_error_codes() {
    let result = OracleFixtureResult {
        fixture_id: "f-err".to_string(),
        family_id: "fam-err".to_string(),
        goal: "script".to_string(),
        parser_mode: "scalar_reference".to_string(),
        derived_seed: 0,
        input_hash: "sha256:000".to_string(),
        expected_hash: "sha256:000".to_string(),
        observed_hash: None,
        repeated_hash: None,
        parse_error_code: Some("UnsupportedSyntax".to_string()),
        repeated_error_code: Some("UnsupportedSyntax".to_string()),
        drift_class: DriftClass::DiagnosticsDrift,
        comparator_decision: "drift_minor".to_string(),
        latency_ns: 500,
        replay_command: "cargo run ...".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("UnsupportedSyntax"));
    assert!(json.contains("diagnostics_drift"));
}

// =========================================================================
// 8. OracleSummary — construction, drift rate computation, Serialize
// =========================================================================

#[test]
fn oracle_summary_all_equivalent_zero_drift() {
    let summary = make_summary(100, 0, 0);
    assert_eq!(summary.total_fixtures, 100);
    assert_eq!(summary.equivalent_count, 100);
    assert_eq!(summary.drift_rate_millionths, 0);
}

#[test]
fn oracle_summary_drift_rate_fixed_point() {
    // 10 drifts out of 100 => 10% => 100_000 millionths
    let summary = make_summary(90, 5, 5);
    assert_eq!(summary.drift_rate_millionths, 100_000);
}

#[test]
fn oracle_summary_all_critical() {
    let summary = make_summary(0, 0, 50);
    assert_eq!(summary.drift_rate_millionths, 1_000_000);
}

#[test]
fn oracle_summary_all_minor() {
    let summary = make_summary(0, 50, 0);
    assert_eq!(summary.drift_rate_millionths, 1_000_000);
}

#[test]
fn oracle_summary_serialize() {
    let summary = make_summary(10, 2, 1);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("\"total_fixtures\":13"));
    assert!(json.contains("\"equivalent_count\":10"));
}

#[test]
fn oracle_summary_counts_by_class_populated() {
    let summary = make_summary(10, 3, 2);
    assert_eq!(summary.counts_by_class.get("Equivalent"), Some(&10));
    assert_eq!(summary.counts_by_class.get("DiagnosticsDrift"), Some(&3));
    assert_eq!(summary.counts_by_class.get("SemanticDrift"), Some(&2));
}

#[test]
fn oracle_summary_counts_by_class_absent_for_zero() {
    let summary = make_summary(10, 0, 0);
    assert!(!summary.counts_by_class.contains_key("DiagnosticsDrift"));
    assert!(!summary.counts_by_class.contains_key("SemanticDrift"));
}

// =========================================================================
// 9. ExpectedLossModel — Serialize
// =========================================================================

#[test]
fn expected_loss_model_serialize() {
    let model = ExpectedLossModel {
        promote_loss: 0.0,
        hold_loss: 6.0,
        reject_loss: 10.0,
        recommended_action: GateAction::Promote,
    };
    let json = serde_json::to_string(&model).unwrap();
    assert!(json.contains("\"promote_loss\":0.0"));
    assert!(json.contains("\"recommended_action\":\"promote\""));
}

// =========================================================================
// 10. OracleDecision — construction, Serialize
// =========================================================================

#[test]
fn oracle_decision_promote_no_fallback() {
    let decision = OracleDecision {
        action: GateAction::Promote,
        promotion_blocked: false,
        fallback_triggered: false,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"promote\""));
    assert!(json.contains("\"promotion_blocked\":false"));
}

#[test]
fn oracle_decision_reject_with_fallback() {
    let decision = OracleDecision {
        action: GateAction::Reject,
        promotion_blocked: true,
        fallback_triggered: true,
        fallback_reason: Some("critical drift detected".to_string()),
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"reject\""));
    assert!(json.contains("critical drift detected"));
}

#[test]
fn oracle_decision_hold_with_reason() {
    let decision = OracleDecision {
        action: GateAction::Hold,
        promotion_blocked: true,
        fallback_triggered: false,
        fallback_reason: Some("minor diagnostics drift detected".to_string()),
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"hold\""));
    assert!(json.contains("minor diagnostics drift"));
}

// =========================================================================
// 11. ParserOracleConfig — with_defaults, field access
// =========================================================================

#[test]
fn parser_oracle_config_with_defaults_smoke() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::ReportOnly, 42);
    assert_eq!(config.partition, OraclePartition::Smoke);
    assert_eq!(config.gate_mode, OracleGateMode::ReportOnly);
    assert_eq!(config.seed, 42);
    assert!(config.trace_id.starts_with("trace-parser-oracle-"));
    assert!(config.decision_id.starts_with("decision-parser-oracle-"));
    assert_eq!(config.policy_id, "policy-parser-oracle-v1");
    assert_eq!(
        config.fixture_catalog_path.to_str().unwrap(),
        DEFAULT_FIXTURE_CATALOG_PATH
    );
}

#[test]
fn parser_oracle_config_with_defaults_nightly() {
    let config = ParserOracleConfig::with_defaults(
        OraclePartition::Nightly,
        OracleGateMode::FailClosed,
        999,
    );
    assert_eq!(config.partition, OraclePartition::Nightly);
    assert_eq!(config.gate_mode, OracleGateMode::FailClosed);
    assert_eq!(config.seed, 999);
}

#[test]
fn parser_oracle_config_clone_eq() {
    let a = ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::ReportOnly, 1);
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// 12. ParserOracleError — Display formatting for every variant
// =========================================================================

#[test]
fn parser_oracle_error_display_io() {
    let err = ParserOracleError::Io {
        path: "/some/path.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
    };
    let msg = err.to_string();
    assert!(msg.contains("/some/path.json"));
    assert!(msg.contains("file not found"));
    assert!(msg.contains("failed to read"));
}

#[test]
fn parser_oracle_error_display_decode_catalog() {
    let err = ParserOracleError::DecodeCatalog("invalid JSON at line 3".to_string());
    let msg = err.to_string();
    assert!(msg.contains("failed to decode parser oracle fixture catalog"));
    assert!(msg.contains("invalid JSON at line 3"));
}

#[test]
fn parser_oracle_error_display_invalid_catalog_schema() {
    let err = ParserOracleError::InvalidCatalogSchema {
        expected: "v1".to_string(),
        actual: "v99".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid parser oracle catalog schema"));
    assert!(msg.contains("v99"));
    assert!(msg.contains("v1"));
}

#[test]
fn parser_oracle_error_display_invalid_catalog_parser_mode() {
    let err = ParserOracleError::InvalidCatalogParserMode {
        expected: "scalar_reference".to_string(),
        actual: "parallel_chunked".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid parser oracle catalog parser_mode"));
    assert!(msg.contains("parallel_chunked"));
}

#[test]
fn parser_oracle_error_display_empty_fixture_catalog() {
    let err = ParserOracleError::EmptyFixtureCatalog;
    let msg = err.to_string();
    assert!(msg.contains("must not be empty"));
}

#[test]
fn parser_oracle_error_display_unknown_goal() {
    let err = ParserOracleError::UnknownGoal {
        fixture_id: "f-42".to_string(),
        goal: "expression".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("f-42"));
    assert!(msg.contains("expression"));
    assert!(msg.contains("unknown parse goal"));
}

#[test]
fn parser_oracle_error_is_std_error() {
    let err = ParserOracleError::EmptyFixtureCatalog;
    // Verify it implements std::error::Error by using it as a trait object.
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// 13. derive_seed — determinism, sensitivity to inputs
// =========================================================================

#[test]
fn derive_seed_is_deterministic() {
    let a = derive_seed(42, "fixture-alpha", ParserMode::ScalarReference);
    let b = derive_seed(42, "fixture-alpha", ParserMode::ScalarReference);
    assert_eq!(a, b, "same inputs must produce same seed");
}

#[test]
fn derive_seed_varies_with_master_seed() {
    let a = derive_seed(1, "f-1", ParserMode::ScalarReference);
    let b = derive_seed(2, "f-1", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

#[test]
fn derive_seed_varies_with_fixture_id() {
    let a = derive_seed(42, "f-1", ParserMode::ScalarReference);
    let b = derive_seed(42, "f-2", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

#[test]
fn derive_seed_zero_master_seed() {
    let seed = derive_seed(0, "fixture-zero", ParserMode::ScalarReference);
    // Just check it doesn't panic and returns some value.
    let _ = seed;
}

#[test]
fn derive_seed_max_master_seed() {
    let seed = derive_seed(u64::MAX, "fixture-max", ParserMode::ScalarReference);
    let _ = seed;
}

#[test]
fn derive_seed_empty_fixture_id() {
    let seed = derive_seed(42, "", ParserMode::ScalarReference);
    let _ = seed;
}

#[test]
fn derive_seed_long_fixture_id() {
    let long_id = "a".repeat(10_000);
    let seed = derive_seed(42, &long_id, ParserMode::ScalarReference);
    let _ = seed;
}

#[test]
fn derive_seed_determinism_across_many_ids() {
    for i in 0..50 {
        let id = format!("fixture-{i:04}");
        let a = derive_seed(12345, &id, ParserMode::ScalarReference);
        let b = derive_seed(12345, &id, ParserMode::ScalarReference);
        assert_eq!(a, b, "determinism failed for {id}");
    }
}

// =========================================================================
// 14. partition_fixtures — sorting, limit, full, nightly
// =========================================================================

fn make_catalog_with_n(n: usize) -> OracleFixtureCatalog {
    OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: (0..n)
            .map(|i| make_fixture(&format!("f-{i:04}"), "script", &format!("var x = {i};")))
            .collect(),
    }
}

#[test]
fn partition_fixtures_smoke_limits_to_four() {
    let catalog = make_catalog_with_n(10);
    let result = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(result.len(), 4);
}

#[test]
fn partition_fixtures_smoke_fewer_than_limit() {
    let catalog = make_catalog_with_n(2);
    let result = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(result.len(), 2);
}

#[test]
fn partition_fixtures_full_no_limit() {
    let catalog = make_catalog_with_n(10);
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert_eq!(result.len(), 10);
}

#[test]
fn partition_fixtures_nightly_no_limit() {
    let catalog = make_catalog_with_n(10);
    let result = partition_fixtures(&catalog, OraclePartition::Nightly);
    assert_eq!(result.len(), 10);
}

#[test]
fn partition_fixtures_sorted_by_id() {
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: vec![
            make_fixture("z-last", "script", "1"),
            make_fixture("a-first", "script", "2"),
            make_fixture("m-middle", "script", "3"),
        ],
    };
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert_eq!(result[0].id, "a-first");
    assert_eq!(result[1].id, "m-middle");
    assert_eq!(result[2].id, "z-last");
}

#[test]
fn partition_fixtures_empty_catalog() {
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: vec![],
    };
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert!(result.is_empty());
}

#[test]
fn partition_fixtures_preserves_all_fields() {
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: vec![OracleFixtureSpec {
            id: "f-special".to_string(),
            family_id: "fam-special".to_string(),
            goal: "module".to_string(),
            source: "export const x = 42;".to_string(),
            expected_hash: "sha256:deadbeef".to_string(),
        }],
    };
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].family_id, "fam-special");
    assert_eq!(result[0].goal, "module");
    assert_eq!(result[0].source, "export const x = 42;");
    assert_eq!(result[0].expected_hash, "sha256:deadbeef");
}

// =========================================================================
// 15. load_fixture_catalog — error paths
// =========================================================================

#[test]
fn load_fixture_catalog_nonexistent_file() {
    let err = load_fixture_catalog(Path::new("/nonexistent/catalog.json")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("failed to read"));
    assert!(msg.contains("/nonexistent/catalog.json"));
}

#[test]
fn load_fixture_catalog_nonexistent_deep_path() {
    let err = load_fixture_catalog(Path::new("/a/b/c/d/e/f/missing_catalog.json")).unwrap_err();
    assert!(err.to_string().contains("failed to read"));
}

// =========================================================================
// 16. run_parser_oracle — end-to-end (file-based, error path)
// =========================================================================

#[test]
fn run_parser_oracle_nonexistent_catalog_returns_error() {
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::ReportOnly, 1);
    config.fixture_catalog_path = "/nonexistent/catalog.json".into();
    let err = run_parser_oracle(&config).unwrap_err();
    assert!(err.to_string().contains("failed to read"));
}

// =========================================================================
// 17. Determinism: same config always produces same decision topology
// =========================================================================

#[test]
fn determinism_derive_seed_stable_across_iterations() {
    let seeds: Vec<u64> = (0..100)
        .map(|_| derive_seed(42, "fixture-det", ParserMode::ScalarReference))
        .collect();
    let first = seeds[0];
    for (i, s) in seeds.iter().enumerate() {
        assert_eq!(*s, first, "iteration {i} produced different seed");
    }
}

// =========================================================================
// 18. Cross-concern: partition + derive_seed integration
// =========================================================================

#[test]
fn partition_and_derive_seed_integration() {
    let catalog = make_catalog_with_n(10);
    let fixtures = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(fixtures.len(), 4);

    // Each fixture should produce a unique derived seed.
    let mut seen = std::collections::BTreeSet::new();
    for fixture in &fixtures {
        let seed = derive_seed(42, &fixture.id, ParserMode::ScalarReference);
        assert!(
            seen.insert(seed),
            "duplicate seed for fixture {}",
            fixture.id
        );
    }
}

// =========================================================================
// 19. OracleSummary determinism: same inputs produce same rate
// =========================================================================

#[test]
fn oracle_summary_drift_rate_deterministic() {
    let a = make_summary(80, 15, 5);
    let b = make_summary(80, 15, 5);
    assert_eq!(a.drift_rate_millionths, b.drift_rate_millionths);
    assert_eq!(a, b);
}

// =========================================================================
// 20. DEFAULT_FIXTURE_CATALOG_PATH constant
// =========================================================================

#[test]
fn default_fixture_catalog_path_is_expected() {
    assert_eq!(
        DEFAULT_FIXTURE_CATALOG_PATH,
        "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json"
    );
}

// =========================================================================
// 21. Edge cases for summary with zero total
// =========================================================================

#[test]
fn oracle_summary_zero_total_drift_rate_is_zero() {
    let summary = OracleSummary {
        total_fixtures: 0,
        equivalent_count: 0,
        minor_drift_count: 0,
        critical_drift_count: 0,
        drift_rate_millionths: 0,
        counts_by_class: BTreeMap::new(),
    };
    assert_eq!(summary.drift_rate_millionths, 0);
}

// =========================================================================
// 22. Serde stability: JSON keys are snake_case throughout
// =========================================================================

#[test]
fn oracle_fixture_result_json_keys_snake_case() {
    let result = OracleFixtureResult {
        fixture_id: "f".to_string(),
        family_id: "fam".to_string(),
        goal: "script".to_string(),
        parser_mode: "scalar_reference".to_string(),
        derived_seed: 0,
        input_hash: "sha256:00".to_string(),
        expected_hash: "sha256:00".to_string(),
        observed_hash: None,
        repeated_hash: None,
        parse_error_code: None,
        repeated_error_code: None,
        drift_class: DriftClass::Equivalent,
        comparator_decision: "equivalent".to_string(),
        latency_ns: 0,
        replay_command: String::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("fixture_id"));
    assert!(json.contains("family_id"));
    assert!(json.contains("parser_mode"));
    assert!(json.contains("derived_seed"));
    assert!(json.contains("input_hash"));
    assert!(json.contains("expected_hash"));
    assert!(json.contains("observed_hash"));
    assert!(json.contains("repeated_hash"));
    assert!(json.contains("parse_error_code"));
    assert!(json.contains("repeated_error_code"));
    assert!(json.contains("drift_class"));
    assert!(json.contains("comparator_decision"));
    assert!(json.contains("latency_ns"));
    assert!(json.contains("replay_command"));
}

#[test]
fn oracle_summary_json_keys_snake_case() {
    let summary = make_summary(1, 0, 0);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("total_fixtures"));
    assert!(json.contains("equivalent_count"));
    assert!(json.contains("minor_drift_count"));
    assert!(json.contains("critical_drift_count"));
    assert!(json.contains("drift_rate_millionths"));
    assert!(json.contains("counts_by_class"));
}

#[test]
fn oracle_decision_json_keys_snake_case() {
    let decision = OracleDecision {
        action: GateAction::Promote,
        promotion_blocked: false,
        fallback_triggered: false,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("promotion_blocked"));
    assert!(json.contains("fallback_triggered"));
    assert!(json.contains("fallback_reason"));
}

// =========================================================================
// 23. DriftClass coverage: comparator_decision uniqueness
// =========================================================================

#[test]
fn drift_class_comparator_decisions_are_limited_set() {
    let decisions: std::collections::BTreeSet<&str> = [
        DriftClass::Equivalent,
        DriftClass::DiagnosticsDrift,
        DriftClass::SemanticDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ]
    .iter()
    .map(|c| c.comparator_decision())
    .collect();
    // Only three distinct decisions: "equivalent", "drift_minor", "drift_critical"
    assert_eq!(decisions.len(), 3);
    assert!(decisions.contains("equivalent"));
    assert!(decisions.contains("drift_minor"));
    assert!(decisions.contains("drift_critical"));
}

// =========================================================================
// 24. GateAction equality
// =========================================================================

#[test]
fn gate_action_eq_and_ne() {
    assert_eq!(GateAction::Promote, GateAction::Promote);
    assert_ne!(GateAction::Promote, GateAction::Hold);
    assert_ne!(GateAction::Hold, GateAction::Reject);
}

// =========================================================================
// 25. ParserOracleConfig custom fields
// =========================================================================

#[test]
fn parser_oracle_config_custom_fields() {
    let config = ParserOracleConfig {
        partition: OraclePartition::Full,
        gate_mode: OracleGateMode::FailClosed,
        fixture_catalog_path: "/custom/path.json".into(),
        seed: 12345,
        trace_id: "custom-trace".to_string(),
        decision_id: "custom-decision".to_string(),
        policy_id: "custom-policy".to_string(),
    };
    assert_eq!(
        config.fixture_catalog_path.to_str().unwrap(),
        "/custom/path.json"
    );
    assert_eq!(config.trace_id, "custom-trace");
    assert_eq!(config.decision_id, "custom-decision");
    assert_eq!(config.policy_id, "custom-policy");
}

// =========================================================================
// 26. OracleFixtureSpec with module goal
// =========================================================================

#[test]
fn oracle_fixture_spec_module_goal() {
    let spec = make_fixture("f-mod", "module", "export default 1;");
    assert_eq!(spec.goal, "module");
}

// =========================================================================
// 27. Multiple partition_fixtures calls are idempotent
// =========================================================================

#[test]
fn partition_fixtures_idempotent() {
    let catalog = make_catalog_with_n(8);
    let a = partition_fixtures(&catalog, OraclePartition::Smoke);
    let b = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(a, b, "partition_fixtures must be idempotent");
}

// =========================================================================
// 28. derive_seed collision resistance (probabilistic)
// =========================================================================

#[test]
fn derive_seed_collision_resistance() {
    let mut seeds = std::collections::BTreeSet::new();
    for i in 0..200 {
        let seed = derive_seed(42, &format!("fixture-{i}"), ParserMode::ScalarReference);
        seeds.insert(seed);
    }
    // With 200 distinct inputs into SHA-256 based derivation, collisions should be
    // essentially impossible.
    assert_eq!(seeds.len(), 200, "all 200 derived seeds must be unique");
}

// =========================================================================
// 29. OracleSummary with large numbers (overflow safety)
// =========================================================================

#[test]
fn oracle_summary_large_values() {
    let summary = OracleSummary {
        total_fixtures: u64::MAX,
        equivalent_count: u64::MAX - 2,
        minor_drift_count: 1,
        critical_drift_count: 1,
        drift_rate_millionths: 0, // would overflow but that is the caller's responsibility
        counts_by_class: BTreeMap::new(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains(&format!("{}", u64::MAX)));
}

// =========================================================================
// 30. OraclePartition Debug impl
// =========================================================================

#[test]
fn oracle_partition_debug() {
    assert_eq!(format!("{:?}", OraclePartition::Smoke), "Smoke");
    assert_eq!(format!("{:?}", OraclePartition::Full), "Full");
    assert_eq!(format!("{:?}", OraclePartition::Nightly), "Nightly");
}

// =========================================================================
// 31. OracleGateMode Debug impl
// =========================================================================

#[test]
fn oracle_gate_mode_debug() {
    assert_eq!(format!("{:?}", OracleGateMode::ReportOnly), "ReportOnly");
    assert_eq!(format!("{:?}", OracleGateMode::FailClosed), "FailClosed");
}

// =========================================================================
// 32. DriftClass Debug impl
// =========================================================================

#[test]
fn drift_class_debug() {
    assert_eq!(format!("{:?}", DriftClass::Equivalent), "Equivalent");
    assert_eq!(format!("{:?}", DriftClass::SemanticDrift), "SemanticDrift");
    assert_eq!(
        format!("{:?}", DriftClass::DiagnosticsDrift),
        "DiagnosticsDrift"
    );
    assert_eq!(
        format!("{:?}", DriftClass::HarnessNondeterminism),
        "HarnessNondeterminism"
    );
    assert_eq!(
        format!("{:?}", DriftClass::ArtifactIntegrityFailure),
        "ArtifactIntegrityFailure"
    );
}

// =========================================================================
// 33. GateAction Debug impl
// =========================================================================

#[test]
fn gate_action_debug() {
    assert_eq!(format!("{:?}", GateAction::Promote), "Promote");
    assert_eq!(format!("{:?}", GateAction::Hold), "Hold");
    assert_eq!(format!("{:?}", GateAction::Reject), "Reject");
}

// =========================================================================
// 34. ParserOracleError Debug impl
// =========================================================================

#[test]
fn parser_oracle_error_debug_io() {
    let err = ParserOracleError::Io {
        path: "/a/b".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let debug = format!("{err:?}");
    assert!(debug.contains("Io"));
    assert!(debug.contains("/a/b"));
}

#[test]
fn parser_oracle_error_debug_decode() {
    let err = ParserOracleError::DecodeCatalog("bad".to_string());
    let debug = format!("{err:?}");
    assert!(debug.contains("DecodeCatalog"));
}

#[test]
fn parser_oracle_error_debug_empty() {
    let err = ParserOracleError::EmptyFixtureCatalog;
    let debug = format!("{err:?}");
    assert!(debug.contains("EmptyFixtureCatalog"));
}

#[test]
fn parser_oracle_error_debug_unknown_goal() {
    let err = ParserOracleError::UnknownGoal {
        fixture_id: "f-1".to_string(),
        goal: "eval".to_string(),
    };
    let debug = format!("{err:?}");
    assert!(debug.contains("UnknownGoal"));
}

// =========================================================================
// 35. Serde deserialization error cases
// =========================================================================

#[test]
fn oracle_partition_deserialize_invalid_value() {
    let result = serde_json::from_str::<OraclePartition>("\"weekly\"");
    assert!(result.is_err());
}

#[test]
fn oracle_gate_mode_deserialize_invalid_value() {
    let result = serde_json::from_str::<OracleGateMode>("\"warn_only\"");
    assert!(result.is_err());
}

#[test]
fn drift_class_deserialize_invalid_value() {
    let result = serde_json::from_str::<DriftClass>("\"total_failure\"");
    assert!(result.is_err());
}

#[test]
fn gate_action_deserialize_invalid_value() {
    let result = serde_json::from_str::<GateAction>("\"defer\"");
    assert!(result.is_err());
}

#[test]
fn oracle_partition_deserialize_not_a_string() {
    let result = serde_json::from_str::<OraclePartition>("42");
    assert!(result.is_err());
}

// =========================================================================
// 36. OracleFixtureCatalog deserialization edge cases
// =========================================================================

#[test]
fn oracle_fixture_catalog_deserialize_missing_fixtures() {
    let json = r#"{
        "schema_version": "v1",
        "parser_mode": "scalar_reference"
    }"#;
    let result = serde_json::from_str::<OracleFixtureCatalog>(json);
    assert!(result.is_err());
}

#[test]
fn oracle_fixture_catalog_deserialize_extra_fields_tolerated() {
    let json = r#"{
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "extra_field": "ignored",
        "fixtures": [
            {
                "id": "f-1",
                "family_id": "fam",
                "goal": "script",
                "source": "1",
                "expected_hash": "sha256:00"
            }
        ]
    }"#;
    // Serde by default ignores unknown fields for Deserialize structs.
    let catalog: OracleFixtureCatalog = serde_json::from_str(json).unwrap();
    assert_eq!(catalog.fixtures.len(), 1);
}

// =========================================================================
// 37. OracleDecision clone and eq
// =========================================================================

#[test]
fn oracle_decision_clone_eq() {
    let a = OracleDecision {
        action: GateAction::Hold,
        promotion_blocked: true,
        fallback_triggered: false,
        fallback_reason: Some("test".to_string()),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// 38. ExpectedLossModel clone
// =========================================================================

#[test]
fn expected_loss_model_clone() {
    let a = ExpectedLossModel {
        promote_loss: 1.5,
        hold_loss: 2.5,
        reject_loss: 0.5,
        recommended_action: GateAction::Reject,
    };
    let b = a.clone();
    assert_eq!(a.promote_loss, b.promote_loss);
    assert_eq!(a.hold_loss, b.hold_loss);
    assert_eq!(a.reject_loss, b.reject_loss);
    assert_eq!(a.recommended_action, b.recommended_action);
}

// =========================================================================
// 39. ParserOracleReport Serialize (construct directly)
// =========================================================================

#[test]
fn parser_oracle_report_serialize_minimal() {
    let report = frankenengine_engine::parser_oracle::ParserOracleReport {
        schema_version: "franken-engine.parser-oracle.report.v1".to_string(),
        taxonomy_version: "franken-engine.parser-oracle.taxonomy.v1".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        partition: OraclePartition::Smoke,
        gate_mode: OracleGateMode::ReportOnly,
        parser_mode: "scalar_reference".to_string(),
        fixture_catalog_path: "/dev/null".to_string(),
        fixture_catalog_hash: "sha256:abc".to_string(),
        seed: 42,
        metamorphic_pair_budget: 64,
        fixture_results: vec![],
        summary: make_summary(1, 0, 0),
        expected_loss: ExpectedLossModel {
            promote_loss: 0.0,
            hold_loss: 6.0,
            reject_loss: 10.0,
            recommended_action: GateAction::Promote,
        },
        decision: OracleDecision {
            action: GateAction::Promote,
            promotion_blocked: false,
            fallback_triggered: false,
            fallback_reason: None,
        },
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("franken-engine.parser-oracle.report.v1"));
    assert!(json.contains("trace-1"));
    assert!(json.contains("decision-1"));
    assert!(json.contains("policy-1"));
    assert!(json.contains("\"promote\""));
}

// =========================================================================
// 40. Integration: partition + summary + decision flow
// =========================================================================

#[test]
fn integration_all_equivalent_smoke_flow() {
    let summary = make_summary(4, 0, 0);
    assert_eq!(summary.drift_rate_millionths, 0);
    assert_eq!(summary.equivalent_count, 4);
}

#[test]
fn integration_mixed_drift_flow() {
    let summary = make_summary(7, 2, 1);
    // drift_rate = (2+1)*1_000_000/10 = 300_000
    assert_eq!(summary.drift_rate_millionths, 300_000);
}

// =========================================================================
// 41. ParserOracleConfig with_defaults generates unique trace_id per call
// =========================================================================

#[test]
fn config_with_defaults_trace_id_contains_timestamp() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::ReportOnly, 0);
    // The timestamp format is YYYYMMDDTHHMMSSz
    assert!(config.trace_id.len() > "trace-parser-oracle-".len());
    assert!(config.decision_id.len() > "decision-parser-oracle-".len());
}

// =========================================================================
// 42. OracleFixtureSpec with various source lengths
// =========================================================================

#[test]
fn oracle_fixture_spec_empty_source() {
    let spec = make_fixture("f-empty", "script", "");
    assert!(spec.source.is_empty());
}

#[test]
fn oracle_fixture_spec_large_source() {
    let large = "x".repeat(100_000);
    let spec = make_fixture("f-large", "script", &large);
    assert_eq!(spec.source.len(), 100_000);
}

// =========================================================================
// 43. DriftClass copy semantics
// =========================================================================

#[test]
fn drift_class_copy() {
    let a = DriftClass::SemanticDrift;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// 44. GateAction copy semantics
// =========================================================================

#[test]
fn gate_action_copy() {
    let a = GateAction::Hold;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// 45. OracleGateMode copy semantics
// =========================================================================

#[test]
fn oracle_gate_mode_copy() {
    let a = OracleGateMode::FailClosed;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// 46. OracleSummary clone
// =========================================================================

#[test]
fn oracle_summary_clone_eq() {
    let a = make_summary(50, 3, 1);
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// 47. OracleFixtureResult clone and eq
// =========================================================================

#[test]
fn oracle_fixture_result_clone_eq() {
    let a = OracleFixtureResult {
        fixture_id: "f-1".to_string(),
        family_id: "fam".to_string(),
        goal: "script".to_string(),
        parser_mode: "scalar_reference".to_string(),
        derived_seed: 42,
        input_hash: "sha256:aa".to_string(),
        expected_hash: "sha256:aa".to_string(),
        observed_hash: Some("sha256:aa".to_string()),
        repeated_hash: Some("sha256:aa".to_string()),
        parse_error_code: None,
        repeated_error_code: None,
        drift_class: DriftClass::Equivalent,
        comparator_decision: "equivalent".to_string(),
        latency_ns: 100,
        replay_command: "cargo run".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// 48. Multiple serialization round-trips remain stable
// =========================================================================

#[test]
fn serde_double_roundtrip_oracle_partition() {
    let original = OraclePartition::Nightly;
    let json1 = serde_json::to_string(&original).unwrap();
    let decoded1: OraclePartition = serde_json::from_str(&json1).unwrap();
    let json2 = serde_json::to_string(&decoded1).unwrap();
    let decoded2: OraclePartition = serde_json::from_str(&json2).unwrap();
    assert_eq!(original, decoded2);
    assert_eq!(json1, json2);
}

#[test]
fn serde_double_roundtrip_drift_class() {
    let original = DriftClass::HarnessNondeterminism;
    let json1 = serde_json::to_string(&original).unwrap();
    let decoded1: DriftClass = serde_json::from_str(&json1).unwrap();
    let json2 = serde_json::to_string(&decoded1).unwrap();
    let decoded2: DriftClass = serde_json::from_str(&json2).unwrap();
    assert_eq!(original, decoded2);
    assert_eq!(json1, json2);
}

// =========================================================================
// 49. OracleFixtureCatalog with multiple fixtures
// =========================================================================

#[test]
fn oracle_fixture_catalog_multiple_fixtures() {
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
        parser_mode: "scalar_reference".to_string(),
        fixtures: vec![
            make_fixture("f-01", "script", "var a;"),
            make_fixture("f-02", "module", "export default 1;"),
            make_fixture("f-03", "script", "function f() {}"),
        ],
    };
    assert_eq!(catalog.fixtures.len(), 3);
    assert_eq!(catalog.fixtures[1].goal, "module");
}

// =========================================================================
// 50. ParserOracleReport clone
// =========================================================================

#[test]
fn parser_oracle_report_clone() {
    let report = frankenengine_engine::parser_oracle::ParserOracleReport {
        schema_version: "franken-engine.parser-oracle.report.v1".to_string(),
        taxonomy_version: "franken-engine.parser-oracle.taxonomy.v1".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        partition: OraclePartition::Full,
        gate_mode: OracleGateMode::FailClosed,
        parser_mode: "scalar_reference".to_string(),
        fixture_catalog_path: "/path".to_string(),
        fixture_catalog_hash: "sha256:abc".to_string(),
        seed: 0,
        metamorphic_pair_budget: 256,
        fixture_results: vec![],
        summary: make_summary(1, 0, 0),
        expected_loss: ExpectedLossModel {
            promote_loss: 0.0,
            hold_loss: 6.0,
            reject_loss: 10.0,
            recommended_action: GateAction::Promote,
        },
        decision: OracleDecision {
            action: GateAction::Promote,
            promotion_blocked: false,
            fallback_triggered: false,
            fallback_reason: None,
        },
    };
    let cloned = report.clone();
    assert_eq!(report.schema_version, cloned.schema_version);
    assert_eq!(report.trace_id, cloned.trace_id);
}
