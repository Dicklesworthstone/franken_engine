#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_oracle` module.

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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use frankenengine_engine::parser::ParserMode;
use frankenengine_engine::parser_oracle::{
    DEFAULT_FIXTURE_CATALOG_PATH, DriftClass, GateAction, OracleDecision, OracleFixtureCatalog,
    OracleFixtureResult, OracleFixtureSpec, OracleGateMode, OraclePartition, OracleSummary,
    PARSER_ORACLE_REPORT_SCHEMA_VERSION, PARSER_ORACLE_TAXONOMY_VERSION, ParserOracleConfig,
    ParserOracleError, derive_seed, load_fixture_catalog, partition_fixtures,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_non_empty() {
    assert!(!DEFAULT_FIXTURE_CATALOG_PATH.is_empty());
    assert!(!PARSER_ORACLE_REPORT_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_ORACLE_TAXONOMY_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// OraclePartition
// ---------------------------------------------------------------------------

#[test]
fn enrichment_partition_as_str_all_distinct() {
    let all = [
        OraclePartition::Smoke,
        OraclePartition::Full,
        OraclePartition::Nightly,
    ];
    let set: BTreeSet<&str> = all.iter().map(|p| p.as_str()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_partition_as_str_values() {
    assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
    assert_eq!(OraclePartition::Full.as_str(), "full");
    assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
}

#[test]
fn enrichment_partition_fixture_limit() {
    assert_eq!(OraclePartition::Smoke.fixture_limit(), Some(4));
    assert_eq!(OraclePartition::Full.fixture_limit(), None);
    assert_eq!(OraclePartition::Nightly.fixture_limit(), None);
}

#[test]
fn enrichment_partition_metamorphic_pairs() {
    assert_eq!(OraclePartition::Smoke.metamorphic_pairs(), 64);
    assert_eq!(OraclePartition::Full.metamorphic_pairs(), 256);
    assert_eq!(OraclePartition::Nightly.metamorphic_pairs(), 1024);
}

#[test]
fn enrichment_partition_from_str_valid() {
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
fn enrichment_partition_from_str_invalid() {
    let err = "unknown".parse::<OraclePartition>().unwrap_err();
    assert!(err.contains("unsupported partition"));
}

#[test]
fn enrichment_partition_serde_roundtrip() {
    for p in [
        OraclePartition::Smoke,
        OraclePartition::Full,
        OraclePartition::Nightly,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: OraclePartition = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn enrichment_partition_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&OraclePartition::Smoke).unwrap(),
        "\"smoke\""
    );
    assert_eq!(
        serde_json::to_string(&OraclePartition::Full).unwrap(),
        "\"full\""
    );
    assert_eq!(
        serde_json::to_string(&OraclePartition::Nightly).unwrap(),
        "\"nightly\""
    );
}

// ---------------------------------------------------------------------------
// OracleGateMode
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_mode_as_str_all_distinct() {
    let all = [OracleGateMode::ReportOnly, OracleGateMode::FailClosed];
    let set: BTreeSet<&str> = all.iter().map(|m| m.as_str()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_gate_mode_as_str_values() {
    assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
    assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
}

#[test]
fn enrichment_gate_mode_from_str_valid() {
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
fn enrichment_gate_mode_from_str_invalid() {
    let err = "bad".parse::<OracleGateMode>().unwrap_err();
    assert!(err.contains("unsupported gate mode"));
}

#[test]
fn enrichment_gate_mode_serde_roundtrip() {
    for m in [OracleGateMode::ReportOnly, OracleGateMode::FailClosed] {
        let json = serde_json::to_string(&m).unwrap();
        let back: OracleGateMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

// ---------------------------------------------------------------------------
// DriftClass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_drift_class_comparator_decision_all() {
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
fn enrichment_drift_class_is_critical() {
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(!DriftClass::DiagnosticsDrift.is_critical());
    assert!(DriftClass::SemanticDrift.is_critical());
    assert!(DriftClass::HarnessNondeterminism.is_critical());
    assert!(DriftClass::ArtifactIntegrityFailure.is_critical());
}

#[test]
fn enrichment_drift_class_is_minor() {
    assert!(DriftClass::DiagnosticsDrift.is_minor());
    assert!(!DriftClass::Equivalent.is_minor());
    assert!(!DriftClass::SemanticDrift.is_minor());
}

#[test]
fn enrichment_drift_class_serde_roundtrip() {
    for dc in [
        DriftClass::Equivalent,
        DriftClass::SemanticDrift,
        DriftClass::DiagnosticsDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ] {
        let json = serde_json::to_string(&dc).unwrap();
        let back: DriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }
}

#[test]
fn enrichment_drift_class_debug_all_distinct() {
    let all = [
        DriftClass::Equivalent,
        DriftClass::SemanticDrift,
        DriftClass::DiagnosticsDrift,
        DriftClass::HarnessNondeterminism,
        DriftClass::ArtifactIntegrityFailure,
    ];
    let set: BTreeSet<String> = all.iter().map(|d| format!("{d:?}")).collect();
    assert_eq!(set.len(), all.len());
}

// ---------------------------------------------------------------------------
// GateAction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_action_serde_roundtrip() {
    for a in [GateAction::Promote, GateAction::Hold, GateAction::Reject] {
        let json = serde_json::to_string(&a).unwrap();
        let back: GateAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

#[test]
fn enrichment_gate_action_debug_all_distinct() {
    let all = [GateAction::Promote, GateAction::Hold, GateAction::Reject];
    let set: BTreeSet<String> = all.iter().map(|a| format!("{a:?}")).collect();
    assert_eq!(set.len(), all.len());
}

// ---------------------------------------------------------------------------
// derive_seed
// ---------------------------------------------------------------------------

#[test]
fn enrichment_derive_seed_deterministic() {
    let a = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
    let b = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
    assert_eq!(a, b);
}

#[test]
fn enrichment_derive_seed_different_fixture_ids() {
    let a = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
    let b = derive_seed(42, "fixture-2", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

#[test]
fn enrichment_derive_seed_different_master_seeds() {
    let a = derive_seed(1, "fixture-1", ParserMode::ScalarReference);
    let b = derive_seed(2, "fixture-1", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// partition_fixtures
// ---------------------------------------------------------------------------

fn make_catalog(n: usize) -> OracleFixtureCatalog {
    OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".into(),
        parser_mode: "scalar_reference".into(),
        fixtures: (0..n)
            .map(|i| OracleFixtureSpec {
                id: format!("f-{i:03}"),
                family_id: "fam".into(),
                goal: "script".into(),
                source: format!("var x = {i};"),
                expected_hash: "sha256:00".into(),
            })
            .collect(),
    }
}

#[test]
fn enrichment_partition_smoke_limits() {
    let catalog = make_catalog(10);
    let result = partition_fixtures(&catalog, OraclePartition::Smoke);
    assert_eq!(result.len(), 4);
}

#[test]
fn enrichment_partition_full_no_limit() {
    let catalog = make_catalog(10);
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert_eq!(result.len(), 10);
}

#[test]
fn enrichment_partition_sorted_by_id() {
    let catalog = OracleFixtureCatalog {
        schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".into(),
        parser_mode: "scalar_reference".into(),
        fixtures: vec![
            OracleFixtureSpec {
                id: "z-last".into(),
                family_id: "fam".into(),
                goal: "script".into(),
                source: "1".into(),
                expected_hash: "sha256:00".into(),
            },
            OracleFixtureSpec {
                id: "a-first".into(),
                family_id: "fam".into(),
                goal: "script".into(),
                source: "2".into(),
                expected_hash: "sha256:00".into(),
            },
        ],
    };
    let result = partition_fixtures(&catalog, OraclePartition::Full);
    assert_eq!(result[0].id, "a-first");
    assert_eq!(result[1].id, "z-last");
}

// ---------------------------------------------------------------------------
// ParserOracleConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_with_defaults() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::ReportOnly, 42);
    assert_eq!(config.partition, OraclePartition::Smoke);
    assert_eq!(config.gate_mode, OracleGateMode::ReportOnly);
    assert_eq!(config.seed, 42);
    assert!(config.trace_id.starts_with("trace-parser-oracle-"));
    assert!(config.decision_id.starts_with("decision-parser-oracle-"));
    assert_eq!(config.policy_id, "policy-parser-oracle-v1");
}

// ---------------------------------------------------------------------------
// ParserOracleError Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_io() {
    let err = ParserOracleError::Io {
        path: "/missing".into(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let msg = err.to_string();
    assert!(msg.contains("/missing"));
    assert!(msg.contains("not found"));
}

#[test]
fn enrichment_error_display_decode_catalog() {
    let err = ParserOracleError::DecodeCatalog("bad json".into());
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn enrichment_error_display_invalid_schema() {
    let err = ParserOracleError::InvalidCatalogSchema {
        expected: "v1".into(),
        actual: "v2".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("v2"));
}

#[test]
fn enrichment_error_display_invalid_parser_mode() {
    let err = ParserOracleError::InvalidCatalogParserMode {
        expected: "scalar_reference".into(),
        actual: "parallel".into(),
    };
    assert!(err.to_string().contains("parallel"));
}

#[test]
fn enrichment_error_display_empty_catalog() {
    let err = ParserOracleError::EmptyFixtureCatalog;
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn enrichment_error_display_unknown_goal() {
    let err = ParserOracleError::UnknownGoal {
        fixture_id: "f1".into(),
        goal: "bad".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("f1"));
    assert!(msg.contains("bad"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err = ParserOracleError::EmptyFixtureCatalog;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// load_fixture_catalog error path
// ---------------------------------------------------------------------------

#[test]
fn enrichment_load_catalog_nonexistent() {
    let err = load_fixture_catalog(Path::new("/nonexistent/catalog.json")).unwrap_err();
    assert!(err.to_string().contains("failed to read"));
}

// ---------------------------------------------------------------------------
// OracleDecision serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_oracle_decision_serde() {
    let decision = OracleDecision {
        action: GateAction::Hold,
        promotion_blocked: true,
        fallback_triggered: false,
        fallback_reason: Some("minor drift".into()),
    };
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("hold"));
    assert!(json.contains("minor drift"));
}

// ---------------------------------------------------------------------------
// OracleSummary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_oracle_summary_serde() {
    let summary = OracleSummary {
        total_fixtures: 100,
        equivalent_count: 90,
        minor_drift_count: 5,
        critical_drift_count: 5,
        drift_rate_millionths: 100_000,
        counts_by_class: {
            let mut m = BTreeMap::new();
            m.insert("Equivalent".into(), 90);
            m.insert("DiagnosticsDrift".into(), 5);
            m.insert("SemanticDrift".into(), 5);
            m
        },
    };
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("total_fixtures"));
    assert!(json.contains("100000"));
}

// ---------------------------------------------------------------------------
// OracleFixtureResult serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fixture_result_serde() {
    let result = OracleFixtureResult {
        fixture_id: "f-01".into(),
        family_id: "fam-1".into(),
        goal: "script".into(),
        parser_mode: "scalar_reference".into(),
        derived_seed: 12345,
        input_hash: "sha256:abc".into(),
        expected_hash: "sha256:abc".into(),
        observed_hash: Some("sha256:abc".into()),
        repeated_hash: Some("sha256:abc".into()),
        parse_error_code: None,
        repeated_error_code: None,
        drift_class: DriftClass::Equivalent,
        comparator_decision: "equivalent".into(),
        latency_ns: 1000,
        replay_command: "cargo run ...".into(),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("f-01"));
    assert!(json.contains("equivalent"));
}
