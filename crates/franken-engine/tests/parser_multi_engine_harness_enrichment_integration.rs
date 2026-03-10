#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_multi_engine_harness` module.
//!
//! Covers JSON field-name stability, Debug distinctness, exact Display messages,
//! serde roundtrips, factory methods, config validation, constants, and
//! DriftClassification/DriftReproPack/DriftMinimizationStats content.

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

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_engine::parser_multi_engine_harness::{
    AstNormalizationAdapter, DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH,
    DiagnosticNormalizationAdapter, DriftCategory, DriftClassification, DriftMinimizationStats,
    DriftReproPack, DriftSeverity, EngineOutcomeKind, HarnessEngineKind, HarnessEngineSpec,
    MultiEngineHarnessConfig, MultiEngineHarnessError, NormalizedAstArtifact,
    NormalizedDiagnosticArtifact, run_multi_engine_harness,
};

// ── Helpers ────────────────────────────────────────────────────────────────

fn test_config(seed: u64) -> MultiEngineHarnessConfig {
    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    config.fixture_limit = Some(1);
    config.trace_id = "trace-enrichment".to_string();
    config.decision_id = "decision-enrichment".to_string();
    config.policy_id = "policy-enrichment-v1".to_string();
    config
}

fn make_drift_classification(
    category: DriftCategory,
    severity: DriftSeverity,
) -> DriftClassification {
    DriftClassification {
        taxonomy_version: "franken-engine.parser-multi-engine-drift-taxonomy.v1".to_string(),
        category,
        severity,
        comparator_decision: match severity {
            DriftSeverity::Minor => "drift_minor".to_string(),
            DriftSeverity::Critical => "drift_critical".to_string(),
        },
        owner_hint: match category {
            DriftCategory::Semantic => "parser-core".to_string(),
            DriftCategory::Diagnostics => "parser-diagnostics-taxonomy".to_string(),
            DriftCategory::Harness => "parser-multi-engine-harness".to_string(),
            DriftCategory::Artifact => "parser-artifact-contract".to_string(),
        },
        remediation_hint: match category {
            DriftCategory::Semantic => {
                "replay fixture and compare normalized AST hashes across engines".to_string()
            }
            DriftCategory::Diagnostics => {
                "inspect normalized diagnostic codes and alias mappings for peer engines"
                    .to_string()
            }
            DriftCategory::Harness => {
                "rerun with fixed seed/env and audit harness/external-command nondeterminism"
                    .to_string()
            }
            DriftCategory::Artifact => {
                "validate normalized artifact shape and schema compatibility per engine outcome"
                    .to_string()
            }
        },
    }
}

fn make_minimization_stats() -> DriftMinimizationStats {
    DriftMinimizationStats {
        attempted: true,
        rounds: 5,
        candidates_evaluated: 20,
        bytes_removed: 100,
        original_bytes: 500,
        minimized_bytes: 400,
        fixed_point: false,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn default_fixture_catalog_path_nonempty() {
    assert!(!DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH.is_empty());
    assert!(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH.ends_with(".json"));
}

// ===========================================================================
// 2. HarnessEngineKind: serde roundtrip
// ===========================================================================

#[test]
fn harness_engine_kind_serde_all_variants() {
    for kind in [
        HarnessEngineKind::FrankenCanonical,
        HarnessEngineKind::FixtureExpectedHash,
        HarnessEngineKind::ExternalCommand,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: HarnessEngineKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back, "roundtrip failed for {kind:?}");
    }
}

// ===========================================================================
// 3. HarnessEngineKind: Debug distinctness
// ===========================================================================

#[test]
fn harness_engine_kind_debug_distinct() {
    let variants = [
        HarnessEngineKind::FrankenCanonical,
        HarnessEngineKind::FixtureExpectedHash,
        HarnessEngineKind::ExternalCommand,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        debugs.insert(format!("{v:?}"));
    }
    assert_eq!(debugs.len(), 3);
}

// ===========================================================================
// 4. HarnessEngineKind: serde rename_all snake_case
// ===========================================================================

#[test]
fn harness_engine_kind_snake_case_serde() {
    let json = serde_json::to_string(&HarnessEngineKind::FrankenCanonical).unwrap();
    assert_eq!(json, "\"franken_canonical\"");

    let json = serde_json::to_string(&HarnessEngineKind::FixtureExpectedHash).unwrap();
    assert_eq!(json, "\"fixture_expected_hash\"");

    let json = serde_json::to_string(&HarnessEngineKind::ExternalCommand).unwrap();
    assert_eq!(json, "\"external_command\"");
}

// ===========================================================================
// 5. HarnessEngineSpec: franken_canonical factory
// ===========================================================================

#[test]
fn harness_engine_spec_franken_canonical() {
    let spec = HarnessEngineSpec::franken_canonical("v1.0");
    assert_eq!(spec.engine_id, "franken_canonical");
    assert_eq!(spec.display_name, "FrankenEngine Canonical Parser");
    assert_eq!(spec.kind, HarnessEngineKind::FrankenCanonical);
    assert_eq!(spec.version_pin, "v1.0");
    assert_eq!(spec.command, None);
    assert!(spec.args.is_empty());
}

// ===========================================================================
// 6. HarnessEngineSpec: fixture_expected_hash factory
// ===========================================================================

#[test]
fn harness_engine_spec_fixture_expected_hash() {
    let spec = HarnessEngineSpec::fixture_expected_hash("catalog@v2");
    assert_eq!(spec.engine_id, "fixture_expected_hash");
    assert_eq!(spec.display_name, "Fixture Expected Hash Baseline");
    assert_eq!(spec.kind, HarnessEngineKind::FixtureExpectedHash);
    assert_eq!(spec.version_pin, "catalog@v2");
    assert_eq!(spec.command, None);
    assert!(spec.args.is_empty());
}

// ===========================================================================
// 7. HarnessEngineSpec: serde roundtrip
// ===========================================================================

#[test]
fn harness_engine_spec_serde_roundtrip() {
    let spec = HarnessEngineSpec::franken_canonical("v1.0");
    let json = serde_json::to_string(&spec).unwrap();
    let back: HarnessEngineSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ===========================================================================
// 8. HarnessEngineSpec: JSON field names
// ===========================================================================

#[test]
fn harness_engine_spec_json_fields() {
    let spec = HarnessEngineSpec::franken_canonical("v1.0");
    let json = serde_json::to_string(&spec).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["engine_id", "display_name", "kind", "version_pin"] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 9. HarnessEngineSpec: with command and args serde
// ===========================================================================

#[test]
fn harness_engine_spec_external_command_serde() {
    let spec = HarnessEngineSpec {
        engine_id: "external_mock".to_string(),
        display_name: "External Mock".to_string(),
        kind: HarnessEngineKind::ExternalCommand,
        version_pin: "v1".to_string(),
        command: Some("sh".to_string()),
        args: vec!["-c".to_string(), "echo test".to_string()],
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: HarnessEngineSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
    assert_eq!(back.command, Some("sh".to_string()));
    assert_eq!(back.args.len(), 2);
}

// ===========================================================================
// 10. MultiEngineHarnessConfig: with_defaults
// ===========================================================================

#[test]
fn config_with_defaults_fields() {
    let config = MultiEngineHarnessConfig::with_defaults(42);
    assert_eq!(config.seed, 42);
    assert_eq!(
        config.fixture_catalog_path,
        PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH)
    );
    assert_eq!(config.fixture_limit, Some(8));
    assert_eq!(config.fixture_id_filter, None);
    assert_eq!(config.locale, "C");
    assert_eq!(config.timezone, "UTC");
    assert!(config.trace_id.contains("parser-multi-engine"));
    assert!(config.decision_id.contains("parser-multi-engine"));
    assert_eq!(config.policy_id, "policy-parser-multi-engine-v1");
    assert_eq!(config.engines.len(), 2);
    assert_eq!(config.engines[0].kind, HarnessEngineKind::FrankenCanonical);
    assert_eq!(
        config.engines[1].kind,
        HarnessEngineKind::FixtureExpectedHash
    );
}

// ===========================================================================
// 11. DriftCategory: serde roundtrip all variants
// ===========================================================================

#[test]
fn drift_category_serde_all_variants() {
    for cat in [
        DriftCategory::Semantic,
        DriftCategory::Diagnostics,
        DriftCategory::Harness,
        DriftCategory::Artifact,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: DriftCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back, "roundtrip failed for {cat:?}");
    }
}

// ===========================================================================
// 12. DriftCategory: Debug distinctness
// ===========================================================================

#[test]
fn drift_category_debug_distinct() {
    let variants = [
        DriftCategory::Semantic,
        DriftCategory::Diagnostics,
        DriftCategory::Harness,
        DriftCategory::Artifact,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        debugs.insert(format!("{v:?}"));
    }
    assert_eq!(debugs.len(), 4);
}

// ===========================================================================
// 13. DriftCategory: snake_case serde values
// ===========================================================================

#[test]
fn drift_category_snake_case_serde() {
    assert_eq!(
        serde_json::to_string(&DriftCategory::Semantic).unwrap(),
        "\"semantic\""
    );
    assert_eq!(
        serde_json::to_string(&DriftCategory::Diagnostics).unwrap(),
        "\"diagnostics\""
    );
    assert_eq!(
        serde_json::to_string(&DriftCategory::Harness).unwrap(),
        "\"harness\""
    );
    assert_eq!(
        serde_json::to_string(&DriftCategory::Artifact).unwrap(),
        "\"artifact\""
    );
}

// ===========================================================================
// 14. DriftSeverity: serde roundtrip
// ===========================================================================

#[test]
fn drift_severity_serde_all_variants() {
    for sev in [DriftSeverity::Minor, DriftSeverity::Critical] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back, "roundtrip failed for {sev:?}");
    }
}

// ===========================================================================
// 15. DriftSeverity: Debug distinctness
// ===========================================================================

#[test]
fn drift_severity_debug_distinct() {
    let debugs: BTreeSet<_> = [DriftSeverity::Minor, DriftSeverity::Critical]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 2);
}

// ===========================================================================
// 16. DriftSeverity: snake_case serde values
// ===========================================================================

#[test]
fn drift_severity_snake_case_serde() {
    assert_eq!(
        serde_json::to_string(&DriftSeverity::Minor).unwrap(),
        "\"minor\""
    );
    assert_eq!(
        serde_json::to_string(&DriftSeverity::Critical).unwrap(),
        "\"critical\""
    );
}

// ===========================================================================
// 17. DriftClassification: serde roundtrip
// ===========================================================================

#[test]
fn drift_classification_serde_roundtrip() {
    let dc = make_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
    let json = serde_json::to_string(&dc).unwrap();
    let back: DriftClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, back);
}

// ===========================================================================
// 18. DriftClassification: JSON field names
// ===========================================================================

#[test]
fn drift_classification_json_fields() {
    let dc = make_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor);
    let json = serde_json::to_string(&dc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "taxonomy_version",
        "category",
        "severity",
        "comparator_decision",
        "owner_hint",
        "remediation_hint",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 19. DriftClassification: owner_hint exact values for each category
// ===========================================================================

#[test]
fn drift_classification_owner_hint_semantic() {
    let dc = make_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
    assert_eq!(dc.owner_hint, "parser-core");
}

#[test]
fn drift_classification_owner_hint_diagnostics() {
    let dc = make_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor);
    assert_eq!(dc.owner_hint, "parser-diagnostics-taxonomy");
}

#[test]
fn drift_classification_owner_hint_harness() {
    let dc = make_drift_classification(DriftCategory::Harness, DriftSeverity::Critical);
    assert_eq!(dc.owner_hint, "parser-multi-engine-harness");
}

#[test]
fn drift_classification_owner_hint_artifact() {
    let dc = make_drift_classification(DriftCategory::Artifact, DriftSeverity::Critical);
    assert_eq!(dc.owner_hint, "parser-artifact-contract");
}

// ===========================================================================
// 20. DriftClassification: comparator_decision exact values
// ===========================================================================

#[test]
fn drift_classification_comparator_minor() {
    let dc = make_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor);
    assert_eq!(dc.comparator_decision, "drift_minor");
}

#[test]
fn drift_classification_comparator_critical() {
    let dc = make_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
    assert_eq!(dc.comparator_decision, "drift_critical");
}

// ===========================================================================
// 21. DriftClassification: all 8 category×severity combos roundtrip
// ===========================================================================

#[test]
fn drift_classification_all_combos_serde() {
    for category in [
        DriftCategory::Semantic,
        DriftCategory::Diagnostics,
        DriftCategory::Harness,
        DriftCategory::Artifact,
    ] {
        for severity in [DriftSeverity::Minor, DriftSeverity::Critical] {
            let dc = make_drift_classification(category, severity);
            let json = serde_json::to_string(&dc).unwrap();
            let back: DriftClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(dc, back, "roundtrip failed for {category:?}/{severity:?}");
        }
    }
}

// ===========================================================================
// 22. DriftMinimizationStats: serde roundtrip
// ===========================================================================

#[test]
fn drift_minimization_stats_serde_roundtrip() {
    let stats = make_minimization_stats();
    let json = serde_json::to_string(&stats).unwrap();
    let back: DriftMinimizationStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

// ===========================================================================
// 23. DriftMinimizationStats: JSON field names
// ===========================================================================

#[test]
fn drift_minimization_stats_json_fields() {
    let stats = make_minimization_stats();
    let json = serde_json::to_string(&stats).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "attempted",
        "rounds",
        "candidates_evaluated",
        "bytes_removed",
        "original_bytes",
        "minimized_bytes",
        "fixed_point",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 24. DriftMinimizationStats: not attempted state
// ===========================================================================

#[test]
fn drift_minimization_stats_not_attempted() {
    let stats = DriftMinimizationStats {
        attempted: false,
        rounds: 0,
        candidates_evaluated: 0,
        bytes_removed: 0,
        original_bytes: 100,
        minimized_bytes: 100,
        fixed_point: true,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: DriftMinimizationStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
    assert!(!back.attempted);
    assert!(back.fixed_point);
}

// ===========================================================================
// 25. DriftReproPack: serde roundtrip
// ===========================================================================

#[test]
fn drift_repro_pack_serde_roundtrip() {
    let pack = DriftReproPack {
        schema_version: "franken-engine.parser-drift-repro-pack.v1".to_string(),
        fixture_id: "fix-1".to_string(),
        family_id: "family-1".to_string(),
        source_hash: "sha256:abc".to_string(),
        minimized_source: "var x;".to_string(),
        minimized_source_hash: "sha256:def".to_string(),
        replay_command: "cargo run --test".to_string(),
        drift_classification: make_drift_classification(
            DriftCategory::Semantic,
            DriftSeverity::Critical,
        ),
        minimization: make_minimization_stats(),
        promotion_hooks: vec!["hook1".to_string(), "hook2".to_string()],
        provenance_hash: "sha256:ghi".to_string(),
    };
    let json = serde_json::to_string(&pack).unwrap();
    let back: DriftReproPack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

// ===========================================================================
// 26. DriftReproPack: JSON field names
// ===========================================================================

#[test]
fn drift_repro_pack_json_fields() {
    let pack = DriftReproPack {
        schema_version: "v1".to_string(),
        fixture_id: "f".to_string(),
        family_id: "fam".to_string(),
        source_hash: "h1".to_string(),
        minimized_source: "x".to_string(),
        minimized_source_hash: "h2".to_string(),
        replay_command: "cmd".to_string(),
        drift_classification: make_drift_classification(
            DriftCategory::Harness,
            DriftSeverity::Critical,
        ),
        minimization: make_minimization_stats(),
        promotion_hooks: vec![],
        provenance_hash: "h3".to_string(),
    };
    let json = serde_json::to_string(&pack).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "fixture_id",
        "family_id",
        "source_hash",
        "minimized_source",
        "minimized_source_hash",
        "replay_command",
        "drift_classification",
        "minimization",
        "promotion_hooks",
        "provenance_hash",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 27. AstNormalizationAdapter: serde roundtrip
// ===========================================================================

#[test]
fn ast_normalization_adapter_serde_roundtrip() {
    let adapter = AstNormalizationAdapter::CanonicalHashPassthroughV1;
    let json = serde_json::to_string(&adapter).unwrap();
    let back: AstNormalizationAdapter = serde_json::from_str(&json).unwrap();
    assert_eq!(adapter, back);
    assert_eq!(json, "\"canonical_hash_passthrough_v1\"");
}

// ===========================================================================
// 28. DiagnosticNormalizationAdapter: serde roundtrip
// ===========================================================================

#[test]
fn diagnostic_normalization_adapter_serde_roundtrip() {
    let adapter = DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1;
    let json = serde_json::to_string(&adapter).unwrap();
    let back: DiagnosticNormalizationAdapter = serde_json::from_str(&json).unwrap();
    assert_eq!(adapter, back);
    assert_eq!(json, "\"parser_diagnostics_taxonomy_v1\"");
}

// ===========================================================================
// 29. NormalizedAstArtifact: serde roundtrip
// ===========================================================================

#[test]
fn normalized_ast_artifact_serde_roundtrip() {
    let artifact = NormalizedAstArtifact {
        schema_version: "franken-engine.parser-ast-normalization.v1".to_string(),
        adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
        canonical_hash: "sha256:abc123".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: NormalizedAstArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ===========================================================================
// 30. NormalizedAstArtifact: JSON field names
// ===========================================================================

#[test]
fn normalized_ast_artifact_json_fields() {
    let artifact = NormalizedAstArtifact {
        schema_version: "v1".to_string(),
        adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
        canonical_hash: "h".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["schema_version", "adapter", "canonical_hash"] {
        assert!(obj.contains_key(key), "missing {key}");
    }
}

// ===========================================================================
// 31. NormalizedDiagnosticArtifact: serde roundtrip
// ===========================================================================

#[test]
fn normalized_diagnostic_artifact_serde_roundtrip() {
    let artifact = NormalizedDiagnosticArtifact {
        schema_version: "franken-engine.parser-diagnostic-normalization.v1".to_string(),
        taxonomy_version: "external.engine-diagnostic.v1".to_string(),
        adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
        diagnostic_code: "empty_source".to_string(),
        category: "syntax".to_string(),
        severity: "error".to_string(),
        parse_error_code: Some("E001".to_string()),
        canonical_hash: "sha256:def456".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: NormalizedDiagnosticArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ===========================================================================
// 32. NormalizedDiagnosticArtifact: JSON field names
// ===========================================================================

#[test]
fn normalized_diagnostic_artifact_json_fields() {
    let artifact = NormalizedDiagnosticArtifact {
        schema_version: "v1".to_string(),
        taxonomy_version: "tv1".to_string(),
        adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
        diagnostic_code: "dc".to_string(),
        category: "cat".to_string(),
        severity: "sev".to_string(),
        parse_error_code: None,
        canonical_hash: "h".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "taxonomy_version",
        "adapter",
        "diagnostic_code",
        "category",
        "severity",
        "canonical_hash",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
    // parse_error_code is skip_serializing_if = "Option::is_none"
    assert!(
        !obj.contains_key("parse_error_code"),
        "None field should be skipped"
    );
}

// ===========================================================================
// 33. NormalizedDiagnosticArtifact: parse_error_code Some present
// ===========================================================================

#[test]
fn normalized_diagnostic_artifact_with_parse_error_code() {
    let artifact = NormalizedDiagnosticArtifact {
        schema_version: "v1".to_string(),
        taxonomy_version: "tv1".to_string(),
        adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
        diagnostic_code: "dc".to_string(),
        category: "cat".to_string(),
        severity: "sev".to_string(),
        parse_error_code: Some("E042".to_string()),
        canonical_hash: "h".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("parse_error_code"));
    assert_eq!(obj["parse_error_code"], "E042");
}

// ===========================================================================
// 34. EngineOutcomeKind: Debug distinctness
// ===========================================================================

#[test]
fn engine_outcome_kind_debug_distinct() {
    let debugs: BTreeSet<_> = [EngineOutcomeKind::Hash, EngineOutcomeKind::Error]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 2);
}

// ===========================================================================
// 35. MultiEngineHarnessError: Display all 11 variants
// ===========================================================================

#[test]
fn error_display_io() {
    let e = MultiEngineHarnessError::Io {
        path: "/tmp/test.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let s = e.to_string();
    assert!(s.contains("/tmp/test.json"));
    assert!(s.contains("not found"));
}

#[test]
fn error_display_decode_catalog() {
    let e = MultiEngineHarnessError::DecodeCatalog("bad json".to_string());
    assert_eq!(
        e.to_string(),
        "failed to decode multi-engine fixture catalog: bad json"
    );
}

#[test]
fn error_display_invalid_catalog_schema() {
    let e = MultiEngineHarnessError::InvalidCatalogSchema {
        expected: "v1".to_string(),
        actual: "v2".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "invalid multi-engine catalog schema `v2` (expected `v1`)"
    );
}

#[test]
fn error_display_invalid_catalog_parser_mode() {
    let e = MultiEngineHarnessError::InvalidCatalogParserMode {
        expected: "scalar_reference".to_string(),
        actual: "tree_sitter".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "invalid multi-engine catalog parser_mode `tree_sitter` (expected `scalar_reference`)"
    );
}

#[test]
fn error_display_empty_fixture_catalog() {
    let e = MultiEngineHarnessError::EmptyFixtureCatalog;
    assert_eq!(
        e.to_string(),
        "multi-engine fixture catalog must not be empty"
    );
}

#[test]
fn error_display_duplicate_fixture_id() {
    let e = MultiEngineHarnessError::DuplicateFixtureId {
        fixture_id: "fix-42".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "multi-engine fixture id `fix-42` appears more than once"
    );
}

#[test]
fn error_display_unknown_goal() {
    let e = MultiEngineHarnessError::UnknownGoal {
        fixture_id: "fix-1".to_string(),
        goal: "jsx".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "fixture `fix-1` has unknown parse goal `jsx`"
    );
}

#[test]
fn error_display_fixture_filter_not_found() {
    let e = MultiEngineHarnessError::FixtureFilterNotFound {
        fixture_id: "missing".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "fixture filter `missing` did not match any fixture"
    );
}

#[test]
fn error_display_invalid_config() {
    let e = MultiEngineHarnessError::InvalidConfig("bad config".to_string());
    assert_eq!(
        e.to_string(),
        "invalid multi-engine harness config: bad config"
    );
}

#[test]
fn error_display_external_engine() {
    let e = MultiEngineHarnessError::ExternalEngine {
        engine_id: "ext-1".to_string(),
        detail: "timeout".to_string(),
    };
    assert_eq!(e.to_string(), "external engine `ext-1` failed: timeout");
}

#[test]
fn error_display_normalization() {
    let e = MultiEngineHarnessError::Normalization {
        engine_id: "ext-2".to_string(),
        detail: "invalid hash".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "normalization adapter for engine `ext-2` failed: invalid hash"
    );
}

// ===========================================================================
// 36. MultiEngineHarnessError: std::error::Error for all variants
// ===========================================================================

#[test]
fn error_std_error_all_variants() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(MultiEngineHarnessError::Io {
            path: "p".to_string(),
            source: std::io::Error::other("e"),
        }),
        Box::new(MultiEngineHarnessError::DecodeCatalog("d".to_string())),
        Box::new(MultiEngineHarnessError::InvalidCatalogSchema {
            expected: "e".to_string(),
            actual: "a".to_string(),
        }),
        Box::new(MultiEngineHarnessError::InvalidCatalogParserMode {
            expected: "e".to_string(),
            actual: "a".to_string(),
        }),
        Box::new(MultiEngineHarnessError::EmptyFixtureCatalog),
        Box::new(MultiEngineHarnessError::DuplicateFixtureId {
            fixture_id: "f".to_string(),
        }),
        Box::new(MultiEngineHarnessError::UnknownGoal {
            fixture_id: "f".to_string(),
            goal: "g".to_string(),
        }),
        Box::new(MultiEngineHarnessError::FixtureFilterNotFound {
            fixture_id: "f".to_string(),
        }),
        Box::new(MultiEngineHarnessError::InvalidConfig("c".to_string())),
        Box::new(MultiEngineHarnessError::ExternalEngine {
            engine_id: "e".to_string(),
            detail: "d".to_string(),
        }),
        Box::new(MultiEngineHarnessError::Normalization {
            engine_id: "e".to_string(),
            detail: "d".to_string(),
        }),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(
        displays.len(),
        11,
        "all 11 Display messages must be distinct"
    );
}

// ===========================================================================
// 37. Config validation: empty trace_id
// ===========================================================================

#[test]
fn config_validation_empty_trace_id() {
    let mut config = test_config(1);
    config.trace_id = "  ".to_string();
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("trace_id")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 38. Config validation: empty decision_id
// ===========================================================================

#[test]
fn config_validation_empty_decision_id() {
    let mut config = test_config(1);
    config.decision_id = "".to_string();
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("decision_id")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 39. Config validation: empty policy_id
// ===========================================================================

#[test]
fn config_validation_empty_policy_id() {
    let mut config = test_config(1);
    config.policy_id = "".to_string();
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("policy_id")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 40. Config validation: fewer than 2 engines
// ===========================================================================

#[test]
fn config_validation_too_few_engines() {
    let mut config = test_config(1);
    config.engines = vec![HarnessEngineSpec::franken_canonical("v1")];
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("two engine")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 41. Config validation: empty engine_id
// ===========================================================================

#[test]
fn config_validation_empty_engine_id() {
    let mut config = test_config(1);
    config.engines[0].engine_id = "".to_string();
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("engine_id")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 42. Config validation: duplicate engine IDs
// ===========================================================================

#[test]
fn config_validation_duplicate_engine_ids() {
    let mut config = test_config(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("v1"),
        HarnessEngineSpec::franken_canonical("v2"),
    ];
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("appears more than once")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 43. Config validation: empty version_pin
// ===========================================================================

#[test]
fn config_validation_empty_version_pin() {
    let mut config = test_config(1);
    config.engines[0].version_pin = "  ".to_string();
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("version_pin")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 44. Config validation: external engine without command
// ===========================================================================

#[test]
fn config_validation_external_no_command() {
    let mut config = test_config(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("v1"),
        HarnessEngineSpec {
            engine_id: "ext".to_string(),
            display_name: "External".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "v1".to_string(),
            command: None,
            args: vec![],
        },
    ];
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::InvalidConfig(ref msg) if msg.contains("requires command")),
        "unexpected error: {err}"
    );
}

// ===========================================================================
// 45. Successful run: report schema version
// ===========================================================================

#[test]
fn successful_run_report_schema() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    assert_eq!(
        report.schema_version,
        "franken-engine.parser-multi-engine.report.v2"
    );
}

// ===========================================================================
// 46. Successful run: report JSON field names
// ===========================================================================

#[test]
fn successful_run_report_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "generated_at_utc",
        "run_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "fixture_catalog_path",
        "fixture_catalog_hash",
        "parser_mode",
        "seed",
        "locale",
        "timezone",
        "fixture_count",
        "engine_specs",
        "parser_telemetry",
        "summary",
        "fixture_results",
    ] {
        assert!(obj.contains_key(key), "report missing field {key}");
    }
}

// ===========================================================================
// 47. Successful run: summary JSON field names
// ===========================================================================

#[test]
fn successful_run_summary_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let json = serde_json::to_string(&report.summary).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "total_fixtures",
        "equivalent_fixtures",
        "divergent_fixtures",
        "fixtures_with_nondeterminism",
        "drift_minor_fixtures",
        "drift_critical_fixtures",
        "drift_counts_by_category",
    ] {
        assert!(obj.contains_key(key), "summary missing field {key}");
    }
}

// ===========================================================================
// 48. Successful run: telemetry JSON field names
// ===========================================================================

#[test]
fn successful_run_telemetry_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let json = serde_json::to_string(&report.parser_telemetry).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "sample_count",
        "throughput_sources_per_second_millionths",
        "throughput_mib_per_second_millionths",
        "latency_ns_p50",
        "latency_ns_p95",
        "latency_ns_p99",
        "ns_per_token_millionths",
        "allocs_per_token_millionths",
        "bytes_per_source_avg",
        "tokens_per_source_avg",
        "peak_rss_bytes",
    ] {
        assert!(obj.contains_key(key), "telemetry missing field {key}");
    }
}

// ===========================================================================
// 49. Successful run: fixture_count matches
// ===========================================================================

#[test]
fn successful_run_fixture_count() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    assert_eq!(report.fixture_count, report.fixture_results.len() as u64);
    assert_eq!(
        report.summary.total_fixtures,
        report.fixture_results.len() as u64
    );
}

// ===========================================================================
// 50. Successful run: fixture result JSON field names
// ===========================================================================

#[test]
fn successful_run_fixture_result_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let fixture = &report.fixture_results[0];
    let json = serde_json::to_string(fixture).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "fixture_id",
        "family_id",
        "goal",
        "source_hash",
        "equivalent_across_engines",
        "nondeterministic_engine_count",
        "replay_command",
        "engine_results",
    ] {
        assert!(obj.contains_key(key), "fixture missing field {key}");
    }
}

// ===========================================================================
// 51. Successful run: engine result JSON field names
// ===========================================================================

#[test]
fn successful_run_engine_result_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let engine = &report.fixture_results[0].engine_results[0];
    let json = serde_json::to_string(engine).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "engine_id",
        "display_name",
        "version_pin",
        "derived_seed",
        "first_run",
        "second_run",
    ] {
        assert!(obj.contains_key(key), "engine result missing field {key}");
    }
}

// ===========================================================================
// 52. Successful run: run outcome JSON field names
// ===========================================================================

#[test]
fn successful_run_outcome_json_fields() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let run = &report.fixture_results[0].engine_results[0].first_run;
    let json = serde_json::to_string(run).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["kind", "value", "deterministic", "duration_us"] {
        assert!(obj.contains_key(key), "run outcome missing field {key}");
    }
}

// ===========================================================================
// 53. Successful run: telemetry sample_count = 2×fixtures (2 runs per fixture)
// ===========================================================================

#[test]
fn successful_run_telemetry_sample_count() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    // Only FrankenCanonical engine contributes telemetry samples (2 runs each)
    assert_eq!(
        report.parser_telemetry.sample_count,
        report.fixture_count * 2
    );
}

// ===========================================================================
// 54. Successful run: report preserves config fields
// ===========================================================================

#[test]
fn successful_run_preserves_config() {
    let config = test_config(77);
    let report = run_multi_engine_harness(&config).unwrap();
    assert_eq!(report.seed, 77);
    assert_eq!(report.trace_id, "trace-enrichment");
    assert_eq!(report.decision_id, "decision-enrichment");
    assert_eq!(report.policy_id, "policy-enrichment-v1");
    assert_eq!(report.locale, "C");
    assert_eq!(report.timezone, "UTC");
}

// ===========================================================================
// 55. Successful run: run_id is deterministic for same seed
// ===========================================================================

#[test]
fn successful_run_deterministic_run_id() {
    let config = test_config(42);
    let r1 = run_multi_engine_harness(&config).unwrap();
    let r2 = run_multi_engine_harness(&config).unwrap();
    assert_eq!(r1.run_id, r2.run_id);
    assert!(r1.run_id.starts_with("sha256:"));
}

// ===========================================================================
// 56. Successful run: parser mode in report
// ===========================================================================

#[test]
fn successful_run_parser_mode() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    assert_eq!(report.parser_mode, "scalar_reference");
}

// ===========================================================================
// 57. Successful run: telemetry latency ordering
// ===========================================================================

#[test]
fn successful_run_telemetry_latency_ordering() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let t = &report.parser_telemetry;
    assert!(t.latency_ns_p50 <= t.latency_ns_p95);
    assert!(t.latency_ns_p95 <= t.latency_ns_p99);
}

// ===========================================================================
// 58. Successful run: equivalent_fixtures + divergent = total
// ===========================================================================

#[test]
fn successful_run_summary_arithmetic() {
    let config = test_config(99);
    let report = run_multi_engine_harness(&config).unwrap();
    let s = &report.summary;
    assert_eq!(
        s.equivalent_fixtures + s.divergent_fixtures,
        s.total_fixtures
    );
}

// ===========================================================================
// 59. EngineOutcomeKind: serde snake_case
// ===========================================================================

#[test]
fn engine_outcome_kind_serde_snake_case() {
    let json = serde_json::to_string(&EngineOutcomeKind::Hash).unwrap();
    assert_eq!(json, "\"hash\"");
    let json = serde_json::to_string(&EngineOutcomeKind::Error).unwrap();
    assert_eq!(json, "\"error\"");
}

// ===========================================================================
// 60. Fixture filter: nonexistent ID
// ===========================================================================

#[test]
fn fixture_filter_nonexistent() {
    let mut config = test_config(1);
    config.fixture_id_filter = Some("does-not-exist-xyz".to_string());
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(matches!(
        err,
        MultiEngineHarnessError::FixtureFilterNotFound { ref fixture_id }
        if fixture_id == "does-not-exist-xyz"
    ));
}

// ===========================================================================
// 61. Catalog path: nonexistent file
// ===========================================================================

#[test]
fn nonexistent_catalog_path() {
    let mut config = test_config(1);
    config.fixture_catalog_path = PathBuf::from("/tmp/nonexistent-catalog-file.json");
    let err = run_multi_engine_harness(&config).unwrap_err();
    assert!(
        matches!(err, MultiEngineHarnessError::Io { .. }),
        "expected Io error, got: {err}"
    );
}

// ===========================================================================
// 62. DriftClassification: remediation_hint for Semantic
// ===========================================================================

#[test]
fn drift_remediation_hint_semantic() {
    let dc = make_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
    assert!(dc.remediation_hint.contains("replay fixture"));
    assert!(dc.remediation_hint.contains("normalized AST hashes"));
}

// ===========================================================================
// 63. DriftClassification: remediation_hint for Diagnostics
// ===========================================================================

#[test]
fn drift_remediation_hint_diagnostics() {
    let dc = make_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor);
    assert!(dc.remediation_hint.contains("diagnostic codes"));
    assert!(dc.remediation_hint.contains("alias mappings"));
}

// ===========================================================================
// 64. DriftClassification: remediation_hint for Harness
// ===========================================================================

#[test]
fn drift_remediation_hint_harness() {
    let dc = make_drift_classification(DriftCategory::Harness, DriftSeverity::Critical);
    assert!(dc.remediation_hint.contains("fixed seed"));
    assert!(dc.remediation_hint.contains("nondeterminism"));
}

// ===========================================================================
// 65. DriftClassification: remediation_hint for Artifact
// ===========================================================================

#[test]
fn drift_remediation_hint_artifact() {
    let dc = make_drift_classification(DriftCategory::Artifact, DriftSeverity::Critical);
    assert!(dc.remediation_hint.contains("artifact shape"));
    assert!(dc.remediation_hint.contains("schema compatibility"));
}
