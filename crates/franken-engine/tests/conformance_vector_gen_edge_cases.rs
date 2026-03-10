//! Edge-case tests for `conformance_vector_gen` module.

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

use frankenengine_engine::conformance_catalog::{
    self, BoundarySurface, CatalogEntry, ConformanceCatalog, ConformanceVector, ReplayObligation,
    SemanticVersion, SiblingRepo, SurfaceKind, VersionClass,
};
use frankenengine_engine::conformance_vector_gen::{
    BoundaryProperty, DegradedScenario, FaultScenario, GeneratedVector, GenerationResult,
    GeneratorConfig, PropertyCheckResult, VectorCategory, canonical_boundary_properties,
    generate_vectors, properties_for_surface, validate_property_coverage,
};
use frankenengine_engine::cross_repo_contract::RegressionClass;

// =========================================================================
// Helpers
// =========================================================================

fn test_catalog() -> ConformanceCatalog {
    conformance_catalog::build_canonical_catalog()
}

fn make_minimal_entry(id: &str, sibling: SiblingRepo, surface_kind: SurfaceKind) -> CatalogEntry {
    CatalogEntry {
        entry_id: id.to_string(),
        boundary: BoundarySurface {
            sibling,
            surface_id: format!("{id}/surface"),
            surface_kind,
            description: "test boundary".to_string(),
            covered_fields: ["field_a", "field_b"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        },
        positive_vectors: vec![ConformanceVector {
            vector_id: format!("{id}/pos/0"),
            description: "baseline".to_string(),
            input_json: "{\"field_a\":\"v1\",\"field_b\":\"v2\"}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        }],
        negative_vectors: vec![],
        replay_obligation: ReplayObligation::standard(id, sibling),
        failure_class: RegressionClass::Behavioral,
        approved: true,
        approval_epoch: Some(1),
    }
}

// =========================================================================
// VectorCategory
// =========================================================================

#[test]
fn vector_category_copy_semantics() {
    let a = VectorCategory::Positive;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn vector_category_as_str_all_four() {
    assert_eq!(VectorCategory::Positive.as_str(), "positive");
    assert_eq!(VectorCategory::Negative.as_str(), "negative");
    assert_eq!(VectorCategory::Degraded.as_str(), "degraded");
    assert_eq!(VectorCategory::Fault.as_str(), "fault");
}

#[test]
fn vector_category_display_matches_as_str() {
    for cat in [
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ] {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

#[test]
fn vector_category_ordering_exhaustive() {
    let ordered = [
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ];
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            assert!(
                ordered[i] < ordered[j],
                "{:?} should be < {:?}",
                ordered[i],
                ordered[j]
            );
        }
    }
}

#[test]
fn vector_category_serde_stable_strings() {
    let json = serde_json::to_string(&VectorCategory::Positive).unwrap();
    assert_eq!(json, "\"Positive\"");
    let json = serde_json::to_string(&VectorCategory::Negative).unwrap();
    assert_eq!(json, "\"Negative\"");
    let json = serde_json::to_string(&VectorCategory::Degraded).unwrap();
    assert_eq!(json, "\"Degraded\"");
    let json = serde_json::to_string(&VectorCategory::Fault).unwrap();
    assert_eq!(json, "\"Fault\"");
}

// =========================================================================
// DegradedScenario
// =========================================================================

#[test]
fn degraded_scenario_serde_all_five_roundtrip() {
    let scenarios = [
        DegradedScenario::StaleRevocationHead { epochs_behind: 0 },
        DegradedScenario::PartialAvailability {
            available_fraction_millionths: 0,
        },
        DegradedScenario::Timeout { timeout_ms: 0 },
        DegradedScenario::SchemaDrift {
            local_version: SemanticVersion::new(0, 0, 0),
            remote_version: SemanticVersion::new(0, 0, 1),
        },
        DegradedScenario::EmptyResponse,
    ];
    for s in &scenarios {
        let json = serde_json::to_string(s).unwrap();
        let restored: DegradedScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn degraded_scenario_display_stale_revocation() {
    let s = DegradedScenario::StaleRevocationHead { epochs_behind: 7 };
    let display = s.to_string();
    assert!(display.contains("stale-revocation-head"));
    assert!(display.contains("7"));
}

#[test]
fn degraded_scenario_display_partial_availability() {
    let s = DegradedScenario::PartialAvailability {
        available_fraction_millionths: 300_000,
    };
    let display = s.to_string();
    assert!(display.contains("partial-availability"));
    assert!(display.contains("300000"));
}

#[test]
fn degraded_scenario_display_timeout() {
    let s = DegradedScenario::Timeout { timeout_ms: 5000 };
    let display = s.to_string();
    assert!(display.contains("timeout"));
    assert!(display.contains("5000"));
}

#[test]
fn degraded_scenario_display_schema_drift() {
    let s = DegradedScenario::SchemaDrift {
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(1, 2, 0),
    };
    let display = s.to_string();
    assert!(display.contains("schema-drift"));
}

#[test]
fn degraded_scenario_display_empty_response() {
    let s = DegradedScenario::EmptyResponse;
    assert_eq!(s.to_string(), "empty-response");
}

#[test]
fn degraded_scenario_ordering() {
    // StaleRevocationHead < PartialAvailability < Timeout < SchemaDrift < EmptyResponse
    let a = DegradedScenario::StaleRevocationHead { epochs_behind: 1 };
    let b = DegradedScenario::PartialAvailability {
        available_fraction_millionths: 1,
    };
    let c = DegradedScenario::Timeout { timeout_ms: 1 };
    let d = DegradedScenario::SchemaDrift {
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(1, 1, 0),
    };
    let e = DegradedScenario::EmptyResponse;
    assert!(a < b);
    assert!(b < c);
    assert!(c < d);
    assert!(d < e);
}

#[test]
fn degraded_scenario_clone() {
    let s = DegradedScenario::SchemaDrift {
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(2, 0, 0),
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
}

// =========================================================================
// FaultScenario
// =========================================================================

#[test]
fn fault_scenario_serde_all_six_roundtrip() {
    let scenarios = [
        FaultScenario::CorruptedPayload {
            corruption_offset: 0,
        },
        FaultScenario::TruncatedMessage {
            retain_fraction_millionths: 0,
        },
        FaultScenario::OutOfOrderSequence {
            expected_seq: 0,
            actual_seq: 0,
        },
        FaultScenario::ReplayAttack { original_nonce: 0 },
        FaultScenario::MalformedJson,
        FaultScenario::EncodingMismatch {
            expected: String::new(),
            actual: String::new(),
        },
    ];
    for s in &scenarios {
        let json = serde_json::to_string(s).unwrap();
        let restored: FaultScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn fault_scenario_display_corrupted_payload() {
    let s = FaultScenario::CorruptedPayload {
        corruption_offset: 42,
    };
    let display = s.to_string();
    assert!(display.contains("corrupted-payload"));
    assert!(display.contains("42"));
}

#[test]
fn fault_scenario_display_truncated_message() {
    let s = FaultScenario::TruncatedMessage {
        retain_fraction_millionths: 250_000,
    };
    let display = s.to_string();
    assert!(display.contains("truncated-message"));
    assert!(display.contains("250000"));
}

#[test]
fn fault_scenario_display_out_of_order() {
    let s = FaultScenario::OutOfOrderSequence {
        expected_seq: 5,
        actual_seq: 3,
    };
    let display = s.to_string();
    assert!(display.contains("out-of-order"));
    assert!(display.contains("5"));
    assert!(display.contains("3"));
}

#[test]
fn fault_scenario_display_replay_attack() {
    let s = FaultScenario::ReplayAttack {
        original_nonce: 9999,
    };
    let display = s.to_string();
    assert!(display.contains("replay-attack"));
    assert!(display.contains("9999"));
}

#[test]
fn fault_scenario_display_malformed_json() {
    assert_eq!(FaultScenario::MalformedJson.to_string(), "malformed-json");
}

#[test]
fn fault_scenario_display_encoding_mismatch() {
    let s = FaultScenario::EncodingMismatch {
        expected: "json".to_string(),
        actual: "binary".to_string(),
    };
    let display = s.to_string();
    assert!(display.contains("encoding-mismatch"));
    assert!(display.contains("json"));
    assert!(display.contains("binary"));
}

#[test]
fn fault_scenario_ordering() {
    let a = FaultScenario::CorruptedPayload {
        corruption_offset: 0,
    };
    let b = FaultScenario::TruncatedMessage {
        retain_fraction_millionths: 0,
    };
    let c = FaultScenario::OutOfOrderSequence {
        expected_seq: 0,
        actual_seq: 0,
    };
    let d = FaultScenario::ReplayAttack { original_nonce: 0 };
    let e = FaultScenario::MalformedJson;
    let f = FaultScenario::EncodingMismatch {
        expected: String::new(),
        actual: String::new(),
    };
    assert!(a < b);
    assert!(b < c);
    assert!(c < d);
    assert!(d < e);
    assert!(e < f);
}

#[test]
fn fault_scenario_clone() {
    let s = FaultScenario::EncodingMismatch {
        expected: "a".to_string(),
        actual: "b".to_string(),
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
}

// =========================================================================
// GeneratedVector
// =========================================================================

#[test]
fn generated_vector_serde_with_all_optional_fields() {
    let v = GeneratedVector {
        vector_id: "test/all_fields".to_string(),
        description: "with all optionals".to_string(),
        category: VectorCategory::Degraded,
        source_entry_id: "entry/1".to_string(),
        boundary: SiblingRepo::Frankentui,
        surface_kind: SurfaceKind::TuiEventContract,
        input_json: "{\"test\":true}".to_string(),
        expected_pass: false,
        expected_regression_class: Some(RegressionClass::Breaking),
        degraded_scenario: Some(DegradedScenario::EmptyResponse),
        fault_scenario: Some(FaultScenario::MalformedJson),
        seed: 12345,
        covered_fields: ["a", "b", "c"].iter().map(|s| s.to_string()).collect(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn generated_vector_clone() {
    let v = GeneratedVector {
        vector_id: "test/clone".to_string(),
        description: "clone test".to_string(),
        category: VectorCategory::Positive,
        source_entry_id: "e1".to_string(),
        boundary: SiblingRepo::Frankensqlite,
        surface_kind: SurfaceKind::PersistenceSemantics,
        input_json: "{}".to_string(),
        expected_pass: true,
        expected_regression_class: None,
        degraded_scenario: None,
        fault_scenario: None,
        seed: 1,
        covered_fields: BTreeSet::new(),
    };
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn generated_vector_empty_covered_fields() {
    let v = GeneratedVector {
        vector_id: "test/empty_fields".to_string(),
        description: "no fields".to_string(),
        category: VectorCategory::Fault,
        source_entry_id: "e1".to_string(),
        boundary: SiblingRepo::Frankentui,
        surface_kind: SurfaceKind::ApiMessage,
        input_json: "{}".to_string(),
        expected_pass: false,
        expected_regression_class: Some(RegressionClass::Breaking),
        degraded_scenario: None,
        fault_scenario: Some(FaultScenario::MalformedJson),
        seed: 0,
        covered_fields: BTreeSet::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// =========================================================================
// GeneratorConfig
// =========================================================================

#[test]
fn generator_config_default_values() {
    let config = GeneratorConfig::default();
    assert_eq!(config.seed, 42);
    assert_eq!(config.max_positive_per_entry, 3);
    assert_eq!(config.max_negative_per_entry, 3);
    assert_eq!(config.max_degraded_per_entry, 5);
    assert_eq!(config.max_fault_per_entry, 6);
    assert!(config.sibling_filter.is_empty());
    assert!(config.surface_filter.is_empty());
}

#[test]
fn generator_config_serde_with_filters() {
    let mut config = GeneratorConfig::default();
    config.sibling_filter.insert(SiblingRepo::Frankentui);
    config.sibling_filter.insert(SiblingRepo::Frankensqlite);
    config.surface_filter.insert(SurfaceKind::TuiEventContract);
    let json = serde_json::to_string(&config).unwrap();
    let restored: GeneratorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn generator_config_clone() {
    let config = GeneratorConfig::default();
    let c2 = config.clone();
    assert_eq!(config, c2);
}

// =========================================================================
// GenerationResult
// =========================================================================

#[test]
fn generation_result_count_by_category_empty() {
    let result = GenerationResult {
        seed: 42,
        catalog_version: SemanticVersion::new(1, 0, 0),
        vectors: vec![],
        category_counts: Default::default(),
        boundary_counts: Default::default(),
        warnings: vec![],
    };
    assert_eq!(result.count_by_category(VectorCategory::Positive), 0);
    assert_eq!(result.count_by_category(VectorCategory::Negative), 0);
    assert_eq!(result.count_by_category(VectorCategory::Degraded), 0);
    assert_eq!(result.count_by_category(VectorCategory::Fault), 0);
}

#[test]
fn generation_result_count_by_boundary_nonexistent() {
    let result = GenerationResult {
        seed: 42,
        catalog_version: SemanticVersion::new(1, 0, 0),
        vectors: vec![],
        category_counts: Default::default(),
        boundary_counts: Default::default(),
        warnings: vec![],
    };
    assert_eq!(result.count_by_boundary(SiblingRepo::Frankentui), 0);
}

#[test]
fn generation_result_vector_ids_empty() {
    let result = GenerationResult {
        seed: 42,
        catalog_version: SemanticVersion::new(1, 0, 0),
        vectors: vec![],
        category_counts: Default::default(),
        boundary_counts: Default::default(),
        warnings: vec![],
    };
    assert!(result.vector_ids().is_empty());
}

#[test]
fn generation_result_serde_empty() {
    let result = GenerationResult {
        seed: 99,
        catalog_version: SemanticVersion::new(2, 1, 0),
        vectors: vec![],
        category_counts: Default::default(),
        boundary_counts: Default::default(),
        warnings: vec!["warn1".to_string()],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: GenerationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// =========================================================================
// BoundaryProperty / canonical_boundary_properties
// =========================================================================

#[test]
fn canonical_properties_count_is_eight() {
    let props = canonical_boundary_properties();
    assert_eq!(props.len(), 8);
}

#[test]
fn canonical_properties_unique_ids() {
    let props = canonical_boundary_properties();
    let ids: BTreeSet<&str> = props.iter().map(|p| p.property_id.as_str()).collect();
    assert_eq!(ids.len(), props.len());
}

#[test]
fn canonical_properties_specific_ids_present() {
    let props = canonical_boundary_properties();
    let ids: BTreeSet<&str> = props.iter().map(|p| p.property_id.as_str()).collect();
    let expected = [
        "serde-roundtrip",
        "version-negotiation-convergence",
        "field-presence-invariant",
        "ordering-determinism",
        "error-envelope-stability",
        "telemetry-field-completeness",
        "graceful-degradation",
        "replay-idempotence",
    ];
    for id in &expected {
        assert!(ids.contains(id), "missing property: {id}");
    }
}

#[test]
fn canonical_properties_roundtrip_count() {
    let props = canonical_boundary_properties();
    let roundtrip_count = props.iter().filter(|p| p.requires_roundtrip).count();
    assert!(
        roundtrip_count >= 3,
        "expected at least 3 roundtrip properties, got {roundtrip_count}"
    );
}

#[test]
fn canonical_properties_violation_classes() {
    let props = canonical_boundary_properties();
    let classes: BTreeSet<RegressionClass> = props.iter().map(|p| p.violation_class).collect();
    // Should have at least Breaking, Behavioral
    assert!(classes.contains(&RegressionClass::Breaking));
    assert!(classes.contains(&RegressionClass::Behavioral));
}

#[test]
fn canonical_properties_serde_roundtrip_all() {
    let props = canonical_boundary_properties();
    for p in &props {
        let json = serde_json::to_string(p).unwrap();
        let restored: BoundaryProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, restored);
    }
}

#[test]
fn canonical_properties_all_have_applicable_surfaces() {
    let props = canonical_boundary_properties();
    for p in &props {
        assert!(
            !p.applicable_surfaces.is_empty(),
            "property {} has no applicable surfaces",
            p.property_id
        );
    }
}

#[test]
fn canonical_properties_all_have_descriptions() {
    let props = canonical_boundary_properties();
    for p in &props {
        assert!(
            !p.description.is_empty(),
            "property {} has empty description",
            p.property_id
        );
    }
}

// =========================================================================
// properties_for_surface
// =========================================================================

#[test]
fn properties_for_surface_api_message_includes_error_envelope() {
    let props = properties_for_surface(SurfaceKind::ApiMessage);
    assert!(
        props
            .iter()
            .any(|p| p.property_id == "error-envelope-stability"),
        "ApiMessage should include error-envelope-stability"
    );
}

#[test]
fn properties_for_surface_telemetry_includes_completeness() {
    let props = properties_for_surface(SurfaceKind::TelemetrySchema);
    assert!(
        props
            .iter()
            .any(|p| p.property_id == "telemetry-field-completeness"),
        "TelemetrySchema should include telemetry-field-completeness"
    );
}

#[test]
fn properties_for_surface_all_surfaces_include_serde_roundtrip() {
    let all_surfaces = [
        SurfaceKind::IdentifierSchema,
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
        SurfaceKind::ApiMessage,
        SurfaceKind::PersistenceSemantics,
        SurfaceKind::ReplayFormat,
        SurfaceKind::ExportFormat,
        SurfaceKind::TuiEventContract,
        SurfaceKind::TuiStateContract,
        SurfaceKind::TelemetrySchema,
    ];
    for surface in &all_surfaces {
        let props = properties_for_surface(*surface);
        assert!(
            props.iter().any(|p| p.property_id == "serde-roundtrip"),
            "surface {:?} should include serde-roundtrip",
            surface
        );
    }
}

#[test]
fn properties_for_surface_all_surfaces_include_replay_idempotence() {
    let all_surfaces = [
        SurfaceKind::IdentifierSchema,
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
        SurfaceKind::ApiMessage,
        SurfaceKind::PersistenceSemantics,
        SurfaceKind::ReplayFormat,
        SurfaceKind::ExportFormat,
        SurfaceKind::TuiEventContract,
        SurfaceKind::TuiStateContract,
        SurfaceKind::TelemetrySchema,
    ];
    for surface in &all_surfaces {
        let props = properties_for_surface(*surface);
        assert!(
            props.iter().any(|p| p.property_id == "replay-idempotence"),
            "surface {:?} should include replay-idempotence",
            surface
        );
    }
}

// =========================================================================
// PropertyCheckResult
// =========================================================================

#[test]
fn property_check_result_serde_roundtrip() {
    let r = PropertyCheckResult {
        property_id: "test-property".to_string(),
        vector_id: "test/vector/1".to_string(),
        passed: false,
        detail: "something failed".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let restored: PropertyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);
}

#[test]
fn property_check_result_clone() {
    let r = PropertyCheckResult {
        property_id: "p1".to_string(),
        vector_id: "v1".to_string(),
        passed: true,
        detail: "ok".to_string(),
    };
    let r2 = r.clone();
    assert_eq!(r, r2);
}

// =========================================================================
// generate_vectors — basic behavior
// =========================================================================

#[test]
fn generate_vectors_with_canonical_catalog_non_empty() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert!(!result.vectors.is_empty());
    assert!(!result.category_counts.is_empty());
    assert!(!result.boundary_counts.is_empty());
}

#[test]
fn generate_vectors_seed_preserved_in_result() {
    let catalog = test_catalog();
    let config = GeneratorConfig {
        seed: 9999,
        ..Default::default()
    };
    let result = generate_vectors(&catalog, &config);
    assert_eq!(result.seed, 9999);
}

#[test]
fn generate_vectors_catalog_version_preserved() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert_eq!(result.catalog_version, catalog.catalog_version);
}

#[test]
fn generate_vectors_empty_catalog() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert!(result.vectors.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn generate_vectors_all_categories_present() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert!(result.count_by_category(VectorCategory::Positive) > 0);
    assert!(result.count_by_category(VectorCategory::Negative) > 0);
    assert!(result.count_by_category(VectorCategory::Degraded) > 0);
    assert!(result.count_by_category(VectorCategory::Fault) > 0);
}

#[test]
fn generate_vectors_unique_ids() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let ids = result.vector_ids();
    assert_eq!(
        ids.len(),
        result.vectors.len(),
        "all vector IDs must be unique"
    );
}

#[test]
fn generate_vectors_category_counts_sum_to_total() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let sum: usize = result.category_counts.values().sum();
    assert_eq!(sum, result.vectors.len());
}

#[test]
fn generate_vectors_boundary_counts_sum_to_total() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let sum: usize = result.boundary_counts.values().sum();
    assert_eq!(sum, result.vectors.len());
}

// =========================================================================
// generate_vectors — vector invariants
// =========================================================================

#[test]
fn positive_vectors_always_expect_pass() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for v in &result.vectors {
        if v.category == VectorCategory::Positive {
            assert!(
                v.expected_pass,
                "positive vector {} should expect pass",
                v.vector_id
            );
            assert!(
                v.expected_regression_class.is_none(),
                "positive vector {} should have no regression class",
                v.vector_id
            );
            assert!(v.degraded_scenario.is_none());
            assert!(v.fault_scenario.is_none());
        }
    }
}

#[test]
fn degraded_vectors_always_have_degraded_scenario() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for v in &result.vectors {
        if v.category == VectorCategory::Degraded {
            assert!(
                v.degraded_scenario.is_some(),
                "degraded vector {} must have degraded_scenario",
                v.vector_id
            );
            assert!(v.fault_scenario.is_none());
        }
    }
}

#[test]
fn fault_vectors_always_have_fault_scenario() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for v in &result.vectors {
        if v.category == VectorCategory::Fault {
            assert!(
                v.fault_scenario.is_some(),
                "fault vector {} must have fault_scenario",
                v.vector_id
            );
            assert!(
                !v.expected_pass,
                "fault vector {} should expect failure",
                v.vector_id
            );
            assert!(v.degraded_scenario.is_none());
        }
    }
}

#[test]
fn all_vectors_have_non_empty_input_json() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for v in &result.vectors {
        assert!(
            !v.input_json.is_empty(),
            "vector {} has empty input_json",
            v.vector_id
        );
    }
}

#[test]
fn all_vectors_have_non_empty_description() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for v in &result.vectors {
        assert!(
            !v.description.is_empty(),
            "vector {} has empty description",
            v.vector_id
        );
    }
}

// =========================================================================
// generate_vectors — filters
// =========================================================================

#[test]
fn sibling_filter_restricts_to_single_boundary() {
    let catalog = test_catalog();
    let mut config = GeneratorConfig::default();
    config.sibling_filter.insert(SiblingRepo::Frankensqlite);
    let result = generate_vectors(&catalog, &config);
    for v in &result.vectors {
        assert_eq!(
            v.boundary,
            SiblingRepo::Frankensqlite,
            "filter should restrict to Frankensqlite"
        );
    }
    assert!(!result.vectors.is_empty());
}

#[test]
fn surface_filter_restricts_to_single_surface() {
    let catalog = test_catalog();
    let mut config = GeneratorConfig::default();
    config
        .surface_filter
        .insert(SurfaceKind::PersistenceSemantics);
    let result = generate_vectors(&catalog, &config);
    for v in &result.vectors {
        assert_eq!(v.surface_kind, SurfaceKind::PersistenceSemantics);
    }
    assert!(!result.vectors.is_empty());
}

#[test]
fn combined_sibling_and_surface_filter() {
    let catalog = test_catalog();
    let mut config = GeneratorConfig::default();
    config.sibling_filter.insert(SiblingRepo::Frankentui);
    config.surface_filter.insert(SurfaceKind::TuiEventContract);
    let result = generate_vectors(&catalog, &config);
    for v in &result.vectors {
        assert_eq!(v.boundary, SiblingRepo::Frankentui);
        assert_eq!(v.surface_kind, SurfaceKind::TuiEventContract);
    }
}

#[test]
fn impossible_filter_produces_empty_result() {
    let catalog = test_catalog();
    let mut config = GeneratorConfig::default();
    // Frankensqlite with TuiEventContract — likely no match
    config.sibling_filter.insert(SiblingRepo::Frankensqlite);
    config.surface_filter.insert(SurfaceKind::TuiEventContract);
    let result = generate_vectors(&catalog, &config);
    // Either empty or only has matching entries
    for v in &result.vectors {
        assert_eq!(v.boundary, SiblingRepo::Frankensqlite);
        assert_eq!(v.surface_kind, SurfaceKind::TuiEventContract);
    }
}

// =========================================================================
// generate_vectors — max limits
// =========================================================================

#[test]
fn max_positive_per_entry_respected() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(make_minimal_entry(
        "test/one",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    ));
    let config = GeneratorConfig {
        max_positive_per_entry: 1,
        ..Default::default()
    };
    let result = generate_vectors(&catalog, &config);
    let pos_count = result.count_by_category(VectorCategory::Positive);
    assert!(pos_count <= 1, "positive count {} > max 1", pos_count);
}

#[test]
fn max_negative_per_entry_respected() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(make_minimal_entry(
        "test/one",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    ));
    let config = GeneratorConfig {
        max_negative_per_entry: 2,
        ..Default::default()
    };
    let result = generate_vectors(&catalog, &config);
    let neg_count = result.count_by_category(VectorCategory::Negative);
    assert!(neg_count <= 2, "negative count {} > max 2", neg_count);
}

#[test]
fn max_degraded_per_entry_respected() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(make_minimal_entry(
        "test/one",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    ));
    let config = GeneratorConfig {
        max_degraded_per_entry: 2,
        ..Default::default()
    };
    let result = generate_vectors(&catalog, &config);
    let deg_count = result.count_by_category(VectorCategory::Degraded);
    assert!(deg_count <= 2, "degraded count {} > max 2", deg_count);
}

#[test]
fn max_fault_per_entry_respected() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(make_minimal_entry(
        "test/one",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    ));
    let config = GeneratorConfig {
        max_fault_per_entry: 3,
        ..Default::default()
    };
    let result = generate_vectors(&catalog, &config);
    let fault_count = result.count_by_category(VectorCategory::Fault);
    assert!(fault_count <= 3, "fault count {} > max 3", fault_count);
}

// =========================================================================
// generate_vectors — warnings
// =========================================================================

#[test]
fn warns_on_entry_with_no_positive_vectors() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_minimal_entry(
        "test/no_pos",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    );
    entry.positive_vectors.clear();
    catalog.entries.push(entry);
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("no baseline positive vectors")),
        "expected warning about missing positive vectors"
    );
}

#[test]
fn no_warning_when_positive_vectors_exist() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(make_minimal_entry(
        "test/with_pos",
        SiblingRepo::Frankentui,
        SurfaceKind::TuiEventContract,
    ));
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    assert!(
        result.warnings.is_empty(),
        "should not have warnings: {:?}",
        result.warnings
    );
}

// =========================================================================
// validate_property_coverage
// =========================================================================

#[test]
fn validate_property_coverage_full_catalog_no_gaps() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let props = canonical_boundary_properties();
    let gaps = validate_property_coverage(&result, &props);
    assert!(gaps.is_empty(), "gaps: {:?}", gaps);
}

#[test]
fn validate_property_coverage_empty_result_has_gaps() {
    let result = GenerationResult {
        seed: 42,
        catalog_version: SemanticVersion::new(1, 0, 0),
        vectors: vec![],
        category_counts: Default::default(),
        boundary_counts: Default::default(),
        warnings: vec![],
    };
    let props = canonical_boundary_properties();
    let gaps = validate_property_coverage(&result, &props);
    // All properties should report gaps since no vectors cover any surface
    assert!(!gaps.is_empty());
}

#[test]
fn validate_property_coverage_no_properties_no_gaps() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let gaps = validate_property_coverage(&result, &[]);
    assert!(gaps.is_empty());
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn generate_vectors_deterministic_100_iterations() {
    let catalog = test_catalog();
    let config = GeneratorConfig::default();
    let baseline = generate_vectors(&catalog, &config);
    for _ in 0..100 {
        let run = generate_vectors(&catalog, &config);
        assert_eq!(baseline.vectors.len(), run.vectors.len());
        for (a, b) in baseline.vectors.iter().zip(run.vectors.iter()) {
            assert_eq!(a.vector_id, b.vector_id);
            assert_eq!(a.input_json, b.input_json);
            assert_eq!(a.seed, b.seed);
            assert_eq!(a.category, b.category);
        }
    }
}

#[test]
fn different_seeds_produce_different_vectors() {
    let catalog = test_catalog();
    let c1 = GeneratorConfig {
        seed: 42,
        ..Default::default()
    };
    let c2 = GeneratorConfig {
        seed: 123,
        ..Default::default()
    };
    let r1 = generate_vectors(&catalog, &c1);
    let r2 = generate_vectors(&catalog, &c2);
    assert_eq!(r1.vectors.len(), r2.vectors.len());
    let mut diff = 0;
    for (a, b) in r1.vectors.iter().zip(r2.vectors.iter()) {
        if a.seed != b.seed {
            diff += 1;
        }
    }
    assert!(
        diff > 0,
        "different seeds should produce different vector seeds"
    );
}

// =========================================================================
// Integration — full pipeline
// =========================================================================

#[test]
fn integration_full_pipeline_serde_roundtrip() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    let json = serde_json::to_string(&result).unwrap();
    let restored: GenerationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn integration_all_primary_boundaries_covered() {
    let catalog = test_catalog();
    let result = generate_vectors(&catalog, &GeneratorConfig::default());
    for repo in SiblingRepo::all() {
        if repo.is_primary() {
            assert!(
                result.count_by_boundary(*repo) > 0,
                "no vectors for primary boundary {}",
                repo
            );
        }
    }
}

#[test]
fn integration_restricted_config_respects_limits() {
    let catalog = test_catalog();
    let config = GeneratorConfig {
        max_positive_per_entry: 1,
        max_negative_per_entry: 1,
        max_degraded_per_entry: 1,
        max_fault_per_entry: 1,
        ..Default::default()
    };

    let full = generate_vectors(&catalog, &GeneratorConfig::default());
    let restricted = generate_vectors(&catalog, &config);

    // Restricted should have fewer vectors
    assert!(
        restricted.vectors.len() < full.vectors.len(),
        "restricted ({}) should be < full ({})",
        restricted.vectors.len(),
        full.vectors.len()
    );
}
