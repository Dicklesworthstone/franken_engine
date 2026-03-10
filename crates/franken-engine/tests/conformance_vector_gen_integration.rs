#![forbid(unsafe_code)]

//! Integration tests for the `conformance_vector_gen` module.
//!
//! Covers: VectorCategory, DegradedScenario, FaultScenario, GeneratedVector,
//! GeneratorConfig, GenerationResult, BoundaryProperty, PropertyCheckResult,
//! canonical_boundary_properties, properties_for_surface, generate_vectors,
//! validate_property_coverage -- plus serde round-trips, Display, Debug, and
//! cross-module interactions with conformance_catalog.

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

use std::collections::{BTreeMap, BTreeSet};

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

fn canonical_catalog() -> ConformanceCatalog {
    conformance_catalog::build_canonical_catalog()
}

fn default_config() -> GeneratorConfig {
    GeneratorConfig::default()
}

/// Build a minimal single-entry catalog for targeted tests.
fn minimal_catalog() -> ConformanceCatalog {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(CatalogEntry {
        entry_id: "integ/minimal/0".to_string(),
        boundary: BoundarySurface {
            sibling: SiblingRepo::Frankentui,
            surface_id: "integ/minimal/0".to_string(),
            surface_kind: SurfaceKind::TuiEventContract,
            description: "minimal integration test surface".to_string(),
            covered_fields: ["alpha", "beta"].iter().map(|s| s.to_string()).collect(),
            version_class: VersionClass::Minor,
        },
        positive_vectors: vec![ConformanceVector {
            vector_id: "integ/minimal/0/pos/0".to_string(),
            description: "baseline positive".to_string(),
            input_json: r#"{"alpha":"a","beta":"b"}"#.to_string(),
            expected_pass: true,
            expected_regression_class: None,
        }],
        negative_vectors: vec![ConformanceVector {
            vector_id: "integ/minimal/0/neg/0".to_string(),
            description: "baseline negative".to_string(),
            input_json: r#"{"bad":true}"#.to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Behavioral),
        }],
        replay_obligation: ReplayObligation::standard("integ/minimal/0", SiblingRepo::Frankentui),
        failure_class: RegressionClass::Behavioral,
        approved: true,
        approval_epoch: Some(1),
    });
    catalog
}

// =========================================================================
// Section 1: VectorCategory
// =========================================================================

#[test]
fn vector_category_display_all_variants() {
    assert_eq!(VectorCategory::Positive.to_string(), "positive");
    assert_eq!(VectorCategory::Negative.to_string(), "negative");
    assert_eq!(VectorCategory::Degraded.to_string(), "degraded");
    assert_eq!(VectorCategory::Fault.to_string(), "fault");
}

#[test]
fn vector_category_as_str_matches_display() {
    for cat in [
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ] {
        assert_eq!(cat.as_str(), &cat.to_string());
    }
}

#[test]
fn vector_category_ordering() {
    assert!(VectorCategory::Positive < VectorCategory::Negative);
    assert!(VectorCategory::Negative < VectorCategory::Degraded);
    assert!(VectorCategory::Degraded < VectorCategory::Fault);
}

#[test]
fn vector_category_serde_roundtrip() {
    for cat in [
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let decoded: VectorCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, decoded);
    }
}

#[test]
fn vector_category_clone_eq() {
    let a = VectorCategory::Degraded;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn vector_category_debug_non_empty() {
    for cat in [
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ] {
        assert!(!format!("{:?}", cat).is_empty());
    }
}

// =========================================================================
// Section 2: DegradedScenario
// =========================================================================

#[test]
fn degraded_scenario_display_stale_revocation() {
    let s = DegradedScenario::StaleRevocationHead { epochs_behind: 7 };
    let d = s.to_string();
    assert!(d.contains("stale-revocation-head"));
    assert!(d.contains("7"));
}

#[test]
fn degraded_scenario_display_partial_availability() {
    let s = DegradedScenario::PartialAvailability {
        available_fraction_millionths: 250_000,
    };
    let d = s.to_string();
    assert!(d.contains("partial-availability"));
    assert!(d.contains("250000"));
}

#[test]
fn degraded_scenario_display_timeout() {
    let s = DegradedScenario::Timeout { timeout_ms: 3000 };
    let d = s.to_string();
    assert!(d.contains("timeout"));
    assert!(d.contains("3000"));
}

#[test]
fn degraded_scenario_display_schema_drift() {
    let s = DegradedScenario::SchemaDrift {
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(1, 3, 0),
    };
    let d = s.to_string();
    assert!(d.contains("schema-drift"));
    assert!(d.contains("1.0.0"));
    assert!(d.contains("1.3.0"));
}

#[test]
fn degraded_scenario_display_empty_response() {
    let s = DegradedScenario::EmptyResponse;
    assert_eq!(s.to_string(), "empty-response");
}

#[test]
fn degraded_scenario_serde_roundtrip_all_variants() {
    let scenarios = vec![
        DegradedScenario::StaleRevocationHead { epochs_behind: 1 },
        DegradedScenario::PartialAvailability {
            available_fraction_millionths: 600_000,
        },
        DegradedScenario::Timeout { timeout_ms: 100 },
        DegradedScenario::SchemaDrift {
            local_version: SemanticVersion::new(2, 0, 0),
            remote_version: SemanticVersion::new(2, 1, 3),
        },
        DegradedScenario::EmptyResponse,
    ];
    for s in &scenarios {
        let json = serde_json::to_string(s).unwrap();
        let decoded: DegradedScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, decoded);
    }
}

#[test]
fn degraded_scenario_display_uniqueness() {
    let scenarios = [
        DegradedScenario::StaleRevocationHead { epochs_behind: 2 },
        DegradedScenario::PartialAvailability {
            available_fraction_millionths: 400_000,
        },
        DegradedScenario::Timeout { timeout_ms: 999 },
        DegradedScenario::SchemaDrift {
            local_version: SemanticVersion::new(1, 0, 0),
            remote_version: SemanticVersion::new(1, 2, 0),
        },
        DegradedScenario::EmptyResponse,
    ];
    let set: BTreeSet<String> = scenarios.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        set.len(),
        5,
        "all 5 degraded scenarios must have unique Display"
    );
}

// =========================================================================
// Section 3: FaultScenario
// =========================================================================

#[test]
fn fault_scenario_display_corrupted_payload() {
    let s = FaultScenario::CorruptedPayload {
        corruption_offset: 42,
    };
    let d = s.to_string();
    assert!(d.contains("corrupted-payload"));
    assert!(d.contains("42"));
}

#[test]
fn fault_scenario_display_truncated_message() {
    let s = FaultScenario::TruncatedMessage {
        retain_fraction_millionths: 300_000,
    };
    let d = s.to_string();
    assert!(d.contains("truncated-message"));
    assert!(d.contains("300000"));
}

#[test]
fn fault_scenario_display_out_of_order() {
    let s = FaultScenario::OutOfOrderSequence {
        expected_seq: 10,
        actual_seq: 3,
    };
    let d = s.to_string();
    assert!(d.contains("out-of-order"));
    assert!(d.contains("10"));
    assert!(d.contains("3"));
}

#[test]
fn fault_scenario_display_replay_attack() {
    let s = FaultScenario::ReplayAttack {
        original_nonce: 12345,
    };
    let d = s.to_string();
    assert!(d.contains("replay-attack"));
    assert!(d.contains("12345"));
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
    let d = s.to_string();
    assert!(d.contains("encoding-mismatch"));
    assert!(d.contains("json"));
    assert!(d.contains("binary"));
}

#[test]
fn fault_scenario_serde_roundtrip_all_variants() {
    let scenarios = vec![
        FaultScenario::CorruptedPayload {
            corruption_offset: 0,
        },
        FaultScenario::TruncatedMessage {
            retain_fraction_millionths: 500_000,
        },
        FaultScenario::OutOfOrderSequence {
            expected_seq: 5,
            actual_seq: 2,
        },
        FaultScenario::ReplayAttack {
            original_nonce: u64::MAX,
        },
        FaultScenario::MalformedJson,
        FaultScenario::EncodingMismatch {
            expected: "application/json".to_string(),
            actual: "application/octet-stream".to_string(),
        },
    ];
    for s in &scenarios {
        let json = serde_json::to_string(s).unwrap();
        let decoded: FaultScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, decoded);
    }
}

#[test]
fn fault_scenario_display_uniqueness() {
    let scenarios = [
        FaultScenario::CorruptedPayload {
            corruption_offset: 1,
        },
        FaultScenario::TruncatedMessage {
            retain_fraction_millionths: 200_000,
        },
        FaultScenario::OutOfOrderSequence {
            expected_seq: 1,
            actual_seq: 0,
        },
        FaultScenario::ReplayAttack { original_nonce: 7 },
        FaultScenario::MalformedJson,
        FaultScenario::EncodingMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
    ];
    let set: BTreeSet<String> = scenarios.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        set.len(),
        6,
        "all 6 fault scenarios must have unique Display"
    );
}

// =========================================================================
// Section 4: GeneratorConfig
// =========================================================================

#[test]
fn generator_config_default_values() {
    let c = GeneratorConfig::default();
    assert_eq!(c.seed, 42);
    assert_eq!(c.max_positive_per_entry, 3);
    assert_eq!(c.max_negative_per_entry, 3);
    assert_eq!(c.max_degraded_per_entry, 5);
    assert_eq!(c.max_fault_per_entry, 6);
    assert!(c.sibling_filter.is_empty());
    assert!(c.surface_filter.is_empty());
}

#[test]
fn generator_config_serde_roundtrip() {
    let mut c = default_config();
    c.seed = 999;
    c.sibling_filter.insert(SiblingRepo::Frankensqlite);
    c.surface_filter.insert(SurfaceKind::ApiMessage);
    let json = serde_json::to_string(&c).unwrap();
    let decoded: GeneratorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
}

#[test]
fn generator_config_debug_format() {
    let c = default_config();
    let dbg = format!("{:?}", c);
    assert!(dbg.contains("seed"));
    assert!(dbg.contains("42"));
}

// =========================================================================
// Section 5: GeneratedVector construction and serde
// =========================================================================

#[test]
fn generated_vector_manual_construction_serde_roundtrip() {
    let v = GeneratedVector {
        vector_id: "integ/test/positive/0".to_string(),
        description: "manually constructed vector".to_string(),
        category: VectorCategory::Positive,
        source_entry_id: "integ/test".to_string(),
        boundary: SiblingRepo::Asupersync,
        surface_kind: SurfaceKind::IdentifierSchema,
        input_json: r#"{"id":"abc"}"#.to_string(),
        expected_pass: true,
        expected_regression_class: None,
        degraded_scenario: None,
        fault_scenario: None,
        seed: 123,
        covered_fields: ["id"].iter().map(|s| s.to_string()).collect(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn generated_vector_with_degraded_scenario_serde() {
    let v = GeneratedVector {
        vector_id: "integ/deg/0".to_string(),
        description: "degraded vector".to_string(),
        category: VectorCategory::Degraded,
        source_entry_id: "integ/entry".to_string(),
        boundary: SiblingRepo::Frankentui,
        surface_kind: SurfaceKind::TuiStateContract,
        input_json: "{}".to_string(),
        expected_pass: false,
        expected_regression_class: Some(RegressionClass::Behavioral),
        degraded_scenario: Some(DegradedScenario::Timeout { timeout_ms: 500 }),
        fault_scenario: None,
        seed: 77,
        covered_fields: BTreeSet::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn generated_vector_with_fault_scenario_serde() {
    let v = GeneratedVector {
        vector_id: "integ/flt/0".to_string(),
        description: "fault vector".to_string(),
        category: VectorCategory::Fault,
        source_entry_id: "integ/entry".to_string(),
        boundary: SiblingRepo::FrankenNode,
        surface_kind: SurfaceKind::ApiMessage,
        input_json: "{INVALID".to_string(),
        expected_pass: false,
        expected_regression_class: Some(RegressionClass::Breaking),
        degraded_scenario: None,
        fault_scenario: Some(FaultScenario::MalformedJson),
        seed: 88,
        covered_fields: BTreeSet::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// =========================================================================
// Section 6: GenerationResult methods
// =========================================================================

#[test]
fn generation_result_count_by_category() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let total = result.count_by_category(VectorCategory::Positive)
        + result.count_by_category(VectorCategory::Negative)
        + result.count_by_category(VectorCategory::Degraded)
        + result.count_by_category(VectorCategory::Fault);
    assert_eq!(total, result.vectors.len());
}

#[test]
fn generation_result_count_by_boundary_covers_all() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let total_from_boundaries: usize = result.boundary_counts.values().sum();
    assert_eq!(total_from_boundaries, result.vectors.len());
}

#[test]
fn generation_result_vector_ids_all_unique() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let ids = result.vector_ids();
    assert_eq!(
        ids.len(),
        result.vectors.len(),
        "duplicate vector IDs detected"
    );
}

#[test]
fn generation_result_category_counts_map_consistency() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for (key, &count) in &result.category_counts {
        let manual = result
            .vectors
            .iter()
            .filter(|v| v.category.as_str() == key)
            .count();
        assert_eq!(manual, count, "mismatch for category {}", key);
    }
}

#[test]
fn generation_result_boundary_counts_map_consistency() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for (key, &count) in &result.boundary_counts {
        let manual = result
            .vectors
            .iter()
            .filter(|v| v.boundary.as_str() == key)
            .count();
        assert_eq!(manual, count, "mismatch for boundary {}", key);
    }
}

#[test]
fn generation_result_serde_roundtrip() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let json = serde_json::to_string(&result).unwrap();
    let decoded: GenerationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// =========================================================================
// Section 7: generate_vectors -- determinism
// =========================================================================

#[test]
fn generate_vectors_deterministic_same_seed() {
    let catalog = canonical_catalog();
    let config = default_config();
    let r1 = generate_vectors(&catalog, &config);
    let r2 = generate_vectors(&catalog, &config);
    assert_eq!(r1.vectors.len(), r2.vectors.len());
    for (a, b) in r1.vectors.iter().zip(r2.vectors.iter()) {
        assert_eq!(a.vector_id, b.vector_id);
        assert_eq!(a.input_json, b.input_json);
        assert_eq!(a.seed, b.seed);
    }
}

#[test]
fn generate_vectors_different_seeds_produce_different_content() {
    let catalog = canonical_catalog();
    let mut c1 = default_config();
    c1.seed = 42;
    let mut c2 = default_config();
    c2.seed = 9999;
    let r1 = generate_vectors(&catalog, &c1);
    let r2 = generate_vectors(&catalog, &c2);
    // Same structure but different seeds in vectors.
    assert_eq!(r1.vectors.len(), r2.vectors.len());
    let diff_count = r1
        .vectors
        .iter()
        .zip(r2.vectors.iter())
        .filter(|(a, b)| a.seed != b.seed)
        .count();
    assert!(
        diff_count > 0,
        "different master seeds should produce different vector seeds"
    );
}

// =========================================================================
// Section 8: generate_vectors -- category invariants
// =========================================================================

#[test]
fn positive_vectors_always_expect_pass() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Positive {
            assert!(
                v.expected_pass,
                "positive vector {} should expect pass",
                v.vector_id
            );
            assert!(v.expected_regression_class.is_none());
            assert!(v.degraded_scenario.is_none());
            assert!(v.fault_scenario.is_none());
        }
    }
}

#[test]
fn degraded_vectors_have_degraded_scenario() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Degraded {
            assert!(
                v.degraded_scenario.is_some(),
                "degraded vector {} must have scenario",
                v.vector_id
            );
            assert!(v.fault_scenario.is_none());
        }
    }
}

#[test]
fn fault_vectors_have_fault_scenario_and_expect_failure() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Fault {
            assert!(
                v.fault_scenario.is_some(),
                "fault vector {} must have fault scenario",
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
fn negative_vectors_mostly_expect_failure() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let neg_total = result.count_by_category(VectorCategory::Negative);
    let neg_fail = result
        .vectors
        .iter()
        .filter(|v| v.category == VectorCategory::Negative && !v.expected_pass)
        .count();
    assert!(
        neg_fail > neg_total / 2,
        "most negative vectors should expect failure (got {}/{})",
        neg_fail,
        neg_total
    );
}

// =========================================================================
// Section 9: generate_vectors -- filters
// =========================================================================

#[test]
fn sibling_filter_restricts_to_single_boundary() {
    let catalog = canonical_catalog();
    let mut config = default_config();
    config.sibling_filter.insert(SiblingRepo::Frankensqlite);
    let result = generate_vectors(&catalog, &config);
    assert!(!result.vectors.is_empty());
    for v in &result.vectors {
        assert_eq!(v.boundary, SiblingRepo::Frankensqlite);
    }
}

#[test]
fn surface_filter_restricts_to_single_surface() {
    let catalog = canonical_catalog();
    let mut config = default_config();
    config
        .surface_filter
        .insert(SurfaceKind::PersistenceSemantics);
    let result = generate_vectors(&catalog, &config);
    assert!(!result.vectors.is_empty());
    for v in &result.vectors {
        assert_eq!(v.surface_kind, SurfaceKind::PersistenceSemantics);
    }
}

#[test]
fn both_filters_combined_narrow_correctly() {
    let catalog = canonical_catalog();
    let mut config = default_config();
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
    let catalog = canonical_catalog();
    let mut config = default_config();
    // frankentui has no IdentifierSchema surfaces (that is asupersync's domain).
    config.sibling_filter.insert(SiblingRepo::Frankentui);
    config.surface_filter.insert(SurfaceKind::IdentifierSchema);
    let result = generate_vectors(&catalog, &config);
    assert!(
        result.vectors.is_empty(),
        "no Frankentui IdentifierSchema vectors expected, got {}",
        result.vectors.len()
    );
}

// =========================================================================
// Section 10: generate_vectors -- max limits
// =========================================================================

#[test]
fn restricted_max_per_entry_limits_output() {
    let catalog = minimal_catalog();
    let mut config = default_config();
    config.max_positive_per_entry = 1;
    config.max_negative_per_entry = 1;
    config.max_degraded_per_entry = 2;
    config.max_fault_per_entry = 2;
    let result = generate_vectors(&catalog, &config);
    let pos = result.count_by_category(VectorCategory::Positive);
    let neg = result.count_by_category(VectorCategory::Negative);
    let deg = result.count_by_category(VectorCategory::Degraded);
    let flt = result.count_by_category(VectorCategory::Fault);
    assert!(pos <= 1, "positive: {} > 1", pos);
    assert!(neg <= 1, "negative: {} > 1", neg);
    assert!(deg <= 2, "degraded: {} > 2", deg);
    assert!(flt <= 2, "fault: {} > 2", flt);
}

#[test]
fn zero_max_positive_per_entry() {
    let catalog = minimal_catalog();
    let mut config = default_config();
    config.max_positive_per_entry = 0;
    let result = generate_vectors(&catalog, &config);
    assert_eq!(result.count_by_category(VectorCategory::Positive), 0);
}

#[test]
fn zero_max_fault_per_entry() {
    let catalog = minimal_catalog();
    let mut config = default_config();
    config.max_fault_per_entry = 0;
    let result = generate_vectors(&catalog, &config);
    assert_eq!(result.count_by_category(VectorCategory::Fault), 0);
}

// =========================================================================
// Section 11: generate_vectors -- warnings
// =========================================================================

#[test]
fn warns_on_entry_without_positive_vectors() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.entries.push(CatalogEntry {
        entry_id: "integ/no_pos".to_string(),
        boundary: BoundarySurface {
            sibling: SiblingRepo::Asupersync,
            surface_id: "integ/no_pos".to_string(),
            surface_kind: SurfaceKind::ApiMessage,
            description: "no positive vectors".to_string(),
            covered_fields: ["x"].iter().map(|s| s.to_string()).collect(),
            version_class: VersionClass::Patch,
        },
        positive_vectors: vec![],
        negative_vectors: vec![ConformanceVector {
            vector_id: "neg0".to_string(),
            description: "neg".to_string(),
            input_json: "{}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Observability),
        }],
        replay_obligation: ReplayObligation::standard("integ/no_pos", SiblingRepo::Asupersync),
        failure_class: RegressionClass::Observability,
        approved: false,
        approval_epoch: None,
    });
    let result = generate_vectors(&catalog, &default_config());
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("no baseline positive vectors")),
        "expected warning about missing positive vectors"
    );
}

#[test]
fn no_warnings_for_well_formed_catalog() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    assert!(
        result.warnings.is_empty(),
        "canonical catalog should produce no warnings, got: {:?}",
        result.warnings
    );
}

// =========================================================================
// Section 12: BoundaryProperty and canonical_boundary_properties
// =========================================================================

#[test]
fn canonical_properties_at_least_five() {
    let props = canonical_boundary_properties();
    assert!(
        props.len() >= 5,
        "expected >= 5 properties, got {}",
        props.len()
    );
}

#[test]
fn canonical_properties_unique_ids() {
    let props = canonical_boundary_properties();
    let mut seen = BTreeSet::new();
    for p in &props {
        assert!(
            seen.insert(&p.property_id),
            "duplicate property_id: {}",
            p.property_id
        );
    }
}

#[test]
fn serde_roundtrip_property() {
    let props = canonical_boundary_properties();
    let first = &props[0];
    let json = serde_json::to_string(first).unwrap();
    let decoded: BoundaryProperty = serde_json::from_str(&json).unwrap();
    assert_eq!(*first, decoded);
}

#[test]
fn canonical_properties_contain_serde_roundtrip() {
    let props = canonical_boundary_properties();
    assert!(
        props.iter().any(|p| p.property_id == "serde-roundtrip"),
        "must include serde-roundtrip property"
    );
}

#[test]
fn serde_roundtrip_property_applies_to_all_surfaces() {
    let props = canonical_boundary_properties();
    let serde_prop = props
        .iter()
        .find(|p| p.property_id == "serde-roundtrip")
        .unwrap();
    assert!(
        serde_prop.applicable_surfaces.len() >= 10,
        "serde-roundtrip should apply to all 10 surface kinds, got {}",
        serde_prop.applicable_surfaces.len()
    );
    assert!(serde_prop.requires_roundtrip);
}

#[test]
fn canonical_properties_violation_classes_are_set() {
    let props = canonical_boundary_properties();
    for p in &props {
        // Just ensure Debug doesn't panic and the class is valid.
        let _ = format!("{:?}", p.violation_class);
    }
}

// =========================================================================
// Section 13: properties_for_surface
// =========================================================================

#[test]
fn properties_for_api_message_includes_error_envelope() {
    let api_props = properties_for_surface(SurfaceKind::ApiMessage);
    assert!(
        api_props
            .iter()
            .any(|p| p.property_id == "error-envelope-stability"),
        "ApiMessage surface should include error-envelope-stability"
    );
}

#[test]
fn properties_for_telemetry_includes_completeness() {
    let tel_props = properties_for_surface(SurfaceKind::TelemetrySchema);
    assert!(
        tel_props
            .iter()
            .any(|p| p.property_id == "telemetry-field-completeness"),
        "TelemetrySchema surface should include telemetry-field-completeness"
    );
}

#[test]
fn properties_for_surface_all_applicable() {
    let props = properties_for_surface(SurfaceKind::DecisionPayload);
    for p in &props {
        assert!(
            p.applicable_surfaces
                .contains(&SurfaceKind::DecisionPayload),
            "property {} should apply to DecisionPayload",
            p.property_id
        );
    }
}

// =========================================================================
// Section 14: PropertyCheckResult
// =========================================================================

#[test]
fn property_check_result_serde_roundtrip() {
    let r = PropertyCheckResult {
        property_id: "serde-roundtrip".to_string(),
        vector_id: "integ/gen/positive/0".to_string(),
        passed: true,
        detail: "all fields preserved".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let decoded: PropertyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

#[test]
fn property_check_result_failed() {
    let r = PropertyCheckResult {
        property_id: "field-presence-invariant".to_string(),
        vector_id: "integ/gen/negative/0".to_string(),
        passed: false,
        detail: "missing required field 'alpha'".to_string(),
    };
    assert!(!r.passed);
    let json = serde_json::to_string(&r).unwrap();
    let decoded: PropertyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

// =========================================================================
// Section 15: validate_property_coverage
// =========================================================================

#[test]
fn validate_property_coverage_no_gaps_canonical() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let props = canonical_boundary_properties();
    let gaps = validate_property_coverage(&result, &props);
    assert!(gaps.is_empty(), "unexpected coverage gaps: {:?}", gaps);
}

#[test]
fn validate_property_coverage_detects_gap_for_missing_surface() {
    // Generate vectors for only one boundary, then check coverage against
    // a property that applies to a surface not in that boundary.
    let catalog = minimal_catalog();
    let result = generate_vectors(&catalog, &default_config());
    // telemetry-field-completeness applies to TelemetrySchema, which is
    // not covered by our minimal catalog (only TuiEventContract).
    let props = vec![BoundaryProperty {
        property_id: "test-gap-property".to_string(),
        description: "applies to TelemetrySchema only".to_string(),
        applicable_surfaces: [SurfaceKind::TelemetrySchema].into_iter().collect(),
        requires_roundtrip: false,
        violation_class: RegressionClass::Observability,
    }];
    let gaps = validate_property_coverage(&result, &props);
    assert!(
        !gaps.is_empty(),
        "should detect gap for TelemetrySchema surface not covered"
    );
    assert!(gaps[0].contains("test-gap-property"));
}

#[test]
fn validate_property_coverage_empty_properties_no_gaps() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    let gaps = validate_property_coverage(&result, &[]);
    assert!(gaps.is_empty());
}

#[test]
fn validate_property_coverage_empty_result_detects_gaps() {
    let empty_result = GenerationResult {
        seed: 0,
        catalog_version: SemanticVersion::new(1, 0, 0),
        vectors: Vec::new(),
        category_counts: BTreeMap::new(),
        boundary_counts: BTreeMap::new(),
        warnings: Vec::new(),
    };
    let props = canonical_boundary_properties();
    let gaps = validate_property_coverage(&empty_result, &props);
    // With no vectors, all properties with non-empty applicable_surfaces
    // should report gaps.
    assert!(!gaps.is_empty(), "empty result should have coverage gaps");
}

// =========================================================================
// Section 16: Full pipeline end-to-end
// =========================================================================

#[test]
fn full_pipeline_canonical_catalog_all_categories_present() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    assert!(result.count_by_category(VectorCategory::Positive) > 0);
    assert!(result.count_by_category(VectorCategory::Negative) > 0);
    assert!(result.count_by_category(VectorCategory::Degraded) > 0);
    assert!(result.count_by_category(VectorCategory::Fault) > 0);
}

#[test]
fn full_pipeline_covers_all_primary_boundaries() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for repo in SiblingRepo::all() {
        if repo.is_primary() {
            assert!(
                result.count_by_boundary(*repo) > 0,
                "primary boundary {} has no vectors",
                repo
            );
        }
    }
}

#[test]
fn full_pipeline_serde_roundtrip_with_validation() {
    let catalog = canonical_catalog();
    let config = default_config();
    let result = generate_vectors(&catalog, &config);
    let props = canonical_boundary_properties();

    // Serde roundtrip of full result.
    let json = serde_json::to_string(&result).unwrap();
    let decoded: GenerationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);

    // Property coverage.
    let gaps = validate_property_coverage(&result, &props);
    assert!(gaps.is_empty());

    // Unique IDs.
    let ids = result.vector_ids();
    assert_eq!(ids.len(), result.vectors.len());
}

#[test]
fn full_pipeline_with_restricted_config() {
    let catalog = canonical_catalog();
    let mut config = default_config();
    config.max_positive_per_entry = 1;
    config.max_negative_per_entry = 1;
    config.max_degraded_per_entry = 2;
    config.max_fault_per_entry = 2;
    config.sibling_filter.insert(SiblingRepo::Asupersync);

    let result = generate_vectors(&catalog, &config);
    for v in &result.vectors {
        assert_eq!(v.boundary, SiblingRepo::Asupersync);
    }

    let asupersync_entries = catalog.entries_for_boundary(SiblingRepo::Asupersync);
    let expected_max = asupersync_entries.len() * (1 + 1 + 2 + 2);
    assert!(
        result.vectors.len() <= expected_max,
        "too many vectors: {} > {}",
        result.vectors.len(),
        expected_max
    );
}

// =========================================================================
// Section 17: Edge cases and miscellaneous
// =========================================================================

#[test]
fn empty_catalog_produces_empty_result() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(0, 0, 1));
    let result = generate_vectors(&catalog, &default_config());
    assert!(result.vectors.is_empty());
    assert!(result.category_counts.is_empty());
    assert!(result.boundary_counts.is_empty());
    assert!(result.warnings.is_empty());
}

#[test]
fn generation_result_seed_matches_config() {
    let catalog = canonical_catalog();
    let mut config = default_config();
    config.seed = 777;
    let result = generate_vectors(&catalog, &config);
    assert_eq!(result.seed, 777);
}

#[test]
fn generation_result_catalog_version_matches() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    assert_eq!(result.catalog_version, catalog.catalog_version);
}

#[test]
fn vector_id_format_contains_gen_and_category() {
    let catalog = minimal_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        assert!(
            v.vector_id.contains("/gen/"),
            "vector_id '{}' should contain '/gen/'",
            v.vector_id
        );
        let has_category_tag = v.vector_id.contains("/positive/")
            || v.vector_id.contains("/negative/")
            || v.vector_id.contains("/degraded/")
            || v.vector_id.contains("/fault/");
        assert!(
            has_category_tag,
            "vector_id '{}' should contain category path segment",
            v.vector_id
        );
    }
}

#[test]
fn negative_vectors_version_mismatch_always_breaking() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Negative
            && v.description.contains("Major version mismatch")
        {
            assert_eq!(
                v.expected_regression_class,
                Some(RegressionClass::Breaking),
                "version mismatch negative vectors should have Breaking regression class"
            );
        }
    }
}

#[test]
fn fault_vectors_always_breaking_regression_class() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Fault {
            assert_eq!(
                v.expected_regression_class,
                Some(RegressionClass::Breaking),
                "fault vector {} should have Breaking regression class",
                v.vector_id
            );
        }
    }
}

#[test]
fn degraded_vectors_behavioral_regression_class() {
    let catalog = canonical_catalog();
    let result = generate_vectors(&catalog, &default_config());
    for v in &result.vectors {
        if v.category == VectorCategory::Degraded {
            assert_eq!(
                v.expected_regression_class,
                Some(RegressionClass::Behavioral),
                "degraded vector {} should have Behavioral regression class",
                v.vector_id
            );
        }
    }
}
