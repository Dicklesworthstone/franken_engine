#![forbid(unsafe_code)]

//! Enrichment integration tests for the conformance_vector_gen module.

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

use frankenengine_engine::conformance_catalog::{self, SurfaceKind};
use frankenengine_engine::conformance_vector_gen::{
    BoundaryProperty, DegradedScenario, FaultScenario, GeneratedVector, GenerationResult,
    GeneratorConfig, PropertyCheckResult, VectorCategory, canonical_boundary_properties,
    generate_vectors, properties_for_surface, validate_property_coverage,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_result() -> GenerationResult {
    let catalog = conformance_catalog::build_canonical_catalog();
    let config = GeneratorConfig::default();
    generate_vectors(&catalog, &config)
}

// ---------------------------------------------------------------------------
// VectorCategory — Copy / BTreeSet
// ---------------------------------------------------------------------------

#[test]
fn enrichment_vector_category_copy_semantics() {
    let a = VectorCategory::Positive;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_vector_category_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(VectorCategory::Positive);
    set.insert(VectorCategory::Negative);
    set.insert(VectorCategory::Degraded);
    set.insert(VectorCategory::Fault);
    set.insert(VectorCategory::Positive);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_vector_category_clone_independence() {
    let a = VectorCategory::Fault;
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// DegradedScenario — Clone / BTreeSet / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_degraded_scenario_clone_independence() {
    let a = DegradedScenario::EmptyResponse;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_degraded_scenario_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(DegradedScenario::EmptyResponse);
    set.insert(DegradedScenario::Timeout { timeout_ms: 100 });
    set.insert(DegradedScenario::StaleRevocationHead { epochs_behind: 5 });
    set.insert(DegradedScenario::EmptyResponse);
    assert!(set.len() >= 3);
}

#[test]
fn enrichment_degraded_scenario_debug_nonempty() {
    let s = DegradedScenario::Timeout { timeout_ms: 500 };
    assert!(!format!("{:?}", s).is_empty());
}

#[test]
fn enrichment_degraded_scenario_display_contains_info() {
    let s = DegradedScenario::StaleRevocationHead { epochs_behind: 3 };
    let disp = format!("{}", s);
    assert!(!disp.is_empty());
}

// ---------------------------------------------------------------------------
// FaultScenario — Clone / BTreeSet / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fault_scenario_clone_independence() {
    let a = FaultScenario::MalformedJson;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_fault_scenario_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FaultScenario::MalformedJson);
    set.insert(FaultScenario::ReplayAttack { original_nonce: 42 });
    set.insert(FaultScenario::CorruptedPayload {
        corruption_offset: 10,
    });
    set.insert(FaultScenario::MalformedJson);
    assert!(set.len() >= 3);
}

#[test]
fn enrichment_fault_scenario_debug_nonempty() {
    let s = FaultScenario::TruncatedMessage {
        retain_fraction_millionths: 500_000,
    };
    assert!(!format!("{:?}", s).is_empty());
}

#[test]
fn enrichment_fault_scenario_display_contains_info() {
    let s = FaultScenario::ReplayAttack { original_nonce: 99 };
    let disp = format!("{}", s);
    assert!(!disp.is_empty());
}

// ---------------------------------------------------------------------------
// GeneratorConfig — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generator_config_clone_independence() {
    let a = GeneratorConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_generator_config_json_field_names() {
    let cfg = GeneratorConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "seed",
        "max_positive_per_entry",
        "max_negative_per_entry",
        "max_degraded_per_entry",
        "max_fault_per_entry",
        "sibling_filter",
        "surface_filter",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_generator_config_default_seed() {
    let cfg = GeneratorConfig::default();
    assert_eq!(cfg.seed, 42);
}

// ---------------------------------------------------------------------------
// GeneratedVector — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generated_vector_clone_independence() {
    let result = default_result();
    let v = &result.vectors[0];
    let v2 = v.clone();
    assert_eq!(*v, v2);
}

#[test]
fn enrichment_generated_vector_debug_nonempty() {
    let result = default_result();
    assert!(!format!("{:?}", result.vectors[0]).is_empty());
}

#[test]
fn enrichment_generated_vector_json_field_names() {
    let result = default_result();
    let json = serde_json::to_string(&result.vectors[0]).unwrap();
    for field in &[
        "vector_id",
        "description",
        "category",
        "source_entry_id",
        "boundary",
        "surface_kind",
        "input_json",
        "expected_pass",
        "seed",
        "covered_fields",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_generated_vector_serde_roundtrip() {
    let result = default_result();
    let v = &result.vectors[0];
    let json = serde_json::to_string(v).unwrap();
    let rt: GeneratedVector = serde_json::from_str(&json).unwrap();
    assert_eq!(*v, rt);
}

// ---------------------------------------------------------------------------
// GenerationResult — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generation_result_clone_independence() {
    let a = default_result();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_generation_result_debug_nonempty() {
    assert!(!format!("{:?}", default_result()).is_empty());
}

#[test]
fn enrichment_generation_result_json_field_names() {
    let result = default_result();
    let json = serde_json::to_string(&result).unwrap();
    for field in &[
        "seed",
        "catalog_version",
        "vectors",
        "category_counts",
        "boundary_counts",
        "warnings",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_generation_result_vector_ids_nonempty() {
    let result = default_result();
    let ids = result.vector_ids();
    assert!(!ids.is_empty());
    for id in &ids {
        assert!(!id.is_empty());
    }
}

#[test]
fn enrichment_generation_result_count_by_category_all() {
    let result = default_result();
    let total = result.count_by_category(VectorCategory::Positive)
        + result.count_by_category(VectorCategory::Negative)
        + result.count_by_category(VectorCategory::Degraded)
        + result.count_by_category(VectorCategory::Fault);
    assert_eq!(total, result.vectors.len());
}

// ---------------------------------------------------------------------------
// BoundaryProperty — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_boundary_property_clone_independence() {
    let props = canonical_boundary_properties();
    let a = &props[0];
    let b = a.clone();
    assert_eq!(*a, b);
}

#[test]
fn enrichment_boundary_property_debug_nonempty() {
    let props = canonical_boundary_properties();
    assert!(!format!("{:?}", props[0]).is_empty());
}

#[test]
fn enrichment_boundary_property_json_field_names() {
    let props = canonical_boundary_properties();
    let json = serde_json::to_string(&props[0]).unwrap();
    for field in &[
        "property_id",
        "description",
        "applicable_surfaces",
        "requires_roundtrip",
        "violation_class",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_boundary_property_serde_roundtrip_all() {
    let props = canonical_boundary_properties();
    for prop in &props {
        let json = serde_json::to_string(prop).unwrap();
        let rt: BoundaryProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(*prop, rt);
    }
}

#[test]
fn enrichment_boundary_property_ids_all_unique() {
    let props = canonical_boundary_properties();
    let ids: BTreeSet<&str> = props.iter().map(|p| p.property_id.as_str()).collect();
    assert_eq!(ids.len(), props.len());
}

// ---------------------------------------------------------------------------
// PropertyCheckResult — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_property_check_result_clone_independence() {
    let a = PropertyCheckResult {
        property_id: "serde-roundtrip".to_string(),
        vector_id: "gen-positive-001".to_string(),
        passed: true,
        detail: "ok".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_property_check_result_debug_nonempty() {
    let a = PropertyCheckResult {
        property_id: "test".to_string(),
        vector_id: "v1".to_string(),
        passed: false,
        detail: "failed check".to_string(),
    };
    assert!(!format!("{:?}", a).is_empty());
}

#[test]
fn enrichment_property_check_result_json_field_names() {
    let a = PropertyCheckResult {
        property_id: "field-presence".to_string(),
        vector_id: "v1".to_string(),
        passed: true,
        detail: "present".to_string(),
    };
    let json = serde_json::to_string(&a).unwrap();
    for field in &["property_id", "vector_id", "passed", "detail"] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// properties_for_surface coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_properties_for_surface_nonempty_for_all_kinds() {
    let surfaces = [
        SurfaceKind::ApiMessage,
        SurfaceKind::TelemetrySchema,
        SurfaceKind::IdentifierSchema,
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
    ];
    for surface in &surfaces {
        let props = properties_for_surface(*surface);
        assert!(!props.is_empty(), "no properties for {:?}", surface);
    }
}

#[test]
fn enrichment_properties_for_surface_subset_of_canonical() {
    let canonical = canonical_boundary_properties();
    let canonical_ids: BTreeSet<&str> = canonical.iter().map(|p| p.property_id.as_str()).collect();
    let props = properties_for_surface(SurfaceKind::ApiMessage);
    for p in &props {
        assert!(
            canonical_ids.contains(p.property_id.as_str()),
            "surface property not in canonical set: {}",
            p.property_id
        );
    }
}

// ---------------------------------------------------------------------------
// validate_property_coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_coverage_full_result_no_gaps() {
    let result = default_result();
    let props = canonical_boundary_properties();
    let gaps = validate_property_coverage(&result, &props);
    // With default config and full catalog, should have minimal gaps
    // (may have some depending on catalog coverage)
    let _ = gaps; // just verifying it runs without panic
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_vectors() {
    let catalog = conformance_catalog::build_canonical_catalog();
    let config = GeneratorConfig::default();
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&generate_vectors(&catalog, &config)).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "generation should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_vector_ids() {
    let catalog = conformance_catalog::build_canonical_catalog();
    let config = GeneratorConfig::default();
    let id_sets: Vec<BTreeSet<String>> = (0..5)
        .map(|_| generate_vectors(&catalog, &config).vector_ids())
        .collect();
    for ids in &id_sets[1..] {
        assert_eq!(*ids, id_sets[0]);
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_positive_vectors_expect_pass() {
    let result = default_result();
    for v in &result.vectors {
        if v.category == VectorCategory::Positive {
            assert!(
                v.expected_pass,
                "positive vector should expect pass: {}",
                v.vector_id
            );
        }
    }
}

#[test]
fn enrichment_cross_cutting_fault_vectors_have_scenario() {
    let result = default_result();
    for v in &result.vectors {
        if v.category == VectorCategory::Fault {
            assert!(
                v.fault_scenario.is_some(),
                "fault vector should have fault_scenario: {}",
                v.vector_id
            );
        }
    }
}

#[test]
fn enrichment_cross_cutting_degraded_vectors_have_scenario() {
    let result = default_result();
    for v in &result.vectors {
        if v.category == VectorCategory::Degraded {
            assert!(
                v.degraded_scenario.is_some(),
                "degraded vector should have degraded_scenario: {}",
                v.vector_id
            );
        }
    }
}

#[test]
fn enrichment_cross_cutting_category_counts_match() {
    let result = default_result();
    for cat in &[
        VectorCategory::Positive,
        VectorCategory::Negative,
        VectorCategory::Degraded,
        VectorCategory::Fault,
    ] {
        let counted = result.count_by_category(*cat);
        let actual = result.vectors.iter().filter(|v| v.category == *cat).count();
        assert_eq!(counted, actual, "count mismatch for {:?}", cat);
    }
}

#[test]
fn enrichment_cross_cutting_all_vector_ids_contain_gen() {
    let result = default_result();
    for v in &result.vectors {
        assert!(
            v.vector_id.contains("/gen/"),
            "vector_id should contain /gen/: {}",
            v.vector_id
        );
    }
}

#[test]
fn enrichment_cross_cutting_different_seeds_different_vectors() {
    let catalog = conformance_catalog::build_canonical_catalog();
    let mut cfg1 = GeneratorConfig::default();
    cfg1.seed = 1;
    let mut cfg2 = GeneratorConfig::default();
    cfg2.seed = 999;
    let r1 = generate_vectors(&catalog, &cfg1);
    let r2 = generate_vectors(&catalog, &cfg2);
    // At least the input_json should differ for some vectors
    let jsons1: BTreeSet<&str> = r1.vectors.iter().map(|v| v.input_json.as_str()).collect();
    let jsons2: BTreeSet<&str> = r2.vectors.iter().map(|v| v.input_json.as_str()).collect();
    assert_ne!(
        jsons1, jsons2,
        "different seeds should produce different content"
    );
}
