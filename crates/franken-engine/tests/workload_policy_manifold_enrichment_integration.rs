//! Enrichment integration tests for `workload_policy_manifold`.

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

use std::collections::BTreeMap;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_policy_manifold::*;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_axis(key: &str, dim: ManifoldDimension, min: i64, max: i64) -> AxisDescriptor {
    AxisDescriptor {
        key: key.to_string(),
        dimension: dim,
        description: format!("{key} axis"),
        unit: "millionths".to_string(),
        min_calibrated_millionths: min,
        max_calibrated_millionths: max,
        required: true,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn enrichment_manifold_schema_version_non_empty() {
    assert!(!MANIFOLD_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_max_axes_positive() {
    assert!(MAX_AXES_PER_DIMENSION > 0);
}

// ---------------------------------------------------------------------------
// ManifoldDimension serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifold_dimension_serde_roundtrip() {
    for dim in [
        ManifoldDimension::Workload,
        ManifoldDimension::Hardware,
        ManifoldDimension::Policy,
        ManifoldDimension::Cache,
    ] {
        let json = serde_json::to_string(&dim).unwrap();
        let back: ManifoldDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(dim, back);
    }
}

// ---------------------------------------------------------------------------
// AxisDescriptor
// ---------------------------------------------------------------------------

#[test]
fn enrichment_axis_descriptor_is_in_range() {
    let axis = make_axis("test", ManifoldDimension::Workload, 0, 1_000_000);
    assert!(axis.is_in_range(0));
    assert!(axis.is_in_range(500_000));
    assert!(axis.is_in_range(1_000_000));
    assert!(!axis.is_in_range(-1));
    assert!(!axis.is_in_range(1_000_001));
}

#[test]
fn enrichment_axis_descriptor_normalize() {
    let axis = make_axis("test", ManifoldDimension::Workload, 0, 1_000_000);
    assert_eq!(axis.normalize(0), Some(0));
    assert_eq!(axis.normalize(1_000_000), Some(1_000_000));
    assert_eq!(axis.normalize(500_000), Some(500_000));
    assert_eq!(axis.normalize(-1), None);
}

#[test]
fn enrichment_axis_descriptor_content_hash_deterministic() {
    let a1 = make_axis("test", ManifoldDimension::Workload, 0, 1_000_000);
    let a2 = make_axis("test", ManifoldDimension::Workload, 0, 1_000_000);
    assert_eq!(a1.content_hash(), a2.content_hash());
}

#[test]
fn enrichment_axis_descriptor_serde_roundtrip() {
    let axis = make_axis("cpu", ManifoldDimension::Hardware, 0, 100_000);
    let json = serde_json::to_string(&axis).unwrap();
    let back: AxisDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(axis, back);
}

// ---------------------------------------------------------------------------
// ManifoldSchema
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifold_schema_new() {
    let axes = vec![
        make_axis("a", ManifoldDimension::Workload, 0, 1_000_000),
        make_axis("b", ManifoldDimension::Hardware, 0, 1_000_000),
    ];
    let schema = ManifoldSchema::new("test-schema", axes, epoch());
    assert_eq!(schema.axis_count(), 2);
}

#[test]
fn enrichment_manifold_schema_axes_for_dimension() {
    let axes = vec![
        make_axis("w1", ManifoldDimension::Workload, 0, 1_000_000),
        make_axis("w2", ManifoldDimension::Workload, 0, 1_000_000),
        make_axis("h1", ManifoldDimension::Hardware, 0, 1_000_000),
    ];
    let schema = ManifoldSchema::new("test", axes, epoch());
    assert_eq!(
        schema.axes_for_dimension(ManifoldDimension::Workload).len(),
        2
    );
    assert_eq!(
        schema.axes_for_dimension(ManifoldDimension::Hardware).len(),
        1
    );
}

#[test]
fn enrichment_manifold_schema_required_keys() {
    let axes = vec![
        make_axis("req", ManifoldDimension::Workload, 0, 1_000_000),
        AxisDescriptor {
            key: "opt".to_string(),
            dimension: ManifoldDimension::Policy,
            description: "optional".to_string(),
            unit: "u".to_string(),
            min_calibrated_millionths: 0,
            max_calibrated_millionths: 1_000_000,
            required: false,
        },
    ];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let required = schema.required_keys();
    assert!(required.contains("req"));
    assert!(!required.contains("opt"));
}

#[test]
fn enrichment_manifold_schema_content_hash_deterministic() {
    let axes = vec![make_axis("x", ManifoldDimension::Cache, 0, 100)];
    let s1 = ManifoldSchema::new("sch", axes.clone(), epoch());
    let s2 = ManifoldSchema::new("sch", axes, epoch());
    assert_eq!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// ManifoldPlacer
// ---------------------------------------------------------------------------

#[test]
fn enrichment_placer_place_valid_coordinate() {
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 1_000_000)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);
    let raw = BTreeMap::from([("a".to_string(), 500_000i64)]);
    let coord = placer.place(&raw, None);
    assert_eq!(coord.validity, PlacementValidity::Valid);
    assert_eq!(placer.placed_count(), 1);
}

#[test]
fn enrichment_placer_place_out_of_range() {
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 100)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);
    let raw = BTreeMap::from([("a".to_string(), 999i64)]);
    let coord = placer.place(&raw, None);
    assert_ne!(coord.validity, PlacementValidity::Valid);
}

#[test]
fn enrichment_placer_place_missing_required() {
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 1_000_000)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);
    let raw = BTreeMap::new();
    let coord = placer.place(&raw, None);
    assert!(!coord.issues.is_empty());
}

// ---------------------------------------------------------------------------
// Distance functions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_chebyshev_distance_same_point() {
    let a = BTreeMap::from([("x".to_string(), 100i64)]);
    let b = a.clone();
    assert_eq!(chebyshev_distance(&a, &b), Some(0));
}

#[test]
fn enrichment_chebyshev_distance_different_points() {
    let a = BTreeMap::from([("x".to_string(), 0i64), ("y".to_string(), 0i64)]);
    let b = BTreeMap::from([("x".to_string(), 30i64), ("y".to_string(), 50i64)]);
    assert_eq!(chebyshev_distance(&a, &b), Some(50));
}

#[test]
fn enrichment_manhattan_distance_same_point() {
    let a = BTreeMap::from([("x".to_string(), 100i64)]);
    assert_eq!(manhattan_distance(&a, &a), Some(0));
}

#[test]
fn enrichment_manhattan_distance_two_axes() {
    let a = BTreeMap::from([("x".to_string(), 0i64), ("y".to_string(), 0i64)]);
    let b = BTreeMap::from([("x".to_string(), 30i64), ("y".to_string(), 50i64)]);
    assert_eq!(manhattan_distance(&a, &b), Some(80));
}

#[test]
fn enrichment_squared_euclidean_same_point() {
    let a = BTreeMap::from([("x".to_string(), 10i64)]);
    assert_eq!(squared_euclidean_distance(&a, &a), Some(0));
}

#[test]
fn enrichment_squared_euclidean_distinct() {
    let a = BTreeMap::from([("x".to_string(), 0i64)]);
    let b = BTreeMap::from([("x".to_string(), 3i64)]);
    assert_eq!(squared_euclidean_distance(&a, &b), Some(9));
}

// ---------------------------------------------------------------------------
// NeighborhoodBuilder
// ---------------------------------------------------------------------------

#[test]
fn enrichment_neighborhood_builder_empty() {
    let builder = NeighborhoodBuilder::new(50_000);
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 1_000_000)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);
    let raw = BTreeMap::from([("a".to_string(), 500_000i64)]);
    let center = placer.place(&raw, None);
    let neighborhood = builder.build(&center, &[], None);
    assert_eq!(neighborhood.member_count, 0);
}

#[test]
fn enrichment_neighborhood_builder_includes_nearby() {
    let builder = NeighborhoodBuilder::new(100_000);
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 1_000_000)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);

    let center = placer.place(&BTreeMap::from([("a".to_string(), 500_000i64)]), None);
    let near = placer.place(&BTreeMap::from([("a".to_string(), 550_000i64)]), None);
    let far = placer.place(&BTreeMap::from([("a".to_string(), 900_000i64)]), None);

    let neighborhood = builder.build(&center, &[near, far], None);
    // "near" should be within radius (50K < 100K), "far" should not (400K > 100K)
    assert!(neighborhood.member_count >= 1);
}

// ---------------------------------------------------------------------------
// default axes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_workload_axes_non_empty() {
    assert!(!default_workload_axes().is_empty());
}

#[test]
fn enrichment_default_hardware_axes_non_empty() {
    assert!(!default_hardware_axes().is_empty());
}

#[test]
fn enrichment_default_policy_axes_non_empty() {
    assert!(!default_policy_axes().is_empty());
}

#[test]
fn enrichment_default_cache_axes_non_empty() {
    assert!(!default_cache_axes().is_empty());
}

#[test]
fn enrichment_default_manifold_schema_has_axes() {
    let schema = default_manifold_schema(epoch());
    assert!(schema.axis_count() > 0);
}

#[test]
fn enrichment_default_manifold_schema_content_hash_deterministic() {
    let s1 = default_manifold_schema(epoch());
    let s2 = default_manifold_schema(epoch());
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn enrichment_default_manifold_schema_has_required_keys() {
    let schema = default_manifold_schema(epoch());
    let required = schema.required_keys();
    assert!(!required.is_empty());
}

#[test]
fn enrichment_coordinate_serde_roundtrip() {
    let axes = vec![make_axis("a", ManifoldDimension::Workload, 0, 1_000_000)];
    let schema = ManifoldSchema::new("test", axes, epoch());
    let mut placer = ManifoldPlacer::new(schema);
    let raw = BTreeMap::from([("a".to_string(), 500_000i64)]);
    let coord = placer.place(&raw, None);
    let json = serde_json::to_string(&coord).unwrap();
    let back: ManifoldCoordinate = serde_json::from_str(&json).unwrap();
    assert_eq!(coord.coordinate_id, back.coordinate_id);
}
