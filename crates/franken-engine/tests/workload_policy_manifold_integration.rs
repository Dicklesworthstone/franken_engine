//! Integration tests for the workload_policy_manifold module (bd-1lsy.7.19.1, RGC-619A).
//!
//! Covers schema construction, axis validation, coordinate placement,
//! distance functions, neighborhoods, failure surface proximity,
//! trajectories, witness records, default axes, serde roundtrips,
//! determinism, and end-to-end pipeline.

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

use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::RegimeLabel;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_policy_manifold::{
    AxisDescriptor, BoundaryDirection, COMPONENT, COORDINATE_SCHEMA_VERSION, CoordinateIssueKind,
    DEFAULT_NEIGHBORHOOD_RADIUS, FailureBoundary, FailureProximity, FailureSurface,
    MANIFOLD_SCHEMA_VERSION, MAX_AXES_PER_DIMENSION, ManifoldCoordinate, ManifoldDimension,
    ManifoldNeighborhood, ManifoldOperation, ManifoldPlacer, ManifoldSchema, ManifoldTrajectory,
    ManifoldWitness, NEIGHBORHOOD_SCHEMA_VERSION, NeighborhoodBuilder, PlacementValidity,
    chebyshev_distance, default_cache_axes, default_hardware_axes, default_manifold_schema,
    default_policy_axes, default_workload_axes, manhattan_distance, squared_euclidean_distance,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn simple_axis(key: &str, dim: ManifoldDimension, required: bool) -> AxisDescriptor {
    AxisDescriptor {
        key: key.into(),
        dimension: dim,
        description: format!("test axis {key}"),
        unit: "units".into(),
        min_calibrated_millionths: 0,
        max_calibrated_millionths: MILLION,
        required,
    }
}

fn three_axis_schema() -> ManifoldSchema {
    ManifoldSchema::new(
        "test-schema-3ax",
        vec![
            AxisDescriptor {
                key: "rate".into(),
                dimension: ManifoldDimension::Workload,
                description: "Request rate".into(),
                unit: "ops/s".into(),
                min_calibrated_millionths: 0,
                max_calibrated_millionths: 1_000 * MILLION,
                required: true,
            },
            AxisDescriptor {
                key: "cores".into(),
                dimension: ManifoldDimension::Hardware,
                description: "CPU cores".into(),
                unit: "count".into(),
                min_calibrated_millionths: MILLION,
                max_calibrated_millionths: 128 * MILLION,
                required: true,
            },
            AxisDescriptor {
                key: "security".into(),
                dimension: ManifoldDimension::Policy,
                description: "Security level".into(),
                unit: "millionths".into(),
                min_calibrated_millionths: 0,
                max_calibrated_millionths: MILLION,
                required: false,
            },
        ],
        test_epoch(),
    )
}

fn raw2(rate: i64, cores: i64) -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    m.insert("rate".into(), rate);
    m.insert("cores".into(), cores);
    m
}

fn make_simple_coord(norm: BTreeMap<String, i64>) -> ManifoldCoordinate {
    ManifoldCoordinate {
        schema_version: "v1".into(),
        schema_id: "test".into(),
        coordinate_id: "c0".into(),
        raw_values: BTreeMap::new(),
        normalized_values: norm,
        validity: PlacementValidity::Valid,
        issues: vec![],
        regime_label: None,
        sequence: 0,
    }
}

// =========================================================================
// 1. Schema construction
// =========================================================================

#[test]
fn schema_new_sets_version_and_id() {
    let schema = three_axis_schema();
    assert_eq!(schema.schema_id, "test-schema-3ax");
    assert_eq!(schema.schema_version, MANIFOLD_SCHEMA_VERSION);
    assert_eq!(schema.epoch, test_epoch());
}

#[test]
fn schema_axis_count_matches_provided_axes() {
    let schema = three_axis_schema();
    assert_eq!(schema.axis_count(), 3);
}

#[test]
fn schema_empty_axes_gives_zero_count() {
    let schema = ManifoldSchema::new("empty", vec![], test_epoch());
    assert_eq!(schema.axis_count(), 0);
    assert!(schema.required_keys().is_empty());
}

#[test]
fn schema_required_keys_identifies_required_only() {
    let schema = three_axis_schema();
    let required = schema.required_keys();
    assert_eq!(required.len(), 2);
    assert!(required.contains("rate"));
    assert!(required.contains("cores"));
    assert!(!required.contains("security"));
}

#[test]
fn schema_axes_for_dimension_workload() {
    let schema = three_axis_schema();
    let workload_axes = schema.axes_for_dimension(ManifoldDimension::Workload);
    assert_eq!(workload_axes.len(), 1);
    assert_eq!(workload_axes[0].key, "rate");
}

#[test]
fn schema_axes_for_dimension_returns_empty_for_absent() {
    let schema = three_axis_schema();
    let cache_axes = schema.axes_for_dimension(ManifoldDimension::Cache);
    assert!(cache_axes.is_empty());
}

#[test]
fn schema_content_hash_is_deterministic() {
    let s1 = three_axis_schema();
    let s2 = three_axis_schema();
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn schema_different_epoch_produces_different_hash() {
    let s1 = ManifoldSchema::new("s", vec![], SecurityEpoch::from_raw(1));
    let s2 = ManifoldSchema::new("s", vec![], SecurityEpoch::from_raw(2));
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn schema_constants_are_valid() {
    assert!(!COMPONENT.is_empty());
    assert!(!MANIFOLD_SCHEMA_VERSION.is_empty());
    assert!(!COORDINATE_SCHEMA_VERSION.is_empty());
    assert!(!NEIGHBORHOOD_SCHEMA_VERSION.is_empty());
    assert!(MAX_AXES_PER_DIMENSION > 0);
    assert!(DEFAULT_NEIGHBORHOOD_RADIUS > 0);
}

// =========================================================================
// 2. Axis validation
// =========================================================================

#[test]
fn axis_is_in_range_boundaries() {
    let axis = AxisDescriptor {
        key: "x".into(),
        dimension: ManifoldDimension::Workload,
        description: "".into(),
        unit: "".into(),
        min_calibrated_millionths: 100,
        max_calibrated_millionths: 500,
        required: true,
    };
    assert!(axis.is_in_range(100));
    assert!(axis.is_in_range(300));
    assert!(axis.is_in_range(500));
    assert!(!axis.is_in_range(99));
    assert!(!axis.is_in_range(501));
}

#[test]
fn axis_normalize_full_range() {
    let axis = simple_axis("x", ManifoldDimension::Workload, true);
    assert_eq!(axis.normalize(0), Some(0));
    assert_eq!(axis.normalize(MILLION), Some(MILLION));
    assert_eq!(axis.normalize(500_000), Some(500_000));
}

#[test]
fn axis_normalize_out_of_range_returns_none() {
    let axis = simple_axis("x", ManifoldDimension::Workload, true);
    assert_eq!(axis.normalize(-1), None);
    assert_eq!(axis.normalize(MILLION + 1), None);
}

#[test]
fn axis_normalize_zero_range_gives_midpoint() {
    let axis = AxisDescriptor {
        key: "x".into(),
        dimension: ManifoldDimension::Workload,
        description: "".into(),
        unit: "".into(),
        min_calibrated_millionths: 42,
        max_calibrated_millionths: 42,
        required: true,
    };
    assert_eq!(axis.normalize(42), Some(MILLION / 2));
}

#[test]
fn axis_normalize_offset_range() {
    let axis = AxisDescriptor {
        key: "x".into(),
        dimension: ManifoldDimension::Workload,
        description: "".into(),
        unit: "".into(),
        min_calibrated_millionths: 200_000,
        max_calibrated_millionths: 800_000,
        required: true,
    };
    assert_eq!(axis.normalize(200_000), Some(0));
    assert_eq!(axis.normalize(800_000), Some(MILLION));
    assert_eq!(axis.normalize(500_000), Some(500_000));
}

#[test]
fn axis_content_hash_deterministic_across_calls() {
    let axis = simple_axis("test_axis", ManifoldDimension::Hardware, false);
    let h1 = axis.content_hash();
    let h2 = axis.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn axis_content_hash_differs_for_different_keys() {
    let a1 = simple_axis("alpha", ManifoldDimension::Workload, true);
    let a2 = simple_axis("beta", ManifoldDimension::Workload, true);
    assert_ne!(a1.content_hash(), a2.content_hash());
}

#[test]
fn axis_content_hash_differs_for_different_dimensions() {
    let a1 = simple_axis("same", ManifoldDimension::Workload, true);
    let a2 = simple_axis("same", ManifoldDimension::Hardware, true);
    assert_ne!(a1.content_hash(), a2.content_hash());
}

// =========================================================================
// 3. Coordinate placement
// =========================================================================

#[test]
fn placer_valid_placement_has_normalized_values() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    assert_eq!(coord.validity, PlacementValidity::Valid);
    assert!(coord.issues.is_empty());
    assert!(coord.normalized_values.contains_key("rate"));
    assert!(coord.normalized_values.contains_key("cores"));
}

#[test]
fn placer_missing_required_axis_reports_issue() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let mut values = BTreeMap::new();
    values.insert("rate".into(), 100 * MILLION);
    // Missing "cores"
    let coord = placer.place(&values, None);
    assert_eq!(coord.validity, PlacementValidity::MissingRequired);
    assert_eq!(coord.issues.len(), 1);
    assert_eq!(coord.issues[0].kind, CoordinateIssueKind::MissingRequired);
}

#[test]
fn placer_value_below_range_reports_below() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let mut values = BTreeMap::new();
    values.insert("rate".into(), 100 * MILLION);
    values.insert("cores".into(), 0); // below min of MILLION
    let coord = placer.place(&values, None);
    assert_eq!(coord.validity, PlacementValidity::OutOfRange);
    assert!(
        coord
            .issues
            .iter()
            .any(|i| i.kind == CoordinateIssueKind::BelowRange)
    );
}

#[test]
fn placer_value_above_range_reports_above() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let mut values = BTreeMap::new();
    values.insert("rate".into(), 100 * MILLION);
    values.insert("cores".into(), 200 * MILLION); // above max of 128M
    let coord = placer.place(&values, None);
    assert_eq!(coord.validity, PlacementValidity::OutOfRange);
    assert!(
        coord
            .issues
            .iter()
            .any(|i| i.kind == CoordinateIssueKind::AboveRange)
    );
}

#[test]
fn placer_missing_and_out_of_range_combined() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    // Missing "cores" (required) + "rate" out of range
    let mut values = BTreeMap::new();
    values.insert("rate".into(), -1);
    let coord = placer.place(&values, None);
    assert_eq!(coord.validity, PlacementValidity::MissingAndOutOfRange);
}

#[test]
fn placer_placed_count_increments() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    assert_eq!(placer.placed_count(), 0);
    let _ = placer.place(&raw2(100 * MILLION, 4 * MILLION), None);
    assert_eq!(placer.placed_count(), 1);
    let _ = placer.place(&raw2(200 * MILLION, 8 * MILLION), None);
    assert_eq!(placer.placed_count(), 2);
}

#[test]
fn placer_sequence_numbers_are_unique() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw2(100 * MILLION, 4 * MILLION), None);
    let c2 = placer.place(&raw2(200 * MILLION, 8 * MILLION), None);
    assert_eq!(c1.sequence, 0);
    assert_eq!(c2.sequence, 1);
    assert_ne!(c1.coordinate_id, c2.coordinate_id);
}

#[test]
fn placer_optional_axis_omitted_is_valid() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    assert_eq!(coord.validity, PlacementValidity::Valid);
    assert!(!coord.normalized_values.contains_key("security"));
}

#[test]
fn placer_with_regime_label_preserved() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let label = RegimeLabel::Classified(Regime::Normal);
    let coord = placer.place(&raw2(100 * MILLION, 4 * MILLION), Some(label));
    assert_eq!(coord.regime_label, Some(label));
}

#[test]
fn placer_abstention_regime_label() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(
        &raw2(100 * MILLION, 4 * MILLION),
        Some(RegimeLabel::Abstention),
    );
    assert_eq!(coord.regime_label, Some(RegimeLabel::Abstention));
}

// =========================================================================
// 4. Distance functions
// =========================================================================

#[test]
fn chebyshev_distance_identical_points_is_zero() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 500_000i64);
    a.insert("y".into(), 700_000i64);
    assert_eq!(chebyshev_distance(&a, &a), Some(0));
}

#[test]
fn chebyshev_distance_takes_max_axis_diff() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    a.insert("y".into(), 200_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 400_000i64);
    b.insert("y".into(), 300_000i64);
    assert_eq!(chebyshev_distance(&a, &b), Some(300_000));
}

#[test]
fn chebyshev_distance_no_shared_axes_returns_none() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    let mut b = BTreeMap::new();
    b.insert("y".into(), 200_000i64);
    assert_eq!(chebyshev_distance(&a, &b), None);
}

#[test]
fn chebyshev_distance_partial_overlap_uses_shared_only() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 0i64);
    a.insert("y".into(), 100_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 50_000i64);
    b.insert("z".into(), 999_999i64);
    assert_eq!(chebyshev_distance(&a, &b), Some(50_000));
}

#[test]
fn chebyshev_distance_empty_maps_returns_none() {
    let a: BTreeMap<String, i64> = BTreeMap::new();
    let b: BTreeMap<String, i64> = BTreeMap::new();
    assert_eq!(chebyshev_distance(&a, &b), None);
}

#[test]
fn manhattan_distance_sums_absolute_diffs() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    a.insert("y".into(), 200_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 400_000i64);
    b.insert("y".into(), 300_000i64);
    assert_eq!(manhattan_distance(&a, &b), Some(400_000));
}

#[test]
fn manhattan_distance_empty_maps_returns_none() {
    let a: BTreeMap<String, i64> = BTreeMap::new();
    let b: BTreeMap<String, i64> = BTreeMap::new();
    assert_eq!(manhattan_distance(&a, &b), None);
}

#[test]
fn squared_euclidean_distance_single_axis() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 0i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 100i64);
    assert_eq!(squared_euclidean_distance(&a, &b), Some(10_000));
}

#[test]
fn squared_euclidean_distance_identical_is_zero() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 42i64);
    a.insert("y".into(), 99i64);
    assert_eq!(squared_euclidean_distance(&a, &a), Some(0));
}

#[test]
fn squared_euclidean_distance_no_shared_axes_returns_none() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100i64);
    let mut b = BTreeMap::new();
    b.insert("y".into(), 200i64);
    assert_eq!(squared_euclidean_distance(&a, &b), None);
}

#[test]
fn distances_are_symmetric() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    a.insert("y".into(), 200_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 400_000i64);
    b.insert("y".into(), 300_000i64);
    assert_eq!(chebyshev_distance(&a, &b), chebyshev_distance(&b, &a));
    assert_eq!(manhattan_distance(&a, &b), manhattan_distance(&b, &a));
    assert_eq!(
        squared_euclidean_distance(&a, &b),
        squared_euclidean_distance(&b, &a)
    );
}

// =========================================================================
// 5. Neighborhood building
// =========================================================================

#[test]
fn neighborhood_includes_nearby_excludes_far() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let near = placer.place(&raw2(510 * MILLION, 64 * MILLION), None);
    let far = placer.place(&raw2(999 * MILLION, 128 * MILLION), None);

    let builder = NeighborhoodBuilder::new(100_000);
    let neighborhood = builder.build(&center, &[near.clone(), far.clone()], None);
    assert!(neighborhood.member_ids.contains(&near.coordinate_id));
    assert!(!neighborhood.member_ids.contains(&far.coordinate_id));
    assert_eq!(neighborhood.member_count, 1);
}

#[test]
fn neighborhood_excludes_center_from_members() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let builder = NeighborhoodBuilder::new(MILLION);
    let neighborhood = builder.build(&center, std::slice::from_ref(&center), None);
    assert_eq!(neighborhood.member_count, 0);
}

#[test]
fn neighborhood_radius_override_respected() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let candidate = placer.place(&raw2(510 * MILLION, 64 * MILLION), None);

    let builder = NeighborhoodBuilder::new(1); // tiny default
    let n1 = builder.build(&center, std::slice::from_ref(&candidate), None);
    assert_eq!(n1.member_count, 0);
    let n2 = builder.build(&center, std::slice::from_ref(&candidate), Some(MILLION));
    assert_eq!(n2.member_count, 1);
}

#[test]
fn neighborhood_excludes_invalid_coordinates() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);

    // Create an invalid coordinate (missing required axis "cores")
    let mut values = BTreeMap::new();
    values.insert("rate".into(), 500 * MILLION);
    let invalid = placer.place(&values, None);
    assert_ne!(invalid.validity, PlacementValidity::Valid);

    let builder = NeighborhoodBuilder::new(MILLION);
    let neighborhood = builder.build(&center, std::slice::from_ref(&invalid), None);
    assert_eq!(neighborhood.member_count, 0);
}

#[test]
fn neighborhood_empty_candidates() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let builder = NeighborhoodBuilder::new(MILLION);
    let neighborhood = builder.build(&center, &[], None);
    assert_eq!(neighborhood.member_count, 0);
    assert!(neighborhood.member_ids.is_empty());
}

// =========================================================================
// 6. Failure surface proximity
// =========================================================================

#[test]
fn failure_proximity_safe_margin_positive() {
    let surface = FailureSurface {
        surface_id: "cliff-1".into(),
        description: "High rate cliff".into(),
        relevant_axes: BTreeSet::from(["rate".into()]),
        boundary_thresholds: BTreeMap::from([(
            "rate".into(),
            FailureBoundary {
                threshold_millionths: 800_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("rate".into(), 500_000i64)]));
    let prox = surface.proximity(&coord);
    assert!(!prox.is_past_boundary);
    assert_eq!(prox.min_margin_millionths, 300_000);
    assert_eq!(prox.closest_axis, Some("rate".into()));
}

#[test]
fn failure_proximity_past_boundary_negative_margin() {
    let surface = FailureSurface {
        surface_id: "cliff-1".into(),
        description: "".into(),
        relevant_axes: BTreeSet::from(["rate".into()]),
        boundary_thresholds: BTreeMap::from([(
            "rate".into(),
            FailureBoundary {
                threshold_millionths: 800_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("rate".into(), 900_000i64)]));
    let prox = surface.proximity(&coord);
    assert!(prox.is_past_boundary);
    assert_eq!(prox.min_margin_millionths, -100_000);
}

#[test]
fn failure_proximity_exactly_at_boundary() {
    let surface = FailureSurface {
        surface_id: "edge".into(),
        description: "".into(),
        relevant_axes: BTreeSet::from(["x".into()]),
        boundary_thresholds: BTreeMap::from([(
            "x".into(),
            FailureBoundary {
                threshold_millionths: 500_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("x".into(), 500_000i64)]));
    let prox = surface.proximity(&coord);
    assert!(!prox.is_past_boundary); // margin == 0, not negative
    assert_eq!(prox.min_margin_millionths, 0);
}

#[test]
fn failure_proximity_below_direction_safe() {
    let surface = FailureSurface {
        surface_id: "oom".into(),
        description: "OOM cliff".into(),
        relevant_axes: BTreeSet::from(["memory".into()]),
        boundary_thresholds: BTreeMap::from([(
            "memory".into(),
            FailureBoundary {
                threshold_millionths: 100_000,
                direction: BoundaryDirection::Below,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("memory".into(), 300_000i64)]));
    let prox = surface.proximity(&coord);
    assert!(!prox.is_past_boundary);
    assert_eq!(prox.min_margin_millionths, 200_000);
}

#[test]
fn failure_proximity_below_direction_past() {
    let surface = FailureSurface {
        surface_id: "oom".into(),
        description: "".into(),
        relevant_axes: BTreeSet::from(["memory".into()]),
        boundary_thresholds: BTreeMap::from([(
            "memory".into(),
            FailureBoundary {
                threshold_millionths: 100_000,
                direction: BoundaryDirection::Below,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("memory".into(), 50_000i64)]));
    let prox = surface.proximity(&coord);
    assert!(prox.is_past_boundary);
    assert_eq!(prox.min_margin_millionths, -50_000);
}

#[test]
fn failure_proximity_multi_axis_takes_minimum() {
    let surface = FailureSurface {
        surface_id: "multi".into(),
        description: "".into(),
        relevant_axes: BTreeSet::from(["a".into(), "b".into()]),
        boundary_thresholds: BTreeMap::from([
            (
                "a".into(),
                FailureBoundary {
                    threshold_millionths: 800_000,
                    direction: BoundaryDirection::Above,
                },
            ),
            (
                "b".into(),
                FailureBoundary {
                    threshold_millionths: 600_000,
                    direction: BoundaryDirection::Above,
                },
            ),
        ]),
    };
    let coord = make_simple_coord(BTreeMap::from([
        ("a".into(), 500_000i64),
        ("b".into(), 550_000i64),
    ]));
    let prox = surface.proximity(&coord);
    // margin_a = 800k - 500k = 300k; margin_b = 600k - 550k = 50k
    assert_eq!(prox.min_margin_millionths, 50_000);
    assert_eq!(prox.closest_axis, Some("b".into()));
}

#[test]
fn failure_proximity_no_matching_axes_returns_zero() {
    let surface = FailureSurface {
        surface_id: "none".into(),
        description: "".into(),
        relevant_axes: BTreeSet::from(["nonexistent".into()]),
        boundary_thresholds: BTreeMap::from([(
            "nonexistent".into(),
            FailureBoundary {
                threshold_millionths: 500_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let coord = make_simple_coord(BTreeMap::from([("other".into(), 500_000i64)]));
    let prox = surface.proximity(&coord);
    assert_eq!(prox.min_margin_millionths, 0);
    assert!(prox.closest_axis.is_none());
}

// =========================================================================
// 7. Trajectory
// =========================================================================

#[test]
fn trajectory_from_multiple_coordinates() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coords: Vec<ManifoldCoordinate> = (0..5)
        .map(|i| placer.place(&raw2((100 + i * 100) * MILLION, 8 * MILLION), None))
        .collect();

    let traj = ManifoldTrajectory::from_coordinates("traj-1", &coords);
    assert_eq!(traj.step_count(), 4);
    assert_eq!(traj.trajectory_id, "traj-1");
    assert_eq!(traj.schema_id, "test-schema-3ax");
    assert!(traj.total_path_length > 0);
    assert!(traj.max_velocity() > 0);
}

#[test]
fn trajectory_empty_input_gives_zero_stats() {
    let traj = ManifoldTrajectory::from_coordinates("empty", &[]);
    assert_eq!(traj.step_count(), 0);
    assert_eq!(traj.total_path_length, 0);
    assert_eq!(traj.max_velocity(), 0);
    assert_eq!(traj.mean_velocity_millionths(), 0);
}

#[test]
fn trajectory_single_coordinate_gives_no_steps() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw2(500 * MILLION, 8 * MILLION), None);
    let traj = ManifoldTrajectory::from_coordinates("single", &[coord]);
    assert_eq!(traj.step_count(), 0);
    assert_eq!(traj.total_path_length, 0);
}

#[test]
fn trajectory_mean_velocity_positive_for_moving_trajectory() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c0 = placer.place(&raw2(0, 4 * MILLION), None);
    let c1 = placer.place(&raw2(500 * MILLION, 4 * MILLION), None);
    let c2 = placer.place(&raw2(1000 * MILLION, 4 * MILLION), None);
    let traj = ManifoldTrajectory::from_coordinates("uniform", &[c0, c1, c2]);
    assert_eq!(traj.step_count(), 2);
    assert!(traj.mean_velocity_millionths() > 0);
}

#[test]
fn trajectory_coordinate_ids_ordered() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c0 = placer.place(&raw2(100 * MILLION, 4 * MILLION), None);
    let c1 = placer.place(&raw2(200 * MILLION, 4 * MILLION), None);
    let c2 = placer.place(&raw2(300 * MILLION, 4 * MILLION), None);
    let traj =
        ManifoldTrajectory::from_coordinates("ordered", &[c0.clone(), c1.clone(), c2.clone()]);
    assert_eq!(traj.coordinate_ids[0], c0.coordinate_id);
    assert_eq!(traj.coordinate_ids[1], c1.coordinate_id);
    assert_eq!(traj.coordinate_ids[2], c2.coordinate_id);
}

// =========================================================================
// 8. Witness records
// =========================================================================

#[test]
fn witness_content_hash_determinism() {
    let w1 = ManifoldWitness::new(
        "w1",
        ManifoldOperation::Placement,
        "s1",
        test_epoch(),
        "placed coord",
    );
    let w2 = ManifoldWitness::new(
        "w1",
        ManifoldOperation::Placement,
        "s1",
        test_epoch(),
        "placed coord",
    );
    assert_eq!(w1.content_hash, w2.content_hash);
}

#[test]
fn witness_different_operations_yield_different_hashes() {
    let w1 = ManifoldWitness::new("w", ManifoldOperation::Placement, "s", test_epoch(), "d");
    let w2 = ManifoldWitness::new(
        "w",
        ManifoldOperation::ProximityCheck,
        "s",
        test_epoch(),
        "d",
    );
    assert_ne!(w1.content_hash, w2.content_hash);
}

#[test]
fn witness_different_details_yield_different_hashes() {
    let w1 = ManifoldWitness::new(
        "w",
        ManifoldOperation::Placement,
        "s",
        test_epoch(),
        "alpha",
    );
    let w2 = ManifoldWitness::new("w", ManifoldOperation::Placement, "s", test_epoch(), "beta");
    assert_ne!(w1.content_hash, w2.content_hash);
}

#[test]
fn witness_different_epochs_yield_different_hashes() {
    let w1 = ManifoldWitness::new(
        "w",
        ManifoldOperation::SchemaCreation,
        "s",
        SecurityEpoch::from_raw(1),
        "d",
    );
    let w2 = ManifoldWitness::new(
        "w",
        ManifoldOperation::SchemaCreation,
        "s",
        SecurityEpoch::from_raw(2),
        "d",
    );
    assert_ne!(w1.content_hash, w2.content_hash);
}

#[test]
fn witness_fields_populated() {
    let w = ManifoldWitness::new(
        "w-fields",
        ManifoldOperation::NeighborhoodBuild,
        "schema-42",
        test_epoch(),
        "some detail",
    );
    assert_eq!(w.witness_id, "w-fields");
    assert_eq!(w.operation, ManifoldOperation::NeighborhoodBuild);
    assert_eq!(w.schema_id, "schema-42");
    assert_eq!(w.epoch, test_epoch());
    assert_eq!(w.detail, "some detail");
}

// =========================================================================
// 9. Default axes
// =========================================================================

#[test]
fn default_workload_axes_all_workload_dimension() {
    for axis in default_workload_axes() {
        assert_eq!(axis.dimension, ManifoldDimension::Workload);
    }
}

#[test]
fn default_hardware_axes_all_hardware_dimension() {
    for axis in default_hardware_axes() {
        assert_eq!(axis.dimension, ManifoldDimension::Hardware);
    }
}

#[test]
fn default_policy_axes_all_policy_dimension() {
    for axis in default_policy_axes() {
        assert_eq!(axis.dimension, ManifoldDimension::Policy);
    }
}

#[test]
fn default_cache_axes_all_cache_dimension() {
    for axis in default_cache_axes() {
        assert_eq!(axis.dimension, ManifoldDimension::Cache);
    }
}

#[test]
fn default_axes_have_valid_ranges() {
    let all_axes: Vec<AxisDescriptor> = default_workload_axes()
        .into_iter()
        .chain(default_hardware_axes())
        .chain(default_policy_axes())
        .chain(default_cache_axes())
        .collect();
    for axis in &all_axes {
        assert!(
            axis.min_calibrated_millionths <= axis.max_calibrated_millionths,
            "Axis {} has min > max",
            axis.key
        );
    }
}

#[test]
fn default_manifold_schema_has_all_four_dimensions() {
    let schema = default_manifold_schema(test_epoch());
    assert!(
        !schema
            .axes_for_dimension(ManifoldDimension::Workload)
            .is_empty()
    );
    assert!(
        !schema
            .axes_for_dimension(ManifoldDimension::Hardware)
            .is_empty()
    );
    assert!(
        !schema
            .axes_for_dimension(ManifoldDimension::Policy)
            .is_empty()
    );
    assert!(
        !schema
            .axes_for_dimension(ManifoldDimension::Cache)
            .is_empty()
    );
}

#[test]
fn default_schema_required_keys_non_empty() {
    let schema = default_manifold_schema(test_epoch());
    assert!(!schema.required_keys().is_empty());
}

// =========================================================================
// 10. Serde roundtrips
// =========================================================================

#[test]
fn serde_roundtrip_manifold_schema() {
    let schema = three_axis_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

#[test]
fn serde_roundtrip_manifold_coordinate() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let json = serde_json::to_string(&coord).unwrap();
    let back: ManifoldCoordinate = serde_json::from_str(&json).unwrap();
    assert_eq!(coord, back);
}

#[test]
fn serde_roundtrip_manifold_neighborhood() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let near = placer.place(&raw2(510 * MILLION, 64 * MILLION), None);
    let builder = NeighborhoodBuilder::new(MILLION);
    let neighborhood = builder.build(&center, std::slice::from_ref(&near), None);
    let json = serde_json::to_string(&neighborhood).unwrap();
    let back: ManifoldNeighborhood = serde_json::from_str(&json).unwrap();
    assert_eq!(neighborhood, back);
}

#[test]
fn serde_roundtrip_manifold_trajectory() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coords: Vec<_> = (0..3)
        .map(|i| placer.place(&raw2((100 + i * 100) * MILLION, 8 * MILLION), None))
        .collect();
    let traj = ManifoldTrajectory::from_coordinates("t", &coords);
    let json = serde_json::to_string(&traj).unwrap();
    let back: ManifoldTrajectory = serde_json::from_str(&json).unwrap();
    assert_eq!(traj, back);
}

#[test]
fn serde_roundtrip_manifold_witness() {
    let w = ManifoldWitness::new(
        "w1",
        ManifoldOperation::TrajectoryBuild,
        "s1",
        test_epoch(),
        "test detail",
    );
    let json = serde_json::to_string(&w).unwrap();
    let back: ManifoldWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn serde_roundtrip_failure_surface() {
    let surface = FailureSurface {
        surface_id: "cliff".into(),
        description: "Test cliff".into(),
        relevant_axes: BTreeSet::from(["x".into(), "y".into()]),
        boundary_thresholds: BTreeMap::from([(
            "x".into(),
            FailureBoundary {
                threshold_millionths: 900_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let json = serde_json::to_string(&surface).unwrap();
    let back: FailureSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, back);
}

#[test]
fn serde_roundtrip_failure_proximity() {
    let prox = FailureProximity {
        surface_id: "s".into(),
        coordinate_id: "c".into(),
        min_margin_millionths: 42_000,
        axis_margins: BTreeMap::from([("x".into(), 42_000i64)]),
        is_past_boundary: false,
        closest_axis: Some("x".into()),
    };
    let json = serde_json::to_string(&prox).unwrap();
    let back: FailureProximity = serde_json::from_str(&json).unwrap();
    assert_eq!(prox, back);
}

#[test]
fn serde_roundtrip_default_schema() {
    let schema = default_manifold_schema(test_epoch());
    let json = serde_json::to_string(&schema).unwrap();
    let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

// =========================================================================
// 11. Determinism
// =========================================================================

#[test]
fn determinism_placement_same_inputs_same_coordinate() {
    let schema = three_axis_schema();
    let mut placer1 = ManifoldPlacer::new(schema.clone());
    let mut placer2 = ManifoldPlacer::new(schema);
    let values = raw2(500 * MILLION, 64 * MILLION);
    let c1 = placer1.place(&values, None);
    let c2 = placer2.place(&values, None);
    assert_eq!(c1.normalized_values, c2.normalized_values);
    assert_eq!(c1.validity, c2.validity);
    assert_eq!(c1.coordinate_id, c2.coordinate_id);
}

#[test]
fn determinism_neighborhood_same_inputs_same_members() {
    let schema = three_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw2(500 * MILLION, 64 * MILLION), None);
    let c1 = placer.place(&raw2(510 * MILLION, 64 * MILLION), None);
    let c2 = placer.place(&raw2(999 * MILLION, 128 * MILLION), None);

    let builder = NeighborhoodBuilder::new(100_000);
    let n1 = builder.build(&center, &[c1.clone(), c2.clone()], None);
    let n2 = builder.build(&center, &[c1, c2], None);
    assert_eq!(n1.member_ids, n2.member_ids);
}

#[test]
fn determinism_schema_hash_repeatable() {
    let h1 = three_axis_schema().content_hash();
    let h2 = three_axis_schema().content_hash();
    assert_eq!(h1, h2);
}

// =========================================================================
// 12. End-to-end pipeline
// =========================================================================

#[test]
fn end_to_end_schema_to_witness_pipeline() {
    // Step 1: Schema construction
    let schema = default_manifold_schema(test_epoch());
    assert!(schema.axis_count() > 0);

    // Step 2: Create placer
    let mut placer = ManifoldPlacer::new(schema.clone());

    // Step 3: Place several coordinates
    let mut coords = Vec::new();
    for i in 0..5 {
        let mut values = BTreeMap::new();
        values.insert("request_rate_ops".into(), (1000 + i * 500) * MILLION);
        values.insert("concurrency_level".into(), (10 + i) * MILLION);
        values.insert("core_count".into(), 8 * MILLION);
        values.insert("security_level".into(), 500_000);
        let coord = placer.place(&values, Some(RegimeLabel::Classified(Regime::Normal)));
        assert_eq!(coord.validity, PlacementValidity::Valid);
        coords.push(coord);
    }
    assert_eq!(placer.placed_count(), 5);

    // Step 4: Build neighborhood
    let builder = NeighborhoodBuilder::new(DEFAULT_NEIGHBORHOOD_RADIUS);
    let neighborhood = builder.build(&coords[0], &coords, None);
    assert!(!neighborhood.member_ids.contains(&coords[0].coordinate_id));

    // Step 5: Failure surface proximity
    let surface = FailureSurface {
        surface_id: "rate-cliff".into(),
        description: "High request rate failure surface".into(),
        relevant_axes: BTreeSet::from(["request_rate_ops".into()]),
        boundary_thresholds: BTreeMap::from([(
            "request_rate_ops".into(),
            FailureBoundary {
                threshold_millionths: 950_000,
                direction: BoundaryDirection::Above,
            },
        )]),
    };
    let prox = surface.proximity(&coords[0]);
    assert!(!prox.is_past_boundary);
    assert!(prox.min_margin_millionths > 0);

    // Step 6: Trajectory
    let traj = ManifoldTrajectory::from_coordinates("e2e-traj", &coords);
    assert_eq!(traj.step_count(), 4);
    assert!(traj.total_path_length > 0);
    assert!(traj.max_velocity() > 0);
    assert!(traj.mean_velocity_millionths() > 0);

    // Step 7: Witness
    let witness = ManifoldWitness::new(
        "e2e-witness",
        ManifoldOperation::TrajectoryBuild,
        &schema.schema_id,
        test_epoch(),
        "end-to-end pipeline test",
    );
    assert_eq!(witness.operation, ManifoldOperation::TrajectoryBuild);
    let witness2 = ManifoldWitness::new(
        "e2e-witness",
        ManifoldOperation::TrajectoryBuild,
        &schema.schema_id,
        test_epoch(),
        "end-to-end pipeline test",
    );
    assert_eq!(witness.content_hash, witness2.content_hash);

    // Step 8: Serde roundtrip of the trajectory
    let json = serde_json::to_string(&traj).unwrap();
    let back: ManifoldTrajectory = serde_json::from_str(&json).unwrap();
    assert_eq!(traj, back);
}
