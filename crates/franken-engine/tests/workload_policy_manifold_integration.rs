//! Integration tests for the workload-policy manifold module (RGC-619A).

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

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn simple_axis(key: &str, dim: ManifoldDimension) -> AxisDescriptor {
    AxisDescriptor {
        key: key.into(),
        dimension: dim,
        description: format!("test axis {key}"),
        unit: "units".into(),
        min_calibrated_millionths: 0,
        max_calibrated_millionths: 1_000_000,
        required: true,
    }
}

fn two_axis_schema() -> ManifoldSchema {
    ManifoldSchema::new(
        "test-schema",
        vec![
            simple_axis("x", ManifoldDimension::Workload),
            simple_axis("y", ManifoldDimension::Hardware),
        ],
        test_epoch(),
    )
}

fn raw_values(x: i64, y: i64) -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    m.insert("x".into(), x);
    m.insert("y".into(), y);
    m
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!MANIFOLD_SCHEMA_VERSION.is_empty());
    assert!(!COORDINATE_SCHEMA_VERSION.is_empty());
    assert!(!NEIGHBORHOOD_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_unique() {
    let versions = [
        MANIFOLD_SCHEMA_VERSION,
        COORDINATE_SCHEMA_VERSION,
        NEIGHBORHOOD_SCHEMA_VERSION,
    ];
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert_ne!(versions[i], versions[j]);
        }
    }
}

#[test]
fn max_axes_positive() {
    const { assert!(MAX_AXES_PER_DIMENSION > 0) };
}

#[test]
fn default_neighborhood_radius_positive() {
    const { assert!(DEFAULT_NEIGHBORHOOD_RADIUS > 0) };
}

// ---------------------------------------------------------------------------
// ManifoldDimension
// ---------------------------------------------------------------------------

#[test]
fn dimension_display_all_variants() {
    let dims = [
        ManifoldDimension::Workload,
        ManifoldDimension::Hardware,
        ManifoldDimension::Cache,
        ManifoldDimension::Policy,
    ];
    for d in &dims {
        let s = format!("{d}");
        assert!(!s.is_empty());
    }
}

#[test]
fn dimension_serde_round_trip() {
    for d in [
        ManifoldDimension::Workload,
        ManifoldDimension::Hardware,
        ManifoldDimension::Cache,
        ManifoldDimension::Policy,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: ManifoldDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// PlacementValidity
// ---------------------------------------------------------------------------

#[test]
fn placement_validity_display() {
    for v in [
        PlacementValidity::Valid,
        PlacementValidity::MissingRequired,
        PlacementValidity::OutOfRange,
        PlacementValidity::MissingAndOutOfRange,
    ] {
        assert!(!format!("{v}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// CoordinateIssueKind
// ---------------------------------------------------------------------------

#[test]
fn coordinate_issue_kind_display() {
    for k in [
        CoordinateIssueKind::MissingRequired,
        CoordinateIssueKind::BelowRange,
        CoordinateIssueKind::AboveRange,
    ] {
        assert!(!format!("{k}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// BoundaryDirection
// ---------------------------------------------------------------------------

#[test]
fn boundary_direction_display() {
    assert_eq!(format!("{}", BoundaryDirection::Above), "above");
    assert_eq!(format!("{}", BoundaryDirection::Below), "below");
}

// ---------------------------------------------------------------------------
// ManifoldOperation
// ---------------------------------------------------------------------------

#[test]
fn manifold_operation_display() {
    for op in [
        ManifoldOperation::Placement,
        ManifoldOperation::NeighborhoodBuild,
        ManifoldOperation::ProximityCheck,
        ManifoldOperation::TrajectoryBuild,
        ManifoldOperation::SchemaCreation,
    ] {
        assert!(!format!("{op}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// AxisDescriptor
// ---------------------------------------------------------------------------

#[test]
fn axis_in_range_checks() {
    let axis = simple_axis("test", ManifoldDimension::Workload);
    assert!(axis.is_in_range(0));
    assert!(axis.is_in_range(500_000));
    assert!(axis.is_in_range(1_000_000));
    assert!(!axis.is_in_range(-1));
    assert!(!axis.is_in_range(1_000_001));
}

#[test]
fn axis_normalize() {
    let axis = AxisDescriptor {
        key: "test".into(),
        dimension: ManifoldDimension::Workload,
        description: "test".into(),
        unit: "u".into(),
        min_calibrated_millionths: 0,
        max_calibrated_millionths: 1_000_000,
        required: true,
    };
    assert_eq!(axis.normalize(0), Some(0));
    assert_eq!(axis.normalize(500_000), Some(500_000));
    assert_eq!(axis.normalize(1_000_000), Some(1_000_000));
}

#[test]
fn axis_normalize_shifted_range() {
    let axis = AxisDescriptor {
        key: "test".into(),
        dimension: ManifoldDimension::Workload,
        description: "test".into(),
        unit: "u".into(),
        min_calibrated_millionths: 200_000,
        max_calibrated_millionths: 800_000,
        required: true,
    };
    // Value at min should normalize to 0
    assert_eq!(axis.normalize(200_000), Some(0));
    // Value at max should normalize to 1_000_000
    assert_eq!(axis.normalize(800_000), Some(1_000_000));
}

#[test]
fn axis_content_hash_deterministic() {
    let a1 = simple_axis("x", ManifoldDimension::Workload);
    let a2 = simple_axis("x", ManifoldDimension::Workload);
    assert_eq!(a1.content_hash(), a2.content_hash());
}

#[test]
fn axis_content_hash_differs() {
    let a1 = simple_axis("x", ManifoldDimension::Workload);
    let a2 = simple_axis("y", ManifoldDimension::Workload);
    assert_ne!(a1.content_hash(), a2.content_hash());
}

#[test]
fn axis_serde_round_trip() {
    let axis = simple_axis("test", ManifoldDimension::Cache);
    let json = serde_json::to_string(&axis).unwrap();
    let back: AxisDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(axis, back);
}

// ---------------------------------------------------------------------------
// ManifoldSchema
// ---------------------------------------------------------------------------

#[test]
fn schema_construction() {
    let schema = two_axis_schema();
    assert_eq!(schema.axis_count(), 2);
    assert_eq!(schema.schema_version, MANIFOLD_SCHEMA_VERSION);
}

#[test]
fn schema_axes_for_dimension() {
    let schema = two_axis_schema();
    let workload = schema.axes_for_dimension(ManifoldDimension::Workload);
    assert_eq!(workload.len(), 1);
    assert_eq!(workload[0].key, "x");
}

#[test]
fn schema_required_keys() {
    let schema = two_axis_schema();
    let required = schema.required_keys();
    assert!(required.contains("x"));
    assert!(required.contains("y"));
}

#[test]
fn schema_content_hash_deterministic() {
    let s1 = two_axis_schema();
    let s2 = two_axis_schema();
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn schema_serde_round_trip() {
    let schema = two_axis_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

// ---------------------------------------------------------------------------
// ManifoldPlacer
// ---------------------------------------------------------------------------

#[test]
fn placer_valid_placement() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw_values(500_000, 500_000), None);
    assert_eq!(coord.validity, PlacementValidity::Valid);
    assert!(coord.issues.is_empty());
}

#[test]
fn placer_missing_required_axis() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let mut vals = BTreeMap::new();
    vals.insert("x".into(), 500_000i64);
    // Missing "y"
    let coord = placer.place(&vals, None);
    assert_ne!(coord.validity, PlacementValidity::Valid);
    assert!(!coord.issues.is_empty());
}

#[test]
fn placer_out_of_range() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw_values(2_000_000, 500_000), None);
    assert_ne!(coord.validity, PlacementValidity::Valid);
}

#[test]
fn placer_sequence_increments() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(100_000, 100_000), None);
    let c2 = placer.place(&raw_values(200_000, 200_000), None);
    assert!(c2.sequence > c1.sequence);
    assert_eq!(placer.placed_count(), 2);
}

#[test]
fn placer_coordinate_ids_unique() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(100_000, 100_000), None);
    let c2 = placer.place(&raw_values(200_000, 200_000), None);
    assert_ne!(c1.coordinate_id, c2.coordinate_id);
}

#[test]
fn placer_coordinate_serde_round_trip() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw_values(500_000, 500_000), None);
    let json = serde_json::to_string(&coord).unwrap();
    let back: ManifoldCoordinate = serde_json::from_str(&json).unwrap();
    assert_eq!(coord, back);
}

// ---------------------------------------------------------------------------
// Distance functions
// ---------------------------------------------------------------------------

#[test]
fn chebyshev_distance_same_point_is_zero() {
    let a = raw_values(500_000, 500_000);
    let norm_a: BTreeMap<String, i64> = a; // already normalized conceptually
    assert_eq!(chebyshev_distance(&norm_a, &norm_a), Some(0));
}

#[test]
fn chebyshev_distance_measures_max_axis_diff() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    a.insert("y".into(), 200_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 400_000i64);
    b.insert("y".into(), 300_000i64);
    let dist = chebyshev_distance(&a, &b).unwrap();
    // max(|400k - 100k|, |300k - 200k|) = max(300k, 100k) = 300k
    assert_eq!(dist, 300_000);
}

#[test]
fn manhattan_distance_sums_axes() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100_000i64);
    a.insert("y".into(), 200_000i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 400_000i64);
    b.insert("y".into(), 300_000i64);
    let dist = manhattan_distance(&a, &b).unwrap();
    // |400k - 100k| + |300k - 200k| = 300k + 100k = 400k
    assert_eq!(dist, 400_000);
}

#[test]
fn squared_euclidean_distance_computes_sum_of_squares() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 0i64);
    let mut b = BTreeMap::new();
    b.insert("x".into(), 3i64);
    let dist = squared_euclidean_distance(&a, &b).unwrap();
    assert_eq!(dist, 9);
}

#[test]
fn distance_empty_maps_returns_none() {
    let a: BTreeMap<String, i64> = BTreeMap::new();
    // Empty maps have no shared axes, so distances are undefined
    assert_eq!(chebyshev_distance(&a, &a), None);
    assert_eq!(manhattan_distance(&a, &a), None);
    assert_eq!(squared_euclidean_distance(&a, &a), None);
}

#[test]
fn distance_mismatched_keys_returns_none() {
    let mut a = BTreeMap::new();
    a.insert("x".into(), 100i64);
    let mut b = BTreeMap::new();
    b.insert("y".into(), 100i64);
    assert!(chebyshev_distance(&a, &b).is_none());
}

// ---------------------------------------------------------------------------
// NeighborhoodBuilder
// ---------------------------------------------------------------------------

#[test]
fn neighborhood_builder_includes_close_points() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw_values(500_000, 500_000), None);
    let near = placer.place(&raw_values(510_000, 510_000), None);
    let far = placer.place(&raw_values(900_000, 900_000), None);

    let builder = NeighborhoodBuilder::new(100_000);
    let neighborhood = builder.build(&center, &[near.clone(), far.clone()], None);

    assert!(neighborhood.member_ids.contains(&near.coordinate_id));
    assert!(!neighborhood.member_ids.contains(&far.coordinate_id));
}

#[test]
fn neighborhood_builder_radius_override() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw_values(500_000, 500_000), None);
    let other = placer.place(&raw_values(900_000, 900_000), None);

    let builder = NeighborhoodBuilder::new(10_000);
    // Small default radius excludes the point
    let n1 = builder.build(&center, std::slice::from_ref(&other), None);
    assert!(n1.member_ids.is_empty());

    // Large override includes the point
    let n2 = builder.build(&center, std::slice::from_ref(&other), Some(1_000_000));
    assert!(!n2.member_ids.is_empty());
}

#[test]
fn neighborhood_serde_round_trip() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let center = placer.place(&raw_values(500_000, 500_000), None);
    let builder = NeighborhoodBuilder::new(100_000);
    let neighborhood = builder.build(&center, &[], None);
    let json = serde_json::to_string(&neighborhood).unwrap();
    let back: ManifoldNeighborhood = serde_json::from_str(&json).unwrap();
    assert_eq!(neighborhood, back);
}

// ---------------------------------------------------------------------------
// FailureSurface / FailureProximity
// ---------------------------------------------------------------------------

#[test]
fn failure_surface_proximity_safe() {
    let mut thresholds = BTreeMap::new();
    thresholds.insert(
        "x".into(),
        FailureBoundary {
            threshold_millionths: 900_000,
            direction: BoundaryDirection::Above,
        },
    );
    let mut relevant = BTreeSet::new();
    relevant.insert("x".into());
    let surface = FailureSurface {
        surface_id: "sf-1".into(),
        description: "test surface".into(),
        relevant_axes: relevant,
        boundary_thresholds: thresholds,
    };
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw_values(500_000, 500_000), None);
    let prox = surface.proximity(&coord);
    assert!(!prox.is_past_boundary);
    assert!(prox.min_margin_millionths > 0);
}

#[test]
fn failure_surface_proximity_past_boundary() {
    let mut thresholds = BTreeMap::new();
    thresholds.insert(
        "x".into(),
        FailureBoundary {
            threshold_millionths: 400_000,
            direction: BoundaryDirection::Above,
        },
    );
    let mut relevant = BTreeSet::new();
    relevant.insert("x".into());
    let surface = FailureSurface {
        surface_id: "sf-2".into(),
        description: "test surface".into(),
        relevant_axes: relevant,
        boundary_thresholds: thresholds,
    };
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let coord = placer.place(&raw_values(500_000, 500_000), None);
    let prox = surface.proximity(&coord);
    assert!(prox.is_past_boundary);
}

#[test]
fn failure_proximity_serde_round_trip() {
    let prox = FailureProximity {
        surface_id: "sf-1".into(),
        coordinate_id: "coord-1".into(),
        min_margin_millionths: 100_000,
        axis_margins: BTreeMap::new(),
        is_past_boundary: false,
        closest_axis: Some("x".into()),
    };
    let json = serde_json::to_string(&prox).unwrap();
    let back: FailureProximity = serde_json::from_str(&json).unwrap();
    assert_eq!(prox, back);
}

// ---------------------------------------------------------------------------
// ManifoldTrajectory
// ---------------------------------------------------------------------------

#[test]
fn trajectory_from_single_coordinate() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(500_000, 500_000), None);
    let traj = ManifoldTrajectory::from_coordinates("t-1", &[c1]);
    assert_eq!(traj.step_count(), 0);
    assert_eq!(traj.total_path_length, 0);
}

#[test]
fn trajectory_from_two_coordinates() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(100_000, 100_000), None);
    let c2 = placer.place(&raw_values(400_000, 200_000), None);
    let traj = ManifoldTrajectory::from_coordinates("t-2", &[c1, c2]);
    assert_eq!(traj.step_count(), 1);
    assert!(traj.total_path_length > 0);
    assert_eq!(traj.max_velocity(), traj.total_path_length);
}

#[test]
fn trajectory_three_steps() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(100_000, 100_000), None);
    let c2 = placer.place(&raw_values(200_000, 200_000), None);
    let c3 = placer.place(&raw_values(300_000, 300_000), None);
    let traj = ManifoldTrajectory::from_coordinates("t-3", &[c1, c2, c3]);
    assert_eq!(traj.step_count(), 2);
    assert!(traj.mean_velocity_millionths() > 0);
}

#[test]
fn trajectory_serde_round_trip() {
    let schema = two_axis_schema();
    let mut placer = ManifoldPlacer::new(schema);
    let c1 = placer.place(&raw_values(100_000, 100_000), None);
    let c2 = placer.place(&raw_values(200_000, 200_000), None);
    let traj = ManifoldTrajectory::from_coordinates("t-serde", &[c1, c2]);
    let json = serde_json::to_string(&traj).unwrap();
    let back: ManifoldTrajectory = serde_json::from_str(&json).unwrap();
    assert_eq!(traj, back);
}

// ---------------------------------------------------------------------------
// ManifoldWitness
// ---------------------------------------------------------------------------

#[test]
fn witness_construction() {
    let w = ManifoldWitness::new(
        "w-1",
        ManifoldOperation::Placement,
        "test-schema",
        test_epoch(),
        "placed coordinate",
    );
    assert_eq!(w.witness_id, "w-1");
    assert_eq!(w.operation, ManifoldOperation::Placement);
}

#[test]
fn witness_content_hash_deterministic() {
    let w1 = ManifoldWitness::new(
        "w-1",
        ManifoldOperation::Placement,
        "test-schema",
        test_epoch(),
        "placed",
    );
    let w2 = ManifoldWitness::new(
        "w-1",
        ManifoldOperation::Placement,
        "test-schema",
        test_epoch(),
        "placed",
    );
    assert_eq!(w1.content_hash, w2.content_hash);
}

#[test]
fn witness_serde_round_trip() {
    let w = ManifoldWitness::new(
        "w-serde",
        ManifoldOperation::ProximityCheck,
        "test-schema",
        test_epoch(),
        "proximity check",
    );
    let json = serde_json::to_string(&w).unwrap();
    let back: ManifoldWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// Default axis factories
// ---------------------------------------------------------------------------

#[test]
fn default_workload_axes_non_empty() {
    let axes = default_workload_axes();
    assert!(!axes.is_empty());
    for a in &axes {
        assert_eq!(a.dimension, ManifoldDimension::Workload);
    }
}

#[test]
fn default_hardware_axes_non_empty() {
    let axes = default_hardware_axes();
    assert!(!axes.is_empty());
    for a in &axes {
        assert_eq!(a.dimension, ManifoldDimension::Hardware);
    }
}

#[test]
fn default_policy_axes_non_empty() {
    let axes = default_policy_axes();
    assert!(!axes.is_empty());
    for a in &axes {
        assert_eq!(a.dimension, ManifoldDimension::Policy);
    }
}

#[test]
fn default_cache_axes_non_empty() {
    let axes = default_cache_axes();
    assert!(!axes.is_empty());
    for a in &axes {
        assert_eq!(a.dimension, ManifoldDimension::Cache);
    }
}

#[test]
fn default_manifold_schema_has_all_dimensions() {
    let schema = default_manifold_schema(test_epoch());
    assert!(schema.axis_count() >= 4);
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

#[test]
fn default_schema_serde_round_trip() {
    let schema = default_manifold_schema(test_epoch());
    let json = serde_json::to_string(&schema).unwrap();
    let back: ManifoldSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

// ---------------------------------------------------------------------------
// End-to-end: place → neighborhood → proximity → trajectory
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_workflow() {
    let schema = default_manifold_schema(test_epoch());
    let mut placer = ManifoldPlacer::new(schema);

    // Build raw values from the default schema's required keys
    let required: Vec<String> = placer.schema.required_keys().into_iter().collect();
    let mut vals = BTreeMap::new();
    for (i, key) in required.iter().enumerate() {
        let axis = &placer.schema.axes[key];
        let mid = (axis.min_calibrated_millionths + axis.max_calibrated_millionths) / 2;
        vals.insert(key.clone(), mid + (i as i64 * 1000));
    }

    let c1 = placer.place(&vals, None);
    assert_eq!(c1.validity, PlacementValidity::Valid);

    // Shift values slightly for c2
    let mut vals2 = vals.clone();
    for v in vals2.values_mut() {
        *v += 10_000;
    }
    let c2 = placer.place(&vals2, None);
    assert_eq!(c2.validity, PlacementValidity::Valid);

    // Build neighborhood
    let builder = NeighborhoodBuilder::new(DEFAULT_NEIGHBORHOOD_RADIUS);
    let neighborhood = builder.build(&c1, std::slice::from_ref(&c2), None);
    assert!(neighborhood.member_count <= 1);

    // Build trajectory
    let traj = ManifoldTrajectory::from_coordinates("e2e", &[c1, c2]);
    assert_eq!(traj.step_count(), 1);
    assert!(traj.total_path_length >= 0);
}
