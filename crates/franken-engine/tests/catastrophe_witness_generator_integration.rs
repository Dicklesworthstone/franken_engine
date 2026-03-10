//! Integration tests for the catastrophe witness generator (RGC-619B).

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

use frankenengine_engine::catastrophe_witness_generator::{
    self, BEAD_ID, BoundaryKind, COMPONENT, MILLIONTHS, ManifoldCoordinate, POLICY_ID, PhaseRegion,
    SCHEMA_VERSION, WitnessError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn coord(name: &str, value: i64) -> ManifoldCoordinate {
    ManifoldCoordinate::new(name, value)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("catastrophe"));
}

#[test]
fn test_bead_id() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "catastrophe_witness_generator");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-619B");
}

#[test]
fn test_millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// PhaseRegion
// ---------------------------------------------------------------------------

#[test]
fn test_phase_region_is_win() {
    assert!(PhaseRegion::RobustWin.is_win());
    assert!(PhaseRegion::BrittleWin.is_win());
    assert!(!PhaseRegion::Neutral.is_win());
    assert!(!PhaseRegion::BrittleLoss.is_win());
    assert!(!PhaseRegion::RobustLoss.is_win());
}

#[test]
fn test_phase_region_is_brittle() {
    assert!(!PhaseRegion::RobustWin.is_brittle());
    assert!(PhaseRegion::BrittleWin.is_brittle());
    assert!(!PhaseRegion::Neutral.is_brittle());
    assert!(PhaseRegion::BrittleLoss.is_brittle());
    assert!(!PhaseRegion::RobustLoss.is_brittle());
}

#[test]
fn test_phase_region_label() {
    assert_eq!(PhaseRegion::RobustWin.label(), "robust_win");
    assert_eq!(PhaseRegion::BrittleLoss.label(), "brittle_loss");
    assert_eq!(PhaseRegion::Neutral.label(), "neutral");
}

#[test]
fn test_phase_region_display() {
    let s = format!("{}", PhaseRegion::RobustWin);
    assert_eq!(s, "robust_win");
}

#[test]
fn test_phase_region_serde_roundtrip() {
    let region = PhaseRegion::BrittleWin;
    let json = serde_json::to_string(&region).unwrap();
    let back: PhaseRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

// ---------------------------------------------------------------------------
// BoundaryKind
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_kind_label() {
    assert_eq!(BoundaryKind::Fold.label(), "fold");
    assert_eq!(BoundaryKind::Cusp.label(), "cusp");
    assert_eq!(BoundaryKind::CliffEdge.label(), "cliff_edge");
}

#[test]
fn test_boundary_kind_from_sharpness_cliff_edge() {
    let kind = BoundaryKind::from_sharpness_and_dims(11_000_000, 1);
    assert_eq!(kind, BoundaryKind::CliffEdge);
}

#[test]
fn test_boundary_kind_from_sharpness_jump() {
    let kind = BoundaryKind::from_sharpness_and_dims(6_000_000, 1);
    assert_eq!(kind, BoundaryKind::Jump);
}

#[test]
fn test_boundary_kind_from_sharpness_fold() {
    let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 1);
    assert_eq!(kind, BoundaryKind::Fold);
}

#[test]
fn test_boundary_kind_from_sharpness_gradual() {
    let kind = BoundaryKind::from_sharpness_and_dims(1_000_000, 1);
    assert_eq!(kind, BoundaryKind::GradualTransition);
}

#[test]
fn test_boundary_kind_from_sharpness_cusp() {
    let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 2);
    assert_eq!(kind, BoundaryKind::Cusp);
}

#[test]
fn test_boundary_kind_from_sharpness_swallowtail() {
    let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 3);
    assert_eq!(kind, BoundaryKind::Swallowtail);
}

#[test]
fn test_boundary_kind_serde_roundtrip() {
    let kind = BoundaryKind::Jump;
    let json = serde_json::to_string(&kind).unwrap();
    let back: BoundaryKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, back);
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate
// ---------------------------------------------------------------------------

#[test]
fn test_manifold_coordinate_new() {
    let c = ManifoldCoordinate::new("lr", 500_000);
    assert_eq!(c.dimension_name, "lr");
    assert_eq!(c.value_millionths, 500_000);
}

#[test]
fn test_manifold_coordinate_squared_distance_same_dim() {
    let a = coord("x", 100_000);
    let b = coord("x", 300_000);
    let dist = a.squared_distance(&b).unwrap();
    assert_eq!(dist, (200_000i128) * (200_000i128));
}

#[test]
fn test_manifold_coordinate_squared_distance_different_dim() {
    let a = coord("x", 100_000);
    let b = coord("y", 300_000);
    assert!(a.squared_distance(&b).is_none());
}

#[test]
fn test_manifold_coordinate_display() {
    let c = coord("lr", 500_000);
    let s = format!("{c}");
    assert!(s.contains("lr"));
    assert!(s.contains("500000"));
}

// ---------------------------------------------------------------------------
// classify_region
// ---------------------------------------------------------------------------

#[test]
fn test_classify_region_robust_win() {
    let region = catastrophe_witness_generator::classify_region(2_000_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::RobustWin);
}

#[test]
fn test_classify_region_brittle_win() {
    let region = catastrophe_witness_generator::classify_region(500_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::BrittleWin);
}

#[test]
fn test_classify_region_neutral() {
    let region = catastrophe_witness_generator::classify_region(100_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::Neutral);
}

#[test]
fn test_classify_region_brittle_loss() {
    let region = catastrophe_witness_generator::classify_region(-500_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::BrittleLoss);
}

#[test]
fn test_classify_region_robust_loss() {
    let region = catastrophe_witness_generator::classify_region(-2_000_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::RobustLoss);
}

// ---------------------------------------------------------------------------
// detect_boundary
// ---------------------------------------------------------------------------

#[test]
fn test_detect_boundary_ok() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let result = catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000);
    assert!(result.is_ok());
    let boundary = result.unwrap();
    assert!(!boundary.boundary_id.is_empty());
    assert!(boundary.is_critical());
}

#[test]
fn test_detect_boundary_same_region_error() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 1)];
    let result = catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, 2_000_001);
    assert!(matches!(result, Err(WitnessError::NoBoundaryDetected)));
}

// ---------------------------------------------------------------------------
// generate_witness
// ---------------------------------------------------------------------------

#[test]
fn test_generate_witness_ok() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary,
        "input-data",
        1_000_000,
        -500_000,
        "throughput",
    )
    .unwrap();
    assert!(!witness.witness_id.is_empty());
    assert!(witness.is_regression());
    assert_eq!(witness.delta_millionths, -1_500_000);
    assert_eq!(witness.magnitude(), 1_500_000);
    assert!(!witness.minimal);
}

#[test]
fn test_generate_witness_input_too_large() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let large_input = "x".repeat(65_537);
    let result = catastrophe_witness_generator::generate_witness(
        &boundary,
        &large_input,
        1_000_000,
        -500_000,
        "throughput",
    );
    assert!(matches!(result, Err(WitnessError::InputTooLarge)));
}

// ---------------------------------------------------------------------------
// minimize_witness
// ---------------------------------------------------------------------------

#[test]
fn test_minimize_witness_ok() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary,
        "test-input",
        1_000_000,
        -500_000,
        "throughput",
    )
    .unwrap();
    if witness.replay_steps > 1 {
        let result = catastrophe_witness_generator::minimize_witness(&witness);
        assert!(result.is_ok());
        let min_result = result.unwrap();
        assert!(min_result.minimized_witness.minimal);
        assert!(min_result.steps_removed > 0);
    }
}

// ---------------------------------------------------------------------------
// compute_boundary_sharpness
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_sharpness_zero_distance() {
    let sharpness =
        catastrophe_witness_generator::compute_boundary_sharpness(1_000_000, -1_000_000, 0);
    assert!(sharpness > 0);
}

#[test]
fn test_boundary_sharpness_large_distance() {
    let sharpness =
        catastrophe_witness_generator::compute_boundary_sharpness(1_000_000, 900_000, 1_000_000);
    assert!(sharpness > 0);
}

// ---------------------------------------------------------------------------
// build_brittleness_report
// ---------------------------------------------------------------------------

#[test]
fn test_build_brittleness_report_empty() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    assert_eq!(report.brittle_region_count, 0);
    assert!(!report.has_critical_boundaries());
    assert_eq!(report.regression_count(), 0);
}

#[test]
fn test_build_brittleness_report_with_data() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary, "input", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    let report = catastrophe_witness_generator::build_brittleness_report(
        test_epoch(),
        vec![boundary],
        vec![witness],
    )
    .unwrap();
    assert!(report.has_critical_boundaries());
    assert_eq!(report.regression_count(), 1);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_nonempty() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert!(!manifest.report_id.is_empty());
    assert!(!manifest.boundaries.is_empty());
}

#[test]
fn test_manifest_deterministic() {
    let a = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    let b = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert_eq!(a.report_id, b.report_id);
}
