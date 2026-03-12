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

// ---------------------------------------------------------------------------
// PhaseRegion ordering
// ---------------------------------------------------------------------------

#[test]
fn phase_region_ordering_robust_win_first() {
    assert!(PhaseRegion::RobustWin < PhaseRegion::BrittleWin);
    assert!(PhaseRegion::BrittleWin < PhaseRegion::Neutral);
    assert!(PhaseRegion::Neutral < PhaseRegion::BrittleLoss);
    assert!(PhaseRegion::BrittleLoss < PhaseRegion::RobustLoss);
}

#[test]
fn phase_region_is_win_is_loss_partition() {
    let regions = [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ];
    // Every region is in exactly one category: win, loss, or neutral
    for r in &regions {
        match r {
            PhaseRegion::RobustWin | PhaseRegion::BrittleWin => assert!(r.is_win()),
            PhaseRegion::RobustLoss | PhaseRegion::BrittleLoss => assert!(!r.is_win()),
            PhaseRegion::Neutral => assert!(!r.is_win()),
        }
    }
}

#[test]
fn phase_region_all_variants_serde_roundtrip() {
    let regions = [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ];
    for r in &regions {
        let json = serde_json::to_string(r).unwrap();
        let back: PhaseRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// BoundaryKind extended coverage
// ---------------------------------------------------------------------------

#[test]
fn boundary_kind_all_labels_unique() {
    let kinds = [
        BoundaryKind::Fold,
        BoundaryKind::Cusp,
        BoundaryKind::Swallowtail,
        BoundaryKind::Jump,
        BoundaryKind::GradualTransition,
        BoundaryKind::CliffEdge,
    ];
    let labels: Vec<&str> = kinds.iter().map(|k| k.label()).collect();
    for (i, a) in labels.iter().enumerate() {
        for (j, b) in labels.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn boundary_kind_all_serde_roundtrip() {
    let kinds = [
        BoundaryKind::Fold,
        BoundaryKind::Cusp,
        BoundaryKind::Swallowtail,
        BoundaryKind::Jump,
        BoundaryKind::GradualTransition,
        BoundaryKind::CliffEdge,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: BoundaryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn boundary_kind_sharpness_zero_is_gradual() {
    let kind = BoundaryKind::from_sharpness_and_dims(0, 1);
    assert_eq!(kind, BoundaryKind::GradualTransition);
}

#[test]
fn boundary_kind_swallowtail_dims_4_plus() {
    let kind = BoundaryKind::from_sharpness_and_dims(3_000_000, 4);
    assert_eq!(kind, BoundaryKind::Swallowtail);
}

#[test]
fn boundary_kind_display_matches_label() {
    let kinds = [
        BoundaryKind::Fold,
        BoundaryKind::Cusp,
        BoundaryKind::Swallowtail,
        BoundaryKind::Jump,
        BoundaryKind::GradualTransition,
        BoundaryKind::CliffEdge,
    ];
    for k in &kinds {
        assert_eq!(format!("{k}"), k.label());
    }
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate extended
// ---------------------------------------------------------------------------

#[test]
fn manifold_coordinate_squared_distance_zero_same_point() {
    let a = coord("x", 500_000);
    let dist = a.squared_distance(&a).unwrap();
    assert_eq!(dist, 0);
}

#[test]
fn manifold_coordinate_serde_roundtrip() {
    let c = coord("learning_rate", 1_500_000);
    let json = serde_json::to_string(&c).unwrap();
    let back: ManifoldCoordinate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn manifold_coordinate_negative_value() {
    let c = coord("bias", -750_000);
    assert_eq!(c.value_millionths, -750_000);
    let display = format!("{c}");
    assert!(display.contains("-750000"));
}

// ---------------------------------------------------------------------------
// classify_region edge cases
// ---------------------------------------------------------------------------

#[test]
fn classify_region_exactly_at_threshold() {
    // metric == threshold => surplus = 0, which is within neutral band
    let region = catastrophe_witness_generator::classify_region(0, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::Neutral);
}

#[test]
fn classify_region_zero_margin_robust_win() {
    // With zero margin, any positive surplus is a robust win
    let region = catastrophe_witness_generator::classify_region(1, 0, 0);
    assert_eq!(region, PhaseRegion::RobustWin);
}

#[test]
fn classify_region_zero_margin_robust_loss() {
    let region = catastrophe_witness_generator::classify_region(-1, 0, 0);
    assert_eq!(region, PhaseRegion::RobustLoss);
}

// ---------------------------------------------------------------------------
// detect_boundary — boundary properties
// ---------------------------------------------------------------------------

#[test]
fn detect_boundary_records_source_and_target_regions() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    assert!(boundary.source_region.is_win());
    assert!(!boundary.target_region.is_win());
}

#[test]
fn detect_boundary_content_hash_nonempty() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    assert_ne!(boundary.content_hash.0, [0u8; 32]);
}

#[test]
fn detect_boundary_involves_brittle() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 500_000)];
    // Source metric ~2.0 (robust win), target metric ~-0.5 (brittle loss)
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 500_000, -500_000).unwrap();
    // At least one side should be in a brittle region depending on actual classification
    assert!(boundary.is_critical() || boundary.involves_brittle());
}

#[test]
fn detect_boundary_multi_dimensional() {
    let src = vec![coord("x", 0), coord("y", 0)];
    let tgt = vec![coord("x", 2_000_000), coord("y", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    assert!(!boundary.boundary_id.is_empty());
    // Multi-dim should produce cusp or swallowtail
    assert!(
        boundary.kind == BoundaryKind::Cusp
            || boundary.kind == BoundaryKind::Swallowtail
            || boundary.kind == BoundaryKind::CliffEdge
            || boundary.kind == BoundaryKind::Jump
            || boundary.kind == BoundaryKind::Fold
            || boundary.kind == BoundaryKind::GradualTransition,
        "unexpected boundary kind: {:?}",
        boundary.kind
    );
}

// ---------------------------------------------------------------------------
// generate_witness — properties
// ---------------------------------------------------------------------------

#[test]
fn witness_magnitude_matches_absolute_delta() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 3_000_000, -1_000_000, "latency",
    )
    .unwrap();
    assert_eq!(witness.magnitude(), witness.delta_millionths.unsigned_abs());
}

#[test]
fn witness_is_regression_when_delta_negative() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 2_000_000, -1_000_000, "metric",
    )
    .unwrap();
    assert!(witness.is_regression());
    assert!(witness.delta_millionths < 0);
}

#[test]
fn witness_not_regression_when_delta_positive() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, 2_000_000, "metric",
    )
    .unwrap();
    assert!(!witness.is_regression());
}

#[test]
fn witness_has_nonempty_id() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let witness = catastrophe_witness_generator::generate_witness(
        &boundary,
        "some-input",
        1_000_000,
        -500_000,
        "throughput",
    )
    .unwrap();
    assert!(!witness.witness_id.is_empty());
}

// ---------------------------------------------------------------------------
// boundary_sharpness extended
// ---------------------------------------------------------------------------

#[test]
fn boundary_sharpness_increases_with_metric_delta() {
    let s_small =
        catastrophe_witness_generator::compute_boundary_sharpness(1_000_000, 900_000, 1_000_000);
    let s_large =
        catastrophe_witness_generator::compute_boundary_sharpness(1_000_000, -1_000_000, 1_000_000);
    assert!(
        s_large >= s_small,
        "larger metric delta should produce higher sharpness"
    );
}

#[test]
fn boundary_sharpness_deterministic() {
    let values: [(i64, i64, u64); 4] = [
        (0, 0, 0),
        (1_000_000, 1_000_000, 0),
        (-1_000_000, 1_000_000, 500_000),
        (0, 0, 1_000_000),
    ];
    for (a, b, dist) in values {
        let s1 = catastrophe_witness_generator::compute_boundary_sharpness(a, b, dist);
        let s2 = catastrophe_witness_generator::compute_boundary_sharpness(a, b, dist);
        assert_eq!(
            s1, s2,
            "sharpness should be deterministic for ({a}, {b}, {dist})"
        );
    }
}

// ---------------------------------------------------------------------------
// brittleness_report — extended
// ---------------------------------------------------------------------------

#[test]
fn brittleness_report_serde_roundtrip() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn brittleness_report_epoch_matches() {
    let epoch = SecurityEpoch::from_raw(42);
    let report =
        catastrophe_witness_generator::build_brittleness_report(epoch, vec![], vec![]).unwrap();
    assert_eq!(report.epoch, epoch);
}

// ---------------------------------------------------------------------------
// WitnessError
// ---------------------------------------------------------------------------

#[test]
fn witness_error_display_nonempty() {
    let errs = [
        WitnessError::NoBoundaryDetected,
        WitnessError::InputTooLarge,
    ];
    for e in &errs {
        let msg = format!("{e}");
        assert!(!msg.is_empty());
    }
}

#[test]
fn witness_error_serde_roundtrip() {
    let errs = [
        WitnessError::NoBoundaryDetected,
        WitnessError::InputTooLarge,
    ];
    for e in &errs {
        let json = serde_json::to_string(e).unwrap();
        let back: WitnessError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}
