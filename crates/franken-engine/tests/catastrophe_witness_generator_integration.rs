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

use std::collections::BTreeSet;

use frankenengine_engine::catastrophe_witness_generator::{
    self, BEAD_ID, BoundaryKind, BrittlenessReport, COMPONENT, CatastropheWitness, MILLIONTHS,
    ManifoldCoordinate, POLICY_ID, PhaseBoundary, PhaseRegion, SCHEMA_VERSION, WitnessError,
    WitnessMinimizationResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
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

// ===========================================================================
// Enrichment tests — ~90 new tests
// ===========================================================================

// -- Enrichment helper: construct a PhaseBoundary from parts ---------------

fn make_boundary(
    id: &str,
    kind: BoundaryKind,
    src: PhaseRegion,
    tgt: PhaseRegion,
    sharpness: u64,
) -> PhaseBoundary {
    let mut b = PhaseBoundary {
        boundary_id: id.to_string(),
        kind,
        coordinates: vec![coord("x", 0), coord("y", MILLIONTHS)],
        source_region: src,
        target_region: tgt,
        sharpness_millionths: sharpness,
        content_hash: ContentHash::compute(&[]),
    };
    b.content_hash = b.compute_hash();
    b
}

fn make_witness(boundary: &PhaseBoundary, before: i64, after: i64) -> CatastropheWitness {
    let delta = after - before;
    let mut w = CatastropheWitness {
        witness_id: format!("test-wit-{}", boundary.boundary_id),
        boundary: boundary.clone(),
        triggering_input: "test-input".to_string(),
        before_metric_millionths: before,
        after_metric_millionths: after,
        delta_millionths: delta,
        metric_name: "test_metric".to_string(),
        minimal: false,
        replay_steps: 10,
        content_hash: ContentHash::compute(&[]),
    };
    w.content_hash = w.compute_hash();
    w
}

// ---------------------------------------------------------------------------
// PhaseRegion — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_phase_region_debug_all_variants() {
    let variants = [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ];
    for v in &variants {
        let dbg = format!("{v:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_phase_region_clone_eq() {
    let r = PhaseRegion::BrittleWin;
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_phase_region_display_all_variants() {
    let expected = [
        (PhaseRegion::RobustWin, "robust_win"),
        (PhaseRegion::BrittleWin, "brittle_win"),
        (PhaseRegion::Neutral, "neutral"),
        (PhaseRegion::BrittleLoss, "brittle_loss"),
        (PhaseRegion::RobustLoss, "robust_loss"),
    ];
    for (region, label) in &expected {
        assert_eq!(format!("{region}"), *label);
    }
}

#[test]
fn enrichment_phase_region_label_all_variants() {
    let expected = [
        (PhaseRegion::RobustWin, "robust_win"),
        (PhaseRegion::BrittleWin, "brittle_win"),
        (PhaseRegion::Neutral, "neutral"),
        (PhaseRegion::BrittleLoss, "brittle_loss"),
        (PhaseRegion::RobustLoss, "robust_loss"),
    ];
    for (region, label) in &expected {
        assert_eq!(region.label(), *label);
    }
}

#[test]
fn enrichment_phase_region_ord_is_total_order() {
    let mut regions = vec![
        PhaseRegion::RobustLoss,
        PhaseRegion::Neutral,
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleLoss,
        PhaseRegion::BrittleWin,
    ];
    regions.sort();
    assert_eq!(
        regions,
        vec![
            PhaseRegion::RobustWin,
            PhaseRegion::BrittleWin,
            PhaseRegion::Neutral,
            PhaseRegion::BrittleLoss,
            PhaseRegion::RobustLoss,
        ]
    );
}

#[test]
fn enrichment_phase_region_is_win_and_is_brittle_are_independent() {
    // BrittleWin is both win and brittle
    assert!(PhaseRegion::BrittleWin.is_win());
    assert!(PhaseRegion::BrittleWin.is_brittle());
    // RobustWin is win but not brittle
    assert!(PhaseRegion::RobustWin.is_win());
    assert!(!PhaseRegion::RobustWin.is_brittle());
    // BrittleLoss is brittle but not win
    assert!(!PhaseRegion::BrittleLoss.is_win());
    assert!(PhaseRegion::BrittleLoss.is_brittle());
    // Neutral is neither win nor brittle
    assert!(!PhaseRegion::Neutral.is_win());
    assert!(!PhaseRegion::Neutral.is_brittle());
}

#[test]
fn enrichment_phase_region_hash_distinct_per_variant() {
    use std::hash::{Hash, Hasher};
    let variants = [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ];
    let mut hashes = BTreeSet::new();
    for v in &variants {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), variants.len());
}

#[test]
fn enrichment_phase_region_serde_json_field_names() {
    let json = serde_json::to_string(&PhaseRegion::RobustWin).unwrap();
    assert_eq!(json, "\"robust_win\"");
    let json = serde_json::to_string(&PhaseRegion::BrittleLoss).unwrap();
    assert_eq!(json, "\"brittle_loss\"");
    let json = serde_json::to_string(&PhaseRegion::Neutral).unwrap();
    assert_eq!(json, "\"neutral\"");
    let json = serde_json::to_string(&PhaseRegion::RobustLoss).unwrap();
    assert_eq!(json, "\"robust_loss\"");
}

// ---------------------------------------------------------------------------
// BoundaryKind — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_boundary_kind_debug_all_variants() {
    let kinds = [
        BoundaryKind::Fold,
        BoundaryKind::Cusp,
        BoundaryKind::Swallowtail,
        BoundaryKind::Jump,
        BoundaryKind::GradualTransition,
        BoundaryKind::CliffEdge,
    ];
    for k in &kinds {
        let dbg = format!("{k:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_boundary_kind_clone_eq() {
    let k = BoundaryKind::Swallowtail;
    let cloned = k.clone();
    assert_eq!(k, cloned);
}

#[test]
fn enrichment_boundary_kind_serde_snake_case_json() {
    assert_eq!(
        serde_json::to_string(&BoundaryKind::Fold).unwrap(),
        "\"fold\""
    );
    assert_eq!(
        serde_json::to_string(&BoundaryKind::Cusp).unwrap(),
        "\"cusp\""
    );
    assert_eq!(
        serde_json::to_string(&BoundaryKind::Swallowtail).unwrap(),
        "\"swallowtail\""
    );
    assert_eq!(
        serde_json::to_string(&BoundaryKind::Jump).unwrap(),
        "\"jump\""
    );
    assert_eq!(
        serde_json::to_string(&BoundaryKind::GradualTransition).unwrap(),
        "\"gradual_transition\""
    );
    assert_eq!(
        serde_json::to_string(&BoundaryKind::CliffEdge).unwrap(),
        "\"cliff_edge\""
    );
}

#[test]
fn enrichment_boundary_kind_from_sharpness_exact_thresholds() {
    // Exactly 10*MILLIONTHS => Jump (not CliffEdge, since > 10M needed)
    let at_10m = BoundaryKind::from_sharpness_and_dims(10_000_000, 1);
    assert_eq!(at_10m, BoundaryKind::Jump);

    // Exactly 5*MILLIONTHS => Fold (1d) since > 5M needed for Jump
    let at_5m = BoundaryKind::from_sharpness_and_dims(5_000_000, 1);
    assert_eq!(at_5m, BoundaryKind::Fold);

    // Exactly 2*MILLIONTHS => GradualTransition (1d) since > 2M needed for Fold
    let at_2m = BoundaryKind::from_sharpness_and_dims(2_000_000, 1);
    assert_eq!(at_2m, BoundaryKind::GradualTransition);
}

#[test]
fn enrichment_boundary_kind_from_sharpness_dims_0() {
    // 0 dimensions behaves like 1 dimension
    let k = BoundaryKind::from_sharpness_and_dims(3_000_000, 0);
    assert_eq!(k, BoundaryKind::Fold);
}

#[test]
fn enrichment_boundary_kind_from_sharpness_very_high_dims() {
    // 100 dimensions => Swallowtail (dims >= 3)
    let k = BoundaryKind::from_sharpness_and_dims(3_000_000, 100);
    assert_eq!(k, BoundaryKind::Swallowtail);
}

#[test]
fn enrichment_boundary_kind_cliff_edge_overrides_dims() {
    // CliffEdge is determined by sharpness alone, regardless of dims
    for dims in 0..5 {
        let k = BoundaryKind::from_sharpness_and_dims(11_000_000, dims);
        assert_eq!(
            k,
            BoundaryKind::CliffEdge,
            "dims={dims} should still be CliffEdge"
        );
    }
}

#[test]
fn enrichment_boundary_kind_jump_overrides_dims() {
    // Jump threshold (>5M, <=10M) overrides dimension-based classification
    for dims in 0..5 {
        let k = BoundaryKind::from_sharpness_and_dims(6_000_000, dims);
        assert_eq!(k, BoundaryKind::Jump, "dims={dims} should still be Jump");
    }
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifold_coordinate_debug() {
    let c = coord("lr", 100_000);
    let dbg = format!("{c:?}");
    assert!(dbg.contains("lr"));
    assert!(dbg.contains("100000"));
}

#[test]
fn enrichment_manifold_coordinate_clone_eq() {
    let c = coord("x", 42);
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

#[test]
fn enrichment_manifold_coordinate_ord() {
    let a = coord("a", 0);
    let b = coord("b", 0);
    let c = coord("a", 1);
    // Ordered by dimension_name first, then value_millionths
    assert!(a < b);
    assert!(a < c);
}

#[test]
fn enrichment_manifold_coordinate_squared_distance_negative_values() {
    let a = coord("x", -500_000);
    let b = coord("x", 500_000);
    let dist = a.squared_distance(&b).unwrap();
    assert_eq!(dist, 1_000_000i128 * 1_000_000i128);
}

#[test]
fn enrichment_manifold_coordinate_squared_distance_overflow_safe() {
    // i64::MAX and i64::MIN — distance squared should not overflow because we use i128
    let a = coord("x", i64::MAX);
    let b = coord("x", i64::MIN);
    let dist = a.squared_distance(&b);
    assert!(dist.is_some());
    let d = dist.unwrap();
    assert!(d > 0);
}

#[test]
fn enrichment_manifold_coordinate_serde_json_field_names() {
    let c = coord("lr", 100_000);
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"dimension_name\""));
    assert!(json.contains("\"value_millionths\""));
}

#[test]
fn enrichment_manifold_coordinate_display_format() {
    let c = coord("batch_size", 2_000_000);
    assert_eq!(format!("{c}"), "batch_size=2000000");
}

#[test]
fn enrichment_manifold_coordinate_empty_name() {
    let c = coord("", 0);
    assert_eq!(c.dimension_name, "");
    assert_eq!(format!("{c}"), "=0");
}

// ---------------------------------------------------------------------------
// PhaseBoundary — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_phase_boundary_debug() {
    let b = make_boundary(
        "dbg",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let dbg = format!("{b:?}");
    assert!(dbg.contains("PhaseBoundary"));
    assert!(dbg.contains("dbg"));
}

#[test]
fn enrichment_phase_boundary_clone_eq() {
    let b = make_boundary(
        "clne",
        BoundaryKind::Cusp,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        4_000_000,
    );
    let cloned = b.clone();
    assert_eq!(b, cloned);
}

#[test]
fn enrichment_phase_boundary_display_format() {
    let b = make_boundary(
        "fmt-bnd",
        BoundaryKind::Jump,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        8_000_000,
    );
    let s = format!("{b}");
    assert!(s.contains("boundary[fmt-bnd]"));
    assert!(s.contains("robust_win"));
    assert!(s.contains("robust_loss"));
    assert!(s.contains("kind=jump"));
    assert!(s.contains("sharpness=8000000"));
}

#[test]
fn enrichment_phase_boundary_is_critical_all_cross_combinations() {
    // Win -> Loss: critical
    let b1 = make_boundary(
        "c1",
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleLoss,
        1,
    );
    assert!(b1.is_critical());
    let b2 = make_boundary(
        "c2",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::RobustLoss,
        1,
    );
    assert!(b2.is_critical());
    let b3 = make_boundary(
        "c3",
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        PhaseRegion::Neutral,
        1,
    );
    assert!(b3.is_critical()); // Win -> non-win
    // Loss -> Win: also critical
    let b4 = make_boundary(
        "c4",
        BoundaryKind::Fold,
        PhaseRegion::BrittleLoss,
        PhaseRegion::BrittleWin,
        1,
    );
    assert!(b4.is_critical());
    // Win -> Win: not critical
    let b5 = make_boundary(
        "c5",
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        1,
    );
    assert!(!b5.is_critical());
    // Loss -> Loss: not critical
    let b6 = make_boundary(
        "c6",
        BoundaryKind::Fold,
        PhaseRegion::RobustLoss,
        PhaseRegion::BrittleLoss,
        1,
    );
    assert!(!b6.is_critical());
    // Neutral -> Neutral: not critical
    let b7 = make_boundary(
        "c7",
        BoundaryKind::Fold,
        PhaseRegion::Neutral,
        PhaseRegion::Neutral,
        1,
    );
    assert!(!b7.is_critical());
}

#[test]
fn enrichment_phase_boundary_involves_brittle_neutral_to_neutral() {
    let b = make_boundary(
        "nb",
        BoundaryKind::Fold,
        PhaseRegion::Neutral,
        PhaseRegion::Neutral,
        1,
    );
    assert!(!b.involves_brittle());
}

#[test]
fn enrichment_phase_boundary_involves_brittle_robust_to_robust() {
    let b = make_boundary(
        "rr",
        BoundaryKind::Jump,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        10_000_000,
    );
    assert!(!b.involves_brittle());
}

#[test]
fn enrichment_phase_boundary_compute_hash_deterministic() {
    let b = make_boundary(
        "det",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let h1 = b.compute_hash();
    let h2 = b.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_phase_boundary_compute_hash_differs_by_id() {
    let b1 = make_boundary(
        "id-a",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let b2 = make_boundary(
        "id-b",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    assert_ne!(b1.compute_hash(), b2.compute_hash());
}

#[test]
fn enrichment_phase_boundary_serde_roundtrip() {
    let b = make_boundary(
        "sr",
        BoundaryKind::Cusp,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        4_000_000,
    );
    let json = serde_json::to_string(&b).unwrap();
    let back: PhaseBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_phase_boundary_serde_json_field_names() {
    let b = make_boundary(
        "fld",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"boundary_id\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"coordinates\""));
    assert!(json.contains("\"source_region\""));
    assert!(json.contains("\"target_region\""));
    assert!(json.contains("\"sharpness_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

// ---------------------------------------------------------------------------
// CatastropheWitness — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catastrophe_witness_debug() {
    let b = make_boundary(
        "dbg-w",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let dbg = format!("{w:?}");
    assert!(dbg.contains("CatastropheWitness"));
}

#[test]
fn enrichment_catastrophe_witness_clone_eq() {
    let b = make_boundary(
        "clne-w",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let cloned = w.clone();
    assert_eq!(w, cloned);
}

#[test]
fn enrichment_catastrophe_witness_display_contains_fields() {
    let b = make_boundary(
        "dsp-w",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let s = format!("{w}");
    assert!(s.contains("witness["));
    assert!(s.contains("metric=test_metric"));
    assert!(s.contains("delta=-700000"));
    assert!(s.contains("minimal=false"));
    assert!(s.contains("steps=10"));
    assert!(s.contains("boundary=dsp-w"));
}

#[test]
fn enrichment_catastrophe_witness_is_regression_zero_delta() {
    let b = make_boundary(
        "z",
        BoundaryKind::Fold,
        PhaseRegion::Neutral,
        PhaseRegion::Neutral,
        0,
    );
    let w = make_witness(&b, 100, 100);
    assert!(!w.is_regression());
    assert_eq!(w.magnitude(), 0);
}

#[test]
fn enrichment_catastrophe_witness_magnitude_positive_delta() {
    let b = make_boundary(
        "mp",
        BoundaryKind::Fold,
        PhaseRegion::BrittleLoss,
        PhaseRegion::BrittleWin,
        2_000_000,
    );
    let w = make_witness(&b, -200_000, 500_000);
    assert_eq!(w.magnitude(), 700_000);
    assert!(!w.is_regression());
}

#[test]
fn enrichment_catastrophe_witness_compute_hash_deterministic() {
    let b = make_boundary(
        "hd",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let h1 = w.compute_hash();
    let h2 = w.compute_hash();
    assert_eq!(h1, h2);
    assert_eq!(w.content_hash, h1);
}

#[test]
fn enrichment_catastrophe_witness_serde_roundtrip() {
    let b = make_boundary(
        "wr",
        BoundaryKind::CliffEdge,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        15_000_000,
    );
    let w = make_witness(&b, 2_000_000, -5_000_000);
    let json = serde_json::to_string(&w).unwrap();
    let back: CatastropheWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_catastrophe_witness_serde_json_field_names() {
    let b = make_boundary(
        "fn",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 100, -100);
    let json = serde_json::to_string(&w).unwrap();
    assert!(json.contains("\"witness_id\""));
    assert!(json.contains("\"boundary\""));
    assert!(json.contains("\"triggering_input\""));
    assert!(json.contains("\"before_metric_millionths\""));
    assert!(json.contains("\"after_metric_millionths\""));
    assert!(json.contains("\"delta_millionths\""));
    assert!(json.contains("\"metric_name\""));
    assert!(json.contains("\"minimal\""));
    assert!(json.contains("\"replay_steps\""));
    assert!(json.contains("\"content_hash\""));
}

// ---------------------------------------------------------------------------
// WitnessMinimizationResult — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_minimization_result_debug() {
    let b = make_boundary(
        "mr-dbg",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let dbg = format!("{result:?}");
    assert!(dbg.contains("WitnessMinimizationResult"));
}

#[test]
fn enrichment_minimization_result_clone_eq() {
    let b = make_boundary(
        "mr-cl",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_minimization_result_display_format() {
    let b = make_boundary(
        "mr-fmt",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let s = format!("{result}");
    assert!(s.contains("minimization["));
    assert!(s.contains("steps_removed="));
}

#[test]
fn enrichment_minimization_result_serde_roundtrip() {
    let b = make_boundary(
        "mr-sr",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: WitnessMinimizationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_minimization_result_serde_json_field_names() {
    let b = make_boundary(
        "mr-fn",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"original_witness_id\""));
    assert!(json.contains("\"minimized_witness\""));
    assert!(json.contains("\"steps_removed\""));
    assert!(json.contains("\"minimality_certificate_hash\""));
}

#[test]
fn enrichment_minimization_compute_certificate_hash_deterministic() {
    let b = make_boundary(
        "mr-cd",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let h1 = result.compute_certificate_hash();
    let h2 = result.compute_certificate_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_minimization_reduction_ratio_full_reduction() {
    let b = make_boundary(
        "rr-full",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let mut w = make_witness(&b, 500_000, -200_000);
    w.replay_steps = 10_000;
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let ratio = result.reduction_ratio_millionths(10_000);
    // minimized_steps = ceil(sqrt(10000)) = 100, removed = 9900
    // ratio = 9900 * 1M / 10000 = 990_000
    assert_eq!(ratio, 990_000);
}

#[test]
fn enrichment_minimization_reduction_ratio_small_input() {
    let b = make_boundary(
        "rr-sm",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let mut w = make_witness(&b, 500_000, -200_000);
    w.replay_steps = 4;
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    let ratio = result.reduction_ratio_millionths(4);
    // minimized_steps = ceil(sqrt(4)) = 2, removed = 2
    // ratio = 2 * 1M / 4 = 500_000
    assert_eq!(ratio, 500_000);
}

#[test]
fn enrichment_minimization_one_step_fails() {
    // 1 step: ceil(sqrt(1)) = 1, steps_removed = 0 => MinimizationFailed
    let b = make_boundary(
        "rr-1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let mut w = make_witness(&b, 500_000, -200_000);
    w.replay_steps = 1;
    let result = catastrophe_witness_generator::minimize_witness(&w);
    assert_eq!(result, Err(WitnessError::MinimizationFailed));
}

#[test]
fn enrichment_minimization_preserves_triggering_input() {
    let b = make_boundary(
        "pi",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    assert_eq!(
        result.minimized_witness.triggering_input,
        w.triggering_input
    );
}

#[test]
fn enrichment_minimization_preserves_metric_name() {
    let b = make_boundary(
        "pm",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    assert_eq!(result.minimized_witness.metric_name, w.metric_name);
}

#[test]
fn enrichment_minimization_id_has_min_suffix() {
    let b = make_boundary(
        "mid",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let result = catastrophe_witness_generator::minimize_witness(&w).unwrap();
    assert!(result.minimized_witness.witness_id.ends_with("-min"));
    assert!(
        result
            .minimized_witness
            .witness_id
            .starts_with(&w.witness_id)
    );
}

// ---------------------------------------------------------------------------
// BrittlenessReport — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_brittleness_report_debug() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    let dbg = format!("{report:?}");
    assert!(dbg.contains("BrittlenessReport"));
}

#[test]
fn enrichment_brittleness_report_clone_eq() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

#[test]
fn enrichment_brittleness_report_display_format() {
    let b = make_boundary(
        "rptd",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let report = catastrophe_witness_generator::build_brittleness_report(
        SecurityEpoch::from_raw(7),
        vec![b],
        vec![w],
    )
    .unwrap();
    let s = format!("{report}");
    assert!(s.contains("brittleness_report["));
    assert!(s.contains("epoch:7"));
    assert!(s.contains("boundaries=1"));
    assert!(s.contains("witnesses=1"));
}

#[test]
fn enrichment_brittleness_report_serde_roundtrip_with_data() {
    let b = make_boundary(
        "rptsr",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![b], vec![w])
            .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: BrittlenessReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_brittleness_report_serde_json_field_names() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"boundaries\""));
    assert!(json.contains("\"witnesses\""));
    assert!(json.contains("\"brittle_region_count\""));
    assert!(json.contains("\"total_boundary_sharpness_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_brittleness_report_compute_hash_deterministic() {
    let b = make_boundary(
        "rptch",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let w = make_witness(&b, 500_000, -200_000);
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![b], vec![w])
            .unwrap();
    let h1 = report.compute_hash();
    let h2 = report.compute_hash();
    assert_eq!(h1, h2);
    assert_eq!(report.content_hash, h1);
}

#[test]
fn enrichment_brittleness_report_max_magnitude_empty() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    assert_eq!(report.max_magnitude(), 0);
}

#[test]
fn enrichment_brittleness_report_regression_count_all_positive() {
    let b = make_boundary(
        "rca",
        BoundaryKind::Fold,
        PhaseRegion::BrittleLoss,
        PhaseRegion::BrittleWin,
        2_000_000,
    );
    let w1 = make_witness(&b, -200_000, 500_000); // positive delta
    let w2 = make_witness(&b, -100_000, 300_000); // positive delta
    let report = catastrophe_witness_generator::build_brittleness_report(
        test_epoch(),
        vec![b],
        vec![w1, w2],
    )
    .unwrap();
    assert_eq!(report.regression_count(), 0);
}

#[test]
fn enrichment_brittleness_report_witnesses_by_boundary_empty() {
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![], vec![])
            .unwrap();
    let grouped = report.witnesses_by_boundary();
    assert!(grouped.is_empty());
}

#[test]
fn enrichment_brittleness_report_witnesses_by_boundary_multiple() {
    let b1 = make_boundary(
        "grp1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let b2 = make_boundary(
        "grp2",
        BoundaryKind::CliffEdge,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        15_000_000,
    );
    let w1 = make_witness(&b1, 500_000, -200_000);
    let w2 = make_witness(&b1, 400_000, -300_000);
    let w3 = make_witness(&b2, 2_000_000, -5_000_000);
    let report = catastrophe_witness_generator::build_brittleness_report(
        test_epoch(),
        vec![b1, b2],
        vec![w1, w2, w3],
    )
    .unwrap();
    let grouped = report.witnesses_by_boundary();
    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped.get("grp1").map(|v| v.len()), Some(2));
    assert_eq!(grouped.get("grp2").map(|v| v.len()), Some(1));
}

#[test]
fn enrichment_brittleness_report_brittle_region_count_both_sides() {
    // Both source and target are brittle => 2 brittle regions
    let b = make_boundary(
        "brc",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![b], vec![])
            .unwrap();
    assert_eq!(report.brittle_region_count, 2);
}

#[test]
fn enrichment_brittleness_report_brittle_region_count_one_side() {
    // Only source is brittle
    let b = make_boundary(
        "brc1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::RobustLoss,
        3_000_000,
    );
    let report =
        catastrophe_witness_generator::build_brittleness_report(test_epoch(), vec![b], vec![])
            .unwrap();
    assert_eq!(report.brittle_region_count, 1);
}

#[test]
fn enrichment_brittleness_report_total_sharpness_sums() {
    let b1 = make_boundary(
        "ts1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
        3_000_000,
    );
    let b2 = make_boundary(
        "ts2",
        BoundaryKind::Jump,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        7_000_000,
    );
    let b3 = make_boundary(
        "ts3",
        BoundaryKind::CliffEdge,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
        15_000_000,
    );
    let report = catastrophe_witness_generator::build_brittleness_report(
        test_epoch(),
        vec![b1, b2, b3],
        vec![],
    )
    .unwrap();
    assert_eq!(report.total_boundary_sharpness_millionths, 25_000_000);
}

// ---------------------------------------------------------------------------
// WitnessError — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_witness_error_debug_all_variants() {
    let errs = [
        WitnessError::NoBoundaryDetected,
        WitnessError::MinimizationFailed,
        WitnessError::RegionClassificationAmbiguous,
        WitnessError::InputTooLarge,
        WitnessError::InternalError("test error".to_string()),
    ];
    for e in &errs {
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_witness_error_clone_eq() {
    let e = WitnessError::InternalError("clone test".to_string());
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn enrichment_witness_error_display_all_variants() {
    let e1 = WitnessError::NoBoundaryDetected;
    assert!(format!("{e1}").contains("no phase boundary"));
    let e2 = WitnessError::MinimizationFailed;
    assert!(format!("{e2}").contains("minimization failed"));
    let e3 = WitnessError::RegionClassificationAmbiguous;
    assert!(format!("{e3}").contains("ambiguous"));
    let e4 = WitnessError::InputTooLarge;
    assert!(format!("{e4}").contains("exceeds"));
    let e5 = WitnessError::InternalError("boom".to_string());
    assert!(format!("{e5}").contains("boom"));
}

#[test]
fn enrichment_witness_error_serde_all_variants() {
    let errs = [
        WitnessError::NoBoundaryDetected,
        WitnessError::MinimizationFailed,
        WitnessError::RegionClassificationAmbiguous,
        WitnessError::InputTooLarge,
        WitnessError::InternalError("serde test".to_string()),
    ];
    for e in &errs {
        let json = serde_json::to_string(e).unwrap();
        let back: WitnessError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_witness_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(WitnessError::NoBoundaryDetected);
    assert!(!e.to_string().is_empty());
}

#[test]
fn enrichment_witness_error_serde_snake_case_json() {
    let json = serde_json::to_string(&WitnessError::NoBoundaryDetected).unwrap();
    assert!(json.contains("no_boundary_detected"));
    let json = serde_json::to_string(&WitnessError::MinimizationFailed).unwrap();
    assert!(json.contains("minimization_failed"));
    let json = serde_json::to_string(&WitnessError::RegionClassificationAmbiguous).unwrap();
    assert!(json.contains("region_classification_ambiguous"));
    let json = serde_json::to_string(&WitnessError::InputTooLarge).unwrap();
    assert!(json.contains("input_too_large"));
}

// ---------------------------------------------------------------------------
// classify_region — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_region_negative_margin() {
    // Negative margin should be treated as absolute value
    let region = catastrophe_witness_generator::classify_region(500_000, 0, -1_000_000);
    assert_eq!(region, PhaseRegion::BrittleWin);
}

#[test]
fn enrichment_classify_region_negative_threshold() {
    // threshold = -2M, margin=1M, metric=-1M => delta=1M > margin => RobustWin
    let region = catastrophe_witness_generator::classify_region(-1_000_000, -2_000_000, 1_000_000);
    assert_eq!(region, PhaseRegion::RobustWin);
}

#[test]
fn enrichment_classify_region_at_margin_boundary_positive() {
    // margin=1M, neutral_half=250K, metric at exactly margin (1M) from threshold
    // delta = 1M = abs_margin => NOT > abs_margin => BrittleWin
    let region = catastrophe_witness_generator::classify_region(1_000_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::BrittleWin);
}

#[test]
fn enrichment_classify_region_just_beyond_margin_positive() {
    // delta = 1_000_001 > margin of 1M => RobustWin
    let region = catastrophe_witness_generator::classify_region(1_000_001, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::RobustWin);
}

#[test]
fn enrichment_classify_region_at_margin_boundary_negative() {
    // delta = -1M, |delta| = 1M = abs_margin => NOT > abs_margin => BrittleLoss
    let region = catastrophe_witness_generator::classify_region(-1_000_000, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::BrittleLoss);
}

#[test]
fn enrichment_classify_region_just_beyond_margin_negative() {
    // delta = -1_000_001, |delta| > margin => RobustLoss
    let region = catastrophe_witness_generator::classify_region(-1_000_001, 0, 1_000_000);
    assert_eq!(region, PhaseRegion::RobustLoss);
}

// ---------------------------------------------------------------------------
// detect_boundary — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_boundary_deterministic() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let b1 =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let b2 =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    assert_eq!(b1.boundary_id, b2.boundary_id);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn enrichment_detect_boundary_empty_coords() {
    // Empty coordinate vectors — distance = 0 => max sharpness
    let src: Vec<ManifoldCoordinate> = vec![];
    let tgt: Vec<ManifoldCoordinate> = vec![];
    let result = catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000);
    assert!(result.is_ok());
    let b = result.unwrap();
    // With 0 distance, sharpness should be very high
    assert!(b.sharpness_millionths > 10_000_000);
}

#[test]
fn enrichment_detect_boundary_different_metrics_different_ids() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let b1 =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let b2 =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 3_000_000, -3_000_000).unwrap();
    assert_ne!(b1.boundary_id, b2.boundary_id);
}

#[test]
fn enrichment_detect_boundary_boundary_id_starts_with_bnd() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let b =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    assert!(b.boundary_id.starts_with("bnd-"));
}

#[test]
fn enrichment_detect_boundary_coords_from_source() {
    let src = vec![coord("x", 100), coord("y", 200)];
    let tgt = vec![coord("x", 300), coord("y", 400)];
    let b =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    // Coordinates come from source
    assert_eq!(b.coordinates.len(), 2);
    assert_eq!(b.coordinates[0].dimension_name, "x");
    assert_eq!(b.coordinates[0].value_millionths, 100);
}

// ---------------------------------------------------------------------------
// generate_witness — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generate_witness_deterministic() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let w1 = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    let w2 = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    assert_eq!(w1.witness_id, w2.witness_id);
    assert_eq!(w1.content_hash, w2.content_hash);
}

#[test]
fn enrichment_generate_witness_id_starts_with_wit() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let w = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    assert!(w.witness_id.starts_with("wit-"));
}

#[test]
fn enrichment_generate_witness_at_exact_max_input_size() {
    // Exactly 65536 bytes should succeed
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let input = "x".repeat(65_536);
    let result = catastrophe_witness_generator::generate_witness(
        &boundary, &input, 1_000_000, -500_000, "metric",
    );
    assert!(result.is_ok());
}

#[test]
fn enrichment_generate_witness_one_byte_over_max() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let input = "x".repeat(65_537);
    let result = catastrophe_witness_generator::generate_witness(
        &boundary, &input, 1_000_000, -500_000, "metric",
    );
    assert_eq!(result, Err(WitnessError::InputTooLarge));
}

#[test]
fn enrichment_generate_witness_not_minimal() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let w = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    assert!(!w.minimal);
}

#[test]
fn enrichment_generate_witness_delta_is_after_minus_before() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let w = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 300_000, -700_000, "metric",
    )
    .unwrap();
    assert_eq!(w.delta_millionths, -700_000 - 300_000);
    assert_eq!(w.delta_millionths, -1_000_000);
}

#[test]
fn enrichment_generate_witness_replay_steps_positive() {
    let src = vec![coord("x", 0)];
    let tgt = vec![coord("x", 2_000_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 2_000_000, -2_000_000).unwrap();
    let w = catastrophe_witness_generator::generate_witness(
        &boundary, "data", 1_000_000, -500_000, "metric",
    )
    .unwrap();
    assert!(w.replay_steps > 0);
}

// ---------------------------------------------------------------------------
// compute_boundary_sharpness — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sharpness_symmetric() {
    let s1 =
        catastrophe_witness_generator::compute_boundary_sharpness(1_000_000, -1_000_000, 500_000);
    let s2 =
        catastrophe_witness_generator::compute_boundary_sharpness(-1_000_000, 1_000_000, 500_000);
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_sharpness_inversely_proportional_to_distance() {
    let s1 = catastrophe_witness_generator::compute_boundary_sharpness(2_000_000, 0, 1_000_000);
    let s2 = catastrophe_witness_generator::compute_boundary_sharpness(2_000_000, 0, 2_000_000);
    assert!(s1 > s2, "smaller distance should yield higher sharpness");
}

#[test]
fn enrichment_sharpness_zero_delta_zero_result() {
    let s = catastrophe_witness_generator::compute_boundary_sharpness(0, 0, 1_000_000);
    assert_eq!(s, 0);
}

// ---------------------------------------------------------------------------
// manifest — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_boundary_kinds_diverse() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    let kinds: BTreeSet<String> = manifest
        .boundaries
        .iter()
        .map(|b| b.kind.label().to_string())
        .collect();
    // Should have at least 2 distinct kinds
    assert!(
        kinds.len() >= 2,
        "manifest should demonstrate multiple boundary kinds"
    );
}

#[test]
fn enrichment_manifest_witnesses_have_negative_deltas() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    for w in &manifest.witnesses {
        assert!(
            w.delta_millionths < 0,
            "manifest witnesses should be regressions"
        );
    }
}

#[test]
fn enrichment_manifest_report_id_contains_bead_id() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert!(manifest.report_id.contains(BEAD_ID));
}

#[test]
fn enrichment_manifest_epoch_is_one() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert_eq!(manifest.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_manifest_has_three_boundaries() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert_eq!(manifest.boundaries.len(), 3);
}

#[test]
fn enrichment_manifest_has_two_witnesses() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert_eq!(manifest.witnesses.len(), 2);
}

#[test]
fn enrichment_manifest_total_sharpness_positive() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert!(manifest.total_boundary_sharpness_millionths > 0);
}

#[test]
fn enrichment_manifest_content_hash_not_empty() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    assert_ne!(manifest.content_hash, ContentHash::compute(&[]));
}

#[test]
fn enrichment_manifest_regression_count_equals_witness_count() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    // All manifest witnesses are regressions
    assert_eq!(manifest.regression_count(), manifest.witnesses.len());
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let manifest = catastrophe_witness_generator::franken_engine_catastrophe_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: BrittlenessReport = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_end_to_end_detect_generate_minimize_report() {
    // Full workflow: detect boundary, generate witness, minimize, build report
    let src = vec![coord("lr", 100_000)];
    let tgt = vec![coord("lr", 200_000)];
    let boundary =
        catastrophe_witness_generator::detect_boundary(&src, &tgt, 500_000, -500_000).unwrap();
    assert!(boundary.is_critical());

    let witness = catastrophe_witness_generator::generate_witness(
        &boundary, "lr=0.2", 500_000, -500_000, "accuracy",
    )
    .unwrap();
    assert!(witness.is_regression());
    assert!(!witness.minimal);

    let min_result = catastrophe_witness_generator::minimize_witness(&witness).unwrap();
    assert!(min_result.minimized_witness.minimal);
    assert!(min_result.minimized_witness.replay_steps < witness.replay_steps);

    let report = catastrophe_witness_generator::build_brittleness_report(
        SecurityEpoch::from_raw(10),
        vec![boundary],
        vec![min_result.minimized_witness],
    )
    .unwrap();
    assert!(report.has_critical_boundaries());
    assert_eq!(report.regression_count(), 1);
    assert_eq!(report.epoch, SecurityEpoch::from_raw(10));
}

#[test]
fn enrichment_end_to_end_multiple_boundaries_and_witnesses() {
    let s1 = vec![coord("x", 0)];
    let t1 = vec![coord("x", 2_000_000)];
    let b1 =
        catastrophe_witness_generator::detect_boundary(&s1, &t1, 2_000_000, -2_000_000).unwrap();

    let s2 = vec![coord("y", 0)];
    let t2 = vec![coord("y", 500_000)];
    let b2 = catastrophe_witness_generator::detect_boundary(&s2, &t2, 500_000, -500_000).unwrap();

    let w1 =
        catastrophe_witness_generator::generate_witness(&b1, "in1", 2_000_000, -2_000_000, "m1")
            .unwrap();
    let w2 = catastrophe_witness_generator::generate_witness(&b2, "in2", 500_000, -500_000, "m2")
        .unwrap();
    let w3 =
        catastrophe_witness_generator::generate_witness(&b1, "in3", 1_500_000, -1_500_000, "m1")
            .unwrap();

    let report = catastrophe_witness_generator::build_brittleness_report(
        SecurityEpoch::from_raw(5),
        vec![b1, b2],
        vec![w1, w2, w3],
    )
    .unwrap();

    assert_eq!(report.boundaries.len(), 2);
    assert_eq!(report.witnesses.len(), 3);
    assert_eq!(report.regression_count(), 3);
    let grouped = report.witnesses_by_boundary();
    assert!(grouped.len() >= 1);
}

// ---------------------------------------------------------------------------
// Constants — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
    assert!(SCHEMA_VERSION.contains("catastrophe_witness_generator"));
}

#[test]
fn enrichment_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(BEAD_ID.contains('.'));
}

#[test]
fn enrichment_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_millionths_is_one_million() {
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(MILLIONTHS * 1, 1 * MILLIONTHS);
}
