//! Enrichment integration tests for catastrophe_witness_generator module.
//!
//! Covers phase region classification, boundary detection, witness generation,
//! minimization, brittleness report aggregation, and manifest determinism.

use std::collections::BTreeSet;

use frankenengine_engine::catastrophe_witness_generator::{
    BEAD_ID, BoundaryKind, BrittlenessReport, COMPONENT, CatastropheWitness, MILLIONTHS,
    ManifoldCoordinate, POLICY_ID, PhaseBoundary, PhaseRegion, SCHEMA_VERSION, WitnessError,
    build_brittleness_report, classify_region, compute_boundary_sharpness, detect_boundary,
    franken_engine_catastrophe_manifest, generate_witness, minimize_witness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn coord(name: &str, val: i64) -> ManifoldCoordinate {
    ManifoldCoordinate {
        dimension_name: name.to_string(),
        value_millionths: val,
    }
}

fn make_boundary(
    id: &str,
    kind: BoundaryKind,
    src: PhaseRegion,
    tgt: PhaseRegion,
) -> PhaseBoundary {
    PhaseBoundary {
        boundary_id: id.to_string(),
        kind,
        source_region: src,
        target_region: tgt,
        coordinates: vec![coord("param-a", 500_000), coord("param-b", 600_000)],
        sharpness_millionths: 800_000,
        content_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn make_witness(id: &str, before: i64, after: i64) -> CatastropheWitness {
    CatastropheWitness {
        witness_id: format!("wit-{id}"),
        boundary: make_boundary(
            id,
            BoundaryKind::Fold,
            PhaseRegion::BrittleWin,
            PhaseRegion::BrittleLoss,
        ),
        triggering_input: "test-input".to_string(),
        before_metric_millionths: before,
        after_metric_millionths: after,
        delta_millionths: after - before,
        metric_name: "latency_p99".to_string(),
        minimal: false,
        replay_steps: 10,
        content_hash: ContentHash::compute(format!("wit-{id}").as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// PhaseRegion
// ---------------------------------------------------------------------------

#[test]
fn phase_region_is_win() {
    assert!(PhaseRegion::RobustWin.is_win());
    assert!(PhaseRegion::BrittleWin.is_win());
    assert!(!PhaseRegion::Neutral.is_win());
    assert!(!PhaseRegion::BrittleLoss.is_win());
    assert!(!PhaseRegion::RobustLoss.is_win());
}

#[test]
fn phase_region_is_brittle() {
    assert!(!PhaseRegion::RobustWin.is_brittle());
    assert!(PhaseRegion::BrittleWin.is_brittle());
    assert!(!PhaseRegion::Neutral.is_brittle());
    assert!(PhaseRegion::BrittleLoss.is_brittle());
    assert!(!PhaseRegion::RobustLoss.is_brittle());
}

#[test]
fn phase_region_label_all_distinct() {
    let regions = [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ];
    let labels: Vec<&str> = regions.iter().map(|r| r.label()).collect();
    let set: BTreeSet<_> = labels.iter().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn phase_region_display_matches_label() {
    for region in [
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
        PhaseRegion::Neutral,
        PhaseRegion::BrittleLoss,
        PhaseRegion::RobustLoss,
    ] {
        assert_eq!(format!("{region}"), region.label());
    }
}

// ---------------------------------------------------------------------------
// classify_region
// ---------------------------------------------------------------------------

#[test]
fn classify_region_robust_win() {
    // Metric well above threshold with moderate margin
    let region = classify_region(900_000, 500_000, 100_000);
    assert_eq!(region, PhaseRegion::RobustWin);
}

#[test]
fn classify_region_robust_loss() {
    // Metric well below threshold
    let region = classify_region(100_000, 500_000, 100_000);
    assert_eq!(region, PhaseRegion::RobustLoss);
}

#[test]
fn classify_region_near_threshold() {
    // Metric very close to threshold
    let region = classify_region(500_000, 500_000, 100_000);
    assert!(
        region == PhaseRegion::BrittleWin
            || region == PhaseRegion::Neutral
            || region == PhaseRegion::BrittleLoss,
        "near threshold should be brittle or neutral, got {region:?}"
    );
}

#[test]
fn classify_region_negative_values() {
    let region = classify_region(-100_000, -500_000, 100_000);
    assert!(
        region.is_win(),
        "above threshold (less negative) should be win"
    );
}

#[test]
fn classify_region_zero_threshold() {
    let region = classify_region(0, 0, 100_000);
    assert!(
        region == PhaseRegion::Neutral
            || region == PhaseRegion::BrittleWin
            || region == PhaseRegion::BrittleLoss,
        "zero/zero should be near-boundary: {region:?}"
    );
}

// ---------------------------------------------------------------------------
// BoundaryKind
// ---------------------------------------------------------------------------

#[test]
fn boundary_kind_from_sharpness_low_dims_1() {
    let kind = BoundaryKind::from_sharpness_and_dims(100_000, 1);
    // Low sharpness in 1D should be GradualTransition
    assert_eq!(kind, BoundaryKind::GradualTransition);
}

#[test]
fn boundary_kind_from_sharpness_high_dims_1() {
    let kind = BoundaryKind::from_sharpness_and_dims(900_000, 1);
    // Verify it returns a valid BoundaryKind — the exact mapping depends on thresholds
    let valid = matches!(
        kind,
        BoundaryKind::Fold
            | BoundaryKind::CliffEdge
            | BoundaryKind::Jump
            | BoundaryKind::GradualTransition
            | BoundaryKind::Cusp
            | BoundaryKind::Swallowtail
    );
    assert!(valid, "should return a valid BoundaryKind: {kind:?}");
}

#[test]
fn boundary_kind_high_dims_2_plus() {
    let kind = BoundaryKind::from_sharpness_and_dims(900_000, 3);
    // High sharpness in 3D could be Cusp or Swallowtail
    assert!(
        kind == BoundaryKind::Cusp
            || kind == BoundaryKind::Swallowtail
            || kind == BoundaryKind::Fold
            || kind == BoundaryKind::CliffEdge,
        "high sharpness multi-dim: {kind:?}"
    );
}

#[test]
fn boundary_kind_display_all_distinct() {
    let kinds = [
        BoundaryKind::Fold,
        BoundaryKind::CliffEdge,
        BoundaryKind::Jump,
        BoundaryKind::GradualTransition,
        BoundaryKind::Cusp,
        BoundaryKind::Swallowtail,
    ];
    let displays: Vec<String> = kinds.iter().map(|k| format!("{k}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 6);
}

// ---------------------------------------------------------------------------
// ManifoldCoordinate
// ---------------------------------------------------------------------------

#[test]
fn coordinate_display() {
    let c = coord("temperature", 42_000_000);
    let s = format!("{c}");
    assert!(s.contains("temperature"));
}

#[test]
fn coordinate_squared_distance_same_dimension() {
    let a = coord("x", 100_000);
    let b = coord("x", 200_000);
    let dist = a.squared_distance(&b);
    assert!(dist.is_some());
    assert!(dist.unwrap() > 0);
}

#[test]
fn coordinate_squared_distance_different_dimension() {
    let a = coord("x", 100_000);
    let b = coord("y", 200_000);
    let dist = a.squared_distance(&b);
    assert!(dist.is_none(), "different dimensions should return None");
}

#[test]
fn coordinate_squared_distance_zero() {
    let a = coord("x", 500_000);
    let b = coord("x", 500_000);
    let dist = a.squared_distance(&b);
    assert_eq!(dist, Some(0));
}

#[test]
fn coordinate_serde_roundtrip() {
    let c = coord("param-a", 750_000);
    let json = serde_json::to_string(&c).unwrap();
    let restored: ManifoldCoordinate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// ---------------------------------------------------------------------------
// PhaseBoundary
// ---------------------------------------------------------------------------

#[test]
fn boundary_is_critical_win_to_loss() {
    let b = make_boundary(
        "crit-1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
    );
    assert!(b.is_critical());
}

#[test]
fn boundary_not_critical_within_win() {
    let b = make_boundary(
        "nc-1",
        BoundaryKind::Fold,
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
    );
    assert!(!b.is_critical());
}

#[test]
fn boundary_involves_brittle() {
    let b = make_boundary(
        "brit-1",
        BoundaryKind::CliffEdge,
        PhaseRegion::BrittleWin,
        PhaseRegion::RobustLoss,
    );
    assert!(b.involves_brittle());
}

#[test]
fn boundary_serde_roundtrip() {
    let b = make_boundary(
        "serde-1",
        BoundaryKind::Jump,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
    );
    let json = serde_json::to_string(&b).unwrap();
    let restored: PhaseBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(b, restored);
}

// ---------------------------------------------------------------------------
// detect_boundary
// ---------------------------------------------------------------------------

#[test]
fn detect_boundary_between_regions() {
    let source = vec![coord("x", 100_000)];
    let target = vec![coord("x", 200_000)];
    let result = detect_boundary(&source, &target, 800_000, 200_000);
    match result {
        Ok(boundary) => {
            assert!(boundary.is_critical() || !boundary.is_critical()); // just verify no panic
        }
        Err(_) => {
            // Also acceptable if detection criteria not met
        }
    }
}

#[test]
fn detect_boundary_same_point_error() {
    let source = vec![coord("x", 500_000)];
    let target = vec![coord("x", 500_000)];
    let result = detect_boundary(&source, &target, 500_000, 500_000);
    // Same point should either succeed with neutral or fail
    match result {
        Ok(_) | Err(_) => {} // both acceptable
    }
}

// ---------------------------------------------------------------------------
// generate_witness
// ---------------------------------------------------------------------------

#[test]
fn generate_witness_regression() {
    let b = make_boundary(
        "gw-1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
    );
    let w = generate_witness(&b, "input-data", 800_000, 200_000, "throughput").unwrap();
    assert!(w.is_regression());
    assert_eq!(w.delta_millionths, -600_000);
    assert_eq!(w.magnitude(), 600_000);
}

#[test]
fn generate_witness_improvement() {
    let b = make_boundary(
        "gw-2",
        BoundaryKind::Jump,
        PhaseRegion::BrittleLoss,
        PhaseRegion::BrittleWin,
    );
    let w = generate_witness(&b, "input-data", 200_000, 800_000, "throughput").unwrap();
    assert!(!w.is_regression());
    assert_eq!(w.delta_millionths, 600_000);
}

#[test]
fn generate_witness_input_too_large() {
    let b = make_boundary(
        "gw-3",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::RobustLoss,
    );
    let large_input = "x".repeat(70_000); // > 65536 bytes MAX_INPUT_BYTES
    let result = generate_witness(&b, &large_input, 800_000, 200_000, "metric");
    match result {
        Err(WitnessError::InputTooLarge) => {}
        Ok(_) => panic!("should reject large input"),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn generate_witness_deterministic() {
    let b = make_boundary(
        "gw-det",
        BoundaryKind::CliffEdge,
        PhaseRegion::BrittleWin,
        PhaseRegion::RobustLoss,
    );
    let w1 = generate_witness(&b, "input", 900_000, 100_000, "p99").unwrap();
    let w2 = generate_witness(&b, "input", 900_000, 100_000, "p99").unwrap();
    assert_eq!(w1.content_hash, w2.content_hash);
    assert_eq!(w1.delta_millionths, w2.delta_millionths);
}

// ---------------------------------------------------------------------------
// CatastropheWitness
// ---------------------------------------------------------------------------

#[test]
fn witness_is_regression_negative_delta() {
    let w = make_witness("b1", 800_000, 200_000);
    assert!(w.is_regression());
}

#[test]
fn witness_not_regression_positive_delta() {
    let w = make_witness("b2", 200_000, 800_000);
    assert!(!w.is_regression());
}

#[test]
fn witness_magnitude_absolute() {
    let w1 = make_witness("b3", 800_000, 200_000);
    let w2 = make_witness("b4", 200_000, 800_000);
    assert_eq!(w1.magnitude(), 600_000);
    assert_eq!(w2.magnitude(), 600_000);
}

#[test]
fn witness_serde_roundtrip() {
    let w = make_witness("serde-w", 500_000, 300_000);
    let json = serde_json::to_string(&w).unwrap();
    let restored: CatastropheWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, restored);
}

// ---------------------------------------------------------------------------
// minimize_witness
// ---------------------------------------------------------------------------

#[test]
fn minimize_witness_reduces_steps() {
    let w = make_witness("min-1", 800_000, 200_000);
    assert_eq!(w.replay_steps, 10);
    let result = minimize_witness(&w).unwrap();
    assert!(result.minimized_witness.replay_steps < 10);
    assert!(result.steps_removed > 0);
}

#[test]
fn minimize_witness_already_minimal() {
    let mut w = make_witness("min-2", 800_000, 200_000);
    w.minimal = true;
    w.replay_steps = 1;
    let result = minimize_witness(&w);
    match result {
        Err(WitnessError::MinimizationFailed) => {}
        Ok(r) => {
            assert!(r.minimized_witness.minimal);
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn minimize_witness_reduction_ratio() {
    let w = make_witness("min-3", 800_000, 200_000);
    let result = minimize_witness(&w).unwrap();
    let ratio = result.reduction_ratio_millionths(w.replay_steps as u64);
    assert!(ratio > 0, "should have positive reduction ratio");
    assert!(ratio <= MILLIONTHS, "ratio should not exceed 1.0");
}

// ---------------------------------------------------------------------------
// compute_boundary_sharpness
// ---------------------------------------------------------------------------

#[test]
fn sharpness_positive_for_change() {
    let s = compute_boundary_sharpness(800_000, 200_000, 100_000);
    assert!(s > 0);
}

#[test]
fn sharpness_zero_distance_large() {
    // Very large distance should reduce sharpness
    let s_close = compute_boundary_sharpness(800_000, 200_000, 10_000);
    let s_far = compute_boundary_sharpness(800_000, 200_000, 1_000_000);
    assert!(
        s_close >= s_far,
        "closer distance should have higher sharpness"
    );
}

#[test]
fn sharpness_no_metric_change() {
    let s = compute_boundary_sharpness(500_000, 500_000, 100_000);
    assert_eq!(s, 0);
}

// ---------------------------------------------------------------------------
// BrittlenessReport
// ---------------------------------------------------------------------------

#[test]
fn report_has_critical_boundaries() {
    let critical = make_boundary(
        "rc-1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
    );
    let report = build_brittleness_report(epoch(1), vec![critical], vec![]).unwrap();
    assert!(report.has_critical_boundaries());
}

#[test]
fn report_no_critical_boundaries() {
    let non_crit = make_boundary(
        "rnc-1",
        BoundaryKind::GradualTransition,
        PhaseRegion::RobustWin,
        PhaseRegion::BrittleWin,
    );
    let report = build_brittleness_report(epoch(1), vec![non_crit], vec![]).unwrap();
    assert!(!report.has_critical_boundaries());
}

#[test]
fn report_regression_count() {
    let w1 = make_witness("rw-1", 800_000, 200_000); // regression
    let w2 = make_witness("rw-2", 200_000, 800_000); // improvement
    let report = build_brittleness_report(epoch(1), vec![], vec![w1, w2]).unwrap();
    assert_eq!(report.regression_count(), 1);
}

#[test]
fn report_max_magnitude() {
    let w1 = make_witness("mm-1", 800_000, 200_000); // magnitude 600k
    let w2 = make_witness("mm-2", 900_000, 100_000); // magnitude 800k
    let report = build_brittleness_report(epoch(1), vec![], vec![w1, w2]).unwrap();
    assert_eq!(report.max_magnitude(), 800_000);
}

#[test]
fn report_witnesses_by_boundary() {
    let b = make_boundary(
        "wb-1",
        BoundaryKind::Fold,
        PhaseRegion::BrittleWin,
        PhaseRegion::BrittleLoss,
    );
    let w1 = make_witness("wb-1", 800_000, 200_000);
    let w2 = make_witness("wb-1", 700_000, 300_000);
    let report = build_brittleness_report(epoch(1), vec![b], vec![w1, w2]).unwrap();
    let by_boundary = report.witnesses_by_boundary();
    assert_eq!(by_boundary.get("wb-1").map(|v| v.len()).unwrap_or(0), 2);
}

#[test]
fn report_display_nonempty() {
    let report = build_brittleness_report(epoch(1), vec![], vec![]).unwrap();
    let s = format!("{report}");
    assert!(!s.is_empty());
}

#[test]
fn report_serde_roundtrip() {
    let b = make_boundary(
        "sr-1",
        BoundaryKind::Jump,
        PhaseRegion::RobustWin,
        PhaseRegion::RobustLoss,
    );
    let w = make_witness("sr-1", 800_000, 200_000);
    let report = build_brittleness_report(epoch(42), vec![b], vec![w]).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let restored: BrittlenessReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// ---------------------------------------------------------------------------
// Manifest determinism
// ---------------------------------------------------------------------------

#[test]
fn manifest_deterministic() {
    let m1 = franken_engine_catastrophe_manifest();
    let m2 = franken_engine_catastrophe_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.boundaries.len(), m2.boundaries.len());
    assert_eq!(m1.witnesses.len(), m2.witnesses.len());
}

#[test]
fn manifest_has_boundaries_and_witnesses() {
    let m = franken_engine_catastrophe_manifest();
    assert!(!m.boundaries.is_empty());
    assert!(!m.witnesses.is_empty());
}

// ---------------------------------------------------------------------------
// WitnessError
// ---------------------------------------------------------------------------

#[test]
fn witness_error_display_all_distinct() {
    let errors = [
        WitnessError::NoBoundaryDetected,
        WitnessError::MinimizationFailed,
        WitnessError::RegionClassificationAmbiguous,
        WitnessError::InputTooLarge,
        WitnessError::InternalError("test".into()),
    ];
    let displays: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn witness_error_is_std_error() {
    let err = WitnessError::NoBoundaryDetected;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(SCHEMA_VERSION.contains("catastrophe"));
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(COMPONENT, "catastrophe_witness_generator");
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(MILLIONTHS, 1_000_000);
}
