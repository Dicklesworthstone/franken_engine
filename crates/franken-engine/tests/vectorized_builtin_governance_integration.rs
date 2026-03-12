// Integration tests for vectorized_builtin_governance module.
//
// Covers: constants, type ordering, constructor verification, lifecycle flows,
// verdict determination, content hash determinism, and E2E scenarios.

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_builtin_governance::*;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("vectorized-builtin-governance"));
}

#[test]
fn test_schema_version_contains_v1() {
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_component_matches() {
    assert_eq!(COMPONENT, "vectorized_builtin_governance");
}

#[test]
fn test_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(BEAD_ID, "bd-1lsy.7.24.3");
}

#[test]
fn test_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
    assert_eq!(POLICY_ID, "RGC-624C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_constants_are_positive() {
    assert!(DEFAULT_MIN_PARITY_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_SKEW_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_COLD_START_OVERHEAD > 0);
    assert!(DEFAULT_MIN_SAMPLES > 0);
    assert!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS > 0);
    assert!(DEFAULT_MIN_OBSERVABILITY_COVERAGE > 0);
}

// ---------------------------------------------------------------------------
// VectorizedLane ordering and display
// ---------------------------------------------------------------------------

#[test]
fn test_vectorized_lane_all_returns_ten() {
    assert_eq!(VectorizedLane::all().len(), 10);
}

#[test]
fn test_vectorized_lane_ordering_first_last() {
    assert!(VectorizedLane::ArrayHigherOrder < VectorizedLane::MathBatch);
}

#[test]
fn test_vectorized_lane_ordering_adjacent() {
    let all = VectorizedLane::all();
    for i in 0..all.len() - 1 {
        assert!(
            all[i] < all[i + 1],
            "lane {:?} should be < {:?}",
            all[i],
            all[i + 1]
        );
    }
}

#[test]
fn test_vectorized_lane_display_array_higher_order() {
    assert_eq!(
        VectorizedLane::ArrayHigherOrder.to_string(),
        "array_higher_order"
    );
}

#[test]
fn test_vectorized_lane_display_json_codec() {
    assert_eq!(VectorizedLane::JsonCodec.to_string(), "json_codec");
}

#[test]
fn test_vectorized_lane_display_math_batch() {
    assert_eq!(VectorizedLane::MathBatch.to_string(), "math_batch");
}

#[test]
fn test_vectorized_lane_all_unique() {
    let all = VectorizedLane::all();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// ParityAxis
// ---------------------------------------------------------------------------

#[test]
fn test_parity_axis_display_semantic() {
    assert_eq!(ParityAxis::Semantic.to_string(), "semantic");
}

#[test]
fn test_parity_axis_display_gc_pressure() {
    assert_eq!(ParityAxis::GcPressure.to_string(), "gc_pressure");
}

#[test]
fn test_parity_axis_ordering() {
    assert!(ParityAxis::Semantic < ParityAxis::GcPressure);
}

// ---------------------------------------------------------------------------
// ParityResult construction
// ---------------------------------------------------------------------------

#[test]
fn test_parity_result_passes_exact_threshold() {
    let r = ParityResult::new(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert!(r.passes);
}

#[test]
fn test_parity_result_fails_below_parity() {
    let r = ParityResult::new(
        VectorizedLane::StringSearch,
        ParityAxis::Performance,
        DEFAULT_MIN_PARITY_MILLIONTHS - 1,
        50,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert!(!r.passes);
}

#[test]
fn test_parity_result_fails_below_samples() {
    let r = ParityResult::new(
        VectorizedLane::StringSearch,
        ParityAxis::Performance,
        FIXED_ONE,
        DEFAULT_MIN_SAMPLES - 1,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert!(!r.passes);
}

#[test]
fn test_parity_result_hash_determinism() {
    let a = ParityResult::new(
        VectorizedLane::JsonCodec,
        ParityAxis::Memory,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    let b = ParityResult::new(
        VectorizedLane::JsonCodec,
        ParityAxis::Memory,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert_eq!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_parity_result_hash_differs_on_lane() {
    let a = ParityResult::new(
        VectorizedLane::JsonCodec,
        ParityAxis::Memory,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    let b = ParityResult::new(
        VectorizedLane::StringSearch,
        ParityAxis::Memory,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

// ---------------------------------------------------------------------------
// SkewEntry
// ---------------------------------------------------------------------------

#[test]
fn test_skew_entry_within_budget() {
    let s = SkewEntry::new(
        VectorizedLane::TypedArrayBulk,
        50_000,
        1000,
        900,
        3000,
        2800,
        100,
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert!(s.within_budget);
}

#[test]
fn test_skew_entry_exceeds_budget() {
    let s = SkewEntry::new(
        VectorizedLane::TypedArrayBulk,
        DEFAULT_MAX_SKEW_MILLIONTHS + 1,
        1000,
        900,
        3000,
        2800,
        100,
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert!(!s.within_budget);
}

#[test]
fn test_skew_entry_hash_determinism() {
    let a = SkewEntry::new(
        VectorizedLane::BufferOps,
        10_000,
        500,
        450,
        1500,
        1400,
        60,
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    let b = SkewEntry::new(
        VectorizedLane::BufferOps,
        10_000,
        500,
        450,
        1500,
        1400,
        60,
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert_eq!(a.entry_hash, b.entry_hash);
}

// ---------------------------------------------------------------------------
// ColdStartEntry
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_overhead_computation() {
    let c = ColdStartEntry::new(
        VectorizedLane::ArrayHigherOrder,
        1200,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_eq!(c.overhead_millionths, 200_000);
    assert!(c.within_budget);
}

#[test]
fn test_cold_start_exceeds_budget() {
    let c = ColdStartEntry::new(
        VectorizedLane::ArrayHigherOrder,
        5000,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert!(!c.within_budget);
}

#[test]
fn test_cold_start_zero_warm_ns() {
    let c = ColdStartEntry::new(
        VectorizedLane::ArrayHigherOrder,
        100,
        0,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_eq!(c.overhead_millionths, FIXED_ONE);
}

#[test]
fn test_cold_start_both_zero() {
    let c = ColdStartEntry::new(
        VectorizedLane::ArrayHigherOrder,
        0,
        0,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_eq!(c.overhead_millionths, 0);
    assert!(c.within_budget);
}

#[test]
fn test_cold_start_no_overhead() {
    let c = ColdStartEntry::new(
        VectorizedLane::MathBatch,
        1000,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_eq!(c.overhead_millionths, 0);
    assert!(c.within_budget);
}

// ---------------------------------------------------------------------------
// TailRiskEntry
// ---------------------------------------------------------------------------

#[test]
fn test_tail_risk_within_budget() {
    let t = TailRiskEntry::new(
        VectorizedLane::RegexpMatch,
        2_050_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert!(t.within_budget);
    assert_eq!(t.regression_millionths, 50_000);
}

#[test]
fn test_tail_risk_exceeds_budget() {
    let t = TailRiskEntry::new(
        VectorizedLane::RegexpMatch,
        3_000_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert!(!t.within_budget);
}

#[test]
fn test_tail_risk_improvement_zero_regression() {
    let t = TailRiskEntry::new(
        VectorizedLane::RegexpMatch,
        1_500_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(t.regression_millionths, 0);
    assert!(t.within_budget);
}

// ---------------------------------------------------------------------------
// ObservabilityCoverage
// ---------------------------------------------------------------------------

#[test]
fn test_observability_adequate_coverage() {
    let o = ObservabilityCoverage::new(
        VectorizedLane::PromiseCombinator,
        100,
        90,
        DEFAULT_MIN_OBSERVABILITY_COVERAGE,
    );
    assert!(o.adequate);
    assert_eq!(o.coverage_millionths, 900_000);
}

#[test]
fn test_observability_inadequate_coverage() {
    let o = ObservabilityCoverage::new(
        VectorizedLane::PromiseCombinator,
        100,
        50,
        DEFAULT_MIN_OBSERVABILITY_COVERAGE,
    );
    assert!(!o.adequate);
}

#[test]
fn test_observability_zero_hooks_treated_as_full() {
    let o = ObservabilityCoverage::new(
        VectorizedLane::PromiseCombinator,
        0,
        0,
        DEFAULT_MIN_OBSERVABILITY_COVERAGE,
    );
    assert!(o.adequate);
    assert_eq!(o.coverage_millionths, FIXED_ONE);
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_strict_requires_all_lanes() {
    let c = GovernanceConfig::strict();
    assert_eq!(c.required_lanes.len(), 10);
    for lane in VectorizedLane::all() {
        assert!(c.required_lanes.contains(lane));
    }
}

#[test]
fn test_config_relaxed_requires_no_lanes() {
    let c = GovernanceConfig::relaxed();
    assert!(c.required_lanes.is_empty());
    assert!(c.required_axes.is_empty());
}

#[test]
fn test_config_default_is_relaxed() {
    let d = GovernanceConfig::default();
    let r = GovernanceConfig::relaxed();
    assert_eq!(d, r);
}

#[test]
fn test_config_strict_tighter_than_relaxed() {
    let s = GovernanceConfig::strict();
    let r = GovernanceConfig::relaxed();
    assert!(s.min_parity_millionths >= r.min_parity_millionths);
    assert!(s.max_skew_millionths <= r.max_skew_millionths);
    assert!(s.max_cold_start_overhead <= r.max_cold_start_overhead);
    assert!(s.min_samples >= r.min_samples);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_approved_does_not_block() {
    assert!(!GovernanceVerdict::Approved.blocks_publication());
}

#[test]
fn test_verdict_all_non_approved_block() {
    let blocking = [
        GovernanceVerdict::ParityViolation,
        GovernanceVerdict::SkewExceeded,
        GovernanceVerdict::ColdStartExceeded,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::ObservabilityInsufficient,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &blocking {
        assert!(v.blocks_publication(), "{:?} should block", v);
    }
}

#[test]
fn test_verdict_display_parity_violation() {
    assert_eq!(
        GovernanceVerdict::ParityViolation.to_string(),
        "parity_violation"
    );
}

#[test]
fn test_verdict_display_cold_start_exceeded() {
    assert_eq!(
        GovernanceVerdict::ColdStartExceeded.to_string(),
        "cold_start_exceeded"
    );
}

#[test]
fn test_verdict_ordering() {
    assert!(GovernanceVerdict::Approved < GovernanceVerdict::MultipleViolations);
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_empty_relaxed_approved() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert!(receipt.lanes_evaluated.is_empty());
}

#[test]
fn test_evaluator_parity_pass() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        980_000,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.parity_results.len(), 1);
}

#[test]
fn test_evaluator_parity_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::StringSearch,
        ParityAxis::Semantic,
        800_000,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
    assert_eq!(receipt.violations.len(), 1);
}

#[test]
fn test_evaluator_skew_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_skew(
        VectorizedLane::JsonCodec,
        200_000,
        1000,
        900,
        3000,
        2800,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::SkewExceeded);
}

#[test]
fn test_evaluator_cold_start_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cold_start(VectorizedLane::RegexpMatch, 5000, 1000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::ColdStartExceeded);
}

#[test]
fn test_evaluator_tail_risk_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_tail_risk(
        VectorizedLane::CollectionIteration,
        3_000_000,
        2_000_000,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
}

#[test]
fn test_evaluator_observability_fail() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_observability(VectorizedLane::PromiseCombinator, 100, 20);
    let receipt = eval.evaluate(epoch());
    assert_eq!(
        receipt.verdict,
        GovernanceVerdict::ObservabilityInsufficient
    );
}

#[test]
fn test_evaluator_missing_required_lane() {
    let mut config = GovernanceConfig::relaxed();
    config.required_lanes.insert(VectorizedLane::MathBatch);
    let eval = GovernanceEvaluator::new(config);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert!(receipt.lanes_missing.contains(&VectorizedLane::MathBatch));
}

#[test]
fn test_evaluator_multiple_violations_parity_and_skew() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::StringSearch,
        ParityAxis::Semantic,
        800_000,
        50,
    );
    eval.add_skew(
        VectorizedLane::JsonCodec,
        200_000,
        1000,
        900,
        3000,
        2800,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violations.len() >= 2);
}

#[test]
fn test_evaluator_multiple_violations_cold_start_and_tail_risk() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cold_start(VectorizedLane::TypedArrayBulk, 5000, 1000);
    eval.add_tail_risk(VectorizedLane::BufferOps, 3_000_000, 2_000_000, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_lanes_evaluated_tracks_coverage() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    eval.add_cold_start(VectorizedLane::JsonCodec, 1100, 1000);
    let receipt = eval.evaluate(epoch());
    assert!(
        receipt
            .lanes_evaluated
            .contains(&VectorizedLane::ArrayHigherOrder)
    );
    assert!(receipt.lanes_evaluated.contains(&VectorizedLane::JsonCodec));
    assert_eq!(receipt.lanes_evaluated.len(), 2);
}

#[test]
fn test_evaluator_epoch_recorded() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let receipt = eval.evaluate(SecurityEpoch::from_raw(99));
    assert_eq!(receipt.epoch, SecurityEpoch::from_raw(99));
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic_two_evaluations() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    eval.add_skew(
        VectorizedLane::ArrayHigherOrder,
        10_000,
        500,
        450,
        1500,
        1400,
        50,
    );
    let r1 = eval.evaluate(epoch());
    let r2 = eval.evaluate(epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_when_data_added() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let r1 = eval.evaluate(epoch());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    let r2 = eval.evaluate(epoch());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_with_epoch() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let r1 = eval.evaluate(SecurityEpoch::from_raw(1));
    let r2 = eval.evaluate(SecurityEpoch::from_raw(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// E2E scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_full_pass_all_lanes_relaxed() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for lane in VectorizedLane::all() {
        eval.add_parity(*lane, ParityAxis::Semantic, 960_000, 50);
        eval.add_parity(*lane, ParityAxis::Performance, 970_000, 50);
        eval.add_skew(*lane, 30_000, 1000, 900, 3000, 2800, 50);
        eval.add_cold_start(*lane, 1100, 1000);
        eval.add_tail_risk(*lane, 2_050_000, 2_050_000, 50);
        eval.add_observability(*lane, 10, 9);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert_eq!(receipt.lanes_evaluated.len(), 10);
    assert!(receipt.lanes_missing.is_empty());
}

#[test]
fn test_e2e_mixed_pass_fail_single_category() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        100,
    );
    eval.add_parity(
        VectorizedLane::StringSearch,
        ParityAxis::Semantic,
        500_000,
        100,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
    assert_eq!(receipt.violations.len(), 1);
    assert_eq!(receipt.violations[0].lane, VectorizedLane::StringSearch);
}

#[test]
fn test_e2e_strict_empty_fails_coverage() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::strict());
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert_eq!(receipt.lanes_missing.len(), 10);
}

#[test]
fn test_e2e_violation_detail_contents() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_skew(
        VectorizedLane::MathBatch,
        150_000,
        1000,
        900,
        3000,
        2800,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.violations.len(), 1);
    let v = &receipt.violations[0];
    assert_eq!(v.lane, VectorizedLane::MathBatch);
    assert_eq!(v.category, GovernanceVerdict::SkewExceeded);
    assert_eq!(v.measured_millionths, 150_000);
    assert_eq!(v.threshold_millionths, DEFAULT_MAX_SKEW_MILLIONTHS);
}

#[test]
fn test_e2e_three_different_violation_categories() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        500_000,
        50,
    );
    eval.add_cold_start(VectorizedLane::TypedArrayBulk, 5000, 1000);
    eval.add_observability(VectorizedLane::BufferOps, 100, 10);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violations.len() >= 3);
}

#[test]
fn test_e2e_single_lane_all_axes_pass() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let lane = VectorizedLane::ObjectEnumeration;
    eval.add_parity(lane, ParityAxis::Semantic, 980_000, 50);
    eval.add_parity(lane, ParityAxis::Performance, 970_000, 50);
    eval.add_parity(lane, ParityAxis::Memory, 990_000, 50);
    eval.add_parity(lane, ParityAxis::ErrorPath, 985_000, 50);
    eval.add_parity(lane, ParityAxis::SideEffect, 975_000, 50);
    eval.add_parity(lane, ParityAxis::GcPressure, 960_000, 50);
    eval.add_skew(lane, 20_000, 800, 750, 2000, 1900, 50);
    eval.add_cold_start(lane, 1100, 1000);
    eval.add_tail_risk(lane, 2_050_000, 2_050_000, 50);
    eval.add_observability(lane, 20, 18);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.lanes_evaluated.contains(&lane));
}
