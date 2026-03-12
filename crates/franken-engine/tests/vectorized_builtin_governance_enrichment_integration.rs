// Enrichment integration tests for vectorized_builtin_governance module.
//
// Covers: SkewInput construction, serde round-trips, arithmetic edge cases,
// per-lane/axis display completeness, strict-mode full-pass, cold-start
// reverse overhead, violation summary format, and multi-entry accumulation.
//
// Bead: bd-1lsy.7.24.3 [RGC-624C]

use std::collections::BTreeSet;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_builtin_governance::*;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// SkewInput struct construction
// ---------------------------------------------------------------------------

#[test]
fn test_skew_input_field_access() {
    let si = SkewInput {
        lane: VectorizedLane::ArrayHigherOrder,
        skew_millionths: 50_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 100,
    };
    assert_eq!(si.lane, VectorizedLane::ArrayHigherOrder);
    assert_eq!(si.skew_millionths, 50_000);
    assert_eq!(si.scalar_p50_ns, 1000);
    assert_eq!(si.vectorized_p50_ns, 900);
    assert_eq!(si.scalar_p99_ns, 3000);
    assert_eq!(si.vectorized_p99_ns, 2800);
    assert_eq!(si.sample_count, 100);
}

#[test]
fn test_skew_input_clone_eq() {
    let si = SkewInput {
        lane: VectorizedLane::MathBatch,
        skew_millionths: 10_000,
        scalar_p50_ns: 500,
        vectorized_p50_ns: 480,
        scalar_p99_ns: 1500,
        vectorized_p99_ns: 1400,
        sample_count: 200,
    };
    let cloned = si;
    assert_eq!(si, cloned);
}

#[test]
fn test_skew_input_zero_skew() {
    let si = SkewInput {
        lane: VectorizedLane::StringSearch,
        skew_millionths: 0,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 1000,
        scalar_p99_ns: 2000,
        vectorized_p99_ns: 2000,
        sample_count: 50,
    };
    assert_eq!(si.skew_millionths, 0);
}

// ---------------------------------------------------------------------------
// Serde round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn test_vectorized_lane_serde_roundtrip() {
    for lane in VectorizedLane::all() {
        let json = serde_json::to_string(lane).unwrap();
        let back: VectorizedLane = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, back);
    }
}

#[test]
fn test_parity_axis_serde_roundtrip() {
    let axes = [
        ParityAxis::Semantic,
        ParityAxis::Performance,
        ParityAxis::Memory,
        ParityAxis::ErrorPath,
        ParityAxis::SideEffect,
        ParityAxis::GcPressure,
    ];
    for axis in &axes {
        let json = serde_json::to_string(axis).unwrap();
        let back: ParityAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*axis, back);
    }
}

#[test]
fn test_governance_verdict_serde_roundtrip() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::ParityViolation,
        GovernanceVerdict::SkewExceeded,
        GovernanceVerdict::ColdStartExceeded,
        GovernanceVerdict::TailRiskExceeded,
        GovernanceVerdict::ObservabilityInsufficient,
        GovernanceVerdict::InsufficientCoverage,
        GovernanceVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_skew_input_serde_roundtrip() {
    let si = SkewInput {
        lane: VectorizedLane::JsonCodec,
        skew_millionths: 75_000,
        scalar_p50_ns: 800,
        vectorized_p50_ns: 720,
        scalar_p99_ns: 2400,
        vectorized_p99_ns: 2100,
        sample_count: 150,
    };
    let json = serde_json::to_string(&si).unwrap();
    let back: SkewInput = serde_json::from_str(&json).unwrap();
    assert_eq!(si, back);
}

#[test]
fn test_parity_result_serde_roundtrip() {
    let pr = ParityResult::new(
        VectorizedLane::BufferOps,
        ParityAxis::Memory,
        970_000,
        80,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    let json = serde_json::to_string(&pr).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

#[test]
fn test_governance_config_serde_roundtrip() {
    let config = GovernanceConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn test_governance_receipt_serde_roundtrip() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        980_000,
        50,
    );
    eval.add_cold_start(VectorizedLane::StringSearch, 1100, 1000);
    let receipt = eval.evaluate(epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// VectorizedLane display completeness
// ---------------------------------------------------------------------------

#[test]
fn test_vectorized_lane_display_string_search() {
    assert_eq!(VectorizedLane::StringSearch.to_string(), "string_search");
}

#[test]
fn test_vectorized_lane_display_typed_array_bulk() {
    assert_eq!(
        VectorizedLane::TypedArrayBulk.to_string(),
        "typed_array_bulk"
    );
}

#[test]
fn test_vectorized_lane_display_regexp_match() {
    assert_eq!(VectorizedLane::RegexpMatch.to_string(), "regexp_match");
}

#[test]
fn test_vectorized_lane_display_object_enumeration() {
    assert_eq!(
        VectorizedLane::ObjectEnumeration.to_string(),
        "object_enumeration"
    );
}

#[test]
fn test_vectorized_lane_display_collection_iteration() {
    assert_eq!(
        VectorizedLane::CollectionIteration.to_string(),
        "collection_iteration"
    );
}

#[test]
fn test_vectorized_lane_display_buffer_ops() {
    assert_eq!(VectorizedLane::BufferOps.to_string(), "buffer_ops");
}

#[test]
fn test_vectorized_lane_display_promise_combinator() {
    assert_eq!(
        VectorizedLane::PromiseCombinator.to_string(),
        "promise_combinator"
    );
}

// ---------------------------------------------------------------------------
// ParityAxis display completeness
// ---------------------------------------------------------------------------

#[test]
fn test_parity_axis_display_performance() {
    assert_eq!(ParityAxis::Performance.to_string(), "performance");
}

#[test]
fn test_parity_axis_display_memory() {
    assert_eq!(ParityAxis::Memory.to_string(), "memory");
}

#[test]
fn test_parity_axis_display_error_path() {
    assert_eq!(ParityAxis::ErrorPath.to_string(), "error_path");
}

#[test]
fn test_parity_axis_display_side_effect() {
    assert_eq!(ParityAxis::SideEffect.to_string(), "side_effect");
}

// ---------------------------------------------------------------------------
// GovernanceVerdict display completeness
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_display_approved() {
    assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
}

#[test]
fn test_verdict_display_skew_exceeded() {
    assert_eq!(GovernanceVerdict::SkewExceeded.to_string(), "skew_exceeded");
}

#[test]
fn test_verdict_display_tail_risk_exceeded() {
    assert_eq!(
        GovernanceVerdict::TailRiskExceeded.to_string(),
        "tail_risk_exceeded"
    );
}

#[test]
fn test_verdict_display_observability_insufficient() {
    assert_eq!(
        GovernanceVerdict::ObservabilityInsufficient.to_string(),
        "observability_insufficient"
    );
}

#[test]
fn test_verdict_display_insufficient_coverage() {
    assert_eq!(
        GovernanceVerdict::InsufficientCoverage.to_string(),
        "insufficient_coverage"
    );
}

#[test]
fn test_verdict_display_multiple_violations() {
    assert_eq!(
        GovernanceVerdict::MultipleViolations.to_string(),
        "multiple_violations"
    );
}

// ---------------------------------------------------------------------------
// Arithmetic edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_cold_less_than_warm_zero_overhead() {
    let c = ColdStartEntry::new(
        VectorizedLane::MathBatch,
        500,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_eq!(c.overhead_millionths, 0);
    assert!(c.within_budget);
}

#[test]
fn test_cold_start_large_values_no_overflow() {
    let c = ColdStartEntry::new(
        VectorizedLane::BufferOps,
        u64::MAX / 2,
        u64::MAX / 4,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    // saturating_mul should cap instead of panicking
    assert!(c.overhead_millionths > 0);
}

#[test]
fn test_skew_entry_exact_budget_boundary() {
    let s = SkewEntry::new(
        SkewInput {
            lane: VectorizedLane::ArrayHigherOrder,
            skew_millionths: DEFAULT_MAX_SKEW_MILLIONTHS,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 900,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2800,
            sample_count: 100,
        },
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert!(s.within_budget);
}

#[test]
fn test_skew_entry_one_over_budget() {
    let s = SkewEntry::new(
        SkewInput {
            lane: VectorizedLane::ArrayHigherOrder,
            skew_millionths: DEFAULT_MAX_SKEW_MILLIONTHS + 1,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 900,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2800,
            sample_count: 100,
        },
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert!(!s.within_budget);
}

#[test]
fn test_tail_risk_exact_budget_boundary() {
    let t = TailRiskEntry::new(
        VectorizedLane::CollectionIteration,
        2_050_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(t.regression_millionths, 50_000);
    assert!(t.within_budget);
}

#[test]
fn test_tail_risk_one_over_budget() {
    let t = TailRiskEntry::new(
        VectorizedLane::CollectionIteration,
        2_050_001,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_eq!(t.regression_millionths, 50_001);
    assert!(!t.within_budget);
}

#[test]
fn test_parity_result_exact_boundary_passes() {
    let r = ParityResult::new(
        VectorizedLane::RegexpMatch,
        ParityAxis::ErrorPath,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert!(r.passes);
}

#[test]
fn test_observability_exact_boundary_adequate() {
    // 80 / 100 = 800_000 millionths = DEFAULT_MIN_OBSERVABILITY_COVERAGE
    let o = ObservabilityCoverage::new(
        VectorizedLane::ObjectEnumeration,
        100,
        80,
        DEFAULT_MIN_OBSERVABILITY_COVERAGE,
    );
    assert_eq!(o.coverage_millionths, 800_000);
    assert!(o.adequate);
}

#[test]
fn test_observability_one_below_boundary() {
    let o = ObservabilityCoverage::new(
        VectorizedLane::ObjectEnumeration,
        100,
        79,
        DEFAULT_MIN_OBSERVABILITY_COVERAGE,
    );
    assert_eq!(o.coverage_millionths, 790_000);
    assert!(!o.adequate);
}

// ---------------------------------------------------------------------------
// Hash collision resistance
// ---------------------------------------------------------------------------

#[test]
fn test_parity_result_hash_differs_on_axis() {
    let a = ParityResult::new(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    let b = ParityResult::new(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Performance,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_parity_result_hash_differs_on_parity_value() {
    let a = ParityResult::new(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        980_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    let b = ParityResult::new(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        970_000,
        100,
        DEFAULT_MIN_PARITY_MILLIONTHS,
        DEFAULT_MIN_SAMPLES,
    );
    assert_ne!(a.evidence_hash, b.evidence_hash);
}

#[test]
fn test_skew_entry_hash_differs_on_lane() {
    let a = SkewEntry::new(
        SkewInput {
            lane: VectorizedLane::ArrayHigherOrder,
            skew_millionths: 50_000,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 900,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2800,
            sample_count: 100,
        },
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    let b = SkewEntry::new(
        SkewInput {
            lane: VectorizedLane::StringSearch,
            skew_millionths: 50_000,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 900,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2800,
            sample_count: 100,
        },
        DEFAULT_MAX_SKEW_MILLIONTHS,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_cold_start_hash_differs_on_times() {
    let a = ColdStartEntry::new(
        VectorizedLane::MathBatch,
        1200,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    let b = ColdStartEntry::new(
        VectorizedLane::MathBatch,
        1300,
        1000,
        DEFAULT_MAX_COLD_START_OVERHEAD,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

#[test]
fn test_tail_risk_hash_differs_on_ratio() {
    let a = TailRiskEntry::new(
        VectorizedLane::RegexpMatch,
        2_100_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    let b = TailRiskEntry::new(
        VectorizedLane::RegexpMatch,
        2_200_000,
        2_000_000,
        100,
        DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
    );
    assert_ne!(a.entry_hash, b.entry_hash);
}

// ---------------------------------------------------------------------------
// Strict config full pass
// ---------------------------------------------------------------------------

#[test]
fn test_strict_config_full_pass_all_lanes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::strict());
    for lane in VectorizedLane::all() {
        eval.add_parity(*lane, ParityAxis::Semantic, FIXED_ONE, 200);
        eval.add_parity(*lane, ParityAxis::Performance, FIXED_ONE, 200);
        eval.add_skew(SkewInput {
            lane: *lane,
            skew_millionths: 10_000,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 950,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2900,
            sample_count: 200,
        });
        eval.add_cold_start(*lane, 1050, 1000);
        eval.add_tail_risk(*lane, 2_010_000, 2_000_000, 200);
        eval.add_observability(*lane, 100, 96);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert_eq!(receipt.lanes_evaluated.len(), 10);
    assert!(receipt.lanes_missing.is_empty());
}

// ---------------------------------------------------------------------------
// Config field mutation
// ---------------------------------------------------------------------------

#[test]
fn test_config_custom_required_lanes_subset() {
    let mut config = GovernanceConfig::relaxed();
    config
        .required_lanes
        .insert(VectorizedLane::ArrayHigherOrder);
    config.required_lanes.insert(VectorizedLane::JsonCodec);
    assert_eq!(config.required_lanes.len(), 2);

    let mut eval = GovernanceEvaluator::new(config);
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    // Missing JsonCodec evidence
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    assert!(receipt.lanes_missing.contains(&VectorizedLane::JsonCodec));
    assert!(
        !receipt
            .lanes_missing
            .contains(&VectorizedLane::ArrayHigherOrder)
    );
}

#[test]
fn test_config_custom_thresholds() {
    let mut config = GovernanceConfig::relaxed();
    config.max_skew_millionths = 500_000; // very lenient
    let mut eval = GovernanceEvaluator::new(config);
    eval.add_skew(SkewInput {
        lane: VectorizedLane::ArrayHigherOrder,
        skew_millionths: 400_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 50,
    });
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
}

// ---------------------------------------------------------------------------
// Multi-entry accumulation
// ---------------------------------------------------------------------------

#[test]
fn test_accumulate_multiple_parity_same_lane_different_axes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let lane = VectorizedLane::TypedArrayBulk;
    eval.add_parity(lane, ParityAxis::Semantic, 990_000, 50);
    eval.add_parity(lane, ParityAxis::Performance, 960_000, 50);
    eval.add_parity(lane, ParityAxis::Memory, 970_000, 50);
    eval.add_parity(lane, ParityAxis::ErrorPath, 980_000, 50);
    eval.add_parity(lane, ParityAxis::SideEffect, 965_000, 50);
    eval.add_parity(lane, ParityAxis::GcPressure, 975_000, 50);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.parity_results.len(), 6);
}

#[test]
fn test_accumulate_skew_across_all_lanes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for lane in VectorizedLane::all() {
        eval.add_skew(SkewInput {
            lane: *lane,
            skew_millionths: 30_000,
            scalar_p50_ns: 1000,
            vectorized_p50_ns: 900,
            scalar_p99_ns: 3000,
            vectorized_p99_ns: 2800,
            sample_count: 50,
        });
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.skew_entries.len(), 10);
    assert_eq!(receipt.lanes_evaluated.len(), 10);
}

#[test]
fn test_accumulate_cold_start_across_all_lanes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for lane in VectorizedLane::all() {
        eval.add_cold_start(*lane, 1100, 1000);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.cold_start_entries.len(), 10);
}

#[test]
fn test_accumulate_tail_risk_across_all_lanes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for lane in VectorizedLane::all() {
        eval.add_tail_risk(*lane, 2_040_000, 2_000_000, 100);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.tail_risk_entries.len(), 10);
}

#[test]
fn test_accumulate_observability_across_all_lanes() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    for lane in VectorizedLane::all() {
        eval.add_observability(*lane, 20, 18);
    }
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    assert_eq!(receipt.observability_entries.len(), 10);
}

// ---------------------------------------------------------------------------
// Violation summary format
// ---------------------------------------------------------------------------

#[test]
fn test_parity_violation_summary_contains_lane_and_axis() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::JsonCodec,
        ParityAxis::ErrorPath,
        800_000,
        50,
    );
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert!(v.summary.contains("error_path"));
    assert!(v.summary.contains("json_codec"));
}

#[test]
fn test_skew_violation_summary_contains_lane() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_skew(SkewInput {
        lane: VectorizedLane::BufferOps,
        skew_millionths: 200_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 50,
    });
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert!(v.summary.contains("buffer_ops"));
}

#[test]
fn test_cold_start_violation_summary_contains_lane() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_cold_start(VectorizedLane::PromiseCombinator, 5000, 1000);
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert!(v.summary.contains("promise_combinator"));
}

#[test]
fn test_observability_violation_summary_contains_lane() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_observability(VectorizedLane::CollectionIteration, 100, 10);
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert!(v.summary.contains("collection_iteration"));
}

#[test]
fn test_missing_lane_violation_summary_contains_lane() {
    let mut config = GovernanceConfig::relaxed();
    config
        .required_lanes
        .insert(VectorizedLane::ObjectEnumeration);
    let eval = GovernanceEvaluator::new(config);
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert!(v.summary.contains("object_enumeration"));
}

// ---------------------------------------------------------------------------
// Evaluator state isolation
// ---------------------------------------------------------------------------

#[test]
fn test_evaluator_new_starts_empty() {
    let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    assert!(eval.parity_results.is_empty());
    assert!(eval.skew_entries.is_empty());
    assert!(eval.cold_start_entries.is_empty());
    assert!(eval.tail_risk_entries.is_empty());
    assert!(eval.observability_entries.is_empty());
}

#[test]
fn test_evaluator_entries_grow_monotonically() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    assert_eq!(eval.parity_results.len(), 0);
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    assert_eq!(eval.parity_results.len(), 1);
    eval.add_parity(
        VectorizedLane::StringSearch,
        ParityAxis::Performance,
        FIXED_ONE,
        50,
    );
    assert_eq!(eval.parity_results.len(), 2);
}

// ---------------------------------------------------------------------------
// ViolationDetail field verification
// ---------------------------------------------------------------------------

#[test]
fn test_violation_detail_measured_vs_threshold_parity() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(VectorizedLane::RegexpMatch, ParityAxis::Memory, 700_000, 50);
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert_eq!(v.measured_millionths, 700_000);
    assert_eq!(v.threshold_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
    assert!(v.measured_millionths < v.threshold_millionths);
}

#[test]
fn test_violation_detail_measured_vs_threshold_skew() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_skew(SkewInput {
        lane: VectorizedLane::TypedArrayBulk,
        skew_millionths: 300_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 50,
    });
    let receipt = eval.evaluate(epoch());
    let v = &receipt.violations[0];
    assert_eq!(v.measured_millionths, 300_000);
    assert_eq!(v.threshold_millionths, DEFAULT_MAX_SKEW_MILLIONTHS);
    assert!(v.measured_millionths > v.threshold_millionths);
}

// ---------------------------------------------------------------------------
// Receipt content integrity
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_preserves_all_entries() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    eval.add_skew(SkewInput {
        lane: VectorizedLane::StringSearch,
        skew_millionths: 20_000,
        scalar_p50_ns: 500,
        vectorized_p50_ns: 480,
        scalar_p99_ns: 1500,
        vectorized_p99_ns: 1400,
        sample_count: 50,
    });
    eval.add_cold_start(VectorizedLane::JsonCodec, 1100, 1000);
    eval.add_tail_risk(VectorizedLane::TypedArrayBulk, 2_020_000, 2_000_000, 50);
    eval.add_observability(VectorizedLane::BufferOps, 10, 9);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.parity_results.len(), 1);
    assert_eq!(receipt.skew_entries.len(), 1);
    assert_eq!(receipt.cold_start_entries.len(), 1);
    assert_eq!(receipt.tail_risk_entries.len(), 1);
    assert_eq!(receipt.observability_entries.len(), 1);
    assert_eq!(receipt.lanes_evaluated.len(), 5);
}

#[test]
fn test_receipt_hash_differs_with_different_violations() {
    let mut eval1 = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval1.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        800_000,
        50,
    );
    let r1 = eval1.evaluate(epoch());

    let mut eval2 = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval2.add_skew(SkewInput {
        lane: VectorizedLane::ArrayHigherOrder,
        skew_millionths: 200_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 50,
    });
    let r2 = eval2.evaluate(epoch());

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// BTreeSet lane collection semantics
// ---------------------------------------------------------------------------

#[test]
fn test_lanes_evaluated_deduplicates() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    let lane = VectorizedLane::ArrayHigherOrder;
    eval.add_parity(lane, ParityAxis::Semantic, FIXED_ONE, 50);
    eval.add_parity(lane, ParityAxis::Performance, FIXED_ONE, 50);
    eval.add_skew(SkewInput {
        lane,
        skew_millionths: 10_000,
        scalar_p50_ns: 500,
        vectorized_p50_ns: 480,
        scalar_p99_ns: 1500,
        vectorized_p99_ns: 1400,
        sample_count: 50,
    });
    eval.add_cold_start(lane, 1100, 1000);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.lanes_evaluated.len(), 1);
    assert!(receipt.lanes_evaluated.contains(&lane));
}

#[test]
fn test_lanes_missing_only_includes_required() {
    let mut config = GovernanceConfig::relaxed();
    config.required_lanes.insert(VectorizedLane::MathBatch);
    config.required_lanes.insert(VectorizedLane::BufferOps);
    let mut eval = GovernanceEvaluator::new(config);
    eval.add_parity(
        VectorizedLane::BufferOps,
        ParityAxis::Semantic,
        FIXED_ONE,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert!(receipt.lanes_missing.contains(&VectorizedLane::MathBatch));
    assert!(!receipt.lanes_missing.contains(&VectorizedLane::BufferOps));
}

// ---------------------------------------------------------------------------
// Multiple violations from same category collapse to single verdict
// ---------------------------------------------------------------------------

#[test]
fn test_same_category_violations_single_verdict() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        800_000,
        50,
    );
    eval.add_parity(
        VectorizedLane::StringSearch,
        ParityAxis::Performance,
        700_000,
        50,
    );
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
    assert_eq!(receipt.violations.len(), 2);
}

#[test]
fn test_four_different_violation_categories_gives_multiple() {
    let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
    eval.add_parity(
        VectorizedLane::ArrayHigherOrder,
        ParityAxis::Semantic,
        800_000,
        50,
    );
    eval.add_skew(SkewInput {
        lane: VectorizedLane::StringSearch,
        skew_millionths: 200_000,
        scalar_p50_ns: 1000,
        vectorized_p50_ns: 900,
        scalar_p99_ns: 3000,
        vectorized_p99_ns: 2800,
        sample_count: 50,
    });
    eval.add_cold_start(VectorizedLane::JsonCodec, 5000, 1000);
    eval.add_observability(VectorizedLane::TypedArrayBulk, 100, 10);
    let receipt = eval.evaluate(epoch());
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    assert!(receipt.violations.len() >= 4);
    let categories: BTreeSet<GovernanceVerdict> =
        receipt.violations.iter().map(|v| v.category).collect();
    assert!(categories.len() >= 4);
}
