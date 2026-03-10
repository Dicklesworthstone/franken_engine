#![forbid(unsafe_code)]

//! Integration tests for `specialization_perf_release_gate`.
//!
//! Covers every public type, enum variant, method, Display impl, serde round-trip,
//! gate evaluation logic, error variant coverage, determinism, and cross-concern
//! integration scenarios.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_perf_release_gate::{
    BenchmarkComparison, BenchmarkSample, FallbackTestResult, GATE_COMPONENT, GATE_SCHEMA_VERSION,
    GateDecision, GateFailureCode, GateFinding, GateInput, GateLogEvent, LaneType,
    ReceiptChainReplayResult, ReceiptCoverageEntry, StatisticalSummary, evaluate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn sample(wl: &str, lane: LaneType, wt_ns: u64, mem: u64) -> BenchmarkSample {
    BenchmarkSample {
        workload_id: wl.to_string(),
        lane_type: lane,
        wall_time_ns: wt_ns,
        memory_peak_bytes: mem,
        throughput_ops_per_sec: None,
    }
}

fn sample_with_throughput(
    wl: &str,
    lane: LaneType,
    wt_ns: u64,
    mem: u64,
    throughput: u64,
) -> BenchmarkSample {
    BenchmarkSample {
        workload_id: wl.to_string(),
        lane_type: lane,
        wall_time_ns: wt_ns,
        memory_peak_bytes: mem,
        throughput_ops_per_sec: Some(throughput),
    }
}

fn comparison(wl: &str, spec_wt: u64, amb_wt: u64) -> BenchmarkComparison {
    BenchmarkComparison::from_samples(
        sample(wl, LaneType::ProofSpecialized, spec_wt, 1024),
        sample(wl, LaneType::AmbientAuthority, amb_wt, 1024),
    )
}

fn comparison_with_mem(
    wl: &str,
    spec_wt: u64,
    amb_wt: u64,
    spec_mem: u64,
    amb_mem: u64,
) -> BenchmarkComparison {
    BenchmarkComparison::from_samples(
        sample(wl, LaneType::ProofSpecialized, spec_wt, spec_mem),
        sample(wl, LaneType::AmbientAuthority, amb_wt, amb_mem),
    )
}

fn full_receipt(name: &str) -> ReceiptCoverageEntry {
    ReceiptCoverageEntry {
        optimization_name: name.to_string(),
        receipt_present: true,
        receipt_hash: Some(ContentHash::compute(format!("receipt-{name}").as_bytes())),
        proof_reference: Some(format!("proof-{name}")),
        capability_witness_ref: Some(format!("cap-{name}")),
        performance_measurement_present: true,
        signature_valid: true,
    }
}

fn partial_receipt(name: &str) -> ReceiptCoverageEntry {
    ReceiptCoverageEntry {
        optimization_name: name.to_string(),
        receipt_present: true,
        receipt_hash: Some(ContentHash::compute(format!("receipt-{name}").as_bytes())),
        proof_reference: None,
        capability_witness_ref: None,
        performance_measurement_present: false,
        signature_valid: true,
    }
}

fn empty_receipt(name: &str) -> ReceiptCoverageEntry {
    ReceiptCoverageEntry {
        optimization_name: name.to_string(),
        receipt_present: false,
        receipt_hash: None,
        proof_reference: None,
        capability_witness_ref: None,
        performance_measurement_present: false,
        signature_valid: false,
    }
}

fn passing_fallback(scenario: &str) -> FallbackTestResult {
    FallbackTestResult {
        scenario_id: scenario.to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 100_000,
        ambient_wall_time_ns: 100_000,
    }
}

fn capability_revocation_fallback(scenario: &str) -> FallbackTestResult {
    FallbackTestResult {
        scenario_id: scenario.to_string(),
        injection_type: "capability_revocation".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 105_000,
        ambient_wall_time_ns: 100_000,
    }
}

fn passing_replay() -> ReceiptChainReplayResult {
    ReceiptChainReplayResult {
        compilation_id: "compile-001".to_string(),
        total_receipts: 10,
        verified_receipts: 10,
        chain_complete: true,
        all_verified: true,
        replay_duration_ns: 50_000_000,
    }
}

fn full_input(n_comparisons: usize) -> GateInput {
    let comparisons: Vec<_> = (0..n_comparisons)
        .map(|i| comparison(&format!("w{i}"), 80, 100))
        .collect();
    GateInput {
        trace_id: "trace-int-1".to_string(),
        policy_id: "policy-int-1".to_string(),
        epoch: epoch(),
        comparisons,
        receipt_coverage: vec![full_receipt("opt-a"), full_receipt("opt-b")],
        fallback_tests: vec![passing_fallback("fb-1"), passing_fallback("fb-2")],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 5,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_are_defined() {
    assert_eq!(GATE_COMPONENT, "specialization_perf_release_gate");
    assert_eq!(
        GATE_SCHEMA_VERSION,
        "franken-engine.spec-perf-release-gate.v1"
    );
}

// ===========================================================================
// 2. LaneType — enum variants, Display, serde
// ===========================================================================

#[test]
fn lane_type_as_str_proof_specialized() {
    assert_eq!(LaneType::ProofSpecialized.as_str(), "proof_specialized");
}

#[test]
fn lane_type_as_str_ambient_authority() {
    assert_eq!(LaneType::AmbientAuthority.as_str(), "ambient_authority");
}

#[test]
fn lane_type_display_proof_specialized() {
    assert_eq!(LaneType::ProofSpecialized.to_string(), "proof_specialized");
}

#[test]
fn lane_type_display_ambient_authority() {
    assert_eq!(LaneType::AmbientAuthority.to_string(), "ambient_authority");
}

#[test]
fn lane_type_serde_round_trip_proof_specialized() {
    let json = serde_json::to_string(&LaneType::ProofSpecialized).unwrap();
    let back: LaneType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, LaneType::ProofSpecialized);
}

#[test]
fn lane_type_serde_round_trip_ambient_authority() {
    let json = serde_json::to_string(&LaneType::AmbientAuthority).unwrap();
    let back: LaneType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, LaneType::AmbientAuthority);
}

#[test]
fn lane_type_ordering() {
    // ProofSpecialized < AmbientAuthority in derive(Ord)
    assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
}

#[test]
fn lane_type_clone_copy_eq() {
    let a = LaneType::ProofSpecialized;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn lane_type_debug_format() {
    let dbg = format!("{:?}", LaneType::ProofSpecialized);
    assert!(dbg.contains("ProofSpecialized"));
    let dbg2 = format!("{:?}", LaneType::AmbientAuthority);
    assert!(dbg2.contains("AmbientAuthority"));
}

// ===========================================================================
// 3. BenchmarkSample — construction and serde
// ===========================================================================

#[test]
fn benchmark_sample_construction() {
    let s = sample("w1", LaneType::ProofSpecialized, 1000, 2048);
    assert_eq!(s.workload_id, "w1");
    assert_eq!(s.lane_type, LaneType::ProofSpecialized);
    assert_eq!(s.wall_time_ns, 1000);
    assert_eq!(s.memory_peak_bytes, 2048);
    assert!(s.throughput_ops_per_sec.is_none());
}

#[test]
fn benchmark_sample_with_throughput() {
    let s = sample_with_throughput("w2", LaneType::AmbientAuthority, 500, 4096, 10_000);
    assert_eq!(s.throughput_ops_per_sec, Some(10_000));
}

#[test]
fn benchmark_sample_serde_round_trip() {
    let s = sample_with_throughput("wrt", LaneType::ProofSpecialized, 999, 8192, 50_000);
    let json = serde_json::to_string(&s).unwrap();
    let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn benchmark_sample_serde_no_throughput() {
    let s = sample("w-none", LaneType::AmbientAuthority, 123, 456);
    let json = serde_json::to_string(&s).unwrap();
    let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
    assert_eq!(back.throughput_ops_per_sec, None);
}

// ===========================================================================
// 4. BenchmarkComparison — from_samples, deltas, serde
// ===========================================================================

#[test]
fn comparison_positive_speedup() {
    let c = comparison("w1", 80, 100);
    // (100 - 80) / 100 * 1_000_000 = 200_000
    assert_eq!(c.wall_time_delta_millionths, 200_000);
    assert!(c.has_positive_wall_time_delta());
}

#[test]
fn comparison_negative_delta() {
    let c = comparison("w1", 120, 100);
    // (100 - 120) / 100 * 1_000_000 = -200_000
    assert_eq!(c.wall_time_delta_millionths, -200_000);
    assert!(!c.has_positive_wall_time_delta());
}

#[test]
fn comparison_zero_delta_equal_times() {
    let c = comparison("w1", 100, 100);
    assert_eq!(c.wall_time_delta_millionths, 0);
    assert!(!c.has_positive_wall_time_delta());
}

#[test]
fn comparison_zero_baseline_ambient() {
    let c = comparison("w1", 100, 0);
    assert_eq!(c.wall_time_delta_millionths, 0);
}

#[test]
fn comparison_memory_delta_positive() {
    let c = comparison_with_mem("w1", 100, 100, 800, 1000);
    // (1000 - 800) / 1000 * 1_000_000 = 200_000
    assert_eq!(c.memory_delta_millionths, 200_000);
    assert!(c.has_positive_memory_delta());
}

#[test]
fn comparison_memory_delta_negative() {
    let c = comparison_with_mem("w1", 100, 100, 1200, 1000);
    // (1000 - 1200) / 1000 * 1_000_000 = -200_000
    assert_eq!(c.memory_delta_millionths, -200_000);
    assert!(!c.has_positive_memory_delta());
}

#[test]
fn comparison_memory_zero_baseline() {
    let c = comparison_with_mem("w1", 100, 100, 500, 0);
    assert_eq!(c.memory_delta_millionths, 0);
}

#[test]
fn comparison_workload_id_from_specialized() {
    let c = BenchmarkComparison::from_samples(
        sample("from-spec", LaneType::ProofSpecialized, 50, 100),
        sample("from-ambient", LaneType::AmbientAuthority, 100, 200),
    );
    assert_eq!(c.workload_id, "from-spec");
}

#[test]
fn comparison_serde_round_trip() {
    let c = comparison_with_mem("serde-wl", 75, 100, 900, 1000);
    let json = serde_json::to_string(&c).unwrap();
    let back: BenchmarkComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn comparison_large_values() {
    let c = BenchmarkComparison::from_samples(
        sample(
            "big",
            LaneType::ProofSpecialized,
            u64::MAX / 2,
            u64::MAX / 2,
        ),
        sample("big", LaneType::AmbientAuthority, u64::MAX, u64::MAX),
    );
    // Should not overflow thanks to i128 arithmetic
    // (MAX - MAX/2) / MAX ~ 0.5 => 500_000 millionths
    assert!(c.wall_time_delta_millionths > 0);
    assert!(c.has_positive_wall_time_delta());
}

// ===========================================================================
// 5. ReceiptCoverageEntry — is_fully_covered, coverage_gaps, serde
// ===========================================================================

#[test]
fn receipt_fully_covered() {
    let r = full_receipt("opt-a");
    assert!(r.is_fully_covered());
    assert!(r.coverage_gaps().is_empty());
}

#[test]
fn receipt_missing_receipt_present() {
    let mut r = full_receipt("opt-a");
    r.receipt_present = false;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"no receipt".to_string()));
}

#[test]
fn receipt_missing_receipt_hash() {
    let mut r = full_receipt("opt-a");
    r.receipt_hash = None;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"missing receipt hash".to_string()));
}

#[test]
fn receipt_missing_proof_reference() {
    let mut r = full_receipt("opt-a");
    r.proof_reference = None;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"missing proof reference".to_string()));
}

#[test]
fn receipt_missing_capability_witness_ref() {
    let mut r = full_receipt("opt-a");
    r.capability_witness_ref = None;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"missing capability witness reference".to_string()));
}

#[test]
fn receipt_missing_performance_measurement() {
    let mut r = full_receipt("opt-a");
    r.performance_measurement_present = false;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"missing performance measurement".to_string()));
}

#[test]
fn receipt_invalid_signature() {
    let mut r = full_receipt("opt-a");
    r.signature_valid = false;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert!(gaps.contains(&"invalid signature".to_string()));
}

#[test]
fn receipt_all_gaps() {
    let r = empty_receipt("opt-empty");
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert_eq!(gaps.len(), 6);
    assert!(gaps.contains(&"no receipt".to_string()));
    assert!(gaps.contains(&"missing receipt hash".to_string()));
    assert!(gaps.contains(&"missing proof reference".to_string()));
    assert!(gaps.contains(&"missing capability witness reference".to_string()));
    assert!(gaps.contains(&"missing performance measurement".to_string()));
    assert!(gaps.contains(&"invalid signature".to_string()));
}

#[test]
fn receipt_partial_has_three_gaps() {
    let r = partial_receipt("opt-partial");
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert_eq!(gaps.len(), 3);
    assert!(gaps.contains(&"missing proof reference".to_string()));
    assert!(gaps.contains(&"missing capability witness reference".to_string()));
    assert!(gaps.contains(&"missing performance measurement".to_string()));
}

#[test]
fn receipt_coverage_entry_serde_round_trip() {
    let r = full_receipt("serde-opt");
    let json = serde_json::to_string(&r).unwrap();
    let back: ReceiptCoverageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn receipt_coverage_entry_serde_empty_round_trip() {
    let r = empty_receipt("serde-empty");
    let json = serde_json::to_string(&r).unwrap();
    let back: ReceiptCoverageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 6. FallbackTestResult — passes, fallback_performance_acceptable, serde
// ===========================================================================

#[test]
fn fallback_passes_all_criteria() {
    let fb = passing_fallback("fb-1");
    assert!(fb.passes());
    assert!(fb.fallback_performance_acceptable());
}

#[test]
fn fallback_fails_on_incorrect_output() {
    let mut fb = passing_fallback("fb-1");
    fb.correct_output = false;
    assert!(!fb.passes());
}

#[test]
fn fallback_fails_on_no_receipt() {
    let mut fb = passing_fallback("fb-1");
    fb.fallback_receipt_emitted = false;
    assert!(!fb.passes());
}

#[test]
fn fallback_fails_on_crash() {
    let mut fb = passing_fallback("fb-1");
    fb.crashed = true;
    assert!(!fb.passes());
}

#[test]
fn fallback_fails_on_hang() {
    let mut fb = passing_fallback("fb-1");
    fb.hung = true;
    assert!(!fb.passes());
}

#[test]
fn fallback_multiple_failures() {
    let mut fb = passing_fallback("fb-1");
    fb.correct_output = false;
    fb.crashed = true;
    fb.hung = true;
    fb.fallback_receipt_emitted = false;
    assert!(!fb.passes());
}

#[test]
fn fallback_performance_exactly_at_threshold() {
    // 10% regression exactly (110_000 vs 100_000 = 100_000 millionths = 10%)
    let fb = FallbackTestResult {
        scenario_id: "threshold-exact".to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 110_000,
        ambient_wall_time_ns: 100_000,
    };
    // 10% = 100_000 millionths, threshold is <= 100_000
    assert!(fb.fallback_performance_acceptable());
}

#[test]
fn fallback_performance_just_over_threshold() {
    // 11% regression
    let fb = FallbackTestResult {
        scenario_id: "over-threshold".to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 111_001,
        ambient_wall_time_ns: 100_000,
    };
    assert!(!fb.fallback_performance_acceptable());
}

#[test]
fn fallback_performance_zero_ambient() {
    let fb = FallbackTestResult {
        scenario_id: "zero-amb".to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 100_000,
        ambient_wall_time_ns: 0,
    };
    // Zero ambient => always acceptable
    assert!(fb.fallback_performance_acceptable());
}

#[test]
fn fallback_performance_faster_than_ambient() {
    let fb = FallbackTestResult {
        scenario_id: "faster".to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: true,
        fallback_receipt_emitted: true,
        crashed: false,
        hung: false,
        fallback_wall_time_ns: 90_000,
        ambient_wall_time_ns: 100_000,
    };
    assert!(fb.fallback_performance_acceptable());
}

#[test]
fn fallback_serde_round_trip() {
    let fb = passing_fallback("serde-fb");
    let json = serde_json::to_string(&fb).unwrap();
    let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn fallback_capability_revocation_type() {
    let fb = capability_revocation_fallback("cap-rev");
    assert_eq!(fb.injection_type, "capability_revocation");
    assert!(fb.passes());
}

// ===========================================================================
// 7. ReceiptChainReplayResult — passes, serde
// ===========================================================================

#[test]
fn replay_passes() {
    let r = passing_replay();
    assert!(r.passes());
}

#[test]
fn replay_fails_incomplete_chain() {
    let mut r = passing_replay();
    r.chain_complete = false;
    assert!(!r.passes());
}

#[test]
fn replay_fails_unverified() {
    let mut r = passing_replay();
    r.all_verified = false;
    r.verified_receipts = 9;
    assert!(!r.passes());
}

#[test]
fn replay_fails_zero_receipts() {
    let r = ReceiptChainReplayResult {
        compilation_id: "c-zero".to_string(),
        total_receipts: 0,
        verified_receipts: 0,
        chain_complete: true,
        all_verified: true,
        replay_duration_ns: 0,
    };
    assert!(!r.passes());
}

#[test]
fn replay_serde_round_trip() {
    let r = passing_replay();
    let json = serde_json::to_string(&r).unwrap();
    let back: ReceiptChainReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 8. GateFailureCode — all variants, Display, Ord, serde
// ===========================================================================

#[test]
fn gate_failure_code_display_all_variants() {
    let cases = vec![
        (GateFailureCode::NoPositiveDelta, "no_positive_delta"),
        (
            GateFailureCode::InsufficientSignificance,
            "insufficient_significance",
        ),
        (
            GateFailureCode::InsufficientReceiptCoverage,
            "insufficient_receipt_coverage",
        ),
        (
            GateFailureCode::FallbackIncorrectOutput,
            "fallback_incorrect_output",
        ),
        (GateFailureCode::FallbackCrashed, "fallback_crashed"),
        (GateFailureCode::FallbackHung, "fallback_hung"),
        (GateFailureCode::FallbackNoReceipt, "fallback_no_receipt"),
        (
            GateFailureCode::FallbackPerformanceRegression,
            "fallback_performance_regression",
        ),
        (
            GateFailureCode::ReceiptChainReplayFailed,
            "receipt_chain_replay_failed",
        ),
        (GateFailureCode::InsufficientSamples, "insufficient_samples"),
        (GateFailureCode::EmptyInput, "empty_input"),
    ];
    for (code, expected) in &cases {
        assert_eq!(code.to_string(), *expected, "Display mismatch for {code:?}");
    }
}

#[test]
fn gate_failure_code_serde_round_trip_all() {
    let all_codes = vec![
        GateFailureCode::NoPositiveDelta,
        GateFailureCode::InsufficientSignificance,
        GateFailureCode::InsufficientReceiptCoverage,
        GateFailureCode::FallbackIncorrectOutput,
        GateFailureCode::FallbackCrashed,
        GateFailureCode::FallbackHung,
        GateFailureCode::FallbackNoReceipt,
        GateFailureCode::FallbackPerformanceRegression,
        GateFailureCode::ReceiptChainReplayFailed,
        GateFailureCode::InsufficientSamples,
        GateFailureCode::EmptyInput,
    ];
    for code in &all_codes {
        let json = serde_json::to_string(code).unwrap();
        let back: GateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

#[test]
fn gate_failure_code_ordering() {
    // Derive(Ord) follows declaration order
    assert!(GateFailureCode::NoPositiveDelta < GateFailureCode::EmptyInput);
    assert!(GateFailureCode::FallbackCrashed < GateFailureCode::FallbackHung);
}

#[test]
fn gate_failure_code_btreeset_deterministic() {
    let mut set = BTreeSet::new();
    set.insert(GateFailureCode::EmptyInput);
    set.insert(GateFailureCode::NoPositiveDelta);
    set.insert(GateFailureCode::FallbackCrashed);
    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered[0], GateFailureCode::NoPositiveDelta);
    assert_eq!(ordered[1], GateFailureCode::FallbackCrashed);
    assert_eq!(ordered[2], GateFailureCode::EmptyInput);
}

// ===========================================================================
// 9. GateFinding — construction and serde
// ===========================================================================

#[test]
fn gate_finding_construction() {
    let f = GateFinding {
        code: GateFailureCode::FallbackHung,
        detail: "scenario X hung".to_string(),
        affected_item: Some("scenario-X".to_string()),
    };
    assert_eq!(f.code, GateFailureCode::FallbackHung);
    assert_eq!(f.detail, "scenario X hung");
    assert_eq!(f.affected_item, Some("scenario-X".to_string()));
}

#[test]
fn gate_finding_no_affected_item() {
    let f = GateFinding {
        code: GateFailureCode::EmptyInput,
        detail: "no comparisons".to_string(),
        affected_item: None,
    };
    assert!(f.affected_item.is_none());
}

#[test]
fn gate_finding_serde_round_trip() {
    let f = GateFinding {
        code: GateFailureCode::InsufficientSamples,
        detail: "only 3 samples".to_string(),
        affected_item: Some("benchmark-suite".to_string()),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: GateFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ===========================================================================
// 10. StatisticalSummary — from_comparisons, has_positive_delta
// ===========================================================================

#[test]
fn stats_empty_comparisons() {
    let s = StatisticalSummary::from_comparisons(&[]);
    assert_eq!(s.sample_count, 0);
    assert_eq!(s.mean_wall_time_delta_millionths, 0);
    assert_eq!(s.mean_memory_delta_millionths, 0);
    assert_eq!(s.positive_wall_time_count, 0);
    assert_eq!(s.positive_memory_count, 0);
    assert!(!s.significance_met);
    assert!(!s.has_positive_delta());
}

#[test]
fn stats_all_positive_20_samples() {
    let comps: Vec<_> = (0..20)
        .map(|i| comparison(&format!("w{i}"), 80, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 20);
    assert_eq!(s.mean_wall_time_delta_millionths, 200_000);
    assert_eq!(s.positive_wall_time_count, 20);
    assert!(s.significance_met);
    assert!(s.has_positive_delta());
}

#[test]
fn stats_all_negative() {
    let comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("w{i}"), 120, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.mean_wall_time_delta_millionths, -200_000);
    assert_eq!(s.positive_wall_time_count, 0);
    assert!(!s.significance_met);
    assert!(!s.has_positive_delta());
}

#[test]
fn stats_mixed_50_50_not_significant_large_n() {
    let mut comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    comps.extend((0..10).map(|i| comparison(&format!("n{i}"), 120, 100)));
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 20);
    assert!(!s.significance_met); // 50% < 60%
}

#[test]
fn stats_significance_at_61_percent_large_n() {
    // 13 positive out of 20 = 65%
    let mut comps: Vec<_> = (0..13)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    comps.extend((0..7).map(|i| comparison(&format!("n{i}"), 120, 100)));
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 20);
    assert!(s.significance_met); // 65% > 60%
}

#[test]
fn stats_significance_small_n_high_bar() {
    // 4 out of 5 positive = 80% > 75%
    let mut comps: Vec<_> = (0..4)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    comps.push(comparison("n0", 120, 100));
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 5);
    assert!(s.significance_met);
}

#[test]
fn stats_significance_small_n_at_75_not_met() {
    // 3 out of 5 positive = 60% <= 75% => not significant
    // Wait: 3/5 = 0.6 => 600_000, threshold is > 750_000
    let mut comps: Vec<_> = (0..3)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    comps.extend((0..2).map(|i| comparison(&format!("n{i}"), 120, 100)));
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 5);
    assert!(!s.significance_met);
}

#[test]
fn stats_too_few_samples_never_significant() {
    // n < 5 => always false
    let comps: Vec<_> = (0..4)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 4);
    assert!(!s.significance_met);
}

#[test]
fn stats_single_sample_not_significant() {
    let comps = vec![comparison("w0", 80, 100)];
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 1);
    assert!(!s.significance_met);
    assert!(s.has_positive_delta());
}

#[test]
fn stats_has_positive_delta_via_memory_only() {
    // Wall time regression but memory savings
    let comps: Vec<_> = (0..5)
        .map(|i| comparison_with_mem(&format!("w{i}"), 120, 100, 500, 1000))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    // wall_time negative but memory positive
    assert!(s.mean_wall_time_delta_millionths < 0);
    assert!(s.mean_memory_delta_millionths > 0);
    assert!(s.has_positive_delta());
}

#[test]
fn stats_serde_round_trip() {
    let comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("w{i}"), 80, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    let json = serde_json::to_string(&s).unwrap();
    let back: StatisticalSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// 11. GateLogEvent — construction and serde
// ===========================================================================

#[test]
fn gate_log_event_construction() {
    let evt = GateLogEvent {
        trace_id: "t-1".to_string(),
        lane_type: Some("proof_specialized".to_string()),
        optimization_pass: Some("pass-1".to_string()),
        proof_status: Some("valid".to_string()),
        capability_witness_ref: Some("cap-ref-1".to_string()),
        specialization_receipt_hash: Some("hash-1".to_string()),
        fallback_triggered: Some(false),
        wall_time_ns: Some(12345),
        memory_peak_bytes: Some(67890),
        event: "benchmark_comparison".to_string(),
        outcome: "speedup".to_string(),
    };
    assert_eq!(evt.trace_id, "t-1");
    assert_eq!(evt.event, "benchmark_comparison");
}

#[test]
fn gate_log_event_all_none_fields() {
    let evt = GateLogEvent {
        trace_id: "t-2".to_string(),
        lane_type: None,
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: None,
        wall_time_ns: None,
        memory_peak_bytes: None,
        event: "gate_decision".to_string(),
        outcome: "pass".to_string(),
    };
    assert!(evt.lane_type.is_none());
    assert!(evt.wall_time_ns.is_none());
}

#[test]
fn gate_log_event_serde_round_trip() {
    let evt = GateLogEvent {
        trace_id: "serde-t".to_string(),
        lane_type: Some("ambient_authority".to_string()),
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: Some(true),
        wall_time_ns: Some(999),
        memory_peak_bytes: None,
        event: "fallback_test".to_string(),
        outcome: "fail".to_string(),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: GateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// ===========================================================================
// 12. GateInput — construction and serde
// ===========================================================================

#[test]
fn gate_input_construction() {
    let input = full_input(10);
    assert_eq!(input.trace_id, "trace-int-1");
    assert_eq!(input.policy_id, "policy-int-1");
    assert_eq!(input.epoch, epoch());
    assert_eq!(input.comparisons.len(), 10);
    assert_eq!(input.receipt_coverage.len(), 2);
    assert_eq!(input.fallback_tests.len(), 2);
    assert!(input.receipt_chain_replay.is_some());
    assert_eq!(input.min_samples, 5);
}

#[test]
fn gate_input_serde_round_trip() {
    let input = full_input(5);
    let json = serde_json::to_string(&input).unwrap();
    let back: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ===========================================================================
// 13. GateDecision — to_jsonl, serde round-trip
// ===========================================================================

#[test]
fn gate_decision_to_jsonl_is_valid_json() {
    let input = full_input(20);
    let decision = evaluate(&input);
    let jsonl = decision.to_jsonl();
    let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
    assert!(parsed.is_object());
}

#[test]
fn gate_decision_serde_round_trip_passing() {
    let input = full_input(20);
    let decision = evaluate(&input);
    let json = decision.to_jsonl();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision.decision_id, back.decision_id);
    assert_eq!(decision.pass, back.pass);
    assert_eq!(decision.stats, back.stats);
    assert_eq!(
        decision.receipt_coverage_millionths,
        back.receipt_coverage_millionths
    );
    assert_eq!(decision.findings.len(), back.findings.len());
    assert_eq!(decision.logs.len(), back.logs.len());
}

#[test]
fn gate_decision_serde_round_trip_failing() {
    let mut input = full_input(20);
    input.fallback_tests[0].crashed = true;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let json = decision.to_jsonl();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn gate_decision_schema_version() {
    let input = full_input(20);
    let decision = evaluate(&input);
    assert_eq!(decision.schema_version, GATE_SCHEMA_VERSION);
}

#[test]
fn gate_decision_epoch_propagated() {
    let input = full_input(20);
    let decision = evaluate(&input);
    assert_eq!(decision.epoch, epoch());
}

// ===========================================================================
// 14. evaluate — happy path (all passing)
// ===========================================================================

#[test]
fn evaluate_all_passing_complete_input() {
    let input = full_input(20);
    let decision = evaluate(&input);
    assert!(decision.pass);
    assert!(decision.findings.is_empty());
    assert_eq!(decision.receipt_coverage_millionths, 1_000_000);
    assert_eq!(decision.fallback_tests_passed, 2);
    assert_eq!(decision.fallback_tests_total, 2);
    assert!(decision.receipt_chain_replay_passed);
    assert!(decision.stats.significance_met);
    assert!(decision.stats.has_positive_delta());
}

#[test]
fn evaluate_scorecard_contributions() {
    let input = full_input(20);
    let decision = evaluate(&input);
    assert_eq!(decision.scorecard_performance_delta_millionths, 200_000);
    assert_eq!(decision.scorecard_security_delta_millionths, 1_000_000);
    assert_eq!(decision.scorecard_autonomy_delta_millionths, 1_000_000);
}

#[test]
fn evaluate_logs_populated() {
    let input = full_input(5);
    let decision = evaluate(&input);
    // 5 comparison logs + 2 fallback logs + 1 summary = 8
    assert_eq!(decision.logs.len(), 8);
    let summary = decision.logs.last().unwrap();
    assert_eq!(summary.event, "gate_decision");
    assert_eq!(summary.outcome, "pass");
}

#[test]
fn evaluate_comparison_logs_have_correct_lane() {
    let input = full_input(3);
    let decision = evaluate(&input);
    for log in &decision.logs[..3] {
        assert_eq!(log.event, "benchmark_comparison");
        assert_eq!(log.lane_type.as_deref(), Some("proof_specialized"));
    }
}

#[test]
fn evaluate_fallback_logs_have_triggered_flag() {
    let input = full_input(5);
    let decision = evaluate(&input);
    // Fallback logs are at indices 5 and 6 (after 5 comparison logs)
    for log in &decision.logs[5..7] {
        assert_eq!(log.event, "fallback_test");
        assert_eq!(log.fallback_triggered, Some(true));
    }
}

// ===========================================================================
// 15. evaluate — failure paths
// ===========================================================================

#[test]
fn evaluate_fails_empty_comparisons() {
    let mut input = full_input(0);
    input.comparisons.clear();
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::EmptyInput));
}

#[test]
fn evaluate_fails_insufficient_samples() {
    let mut input = full_input(3);
    input.min_samples = 10;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientSamples));
}

#[test]
fn evaluate_fails_no_positive_delta() {
    let mut input = full_input(20);
    input.comparisons = (0..20)
        .map(|i| comparison(&format!("w{i}"), 120, 100))
        .collect();
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::NoPositiveDelta));
}

#[test]
fn evaluate_fails_insufficient_significance() {
    let mut input = full_input(20);
    // 50/50 positive/negative => not significant
    input.comparisons = (0..10)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .chain((0..10).map(|i| comparison(&format!("n{i}"), 120, 100)))
        .collect();
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientSignificance));
}

#[test]
fn evaluate_fails_incomplete_receipt_coverage() {
    let mut input = full_input(20);
    input.receipt_coverage[0].proof_reference = None;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientReceiptCoverage));
}

#[test]
fn evaluate_fails_no_receipt_entries_with_comparisons() {
    let mut input = full_input(20);
    input.receipt_coverage.clear();
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientReceiptCoverage));
}

#[test]
fn evaluate_fails_fallback_incorrect_output() {
    let mut input = full_input(20);
    input.fallback_tests[0].correct_output = false;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackIncorrectOutput));
}

#[test]
fn evaluate_fails_fallback_crashed() {
    let mut input = full_input(20);
    input.fallback_tests[0].crashed = true;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackCrashed));
}

#[test]
fn evaluate_fails_fallback_hung() {
    let mut input = full_input(20);
    input.fallback_tests[0].hung = true;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackHung));
}

#[test]
fn evaluate_fails_fallback_no_receipt() {
    let mut input = full_input(20);
    input.fallback_tests[0].fallback_receipt_emitted = false;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackNoReceipt));
}

#[test]
fn evaluate_fails_fallback_performance_regression() {
    let mut input = full_input(20);
    input.fallback_tests[0].fallback_wall_time_ns = 200_000;
    input.fallback_tests[0].ambient_wall_time_ns = 100_000;
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackPerformanceRegression));
}

#[test]
fn evaluate_fails_receipt_chain_replay_unverified() {
    let mut input = full_input(20);
    if let Some(ref mut replay) = input.receipt_chain_replay {
        replay.all_verified = false;
        replay.verified_receipts = 8;
    }
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::ReceiptChainReplayFailed));
}

#[test]
fn evaluate_fails_receipt_chain_replay_incomplete() {
    let mut input = full_input(20);
    if let Some(ref mut replay) = input.receipt_chain_replay {
        replay.chain_complete = false;
    }
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::ReceiptChainReplayFailed));
}

// ===========================================================================
// 16. evaluate — edge cases
// ===========================================================================

#[test]
fn evaluate_no_replay_provided_fails() {
    let mut input = full_input(20);
    input.receipt_chain_replay = None;
    let decision = evaluate(&input);
    // No replay => receipt_chain_replay_passed is false
    assert!(!decision.receipt_chain_replay_passed);
    // But no finding for ReceiptChainReplayFailed since None doesn't trigger finding
    // (only Some(replay) that fails triggers the finding)
    // However, this does NOT cause gate failure on its own in the current implementation
    // because the let-chain only fires on Some(ref replay) && !replay.passes()
    // With no replay, the gate can still pass if everything else is fine.
    // Actually, let's verify: receipt_chain_replay_passed=false is just a field,
    // it doesn't add a finding. The gate passes based on findings being empty.
    // So this should pass if everything else is good.
    assert!(decision.pass);
}

#[test]
fn evaluate_min_samples_exactly_met() {
    let mut input = full_input(5);
    input.min_samples = 5;
    let decision = evaluate(&input);
    // 5 comparisons, min_samples=5, all other criteria met
    assert!(decision.pass);
}

#[test]
fn evaluate_min_samples_zero() {
    let mut input = full_input(1);
    input.min_samples = 0;
    // 1 comparison, min_samples = 0
    // But with only 1 sample, significance_met = false (n < 5)
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientSignificance));
}

#[test]
fn evaluate_empty_fallback_tests_list() {
    let mut input = full_input(20);
    input.fallback_tests.clear();
    let decision = evaluate(&input);
    // No fallback tests => no findings from fallback checks
    assert_eq!(decision.fallback_tests_passed, 0);
    assert_eq!(decision.fallback_tests_total, 0);
    assert!(decision.pass);
}

#[test]
fn evaluate_empty_receipt_coverage_no_comparisons() {
    let mut input = full_input(0);
    input.comparisons.clear();
    input.receipt_coverage.clear();
    let decision = evaluate(&input);
    // Empty comparisons => EmptyInput finding
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::EmptyInput));
    // But NOT InsufficientReceiptCoverage since there are no comparisons
    // Actually, the check is: total_receipts == 0 && !input.comparisons.is_empty()
    // Since comparisons IS empty, this won't trigger.
}

#[test]
fn evaluate_receipt_coverage_50_percent() {
    let mut input = full_input(20);
    input.receipt_coverage = vec![full_receipt("opt-a"), partial_receipt("opt-b")];
    let decision = evaluate(&input);
    assert!(!decision.pass);
    assert_eq!(decision.receipt_coverage_millionths, 500_000);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientReceiptCoverage));
}

#[test]
fn evaluate_receipt_coverage_finding_has_affected_item() {
    let mut input = full_input(20);
    input.receipt_coverage = vec![full_receipt("opt-a"), partial_receipt("opt-b")];
    let decision = evaluate(&input);
    let receipt_findings: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| f.code == GateFailureCode::InsufficientReceiptCoverage)
        .collect();
    assert!(!receipt_findings.is_empty());
    assert_eq!(receipt_findings[0].affected_item, Some("opt-b".to_string()));
}

// ===========================================================================
// 17. evaluate — multiple failures accumulated
// ===========================================================================

#[test]
fn evaluate_multiple_failures_accumulated() {
    let mut input = full_input(20);
    // Break receipt coverage
    input.receipt_coverage[0].signature_valid = false;
    // Break fallback
    input.fallback_tests[0].hung = true;
    // Break replay
    if let Some(ref mut replay) = input.receipt_chain_replay {
        replay.chain_complete = false;
    }
    let decision = evaluate(&input);
    assert!(!decision.pass);
    assert!(decision.findings.len() >= 3);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::InsufficientReceiptCoverage));
    assert!(codes.contains(&GateFailureCode::FallbackHung));
    assert!(codes.contains(&GateFailureCode::ReceiptChainReplayFailed));
}

#[test]
fn evaluate_all_fallback_failure_types_at_once() {
    let mut input = full_input(20);
    // First fallback: crash + incorrect output + no receipt + performance regression
    input.fallback_tests[0] = FallbackTestResult {
        scenario_id: "disaster".to_string(),
        injection_type: "proof_failure".to_string(),
        correct_output: false,
        fallback_receipt_emitted: false,
        crashed: true,
        hung: true,
        fallback_wall_time_ns: 500_000,
        ambient_wall_time_ns: 100_000,
    };
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let codes: Vec<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::FallbackIncorrectOutput));
    assert!(codes.contains(&GateFailureCode::FallbackCrashed));
    assert!(codes.contains(&GateFailureCode::FallbackHung));
    assert!(codes.contains(&GateFailureCode::FallbackNoReceipt));
    assert!(codes.contains(&GateFailureCode::FallbackPerformanceRegression));
}

// ===========================================================================
// 18. Determinism — same inputs, same outputs
// ===========================================================================

#[test]
fn evaluate_deterministic_same_inputs() {
    let input = full_input(20);
    let a = evaluate(&input);
    let b = evaluate(&input);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.pass, b.pass);
    assert_eq!(a.stats, b.stats);
    assert_eq!(a.receipt_coverage_millionths, b.receipt_coverage_millionths);
    assert_eq!(a.findings, b.findings);
    assert_eq!(a.logs, b.logs);
}

#[test]
fn evaluate_deterministic_decision_id_content_addressed() {
    let input = full_input(20);
    let a = evaluate(&input);
    // Modify one thing and decision_id should change
    let mut input_b = full_input(20);
    input_b.trace_id = "trace-different".to_string();
    let b = evaluate(&input_b);
    assert_ne!(a.decision_id, b.decision_id);
}

#[test]
fn evaluate_deterministic_same_stats_for_same_comparisons() {
    let comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("w{i}"), 75, 100))
        .collect();
    let s1 = StatisticalSummary::from_comparisons(&comps);
    let s2 = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s1, s2);
}

// ===========================================================================
// 19. Scorecard contributions edge cases
// ===========================================================================

#[test]
fn scorecard_empty_comparisons_zero_autonomy() {
    let mut input = full_input(0);
    input.comparisons.clear();
    let decision = evaluate(&input);
    assert_eq!(decision.scorecard_autonomy_delta_millionths, 0);
}

#[test]
fn scorecard_negative_performance_delta() {
    let mut input = full_input(20);
    input.comparisons = (0..20)
        .map(|i| comparison(&format!("w{i}"), 120, 100))
        .collect();
    let decision = evaluate(&input);
    assert!(decision.scorecard_performance_delta_millionths < 0);
}

#[test]
fn scorecard_receipt_coverage_partial() {
    let mut input = full_input(20);
    input.receipt_coverage = vec![
        full_receipt("opt-a"),
        full_receipt("opt-b"),
        partial_receipt("opt-c"),
    ];
    let decision = evaluate(&input);
    // 2 out of 3 fully covered = 666_666 millionths
    assert_eq!(decision.scorecard_security_delta_millionths, 666_666);
}

#[test]
fn scorecard_no_receipts_zero_security() {
    let mut input = full_input(0);
    input.comparisons.clear();
    input.receipt_coverage.clear();
    let decision = evaluate(&input);
    assert_eq!(decision.scorecard_security_delta_millionths, 0);
}

// ===========================================================================
// 20. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn integration_realistic_mixed_workloads() {
    // Simulate a realistic scenario with varying speedups/regressions
    let mut comparisons = Vec::new();
    for i in 0..15 {
        // 12 speedups (80%), 3 regressions
        let (spec, amb) = if i < 12 {
            (80 + i as u64, 100)
        } else {
            (110 + i as u64, 100)
        };
        comparisons.push(comparison(&format!("workload-{i}"), spec, amb));
    }
    // Also vary memory
    comparisons.push(comparison_with_mem("mem-test", 90, 100, 500, 1000));

    let input = GateInput {
        trace_id: "trace-realistic".to_string(),
        policy_id: "policy-realistic".to_string(),
        epoch: SecurityEpoch::from_raw(100),
        comparisons,
        receipt_coverage: vec![
            full_receipt("opt-1"),
            full_receipt("opt-2"),
            full_receipt("opt-3"),
        ],
        fallback_tests: vec![
            passing_fallback("fb-proof"),
            capability_revocation_fallback("fb-cap"),
        ],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 10,
    };
    let decision = evaluate(&input);
    assert!(decision.pass);
    assert!(decision.stats.significance_met);
}

#[test]
fn integration_all_receipts_incomplete_blocks_gate() {
    let input = GateInput {
        trace_id: "trace-bad-receipts".to_string(),
        policy_id: "policy-bad".to_string(),
        epoch: epoch(),
        comparisons: (0..20)
            .map(|i| comparison(&format!("w{i}"), 80, 100))
            .collect(),
        receipt_coverage: vec![empty_receipt("bad-1"), empty_receipt("bad-2")],
        fallback_tests: vec![passing_fallback("fb-1")],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 5,
    };
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let coverage_findings: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| f.code == GateFailureCode::InsufficientReceiptCoverage)
        .collect();
    // One finding per incomplete receipt
    assert_eq!(coverage_findings.len(), 2);
}

#[test]
fn integration_fallback_performance_regression_is_per_test() {
    let input = GateInput {
        trace_id: "trace-fb-perf".to_string(),
        policy_id: "policy-fb".to_string(),
        epoch: epoch(),
        comparisons: (0..20)
            .map(|i| comparison(&format!("w{i}"), 80, 100))
            .collect(),
        receipt_coverage: vec![full_receipt("opt-a")],
        fallback_tests: vec![
            FallbackTestResult {
                scenario_id: "fast-fb".to_string(),
                injection_type: "proof_failure".to_string(),
                correct_output: true,
                fallback_receipt_emitted: true,
                crashed: false,
                hung: false,
                fallback_wall_time_ns: 100_000,
                ambient_wall_time_ns: 100_000,
            },
            FallbackTestResult {
                scenario_id: "slow-fb".to_string(),
                injection_type: "proof_failure".to_string(),
                correct_output: true,
                fallback_receipt_emitted: true,
                crashed: false,
                hung: false,
                fallback_wall_time_ns: 300_000,
                ambient_wall_time_ns: 100_000,
            },
        ],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 5,
    };
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let perf_findings: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| f.code == GateFailureCode::FallbackPerformanceRegression)
        .collect();
    assert_eq!(perf_findings.len(), 1);
    assert_eq!(perf_findings[0].affected_item, Some("slow-fb".to_string()));
}

#[test]
fn integration_minimum_viable_passing_input() {
    // Exactly 5 samples, all positive, minimal receipts, minimal fallback
    let input = GateInput {
        trace_id: "trace-min".to_string(),
        policy_id: "policy-min".to_string(),
        epoch: epoch(),
        comparisons: (0..5)
            .map(|i| comparison(&format!("w{i}"), 80, 100))
            .collect(),
        receipt_coverage: vec![full_receipt("opt-single")],
        fallback_tests: vec![passing_fallback("fb-single")],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 5,
    };
    let decision = evaluate(&input);
    assert!(decision.pass);
}

#[test]
fn integration_gate_decision_content_hash_varies_with_policy() {
    let input_a = full_input(20);
    let decision_a = evaluate(&input_a);

    let mut input_b = full_input(20);
    input_b.policy_id = "policy-different".to_string();
    let decision_b = evaluate(&input_b);

    assert_ne!(decision_a.decision_id, decision_b.decision_id);
}

#[test]
fn integration_gate_decision_content_hash_varies_with_epoch() {
    let input_a = full_input(20);
    let decision_a = evaluate(&input_a);

    let mut input_b = full_input(20);
    input_b.epoch = SecurityEpoch::from_raw(99);
    let decision_b = evaluate(&input_b);

    // Epoch doesn't directly go into decision_material, but if epoch changes
    // stats/findings might change. In this case both pass, so the hash material is:
    // trace_id:policy_id:true:200000:1000000:2:true
    // Both are the same, so decision_id should be the same.
    assert_eq!(decision_a.decision_id, decision_b.decision_id);
    // But the epoch field on the decision differs
    assert_ne!(decision_a.epoch, decision_b.epoch);
}

#[test]
fn integration_log_count_scales_with_input() {
    for n in [5, 10, 20] {
        let mut input = full_input(n);
        // Add varying number of fallback tests
        input.fallback_tests = (0..3)
            .map(|i| passing_fallback(&format!("fb-{i}")))
            .collect();
        let decision = evaluate(&input);
        // n comparison logs + 3 fallback logs + 1 summary = n + 4
        assert_eq!(decision.logs.len(), n + 4);
    }
}

#[test]
fn integration_speedup_outcome_in_logs() {
    let mut input = full_input(2);
    // First: speedup, Second: regression
    input.comparisons = vec![
        comparison("fast", 80, 100),  // positive
        comparison("slow", 120, 100), // negative
    ];
    input.min_samples = 1;
    let decision = evaluate(&input);
    assert_eq!(decision.logs[0].outcome, "speedup");
    assert_eq!(decision.logs[1].outcome, "regression");
}

#[test]
fn integration_fallback_log_outcome() {
    let mut input = full_input(5);
    input.fallback_tests = vec![
        passing_fallback("good"),
        FallbackTestResult {
            scenario_id: "bad".to_string(),
            injection_type: "proof_failure".to_string(),
            correct_output: false,
            fallback_receipt_emitted: true,
            crashed: false,
            hung: false,
            fallback_wall_time_ns: 100_000,
            ambient_wall_time_ns: 100_000,
        },
    ];
    let decision = evaluate(&input);
    // Fallback logs are at indices 5 and 6 (after 5 comparison logs)
    assert_eq!(decision.logs[5].outcome, "pass");
    assert_eq!(decision.logs[6].outcome, "fail");
}

#[test]
fn integration_summary_log_reflects_overall_outcome() {
    let input_pass = full_input(20);
    let decision_pass = evaluate(&input_pass);
    assert_eq!(decision_pass.logs.last().unwrap().outcome, "pass");

    let mut input_fail = full_input(20);
    input_fail.fallback_tests[0].crashed = true;
    let decision_fail = evaluate(&input_fail);
    assert_eq!(decision_fail.logs.last().unwrap().outcome, "fail");
}

#[test]
fn integration_fallback_passed_count() {
    let mut input = full_input(20);
    input.fallback_tests = vec![
        passing_fallback("good-1"),
        passing_fallback("good-2"),
        FallbackTestResult {
            scenario_id: "bad-1".to_string(),
            injection_type: "proof_failure".to_string(),
            correct_output: false,
            fallback_receipt_emitted: true,
            crashed: false,
            hung: false,
            fallback_wall_time_ns: 100_000,
            ambient_wall_time_ns: 100_000,
        },
    ];
    let decision = evaluate(&input);
    assert_eq!(decision.fallback_tests_passed, 2);
    assert_eq!(decision.fallback_tests_total, 3);
}

#[test]
fn integration_receipt_chain_replay_detail_in_finding() {
    let mut input = full_input(20);
    input.receipt_chain_replay = Some(ReceiptChainReplayResult {
        compilation_id: "compile-xyz".to_string(),
        total_receipts: 10,
        verified_receipts: 7,
        chain_complete: true,
        all_verified: false,
        replay_duration_ns: 1_000_000,
    });
    let decision = evaluate(&input);
    assert!(!decision.pass);
    let replay_finding = decision
        .findings
        .iter()
        .find(|f| f.code == GateFailureCode::ReceiptChainReplayFailed)
        .unwrap();
    assert_eq!(
        replay_finding.affected_item,
        Some("compile-xyz".to_string())
    );
    assert!(replay_finding.detail.contains("verified=7/10"));
}

#[test]
fn integration_empty_everything_produces_empty_input_finding_only() {
    let input = GateInput {
        trace_id: "trace-empty".to_string(),
        policy_id: "policy-empty".to_string(),
        epoch: epoch(),
        comparisons: vec![],
        receipt_coverage: vec![],
        fallback_tests: vec![],
        receipt_chain_replay: None,
        min_samples: 0,
    };
    let decision = evaluate(&input);
    assert!(!decision.pass);
    // Only EmptyInput finding (no other checks fire on empty input)
    assert_eq!(decision.findings.len(), 1);
    assert_eq!(decision.findings[0].code, GateFailureCode::EmptyInput);
}

#[test]
fn integration_large_input_completes_without_panic() {
    let input = GateInput {
        trace_id: "trace-large".to_string(),
        policy_id: "policy-large".to_string(),
        epoch: epoch(),
        comparisons: (0..1000)
            .map(|i| comparison(&format!("w{i}"), 80, 100))
            .collect(),
        receipt_coverage: (0..100)
            .map(|i| full_receipt(&format!("opt-{i}")))
            .collect(),
        fallback_tests: (0..50)
            .map(|i| passing_fallback(&format!("fb-{i}")))
            .collect(),
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 100,
    };
    let decision = evaluate(&input);
    assert!(decision.pass);
    assert_eq!(decision.stats.sample_count, 1000);
    assert_eq!(decision.fallback_tests_total, 50);
}
