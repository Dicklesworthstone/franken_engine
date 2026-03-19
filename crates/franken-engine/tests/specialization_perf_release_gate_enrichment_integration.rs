//! Enrichment integration tests for `specialization_perf_release_gate`.
//!
//! Covers: full gate evaluation (pass/fail scenarios), BenchmarkComparison
//! delta computation, ReceiptCoverageEntry gap detection, FallbackTestResult
//! pass/fail logic, StatisticalSummary significance thresholds, receipt chain
//! replay, scorecard contributions, structured log events, serde round-trips,
//! and Display coverage.

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

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
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

fn comparison(wl: &str, spec_wt: u64, amb_wt: u64) -> BenchmarkComparison {
    BenchmarkComparison::from_samples(
        sample(wl, LaneType::ProofSpecialized, spec_wt, 1024),
        sample(wl, LaneType::AmbientAuthority, amb_wt, 1024),
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

fn passing_replay() -> ReceiptChainReplayResult {
    ReceiptChainReplayResult {
        compilation_id: "compile-enrich".to_string(),
        total_receipts: 10,
        verified_receipts: 10,
        chain_complete: true,
        all_verified: true,
        replay_duration_ns: 50_000_000,
    }
}

fn full_input(n: usize) -> GateInput {
    let comparisons: Vec<_> = (0..n)
        .map(|i| comparison(&format!("w{i}"), 80, 100))
        .collect();
    GateInput {
        trace_id: "enrich-trace".to_string(),
        policy_id: "enrich-policy".to_string(),
        epoch: ep(),
        comparisons,
        receipt_coverage: vec![full_receipt("opt-a"), full_receipt("opt-b")],
        fallback_tests: vec![passing_fallback("fb-1"), passing_fallback("fb-2")],
        receipt_chain_replay: Some(passing_replay()),
        min_samples: 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// --- LaneType ---

#[test]
fn enrichment_lane_type_as_str_unique() {
    let strs: BTreeSet<&str> = [LaneType::ProofSpecialized, LaneType::AmbientAuthority]
        .iter()
        .map(|l| l.as_str())
        .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn enrichment_lane_type_display_matches_as_str() {
    assert_eq!(LaneType::ProofSpecialized.to_string(), "proof_specialized");
    assert_eq!(LaneType::AmbientAuthority.to_string(), "ambient_authority");
}

#[test]
fn enrichment_lane_type_serde_roundtrip() {
    for lt in [LaneType::ProofSpecialized, LaneType::AmbientAuthority] {
        let json = serde_json::to_string(&lt).unwrap();
        let back: LaneType = serde_json::from_str(&json).unwrap();
        assert_eq!(lt, back);
    }
}

#[test]
fn enrichment_lane_type_ordering() {
    assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
}

// --- BenchmarkComparison ---

#[test]
fn enrichment_comparison_positive_speedup() {
    let c = comparison("w1", 80, 100);
    assert_eq!(c.wall_time_delta_millionths, 200_000);
    assert!(c.has_positive_wall_time_delta());
}

#[test]
fn enrichment_comparison_negative_regression() {
    let c = comparison("w1", 120, 100);
    assert_eq!(c.wall_time_delta_millionths, -200_000);
    assert!(!c.has_positive_wall_time_delta());
}

#[test]
fn enrichment_comparison_zero_baseline_no_crash() {
    let c = comparison("w1", 100, 0);
    assert_eq!(c.wall_time_delta_millionths, 0);
}

#[test]
fn enrichment_comparison_equal_times() {
    let c = comparison("w1", 100, 100);
    assert_eq!(c.wall_time_delta_millionths, 0);
}

#[test]
fn enrichment_comparison_memory_delta_positive() {
    let c = BenchmarkComparison::from_samples(
        sample("w1", LaneType::ProofSpecialized, 100, 800),
        sample("w1", LaneType::AmbientAuthority, 100, 1000),
    );
    assert_eq!(c.memory_delta_millionths, 200_000);
    assert!(c.has_positive_memory_delta());
}

#[test]
fn enrichment_comparison_serde_roundtrip() {
    let c = comparison("serde-w", 85, 100);
    let json = serde_json::to_string(&c).unwrap();
    let back: BenchmarkComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// --- ReceiptCoverageEntry ---

#[test]
fn enrichment_receipt_fully_covered_no_gaps() {
    let r = full_receipt("opt");
    assert!(r.is_fully_covered());
    assert!(r.coverage_gaps().is_empty());
}

#[test]
fn enrichment_receipt_missing_all_has_six_gaps() {
    let r = ReceiptCoverageEntry {
        optimization_name: "opt".to_string(),
        receipt_present: false,
        receipt_hash: None,
        proof_reference: None,
        capability_witness_ref: None,
        performance_measurement_present: false,
        signature_valid: false,
    };
    assert!(!r.is_fully_covered());
    assert_eq!(r.coverage_gaps().len(), 6);
}

#[test]
fn enrichment_receipt_missing_single_field() {
    let mut r = full_receipt("opt");
    r.capability_witness_ref = None;
    assert!(!r.is_fully_covered());
    let gaps = r.coverage_gaps();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].contains("capability witness"));
}

#[test]
fn enrichment_receipt_invalid_signature_gap() {
    let mut r = full_receipt("opt");
    r.signature_valid = false;
    assert!(!r.is_fully_covered());
    assert!(r.coverage_gaps().contains(&"invalid signature".to_string()));
}

// --- FallbackTestResult ---

#[test]
fn enrichment_fallback_passes_all_criteria() {
    let fb = passing_fallback("fb");
    assert!(fb.passes());
    assert!(fb.fallback_performance_acceptable());
}

#[test]
fn enrichment_fallback_fails_on_crash() {
    let mut fb = passing_fallback("fb");
    fb.crashed = true;
    assert!(!fb.passes());
}

#[test]
fn enrichment_fallback_fails_on_hang() {
    let mut fb = passing_fallback("fb");
    fb.hung = true;
    assert!(!fb.passes());
}

#[test]
fn enrichment_fallback_fails_on_incorrect_output() {
    let mut fb = passing_fallback("fb");
    fb.correct_output = false;
    assert!(!fb.passes());
}

#[test]
fn enrichment_fallback_fails_on_missing_receipt() {
    let mut fb = passing_fallback("fb");
    fb.fallback_receipt_emitted = false;
    assert!(!fb.passes());
}

#[test]
fn enrichment_fallback_performance_at_10_percent_threshold() {
    let mut fb = passing_fallback("fb");
    fb.ambient_wall_time_ns = 1_000_000;
    fb.fallback_wall_time_ns = 1_100_000;
    assert!(fb.fallback_performance_acceptable());
    fb.fallback_wall_time_ns = 1_100_001;
    assert!(!fb.fallback_performance_acceptable());
}

#[test]
fn enrichment_fallback_zero_ambient_is_acceptable() {
    let mut fb = passing_fallback("fb");
    fb.ambient_wall_time_ns = 0;
    fb.fallback_wall_time_ns = 999_999;
    assert!(fb.fallback_performance_acceptable());
}

// --- ReceiptChainReplayResult ---

#[test]
fn enrichment_replay_passes_when_complete_and_verified() {
    assert!(passing_replay().passes());
}

#[test]
fn enrichment_replay_fails_incomplete_chain() {
    let mut r = passing_replay();
    r.chain_complete = false;
    assert!(!r.passes());
}

#[test]
fn enrichment_replay_fails_unverified_receipts() {
    let mut r = passing_replay();
    r.all_verified = false;
    assert!(!r.passes());
}

#[test]
fn enrichment_replay_fails_zero_total_receipts() {
    let r = ReceiptChainReplayResult {
        compilation_id: "c".to_string(),
        total_receipts: 0,
        verified_receipts: 0,
        chain_complete: true,
        all_verified: true,
        replay_duration_ns: 0,
    };
    assert!(!r.passes());
}

// --- StatisticalSummary ---

#[test]
fn enrichment_stats_empty_comparisons() {
    let s = StatisticalSummary::from_comparisons(&[]);
    assert_eq!(s.sample_count, 0);
    assert!(!s.has_positive_delta());
    assert!(!s.significance_met);
}

#[test]
fn enrichment_stats_all_positive_significant() {
    let comps: Vec<_> = (0..20)
        .map(|i| comparison(&format!("w{i}"), 80, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    assert_eq!(s.sample_count, 20);
    assert!(s.has_positive_delta());
    assert!(s.significance_met);
    assert_eq!(s.positive_wall_time_count, 20);
}

#[test]
fn enrichment_stats_mixed_not_significant() {
    let mut comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("p{i}"), 80, 100))
        .collect();
    comps.extend((0..10).map(|i| comparison(&format!("n{i}"), 120, 100)));
    let s = StatisticalSummary::from_comparisons(&comps);
    assert!(!s.significance_met);
}

#[test]
fn enrichment_stats_few_samples_not_significant() {
    let comps: Vec<_> = (0..4)
        .map(|i| comparison(&format!("t{i}"), 50, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    assert!(!s.significance_met);
}

#[test]
fn enrichment_stats_serde_roundtrip() {
    let comps: Vec<_> = (0..10)
        .map(|i| comparison(&format!("s{i}"), 85, 100))
        .collect();
    let s = StatisticalSummary::from_comparisons(&comps);
    let json = serde_json::to_string(&s).unwrap();
    let back: StatisticalSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// --- GateFailureCode ---

#[test]
fn enrichment_failure_code_display_all_eleven_unique() {
    let codes = [
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
    let strs: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
    assert_eq!(strs.len(), 11);
}

#[test]
fn enrichment_failure_code_serde_roundtrip() {
    for code in [
        GateFailureCode::NoPositiveDelta,
        GateFailureCode::InsufficientSignificance,
        GateFailureCode::FallbackCrashed,
        GateFailureCode::ReceiptChainReplayFailed,
        GateFailureCode::EmptyInput,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: GateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

// --- Full gate evaluation: pass ---

#[test]
fn enrichment_gate_passes_with_valid_input() {
    let input = full_input(20);
    let d = evaluate(&input);
    assert!(d.pass);
    assert!(d.findings.is_empty());
    assert_eq!(d.receipt_coverage_millionths, 1_000_000);
    assert_eq!(d.fallback_tests_passed, 2);
    assert_eq!(d.fallback_tests_total, 2);
    assert!(d.receipt_chain_replay_passed);
    assert_eq!(d.schema_version, GATE_SCHEMA_VERSION);
}

// --- Full gate evaluation: various failures ---

#[test]
fn enrichment_gate_fails_empty_comparisons() {
    let mut input = full_input(0);
    input.comparisons.clear();
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::EmptyInput)
    );
}

#[test]
fn enrichment_gate_fails_insufficient_samples() {
    let mut input = full_input(3);
    input.min_samples = 10;
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::InsufficientSamples)
    );
}

#[test]
fn enrichment_gate_fails_no_positive_delta() {
    let mut input = full_input(20);
    input.comparisons = (0..20)
        .map(|i| comparison(&format!("w{i}"), 120, 100))
        .collect();
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::NoPositiveDelta)
    );
}

#[test]
fn enrichment_gate_fails_insufficient_receipt_coverage() {
    let mut input = full_input(20);
    input.receipt_coverage[0].proof_reference = None;
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::InsufficientReceiptCoverage)
    );
}

#[test]
fn enrichment_gate_fails_on_fallback_crash() {
    let mut input = full_input(20);
    input.fallback_tests[0].crashed = true;
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackCrashed)
    );
}

#[test]
fn enrichment_gate_fails_on_fallback_hung() {
    let mut input = full_input(20);
    input.fallback_tests[0].hung = true;
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackHung)
    );
}

#[test]
fn enrichment_gate_fails_on_replay_failure() {
    let mut input = full_input(20);
    if let Some(ref mut replay) = input.receipt_chain_replay {
        replay.all_verified = false;
        replay.verified_receipts = 8;
    }
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ReceiptChainReplayFailed)
    );
}

#[test]
fn enrichment_gate_fails_fallback_performance_regression() {
    let mut input = full_input(20);
    input.fallback_tests[0].fallback_wall_time_ns = 250_000;
    input.fallback_tests[0].ambient_wall_time_ns = 100_000;
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPerformanceRegression)
    );
}

// --- Multiple failures accumulate ---

#[test]
fn enrichment_gate_multiple_failures_accumulate() {
    let mut input = full_input(20);
    input.receipt_coverage[0].signature_valid = false;
    input.fallback_tests[0].hung = true;
    if let Some(ref mut replay) = input.receipt_chain_replay {
        replay.chain_complete = false;
    }
    let d = evaluate(&input);
    assert!(!d.pass);
    assert!(d.findings.len() >= 3);
}

// --- Scorecard contributions ---

#[test]
fn enrichment_scorecard_performance_positive() {
    let input = full_input(20);
    let d = evaluate(&input);
    assert_eq!(d.scorecard_performance_delta_millionths, 200_000);
    assert_eq!(d.scorecard_security_delta_millionths, 1_000_000);
    assert_eq!(d.scorecard_autonomy_delta_millionths, 1_000_000);
}

#[test]
fn enrichment_scorecard_zero_when_empty() {
    let mut input = full_input(0);
    input.comparisons.clear();
    let d = evaluate(&input);
    assert_eq!(d.scorecard_autonomy_delta_millionths, 0);
}

// --- Decision determinism ---

#[test]
fn enrichment_decision_deterministic() {
    let input = full_input(20);
    let a = evaluate(&input);
    let b = evaluate(&input);
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.pass, b.pass);
    assert_eq!(a.stats, b.stats);
}

#[test]
fn enrichment_decision_id_changes_with_trace() {
    let mut a_input = full_input(20);
    a_input.trace_id = "trace-a".to_string();
    let mut b_input = full_input(20);
    b_input.trace_id = "trace-b".to_string();
    let da = evaluate(&a_input);
    let db = evaluate(&b_input);
    assert_ne!(da.decision_id, db.decision_id);
}

// --- Structured logs ---

#[test]
fn enrichment_logs_include_comparisons_fallbacks_and_summary() {
    let input = full_input(5);
    let d = evaluate(&input);
    // 5 comparison + 2 fallback + 1 summary = 8
    assert_eq!(d.logs.len(), 8);
    let last = d.logs.last().unwrap();
    assert_eq!(last.event, "gate_decision");
}

#[test]
fn enrichment_logs_pass_outcome_on_success() {
    let input = full_input(20);
    let d = evaluate(&input);
    let last = d.logs.last().unwrap();
    assert_eq!(last.outcome, "pass");
}

#[test]
fn enrichment_logs_fail_outcome_on_failure() {
    let mut input = full_input(20);
    input.fallback_tests[0].crashed = true;
    let d = evaluate(&input);
    let last = d.logs.last().unwrap();
    assert_eq!(last.outcome, "fail");
}

// --- Serde round-trips ---

#[test]
fn enrichment_gate_decision_serde_roundtrip() {
    let input = full_input(20);
    let d = evaluate(&input);
    let json = d.to_jsonl();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d.pass, back.pass);
    assert_eq!(d.decision_id, back.decision_id);
}

#[test]
fn enrichment_gate_input_serde_roundtrip() {
    let input = full_input(5);
    let json = serde_json::to_string(&input).unwrap();
    let back: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn enrichment_gate_finding_serde_roundtrip() {
    let finding = GateFinding {
        code: GateFailureCode::FallbackNoReceipt,
        detail: "scenario fb-1 did not emit fallback receipt".to_string(),
        affected_item: Some("fb-1".to_string()),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: GateFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn enrichment_gate_log_event_serde_roundtrip() {
    let evt = GateLogEvent {
        trace_id: "t".into(),
        lane_type: Some("proof_specialized".into()),
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: Some(true),
        wall_time_ns: Some(1234),
        memory_peak_bytes: None,
        event: "fallback_test".into(),
        outcome: "pass".into(),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: GateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// --- Constants ---

#[test]
fn enrichment_gate_component_constant() {
    assert_eq!(GATE_COMPONENT, "specialization_perf_release_gate");
}

#[test]
fn enrichment_gate_schema_version_format() {
    assert!(GATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(GATE_SCHEMA_VERSION.contains(".v"));
}
