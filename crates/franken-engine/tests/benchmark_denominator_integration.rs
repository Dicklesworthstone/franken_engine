#![forbid(unsafe_code)]

//! Integration tests for the `benchmark_denominator` module.
//!
//! Covers: BaselineEngine, BenchmarkCase, PublicationContext, NativeCoveragePoint,
//! PublicationGateInput, PublicationGateDecision, BenchmarkPublicationEvent,
//! BenchmarkDenominatorError, weighted_geometric_mean, evaluate_publication_gate,
//! serde round-trips, Display/Debug, error stable codes, and boundary conditions.

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

use frankenengine_engine::benchmark_denominator::{
    BENCHMARK_PUBLICATION_COMPONENT, BaselineEngine, BenchmarkCase, BenchmarkDenominatorError,
    BenchmarkPublicationEvent, NativeCoveragePoint, PublicationContext, PublicationGateDecision,
    PublicationGateInput, SCORE_THRESHOLD, evaluate_publication_gate, weighted_geometric_mean,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn case(id: &str, franken: f64, baseline: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: id.into(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn case_w(id: &str, franken: f64, baseline: f64, weight: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: id.into(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: Some(weight),
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn ctx() -> PublicationContext {
    PublicationContext::new("trace-int-1", "dec-int-1", "pol-int-1")
}

fn coverage_point(ts: &str, native: u64, total: u64) -> NativeCoveragePoint {
    NativeCoveragePoint {
        recorded_at_utc: ts.into(),
        native_slots: native,
        total_slots: total,
    }
}

fn passing_input() -> PublicationGateInput {
    PublicationGateInput {
        node_cases: vec![case("wk-a", 4000.0, 1000.0)],
        bun_cases: vec![case("wk-b", 5000.0, 1000.0)],
        native_coverage_progression: vec![coverage_point("2026-01-15T00:00:00Z", 15, 30)],
        replacement_lineage_ids: vec!["lin-001".into()],
    }
}

// ── Section 1: BaselineEngine ───────────────────────────────────────────

#[test]
fn baseline_engine_node_as_str() {
    assert_eq!(BaselineEngine::Node.as_str(), "node");
}

#[test]
fn baseline_engine_bun_as_str() {
    assert_eq!(BaselineEngine::Bun.as_str(), "bun");
}

#[test]
fn baseline_engine_serde_round_trip_node() {
    let json = serde_json::to_string(&BaselineEngine::Node).unwrap();
    assert_eq!(json, "\"node\"");
    let back: BaselineEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(back, BaselineEngine::Node);
}

#[test]
fn baseline_engine_serde_round_trip_bun() {
    let json = serde_json::to_string(&BaselineEngine::Bun).unwrap();
    assert_eq!(json, "\"bun\"");
    let back: BaselineEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(back, BaselineEngine::Bun);
}

#[test]
fn baseline_engine_debug() {
    let dbg = format!("{:?}", BaselineEngine::Node);
    assert!(dbg.contains("Node"));
}

#[test]
fn baseline_engine_copy_semantics() {
    let a = BaselineEngine::Bun;
    let b = a;
    assert_eq!(a, b);
}

// ── Section 2: BenchmarkCase ────────────────────────────────────────────

#[test]
fn benchmark_case_speedup_3x() {
    let c = case("w1", 3000.0, 1000.0);
    assert!((c.speedup() - 3.0).abs() < 1e-10);
}

#[test]
fn benchmark_case_speedup_fractional() {
    let c = case("w1", 500.0, 2000.0);
    assert!((c.speedup() - 0.25).abs() < 1e-10);
}

#[test]
fn benchmark_case_speedup_1x() {
    let c = case("w1", 1000.0, 1000.0);
    assert!((c.speedup() - 1.0).abs() < 1e-10);
}

#[test]
fn benchmark_case_serde_round_trip() {
    let c = case_w("wk-serde", 7777.0, 2222.0, 0.5);
    let json = serde_json::to_string(&c).unwrap();
    let back: BenchmarkCase = serde_json::from_str(&json).unwrap();
    assert_eq!(c.workload_id, back.workload_id);
    assert!((c.throughput_franken_tps - back.throughput_franken_tps).abs() < 1e-10);
    assert!((c.throughput_baseline_tps - back.throughput_baseline_tps).abs() < 1e-10);
    assert_eq!(c.weight, back.weight);
    assert_eq!(c.behavior_equivalent, back.behavior_equivalent);
}

#[test]
fn benchmark_case_defaults_from_json() {
    let json =
        r#"{"workload_id":"w","throughput_franken_tps":100.0,"throughput_baseline_tps":50.0}"#;
    let c: BenchmarkCase = serde_json::from_str(json).unwrap();
    assert!(c.behavior_equivalent);
    assert!(c.latency_envelope_ok);
    assert!(c.error_envelope_ok);
    assert!(c.weight.is_none());
}

#[test]
fn benchmark_case_clone_equality() {
    let c = case("clone-me", 9000.0, 3000.0);
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn benchmark_case_json_field_names() {
    let c = case("fnames", 100.0, 50.0);
    let json = serde_json::to_string(&c).unwrap();
    for field in &[
        "workload_id",
        "throughput_franken_tps",
        "throughput_baseline_tps",
        "behavior_equivalent",
        "latency_envelope_ok",
        "error_envelope_ok",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ── Section 3: PublicationContext ────────────────────────────────────────

#[test]
fn publication_context_new_fields() {
    let c = PublicationContext::new("t", "d", "p");
    assert_eq!(c.trace_id, "t");
    assert_eq!(c.decision_id, "d");
    assert_eq!(c.policy_id, "p");
}

#[test]
fn publication_context_serde_round_trip() {
    let c = ctx();
    let json = serde_json::to_string(&c).unwrap();
    let back: PublicationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn publication_context_clone_eq() {
    let c = ctx();
    assert_eq!(c, c.clone());
}

// ── Section 4: NativeCoveragePoint ──────────────────────────────────────

#[test]
fn native_coverage_point_serde_round_trip() {
    let p = coverage_point("2026-02-01T12:00:00Z", 42, 100);
    let json = serde_json::to_string(&p).unwrap();
    let back: NativeCoveragePoint = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn native_coverage_point_clone_eq() {
    let p = coverage_point("2026-03-01T00:00:00Z", 0, 10);
    assert_eq!(p, p.clone());
}

// ── Section 5: BenchmarkPublicationEvent ────────────────────────────────

#[test]
fn benchmark_publication_event_serde_round_trip() {
    let e = BenchmarkPublicationEvent {
        trace_id: "t-evt".into(),
        decision_id: "d-evt".into(),
        policy_id: "p-evt".into(),
        component: BENCHMARK_PUBLICATION_COMPONENT.into(),
        event: "some_event".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: BenchmarkPublicationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn benchmark_publication_event_with_error_code_round_trip() {
    let e = BenchmarkPublicationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "fail".into(),
        error_code: Some("FE-BENCH-1007".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: BenchmarkPublicationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ── Section 6: BenchmarkDenominatorError ────────────────────────────────

#[test]
fn error_stable_code_empty_case_set() {
    let e = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".into(),
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1001");
}

#[test]
fn error_stable_code_empty_workload_id() {
    let e = BenchmarkDenominatorError::EmptyWorkloadId {
        baseline: "bun".into(),
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1001");
}

#[test]
fn error_stable_code_duplicate_workload() {
    let e = BenchmarkDenominatorError::DuplicateWorkloadId {
        baseline: "node".into(),
        workload_id: "w1".into(),
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1001");
}

#[test]
fn error_stable_code_invalid_weight() {
    let e = BenchmarkDenominatorError::InvalidWeight {
        workload_id: "w1".into(),
        reason: "bad".into(),
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1002");
}

#[test]
fn error_stable_code_invalid_throughput() {
    let e = BenchmarkDenominatorError::InvalidThroughput {
        workload_id: "w1".into(),
        field: "f".into(),
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1003");
}

#[test]
fn error_stable_code_weight_sum() {
    let e = BenchmarkDenominatorError::InvalidWeightSum {
        baseline: "node".into(),
        sum: 0.5,
    };
    assert_eq!(e.stable_code(), "FE-BENCH-1004");
}

#[test]
fn error_stable_code_missing_coverage() {
    assert_eq!(
        BenchmarkDenominatorError::MissingCoverageProgression.stable_code(),
        "FE-BENCH-1005"
    );
}

#[test]
fn error_stable_code_missing_lineage() {
    assert_eq!(
        BenchmarkDenominatorError::MissingReplacementLineage.stable_code(),
        "FE-BENCH-1006"
    );
}

#[test]
fn error_stable_code_serialization_failure() {
    let e = BenchmarkDenominatorError::SerializationFailure("oops".into());
    assert_eq!(e.stable_code(), "FE-BENCH-1007");
}

#[test]
fn error_display_all_variants_unique() {
    let variants: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".into(),
        },
        BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "bun".into(),
        },
        BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".into(),
            workload_id: "w1".into(),
        },
        BenchmarkDenominatorError::InvalidWeight {
            workload_id: "w1".into(),
            reason: "bad".into(),
        },
        BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "w1".into(),
            field: "f".into(),
        },
        BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "node".into(),
            sum: 0.5,
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("err".into()),
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn error_display_contains_baseline_name() {
    let e = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "bun".into(),
    };
    assert!(e.to_string().contains("bun"));
}

#[test]
fn error_display_differentiates_baselines() {
    let node_err = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".into(),
    };
    let bun_err = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "bun".into(),
    };
    assert_ne!(node_err.to_string(), bun_err.to_string());
}

#[test]
fn error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_source_is_none() {
    use std::error::Error as StdError;
    let err = BenchmarkDenominatorError::MissingCoverageProgression;
    assert!(err.source().is_none());
}

#[test]
fn error_serde_round_trip() {
    let err = BenchmarkDenominatorError::DuplicateWorkloadId {
        baseline: "bun".into(),
        workload_id: "dup-w".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: BenchmarkDenominatorError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn error_debug_not_empty() {
    let err = BenchmarkDenominatorError::MissingReplacementLineage;
    let dbg = format!("{:?}", err);
    assert!(!dbg.is_empty());
}

// ── Section 7: weighted_geometric_mean ──────────────────────────────────

#[test]
fn wgm_single_case_equals_speedup() {
    let cases = vec![case("w1", 5000.0, 1000.0)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 5.0).abs() < 1e-6);
}

#[test]
fn wgm_multiple_equal_speedups() {
    let cases = vec![
        case("a", 4000.0, 1000.0),
        case("b", 4000.0, 1000.0),
        case("c", 4000.0, 1000.0),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap();
    assert!((score - 4.0).abs() < 1e-6);
}

#[test]
fn wgm_explicit_equal_weights() {
    let cases = vec![
        case_w("a", 9000.0, 1000.0, 0.5),
        case_w("b", 1000.0, 1000.0, 0.5),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    // geometric mean of 9x and 1x = sqrt(9) = 3
    assert!((score - 3.0).abs() < 1e-6);
}

#[test]
fn wgm_asymmetric_weights() {
    // Weight 0.75 on 16x, 0.25 on 1x => 16^0.75 * 1^0.25 = 8
    let cases = vec![
        case_w("heavy", 16000.0, 1000.0, 0.75),
        case_w("light", 1000.0, 1000.0, 0.25),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 8.0).abs() < 1e-4);
}

#[test]
fn wgm_deterministic_across_calls() {
    let cases = vec![
        case("x", 3000.0, 1000.0),
        case("y", 5000.0, 1000.0),
        case("z", 7000.0, 1000.0),
    ];
    let s1 = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    let s2 = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert_eq!(s1, s2, "must be bitwise deterministic");
}

#[test]
fn wgm_err_empty_cases() {
    let err = weighted_geometric_mean(&[], BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyCaseSet { .. }
    ));
}

#[test]
fn wgm_err_empty_workload_id() {
    let cases = vec![case("", 3000.0, 1000.0)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyWorkloadId { .. }
    ));
}

#[test]
fn wgm_err_whitespace_only_workload_id() {
    let cases = vec![case("   ", 3000.0, 1000.0)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyWorkloadId { .. }
    ));
}

#[test]
fn wgm_err_duplicate_workload_id() {
    let cases = vec![case("w1", 3000.0, 1000.0), case("w1", 4000.0, 1000.0)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::DuplicateWorkloadId { .. }
    ));
}

#[test]
fn wgm_err_franken_throughput_zero() {
    let cases = vec![case("w1", 0.0, 1000.0)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidThroughput { .. }
    ));
}

#[test]
fn wgm_err_franken_throughput_negative() {
    let cases = vec![case("w1", -1.0, 1000.0)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_baseline_throughput_zero() {
    let cases = vec![case("w1", 3000.0, 0.0)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_throughput_nan() {
    let cases = vec![case("w1", f64::NAN, 1000.0)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_throughput_inf() {
    let cases = vec![case("w1", f64::INFINITY, 1000.0)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_negative_weight() {
    let cases = vec![case_w("w1", 3000.0, 1000.0, -0.5)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_zero_weight() {
    let cases = vec![case_w("w1", 3000.0, 1000.0, 0.0)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_mixed_weights() {
    let cases = vec![
        case("w1", 3000.0, 1000.0),        // None
        case_w("w2", 4000.0, 1000.0, 1.0), // Some
    ];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidWeight { .. }
    ));
}

#[test]
fn wgm_err_weights_not_summing_to_one() {
    let cases = vec![
        case_w("w1", 3000.0, 1000.0, 0.3),
        case_w("w2", 4000.0, 1000.0, 0.3),
    ];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidWeightSum { .. }
    ));
}

#[test]
fn wgm_err_weight_nan() {
    let cases = vec![case_w("w1", 3000.0, 1000.0, f64::NAN)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

#[test]
fn wgm_err_weight_inf() {
    let cases = vec![case_w("w1", 3000.0, 1000.0, f64::INFINITY)];
    assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
}

// ── Section 8: evaluate_publication_gate — passing path ─────────────────

#[test]
fn gate_passing_basic() {
    let input = passing_input();
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(decision.publish_allowed);
    assert!(decision.score_vs_node >= SCORE_THRESHOLD);
    assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
    assert!(decision.blockers.is_empty());
}

#[test]
fn gate_passing_events_count_is_three() {
    let decision = evaluate_publication_gate(&passing_input(), &ctx()).unwrap();
    assert_eq!(decision.events.len(), 3);
}

#[test]
fn gate_passing_events_contain_expected_names() {
    let decision = evaluate_publication_gate(&passing_input(), &ctx()).unwrap();
    let event_names: BTreeSet<String> = decision.events.iter().map(|e| e.event.clone()).collect();
    assert!(event_names.contains("node_score_evaluated"));
    assert!(event_names.contains("bun_score_evaluated"));
    assert!(event_names.contains("publication_gate_decision"));
}

#[test]
fn gate_passing_all_events_pass_or_allow() {
    let decision = evaluate_publication_gate(&passing_input(), &ctx()).unwrap();
    for event in &decision.events {
        assert!(
            event.outcome == "pass" || event.outcome == "allow",
            "unexpected outcome: {}",
            event.outcome
        );
        assert!(event.error_code.is_none());
    }
}

#[test]
fn gate_passing_events_carry_context_ids() {
    let c = ctx();
    let decision = evaluate_publication_gate(&passing_input(), &c).unwrap();
    for event in &decision.events {
        assert_eq!(event.trace_id, c.trace_id);
        assert_eq!(event.decision_id, c.decision_id);
        assert_eq!(event.policy_id, c.policy_id);
        assert_eq!(event.component, BENCHMARK_PUBLICATION_COMPONENT);
    }
}

#[test]
fn gate_passing_preserves_coverage_progression() {
    let input = passing_input();
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert_eq!(
        decision.native_coverage_progression.len(),
        input.native_coverage_progression.len()
    );
    assert_eq!(
        decision.native_coverage_progression[0].native_slots,
        input.native_coverage_progression[0].native_slots
    );
}

#[test]
fn gate_exact_3x_threshold_passes() {
    let input = PublicationGateInput {
        node_cases: vec![case("exact-n", 3000.0, 1000.0)],
        bun_cases: vec![case("exact-b", 3000.0, 1000.0)],
        native_coverage_progression: vec![coverage_point("2026-02-27T00:00:00Z", 5, 10)],
        replacement_lineage_ids: vec!["lin-exact".into()],
    };
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(decision.publish_allowed, "exactly 3x must pass");
}

// ── Section 9: evaluate_publication_gate — blocking paths ───────────────

#[test]
fn gate_below_threshold_node_blocks() {
    let mut input = passing_input();
    input.node_cases = vec![case("slow-node", 2000.0, 1000.0)]; // 2x < 3x
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("score_vs_node"))
    );
}

#[test]
fn gate_below_threshold_bun_blocks() {
    let mut input = passing_input();
    input.bun_cases = vec![case("slow-bun", 1500.0, 1000.0)]; // 1.5x < 3x
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("score_vs_bun")));
}

#[test]
fn gate_both_below_threshold_reports_both() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 1000.0, 1000.0)], // 1x
        bun_cases: vec![case("b", 2000.0, 1000.0)],  // 2x
        native_coverage_progression: vec![coverage_point("2026-01-01T00:00:00Z", 1, 1)],
        replacement_lineage_ids: vec!["lin-x".into()],
    };
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("score_vs_node"))
    );
    assert!(decision.blockers.iter().any(|b| b.contains("score_vs_bun")));
}

#[test]
fn gate_behavior_equivalent_false_blocks() {
    let mut input = passing_input();
    input.node_cases[0].behavior_equivalent = false;
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("behavior-equivalence"))
    );
}

#[test]
fn gate_latency_envelope_false_blocks() {
    let mut input = passing_input();
    input.bun_cases[0].latency_envelope_ok = false;
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("latency envelope"))
    );
}

#[test]
fn gate_error_envelope_false_blocks() {
    let mut input = passing_input();
    input.node_cases[0].error_envelope_ok = false;
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("error envelope"))
    );
}

#[test]
fn gate_multiple_quality_blockers_accumulated() {
    let mut input = passing_input();
    input.node_cases[0].behavior_equivalent = false;
    input.node_cases[0].latency_envelope_ok = false;
    input.node_cases[0].error_envelope_ok = false;
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert!(!decision.publish_allowed);
    // 3 quality blockers from node + possibly score blockers
    assert!(decision.blockers.len() >= 3);
}

#[test]
fn gate_fail_events_have_error_codes() {
    let mut input = passing_input();
    input.node_cases = vec![case("slow", 1000.0, 1000.0)]; // 1x < 3x
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    let node_evt = decision
        .events
        .iter()
        .find(|e| e.event == "node_score_evaluated")
        .unwrap();
    assert_eq!(node_evt.outcome, "fail");
    assert!(node_evt.error_code.is_some());
    let final_evt = decision
        .events
        .iter()
        .find(|e| e.event == "publication_gate_decision")
        .unwrap();
    assert_eq!(final_evt.outcome, "deny");
    assert!(final_evt.error_code.is_some());
}

// ── Section 10: evaluate_publication_gate — error paths ─────────────────

#[test]
fn gate_err_missing_coverage_progression() {
    let mut input = passing_input();
    input.native_coverage_progression.clear();
    let err = evaluate_publication_gate(&input, &ctx()).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::MissingCoverageProgression
    ));
}

#[test]
fn gate_err_missing_lineage() {
    let mut input = passing_input();
    input.replacement_lineage_ids.clear();
    let err = evaluate_publication_gate(&input, &ctx()).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::MissingReplacementLineage
    ));
}

#[test]
fn gate_err_empty_lineage_strings_filtered() {
    let mut input = passing_input();
    input.replacement_lineage_ids = vec!["  ".into(), "".into()];
    let err = evaluate_publication_gate(&input, &ctx()).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::MissingReplacementLineage
    ));
}

#[test]
fn gate_lineage_dedup_and_trim() {
    let mut input = passing_input();
    input.replacement_lineage_ids = vec![" lin-001 ".into(), "lin-001".into(), "lin-002".into()];
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert_eq!(decision.replacement_lineage_ids.len(), 2);
    assert_eq!(decision.replacement_lineage_ids[0], "lin-001");
    assert_eq!(decision.replacement_lineage_ids[1], "lin-002");
}

#[test]
fn gate_lineage_sorted() {
    let mut input = passing_input();
    input.replacement_lineage_ids = vec!["zzz".into(), "aaa".into(), "mmm".into()];
    let decision = evaluate_publication_gate(&input, &ctx()).unwrap();
    assert_eq!(decision.replacement_lineage_ids, vec!["aaa", "mmm", "zzz"]);
}

// ── Section 11: PublicationGateDecision ─────────────────────────────────

#[test]
fn decision_to_json_pretty_contains_expected_fields() {
    let decision = evaluate_publication_gate(&passing_input(), &ctx()).unwrap();
    let json = decision.to_json_pretty().unwrap();
    assert!(json.contains("publish_allowed"));
    assert!(json.contains("score_vs_node"));
    assert!(json.contains("score_vs_bun"));
    assert!(json.contains("events"));
}

#[test]
fn decision_serde_round_trip() {
    let decision = evaluate_publication_gate(&passing_input(), &ctx()).unwrap();
    let json = serde_json::to_string(&decision).unwrap();
    let back: PublicationGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision.publish_allowed, back.publish_allowed);
    assert!((decision.score_vs_node - back.score_vs_node).abs() < 1e-10);
    assert!((decision.score_vs_bun - back.score_vs_bun).abs() < 1e-10);
    assert_eq!(decision.blockers, back.blockers);
    assert_eq!(decision.events.len(), back.events.len());
}

// ── Section 12: PublicationGateInput serde ──────────────────────────────

#[test]
fn publication_gate_input_serde_round_trip() {
    let input = passing_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: PublicationGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.node_cases.len(), back.node_cases.len());
    assert_eq!(input.bun_cases.len(), back.bun_cases.len());
    assert_eq!(
        input.native_coverage_progression.len(),
        back.native_coverage_progression.len()
    );
    assert_eq!(input.replacement_lineage_ids, back.replacement_lineage_ids);
}

// ── Section 13: Constants ──────────────────────────────────────────────

#[test]
fn score_threshold_is_3() {
    assert!((SCORE_THRESHOLD - 3.0).abs() < f64::EPSILON);
}

#[test]
fn benchmark_publication_component_value() {
    assert_eq!(BENCHMARK_PUBLICATION_COMPONENT, "benchmark_denominator");
}
