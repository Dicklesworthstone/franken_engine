#![forbid(unsafe_code)]

//! Enrichment integration tests for the `benchmark_denominator` module.
//!
//! Covers Clone independence, BTreeSet ordering, Debug/Default, serde
//! field-name stability, std::error::Error, determinism, and edge cases.

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

use frankenengine_engine::benchmark_denominator::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_case(workload_id: &str, franken: f64, baseline: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn make_weighted_case(
    workload_id: &str,
    franken: f64,
    baseline: f64,
    weight: f64,
) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: Some(weight),
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn make_ctx() -> PublicationContext {
    PublicationContext::new("trace-enr-1", "dec-enr-1", "pol-enr-1")
}

fn make_coverage() -> Vec<NativeCoveragePoint> {
    vec![NativeCoveragePoint {
        recorded_at_utc: "2026-03-12T00:00:00Z".to_string(),
        native_slots: 10,
        total_slots: 20,
    }]
}

fn passing_input() -> PublicationGateInput {
    PublicationGateInput {
        node_cases: vec![make_case("w1", 400.0, 100.0)],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    }
}

// ===========================================================================
// Copy semantics (BaselineEngine has Copy)
// ===========================================================================

#[test]
fn enrichment_baseline_engine_copy() {
    let a = BaselineEngine::Node;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_benchmark_case_clone_independence() {
    let original = make_case("w1", 100.0, 50.0);
    let mut cloned = original.clone();
    cloned.workload_id = "mutated".to_string();
    assert_eq!(original.workload_id, "w1");
    assert_ne!(original.workload_id, cloned.workload_id);
}

#[test]
fn enrichment_publication_context_clone_independence() {
    let original = make_ctx();
    let mut cloned = original.clone();
    cloned.trace_id = "mutated".to_string();
    assert_eq!(original.trace_id, "trace-enr-1");
}

#[test]
fn enrichment_native_coverage_point_clone_independence() {
    let original = NativeCoveragePoint {
        recorded_at_utc: "2026-01-01T00:00:00Z".to_string(),
        native_slots: 5,
        total_slots: 10,
    };
    let mut cloned = original.clone();
    cloned.native_slots = 99;
    assert_eq!(original.native_slots, 5);
}

#[test]
fn enrichment_publication_gate_input_clone_independence() {
    let original = passing_input();
    let mut cloned = original.clone();
    cloned.replacement_lineage_ids.push("extra".to_string());
    assert_eq!(original.replacement_lineage_ids.len(), 1);
}

#[test]
fn enrichment_publication_gate_decision_clone_independence() {
    let decision = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let mut cloned = decision.clone();
    cloned.publish_allowed = !decision.publish_allowed;
    assert_ne!(decision.publish_allowed, cloned.publish_allowed);
}

#[test]
fn enrichment_benchmark_error_clone_independence() {
    let original = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_publication_event_clone_independence() {
    let event = BenchmarkPublicationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
    };
    let mut cloned = event.clone();
    cloned.outcome = "mutated".to_string();
    assert_eq!(event.outcome, "o");
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_baseline_engine_btreeset_ordering() {
    // BaselineEngine doesn't impl Ord — skip BTreeSet test
    // But we can test PartialEq
    assert_ne!(BaselineEngine::Node, BaselineEngine::Bun);
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_baseline_engine_debug() {
    let dbg = format!("{:?}", BaselineEngine::Node);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Node"));
}

#[test]
fn enrichment_benchmark_case_debug() {
    let dbg = format!("{:?}", make_case("w1", 100.0, 50.0));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("BenchmarkCase"));
}

#[test]
fn enrichment_publication_context_debug() {
    let dbg = format!("{:?}", make_ctx());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PublicationContext"));
}

#[test]
fn enrichment_native_coverage_point_debug() {
    let dbg = format!("{:?}", make_coverage()[0]);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("NativeCoveragePoint"));
}

#[test]
fn enrichment_publication_gate_decision_debug() {
    let decision = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let dbg = format!("{:?}", decision);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PublicationGateDecision"));
}

#[test]
fn enrichment_benchmark_error_debug() {
    let dbg = format!(
        "{:?}",
        BenchmarkDenominatorError::MissingCoverageProgression
    );
    assert!(!dbg.is_empty());
    assert!(dbg.contains("MissingCoverageProgression"));
}

#[test]
fn enrichment_publication_event_debug() {
    let decision = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let dbg = format!("{:?}", decision.events[0]);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("BenchmarkPublicationEvent"));
}

// ===========================================================================
// Display coverage (error variants)
// ===========================================================================

#[test]
fn enrichment_error_display_all_variants_unique() {
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".to_string(),
        },
        BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "bun".to_string(),
        },
        BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".to_string(),
            workload_id: "w1".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeight {
            workload_id: "w2".to_string(),
            reason: "negative".to_string(),
        },
        BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "w3".to_string(),
            field: "franken".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "node".to_string(),
            sum: 0.5,
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("json error".to_string()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ===========================================================================
// std::error::Error
// ===========================================================================

#[test]
fn enrichment_error_is_std_error() {
    let e = BenchmarkDenominatorError::MissingCoverageProgression;
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// stable_code coverage
// ===========================================================================

#[test]
fn enrichment_error_stable_codes_all_nonempty() {
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "x".to_string(),
        },
        BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "x".to_string(),
        },
        BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "x".to_string(),
            workload_id: "w".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeight {
            workload_id: "w".to_string(),
            reason: "r".to_string(),
        },
        BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "w".to_string(),
            field: "f".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "x".to_string(),
            sum: 0.0,
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("e".to_string()),
    ];
    let mut codes = BTreeSet::new();
    for e in &errors {
        let code = e.stable_code();
        assert!(!code.is_empty());
        assert!(code.starts_with("FE-BENCH-"));
        codes.insert(code);
    }
    // There are 7 unique codes (some variants share codes)
    assert!(codes.len() >= 7);
}

// ===========================================================================
// JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_benchmark_case_json_field_names() {
    let c = make_case("w1", 100.0, 50.0);
    let json = serde_json::to_value(&c).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "workload_id",
        "throughput_franken_tps",
        "throughput_baseline_tps",
        "behavior_equivalent",
        "latency_envelope_ok",
        "error_envelope_ok",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_publication_context_json_field_names() {
    let c = make_ctx();
    let json = serde_json::to_value(&c).unwrap();
    let obj = json.as_object().unwrap();
    for field in ["trace_id", "decision_id", "policy_id"] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_native_coverage_point_json_field_names() {
    let p = &make_coverage()[0];
    let json = serde_json::to_value(p).unwrap();
    let obj = json.as_object().unwrap();
    for field in ["recorded_at_utc", "native_slots", "total_slots"] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_publication_gate_decision_json_field_names() {
    let d = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let json = serde_json::to_value(&d).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "score_vs_node",
        "score_vs_bun",
        "publish_allowed",
        "blockers",
        "native_coverage_progression",
        "replacement_lineage_ids",
        "events",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_publication_event_json_field_names() {
    let d = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let json = serde_json::to_value(&d.events[0]).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_baseline_engine_serde_roundtrip() {
    for e in [BaselineEngine::Node, BaselineEngine::Bun] {
        let json = serde_json::to_string(&e).unwrap();
        let back: BaselineEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn enrichment_benchmark_case_serde_roundtrip() {
    let c = make_case("w1", 100.0, 50.0);
    let json = serde_json::to_string(&c).unwrap();
    let back: BenchmarkCase = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_benchmark_case_weighted_serde_roundtrip() {
    let c = make_weighted_case("w1", 100.0, 50.0, 0.5);
    let json = serde_json::to_string(&c).unwrap();
    let back: BenchmarkCase = serde_json::from_str(&json).unwrap();
    assert_eq!(c.weight, back.weight);
}

#[test]
fn enrichment_publication_context_serde_roundtrip() {
    let c = make_ctx();
    let json = serde_json::to_string(&c).unwrap();
    let back: PublicationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_native_coverage_point_serde_roundtrip() {
    let p = make_coverage()[0].clone();
    let json = serde_json::to_string(&p).unwrap();
    let back: NativeCoveragePoint = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".to_string(),
        },
        BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "bun".to_string(),
        },
        BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".to_string(),
            workload_id: "w1".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeight {
            workload_id: "w".to_string(),
            reason: "r".to_string(),
        },
        BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "w".to_string(),
            field: "f".to_string(),
        },
        BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "bun".to_string(),
            sum: 0.5,
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("err".to_string()),
    ];
    let jsons: BTreeSet<String> = errors
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    assert_eq!(jsons.len(), errors.len());
    for json in &jsons {
        let _back: BenchmarkDenominatorError = serde_json::from_str(json).unwrap();
    }
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_weighted_geometric_mean_determinism_20_runs() {
    let cases = vec![make_case("w1", 400.0, 100.0), make_case("w2", 350.0, 100.0)];
    let mut scores = BTreeSet::new();
    for _ in 0..20 {
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
        scores.insert(score.to_bits());
    }
    assert_eq!(scores.len(), 1, "must be deterministic");
}

#[test]
fn enrichment_publication_gate_determinism_20_runs() {
    let input = passing_input();
    let ctx = make_ctx();
    let mut results = BTreeSet::new();
    for _ in 0..20 {
        let d = evaluate_publication_gate(&input, &ctx).unwrap();
        results.insert(format!(
            "{:?}:{:?}",
            d.score_vs_node.to_bits(),
            d.publish_allowed
        ));
    }
    assert_eq!(results.len(), 1, "must be deterministic");
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_nonempty() {
    assert!(!BENCHMARK_PUBLICATION_COMPONENT.is_empty());
    assert!(SCORE_THRESHOLD > 0.0);
}

// ===========================================================================
// BaselineEngine methods
// ===========================================================================

#[test]
fn enrichment_baseline_engine_as_str_all() {
    assert_eq!(BaselineEngine::Node.as_str(), "node");
    assert_eq!(BaselineEngine::Bun.as_str(), "bun");
}

// ===========================================================================
// BenchmarkCase methods
// ===========================================================================

#[test]
fn enrichment_benchmark_case_speedup() {
    let c = make_case("w1", 400.0, 100.0);
    assert!((c.speedup() - 4.0).abs() < 1e-9);
}

#[test]
fn enrichment_benchmark_case_speedup_fractional() {
    let c = make_case("w1", 50.0, 100.0);
    assert!((c.speedup() - 0.5).abs() < 1e-9);
}

// ===========================================================================
// weighted_geometric_mean edge cases
// ===========================================================================

#[test]
fn enrichment_wgm_single_case() {
    let cases = vec![make_case("w1", 400.0, 100.0)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 4.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_equal_throughput() {
    let cases = vec![make_case("w1", 100.0, 100.0)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 1.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_empty_cases_error() {
    let result = weighted_geometric_mean(&[], BaselineEngine::Node);
    assert!(result.is_err());
    match result.unwrap_err() {
        BenchmarkDenominatorError::EmptyCaseSet { baseline } => {
            assert_eq!(baseline, "node");
        }
        other => panic!("expected EmptyCaseSet, got: {other:?}"),
    }
}

#[test]
fn enrichment_wgm_zero_franken_throughput_error() {
    let cases = vec![make_case("w1", 0.0, 100.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_zero_baseline_throughput_error() {
    let cases = vec![make_case("w1", 100.0, 0.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_negative_throughput_error() {
    let cases = vec![make_case("w1", -100.0, 100.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_nan_throughput_error() {
    let cases = vec![make_case("w1", f64::NAN, 100.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_infinity_throughput_error() {
    let cases = vec![make_case("w1", f64::INFINITY, 100.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_duplicate_workload_id_error() {
    let cases = vec![make_case("w1", 100.0, 50.0), make_case("w1", 200.0, 60.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Bun);
    assert!(result.is_err());
    match result.unwrap_err() {
        BenchmarkDenominatorError::DuplicateWorkloadId { workload_id, .. } => {
            assert_eq!(workload_id, "w1");
        }
        other => panic!("expected DuplicateWorkloadId, got: {other:?}"),
    }
}

#[test]
fn enrichment_wgm_empty_workload_id_error() {
    let cases = vec![make_case("", 100.0, 50.0)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_mixed_weights_error() {
    let cases = vec![
        make_weighted_case("w1", 100.0, 50.0, 0.5),
        make_case("w2", 200.0, 60.0), // no weight
    ];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
    match result.unwrap_err() {
        BenchmarkDenominatorError::InvalidWeight { reason, .. } => {
            assert!(reason.contains("all cases or none"));
        }
        other => panic!("expected InvalidWeight, got: {other:?}"),
    }
}

#[test]
fn enrichment_wgm_negative_weight_error() {
    let cases = vec![make_weighted_case("w1", 100.0, 50.0, -0.5)];
    let result = weighted_geometric_mean(&cases, BaselineEngine::Node);
    assert!(result.is_err());
}

#[test]
fn enrichment_wgm_explicit_equal_weights() {
    let cases = vec![
        make_weighted_case("w1", 400.0, 100.0, 0.5),
        make_weighted_case("w2", 400.0, 100.0, 0.5),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 4.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_unequal_weights() {
    // Heavy weight on 4x, light weight on 1x => geometric mean closer to 4
    let cases = vec![
        make_weighted_case("w1", 400.0, 100.0, 0.9),
        make_weighted_case("w2", 100.0, 100.0, 0.1),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!(score > 3.0);
    assert!(score < 4.0);
}

// ===========================================================================
// Publication gate edge cases
// ===========================================================================

#[test]
fn enrichment_gate_missing_coverage_error() {
    let input = PublicationGateInput {
        node_cases: vec![make_case("w1", 400.0, 100.0)],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: vec![],
        replacement_lineage_ids: vec!["l1".to_string()],
    };
    let result = evaluate_publication_gate(&input, &make_ctx());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        BenchmarkDenominatorError::MissingCoverageProgression
    ));
}

#[test]
fn enrichment_gate_missing_lineage_error() {
    let input = PublicationGateInput {
        node_cases: vec![make_case("w1", 400.0, 100.0)],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec![],
    };
    let result = evaluate_publication_gate(&input, &make_ctx());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        BenchmarkDenominatorError::MissingReplacementLineage
    ));
}

#[test]
fn enrichment_gate_whitespace_only_lineage_treated_as_empty() {
    let input = PublicationGateInput {
        node_cases: vec![make_case("w1", 400.0, 100.0)],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["  ".to_string(), "".to_string()],
    };
    let result = evaluate_publication_gate(&input, &make_ctx());
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_passing_has_no_blockers() {
    let d = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    assert!(d.publish_allowed);
    assert!(d.blockers.is_empty());
    assert!(d.score_vs_node >= SCORE_THRESHOLD);
    assert!(d.score_vs_bun >= SCORE_THRESHOLD);
}

#[test]
fn enrichment_gate_below_threshold_blocked() {
    let input = PublicationGateInput {
        node_cases: vec![make_case("w1", 200.0, 100.0)], // 2x < 3x threshold
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["l1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &make_ctx()).unwrap();
    assert!(!d.publish_allowed);
    assert!(!d.blockers.is_empty());
}

#[test]
fn enrichment_gate_behavior_equivalence_failure_blocked() {
    let mut case = make_case("w1", 400.0, 100.0);
    case.behavior_equivalent = false;
    let input = PublicationGateInput {
        node_cases: vec![case],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["l1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &make_ctx()).unwrap();
    assert!(!d.publish_allowed);
    assert!(
        d.blockers
            .iter()
            .any(|b| b.contains("behavior-equivalence"))
    );
}

#[test]
fn enrichment_gate_latency_envelope_failure_blocked() {
    let mut case = make_case("w1", 400.0, 100.0);
    case.latency_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![case],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["l1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &make_ctx()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("latency envelope")));
}

#[test]
fn enrichment_gate_error_envelope_failure_blocked() {
    let mut case = make_case("w1", 400.0, 100.0);
    case.error_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![case],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec!["l1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &make_ctx()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("error envelope")));
}

#[test]
fn enrichment_gate_events_contain_baseline_scores() {
    let d = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    // Should have at least 3 events: node_score, bun_score, gate_decision
    assert!(d.events.len() >= 3);
    let event_names: Vec<&str> = d.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.iter().any(|e| e.contains("node_score")));
    assert!(event_names.iter().any(|e| e.contains("bun_score")));
    assert!(
        event_names
            .iter()
            .any(|e| e.contains("publication_gate_decision"))
    );
}

#[test]
fn enrichment_gate_lineage_ids_deduplicated_and_sorted() {
    let input = PublicationGateInput {
        node_cases: vec![make_case("w1", 400.0, 100.0)],
        bun_cases: vec![make_case("w1", 400.0, 100.0)],
        native_coverage_progression: make_coverage(),
        replacement_lineage_ids: vec![
            "b".to_string(),
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ],
    };
    let d = evaluate_publication_gate(&input, &make_ctx()).unwrap();
    assert_eq!(d.replacement_lineage_ids, vec!["a", "b", "c"]);
}

// ===========================================================================
// PublicationGateDecision::to_json_pretty
// ===========================================================================

#[test]
fn enrichment_decision_to_json_pretty() {
    let d = evaluate_publication_gate(&passing_input(), &make_ctx()).unwrap();
    let json = d.to_json_pretty().unwrap();
    assert!(json.contains("score_vs_node"));
    assert!(json.contains("publish_allowed"));
}

// ===========================================================================
// PublicationContext::new
// ===========================================================================

#[test]
fn enrichment_publication_context_new() {
    let c = PublicationContext::new("t1", "d1", "p1");
    assert_eq!(c.trace_id, "t1");
    assert_eq!(c.decision_id, "d1");
    assert_eq!(c.policy_id, "p1");
}
