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

use frankenengine_engine::benchmark_denominator::{
    BaselineEngine, BenchmarkCase, BenchmarkDenominatorError, NativeCoveragePoint,
    PublicationContext, PublicationGateInput, SCORE_THRESHOLD, evaluate_publication_gate,
    weighted_geometric_mean,
};

fn case(workload_id: &str, speedup: f64, weight: Option<f64>) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: 100.0 * speedup,
        throughput_baseline_tps: 100.0,
        weight,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn context() -> PublicationContext {
    PublicationContext::new(
        "trace-benchmark-denominator-test",
        "decision-benchmark-denominator-test",
        "policy-benchmark-denominator-v1",
    )
}

fn coverage() -> Vec<NativeCoveragePoint> {
    vec![
        NativeCoveragePoint {
            recorded_at_utc: "2026-02-22T00:00:00Z".to_string(),
            native_slots: 80,
            total_slots: 100,
        },
        NativeCoveragePoint {
            recorded_at_utc: "2026-02-23T00:00:00Z".to_string(),
            native_slots: 84,
            total_slots: 100,
        },
    ]
}

#[test]
fn weighted_geometric_mean_matches_known_vector() {
    let cases = vec![case("c1", 2.0, Some(0.5)), case("c2", 8.0, Some(0.5))];
    let score =
        weighted_geometric_mean(&cases, BaselineEngine::Node).expect("score should compute");
    assert!(
        (score - 4.0).abs() < 1e-12,
        "expected score 4.0, got {score}"
    );
}

#[test]
fn weighted_geometric_mean_handles_single_case_equal_weight_defaults_and_outlier() {
    let single = vec![case("single", 3.25, None)];
    let single_score =
        weighted_geometric_mean(&single, BaselineEngine::Node).expect("single-case score");
    assert!((single_score - 3.25).abs() < 1e-12);

    let equal_defaults = vec![
        case("a", 5.0, None),
        case("b", 5.0, None),
        case("c", 5.0, None),
    ];
    let equal_score = weighted_geometric_mean(&equal_defaults, BaselineEngine::Bun)
        .expect("equal default-weight score");
    assert!((equal_score - 5.0).abs() < 1e-12);

    let outlier = vec![
        case("x", 100.0, None),
        case("y", 1.0, None),
        case("z", 1.0, None),
    ];
    let outlier_score =
        weighted_geometric_mean(&outlier, BaselineEngine::Node).expect("outlier score");
    assert!(outlier_score > 4.5 && outlier_score < 4.7);
}

#[test]
fn weighted_geometric_mean_rejects_invalid_weight_sum() {
    let invalid = vec![case("c1", 2.0, Some(0.7)), case("c2", 2.0, Some(0.7))];
    let err = weighted_geometric_mean(&invalid, BaselineEngine::Node)
        .expect_err("invalid weight sum should fail");

    match err {
        BenchmarkDenominatorError::InvalidWeightSum { baseline, .. } => {
            assert_eq!(baseline, "node");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn publication_gate_allows_when_scores_and_quality_gates_pass() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.2, None), case("n2", 3.4, None)],
        bun_cases: vec![case("b1", 3.1, None), case("b2", 3.3, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-a".to_string(), "lineage-slot-b".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(decision.publish_allowed, "gate should allow publication");
    assert!(decision.score_vs_node >= SCORE_THRESHOLD);
    assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.events.len(), 3);
}

#[test]
fn publication_gate_denies_on_equivalence_or_threshold_failures() {
    let mut node_bad = case("node-bad", 3.5, None);
    node_bad.behavior_equivalent = false;

    let input = PublicationGateInput {
        node_cases: vec![node_bad],
        bun_cases: vec![case("bun-low", 2.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-z".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(!decision.publish_allowed);

    let blockers = decision.blockers.join(" | ");
    assert!(blockers.contains("failed behavior-equivalence"));
    assert!(blockers.contains("score_vs_bun below threshold"));

    let gate_event = decision
        .events
        .iter()
        .find(|event| event.event == "publication_gate_decision")
        .expect("publication gate event should exist");
    assert_eq!(gate_event.outcome, "deny");
    assert!(gate_event.error_code.is_some());
}

#[test]
fn publication_gate_requires_coverage_and_lineage_metadata() {
    let missing_coverage = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: Vec::new(),
        replacement_lineage_ids: vec!["lineage".to_string()],
    };

    let coverage_err = evaluate_publication_gate(&missing_coverage, &context())
        .expect_err("missing coverage should fail");
    assert!(matches!(
        coverage_err,
        BenchmarkDenominatorError::MissingCoverageProgression
    ));

    let missing_lineage = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["  ".to_string()],
    };

    let lineage_err = evaluate_publication_gate(&missing_lineage, &context())
        .expect_err("missing lineage should fail");
    assert!(matches!(
        lineage_err,
        BenchmarkDenominatorError::MissingReplacementLineage
    ));
}

#[test]
fn publication_gate_events_include_required_structured_fields() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    for event in decision.events {
        assert_eq!(event.component, "benchmark_denominator");
        assert_eq!(event.trace_id, "trace-benchmark-denominator-test");
        assert_eq!(event.decision_id, "decision-benchmark-denominator-test");
        assert_eq!(event.policy_id, "policy-benchmark-denominator-v1");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: error variants, serde, edge cases, determinism
// ────────────────────────────────────────────────────────────

#[test]
fn weighted_geometric_mean_rejects_empty_case_set() {
    let err =
        weighted_geometric_mean(&[], BaselineEngine::Node).expect_err("empty case set should fail");
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyCaseSet { .. }
    ));
}

#[test]
fn weighted_geometric_mean_rejects_empty_workload_id() {
    let bad = BenchmarkCase {
        workload_id: "".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: 50.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    let err = weighted_geometric_mean(&[bad], BaselineEngine::Node)
        .expect_err("empty workload_id should fail");
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyWorkloadId { .. }
    ));
}

#[test]
fn weighted_geometric_mean_rejects_duplicate_workload_ids() {
    let cases = vec![case("dup-wl", 3.0, None), case("dup-wl", 4.0, None)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node)
        .expect_err("duplicate workload_id should fail");
    assert!(matches!(
        err,
        BenchmarkDenominatorError::DuplicateWorkloadId { .. }
    ));
}

#[test]
fn weighted_geometric_mean_rejects_zero_baseline_throughput() {
    let bad = BenchmarkCase {
        workload_id: "zero-baseline".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: 0.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    let err = weighted_geometric_mean(&[bad], BaselineEngine::Bun)
        .expect_err("zero baseline throughput should fail");
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidThroughput { .. }
    ));
}

#[test]
fn publication_gate_denies_on_latency_envelope_failure() {
    let mut node_bad = case("node-lat", 3.5, None);
    node_bad.latency_envelope_ok = false;

    let input = PublicationGateInput {
        node_cases: vec![node_bad],
        bun_cases: vec![case("bun-ok", 3.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("latency")));
}

#[test]
fn publication_gate_denies_on_error_envelope_failure() {
    let mut node_bad = case("node-err", 3.5, None);
    node_bad.error_envelope_ok = false;

    let input = PublicationGateInput {
        node_cases: vec![node_bad],
        bun_cases: vec![case("bun-ok", 3.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(!decision.publish_allowed);
    assert!(decision.blockers.iter().any(|b| b.contains("error")));
}

#[test]
fn publication_gate_requires_both_node_and_bun_above_threshold() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 4.0, None)],
        bun_cases: vec![case("b1", 2.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(!decision.publish_allowed);
    assert!(decision.score_vs_node >= SCORE_THRESHOLD);
    assert!(decision.score_vs_bun < SCORE_THRESHOLD);
    assert!(decision.blockers.iter().any(|b| b.contains("score_vs_bun")));
}

#[test]
fn publication_gate_decision_json_roundtrip() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.0, None)],
        bun_cases: vec![case("b1", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    let json = decision.to_json_pretty().expect("to_json_pretty");
    let recovered: PublicationGateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision.publish_allowed, recovered.publish_allowed);
    assert_eq!(decision.blockers, recovered.blockers);
}

#[test]
fn publication_gate_is_deterministic_for_identical_inputs() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.2, None), case("n2", 3.4, None)],
        bun_cases: vec![case("b1", 3.1, None), case("b2", 3.3, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-a".to_string()],
    };

    let d1 = evaluate_publication_gate(&input, &context()).expect("gate 1");
    let d2 = evaluate_publication_gate(&input, &context()).expect("gate 2");
    assert_eq!(d1.score_vs_node, d2.score_vs_node);
    assert_eq!(d1.score_vs_bun, d2.score_vs_bun);
    assert_eq!(d1.publish_allowed, d2.publish_allowed);
    assert_eq!(d1.blockers, d2.blockers);
}

#[test]
fn benchmark_error_stable_codes_are_non_empty() {
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".to_string(),
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
    ];
    for err in &errors {
        let code = err.stable_code();
        assert!(!code.is_empty());
        assert!(code.starts_with("FE-BENCH-"));
    }
}

#[test]
fn benchmark_error_display_is_informative() {
    let err = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("node"));
    assert!(msg.contains("empty"));
}

#[test]
fn benchmark_error_serde_roundtrip() {
    let err = BenchmarkDenominatorError::InvalidWeightSum {
        baseline: "bun".to_string(),
        sum: 1.5,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: BenchmarkDenominatorError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn benchmark_case_serde_roundtrip() {
    let c = case("serde-wl", 3.5, Some(0.6));
    let json = serde_json::to_string(&c).expect("serialize");
    let recovered: BenchmarkCase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c.workload_id, recovered.workload_id);
    assert_eq!(c.weight, recovered.weight);
}

#[test]
fn publication_gate_preserves_coverage_and_lineage_in_output() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 3.5, None)],
        bun_cases: vec![case("b", 3.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-a".to_string(), "lineage-b".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert_eq!(decision.native_coverage_progression.len(), 2);
    assert!(
        decision
            .replacement_lineage_ids
            .contains(&"lineage-a".to_string())
    );
    assert!(
        decision
            .replacement_lineage_ids
            .contains(&"lineage-b".to_string())
    );
}

use frankenengine_engine::benchmark_denominator::{
    BenchmarkPublicationEvent, PublicationGateDecision,
};

#[test]
fn publication_event_serde_roundtrip() {
    let event = BenchmarkPublicationEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "benchmark_denominator".to_string(),
        event: "gate_decision".to_string(),
        outcome: "allow".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: BenchmarkPublicationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: enum serde, speedup(), constants,
// context/coverage serde, error Display coverage
// ────────────────────────────────────────────────────────────

#[test]
fn baseline_engine_as_str_values() {
    assert_eq!(BaselineEngine::Node.as_str(), "node");
    assert_eq!(BaselineEngine::Bun.as_str(), "bun");
}

#[test]
fn baseline_engine_serde_round_trip() {
    for engine in [BaselineEngine::Node, BaselineEngine::Bun] {
        let json = serde_json::to_string(&engine).expect("serialize");
        let recovered: BaselineEngine = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(engine, recovered);
    }
}

#[test]
fn benchmark_case_speedup_computes_ratio() {
    let c = BenchmarkCase {
        workload_id: "speedup-test".to_string(),
        throughput_franken_tps: 300.0,
        throughput_baseline_tps: 100.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!((c.speedup() - 3.0).abs() < 1e-12);
}

#[test]
fn benchmark_publication_component_constant_is_stable() {
    use frankenengine_engine::benchmark_denominator::BENCHMARK_PUBLICATION_COMPONENT;
    assert_eq!(BENCHMARK_PUBLICATION_COMPONENT, "benchmark_denominator");
}

#[test]
fn score_threshold_constant_is_three() {
    assert!((SCORE_THRESHOLD - 3.0).abs() < 1e-12);
}

#[test]
fn publication_context_serde_round_trip() {
    let ctx = context();
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: PublicationContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, recovered);
}

#[test]
fn native_coverage_point_serde_round_trip() {
    let point = NativeCoveragePoint {
        recorded_at_utc: "2026-03-04T12:00:00Z".to_string(),
        native_slots: 90,
        total_slots: 100,
    };
    let json = serde_json::to_string(&point).expect("serialize");
    let recovered: NativeCoveragePoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(point, recovered);
}

#[test]
fn publication_gate_input_serde_round_trip() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.5, None)],
        bun_cases: vec![case("b1", 3.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: PublicationGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input.node_cases.len(), recovered.node_cases.len());
    assert_eq!(
        input.replacement_lineage_ids,
        recovered.replacement_lineage_ids
    );
}

#[test]
fn benchmark_error_display_all_unique() {
    let errors: Vec<String> = vec![
        BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".to_string(),
        },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "node".to_string(),
            sum: 1.5,
        },
        BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "node".to_string(),
        },
        BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".to_string(),
            workload_id: "w".to_string(),
        },
        BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "w".to_string(),
            field: "throughput_franken_tps".to_string(),
        },
    ]
    .into_iter()
    .map(|e| e.to_string())
    .collect();

    // Each variant should produce a unique Display message
    let unique: std::collections::BTreeSet<_> = errors.iter().collect();
    assert_eq!(unique.len(), errors.len());
}

#[test]
fn benchmark_error_is_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(BenchmarkDenominatorError::MissingCoverageProgression);
    assert!(!err.to_string().is_empty());
}

#[test]
fn weighted_geometric_mean_negative_throughput_rejected() {
    let bad = BenchmarkCase {
        workload_id: "neg-throughput".to_string(),
        throughput_franken_tps: -100.0,
        throughput_baseline_tps: 100.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    let err = weighted_geometric_mean(&[bad], BaselineEngine::Node)
        .expect_err("negative throughput should fail");
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidThroughput { .. }
    ));
}
