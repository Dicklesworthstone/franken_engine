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
    BENCHMARK_PUBLICATION_COMPONENT, BaselineEngine, BenchmarkCase, BenchmarkDenominatorError,
    BenchmarkPublicationEvent, NativeCoveragePoint, PublicationContext, PublicationGateDecision,
    PublicationGateInput, SCORE_THRESHOLD, evaluate_publication_gate, weighted_geometric_mean,
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

// ────────────────────────────────────────────────────────────────────────
// Enrichment: deep coverage of weighted_geometric_mean, evaluate_publication_gate,
// serde fidelity, error variant semantics, determinism invariants, boundary
// conditions, quality-gate blocker accumulation, event structure contracts.
// ────────────────────────────────────────────────────────────────────────

#[test]
fn enrichment_wgm_four_equal_speedups_equals_any_single() {
    let cases = vec![
        case("a", 7.0, None),
        case("b", 7.0, None),
        case("c", 7.0, None),
        case("d", 7.0, None),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 7.0).abs() < 1e-9);
}

#[test]
fn enrichment_wgm_two_cases_geometric_mean_sqrt() {
    // geometric mean of 4x and 9x = sqrt(36) = 6
    let cases = vec![case("a", 4.0, None), case("b", 9.0, None)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap();
    assert!((score - 6.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_three_cases_cube_root() {
    // geometric mean of 2x, 4x, 8x = (2*4*8)^(1/3) = (64)^(1/3) = 4
    let cases = vec![
        case("a", 2.0, None),
        case("b", 4.0, None),
        case("c", 8.0, None),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 4.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_weighted_single_case_weight_one() {
    let cases = vec![case("only", 5.5, Some(1.0))];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 5.5).abs() < 1e-9);
}

#[test]
fn enrichment_wgm_heavily_skewed_weights() {
    // 0.9 weight on 10x, 0.1 weight on 1x => 10^0.9 * 1^0.1 = 10^0.9
    let cases = vec![
        case("heavy", 10.0, Some(0.9)),
        case("light", 1.0, Some(0.1)),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    let expected = 10.0_f64.powf(0.9);
    assert!((score - expected).abs() < 1e-4);
}

#[test]
fn enrichment_wgm_three_explicit_weights_summing_to_one() {
    let cases = vec![
        case("a", 2.0, Some(0.2)),
        case("b", 4.0, Some(0.3)),
        case("c", 8.0, Some(0.5)),
    ];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap();
    let expected = 2.0_f64.powf(0.2) * 4.0_f64.powf(0.3) * 8.0_f64.powf(0.5);
    assert!((score - expected).abs() < 1e-4);
}

#[test]
fn enrichment_wgm_baseline_engine_does_not_affect_score() {
    let cases = vec![case("a", 5.0, None), case("b", 5.0, None)];
    let node_score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    let bun_score = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap();
    assert!((node_score - bun_score).abs() < 1e-12);
}

#[test]
fn enrichment_wgm_large_number_of_cases() {
    let cases: Vec<BenchmarkCase> = (0..20)
        .map(|i| case(&format!("wk-{i}"), 3.0, None))
        .collect();
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 3.0).abs() < 1e-6);
}

#[test]
fn enrichment_wgm_very_small_speedup() {
    let cases = vec![case("tiny", 0.01, None)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 0.01).abs() < 1e-9);
}

#[test]
fn enrichment_wgm_very_large_speedup() {
    let cases = vec![case("huge", 1000.0, None)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!((score - 1000.0).abs() < 1e-3);
}

#[test]
fn enrichment_wgm_near_threshold_speedup_below() {
    let cases = vec![case("near", 2.999, None)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!(score < SCORE_THRESHOLD);
}

#[test]
fn enrichment_wgm_near_threshold_speedup_above() {
    let cases = vec![case("near", 3.001, None)];
    let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    assert!(score >= SCORE_THRESHOLD);
}

#[test]
fn enrichment_wgm_err_whitespace_only_workload() {
    let bad = BenchmarkCase {
        workload_id: "\t  \n".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: 50.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    let err = weighted_geometric_mean(&[bad], BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::EmptyWorkloadId { .. }
    ));
}

#[test]
fn enrichment_wgm_err_neg_inf_throughput() {
    let bad = BenchmarkCase {
        workload_id: "neg-inf".to_string(),
        throughput_franken_tps: f64::NEG_INFINITY,
        throughput_baseline_tps: 100.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_baseline_nan() {
    let bad = BenchmarkCase {
        workload_id: "nan-base".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: f64::NAN,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_baseline_negative() {
    let bad = BenchmarkCase {
        workload_id: "neg-base".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: -50.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_baseline_inf() {
    let bad = BenchmarkCase {
        workload_id: "inf-base".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: f64::INFINITY,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_weight_nan() {
    let bad = case("wnan", 3.0, Some(f64::NAN));
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_weight_inf() {
    let bad = case("winf", 3.0, Some(f64::INFINITY));
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_weight_neg_inf() {
    let bad = case("wneginf", 3.0, Some(f64::NEG_INFINITY));
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_weight_zero() {
    let bad = case("wzero", 3.0, Some(0.0));
    assert!(weighted_geometric_mean(&[bad], BaselineEngine::Node).is_err());
}

#[test]
fn enrichment_wgm_err_weight_sum_just_over() {
    let cases = vec![
        case("a", 3.0, Some(0.50000001)),
        case("b", 3.0, Some(0.50000001)),
    ];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidWeightSum { .. }
    ));
}

#[test]
fn enrichment_wgm_err_weight_sum_just_under() {
    let cases = vec![
        case("a", 3.0, Some(0.49999999)),
        case("b", 3.0, Some(0.49999999)),
    ];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidWeightSum { .. }
    ));
}

#[test]
fn enrichment_wgm_err_mixed_some_none_weights() {
    let cases = vec![
        case("a", 3.0, None),
        case("b", 3.0, Some(0.5)),
        case("c", 3.0, None),
    ];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkDenominatorError::InvalidWeight { .. }
    ));
}

#[test]
fn enrichment_wgm_err_duplicate_in_bun_baseline() {
    let cases = vec![case("dup", 3.0, None), case("dup", 4.0, None)];
    let err = weighted_geometric_mean(&cases, BaselineEngine::Bun).unwrap_err();
    if let BenchmarkDenominatorError::DuplicateWorkloadId { baseline, workload_id } = &err {
        assert_eq!(baseline, "bun");
        assert_eq!(workload_id, "dup");
    } else {
        panic!("expected DuplicateWorkloadId, got {err:?}");
    }
}

#[test]
fn enrichment_wgm_err_empty_case_set_bun() {
    let err = weighted_geometric_mean(&[], BaselineEngine::Bun).unwrap_err();
    if let BenchmarkDenominatorError::EmptyCaseSet { baseline } = &err {
        assert_eq!(baseline, "bun");
    } else {
        panic!("expected EmptyCaseSet, got {err:?}");
    }
}

#[test]
fn enrichment_wgm_order_independent() {
    let cases_ab = vec![case("alpha", 2.0, None), case("beta", 8.0, None)];
    let cases_ba = vec![case("beta", 8.0, None), case("alpha", 2.0, None)];
    let score_ab = weighted_geometric_mean(&cases_ab, BaselineEngine::Node).unwrap();
    let score_ba = weighted_geometric_mean(&cases_ba, BaselineEngine::Node).unwrap();
    assert_eq!(score_ab, score_ba, "order must not affect result");
}

#[test]
fn enrichment_wgm_determinism_ten_runs() {
    let cases = vec![
        case("x", 3.14, None),
        case("y", 2.72, None),
        case("z", 1.41, None),
    ];
    let first = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
    for _ in 0..10 {
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap();
        assert_eq!(first, score);
    }
}

// ── evaluate_publication_gate enrichment ─────────────────────────────

#[test]
fn enrichment_gate_exact_threshold_both_engines() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(d.publish_allowed);
    assert!(d.blockers.is_empty());
}

#[test]
fn enrichment_gate_just_below_threshold_node() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 2.999, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("score_vs_node")));
}

#[test]
fn enrichment_gate_just_below_threshold_bun() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 2.999, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("score_vs_bun")));
}

#[test]
fn enrichment_gate_both_well_above_threshold() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 100.0, None)],
        bun_cases: vec![case("b", 50.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(d.publish_allowed);
    assert!(d.blockers.is_empty());
    assert!(d.score_vs_node > 10.0);
    assert!(d.score_vs_bun > 10.0);
}

#[test]
fn enrichment_gate_multi_case_per_baseline() {
    let input = PublicationGateInput {
        node_cases: vec![
            case("n1", 4.0, None),
            case("n2", 5.0, None),
            case("n3", 3.5, None),
        ],
        bun_cases: vec![
            case("b1", 3.5, None),
            case("b2", 4.5, None),
        ],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(d.publish_allowed);
    assert!(d.score_vs_node >= SCORE_THRESHOLD);
    assert!(d.score_vs_bun >= SCORE_THRESHOLD);
}

#[test]
fn enrichment_gate_behavior_false_on_bun_blocks() {
    let mut bad_bun = case("bun-behav", 5.0, None);
    bad_bun.behavior_equivalent = false;
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![bad_bun],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("behavior-equivalence")));
    assert!(d.blockers.iter().any(|b| b.contains("bun")));
}

#[test]
fn enrichment_gate_latency_false_on_node_blocks() {
    let mut bad_node = case("node-lat", 5.0, None);
    bad_node.latency_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![bad_node],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("latency")));
    assert!(d.blockers.iter().any(|b| b.contains("node")));
}

#[test]
fn enrichment_gate_error_false_on_bun_blocks() {
    let mut bad_bun = case("bun-err", 5.0, None);
    bad_bun.error_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![bad_bun],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.iter().any(|b| b.contains("error")));
    assert!(d.blockers.iter().any(|b| b.contains("bun")));
}

#[test]
fn enrichment_gate_all_three_quality_flags_false_node() {
    let mut bad = case("node-all-bad", 5.0, None);
    bad.behavior_equivalent = false;
    bad.latency_envelope_ok = false;
    bad.error_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![bad],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.len() >= 3);
}

#[test]
fn enrichment_gate_all_three_quality_flags_false_bun() {
    let mut bad = case("bun-all-bad", 5.0, None);
    bad.behavior_equivalent = false;
    bad.latency_envelope_ok = false;
    bad.error_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![bad],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.len() >= 3);
}

#[test]
fn enrichment_gate_mixed_quality_flags_multiple_cases() {
    let mut bad_n1 = case("n1", 5.0, None);
    bad_n1.behavior_equivalent = false;
    let mut bad_n2 = case("n2", 5.0, None);
    bad_n2.latency_envelope_ok = false;
    let input = PublicationGateInput {
        node_cases: vec![bad_n1, bad_n2],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(d.blockers.len() >= 2);
}

#[test]
fn enrichment_gate_quality_plus_score_blockers_accumulated() {
    let mut bad_n = case("n", 2.0, None);
    bad_n.behavior_equivalent = false;
    let input = PublicationGateInput {
        node_cases: vec![bad_n],
        bun_cases: vec![case("b", 2.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    // Should have behavior blocker + score_vs_node + score_vs_bun
    assert!(d.blockers.len() >= 3);
}

#[test]
fn enrichment_gate_events_always_three() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 5.0, None), case("n2", 4.0, None)],
        bun_cases: vec![case("b1", 3.0, None), case("b2", 4.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.events.len(), 3);
}

#[test]
fn enrichment_gate_events_order_node_bun_decision() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.events[0].event, "node_score_evaluated");
    assert_eq!(d.events[1].event, "bun_score_evaluated");
    assert_eq!(d.events[2].event, "publication_gate_decision");
}

#[test]
fn enrichment_gate_deny_events_have_error_codes() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 1.0, None)],
        bun_cases: vec![case("b", 1.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    for event in &d.events {
        if event.outcome == "fail" || event.outcome == "deny" {
            assert!(event.error_code.is_some());
        }
    }
}

#[test]
fn enrichment_gate_allow_events_have_no_error_codes() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(d.publish_allowed);
    for event in &d.events {
        assert!(event.error_code.is_none());
    }
}

#[test]
fn enrichment_gate_events_carry_trace_decision_policy() {
    let ctx = PublicationContext::new("trace-enr", "dec-enr", "pol-enr");
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &ctx).unwrap();
    for event in &d.events {
        assert_eq!(event.trace_id, "trace-enr");
        assert_eq!(event.decision_id, "dec-enr");
        assert_eq!(event.policy_id, "pol-enr");
        assert_eq!(event.component, BENCHMARK_PUBLICATION_COMPONENT);
    }
}

#[test]
fn enrichment_gate_events_component_constant() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    for event in &d.events {
        assert_eq!(event.component, "benchmark_denominator");
    }
}

// ── Lineage and coverage handling enrichment ────────────────────────

#[test]
fn enrichment_gate_lineage_dedup_three_copies() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec![
            "lin-a".to_string(),
            "lin-a".to_string(),
            "lin-a".to_string(),
        ],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.replacement_lineage_ids.len(), 1);
    assert_eq!(d.replacement_lineage_ids[0], "lin-a");
}

#[test]
fn enrichment_gate_lineage_trim_preserves_content() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec![
            "  lin-spaced  ".to_string(),
        ],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.replacement_lineage_ids[0], "lin-spaced");
}

#[test]
fn enrichment_gate_lineage_sorted_output() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec![
            "zzz-lineage".to_string(),
            "aaa-lineage".to_string(),
            "mmm-lineage".to_string(),
        ],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.replacement_lineage_ids, vec!["aaa-lineage", "mmm-lineage", "zzz-lineage"]);
}

#[test]
fn enrichment_gate_lineage_all_whitespace_rejected() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec![
            "   ".to_string(),
            "\t".to_string(),
        ],
    };
    let err = evaluate_publication_gate(&input, &context()).unwrap_err();
    assert!(matches!(err, BenchmarkDenominatorError::MissingReplacementLineage));
}

#[test]
fn enrichment_gate_coverage_single_point_preserved() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: vec![NativeCoveragePoint {
            recorded_at_utc: "2026-06-01T00:00:00Z".to_string(),
            native_slots: 50,
            total_slots: 100,
        }],
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.native_coverage_progression.len(), 1);
    assert_eq!(d.native_coverage_progression[0].native_slots, 50);
    assert_eq!(d.native_coverage_progression[0].total_slots, 100);
}

#[test]
fn enrichment_gate_coverage_many_points_preserved() {
    let points: Vec<NativeCoveragePoint> = (0..10)
        .map(|i| NativeCoveragePoint {
            recorded_at_utc: format!("2026-01-{:02}T00:00:00Z", i + 1),
            native_slots: i * 10,
            total_slots: 100,
        })
        .collect();
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: points.clone(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d.native_coverage_progression.len(), 10);
    for (i, pt) in d.native_coverage_progression.iter().enumerate() {
        assert_eq!(pt.native_slots, points[i].native_slots);
    }
}

#[test]
fn enrichment_gate_missing_coverage_err_checked_before_lineage() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: vec![],
        replacement_lineage_ids: vec![],
    };
    let err = evaluate_publication_gate(&input, &context()).unwrap_err();
    // Coverage checked first
    assert!(matches!(err, BenchmarkDenominatorError::MissingCoverageProgression));
}

// ── Serde round-trip enrichment ─────────────────────────────────────

#[test]
fn enrichment_gate_decision_serde_full_roundtrip() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.5, None), case("n2", 4.0, None)],
        bun_cases: vec![case("b1", 3.2, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-a".to_string(), "lin-b".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let recovered: PublicationGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d.publish_allowed, recovered.publish_allowed);
    assert_eq!(d.blockers, recovered.blockers);
    assert_eq!(d.replacement_lineage_ids, recovered.replacement_lineage_ids);
    assert_eq!(d.events.len(), recovered.events.len());
    assert!((d.score_vs_node - recovered.score_vs_node).abs() < 1e-12);
    assert!((d.score_vs_bun - recovered.score_vs_bun).abs() < 1e-12);
}

#[test]
fn enrichment_gate_decision_to_json_pretty_valid_json() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    let json_pretty = d.to_json_pretty().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_pretty).unwrap();
    assert!(parsed.is_object());
    assert!(parsed.get("publish_allowed").is_some());
    assert!(parsed.get("score_vs_node").is_some());
    assert!(parsed.get("score_vs_bun").is_some());
    assert!(parsed.get("blockers").is_some());
    assert!(parsed.get("events").is_some());
}

#[test]
fn enrichment_gate_decision_deny_to_json_pretty() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 1.0, None)],
        bun_cases: vec![case("b", 1.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    let json_pretty = d.to_json_pretty().unwrap();
    assert!(json_pretty.contains("\"publish_allowed\": false"));
}

#[test]
fn enrichment_publication_event_with_error_code_serde() {
    let event = BenchmarkPublicationEvent {
        trace_id: "t-err".to_string(),
        decision_id: "d-err".to_string(),
        policy_id: "p-err".to_string(),
        component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
        event: "node_score_evaluated".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-BENCH-1007".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let recovered: BenchmarkPublicationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, recovered);
    assert!(json.contains("FE-BENCH-1007"));
}

#[test]
fn enrichment_benchmark_case_with_weight_serde() {
    let c = case("weighted-serde", 4.0, Some(0.7));
    let json = serde_json::to_string(&c).unwrap();
    let recovered: BenchmarkCase = serde_json::from_str(&json).unwrap();
    assert_eq!(c.workload_id, recovered.workload_id);
    assert_eq!(c.weight, recovered.weight);
    assert!((c.throughput_franken_tps - recovered.throughput_franken_tps).abs() < 1e-12);
}

#[test]
fn enrichment_benchmark_case_without_weight_serde() {
    let c = case("no-weight-serde", 3.0, None);
    let json = serde_json::to_string(&c).unwrap();
    let recovered: BenchmarkCase = serde_json::from_str(&json).unwrap();
    assert!(recovered.weight.is_none());
}

#[test]
fn enrichment_benchmark_case_json_defaults_applied() {
    let json = r#"{"workload_id":"minimal","throughput_franken_tps":200.0,"throughput_baseline_tps":100.0}"#;
    let c: BenchmarkCase = serde_json::from_str(json).unwrap();
    assert!(c.behavior_equivalent);
    assert!(c.latency_envelope_ok);
    assert!(c.error_envelope_ok);
    assert!(c.weight.is_none());
    assert!((c.speedup() - 2.0).abs() < 1e-12);
}

#[test]
fn enrichment_baseline_engine_serde_node_string() {
    let json = serde_json::to_string(&BaselineEngine::Node).unwrap();
    assert_eq!(json, "\"node\"");
}

#[test]
fn enrichment_baseline_engine_serde_bun_string() {
    let json = serde_json::to_string(&BaselineEngine::Bun).unwrap();
    assert_eq!(json, "\"bun\"");
}

#[test]
fn enrichment_baseline_engine_invalid_serde_rejected() {
    let result: Result<BaselineEngine, _> = serde_json::from_str("\"deno\"");
    assert!(result.is_err());
}

// ── Error variant enrichment ────────────────────────────────────────

#[test]
fn enrichment_error_empty_case_set_display_contains_baseline() {
    let err = BenchmarkDenominatorError::EmptyCaseSet {
        baseline: "node".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("node"));
    assert!(msg.contains("empty"));
}

#[test]
fn enrichment_error_empty_workload_display() {
    let err = BenchmarkDenominatorError::EmptyWorkloadId {
        baseline: "bun".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("bun"));
    assert!(msg.contains("empty"));
}

#[test]
fn enrichment_error_duplicate_workload_display() {
    let err = BenchmarkDenominatorError::DuplicateWorkloadId {
        baseline: "node".to_string(),
        workload_id: "wk-dup".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("wk-dup"));
    assert!(msg.contains("duplicate"));
}

#[test]
fn enrichment_error_invalid_weight_display() {
    let err = BenchmarkDenominatorError::InvalidWeight {
        workload_id: "wk-w".to_string(),
        reason: "must be finite".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("wk-w"));
    assert!(msg.contains("must be finite"));
}

#[test]
fn enrichment_error_invalid_throughput_display() {
    let err = BenchmarkDenominatorError::InvalidThroughput {
        workload_id: "wk-t".to_string(),
        field: "throughput_franken_tps".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("wk-t"));
    assert!(msg.contains("throughput_franken_tps"));
}

#[test]
fn enrichment_error_invalid_weight_sum_display() {
    let err = BenchmarkDenominatorError::InvalidWeightSum {
        baseline: "bun".to_string(),
        sum: 1.5,
    };
    let msg = err.to_string();
    assert!(msg.contains("bun"));
    assert!(msg.contains("1.5"));
}

#[test]
fn enrichment_error_missing_coverage_display() {
    let err = BenchmarkDenominatorError::MissingCoverageProgression;
    let msg = err.to_string();
    assert!(msg.contains("coverage"));
}

#[test]
fn enrichment_error_missing_lineage_display() {
    let err = BenchmarkDenominatorError::MissingReplacementLineage;
    let msg = err.to_string();
    assert!(msg.contains("lineage"));
}

#[test]
fn enrichment_error_serialization_failure_display() {
    let err = BenchmarkDenominatorError::SerializationFailure("io broken".to_string());
    let msg = err.to_string();
    assert!(msg.contains("io broken"));
}

#[test]
fn enrichment_error_stable_code_groups() {
    // EmptyCaseSet, EmptyWorkloadId, DuplicateWorkloadId share FE-BENCH-1001
    let codes: Vec<&str> = vec![
        BenchmarkDenominatorError::EmptyCaseSet { baseline: "x".into() }.stable_code(),
        BenchmarkDenominatorError::EmptyWorkloadId { baseline: "x".into() }.stable_code(),
        BenchmarkDenominatorError::DuplicateWorkloadId { baseline: "x".into(), workload_id: "w".into() }.stable_code(),
    ];
    assert!(codes.iter().all(|c| *c == "FE-BENCH-1001"));
}

#[test]
fn enrichment_error_stable_codes_distinct_families() {
    use std::collections::BTreeSet;
    let codes: BTreeSet<&str> = vec![
        BenchmarkDenominatorError::EmptyCaseSet { baseline: "x".into() }.stable_code(),
        BenchmarkDenominatorError::InvalidWeight { workload_id: "x".into(), reason: "r".into() }.stable_code(),
        BenchmarkDenominatorError::InvalidThroughput { workload_id: "x".into(), field: "f".into() }.stable_code(),
        BenchmarkDenominatorError::InvalidWeightSum { baseline: "x".into(), sum: 0.5 }.stable_code(),
        BenchmarkDenominatorError::MissingCoverageProgression.stable_code(),
        BenchmarkDenominatorError::MissingReplacementLineage.stable_code(),
        BenchmarkDenominatorError::SerializationFailure("x".into()).stable_code(),
    ]
    .into_iter()
    .collect();
    assert_eq!(codes.len(), 7, "7 distinct stable code families");
}

#[test]
fn enrichment_error_all_serde_roundtrip() {
    let errors = vec![
        BenchmarkDenominatorError::EmptyCaseSet { baseline: "node".to_string() },
        BenchmarkDenominatorError::EmptyWorkloadId { baseline: "bun".to_string() },
        BenchmarkDenominatorError::DuplicateWorkloadId { baseline: "node".to_string(), workload_id: "w".to_string() },
        BenchmarkDenominatorError::InvalidWeight { workload_id: "w".to_string(), reason: "bad".to_string() },
        BenchmarkDenominatorError::InvalidThroughput { workload_id: "w".to_string(), field: "f".to_string() },
        BenchmarkDenominatorError::InvalidWeightSum { baseline: "node".to_string(), sum: 1.5 },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("oops".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let recovered: BenchmarkDenominatorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, recovered, "roundtrip failed for {err:?}");
    }
}

#[test]
fn enrichment_error_debug_not_empty_all_variants() {
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet { baseline: "x".into() },
        BenchmarkDenominatorError::EmptyWorkloadId { baseline: "x".into() },
        BenchmarkDenominatorError::DuplicateWorkloadId { baseline: "x".into(), workload_id: "w".into() },
        BenchmarkDenominatorError::InvalidWeight { workload_id: "w".into(), reason: "r".into() },
        BenchmarkDenominatorError::InvalidThroughput { workload_id: "w".into(), field: "f".into() },
        BenchmarkDenominatorError::InvalidWeightSum { baseline: "x".into(), sum: 0.5 },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::MissingReplacementLineage,
        BenchmarkDenominatorError::SerializationFailure("x".into()),
    ];
    for err in &errors {
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty(), "Debug should not be empty for {err:?}");
    }
}

#[test]
fn enrichment_error_source_none_all_variants() {
    use std::error::Error as StdError;
    let errors: Vec<BenchmarkDenominatorError> = vec![
        BenchmarkDenominatorError::EmptyCaseSet { baseline: "x".into() },
        BenchmarkDenominatorError::MissingCoverageProgression,
        BenchmarkDenominatorError::SerializationFailure("x".into()),
    ];
    for err in &errors {
        assert!(err.source().is_none());
    }
}

// ── Determinism enrichment ──────────────────────────────────────────

#[test]
fn enrichment_gate_determinism_full_decision() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.14, None), case("n2", 4.56, None)],
        bun_cases: vec![case("b1", 3.78, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-x".to_string()],
    };
    let d1 = evaluate_publication_gate(&input, &context()).unwrap();
    let d2 = evaluate_publication_gate(&input, &context()).unwrap();
    assert_eq!(d1.score_vs_node, d2.score_vs_node);
    assert_eq!(d1.score_vs_bun, d2.score_vs_bun);
    assert_eq!(d1.publish_allowed, d2.publish_allowed);
    assert_eq!(d1.blockers, d2.blockers);
    assert_eq!(d1.events.len(), d2.events.len());
    assert_eq!(d1.replacement_lineage_ids, d2.replacement_lineage_ids);
}

#[test]
fn enrichment_gate_determinism_deny_path() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 2.0, None)],
        bun_cases: vec![case("b", 2.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d1 = evaluate_publication_gate(&input, &context()).unwrap();
    let d2 = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d1.publish_allowed);
    assert_eq!(d1.blockers, d2.blockers);
    assert_eq!(d1.score_vs_node, d2.score_vs_node);
}

// ── Speedup method enrichment ───────────────────────────────────────

#[test]
fn enrichment_speedup_exact_ratio() {
    let c = BenchmarkCase {
        workload_id: "sp1".to_string(),
        throughput_franken_tps: 750.0,
        throughput_baseline_tps: 250.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!((c.speedup() - 3.0).abs() < 1e-12);
}

#[test]
fn enrichment_speedup_fractional() {
    let c = BenchmarkCase {
        workload_id: "sp2".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: 400.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!((c.speedup() - 0.25).abs() < 1e-12);
}

#[test]
fn enrichment_speedup_equal_throughputs() {
    let c = case("equal", 1.0, None);
    assert!((c.speedup() - 1.0).abs() < 1e-12);
}

#[test]
fn enrichment_speedup_very_high() {
    let c = BenchmarkCase {
        workload_id: "high-sp".to_string(),
        throughput_franken_tps: 1_000_000.0,
        throughput_baseline_tps: 1.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    };
    assert!((c.speedup() - 1_000_000.0).abs() < 1e-3);
}

// ── PublicationContext enrichment ────────────────────────────────────

#[test]
fn enrichment_context_new_with_into() {
    let ctx = PublicationContext::new(
        String::from("trace-str"),
        String::from("dec-str"),
        String::from("pol-str"),
    );
    assert_eq!(ctx.trace_id, "trace-str");
    assert_eq!(ctx.decision_id, "dec-str");
    assert_eq!(ctx.policy_id, "pol-str");
}

#[test]
fn enrichment_context_clone_independence() {
    let original = context();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // They are separate allocations
    assert_eq!(original.trace_id, cloned.trace_id);
}

// ── Constants enrichment ────────────────────────────────────────────

#[test]
fn enrichment_score_threshold_exactly_three() {
    assert_eq!(SCORE_THRESHOLD, 3.0);
}

#[test]
fn enrichment_publication_component_matches_module_name() {
    assert_eq!(BENCHMARK_PUBLICATION_COMPONENT, "benchmark_denominator");
    assert!(!BENCHMARK_PUBLICATION_COMPONENT.is_empty());
}

// ── NativeCoveragePoint enrichment ──────────────────────────────────

#[test]
fn enrichment_coverage_point_zero_slots() {
    let pt = NativeCoveragePoint {
        recorded_at_utc: "2026-01-01T00:00:00Z".to_string(),
        native_slots: 0,
        total_slots: 0,
    };
    let json = serde_json::to_string(&pt).unwrap();
    let recovered: NativeCoveragePoint = serde_json::from_str(&json).unwrap();
    assert_eq!(pt, recovered);
}

#[test]
fn enrichment_coverage_point_max_slots() {
    let pt = NativeCoveragePoint {
        recorded_at_utc: "2026-12-31T23:59:59Z".to_string(),
        native_slots: u64::MAX,
        total_slots: u64::MAX,
    };
    let json = serde_json::to_string(&pt).unwrap();
    let recovered: NativeCoveragePoint = serde_json::from_str(&json).unwrap();
    assert_eq!(pt.native_slots, recovered.native_slots);
    assert_eq!(pt.total_slots, recovered.total_slots);
}

// ── PublicationGateInput serde enrichment ────────────────────────────

#[test]
fn enrichment_gate_input_serde_many_cases() {
    let node_cases: Vec<BenchmarkCase> = (0..5)
        .map(|i| case(&format!("n{i}"), 4.0 + i as f64, None))
        .collect();
    let bun_cases: Vec<BenchmarkCase> = (0..3)
        .map(|i| case(&format!("b{i}"), 3.5 + i as f64, None))
        .collect();
    let input = PublicationGateInput {
        node_cases,
        bun_cases,
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let json = serde_json::to_string(&input).unwrap();
    let recovered: PublicationGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.node_cases.len(), 5);
    assert_eq!(recovered.bun_cases.len(), 3);
}

#[test]
fn enrichment_gate_input_clone_eq() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let cloned = input.clone();
    assert_eq!(input.node_cases.len(), cloned.node_cases.len());
    assert_eq!(input.replacement_lineage_ids, cloned.replacement_lineage_ids);
}

// ── BenchmarkPublicationEvent enrichment ────────────────────────────

#[test]
fn enrichment_event_clone_eq() {
    let evt = BenchmarkPublicationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let cloned = evt.clone();
    assert_eq!(evt, cloned);
}

#[test]
fn enrichment_event_json_field_names() {
    let evt = BenchmarkPublicationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: Some("code".to_string()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    for field in &["trace_id", "decision_id", "policy_id", "component", "event", "outcome", "error_code"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ── PublicationGateDecision enrichment ──────────────────────────────

#[test]
fn enrichment_decision_clone_eq() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    let cloned = d.clone();
    assert_eq!(d.publish_allowed, cloned.publish_allowed);
    assert_eq!(d.blockers, cloned.blockers);
    assert!((d.score_vs_node - cloned.score_vs_node).abs() < 1e-15);
}

#[test]
fn enrichment_decision_json_pretty_is_multiline() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 5.0, None)],
        bun_cases: vec![case("b", 5.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    let json_pretty = d.to_json_pretty().unwrap();
    assert!(json_pretty.contains('\n'), "pretty JSON should be multiline");
}

#[test]
fn enrichment_decision_blockers_empty_when_passing() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 10.0, None)],
        bun_cases: vec![case("b", 10.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(d.publish_allowed);
    assert!(d.blockers.is_empty());
}

#[test]
fn enrichment_decision_blockers_nonempty_when_denied() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 1.0, None)],
        bun_cases: vec![case("b", 1.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lin-1".to_string()],
    };
    let d = evaluate_publication_gate(&input, &context()).unwrap();
    assert!(!d.publish_allowed);
    assert!(!d.blockers.is_empty());
}
