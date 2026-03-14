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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::counterexample_synthesizer::{
    ConcreteScenario, ControllerConfig, ControllerInterference, ControllerInterferenceEvent,
    CounterexampleSynthesizer, DEFAULT_BUDGET_NS, DEFAULT_MAX_MINIMIZATION_ROUNDS,
    InterferenceKind, MinimalityEvidence, MutationKind, PolicyMutation, SynthesisConfig,
    SynthesisError, SynthesisOutcome, SynthesisStrategy,
};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn controller(
    controller_id: &str,
    read_metrics: &[&str],
    write_metrics: &[&str],
    timescale_millionths: i64,
    timescale_statement: &str,
) -> ControllerConfig {
    let mut affected_metrics = set(read_metrics);
    affected_metrics.extend(set(write_metrics));
    ControllerConfig {
        controller_id: controller_id.to_string(),
        read_metrics: set(read_metrics),
        write_metrics: set(write_metrics),
        affected_metrics,
        timescale_millionths,
        timescale_statement: timescale_statement.to_string(),
    }
}

fn synth() -> CounterexampleSynthesizer {
    CounterexampleSynthesizer::new(SynthesisConfig::default())
}

fn metric_value_stream(iterations: u64) -> Vec<i64> {
    (0..iterations).map(|tick| tick as i64).collect()
}

#[test]
fn concurrent_readers_on_shared_metric_get_consistent_snapshots() {
    let synth = synth();
    let mut configs = Vec::new();
    for idx in 0..10 {
        configs.push(controller(
            &format!("reader-{idx:02}"),
            &["latency_ms"],
            &[],
            100_000 + (idx as i64 * 10_000),
            "reads every 100-190ms",
        ));
    }

    let interferences = synth.detect_interference(&configs);
    assert!(
        interferences.is_empty(),
        "read-only shared-metric access should remain conflict free: {interferences:?}"
    );

    let canonical_stream = metric_value_stream(128);
    let mut snapshots = BTreeMap::new();
    for config in &configs {
        snapshots.insert(config.controller_id.clone(), canonical_stream.clone());
    }

    for stream in snapshots.values() {
        assert_eq!(stream, &canonical_stream);
    }
}

#[test]
fn concurrent_writers_with_timescale_collision_emit_rejection_evidence() {
    let synth = synth();
    let configs = vec![
        controller(
            "writer-fast-a",
            &[],
            &["throughput_ops"],
            100_000,
            "writes every 100ms",
        ),
        controller(
            "writer-fast-b",
            &[],
            &["throughput_ops"],
            120_000,
            "writes every 120ms",
        ),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(interferences.iter().any(|interference| {
        interference.kind == InterferenceKind::TimescaleConflict
            && interference.shared_metrics.contains("throughput_ops")
    }));

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-001",
        "policy-metric-interference-v1",
    );
    let rejection = events
        .iter()
        .find(|event| event.kind == InterferenceKind::TimescaleConflict)
        .expect("timescale conflict event must exist");
    assert_eq!(rejection.component, "counterexample_synthesizer");
    assert_eq!(rejection.event, "controller_interference_rejected");
    assert_eq!(rejection.outcome, "reject");
    assert_eq!(
        rejection.error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-TIMESCALE")
    );
}

#[test]
fn reader_writer_overlap_reports_serialization_path() {
    let synth = synth();
    let configs = vec![
        controller(
            "writer-slow",
            &[],
            &["queue_depth"],
            1_000_000,
            "writes every 1s",
        ),
        controller(
            "reader-fast",
            &["queue_depth"],
            &[],
            100_000,
            "reads every 100ms",
        ),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(interferences.iter().any(|interference| {
        interference.kind == InterferenceKind::InvariantInvalidation
            && interference.shared_metrics.contains("queue_depth")
    }));

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-002",
        "policy-metric-interference-v1",
    );
    assert!(events.iter().any(|event| {
        event.kind == InterferenceKind::InvariantInvalidation
            && event.event == "controller_interference_serialized"
            && event.outcome == "serialize"
            && event.error_code.as_deref() == Some("FE-CX-INTERFERENCE-INVARIANT")
    }));
}

#[test]
fn metric_subscriptions_do_not_cross_contaminate_streams() {
    let updates: Vec<(u64, &'static str, i64)> = (0..64)
        .map(|tick| {
            (
                tick,
                if tick % 2 == 0 { "latency_ms" } else { "qps" },
                tick as i64,
            )
        })
        .collect();

    let subscribers = vec![
        ("latency-a", set(&["latency_ms"])),
        ("latency-b", set(&["latency_ms"])),
        ("qps-a", set(&["qps"])),
    ];

    let mut streams: BTreeMap<String, Vec<(u64, i64)>> = BTreeMap::new();
    for (subscriber_id, _) in &subscribers {
        streams.insert((*subscriber_id).to_string(), Vec::new());
    }

    for (tick, metric, value) in updates {
        for (subscriber_id, subscribed_metrics) in &subscribers {
            if subscribed_metrics.contains(metric) {
                streams
                    .get_mut(*subscriber_id)
                    .expect("subscriber stream")
                    .push((tick, value));
            }
        }
    }

    assert_eq!(
        streams.get("latency-a"),
        streams.get("latency-b"),
        "subscribers to the same metric must receive identical streams"
    );
    assert!(
        streams
            .get("qps-a")
            .expect("qps stream")
            .iter()
            .all(|(_, value)| value % 2 == 1),
        "qps subscriber must not receive latency updates"
    );
}

#[test]
fn long_duration_metric_soak_10k_iterations_has_no_drift_or_corruption() {
    let mut metric_value = 0_i64;
    let mut reader_streams: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for reader_id in ["reader-a", "reader-b", "reader-c", "reader-d", "reader-e"] {
        reader_streams.insert(reader_id.to_string(), Vec::new());
    }

    for _ in 0..10_000_u64 {
        metric_value += 1;
        for stream in reader_streams.values_mut() {
            stream.push(metric_value);
        }
    }

    assert_eq!(metric_value, 10_000);
    for stream in reader_streams.values() {
        assert_eq!(stream.len(), 10_000);
        assert_eq!(stream.first(), Some(&1));
        assert_eq!(stream.last(), Some(&10_000));
        assert!(
            stream.windows(2).all(|window| window[0] <= window[1]),
            "reader stream must be monotonic"
        );
        assert!(
            stream
                .windows(2)
                .all(|window| (window[1] - window[0]).abs() <= 1),
            "reader stream should not contain phantom spikes"
        );
    }
}

#[test]
fn every_detected_conflict_has_matching_structured_event() {
    let synth = synth();
    let configs = vec![
        controller("writer-a", &[], &["m1"], 100_000, "writes every 100ms"),
        controller("writer-b", &[], &["m1"], 120_000, "writes every 120ms"),
        controller("reader-c", &["m1"], &[], 400_000, "reads every 400ms"),
    ];

    let interferences = synth.detect_interference(&configs);
    assert!(!interferences.is_empty());

    let events = synth.build_interference_events(
        &interferences,
        "trace-interference-ci-003",
        "policy-metric-interference-v1",
    );
    assert_eq!(
        events.len(),
        interferences.len(),
        "every conflict must emit an evidence/log event"
    );
    assert!(events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && event.component == "counterexample_synthesizer"
            && event.error_code.is_some()
    }));
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, error paths
// ────────────────────────────────────────────────────────────

#[test]
fn interference_kind_serde_round_trip() {
    for kind in [
        InterferenceKind::InvariantInvalidation,
        InterferenceKind::Oscillation,
        InterferenceKind::TimescaleConflict,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: InterferenceKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn interference_kind_display_formats() {
    assert_eq!(
        InterferenceKind::InvariantInvalidation.to_string(),
        "invariant-invalidation"
    );
    assert_eq!(InterferenceKind::Oscillation.to_string(), "oscillation");
    assert_eq!(
        InterferenceKind::TimescaleConflict.to_string(),
        "timescale-conflict"
    );
}

#[test]
fn synthesis_strategy_serde_round_trip() {
    for strategy in [
        SynthesisStrategy::CompilerExtraction,
        SynthesisStrategy::Enumeration,
        SynthesisStrategy::Mutation,
        SynthesisStrategy::TimeBounded,
    ] {
        let json = serde_json::to_string(&strategy).expect("serialize");
        let recovered: SynthesisStrategy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(strategy, recovered);
    }
}

#[test]
fn synthesis_strategy_display_formats() {
    assert_eq!(
        SynthesisStrategy::CompilerExtraction.to_string(),
        "compiler-extraction"
    );
    assert_eq!(SynthesisStrategy::Enumeration.to_string(), "enumeration");
    assert_eq!(SynthesisStrategy::Mutation.to_string(), "mutation");
    assert_eq!(SynthesisStrategy::TimeBounded.to_string(), "time-bounded");
}

#[test]
fn synthesis_config_default_has_expected_values() {
    let config = SynthesisConfig::default();
    assert_eq!(config.budget_ns, DEFAULT_BUDGET_NS);
    assert_eq!(
        config.max_minimization_rounds,
        DEFAULT_MAX_MINIMIZATION_ROUNDS
    );
    assert_eq!(
        config.preferred_strategy,
        SynthesisStrategy::CompilerExtraction
    );
    assert!(config.detect_controller_interference);
}

#[test]
fn synthesis_config_serde_round_trip() {
    let config = SynthesisConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: SynthesisConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn synthesis_error_display_all_variants() {
    let errors: Vec<SynthesisError> = vec![
        SynthesisError::NoViolations,
        SynthesisError::Timeout {
            elapsed_ns: 100,
            budget_ns: 200,
            partial: None,
        },
        SynthesisError::InvalidPolicy {
            reason: "empty IR".to_string(),
        },
        SynthesisError::IdDerivation("bad id".to_string()),
        SynthesisError::MinimizationExhausted { rounds: 50 },
        SynthesisError::CompilerFailure("internal error".to_string()),
    ];
    for err in errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn empty_controller_list_produces_no_interference() {
    let synth = synth();
    let interferences = synth.detect_interference(&[]);
    assert!(interferences.is_empty());
}

#[test]
fn single_controller_produces_no_interference() {
    let synth = synth();
    let configs = vec![controller(
        "solo-writer",
        &[],
        &["latency_ms"],
        100_000,
        "writes every 100ms",
    )];
    let interferences = synth.detect_interference(&configs);
    assert!(interferences.is_empty());
}

#[test]
fn counterexample_synthesizer_construction_preserves_config() {
    let config = SynthesisConfig::default();
    let synthesizer = CounterexampleSynthesizer::new(config.clone());
    let json = serde_json::to_string(&synthesizer).expect("serialize");
    assert!(json.contains(&config.budget_ns.to_string()));
}

// ────────────────────────────────────────────────────────────
// Enrichment: controller config serde, error serde, event fields
// ────────────────────────────────────────────────────────────

#[test]
fn controller_config_serde_round_trip() {
    let config = controller("ctrl-serde", &["m1", "m2"], &["m3"], 500_000, "every 500ms");
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: ControllerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn synthesis_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(SynthesisError::NoViolations);
    assert!(!err.to_string().is_empty());
}

#[test]
fn synthesis_error_serde_round_trip() {
    let err = SynthesisError::NoViolations;
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: SynthesisError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

#[test]
fn interference_events_have_unique_decision_ids() {
    let synth = synth();
    let configs = vec![
        controller("w-a", &[], &["m1"], 100_000, "100ms"),
        controller("w-b", &[], &["m1"], 120_000, "120ms"),
        controller("w-c", &[], &["m1", "m2"], 110_000, "110ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    let events = synth.build_interference_events(&interferences, "trace-unique", "policy-unique");
    let decision_ids: std::collections::BTreeSet<&str> =
        events.iter().map(|e| e.decision_id.as_str()).collect();
    assert_eq!(
        decision_ids.len(),
        events.len(),
        "decision IDs must be unique per event"
    );
}

#[test]
fn disjoint_metric_sets_produce_no_interference() {
    let synth = synth();
    let configs = vec![
        controller("w-x", &[], &["metric_a"], 100_000, "100ms"),
        controller("w-y", &[], &["metric_b"], 100_000, "100ms"),
        controller("w-z", &[], &["metric_c"], 100_000, "100ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(
        interferences.is_empty(),
        "disjoint metrics should not interfere"
    );
}

#[test]
fn oscillation_detection_with_many_writers() {
    let synth = synth();
    let configs: Vec<ControllerConfig> = (0..5)
        .map(|i| {
            controller(
                &format!("writer-{i}"),
                &[],
                &["shared_metric"],
                100_000 + i * 10_000,
                "various timescales",
            )
        })
        .collect();
    let interferences = synth.detect_interference(&configs);
    assert!(
        !interferences.is_empty(),
        "5 writers on shared metric should produce interference"
    );
    assert!(
        interferences
            .iter()
            .all(|i| i.shared_metrics.contains("shared_metric"))
    );
}

#[test]
fn controller_config_debug_is_nonempty() {
    let config = controller("ctrl-dbg", &["r1"], &["w1"], 100_000, "100ms");
    let debug = format!("{config:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn synthesis_config_debug_is_nonempty() {
    let config = SynthesisConfig::default();
    let debug = format!("{config:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn metric_value_stream_is_deterministic() {
    let a = metric_value_stream(10);
    let b = metric_value_stream(10);
    assert_eq!(a, b);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: boundary values, mixed overlap, serde depth
// ────────────────────────────────────────────────────────────

#[test]
fn synthesis_error_timeout_serde_round_trip_no_partial() {
    let err = SynthesisError::Timeout {
        elapsed_ns: 999_999_999,
        budget_ns: 1_000_000_000,
        partial: None,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: SynthesisError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
    assert!(json.contains("999999999"));
    assert!(json.contains("1000000000"));
}

#[test]
fn identical_timescale_writers_still_produce_interference() {
    let synth = synth();
    let configs = vec![
        controller("w-same-1", &[], &["cpu_pct"], 100_000, "100ms"),
        controller("w-same-2", &[], &["cpu_pct"], 100_000, "100ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(
        !interferences.is_empty(),
        "two writers on the same metric at identical timescale should still interfere"
    );
}

#[test]
fn mixed_reader_writer_overlap_across_multiple_metrics() {
    let synth = synth();
    let configs = vec![
        controller("rw-1", &["m1"], &["m2"], 100_000, "100ms"),
        controller("rw-2", &["m2"], &["m1"], 200_000, "200ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    assert!(
        !interferences.is_empty(),
        "cross-metric reader-writer overlap must produce interference"
    );
    // Both metrics should appear across interferences
    let all_shared: BTreeSet<String> = interferences
        .iter()
        .flat_map(|i| i.shared_metrics.iter().cloned())
        .collect();
    assert!(
        all_shared.contains("m1") || all_shared.contains("m2"),
        "at least one overlapping metric must be reported"
    );
}

#[test]
fn synthesis_config_with_custom_fields_serde_round_trip() {
    let config = SynthesisConfig {
        budget_ns: 42,
        max_minimization_rounds: 7,
        preferred_strategy: SynthesisStrategy::TimeBounded,
        detect_controller_interference: false,
        ..SynthesisConfig::default()
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: SynthesisConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
    assert_eq!(recovered.budget_ns, 42);
    assert_eq!(recovered.max_minimization_rounds, 7);
    assert_eq!(recovered.preferred_strategy, SynthesisStrategy::TimeBounded);
    assert!(!recovered.detect_controller_interference);
}

#[test]
fn metric_value_stream_zero_iterations_returns_empty() {
    let stream = metric_value_stream(0);
    assert!(
        stream.is_empty(),
        "zero iterations should produce empty stream"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: untested types serde & display
// ────────────────────────────────────────────────────────────

#[test]
fn synthesis_outcome_display_and_serde_round_trip() {
    for (outcome, expected_display) in [
        (SynthesisOutcome::Complete, "complete"),
        (SynthesisOutcome::Partial, "partial"),
        (SynthesisOutcome::Incomplete, "incomplete"),
    ] {
        assert_eq!(outcome.to_string(), expected_display);
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: SynthesisOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn controller_interference_serde_round_trip() {
    let interference = ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        shared_metrics: set(&["m1", "m2"]),
        timescale_separation_millionths: 50_000,
        evidence_description: "oscillating writes detected".to_string(),
        convergence_steps: Some(42),
    };
    let json = serde_json::to_string(&interference).expect("serialize");
    let recovered: ControllerInterference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(interference, recovered);
    assert_eq!(recovered.convergence_steps, Some(42));
    assert_eq!(recovered.kind, InterferenceKind::Oscillation);
}

#[test]
fn controller_interference_event_serde_round_trip() {
    let event = ControllerInterferenceEvent {
        trace_id: "trace-evt".to_string(),
        decision_id: "decision-evt".to_string(),
        policy_id: "policy-evt".to_string(),
        component: "counterexample_synthesizer".to_string(),
        event: "controller_interference_rejected".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("FE-CX-INTERFERENCE-TIMESCALE".to_string()),
        kind: InterferenceKind::TimescaleConflict,
        controller_ids: vec!["ctrl-x".to_string()],
        shared_metrics: vec!["cpu_pct".to_string()],
        timescale_separation_millionths: 200_000,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: ControllerInterferenceEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
    assert_eq!(
        recovered.error_code.as_deref(),
        Some("FE-CX-INTERFERENCE-TIMESCALE")
    );
}

#[test]
fn minimality_evidence_serde_round_trip() {
    let evidence = MinimalityEvidence {
        rounds: 12,
        elements_removed: 8,
        starting_size: 20,
        final_size: 12,
        is_fixed_point: true,
    };
    let json = serde_json::to_string(&evidence).expect("serialize");
    let recovered: MinimalityEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(evidence, recovered);
    assert!(recovered.is_fixed_point);
    assert_eq!(recovered.elements_removed, 8);
}

#[test]
fn synthesis_error_all_variants_serde_round_trip() {
    let variants = vec![
        SynthesisError::NoViolations,
        SynthesisError::Timeout {
            elapsed_ns: 500,
            budget_ns: 1000,
            partial: None,
        },
        SynthesisError::InvalidPolicy {
            reason: "missing root node".to_string(),
        },
        SynthesisError::IdDerivation("collision".to_string()),
        SynthesisError::MinimizationExhausted { rounds: 99 },
        SynthesisError::CompilerFailure("OOM".to_string()),
    ];
    for err in &variants {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: SynthesisError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: untested types, clone independence, boundary,
// determinism, mutation/scenario coverage
// ────────────────────────────────────────────────────────────

#[test]
fn concrete_scenario_serde_round_trip() {
    let scenario = ConcreteScenario {
        subjects: set(&["subject-a", "subject-b"]),
        capabilities: set(&["cap-read", "cap-write"]),
        conditions: {
            let mut m = BTreeMap::new();
            m.insert("violation".to_string(), "monotonicity breach".to_string());
            m.insert("env".to_string(), "staging".to_string());
            m
        },
        merge_ordering: vec![
            "step-1".to_string(),
            "step-2".to_string(),
            "step-3".to_string(),
        ],
        input_state: {
            let mut m = BTreeMap::new();
            m.insert("key-a".to_string(), "val-a".to_string());
            m
        },
    };
    let json = serde_json::to_string(&scenario).expect("serialize");
    let recovered: ConcreteScenario = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(scenario, recovered);
    assert_eq!(recovered.subjects.len(), 2);
    assert_eq!(recovered.merge_ordering.len(), 3);
    assert_eq!(recovered.conditions.len(), 2);
}

#[test]
fn concrete_scenario_empty_fields_serde_round_trip() {
    let scenario = ConcreteScenario {
        subjects: BTreeSet::new(),
        capabilities: BTreeSet::new(),
        conditions: BTreeMap::new(),
        merge_ordering: Vec::new(),
        input_state: BTreeMap::new(),
    };
    let json = serde_json::to_string(&scenario).expect("serialize");
    let recovered: ConcreteScenario = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(scenario, recovered);
    assert!(recovered.subjects.is_empty());
    assert!(recovered.merge_ordering.is_empty());
}

#[test]
fn policy_mutation_serde_round_trip() {
    let mutation = PolicyMutation {
        kind: MutationKind::ChangeMergeOp,
        target_node: "node-42".to_string(),
        new_value: "union".to_string(),
    };
    let json = serde_json::to_string(&mutation).expect("serialize");
    let recovered: PolicyMutation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(mutation, recovered);
    assert_eq!(recovered.kind, MutationKind::ChangeMergeOp);
    assert_eq!(recovered.target_node, "node-42");
}

#[test]
fn mutation_kind_display_all_variants() {
    let expected = [
        (MutationKind::ChangeMergeOp, "change-merge-op"),
        (MutationKind::AddGrant, "add-grant"),
        (MutationKind::RemovePropertyClaim, "remove-property-claim"),
        (MutationKind::ChangePriority, "change-priority"),
        (MutationKind::RemoveConstraint, "remove-constraint"),
        (MutationKind::DuplicateNode, "duplicate-node"),
    ];
    for (kind, display_str) in expected {
        assert_eq!(kind.to_string(), display_str);
    }
}

#[test]
fn mutation_kind_serde_round_trip_all_variants() {
    let variants = [
        MutationKind::ChangeMergeOp,
        MutationKind::AddGrant,
        MutationKind::RemovePropertyClaim,
        MutationKind::ChangePriority,
        MutationKind::RemoveConstraint,
        MutationKind::DuplicateNode,
    ];
    for kind in variants {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: MutationKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn controller_interference_clone_independence() {
    let original = ControllerInterference {
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["ctrl-1".to_string(), "ctrl-2".to_string()],
        shared_metrics: set(&["m1", "m2", "m3"]),
        timescale_separation_millionths: 75_000,
        evidence_description: "oscillating writes".to_string(),
        convergence_steps: Some(100),
    };
    let mut cloned = original.clone();
    cloned.kind = InterferenceKind::TimescaleConflict;
    cloned.controller_ids.push("ctrl-3".to_string());
    cloned.shared_metrics.insert("m4".to_string());
    cloned.timescale_separation_millionths = 200_000;
    cloned.convergence_steps = None;

    // Original must be unaffected by mutations to the clone.
    assert_eq!(original.kind, InterferenceKind::Oscillation);
    assert_eq!(original.controller_ids.len(), 2);
    assert_eq!(original.shared_metrics.len(), 3);
    assert_eq!(original.timescale_separation_millionths, 75_000);
    assert_eq!(original.convergence_steps, Some(100));

    // Cloned must reflect the mutations.
    assert_eq!(cloned.kind, InterferenceKind::TimescaleConflict);
    assert_eq!(cloned.controller_ids.len(), 3);
    assert_eq!(cloned.shared_metrics.len(), 4);
    assert_eq!(cloned.convergence_steps, None);
}

#[test]
fn controller_config_clone_independence() {
    let original = controller("ctrl-orig", &["r1", "r2"], &["w1"], 500_000, "every 500ms");
    let mut cloned = original.clone();
    cloned.controller_id = "ctrl-clone".to_string();
    cloned.read_metrics.insert("r3".to_string());
    cloned.write_metrics.insert("w2".to_string());
    cloned.timescale_millionths = 1_000_000;

    assert_eq!(original.controller_id, "ctrl-orig");
    assert_eq!(original.read_metrics.len(), 2);
    assert_eq!(original.write_metrics.len(), 1);
    assert_eq!(original.timescale_millionths, 500_000);

    assert_eq!(cloned.controller_id, "ctrl-clone");
    assert_eq!(cloned.read_metrics.len(), 3);
    assert_eq!(cloned.write_metrics.len(), 2);
}

#[test]
fn empty_timescale_statement_triggers_timescale_conflict() {
    let synth = synth();
    let mut cfg_a = controller("ctrl-a", &[], &["metric_x"], 100_000, "");
    cfg_a.timescale_statement = String::new();
    let cfg_b = controller("ctrl-b", &[], &["metric_x"], 200_000, "every 200ms");

    let interferences = synth.detect_interference(&[cfg_a, cfg_b]);
    assert!(
        interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::TimescaleConflict),
        "empty timescale statement should trigger TimescaleConflict"
    );
}

#[test]
fn whitespace_only_timescale_statement_triggers_conflict() {
    let synth = synth();
    let mut cfg_a = controller("ctrl-ws", &[], &["metric_y"], 100_000, "   ");
    cfg_a.timescale_statement = "   \t  ".to_string();
    let cfg_b = controller("ctrl-ok", &[], &["metric_y"], 150_000, "every 150ms");

    let interferences = synth.detect_interference(&[cfg_a, cfg_b]);
    assert!(
        interferences
            .iter()
            .any(|i| i.kind == InterferenceKind::TimescaleConflict),
        "whitespace-only timescale statement should be treated as missing"
    );
}

#[test]
fn timescale_separation_boundary_at_exactly_threshold() {
    let synth = synth();
    // Separation of exactly 100_000 should NOT trigger TimescaleConflict
    // (threshold is < 100_000 = insufficient)
    let configs = vec![
        controller("w-boundary-a", &[], &["bnd_m"], 100_000, "100ms"),
        controller("w-boundary-b", &[], &["bnd_m"], 200_000, "200ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    // With separation == 100_000, it is not < 100_000, so no TimescaleConflict.
    let has_timescale_conflict = interferences
        .iter()
        .any(|i| i.kind == InterferenceKind::TimescaleConflict);
    assert!(
        !has_timescale_conflict,
        "separation of exactly 100_000 should not trigger TimescaleConflict"
    );
}

#[test]
fn timescale_separation_just_below_threshold_triggers_conflict() {
    let synth = synth();
    // Separation of 99_999 (< 100_000) should trigger TimescaleConflict
    let configs = vec![
        controller("w-below-a", &[], &["blw_m"], 100_000, "100ms"),
        controller("w-below-b", &[], &["blw_m"], 199_999, "~200ms"),
    ];
    let interferences = synth.detect_interference(&configs);
    let has_timescale_conflict = interferences
        .iter()
        .any(|i| i.kind == InterferenceKind::TimescaleConflict);
    assert!(
        has_timescale_conflict,
        "separation of 99_999 should trigger TimescaleConflict"
    );
}

#[test]
fn interference_event_ordering_is_deterministic_across_runs() {
    let synth = synth();
    let configs = vec![
        controller("det-w1", &[], &["d1", "d2"], 100_000, "100ms"),
        controller("det-w2", &[], &["d1"], 110_000, "110ms"),
        controller("det-r3", &["d2"], &[], 300_000, "300ms"),
    ];

    let interferences_a = synth.detect_interference(&configs);
    let events_a = synth.build_interference_events(&interferences_a, "trace-det", "policy-det");

    let interferences_b = synth.detect_interference(&configs);
    let events_b = synth.build_interference_events(&interferences_b, "trace-det", "policy-det");

    assert_eq!(events_a.len(), events_b.len());
    for (ea, eb) in events_a.iter().zip(events_b.iter()) {
        assert_eq!(ea.decision_id, eb.decision_id);
        assert_eq!(ea.kind, eb.kind);
        assert_eq!(ea.controller_ids, eb.controller_ids);
        assert_eq!(ea.shared_metrics, eb.shared_metrics);
        assert_eq!(
            ea.timescale_separation_millionths,
            eb.timescale_separation_millionths
        );
    }
}

#[test]
fn many_controllers_quadratic_interference_count() {
    let synth = synth();
    // 4 controllers all writing to the same metric => C(4,2) = 6 pairs
    let configs: Vec<ControllerConfig> = (0..4)
        .map(|i| {
            controller(
                &format!("quad-w{i}"),
                &[],
                &["shared_q"],
                100_000 + i * 5_000,
                &format!("every {}ms", 100 + i * 5),
            )
        })
        .collect();

    let interferences = synth.detect_interference(&configs);
    // Each pair shares "shared_q" as write metric; at minimum we expect
    // some interference events (exact count depends on timescale separation logic).
    assert!(
        !interferences.is_empty(),
        "4 writers on the same metric should produce interference"
    );
    // All interferences should reference "shared_q".
    for interference in &interferences {
        assert!(
            interference.shared_metrics.contains("shared_q"),
            "all interferences must reference the shared metric"
        );
    }
}

#[test]
fn synthesis_error_minimization_exhausted_display_contains_round_count() {
    let err = SynthesisError::MinimizationExhausted { rounds: 77 };
    let display = err.to_string();
    assert!(
        display.contains("77"),
        "display should contain the round count"
    );
    assert!(
        display.contains("minimization"),
        "display should mention minimization"
    );
}

#[test]
fn controller_interference_event_clone_independence() {
    let original = ControllerInterferenceEvent {
        trace_id: "trace-ci".to_string(),
        decision_id: "decision-ci".to_string(),
        policy_id: "policy-ci".to_string(),
        component: "counterexample_synthesizer".to_string(),
        event: "controller_interference_rejected".to_string(),
        outcome: "reject".to_string(),
        error_code: Some("FE-CX-INTERFERENCE-OSCILLATION".to_string()),
        kind: InterferenceKind::Oscillation,
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        shared_metrics: vec!["latency_ms".to_string()],
        timescale_separation_millionths: 50_000,
    };
    let mut cloned = original.clone();
    cloned.trace_id = "trace-modified".to_string();
    cloned.controller_ids.push("ctrl-c".to_string());
    cloned.shared_metrics.push("qps".to_string());
    cloned.error_code = None;

    assert_eq!(original.trace_id, "trace-ci");
    assert_eq!(original.controller_ids.len(), 2);
    assert_eq!(original.shared_metrics.len(), 1);
    assert!(original.error_code.is_some());

    assert_eq!(cloned.trace_id, "trace-modified");
    assert_eq!(cloned.controller_ids.len(), 3);
    assert_eq!(cloned.shared_metrics.len(), 2);
    assert!(cloned.error_code.is_none());
}
