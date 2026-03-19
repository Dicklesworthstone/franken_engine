#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `phase_gate` module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::phase_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_eval() -> GateEvaluator {
    GateEvaluator::new(epoch(1), GateThresholds::default())
}

fn pass_all_gates(eval: &mut GateEvaluator) {
    eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"ok"),
            replayed_hash: ContentHash::compute(b"ok"),
            event_count: 100,
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 100,
            unresolved_failures: 0,
            regression_transcripts: 5,
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 600,
            passed_vectors: 600,
            failed_vectors: 0,
            categories: vec!["a".into()],
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 48,
            crashes: 0,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec!["t1".into()],
        },
        "ci",
        "t",
        0,
    );
}

// ===========================================================================
// GateId enrichment
// ===========================================================================

#[test]
fn gate_id_clone_copy_eq() {
    let a = GateId::DeterministicReplay;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn gate_id_all_variants_distinct_display() {
    let variants = [
        GateId::DeterministicReplay,
        GateId::InterleavingSuite,
        GateId::ConformanceVectors,
        GateId::FuzzAdversarial,
    ];
    let displays: std::collections::BTreeSet<String> =
        variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn gate_id_debug_contains_variant_name() {
    let dbg = format!("{:?}", GateId::FuzzAdversarial);
    assert!(dbg.contains("FuzzAdversarial"));
}

#[test]
fn gate_id_hash_distinct() {
    use std::collections::BTreeSet;
    let mut s = BTreeSet::new();
    s.insert(GateId::DeterministicReplay);
    s.insert(GateId::InterleavingSuite);
    s.insert(GateId::ConformanceVectors);
    s.insert(GateId::FuzzAdversarial);
    assert_eq!(s.len(), 4);
}

// ===========================================================================
// GateStatus enrichment
// ===========================================================================

#[test]
fn gate_status_failed_display_joins_reasons() {
    let status = GateStatus::Failed {
        reasons: vec!["reason1".into(), "reason2".into()],
    };
    let display = status.to_string();
    assert!(display.contains("reason1"));
    assert!(display.contains("reason2"));
    assert!(display.contains("; "));
}

#[test]
fn gate_status_failed_empty_reasons() {
    let status = GateStatus::Failed {
        reasons: vec![],
    };
    assert!(!status.is_passed());
    assert!(status.is_terminal());
    let display = status.to_string();
    assert!(display.contains("failed"));
}

#[test]
fn gate_status_skipped_display_includes_reason() {
    let status = GateStatus::Skipped {
        reason: "not applicable".into(),
    };
    let display = status.to_string();
    assert!(display.contains("not applicable"));
}

#[test]
fn gate_status_clone_eq() {
    let a = GateStatus::Passed;
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// GateMetrics enrichment
// ===========================================================================

#[test]
fn gate_metrics_overwrite_key() {
    let m = GateMetrics::empty().with("k", "v1").with("k", "v2");
    assert_eq!(m.get("k"), Some("v2"));
    assert_eq!(m.values.len(), 1);
}

#[test]
fn gate_metrics_many_keys() {
    let mut m = GateMetrics::empty();
    for i in 0..50 {
        m = m.with(&format!("key_{i}"), &format!("val_{i}"));
    }
    assert_eq!(m.values.len(), 50);
    assert_eq!(m.get("key_0"), Some("val_0"));
    assert_eq!(m.get("key_49"), Some("val_49"));
}

// ===========================================================================
// GateReport enrichment
// ===========================================================================

#[test]
fn gate_report_has_all_fields_populated() {
    let mut eval = default_eval();
    let report = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"data"),
            replayed_hash: ContentHash::compute(b"data"),
            event_count: 256,
        },
        "ci-run-42",
        "trace-xyz",
        9999,
    );
    assert_eq!(report.gate_id, GateId::DeterministicReplay);
    assert!(report.status.is_passed());
    assert_eq!(report.ci_run_id, "ci-run-42");
    assert_eq!(report.trace_id, "trace-xyz");
    assert_eq!(report.timestamp_ticks, 9999);
    assert_eq!(report.epoch_id, 1);
    assert_eq!(report.metrics.get("event_count"), Some("256"));
}

#[test]
fn gate_report_hash_differs_for_different_inputs() {
    let mut eval = default_eval();
    let r1 = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"a"),
            replayed_hash: ContentHash::compute(b"a"),
            event_count: 1,
        },
        "ci-1",
        "t1",
        100,
    );
    let r2 = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"b"),
            replayed_hash: ContentHash::compute(b"b"),
            event_count: 2,
        },
        "ci-2",
        "t2",
        200,
    );
    assert_ne!(r1.report_hash, r2.report_hash);
}

// ===========================================================================
// GateThresholds enrichment
// ===========================================================================

#[test]
fn gate_thresholds_custom_values() {
    let t = GateThresholds {
        interleaving_coverage_pct: 80,
        min_conformance_vectors: 100,
        min_fuzz_cpu_hours: 8,
    };
    assert_eq!(t.interleaving_coverage_pct, 80);
    assert_eq!(t.min_conformance_vectors, 100);
    assert_eq!(t.min_fuzz_cpu_hours, 8);
}

#[test]
fn gate_thresholds_custom_affects_evaluator() {
    let thresholds = GateThresholds {
        interleaving_coverage_pct: 50,
        min_conformance_vectors: 10,
        min_fuzz_cpu_hours: 1,
    };
    let mut eval = GateEvaluator::new(epoch(1), thresholds);
    let report = eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 51,
            unresolved_failures: 0,
            regression_transcripts: 0,
        },
        "ci",
        "t",
        0,
    );
    assert!(report.status.is_passed());
}

// ===========================================================================
// GateEvaluator — replay gate enrichment
// ===========================================================================

#[test]
fn replay_gate_match_metric_true_on_pass() {
    let mut eval = default_eval();
    let report = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"same"),
            replayed_hash: ContentHash::compute(b"same"),
            event_count: 10,
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.metrics.get("match"), Some("true"));
}

#[test]
fn replay_gate_match_metric_false_on_fail() {
    let mut eval = default_eval();
    let report = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"aaa"),
            replayed_hash: ContentHash::compute(b"bbb"),
            event_count: 10,
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.metrics.get("match"), Some("false"));
}

// ===========================================================================
// GateEvaluator — interleaving gate enrichment
// ===========================================================================

#[test]
fn interleaving_gate_reports_correct_metrics() {
    let mut eval = default_eval();
    let report = eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 200,
            explored_surfaces: 190,
            unresolved_failures: 0,
            regression_transcripts: 10,
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.metrics.get("total_surfaces"), Some("200"));
    assert_eq!(report.metrics.get("explored_surfaces"), Some("190"));
    assert_eq!(report.metrics.get("coverage_pct"), Some("95"));
    assert_eq!(report.metrics.get("regression_transcripts"), Some("10"));
}

#[test]
fn interleaving_both_coverage_and_failures_reported() {
    let mut eval = default_eval();
    let report = eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 80,
            unresolved_failures: 3,
            regression_transcripts: 0,
        },
        "ci",
        "t",
        0,
    );
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.len() >= 2);
    } else {
        panic!("expected failed");
    }
}

// ===========================================================================
// GateEvaluator — conformance gate enrichment
// ===========================================================================

#[test]
fn conformance_gate_metrics_populated() {
    let mut eval = default_eval();
    let report = eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 700,
            passed_vectors: 695,
            failed_vectors: 5,
            categories: vec!["cat1".into(), "cat2".into(), "cat3".into()],
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.metrics.get("total_vectors"), Some("700"));
    assert_eq!(report.metrics.get("passed_vectors"), Some("695"));
    assert_eq!(report.metrics.get("failed_vectors"), Some("5"));
    assert_eq!(report.metrics.get("categories"), Some("3"));
}

#[test]
fn conformance_both_too_few_and_failures() {
    let mut eval = default_eval();
    let report = eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 100,
            passed_vectors: 90,
            failed_vectors: 10,
            categories: vec![],
        },
        "ci",
        "t",
        0,
    );
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.len() >= 2);
    } else {
        panic!("expected failed");
    }
}

// ===========================================================================
// GateEvaluator — fuzz gate enrichment
// ===========================================================================

#[test]
fn fuzz_gate_metrics_populated() {
    let mut eval = default_eval();
    let report = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 72,
            crashes: 1,
            unexpected_panics: 2,
            bypasses: 3,
            targets: vec!["t1".into(), "t2".into()],
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.metrics.get("cpu_hours"), Some("72"));
    assert_eq!(report.metrics.get("crashes"), Some("1"));
    assert_eq!(report.metrics.get("unexpected_panics"), Some("2"));
    assert_eq!(report.metrics.get("bypasses"), Some("3"));
    assert_eq!(report.metrics.get("targets"), Some("2"));
}

#[test]
fn fuzz_gate_all_failure_reasons() {
    let mut eval = default_eval();
    let report = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 10,
            crashes: 1,
            unexpected_panics: 1,
            bypasses: 1,
            targets: vec![],
        },
        "ci",
        "t",
        0,
    );
    if let GateStatus::Failed { reasons } = &report.status {
        assert_eq!(reasons.len(), 4);
    } else {
        panic!("expected failed");
    }
}

// ===========================================================================
// GateEvaluator — all_gates_passed enrichment
// ===========================================================================

#[test]
fn all_gates_passed_after_full_pass() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    assert!(eval.all_gates_passed());
}

#[test]
fn all_gates_passed_false_with_one_missing() {
    let mut eval = default_eval();
    eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"x"),
            replayed_hash: ContentHash::compute(b"x"),
            event_count: 1,
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 100,
            unresolved_failures: 0,
            regression_transcripts: 0,
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 600,
            passed_vectors: 600,
            failed_vectors: 0,
            categories: vec![],
        },
        "ci",
        "t",
        0,
    );
    // Fuzz gate missing
    assert!(!eval.all_gates_passed());
}

// ===========================================================================
// GateEvaluator — summary/report/events enrichment
// ===========================================================================

#[test]
fn summary_reflects_all_evaluated() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    let summary = eval.summary();
    assert_eq!(summary.len(), 4);
    for (_, status) in &summary {
        assert!(status.is_passed());
    }
}

#[test]
fn export_reports_count_matches_evaluations() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    assert_eq!(eval.export_reports().len(), 4);
}

#[test]
fn events_accumulate_across_evaluations() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    let events = eval.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(eval.event_counts().get("gate_evaluated"), Some(&4));
    assert_eq!(eval.event_counts().get("gate_passed"), Some(&4));
}

#[test]
fn event_counts_separate_pass_and_fail() {
    let mut eval = default_eval();
    eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"a"),
            replayed_hash: ContentHash::compute(b"b"),
            event_count: 1,
        },
        "ci",
        "t",
        0,
    );
    eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 48,
            crashes: 0,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(eval.event_counts().get("gate_evaluated"), Some(&2));
    assert_eq!(eval.event_counts().get("gate_passed"), Some(&1));
}

// ===========================================================================
// GateEvaluator — epoch propagation
// ===========================================================================

#[test]
fn report_inherits_evaluator_epoch() {
    let eval_epoch = epoch(42);
    let mut eval = GateEvaluator::new(eval_epoch, GateThresholds::default());
    let report = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"x"),
            replayed_hash: ContentHash::compute(b"x"),
            event_count: 1,
        },
        "ci",
        "t",
        0,
    );
    assert_eq!(report.epoch_id, 42);
}

// ===========================================================================
// GateEvent enrichment
// ===========================================================================

#[test]
fn gate_event_fields_from_evaluation() {
    let mut eval = default_eval();
    eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 600,
            passed_vectors: 600,
            failed_vectors: 0,
            categories: vec![],
        },
        "ci",
        "t",
        0,
    );
    let events = eval.drain_events();
    assert_eq!(events[0].gate_id, "conformance_vectors");
    assert_eq!(events[0].status, "passed");
    assert_eq!(events[0].event, "gate_evaluated");
    assert_eq!(events[0].epoch_id, 1);
}

// ===========================================================================
// Serde enrichment
// ===========================================================================

#[test]
fn full_evaluator_reports_serde_roundtrip() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    for report in eval.export_reports() {
        let json = serde_json::to_string(report).expect("serialize");
        let restored: GateReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*report, restored);
    }
}

#[test]
fn gate_event_vec_serde_roundtrip() {
    let mut eval = default_eval();
    pass_all_gates(&mut eval);
    let events = eval.drain_events();
    let json = serde_json::to_string(&events).expect("serialize");
    let restored: Vec<GateEvent> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(events, restored);
}

#[test]
fn replay_input_with_zero_events_serde() {
    let ri = ReplayInput {
        recorded_hash: ContentHash::compute(b""),
        replayed_hash: ContentHash::compute(b""),
        event_count: 0,
    };
    let json = serde_json::to_string(&ri).expect("serialize");
    let restored: ReplayInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ri, restored);
}

#[test]
fn fuzz_input_no_targets_serde() {
    let fi = FuzzInput {
        cpu_hours: 0,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![],
    };
    let json = serde_json::to_string(&fi).expect("serialize");
    let restored: FuzzInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fi, restored);
}

// ===========================================================================
// Determinism enrichment
// ===========================================================================

#[test]
fn deterministic_across_multiple_evaluators() {
    let run = || {
        let mut eval = default_eval();
        pass_all_gates(&mut eval);
        eval.export_reports()
            .iter()
            .map(|r| r.report_hash)
            .collect::<Vec<_>>()
    };
    let hashes1 = run();
    let hashes2 = run();
    assert_eq!(hashes1, hashes2);
}

#[test]
fn deterministic_event_ordering() {
    let run = || {
        let mut eval = default_eval();
        pass_all_gates(&mut eval);
        eval.drain_events()
    };
    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn re_evaluate_replaces_previous_report() {
    let mut eval = default_eval();
    let r1 = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 10,
            crashes: 5,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci-1",
        "t1",
        100,
    );
    assert!(!r1.status.is_passed());

    let r2 = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 48,
            crashes: 0,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci-2",
        "t2",
        200,
    );
    assert!(r2.status.is_passed());

    let stored = eval.report(GateId::FuzzAdversarial).unwrap();
    assert_eq!(stored.ci_run_id, "ci-2");
    assert!(stored.status.is_passed());
}

#[test]
fn report_none_for_unevaluated_gate() {
    let eval = default_eval();
    assert!(eval.report(GateId::DeterministicReplay).is_none());
    assert!(eval.report(GateId::InterleavingSuite).is_none());
    assert!(eval.report(GateId::ConformanceVectors).is_none());
    assert!(eval.report(GateId::FuzzAdversarial).is_none());
}

#[test]
fn interleaving_exact_boundary_95_passes() {
    let mut eval = default_eval();
    let report = eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 95,
            unresolved_failures: 0,
            regression_transcripts: 0,
        },
        "ci",
        "t",
        0,
    );
    assert!(report.status.is_passed());
}

#[test]
fn conformance_exact_boundary_500_passes() {
    let mut eval = default_eval();
    let report = eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 500,
            passed_vectors: 500,
            failed_vectors: 0,
            categories: vec![],
        },
        "ci",
        "t",
        0,
    );
    assert!(report.status.is_passed());
}

#[test]
fn fuzz_exact_boundary_24_hours_passes() {
    let mut eval = default_eval();
    let report = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 24,
            crashes: 0,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci",
        "t",
        0,
    );
    assert!(report.status.is_passed());
}
