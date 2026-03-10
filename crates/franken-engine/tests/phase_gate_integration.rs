#![forbid(unsafe_code)]

//! Integration tests for the `phase_gate` module.
//!
//! Covers: GateId, GateStatus, GateMetrics, GateReport, GateThresholds,
//! GateEvent, GateEvaluator — Display impls, construction/defaults, state
//! transitions, error conditions, serde roundtrips, deterministic replay,
//! and cross-gate interaction.

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

use std::collections::BTreeMap;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::phase_gate::{
    ConformanceInput, FuzzInput, GateEvaluator, GateEvent, GateId, GateMetrics, GateReport,
    GateStatus, GateThresholds, InterleavingInput, ReplayInput,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn default_evaluator() -> GateEvaluator {
    GateEvaluator::new(test_epoch(), GateThresholds::default())
}

fn passing_replay_input() -> ReplayInput {
    ReplayInput {
        recorded_hash: ContentHash::compute(b"events-data"),
        replayed_hash: ContentHash::compute(b"events-data"),
        event_count: 500,
    }
}

fn passing_interleaving_input() -> InterleavingInput {
    InterleavingInput {
        total_surfaces: 200,
        explored_surfaces: 192, // 96% > 95%
        unresolved_failures: 0,
        regression_transcripts: 10,
    }
}

fn passing_conformance_input() -> ConformanceInput {
    ConformanceInput {
        total_vectors: 600,
        passed_vectors: 600,
        failed_vectors: 0,
        categories: vec![
            "capability".to_string(),
            "evidence".to_string(),
            "hash_chain".to_string(),
            "epoch".to_string(),
        ],
    }
}

fn passing_fuzz_input() -> FuzzInput {
    FuzzInput {
        cpu_hours: 48,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![
            "schema".to_string(),
            "capability".to_string(),
            "evidence".to_string(),
        ],
    }
}

fn evaluate_all_passing(eval: &mut GateEvaluator) {
    eval.evaluate_replay(&passing_replay_input(), "ci-1", "trace-1", 1000);
    eval.evaluate_interleaving(&passing_interleaving_input(), "ci-1", "trace-2", 2000);
    eval.evaluate_conformance(&passing_conformance_input(), "ci-1", "trace-3", 3000);
    eval.evaluate_fuzz(&passing_fuzz_input(), "ci-1", "trace-4", 4000);
}

// ===========================================================================
// Section 1: GateId — Display, ordering, serde
// ===========================================================================

#[test]
fn gate_id_display_all_variants() {
    assert_eq!(
        GateId::DeterministicReplay.to_string(),
        "deterministic_replay"
    );
    assert_eq!(GateId::InterleavingSuite.to_string(), "interleaving_suite");
    assert_eq!(
        GateId::ConformanceVectors.to_string(),
        "conformance_vectors"
    );
    assert_eq!(GateId::FuzzAdversarial.to_string(), "fuzz_adversarial");
}

#[test]
fn gate_id_ordering_is_deterministic() {
    let mut ids = vec![
        GateId::FuzzAdversarial,
        GateId::DeterministicReplay,
        GateId::ConformanceVectors,
        GateId::InterleavingSuite,
    ];
    ids.sort();
    assert_eq!(
        ids,
        vec![
            GateId::DeterministicReplay,
            GateId::InterleavingSuite,
            GateId::ConformanceVectors,
            GateId::FuzzAdversarial,
        ]
    );
}

#[test]
fn gate_id_clone_and_copy() {
    let id = GateId::InterleavingSuite;
    let cloned = id;
    assert_eq!(id, cloned);
}

#[test]
fn gate_id_serde_roundtrip_all() {
    let ids = [
        GateId::DeterministicReplay,
        GateId::InterleavingSuite,
        GateId::ConformanceVectors,
        GateId::FuzzAdversarial,
    ];
    for id in &ids {
        let json = serde_json::to_string(id).expect("serialize GateId");
        let restored: GateId = serde_json::from_str(&json).expect("deserialize GateId");
        assert_eq!(*id, restored);
    }
}

#[test]
fn gate_id_btreemap_key() {
    let mut map = BTreeMap::new();
    map.insert(GateId::FuzzAdversarial, "fuzz");
    map.insert(GateId::DeterministicReplay, "replay");
    // BTreeMap should order keys
    let keys: Vec<_> = map.keys().collect();
    assert_eq!(keys[0], &GateId::DeterministicReplay);
    assert_eq!(keys[1], &GateId::FuzzAdversarial);
}

// ===========================================================================
// Section 2: GateStatus — Display, predicates, serde
// ===========================================================================

#[test]
fn gate_status_pending_display() {
    assert_eq!(GateStatus::Pending.to_string(), "pending");
}

#[test]
fn gate_status_passed_display() {
    assert_eq!(GateStatus::Passed.to_string(), "passed");
}

#[test]
fn gate_status_failed_display_no_reasons() {
    let status = GateStatus::Failed { reasons: vec![] };
    assert_eq!(status.to_string(), "failed()");
}

#[test]
fn gate_status_failed_display_single_reason() {
    let status = GateStatus::Failed {
        reasons: vec!["low coverage".to_string()],
    };
    assert_eq!(status.to_string(), "failed(low coverage)");
}

#[test]
fn gate_status_failed_display_multiple_reasons() {
    let status = GateStatus::Failed {
        reasons: vec!["reason1".to_string(), "reason2".to_string()],
    };
    assert_eq!(status.to_string(), "failed(reason1; reason2)");
}

#[test]
fn gate_status_skipped_display() {
    let status = GateStatus::Skipped {
        reason: "not applicable".to_string(),
    };
    assert_eq!(status.to_string(), "skipped(not applicable)");
}

#[test]
fn gate_status_is_passed_predicate() {
    assert!(GateStatus::Passed.is_passed());
    assert!(!GateStatus::Pending.is_passed());
    assert!(!GateStatus::Failed { reasons: vec![] }.is_passed());
    assert!(
        !GateStatus::Skipped {
            reason: String::new()
        }
        .is_passed()
    );
}

#[test]
fn gate_status_is_terminal_predicate() {
    assert!(!GateStatus::Pending.is_terminal());
    assert!(GateStatus::Passed.is_terminal());
    assert!(GateStatus::Failed { reasons: vec![] }.is_terminal());
    assert!(
        GateStatus::Skipped {
            reason: String::new()
        }
        .is_terminal()
    );
}

#[test]
fn gate_status_serde_roundtrip_all_variants() {
    let statuses = vec![
        GateStatus::Pending,
        GateStatus::Passed,
        GateStatus::Failed {
            reasons: vec!["bad".to_string(), "worse".to_string()],
        },
        GateStatus::Skipped {
            reason: "config".to_string(),
        },
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).expect("serialize");
        let restored: GateStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, restored);
    }
}

// ===========================================================================
// Section 3: GateMetrics — construction, builder, lookup, serde
// ===========================================================================

#[test]
fn gate_metrics_empty() {
    let m = GateMetrics::empty();
    assert_eq!(m.values.len(), 0);
    assert_eq!(m.get("anything"), None);
}

#[test]
fn gate_metrics_with_builder() {
    let m = GateMetrics::empty()
        .with("coverage_pct", "97")
        .with("total_surfaces", "100")
        .with("explored", "97");
    assert_eq!(m.get("coverage_pct"), Some("97"));
    assert_eq!(m.get("total_surfaces"), Some("100"));
    assert_eq!(m.get("explored"), Some("97"));
    assert_eq!(m.get("nonexistent"), None);
    assert_eq!(m.values.len(), 3);
}

#[test]
fn gate_metrics_overwrite_key() {
    let m = GateMetrics::empty().with("key", "v1").with("key", "v2");
    assert_eq!(m.get("key"), Some("v2"));
    assert_eq!(m.values.len(), 1);
}

#[test]
fn gate_metrics_serde_roundtrip() {
    let m = GateMetrics::empty()
        .with("alpha", "1")
        .with("beta", "2")
        .with("gamma", "3");
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: GateMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

#[test]
fn gate_metrics_btreemap_ordering() {
    let m = GateMetrics::empty()
        .with("zebra", "z")
        .with("apple", "a")
        .with("mango", "m");
    let keys: Vec<&String> = m.values.keys().collect();
    assert_eq!(keys, vec!["apple", "mango", "zebra"]);
}

// ===========================================================================
// Section 4: GateThresholds — defaults, serde
// ===========================================================================

#[test]
fn gate_thresholds_default_values() {
    let t = GateThresholds::default();
    assert_eq!(t.interleaving_coverage_pct, 95);
    assert_eq!(t.min_conformance_vectors, 500);
    assert_eq!(t.min_fuzz_cpu_hours, 24);
}

#[test]
fn gate_thresholds_custom_values() {
    let t = GateThresholds {
        interleaving_coverage_pct: 80,
        min_conformance_vectors: 200,
        min_fuzz_cpu_hours: 12,
    };
    assert_eq!(t.interleaving_coverage_pct, 80);
    assert_eq!(t.min_conformance_vectors, 200);
    assert_eq!(t.min_fuzz_cpu_hours, 12);
}

#[test]
fn gate_thresholds_serde_roundtrip() {
    let t = GateThresholds::default();
    let json = serde_json::to_string(&t).expect("serialize");
    let restored: GateThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(t, restored);
}

#[test]
fn gate_thresholds_custom_serde_roundtrip() {
    let t = GateThresholds {
        interleaving_coverage_pct: 50,
        min_conformance_vectors: 100,
        min_fuzz_cpu_hours: 1,
    };
    let json = serde_json::to_string(&t).expect("serialize");
    let restored: GateThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(t, restored);
}

// ===========================================================================
// Section 5: GateEvent — construction, serde
// ===========================================================================

#[test]
fn gate_event_construction() {
    let event = GateEvent {
        gate_id: "deterministic_replay".to_string(),
        status: "passed".to_string(),
        trace_id: "trace-42".to_string(),
        epoch_id: 1,
        event: "gate_evaluated".to_string(),
    };
    assert_eq!(event.gate_id, "deterministic_replay");
    assert_eq!(event.event, "gate_evaluated");
}

#[test]
fn gate_event_serde_roundtrip() {
    let event = GateEvent {
        gate_id: "fuzz_adversarial".to_string(),
        status: "failed(3 crashes found)".to_string(),
        trace_id: "trace-99".to_string(),
        epoch_id: 5,
        event: "gate_evaluated".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: GateEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// ===========================================================================
// Section 6: GateReport — serde roundtrip
// ===========================================================================

#[test]
fn gate_report_serde_roundtrip() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "ci-42", "trace-7", 9999);
    let json = serde_json::to_string(&report).expect("serialize");
    let restored: GateReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

#[test]
fn gate_report_fields_are_populated() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "ci-build-5", "t-abc", 7777);
    assert_eq!(report.gate_id, GateId::DeterministicReplay);
    assert!(report.status.is_passed());
    assert_eq!(report.ci_run_id, "ci-build-5");
    assert_eq!(report.trace_id, "t-abc");
    assert_eq!(report.epoch_id, 1);
    assert_eq!(report.timestamp_ticks, 7777);
}

// ===========================================================================
// Section 7: ReplayInput — serde
// ===========================================================================

#[test]
fn replay_input_serde_roundtrip() {
    let input = passing_replay_input();
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: ReplayInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

// ===========================================================================
// Section 8: InterleavingInput — serde
// ===========================================================================

#[test]
fn interleaving_input_serde_roundtrip() {
    let input = passing_interleaving_input();
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: InterleavingInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

// ===========================================================================
// Section 9: ConformanceInput — serde
// ===========================================================================

#[test]
fn conformance_input_serde_roundtrip() {
    let input = passing_conformance_input();
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: ConformanceInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

// ===========================================================================
// Section 10: FuzzInput — serde
// ===========================================================================

#[test]
fn fuzz_input_serde_roundtrip() {
    let input = passing_fuzz_input();
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: FuzzInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

// ===========================================================================
// Section 11: Gate 1 — Deterministic Replay evaluation
// ===========================================================================

#[test]
fn replay_gate_passes_on_matching_hashes() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "ci-1", "t1", 1000);
    assert!(report.status.is_passed());
    assert_eq!(report.metrics.get("event_count"), Some("500"));
    assert_eq!(report.metrics.get("match"), Some("true"));
}

#[test]
fn replay_gate_fails_on_mismatch() {
    let mut eval = default_evaluator();
    let input = ReplayInput {
        recorded_hash: ContentHash::compute(b"original"),
        replayed_hash: ContentHash::compute(b"diverged"),
        event_count: 50,
    };
    let report = eval.evaluate_replay(&input, "ci-1", "t1", 1000);
    assert!(!report.status.is_passed());
    assert_eq!(report.metrics.get("match"), Some("false"));
    if let GateStatus::Failed { reasons } = &report.status {
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("transcript mismatch"));
    } else {
        panic!("expected Failed status");
    }
}

#[test]
fn replay_gate_zero_events() {
    let mut eval = default_evaluator();
    let input = ReplayInput {
        recorded_hash: ContentHash::compute(b"empty"),
        replayed_hash: ContentHash::compute(b"empty"),
        event_count: 0,
    };
    let report = eval.evaluate_replay(&input, "ci", "t", 0);
    assert!(report.status.is_passed());
    assert_eq!(report.metrics.get("event_count"), Some("0"));
}

// ===========================================================================
// Section 12: Gate 2 — Interleaving Suite evaluation
// ===========================================================================

#[test]
fn interleaving_gate_passes_at_threshold() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 100,
        explored_surfaces: 95, // exactly 95% == threshold
        unresolved_failures: 0,
        regression_transcripts: 5,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert!(report.status.is_passed());
    assert_eq!(report.metrics.get("coverage_pct"), Some("95"));
}

#[test]
fn interleaving_gate_fails_below_threshold() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 100,
        explored_surfaces: 94, // 94% < 95%
        unresolved_failures: 0,
        regression_transcripts: 0,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons[0].contains("coverage 94%"));
        assert!(reasons[0].contains("required 95%"));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn interleaving_gate_fails_with_unresolved_failures() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 100,
        explored_surfaces: 100,
        unresolved_failures: 3,
        regression_transcripts: 0,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.iter().any(|r| r.contains("3 unresolved")));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn interleaving_gate_fails_both_coverage_and_unresolved() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 100,
        explored_surfaces: 80,
        unresolved_failures: 5,
        regression_transcripts: 0,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert_eq!(reasons.len(), 2);
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn interleaving_gate_zero_surfaces_does_not_panic() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 0,
        explored_surfaces: 0,
        unresolved_failures: 0,
        regression_transcripts: 0,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    // coverage 0/0 checked_div -> 0, which is < 95
    assert!(!report.status.is_passed());
    assert_eq!(report.metrics.get("coverage_pct"), Some("0"));
}

#[test]
fn interleaving_gate_custom_threshold() {
    let thresholds = GateThresholds {
        interleaving_coverage_pct: 50,
        ..GateThresholds::default()
    };
    let mut eval = GateEvaluator::new(test_epoch(), thresholds);
    let input = InterleavingInput {
        total_surfaces: 100,
        explored_surfaces: 51,
        unresolved_failures: 0,
        regression_transcripts: 0,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert!(report.status.is_passed());
}

#[test]
fn interleaving_metrics_populated() {
    let mut eval = default_evaluator();
    let input = InterleavingInput {
        total_surfaces: 200,
        explored_surfaces: 190,
        unresolved_failures: 2,
        regression_transcripts: 8,
    };
    let report = eval.evaluate_interleaving(&input, "ci", "t", 2000);
    assert_eq!(report.metrics.get("total_surfaces"), Some("200"));
    assert_eq!(report.metrics.get("explored_surfaces"), Some("190"));
    assert_eq!(report.metrics.get("coverage_pct"), Some("95"));
    assert_eq!(report.metrics.get("unresolved_failures"), Some("2"));
    assert_eq!(report.metrics.get("regression_transcripts"), Some("8"));
}

// ===========================================================================
// Section 13: Gate 3 — Conformance Vectors evaluation
// ===========================================================================

#[test]
fn conformance_gate_passes_at_minimum() {
    let mut eval = default_evaluator();
    let input = ConformanceInput {
        total_vectors: 500,
        passed_vectors: 500,
        failed_vectors: 0,
        categories: vec!["single_cat".to_string()],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert!(report.status.is_passed());
}

#[test]
fn conformance_gate_fails_below_minimum_vectors() {
    let mut eval = default_evaluator();
    let input = ConformanceInput {
        total_vectors: 499,
        passed_vectors: 499,
        failed_vectors: 0,
        categories: vec![],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons[0].contains("499"));
        assert!(reasons[0].contains("minimum 500"));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn conformance_gate_fails_with_failed_vectors() {
    let mut eval = default_evaluator();
    let input = ConformanceInput {
        total_vectors: 600,
        passed_vectors: 598,
        failed_vectors: 2,
        categories: vec!["cat_a".to_string()],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.iter().any(|r| r.contains("2 conformance")));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn conformance_gate_fails_both_too_few_and_failures() {
    let mut eval = default_evaluator();
    let input = ConformanceInput {
        total_vectors: 100,
        passed_vectors: 95,
        failed_vectors: 5,
        categories: vec![],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert_eq!(reasons.len(), 2);
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn conformance_gate_custom_threshold() {
    let thresholds = GateThresholds {
        min_conformance_vectors: 10,
        ..GateThresholds::default()
    };
    let mut eval = GateEvaluator::new(test_epoch(), thresholds);
    let input = ConformanceInput {
        total_vectors: 10,
        passed_vectors: 10,
        failed_vectors: 0,
        categories: vec![],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert!(report.status.is_passed());
}

#[test]
fn conformance_metrics_populated() {
    let mut eval = default_evaluator();
    let input = ConformanceInput {
        total_vectors: 700,
        passed_vectors: 695,
        failed_vectors: 5,
        categories: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    let report = eval.evaluate_conformance(&input, "ci", "t", 3000);
    assert_eq!(report.metrics.get("total_vectors"), Some("700"));
    assert_eq!(report.metrics.get("passed_vectors"), Some("695"));
    assert_eq!(report.metrics.get("failed_vectors"), Some("5"));
    assert_eq!(report.metrics.get("categories"), Some("3"));
}

// ===========================================================================
// Section 14: Gate 4 — Fuzz/Adversarial evaluation
// ===========================================================================

#[test]
fn fuzz_gate_passes_above_minimum() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_fuzz(&passing_fuzz_input(), "ci", "t", 4000);
    assert!(report.status.is_passed());
}

#[test]
fn fuzz_gate_passes_at_minimum_hours() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 24,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(report.status.is_passed());
}

#[test]
fn fuzz_gate_fails_insufficient_hours() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 23,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons[0].contains("23h"));
        assert!(reasons[0].contains("minimum 24h"));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn fuzz_gate_fails_with_crashes() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 48,
        crashes: 7,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.iter().any(|r| r.contains("7 crashes")));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn fuzz_gate_fails_with_unexpected_panics() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 48,
        crashes: 0,
        unexpected_panics: 2,
        bypasses: 0,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.iter().any(|r| r.contains("2 unexpected panics")));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn fuzz_gate_fails_with_bypasses() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 48,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 1,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert!(reasons.iter().any(|r| r.contains("1 bypass")));
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn fuzz_gate_fails_with_all_issues() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 10,
        crashes: 3,
        unexpected_panics: 2,
        bypasses: 1,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(!report.status.is_passed());
    if let GateStatus::Failed { reasons } = &report.status {
        assert_eq!(reasons.len(), 4);
    } else {
        panic!("expected Failed");
    }
}

#[test]
fn fuzz_gate_custom_threshold() {
    let thresholds = GateThresholds {
        min_fuzz_cpu_hours: 1,
        ..GateThresholds::default()
    };
    let mut eval = GateEvaluator::new(test_epoch(), thresholds);
    let input = FuzzInput {
        cpu_hours: 1,
        crashes: 0,
        unexpected_panics: 0,
        bypasses: 0,
        targets: vec![],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert!(report.status.is_passed());
}

#[test]
fn fuzz_metrics_populated() {
    let mut eval = default_evaluator();
    let input = FuzzInput {
        cpu_hours: 100,
        crashes: 2,
        unexpected_panics: 1,
        bypasses: 3,
        targets: vec!["t1".to_string(), "t2".to_string()],
    };
    let report = eval.evaluate_fuzz(&input, "ci", "t", 4000);
    assert_eq!(report.metrics.get("cpu_hours"), Some("100"));
    assert_eq!(report.metrics.get("crashes"), Some("2"));
    assert_eq!(report.metrics.get("unexpected_panics"), Some("1"));
    assert_eq!(report.metrics.get("bypasses"), Some("3"));
    assert_eq!(report.metrics.get("targets"), Some("2"));
}

// ===========================================================================
// Section 15: all_gates_passed — requires all four
// ===========================================================================

#[test]
fn all_gates_passed_initially_false() {
    let eval = default_evaluator();
    assert!(!eval.all_gates_passed());
}

#[test]
fn all_gates_passed_with_one_gate() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    assert!(!eval.all_gates_passed());
}

#[test]
fn all_gates_passed_with_two_gates() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    eval.evaluate_interleaving(&passing_interleaving_input(), "ci", "t", 0);
    assert!(!eval.all_gates_passed());
}

#[test]
fn all_gates_passed_with_three_gates() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    eval.evaluate_interleaving(&passing_interleaving_input(), "ci", "t", 0);
    eval.evaluate_conformance(&passing_conformance_input(), "ci", "t", 0);
    assert!(!eval.all_gates_passed());
}

#[test]
fn all_gates_passed_with_all_four() {
    let mut eval = default_evaluator();
    evaluate_all_passing(&mut eval);
    assert!(eval.all_gates_passed());
}

#[test]
fn all_gates_passed_false_if_any_failed() {
    // Gate 1 fails, rest pass
    let mut eval = default_evaluator();
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
    eval.evaluate_interleaving(&passing_interleaving_input(), "ci", "t", 0);
    eval.evaluate_conformance(&passing_conformance_input(), "ci", "t", 0);
    eval.evaluate_fuzz(&passing_fuzz_input(), "ci", "t", 0);
    assert!(!eval.all_gates_passed());
}

#[test]
fn all_gates_passed_false_if_fuzz_failed() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    eval.evaluate_interleaving(&passing_interleaving_input(), "ci", "t", 0);
    eval.evaluate_conformance(&passing_conformance_input(), "ci", "t", 0);
    eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 48,
            crashes: 1,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci",
        "t",
        0,
    );
    assert!(!eval.all_gates_passed());
}

// ===========================================================================
// Section 16: Summary and report accessors
// ===========================================================================

#[test]
fn summary_empty_initially() {
    let eval = default_evaluator();
    assert!(eval.summary().is_empty());
}

#[test]
fn summary_shows_evaluated_gates() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    eval.evaluate_fuzz(&passing_fuzz_input(), "ci", "t", 0);

    let summary = eval.summary();
    assert_eq!(summary.len(), 2);
    assert!(summary.contains_key(&GateId::DeterministicReplay));
    assert!(summary.contains_key(&GateId::FuzzAdversarial));
    assert!(summary[&GateId::DeterministicReplay].is_passed());
    assert!(summary[&GateId::FuzzAdversarial].is_passed());
}

#[test]
fn report_returns_specific_gate() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);

    let report = eval.report(GateId::DeterministicReplay);
    assert!(report.is_some());
    assert!(report.unwrap().status.is_passed());

    // Non-evaluated gate returns None
    assert!(eval.report(GateId::FuzzAdversarial).is_none());
}

#[test]
fn export_reports_returns_all_evaluated() {
    let mut eval = default_evaluator();
    evaluate_all_passing(&mut eval);

    let reports = eval.export_reports();
    assert_eq!(reports.len(), 4);
}

#[test]
fn export_reports_empty_initially() {
    let eval = default_evaluator();
    assert!(eval.export_reports().is_empty());
}

// ===========================================================================
// Section 17: Audit events and drain
// ===========================================================================

#[test]
fn evaluation_emits_events() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t-trace", 0);

    let events = eval.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "gate_evaluated");
    assert_eq!(events[0].gate_id, "deterministic_replay");
    assert_eq!(events[0].status, "passed");
    assert_eq!(events[0].trace_id, "t-trace");
    assert_eq!(events[0].epoch_id, 1);
}

#[test]
fn drain_events_clears_buffer() {
    let mut eval = default_evaluator();
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);

    let events1 = eval.drain_events();
    assert_eq!(events1.len(), 1);

    let events2 = eval.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn multiple_evaluations_accumulate_events() {
    let mut eval = default_evaluator();
    evaluate_all_passing(&mut eval);

    let events = eval.drain_events();
    assert_eq!(events.len(), 4);
}

#[test]
fn event_counts_track_evaluations() {
    let mut eval = default_evaluator();
    evaluate_all_passing(&mut eval);

    let counts = eval.event_counts();
    assert_eq!(counts.get("gate_evaluated"), Some(&4));
    assert_eq!(counts.get("gate_passed"), Some(&4));
}

#[test]
fn event_counts_distinguish_passed_from_failed() {
    let mut eval = default_evaluator();
    // Two pass
    eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    eval.evaluate_fuzz(&passing_fuzz_input(), "ci", "t", 0);
    // One fail
    eval.evaluate_conformance(
        &ConformanceInput {
            total_vectors: 10,
            passed_vectors: 10,
            failed_vectors: 0,
            categories: vec![],
        },
        "ci",
        "t",
        0,
    );

    let counts = eval.event_counts();
    assert_eq!(counts.get("gate_evaluated"), Some(&3));
    // conformance failed (10 < 500 threshold)
    assert_eq!(counts.get("gate_passed"), Some(&2));
}

#[test]
fn failed_event_includes_status_string() {
    let mut eval = default_evaluator();
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

    let events = eval.drain_events();
    assert!(events[0].status.starts_with("failed("));
}

// ===========================================================================
// Section 18: Re-evaluation overwrites previous result
// ===========================================================================

#[test]
fn reevaluation_overwrites_gate_report() {
    let mut eval = default_evaluator();

    // First evaluation fails
    let r1 = eval.evaluate_replay(
        &ReplayInput {
            recorded_hash: ContentHash::compute(b"a"),
            replayed_hash: ContentHash::compute(b"b"),
            event_count: 1,
        },
        "ci-1",
        "t1",
        100,
    );
    assert!(!r1.status.is_passed());

    // Re-evaluate with passing input
    let r2 = eval.evaluate_replay(&passing_replay_input(), "ci-2", "t2", 200);
    assert!(r2.status.is_passed());

    // Stored report should be updated
    let stored = eval.report(GateId::DeterministicReplay).unwrap();
    assert!(stored.status.is_passed());
    assert_eq!(stored.ci_run_id, "ci-2");
}

// ===========================================================================
// Section 19: Deterministic report hash
// ===========================================================================

#[test]
fn same_inputs_produce_same_report_hash() {
    let run = || {
        let mut eval = default_evaluator();
        eval.evaluate_replay(&passing_replay_input(), "ci-1", "t1", 1000)
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn different_ci_run_id_produces_different_hash() {
    let mut eval1 = default_evaluator();
    let r1 = eval1.evaluate_replay(&passing_replay_input(), "ci-1", "t1", 1000);

    let mut eval2 = default_evaluator();
    let r2 = eval2.evaluate_replay(&passing_replay_input(), "ci-2", "t1", 1000);

    assert_ne!(r1.report_hash, r2.report_hash);
}

#[test]
fn different_epoch_produces_different_hash() {
    let mut eval1 = GateEvaluator::new(SecurityEpoch::from_raw(1), GateThresholds::default());
    let r1 = eval1.evaluate_replay(&passing_replay_input(), "ci", "t", 1000);

    let mut eval2 = GateEvaluator::new(SecurityEpoch::from_raw(2), GateThresholds::default());
    let r2 = eval2.evaluate_replay(&passing_replay_input(), "ci", "t", 1000);

    assert_ne!(r1.report_hash, r2.report_hash);
}

#[test]
fn different_timestamp_produces_different_hash() {
    let mut eval1 = default_evaluator();
    let r1 = eval1.evaluate_replay(&passing_replay_input(), "ci", "t", 1000);

    let mut eval2 = default_evaluator();
    let r2 = eval2.evaluate_replay(&passing_replay_input(), "ci", "t", 2000);

    assert_ne!(r1.report_hash, r2.report_hash);
}

// ===========================================================================
// Section 20: Cross-gate interaction scenarios
// ===========================================================================

#[test]
fn mixed_pass_fail_across_gates() {
    let mut eval = default_evaluator();

    // Replay passes
    let r1 = eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    assert!(r1.status.is_passed());

    // Interleaving fails
    let r2 = eval.evaluate_interleaving(
        &InterleavingInput {
            total_surfaces: 100,
            explored_surfaces: 50,
            unresolved_failures: 1,
            regression_transcripts: 0,
        },
        "ci",
        "t",
        0,
    );
    assert!(!r2.status.is_passed());

    // Conformance passes
    let r3 = eval.evaluate_conformance(&passing_conformance_input(), "ci", "t", 0);
    assert!(r3.status.is_passed());

    // Fuzz fails
    let r4 = eval.evaluate_fuzz(
        &FuzzInput {
            cpu_hours: 48,
            crashes: 1,
            unexpected_panics: 0,
            bypasses: 0,
            targets: vec![],
        },
        "ci",
        "t",
        0,
    );
    assert!(!r4.status.is_passed());

    assert!(!eval.all_gates_passed());
    assert_eq!(eval.summary().len(), 4);
    assert_eq!(eval.export_reports().len(), 4);
}

#[test]
fn each_gate_has_distinct_gate_id_in_report() {
    let mut eval = default_evaluator();
    evaluate_all_passing(&mut eval);

    let events = eval.drain_events();
    let gate_ids: Vec<&str> = events.iter().map(|e| e.gate_id.as_str()).collect();
    assert!(gate_ids.contains(&"deterministic_replay"));
    assert!(gate_ids.contains(&"interleaving_suite"));
    assert!(gate_ids.contains(&"conformance_vectors"));
    assert!(gate_ids.contains(&"fuzz_adversarial"));
}

// ===========================================================================
// Section 21: Different epoch scenarios
// ===========================================================================

#[test]
fn genesis_epoch_evaluator() {
    let mut eval = GateEvaluator::new(SecurityEpoch::GENESIS, GateThresholds::default());
    let report = eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    assert_eq!(report.epoch_id, 0);
}

#[test]
fn high_epoch_evaluator() {
    let epoch = SecurityEpoch::from_raw(999_999);
    let mut eval = GateEvaluator::new(epoch, GateThresholds::default());
    let report = eval.evaluate_replay(&passing_replay_input(), "ci", "t", 0);
    assert_eq!(report.epoch_id, 999_999);
}

// ===========================================================================
// Section 22: Serde stability (JSON field presence)
// ===========================================================================

#[test]
fn gate_report_json_has_expected_fields() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "ci-1", "t-1", 1234);
    let json = serde_json::to_string(&report).expect("serialize");

    // Verify all expected fields appear in JSON
    assert!(json.contains("gate_id"));
    assert!(json.contains("status"));
    assert!(json.contains("metrics"));
    assert!(json.contains("report_hash"));
    assert!(json.contains("ci_run_id"));
    assert!(json.contains("epoch_id"));
    assert!(json.contains("timestamp_ticks"));
    assert!(json.contains("trace_id"));
}

#[test]
fn gate_event_json_has_expected_fields() {
    let event = GateEvent {
        gate_id: "test_gate".to_string(),
        status: "passed".to_string(),
        trace_id: "trace-1".to_string(),
        epoch_id: 42,
        event: "gate_evaluated".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    assert!(json.contains("gate_id"));
    assert!(json.contains("status"));
    assert!(json.contains("trace_id"));
    assert!(json.contains("epoch_id"));
    assert!(json.contains("\"event\""));
}

// ===========================================================================
// Section 23: Edge cases
// ===========================================================================

#[test]
fn empty_ci_run_id_and_trace_id() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "", "", 0);
    assert!(report.status.is_passed());
    assert_eq!(report.ci_run_id, "");
    assert_eq!(report.trace_id, "");
}

#[test]
fn very_large_event_count() {
    let mut eval = default_evaluator();
    let input = ReplayInput {
        recorded_hash: ContentHash::compute(b"x"),
        replayed_hash: ContentHash::compute(b"x"),
        event_count: u64::MAX,
    };
    let report = eval.evaluate_replay(&input, "ci", "t", 0);
    assert!(report.status.is_passed());
    assert_eq!(
        report.metrics.get("event_count"),
        Some(u64::MAX.to_string().as_str())
    );
}

#[test]
fn max_timestamp_ticks() {
    let mut eval = default_evaluator();
    let report = eval.evaluate_replay(&passing_replay_input(), "ci", "t", u64::MAX);
    assert_eq!(report.timestamp_ticks, u64::MAX);
}
