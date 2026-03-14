#![forbid(unsafe_code)]

//! Enrichment integration tests for the specialization_rollback_gate module.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_rollback_gate::{
    BEAD_ID, BlockingReason, COMPONENT, DEFAULT_MAX_INTERFERENCE_MILLIONTHS,
    DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS, DEFAULT_MIN_PARITY_MILLIONTHS, DEFAULT_MIN_SAMPLES,
    DEFAULT_ROLLBACK_COOLDOWN_NS, GateConfig, GateVerdict, InterferenceKind, InterferenceReport,
    MAX_CONSECUTIVE_ROLLBACKS, MILLIONTHS, POLICY_ID, SCHEMA_VERSION, SpecializationEvidence,
    SpecializationKind, SpecializationRollbackGate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_evidence(kind: SpecializationKind) -> SpecializationEvidence {
    SpecializationEvidence::new("ev-001", kind, "envelope-001", 100, 1_000_000, 0, 0, vec![])
}

// ---------------------------------------------------------------------------
// SpecializationKind — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specialization_kind_copy_semantics() {
    let a = SpecializationKind::TraceFusion;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_specialization_kind_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    set.insert(SpecializationKind::TraceFusion);
    set.insert(SpecializationKind::CapabilityPruning);
    set.insert(SpecializationKind::GuardElision);
    set.insert(SpecializationKind::AllocationElision);
    set.insert(SpecializationKind::InlineCache);
    set.insert(SpecializationKind::TypeSpecialization);
    set.insert(SpecializationKind::TraceFusion);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_specialization_kind_clone_independence() {
    let a = SpecializationKind::InlineCache;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_specialization_kind_debug_all_unique() {
    let all = [
        SpecializationKind::TraceFusion,
        SpecializationKind::CapabilityPruning,
        SpecializationKind::GuardElision,
        SpecializationKind::AllocationElision,
        SpecializationKind::InlineCache,
        SpecializationKind::TypeSpecialization,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 6);
}

#[test]
fn enrichment_specialization_kind_as_str_unique() {
    let all = [
        SpecializationKind::TraceFusion,
        SpecializationKind::CapabilityPruning,
        SpecializationKind::GuardElision,
        SpecializationKind::AllocationElision,
        SpecializationKind::InlineCache,
        SpecializationKind::TypeSpecialization,
    ];
    let strs: BTreeSet<&str> = all.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

// ---------------------------------------------------------------------------
// InterferenceKind — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_interference_kind_copy_semantics() {
    let a = InterferenceKind::SharedState;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_interference_kind_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    set.insert(InterferenceKind::SharedState);
    set.insert(InterferenceKind::CacheContention);
    set.insert(InterferenceKind::GuardConflict);
    set.insert(InterferenceKind::CapabilityOverlap);
    set.insert(InterferenceKind::TypeFeedbackConflict);
    set.insert(InterferenceKind::SharedState);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_interference_kind_debug_all_unique() {
    let all = [
        InterferenceKind::SharedState,
        InterferenceKind::CacheContention,
        InterferenceKind::GuardConflict,
        InterferenceKind::CapabilityOverlap,
        InterferenceKind::TypeFeedbackConflict,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

// ---------------------------------------------------------------------------
// GateVerdict — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_verdict_copy_semantics() {
    let a = GateVerdict::Approved;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_verdict_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    set.insert(GateVerdict::Approved);
    set.insert(GateVerdict::Denied);
    set.insert(GateVerdict::RolledBack);
    set.insert(GateVerdict::Inconclusive);
    set.insert(GateVerdict::Approved);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_gate_verdict_debug_all_unique() {
    let all = [
        GateVerdict::Approved,
        GateVerdict::Denied,
        GateVerdict::RolledBack,
        GateVerdict::Inconclusive,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn enrichment_gate_verdict_is_approved_only_one() {
    assert!(GateVerdict::Approved.is_approved());
    assert!(!GateVerdict::Denied.is_approved());
    assert!(!GateVerdict::RolledBack.is_approved());
    assert!(!GateVerdict::Inconclusive.is_approved());
}

// ---------------------------------------------------------------------------
// BlockingReason — BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_blocking_reason_clone_independence() {
    let a = BlockingReason::TailLatencyRegression {
        regression_millionths: 50_000,
        threshold_millionths: 30_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_blocking_reason_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(BlockingReason::TailLatencyRegression {
        regression_millionths: 50_000,
        threshold_millionths: 30_000,
    });
    set.insert(BlockingReason::InterferenceExceeded {
        interference_millionths: 200_000,
        threshold_millionths: 100_000,
    });
    set.insert(BlockingReason::InsufficientSamples {
        actual: 10,
        minimum: 50,
    });
    set.insert(BlockingReason::RollbackLockout { consecutive: 3 });
    set.insert(BlockingReason::CooldownActive { remaining_ns: 1000 });
    set.insert(BlockingReason::TailLatencyRegression {
        regression_millionths: 50_000,
        threshold_millionths: 30_000,
    });
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_blocking_reason_debug_nonempty() {
    let r = BlockingReason::ParityInsufficient {
        parity_millionths: 500_000,
        minimum_millionths: 1_000_000,
    };
    assert!(!format!("{:?}", r).is_empty());
}

// ---------------------------------------------------------------------------
// InterferenceReport — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_interference_report_clone_independence() {
    let a = InterferenceReport::new(
        "rpt-1",
        "env-a",
        "env-b",
        InterferenceKind::SharedState,
        50_000,
        BTreeSet::new(),
    );
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_interference_report_debug_nonempty() {
    let r = InterferenceReport::new(
        "rpt-1",
        "env-a",
        "env-b",
        InterferenceKind::CacheContention,
        100_000,
        BTreeSet::new(),
    );
    assert!(!format!("{:?}", r).is_empty());
}

#[test]
fn enrichment_interference_report_json_field_names() {
    let r = InterferenceReport::new(
        "rpt-1",
        "env-a",
        "env-b",
        InterferenceKind::SharedState,
        50_000,
        BTreeSet::from(["site-1".to_string()]),
    );
    let json = serde_json::to_string(&r).unwrap();
    for field in &[
        "report_id",
        "envelope_a",
        "envelope_b",
        "kind",
        "severity_millionths",
        "shared_sites",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// SpecializationEvidence — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specialization_evidence_clone_independence() {
    let a = make_evidence(SpecializationKind::TraceFusion);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_specialization_evidence_debug_nonempty() {
    assert!(!format!("{:?}", make_evidence(SpecializationKind::InlineCache)).is_empty());
}

#[test]
fn enrichment_specialization_evidence_json_field_names() {
    let ev = make_evidence(SpecializationKind::GuardElision);
    let json = serde_json::to_string(&ev).unwrap();
    for field in &[
        "evidence_id",
        "kind",
        "envelope_id",
        "sample_count",
        "parity_millionths",
        "tail_regression_millionths",
        "budget_usage_millionths",
        "interference_reports",
        "max_interference_millionths",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// GateConfig — Clone / Debug / JSON fields / builder chain
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_clone_independence() {
    let a = GateConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_config_debug_nonempty() {
    assert!(!format!("{:?}", GateConfig::default()).is_empty());
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "max_tail_regression_millionths",
        "max_interference_millionths",
        "min_parity_millionths",
        "min_samples",
        "max_consecutive_rollbacks",
        "rollback_cooldown_ns",
        "kind_budgets",
        "fail_closed",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_gate_config_builder_chain() {
    let cfg = GateConfig::default()
        .with_tail_regression(50_000)
        .with_interference_threshold(200_000)
        .with_parity_threshold(900_000)
        .fail_open()
        .with_kind_budget(&SpecializationKind::TraceFusion, 500_000);
    assert_eq!(cfg.max_tail_regression_millionths, 50_000);
    assert_eq!(cfg.max_interference_millionths, 200_000);
    assert_eq!(cfg.min_parity_millionths, 900_000);
    assert!(!cfg.fail_closed);
}

// ---------------------------------------------------------------------------
// GateSummary — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_summary_clone_independence() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let a = gate.summary();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_summary_debug_nonempty() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    assert!(!format!("{:?}", gate.summary()).is_empty());
}

#[test]
fn enrichment_gate_summary_json_field_names() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&gate.summary()).unwrap();
    for field in &[
        "total_evaluations",
        "approved_count",
        "denied_count",
        "rollback_count",
        "is_locked_out",
        "pass_rate_millionths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// SpecializationRollbackGate — accessors / state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_initial_state() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(5));
    assert_eq!(gate.evaluation_count(), 0);
    assert_eq!(gate.approved_count(), 0);
    assert_eq!(gate.denied_count(), 0);
    assert!(!gate.is_locked_out());
    assert!(gate.last_receipt().is_none());
    assert!(gate.rollback_history().is_empty());
}

#[test]
fn enrichment_gate_evaluate_updates_counts() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = make_evidence(SpecializationKind::TraceFusion);
    let verdict = gate.evaluate("r1", &ev, 0);
    assert_eq!(gate.evaluation_count(), 1);
    if verdict.is_approved() {
        assert_eq!(gate.approved_count(), 1);
    } else {
        assert_eq!(gate.denied_count(), 1);
    }
}

#[test]
fn enrichment_gate_receipt_after_evaluation() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = make_evidence(SpecializationKind::TraceFusion);
    gate.evaluate("r1", &ev, 0);
    let receipt = gate.last_receipt().expect("should have receipt");
    assert_eq!(receipt.receipt_id, "r1");
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.specialization-rollback-gate.v1"
    );
    assert_eq!(BEAD_ID, "bd-1lsy.7.4.3");
    assert_eq!(COMPONENT, "specialization_rollback_gate");
    assert_eq!(POLICY_ID, "RGC-604C");
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS, 30_000);
    assert_eq!(DEFAULT_MAX_INTERFERENCE_MILLIONTHS, 100_000);
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_MIN_SAMPLES, 50);
    assert_eq!(MAX_CONSECUTIVE_ROLLBACKS, 3);
    assert_eq!(DEFAULT_ROLLBACK_COOLDOWN_NS, 5_000_000_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_evaluate() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
            let ev = make_evidence(SpecializationKind::TraceFusion);
            gate.evaluate("r1", &ev, 0);
            serde_json::to_string(gate.last_receipt().unwrap()).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "evaluation should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_summary_matches_gate() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = make_evidence(SpecializationKind::TraceFusion);
    gate.evaluate("r1", &ev, 0);
    gate.evaluate("r2", &ev, 100);
    let summary = gate.summary();
    assert_eq!(summary.total_evaluations, gate.evaluation_count());
    assert_eq!(summary.approved_count, gate.approved_count());
    assert_eq!(summary.denied_count, gate.denied_count());
}

#[test]
fn enrichment_cross_cutting_approved_plus_denied_equals_total() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = make_evidence(SpecializationKind::TraceFusion);
    gate.evaluate("r1", &ev, 0);
    gate.evaluate("r2", &ev, 100);
    assert_eq!(
        gate.approved_count() + gate.denied_count(),
        gate.evaluation_count()
    );
}

#[test]
fn enrichment_cross_cutting_pass_rate_consistency() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    assert_eq!(gate.pass_rate_millionths(), 0);
    let ev = make_evidence(SpecializationKind::TraceFusion);
    gate.evaluate("r1", &ev, 0);
    let rate = gate.pass_rate_millionths();
    if gate.approved_count() == 1 {
        assert_eq!(rate, 1_000_000);
    } else {
        assert_eq!(rate, 0);
    }
}

// ===== PearlTower enrichment session 2026-03-14 =====

#[test]
fn enrichment_evidence_serde_roundtrip() {
    let ev = make_evidence(SpecializationKind::GuardElision);
    let json = serde_json::to_string(&ev).unwrap();
    let back: SpecializationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_interference_report_serde_roundtrip() {
    let r = InterferenceReport::new(
        "rpt-2",
        "env-x",
        "env-y",
        InterferenceKind::GuardConflict,
        75_000,
        BTreeSet::from(["site-a".to_string(), "site-b".to_string()]),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: InterferenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_gate_config_fail_open_sets_flag() {
    let cfg = GateConfig::default().fail_open();
    assert!(!cfg.fail_closed);
}

#[test]
fn enrichment_gate_config_default_is_fail_closed() {
    let cfg = GateConfig::default();
    assert!(cfg.fail_closed);
}

#[test]
fn enrichment_gate_config_default_uses_constant_values() {
    let cfg = GateConfig::default();
    assert_eq!(
        cfg.max_tail_regression_millionths,
        DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS
    );
    assert_eq!(
        cfg.max_interference_millionths,
        DEFAULT_MAX_INTERFERENCE_MILLIONTHS
    );
    assert_eq!(cfg.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
    assert_eq!(cfg.min_samples, DEFAULT_MIN_SAMPLES);
    assert_eq!(cfg.max_consecutive_rollbacks, MAX_CONSECUTIVE_ROLLBACKS);
    assert_eq!(cfg.rollback_cooldown_ns, DEFAULT_ROLLBACK_COOLDOWN_NS);
}

#[test]
fn enrichment_specialization_kind_serde_roundtrip_all() {
    let all = [
        SpecializationKind::TraceFusion,
        SpecializationKind::CapabilityPruning,
        SpecializationKind::GuardElision,
        SpecializationKind::AllocationElision,
        SpecializationKind::InlineCache,
        SpecializationKind::TypeSpecialization,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: SpecializationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, &back);
    }
}

#[test]
fn enrichment_interference_kind_serde_roundtrip_all() {
    let all = [
        InterferenceKind::SharedState,
        InterferenceKind::CacheContention,
        InterferenceKind::GuardConflict,
        InterferenceKind::CapabilityOverlap,
        InterferenceKind::TypeFeedbackConflict,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: InterferenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, &back);
    }
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip_all() {
    let all = [
        GateVerdict::Approved,
        GateVerdict::Denied,
        GateVerdict::RolledBack,
        GateVerdict::Inconclusive,
    ];
    for verdict in &all {
        let json = serde_json::to_string(verdict).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, &back);
    }
}

// ===== PearlTower enrichment batch 2 — 2026-03-14 =====

// ---------------------------------------------------------------------------
// GateVerdict::as_str — all variants produce distinct non-empty labels
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_verdict_as_str_distinct() {
    let strs: BTreeSet<&str> = [
        GateVerdict::Approved,
        GateVerdict::Denied,
        GateVerdict::RolledBack,
        GateVerdict::Inconclusive,
    ]
    .iter()
    .map(|v| v.as_str())
    .collect();
    assert_eq!(strs.len(), 4, "every variant must have a unique label");
    for s in &strs {
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord — construction, seal, serde, clone
// ---------------------------------------------------------------------------

fn make_rollback_record() -> frankenengine_engine::specialization_rollback_gate::RollbackRecord {
    frankenengine_engine::specialization_rollback_gate::RollbackRecord::new(
        "rb-001",
        SecurityEpoch::from_raw(2),
        "envelope-99",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 60_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    )
}

#[test]
fn enrichment_rollback_record_fields() {
    let r = make_rollback_record();
    assert_eq!(r.record_id, "rb-001");
    assert_eq!(r.epoch, SecurityEpoch::from_raw(2));
    assert_eq!(r.envelope_id, "envelope-99");
    assert_eq!(r.timestamp_ns, 1_000_000_000);
    assert_ne!(
        r.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b""),
        "seal must produce a non-trivial hash"
    );
}

#[test]
fn enrichment_rollback_record_clone_independence() {
    let a = make_rollback_record();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_record_serde_roundtrip() {
    let original = make_rollback_record();
    let json = serde_json::to_string(&original).unwrap();
    let restored: frankenengine_engine::specialization_rollback_gate::RollbackRecord =
        serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn enrichment_rollback_record_json_field_names() {
    let r = make_rollback_record();
    let json = serde_json::to_string(&r).unwrap();
    for field in &[
        "record_id",
        "epoch",
        "envelope_id",
        "reason",
        "timestamp_ns",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_rollback_record_seal_deterministic() {
    let a = make_rollback_record();
    let b = make_rollback_record();
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// DecisionReceipt — JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(3));
    let ev = make_evidence(SpecializationKind::CapabilityPruning);
    gate.evaluate("rcpt-serde", &ev, 0);
    let receipt = gate.last_receipt().unwrap().clone();
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: frankenengine_engine::specialization_rollback_gate::DecisionReceipt =
        serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

#[test]
fn enrichment_decision_receipt_json_field_names() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = make_evidence(SpecializationKind::GuardElision);
    gate.evaluate("rcpt-fields", &ev, 0);
    let json = serde_json::to_string(gate.last_receipt().unwrap()).unwrap();
    for field in &[
        "receipt_id",
        "epoch",
        "envelope_id",
        "kind",
        "verdict",
        "blocking_reasons",
        "evidence_hash",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// Cooldown logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cooldown_inactive_initially() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    assert!(!gate.is_cooldown_active(0));
    assert!(!gate.is_cooldown_active(u64::MAX));
}

#[test]
fn enrichment_cooldown_active_after_rollback() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    gate.rollback(
        "rb-cd",
        "env-cd",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 40_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    assert!(
        gate.is_cooldown_active(1_000_000_000 + 1),
        "should be in cooldown right after rollback"
    );
    assert!(
        !gate.is_cooldown_active(1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS),
        "should exit cooldown at exactly cooldown duration"
    );
}

#[test]
fn enrichment_evaluate_denied_during_cooldown() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    gate.rollback(
        "rb-c2",
        "env-c2",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 40_000,
            threshold_millionths: 30_000,
        },
        1_000,
    );
    let ev = make_evidence(SpecializationKind::TraceFusion);
    let verdict = gate.evaluate("r-cd", &ev, 2_000);
    assert!(!verdict.is_approved(), "should not approve during cooldown");
}

// ---------------------------------------------------------------------------
// Rollback and lockout
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_increments_history() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    assert!(gate.rollback_history().is_empty());

    gate.rollback(
        "rb-1",
        "env-1",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 50_000,
            threshold_millionths: 30_000,
        },
        100,
    );
    assert_eq!(gate.rollback_history().len(), 1);

    gate.rollback(
        "rb-2",
        "env-2",
        BlockingReason::InterferenceExceeded {
            interference_millionths: 200_000,
            threshold_millionths: 100_000,
        },
        200,
    );
    assert_eq!(gate.rollback_history().len(), 2);
}

#[test]
fn enrichment_lockout_after_max_consecutive_rollbacks() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    assert!(!gate.is_locked_out());

    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        gate.rollback(
            &format!("rb-{}", i),
            &format!("env-{}", i),
            BlockingReason::TailLatencyRegression {
                regression_millionths: 50_000,
                threshold_millionths: 30_000,
            },
            (i as u64 + 1) * 1_000,
        );
    }
    assert!(
        gate.is_locked_out(),
        "should be locked out after {} consecutive rollbacks",
        MAX_CONSECUTIVE_ROLLBACKS
    );
}

#[test]
fn enrichment_reset_rollback_counter_clears_lockout() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        gate.rollback(
            &format!("rb-{}", i),
            &format!("env-{}", i),
            BlockingReason::TailLatencyRegression {
                regression_millionths: 50_000,
                threshold_millionths: 30_000,
            },
            (i as u64 + 1) * 1_000,
        );
    }
    assert!(gate.is_locked_out());
    gate.reset_rollback_counter();
    assert!(!gate.is_locked_out());
}

#[test]
fn enrichment_locked_out_gate_denies_evaluation() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        gate.rollback(
            &format!("rb-{}", i),
            &format!("env-{}", i),
            BlockingReason::TailLatencyRegression {
                regression_millionths: 50_000,
                threshold_millionths: 30_000,
            },
            (i as u64 + 1) * 100,
        );
    }
    let ev = make_evidence(SpecializationKind::TraceFusion);
    let verdict = gate.evaluate("r-lockout", &ev, DEFAULT_ROLLBACK_COOLDOWN_NS + 100_000);
    assert_eq!(
        verdict,
        GateVerdict::Denied,
        "locked-out gate must deny even valid evidence"
    );
}

// ---------------------------------------------------------------------------
// Evaluation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_insufficient_samples_not_approved() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-low",
        SpecializationKind::TraceFusion,
        "envelope-low",
        10, // below DEFAULT_MIN_SAMPLES (50)
        1_000_000,
        0,
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-low", &ev, 0);
    assert!(!verdict.is_approved());
}

#[test]
fn enrichment_high_tail_regression_denied() {
    let config = GateConfig::default();
    let mut gate = SpecializationRollbackGate::new(config, SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-tail",
        SpecializationKind::InlineCache,
        "envelope-tail",
        100,
        1_000_000,
        50_000, // above DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS (30_000)
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-tail", &ev, 0);
    assert_eq!(verdict, GateVerdict::Denied);
}

#[test]
fn enrichment_high_interference_denied() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-int",
        SpecializationKind::AllocationElision,
        "envelope-int",
        100,
        1_000_000,
        0,
        200_000, // above DEFAULT_MAX_INTERFERENCE_MILLIONTHS (100_000)
        vec![],
    );
    let verdict = gate.evaluate("r-int", &ev, 0);
    assert_eq!(verdict, GateVerdict::Denied);
}

#[test]
fn enrichment_low_parity_not_approved() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-par",
        SpecializationKind::TypeSpecialization,
        "envelope-par",
        100,
        500_000, // below DEFAULT_MIN_PARITY_MILLIONTHS (1_000_000)
        0,
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-par", &ev, 0);
    assert!(!verdict.is_approved());
}

// ---------------------------------------------------------------------------
// Fail-open config
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fail_open_yields_inconclusive_on_soft_failure() {
    let config = GateConfig::default().fail_open();
    let mut gate = SpecializationRollbackGate::new(config, SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-fo",
        SpecializationKind::TraceFusion,
        "envelope-fo",
        10, // below min_samples — soft failure
        1_000_000,
        0,
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-fo", &ev, 0);
    assert_eq!(
        verdict,
        GateVerdict::Inconclusive,
        "fail-open config should yield Inconclusive for soft failures"
    );
}

#[test]
fn enrichment_fail_open_still_denies_on_hard_failure() {
    let config = GateConfig::default().fail_open();
    let mut gate = SpecializationRollbackGate::new(config, SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-hard",
        SpecializationKind::TraceFusion,
        "envelope-hard",
        100,
        1_000_000,
        50_000, // tail regression above threshold — hard failure
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-hard", &ev, 0);
    assert_eq!(
        verdict,
        GateVerdict::Denied,
        "tail regression is a hard failure even in fail-open mode"
    );
}

// ---------------------------------------------------------------------------
// Custom config via new()
// ---------------------------------------------------------------------------

#[test]
fn enrichment_custom_config_relaxed_thresholds_approve() {
    let config = GateConfig::default()
        .with_tail_regression(100_000)
        .with_interference_threshold(500_000)
        .with_parity_threshold(500_000);
    let mut gate = SpecializationRollbackGate::new(config, SecurityEpoch::from_raw(1));
    let ev = SpecializationEvidence::new(
        "ev-custom",
        SpecializationKind::GuardElision,
        "envelope-custom",
        100,
        600_000, // above relaxed parity threshold
        80_000,  // below relaxed tail threshold
        0,
        vec![],
    );
    let verdict = gate.evaluate("r-custom", &ev, 0);
    assert!(
        verdict.is_approved(),
        "relaxed thresholds should allow this evidence"
    );
}

// ---------------------------------------------------------------------------
// Manifest function
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_returns_zero_state() {
    let manifest =
        frankenengine_engine::specialization_rollback_gate::specialization_rollback_gate_manifest();
    assert_eq!(manifest.total_evaluations, 0);
    assert_eq!(manifest.approved_count, 0);
    assert_eq!(manifest.denied_count, 0);
    assert_eq!(manifest.rollback_count, 0);
    assert!(!manifest.is_locked_out);
    assert_eq!(manifest.pass_rate_millionths, 0);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let original =
        frankenengine_engine::specialization_rollback_gate::specialization_rollback_gate_manifest();
    let json = serde_json::to_string(&original).unwrap();
    let restored: frankenengine_engine::specialization_rollback_gate::GateSummary =
        serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

// ---------------------------------------------------------------------------
// Seal determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_interference_report_seal_deterministic() {
    let a = InterferenceReport::new(
        "rpt-det",
        "env-a",
        "env-b",
        InterferenceKind::GuardConflict,
        75_000,
        BTreeSet::from(["site-x".to_string()]),
    );
    let b = InterferenceReport::new(
        "rpt-det",
        "env-a",
        "env-b",
        InterferenceKind::GuardConflict,
        75_000,
        BTreeSet::from(["site-x".to_string()]),
    );
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_evidence_seal_deterministic() {
    let a = make_evidence(SpecializationKind::AllocationElision);
    let b = make_evidence(SpecializationKind::AllocationElision);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_evidence_different_kind_different_hash() {
    let a = make_evidence(SpecializationKind::AllocationElision);
    let b = make_evidence(SpecializationKind::TraceFusion);
    assert_ne!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// Multiple evaluations — pass rate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pass_rate_after_mixed_evaluations() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    let good_ev = make_evidence(SpecializationKind::TraceFusion);
    let bad_ev = SpecializationEvidence::new(
        "ev-bad",
        SpecializationKind::TraceFusion,
        "envelope-bad",
        10,
        1_000_000,
        0,
        0,
        vec![],
    );

    gate.evaluate("r1", &good_ev, 0);
    gate.evaluate("r2", &bad_ev, 100);
    gate.evaluate("r3", &good_ev, 200);

    assert_eq!(gate.evaluation_count(), 3);
    let rate = gate.pass_rate_millionths();
    assert!(rate <= 1_000_000);
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_epoch_accessor() {
    let gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(42));
    assert_eq!(*gate.epoch(), SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_gate_config_accessor_reflects_custom() {
    let config = GateConfig::default().with_tail_regression(77_000);
    let gate = SpecializationRollbackGate::new(config, SecurityEpoch::from_raw(1));
    assert_eq!(gate.config().max_tail_regression_millionths, 77_000);
}

// ---------------------------------------------------------------------------
// Approved evaluation resets consecutive rollback counter
// ---------------------------------------------------------------------------

#[test]
fn enrichment_approved_evaluation_resets_consecutive_rollbacks() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    // Roll back twice (not enough for lockout)
    gate.rollback(
        "rb-a",
        "env-a",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 40_000,
            threshold_millionths: 30_000,
        },
        100,
    );
    gate.rollback(
        "rb-b",
        "env-b",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 40_000,
            threshold_millionths: 30_000,
        },
        200,
    );
    // Approve an evaluation past cooldown
    let ev = make_evidence(SpecializationKind::TraceFusion);
    let verdict = gate.evaluate("r-reset", &ev, DEFAULT_ROLLBACK_COOLDOWN_NS + 1_000);
    assert!(verdict.is_approved());
    // Now the consecutive counter is reset — can tolerate more rollbacks
    assert!(!gate.is_locked_out());
}

// ---------------------------------------------------------------------------
// Blocking reasons — Display impl existence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_blocking_reason_display_nonempty_all_variants() {
    let reasons = [
        BlockingReason::TailLatencyRegression {
            regression_millionths: 50_000,
            threshold_millionths: 30_000,
        },
        BlockingReason::InterferenceExceeded {
            interference_millionths: 200_000,
            threshold_millionths: 100_000,
        },
        BlockingReason::InsufficientSamples {
            actual: 10,
            minimum: 50,
        },
        BlockingReason::ParityInsufficient {
            parity_millionths: 500_000,
            minimum_millionths: 1_000_000,
        },
        BlockingReason::RollbackLockout { consecutive: 3 },
        BlockingReason::CooldownActive { remaining_ns: 1000 },
    ];
    for reason in &reasons {
        let display = format!("{}", reason);
        assert!(
            !display.is_empty(),
            "Display for {:?} must be non-empty",
            reason
        );
    }
}

// ---------------------------------------------------------------------------
// Gate summary rollback_count matches history length
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_rollback_count_matches_history() {
    let mut gate = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(1));
    gate.rollback(
        "rb-s1",
        "env-s1",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 50_000,
            threshold_millionths: 30_000,
        },
        100,
    );
    gate.rollback(
        "rb-s2",
        "env-s2",
        BlockingReason::InterferenceExceeded {
            interference_millionths: 200_000,
            threshold_millionths: 100_000,
        },
        200,
    );
    let summary = gate.summary();
    assert_eq!(summary.rollback_count, gate.rollback_history().len() as u64);
}
