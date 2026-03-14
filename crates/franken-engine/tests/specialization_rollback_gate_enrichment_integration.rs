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
