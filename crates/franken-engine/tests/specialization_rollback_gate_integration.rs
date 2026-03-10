//! Integration tests for specialization_rollback_gate (RGC-604C).
//!
//! Bead: bd-1lsy.7.4.3

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
    MAX_CONSECUTIVE_ROLLBACKS, MILLIONTHS, POLICY_ID, RollbackRecord, SCHEMA_VERSION,
    SpecializationEvidence, SpecializationKind, SpecializationRollbackGate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn good_evidence() -> SpecializationEvidence {
    SpecializationEvidence::new(
        "ev-001",
        SpecializationKind::TraceFusion,
        "env-001",
        100,
        MILLIONTHS,
        0,
        500_000,
        vec![],
    )
}

fn bad_parity_evidence() -> SpecializationEvidence {
    SpecializationEvidence::new(
        "ev-002",
        SpecializationKind::TraceFusion,
        "env-002",
        100,
        800_000,
        0,
        500_000,
        vec![],
    )
}

fn bad_tail_evidence() -> SpecializationEvidence {
    SpecializationEvidence::new(
        "ev-003",
        SpecializationKind::GuardElision,
        "env-003",
        100,
        MILLIONTHS,
        100_000,
        500_000,
        vec![],
    )
}

fn interference_evidence() -> SpecializationEvidence {
    let report = InterferenceReport::new(
        "ir-001",
        "env-a",
        "env-b",
        InterferenceKind::SharedState,
        200_000,
        BTreeSet::from(["site-1".to_string(), "site-2".to_string()]),
    );
    SpecializationEvidence::new(
        "ev-004",
        SpecializationKind::InlineCache,
        "env-004",
        100,
        MILLIONTHS,
        0,
        500_000,
        vec![report],
    )
}

fn insufficient_evidence() -> SpecializationEvidence {
    SpecializationEvidence::new(
        "ev-005",
        SpecializationKind::TypeSpecialization,
        "env-005",
        5,
        MILLIONTHS,
        0,
        500_000,
        vec![],
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(SCHEMA_VERSION.contains("specialization-rollback-gate"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "specialization_rollback_gate");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-604C");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_default_thresholds() {
    assert_eq!(DEFAULT_MAX_TAIL_REGRESSION_MILLIONTHS, 30_000);
    assert_eq!(DEFAULT_MAX_INTERFERENCE_MILLIONTHS, 100_000);
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, MILLIONTHS);
    assert_eq!(DEFAULT_MIN_SAMPLES, 50);
}

// ---------------------------------------------------------------------------
// SpecializationKind
// ---------------------------------------------------------------------------

#[test]
fn test_specialization_kind_display() {
    assert_eq!(
        format!("{}", SpecializationKind::TraceFusion),
        "trace_fusion"
    );
    assert_eq!(
        format!("{}", SpecializationKind::CapabilityPruning),
        "capability_pruning"
    );
    assert_eq!(
        format!("{}", SpecializationKind::GuardElision),
        "guard_elision"
    );
    assert_eq!(
        format!("{}", SpecializationKind::AllocationElision),
        "allocation_elision"
    );
    assert_eq!(
        format!("{}", SpecializationKind::InlineCache),
        "inline_cache"
    );
    assert_eq!(
        format!("{}", SpecializationKind::TypeSpecialization),
        "type_specialization"
    );
}

#[test]
fn test_specialization_kind_serde() {
    for k in [
        SpecializationKind::TraceFusion,
        SpecializationKind::CapabilityPruning,
        SpecializationKind::GuardElision,
        SpecializationKind::AllocationElision,
        SpecializationKind::InlineCache,
        SpecializationKind::TypeSpecialization,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: SpecializationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// InterferenceKind
// ---------------------------------------------------------------------------

#[test]
fn test_interference_kind_display() {
    assert_eq!(format!("{}", InterferenceKind::SharedState), "shared_state");
    assert_eq!(
        format!("{}", InterferenceKind::CacheContention),
        "cache_contention"
    );
    assert_eq!(
        format!("{}", InterferenceKind::GuardConflict),
        "guard_conflict"
    );
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_approved() {
    assert!(GateVerdict::Approved.is_approved());
    assert!(!GateVerdict::Denied.is_approved());
    assert!(!GateVerdict::RolledBack.is_approved());
    assert!(!GateVerdict::Inconclusive.is_approved());
}

#[test]
fn test_verdict_as_str() {
    assert_eq!(GateVerdict::Approved.as_str(), "approved");
    assert_eq!(GateVerdict::Denied.as_str(), "denied");
    assert_eq!(GateVerdict::RolledBack.as_str(), "rolled_back");
    assert_eq!(GateVerdict::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn test_verdict_display() {
    assert_eq!(format!("{}", GateVerdict::Denied), "denied");
}

// ---------------------------------------------------------------------------
// BlockingReason
// ---------------------------------------------------------------------------

#[test]
fn test_blocking_reason_tail_display() {
    let r = BlockingReason::TailLatencyRegression {
        regression_millionths: 100_000,
        threshold_millionths: 30_000,
    };
    assert!(format!("{r}").contains("100000>30000"));
}

#[test]
fn test_blocking_reason_interference_display() {
    let r = BlockingReason::InterferenceExceeded {
        interference_millionths: 200_000,
        threshold_millionths: 100_000,
    };
    assert!(format!("{r}").contains("200000>100000"));
}

#[test]
fn test_blocking_reason_parity_display() {
    let r = BlockingReason::ParityInsufficient {
        parity_millionths: 800_000,
        minimum_millionths: 1_000_000,
    };
    assert!(format!("{r}").contains("800000<1000000"));
}

#[test]
fn test_blocking_reason_budget_display() {
    let r = BlockingReason::BudgetExceeded {
        kind: SpecializationKind::AllocationElision,
        used: 800_000,
        budget: 500_000,
    };
    let s = format!("{r}");
    assert!(s.contains("allocation_elision"));
    assert!(s.contains("800000>500000"));
}

#[test]
fn test_blocking_reason_serde() {
    let r = BlockingReason::CooldownActive { remaining_ns: 5000 };
    let json = serde_json::to_string(&r).unwrap();
    let back: BlockingReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// InterferenceReport
// ---------------------------------------------------------------------------

#[test]
fn test_interference_report_creation() {
    let sites = BTreeSet::from(["s1".to_string(), "s2".to_string()]);
    let r = InterferenceReport::new(
        "ir-001",
        "env-a",
        "env-b",
        InterferenceKind::SharedState,
        200_000,
        sites.clone(),
    );
    assert_eq!(r.report_id, "ir-001");
    assert_eq!(r.shared_sites, sites);
    assert_eq!(r.severity_millionths, 200_000);
}

#[test]
fn test_interference_report_deterministic() {
    let a = InterferenceReport::new(
        "ir-001",
        "a",
        "b",
        InterferenceKind::GuardConflict,
        100_000,
        BTreeSet::new(),
    );
    let b = InterferenceReport::new(
        "ir-001",
        "a",
        "b",
        InterferenceKind::GuardConflict,
        100_000,
        BTreeSet::new(),
    );
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_interference_report_serde() {
    let r = InterferenceReport::new(
        "ir-001",
        "a",
        "b",
        InterferenceKind::CacheContention,
        150_000,
        BTreeSet::from(["x".to_string()]),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: InterferenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.report_id, back.report_id);
}

// ---------------------------------------------------------------------------
// SpecializationEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_evidence_max_interference() {
    let ev = interference_evidence();
    assert_eq!(ev.max_interference_millionths, 200_000);
}

#[test]
fn test_evidence_no_interference() {
    let ev = good_evidence();
    assert_eq!(ev.max_interference_millionths, 0);
}

#[test]
fn test_evidence_seal_deterministic() {
    let a = good_evidence();
    let b = good_evidence();
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_evidence_serde() {
    let ev = good_evidence();
    let json = serde_json::to_string(&ev).unwrap();
    let back: SpecializationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_record_creation() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        "env-001",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    assert_eq!(r.record_id, "rb-001");
    assert_eq!(r.envelope_id, "env-001");
    assert_eq!(r.timestamp_ns, 1_000_000_000);
}

#[test]
fn test_rollback_record_serde() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        "env-001",
        BlockingReason::RollbackLockout { consecutive: 3 },
        2_000_000_000,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r.record_id, back.record_id);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_default() {
    let c = GateConfig::default();
    assert_eq!(c.max_tail_regression_millionths, 30_000);
    assert_eq!(c.max_interference_millionths, 100_000);
    assert_eq!(c.min_parity_millionths, MILLIONTHS);
    assert_eq!(c.min_samples, 50);
    assert_eq!(c.max_consecutive_rollbacks, 3);
    assert!(c.fail_closed);
}

#[test]
fn test_config_builders() {
    let c = GateConfig::default()
        .with_tail_regression(50_000)
        .with_interference_threshold(200_000)
        .with_parity_threshold(900_000)
        .fail_open();
    assert_eq!(c.max_tail_regression_millionths, 50_000);
    assert_eq!(c.max_interference_millionths, 200_000);
    assert_eq!(c.min_parity_millionths, 900_000);
    assert!(!c.fail_closed);
}

#[test]
fn test_config_kind_budget() {
    let c = GateConfig::default().with_kind_budget(&SpecializationKind::TraceFusion, 800_000);
    assert_eq!(c.kind_budgets.get("trace_fusion"), Some(&800_000));
}

#[test]
fn test_config_serde() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// SpecializationRollbackGate — construction
// ---------------------------------------------------------------------------

#[test]
fn test_gate_new() {
    let g = SpecializationRollbackGate::with_defaults(epoch());
    assert_eq!(g.evaluation_count(), 0);
    assert_eq!(g.approved_count(), 0);
    assert_eq!(g.denied_count(), 0);
    assert!(!g.is_locked_out());
    assert!(g.last_receipt().is_none());
    assert!(g.rollback_history().is_empty());
}

#[test]
fn test_gate_custom_epoch() {
    let g = SpecializationRollbackGate::with_defaults(SecurityEpoch::from_raw(99));
    assert_eq!(g.epoch().as_u64(), 99);
}

#[test]
fn test_gate_custom_config() {
    let config = GateConfig::default().with_tail_regression(100_000);
    let g = SpecializationRollbackGate::new(config, epoch());
    assert_eq!(g.config().max_tail_regression_millionths, 100_000);
}

// ---------------------------------------------------------------------------
// SpecializationRollbackGate — evaluate
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_approve() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let v = g.evaluate("r-001", &good_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Approved);
    assert_eq!(g.approved_count(), 1);
}

#[test]
fn test_evaluate_deny_parity() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let v = g.evaluate("r-001", &bad_parity_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, BlockingReason::ParityInsufficient { .. }) })
    );
}

#[test]
fn test_evaluate_deny_tail_regression() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let v = g.evaluate("r-001", &bad_tail_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, BlockingReason::TailLatencyRegression { .. }) })
    );
}

#[test]
fn test_evaluate_deny_interference() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let v = g.evaluate("r-001", &interference_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, BlockingReason::InterferenceExceeded { .. }) })
    );
}

#[test]
fn test_evaluate_deny_insufficient_samples() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let v = g.evaluate("r-001", &insufficient_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Denied);
}

#[test]
fn test_evaluate_budget_exceeded() {
    let config = GateConfig::default().with_kind_budget(&SpecializationKind::TraceFusion, 400_000);
    let mut g = SpecializationRollbackGate::new(config, epoch());
    let v = g.evaluate("r-001", &good_evidence(), 100_000_000);
    assert_eq!(v, GateVerdict::Denied);
}

#[test]
fn test_evaluate_multiple() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    for i in 0..5 {
        g.evaluate(
            &format!("r-{i:03}"),
            &good_evidence(),
            (i as u64 + 1) * 100_000_000,
        );
    }
    assert_eq!(g.evaluation_count(), 5);
    assert_eq!(g.approved_count(), 5);
}

// ---------------------------------------------------------------------------
// Rollback governance
// ---------------------------------------------------------------------------

#[test]
fn test_rollback() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let record = g.rollback(
        "rb-001",
        "env-001",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    assert_eq!(record.record_id, "rb-001");
    assert_eq!(g.rollback_history().len(), 1);
}

#[test]
fn test_rollback_lockout() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        g.rollback(
            &format!("rb-{i:03}"),
            "env-001",
            BlockingReason::TailLatencyRegression {
                regression_millionths: 100_000,
                threshold_millionths: 30_000,
            },
            (i as u64 + 1) * 1_000_000_000,
        );
    }
    assert!(g.is_locked_out());

    let ts = (MAX_CONSECUTIVE_ROLLBACKS as u64 + 100) * 1_000_000_000;
    let v = g.evaluate("r-locked", &good_evidence(), ts);
    assert_eq!(v, GateVerdict::Denied);
}

#[test]
fn test_cooldown_active() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        "env-001",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    assert!(g.is_cooldown_active(1_000_000_001));
    assert!(!g.is_cooldown_active(1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1));
}

#[test]
fn test_cooldown_blocks_approval() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        "env-001",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    let v = g.evaluate("r-001", &good_evidence(), 1_000_000_001);
    assert_eq!(v, GateVerdict::Denied);
}

#[test]
fn test_reset_rollback_counter() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        "env-001",
        BlockingReason::RollbackLockout { consecutive: 1 },
        1_000_000_000,
    );
    g.reset_rollback_counter();
    assert!(!g.is_locked_out());
}

// ---------------------------------------------------------------------------
// Pass rate and summary
// ---------------------------------------------------------------------------

#[test]
fn test_pass_rate_empty() {
    let g = SpecializationRollbackGate::with_defaults(epoch());
    assert_eq!(g.pass_rate_millionths(), 0);
}

#[test]
fn test_pass_rate_all() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    g.evaluate("r-002", &good_evidence(), 200_000_000);
    assert_eq!(g.pass_rate_millionths(), MILLIONTHS);
}

#[test]
fn test_pass_rate_half() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    g.evaluate("r-002", &bad_tail_evidence(), 200_000_000);
    assert_eq!(g.pass_rate_millionths(), 500_000);
}

#[test]
fn test_summary() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    let s = g.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.approved_count, 1);
    assert_eq!(s.denied_count, 0);
    assert_eq!(s.rollback_count, 0);
    assert!(!s.is_locked_out);
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_present() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    assert!(g.last_receipt().is_none());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    assert!(g.last_receipt().is_some());
}

#[test]
fn test_receipt_approved_clean() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert!(receipt.blocking_reasons.is_empty());
}

#[test]
fn test_receipt_denied_has_reasons() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &bad_tail_evidence(), 100_000_000);
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.verdict, GateVerdict::Denied);
    assert!(!receipt.blocking_reasons.is_empty());
}

#[test]
fn test_receipt_hash_deterministic() {
    let mut g1 = SpecializationRollbackGate::with_defaults(epoch());
    let mut g2 = SpecializationRollbackGate::with_defaults(epoch());
    g1.evaluate("r-001", &good_evidence(), 100_000_000);
    g2.evaluate("r-001", &good_evidence(), 100_000_000);
    assert_eq!(
        g1.last_receipt().unwrap().content_hash,
        g2.last_receipt().unwrap().content_hash,
    );
}

// ---------------------------------------------------------------------------
// Gate serde
// ---------------------------------------------------------------------------

#[test]
fn test_gate_serde_roundtrip() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.evaluate("r-001", &good_evidence(), 100_000_000);
    let json = serde_json::to_string(&g).unwrap();
    let back: SpecializationRollbackGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.approved_count(), 1);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let m =
        frankenengine_engine::specialization_rollback_gate::specialization_rollback_gate_manifest();
    assert_eq!(m.total_evaluations, 0);
    assert!(!m.is_locked_out);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_approval_resets_rollback_counter() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        "env-001",
        BlockingReason::TailLatencyRegression {
            regression_millionths: 100_000,
            threshold_millionths: 30_000,
        },
        1_000_000_000,
    );
    let ts = 1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1;
    g.evaluate("r-001", &good_evidence(), ts);
    assert!(!g.is_locked_out());
}

#[test]
fn test_multiple_kinds() {
    let mut g = SpecializationRollbackGate::with_defaults(epoch());
    let kinds = [
        SpecializationKind::TraceFusion,
        SpecializationKind::CapabilityPruning,
        SpecializationKind::GuardElision,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let ev = SpecializationEvidence::new(
            &format!("ev-{i:03}"),
            kind.clone(),
            &format!("env-{i:03}"),
            100,
            MILLIONTHS,
            0,
            500_000,
            vec![],
        );
        let v = g.evaluate(&format!("r-{i:03}"), &ev, (i as u64 + 1) * 100_000_000);
        assert_eq!(v, GateVerdict::Approved);
    }
    assert_eq!(g.approved_count(), 3);
}
