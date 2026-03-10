//! Enrichment integration tests for `assumptions_ledger` (FRX-13.3).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display/Debug exact
//! values, error variant coverage, assumption lifecycle, monitor check
//! semantics, demotion pipeline, ledger reporting, chain-hash tamper
//! evidence, and edge cases.

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

use frankenengine_engine::assumptions_ledger::*;

// ── helpers ────────────────────────────────────────────────────────────

fn make_assumption(
    id: &str,
    category: AssumptionCategory,
    severity: ViolationSeverity,
) -> Assumption {
    Assumption {
        id: id.to_string(),
        category,
        origin: AssumptionOrigin::Runtime,
        status: AssumptionStatus::Active,
        description: format!("test assumption {id}"),
        decision_id: format!("decision-{id}"),
        epoch: 1,
        dependencies: BTreeSet::new(),
        violation_severity: severity,
        predicate_hash: format!("hash-{id}"),
    }
}

fn make_monitor(
    monitor_id: &str,
    assumption_id: &str,
    threshold: i64,
    op: MonitorOp,
    trigger_count: u32,
) -> FalsificationMonitor {
    FalsificationMonitor {
        monitor_id: monitor_id.to_string(),
        assumption_id: assumption_id.to_string(),
        kind: MonitorKind::Threshold,
        variable: "latency".to_string(),
        threshold_millionths: threshold,
        op,
        trigger_count,
        current_violations: 0,
        triggered: false,
    }
}

fn ledger_with_assumption() -> (AssumptionLedger, String) {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let a = make_assumption(
        "a-1",
        AssumptionCategory::Statistical,
        ViolationSeverity::Warning,
    );
    let id = a.id.clone();
    ledger.record_assumption(a).unwrap();
    (ledger, id)
}

// ── AssumptionCategory ─────────────────────────────────────────────────

#[test]
fn assumption_category_debug_distinct() {
    let cats = [
        AssumptionCategory::Statistical,
        AssumptionCategory::Behavioral,
        AssumptionCategory::Resource,
        AssumptionCategory::Safety,
        AssumptionCategory::Structural,
    ];
    let mut dbgs = BTreeSet::new();
    for c in &cats {
        dbgs.insert(format!("{c:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn assumption_category_serde_tags_exact() {
    assert_eq!(
        serde_json::to_string(&AssumptionCategory::Statistical).unwrap(),
        "\"Statistical\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionCategory::Behavioral).unwrap(),
        "\"Behavioral\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionCategory::Resource).unwrap(),
        "\"Resource\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionCategory::Safety).unwrap(),
        "\"Safety\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionCategory::Structural).unwrap(),
        "\"Structural\""
    );
}

#[test]
fn assumption_category_serde_roundtrip_all() {
    for c in [
        AssumptionCategory::Statistical,
        AssumptionCategory::Behavioral,
        AssumptionCategory::Resource,
        AssumptionCategory::Safety,
        AssumptionCategory::Structural,
    ] {
        let json = serde_json::to_vec(&c).unwrap();
        let back: AssumptionCategory = serde_json::from_slice(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ── AssumptionOrigin ───────────────────────────────────────────────────

#[test]
fn assumption_origin_debug_distinct() {
    let origins = [
        AssumptionOrigin::CompileTime,
        AssumptionOrigin::Runtime,
        AssumptionOrigin::PolicyInherited,
        AssumptionOrigin::Inferred,
    ];
    let mut dbgs = BTreeSet::new();
    for o in &origins {
        dbgs.insert(format!("{o:?}"));
    }
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn assumption_origin_serde_tags_exact() {
    assert_eq!(
        serde_json::to_string(&AssumptionOrigin::CompileTime).unwrap(),
        "\"CompileTime\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionOrigin::Runtime).unwrap(),
        "\"Runtime\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionOrigin::PolicyInherited).unwrap(),
        "\"PolicyInherited\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionOrigin::Inferred).unwrap(),
        "\"Inferred\""
    );
}

#[test]
fn assumption_origin_serde_roundtrip_all() {
    for o in [
        AssumptionOrigin::CompileTime,
        AssumptionOrigin::Runtime,
        AssumptionOrigin::PolicyInherited,
        AssumptionOrigin::Inferred,
    ] {
        let json = serde_json::to_vec(&o).unwrap();
        let back: AssumptionOrigin = serde_json::from_slice(&json).unwrap();
        assert_eq!(o, back);
    }
}

// ── AssumptionStatus ───────────────────────────────────────────────────

#[test]
fn assumption_status_debug_distinct() {
    let statuses = [
        AssumptionStatus::Active,
        AssumptionStatus::Violated,
        AssumptionStatus::Retired,
        AssumptionStatus::Suspended,
    ];
    let mut dbgs = BTreeSet::new();
    for s in &statuses {
        dbgs.insert(format!("{s:?}"));
    }
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn assumption_status_serde_tags_exact() {
    assert_eq!(
        serde_json::to_string(&AssumptionStatus::Active).unwrap(),
        "\"Active\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionStatus::Violated).unwrap(),
        "\"Violated\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionStatus::Retired).unwrap(),
        "\"Retired\""
    );
    assert_eq!(
        serde_json::to_string(&AssumptionStatus::Suspended).unwrap(),
        "\"Suspended\""
    );
}

#[test]
fn assumption_status_serde_roundtrip_all() {
    for s in [
        AssumptionStatus::Active,
        AssumptionStatus::Violated,
        AssumptionStatus::Retired,
        AssumptionStatus::Suspended,
    ] {
        let json = serde_json::to_vec(&s).unwrap();
        let back: AssumptionStatus = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── ViolationSeverity ──────────────────────────────────────────────────

#[test]
fn violation_severity_debug_distinct() {
    let sevs = [
        ViolationSeverity::Advisory,
        ViolationSeverity::Warning,
        ViolationSeverity::Critical,
        ViolationSeverity::Fatal,
    ];
    let mut dbgs = BTreeSet::new();
    for s in &sevs {
        dbgs.insert(format!("{s:?}"));
    }
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn violation_severity_ordering() {
    assert!(ViolationSeverity::Advisory < ViolationSeverity::Warning);
    assert!(ViolationSeverity::Warning < ViolationSeverity::Critical);
    assert!(ViolationSeverity::Critical < ViolationSeverity::Fatal);
}

#[test]
fn violation_severity_serde_roundtrip_all() {
    for s in [
        ViolationSeverity::Advisory,
        ViolationSeverity::Warning,
        ViolationSeverity::Critical,
        ViolationSeverity::Fatal,
    ] {
        let json = serde_json::to_vec(&s).unwrap();
        let back: ViolationSeverity = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── MonitorKind ────────────────────────────────────────────────────────

#[test]
fn monitor_kind_debug_distinct() {
    let kinds = [
        MonitorKind::Threshold,
        MonitorKind::Drift,
        MonitorKind::Coverage,
        MonitorKind::Invariant,
        MonitorKind::Budget,
    ];
    let mut dbgs = BTreeSet::new();
    for k in &kinds {
        dbgs.insert(format!("{k:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn monitor_kind_serde_roundtrip_all() {
    for k in [
        MonitorKind::Threshold,
        MonitorKind::Drift,
        MonitorKind::Coverage,
        MonitorKind::Invariant,
        MonitorKind::Budget,
    ] {
        let json = serde_json::to_vec(&k).unwrap();
        let back: MonitorKind = serde_json::from_slice(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ── MonitorOp ──────────────────────────────────────────────────────────

#[test]
fn monitor_op_debug_distinct() {
    let ops = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
    let mut dbgs = BTreeSet::new();
    for o in &ops {
        dbgs.insert(format!("{o:?}"));
    }
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn monitor_op_serde_roundtrip_all() {
    for o in [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq] {
        let json = serde_json::to_vec(&o).unwrap();
        let back: MonitorOp = serde_json::from_slice(&json).unwrap();
        assert_eq!(o, back);
    }
}

// ── Assumption JSON field stability ────────────────────────────────────

#[test]
fn assumption_json_fields() {
    let a = make_assumption(
        "a-f",
        AssumptionCategory::Safety,
        ViolationSeverity::Critical,
    );
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("id"));
    assert!(obj.contains_key("category"));
    assert!(obj.contains_key("origin"));
    assert!(obj.contains_key("status"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("dependencies"));
    assert!(obj.contains_key("violation_severity"));
    assert!(obj.contains_key("predicate_hash"));
}

#[test]
fn assumption_serde_roundtrip() {
    let a = make_assumption(
        "a-rt",
        AssumptionCategory::Behavioral,
        ViolationSeverity::Advisory,
    );
    let json = serde_json::to_vec(&a).unwrap();
    let back: Assumption = serde_json::from_slice(&json).unwrap();
    assert_eq!(a, back);
}

// ── FalsificationEvidence ──────────────────────────────────────────────

#[test]
fn falsification_evidence_json_fields() {
    let ev = FalsificationEvidence {
        assumption_id: "a-1".to_string(),
        monitor_id: "m-1".to_string(),
        epoch: 3,
        tick: 42,
        observed_value_millionths: 1_500_000,
        threshold_millionths: 1_000_000,
        explanation: "exceeded".to_string(),
        evidence_hash: "aaaa".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("assumption_id"));
    assert!(obj.contains_key("monitor_id"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("tick"));
    assert!(obj.contains_key("observed_value_millionths"));
    assert!(obj.contains_key("threshold_millionths"));
    assert!(obj.contains_key("explanation"));
    assert!(obj.contains_key("evidence_hash"));
}

#[test]
fn falsification_evidence_serde_roundtrip() {
    let ev = FalsificationEvidence {
        assumption_id: "a-2".to_string(),
        monitor_id: "m-2".to_string(),
        epoch: 5,
        tick: 100,
        observed_value_millionths: -500_000,
        threshold_millionths: 0,
        explanation: "below zero".to_string(),
        evidence_hash: "bbbb".to_string(),
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: FalsificationEvidence = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

// ── FalsificationMonitor ───────────────────────────────────────────────

#[test]
fn monitor_json_fields() {
    let m = make_monitor("m-f", "a-1", 1_000_000, MonitorOp::Le, 3);
    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("monitor_id"));
    assert!(obj.contains_key("assumption_id"));
    assert!(obj.contains_key("kind"));
    assert!(obj.contains_key("variable"));
    assert!(obj.contains_key("threshold_millionths"));
    assert!(obj.contains_key("op"));
    assert!(obj.contains_key("trigger_count"));
    assert!(obj.contains_key("current_violations"));
    assert!(obj.contains_key("triggered"));
}

#[test]
fn monitor_serde_roundtrip() {
    let m = make_monitor("m-rt", "a-2", 500_000, MonitorOp::Ge, 2);
    let json = serde_json::to_vec(&m).unwrap();
    let back: FalsificationMonitor = serde_json::from_slice(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn monitor_check_le_holds() {
    let mut m = make_monitor("m-le", "a-le", 1_000_000, MonitorOp::Le, 1);
    let result = m.check(999_999, 1, 1);
    assert!(result.is_none()); // within threshold
    assert_eq!(m.current_violations, 0);
}

#[test]
fn monitor_check_le_violated_triggers() {
    let mut m = make_monitor("m-le2", "a-le2", 1_000_000, MonitorOp::Le, 1);
    let result = m.check(1_000_001, 1, 1);
    assert!(result.is_some());
    assert!(m.triggered);
}

#[test]
fn monitor_check_ge_holds() {
    let mut m = make_monitor("m-ge", "a-ge", 500_000, MonitorOp::Ge, 1);
    let result = m.check(500_001, 1, 1);
    assert!(result.is_none());
}

#[test]
fn monitor_check_ge_violated() {
    let mut m = make_monitor("m-ge2", "a-ge2", 500_000, MonitorOp::Ge, 1);
    let result = m.check(499_999, 1, 1);
    assert!(result.is_some());
}

#[test]
fn monitor_check_eq_exact() {
    let mut m = make_monitor("m-eq", "a-eq", 100, MonitorOp::Eq, 1);
    assert!(m.check(100, 1, 1).is_none());
    assert!(m.check(101, 1, 1).is_some());
}

#[test]
fn monitor_trigger_count_requires_consecutive() {
    let mut m = make_monitor("m-tc", "a-tc", 1_000_000, MonitorOp::Le, 3);
    assert!(m.check(2_000_000, 1, 1).is_none()); // 1 of 3
    assert!(m.check(2_000_000, 1, 2).is_none()); // 2 of 3
    assert!(m.check(2_000_000, 1, 3).is_some()); // 3 of 3 = trigger
}

#[test]
fn monitor_consecutive_reset_on_good_value() {
    let mut m = make_monitor("m-rs", "a-rs", 1_000_000, MonitorOp::Le, 3);
    m.check(2_000_000, 1, 1); // violation 1
    m.check(2_000_000, 1, 2); // violation 2
    m.check(500_000, 1, 3); // good value => reset
    assert_eq!(m.current_violations, 0);
    assert!(m.check(2_000_000, 1, 4).is_none()); // restart count
}

#[test]
fn monitor_does_not_retrigger() {
    let mut m = make_monitor("m-nr", "a-nr", 1_000_000, MonitorOp::Le, 1);
    let first = m.check(2_000_000, 1, 1);
    assert!(first.is_some());
    let second = m.check(2_000_000, 1, 2);
    assert!(second.is_none()); // already triggered
}

#[test]
fn monitor_reset_clears_triggered() {
    let mut m = make_monitor("m-reset", "a-reset", 1_000_000, MonitorOp::Le, 1);
    m.check(2_000_000, 1, 1);
    assert!(m.triggered);
    m.reset();
    assert!(!m.triggered);
    assert_eq!(m.current_violations, 0);
}

// ── DemotionAction ─────────────────────────────────────────────────────

#[test]
fn demotion_action_debug_distinct() {
    let actions = [
        DemotionAction::EnterSafeMode {
            reason: "r".to_string(),
        },
        DemotionAction::DemoteLane {
            lane_id: "l".to_string(),
            reason: "r".to_string(),
        },
        DemotionAction::SuspendAdaptive {
            reason: "r".to_string(),
        },
        DemotionAction::EscalateToOperator {
            reason: "r".to_string(),
        },
        DemotionAction::NoAction,
    ];
    let mut dbgs = BTreeSet::new();
    for a in &actions {
        dbgs.insert(format!("{a:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn demotion_action_serde_roundtrip_all() {
    let actions = [
        DemotionAction::EnterSafeMode {
            reason: "test safe".to_string(),
        },
        DemotionAction::DemoteLane {
            lane_id: "lane-1".to_string(),
            reason: "demote".to_string(),
        },
        DemotionAction::SuspendAdaptive {
            reason: "suspend".to_string(),
        },
        DemotionAction::EscalateToOperator {
            reason: "escalate".to_string(),
        },
        DemotionAction::NoAction,
    ];
    for a in &actions {
        let json = serde_json::to_vec(a).unwrap();
        let back: DemotionAction = serde_json::from_slice(&json).unwrap();
        assert_eq!(a, &back);
    }
}

// ── DemotionPolicy ─────────────────────────────────────────────────────

#[test]
fn demotion_policy_default_advisory_is_no_action() {
    let p = DemotionPolicy::default();
    assert_eq!(p.advisory_action, DemotionAction::NoAction);
}

#[test]
fn demotion_policy_default_serde_roundtrip() {
    let p = DemotionPolicy::default();
    let json = serde_json::to_vec(&p).unwrap();
    let back: DemotionPolicy = serde_json::from_slice(&json).unwrap();
    assert_eq!(p, back);
}

// ── DemotionRecord ─────────────────────────────────────────────────────

#[test]
fn demotion_record_json_fields() {
    let rec = DemotionRecord {
        record_id: "dem-0".to_string(),
        assumption_id: "a-1".to_string(),
        evidence: FalsificationEvidence {
            assumption_id: "a-1".to_string(),
            monitor_id: "m-1".to_string(),
            epoch: 1,
            tick: 1,
            observed_value_millionths: 2_000_000,
            threshold_millionths: 1_000_000,
            explanation: "exceeded".to_string(),
            evidence_hash: "hash".to_string(),
        },
        action: DemotionAction::NoAction,
        epoch: 1,
        severity: ViolationSeverity::Advisory,
    };
    let v: serde_json::Value = serde_json::to_value(&rec).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("record_id"));
    assert!(obj.contains_key("assumption_id"));
    assert!(obj.contains_key("evidence"));
    assert!(obj.contains_key("action"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("severity"));
}

// ── LedgerError ────────────────────────────────────────────────────────

#[test]
fn ledger_error_display_duplicate() {
    let e = LedgerError::DuplicateAssumption("a-dup".to_string());
    assert_eq!(e.to_string(), "duplicate assumption: a-dup");
}

#[test]
fn ledger_error_display_not_found() {
    let e = LedgerError::AssumptionNotFound("a-nf".to_string());
    assert_eq!(e.to_string(), "assumption not found: a-nf");
}

#[test]
fn ledger_error_display_monitor_not_found() {
    let e = LedgerError::MonitorNotFound("m-nf".to_string());
    assert_eq!(e.to_string(), "monitor not found: m-nf");
}

#[test]
fn ledger_error_display_duplicate_monitor() {
    let e = LedgerError::DuplicateMonitor("m-dup".to_string());
    assert_eq!(e.to_string(), "duplicate monitor: m-dup");
}

#[test]
fn ledger_error_display_invalid_transition() {
    let e = LedgerError::InvalidTransition {
        assumption_id: "a-1".to_string(),
        from: AssumptionStatus::Violated,
        to: AssumptionStatus::Retired,
    };
    let s = e.to_string();
    assert!(s.contains("invalid transition"));
    assert!(s.contains("a-1"));
}

#[test]
fn ledger_error_is_std_error() {
    let e = LedgerError::DuplicateAssumption("a".to_string());
    let _: &dyn std::error::Error = &e;
}

#[test]
fn ledger_error_debug_distinct() {
    let errors = [
        LedgerError::DuplicateAssumption("a".to_string()),
        LedgerError::AssumptionNotFound("b".to_string()),
        LedgerError::MonitorNotFound("c".to_string()),
        LedgerError::DuplicateMonitor("d".to_string()),
        LedgerError::InvalidTransition {
            assumption_id: "e".to_string(),
            from: AssumptionStatus::Active,
            to: AssumptionStatus::Active,
        },
    ];
    let mut dbgs = BTreeSet::new();
    for e in &errors {
        dbgs.insert(format!("{e:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn ledger_error_serde_roundtrip_all() {
    let errors = [
        LedgerError::DuplicateAssumption("a".to_string()),
        LedgerError::AssumptionNotFound("b".to_string()),
        LedgerError::MonitorNotFound("c".to_string()),
        LedgerError::DuplicateMonitor("d".to_string()),
        LedgerError::InvalidTransition {
            assumption_id: "e".to_string(),
            from: AssumptionStatus::Active,
            to: AssumptionStatus::Retired,
        },
    ];
    for e in &errors {
        let json = serde_json::to_vec(e).unwrap();
        let back: LedgerError = serde_json::from_slice(&json).unwrap();
        assert_eq!(e, &back);
    }
}

// ── AssumptionLedger lifecycle ──────────────────────────────────────────

#[test]
fn ledger_new_is_empty() {
    let ledger = AssumptionLedger::new(DemotionPolicy::default());
    assert_eq!(ledger.assumption_count(), 0);
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.violated_count(), 0);
    assert!(ledger.falsification_history().is_empty());
    assert!(ledger.demotion_records().is_empty());
}

#[test]
fn ledger_record_assumption_increases_count() {
    let (ledger, _) = ledger_with_assumption();
    assert_eq!(ledger.assumption_count(), 1);
    assert_eq!(ledger.active_count(), 1);
}

#[test]
fn ledger_duplicate_assumption_errors() {
    let (mut ledger, id) = ledger_with_assumption();
    let dup = make_assumption(&id, AssumptionCategory::Safety, ViolationSeverity::Fatal);
    let err = ledger.record_assumption(dup).unwrap_err();
    assert!(matches!(err, LedgerError::DuplicateAssumption(_)));
}

#[test]
fn ledger_get_assumption_by_id() {
    let (ledger, id) = ledger_with_assumption();
    let a = ledger.assumption(&id).unwrap();
    assert_eq!(a.id, id);
    assert_eq!(a.status, AssumptionStatus::Active);
}

#[test]
fn ledger_get_nonexistent_returns_none() {
    let ledger = AssumptionLedger::new(DemotionPolicy::default());
    assert!(ledger.assumption("nonexistent").is_none());
}

#[test]
fn ledger_retire_assumption() {
    let (mut ledger, id) = ledger_with_assumption();
    ledger.retire_assumption(&id).unwrap();
    let a = ledger.assumption(&id).unwrap();
    assert_eq!(a.status, AssumptionStatus::Retired);
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn ledger_retire_nonexistent_errors() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let err = ledger.retire_assumption("nope").unwrap_err();
    assert!(matches!(err, LedgerError::AssumptionNotFound(_)));
}

#[test]
fn ledger_retire_non_active_errors() {
    let (mut ledger, id) = ledger_with_assumption();
    ledger.retire_assumption(&id).unwrap();
    let err = ledger.retire_assumption(&id).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

#[test]
fn ledger_suspend_assumption() {
    let (mut ledger, id) = ledger_with_assumption();
    ledger.suspend_assumption(&id).unwrap();
    let a = ledger.assumption(&id).unwrap();
    assert_eq!(a.status, AssumptionStatus::Suspended);
}

#[test]
fn ledger_suspend_non_active_errors() {
    let (mut ledger, id) = ledger_with_assumption();
    ledger.suspend_assumption(&id).unwrap();
    let err = ledger.suspend_assumption(&id).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

// ── Monitor registration ───────────────────────────────────────────────

#[test]
fn ledger_register_monitor_for_existing_assumption() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-1", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    assert_eq!(ledger.monitors().len(), 1);
}

#[test]
fn ledger_register_monitor_for_missing_assumption_errors() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let m = make_monitor("m-1", "a-missing", 1_000_000, MonitorOp::Le, 1);
    let err = ledger.register_monitor(m).unwrap_err();
    assert!(matches!(err, LedgerError::AssumptionNotFound(_)));
}

#[test]
fn ledger_register_duplicate_monitor_errors() {
    let (mut ledger, id) = ledger_with_assumption();
    let m1 = make_monitor("m-dup", &id, 1_000_000, MonitorOp::Le, 1);
    let m2 = make_monitor("m-dup", &id, 500_000, MonitorOp::Ge, 2);
    ledger.register_monitor(m1).unwrap();
    let err = ledger.register_monitor(m2).unwrap_err();
    assert!(matches!(err, LedgerError::DuplicateMonitor(_)));
}

// ── Observe pipeline ───────────────────────────────────────────────────

#[test]
fn ledger_observe_no_violation_returns_empty() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-obs", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let actions = ledger.observe("latency", 500_000, 1, 1);
    assert!(actions.is_empty());
    assert_eq!(ledger.violated_count(), 0);
}

#[test]
fn ledger_observe_violation_triggers_demotion() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-obs2", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let actions = ledger.observe("latency", 2_000_000, 1, 1);
    assert_eq!(actions.len(), 1);
    assert_eq!(ledger.violated_count(), 1);
    assert_eq!(ledger.falsification_history().len(), 1);
    assert_eq!(ledger.demotion_records().len(), 1);
}

#[test]
fn ledger_observe_wrong_variable_no_trigger() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-obs3", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let actions = ledger.observe("throughput", 2_000_000, 1, 1);
    assert!(actions.is_empty()); // monitor watches "latency", not "throughput"
}

#[test]
fn ledger_demotion_action_matches_severity_advisory() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let a = make_assumption(
        "a-adv",
        AssumptionCategory::Statistical,
        ViolationSeverity::Advisory,
    );
    ledger.record_assumption(a).unwrap();
    let m = make_monitor("m-adv", "a-adv", 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let actions = ledger.observe("latency", 2_000_000, 1, 1);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0], DemotionAction::NoAction);
}

#[test]
fn ledger_demotion_action_matches_severity_critical() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let a = make_assumption(
        "a-crit",
        AssumptionCategory::Safety,
        ViolationSeverity::Critical,
    );
    ledger.record_assumption(a).unwrap();
    let m = make_monitor("m-crit", "a-crit", 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let actions = ledger.observe("latency", 2_000_000, 1, 1);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], DemotionAction::EnterSafeMode { .. }));
}

// ── Chain hash tamper evidence ─────────────────────────────────────────

#[test]
fn ledger_chain_hash_changes_on_record() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let hash_before = ledger.chain_hash().to_string();
    let a = make_assumption(
        "a-hash",
        AssumptionCategory::Resource,
        ViolationSeverity::Warning,
    );
    ledger.record_assumption(a).unwrap();
    assert_ne!(ledger.chain_hash(), &hash_before);
}

#[test]
fn ledger_chain_hash_changes_on_violation() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-hash", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    let hash_before = ledger.chain_hash().to_string();
    ledger.observe("latency", 2_000_000, 1, 1);
    assert_ne!(ledger.chain_hash(), &hash_before);
}

// ── Report ─────────────────────────────────────────────────────────────

#[test]
fn ledger_report_contains_header() {
    let ledger = AssumptionLedger::new(DemotionPolicy::default());
    let report = ledger.report();
    assert!(report.contains("Assumptions Ledger Report"));
    assert!(report.contains("Total assumptions: 0"));
}

#[test]
fn ledger_report_with_falsification() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-rep", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    ledger.observe("latency", 2_000_000, 1, 1);
    let report = ledger.report();
    assert!(report.contains("Recent Falsifications"));
    assert!(report.contains("Violated: 1"));
}

// ── Ledger serde roundtrip ─────────────────────────────────────────────

#[test]
fn ledger_serde_roundtrip_empty() {
    let ledger = AssumptionLedger::new(DemotionPolicy::default());
    let json = serde_json::to_vec(&ledger).unwrap();
    let back: AssumptionLedger = serde_json::from_slice(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn ledger_serde_roundtrip_with_data() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-serde", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    ledger.observe("latency", 2_000_000, 1, 1);
    let json = serde_json::to_vec(&ledger).unwrap();
    let back: AssumptionLedger = serde_json::from_slice(&json).unwrap();
    assert_eq!(ledger, back);
}

// ── Active/violated query helpers ──────────────────────────────────────

#[test]
fn active_assumptions_only_returns_active() {
    let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
    let a1 = make_assumption(
        "a-act1",
        AssumptionCategory::Statistical,
        ViolationSeverity::Warning,
    );
    let a2 = make_assumption(
        "a-act2",
        AssumptionCategory::Behavioral,
        ViolationSeverity::Critical,
    );
    ledger.record_assumption(a1).unwrap();
    ledger.record_assumption(a2).unwrap();
    ledger.retire_assumption("a-act1").unwrap();
    let active = ledger.active_assumptions();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "a-act2");
}

#[test]
fn violated_assumptions_after_observe() {
    let (mut ledger, id) = ledger_with_assumption();
    let m = make_monitor("m-va", &id, 1_000_000, MonitorOp::Le, 1);
    ledger.register_monitor(m).unwrap();
    ledger.observe("latency", 2_000_000, 1, 1);
    let violated = ledger.violated_assumptions();
    assert_eq!(violated.len(), 1);
    assert_eq!(violated[0].id, id);
}
