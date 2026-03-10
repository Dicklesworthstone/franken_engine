//! Integration tests for the `assumptions_ledger` module.
//!
//! Covers assumption primitives, falsification monitors, demotion controller,
//! the append-only ledger, chain-hash tamper-evidence, error paths, Display/Debug,
//! and serde round-trips for all public types.

#![forbid(unsafe_code)]
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

use frankenengine_engine::assumptions_ledger::{
    Assumption, AssumptionCategory, AssumptionLedger, AssumptionOrigin, AssumptionStatus,
    DemotionAction, DemotionController, DemotionPolicy, DemotionRecord, FalsificationEvidence,
    FalsificationMonitor, LedgerError, MonitorKind, MonitorOp, ViolationSeverity,
};

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_assumption(id: &str, severity: ViolationSeverity) -> Assumption {
    Assumption {
        id: id.to_string(),
        category: AssumptionCategory::Statistical,
        origin: AssumptionOrigin::Runtime,
        status: AssumptionStatus::Active,
        description: format!("Test assumption {id}"),
        decision_id: "decision_0".into(),
        epoch: 1,
        dependencies: BTreeSet::from(["risk".to_string()]),
        violation_severity: severity,
        predicate_hash: format!("hash_{id}"),
    }
}

fn make_assumption_full(
    id: &str,
    category: AssumptionCategory,
    origin: AssumptionOrigin,
    severity: ViolationSeverity,
    deps: &[&str],
) -> Assumption {
    Assumption {
        id: id.to_string(),
        category,
        origin,
        status: AssumptionStatus::Active,
        description: format!("Full assumption {id}"),
        decision_id: format!("dec_{id}"),
        epoch: 42,
        dependencies: deps.iter().map(|s| s.to_string()).collect(),
        violation_severity: severity,
        predicate_hash: format!("pred_{id}"),
    }
}

fn make_monitor(monitor_id: &str, assumption_id: &str) -> FalsificationMonitor {
    FalsificationMonitor {
        monitor_id: monitor_id.into(),
        assumption_id: assumption_id.into(),
        kind: MonitorKind::Threshold,
        variable: "risk".into(),
        threshold_millionths: 500_000,
        op: MonitorOp::Le,
        trigger_count: 1,
        current_violations: 0,
        triggered: false,
    }
}

fn make_monitor_with_trigger_count(
    monitor_id: &str,
    assumption_id: &str,
    trigger_count: u32,
) -> FalsificationMonitor {
    FalsificationMonitor {
        monitor_id: monitor_id.into(),
        assumption_id: assumption_id.into(),
        kind: MonitorKind::Threshold,
        variable: "risk".into(),
        threshold_millionths: 500_000,
        op: MonitorOp::Le,
        trigger_count,
        current_violations: 0,
        triggered: false,
    }
}

fn make_evidence(assumption_id: &str, monitor_id: &str) -> FalsificationEvidence {
    FalsificationEvidence {
        assumption_id: assumption_id.into(),
        monitor_id: monitor_id.into(),
        epoch: 1,
        tick: 0,
        observed_value_millionths: 600_000,
        threshold_millionths: 500_000,
        explanation: "test evidence".into(),
        evidence_hash: "ev_hash_0".into(),
    }
}

fn default_ledger() -> AssumptionLedger {
    AssumptionLedger::new(DemotionPolicy::default())
}

// ── Section 1: Assumption Primitives ─────────────────────────────────────

#[test]
fn assumption_category_all_variants_distinct() {
    let cats = [
        AssumptionCategory::Statistical,
        AssumptionCategory::Behavioral,
        AssumptionCategory::Resource,
        AssumptionCategory::Safety,
        AssumptionCategory::Structural,
    ];
    let set: BTreeSet<AssumptionCategory> = cats.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn assumption_category_ordering_is_declaration_order() {
    assert!(AssumptionCategory::Statistical < AssumptionCategory::Behavioral);
    assert!(AssumptionCategory::Behavioral < AssumptionCategory::Resource);
    assert!(AssumptionCategory::Resource < AssumptionCategory::Safety);
    assert!(AssumptionCategory::Safety < AssumptionCategory::Structural);
}

#[test]
fn assumption_origin_all_variants_distinct() {
    let origins = [
        AssumptionOrigin::CompileTime,
        AssumptionOrigin::Runtime,
        AssumptionOrigin::PolicyInherited,
        AssumptionOrigin::Inferred,
    ];
    let set: BTreeSet<AssumptionOrigin> = origins.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn assumption_status_all_variants_debug() {
    let statuses = [
        AssumptionStatus::Active,
        AssumptionStatus::Violated,
        AssumptionStatus::Retired,
        AssumptionStatus::Suspended,
    ];
    let debugs: BTreeSet<String> = statuses.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn violation_severity_ordering() {
    assert!(ViolationSeverity::Advisory < ViolationSeverity::Warning);
    assert!(ViolationSeverity::Warning < ViolationSeverity::Critical);
    assert!(ViolationSeverity::Critical < ViolationSeverity::Fatal);
}

#[test]
fn monitor_kind_all_variants_distinct() {
    let kinds = [
        MonitorKind::Threshold,
        MonitorKind::Drift,
        MonitorKind::Coverage,
        MonitorKind::Invariant,
        MonitorKind::Budget,
    ];
    let set: BTreeSet<MonitorKind> = kinds.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn monitor_op_all_variants_distinct() {
    let ops = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
    let set: BTreeSet<MonitorOp> = ops.iter().copied().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn assumption_struct_fields_accessible() {
    let a = make_assumption_full(
        "a1",
        AssumptionCategory::Safety,
        AssumptionOrigin::CompileTime,
        ViolationSeverity::Critical,
        &["x", "y"],
    );
    assert_eq!(a.id, "a1");
    assert_eq!(a.category, AssumptionCategory::Safety);
    assert_eq!(a.origin, AssumptionOrigin::CompileTime);
    assert_eq!(a.status, AssumptionStatus::Active);
    assert_eq!(a.description, "Full assumption a1");
    assert_eq!(a.decision_id, "dec_a1");
    assert_eq!(a.epoch, 42);
    assert_eq!(a.dependencies.len(), 2);
    assert!(a.dependencies.contains("x"));
    assert!(a.dependencies.contains("y"));
    assert_eq!(a.violation_severity, ViolationSeverity::Critical);
    assert_eq!(a.predicate_hash, "pred_a1");
}

#[test]
fn assumption_clone_is_equal() {
    let a = make_assumption("a1", ViolationSeverity::Warning);
    let b = a.clone();
    assert_eq!(a, b);
}

// ── Section 2: FalsificationMonitor check logic ──────────────────────────

#[test]
fn monitor_le_holds_at_threshold() {
    let mut m = make_monitor("m1", "a1");
    // Exactly at threshold => holds (Le means <=)
    assert!(m.check(500_000, 1, 0).is_none());
    assert_eq!(m.current_violations, 0);
}

#[test]
fn monitor_le_violation_above_threshold() {
    let mut m = make_monitor("m1", "a1");
    let ev = m.check(500_001, 1, 0);
    assert!(ev.is_some());
    let ev = ev.unwrap();
    assert_eq!(ev.assumption_id, "a1");
    assert_eq!(ev.monitor_id, "m1");
    assert_eq!(ev.observed_value_millionths, 500_001);
    assert_eq!(ev.threshold_millionths, 500_000);
    assert!(m.triggered);
}

#[test]
fn monitor_ge_holds_at_threshold() {
    let mut m = FalsificationMonitor {
        monitor_id: "m1".into(),
        assumption_id: "a1".into(),
        kind: MonitorKind::Budget,
        variable: "budget".into(),
        threshold_millionths: 100_000,
        op: MonitorOp::Ge,
        trigger_count: 1,
        current_violations: 0,
        triggered: false,
    };
    assert!(m.check(100_000, 1, 0).is_none());
}

#[test]
fn monitor_ge_violation_below_threshold() {
    let mut m = FalsificationMonitor {
        monitor_id: "m1".into(),
        assumption_id: "a1".into(),
        kind: MonitorKind::Budget,
        variable: "budget".into(),
        threshold_millionths: 100_000,
        op: MonitorOp::Ge,
        trigger_count: 1,
        current_violations: 0,
        triggered: false,
    };
    let ev = m.check(99_999, 1, 0);
    assert!(ev.is_some());
}

#[test]
fn monitor_eq_holds_when_equal() {
    let mut m = FalsificationMonitor {
        monitor_id: "m1".into(),
        assumption_id: "a1".into(),
        kind: MonitorKind::Invariant,
        variable: "flag".into(),
        threshold_millionths: 1_000_000,
        op: MonitorOp::Eq,
        trigger_count: 1,
        current_violations: 0,
        triggered: false,
    };
    assert!(m.check(1_000_000, 1, 0).is_none());
}

#[test]
fn monitor_eq_violation_when_not_equal() {
    let mut m = FalsificationMonitor {
        monitor_id: "m1".into(),
        assumption_id: "a1".into(),
        kind: MonitorKind::Invariant,
        variable: "flag".into(),
        threshold_millionths: 1_000_000,
        op: MonitorOp::Eq,
        trigger_count: 1,
        current_violations: 0,
        triggered: false,
    };
    assert!(m.check(999_999, 1, 0).is_some());
}

#[test]
fn monitor_consecutive_violations_below_trigger_count() {
    let mut m = make_monitor_with_trigger_count("m1", "a1", 3);
    assert!(m.check(600_000, 1, 0).is_none()); // 1st violation
    assert_eq!(m.current_violations, 1);
    assert!(m.check(700_000, 1, 1).is_none()); // 2nd violation
    assert_eq!(m.current_violations, 2);
    assert!(!m.triggered);
}

#[test]
fn monitor_consecutive_violations_reaches_trigger_count() {
    let mut m = make_monitor_with_trigger_count("m1", "a1", 3);
    assert!(m.check(600_000, 1, 0).is_none());
    assert!(m.check(700_000, 1, 1).is_none());
    let ev = m.check(800_000, 1, 2);
    assert!(ev.is_some());
    assert!(m.triggered);
    assert_eq!(m.current_violations, 3);
}

#[test]
fn monitor_violations_reset_on_passing_observation() {
    let mut m = make_monitor_with_trigger_count("m1", "a1", 3);
    assert!(m.check(600_000, 1, 0).is_none()); // violation #1
    assert!(m.check(700_000, 1, 1).is_none()); // violation #2
    assert!(m.check(400_000, 1, 2).is_none()); // passes => reset
    assert_eq!(m.current_violations, 0);
}

#[test]
fn monitor_does_not_double_trigger() {
    let mut m = make_monitor("m1", "a1");
    let first = m.check(600_000, 1, 0);
    assert!(first.is_some());
    // Already triggered; second violation produces None
    let second = m.check(700_000, 1, 1);
    assert!(second.is_none());
}

#[test]
fn monitor_reset_clears_state() {
    let mut m = make_monitor("m1", "a1");
    m.check(600_000, 1, 0);
    assert!(m.triggered);
    m.reset();
    assert!(!m.triggered);
    assert_eq!(m.current_violations, 0);
}

#[test]
fn monitor_reset_allows_re_trigger() {
    let mut m = make_monitor("m1", "a1");
    m.check(600_000, 1, 0);
    assert!(m.triggered);
    m.reset();
    let ev = m.check(700_000, 2, 0);
    assert!(ev.is_some());
}

#[test]
fn monitor_evidence_contains_epoch_and_tick() {
    let mut m = make_monitor("m1", "a1");
    let ev = m.check(999_999, 7, 42).unwrap();
    assert_eq!(ev.epoch, 7);
    assert_eq!(ev.tick, 42);
}

#[test]
fn monitor_evidence_hash_is_nonempty() {
    let mut m = make_monitor("m1", "a1");
    let ev = m.check(600_000, 1, 0).unwrap();
    assert!(!ev.evidence_hash.is_empty());
}

#[test]
fn monitor_evidence_explanation_contains_details() {
    let mut m = make_monitor("m1", "a1");
    let ev = m.check(600_000, 1, 0).unwrap();
    assert!(ev.explanation.contains("m1"));
    assert!(ev.explanation.contains("600000"));
}

// ── Section 3: DemotionPolicy and DemotionController ─────────────────────

#[test]
fn demotion_policy_default_actions() {
    let policy = DemotionPolicy::default();
    assert!(matches!(policy.advisory_action, DemotionAction::NoAction));
    assert!(matches!(
        policy.warning_action,
        DemotionAction::SuspendAdaptive { .. }
    ));
    assert!(matches!(
        policy.critical_action,
        DemotionAction::EnterSafeMode { .. }
    ));
    assert!(matches!(
        policy.fatal_action,
        DemotionAction::EnterSafeMode { .. }
    ));
}

#[test]
fn demotion_controller_starts_empty() {
    let ctrl = DemotionController::new(DemotionPolicy::default());
    assert_eq!(ctrl.demotion_count(), 0);
    assert!(ctrl.records().is_empty());
}

#[test]
fn demotion_controller_process_advisory() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Advisory);
    let ev = make_evidence("a1", "m1");
    let action = ctrl.process_violation(&a, ev);
    assert!(matches!(action, DemotionAction::NoAction));
    assert_eq!(ctrl.demotion_count(), 1);
}

#[test]
fn demotion_controller_process_warning() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Warning);
    let ev = make_evidence("a1", "m1");
    let action = ctrl.process_violation(&a, ev);
    assert!(matches!(action, DemotionAction::SuspendAdaptive { .. }));
}

#[test]
fn demotion_controller_process_critical() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Critical);
    let ev = make_evidence("a1", "m1");
    let action = ctrl.process_violation(&a, ev);
    assert!(matches!(action, DemotionAction::EnterSafeMode { .. }));
}

#[test]
fn demotion_controller_process_fatal() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Fatal);
    let ev = make_evidence("a1", "m1");
    let action = ctrl.process_violation(&a, ev);
    assert!(matches!(action, DemotionAction::EnterSafeMode { .. }));
}

#[test]
fn demotion_controller_record_ids_increment() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Warning);
    ctrl.process_violation(&a, make_evidence("a1", "m1"));
    ctrl.process_violation(&a, make_evidence("a1", "m2"));
    assert_eq!(ctrl.records()[0].record_id, "demotion_0");
    assert_eq!(ctrl.records()[1].record_id, "demotion_1");
}

#[test]
fn demotion_controller_custom_policy() {
    let policy = DemotionPolicy {
        advisory_action: DemotionAction::EscalateToOperator {
            reason: "advisory escalation".into(),
        },
        warning_action: DemotionAction::DemoteLane {
            lane_id: "js".into(),
            reason: "warning demotion".into(),
        },
        critical_action: DemotionAction::SuspendAdaptive {
            reason: "critical suspend".into(),
        },
        fatal_action: DemotionAction::EnterSafeMode {
            reason: "fatal safe".into(),
        },
    };
    let mut ctrl = DemotionController::new(policy);
    let a_adv = make_assumption("a1", ViolationSeverity::Advisory);
    let action = ctrl.process_violation(&a_adv, make_evidence("a1", "m1"));
    assert!(matches!(action, DemotionAction::EscalateToOperator { .. }));

    let a_warn = make_assumption("a2", ViolationSeverity::Warning);
    let action = ctrl.process_violation(&a_warn, make_evidence("a2", "m2"));
    assert!(matches!(action, DemotionAction::DemoteLane { .. }));
}

#[test]
fn demotion_record_stores_severity_and_epoch() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Critical);
    ctrl.process_violation(&a, make_evidence("a1", "m1"));
    let rec = &ctrl.records()[0];
    assert_eq!(rec.severity, ViolationSeverity::Critical);
    assert_eq!(rec.epoch, a.epoch);
    assert_eq!(rec.assumption_id, "a1");
}

// ── Section 4: AssumptionLedger core operations ──────────────────────────

#[test]
fn new_ledger_is_empty() {
    let ledger = default_ledger();
    assert_eq!(ledger.assumption_count(), 0);
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.violated_count(), 0);
    assert!(ledger.falsification_history().is_empty());
    assert!(ledger.demotion_records().is_empty());
    assert!(ledger.assumptions().is_empty());
    assert!(ledger.monitors().is_empty());
}

#[test]
fn new_ledger_has_genesis_chain_hash() {
    let ledger = default_ledger();
    let hash = ledger.chain_hash();
    assert!(!hash.is_empty());
    // Genesis hash is deterministic
    let ledger2 = default_ledger();
    assert_eq!(ledger.chain_hash(), ledger2.chain_hash());
}

#[test]
fn record_assumption_success() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    assert_eq!(ledger.assumption_count(), 1);
    assert_eq!(ledger.active_count(), 1);
    let a = ledger.assumption("a1").unwrap();
    assert_eq!(a.status, AssumptionStatus::Active);
}

#[test]
fn record_assumption_duplicate_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    let err = ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Critical))
        .unwrap_err();
    assert_eq!(err, LedgerError::DuplicateAssumption("a1".into()));
}

#[test]
fn record_assumption_changes_chain_hash() {
    let mut ledger = default_ledger();
    let h0 = ledger.chain_hash().to_string();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    let h1 = ledger.chain_hash().to_string();
    assert_ne!(h0, h1);
}

#[test]
fn record_multiple_assumptions() {
    let mut ledger = default_ledger();
    for i in 0..10 {
        ledger
            .record_assumption(make_assumption(
                &format!("a{i}"),
                ViolationSeverity::Warning,
            ))
            .unwrap();
    }
    assert_eq!(ledger.assumption_count(), 10);
    assert_eq!(ledger.active_count(), 10);
}

#[test]
fn assumption_lookup_by_id() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    assert!(ledger.assumption("a1").is_some());
    assert!(ledger.assumption("nonexistent").is_none());
}

#[test]
fn assumptions_btreemap_ordered_by_id() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("c", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("b", ViolationSeverity::Warning))
        .unwrap();
    let keys: Vec<&String> = ledger.assumptions().keys().collect();
    assert_eq!(keys, vec!["a", "b", "c"]);
}

// ── Section 5: Monitor registration ──────────────────────────────────────

#[test]
fn register_monitor_success() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    assert_eq!(ledger.monitors().len(), 1);
}

#[test]
fn register_monitor_missing_assumption_fails() {
    let mut ledger = default_ledger();
    let err = ledger
        .register_monitor(make_monitor("m1", "nonexistent"))
        .unwrap_err();
    assert_eq!(err, LedgerError::AssumptionNotFound("nonexistent".into()));
}

#[test]
fn register_duplicate_monitor_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let err = ledger
        .register_monitor(make_monitor("m1", "a1"))
        .unwrap_err();
    assert_eq!(err, LedgerError::DuplicateMonitor("m1".into()));
}

#[test]
fn register_multiple_monitors_for_same_assumption() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let mut m2 = make_monitor("m2", "a1");
    m2.threshold_millionths = 700_000;
    ledger.register_monitor(m2).unwrap();
    assert_eq!(ledger.monitors().len(), 2);
}

// ── Section 6: Observe (falsification pipeline) ──────────────────────────

#[test]
fn observe_no_violation_under_threshold() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let actions = ledger.observe("risk", 400_000, 1, 0);
    assert!(actions.is_empty());
    assert_eq!(ledger.violated_count(), 0);
    assert!(ledger.falsification_history().is_empty());
}

#[test]
fn observe_violation_triggers_demotion() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let actions = ledger.observe("risk", 600_000, 1, 0);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], DemotionAction::SuspendAdaptive { .. }));
    assert_eq!(ledger.violated_count(), 1);
    assert_eq!(ledger.falsification_history().len(), 1);
    assert_eq!(ledger.demotion_records().len(), 1);
}

#[test]
fn observe_wrong_variable_no_effect() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let actions = ledger.observe("latency", 999_999, 1, 0);
    assert!(actions.is_empty());
}

#[test]
fn observe_violation_changes_chain_hash() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let h_before = ledger.chain_hash().to_string();
    ledger.observe("risk", 600_000, 1, 0);
    assert_ne!(h_before, ledger.chain_hash());
}

#[test]
fn observe_consecutive_violations_with_trigger_count() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .register_monitor(make_monitor_with_trigger_count("m1", "a1", 3))
        .unwrap();
    assert!(ledger.observe("risk", 600_000, 1, 0).is_empty()); // 1
    assert!(ledger.observe("risk", 700_000, 1, 1).is_empty()); // 2
    let actions = ledger.observe("risk", 800_000, 1, 2); // 3 => triggers
    assert_eq!(actions.len(), 1);
}

#[test]
fn observe_consecutive_violations_reset_on_pass() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .register_monitor(make_monitor_with_trigger_count("m1", "a1", 3))
        .unwrap();
    assert!(ledger.observe("risk", 600_000, 1, 0).is_empty()); // 1
    assert!(ledger.observe("risk", 700_000, 1, 1).is_empty()); // 2
    assert!(ledger.observe("risk", 400_000, 1, 2).is_empty()); // pass => reset
    assert!(ledger.observe("risk", 600_000, 1, 3).is_empty()); // 1 again
    assert!(ledger.observe("risk", 700_000, 1, 4).is_empty()); // 2 again
    let actions = ledger.observe("risk", 800_000, 1, 5); // 3 => triggers
    assert_eq!(actions.len(), 1);
}

#[test]
fn observe_monitor_does_not_double_trigger_via_ledger() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    assert_eq!(ledger.observe("risk", 600_000, 1, 0).len(), 1);
    // Already triggered, should not trigger again
    assert!(ledger.observe("risk", 700_000, 1, 1).is_empty());
    // History still has exactly 1 entry
    assert_eq!(ledger.falsification_history().len(), 1);
}

#[test]
fn observe_multiple_assumptions_independent() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.register_monitor(make_monitor("m2", "a2")).unwrap();
    let actions = ledger.observe("risk", 600_000, 1, 0);
    // Both monitors trigger on same variable
    assert_eq!(actions.len(), 2);
    assert_eq!(ledger.violated_count(), 2);
}

#[test]
fn observe_falsification_evidence_fields() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 750_000, 3, 99);
    let ev = &ledger.falsification_history()[0];
    assert_eq!(ev.assumption_id, "a1");
    assert_eq!(ev.monitor_id, "m1");
    assert_eq!(ev.epoch, 3);
    assert_eq!(ev.tick, 99);
    assert_eq!(ev.observed_value_millionths, 750_000);
    assert_eq!(ev.threshold_millionths, 500_000);
    assert!(!ev.evidence_hash.is_empty());
    assert!(!ev.explanation.is_empty());
}

// ── Section 7: Retire and suspend assumptions ────────────────────────────

#[test]
fn retire_active_assumption() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.retire_assumption("a1").unwrap();
    assert_eq!(
        ledger.assumption("a1").unwrap().status,
        AssumptionStatus::Retired
    );
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn retire_nonexistent_fails() {
    let mut ledger = default_ledger();
    let err = ledger.retire_assumption("ghost").unwrap_err();
    assert_eq!(err, LedgerError::AssumptionNotFound("ghost".into()));
}

#[test]
fn retire_violated_assumption_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let err = ledger.retire_assumption("a1").unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

#[test]
fn retire_suspended_assumption_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.suspend_assumption("a1").unwrap();
    let err = ledger.retire_assumption("a1").unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

#[test]
fn suspend_active_assumption() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.suspend_assumption("a1").unwrap();
    assert_eq!(
        ledger.assumption("a1").unwrap().status,
        AssumptionStatus::Suspended
    );
}

#[test]
fn suspend_nonexistent_fails() {
    let mut ledger = default_ledger();
    let err = ledger.suspend_assumption("ghost").unwrap_err();
    assert_eq!(err, LedgerError::AssumptionNotFound("ghost".into()));
}

#[test]
fn suspend_violated_assumption_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let err = ledger.suspend_assumption("a1").unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

#[test]
fn suspend_retired_assumption_fails() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.retire_assumption("a1").unwrap();
    let err = ledger.suspend_assumption("a1").unwrap_err();
    assert!(matches!(err, LedgerError::InvalidTransition { .. }));
}

// ── Section 8: Filter views ─────────────────────────────────────────────

#[test]
fn active_assumptions_filter() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a3", ViolationSeverity::Advisory))
        .unwrap();
    ledger.retire_assumption("a2").unwrap();
    let active = ledger.active_assumptions();
    assert_eq!(active.len(), 2);
    let ids: BTreeSet<&str> = active.iter().map(|a| a.id.as_str()).collect();
    assert!(ids.contains("a1"));
    assert!(ids.contains("a3"));
}

#[test]
fn violated_assumptions_filter() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a2", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let violated = ledger.violated_assumptions();
    assert_eq!(violated.len(), 1);
    assert_eq!(violated[0].id, "a1");
}

// ── Section 9: Report ────────────────────────────────────────────────────

#[test]
fn report_empty_ledger() {
    let ledger = default_ledger();
    let report = ledger.report();
    assert!(report.contains("Assumptions Ledger Report"));
    assert!(report.contains("Total assumptions: 0"));
    assert!(report.contains("Active: 0"));
    assert!(report.contains("Violated: 0"));
    assert!(report.contains("Monitors: 0"));
    assert!(report.contains("Falsifications: 0"));
    assert!(report.contains("Demotions: 0"));
    // No "Recent Falsifications" section when empty
    assert!(!report.contains("Recent Falsifications"));
}

#[test]
fn report_with_falsifications_shows_recent() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let report = ledger.report();
    assert!(report.contains("Falsifications: 1"));
    assert!(report.contains("Recent Falsifications"));
    assert!(report.contains("m1"));
    assert!(report.contains("a1"));
}

#[test]
fn report_shows_correct_counts_after_mixed_operations() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a3", ViolationSeverity::Advisory))
        .unwrap();
    ledger.retire_assumption("a3").unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let report = ledger.report();
    assert!(report.contains("Total assumptions: 3"));
    assert!(report.contains("Active: 1")); // only a2 is active
    assert!(report.contains("Violated: 1")); // a1 violated
    assert!(report.contains("Monitors: 1"));
    assert!(report.contains("Demotions: 1"));
}

// ── Section 10: LedgerError Display ──────────────────────────────────────

#[test]
fn ledger_error_display_duplicate_assumption() {
    let e = LedgerError::DuplicateAssumption("xyz".into());
    assert_eq!(e.to_string(), "duplicate assumption: xyz");
}

#[test]
fn ledger_error_display_assumption_not_found() {
    let e = LedgerError::AssumptionNotFound("abc".into());
    assert_eq!(e.to_string(), "assumption not found: abc");
}

#[test]
fn ledger_error_display_monitor_not_found() {
    let e = LedgerError::MonitorNotFound("m99".into());
    assert_eq!(e.to_string(), "monitor not found: m99");
}

#[test]
fn ledger_error_display_duplicate_monitor() {
    let e = LedgerError::DuplicateMonitor("m1".into());
    assert_eq!(e.to_string(), "duplicate monitor: m1");
}

#[test]
fn ledger_error_display_invalid_transition() {
    let e = LedgerError::InvalidTransition {
        assumption_id: "a1".into(),
        from: AssumptionStatus::Violated,
        to: AssumptionStatus::Retired,
    };
    let s = e.to_string();
    assert!(s.contains("a1"));
    assert!(s.contains("Violated"));
    assert!(s.contains("Retired"));
}

#[test]
fn ledger_error_all_display_strings_distinct() {
    let errors = [
        LedgerError::DuplicateAssumption("x".into()),
        LedgerError::AssumptionNotFound("x".into()),
        LedgerError::MonitorNotFound("x".into()),
        LedgerError::DuplicateMonitor("x".into()),
        LedgerError::InvalidTransition {
            assumption_id: "x".into(),
            from: AssumptionStatus::Active,
            to: AssumptionStatus::Violated,
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn ledger_error_implements_std_error() {
    let e = LedgerError::DuplicateAssumption("test".into());
    let _: &dyn std::error::Error = &e;
}

// ── Section 11: Serde round-trips ────────────────────────────────────────

#[test]
fn serde_roundtrip_assumption_category_all_variants() {
    let variants = [
        AssumptionCategory::Statistical,
        AssumptionCategory::Behavioral,
        AssumptionCategory::Resource,
        AssumptionCategory::Safety,
        AssumptionCategory::Structural,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: AssumptionCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_assumption_origin_all_variants() {
    let variants = [
        AssumptionOrigin::CompileTime,
        AssumptionOrigin::Runtime,
        AssumptionOrigin::PolicyInherited,
        AssumptionOrigin::Inferred,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: AssumptionOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_assumption_status_all_variants() {
    let variants = [
        AssumptionStatus::Active,
        AssumptionStatus::Violated,
        AssumptionStatus::Retired,
        AssumptionStatus::Suspended,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: AssumptionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_violation_severity_all_variants() {
    let variants = [
        ViolationSeverity::Advisory,
        ViolationSeverity::Warning,
        ViolationSeverity::Critical,
        ViolationSeverity::Fatal,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_monitor_kind_all_variants() {
    let variants = [
        MonitorKind::Threshold,
        MonitorKind::Drift,
        MonitorKind::Coverage,
        MonitorKind::Invariant,
        MonitorKind::Budget,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: MonitorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_monitor_op_all_variants() {
    let variants = [MonitorOp::Le, MonitorOp::Ge, MonitorOp::Eq];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: MonitorOp = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_assumption() {
    let a = make_assumption_full(
        "a1",
        AssumptionCategory::Structural,
        AssumptionOrigin::CompileTime,
        ViolationSeverity::Fatal,
        &["dep_a", "dep_b"],
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: Assumption = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn serde_roundtrip_falsification_evidence() {
    let ev = FalsificationEvidence {
        assumption_id: "a1".into(),
        monitor_id: "m1".into(),
        epoch: 7,
        tick: 42,
        observed_value_millionths: -500_000,
        threshold_millionths: 100_000,
        explanation: "negative value observed".into(),
        evidence_hash: "h123".into(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: FalsificationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_falsification_monitor() {
    let m = FalsificationMonitor {
        monitor_id: "m1".into(),
        assumption_id: "a1".into(),
        kind: MonitorKind::Drift,
        variable: "kl_divergence".into(),
        threshold_millionths: 50_000,
        op: MonitorOp::Le,
        trigger_count: 5,
        current_violations: 2,
        triggered: false,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: FalsificationMonitor = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_demotion_action_all_variants() {
    let actions = vec![
        DemotionAction::EnterSafeMode {
            reason: "critical".into(),
        },
        DemotionAction::DemoteLane {
            lane_id: "js".into(),
            reason: "overloaded".into(),
        },
        DemotionAction::SuspendAdaptive {
            reason: "drift detected".into(),
        },
        DemotionAction::EscalateToOperator {
            reason: "review needed".into(),
        },
        DemotionAction::NoAction,
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: DemotionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

#[test]
fn serde_roundtrip_demotion_record() {
    let record = DemotionRecord {
        record_id: "d0".into(),
        assumption_id: "a1".into(),
        evidence: make_evidence("a1", "m1"),
        action: DemotionAction::EnterSafeMode {
            reason: "test".into(),
        },
        epoch: 1,
        severity: ViolationSeverity::Critical,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: DemotionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn serde_roundtrip_demotion_policy() {
    let policy = DemotionPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn serde_roundtrip_demotion_controller() {
    let mut ctrl = DemotionController::new(DemotionPolicy::default());
    let a = make_assumption("a1", ViolationSeverity::Warning);
    ctrl.process_violation(&a, make_evidence("a1", "m1"));
    let json = serde_json::to_string(&ctrl).unwrap();
    let back: DemotionController = serde_json::from_str(&json).unwrap();
    assert_eq!(ctrl, back);
}

#[test]
fn serde_roundtrip_ledger_error_all_variants() {
    let variants: Vec<LedgerError> = vec![
        LedgerError::DuplicateAssumption("a1".into()),
        LedgerError::AssumptionNotFound("a2".into()),
        LedgerError::MonitorNotFound("m1".into()),
        LedgerError::DuplicateMonitor("m2".into()),
        LedgerError::InvalidTransition {
            assumption_id: "a3".into(),
            from: AssumptionStatus::Active,
            to: AssumptionStatus::Violated,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: LedgerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn serde_roundtrip_ledger_empty() {
    let ledger = default_ledger();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: AssumptionLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn serde_roundtrip_ledger_with_data() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger
        .record_assumption(make_assumption("a2", ViolationSeverity::Critical))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    ledger.register_monitor(make_monitor("m2", "a2")).unwrap();
    ledger.observe("risk", 600_000, 1, 0);
    let json = serde_json::to_string(&ledger).unwrap();
    let back: AssumptionLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

// ── Section 12: Debug trait ──────────────────────────────────────────────

#[test]
fn debug_trait_assumption() {
    let a = make_assumption("a1", ViolationSeverity::Warning);
    let dbg = format!("{a:?}");
    assert!(dbg.contains("Assumption"));
    assert!(dbg.contains("a1"));
}

#[test]
fn debug_trait_monitor() {
    let m = make_monitor("m1", "a1");
    let dbg = format!("{m:?}");
    assert!(dbg.contains("FalsificationMonitor"));
    assert!(dbg.contains("m1"));
}

#[test]
fn debug_trait_ledger() {
    let ledger = default_ledger();
    let dbg = format!("{ledger:?}");
    assert!(dbg.contains("AssumptionLedger"));
}

#[test]
fn debug_trait_demotion_action_all_variants() {
    let actions = [
        DemotionAction::EnterSafeMode { reason: "r".into() },
        DemotionAction::DemoteLane {
            lane_id: "l".into(),
            reason: "r".into(),
        },
        DemotionAction::SuspendAdaptive { reason: "r".into() },
        DemotionAction::EscalateToOperator { reason: "r".into() },
        DemotionAction::NoAction,
    ];
    for a in &actions {
        let dbg = format!("{a:?}");
        assert!(!dbg.is_empty());
    }
}

// ── Section 13: Chain hash determinism ───────────────────────────────────

#[test]
fn chain_hash_deterministic_for_same_operations() {
    let mut l1 = default_ledger();
    let mut l2 = default_ledger();
    l1.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    l2.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    assert_eq!(l1.chain_hash(), l2.chain_hash());
}

#[test]
fn chain_hash_differs_for_different_assumption_ids() {
    let mut l1 = default_ledger();
    let mut l2 = default_ledger();
    l1.record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    l2.record_assumption(make_assumption("a2", ViolationSeverity::Warning))
        .unwrap();
    assert_ne!(l1.chain_hash(), l2.chain_hash());
}

#[test]
fn chain_hash_is_16_hex_chars() {
    let ledger = default_ledger();
    let h = ledger.chain_hash();
    assert_eq!(h.len(), 16);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── Section 14: Edge cases ───────────────────────────────────────────────

#[test]
fn assumption_with_no_dependencies() {
    let a = Assumption {
        id: "a_empty".into(),
        category: AssumptionCategory::Behavioral,
        origin: AssumptionOrigin::Inferred,
        status: AssumptionStatus::Active,
        description: "no deps".into(),
        decision_id: "d0".into(),
        epoch: 0,
        dependencies: BTreeSet::new(),
        violation_severity: ViolationSeverity::Advisory,
        predicate_hash: "empty".into(),
    };
    let mut ledger = default_ledger();
    ledger.record_assumption(a).unwrap();
    assert_eq!(ledger.assumption("a_empty").unwrap().dependencies.len(), 0);
}

#[test]
fn observe_with_negative_value() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    // -100_000 <= 500_000, so it holds
    let actions = ledger.observe("risk", -100_000, 1, 0);
    assert!(actions.is_empty());
}

#[test]
fn observe_with_zero_value() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let actions = ledger.observe("risk", 0, 1, 0);
    assert!(actions.is_empty());
}

#[test]
fn observe_with_i64_max_triggers() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    ledger.register_monitor(make_monitor("m1", "a1")).unwrap();
    let actions = ledger.observe("risk", i64::MAX, 1, 0);
    assert_eq!(actions.len(), 1);
}

#[test]
fn many_monitors_different_variables() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    let mut m1 = make_monitor("m_risk", "a1");
    m1.variable = "risk".into();
    let mut m2 = make_monitor("m_latency", "a1");
    m2.variable = "latency".into();
    m2.threshold_millionths = 200_000;
    ledger.register_monitor(m1).unwrap();
    ledger.register_monitor(m2).unwrap();
    // Only trigger risk monitor
    let actions = ledger.observe("risk", 600_000, 1, 0);
    assert_eq!(actions.len(), 1);
    // latency monitor not touched
    assert_eq!(ledger.falsification_history().len(), 1);
}

#[test]
fn observe_no_monitors_registered() {
    let mut ledger = default_ledger();
    ledger
        .record_assumption(make_assumption("a1", ViolationSeverity::Warning))
        .unwrap();
    // No monitors registered - observe should return empty
    let actions = ledger.observe("risk", 999_999, 1, 0);
    assert!(actions.is_empty());
}
