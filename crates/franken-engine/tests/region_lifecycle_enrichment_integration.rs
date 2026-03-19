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
    clippy::identity_op
)]

//! Enrichment integration tests for the `region_lifecycle` module.

use std::collections::BTreeSet;

use frankenengine_engine::region_lifecycle::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_region() -> Region {
    Region::new("region-enrich", "extension_cell", "trace-enrich")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_region_state_all_display_unique() {
    let displays: BTreeSet<String> = [
        RegionState::Running,
        RegionState::CancelRequested,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_region_state_ordering() {
    assert!(RegionState::Running < RegionState::CancelRequested);
    assert!(RegionState::CancelRequested < RegionState::Draining);
    assert!(RegionState::Draining < RegionState::Finalizing);
    assert!(RegionState::Finalizing < RegionState::Closed);
}

#[test]
fn enrichment_region_state_serde_all_variants() {
    for state in [
        RegionState::Running,
        RegionState::CancelRequested,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: RegionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn enrichment_cancel_reason_all_display_unique() {
    let displays: BTreeSet<String> = [
        CancelReason::OperatorShutdown,
        CancelReason::Quarantine,
        CancelReason::Revocation,
        CancelReason::BudgetExhausted,
        CancelReason::ParentClosing,
        CancelReason::Custom("test".to_string()),
    ]
    .iter()
    .map(|r| r.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_cancel_reason_serde_all_variants() {
    let reasons = [
        CancelReason::OperatorShutdown,
        CancelReason::Quarantine,
        CancelReason::Revocation,
        CancelReason::BudgetExhausted,
        CancelReason::ParentClosing,
        CancelReason::Custom("my_reason".to_string()),
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: CancelReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn enrichment_cancel_reason_ordering() {
    assert!(CancelReason::OperatorShutdown < CancelReason::Quarantine);
    assert!(CancelReason::Quarantine < CancelReason::Revocation);
    assert!(CancelReason::Revocation < CancelReason::BudgetExhausted);
    assert!(CancelReason::BudgetExhausted < CancelReason::ParentClosing);
}

#[test]
fn enrichment_region_new_initial_state() {
    let r = Region::new("id-1", "task_group", "trace-1");
    assert_eq!(r.state(), RegionState::Running);
    assert!(r.cancel_reason().is_none());
    assert_eq!(r.pending_obligations(), 0);
    assert_eq!(r.child_count(), 0);
    assert_eq!(r.event_count(), 0);
    assert_eq!(r.id, "id-1");
    assert_eq!(r.region_type, "task_group");
    assert_eq!(r.trace_id, "trace-1");
}

#[test]
fn enrichment_cancel_from_running_succeeds() {
    let mut r = test_region();
    assert!(r.cancel(CancelReason::OperatorShutdown).is_ok());
    assert_eq!(r.state(), RegionState::CancelRequested);
    assert_eq!(r.cancel_reason(), Some(&CancelReason::OperatorShutdown));
}

#[test]
fn enrichment_cancel_from_cancel_requested_fails() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    let err = r.cancel(CancelReason::Quarantine).unwrap_err();
    assert_eq!(err.current_state, RegionState::CancelRequested);
    assert_eq!(err.attempted_transition, "cancel");
}

#[test]
fn enrichment_drain_from_running_fails() {
    let mut r = test_region();
    let err = r.drain(DrainDeadline::default()).unwrap_err();
    assert_eq!(err.current_state, RegionState::Running);
    assert_eq!(err.attempted_transition, "drain");
}

#[test]
fn enrichment_drain_from_cancel_requested_succeeds() {
    let mut r = test_region();
    r.cancel(CancelReason::Quarantine).unwrap();
    assert!(r.drain(DrainDeadline::default()).is_ok());
    assert_eq!(r.state(), RegionState::Draining);
}

#[test]
fn enrichment_finalize_from_running_fails() {
    let mut r = test_region();
    let err = r.finalize().unwrap_err();
    assert_eq!(err.current_state, RegionState::Running);
    assert_eq!(err.attempted_transition, "finalize");
}

#[test]
fn enrichment_finalize_from_cancel_requested_fails() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    let err = r.finalize().unwrap_err();
    assert_eq!(err.current_state, RegionState::CancelRequested);
    assert_eq!(err.attempted_transition, "finalize");
}

#[test]
fn enrichment_full_lifecycle_no_obligations() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline::default()).unwrap();
    let result = r.finalize().unwrap();
    assert!(result.success);
    assert_eq!(result.obligations_committed, 0);
    assert_eq!(result.obligations_aborted, 0);
    assert!(!result.drain_timeout_escalated);
    assert_eq!(r.state(), RegionState::Closed);
}

#[test]
fn enrichment_full_lifecycle_with_committed_obligations() {
    let mut r = test_region();
    r.register_obligation("ob-1", "flush cache");
    r.register_obligation("ob-2", "release locks");
    r.commit_obligation("ob-1");
    r.commit_obligation("ob-2");
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline::default()).unwrap();
    let result = r.finalize().unwrap();
    assert!(result.success);
    assert_eq!(result.obligations_committed, 2);
    assert_eq!(result.obligations_aborted, 0);
}

#[test]
fn enrichment_full_lifecycle_with_pending_obligations_fails() {
    let mut r = test_region();
    r.register_obligation("ob-1", "stuck task");
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline::default()).unwrap();
    let result = r.finalize().unwrap();
    assert!(!result.success);
}

#[test]
fn enrichment_close_shortcut_with_no_obligations() {
    let mut r = test_region();
    let result = r
        .close(CancelReason::Quarantine, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
    assert_eq!(r.state(), RegionState::Closed);
}

#[test]
fn enrichment_close_shortcut_preserves_reason() {
    let mut r = test_region();
    r.close(CancelReason::BudgetExhausted, DrainDeadline::default())
        .unwrap();
    assert_eq!(r.cancel_reason(), Some(&CancelReason::BudgetExhausted));
}

#[test]
fn enrichment_double_close_fails() {
    let mut r = test_region();
    r.close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(
        r.close(CancelReason::Quarantine, DrainDeadline::default())
            .is_err()
    );
}

#[test]
fn enrichment_obligation_commit_nonexistent_returns_false() {
    let mut r = test_region();
    assert!(!r.commit_obligation("no-such"));
}

#[test]
fn enrichment_obligation_abort_nonexistent_returns_false() {
    let mut r = test_region();
    assert!(!r.abort_obligation("no-such"));
}

#[test]
fn enrichment_obligation_register_replaces_existing() {
    let mut r = test_region();
    r.register_obligation("ob-1", "first version");
    r.register_obligation("ob-1", "replaced version");
    assert_eq!(r.pending_obligations(), 1);
}

#[test]
fn enrichment_drain_tick_on_non_draining_returns_false() {
    let mut r = test_region();
    assert!(!r.drain_tick());
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    assert!(!r.drain_tick());
}

#[test]
fn enrichment_drain_timeout_escalation_force_aborts() {
    let mut r = test_region();
    r.register_obligation("ob-1", "slow task");
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline { max_ticks: 3 }).unwrap();
    for _ in 0..2 {
        assert!(!r.drain_tick());
    }
    assert!(r.drain_tick()); // 3rd tick => timeout
    let result = r.finalize().unwrap();
    assert!(result.drain_timeout_escalated);
    assert_eq!(result.obligations_aborted, 1);
    assert!(result.success); // force-aborted counts as resolved
}

#[test]
fn enrichment_drain_timeout_fires_only_once() {
    let mut r = test_region();
    r.register_obligation("ob-1", "slow");
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline { max_ticks: 2 }).unwrap();
    r.drain_tick();
    assert!(r.drain_tick()); // timeout fires
    let pre_count = r.event_count();
    assert!(r.drain_tick()); // still timed out
    assert_eq!(r.event_count(), pre_count); // no new escalation event
}

#[test]
fn enrichment_events_emitted_at_each_phase() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    r.drain(DrainDeadline::default()).unwrap();
    r.finalize().unwrap();
    let events = r.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].outcome, "cancel_initiated");
    assert_eq!(events[1].outcome, "drain_started");
    assert_eq!(events[2].outcome, "finalize_success");
    assert_eq!(events[3].outcome, "closed");
}

#[test]
fn enrichment_events_carry_correct_metadata() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    let events = r.drain_events();
    let event = &events[0];
    assert_eq!(event.trace_id, "trace-enrich");
    assert_eq!(event.region_id, "region-enrich");
    assert_eq!(event.region_type, "extension_cell");
    assert_eq!(event.phase, RegionState::CancelRequested);
}

#[test]
fn enrichment_drain_events_clears_after_call() {
    let mut r = test_region();
    r.cancel(CancelReason::OperatorShutdown).unwrap();
    let events1 = r.drain_events();
    assert!(!events1.is_empty());
    let events2 = r.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn enrichment_parent_cancel_cascades_to_children() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("c1", "ext", "t"));
    parent.add_child(Region::new("c2", "ext", "t"));
    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    assert_eq!(parent.state(), RegionState::CancelRequested);
}

#[test]
fn enrichment_hierarchical_close_collects_child_events() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child", "ext", "t"));
    parent
        .close(CancelReason::Quarantine, DrainDeadline::default())
        .unwrap();
    let events = parent.drain_events();
    let parent_events: Vec<_> = events.iter().filter(|e| e.region_id == "parent").collect();
    let child_events: Vec<_> = events.iter().filter(|e| e.region_id == "child").collect();
    assert!(!parent_events.is_empty());
    assert!(!child_events.is_empty());
}

#[test]
fn enrichment_multiple_children_close_independently() {
    let mut parent = Region::new("parent", "svc", "t");
    let mut c1 = Region::new("c1", "ext", "t");
    c1.register_obligation("ob-c1", "flush");
    c1.commit_obligation("ob-c1");
    let c2 = Region::new("c2", "ext", "t");
    parent.add_child(c1);
    parent.add_child(c2);
    let result = parent
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
    assert_eq!(parent.state(), RegionState::Closed);
}

#[test]
fn enrichment_deterministic_event_sequence() {
    let run = || -> Vec<RegionEvent> {
        let mut r = Region::new("r", "ext", "t");
        r.register_obligation("ob-1", "flush");
        r.cancel(CancelReason::Quarantine).unwrap();
        r.drain(DrainDeadline { max_ticks: 3 }).unwrap();
        for _ in 0..3 {
            r.drain_tick();
        }
        r.finalize().unwrap();
        r.drain_events()
    };
    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

#[test]
fn enrichment_phase_order_violation_display() {
    let v = PhaseOrderViolation {
        current_state: RegionState::Running,
        attempted_transition: "drain".to_string(),
        region_id: "r-test".to_string(),
    };
    let msg = v.to_string();
    assert!(msg.contains("phase order violation"));
    assert!(msg.contains("r-test"));
    assert!(msg.contains("drain"));
    assert!(msg.contains("running"));
}

#[test]
fn enrichment_phase_order_violation_serde_roundtrip() {
    let v = PhaseOrderViolation {
        current_state: RegionState::Draining,
        attempted_transition: "cancel".to_string(),
        region_id: "r-42".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: PhaseOrderViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_phase_order_violation_std_error() {
    let v = PhaseOrderViolation {
        current_state: RegionState::Running,
        attempted_transition: "finalize".to_string(),
        region_id: "r-err".to_string(),
    };
    let err: &dyn std::error::Error = &v;
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

#[test]
fn enrichment_obligation_status_serde_all() {
    for status in [
        ObligationStatus::Pending,
        ObligationStatus::Committed,
        ObligationStatus::Aborted,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: ObligationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn enrichment_obligation_serde_roundtrip() {
    let ob = Obligation {
        id: "ob-serde".to_string(),
        description: "test obligation".to_string(),
        status: ObligationStatus::Committed,
    };
    let json = serde_json::to_string(&ob).unwrap();
    let back: Obligation = serde_json::from_str(&json).unwrap();
    assert_eq!(ob, back);
}

#[test]
fn enrichment_drain_deadline_default() {
    let dd = DrainDeadline::default();
    assert_eq!(dd.max_ticks, 10_000);
}

#[test]
fn enrichment_drain_deadline_serde_roundtrip() {
    let dd = DrainDeadline { max_ticks: 500 };
    let json = serde_json::to_string(&dd).unwrap();
    let back: DrainDeadline = serde_json::from_str(&json).unwrap();
    assert_eq!(dd, back);
}

#[test]
fn enrichment_finalize_result_serde_roundtrip() {
    let result = FinalizeResult {
        region_id: "r-serde".to_string(),
        success: false,
        obligations_committed: 3,
        obligations_aborted: 2,
        drain_timeout_escalated: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FinalizeResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_region_event_serde_roundtrip() {
    let event = RegionEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        region_type: "ext".to_string(),
        phase: RegionState::Draining,
        outcome: "drain_started".to_string(),
        obligations_pending: 2,
        drain_elapsed_ticks: 5,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_child_count_and_add_child() {
    let mut r = test_region();
    assert_eq!(r.child_count(), 0);
    r.add_child(Region::new("c1", "ext", "t"));
    assert_eq!(r.child_count(), 1);
    r.add_child(Region::new("c2", "ext", "t"));
    assert_eq!(r.child_count(), 2);
}

#[test]
fn enrichment_event_count_tracks_own_events() {
    let mut parent = Region::new("parent", "svc", "t");
    parent.add_child(Region::new("child", "ext", "t"));
    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    // event_count only counts parent's own events
    assert_eq!(parent.event_count(), 1);
}
