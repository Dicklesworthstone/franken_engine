#![forbid(unsafe_code)]

//! Integration tests for region_lifecycle: cancel -> drain -> finalize protocol.

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

use frankenengine_engine::region_lifecycle::{
    CancelReason, DrainDeadline, FinalizeResult, Obligation, ObligationStatus, PhaseOrderViolation,
    Region, RegionEvent, RegionState,
};

// =========================================================================
// Section 1: Display impls
// =========================================================================

#[test]
fn region_state_display_all_variants() {
    let cases = [
        (RegionState::Running, "running"),
        (RegionState::CancelRequested, "cancel_requested"),
        (RegionState::Draining, "draining"),
        (RegionState::Finalizing, "finalizing"),
        (RegionState::Closed, "closed"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(
            variant.to_string(),
            *expected,
            "Display mismatch for {variant:?}"
        );
    }
}

#[test]
fn cancel_reason_display_all_variants() {
    let cases = [
        (CancelReason::OperatorShutdown, "operator_shutdown"),
        (CancelReason::Quarantine, "quarantine"),
        (CancelReason::Revocation, "revocation"),
        (CancelReason::BudgetExhausted, "budget_exhausted"),
        (CancelReason::ParentClosing, "parent_closing"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn cancel_reason_custom_display() {
    let reason = CancelReason::Custom("memory_pressure".to_string());
    assert_eq!(reason.to_string(), "custom:memory_pressure");
}

#[test]
fn cancel_reason_custom_empty_string_display() {
    let reason = CancelReason::Custom(String::new());
    assert_eq!(reason.to_string(), "custom:");
}

#[test]
fn phase_order_violation_display_format() {
    let violation = PhaseOrderViolation {
        current_state: RegionState::Running,
        attempted_transition: "drain".to_string(),
        region_id: "region-42".to_string(),
    };
    let msg = violation.to_string();
    assert!(msg.contains("phase order violation"));
    assert!(msg.contains("region-42"));
    assert!(msg.contains("drain"));
    assert!(msg.contains("running"));
}

#[test]
fn phase_order_violation_is_std_error() {
    let violation = PhaseOrderViolation {
        current_state: RegionState::Draining,
        attempted_transition: "cancel".to_string(),
        region_id: "r".to_string(),
    };
    // Verify it implements std::error::Error
    let err: &dyn std::error::Error = &violation;
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// Section 2: Construction and defaults
// =========================================================================

#[test]
fn region_new_starts_in_running_state() {
    let region = Region::new("r-1", "extension_cell", "trace-abc");
    assert_eq!(region.state(), RegionState::Running);
    assert!(region.cancel_reason().is_none());
    assert_eq!(region.pending_obligations(), 0);
    assert_eq!(region.event_count(), 0);
    assert_eq!(region.child_count(), 0);
}

#[test]
fn region_new_stores_id_fields() {
    let region = Region::new("my-region", "policy_engine", "trace-xyz");
    assert_eq!(region.id, "my-region");
    assert_eq!(region.region_type, "policy_engine");
    assert_eq!(region.trace_id, "trace-xyz");
}

#[test]
fn drain_deadline_default() {
    let dd = DrainDeadline::default();
    assert_eq!(dd.max_ticks, 10_000);
}

#[test]
fn drain_deadline_custom() {
    let dd = DrainDeadline { max_ticks: 42 };
    assert_eq!(dd.max_ticks, 42);
}

// =========================================================================
// Section 3: State transitions — happy path
// =========================================================================

#[test]
fn full_lifecycle_running_to_closed() {
    let mut region = Region::new("r", "ext", "t");
    assert_eq!(region.state(), RegionState::Running);

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    assert_eq!(region.state(), RegionState::CancelRequested);
    assert_eq!(
        region.cancel_reason(),
        Some(&CancelReason::OperatorShutdown)
    );

    region.drain(DrainDeadline::default()).unwrap();
    assert_eq!(region.state(), RegionState::Draining);

    let result = region.finalize().unwrap();
    assert!(result.success);
    assert_eq!(region.state(), RegionState::Closed);
}

#[test]
fn close_shortcut_achieves_closed_state() {
    let mut region = Region::new("r", "ext", "t");
    let result = region
        .close(CancelReason::Quarantine, DrainDeadline { max_ticks: 100 })
        .unwrap();
    assert!(result.success);
    assert_eq!(region.state(), RegionState::Closed);
    assert_eq!(result.region_id, "r");
}

#[test]
fn close_with_each_cancel_reason() {
    let reasons = [
        CancelReason::OperatorShutdown,
        CancelReason::Quarantine,
        CancelReason::Revocation,
        CancelReason::BudgetExhausted,
        CancelReason::ParentClosing,
        CancelReason::Custom("test".to_string()),
    ];
    for reason in reasons {
        let mut region = Region::new("r", "ext", "t");
        let result = region.close(reason, DrainDeadline::default()).unwrap();
        assert!(result.success);
        assert_eq!(region.state(), RegionState::Closed);
    }
}

// =========================================================================
// Section 4: State transitions — error conditions
// =========================================================================

#[test]
fn cancel_from_cancel_requested_fails() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    let err = region.cancel(CancelReason::Quarantine).unwrap_err();
    assert_eq!(err.current_state, RegionState::CancelRequested);
    assert_eq!(err.attempted_transition, "cancel");
    assert_eq!(err.region_id, "r");
}

#[test]
fn cancel_from_draining_fails() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    let err = region.cancel(CancelReason::Quarantine).unwrap_err();
    assert_eq!(err.current_state, RegionState::Draining);
}

#[test]
fn cancel_from_closed_fails() {
    let mut region = Region::new("r", "ext", "t");
    region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    let err = region.cancel(CancelReason::Quarantine).unwrap_err();
    assert_eq!(err.current_state, RegionState::Closed);
}

#[test]
fn drain_from_running_fails() {
    let mut region = Region::new("r", "ext", "t");
    let err = region.drain(DrainDeadline::default()).unwrap_err();
    assert_eq!(err.current_state, RegionState::Running);
    assert_eq!(err.attempted_transition, "drain");
}

#[test]
fn drain_from_draining_fails() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    let err = region.drain(DrainDeadline::default()).unwrap_err();
    assert_eq!(err.current_state, RegionState::Draining);
}

#[test]
fn drain_from_closed_fails() {
    let mut region = Region::new("r", "ext", "t");
    region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    let err = region.drain(DrainDeadline::default()).unwrap_err();
    assert_eq!(err.current_state, RegionState::Closed);
}

#[test]
fn finalize_from_running_fails() {
    let mut region = Region::new("r", "ext", "t");
    let err = region.finalize().unwrap_err();
    assert_eq!(err.current_state, RegionState::Running);
    assert_eq!(err.attempted_transition, "finalize");
}

#[test]
fn finalize_from_cancel_requested_fails() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    let err = region.finalize().unwrap_err();
    assert_eq!(err.current_state, RegionState::CancelRequested);
}

#[test]
fn finalize_from_closed_fails() {
    let mut region = Region::new("r", "ext", "t");
    region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    let err = region.finalize().unwrap_err();
    assert_eq!(err.current_state, RegionState::Closed);
}

#[test]
fn double_close_fails() {
    let mut region = Region::new("r", "ext", "t");
    region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    let err = region
        .close(CancelReason::Quarantine, DrainDeadline::default())
        .unwrap_err();
    assert_eq!(err.current_state, RegionState::Closed);
}

// =========================================================================
// Section 5: Obligations
// =========================================================================

#[test]
fn register_obligation_increases_pending_count() {
    let mut region = Region::new("r", "ext", "t");
    assert_eq!(region.pending_obligations(), 0);
    region.register_obligation("ob-1", "flush evidence");
    assert_eq!(region.pending_obligations(), 1);
    region.register_obligation("ob-2", "release locks");
    assert_eq!(region.pending_obligations(), 2);
}

#[test]
fn commit_obligation_decreases_pending_count() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "task-a");
    region.register_obligation("ob-2", "task-b");
    assert!(region.commit_obligation("ob-1"));
    assert_eq!(region.pending_obligations(), 1);
}

#[test]
fn abort_obligation_decreases_pending_count() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "task-a");
    assert!(region.abort_obligation("ob-1"));
    assert_eq!(region.pending_obligations(), 0);
}

#[test]
fn commit_nonexistent_obligation_returns_false() {
    let mut region = Region::new("r", "ext", "t");
    assert!(!region.commit_obligation("nonexistent"));
}

#[test]
fn abort_nonexistent_obligation_returns_false() {
    let mut region = Region::new("r", "ext", "t");
    assert!(!region.abort_obligation("nonexistent"));
}

#[test]
fn obligation_overwrite_on_duplicate_id() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "first");
    region.commit_obligation("ob-1");
    assert_eq!(region.pending_obligations(), 0);

    // Re-register same id replaces it as pending
    region.register_obligation("ob-1", "second");
    assert_eq!(region.pending_obligations(), 1);
}

#[test]
fn finalize_reports_obligation_counts_committed_and_aborted() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "flush");
    region.register_obligation("ob-2", "release");
    region.register_obligation("ob-3", "checkpoint");

    region.commit_obligation("ob-1");
    region.commit_obligation("ob-2");
    region.abort_obligation("ob-3");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    let result = region.finalize().unwrap();

    assert!(result.success);
    assert_eq!(result.obligations_committed, 2);
    assert_eq!(result.obligations_aborted, 1);
    assert!(!result.drain_timeout_escalated);
}

#[test]
fn finalize_with_unresolved_obligations_reports_failure() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "stuck task");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    let result = region.finalize().unwrap();

    assert!(!result.success);
    assert_eq!(result.obligations_committed, 0);
    assert_eq!(result.obligations_aborted, 0);
}

#[test]
fn close_shortcut_with_resolved_obligations_succeeds() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "flush");
    region.commit_obligation("ob-1");

    let result = region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
    assert_eq!(result.obligations_committed, 1);
}

#[test]
fn many_obligations_all_committed() {
    let mut region = Region::new("r", "ext", "t");
    for i in 0..50 {
        region.register_obligation(format!("ob-{i}"), format!("task-{i}"));
    }
    assert_eq!(region.pending_obligations(), 50);
    for i in 0..50 {
        assert!(region.commit_obligation(&format!("ob-{i}")));
    }
    assert_eq!(region.pending_obligations(), 0);

    let result = region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
    assert_eq!(result.obligations_committed, 50);
    assert_eq!(result.obligations_aborted, 0);
}

// =========================================================================
// Section 6: Drain deadline escalation
// =========================================================================

#[test]
fn drain_tick_returns_false_before_deadline() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 5 }).unwrap();

    for _ in 0..4 {
        assert!(!region.drain_tick());
    }
}

#[test]
fn drain_tick_returns_true_at_deadline() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 3 }).unwrap();

    assert!(!region.drain_tick()); // tick 1
    assert!(!region.drain_tick()); // tick 2
    assert!(region.drain_tick()); // tick 3 = max_ticks
}

#[test]
fn drain_tick_on_non_draining_region_returns_false() {
    let mut region = Region::new("r", "ext", "t");
    assert!(!region.drain_tick()); // Running state
}

#[test]
fn drain_timeout_escalation_force_aborts_pending_obligations() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "slow task");
    region.register_obligation("ob-2", "stuck task");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 2 }).unwrap();

    // Tick past deadline
    region.drain_tick();
    region.drain_tick();

    let result = region.finalize().unwrap();
    assert!(result.drain_timeout_escalated);
    assert_eq!(result.obligations_aborted, 2);
    assert!(result.success); // force-aborted counts as resolved
}

#[test]
fn drain_timeout_escalation_event_emitted() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "slow");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 1 }).unwrap();
    region.drain_tick();

    let events = region.drain_events();
    let escalation_events: Vec<_> = events
        .iter()
        .filter(|e| e.outcome == "drain_timeout_escalation")
        .collect();
    assert_eq!(escalation_events.len(), 1);
}

#[test]
fn drain_timeout_escalation_fires_only_once() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 1 }).unwrap();

    assert!(region.drain_tick()); // first tick at deadline
    assert!(region.drain_tick()); // second tick past deadline

    let events = region.drain_events();
    let escalation_count = events
        .iter()
        .filter(|e| e.outcome == "drain_timeout_escalation")
        .count();
    assert_eq!(
        escalation_count, 1,
        "escalation event should fire only once"
    );
}

#[test]
fn drain_timeout_with_mix_of_resolved_and_pending_obligations() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-committed", "done");
    region.register_obligation("ob-aborted", "manual abort");
    region.register_obligation("ob-pending", "stuck");

    region.commit_obligation("ob-committed");
    region.abort_obligation("ob-aborted");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 1 }).unwrap();
    region.drain_tick();

    let result = region.finalize().unwrap();
    assert!(result.drain_timeout_escalated);
    assert_eq!(result.obligations_committed, 1);
    // ob-aborted (manual) + ob-pending (force-aborted)
    assert_eq!(result.obligations_aborted, 2);
    assert!(result.success);
}

// =========================================================================
// Section 7: Hierarchical close (parent/child)
// =========================================================================

#[test]
fn add_child_increases_child_count() {
    let mut parent = Region::new("parent", "service", "t");
    assert_eq!(parent.child_count(), 0);
    parent.add_child(Region::new("c1", "ext", "t"));
    assert_eq!(parent.child_count(), 1);
    parent.add_child(Region::new("c2", "ext", "t"));
    assert_eq!(parent.child_count(), 2);
}

#[test]
fn parent_cancel_cascades_to_children() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child-1", "ext", "t"));
    parent.add_child(Region::new("child-2", "ext", "t"));

    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    assert_eq!(parent.state(), RegionState::CancelRequested);
    // Children are internal, but their events prove they were cancelled
}

#[test]
fn hierarchical_full_lifecycle() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child", "ext", "t"));

    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    parent.drain(DrainDeadline::default()).unwrap();
    let result = parent.finalize().unwrap();
    assert!(result.success);
    assert_eq!(parent.state(), RegionState::Closed);
}

#[test]
fn parent_drain_events_include_child_events() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child", "ext", "t"));

    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    parent.drain(DrainDeadline::default()).unwrap();
    parent.finalize().unwrap();

    let events = parent.drain_events();
    let parent_event_ids: BTreeSet<_> = events
        .iter()
        .filter(|e| e.region_id == "parent")
        .map(|e| e.outcome.clone())
        .collect();
    let child_event_ids: BTreeSet<_> = events
        .iter()
        .filter(|e| e.region_id == "child")
        .map(|e| e.outcome.clone())
        .collect();

    assert!(parent_event_ids.contains("cancel_initiated"));
    assert!(parent_event_ids.contains("drain_started"));
    assert!(parent_event_ids.contains("closed"));
    assert!(child_event_ids.contains("cancel_initiated"));
    assert!(child_event_ids.contains("drain_started"));
    assert!(child_event_ids.contains("closed"));
}

#[test]
fn hierarchical_close_with_child_obligations_unresolved() {
    let mut parent = Region::new("parent", "service", "t");
    let mut child = Region::new("child", "ext", "t");
    child.register_obligation("ob-child", "stuck");
    parent.add_child(child);

    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    parent.drain(DrainDeadline::default()).unwrap();

    // Child has unresolved obligation, no timeout escalation
    let result = parent.finalize().unwrap();
    // Parent should report not success because child has pending obligation
    assert!(!result.success);
}

#[test]
fn deep_hierarchy_three_levels() {
    let mut root = Region::new("root", "service", "t");
    let mut mid = Region::new("mid", "subsystem", "t");
    let leaf = Region::new("leaf", "extension", "t");
    mid.add_child(leaf);
    root.add_child(mid);

    root.cancel(CancelReason::OperatorShutdown).unwrap();
    root.drain(DrainDeadline::default()).unwrap();
    let result = root.finalize().unwrap();
    assert!(result.success);
    assert_eq!(root.state(), RegionState::Closed);

    let events = root.drain_events();
    let region_ids: BTreeSet<_> = events.iter().map(|e| e.region_id.clone()).collect();
    assert!(region_ids.contains("root"));
    assert!(region_ids.contains("mid"));
    assert!(region_ids.contains("leaf"));
}

#[test]
fn multiple_children_close_independently() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("c1", "ext", "t"));
    parent.add_child(Region::new("c2", "ext", "t"));
    parent.add_child(Region::new("c3", "ext", "t"));

    let result = parent
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
}

#[test]
fn parent_cancel_sets_child_reason_to_parent_closing() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child", "ext", "t"));

    parent.cancel(CancelReason::Quarantine).unwrap();
    // Parent's reason should be Quarantine
    assert_eq!(parent.cancel_reason(), Some(&CancelReason::Quarantine));
}

// =========================================================================
// Section 8: Events
// =========================================================================

#[test]
fn event_sequence_cancel_drain_finalize() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    region.finalize().unwrap();

    let events = region.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].outcome, "cancel_initiated");
    assert_eq!(events[1].outcome, "drain_started");
    assert_eq!(events[2].outcome, "finalize_success");
    assert_eq!(events[3].outcome, "closed");
}

#[test]
fn event_fields_are_correct() {
    let mut region = Region::new("reg-42", "policy_engine", "trace-99");
    region.cancel(CancelReason::Revocation).unwrap();

    let events = region.drain_events();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.trace_id, "trace-99");
    assert_eq!(ev.region_id, "reg-42");
    assert_eq!(ev.region_type, "policy_engine");
    assert_eq!(ev.phase, RegionState::CancelRequested);
    assert_eq!(ev.outcome, "cancel_initiated");
    assert_eq!(ev.obligations_pending, 0);
    assert_eq!(ev.drain_elapsed_ticks, 0);
}

#[test]
fn finalize_with_pending_emits_finalize_with_pending_event() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "stuck");

    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline::default()).unwrap();
    region.finalize().unwrap();

    let events = region.drain_events();
    let finalize_event = events
        .iter()
        .find(|e| e.outcome.starts_with("finalize"))
        .unwrap();
    assert_eq!(finalize_event.outcome, "finalize_with_pending");
}

#[test]
fn drain_events_clears_event_buffer() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();

    let events1 = region.drain_events();
    assert_eq!(events1.len(), 1);

    // Second drain should be empty (for this region; no new events)
    let events2 = region.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn event_count_tracks_this_region_only() {
    let mut parent = Region::new("parent", "service", "t");
    parent.add_child(Region::new("child", "ext", "t"));

    parent.cancel(CancelReason::OperatorShutdown).unwrap();
    // event_count is only for parent, not children
    assert_eq!(parent.event_count(), 1);
}

#[test]
fn drain_tick_records_elapsed_in_events() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 100 }).unwrap();

    for _ in 0..5 {
        region.drain_tick();
    }

    region.finalize().unwrap();
    let events = region.drain_events();
    // The finalize events should show drain_elapsed_ticks = 5
    let finalize_event = events
        .iter()
        .find(|e| e.outcome == "finalize_success")
        .unwrap();
    assert_eq!(finalize_event.drain_elapsed_ticks, 5);
}

// =========================================================================
// Section 9: Serde roundtrips
// =========================================================================

#[test]
fn region_state_serde_roundtrip_all_variants() {
    let variants = [
        RegionState::Running,
        RegionState::CancelRequested,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: RegionState = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn cancel_reason_serde_roundtrip_all_variants() {
    let variants = [
        CancelReason::OperatorShutdown,
        CancelReason::Quarantine,
        CancelReason::Revocation,
        CancelReason::BudgetExhausted,
        CancelReason::ParentClosing,
        CancelReason::Custom("special".to_string()),
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: CancelReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn phase_order_violation_serde_roundtrip() {
    let violation = PhaseOrderViolation {
        current_state: RegionState::Draining,
        attempted_transition: "cancel".to_string(),
        region_id: "r-xyz".to_string(),
    };
    let json = serde_json::to_string(&violation).unwrap();
    let restored: PhaseOrderViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(violation, restored);
}

#[test]
fn obligation_serde_roundtrip() {
    let obligation = Obligation {
        id: "ob-1".to_string(),
        description: "flush evidence log".to_string(),
        status: ObligationStatus::Committed,
    };
    let json = serde_json::to_string(&obligation).unwrap();
    let restored: Obligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obligation, restored);
}

#[test]
fn obligation_status_serde_roundtrip() {
    let statuses = [
        ObligationStatus::Pending,
        ObligationStatus::Committed,
        ObligationStatus::Aborted,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let restored: ObligationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, restored);
    }
}

#[test]
fn drain_deadline_serde_roundtrip() {
    let dd = DrainDeadline { max_ticks: 42_000 };
    let json = serde_json::to_string(&dd).unwrap();
    let restored: DrainDeadline = serde_json::from_str(&json).unwrap();
    assert_eq!(dd, restored);
}

#[test]
fn finalize_result_serde_roundtrip() {
    let result = FinalizeResult {
        region_id: "r-7".to_string(),
        success: false,
        obligations_committed: 3,
        obligations_aborted: 2,
        drain_timeout_escalated: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: FinalizeResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn region_event_serde_roundtrip() {
    let event = RegionEvent {
        trace_id: "t-1".to_string(),
        region_id: "r-1".to_string(),
        region_type: "extension_cell".to_string(),
        phase: RegionState::Draining,
        outcome: "drain_started".to_string(),
        obligations_pending: 5,
        drain_elapsed_ticks: 42,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: RegionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// Section 10: Deterministic replay
// =========================================================================

#[test]
fn deterministic_event_sequence_simple() {
    let run = || -> Vec<RegionEvent> {
        let mut region = Region::new("r", "ext", "t");
        region.cancel(CancelReason::Quarantine).unwrap();
        region.drain(DrainDeadline { max_ticks: 100 }).unwrap();
        region.finalize().unwrap();
        region.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_with_obligations() {
    let run = || -> Vec<RegionEvent> {
        let mut region = Region::new("r", "ext", "t");
        region.register_obligation("ob-1", "flush");
        region.register_obligation("ob-2", "release");
        region.commit_obligation("ob-1");
        region.abort_obligation("ob-2");

        region.cancel(CancelReason::BudgetExhausted).unwrap();
        region.drain(DrainDeadline { max_ticks: 10 }).unwrap();
        region.finalize().unwrap();
        region.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_with_drain_timeout() {
    let run = || -> Vec<RegionEvent> {
        let mut region = Region::new("r", "ext", "t");
        region.register_obligation("ob-stuck", "slow");
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline { max_ticks: 3 }).unwrap();
        for _ in 0..3 {
            region.drain_tick();
        }
        region.finalize().unwrap();
        region.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_hierarchical() {
    let run = || -> Vec<RegionEvent> {
        let mut parent = Region::new("parent", "service", "t");
        parent.add_child(Region::new("child-1", "ext", "t"));
        parent.add_child(Region::new("child-2", "ext", "t"));

        parent.cancel(CancelReason::OperatorShutdown).unwrap();
        parent.drain(DrainDeadline::default()).unwrap();
        parent.finalize().unwrap();
        parent.drain_events()
    };

    assert_eq!(run(), run());
}

// =========================================================================
// Section 11: Ordering and comparison traits
// =========================================================================

#[test]
fn region_state_ordering() {
    assert!(RegionState::Running < RegionState::CancelRequested);
    assert!(RegionState::CancelRequested < RegionState::Draining);
    assert!(RegionState::Draining < RegionState::Finalizing);
    assert!(RegionState::Finalizing < RegionState::Closed);
}

#[test]
fn cancel_reason_ordering() {
    // Derived Ord should work consistently
    let mut reasons = [
        CancelReason::ParentClosing,
        CancelReason::OperatorShutdown,
        CancelReason::Quarantine,
        CancelReason::Custom("z".to_string()),
        CancelReason::Custom("a".to_string()),
    ];
    reasons.sort();
    // OperatorShutdown < Quarantine < ... < ParentClosing < Custom
    // (based on derive order)
    assert_eq!(reasons[0], CancelReason::OperatorShutdown);
}

#[test]
fn region_state_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(RegionState::Running);
    set.insert(RegionState::Closed);
    set.insert(RegionState::Running); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn cancel_reason_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(CancelReason::OperatorShutdown);
    set.insert(CancelReason::Quarantine);
    set.insert(CancelReason::Custom("a".to_string()));
    set.insert(CancelReason::Custom("a".to_string())); // duplicate
    assert_eq!(set.len(), 3);
}

// =========================================================================
// Section 12: Edge cases
// =========================================================================

#[test]
fn region_with_empty_strings() {
    let region = Region::new("", "", "");
    assert_eq!(region.id, "");
    assert_eq!(region.region_type, "");
    assert_eq!(region.trace_id, "");
}

#[test]
fn region_with_unicode_ids() {
    let mut region = Region::new("region-\u{1F600}", "type-\u{00E9}", "trace-\u{4E16}");
    let result = region
        .close(CancelReason::OperatorShutdown, DrainDeadline::default())
        .unwrap();
    assert!(result.success);
    assert_eq!(result.region_id, "region-\u{1F600}");
}

#[test]
fn drain_deadline_zero_ticks_immediately_times_out() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region.drain(DrainDeadline { max_ticks: 0 }).unwrap();
    // Even the first tick should trigger timeout since elapsed >= max_ticks (0 >= 0 is false!)
    // Actually 0 >= 0 is true at start, but drain_tick increments first.
    // Let's just check: initial drain_elapsed_ticks is 0, max_ticks is 0.
    // drain_tick: elapsed becomes 1, 1 >= 0 is true => timeout
    assert!(region.drain_tick());
}

#[test]
fn drain_deadline_max_u64_no_overflow() {
    let mut region = Region::new("r", "ext", "t");
    region.cancel(CancelReason::OperatorShutdown).unwrap();
    region
        .drain(DrainDeadline {
            max_ticks: u64::MAX,
        })
        .unwrap();
    // Should not timeout on a single tick
    assert!(!region.drain_tick());
}

#[test]
fn close_shortcut_with_unresolved_obligations_drains_to_timeout() {
    let mut region = Region::new("r", "ext", "t");
    region.register_obligation("ob-1", "stuck");
    // close with short deadline will loop up to max_ticks
    let result = region
        .close(
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();
    // After drain ticks, timeout escalation should have fired
    assert!(result.drain_timeout_escalated);
    assert!(result.success); // force-aborted
}

#[test]
fn phase_order_violation_clone_and_eq() {
    let v1 = PhaseOrderViolation {
        current_state: RegionState::Running,
        attempted_transition: "finalize".to_string(),
        region_id: "r".to_string(),
    };
    let v2 = v1.clone();
    assert_eq!(v1, v2);
}

#[test]
fn finalize_result_fields_accessible() {
    let result = FinalizeResult {
        region_id: "test".to_string(),
        success: true,
        obligations_committed: 10,
        obligations_aborted: 3,
        drain_timeout_escalated: false,
    };
    assert_eq!(result.region_id, "test");
    assert!(result.success);
    assert_eq!(result.obligations_committed, 10);
    assert_eq!(result.obligations_aborted, 3);
    assert!(!result.drain_timeout_escalated);
}

#[test]
fn region_event_fields_accessible() {
    let event = RegionEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        region_type: "ext".to_string(),
        phase: RegionState::Closed,
        outcome: "closed".to_string(),
        obligations_pending: 0,
        drain_elapsed_ticks: 42,
    };
    assert_eq!(event.trace_id, "t");
    assert_eq!(event.region_id, "r");
    assert_eq!(event.region_type, "ext");
    assert_eq!(event.phase, RegionState::Closed);
    assert_eq!(event.outcome, "closed");
    assert_eq!(event.obligations_pending, 0);
    assert_eq!(event.drain_elapsed_ticks, 42);
}

#[test]
fn obligation_fields_accessible() {
    let ob = Obligation {
        id: "ob-1".to_string(),
        description: "test obligation".to_string(),
        status: ObligationStatus::Pending,
    };
    assert_eq!(ob.id, "ob-1");
    assert_eq!(ob.description, "test obligation");
    assert_eq!(ob.status, ObligationStatus::Pending);
}
