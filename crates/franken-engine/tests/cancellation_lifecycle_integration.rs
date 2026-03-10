#![forbid(unsafe_code)]

//! Integration tests for the `cancellation_lifecycle` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! all five lifecycle events (unload, quarantine, suspend, terminate,
//! revocation), the three-phase cancellation protocol (request, drain,
//! finalize), idempotency, mode overrides, evidence emission, error
//! paths, serde round-trips, Display impls, and determinism guarantees.

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

use frankenengine_engine::cancellation_lifecycle::{
    CancellationError, CancellationEvent, CancellationManager, CancellationMode,
    CancellationOutcome, LifecycleEvent,
};
use frankenengine_engine::control_plane::ContextAdapter;
use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::execution_cell::{CellError, CellKind, CellManager, ExecutionCell};
use frankenengine_engine::region_lifecycle::{CancelReason, FinalizeResult, RegionState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(budget_ms))
}

const ALL_EVENTS: [LifecycleEvent; 5] = [
    LifecycleEvent::Unload,
    LifecycleEvent::Quarantine,
    LifecycleEvent::Suspend,
    LifecycleEvent::Terminate,
    LifecycleEvent::Revocation,
];

// ===========================================================================
// Section 1: LifecycleEvent enum — Display, serde, ordering, classification
// ===========================================================================

#[test]
fn lifecycle_event_display_all_variants() {
    assert_eq!(LifecycleEvent::Unload.to_string(), "unload");
    assert_eq!(LifecycleEvent::Quarantine.to_string(), "quarantine");
    assert_eq!(LifecycleEvent::Suspend.to_string(), "suspend");
    assert_eq!(LifecycleEvent::Terminate.to_string(), "terminate");
    assert_eq!(LifecycleEvent::Revocation.to_string(), "revocation");
}

#[test]
fn lifecycle_event_display_is_lowercase() {
    for event in ALL_EVENTS {
        let display = event.to_string();
        assert_eq!(
            display,
            display.to_lowercase(),
            "Display for {event:?} must be lowercase"
        );
    }
}

#[test]
fn lifecycle_event_serde_roundtrip_all_variants() {
    for event in ALL_EVENTS {
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LifecycleEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored, "serde roundtrip failed for {event:?}");
    }
}

#[test]
fn lifecycle_event_cancel_reason_mapping() {
    assert_eq!(
        LifecycleEvent::Unload.cancel_reason(),
        CancelReason::OperatorShutdown
    );
    assert_eq!(
        LifecycleEvent::Quarantine.cancel_reason(),
        CancelReason::Quarantine
    );
    assert_eq!(
        LifecycleEvent::Suspend.cancel_reason(),
        CancelReason::Custom("suspend".to_string())
    );
    assert_eq!(
        LifecycleEvent::Terminate.cancel_reason(),
        CancelReason::Custom("terminate".to_string())
    );
    assert_eq!(
        LifecycleEvent::Revocation.cancel_reason(),
        CancelReason::Revocation
    );
}

#[test]
fn lifecycle_event_is_forced_only_terminate() {
    for event in ALL_EVENTS {
        if event == LifecycleEvent::Terminate {
            assert!(event.is_forced(), "Terminate must be forced");
        } else {
            assert!(!event.is_forced(), "{event:?} must NOT be forced");
        }
    }
}

#[test]
fn lifecycle_event_is_cooperative_only_unload_and_suspend() {
    for event in ALL_EVENTS {
        let expected = matches!(event, LifecycleEvent::Unload | LifecycleEvent::Suspend);
        assert_eq!(
            event.is_cooperative(),
            expected,
            "{event:?} cooperative mismatch"
        );
    }
}

#[test]
fn lifecycle_event_is_forced_and_cooperative_mutually_exclusive() {
    for event in ALL_EVENTS {
        // An event cannot be both forced and cooperative
        assert!(
            !(event.is_forced() && event.is_cooperative()),
            "{event:?} must not be both forced and cooperative"
        );
    }
}

#[test]
fn lifecycle_event_ordering_is_declaration_order() {
    assert!(LifecycleEvent::Unload < LifecycleEvent::Quarantine);
    assert!(LifecycleEvent::Quarantine < LifecycleEvent::Suspend);
    assert!(LifecycleEvent::Suspend < LifecycleEvent::Terminate);
    assert!(LifecycleEvent::Terminate < LifecycleEvent::Revocation);
}

#[test]
fn lifecycle_event_clone_and_copy() {
    let event = LifecycleEvent::Quarantine;
    let cloned = event;
    let copied = event;
    assert_eq!(event, cloned);
    assert_eq!(event, copied);
}

#[test]
fn lifecycle_event_debug_format_is_non_empty() {
    for event in ALL_EVENTS {
        let debug = format!("{event:?}");
        assert!(!debug.is_empty());
    }
}

// ===========================================================================
// Section 2: CancellationMode — per-event defaults, serde, field values
// ===========================================================================

#[test]
fn cancellation_mode_for_unload_defaults() {
    let mode = CancellationMode::for_event(LifecycleEvent::Unload);
    assert_eq!(mode.drain_budget_ticks, 10_000);
    assert!(mode.force_abort_on_timeout);
    assert!(mode.propagate_to_children);
    assert_eq!(mode.evidence_event_name, "cancellation_unload");
}

#[test]
fn cancellation_mode_for_quarantine_defaults() {
    let mode = CancellationMode::for_event(LifecycleEvent::Quarantine);
    assert_eq!(mode.drain_budget_ticks, 1_000);
    assert!(mode.force_abort_on_timeout);
    assert!(mode.propagate_to_children);
    assert_eq!(mode.evidence_event_name, "cancellation_quarantine");
}

#[test]
fn cancellation_mode_for_suspend_defaults() {
    let mode = CancellationMode::for_event(LifecycleEvent::Suspend);
    assert_eq!(mode.drain_budget_ticks, 5_000);
    assert!(!mode.force_abort_on_timeout);
    assert!(!mode.propagate_to_children);
    assert_eq!(mode.evidence_event_name, "cancellation_suspend");
}

#[test]
fn cancellation_mode_for_terminate_defaults() {
    let mode = CancellationMode::for_event(LifecycleEvent::Terminate);
    assert_eq!(mode.drain_budget_ticks, 0);
    assert!(mode.force_abort_on_timeout);
    assert!(mode.propagate_to_children);
    assert_eq!(mode.evidence_event_name, "cancellation_terminate");
}

#[test]
fn cancellation_mode_for_revocation_defaults() {
    let mode = CancellationMode::for_event(LifecycleEvent::Revocation);
    assert_eq!(mode.drain_budget_ticks, 500);
    assert!(mode.force_abort_on_timeout);
    assert!(mode.propagate_to_children);
    assert_eq!(mode.evidence_event_name, "cancellation_revocation");
}

#[test]
fn cancellation_mode_serde_roundtrip_all_events() {
    for event in ALL_EVENTS {
        let mode = CancellationMode::for_event(event);
        let json = serde_json::to_string(&mode).expect("serialize");
        let restored: CancellationMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, restored, "serde roundtrip failed for {event:?} mode");
    }
}

#[test]
fn cancellation_mode_evidence_event_names_are_unique() {
    let names: BTreeSet<String> = ALL_EVENTS
        .iter()
        .map(|e| CancellationMode::for_event(*e).evidence_event_name)
        .collect();
    assert_eq!(names.len(), ALL_EVENTS.len());
}

#[test]
fn cancellation_mode_evidence_event_names_start_with_cancellation() {
    for event in ALL_EVENTS {
        let mode = CancellationMode::for_event(event);
        assert!(
            mode.evidence_event_name.starts_with("cancellation_"),
            "event name for {event:?} must start with 'cancellation_'"
        );
    }
}

#[test]
fn cancellation_mode_terminate_has_zero_drain() {
    let mode = CancellationMode::for_event(LifecycleEvent::Terminate);
    assert_eq!(
        mode.drain_budget_ticks, 0,
        "terminate mode must have zero drain ticks for immediate finalize"
    );
}

// ===========================================================================
// Section 3: CancellationError — Display, error_code, serde, From<CellError>
// ===========================================================================

#[test]
fn cancellation_error_cell_not_found_display() {
    let err = CancellationError::CellNotFound {
        cell_id: "ext-99".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("cell not found"));
    assert!(msg.contains("ext-99"));
}

#[test]
fn cancellation_error_budget_exhausted_display() {
    let err = CancellationError::BudgetExhausted {
        cell_id: "ext-1".to_string(),
        event: LifecycleEvent::Quarantine,
    };
    let msg = err.to_string();
    assert!(msg.contains("budget exhausted"));
    assert!(msg.contains("ext-1"));
    assert!(msg.contains("quarantine"));
}

#[test]
fn cancellation_error_cell_error_display() {
    let err = CancellationError::CellError {
        cell_id: "ext-2".to_string(),
        error_code: "cell_invalid_state".to_string(),
        message: "cannot close from running".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-2"));
    assert!(msg.contains("cell_invalid_state"));
    assert!(msg.contains("cannot close from running"));
}

#[test]
fn cancellation_error_error_codes_are_unique() {
    let errors = [
        CancellationError::CellNotFound {
            cell_id: "c".to_string(),
        },
        CancellationError::BudgetExhausted {
            cell_id: "c".to_string(),
            event: LifecycleEvent::Unload,
        },
        CancellationError::CellError {
            cell_id: "c".to_string(),
            error_code: "x".to_string(),
            message: "m".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), errors.len());
}

#[test]
fn cancellation_error_error_codes_stable() {
    assert_eq!(
        CancellationError::CellNotFound {
            cell_id: "x".to_string()
        }
        .error_code(),
        "cancel_cell_not_found"
    );
    assert_eq!(
        CancellationError::BudgetExhausted {
            cell_id: "x".to_string(),
            event: LifecycleEvent::Terminate
        }
        .error_code(),
        "cancel_budget_exhausted"
    );
    assert_eq!(
        CancellationError::CellError {
            cell_id: "x".to_string(),
            error_code: "y".to_string(),
            message: "m".to_string()
        }
        .error_code(),
        "cancel_cell_error"
    );
}

#[test]
fn cancellation_error_serde_roundtrip_all_variants() {
    let errors = vec![
        CancellationError::CellNotFound {
            cell_id: "c1".to_string(),
        },
        CancellationError::BudgetExhausted {
            cell_id: "c2".to_string(),
            event: LifecycleEvent::Revocation,
        },
        CancellationError::CellError {
            cell_id: "c3".to_string(),
            error_code: "cell_invalid_state".to_string(),
            message: "test message".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: CancellationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn cancellation_error_from_cell_error_cell_not_found() {
    let cell_err = CellError::CellNotFound {
        cell_id: "cell-abc".to_string(),
    };
    let cancel_err: CancellationError = cell_err.into();
    assert_eq!(cancel_err.error_code(), "cancel_cell_error");
    if let CancellationError::CellError {
        cell_id, message, ..
    } = &cancel_err
    {
        assert_eq!(cell_id, "cell-abc");
        assert!(!message.is_empty());
    } else {
        panic!("expected CellError variant");
    }
}

#[test]
fn cancellation_error_from_cell_error_budget_exhausted() {
    let cell_err = CellError::BudgetExhausted {
        cell_id: "cell-xyz".to_string(),
        requested_ms: 100,
        remaining_ms: 0,
    };
    let cancel_err: CancellationError = cell_err.into();
    if let CancellationError::CellError { cell_id, .. } = &cancel_err {
        assert_eq!(cell_id, "cell-xyz");
    } else {
        panic!("expected CellError variant");
    }
}

#[test]
fn cancellation_error_is_std_error() {
    let err = CancellationError::CellNotFound {
        cell_id: "c".to_string(),
    };
    // Verify it implements std::error::Error
    let _dyn_err: &dyn std::error::Error = &err;
}

// ===========================================================================
// Section 4: CancellationEvent — construction, serde
// ===========================================================================

#[test]
fn cancellation_event_serde_roundtrip() {
    let event = CancellationEvent {
        trace_id: "trace-42".to_string(),
        cell_id: "ext-7".to_string(),
        cell_kind: CellKind::Extension,
        lifecycle_event: LifecycleEvent::Quarantine,
        phase: "drain".to_string(),
        outcome: "completed".to_string(),
        component: "cancellation_lifecycle".to_string(),
        obligations_pending: 3,
        budget_consumed_ms: 10,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: CancellationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn cancellation_event_fields_round_trip_json_preserves_all() {
    let event = CancellationEvent {
        trace_id: "t".to_string(),
        cell_id: "c".to_string(),
        cell_kind: CellKind::Delegate,
        lifecycle_event: LifecycleEvent::Revocation,
        phase: "finalize".to_string(),
        outcome: "success".to_string(),
        component: "cancellation_lifecycle".to_string(),
        obligations_pending: 0,
        budget_consumed_ms: 999,
    };
    let json = serde_json::to_string(&event).unwrap();
    // All key fields present in JSON
    assert!(json.contains("trace_id"));
    assert!(json.contains("cell_id"));
    assert!(json.contains("lifecycle_event"));
    assert!(json.contains("phase"));
    assert!(json.contains("outcome"));
    assert!(json.contains("obligations_pending"));
    assert!(json.contains("budget_consumed_ms"));
}

// ===========================================================================
// Section 5: CancellationOutcome — serde
// ===========================================================================

#[test]
fn cancellation_outcome_serde_roundtrip() {
    let outcome = CancellationOutcome {
        cell_id: "ext-1".to_string(),
        event: LifecycleEvent::Unload,
        success: true,
        finalize_result: FinalizeResult {
            region_id: "ext-1".to_string(),
            success: true,
            obligations_committed: 2,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        },
        timeout_escalated: false,
        children_cancelled: 0,
        was_idempotent: false,
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let restored: CancellationOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(outcome, restored);
}

#[test]
fn cancellation_outcome_serde_roundtrip_with_timeout_escalation() {
    let outcome = CancellationOutcome {
        cell_id: "ext-2".to_string(),
        event: LifecycleEvent::Quarantine,
        success: true,
        finalize_result: FinalizeResult {
            region_id: "ext-2".to_string(),
            success: false,
            obligations_committed: 0,
            obligations_aborted: 3,
            drain_timeout_escalated: true,
        },
        timeout_escalated: true,
        children_cancelled: 0,
        was_idempotent: false,
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let restored: CancellationOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(outcome, restored);
}

#[test]
fn cancellation_outcome_serde_roundtrip_idempotent() {
    let outcome = CancellationOutcome {
        cell_id: "ext-3".to_string(),
        event: LifecycleEvent::Terminate,
        success: true,
        finalize_result: FinalizeResult {
            region_id: "ext-3".to_string(),
            success: true,
            obligations_committed: 0,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        },
        timeout_escalated: false,
        children_cancelled: 0,
        was_idempotent: true,
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let restored: CancellationOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(outcome, restored);
    assert!(restored.was_idempotent);
}

// ===========================================================================
// Section 6: CancellationManager — basic cancel_cell for each event type
// ===========================================================================

#[test]
fn cancel_cell_unload_clean_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel should succeed");

    assert!(outcome.success);
    assert!(!outcome.was_idempotent);
    assert!(!outcome.timeout_escalated);
    assert_eq!(outcome.event, LifecycleEvent::Unload);
    assert_eq!(outcome.cell_id, "ext-1");
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_cell_quarantine_clean_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel");

    assert!(outcome.success);
    assert_eq!(outcome.event, LifecycleEvent::Quarantine);
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_cell_suspend_clean_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Suspend)
        .expect("cancel");

    assert!(outcome.success);
    assert_eq!(outcome.event, LifecycleEvent::Suspend);
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_cell_terminate_immediate_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
        .expect("cancel");

    assert!(outcome.success);
    assert_eq!(outcome.event, LifecycleEvent::Terminate);
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_cell_revocation_clean_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Revocation)
        .expect("cancel");

    assert!(outcome.success);
    assert_eq!(outcome.event, LifecycleEvent::Revocation);
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_cell_all_events_leave_cell_closed() {
    for event in ALL_EVENTS {
        let mut cell = ExecutionCell::new(format!("ext-{event}"), CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, event)
            .unwrap_or_else(|e| panic!("cancel failed for {event}: {e}"));

        assert_eq!(
            cell.state(),
            RegionState::Closed,
            "cell must be Closed after {event}"
        );
    }
}

// ===========================================================================
// Section 7: CancellationManager — different cell kinds
// ===========================================================================

#[test]
fn cancel_delegate_cell() {
    let mut cell = ExecutionCell::new("del-1", CellKind::Delegate, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel delegate");

    assert!(outcome.success);
    assert_eq!(cell.state(), RegionState::Closed);
}

#[test]
fn cancel_session_cell() {
    let mut cell = ExecutionCell::new("sess-1", CellKind::Session, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel session");

    assert!(outcome.success);
    assert_eq!(cell.state(), RegionState::Closed);
}

// ===========================================================================
// Section 8: Idempotency
// ===========================================================================

#[test]
fn cancel_idempotent_on_already_closed_cell() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(200);
    let mut mgr = CancellationManager::new();

    // First cancel
    let first = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("first cancel");
    assert!(!first.was_idempotent);

    // Second cancel: idempotent
    let second = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("second cancel");
    assert!(second.was_idempotent);
    assert!(second.success);
    assert_eq!(second.children_cancelled, 0);
    assert!(!second.timeout_escalated);
}

#[test]
fn cancel_idempotent_with_different_event() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(200);
    let mut mgr = CancellationManager::new();

    // First cancel with quarantine
    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("first");

    // Second cancel with terminate: still idempotent (cell already closed)
    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
        .expect("second");
    assert!(outcome.was_idempotent);
}

#[test]
fn idempotent_cancel_increments_outcome_count() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(200);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("first");
    assert_eq!(mgr.outcome_count(), 1);

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("second");
    assert_eq!(mgr.outcome_count(), 2);

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("third");
    assert_eq!(mgr.outcome_count(), 3);
}

// ===========================================================================
// Section 9: Obligations — committed, pending, timeout escalation
// ===========================================================================

#[test]
fn cancel_with_committed_obligations_no_timeout() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-1", "flush evidence");
    cell.commit_obligation("ob-1").expect("commit");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    assert!(outcome.success);
    assert!(!outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_committed, 1);
    assert_eq!(outcome.finalize_result.obligations_aborted, 0);
}

#[test]
fn cancel_with_pending_obligations_causes_timeout_escalation() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-slow", "never finishes");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel");

    assert!(outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_aborted, 1);
    assert!(outcome.finalize_result.drain_timeout_escalated);
}

#[test]
fn terminate_with_pending_obligations_force_aborts() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-1", "in progress");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
        .expect("terminate");

    assert!(outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_aborted, 1);
}

#[test]
fn revocation_with_multiple_pending_obligations() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-1", "revoked cap op");
    cell.register_obligation("ob-2", "another op");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Revocation)
        .expect("revocation");

    assert!(outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_aborted, 2);
}

#[test]
fn cancel_with_mix_of_committed_and_pending_obligations() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-done", "completed work");
    cell.commit_obligation("ob-done").expect("commit");
    cell.register_obligation("ob-pending", "incomplete work");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    // One committed, one force-aborted
    assert_eq!(outcome.finalize_result.obligations_committed, 1);
    assert_eq!(outcome.finalize_result.obligations_aborted, 1);
    assert!(outcome.timeout_escalated);
}

#[test]
fn cancel_with_aborted_obligation_no_pending() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-abort", "will abort");
    cell.abort_obligation("ob-abort").expect("abort");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    assert!(!outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_aborted, 1);
}

// ===========================================================================
// Section 10: Budget exhaustion
// ===========================================================================

#[test]
fn cancel_with_zero_budget_returns_budget_error() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(0);
    let mut mgr = CancellationManager::new();

    let err = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .unwrap_err();
    assert_eq!(err.error_code(), "cancel_budget_exhausted");
}

#[test]
fn cancel_budget_exhaustion_preserves_cell_id_in_error() {
    let mut cell = ExecutionCell::new("special-ext", CellKind::Extension, "t");
    let mut cx = mock_cx(0);
    let mut mgr = CancellationManager::new();

    let err = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .unwrap_err();

    if let CancellationError::BudgetExhausted { cell_id, event } = &err {
        assert_eq!(cell_id, "special-ext");
        assert_eq!(*event, LifecycleEvent::Quarantine);
    } else {
        panic!("expected BudgetExhausted, got {err:?}");
    }
}

// ===========================================================================
// Section 11: CancellationManager — managed cells via CellManager
// ===========================================================================

#[test]
fn cancel_managed_cell_success() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-1", "t1");
    let mut cx = mock_cx(200);
    let mut cancel_mgr = CancellationManager::new();

    let outcome = cancel_mgr
        .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Unload)
        .expect("cancel managed cell");

    assert!(outcome.success);
    assert_eq!(outcome.cell_id, "ext-1");
}

#[test]
fn cancel_managed_cell_not_found_returns_error() {
    let mut cell_mgr = CellManager::new();
    let mut cx = mock_cx(100);
    let mut cancel_mgr = CancellationManager::new();

    let err = cancel_mgr
        .cancel_managed_cell(
            &mut cell_mgr,
            "nonexistent",
            &mut cx,
            LifecycleEvent::Unload,
        )
        .unwrap_err();

    assert_eq!(err.error_code(), "cancel_cell_not_found");
    if let CancellationError::CellNotFound { cell_id } = &err {
        assert_eq!(cell_id, "nonexistent");
    } else {
        panic!("expected CellNotFound");
    }
}

#[test]
fn cancel_managed_delegate_cell() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_delegate_cell("del-1", "t1");
    let mut cx = mock_cx(200);
    let mut cancel_mgr = CancellationManager::new();

    let outcome = cancel_mgr
        .cancel_managed_cell(&mut cell_mgr, "del-1", &mut cx, LifecycleEvent::Revocation)
        .expect("cancel managed delegate");

    assert!(outcome.success);
    assert_eq!(outcome.cell_id, "del-1");
}

// ===========================================================================
// Section 12: cancel_all — bulk cancellation
// ===========================================================================

#[test]
fn cancel_all_cells_succeeds() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-1", "t1");
    cell_mgr.create_extension_cell("ext-2", "t2");
    cell_mgr.create_delegate_cell("del-1", "t3");
    let mut cx = mock_cx(500);
    let mut cancel_mgr = CancellationManager::new();

    let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Quarantine);

    assert_eq!(results.len(), 3);
    for r in &results {
        let outcome = r.as_ref().expect("all should succeed");
        assert!(outcome.success);
    }
    assert_eq!(cancel_mgr.outcome_count(), 3);
}

#[test]
fn cancel_all_on_empty_manager_returns_empty() {
    let mut cell_mgr = CellManager::new();
    let mut cx = mock_cx(100);
    let mut cancel_mgr = CancellationManager::new();

    let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Unload);
    assert!(results.is_empty());
    assert_eq!(cancel_mgr.outcome_count(), 0);
}

#[test]
fn cancel_all_with_single_cell() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-solo", "t1");
    let mut cx = mock_cx(200);
    let mut cancel_mgr = CancellationManager::new();

    let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Terminate);

    assert_eq!(results.len(), 1);
    assert!(results[0].as_ref().unwrap().success);
}

// ===========================================================================
// Section 13: Cross-cell isolation
// ===========================================================================

#[test]
fn cancel_one_cell_does_not_affect_another() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-1", "t1");
    cell_mgr.create_extension_cell("ext-2", "t2");
    let mut cx = mock_cx(200);
    let mut cancel_mgr = CancellationManager::new();

    cancel_mgr
        .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel ext-1");

    // ext-2 should still be running
    let cell2 = cell_mgr.get("ext-2").expect("ext-2 exists");
    assert_eq!(cell2.state(), RegionState::Running);
}

#[test]
fn is_cancelled_tracks_only_cancelled_cells() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-1", "t1");
    cell_mgr.create_extension_cell("ext-2", "t2");
    let mut cx = mock_cx(200);
    let mut cancel_mgr = CancellationManager::new();

    assert!(!cancel_mgr.is_cancelled("ext-1"));
    assert!(!cancel_mgr.is_cancelled("ext-2"));

    cancel_mgr
        .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Unload)
        .expect("cancel ext-1");

    assert!(cancel_mgr.is_cancelled("ext-1"));
    assert!(!cancel_mgr.is_cancelled("ext-2"));
}

// ===========================================================================
// Section 14: Evidence emission
// ===========================================================================

#[test]
fn cancel_emits_four_phase_events() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    let events = mgr.events();
    assert!(events.len() >= 4);

    let phases: Vec<&str> = events.iter().map(|e| e.phase.as_str()).collect();
    assert!(phases.contains(&"request"));
    assert!(phases.contains(&"cancel"));
    assert!(phases.contains(&"drain"));
    assert!(phases.contains(&"finalize"));
}

#[test]
fn all_events_have_correct_cell_info() {
    let mut cell = ExecutionCell::new("ext-check", CellKind::Delegate, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel");

    for event in mgr.events() {
        assert_eq!(event.cell_id, "ext-check");
        assert_eq!(event.cell_kind, CellKind::Delegate);
        assert_eq!(event.lifecycle_event, LifecycleEvent::Quarantine);
        assert_eq!(event.component, "cancellation_lifecycle");
    }
}

#[test]
fn drain_events_clears_buffer() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    let events = mgr.drain_events();
    assert!(!events.is_empty());
    assert!(mgr.events().is_empty(), "drain should clear buffer");
}

#[test]
fn events_accumulate_across_multiple_cancellations() {
    let mut cell1 = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cell2 = ExecutionCell::new("ext-2", CellKind::Extension, "t");
    let mut cx = mock_cx(300);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell1, &mut cx, LifecycleEvent::Unload)
        .expect("cancel 1");
    let count_after_first = mgr.events().len();
    assert!(count_after_first >= 4);

    mgr.cancel_cell(&mut cell2, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel 2");
    assert!(mgr.events().len() >= count_after_first + 4);
}

#[test]
fn timeout_escalation_emitted_in_drain_event() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-slow", "will timeout");

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel");

    let events = mgr.events();
    let drain_event = events
        .iter()
        .find(|e| e.phase == "drain")
        .expect("drain event");
    assert_eq!(drain_event.outcome, "timeout_escalated");
}

#[test]
fn request_event_has_initiated_outcome() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Suspend)
        .expect("cancel");

    let events = mgr.events();
    let request_event = events
        .iter()
        .find(|e| e.phase == "request")
        .expect("request event");
    assert_eq!(request_event.outcome, "initiated");
}

#[test]
fn finalize_success_event_on_clean_cancel() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    let events = mgr.events();
    let finalize_event = events
        .iter()
        .find(|e| e.phase == "finalize")
        .expect("finalize event");
    assert_eq!(finalize_event.outcome, "success");
}

// ===========================================================================
// Section 15: Mode overrides
// ===========================================================================

#[test]
fn mode_override_changes_effective_mode() {
    let mut mgr = CancellationManager::new();
    let custom = CancellationMode {
        drain_budget_ticks: 42,
        force_abort_on_timeout: false,
        propagate_to_children: false,
        evidence_event_name: "custom_test".to_string(),
    };
    mgr.set_mode_override(LifecycleEvent::Terminate, custom.clone());

    assert_eq!(mgr.effective_mode(LifecycleEvent::Terminate), custom);
    // Other events still use defaults
    assert_eq!(
        mgr.effective_mode(LifecycleEvent::Unload),
        CancellationMode::for_event(LifecycleEvent::Unload)
    );
}

#[test]
fn mode_override_affects_cancellation_behavior() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    // Override unload to have 1 tick drain
    mgr.set_mode_override(
        LifecycleEvent::Unload,
        CancellationMode {
            drain_budget_ticks: 1,
            force_abort_on_timeout: true,
            propagate_to_children: false,
            evidence_event_name: "custom_unload".to_string(),
        },
    );

    cell.register_obligation("ob-1", "will timeout quickly");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    assert!(outcome.timeout_escalated);
    assert_eq!(outcome.finalize_result.obligations_aborted, 1);
}

#[test]
fn mode_override_replaces_previous_override() {
    let mut mgr = CancellationManager::new();

    mgr.set_mode_override(
        LifecycleEvent::Suspend,
        CancellationMode {
            drain_budget_ticks: 100,
            force_abort_on_timeout: true,
            propagate_to_children: true,
            evidence_event_name: "override_v1".to_string(),
        },
    );

    mgr.set_mode_override(
        LifecycleEvent::Suspend,
        CancellationMode {
            drain_budget_ticks: 200,
            force_abort_on_timeout: false,
            propagate_to_children: false,
            evidence_event_name: "override_v2".to_string(),
        },
    );

    let effective = mgr.effective_mode(LifecycleEvent::Suspend);
    assert_eq!(effective.drain_budget_ticks, 200);
    assert_eq!(effective.evidence_event_name, "override_v2");
}

#[test]
fn effective_mode_without_override_returns_default() {
    let mgr = CancellationManager::new();
    for event in ALL_EVENTS {
        assert_eq!(
            mgr.effective_mode(event),
            CancellationMode::for_event(event),
            "effective_mode for {event:?} should match default"
        );
    }
}

// ===========================================================================
// Section 16: CancellationManager — is_cancelled, outcomes, outcome_count
// ===========================================================================

#[test]
fn new_manager_has_zero_outcomes() {
    let mgr = CancellationManager::new();
    assert_eq!(mgr.outcome_count(), 0);
    assert!(mgr.outcomes().is_empty());
}

#[test]
fn new_manager_has_no_events() {
    let mgr = CancellationManager::new();
    assert!(mgr.events().is_empty());
}

#[test]
fn is_cancelled_false_for_unknown_cell() {
    let mgr = CancellationManager::new();
    assert!(!mgr.is_cancelled("never-existed"));
}

#[test]
fn is_cancelled_true_after_cancel() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    assert!(!mgr.is_cancelled("ext-1"));

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    assert!(mgr.is_cancelled("ext-1"));
    assert!(!mgr.is_cancelled("ext-2"));
}

#[test]
fn outcomes_returns_all_completed() {
    let mut mgr = CancellationManager::new();

    let mut cell1 = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cell2 = ExecutionCell::new("ext-2", CellKind::Extension, "t");
    let mut cx = mock_cx(300);

    mgr.cancel_cell(&mut cell1, &mut cx, LifecycleEvent::Unload)
        .expect("cancel 1");
    mgr.cancel_cell(&mut cell2, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel 2");

    assert_eq!(mgr.outcome_count(), 2);
    let outcomes = mgr.outcomes();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].cell_id, "ext-1");
    assert_eq!(outcomes[1].cell_id, "ext-2");
}

// ===========================================================================
// Section 17: Default trait
// ===========================================================================

#[test]
fn cancellation_manager_default_is_same_as_new() {
    let a = CancellationManager::new();
    let b = CancellationManager::default();
    assert_eq!(a.outcome_count(), b.outcome_count());
    assert!(a.events().is_empty());
    assert!(b.events().is_empty());
}

// ===========================================================================
// Section 18: Three-phase protocol compliance for all events
// ===========================================================================

#[test]
fn all_events_emit_three_phase_evidence() {
    for event in ALL_EVENTS {
        let mut cell = ExecutionCell::new(format!("ext-{event}"), CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, event)
            .unwrap_or_else(|e| panic!("cancel failed for {event}: {e}"));

        let events = mgr.drain_events();
        let phases: Vec<&str> = events.iter().map(|e| e.phase.as_str()).collect();
        assert!(
            phases.contains(&"request"),
            "missing request phase for {event}"
        );
        assert!(
            phases.contains(&"cancel"),
            "missing cancel phase for {event}"
        );
        assert!(phases.contains(&"drain"), "missing drain phase for {event}");
        assert!(
            phases.contains(&"finalize"),
            "missing finalize phase for {event}"
        );
    }
}

// ===========================================================================
// Section 19: Deterministic replay
// ===========================================================================

#[test]
fn deterministic_cancellation_events_same_across_runs() {
    let run = || -> Vec<CancellationEvent> {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "flush");
        cell.commit_obligation("ob-1").unwrap();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .unwrap();
        mgr.drain_events()
    };

    let e1 = run();
    let e2 = run();
    assert_eq!(e1, e2, "events must be deterministic across identical runs");
}

#[test]
fn deterministic_outcomes_same_across_runs() {
    let run = || -> CancellationOutcome {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "pending");

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .unwrap()
    };

    let o1 = run();
    let o2 = run();
    assert_eq!(o1, o2, "outcomes must be deterministic");
}

#[test]
fn deterministic_error_on_budget_exhaustion() {
    let run = || -> CancellationError {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(0);
        let mut mgr = CancellationManager::new();
        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .unwrap_err()
    };

    let e1 = run();
    let e2 = run();
    assert_eq!(e1, e2, "errors must be deterministic");
}

// ===========================================================================
// Section 20: Complex scenarios
// ===========================================================================

#[test]
fn sequential_cancellation_of_all_events_on_separate_cells() {
    let mut cancel_mgr = CancellationManager::new();
    let mut cx = mock_cx(1000);

    for (i, event) in ALL_EVENTS.iter().enumerate() {
        let cell_id = format!("ext-{i}");
        let mut cell = ExecutionCell::new(&cell_id, CellKind::Extension, "t");

        let outcome = cancel_mgr
            .cancel_cell(&mut cell, &mut cx, *event)
            .unwrap_or_else(|e| panic!("cancel failed for {event}: {e}"));

        assert!(outcome.success);
        assert_eq!(outcome.event, *event);
        assert!(cancel_mgr.is_cancelled(&cell_id));
    }

    assert_eq!(cancel_mgr.outcome_count(), 5);
}

#[test]
fn cancel_all_with_obligations_mixed() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-clean", "t1");
    cell_mgr.create_extension_cell("ext-pending", "t2");

    // Add pending obligation to one cell
    {
        let cell = cell_mgr.get_mut("ext-pending").unwrap();
        cell.register_obligation("ob-1", "incomplete");
    }

    let mut cx = mock_cx(500);
    let mut cancel_mgr = CancellationManager::new();

    let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Quarantine);

    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(r.is_ok());
    }
}

#[test]
fn cancel_cell_with_many_obligations() {
    let mut cell = ExecutionCell::new("ext-heavy", CellKind::Extension, "t");
    let mut cx = mock_cx(200);
    let mut mgr = CancellationManager::new();

    for i in 0..10 {
        cell.register_obligation(format!("ob-{i}"), format!("obligation {i}"));
    }
    // Commit 3 of them
    for i in 0..3 {
        cell.commit_obligation(&format!("ob-{i}")).expect("commit");
    }

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    assert_eq!(outcome.finalize_result.obligations_committed, 3);
    assert_eq!(outcome.finalize_result.obligations_aborted, 7);
    assert!(outcome.timeout_escalated);
}

#[test]
fn evidence_trace_id_matches_context() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let expected_trace = cx.trace_id().to_string();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    for event in mgr.events() {
        assert_eq!(
            event.trace_id, expected_trace,
            "event trace_id must match context"
        );
    }
}

#[test]
fn events_component_is_always_cancellation_lifecycle() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Revocation)
        .expect("cancel");

    for event in mgr.events() {
        assert_eq!(event.component, "cancellation_lifecycle");
    }
}

// ===========================================================================
// Section 21: Serde stability — JSON key presence
// ===========================================================================

#[test]
fn lifecycle_event_json_format_is_string() {
    for event in ALL_EVENTS {
        let json = serde_json::to_string(&event).unwrap();
        // Should be a JSON string like "\"Unload\""
        assert!(json.starts_with('"'), "event JSON should be a string");
        assert!(json.ends_with('"'), "event JSON should be a string");
    }
}

#[test]
fn cancellation_mode_json_has_all_fields() {
    let mode = CancellationMode::for_event(LifecycleEvent::Unload);
    let json = serde_json::to_string(&mode).unwrap();
    assert!(json.contains("drain_budget_ticks"));
    assert!(json.contains("force_abort_on_timeout"));
    assert!(json.contains("propagate_to_children"));
    assert!(json.contains("evidence_event_name"));
}

#[test]
fn cancellation_error_json_roundtrip_preserves_variant_tag() {
    let errors = vec![
        CancellationError::CellNotFound {
            cell_id: "c1".to_string(),
        },
        CancellationError::BudgetExhausted {
            cell_id: "c2".to_string(),
            event: LifecycleEvent::Terminate,
        },
        CancellationError::CellError {
            cell_id: "c3".to_string(),
            error_code: "test_code".to_string(),
            message: "test message".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: CancellationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.error_code(), restored.error_code());
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// Section 22: Edge cases
// ===========================================================================

#[test]
fn cancel_cell_with_empty_string_id() {
    let mut cell = ExecutionCell::new("", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel empty ID cell");

    assert!(outcome.success);
    assert_eq!(outcome.cell_id, "");
    assert!(mgr.is_cancelled(""));
}

#[test]
fn cancel_cell_with_unicode_id() {
    let mut cell = ExecutionCell::new("ext-\u{1F600}-emoji", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel unicode ID");

    assert!(outcome.success);
    assert!(mgr.is_cancelled("ext-\u{1F600}-emoji"));
}

#[test]
fn idempotent_cancel_returns_zero_obligations() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(200);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("first");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("idempotent");

    assert!(outcome.was_idempotent);
    assert_eq!(outcome.finalize_result.obligations_committed, 0);
    assert_eq!(outcome.finalize_result.obligations_aborted, 0);
    assert!(!outcome.finalize_result.drain_timeout_escalated);
}

#[test]
fn cancel_outcome_success_set_correctly_on_timeout_escalation() {
    // When timeout_escalated is true, success is still true because the
    // protocol completed (finalize ran, obligations were force-aborted).
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    cell.register_obligation("ob-1", "pending");

    let outcome = mgr
        .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel");

    assert!(outcome.timeout_escalated);
    // When timeout_escalated is true, success = finalize_result.success && !timeout_escalated = false
    assert!(!outcome.success);
}

#[test]
fn drain_events_twice_second_is_empty() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cx = mock_cx(100);
    let mut mgr = CancellationManager::new();

    mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
        .expect("cancel");

    let first = mgr.drain_events();
    assert!(!first.is_empty());

    let second = mgr.drain_events();
    assert!(second.is_empty(), "second drain should return empty");
}

#[test]
fn cancel_all_idempotent_on_already_cancelled_cells() {
    let mut cell_mgr = CellManager::new();
    cell_mgr.create_extension_cell("ext-1", "t1");
    cell_mgr.create_extension_cell("ext-2", "t2");
    let mut cx = mock_cx(500);
    let mut cancel_mgr = CancellationManager::new();

    // Cancel all once
    let first_results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Unload);
    assert_eq!(first_results.len(), 2);
    for r in &first_results {
        assert!(!r.as_ref().unwrap().was_idempotent);
    }

    // After cancel_all, the cells were archived so there are no active cells
    // calling cancel_all again returns empty
    let second_results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Unload);
    assert!(
        second_results.is_empty(),
        "no active cells remain after cancel_all + archive"
    );
}

// ===========================================================================
// Section 23: Multiple managers are independent
// ===========================================================================

#[test]
fn two_managers_are_independent() {
    let mut cell1 = ExecutionCell::new("ext-1", CellKind::Extension, "t");
    let mut cell2 = ExecutionCell::new("ext-2", CellKind::Extension, "t");
    let mut cx = mock_cx(300);

    let mut mgr_a = CancellationManager::new();
    let mut mgr_b = CancellationManager::new();

    mgr_a
        .cancel_cell(&mut cell1, &mut cx, LifecycleEvent::Unload)
        .expect("cancel in mgr_a");

    mgr_b
        .cancel_cell(&mut cell2, &mut cx, LifecycleEvent::Quarantine)
        .expect("cancel in mgr_b");

    assert!(mgr_a.is_cancelled("ext-1"));
    assert!(!mgr_a.is_cancelled("ext-2"));
    assert!(!mgr_b.is_cancelled("ext-1"));
    assert!(mgr_b.is_cancelled("ext-2"));

    assert_eq!(mgr_a.outcome_count(), 1);
    assert_eq!(mgr_b.outcome_count(), 1);
}
