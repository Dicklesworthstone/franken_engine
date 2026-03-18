//! Enrichment integration tests for `cancellation_lifecycle`.
//!
//! Covers gaps: LifecycleEvent Display uniqueness, CancellationMode for_event
//! defaults per event type, CancellationError error_code, serde roundtrips
//! for all public enums and structs, CancellationManager new state,
//! is_forced/is_cooperative classification, and cancel_reason mapping.

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

use std::collections::BTreeSet;

use frankenengine_engine::cancellation_lifecycle::{
    CancellationError, CancellationEvent, CancellationManager, CancellationMode,
    CancellationOutcome, LifecycleEvent,
};

// ===========================================================================
// LifecycleEvent Display uniqueness
// ===========================================================================

#[test]
fn enrichment_lifecycle_event_display_all_unique() {
    let all = [
        LifecycleEvent::Unload,
        LifecycleEvent::Quarantine,
        LifecycleEvent::Suspend,
        LifecycleEvent::Terminate,
        LifecycleEvent::Revocation,
    ];
    let displays: BTreeSet<String> = all.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_lifecycle_event_serde_roundtrip() {
    let all = [
        LifecycleEvent::Unload,
        LifecycleEvent::Quarantine,
        LifecycleEvent::Suspend,
        LifecycleEvent::Terminate,
        LifecycleEvent::Revocation,
    ];
    for event in &all {
        let json = serde_json::to_string(event).unwrap();
        let back: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, back);
    }
}

// ===========================================================================
// LifecycleEvent: is_forced / is_cooperative
// ===========================================================================

#[test]
fn enrichment_terminate_is_forced() {
    assert!(LifecycleEvent::Terminate.is_forced());
}

#[test]
fn enrichment_quarantine_is_forced() {
    assert!(LifecycleEvent::Quarantine.is_forced());
}

#[test]
fn enrichment_revocation_is_forced() {
    assert!(LifecycleEvent::Revocation.is_forced());
}

#[test]
fn enrichment_unload_is_cooperative() {
    assert!(LifecycleEvent::Unload.is_cooperative());
}

#[test]
fn enrichment_suspend_is_cooperative() {
    assert!(LifecycleEvent::Suspend.is_cooperative());
}

#[test]
fn enrichment_forced_not_cooperative() {
    for event in &[
        LifecycleEvent::Terminate,
        LifecycleEvent::Quarantine,
        LifecycleEvent::Revocation,
    ] {
        assert!(!event.is_cooperative(), "{event} should not be cooperative");
    }
}

#[test]
fn enrichment_cooperative_not_forced() {
    for event in &[LifecycleEvent::Unload, LifecycleEvent::Suspend] {
        assert!(!event.is_forced(), "{event} should not be forced");
    }
}

// ===========================================================================
// LifecycleEvent: cancel_reason mapping
// ===========================================================================

#[test]
fn enrichment_cancel_reason_exists_for_all_events() {
    let all = [
        LifecycleEvent::Unload,
        LifecycleEvent::Quarantine,
        LifecycleEvent::Suspend,
        LifecycleEvent::Terminate,
        LifecycleEvent::Revocation,
    ];
    for event in &all {
        let reason = event.cancel_reason();
        // Just verify it doesn't panic and produces a value
        let _ = reason;
    }
}

// ===========================================================================
// CancellationMode: for_event defaults
// ===========================================================================

#[test]
fn enrichment_mode_for_unload_is_cooperative() {
    let mode = CancellationMode::for_event(LifecycleEvent::Unload);
    assert!(
        mode.drain_budget_ticks > 0,
        "Unload should have nonzero drain budget"
    );
    assert!(
        !mode.force_abort_on_timeout,
        "Unload should not force-abort by default"
    );
}

#[test]
fn enrichment_mode_for_terminate_is_forced() {
    let mode = CancellationMode::for_event(LifecycleEvent::Terminate);
    assert!(
        mode.force_abort_on_timeout,
        "Terminate should force-abort on timeout"
    );
}

#[test]
fn enrichment_mode_for_quarantine_propagates_to_children() {
    let mode = CancellationMode::for_event(LifecycleEvent::Quarantine);
    assert!(
        mode.propagate_to_children,
        "Quarantine should propagate to children"
    );
}

#[test]
fn enrichment_mode_evidence_event_name_nonempty() {
    let all = [
        LifecycleEvent::Unload,
        LifecycleEvent::Quarantine,
        LifecycleEvent::Suspend,
        LifecycleEvent::Terminate,
        LifecycleEvent::Revocation,
    ];
    for event in &all {
        let mode = CancellationMode::for_event(*event);
        assert!(
            !mode.evidence_event_name.is_empty(),
            "Mode for {event} should have an evidence event name"
        );
    }
}

#[test]
fn enrichment_mode_serde_roundtrip() {
    let mode = CancellationMode::for_event(LifecycleEvent::Unload);
    let json = serde_json::to_string(&mode).unwrap();
    let back: CancellationMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode.drain_budget_ticks, back.drain_budget_ticks);
    assert_eq!(mode.force_abort_on_timeout, back.force_abort_on_timeout);
}

// ===========================================================================
// CancellationError error_code and serde
// ===========================================================================

#[test]
fn enrichment_error_code_nonempty() {
    let errors = [
        CancellationError::CellNotFound {
            cell_id: "c1".to_string(),
        },
        CancellationError::BudgetExhausted {
            cell_id: "c1".to_string(),
            event: LifecycleEvent::Unload,
        },
        CancellationError::CellError {
            cell_id: "c1".to_string(),
            error_code: "E001".to_string(),
            message: "test".to_string(),
        },
    ];
    for err in &errors {
        assert!(!err.error_code().is_empty());
    }
}

#[test]
fn enrichment_error_display_nonempty() {
    let err = CancellationError::CellNotFound {
        cell_id: "cell-001".to_string(),
    };
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let errors = [
        CancellationError::CellNotFound {
            cell_id: "c1".to_string(),
        },
        CancellationError::BudgetExhausted {
            cell_id: "c2".to_string(),
            event: LifecycleEvent::Terminate,
        },
        CancellationError::CellError {
            cell_id: "c3".to_string(),
            error_code: "E999".to_string(),
            message: "fail".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CancellationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// CancellationManager: initial state
// ===========================================================================

#[test]
fn enrichment_manager_new_empty() {
    let manager = CancellationManager::new();
    assert_eq!(manager.outcome_count(), 0);
    assert!(manager.outcomes().is_empty());
}

#[test]
fn enrichment_manager_not_cancelled_initially() {
    let manager = CancellationManager::new();
    assert!(!manager.is_cancelled("any-cell"));
}

#[test]
fn enrichment_manager_events_empty_initially() {
    let mut manager = CancellationManager::new();
    let events = manager.drain_events();
    assert!(events.is_empty());
}

#[test]
fn enrichment_manager_events_accessor_empty() {
    let manager = CancellationManager::new();
    assert!(manager.events().is_empty());
}

// ===========================================================================
// CancellationManager: mode override
// ===========================================================================

#[test]
fn enrichment_manager_set_mode_override() {
    let mut manager = CancellationManager::new();
    let custom_mode = CancellationMode {
        drain_budget_ticks: 999,
        force_abort_on_timeout: true,
        propagate_to_children: false,
        evidence_event_name: "custom_cancel".to_string(),
    };
    manager.set_mode_override(LifecycleEvent::Unload, custom_mode.clone());
    let effective = manager.effective_mode(LifecycleEvent::Unload);
    assert_eq!(effective.drain_budget_ticks, 999);
}

#[test]
fn enrichment_manager_effective_mode_default_without_override() {
    let manager = CancellationManager::new();
    let mode = manager.effective_mode(LifecycleEvent::Suspend);
    // Should return the default for_event mode
    let default_mode = CancellationMode::for_event(LifecycleEvent::Suspend);
    assert_eq!(mode.drain_budget_ticks, default_mode.drain_budget_ticks);
}

// ===========================================================================
// CancellationOutcome serde roundtrip
// ===========================================================================

#[test]
fn enrichment_outcome_serde_roundtrip() {
    let outcome = CancellationOutcome {
        cell_id: "cell-001".to_string(),
        event: LifecycleEvent::Unload,
        success: true,
        finalize_result: frankenengine_engine::region_lifecycle::FinalizeResult {
            region_id: "region-001".to_string(),
            success: true,
            obligations_committed: 0,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        },
        timeout_escalated: false,
        children_cancelled: 0,
        was_idempotent: false,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: CancellationOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome.cell_id, back.cell_id);
    assert_eq!(outcome.success, back.success);
}

// ===========================================================================
// CancellationEvent serde roundtrip
// ===========================================================================

#[test]
fn enrichment_cancellation_event_serde_roundtrip() {
    let event = CancellationEvent {
        trace_id: "trace-001".to_string(),
        cell_id: "cell-001".to_string(),
        cell_kind: frankenengine_engine::execution_cell::CellKind::Extension,
        lifecycle_event: LifecycleEvent::Terminate,
        phase: "drain".to_string(),
        outcome: "success".to_string(),
        component: "cancellation_lifecycle".to_string(),
        obligations_pending: 0,
        budget_consumed_ms: 50,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CancellationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.trace_id, back.trace_id);
    assert_eq!(event.cell_id, back.cell_id);
}
