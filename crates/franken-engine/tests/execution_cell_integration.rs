#![forbid(unsafe_code)]
//! Integration tests for the `execution_cell` module.
//!
//! Exercises CellKind, CellError, CellEvent, ExecutionCell construction,
//! effect execution with budget, obligation lifecycle, quiescent close
//! protocol (cancel → drain → finalize), child-session creation,
//! CellManager CRUD, close_all, and serde round-trips.

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

use serde::Serialize;

use frankenengine_engine::control_plane::{
    Budget, ContextAdapter, ControlPlaneAdapterError, TraceId,
};
use frankenengine_engine::cx_threading::EffectCategory;
use frankenengine_engine::execution_cell::{
    CellError, CellEvent, CellKind, CellManager, ExecutionCell, ExtensionHostBinding,
};
use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline, RegionState};
use frankenengine_test_support::control_plane::{MockBudget, MockCx};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trace_id() -> TraceId {
    TraceId::from_raw(42)
}

fn make_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id(), MockBudget::new(budget_ms))
}

#[derive(Debug, Clone)]
struct IntegrationCx {
    trace_id: TraceId,
    budget: Budget,
}

impl IntegrationCx {
    fn new(budget_ms: u64) -> Self {
        Self {
            trace_id: TraceId::from_raw(0xfeed_f00d),
            budget: Budget::new(budget_ms),
        }
    }
}

impl ContextAdapter for IntegrationCx {
    fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    fn budget(&self) -> Budget {
        self.budget
    }

    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
        self.budget = self
            .budget
            .consume(requested_ms)
            .ok_or(ControlPlaneAdapterError::BudgetExhausted { requested_ms })?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BindingE2eLogEntry {
    phase: &'static str,
    extension_id: String,
    session_binding_id: String,
    session_cell_id: String,
    active_cell_ids: Vec<String>,
    evidence_count: u64,
    outcome: &'static str,
}

fn active_cell_ids(binding: &ExtensionHostBinding) -> Vec<String> {
    binding
        .manager()
        .active_cell_ids()
        .into_iter()
        .map(str::to_string)
        .collect()
}

// ===========================================================================
// 1. CellKind
// ===========================================================================

#[test]
fn cell_kind_display() {
    assert_eq!(CellKind::Extension.to_string(), "extension");
    assert_eq!(CellKind::Session.to_string(), "session");
    assert_eq!(CellKind::Delegate.to_string(), "delegate");
}

#[test]
fn cell_kind_serde_round_trip() {
    for kind in [CellKind::Extension, CellKind::Session, CellKind::Delegate] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: CellKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn cell_kind_ordering() {
    assert!(CellKind::Extension < CellKind::Session);
    assert!(CellKind::Session < CellKind::Delegate);
}

// ===========================================================================
// 2. CellError
// ===========================================================================

#[test]
fn cell_error_invalid_state_display() {
    let err = CellError::InvalidState {
        cell_id: "cell-1".into(),
        current: RegionState::Running,
        attempted: "finalize".into(),
    };
    let s = err.to_string();
    assert!(s.contains("cell-1"));
    assert!(s.contains("finalize"));
}

#[test]
fn cell_error_budget_exhausted_display() {
    let err = CellError::BudgetExhausted {
        cell_id: "cell-1".into(),
        requested_ms: 10,
        remaining_ms: 2,
    };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("2"));
}

#[test]
fn cell_error_not_found_display() {
    let err = CellError::CellNotFound {
        cell_id: "missing-cell".into(),
    };
    assert!(err.to_string().contains("missing-cell"));
}

#[test]
fn cell_error_session_rejected_display() {
    let err = CellError::SessionRejected {
        parent_cell_id: "parent".into(),
        reason: "not running".into(),
    };
    assert!(err.to_string().contains("parent"));
    assert!(err.to_string().contains("not running"));
}

#[test]
fn cell_error_obligation_not_found_display() {
    let err = CellError::ObligationNotFound {
        cell_id: "cell-1".into(),
        obligation_id: "obl-99".into(),
    };
    assert!(err.to_string().contains("obl-99"));
}

#[test]
fn cell_error_stable_codes() {
    assert_eq!(
        CellError::InvalidState {
            cell_id: "x".into(),
            current: RegionState::Running,
            attempted: "y".into()
        }
        .error_code(),
        "cell_invalid_state"
    );
    assert_eq!(
        CellError::BudgetExhausted {
            cell_id: "x".into(),
            requested_ms: 1,
            remaining_ms: 0
        }
        .error_code(),
        "cell_budget_exhausted"
    );
    assert_eq!(
        CellError::CxThreading {
            cell_id: "x".into(),
            error_code: "e".into(),
            message: "m".into()
        }
        .error_code(),
        "cell_cx_threading"
    );
    assert_eq!(
        CellError::CellNotFound {
            cell_id: "x".into()
        }
        .error_code(),
        "cell_not_found"
    );
    assert_eq!(
        CellError::SessionRejected {
            parent_cell_id: "x".into(),
            reason: "r".into()
        }
        .error_code(),
        "cell_session_rejected"
    );
    assert_eq!(
        CellError::ObligationNotFound {
            cell_id: "x".into(),
            obligation_id: "o".into()
        }
        .error_code(),
        "cell_obligation_not_found"
    );
}

#[test]
fn cell_error_serde_round_trip() {
    let errors = vec![
        CellError::InvalidState {
            cell_id: "c".into(),
            current: RegionState::Running,
            attempted: "op".into(),
        },
        CellError::BudgetExhausted {
            cell_id: "c".into(),
            requested_ms: 5,
            remaining_ms: 1,
        },
        CellError::CellNotFound {
            cell_id: "c".into(),
        },
        CellError::SessionRejected {
            parent_cell_id: "p".into(),
            reason: "r".into(),
        },
        CellError::ObligationNotFound {
            cell_id: "c".into(),
            obligation_id: "o".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CellError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 3. ExecutionCell — construction
// ===========================================================================

#[test]
fn new_cell_is_running() {
    let cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    assert_eq!(cell.cell_id(), "cell-1");
    assert_eq!(cell.kind(), CellKind::Extension);
    assert_eq!(cell.state(), RegionState::Running);
    assert_eq!(cell.trace_id(), "trace-1");
    assert_eq!(cell.total_budget_consumed_ms(), 0);
    assert_eq!(cell.pending_obligations(), 0);
    assert_eq!(cell.session_count(), 0);
}

#[test]
fn with_context_sets_decision_and_policy() {
    let cell = ExecutionCell::with_context("cell-2", CellKind::Session, "t", "d-1", "p-1");
    assert_eq!(cell.decision_id(), "d-1");
    assert_eq!(cell.policy_id(), "p-1");
    assert_eq!(cell.kind(), CellKind::Session);
    assert_eq!(cell.state(), RegionState::Running);
}

// ===========================================================================
// 4. ExecutionCell — execute_effect
// ===========================================================================

#[test]
fn execute_effect_returns_sequence_number() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    let seq1 = cell
        .execute_effect(&mut cx, EffectCategory::Hostcall, "op1")
        .unwrap();
    let seq2 = cell
        .execute_effect(&mut cx, EffectCategory::Hostcall, "op2")
        .unwrap();

    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
}

#[test]
fn execute_effect_consumes_budget() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op")
        .unwrap();
    assert!(cell.total_budget_consumed_ms() > 0);
}

#[test]
fn execute_effect_records_in_effect_log() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.execute_effect(&mut cx, EffectCategory::Hostcall, "my-op")
        .unwrap();

    let log = cell.effect_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].operation, "my-op");
    assert_eq!(log[0].outcome, "ok");
}

#[test]
fn execute_effect_emits_cell_event() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.execute_effect(&mut cx, EffectCategory::Hostcall, "my-op")
        .unwrap();

    let events = cell.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].event, "my-op");
    assert_eq!(events[0].component, "execution_cell");
}

#[test]
fn execute_effect_fails_when_budget_exhausted() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(0); // zero budget

    let result = cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op");
    assert!(result.is_err());
    match result.unwrap_err() {
        CellError::BudgetExhausted { .. } => {}
        other => panic!("expected BudgetExhausted, got {other:?}"),
    }
}

#[test]
fn execute_effect_fails_when_not_running() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    // Close the cell first
    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 10 },
    )
    .unwrap();

    let result = cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op");
    assert!(result.is_err());
    match result.unwrap_err() {
        CellError::InvalidState { .. } => {}
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

// ===========================================================================
// 5. ExecutionCell — obligations
// ===========================================================================

#[test]
fn register_and_commit_obligation() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    cell.register_obligation("obl-1", "test obligation");
    assert_eq!(cell.pending_obligations(), 1);

    cell.commit_obligation("obl-1").unwrap();
    assert_eq!(cell.pending_obligations(), 0);
}

#[test]
fn commit_unknown_obligation_fails() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let result = cell.commit_obligation("nonexistent");
    assert!(result.is_err());
    match result.unwrap_err() {
        CellError::ObligationNotFound { obligation_id, .. } => {
            assert_eq!(obligation_id, "nonexistent");
        }
        other => panic!("expected ObligationNotFound, got {other:?}"),
    }
}

#[test]
fn abort_obligation() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    cell.register_obligation("obl-1", "test");
    assert_eq!(cell.pending_obligations(), 1);

    cell.abort_obligation("obl-1").unwrap();
    assert_eq!(cell.pending_obligations(), 0);
}

#[test]
fn abort_unknown_obligation_fails() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let result = cell.abort_obligation("nonexistent");
    assert!(result.is_err());
}

#[test]
fn multiple_obligations() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    cell.register_obligation("obl-1", "first");
    cell.register_obligation("obl-2", "second");
    cell.register_obligation("obl-3", "third");
    assert_eq!(cell.pending_obligations(), 3);

    cell.commit_obligation("obl-2").unwrap();
    assert_eq!(cell.pending_obligations(), 2);

    cell.abort_obligation("obl-1").unwrap();
    assert_eq!(cell.pending_obligations(), 1);

    cell.commit_obligation("obl-3").unwrap();
    assert_eq!(cell.pending_obligations(), 0);
}

// ===========================================================================
// 6. ExecutionCell — quiescent close
// ===========================================================================

#[test]
fn close_running_cell_succeeds() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    let result = cell
        .close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();
    assert!(result.success);
}

#[test]
fn close_with_resolved_obligations_succeeds() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.register_obligation("obl-1", "test");
    cell.commit_obligation("obl-1").unwrap();

    let result = cell
        .close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();
    assert!(result.success);
}

#[test]
fn close_emits_events() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 10 },
    )
    .unwrap();

    let events = cell.events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"cancel"));
    assert!(event_names.contains(&"drain"));
    assert!(event_names.contains(&"finalize"));
}

#[test]
fn initiate_close_then_finalize() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.initiate_close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    // Drain ticks
    for _ in 0..5 {
        cell.drain_tick();
    }

    let result = cell.finalize().unwrap();
    assert!(result.success);
}

#[test]
fn close_budget_error() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(0);

    let result = cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 10 },
    );
    assert!(result.is_err());
}

// ===========================================================================
// 7. ExecutionCell — session creation
// ===========================================================================

#[test]
fn create_session_on_running_cell() {
    let mut cell = ExecutionCell::with_context("parent", CellKind::Extension, "t", "d", "p");

    let session = cell.create_session("session-1", "trace-s1").unwrap();
    assert_eq!(session.cell_id(), "session-1");
    assert_eq!(session.kind(), CellKind::Session);
    assert_eq!(session.decision_id(), "d");
    assert_eq!(session.policy_id(), "p");
    assert_eq!(session.state(), RegionState::Running);
    assert_eq!(cell.session_count(), 1);
}

#[test]
fn create_multiple_sessions() {
    let mut cell = ExecutionCell::new("parent", CellKind::Extension, "t");

    let _s1 = cell.create_session("s1", "t1").unwrap();
    let _s2 = cell.create_session("s2", "t2").unwrap();
    assert_eq!(cell.session_count(), 2);
}

#[test]
fn create_session_on_closed_cell_fails() {
    let mut cell = ExecutionCell::new("parent", CellKind::Extension, "t");
    let mut cx = make_cx(1000);
    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let result = cell.create_session("session-1", "trace-s");
    assert!(result.is_err());
    match result.unwrap_err() {
        CellError::SessionRejected { .. } => {}
        other => panic!("expected SessionRejected, got {other:?}"),
    }
}

// ===========================================================================
// 8. ExecutionCell — drain events
// ===========================================================================

#[test]
fn drain_events_empties_and_returns() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);

    cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op")
        .unwrap();

    let events = cell.drain_events();
    assert!(!events.is_empty());
    assert!(cell.events().is_empty());
}

#[test]
fn drain_region_events() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    let mut cx = make_cx(1000);
    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let region_events = cell.drain_region_events();
    assert!(!region_events.is_empty());
}

// ===========================================================================
// 9. CellEvent — serde
// ===========================================================================

#[test]
fn cell_event_serde_round_trip() {
    let event = CellEvent {
        trace_id: "trace-1".into(),
        cell_id: "cell-1".into(),
        cell_kind: CellKind::Extension,
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        event: "execute_effect".into(),
        component: "execution_cell".into(),
        outcome: "ok".into(),
        error_code: None,
        region_state: RegionState::Running,
        budget_consumed_ms: 5,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CellEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn cell_event_with_error_code() {
    let event = CellEvent {
        trace_id: "trace-1".into(),
        cell_id: "cell-1".into(),
        cell_kind: CellKind::Delegate,
        decision_id: "d".into(),
        policy_id: "p".into(),
        event: "execute_effect".into(),
        component: "execution_cell".into(),
        outcome: "error".into(),
        error_code: Some("cell_budget_exhausted".into()),
        region_state: RegionState::Running,
        budget_consumed_ms: 0,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CellEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("cell_budget_exhausted".into()));
}

// ===========================================================================
// 10. CellManager — construction and CRUD
// ===========================================================================

#[test]
fn manager_new_is_empty() {
    let mgr = CellManager::new();
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.closed_count(), 0);
}

#[test]
fn create_extension_cell() {
    let mut mgr = CellManager::new();
    let cell = mgr.create_extension_cell("ext-1", "trace-1").unwrap();
    assert_eq!(cell.kind(), CellKind::Extension);
    assert_eq!(cell.cell_id(), "ext-1");
    assert_eq!(mgr.active_count(), 1);
}

#[test]
fn create_delegate_cell() {
    let mut mgr = CellManager::new();
    let cell = mgr.create_delegate_cell("del-1", "trace-1").unwrap();
    assert_eq!(cell.kind(), CellKind::Delegate);
    assert_eq!(mgr.active_count(), 1);
}

#[test]
fn manager_get_and_get_mut() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-1", "trace-1").unwrap();

    assert!(mgr.get("ext-1").is_some());
    assert!(mgr.get("nonexistent").is_none());

    let cell_mut = mgr.get_mut("ext-1").unwrap();
    cell_mut.register_obligation("obl-1", "test");
    assert_eq!(mgr.get("ext-1").unwrap().pending_obligations(), 1);
}

#[test]
fn manager_insert_cell() {
    let mut mgr = CellManager::new();
    let cell = ExecutionCell::with_context("custom-1", CellKind::Extension, "t", "d", "p");
    mgr.insert_cell("custom-1", cell).unwrap();
    assert_eq!(mgr.active_count(), 1);
    assert_eq!(mgr.get("custom-1").unwrap().decision_id(), "d");
}

#[test]
fn manager_active_cell_ids() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-b", "t1").unwrap();
    mgr.create_extension_cell("ext-a", "t2").unwrap();

    let ids = mgr.active_cell_ids();
    assert_eq!(ids.len(), 2);
    // BTreeMap ordering: ext-a < ext-b
    assert_eq!(ids[0], "ext-a");
    assert_eq!(ids[1], "ext-b");
}

// ===========================================================================
// 11. CellManager — close and archive
// ===========================================================================

#[test]
fn close_cell_moves_to_closed() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-1", "trace-1").unwrap();
    let mut cx = make_cx(1000);

    let result = mgr
        .close_cell(
            "ext-1",
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();
    assert!(result.success);
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.closed_count(), 1);
}

#[test]
fn close_nonexistent_cell_fails() {
    let mut mgr = CellManager::new();
    let mut cx = make_cx(1000);

    let result = mgr.close_cell(
        "missing",
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        CellError::CellNotFound { cell_id } => assert_eq!(cell_id, "missing"),
        other => panic!("expected CellNotFound, got {other:?}"),
    }
}

#[test]
fn close_all_cells() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-1", "t1").unwrap();
    mgr.create_extension_cell("ext-2", "t2").unwrap();
    mgr.create_delegate_cell("del-1", "t3").unwrap();
    let mut cx = make_cx(10_000);

    let results = mgr.close_all(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 10 },
    );
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.is_ok());
    }
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.closed_count(), 3);
}

#[test]
fn closed_results_preserved() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-1", "t1").unwrap();
    let mut cx = make_cx(1000);

    mgr.close_cell(
        "ext-1",
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let closed = mgr.closed_results();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].0, "ext-1");
    assert!(closed[0].1.success);
}

// ===========================================================================
// 12. CellManager — archive_cell
// ===========================================================================

#[test]
fn archive_cell_removes_from_active() {
    let mut mgr = CellManager::new();
    mgr.create_extension_cell("ext-1", "t1").unwrap();
    let mut cx = make_cx(1000);

    // Manually close the cell and archive
    let cell = mgr.get_mut("ext-1").unwrap();
    let result = cell
        .close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();
    mgr.archive_cell("ext-1", result);

    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.closed_count(), 1);
}

// ===========================================================================
// 13. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_extension_with_sessions() {
    let mut mgr = CellManager::new();
    let mut cx = make_cx(10_000);

    // Create extension cell
    let ext_cell = mgr.create_extension_cell("ext-app", "trace-main").unwrap();
    ext_cell.register_obligation("load-manifest", "load extension manifest");

    // Execute some effects
    let cell = mgr.get_mut("ext-app").unwrap();
    let seq = cell
        .execute_effect(&mut cx, EffectCategory::Hostcall, "parse-config")
        .unwrap();
    assert_eq!(seq, 1);

    // Create a session
    let cell = mgr.get_mut("ext-app").unwrap();
    let mut session = cell.create_session("sess-1", "trace-s1").unwrap();

    // Execute effects in the session
    let s_seq = session
        .execute_effect(&mut cx, EffectCategory::Hostcall, "eval-script")
        .unwrap();
    assert_eq!(s_seq, 1);

    // Close the session
    let s_result = session
        .close(
            &mut cx,
            CancelReason::ParentClosing,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();
    assert!(s_result.success);

    // Commit the extension obligation and close
    let cell = mgr.get_mut("ext-app").unwrap();
    cell.commit_obligation("load-manifest").unwrap();

    let result = mgr
        .close_cell(
            "ext-app",
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();
    assert!(result.success);
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.closed_count(), 1);
}

#[test]
fn multiple_effect_categories() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "t");
    let mut cx = make_cx(10_000);

    let categories = [
        EffectCategory::Hostcall,
        EffectCategory::PolicyCheck,
        EffectCategory::LifecycleTransition,
    ];

    for (i, cat) in categories.iter().enumerate() {
        let seq = cell
            .execute_effect(&mut cx, *cat, &format!("op-{i}"))
            .unwrap();
        assert_eq!(seq, (i + 1) as u64);
    }

    assert_eq!(cell.effect_log().len(), 3);
    assert!(cell.total_budget_consumed_ms() > 0);
}

#[test]
fn close_with_pending_obligations_still_finalizes() {
    let mut cell = ExecutionCell::new("cell-1", CellKind::Extension, "t");
    let mut cx = make_cx(1000);

    cell.register_obligation("never-resolved", "will stay pending");

    // Even with unresolved obligations, close completes (the region handles draining)
    let _ = cell
        .close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 3 },
        )
        .unwrap();

    // Verify finalize completed (success depends on region implementation)
    let events = cell.events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"finalize"));
}

// ===========================================================================
// 14. ExtensionHostBinding — extension-scoped session IDs
// ===========================================================================

#[test]
fn extension_host_binding_scopes_same_session_binding_id_per_extension() {
    let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
    let mut cx = IntegrationCx::new(1_000);
    let mut log_entries = Vec::new();

    binding
        .load_extension("ext-a", &mut cx, "decision-a", "policy-a")
        .unwrap();
    binding
        .load_extension("ext-b", &mut cx, "decision-b", "policy-b")
        .unwrap();

    let ext_a_session = binding
        .start_session("ext-a", "sess-1", "trace-ext-a-sess-1")
        .unwrap();
    log_entries.push(BindingE2eLogEntry {
        phase: "start_session",
        extension_id: "ext-a".to_string(),
        session_binding_id: "sess-1".to_string(),
        session_cell_id: ext_a_session.clone(),
        active_cell_ids: active_cell_ids(&binding),
        evidence_count: binding.evidence_count(),
        outcome: "ok",
    });

    let ext_b_session = binding
        .start_session("ext-b", "sess-1", "trace-ext-b-sess-1")
        .unwrap();
    log_entries.push(BindingE2eLogEntry {
        phase: "start_session",
        extension_id: "ext-b".to_string(),
        session_binding_id: "sess-1".to_string(),
        session_cell_id: ext_b_session.clone(),
        active_cell_ids: active_cell_ids(&binding),
        evidence_count: binding.evidence_count(),
        outcome: "ok",
    });

    assert_ne!(
        ext_a_session, ext_b_session,
        "same caller session id must not collide across extensions"
    );
    assert_eq!(
        ext_a_session,
        ExtensionHostBinding::session_cell_id("ext-a", "sess-1")
    );
    assert_eq!(
        ext_b_session,
        ExtensionHostBinding::session_cell_id("ext-b", "sess-1")
    );
    assert_ne!(
        ExtensionHostBinding::session_cell_id("ab", "c"),
        ExtensionHostBinding::session_cell_id("a", "bc"),
        "length-prefixed hashing must keep tuple boundaries unambiguous"
    );
    assert!(binding.manager().get("sess-1").is_none());
    assert!(binding.manager().get(&ext_a_session).is_some());
    assert!(binding.manager().get(&ext_b_session).is_some());

    let session_evidence = binding.evidence_for_event("session_start");
    let session_evidence_ids: Vec<&str> = session_evidence
        .iter()
        .map(|entry| entry.cell_id.as_str())
        .collect();
    assert_eq!(
        session_evidence_ids,
        vec![ext_a_session.as_str(), ext_b_session.as_str()]
    );
    let session_bindings: Vec<(&str, &str)> = session_evidence
        .iter()
        .map(|entry| {
            (
                entry
                    .metadata
                    .get("extension_id")
                    .map(String::as_str)
                    .expect("session evidence should include extension_id"),
                entry
                    .metadata
                    .get("session_binding_id")
                    .map(String::as_str)
                    .expect("session evidence should include caller session binding id"),
            )
        })
        .collect();
    assert_eq!(
        session_bindings,
        vec![("ext-a", "sess-1"), ("ext-b", "sess-1")]
    );

    binding
        .unload_extension("ext-a", &mut cx, CancelReason::Quarantine)
        .unwrap();
    log_entries.push(BindingE2eLogEntry {
        phase: "unload_extension",
        extension_id: "ext-a".to_string(),
        session_binding_id: "sess-1".to_string(),
        session_cell_id: ext_a_session.clone(),
        active_cell_ids: active_cell_ids(&binding),
        evidence_count: binding.evidence_count(),
        outcome: "ok",
    });

    assert!(binding.manager().get("ext-a").is_none());
    assert!(binding.manager().get(&ext_a_session).is_none());
    assert!(binding.manager().get("ext-b").is_some());
    assert!(binding.manager().get(&ext_b_session).is_some());

    binding
        .unload_extension("ext-b", &mut cx, CancelReason::OperatorShutdown)
        .unwrap();
    log_entries.push(BindingE2eLogEntry {
        phase: "unload_extension",
        extension_id: "ext-b".to_string(),
        session_binding_id: "sess-1".to_string(),
        session_cell_id: ext_b_session.clone(),
        active_cell_ids: active_cell_ids(&binding),
        evidence_count: binding.evidence_count(),
        outcome: "ok",
    });

    assert_eq!(binding.manager().active_count(), 0);
    assert_eq!(
        binding
            .evidence_log()
            .iter()
            .filter(|entry| entry.event == "extension_unload")
            .count(),
        2
    );

    let json_lines: Vec<String> = log_entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(json_lines.len(), 4);
    assert!(
        json_lines
            .iter()
            .all(|line| line.contains("\"outcome\":\"ok\""))
    );
}
