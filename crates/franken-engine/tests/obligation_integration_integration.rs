//! Integration tests for the `obligation_integration` module.
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

use std::collections::BTreeMap;

use frankenengine_engine::execution_cell::{CellError, CellKind, ExecutionCell};
use frankenengine_engine::obligation_integration::{
    CategoryStats, LeakPolicy, LeakRecord, ObligationEvent, ObligationIntegrationError,
    ObligationTracker, OperationPhase, TwoPhaseCategory, TwoPhaseOperation,
};
use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline, RegionState};

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(budget_ms))
}

// ===========================================================================
// 1. Multi-step lifecycle workflows (8+ tests)
// ===========================================================================

#[test]
fn lifecycle_begin_commit_verify_stats_and_events() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::ResourceAlloc,
            "allocate buffer",
        )
        .unwrap();

    assert_eq!(tracker.active_count(), 1);
    assert_eq!(tracker.total_count(), 1);
    assert_eq!(cell.pending_obligations(), 1);

    tracker.commit_operation(&mut cell, "op-1").unwrap();

    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.total_count(), 1);
    assert_eq!(cell.pending_obligations(), 0);

    let stats = tracker.category_stats();
    let alloc_stats = stats.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_stats.started, 1);
    assert_eq!(alloc_stats.committed, 1);
    assert_eq!(alloc_stats.aborted, 0);
    assert_eq!(alloc_stats.leaked, 0);

    let events = tracker.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "begin");
    assert_eq!(events[0].outcome, "phase1_active");
    assert_eq!(events[1].event, "commit");
    assert_eq!(events[1].outcome, "committed");
}

#[test]
fn lifecycle_begin_abort_verify_stats_and_events() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::PermissionGrant,
            "grant network",
        )
        .unwrap();

    tracker.abort_operation(&mut cell, "op-1").unwrap();

    assert_eq!(tracker.active_count(), 0);

    let stats = tracker.category_stats();
    let perm_stats = stats.get(&TwoPhaseCategory::PermissionGrant).unwrap();
    assert_eq!(perm_stats.started, 1);
    assert_eq!(perm_stats.committed, 0);
    assert_eq!(perm_stats.aborted, 1);
    assert_eq!(perm_stats.leaked, 0);

    let events = tracker.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "begin");
    assert_eq!(events[1].event, "abort");
    assert_eq!(events[1].outcome, "aborted");
}

#[test]
fn lifecycle_begin_detect_leaks_running_then_close_and_detect() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::StateMutation,
            "state change",
        )
        .unwrap();

    // Cell still running: no leaks detected
    let leaks = tracker.detect_leaks(&cell);
    assert!(leaks.is_empty());
    assert!(!tracker.has_leaks());

    // Close cell
    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    // Now detect leaks
    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].operation_id, "op-1");
    assert!(tracker.has_leaks());
}

#[test]
fn lifecycle_mixed_outcomes_across_categories() {
    let mut cell = ExecutionCell::new("ext-mix", CellKind::Extension, "trace-mix");
    let mut cx = mock_cx(500);
    let mut tracker = ObligationTracker::default();

    // Begin 4 operations in different categories
    tracker
        .begin_operation(
            &mut cell,
            "alloc-1",
            TwoPhaseCategory::ResourceAlloc,
            "buffer",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "perm-1",
            TwoPhaseCategory::PermissionGrant,
            "access",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "state-1",
            TwoPhaseCategory::StateMutation,
            "config",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "ev-1",
            TwoPhaseCategory::EvidenceCommit,
            "evidence",
        )
        .unwrap();

    assert_eq!(tracker.active_count(), 4);

    // Commit 1, abort 1, leak 2
    tracker.commit_operation(&mut cell, "alloc-1").unwrap();
    tracker.abort_operation(&mut cell, "perm-1").unwrap();

    // Close cell to cause leaks for remaining active ops
    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 2);

    let leak_ids: Vec<&str> = leaks.iter().map(|l| l.operation_id.as_str()).collect();
    assert!(leak_ids.contains(&"state-1"));
    assert!(leak_ids.contains(&"ev-1"));

    // Check stats
    let stats = tracker.category_stats();
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].committed, 1);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].aborted, 1);
    assert_eq!(stats[&TwoPhaseCategory::StateMutation].leaked, 1);
    assert_eq!(stats[&TwoPhaseCategory::EvidenceCommit].leaked, 1);
}

#[test]
fn lifecycle_session_cell_tracked_independently_from_parent() {
    let mut ext_cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut ext_cell,
            "ext-op",
            TwoPhaseCategory::ResourceAlloc,
            "extension buffer",
        )
        .unwrap();

    let mut session_cell = ext_cell.create_session("sess-1", "trace-sess").unwrap();

    tracker
        .begin_operation(
            &mut session_cell,
            "sess-op",
            TwoPhaseCategory::PermissionGrant,
            "session grant",
        )
        .unwrap();

    assert_eq!(tracker.active_count(), 2);

    // Commit only the session operation
    tracker
        .commit_operation(&mut session_cell, "sess-op")
        .unwrap();

    assert_eq!(tracker.active_count(), 1);

    // Extension operation still active
    let ext_op = tracker.get_operation("ext-op").unwrap();
    assert_eq!(ext_op.phase, OperationPhase::Phase1Active);

    // Session operation committed
    let sess_op = tracker.get_operation("sess-op").unwrap();
    assert_eq!(sess_op.phase, OperationPhase::Committed);
}

#[test]
fn lifecycle_commit_during_drain_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::ResourceAlloc,
            "buffer cleanup",
        )
        .unwrap();

    // Initiate close (starts drain phase)
    cell.initiate_close(
        &mut cx,
        CancelReason::Quarantine,
        DrainDeadline { max_ticks: 100 },
    )
    .unwrap();

    // Commit during drain should work
    tracker.commit_operation(&mut cell, "op-1").unwrap();

    let op = tracker.get_operation("op-1").unwrap();
    assert_eq!(op.phase, OperationPhase::Committed);

    // Finalize succeeds because obligation was resolved
    let result = cell.finalize().unwrap();
    assert!(result.success);
    assert_eq!(result.obligations_committed, 1);
}

#[test]
fn lifecycle_multiple_operations_same_category() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    for i in 0..5 {
        tracker
            .begin_operation(
                &mut cell,
                format!("alloc-{i}"),
                TwoPhaseCategory::ResourceAlloc,
                format!("buffer {i}"),
            )
            .unwrap();
    }

    assert_eq!(tracker.active_count(), 5);
    assert_eq!(cell.pending_obligations(), 5);

    // Commit 3, abort 2
    for i in 0..3 {
        tracker
            .commit_operation(&mut cell, &format!("alloc-{i}"))
            .unwrap();
    }
    for i in 3..5 {
        tracker
            .abort_operation(&mut cell, &format!("alloc-{i}"))
            .unwrap();
    }

    assert_eq!(tracker.active_count(), 0);

    let stats = tracker.category_stats();
    let alloc_stats = stats.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_stats.started, 5);
    assert_eq!(alloc_stats.committed, 3);
    assert_eq!(alloc_stats.aborted, 2);
}

#[test]
fn lifecycle_abort_during_drain_succeeds() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::StateMutation,
            "rollback during drain",
        )
        .unwrap();

    cell.initiate_close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 100 },
    )
    .unwrap();

    // Abort during drain
    tracker.abort_operation(&mut cell, "op-1").unwrap();

    let op = tracker.get_operation("op-1").unwrap();
    assert_eq!(op.phase, OperationPhase::Aborted);
}

// ===========================================================================
// 2. Error paths and edge cases (8+ tests)
// ===========================================================================

#[test]
fn error_begin_on_closed_cell() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline::default(),
    )
    .unwrap();

    let mut tracker = ObligationTracker::default();
    let err = tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::ResourceAlloc,
            "too late",
        )
        .unwrap_err();

    assert_eq!(err.error_code(), "obligation_cell_not_running");
    match err {
        ObligationIntegrationError::CellNotRunning {
            cell_id,
            current_state,
        } => {
            assert_eq!(cell_id, "ext-1");
            assert_eq!(current_state, RegionState::Closed);
        }
        other => panic!("expected CellNotRunning, got: {other}"),
    }
}

#[test]
fn error_begin_duplicate_operation_id() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-dup",
            TwoPhaseCategory::ResourceAlloc,
            "first",
        )
        .unwrap();

    let err = tracker
        .begin_operation(
            &mut cell,
            "op-dup",
            TwoPhaseCategory::PermissionGrant,
            "duplicate",
        )
        .unwrap_err();

    assert_eq!(err.error_code(), "obligation_duplicate_operation");
    match err {
        ObligationIntegrationError::DuplicateOperation { operation_id } => {
            assert_eq!(operation_id, "op-dup");
        }
        other => panic!("expected DuplicateOperation, got: {other}"),
    }
}

#[test]
fn error_commit_nonexistent_operation() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    let err = tracker
        .commit_operation(&mut cell, "nonexistent")
        .unwrap_err();

    assert_eq!(err.error_code(), "obligation_operation_not_found");
    match err {
        ObligationIntegrationError::OperationNotFound { operation_id } => {
            assert_eq!(operation_id, "nonexistent");
        }
        other => panic!("expected OperationNotFound, got: {other}"),
    }
}

#[test]
fn error_commit_already_committed() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "tx")
        .unwrap();
    tracker.commit_operation(&mut cell, "op-1").unwrap();

    let err = tracker.commit_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_already_resolved");
    match err {
        ObligationIntegrationError::AlreadyResolved {
            operation_id,
            current_phase,
        } => {
            assert_eq!(operation_id, "op-1");
            assert_eq!(current_phase, OperationPhase::Committed);
        }
        other => panic!("expected AlreadyResolved, got: {other}"),
    }
}

#[test]
fn error_abort_already_aborted() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::EvidenceCommit,
            "evidence",
        )
        .unwrap();
    tracker.abort_operation(&mut cell, "op-1").unwrap();

    let err = tracker.abort_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_already_resolved");
    match err {
        ObligationIntegrationError::AlreadyResolved { current_phase, .. } => {
            assert_eq!(current_phase, OperationPhase::Aborted);
        }
        other => panic!("expected AlreadyResolved, got: {other}"),
    }
}

#[test]
fn error_commit_already_aborted_cross_phase() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();
    tracker.abort_operation(&mut cell, "op-1").unwrap();

    let err = tracker.commit_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_already_resolved");
    match err {
        ObligationIntegrationError::AlreadyResolved { current_phase, .. } => {
            assert_eq!(current_phase, OperationPhase::Aborted);
        }
        other => panic!("expected AlreadyResolved(Aborted), got: {other}"),
    }
}

#[test]
fn error_abort_already_committed_cross_phase() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();
    tracker.commit_operation(&mut cell, "op-1").unwrap();

    let err = tracker.abort_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_already_resolved");
    match err {
        ObligationIntegrationError::AlreadyResolved { current_phase, .. } => {
            assert_eq!(current_phase, OperationPhase::Committed);
        }
        other => panic!("expected AlreadyResolved(Committed), got: {other}"),
    }
}

#[test]
fn error_begin_on_draining_cell() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    cell.initiate_close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 100 },
    )
    .unwrap();

    let err = tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::StateMutation,
            "rejected",
        )
        .unwrap_err();

    assert_eq!(err.error_code(), "obligation_cell_not_running");
    match err {
        ObligationIntegrationError::CellNotRunning { current_state, .. } => {
            assert_ne!(current_state, RegionState::Running);
        }
        other => panic!("expected CellNotRunning, got: {other}"),
    }
}

#[test]
fn error_abort_nonexistent_operation() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    let err = tracker.abort_operation(&mut cell, "ghost").unwrap_err();

    assert_eq!(err.error_code(), "obligation_operation_not_found");
}

// ===========================================================================
// 3. Leak detection comprehensive (8+ tests)
// ===========================================================================

#[test]
fn leak_single_operation() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "leak-1",
            TwoPhaseCategory::ResourceAlloc,
            "will leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].operation_id, "leak-1");
    assert_eq!(leaks[0].category, TwoPhaseCategory::ResourceAlloc);
    assert_eq!(leaks[0].cell_id, "ext-1");
}

#[test]
fn leak_multiple_same_category() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    for i in 0..3 {
        tracker
            .begin_operation(
                &mut cell,
                format!("alloc-{i}"),
                TwoPhaseCategory::ResourceAlloc,
                format!("buffer {i}"),
            )
            .unwrap();
    }

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 3);
    for leak in &leaks {
        assert_eq!(leak.category, TwoPhaseCategory::ResourceAlloc);
    }
}

#[test]
fn leak_multiple_different_categories() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "alloc-1",
            TwoPhaseCategory::ResourceAlloc,
            "buffer",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "perm-1",
            TwoPhaseCategory::PermissionGrant,
            "access",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "state-1",
            TwoPhaseCategory::StateMutation,
            "config",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::Quarantine,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 3);

    let categories: Vec<TwoPhaseCategory> = leaks.iter().map(|l| l.category).collect();
    assert!(categories.contains(&TwoPhaseCategory::ResourceAlloc));
    assert!(categories.contains(&TwoPhaseCategory::PermissionGrant));
    assert!(categories.contains(&TwoPhaseCategory::StateMutation));
}

#[test]
fn leak_none_when_all_committed() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "op-2",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();

    tracker.commit_operation(&mut cell, "op-1").unwrap();
    tracker.commit_operation(&mut cell, "op-2").unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline::default(),
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert!(leaks.is_empty());
    assert!(!tracker.has_leaks());
}

#[test]
fn leak_none_when_all_aborted() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "tx1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "op-2", TwoPhaseCategory::EvidenceCommit, "ev1")
        .unwrap();

    tracker.abort_operation(&mut cell, "op-1").unwrap();
    tracker.abort_operation(&mut cell, "op-2").unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline::default(),
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert!(leaks.is_empty());
    assert!(!tracker.has_leaks());
}

#[test]
fn leak_none_when_cell_still_running() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "active")
        .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert!(leaks.is_empty());
    assert!(!tracker.has_leaks());
}

#[test]
fn leak_phase_is_terminal() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-leak",
            TwoPhaseCategory::ResourceAlloc,
            "will leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    let op = tracker.get_operation("op-leak").unwrap();
    assert_eq!(op.phase, OperationPhase::Leaked);

    // Second call to detect_leaks should not re-detect already-leaked ops
    let leaks_again = tracker.detect_leaks(&cell);
    assert!(leaks_again.is_empty());
}

#[test]
fn leak_stats_accumulate_correctly() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "alloc-2", TwoPhaseCategory::ResourceAlloc, "a2")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "alloc-3", TwoPhaseCategory::ResourceAlloc, "a3")
        .unwrap();

    // Commit one, abort one, leak one
    tracker.commit_operation(&mut cell, "alloc-1").unwrap();
    tracker.abort_operation(&mut cell, "alloc-2").unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    let stats = tracker.category_stats();
    let alloc_stats = stats.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_stats.started, 3);
    assert_eq!(alloc_stats.committed, 1);
    assert_eq!(alloc_stats.aborted, 1);
    assert_eq!(alloc_stats.leaked, 1);
}

// ===========================================================================
// 4. Lab vs Production policy (6+ tests)
// ===========================================================================

#[test]
fn policy_lab_should_fail_run_after_leak() {
    let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "trace-lab");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::lab();

    tracker
        .begin_operation(
            &mut cell,
            "op-lab",
            TwoPhaseCategory::ResourceAlloc,
            "leak me",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    assert!(tracker.should_fail_run());
    assert!(tracker.has_leaks());
}

#[test]
fn policy_lab_emits_lab_failure_event() {
    let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "trace-lab");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::lab();

    tracker
        .begin_operation(
            &mut cell,
            "op-lab",
            TwoPhaseCategory::PermissionGrant,
            "leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    let lab_events: Vec<&ObligationEvent> = tracker
        .events()
        .iter()
        .filter(|e| e.event == "lab_failure")
        .collect();
    assert_eq!(lab_events.len(), 1);
    assert_eq!(lab_events[0].outcome, "fatal");
    assert_eq!(lab_events[0].operation_id, "op-lab");
}

#[test]
fn policy_production_should_not_fail_run_with_leaks() {
    let mut cell = ExecutionCell::new("ext-prod", CellKind::Extension, "trace-prod");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-prod",
            TwoPhaseCategory::EvidenceCommit,
            "leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    assert!(!tracker.should_fail_run());
    assert!(tracker.has_leaks());
}

#[test]
fn policy_production_emits_production_fallback_event() {
    let mut cell = ExecutionCell::new("ext-prod", CellKind::Extension, "trace-prod");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-prod",
            TwoPhaseCategory::StateMutation,
            "leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    let fallback_events: Vec<&ObligationEvent> = tracker
        .events()
        .iter()
        .filter(|e| e.event == "production_fallback")
        .collect();
    assert_eq!(fallback_events.len(), 1);
    assert_eq!(fallback_events[0].outcome, "forced_cleanup");
    assert_eq!(fallback_events[0].operation_id, "op-prod");
}

#[test]
fn policy_default_tracker_is_production() {
    let tracker = ObligationTracker::default();
    assert_eq!(tracker.leak_policy(), LeakPolicy::Production);
}

#[test]
fn policy_lab_tracker_is_lab() {
    let tracker = ObligationTracker::lab();
    assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
}

#[test]
fn policy_lab_no_leaks_should_not_fail_run() {
    let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "trace-lab");
    let mut tracker = ObligationTracker::lab();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "clean")
        .unwrap();
    tracker.commit_operation(&mut cell, "op-1").unwrap();

    assert!(!tracker.should_fail_run());
    assert!(!tracker.has_leaks());
}

// ===========================================================================
// 5. Event emission and evidence (7+ tests)
// ===========================================================================

#[test]
fn event_begin_has_correct_fields() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-begin");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-begin",
            TwoPhaseCategory::ResourceAlloc,
            "alloc",
        )
        .unwrap();

    let events = tracker.events();
    assert_eq!(events.len(), 1);

    let event = &events[0];
    assert_eq!(event.event, "begin");
    assert_eq!(event.outcome, "phase1_active");
    assert_eq!(event.phase, OperationPhase::Phase1Active);
    assert_eq!(event.operation_id, "op-begin");
    assert_eq!(event.cell_id, "ext-1");
    assert_eq!(event.cell_kind, CellKind::Extension);
    assert_eq!(event.category, TwoPhaseCategory::ResourceAlloc);
    assert_eq!(event.trace_id, "trace-begin");
    assert_eq!(event.component, "obligation_integration");
}

#[test]
fn event_commit_has_correct_fields() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-commit");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-commit",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();
    tracker.commit_operation(&mut cell, "op-commit").unwrap();

    let events = tracker.events();
    assert_eq!(events.len(), 2);

    let event = &events[1];
    assert_eq!(event.event, "commit");
    assert_eq!(event.outcome, "committed");
    assert_eq!(event.phase, OperationPhase::Committed);
    assert_eq!(event.operation_id, "op-commit");
    assert_eq!(event.component, "obligation_integration");
}

#[test]
fn event_abort_has_correct_fields() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-abort");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-abort",
            TwoPhaseCategory::StateMutation,
            "rollback",
        )
        .unwrap();
    tracker.abort_operation(&mut cell, "op-abort").unwrap();

    let events = tracker.events();
    assert_eq!(events.len(), 2);

    let event = &events[1];
    assert_eq!(event.event, "abort");
    assert_eq!(event.outcome, "aborted");
    assert_eq!(event.phase, OperationPhase::Aborted);
    assert_eq!(event.operation_id, "op-abort");
    assert_eq!(event.component, "obligation_integration");
}

#[test]
fn event_leak_detected_has_correct_fields() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-leak");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-leak",
            TwoPhaseCategory::EvidenceCommit,
            "evidence leak",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    let leak_events: Vec<&ObligationEvent> = tracker
        .events()
        .iter()
        .filter(|e| e.event == "leak_detected")
        .collect();
    assert_eq!(leak_events.len(), 1);

    let event = leak_events[0];
    assert_eq!(event.outcome, "leaked");
    assert_eq!(event.phase, OperationPhase::Leaked);
    assert_eq!(event.operation_id, "op-leak");
    assert_eq!(event.category, TwoPhaseCategory::EvidenceCommit);
    assert_eq!(event.component, "obligation_integration");
}

#[test]
fn event_drain_events_clears_buffer() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();

    assert!(!tracker.events().is_empty());

    let drained = tracker.drain_events();
    assert!(!drained.is_empty());
    assert!(tracker.events().is_empty());
}

#[test]
fn event_events_returns_accumulated_without_clearing() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "op-2",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();

    let first_read = tracker.events().len();
    let second_read = tracker.events().len();
    assert_eq!(first_read, 2);
    assert_eq!(first_read, second_read);
}

#[test]
fn event_component_field_is_always_obligation_integration() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();
    tracker.commit_operation(&mut cell, "op-1").unwrap();
    tracker
        .begin_operation(&mut cell, "op-2", TwoPhaseCategory::StateMutation, "mutate")
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);

    for event in tracker.events() {
        assert_eq!(
            event.component, "obligation_integration",
            "event {} has wrong component: {}",
            event.event, event.component
        );
    }
}

// ===========================================================================
// 6. Statistics tracking (6+ tests)
// ===========================================================================

#[test]
fn stats_accumulate_per_category() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "alloc-2", TwoPhaseCategory::ResourceAlloc, "a2")
        .unwrap();

    tracker.commit_operation(&mut cell, "alloc-1").unwrap();
    tracker.abort_operation(&mut cell, "alloc-2").unwrap();

    let stats = tracker.category_stats();
    let alloc_stats = stats.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_stats.started, 2);
    assert_eq!(alloc_stats.committed, 1);
    assert_eq!(alloc_stats.aborted, 1);
}

#[test]
fn stats_multiple_categories_tracked_independently() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "perm-1", TwoPhaseCategory::PermissionGrant, "p")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "state-1", TwoPhaseCategory::StateMutation, "s")
        .unwrap();

    tracker.commit_operation(&mut cell, "alloc-1").unwrap();
    tracker.abort_operation(&mut cell, "perm-1").unwrap();
    tracker.commit_operation(&mut cell, "state-1").unwrap();

    let stats = tracker.category_stats();
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].committed, 1);
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].aborted, 0);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].committed, 0);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].aborted, 1);
    assert_eq!(stats[&TwoPhaseCategory::StateMutation].committed, 1);
}

#[test]
fn stats_after_mixed_operations() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    for i in 0..4 {
        tracker
            .begin_operation(
                &mut cell,
                format!("ev-{i}"),
                TwoPhaseCategory::EvidenceCommit,
                format!("evidence {i}"),
            )
            .unwrap();
    }

    tracker.commit_operation(&mut cell, "ev-0").unwrap();
    tracker.commit_operation(&mut cell, "ev-1").unwrap();
    tracker.abort_operation(&mut cell, "ev-2").unwrap();
    tracker.abort_operation(&mut cell, "ev-3").unwrap();

    let stats = tracker.category_stats();
    let ev_stats = stats.get(&TwoPhaseCategory::EvidenceCommit).unwrap();
    assert_eq!(ev_stats.started, 4);
    assert_eq!(ev_stats.committed, 2);
    assert_eq!(ev_stats.aborted, 2);
    assert_eq!(ev_stats.leaked, 0);
}

#[test]
fn stats_include_leaked_count_after_detect_leaks() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "alloc-2", TwoPhaseCategory::ResourceAlloc, "a2")
        .unwrap();
    tracker.commit_operation(&mut cell, "alloc-1").unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    // Before detect_leaks
    let stats_before = tracker.category_stats();
    let alloc_before = stats_before.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_before.leaked, 0);

    tracker.detect_leaks(&cell);

    // After detect_leaks
    let stats_after = tracker.category_stats();
    let alloc_after = stats_after.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
    assert_eq!(alloc_after.leaked, 1);
    assert_eq!(alloc_after.started, 2);
    assert_eq!(alloc_after.committed, 1);
}

#[test]
fn stats_empty_for_unused_categories() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a")
        .unwrap();
    tracker.commit_operation(&mut cell, "alloc-1").unwrap();

    let stats = tracker.category_stats();
    // PermissionGrant was never used, so it should not be present
    assert!(stats.get(&TwoPhaseCategory::PermissionGrant).is_none());
    assert!(stats.get(&TwoPhaseCategory::StateMutation).is_none());
    assert!(stats.get(&TwoPhaseCategory::EvidenceCommit).is_none());
    // ResourceAlloc should be present
    assert!(stats.get(&TwoPhaseCategory::ResourceAlloc).is_some());
}

#[test]
fn stats_active_count_and_total_count() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.total_count(), 0);

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "a")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "op-2", TwoPhaseCategory::PermissionGrant, "p")
        .unwrap();

    assert_eq!(tracker.active_count(), 2);
    assert_eq!(tracker.total_count(), 2);

    tracker.commit_operation(&mut cell, "op-1").unwrap();

    assert_eq!(tracker.active_count(), 1);
    assert_eq!(tracker.total_count(), 2);

    tracker.abort_operation(&mut cell, "op-2").unwrap();

    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.total_count(), 2);
}

// ===========================================================================
// 7. Serde roundtrips (8+ tests)
// ===========================================================================

#[test]
fn serde_two_phase_category_all_variants() {
    let variants = [
        TwoPhaseCategory::ResourceAlloc,
        TwoPhaseCategory::PermissionGrant,
        TwoPhaseCategory::StateMutation,
        TwoPhaseCategory::EvidenceCommit,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: TwoPhaseCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_operation_phase_all_variants() {
    let variants = [
        OperationPhase::Phase1Active,
        OperationPhase::Committed,
        OperationPhase::Aborted,
        OperationPhase::Leaked,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let restored: OperationPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, restored);
    }
}

#[test]
fn serde_two_phase_operation() {
    let op = TwoPhaseOperation {
        operation_id: "op-serde-1".to_string(),
        cell_id: "cell-serde".to_string(),
        category: TwoPhaseCategory::PermissionGrant,
        description: "test serde roundtrip".to_string(),
        trace_id: "trace-serde".to_string(),
        phase: OperationPhase::Committed,
    };
    let json = serde_json::to_string(&op).expect("serialize");
    let restored: TwoPhaseOperation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(op, restored);
}

#[test]
fn serde_obligation_event() {
    let event = ObligationEvent {
        trace_id: "trace-serde".to_string(),
        cell_id: "cell-serde".to_string(),
        cell_kind: CellKind::Session,
        operation_id: "op-serde".to_string(),
        category: TwoPhaseCategory::StateMutation,
        event: "commit".to_string(),
        outcome: "committed".to_string(),
        component: "obligation_integration".to_string(),
        phase: OperationPhase::Committed,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: ObligationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn serde_leak_record() {
    let leak = LeakRecord {
        operation_id: "leaked-op".to_string(),
        cell_id: "leaked-cell".to_string(),
        category: TwoPhaseCategory::EvidenceCommit,
        trace_id: "leaked-trace".to_string(),
        description: "evidence that leaked".to_string(),
    };
    let json = serde_json::to_string(&leak).expect("serialize");
    let restored: LeakRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(leak, restored);
}

#[test]
fn serde_category_stats() {
    let stats = CategoryStats {
        started: 10,
        committed: 7,
        aborted: 2,
        leaked: 1,
    };
    let json = serde_json::to_string(&stats).expect("serialize");
    let restored: CategoryStats = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stats, restored);
}

#[test]
fn serde_leak_policy_both_variants() {
    for policy in [LeakPolicy::Lab, LeakPolicy::Production] {
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: LeakPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }
}

#[test]
fn serde_obligation_integration_error_all_variants() {
    let errors = vec![
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c1".to_string(),
            current_state: RegionState::Closed,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op-miss".to_string(),
        },
        ObligationIntegrationError::AlreadyResolved {
            operation_id: "op-done".to_string(),
            current_phase: OperationPhase::Committed,
        },
        ObligationIntegrationError::DuplicateOperation {
            operation_id: "op-dup".to_string(),
        },
        ObligationIntegrationError::CellError {
            message: "cell broke".to_string(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ObligationIntegrationError =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, &restored);
    }
}

// ===========================================================================
// 8. Determinism (2+ tests)
// ===========================================================================

#[test]
fn determinism_same_sequence_produces_identical_events() {
    let run = || -> Vec<ObligationEvent> {
        let mut cell = ExecutionCell::new("ext-det", CellKind::Extension, "trace-det");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "alloc-1",
                TwoPhaseCategory::ResourceAlloc,
                "buffer",
            )
            .unwrap();
        tracker
            .begin_operation(
                &mut cell,
                "perm-1",
                TwoPhaseCategory::PermissionGrant,
                "grant",
            )
            .unwrap();
        tracker
            .begin_operation(&mut cell, "state-1", TwoPhaseCategory::StateMutation, "tx")
            .unwrap();

        tracker.commit_operation(&mut cell, "alloc-1").unwrap();
        tracker.abort_operation(&mut cell, "perm-1").unwrap();
        tracker.commit_operation(&mut cell, "state-1").unwrap();

        tracker.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

#[test]
fn determinism_same_sequence_produces_identical_stats() {
    let run = || -> BTreeMap<TwoPhaseCategory, CategoryStats> {
        let mut cell = ExecutionCell::new("ext-det", CellKind::Extension, "trace-det");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "alloc-2", TwoPhaseCategory::ResourceAlloc, "a2")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "perm-1", TwoPhaseCategory::PermissionGrant, "p1")
            .unwrap();

        tracker.commit_operation(&mut cell, "alloc-1").unwrap();
        tracker.abort_operation(&mut cell, "alloc-2").unwrap();
        tracker.commit_operation(&mut cell, "perm-1").unwrap();

        tracker.category_stats().clone()
    };

    let stats1 = run();
    let stats2 = run();
    assert_eq!(stats1, stats2);
}

#[test]
fn determinism_leak_detection_order_is_stable() {
    let run = || -> Vec<String> {
        let mut cell = ExecutionCell::new("ext-det", CellKind::Extension, "trace-det");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "perm-1", TwoPhaseCategory::PermissionGrant, "p1")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "state-1", TwoPhaseCategory::StateMutation, "s1")
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        leaks.iter().map(|l| l.operation_id.clone()).collect()
    };

    let order1 = run();
    let order2 = run();
    assert_eq!(order1, order2);
}

// ===========================================================================
// Additional edge-case tests
// ===========================================================================

#[test]
fn error_display_formats_are_nonempty() {
    let errors = vec![
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c1".to_string(),
            current_state: RegionState::Draining,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op-1".to_string(),
        },
        ObligationIntegrationError::AlreadyResolved {
            operation_id: "op-1".to_string(),
            current_phase: OperationPhase::Leaked,
        },
        ObligationIntegrationError::DuplicateOperation {
            operation_id: "op-1".to_string(),
        },
        ObligationIntegrationError::CellError {
            message: "something failed".to_string(),
        },
    ];

    for err in &errors {
        let display = err.to_string();
        assert!(
            !display.is_empty(),
            "Display for {err:?} should not be empty"
        );
        let code = err.error_code();
        assert!(
            code.starts_with("obligation_"),
            "error_code should start with obligation_: {code}"
        );
    }
}

#[test]
fn error_from_cell_error_conversion() {
    let cell_err = CellError::CellNotFound {
        cell_id: "missing-cell".to_string(),
    };
    let integration_err: ObligationIntegrationError = cell_err.into();
    assert_eq!(integration_err.error_code(), "obligation_cell_error");
    match integration_err {
        ObligationIntegrationError::CellError { message } => {
            assert!(message.contains("missing-cell"));
        }
        other => panic!("expected CellError, got: {other}"),
    }
}

#[test]
fn get_operation_returns_none_for_nonexistent() {
    let tracker = ObligationTracker::default();
    assert!(tracker.get_operation("nonexistent").is_none());
}

#[test]
fn get_operation_returns_correct_after_begin() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-get",
            TwoPhaseCategory::EvidenceCommit,
            "evidence for get test",
        )
        .unwrap();

    let op = tracker.get_operation("op-get").unwrap();
    assert_eq!(op.operation_id, "op-get");
    assert_eq!(op.cell_id, "ext-1");
    assert_eq!(op.category, TwoPhaseCategory::EvidenceCommit);
    assert_eq!(op.description, "evidence for get test");
    assert_eq!(op.trace_id, "trace-1");
    assert_eq!(op.phase, OperationPhase::Phase1Active);
}

#[test]
fn leak_record_metadata_matches_operation() {
    let mut cell = ExecutionCell::new("ext-meta", CellKind::Extension, "trace-meta");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "meta-op",
            TwoPhaseCategory::PermissionGrant,
            "grant with metadata",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::Revocation,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].operation_id, "meta-op");
    assert_eq!(leaks[0].cell_id, "ext-meta");
    assert_eq!(leaks[0].category, TwoPhaseCategory::PermissionGrant);
    assert_eq!(leaks[0].trace_id, "trace-meta");
    assert_eq!(leaks[0].description, "grant with metadata");
}

#[test]
fn commit_on_closed_cell_returns_cell_not_running() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let err = tracker.commit_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_cell_not_running");
}

#[test]
fn abort_on_closed_cell_returns_cell_not_running() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut cx = mock_cx(200);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-1",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let err = tracker.abort_operation(&mut cell, "op-1").unwrap_err();
    assert_eq!(err.error_code(), "obligation_cell_not_running");
}

#[test]
fn two_phase_category_display_strings() {
    assert_eq!(
        TwoPhaseCategory::ResourceAlloc.to_string(),
        "resource_alloc"
    );
    assert_eq!(
        TwoPhaseCategory::PermissionGrant.to_string(),
        "permission_grant"
    );
    assert_eq!(
        TwoPhaseCategory::StateMutation.to_string(),
        "state_mutation"
    );
    assert_eq!(
        TwoPhaseCategory::EvidenceCommit.to_string(),
        "evidence_commit"
    );
}

#[test]
fn operation_phase_display_strings() {
    assert_eq!(OperationPhase::Phase1Active.to_string(), "phase1_active");
    assert_eq!(OperationPhase::Committed.to_string(), "committed");
    assert_eq!(OperationPhase::Aborted.to_string(), "aborted");
    assert_eq!(OperationPhase::Leaked.to_string(), "leaked");
}
