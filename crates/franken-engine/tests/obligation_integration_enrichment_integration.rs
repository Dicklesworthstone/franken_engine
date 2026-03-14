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

use std::collections::BTreeSet;

use frankenengine_engine::execution_cell::{CellKind, ExecutionCell};
use frankenengine_engine::obligation_integration::{
    CategoryStats, LeakPolicy, LeakRecord, ObligationEvent, ObligationIntegrationError,
    ObligationTracker, OperationPhase, TwoPhaseCategory, TwoPhaseOperation,
};
use frankenengine_engine::region_lifecycle::RegionState;

// =========================================================================
// A. BTreeSet ordering and dedup for enums
// =========================================================================

#[test]
fn enrichment_two_phase_category_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(TwoPhaseCategory::ResourceAlloc);
    set.insert(TwoPhaseCategory::PermissionGrant);
    set.insert(TwoPhaseCategory::StateMutation);
    set.insert(TwoPhaseCategory::EvidenceCommit);
    set.insert(TwoPhaseCategory::ResourceAlloc); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_operation_phase_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(OperationPhase::Phase1Active);
    set.insert(OperationPhase::Committed);
    set.insert(OperationPhase::Aborted);
    set.insert(OperationPhase::Leaked);
    set.insert(OperationPhase::Phase1Active); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_two_phase_category_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for cat in &[
        TwoPhaseCategory::ResourceAlloc,
        TwoPhaseCategory::PermissionGrant,
        TwoPhaseCategory::StateMutation,
        TwoPhaseCategory::EvidenceCommit,
    ] {
        let mut h1 = DefaultHasher::new();
        cat.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        cat.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_operation_phase_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for phase in &[
        OperationPhase::Phase1Active,
        OperationPhase::Committed,
        OperationPhase::Aborted,
        OperationPhase::Leaked,
    ] {
        let mut h1 = DefaultHasher::new();
        phase.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        phase.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// =========================================================================
// C. Display values distinct
// =========================================================================

#[test]
fn enrichment_two_phase_category_display_distinct() {
    let displays: BTreeSet<String> = [
        TwoPhaseCategory::ResourceAlloc,
        TwoPhaseCategory::PermissionGrant,
        TwoPhaseCategory::StateMutation,
        TwoPhaseCategory::EvidenceCommit,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_operation_phase_display_distinct() {
    let displays: BTreeSet<String> = [
        OperationPhase::Phase1Active,
        OperationPhase::Committed,
        OperationPhase::Aborted,
        OperationPhase::Leaked,
    ]
    .iter()
    .map(|p| p.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_error_display_distinct() {
    let errors = [
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c1".to_string(),
            current_state: RegionState::Closed,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op-1".to_string(),
        },
        ObligationIntegrationError::AlreadyResolved {
            operation_id: "op-2".to_string(),
            current_phase: OperationPhase::Committed,
        },
        ObligationIntegrationError::DuplicateOperation {
            operation_id: "op-3".to_string(),
        },
        ObligationIntegrationError::CellError {
            message: "broke".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

// =========================================================================
// D. Debug nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_enums() {
    for cat in &[
        TwoPhaseCategory::ResourceAlloc,
        TwoPhaseCategory::PermissionGrant,
        TwoPhaseCategory::StateMutation,
        TwoPhaseCategory::EvidenceCommit,
    ] {
        assert!(!format!("{cat:?}").is_empty());
    }
    for phase in &[
        OperationPhase::Phase1Active,
        OperationPhase::Committed,
        OperationPhase::Aborted,
        OperationPhase::Leaked,
    ] {
        assert!(!format!("{phase:?}").is_empty());
    }
    assert!(!format!("{:?}", LeakPolicy::Lab).is_empty());
    assert!(!format!("{:?}", LeakPolicy::Production).is_empty());
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let op = TwoPhaseOperation {
        operation_id: "op-1".to_string(),
        cell_id: "cell-1".to_string(),
        category: TwoPhaseCategory::ResourceAlloc,
        description: "test".to_string(),
        trace_id: "trace-1".to_string(),
        phase: OperationPhase::Phase1Active,
    };
    assert!(!format!("{op:?}").is_empty());

    let stats = CategoryStats::default();
    assert!(!format!("{stats:?}").is_empty());

    let leak = LeakRecord {
        operation_id: "op-1".to_string(),
        cell_id: "cell-1".to_string(),
        category: TwoPhaseCategory::ResourceAlloc,
        trace_id: "t".to_string(),
        description: "d".to_string(),
    };
    assert!(!format!("{leak:?}").is_empty());

    let event = ObligationEvent {
        trace_id: "t".to_string(),
        cell_id: "c".to_string(),
        cell_kind: CellKind::Extension,
        operation_id: "op".to_string(),
        category: TwoPhaseCategory::StateMutation,
        event: "begin".to_string(),
        outcome: "phase1_active".to_string(),
        component: "obligation_integration".to_string(),
        phase: OperationPhase::Phase1Active,
    };
    assert!(!format!("{event:?}").is_empty());

    let tracker = ObligationTracker::default();
    assert!(!format!("{tracker:?}").is_empty());

    for err in &[
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c".to_string(),
            current_state: RegionState::Closed,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op".to_string(),
        },
    ] {
        assert!(!format!("{err:?}").is_empty());
    }
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_two_phase_operation() {
    let original = TwoPhaseOperation {
        operation_id: "op-orig".to_string(),
        cell_id: "cell-1".to_string(),
        category: TwoPhaseCategory::ResourceAlloc,
        description: "original".to_string(),
        trace_id: "t-orig".to_string(),
        phase: OperationPhase::Phase1Active,
    };
    let mut cloned = original.clone();
    cloned.operation_id = "op-mod".to_string();
    cloned.phase = OperationPhase::Committed;
    assert_eq!(original.operation_id, "op-orig");
    assert_eq!(original.phase, OperationPhase::Phase1Active);
}

#[test]
fn enrichment_clone_independence_leak_record() {
    let original = LeakRecord {
        operation_id: "op-1".to_string(),
        cell_id: "cell-1".to_string(),
        category: TwoPhaseCategory::EvidenceCommit,
        trace_id: "t-1".to_string(),
        description: "original".to_string(),
    };
    let mut cloned = original.clone();
    cloned.operation_id = "op-modified".to_string();
    assert_eq!(original.operation_id, "op-1");
}

#[test]
fn enrichment_clone_independence_category_stats() {
    let original = CategoryStats {
        started: 10,
        committed: 8,
        aborted: 1,
        leaked: 1,
    };
    let cloned = original.clone();
    assert_eq!(cloned.started, 10);
    assert_eq!(cloned.committed, 8);
    assert_eq!(original.started, 10);
}

// =========================================================================
// F. Copy semantics
// =========================================================================

#[test]
fn enrichment_copy_semantics_two_phase_category() {
    let a = TwoPhaseCategory::PermissionGrant;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_operation_phase() {
    let a = OperationPhase::Leaked;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_leak_policy() {
    let a = LeakPolicy::Lab;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// G. Serde roundtrips
// =========================================================================

#[test]
fn enrichment_two_phase_operation_serde_roundtrip() {
    let op = TwoPhaseOperation {
        operation_id: "op-serde".to_string(),
        cell_id: "cell-serde".to_string(),
        category: TwoPhaseCategory::StateMutation,
        description: "test serde".to_string(),
        trace_id: "trace-serde".to_string(),
        phase: OperationPhase::Aborted,
    };
    let json = serde_json::to_string(&op).unwrap();
    let back: TwoPhaseOperation = serde_json::from_str(&json).unwrap();
    assert_eq!(op, back);
}

#[test]
fn enrichment_obligation_event_serde_roundtrip() {
    let event = ObligationEvent {
        trace_id: "t-001".to_string(),
        cell_id: "cell-001".to_string(),
        cell_kind: CellKind::Extension,
        operation_id: "op-001".to_string(),
        category: TwoPhaseCategory::EvidenceCommit,
        event: "commit".to_string(),
        outcome: "committed".to_string(),
        component: "obligation_integration".to_string(),
        phase: OperationPhase::Committed,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_leak_record_serde_roundtrip() {
    let leak = LeakRecord {
        operation_id: "op-leak".to_string(),
        cell_id: "cell-leak".to_string(),
        category: TwoPhaseCategory::ResourceAlloc,
        trace_id: "t-leak".to_string(),
        description: "leaked memory buffer".to_string(),
    };
    let json = serde_json::to_string(&leak).unwrap();
    let back: LeakRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(leak, back);
}

#[test]
fn enrichment_category_stats_serde_roundtrip() {
    let stats = CategoryStats {
        started: 100,
        committed: 90,
        aborted: 5,
        leaked: 5,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: CategoryStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn enrichment_category_stats_default_serde() {
    let stats = CategoryStats::default();
    let json = serde_json::to_string(&stats).unwrap();
    let back: CategoryStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
    assert_eq!(back.started, 0);
    assert_eq!(back.committed, 0);
    assert_eq!(back.aborted, 0);
    assert_eq!(back.leaked, 0);
}

#[test]
fn enrichment_leak_policy_serde_roundtrip() {
    for policy in &[LeakPolicy::Lab, LeakPolicy::Production] {
        let json = serde_json::to_string(policy).unwrap();
        let back: LeakPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*policy, back);
    }
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = [
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c".to_string(),
            current_state: RegionState::Closed,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op".to_string(),
        },
        ObligationIntegrationError::AlreadyResolved {
            operation_id: "op".to_string(),
            current_phase: OperationPhase::Aborted,
        },
        ObligationIntegrationError::DuplicateOperation {
            operation_id: "op".to_string(),
        },
        ObligationIntegrationError::CellError {
            message: "broke".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ObligationIntegrationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// =========================================================================
// H. Error codes are stable and distinct
// =========================================================================

#[test]
fn enrichment_error_codes_distinct() {
    let errors = [
        ObligationIntegrationError::CellNotRunning {
            cell_id: "c".to_string(),
            current_state: RegionState::Closed,
        },
        ObligationIntegrationError::OperationNotFound {
            operation_id: "op".to_string(),
        },
        ObligationIntegrationError::AlreadyResolved {
            operation_id: "op".to_string(),
            current_phase: OperationPhase::Committed,
        },
        ObligationIntegrationError::DuplicateOperation {
            operation_id: "op".to_string(),
        },
        ObligationIntegrationError::CellError {
            message: "m".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), 5);
    // All start with "obligation_"
    for code in &codes {
        assert!(
            code.starts_with("obligation_"),
            "code {code} missing prefix"
        );
    }
}

// =========================================================================
// I. Error implements std::error::Error
// =========================================================================

#[test]
fn enrichment_error_is_std_error() {
    let err = ObligationIntegrationError::OperationNotFound {
        operation_id: "op-1".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
    assert!(dyn_err.source().is_none());
}

// =========================================================================
// J. LeakPolicy default
// =========================================================================

#[test]
fn enrichment_leak_policy_default_is_production() {
    assert_eq!(LeakPolicy::default(), LeakPolicy::Production);
}

// =========================================================================
// K. Tracker constructors and initial state
// =========================================================================

#[test]
fn enrichment_tracker_default_initial_state() {
    let tracker = ObligationTracker::default();
    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.total_count(), 0);
    assert!(!tracker.has_leaks());
    assert!(!tracker.should_fail_run());
    assert!(tracker.leaks().is_empty());
    assert!(tracker.events().is_empty());
    assert!(tracker.category_stats().is_empty());
    assert_eq!(tracker.leak_policy(), LeakPolicy::Production);
}

#[test]
fn enrichment_tracker_lab_initial_state() {
    let tracker = ObligationTracker::lab();
    assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
    assert_eq!(tracker.active_count(), 0);
    assert!(!tracker.has_leaks());
    assert!(!tracker.should_fail_run()); // no leaks yet
}

// =========================================================================
// L. Begin/commit/abort lifecycle with events and stats
// =========================================================================

#[test]
fn enrichment_begin_commit_emits_events() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();

    let events = tracker.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].event, "begin");
    assert_eq!(events[0].phase, OperationPhase::Phase1Active);
    assert_eq!(events[0].category, TwoPhaseCategory::ResourceAlloc);

    tracker.commit_operation(&mut cell, "op-1").unwrap();
    let events = tracker.events();
    assert!(events.len() >= 2);
    let last = events.last().unwrap();
    assert_eq!(last.event, "commit");
    assert_eq!(last.phase, OperationPhase::Committed);
}

#[test]
fn enrichment_begin_abort_updates_stats() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "mutate")
        .unwrap();

    tracker.abort_operation(&mut cell, "op-1").unwrap();

    let stats = tracker.category_stats();
    let cat_stats = &stats[&TwoPhaseCategory::StateMutation];
    assert_eq!(cat_stats.started, 1);
    assert_eq!(cat_stats.aborted, 1);
    assert_eq!(cat_stats.committed, 0);

    let op = tracker.get_operation("op-1").unwrap();
    assert_eq!(op.phase, OperationPhase::Aborted);
}

// =========================================================================
// M. Error conditions
// =========================================================================

#[test]
fn enrichment_duplicate_operation_rejected() {
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
            TwoPhaseCategory::ResourceAlloc,
            "second",
        )
        .unwrap_err();

    assert!(matches!(
        err,
        ObligationIntegrationError::DuplicateOperation { .. }
    ));
}

#[test]
fn enrichment_commit_nonexistent_operation() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    let err = tracker
        .commit_operation(&mut cell, "nonexistent")
        .unwrap_err();
    assert!(matches!(
        err,
        ObligationIntegrationError::OperationNotFound { .. }
    ));
}

#[test]
fn enrichment_double_commit_rejected() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-dbl",
            TwoPhaseCategory::EvidenceCommit,
            "evidence",
        )
        .unwrap();
    tracker.commit_operation(&mut cell, "op-dbl").unwrap();

    let err = tracker.commit_operation(&mut cell, "op-dbl").unwrap_err();
    assert!(matches!(
        err,
        ObligationIntegrationError::AlreadyResolved { .. }
    ));
}

// =========================================================================
// N. Drain events clears accumulator
// =========================================================================

#[test]
fn enrichment_drain_events_clears() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();

    let drained = tracker.drain_events();
    assert!(!drained.is_empty());
    assert!(tracker.events().is_empty());
}

// =========================================================================
// O. Multiple categories in same tracker
// =========================================================================

#[test]
fn enrichment_multiple_categories_tracked_separately() {
    let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-alloc",
            TwoPhaseCategory::ResourceAlloc,
            "alloc",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "op-perm",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "op-mut",
            TwoPhaseCategory::StateMutation,
            "mutate",
        )
        .unwrap();

    assert_eq!(tracker.active_count(), 3);
    assert_eq!(tracker.total_count(), 3);

    tracker.commit_operation(&mut cell, "op-alloc").unwrap();
    tracker.abort_operation(&mut cell, "op-perm").unwrap();

    assert_eq!(tracker.active_count(), 1);

    let stats = tracker.category_stats();
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].committed, 1);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].aborted, 1);
    assert_eq!(stats[&TwoPhaseCategory::StateMutation].started, 1);
}

// =========================================================================
// P. detect_leaks lifecycle — running cell yields no leaks, closed cell does
// =========================================================================

#[test]
fn enrichment_detect_leaks_no_leaks_while_running() {
    let mut cell = ExecutionCell::new("ext-dl", CellKind::Extension, "trace-dl");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-run",
            TwoPhaseCategory::ResourceAlloc,
            "alloc",
        )
        .unwrap();

    // Cell still running — detect_leaks must return empty
    let leaks = tracker.detect_leaks(&cell);
    assert!(leaks.is_empty());
    assert!(!tracker.has_leaks());
    assert_eq!(tracker.active_count(), 1);
}

#[test]
fn enrichment_detect_leaks_after_close_finds_pending() {
    use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
    use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline};

    let mut cell = ExecutionCell::new("ext-dlc", CellKind::Extension, "trace-dlc");
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(200));
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-p1",
            TwoPhaseCategory::PermissionGrant,
            "grant",
        )
        .unwrap();
    tracker
        .begin_operation(
            &mut cell,
            "op-p2",
            TwoPhaseCategory::EvidenceCommit,
            "evidence",
        )
        .unwrap();
    // Commit one so only one leaks
    tracker.commit_operation(&mut cell, "op-p1").unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].operation_id, "op-p2");
    assert_eq!(leaks[0].category, TwoPhaseCategory::EvidenceCommit);
    assert!(tracker.has_leaks());
}

// =========================================================================
// Q. should_fail_run: lab vs production policy
// =========================================================================

#[test]
fn enrichment_should_fail_run_lab_with_leaks() {
    use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
    use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline};

    let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "trace-lab");
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(200));
    let mut tracker = ObligationTracker::lab();

    tracker
        .begin_operation(
            &mut cell,
            "op-lab",
            TwoPhaseCategory::StateMutation,
            "mutate",
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
}

#[test]
fn enrichment_should_fail_run_production_with_leaks_false() {
    use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
    use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline};

    let mut cell = ExecutionCell::new("ext-prod", CellKind::Extension, "trace-prod");
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(200));
    let mut tracker = ObligationTracker::default(); // Production policy

    tracker
        .begin_operation(
            &mut cell,
            "op-prod",
            TwoPhaseCategory::StateMutation,
            "mutate",
        )
        .unwrap();

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 5 },
    )
    .unwrap();

    tracker.detect_leaks(&cell);
    // Production policy: has_leaks is true, but should_fail_run is false
    assert!(tracker.has_leaks());
    assert!(!tracker.should_fail_run());
}

// =========================================================================
// R. Abort on nonexistent operation
// =========================================================================

#[test]
fn enrichment_abort_nonexistent_operation_returns_not_found() {
    let mut cell = ExecutionCell::new("ext-anf", CellKind::Extension, "trace-anf");
    let mut tracker = ObligationTracker::default();

    let err = tracker
        .abort_operation(&mut cell, "does-not-exist")
        .unwrap_err();
    assert!(matches!(
        err,
        ObligationIntegrationError::OperationNotFound { .. }
    ));
    assert_eq!(err.error_code(), "obligation_operation_not_found");
}

// =========================================================================
// S. Double abort rejected
// =========================================================================

#[test]
fn enrichment_double_abort_rejected() {
    let mut cell = ExecutionCell::new("ext-da", CellKind::Extension, "trace-da");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-da", TwoPhaseCategory::ResourceAlloc, "alloc")
        .unwrap();
    tracker.abort_operation(&mut cell, "op-da").unwrap();

    let err = tracker.abort_operation(&mut cell, "op-da").unwrap_err();
    assert!(matches!(
        err,
        ObligationIntegrationError::AlreadyResolved { .. }
    ));
}

// =========================================================================
// T. get_operation returns None for missing
// =========================================================================

#[test]
fn enrichment_get_operation_none_for_missing() {
    let tracker = ObligationTracker::default();
    assert!(tracker.get_operation("nonexistent-op").is_none());
}

// =========================================================================
// U. total_count vs active_count after resolution
// =========================================================================

#[test]
fn enrichment_total_vs_active_count_diverges_after_resolution() {
    let mut cell = ExecutionCell::new("ext-cnt", CellKind::Extension, "trace-cnt");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(&mut cell, "op-c1", TwoPhaseCategory::ResourceAlloc, "a1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "op-c2", TwoPhaseCategory::PermissionGrant, "g1")
        .unwrap();
    tracker
        .begin_operation(&mut cell, "op-c3", TwoPhaseCategory::StateMutation, "m1")
        .unwrap();

    assert_eq!(tracker.active_count(), 3);
    assert_eq!(tracker.total_count(), 3);

    tracker.commit_operation(&mut cell, "op-c1").unwrap();
    tracker.abort_operation(&mut cell, "op-c2").unwrap();

    // total stays 3, active drops to 1
    assert_eq!(tracker.total_count(), 3);
    assert_eq!(tracker.active_count(), 1);
}

// =========================================================================
// V. Event field correctness (component, cell_kind, trace_id)
// =========================================================================

#[test]
fn enrichment_event_fields_correctly_populated() {
    let mut cell = ExecutionCell::new("ext-ef", CellKind::Session, "trace-ef");
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "op-ef",
            TwoPhaseCategory::EvidenceCommit,
            "commit evidence",
        )
        .unwrap();

    let events = tracker.events();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.cell_id, "ext-ef");
    assert_eq!(ev.cell_kind, CellKind::Session);
    assert_eq!(ev.trace_id, "trace-ef");
    assert_eq!(ev.operation_id, "op-ef");
    assert_eq!(ev.category, TwoPhaseCategory::EvidenceCommit);
    assert_eq!(ev.component, "obligation_integration");
    assert_eq!(ev.event, "begin");
    assert_eq!(ev.outcome, "phase1_active");
    assert_eq!(ev.phase, OperationPhase::Phase1Active);
}

// =========================================================================
// W. Determinism: identical operations yield identical event sequences
// =========================================================================

#[test]
fn enrichment_deterministic_event_sequence() {
    fn run_scenario() -> Vec<(String, String, String)> {
        let mut cell = ExecutionCell::new("ext-det", CellKind::Extension, "trace-det");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-a", TwoPhaseCategory::ResourceAlloc, "alloc")
            .unwrap();
        tracker
            .begin_operation(
                &mut cell,
                "op-b",
                TwoPhaseCategory::PermissionGrant,
                "grant",
            )
            .unwrap();
        tracker.commit_operation(&mut cell, "op-a").unwrap();
        tracker.abort_operation(&mut cell, "op-b").unwrap();

        tracker
            .events()
            .iter()
            .map(|e| (e.operation_id.clone(), e.event.clone(), e.outcome.clone()))
            .collect()
    }

    let run1 = run_scenario();
    let run2 = run_scenario();
    assert_eq!(run1, run2);
    assert_eq!(run1.len(), 4); // begin, begin, commit, abort
}

// =========================================================================
// X. Display format content validation (not just distinctness)
// =========================================================================

#[test]
fn enrichment_display_format_contains_expected_text() {
    let err_not_running = ObligationIntegrationError::CellNotRunning {
        cell_id: "my-cell".to_string(),
        current_state: RegionState::Closed,
    };
    let display = err_not_running.to_string();
    assert!(display.contains("my-cell"));
    assert!(display.contains("closed"));

    let err_not_found = ObligationIntegrationError::OperationNotFound {
        operation_id: "op-xyz".to_string(),
    };
    assert!(err_not_found.to_string().contains("op-xyz"));

    let err_resolved = ObligationIntegrationError::AlreadyResolved {
        operation_id: "op-res".to_string(),
        current_phase: OperationPhase::Committed,
    };
    let display_resolved = err_resolved.to_string();
    assert!(display_resolved.contains("op-res"));
    assert!(display_resolved.contains("committed"));

    let err_dup = ObligationIntegrationError::DuplicateOperation {
        operation_id: "op-dup".to_string(),
    };
    assert!(err_dup.to_string().contains("op-dup"));

    let err_cell = ObligationIntegrationError::CellError {
        message: "internal failure".to_string(),
    };
    assert!(err_cell.to_string().contains("internal failure"));
}

// =========================================================================
// Y. ObligationTracker::new constructor with explicit policy
// =========================================================================

#[test]
fn enrichment_tracker_new_with_explicit_policy() {
    let tracker_lab = ObligationTracker::new(LeakPolicy::Lab);
    assert_eq!(tracker_lab.leak_policy(), LeakPolicy::Lab);
    assert_eq!(tracker_lab.active_count(), 0);
    assert_eq!(tracker_lab.total_count(), 0);
    assert!(tracker_lab.events().is_empty());

    let tracker_prod = ObligationTracker::new(LeakPolicy::Production);
    assert_eq!(tracker_prod.leak_policy(), LeakPolicy::Production);
}
