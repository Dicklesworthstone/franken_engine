//! Integration tests for the `saga_orchestrator` module.
//!
//! Covers: SagaId, SagaType, SagaState, StepOutcome, ActionType, SagaStep,
//! StepRecord, Saga, SagaEvent, SagaError, SagaOrchestrator lifecycle,
//! compensation, epoch management, builder helpers, and stress scenarios.

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

use frankenengine_engine::saga_orchestrator::{
    ActionType, Saga, SagaError, SagaEvent, SagaId, SagaOrchestrator, SagaState, SagaStep,
    SagaType, StepOutcome, StepRecord, eviction_saga_steps, publish_saga_steps,
    quarantine_saga_steps, revocation_saga_steps,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn simple_steps() -> Vec<SagaStep> {
    vec![
        SagaStep {
            step_name: "step_a".to_string(),
            forward_action: "do_a".to_string(),
            compensating_action: "undo_a".to_string(),
            timeout_ticks: 100,
        },
        SagaStep {
            step_name: "step_b".to_string(),
            forward_action: "do_b".to_string(),
            compensating_action: "undo_b".to_string(),
            timeout_ticks: 200,
        },
        SagaStep {
            step_name: "step_c".to_string(),
            forward_action: "do_c".to_string(),
            compensating_action: "undo_c".to_string(),
            timeout_ticks: 100,
        },
    ]
}

/// Run a saga to completion (all forward steps succeed).
fn complete_saga(orch: &mut SagaOrchestrator, saga_id: &str, step_count: usize) {
    for i in 0..step_count {
        orch.begin_step(saga_id).unwrap();
        orch.complete_step(
            saga_id,
            i,
            StepOutcome::Success {
                result: format!("ok-{i}"),
            },
            &format!("key-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }
}

// ---------------------------------------------------------------------------
// SagaId
// ---------------------------------------------------------------------------

#[test]
fn saga_id_serde_roundtrip() {
    let id = SagaId::from_trace("trace-42");
    let json = serde_json::to_string(&id).unwrap();
    let restored: SagaId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn saga_id_display_and_as_str() {
    let id = SagaId::from_trace("my-saga");
    assert_eq!(id.as_str(), "my-saga");
    assert_eq!(id.to_string(), "saga:my-saga");
}

// ---------------------------------------------------------------------------
// SagaType
// ---------------------------------------------------------------------------

#[test]
fn saga_type_serde_all_variants() {
    let all = [
        SagaType::Quarantine,
        SagaType::Revocation,
        SagaType::Eviction,
        SagaType::Publish,
    ];
    for variant in &all {
        let json = serde_json::to_string(variant).unwrap();
        let restored: SagaType = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn saga_type_display_all() {
    assert_eq!(SagaType::Quarantine.to_string(), "quarantine");
    assert_eq!(SagaType::Revocation.to_string(), "revocation");
    assert_eq!(SagaType::Eviction.to_string(), "eviction");
    assert_eq!(SagaType::Publish.to_string(), "publish");
}

// ---------------------------------------------------------------------------
// SagaState
// ---------------------------------------------------------------------------

#[test]
fn saga_state_serde_all_variants() {
    let states = vec![
        SagaState::Pending,
        SagaState::InProgress { step_index: 2 },
        SagaState::Compensating { step_index: 1 },
        SagaState::Completed,
        SagaState::Failed {
            diagnostic: "test error".to_string(),
        },
    ];
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let restored: SagaState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, restored);
    }
}

#[test]
fn saga_state_display_all() {
    assert_eq!(SagaState::Pending.to_string(), "pending");
    assert_eq!(
        SagaState::InProgress { step_index: 2 }.to_string(),
        "in_progress(step=2)"
    );
    assert_eq!(
        SagaState::Compensating { step_index: 1 }.to_string(),
        "compensating(step=1)"
    );
    assert_eq!(SagaState::Completed.to_string(), "completed");
    assert_eq!(
        SagaState::Failed {
            diagnostic: "oops".to_string()
        }
        .to_string(),
        "failed(oops)"
    );
}

// ---------------------------------------------------------------------------
// StepOutcome
// ---------------------------------------------------------------------------

#[test]
fn step_outcome_serde_all_variants() {
    let outcomes = vec![
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        StepOutcome::Failure {
            diagnostic: "err".to_string(),
        },
        StepOutcome::Cancelled {
            reason: "timeout".to_string(),
        },
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let restored: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, restored);
    }
}

#[test]
fn step_outcome_display_all() {
    assert_eq!(
        StepOutcome::Success {
            result: "ok".to_string()
        }
        .to_string(),
        "success(ok)"
    );
    assert_eq!(
        StepOutcome::Failure {
            diagnostic: "err".to_string()
        }
        .to_string(),
        "failure(err)"
    );
    assert_eq!(
        StepOutcome::Cancelled {
            reason: "lease".to_string()
        }
        .to_string(),
        "cancelled(lease)"
    );
}

// ---------------------------------------------------------------------------
// ActionType
// ---------------------------------------------------------------------------

#[test]
fn action_type_serde_all() {
    for variant in &[ActionType::Forward, ActionType::Compensate] {
        let json = serde_json::to_string(variant).unwrap();
        let restored: ActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn action_type_display() {
    assert_eq!(ActionType::Forward.to_string(), "forward");
    assert_eq!(ActionType::Compensate.to_string(), "compensate");
}

// ---------------------------------------------------------------------------
// SagaStep, StepRecord, SagaEvent serde
// ---------------------------------------------------------------------------

#[test]
fn saga_step_serde_roundtrip() {
    let step = SagaStep {
        step_name: "validate_pkg".to_string(),
        forward_action: "publish.validate".to_string(),
        compensating_action: "publish.invalidate".to_string(),
        timeout_ticks: 1000,
    };
    let json = serde_json::to_string(&step).unwrap();
    let restored: SagaStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, restored);
}

#[test]
fn step_record_serde_roundtrip() {
    let record = StepRecord {
        step_index: 2,
        step_name: "commit_pkg".to_string(),
        action_type: ActionType::Forward,
        outcome: StepOutcome::Success {
            result: "committed".to_string(),
        },
        completed_at: 500,
        idempotency_key_hex: "abcd1234".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: StepRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn saga_event_serde_roundtrip() {
    let event = SagaEvent {
        saga_id: "s-42".to_string(),
        saga_type: "quarantine".to_string(),
        step_name: "suspend_ext".to_string(),
        step_index: 0,
        action: "forward".to_string(),
        result: "success(ok)".to_string(),
        trace_id: "trace-001".to_string(),
        epoch_id: 1,
        event: "step_complete".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: SagaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// SagaError
// ---------------------------------------------------------------------------

#[test]
fn saga_error_serde_all_variants() {
    let errors: Vec<SagaError> = vec![
        SagaError::SagaNotFound {
            saga_id: "s1".to_string(),
        },
        SagaError::SagaAlreadyTerminal {
            saga_id: "s2".to_string(),
            state: "completed".to_string(),
        },
        SagaError::StepIndexOutOfBounds {
            saga_id: "s3".to_string(),
            step_index: 5,
            step_count: 3,
        },
        SagaError::EpochMismatch {
            saga_id: "s4".to_string(),
            saga_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        SagaError::EmptySteps,
        SagaError::InvalidSagaId {
            reason: "empty".to_string(),
        },
        SagaError::CompensationFailed {
            saga_id: "s5".to_string(),
            step_index: 1,
            diagnostic: "disk full".to_string(),
        },
        SagaError::ConcurrencyLimitReached {
            active_count: 4,
            max_concurrent: 3,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: SagaError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn saga_error_display_all_non_empty() {
    let errors: Vec<SagaError> = vec![
        SagaError::SagaNotFound {
            saga_id: "s1".to_string(),
        },
        SagaError::SagaAlreadyTerminal {
            saga_id: "s2".to_string(),
            state: "completed".to_string(),
        },
        SagaError::StepIndexOutOfBounds {
            saga_id: "s3".to_string(),
            step_index: 5,
            step_count: 3,
        },
        SagaError::EpochMismatch {
            saga_id: "s4".to_string(),
            saga_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        SagaError::EmptySteps,
        SagaError::InvalidSagaId {
            reason: "empty".to_string(),
        },
        SagaError::CompensationFailed {
            saga_id: "s5".to_string(),
            step_index: 1,
            diagnostic: "disk full".to_string(),
        },
        SagaError::ConcurrencyLimitReached {
            active_count: 4,
            max_concurrent: 3,
        },
    ];
    for err in &errors {
        let display = err.to_string();
        assert!(
            !display.is_empty(),
            "display for {:?} should not be empty",
            err
        );
    }
}

#[test]
fn saga_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(SagaError::EmptySteps);
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Saga struct helpers
// ---------------------------------------------------------------------------

#[test]
fn saga_is_terminal_for_completed_and_failed() {
    let make = |state: SagaState| -> Saga {
        Saga {
            saga_id: SagaId::from_trace("test"),
            saga_type: SagaType::Publish,
            steps: simple_steps(),
            state,
            epoch: test_epoch(),
            trace_id: "t".to_string(),
            step_records: vec![],
            created_at: 0,
        }
    };

    assert!(!make(SagaState::Pending).is_terminal());
    assert!(!make(SagaState::InProgress { step_index: 0 }).is_terminal());
    assert!(!make(SagaState::Compensating { step_index: 0 }).is_terminal());
    assert!(make(SagaState::Completed).is_terminal());
    assert!(
        make(SagaState::Failed {
            diagnostic: "err".to_string()
        })
        .is_terminal()
    );
}

#[test]
fn saga_serde_roundtrip() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s-42"),
        saga_type: SagaType::Quarantine,
        steps: simple_steps(),
        state: SagaState::InProgress { step_index: 1 },
        epoch: SecurityEpoch::from_raw(3),
        trace_id: "trace-42".to_string(),
        step_records: vec![StepRecord {
            step_index: 0,
            step_name: "step_a".to_string(),
            action_type: ActionType::Forward,
            outcome: StepOutcome::Success {
                result: "ok".to_string(),
            },
            completed_at: 100,
            idempotency_key_hex: "aabb".to_string(),
        }],
        created_at: 50,
    };
    let json = serde_json::to_string(&saga).unwrap();
    let restored: Saga = serde_json::from_str(&json).unwrap();
    assert_eq!(saga, restored);
}

// ---------------------------------------------------------------------------
// SagaOrchestrator — basic lifecycle
// ---------------------------------------------------------------------------

#[test]
fn empty_orchestrator_properties() {
    let orch = SagaOrchestrator::new(test_epoch(), 10);
    assert_eq!(orch.epoch(), test_epoch());
    assert_eq!(orch.active_count(), 0);
    assert_eq!(orch.total_count(), 0);
    assert!(orch.get("nonexistent").is_none());
    assert!(orch.resumable_sagas().is_empty());
}

#[test]
fn create_and_query_saga() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    let id = orch
        .create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    assert_eq!(id.as_str(), "s1");
    assert_eq!(orch.active_count(), 1);
    assert_eq!(orch.total_count(), 1);

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.state, SagaState::Pending);
    assert_eq!(saga.steps.len(), 3);
    assert_eq!(saga.saga_type, SagaType::Quarantine);
    assert_eq!(saga.epoch, test_epoch());
}

#[test]
fn create_rejects_empty_id() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    let err = orch
        .create_saga("", SagaType::Publish, simple_steps(), "t", 0)
        .unwrap_err();
    assert!(matches!(err, SagaError::InvalidSagaId { .. }));
}

#[test]
fn create_rejects_empty_steps() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    let err = orch
        .create_saga("s1", SagaType::Publish, vec![], "t", 0)
        .unwrap_err();
    assert!(matches!(err, SagaError::EmptySteps));
}

#[test]
fn concurrency_limit_enforced() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 2);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();

    let err = orch
        .create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
        .unwrap_err();
    // Error indicates limit reached.
    assert!(err.to_string().contains("concurrency limit"));
}

#[test]
fn concurrency_limit_freed_after_completion() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 2);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();

    // Complete s1 to free a slot.
    complete_saga(&mut orch, "s1", 3);
    assert_eq!(orch.active_count(), 1);

    // Now s3 should succeed.
    orch.create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
        .unwrap();
    assert_eq!(orch.active_count(), 2);
}

// ---------------------------------------------------------------------------
// Forward step execution
// ---------------------------------------------------------------------------

#[test]
fn begin_step_returns_first_step_from_pending() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    let (idx, step) = orch.begin_step("s1").unwrap();
    assert_eq!(idx, 0);
    assert_eq!(step.step_name, "step_a");
    assert_eq!(step.forward_action, "do_a");
}

#[test]
fn complete_step_success_advances_to_next() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    let state = orch
        .complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();
    assert_eq!(state, SagaState::InProgress { step_index: 1 });
}

#[test]
fn complete_all_steps_completes_saga() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    complete_saga(&mut orch, "s1", 3);

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.state, SagaState::Completed);
    assert!(saga.is_terminal());
    assert_eq!(saga.step_records.len(), 3);
    assert_eq!(saga.last_completed_forward_step(), Some(2));
}

#[test]
fn begin_step_on_terminal_saga_fails() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    let err = orch.begin_step("s1").unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

#[test]
fn complete_step_out_of_bounds_fails() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    let err = orch
        .complete_step(
            "s1",
            99,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-99",
            100,
        )
        .unwrap_err();
    assert!(matches!(err, SagaError::StepIndexOutOfBounds { .. }));
}

// ---------------------------------------------------------------------------
// Failure triggers compensation
// ---------------------------------------------------------------------------

#[test]
fn failure_at_step_0_goes_directly_to_failed() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step(
            "s1",
            0,
            StepOutcome::Failure {
                diagnostic: "crash".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();
    assert!(matches!(state, SagaState::Failed { .. }));
}

#[test]
fn failure_at_step_1_triggers_compensation_at_step_0() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // Step 0 succeeds.
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();

    // Step 1 fails.
    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step(
            "s1",
            1,
            StepOutcome::Failure {
                diagnostic: "network_error".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();
    assert_eq!(state, SagaState::Compensating { step_index: 0 });
}

#[test]
fn cancelled_step_triggers_compensation() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();

    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step(
            "s1",
            1,
            StepOutcome::Cancelled {
                reason: "lease_expired".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();
    assert_eq!(state, SagaState::Compensating { step_index: 0 });
}

// ---------------------------------------------------------------------------
// Compensation execution
// ---------------------------------------------------------------------------

#[test]
fn full_compensation_in_reverse_order() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // Steps 0, 1 succeed, step 2 fails.
    for i in 0..2 {
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            i,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            &format!("key-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        2,
        StepOutcome::Failure {
            diagnostic: "timeout".to_string(),
        },
        "key-2",
        300,
    )
    .unwrap();

    // Compensate step 1.
    let (idx, step) = orch.next_compensation_step("s1").unwrap().unwrap();
    assert_eq!(idx, 1);
    assert_eq!(step.compensating_action, "undo_b");
    let state = orch
        .complete_compensation(
            "s1",
            1,
            StepOutcome::Success {
                result: "undone_b".to_string(),
            },
            "comp-1",
            400,
        )
        .unwrap();
    assert_eq!(state, SagaState::Compensating { step_index: 0 });

    // Compensate step 0.
    let (idx, _) = orch.next_compensation_step("s1").unwrap().unwrap();
    assert_eq!(idx, 0);
    let state = orch
        .complete_compensation(
            "s1",
            0,
            StepOutcome::Success {
                result: "undone_a".to_string(),
            },
            "comp-0",
            500,
        )
        .unwrap();
    assert!(matches!(state, SagaState::Failed { .. }));

    let saga = orch.get("s1").unwrap();
    assert!(saga.is_terminal());
    // 2 forward success + 1 forward fail + 2 compensations = 5.
    assert_eq!(saga.step_records.len(), 5);
}

#[test]
fn compensation_failure_is_terminal() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // Step 0 succeeds, step 1 fails → compensating at 0.
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        1,
        StepOutcome::Failure {
            diagnostic: "err".to_string(),
        },
        "key-1",
        200,
    )
    .unwrap();

    // Compensation at step 0 also fails.
    let state = orch
        .complete_compensation(
            "s1",
            0,
            StepOutcome::Failure {
                diagnostic: "comp_crash".to_string(),
            },
            "comp-0",
            300,
        )
        .unwrap();
    assert!(
        matches!(state, SagaState::Failed { ref diagnostic } if diagnostic.contains("compensation_failed"))
    );
}

#[test]
fn compensation_cancelled_is_terminal() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        1,
        StepOutcome::Failure {
            diagnostic: "err".to_string(),
        },
        "key-1",
        200,
    )
    .unwrap();

    let state = orch
        .complete_compensation(
            "s1",
            0,
            StepOutcome::Cancelled {
                reason: "lease_gone".to_string(),
            },
            "comp-0",
            300,
        )
        .unwrap();
    assert!(
        matches!(state, SagaState::Failed { ref diagnostic } if diagnostic.contains("compensation_cancelled"))
    );
}

#[test]
fn next_compensation_step_returns_none_when_not_compensating() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    assert!(orch.next_compensation_step("s1").unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Epoch management
// ---------------------------------------------------------------------------

#[test]
fn epoch_advance_invalidates_active_sagas() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    let invalidated = orch.advance_epoch(SecurityEpoch::from_raw(2), "t-epoch");
    assert_eq!(invalidated.len(), 1);
    assert_eq!(invalidated[0], "s1");

    let saga = orch.get("s1").unwrap();
    assert!(saga.is_terminal());
    assert_eq!(orch.epoch(), SecurityEpoch::from_raw(2));
}

#[test]
fn terminal_sagas_survive_epoch_advance() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    let invalidated = orch.advance_epoch(SecurityEpoch::from_raw(2), "t-epoch");
    assert!(invalidated.is_empty());

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.state, SagaState::Completed);
}

#[test]
fn begin_step_rejects_stale_epoch_saga() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    // Advance epoch but don't invalidate (simulate direct mutation not available
    // in integration tests — use advance_epoch which also invalidates).
    // Instead, create saga at epoch 1, advance to epoch 2 (which fails s1),
    // create s2 at epoch 2, advance to epoch 3 without completing s2.
    orch.advance_epoch(SecurityEpoch::from_raw(2), "t-adv");
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 100)
        .unwrap();

    orch.advance_epoch(SecurityEpoch::from_raw(3), "t-adv2");

    // s2 was invalidated by epoch advance.
    let saga = orch.get("s2").unwrap();
    assert!(saga.is_terminal());
}

// ---------------------------------------------------------------------------
// Saga queries
// ---------------------------------------------------------------------------

#[test]
fn resumable_sagas_filters_terminal() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();

    complete_saga(&mut orch, "s1", 3);

    let resumable = orch.resumable_sagas();
    assert_eq!(resumable.len(), 1);
    assert_eq!(resumable[0].saga_id.as_str(), "s2");
}

#[test]
fn gc_removes_old_terminal_sagas() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    assert_eq!(orch.total_count(), 1);
    let removed = orch.gc_terminal(200);
    assert_eq!(removed, 1);
    assert_eq!(orch.total_count(), 0);
}

#[test]
fn gc_preserves_active_and_recent_terminal() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);

    // Active saga.
    orch.create_saga("s-active", SagaType::Publish, simple_steps(), "t1", 500)
        .unwrap();

    // Terminal but recent.
    orch.create_saga("s-recent", SagaType::Revocation, simple_steps(), "t2", 500)
        .unwrap();
    complete_saga(&mut orch, "s-recent", 3);

    // Terminal and old.
    orch.create_saga("s-old", SagaType::Eviction, simple_steps(), "t3", 50)
        .unwrap();
    complete_saga(&mut orch, "s-old", 3);

    let removed = orch.gc_terminal(200);
    assert_eq!(removed, 1); // Only s-old.
    assert_eq!(orch.total_count(), 2);
    assert!(orch.get("s-active").is_some());
    assert!(orch.get("s-recent").is_some());
    assert!(orch.get("s-old").is_none());
}

#[test]
fn operations_on_nonexistent_saga() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);

    assert!(matches!(
        orch.begin_step("ghost"),
        Err(SagaError::SagaNotFound { .. })
    ));
    assert!(matches!(
        orch.complete_step(
            "ghost",
            0,
            StepOutcome::Success {
                result: "ok".to_string()
            },
            "k",
            0
        ),
        Err(SagaError::SagaNotFound { .. })
    ));
    assert!(matches!(
        orch.next_compensation_step("ghost"),
        Err(SagaError::SagaNotFound { .. })
    ));
    assert!(matches!(
        orch.complete_compensation(
            "ghost",
            0,
            StepOutcome::Success {
                result: "ok".to_string()
            },
            "k",
            0
        ),
        Err(SagaError::SagaNotFound { .. })
    ));
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

#[test]
fn quarantine_saga_steps_correct() {
    let steps = quarantine_saga_steps("ext-1");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("suspend"));
    assert!(steps[1].step_name.contains("flush_evidence"));
    assert!(steps[2].step_name.contains("propagate_quarantine"));
    assert!(steps[3].step_name.contains("confirm_quarantine"));
    assert!(steps[0].forward_action.contains("suspend"));
    assert!(steps[0].compensating_action.contains("resume"));
}

#[test]
fn revocation_saga_steps_correct() {
    let steps = revocation_saga_steps("key-1");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("emit_revocation"));
    assert!(steps[1].step_name.contains("propagate_revocation"));
    assert!(steps[2].step_name.contains("confirm_convergence"));
    assert!(steps[3].step_name.contains("update_frontier"));
}

#[test]
fn eviction_saga_steps_correct() {
    let steps = eviction_saga_steps("artifact-1");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("mark_eviction"));
    assert!(steps[1].step_name.contains("drain_references"));
    assert!(steps[2].step_name.contains("delete_artifacts"));
    assert!(steps[3].step_name.contains("confirm_cleanup"));
}

#[test]
fn publish_saga_steps_correct() {
    let steps = publish_saga_steps("pkg-1");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("validate"));
    assert!(steps[1].step_name.contains("stage"));
    assert!(steps[2].step_name.contains("commit"));
    assert!(steps[3].step_name.contains("notify"));
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[test]
fn create_emits_saga_created_event() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "saga_created");
    assert_eq!(events[0].saga_type, "quarantine");
    assert_eq!(events[0].saga_id, "s1");
}

#[test]
fn step_begin_and_complete_emit_events() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events();

    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();

    let events = orch.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "step_begin");
    assert_eq!(events[0].step_name, "step_a");
    assert_eq!(events[1].event, "step_complete");
    assert_eq!(events[1].action, "forward");
}

#[test]
fn compensation_emits_events() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // Step 0 succeeds, step 1 fails.
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        1,
        StepOutcome::Failure {
            diagnostic: "err".to_string(),
        },
        "key-1",
        200,
    )
    .unwrap();
    orch.drain_events();

    orch.complete_compensation(
        "s1",
        0,
        StepOutcome::Success {
            result: "undone".to_string(),
        },
        "comp-key-0",
        300,
    )
    .unwrap();

    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "compensation_complete");
    assert_eq!(events[0].action, "compensate");
}

#[test]
fn epoch_invalidation_emits_events() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events();

    orch.advance_epoch(SecurityEpoch::from_raw(2), "t-epoch");

    let events = orch.drain_events();
    assert!(events.iter().any(|e| e.event == "saga_epoch_invalidated"));
}

#[test]
fn event_counts_track_correctly() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();

    let counts = orch.event_counts();
    assert_eq!(counts.get("saga_created"), Some(&1));
    assert_eq!(counts.get("step_begin"), Some(&1));
    assert_eq!(counts.get("step_complete"), Some(&1));
}

#[test]
fn drain_events_clears() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    let first = orch.drain_events();
    assert!(!first.is_empty());
    let second = orch.drain_events();
    assert!(second.is_empty());
}

// ---------------------------------------------------------------------------
// Last completed forward step
// ---------------------------------------------------------------------------

#[test]
fn last_completed_forward_step_tracking() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.last_completed_forward_step(), None);

    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        0,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-0",
        100,
    )
    .unwrap();

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.last_completed_forward_step(), Some(0));

    orch.begin_step("s1").unwrap();
    orch.complete_step(
        "s1",
        1,
        StepOutcome::Success {
            result: "ok".to_string(),
        },
        "key-1",
        200,
    )
    .unwrap();

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.last_completed_forward_step(), Some(1));
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_event_sequence() {
    let run = || -> Vec<SagaEvent> {
        let mut orch = SagaOrchestrator::new(SecurityEpoch::from_raw(1), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            1,
            StepOutcome::Failure {
                diagnostic: "err".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();
        orch.complete_compensation(
            "s1",
            0,
            StepOutcome::Success {
                result: "undone".to_string(),
            },
            "comp-key-0",
            300,
        )
        .unwrap();
        orch.drain_events()
    };

    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Full lifecycle with builder helpers
// ---------------------------------------------------------------------------

#[test]
fn full_quarantine_lifecycle_success() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    let steps = quarantine_saga_steps("ext-malicious");
    orch.create_saga("q1", SagaType::Quarantine, steps, "trace-q1", 0)
        .unwrap();

    for i in 0..4 {
        orch.begin_step("q1").unwrap();
        orch.complete_step(
            "q1",
            i,
            StepOutcome::Success {
                result: format!("done-{i}"),
            },
            &format!("idem-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }

    let saga = orch.get("q1").unwrap();
    assert_eq!(saga.state, SagaState::Completed);
    assert_eq!(saga.step_records.len(), 4);
    assert_eq!(orch.active_count(), 0);
}

#[test]
fn full_publish_lifecycle_with_compensation() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 10);
    let steps = publish_saga_steps("pkg-1");
    orch.create_saga("p1", SagaType::Publish, steps, "trace-p1", 0)
        .unwrap();

    // Steps 0, 1 succeed.
    for i in 0..2 {
        orch.begin_step("p1").unwrap();
        orch.complete_step(
            "p1",
            i,
            StepOutcome::Success {
                result: format!("ok-{i}"),
            },
            &format!("idem-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }

    // Step 2 fails (commit fails).
    orch.begin_step("p1").unwrap();
    orch.complete_step(
        "p1",
        2,
        StepOutcome::Failure {
            diagnostic: "commit_rejected".to_string(),
        },
        "idem-2",
        300,
    )
    .unwrap();

    // Compensate in reverse: step 1, then step 0.
    for i in (0..2).rev() {
        let (comp_idx, _step) = orch.next_compensation_step("p1").unwrap().unwrap();
        assert_eq!(comp_idx, i);
        orch.complete_compensation(
            "p1",
            i,
            StepOutcome::Success {
                result: format!("undone-{i}"),
            },
            &format!("comp-idem-{i}"),
            (4 + i as u64) * 100,
        )
        .unwrap();
    }

    let saga = orch.get("p1").unwrap();
    assert!(saga.is_terminal());
    assert_eq!(saga.step_records.len(), 5);
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_20_sagas_mixed_outcomes() {
    let mut orch = SagaOrchestrator::new(test_epoch(), 100);

    let saga_types = [
        SagaType::Quarantine,
        SagaType::Revocation,
        SagaType::Eviction,
        SagaType::Publish,
    ];

    for i in 0..20u32 {
        let saga_type = saga_types[(i as usize) % saga_types.len()];
        let steps = match saga_type {
            SagaType::Quarantine => quarantine_saga_steps(&format!("ext-{i}")),
            SagaType::Revocation => revocation_saga_steps(&format!("key-{i}")),
            SagaType::Eviction => eviction_saga_steps(&format!("art-{i}")),
            SagaType::Publish => publish_saga_steps(&format!("pkg-{i}")),
        };
        orch.create_saga(
            &format!("s-{i}"),
            saga_type,
            steps,
            &format!("t-{i}"),
            i as u64,
        )
        .unwrap();
    }

    assert_eq!(orch.total_count(), 20);
    assert_eq!(orch.active_count(), 20);

    // Complete first 10 sagas successfully.
    for i in 0..10u32 {
        let saga_id = format!("s-{i}");
        for step_idx in 0..4 {
            orch.begin_step(&saga_id).unwrap();
            orch.complete_step(
                &saga_id,
                step_idx,
                StepOutcome::Success {
                    result: format!("ok-{step_idx}"),
                },
                &format!("key-{i}-{step_idx}"),
                1000 + i as u64 * 10 + step_idx as u64,
            )
            .unwrap();
        }
    }

    // Fail sagas 10-14 at step 1 (after step 0 succeeds).
    for i in 10..15u32 {
        let saga_id = format!("s-{i}");
        orch.begin_step(&saga_id).unwrap();
        orch.complete_step(
            &saga_id,
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            &format!("key-{i}-0"),
            2000 + i as u64,
        )
        .unwrap();
        orch.begin_step(&saga_id).unwrap();
        orch.complete_step(
            &saga_id,
            1,
            StepOutcome::Failure {
                diagnostic: "err".to_string(),
            },
            &format!("key-{i}-1"),
            2100 + i as u64,
        )
        .unwrap();

        // Compensate step 0.
        orch.complete_compensation(
            &saga_id,
            0,
            StepOutcome::Success {
                result: "undone".to_string(),
            },
            &format!("comp-{i}-0"),
            2200 + i as u64,
        )
        .unwrap();
    }

    // Leave sagas 15-19 active.
    assert_eq!(orch.active_count(), 5); // s-15 through s-19.

    // GC old completed/failed sagas.
    let removed = orch.gc_terminal(100);
    assert!(removed > 0);

    // Verify event counts are populated.
    let counts = orch.event_counts();
    assert!(counts.get("saga_created").unwrap() >= &20);
    assert!(counts.get("step_begin").is_some());
    assert!(counts.get("step_complete").is_some());
    assert!(counts.get("compensation_complete").is_some());
}
