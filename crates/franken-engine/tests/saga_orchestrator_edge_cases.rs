//! Edge-case integration tests for `saga_orchestrator` module.
//!
//! Covers saga lifecycle edge cases, compensation semantics,
//! concurrency limits, epoch binding, GC boundaries, builder
//! helpers, serde round-trips, and multi-saga orchestration.

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
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

fn single_step() -> Vec<SagaStep> {
    vec![SagaStep {
        step_name: "only_step".to_string(),
        forward_action: "do_it".to_string(),
        compensating_action: "undo_it".to_string(),
        timeout_ticks: 50,
    }]
}

fn success(val: &str) -> StepOutcome {
    StepOutcome::Success {
        result: val.to_string(),
    }
}

fn failure(msg: &str) -> StepOutcome {
    StepOutcome::Failure {
        diagnostic: msg.to_string(),
    }
}

fn cancelled(reason: &str) -> StepOutcome {
    StepOutcome::Cancelled {
        reason: reason.to_string(),
    }
}

// ===========================================================================
// SagaId
// ===========================================================================

#[test]
fn saga_id_serde_roundtrip() {
    let id = SagaId::from_trace("trace-abc-123");
    let json = serde_json::to_string(&id).unwrap();
    let restored: SagaId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn saga_id_display_format() {
    let id = SagaId::from_trace("my-trace");
    assert_eq!(id.to_string(), "saga:my-trace");
}

#[test]
fn saga_id_as_str() {
    let id = SagaId::from_trace("raw-value");
    assert_eq!(id.as_str(), "raw-value");
}

#[test]
fn saga_id_ordering() {
    let a = SagaId::from_trace("aaa");
    let b = SagaId::from_trace("bbb");
    assert!(a < b);
}

#[test]
fn saga_id_hash_deterministic() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(SagaId::from_trace("x"));
    set.insert(SagaId::from_trace("x"));
    assert_eq!(set.len(), 1);
    set.insert(SagaId::from_trace("y"));
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// SagaType
// ===========================================================================

#[test]
fn saga_type_serde_all_variants() {
    let types = [
        SagaType::Quarantine,
        SagaType::Revocation,
        SagaType::Eviction,
        SagaType::Publish,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let restored: SagaType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn saga_type_display_all_variants() {
    assert_eq!(SagaType::Quarantine.to_string(), "quarantine");
    assert_eq!(SagaType::Revocation.to_string(), "revocation");
    assert_eq!(SagaType::Eviction.to_string(), "eviction");
    assert_eq!(SagaType::Publish.to_string(), "publish");
}

#[test]
fn saga_type_ordering_deterministic() {
    let mut types = [
        SagaType::Publish,
        SagaType::Quarantine,
        SagaType::Eviction,
        SagaType::Revocation,
    ];
    types.sort();
    let mut again = types;
    again.sort();
    assert_eq!(types, again);
}

// ===========================================================================
// SagaState
// ===========================================================================

#[test]
fn saga_state_serde_all_variants() {
    let states = [
        SagaState::Pending,
        SagaState::InProgress { step_index: 0 },
        SagaState::InProgress { step_index: 99 },
        SagaState::Compensating { step_index: 3 },
        SagaState::Completed,
        SagaState::Failed {
            diagnostic: "something broke".to_string(),
        },
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let restored: SagaState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn saga_state_display_includes_details() {
    assert_eq!(SagaState::Pending.to_string(), "pending");
    assert!(
        SagaState::InProgress { step_index: 5 }
            .to_string()
            .contains("5")
    );
    assert!(
        SagaState::Compensating { step_index: 2 }
            .to_string()
            .contains("2")
    );
    assert_eq!(SagaState::Completed.to_string(), "completed");
    assert!(
        SagaState::Failed {
            diagnostic: "reason".to_string()
        }
        .to_string()
        .contains("reason")
    );
}

// ===========================================================================
// StepOutcome
// ===========================================================================

#[test]
fn step_outcome_serde_all_variants() {
    let outcomes = [
        success("result-val"),
        failure("diag"),
        cancelled("lease expired"),
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let restored: StepOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, restored);
    }
}

#[test]
fn step_outcome_display_all_variants() {
    assert!(success("ok").to_string().contains("success"));
    assert!(failure("err").to_string().contains("failure"));
    assert!(cancelled("timeout").to_string().contains("cancelled"));
}

// ===========================================================================
// ActionType
// ===========================================================================

#[test]
fn action_type_serde_roundtrip() {
    for at in [ActionType::Forward, ActionType::Compensate] {
        let json = serde_json::to_string(&at).unwrap();
        let restored: ActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(at, restored);
    }
}

#[test]
fn action_type_display() {
    assert_eq!(ActionType::Forward.to_string(), "forward");
    assert_eq!(ActionType::Compensate.to_string(), "compensate");
}

// ===========================================================================
// SagaStep serde
// ===========================================================================

#[test]
fn saga_step_serde_roundtrip() {
    let step = SagaStep {
        step_name: "validate".to_string(),
        forward_action: "publish.validate".to_string(),
        compensating_action: "publish.invalidate".to_string(),
        timeout_ticks: 5000,
    };
    let json = serde_json::to_string(&step).unwrap();
    let restored: SagaStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, restored);
}

// ===========================================================================
// StepRecord serde
// ===========================================================================

#[test]
fn step_record_serde_roundtrip() {
    let record = StepRecord {
        step_index: 2,
        step_name: "commit".to_string(),
        action_type: ActionType::Forward,
        outcome: success("committed"),
        completed_at: 42000,
        idempotency_key_hex: "deadbeef".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: StepRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn step_record_compensation_type() {
    let record = StepRecord {
        step_index: 1,
        step_name: "undo_stage".to_string(),
        action_type: ActionType::Compensate,
        outcome: success("unstaged"),
        completed_at: 50000,
        idempotency_key_hex: "cafe".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: StepRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.action_type, ActionType::Compensate);
    assert_eq!(record, restored);
}

// ===========================================================================
// SagaEvent serde
// ===========================================================================

#[test]
fn saga_event_serde_roundtrip() {
    let event = SagaEvent {
        saga_id: "s1".to_string(),
        saga_type: "quarantine".to_string(),
        step_name: "suspend".to_string(),
        step_index: 0,
        action: "forward".to_string(),
        result: "success(ok)".to_string(),
        trace_id: "t1".to_string(),
        epoch_id: 42,
        event: "step_complete".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: SagaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// SagaError
// ===========================================================================

#[test]
fn saga_error_serde_all_variants() {
    let errors = [
        SagaError::SagaNotFound {
            saga_id: "s1".to_string(),
        },
        SagaError::SagaAlreadyTerminal {
            saga_id: "s2".to_string(),
            state: "completed".to_string(),
        },
        SagaError::StepIndexOutOfBounds {
            saga_id: "s3".to_string(),
            step_index: 10,
            step_count: 4,
        },
        SagaError::EpochMismatch {
            saga_id: "s4".to_string(),
            saga_epoch: epoch(1),
            current_epoch: epoch(2),
        },
        SagaError::EmptySteps,
        SagaError::InvalidSagaId {
            reason: "empty".to_string(),
        },
        SagaError::CompensationFailed {
            saga_id: "s5".to_string(),
            step_index: 2,
            diagnostic: "disk full".to_string(),
        },
        SagaError::ConcurrencyLimitReached {
            active_count: 5,
            max_concurrent: 4,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: SagaError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn saga_error_display_all_variants() {
    let cases = [
        (
            SagaError::SagaNotFound {
                saga_id: "s1".to_string(),
            },
            "s1",
        ),
        (
            SagaError::SagaAlreadyTerminal {
                saga_id: "s2".to_string(),
                state: "completed".to_string(),
            },
            "terminal",
        ),
        (
            SagaError::StepIndexOutOfBounds {
                saga_id: "s3".to_string(),
                step_index: 10,
                step_count: 4,
            },
            "out of bounds",
        ),
        (
            SagaError::EpochMismatch {
                saga_id: "s4".to_string(),
                saga_epoch: epoch(1),
                current_epoch: epoch(2),
            },
            "epoch mismatch",
        ),
        (SagaError::EmptySteps, "at least one step"),
        (
            SagaError::InvalidSagaId {
                reason: "empty".to_string(),
            },
            "invalid saga ID",
        ),
        (
            SagaError::CompensationFailed {
                saga_id: "s5".to_string(),
                step_index: 2,
                diagnostic: "disk full".to_string(),
            },
            "compensation failed",
        ),
        (
            SagaError::ConcurrencyLimitReached {
                active_count: 5,
                max_concurrent: 4,
            },
            "concurrency limit reached",
        ),
    ];
    for (err, expected) in &cases {
        assert!(
            err.to_string().contains(expected),
            "expected '{}' in '{}'",
            expected,
            err
        );
    }
}

#[test]
fn saga_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(SagaError::EmptySteps);
    assert!(err.to_string().contains("at least one"));
}

// ===========================================================================
// Saga struct helpers
// ===========================================================================

#[test]
fn saga_is_terminal_for_completed() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Completed,
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert!(saga.is_terminal());
}

#[test]
fn saga_is_terminal_for_failed() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Failed {
            diagnostic: "err".to_string(),
        },
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert!(saga.is_terminal());
}

#[test]
fn saga_not_terminal_for_pending() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Pending,
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert!(!saga.is_terminal());
}

#[test]
fn saga_not_terminal_for_in_progress() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::InProgress { step_index: 1 },
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert!(!saga.is_terminal());
}

#[test]
fn saga_not_terminal_for_compensating() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Compensating { step_index: 0 },
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert!(!saga.is_terminal());
}

#[test]
fn saga_last_completed_forward_step_none_when_empty() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Pending,
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: Vec::new(),
        created_at: 0,
    };
    assert_eq!(saga.last_completed_forward_step(), None);
}

#[test]
fn saga_last_completed_forward_step_ignores_compensation() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::Failed {
            diagnostic: "compensated".to_string(),
        },
        epoch: epoch(1),
        trace_id: "t".to_string(),
        step_records: vec![
            StepRecord {
                step_index: 0,
                step_name: "step_a".to_string(),
                action_type: ActionType::Forward,
                outcome: success("ok"),
                completed_at: 100,
                idempotency_key_hex: "k0".to_string(),
            },
            StepRecord {
                step_index: 1,
                step_name: "step_b".to_string(),
                action_type: ActionType::Forward,
                outcome: failure("err"),
                completed_at: 200,
                idempotency_key_hex: "k1".to_string(),
            },
            StepRecord {
                step_index: 0,
                step_name: "step_a".to_string(),
                action_type: ActionType::Compensate,
                outcome: success("undone"),
                completed_at: 300,
                idempotency_key_hex: "ck0".to_string(),
            },
        ],
        created_at: 0,
    };
    // Only forward success at index 0.
    assert_eq!(saga.last_completed_forward_step(), Some(0));
}

#[test]
fn saga_serde_roundtrip() {
    let saga = Saga {
        saga_id: SagaId::from_trace("s-full"),
        saga_type: SagaType::Quarantine,
        steps: quarantine_saga_steps("ext-1"),
        state: SagaState::InProgress { step_index: 2 },
        epoch: epoch(5),
        trace_id: "trace-full".to_string(),
        step_records: vec![
            StepRecord {
                step_index: 0,
                step_name: "suspend_ext-1".to_string(),
                action_type: ActionType::Forward,
                outcome: success("suspended"),
                completed_at: 100,
                idempotency_key_hex: "aabb".to_string(),
            },
            StepRecord {
                step_index: 1,
                step_name: "flush_evidence_ext-1".to_string(),
                action_type: ActionType::Forward,
                outcome: success("flushed"),
                completed_at: 200,
                idempotency_key_hex: "ccdd".to_string(),
            },
        ],
        created_at: 50,
    };
    let json = serde_json::to_string(&saga).unwrap();
    let restored: Saga = serde_json::from_str(&json).unwrap();
    assert_eq!(saga, restored);
}

// ===========================================================================
// SagaOrchestrator — creation edge cases
// ===========================================================================

#[test]
fn orchestrator_epoch_accessor() {
    let orch = SagaOrchestrator::new(epoch(42), 10);
    assert_eq!(orch.epoch(), epoch(42));
}

#[test]
fn orchestrator_empty_initially() {
    let orch = SagaOrchestrator::new(epoch(1), 10);
    assert_eq!(orch.active_count(), 0);
    assert_eq!(orch.total_count(), 0);
    assert!(orch.resumable_sagas().is_empty());
}

#[test]
fn create_saga_concurrency_limit_exact_boundary() {
    let mut orch = SagaOrchestrator::new(epoch(1), 2);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();
    // Third should fail.
    assert!(
        orch.create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
            .is_err()
    );
    assert_eq!(orch.active_count(), 2);
}

#[test]
fn create_saga_after_completing_one_frees_slot() {
    let mut orch = SagaOrchestrator::new(epoch(1), 1);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    // Complete s1.
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("done"), "k0", 100)
        .unwrap();
    assert_eq!(orch.active_count(), 0);
    // Now we can create another.
    orch.create_saga("s2", SagaType::Publish, single_step(), "t2", 200)
        .unwrap();
    assert_eq!(orch.active_count(), 1);
}

#[test]
fn create_saga_with_max_concurrent_zero() {
    let mut orch = SagaOrchestrator::new(epoch(1), 0);
    assert!(
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t", 0)
            .is_err()
    );
}

// ===========================================================================
// SagaOrchestrator — begin_step edge cases
// ===========================================================================

#[test]
fn begin_step_on_completed_saga_errors() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();

    assert!(matches!(
        orch.begin_step("s1"),
        Err(SagaError::SagaAlreadyTerminal { .. })
    ));
}

#[test]
fn begin_step_on_failed_saga_errors() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, failure("crash"), "k0", 100)
        .unwrap();

    assert!(matches!(
        orch.begin_step("s1"),
        Err(SagaError::SagaAlreadyTerminal { .. })
    ));
}

#[test]
fn begin_step_on_compensating_saga_errors() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    // Step 0 succeeds.
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    // Step 1 fails → compensating at step 0.
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();

    assert!(matches!(
        orch.begin_step("s1"),
        Err(SagaError::SagaAlreadyTerminal { .. })
    ));
}

#[test]
fn begin_step_on_nonexistent_saga() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    assert!(matches!(
        orch.begin_step("nonexistent"),
        Err(SagaError::SagaNotFound { .. })
    ));
}

// ===========================================================================
// SagaOrchestrator — complete_step edge cases
// ===========================================================================

#[test]
fn complete_step_out_of_bounds() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    assert!(matches!(
        orch.complete_step("s1", 99, success("ok"), "k", 100),
        Err(SagaError::StepIndexOutOfBounds { .. })
    ));
}

#[test]
fn complete_step_cancelled_triggers_compensation() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    // Step 0 succeeds.
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    // Step 1 cancelled.
    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step("s1", 1, cancelled("lease expired"), "k1", 200)
        .unwrap();
    assert_eq!(state, SagaState::Compensating { step_index: 0 });
}

#[test]
fn complete_step_failure_at_step_0_goes_directly_to_failed() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step("s1", 0, failure("boom"), "k0", 100)
        .unwrap();
    assert!(matches!(state, SagaState::Failed { .. }));
}

#[test]
fn single_step_saga_completes_on_success() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step("s1", 0, success("done"), "k0", 100)
        .unwrap();
    assert_eq!(state, SagaState::Completed);
}

#[test]
fn single_step_saga_failure_goes_directly_to_failed() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    let state = orch
        .complete_step("s1", 0, failure("crash"), "k0", 100)
        .unwrap();
    // Step 0 failure: nothing to compensate.
    assert!(matches!(state, SagaState::Failed { .. }));
}

// ===========================================================================
// SagaOrchestrator — compensation edge cases
// ===========================================================================

#[test]
fn next_compensation_step_when_not_compensating() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    // Still pending.
    assert_eq!(orch.next_compensation_step("s1").unwrap(), None);
}

#[test]
fn next_compensation_step_nonexistent() {
    let orch = SagaOrchestrator::new(epoch(1), 10);
    assert!(matches!(
        orch.next_compensation_step("ghost"),
        Err(SagaError::SagaNotFound { .. })
    ));
}

#[test]
fn compensation_out_of_bounds_step() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();

    assert!(matches!(
        orch.complete_compensation("s1", 99, success("ok"), "ck", 300),
        Err(SagaError::StepIndexOutOfBounds { .. })
    ));
}

#[test]
fn compensation_cancelled_is_terminal() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();

    let state = orch
        .complete_compensation("s1", 0, cancelled("timeout"), "ck0", 300)
        .unwrap();
    assert!(
        matches!(state, SagaState::Failed { diagnostic } if diagnostic.contains("compensation_cancelled"))
    );
}

#[test]
fn compensation_failure_is_terminal_with_diagnostic() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();

    let state = orch
        .complete_compensation("s1", 0, failure("disk full"), "ck0", 300)
        .unwrap();
    assert!(
        matches!(state, SagaState::Failed { diagnostic } if diagnostic.contains("compensation_failed") && diagnostic.contains("disk full"))
    );
}

#[test]
fn full_compensation_chain_three_steps() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // Steps 0, 1 succeed.
    for i in 0..2 {
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            i,
            success("ok"),
            &format!("k{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }
    // Step 2 fails.
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 2, failure("timeout"), "k2", 300)
        .unwrap();

    // Compensation: step 1, then step 0.
    let (idx1, _) = orch.next_compensation_step("s1").unwrap().unwrap();
    assert_eq!(idx1, 1);
    let state = orch
        .complete_compensation("s1", 1, success("undone_b"), "ck1", 400)
        .unwrap();
    assert_eq!(state, SagaState::Compensating { step_index: 0 });

    let (idx0, _) = orch.next_compensation_step("s1").unwrap().unwrap();
    assert_eq!(idx0, 0);
    let state = orch
        .complete_compensation("s1", 0, success("undone_a"), "ck0", 500)
        .unwrap();
    assert!(matches!(
        state,
        SagaState::Failed {
            diagnostic
        } if diagnostic == "compensated"
    ));

    let saga = orch.get("s1").unwrap();
    assert!(saga.is_terminal());
    // 2 forward success + 1 forward failure + 2 compensation = 5 records.
    assert_eq!(saga.step_records.len(), 5);
}

// ===========================================================================
// Epoch binding
// ===========================================================================

#[test]
fn advance_epoch_with_no_active_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    let invalidated = orch.advance_epoch(epoch(2), "t");
    assert!(invalidated.is_empty());
    assert_eq!(orch.epoch(), epoch(2));
}

#[test]
fn advance_epoch_preserves_terminal_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("done"), "k0", 100)
        .unwrap();

    let invalidated = orch.advance_epoch(epoch(2), "t");
    assert!(invalidated.is_empty());
    // s1 is still there (completed).
    assert!(orch.get("s1").is_some());
}

#[test]
fn advance_epoch_invalidates_multiple() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();
    orch.begin_step("s1").unwrap(); // s1 is InProgress

    let invalidated = orch.advance_epoch(epoch(2), "t");
    assert_eq!(invalidated.len(), 2);
    assert!(orch.get("s1").unwrap().is_terminal());
    assert!(orch.get("s2").unwrap().is_terminal());
}

#[test]
fn advance_epoch_emits_invalidation_events() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events();

    orch.advance_epoch(epoch(2), "epoch-trace");
    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "saga_epoch_invalidated");
    assert_eq!(events[0].epoch_id, 2);
    assert_eq!(orch.event_counts().get("saga_epoch_invalidated"), Some(&1));
}

// ===========================================================================
// GC terminal
// ===========================================================================

#[test]
fn gc_preserves_recent_terminal() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 500)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 600)
        .unwrap();

    // GC with threshold at 500 → created_at = 500, not < 500.
    let removed = orch.gc_terminal(500);
    assert_eq!(removed, 0);
}

#[test]
fn gc_removes_exactly_older_than_threshold() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    // s1 created at 100 (old).
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 200)
        .unwrap();
    // s2 created at 300 (recent).
    orch.create_saga("s2", SagaType::Publish, single_step(), "t2", 300)
        .unwrap();
    orch.begin_step("s2").unwrap();
    orch.complete_step("s2", 0, success("ok"), "k0", 400)
        .unwrap();

    let removed = orch.gc_terminal(200);
    assert_eq!(removed, 1); // only s1
    assert!(orch.get("s1").is_none());
    assert!(orch.get("s2").is_some());
}

#[test]
fn gc_does_not_remove_active_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    let removed = orch.gc_terminal(1000);
    assert_eq!(removed, 0);
}

// ===========================================================================
// Resumable sagas
// ===========================================================================

#[test]
fn resumable_includes_pending_and_in_progress() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();
    orch.begin_step("s2").unwrap();

    let resumable = orch.resumable_sagas();
    assert_eq!(resumable.len(), 2);
}

#[test]
fn resumable_includes_compensating() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();

    let resumable = orch.resumable_sagas();
    assert_eq!(resumable.len(), 1);
    assert!(matches!(resumable[0].state, SagaState::Compensating { .. }));
}

#[test]
fn resumable_excludes_completed_and_failed() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    // Complete one.
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    // Fail one.
    orch.create_saga("s2", SagaType::Publish, single_step(), "t2", 0)
        .unwrap();
    orch.begin_step("s2").unwrap();
    orch.complete_step("s2", 0, failure("err"), "k0", 200)
        .unwrap();

    assert!(orch.resumable_sagas().is_empty());
}

// ===========================================================================
// Events and counters
// ===========================================================================

#[test]
fn drain_events_clears() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert!(orch.drain_events().is_empty());
}

#[test]
fn event_counts_accumulate_across_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Revocation, single_step(), "t2", 0)
        .unwrap();
    assert_eq!(orch.event_counts().get("saga_created"), Some(&2));
}

#[test]
fn create_event_has_correct_fields() {
    let mut orch = SagaOrchestrator::new(epoch(7), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "trace-99", 0)
        .unwrap();
    let events = orch.drain_events();
    assert_eq!(events[0].event, "saga_created");
    assert_eq!(events[0].saga_id, "s1");
    assert_eq!(events[0].saga_type, "quarantine");
    assert_eq!(events[0].trace_id, "trace-99");
    assert_eq!(events[0].epoch_id, 7);
    assert_eq!(events[0].action, "create");
    assert_eq!(events[0].result, "pending");
}

#[test]
fn step_begin_event_has_correct_fields() {
    let mut orch = SagaOrchestrator::new(epoch(3), 10);
    orch.create_saga("s1", SagaType::Eviction, simple_steps(), "t-x", 0)
        .unwrap();
    orch.drain_events();

    orch.begin_step("s1").unwrap();
    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "step_begin");
    assert_eq!(events[0].step_name, "step_a");
    assert_eq!(events[0].step_index, 0);
    assert_eq!(events[0].action, "forward");
}

// ===========================================================================
// Builder helpers
// ===========================================================================

#[test]
fn quarantine_steps_have_correct_structure() {
    let steps = quarantine_saga_steps("ext-abc");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("suspend"));
    assert!(steps[0].step_name.contains("ext-abc"));
    assert_eq!(steps[0].forward_action, "extension.suspend");
    assert_eq!(steps[0].compensating_action, "extension.resume");
    assert!(steps[3].step_name.contains("confirm_quarantine"));
}

#[test]
fn revocation_steps_have_correct_structure() {
    let steps = revocation_saga_steps("key-99");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("emit_revocation"));
    assert!(steps[0].step_name.contains("key-99"));
    assert!(steps[3].step_name.contains("update_frontier"));
    assert_eq!(steps[3].forward_action, "revocation.update_frontier");
}

#[test]
fn eviction_steps_have_correct_structure() {
    let steps = eviction_saga_steps("art-1");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("mark_eviction"));
    assert!(steps[2].step_name.contains("delete_artifacts"));
    assert!(steps[2].step_name.contains("art-1"));
}

#[test]
fn publish_steps_have_correct_structure() {
    let steps = publish_saga_steps("pkg-2");
    assert_eq!(steps.len(), 4);
    assert!(steps[0].step_name.contains("validate"));
    assert!(steps[1].step_name.contains("stage"));
    assert!(steps[2].step_name.contains("commit"));
    assert!(steps[3].step_name.contains("notify"));
    assert!(steps[3].step_name.contains("pkg-2"));
}

#[test]
fn all_builder_steps_have_nonzero_timeout() {
    for steps in [
        quarantine_saga_steps("x"),
        revocation_saga_steps("x"),
        eviction_saga_steps("x"),
        publish_saga_steps("x"),
    ] {
        for step in &steps {
            assert!(
                step.timeout_ticks > 0,
                "step {} has zero timeout",
                step.step_name
            );
        }
    }
}

#[test]
fn all_builder_steps_have_forward_and_compensating() {
    for steps in [
        quarantine_saga_steps("x"),
        revocation_saga_steps("x"),
        eviction_saga_steps("x"),
        publish_saga_steps("x"),
    ] {
        for step in &steps {
            assert!(!step.forward_action.is_empty());
            assert!(!step.compensating_action.is_empty());
            assert_ne!(step.forward_action, step.compensating_action);
        }
    }
}

// ===========================================================================
// Integration scenarios
// ===========================================================================

#[test]
fn multiple_concurrent_sagas_independent_lifecycle() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga(
        "q1",
        SagaType::Quarantine,
        quarantine_saga_steps("ext-a"),
        "t1",
        0,
    )
    .unwrap();
    orch.create_saga(
        "p1",
        SagaType::Publish,
        publish_saga_steps("pkg-b"),
        "t2",
        0,
    )
    .unwrap();

    // Complete q1 fully.
    for i in 0..4 {
        orch.begin_step("q1").unwrap();
        orch.complete_step(
            "q1",
            i,
            success(&format!("ok-{i}")),
            &format!("qk{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }

    // p1 still in progress.
    orch.begin_step("p1").unwrap();
    orch.complete_step("p1", 0, success("validated"), "pk0", 500)
        .unwrap();

    assert_eq!(orch.active_count(), 1);
    assert_eq!(orch.total_count(), 2);
    assert!(orch.get("q1").unwrap().is_terminal());
    assert!(!orch.get("p1").unwrap().is_terminal());
}

#[test]
fn saga_failure_at_each_step_position() {
    for fail_at in 0..3 {
        let mut orch = SagaOrchestrator::new(epoch(1), 10);
        let id = format!("s-fail-at-{fail_at}");
        orch.create_saga(&id, SagaType::Quarantine, simple_steps(), "t", 0)
            .unwrap();

        for i in 0..=fail_at {
            orch.begin_step(&id).unwrap();
            if i == fail_at {
                orch.complete_step(
                    &id,
                    i,
                    failure("err"),
                    &format!("k{i}"),
                    (i as u64 + 1) * 100,
                )
                .unwrap();
            } else {
                orch.complete_step(
                    &id,
                    i,
                    success("ok"),
                    &format!("k{i}"),
                    (i as u64 + 1) * 100,
                )
                .unwrap();
            }
        }

        let saga = orch.get(&id).unwrap();
        if fail_at == 0 {
            // No compensation needed.
            assert!(saga.is_terminal());
        } else {
            // Should be compensating.
            assert!(matches!(saga.state, SagaState::Compensating { .. }));
        }
    }
}

#[test]
fn epoch_advance_mid_saga_with_active_and_terminal() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);

    // s1: completed (terminal).
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("done"), "k", 100)
        .unwrap();

    // s2: in progress (active).
    orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
        .unwrap();
    orch.begin_step("s2").unwrap();

    // s3: pending (active).
    orch.create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
        .unwrap();

    let invalidated = orch.advance_epoch(epoch(2), "epoch-t");
    // Only s2 and s3 should be invalidated.
    assert_eq!(invalidated.len(), 2);
    assert!(invalidated.contains(&"s2".to_string()));
    assert!(invalidated.contains(&"s3".to_string()));
    // s1 stays completed.
    assert_eq!(orch.get("s1").unwrap().state, SagaState::Completed);
}

#[test]
fn gc_after_epoch_invalidation() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
        .unwrap();
    orch.advance_epoch(epoch(2), "t");
    // s1 is now Failed (terminal) created at 100.
    let removed = orch.gc_terminal(200);
    assert_eq!(removed, 1);
    assert_eq!(orch.total_count(), 0);
}

#[test]
fn deterministic_saga_replay() {
    let run = || {
        let mut orch = SagaOrchestrator::new(epoch(1), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "trace-det", 0)
            .unwrap();

        orch.begin_step("s1").unwrap();
        orch.complete_step("s1", 0, success("a-ok"), "key-0", 100)
            .unwrap();
        orch.begin_step("s1").unwrap();
        orch.complete_step("s1", 1, failure("crash"), "key-1", 200)
            .unwrap();
        orch.complete_compensation("s1", 0, success("undone-a"), "comp-0", 300)
            .unwrap();

        let events = orch.drain_events();
        let saga = orch.get("s1").unwrap().clone();
        (events, saga)
    };

    let (e1, s1) = run();
    let (e2, s2) = run();
    assert_eq!(e1, e2);
    assert_eq!(s1, s2);
}

#[test]
fn idempotency_keys_preserved_in_records() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "idem-aabb", 100)
        .unwrap();

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.step_records[0].idempotency_key_hex, "idem-aabb");
}

#[test]
fn step_records_track_completed_at_ticks() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 42)
        .unwrap();

    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, success("ok"), "k1", 99)
        .unwrap();

    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.step_records[0].completed_at, 42);
    assert_eq!(saga.step_records[1].completed_at, 99);
}

#[test]
fn full_publish_saga_with_all_builder_steps() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    let steps = publish_saga_steps("my-package");
    orch.create_saga("p1", SagaType::Publish, steps, "trace-pub", 0)
        .unwrap();

    for i in 0..4 {
        let (idx, step) = orch.begin_step("p1").unwrap();
        assert_eq!(idx, i);
        assert!(!step.step_name.is_empty());
        orch.complete_step(
            "p1",
            i,
            success(&format!("step-{i}-done")),
            &format!("pub-key-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }

    let saga = orch.get("p1").unwrap();
    assert_eq!(saga.state, SagaState::Completed);
    assert_eq!(saga.step_records.len(), 4);
    assert_eq!(saga.last_completed_forward_step(), Some(3));
}

#[test]
fn full_revocation_saga_with_failure_and_compensation() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    let steps = revocation_saga_steps("key-compromised");
    orch.create_saga("r1", SagaType::Revocation, steps, "trace-rev", 0)
        .unwrap();

    // Steps 0, 1, 2 succeed.
    for i in 0..3 {
        orch.begin_step("r1").unwrap();
        orch.complete_step(
            "r1",
            i,
            success("ok"),
            &format!("rk{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }
    // Step 3 (update_frontier) fails.
    orch.begin_step("r1").unwrap();
    orch.complete_step("r1", 3, failure("frontier_locked"), "rk3", 400)
        .unwrap();

    // Compensate steps 2, 1, 0.
    for i in (0..3).rev() {
        let (comp_idx, _) = orch.next_compensation_step("r1").unwrap().unwrap();
        assert_eq!(comp_idx, i);
        orch.complete_compensation(
            "r1",
            i,
            success(&format!("undone-{i}")),
            &format!("crk{i}"),
            (5 + i as u64) * 100,
        )
        .unwrap();
    }

    let saga = orch.get("r1").unwrap();
    assert!(saga.is_terminal());
    // 3 success + 1 failure + 3 compensation = 7 records.
    assert_eq!(saga.step_records.len(), 7);
    assert_eq!(saga.last_completed_forward_step(), Some(2));
}
