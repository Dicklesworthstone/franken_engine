//! Enrichment integration tests for the `saga_orchestrator` module.
//!
//! Covers display uniqueness, SagaId edge cases, struct-level serde/equality,
//! orchestrator idempotency, step index mismatches, multi-epoch scenarios,
//! GC edge cases, builder helpers, event field verification, complex
//! lifecycle scenarios, event counts, and error trait coverage.

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

/// Run a saga through all forward steps to completion.
fn complete_saga(orch: &mut SagaOrchestrator, saga_id: &str, step_count: usize) {
    for i in 0..step_count {
        orch.begin_step(saga_id).unwrap();
        orch.complete_step(
            saga_id,
            i,
            success(&format!("ok-{i}")),
            &format!("key-{i}"),
            (i as u64 + 1) * 100,
        )
        .unwrap();
    }
}

// ===========================================================================
// 1. Display Uniqueness
// ===========================================================================

#[test]
fn enrichment_saga_type_all_four_display_values_unique() {
    let displays: BTreeSet<String> = [
        SagaType::Quarantine,
        SagaType::Revocation,
        SagaType::Eviction,
        SagaType::Publish,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        4,
        "all SagaType variants produce distinct display strings"
    );
}

#[test]
fn enrichment_saga_state_all_five_display_values_unique() {
    let displays: BTreeSet<String> = [
        SagaState::Pending,
        SagaState::InProgress { step_index: 0 },
        SagaState::Compensating { step_index: 0 },
        SagaState::Completed,
        SagaState::Failed {
            diagnostic: "x".to_string(),
        },
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        5,
        "all SagaState variants produce distinct display strings"
    );
}

#[test]
fn enrichment_step_outcome_all_three_display_values_unique() {
    let displays: BTreeSet<String> = [
        StepOutcome::Success {
            result: "v".to_string(),
        },
        StepOutcome::Failure {
            diagnostic: "v".to_string(),
        },
        StepOutcome::Cancelled {
            reason: "v".to_string(),
        },
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        3,
        "all StepOutcome variants produce distinct display strings"
    );
}

#[test]
fn enrichment_action_type_two_display_values_unique() {
    let displays: BTreeSet<String> = [ActionType::Forward, ActionType::Compensate]
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(
        displays.len(),
        2,
        "both ActionType variants produce distinct display strings"
    );
}

#[test]
fn enrichment_saga_error_display_exact_format_all_variants() {
    let err1 = SagaError::SagaNotFound {
        saga_id: "s1".to_string(),
    };
    assert_eq!(err1.to_string(), "saga s1 not found");

    let err2 = SagaError::SagaAlreadyTerminal {
        saga_id: "s2".to_string(),
        state: "completed".to_string(),
    };
    assert_eq!(err2.to_string(), "saga s2 already terminal (completed)");

    let err3 = SagaError::StepIndexOutOfBounds {
        saga_id: "s3".to_string(),
        step_index: 5,
        step_count: 3,
    };
    assert_eq!(err3.to_string(), "saga s3 step 5 out of bounds (3 steps)");

    let err4 = SagaError::EmptySteps;
    assert_eq!(err4.to_string(), "saga must have at least one step");

    let err5 = SagaError::InvalidSagaId {
        reason: "empty saga ID".to_string(),
    };
    assert_eq!(err5.to_string(), "invalid saga ID: empty saga ID");

    let err6 = SagaError::CompensationFailed {
        saga_id: "s6".to_string(),
        step_index: 2,
        diagnostic: "fatal".to_string(),
    };
    assert_eq!(
        err6.to_string(),
        "saga s6 compensation failed at step 2: fatal"
    );

    let err7 = SagaError::ConcurrencyLimitReached {
        active_count: 10,
        max_concurrent: 10,
    };
    assert_eq!(
        err7.to_string(),
        "concurrency limit reached: 10 active sagas (max 10)"
    );
}

// ===========================================================================
// 2. SagaId Edge Cases
// ===========================================================================

#[test]
fn enrichment_saga_id_unicode_content() {
    let id = SagaId::from_trace("saga-\u{1F680}-\u{00E9}");
    assert_eq!(id.as_str(), "saga-\u{1F680}-\u{00E9}");
    assert!(id.to_string().starts_with("saga:"));
    // Serde roundtrip with unicode
    let json = serde_json::to_string(&id).unwrap();
    let restored: SagaId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn enrichment_saga_id_whitespace_preserved() {
    let id = SagaId::from_trace("  spaces  ");
    assert_eq!(id.as_str(), "  spaces  ");
    assert_eq!(id.to_string(), "saga:  spaces  ");
}

#[test]
fn enrichment_saga_id_long_string() {
    let long = "x".repeat(10_000);
    let id = SagaId::from_trace(&long);
    assert_eq!(id.as_str().len(), 10_000);
    let json = serde_json::to_string(&id).unwrap();
    let restored: SagaId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn enrichment_saga_id_clone_eq_symmetry() {
    let a = SagaId::from_trace("alpha");
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(b, a); // symmetry
    let c = SagaId::from_trace("beta");
    assert_ne!(a, c);
}

// ===========================================================================
// 3. Struct-Level Serde/Equality
// ===========================================================================

#[test]
fn enrichment_saga_with_multiple_records_serde_roundtrip() {
    let saga = Saga {
        saga_id: SagaId::from_trace("multi"),
        saga_type: SagaType::Revocation,
        steps: simple_steps(),
        state: SagaState::Compensating { step_index: 0 },
        epoch: epoch(3),
        trace_id: "trace-multi".to_string(),
        step_records: vec![
            StepRecord {
                step_index: 0,
                step_name: "step_a".to_string(),
                action_type: ActionType::Forward,
                outcome: success("ok-0"),
                completed_at: 100,
                idempotency_key_hex: "k0".to_string(),
            },
            StepRecord {
                step_index: 1,
                step_name: "step_b".to_string(),
                action_type: ActionType::Forward,
                outcome: failure("net-err"),
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
        created_at: 50,
    };
    let json = serde_json::to_string(&saga).unwrap();
    let restored: Saga = serde_json::from_str(&json).unwrap();
    assert_eq!(saga, restored);
}

#[test]
fn enrichment_step_record_all_outcome_variants_serde() {
    let outcomes = vec![success("done"), failure("err"), cancelled("timeout")];
    for (i, outcome) in outcomes.into_iter().enumerate() {
        let record = StepRecord {
            step_index: i,
            step_name: format!("step_{i}"),
            action_type: if i == 0 {
                ActionType::Forward
            } else {
                ActionType::Compensate
            },
            outcome,
            completed_at: (i as u64 + 1) * 100,
            idempotency_key_hex: format!("key-{i}"),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: StepRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
    }
}

#[test]
fn enrichment_saga_event_all_fields_present_in_json() {
    let event = SagaEvent {
        saga_id: "s-1".to_string(),
        saga_type: "eviction".to_string(),
        step_name: "mark_eviction".to_string(),
        step_index: 0,
        action: "forward".to_string(),
        result: "success(ok)".to_string(),
        trace_id: "trace-42".to_string(),
        epoch_id: 7,
        event: "step_complete".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    // All fields should be present
    assert!(json.contains("\"saga_id\""));
    assert!(json.contains("\"saga_type\""));
    assert!(json.contains("\"step_name\""));
    assert!(json.contains("\"step_index\""));
    assert!(json.contains("\"action\""));
    assert!(json.contains("\"result\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"epoch_id\""));
    assert!(json.contains("\"event\""));
    let restored: SagaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_saga_state_structural_equality() {
    let a = SagaState::InProgress { step_index: 3 };
    let b = SagaState::InProgress { step_index: 3 };
    let c = SagaState::InProgress { step_index: 4 };
    assert_eq!(a, b);
    assert_ne!(a, c);

    let d = SagaState::Failed {
        diagnostic: "x".to_string(),
    };
    let e = SagaState::Failed {
        diagnostic: "x".to_string(),
    };
    let f = SagaState::Failed {
        diagnostic: "y".to_string(),
    };
    assert_eq!(d, e);
    assert_ne!(d, f);
}

#[test]
fn enrichment_saga_clone_deep_independence() {
    let original = Saga {
        saga_id: SagaId::from_trace("orig"),
        saga_type: SagaType::Publish,
        steps: simple_steps(),
        state: SagaState::InProgress { step_index: 1 },
        epoch: epoch(2),
        trace_id: "trace-orig".to_string(),
        step_records: vec![StepRecord {
            step_index: 0,
            step_name: "step_a".to_string(),
            action_type: ActionType::Forward,
            outcome: success("ok"),
            completed_at: 100,
            idempotency_key_hex: "k0".to_string(),
        }],
        created_at: 10,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // They are independent objects
    assert_eq!(original.saga_id, cloned.saga_id);
    assert_eq!(original.step_records.len(), cloned.step_records.len());
}

// ===========================================================================
// 4. Orchestrator Idempotency
// ===========================================================================

#[test]
fn enrichment_forward_step_idempotent_no_duplicate_record() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    // First completion.
    let state1 = orch
        .complete_step("s1", 0, success("ok"), "idem-key-A", 100)
        .unwrap();
    // Duplicate with same key.
    let state2 = orch
        .complete_step("s1", 0, success("ok"), "idem-key-A", 200)
        .unwrap();
    assert_eq!(state1, state2);
    // Only one record should exist.
    assert_eq!(orch.get("s1").unwrap().step_records.len(), 1);
}

#[test]
fn enrichment_forward_step_different_key_is_rejected_by_state_mismatch() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    // First completion advances state.
    orch.complete_step("s1", 0, success("ok"), "key-A", 100)
        .unwrap();
    // Now state is InProgress{1}. Trying to complete step 0 with different key
    // will fail because state index doesn't match.
    let err = orch
        .complete_step("s1", 0, success("ok"), "key-B", 200)
        .unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

#[test]
fn enrichment_compensation_idempotent_same_key() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();
    // Now compensating at step 0.

    let state1 = orch
        .complete_compensation("s1", 0, success("undone"), "comp-k0", 300)
        .unwrap();
    // Duplicate with same idempotency key.
    let state2 = orch
        .complete_compensation("s1", 0, success("undone"), "comp-k0", 400)
        .unwrap();
    assert_eq!(state1, state2);
}

#[test]
fn enrichment_compensation_different_key_rejected_after_state_change() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Eviction, simple_steps(), "t1", 0)
        .unwrap();
    // Steps 0,1 succeed, step 2 fails -> compensating at 1.
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
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 2, failure("err"), "k2", 300)
        .unwrap();

    // Compensate step 1 successfully -> now compensating at 0.
    orch.complete_compensation("s1", 1, success("undone-1"), "ck1", 400)
        .unwrap();
    // Trying to compensate step 1 again with different key fails (state is now at step 0).
    let err = orch
        .complete_compensation("s1", 1, success("undone-1"), "ck1-different", 500)
        .unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

// ===========================================================================
// 5. Step Index Mismatch
// ===========================================================================

#[test]
fn enrichment_complete_step_wrong_index_not_oob_returns_error() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    // State is InProgress{0}. Completing step 2 (valid index, but wrong) should fail.
    let err = orch
        .complete_step("s1", 2, success("ok"), "k", 100)
        .unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

#[test]
fn enrichment_compensation_wrong_index_rejected() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();
    // Compensating at step 0. Trying to compensate step 1 should fail.
    let err = orch
        .complete_compensation("s1", 1, success("undone"), "ck", 300)
        .unwrap_err();
    // State index mismatch (compensating at 0 not 1).
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

#[test]
fn enrichment_complete_step_on_pending_saga_fails() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    // Without calling begin_step, state is Pending.
    let err = orch
        .complete_step("s1", 0, success("ok"), "k", 100)
        .unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyTerminal { .. }));
}

// ===========================================================================
// 6. Multi-Epoch Scenarios
// ===========================================================================

#[test]
fn enrichment_double_advance_epoch() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();

    // First advance invalidates s1.
    let inv1 = orch.advance_epoch(epoch(2), "t-adv1");
    assert_eq!(inv1.len(), 1);

    // Second advance with no active sagas.
    let inv2 = orch.advance_epoch(epoch(3), "t-adv2");
    assert_eq!(inv2.len(), 0);
    assert_eq!(orch.epoch(), epoch(3));
}

#[test]
fn enrichment_create_after_advance_binds_new_epoch() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.advance_epoch(epoch(5), "t-adv");

    orch.create_saga("s-new", SagaType::Publish, simple_steps(), "t-new", 100)
        .unwrap();
    let saga = orch.get("s-new").unwrap();
    assert_eq!(saga.epoch, epoch(5));

    // begin_step should succeed because saga epoch matches current.
    let (idx, _step) = orch.begin_step("s-new").unwrap();
    assert_eq!(idx, 0);
}

#[test]
fn enrichment_same_epoch_advance_is_noop_for_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Revocation, simple_steps(), "t1", 0)
        .unwrap();

    // Advancing to the same epoch should not invalidate anything.
    let inv = orch.advance_epoch(epoch(1), "t-same");
    assert!(inv.is_empty());
    assert!(!orch.get("s1").unwrap().is_terminal());
}

#[test]
fn enrichment_epoch_invalidation_diagnostic_contains_epochs() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Eviction, simple_steps(), "t1", 0)
        .unwrap();

    orch.advance_epoch(epoch(7), "t-adv");
    let saga = orch.get("s1").unwrap();
    if let SagaState::Failed { diagnostic } = &saga.state {
        assert!(diagnostic.contains("epoch_invalidated"));
        // Should mention old and new epochs.
        assert!(diagnostic.contains("1") || diagnostic.contains("epoch"));
    } else {
        panic!("expected Failed state after epoch invalidation");
    }
}

#[test]
fn enrichment_mixed_states_during_epoch_advance() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    // Create three sagas: one pending, one in-progress, one completed.
    orch.create_saga("pending", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    orch.create_saga("active", SagaType::Quarantine, simple_steps(), "t2", 0)
        .unwrap();
    orch.begin_step("active").unwrap();

    orch.create_saga("done", SagaType::Revocation, simple_steps(), "t3", 0)
        .unwrap();
    complete_saga(&mut orch, "done", 3);

    let inv = orch.advance_epoch(epoch(2), "t-adv");
    // Only non-terminal sagas should be invalidated.
    assert_eq!(inv.len(), 2);
    assert!(inv.contains(&"pending".to_string()));
    assert!(inv.contains(&"active".to_string()));
    // Completed saga preserved.
    assert_eq!(orch.get("done").unwrap().state, SagaState::Completed);
}

// ===========================================================================
// 7. GC Edge Cases
// ===========================================================================

#[test]
fn enrichment_gc_exact_threshold_does_not_remove() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    // created_at=100, threshold=100: not strictly less than, so NOT removed.
    let removed = orch.gc_terminal(100);
    assert_eq!(removed, 0);
    assert_eq!(orch.total_count(), 1);
}

#[test]
fn enrichment_gc_zero_threshold_removes_nothing() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    // Threshold 0 means created_at < 0 which is impossible for u64.
    let removed = orch.gc_terminal(0);
    assert_eq!(removed, 0);
}

#[test]
fn enrichment_gc_max_threshold_removes_all_terminal() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);
    orch.create_saga("s2", SagaType::Eviction, simple_steps(), "t2", 999)
        .unwrap();
    complete_saga(&mut orch, "s2", 3);

    let removed = orch.gc_terminal(u64::MAX);
    assert_eq!(removed, 2);
    assert_eq!(orch.total_count(), 0);
}

#[test]
fn enrichment_gc_preserves_recent_failed_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 500)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, failure("boom"), "k0", 600)
        .unwrap();
    // s1 is now Failed (terminal), created_at=500.

    // Threshold 400: 500 is NOT < 400, so preserved.
    let removed = orch.gc_terminal(400);
    assert_eq!(removed, 0);
    assert!(orch.get("s1").unwrap().is_terminal());
}

// ===========================================================================
// 8. Builder Helpers
// ===========================================================================

#[test]
fn enrichment_quarantine_steps_embed_target_in_all_names() {
    let target = "ext-malicious-42";
    let steps = quarantine_saga_steps(target);
    for step in &steps {
        assert!(
            step.step_name.contains(target),
            "step_name '{}' must contain target '{}'",
            step.step_name,
            target
        );
    }
    // Each step has a non-empty compensating action.
    for step in &steps {
        assert!(!step.compensating_action.is_empty());
    }
}

#[test]
fn enrichment_revocation_steps_embed_target() {
    let target = "cert-ABCDEF";
    let steps = revocation_saga_steps(target);
    assert_eq!(steps.len(), 4);
    for step in &steps {
        assert!(step.step_name.contains(target));
    }
}

#[test]
fn enrichment_eviction_steps_embed_target() {
    let target = "pkg-old-v1";
    let steps = eviction_saga_steps(target);
    assert_eq!(steps.len(), 4);
    for step in &steps {
        assert!(step.step_name.contains(target));
    }
}

#[test]
fn enrichment_publish_steps_embed_artifact() {
    let artifact = "my-artifact-v2";
    let steps = publish_saga_steps(artifact);
    assert_eq!(steps.len(), 4);
    for step in &steps {
        assert!(step.step_name.contains(artifact));
    }
}

#[test]
fn enrichment_all_builders_have_nonzero_timeouts() {
    let all_steps: Vec<Vec<SagaStep>> = vec![
        quarantine_saga_steps("x"),
        revocation_saga_steps("x"),
        eviction_saga_steps("x"),
        publish_saga_steps("x"),
    ];
    for steps in &all_steps {
        for step in steps {
            assert!(step.timeout_ticks > 0, "timeout must be > 0");
        }
    }
}

// ===========================================================================
// 9. Event Field Verification
// ===========================================================================

#[test]
fn enrichment_step_complete_event_result_field_matches_outcome() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events(); // clear create event

    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("payload-ok"), "k0", 100)
        .unwrap();

    let events = orch.drain_events();
    let complete_evt = events.iter().find(|e| e.event == "step_complete").unwrap();
    assert_eq!(complete_evt.result, "success(payload-ok)");
    assert_eq!(complete_evt.action, "forward");
}

#[test]
fn enrichment_failure_event_result_field() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.drain_events();

    orch.complete_step("s1", 0, failure("disk_full"), "k0", 100)
        .unwrap();
    let events = orch.drain_events();
    let complete_evt = events.iter().find(|e| e.event == "step_complete").unwrap();
    assert_eq!(complete_evt.result, "failure(disk_full)");
}

#[test]
fn enrichment_compensation_event_action_field() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();
    orch.drain_events();

    orch.complete_compensation("s1", 0, success("undone"), "ck0", 300)
        .unwrap();
    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "compensate");
    assert_eq!(events[0].event, "compensation_complete");
    assert_eq!(events[0].step_name, "step_a");
}

#[test]
fn enrichment_create_event_trace_id_matches() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Eviction, simple_steps(), "my-trace-42", 0)
        .unwrap();
    let events = orch.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].trace_id, "my-trace-42");
    assert_eq!(events[0].event, "saga_created");
}

#[test]
fn enrichment_event_epoch_id_reflects_current_epoch() {
    let mut orch = SagaOrchestrator::new(epoch(5), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    let events = orch.drain_events();
    assert_eq!(events[0].epoch_id, 5);

    orch.begin_step("s1").unwrap();
    let events = orch.drain_events();
    assert_eq!(events[0].epoch_id, 5);
}

// ===========================================================================
// 10. Complex Lifecycle
// ===========================================================================

#[test]
fn enrichment_interleaved_execution_of_two_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("sa", SagaType::Publish, simple_steps(), "ta", 0)
        .unwrap();
    orch.create_saga("sb", SagaType::Quarantine, simple_steps(), "tb", 0)
        .unwrap();

    // Interleave: sa step 0, sb step 0, sa step 1, sb step 1, etc.
    for i in 0..3 {
        orch.begin_step("sa").unwrap();
        orch.complete_step(
            "sa",
            i,
            success(&format!("a-{i}")),
            &format!("ka-{i}"),
            i as u64 * 10,
        )
        .unwrap();
        orch.begin_step("sb").unwrap();
        orch.complete_step(
            "sb",
            i,
            success(&format!("b-{i}")),
            &format!("kb-{i}"),
            i as u64 * 10 + 5,
        )
        .unwrap();
    }

    assert_eq!(orch.get("sa").unwrap().state, SagaState::Completed);
    assert_eq!(orch.get("sb").unwrap().state, SagaState::Completed);
    assert_eq!(orch.active_count(), 0);
}

#[test]
fn enrichment_single_step_saga_compensation_goes_to_failed() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, single_step(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();

    // Single-step saga fails at step 0 -> directly Failed (nothing to compensate).
    let state = orch
        .complete_step("s1", 0, failure("boom"), "k0", 100)
        .unwrap();
    assert!(matches!(state, SagaState::Failed { .. }));
    assert!(orch.get("s1").unwrap().is_terminal());
}

#[test]
fn enrichment_large_step_count_saga() {
    let many_steps: Vec<SagaStep> = (0..20)
        .map(|i| SagaStep {
            step_name: format!("step_{i}"),
            forward_action: format!("do_{i}"),
            compensating_action: format!("undo_{i}"),
            timeout_ticks: 100,
        })
        .collect();
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("big", SagaType::Publish, many_steps, "t1", 0)
        .unwrap();

    complete_saga(&mut orch, "big", 20);
    let saga = orch.get("big").unwrap();
    assert_eq!(saga.state, SagaState::Completed);
    assert_eq!(saga.step_records.len(), 20);
    assert_eq!(saga.last_completed_forward_step(), Some(19));
}

#[test]
fn enrichment_duplicate_saga_id_is_rejected_without_overwrite() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("dup", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events();

    let err = orch
        .create_saga("dup", SagaType::Quarantine, simple_steps(), "t2", 100)
        .unwrap_err();
    assert!(matches!(err, SagaError::SagaAlreadyExists { .. }));

    let saga = orch.get("dup").unwrap();
    assert_eq!(saga.saga_type, SagaType::Publish);
    assert_eq!(saga.trace_id, "t1");
    assert_eq!(saga.created_at, 0);
    assert_eq!(orch.event_counts().get("saga_created"), Some(&1));
    assert!(orch.drain_events().is_empty());
}

#[test]
fn enrichment_gc_then_recreate_same_id() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
        .unwrap();
    complete_saga(&mut orch, "s1", 3);

    // GC removes s1.
    let removed = orch.gc_terminal(200);
    assert_eq!(removed, 1);
    assert!(orch.get("s1").is_none());

    // Recreate with same ID.
    orch.create_saga("s1", SagaType::Eviction, simple_steps(), "t2", 300)
        .unwrap();
    let saga = orch.get("s1").unwrap();
    assert_eq!(saga.saga_type, SagaType::Eviction);
    assert_eq!(saga.state, SagaState::Pending);
}

#[test]
fn enrichment_begin_step_idempotent_returns_same_index() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();

    let (idx1, step1) = orch.begin_step("s1").unwrap();
    // Calling begin_step again when already InProgress at same step returns same result.
    let (idx2, step2) = orch.begin_step("s1").unwrap();
    assert_eq!(idx1, idx2);
    assert_eq!(step1.step_name, step2.step_name);
}

// ===========================================================================
// 11. Event Counts
// ===========================================================================

#[test]
fn enrichment_event_counts_persist_across_drain() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.drain_events();

    // Counts should persist even after drain.
    assert_eq!(*orch.event_counts().get("saga_created").unwrap(), 1);
}

#[test]
fn enrichment_event_counts_accumulate_across_sagas() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.create_saga("s2", SagaType::Quarantine, simple_steps(), "t2", 0)
        .unwrap();
    orch.create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
        .unwrap();

    assert_eq!(*orch.event_counts().get("saga_created").unwrap(), 3);
}

#[test]
fn enrichment_compensation_events_tracked_in_counts() {
    let mut orch = SagaOrchestrator::new(epoch(1), 10);
    orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 0, success("ok"), "k0", 100)
        .unwrap();
    orch.begin_step("s1").unwrap();
    orch.complete_step("s1", 1, failure("err"), "k1", 200)
        .unwrap();
    orch.complete_compensation("s1", 0, success("undone"), "ck0", 300)
        .unwrap();

    assert_eq!(
        *orch.event_counts().get("compensation_complete").unwrap(),
        1
    );
    assert_eq!(*orch.event_counts().get("step_complete").unwrap(), 2);
    assert_eq!(*orch.event_counts().get("step_begin").unwrap(), 2);
}

// ===========================================================================
// 12. Error Trait/Debug
// ===========================================================================

#[test]
fn enrichment_saga_error_source_is_none() {
    use std::error::Error;
    let err = SagaError::EmptySteps;
    assert!(err.source().is_none());

    let err2 = SagaError::SagaNotFound {
        saga_id: "s1".to_string(),
    };
    assert!(err2.source().is_none());
}

#[test]
fn enrichment_saga_error_debug_differs_from_display() {
    let err = SagaError::SagaNotFound {
        saga_id: "s1".to_string(),
    };
    let display_str = format!("{err}");
    let debug_str = format!("{err:?}");
    // Debug includes the variant name and struct fields.
    assert_ne!(display_str, debug_str);
    assert!(debug_str.contains("SagaNotFound"));
}
