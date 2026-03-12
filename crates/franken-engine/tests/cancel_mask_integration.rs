//! Integration tests for the `cancel_mask` module.
//!
//! Tests bounded cancellation masking: policy allowlist, mask lifecycle,
//! tick bounds, nesting denial, event emission, and serde roundtrips.

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

use frankenengine_engine::cancel_mask::{
    CancelMaskContext, MaskBounds, MaskError, MaskEvent, MaskJustification, MaskOutcome, MaskPolicy,
};

// ---------------------------------------------------------------------------
// MaskOutcome display
// ---------------------------------------------------------------------------

#[test]
fn mask_outcome_display() {
    assert_eq!(MaskOutcome::CleanRelease.to_string(), "clean_release");
    assert_eq!(MaskOutcome::BoundExceeded.to_string(), "bound_exceeded");
    assert_eq!(MaskOutcome::CancelDeferred.to_string(), "cancel_deferred");
}

// ---------------------------------------------------------------------------
// MaskBounds
// ---------------------------------------------------------------------------

#[test]
fn mask_bounds_default() {
    let b = MaskBounds::default();
    assert_eq!(b.max_ops, 64);
}

// ---------------------------------------------------------------------------
// MaskPolicy
// ---------------------------------------------------------------------------

#[test]
fn standard_policy_allows_four_operations() {
    let policy = MaskPolicy::standard();
    assert!(policy.is_allowed("checkpoint_write"));
    assert!(policy.is_allowed("evidence_append"));
    assert!(policy.is_allowed("two_phase_commit"));
    assert!(policy.is_allowed("hash_link_finalize"));
    assert!(!policy.is_allowed("arbitrary_computation"));
}

#[test]
fn policy_bounds_for_known_operations() {
    let policy = MaskPolicy::standard();
    assert_eq!(
        policy.bounds_for("checkpoint_write"),
        Some(MaskBounds { max_ops: 32 })
    );
    assert_eq!(
        policy.bounds_for("evidence_append"),
        Some(MaskBounds { max_ops: 16 })
    );
    assert_eq!(
        policy.bounds_for("two_phase_commit"),
        Some(MaskBounds { max_ops: 64 })
    );
    assert_eq!(
        policy.bounds_for("hash_link_finalize"),
        Some(MaskBounds { max_ops: 8 })
    );
    assert_eq!(policy.bounds_for("unknown"), None);
}

// ---------------------------------------------------------------------------
// MaskError display
// ---------------------------------------------------------------------------

#[test]
fn mask_error_display() {
    assert_eq!(MaskError::NestingDenied.to_string(), "mask nesting denied");
    assert!(
        MaskError::OperationNotAllowed {
            operation_name: "x".to_string()
        }
        .to_string()
        .contains("x")
    );
    assert_eq!(
        MaskError::AlreadyReleased.to_string(),
        "mask already released"
    );
}

#[test]
fn mask_error_is_std_error() {
    let err = MaskError::NestingDenied;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_context() -> CancelMaskContext {
    CancelMaskContext::new(MaskPolicy::standard(), "trace-1", "region-1")
}

fn checkpoint_just() -> MaskJustification {
    MaskJustification {
        operation_name: "checkpoint_write".to_string(),
        expected_ops_hint: 10,
        atomicity_reason: "atomic checkpoint finalization".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Mask creation
// ---------------------------------------------------------------------------

#[test]
fn create_mask_succeeds() {
    let mut ctx = test_context();
    let mask_id = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(mask_id, 1);
    assert!(ctx.is_masked());
}

#[test]
fn create_mask_denied_for_disallowed() {
    let mut ctx = test_context();
    let just = MaskJustification {
        operation_name: "long_computation".to_string(),
        expected_ops_hint: 10000,
        atomicity_reason: "none".to_string(),
    };
    let err = ctx.create_mask(&just).unwrap_err();
    assert_eq!(
        err,
        MaskError::OperationNotAllowed {
            operation_name: "long_computation".to_string()
        }
    );
}

#[test]
fn nesting_denied() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    let err = ctx.create_mask(&checkpoint_just()).unwrap_err();
    assert_eq!(err, MaskError::NestingDenied);
}

// ---------------------------------------------------------------------------
// Mask lifecycle
// ---------------------------------------------------------------------------

#[test]
fn clean_release_within_bounds() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..10 {
        assert!(ctx.tick());
    }
    let outcome = ctx.release_mask(false).unwrap();
    assert_eq!(outcome, MaskOutcome::CleanRelease);
    assert!(!ctx.is_masked());
}

#[test]
fn bound_exceeded_auto_unmasks() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    // checkpoint_write: max_ops = 32
    for _ in 0..31 {
        assert!(ctx.tick());
    }
    assert!(!ctx.tick()); // 32nd exceeds
    assert!(!ctx.is_masked());
}

#[test]
fn release_after_bound_exceeded() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    let outcome = ctx.release_mask(false).unwrap();
    assert_eq!(outcome, MaskOutcome::BoundExceeded);
}

#[test]
fn cancel_deferred_on_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    let outcome = ctx.release_mask(true).unwrap();
    assert_eq!(outcome, MaskOutcome::CancelDeferred);
}

#[test]
fn release_without_active_mask_fails() {
    let mut ctx = test_context();
    let err = ctx.release_mask(false).unwrap_err();
    assert_eq!(err, MaskError::AlreadyReleased);
}

#[test]
fn tick_without_active_mask_returns_false() {
    let mut ctx = test_context();
    assert!(!ctx.tick());
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[test]
fn clean_release_emits_event() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, MaskOutcome::CleanRelease);
    assert_eq!(events[0].operation_name, "checkpoint_write");
    assert_eq!(events[0].ops_executed, 1);
}

#[test]
fn bound_exceeded_emits_event() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, MaskOutcome::BoundExceeded);
    assert_eq!(events[0].ops_executed, 32);
}

#[test]
fn event_carries_correct_ids() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();

    let events = ctx.drain_events();
    assert_eq!(events[0].trace_id, "trace-1");
    assert_eq!(events[0].region_id, "region-1");
    assert_eq!(events[0].mask_id, 1);
}

#[test]
fn event_count_tracks() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();
    assert_eq!(ctx.event_count(), 1); // one event emitted, not yet drained
    let _ = ctx.drain_events();
    assert_eq!(ctx.event_count(), 0); // drained
}

// ---------------------------------------------------------------------------
// Sequential masks
// ---------------------------------------------------------------------------

#[test]
fn sequential_masks_unique_ids() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();

    let mask_id = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(mask_id, 2);
    ctx.release_mask(false).unwrap();
}

#[test]
fn sequential_after_bound_exceeded() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    ctx.release_mask(false).unwrap();

    // Can create a new mask after the previous exceeded.
    let mask_id = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(mask_id, 2);
    ctx.release_mask(false).unwrap();
}

// ---------------------------------------------------------------------------
// Hash link finalize bounds
// ---------------------------------------------------------------------------

#[test]
fn hash_link_finalize_tight_bounds() {
    let mut ctx = test_context();
    ctx.create_mask(&MaskJustification {
        operation_name: "hash_link_finalize".to_string(),
        expected_ops_hint: 4,
        atomicity_reason: "hash chain append".to_string(),
    })
    .unwrap();

    for _ in 0..7 {
        assert!(ctx.tick());
    }
    assert!(!ctx.tick()); // 8th exceeds max_ops=8
}

// ---------------------------------------------------------------------------
// Lab mode
// ---------------------------------------------------------------------------

#[test]
fn lab_mode_flag() {
    let mut policy = MaskPolicy::standard();
    policy.lab_mode = true;
    let ctx = CancelMaskContext::new(policy, "t", "r");
    assert!(ctx.is_lab_mode());
}

#[test]
fn non_lab_mode_by_default() {
    let ctx = test_context();
    assert!(!ctx.is_lab_mode());
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_event_sequence() {
    let run = || -> Vec<MaskEvent> {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_just()).unwrap();
        for _ in 0..5 {
            ctx.tick();
        }
        ctx.release_mask(false).unwrap();

        ctx.create_mask(&MaskJustification {
            operation_name: "evidence_append".to_string(),
            expected_ops_hint: 3,
            atomicity_reason: "atomic append".to_string(),
        })
        .unwrap();
        for _ in 0..16 {
            ctx.tick();
        }
        ctx.release_mask(true).unwrap();
        ctx.drain_events()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn mask_justification_serde_roundtrip() {
    let just = checkpoint_just();
    let json = serde_json::to_string(&just).unwrap();
    let restored: MaskJustification = serde_json::from_str(&json).unwrap();
    assert_eq!(just, restored);
}

#[test]
fn mask_policy_serde_roundtrip() {
    let policy = MaskPolicy::standard();
    let json = serde_json::to_string(&policy).unwrap();
    let restored: MaskPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

#[test]
fn mask_event_serde_roundtrip() {
    let event = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: 1,
        operation_name: "checkpoint_write".to_string(),
        ops_executed: 10,
        outcome: MaskOutcome::CleanRelease,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MaskEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn mask_outcome_serde_roundtrip() {
    let outcomes = [
        MaskOutcome::CleanRelease,
        MaskOutcome::BoundExceeded,
        MaskOutcome::CancelDeferred,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let restored: MaskOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, restored);
    }
}

#[test]
fn mask_error_serde_roundtrip() {
    let errors = [
        MaskError::NestingDenied,
        MaskError::OperationNotAllowed {
            operation_name: "x".to_string(),
        },
        MaskError::AlreadyReleased,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: MaskError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn mask_bounds_serde_roundtrip() {
    let bounds = MaskBounds { max_ops: 42 };
    let json = serde_json::to_string(&bounds).unwrap();
    let restored: MaskBounds = serde_json::from_str(&json).unwrap();
    assert_eq!(bounds, restored);
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

#[test]
fn evidence_append_bounds_respected() {
    let mut ctx = test_context();
    ctx.create_mask(&MaskJustification {
        operation_name: "evidence_append".to_string(),
        expected_ops_hint: 10,
        atomicity_reason: "append evidence atomically".to_string(),
    })
    .unwrap();
    for _ in 0..15 {
        assert!(ctx.tick());
    }
    // 16th tick hits bound (max_ops=16)
    assert!(!ctx.tick());
}

#[test]
fn two_phase_commit_bounds_respected() {
    let mut ctx = test_context();
    ctx.create_mask(&MaskJustification {
        operation_name: "two_phase_commit".to_string(),
        expected_ops_hint: 50,
        atomicity_reason: "two phase commit".to_string(),
    })
    .unwrap();
    for _ in 0..63 {
        assert!(ctx.tick());
    }
    assert!(!ctx.tick()); // 64th hits max_ops=64
}

#[test]
fn cancel_deferred_emits_correct_event() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..5 {
        ctx.tick();
    }
    ctx.release_mask(true).unwrap();

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, MaskOutcome::CancelDeferred);
    assert_eq!(events[0].ops_executed, 5);
}

#[test]
fn tick_after_bound_exceeded_stays_false() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    // Subsequent ticks also return false
    assert!(!ctx.tick());
    assert!(!ctx.tick());
    assert!(!ctx.tick());
}

#[test]
fn multiple_masks_accumulate_events() {
    let mut ctx = test_context();

    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();

    ctx.create_mask(&MaskJustification {
        operation_name: "evidence_append".to_string(),
        expected_ops_hint: 3,
        atomicity_reason: "append".to_string(),
    })
    .unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();

    ctx.create_mask(&MaskJustification {
        operation_name: "hash_link_finalize".to_string(),
        expected_ops_hint: 2,
        atomicity_reason: "finalize".to_string(),
    })
    .unwrap();
    ctx.tick();
    ctx.release_mask(true).unwrap();

    assert_eq!(ctx.event_count(), 3);
    let events = ctx.drain_events();
    assert_eq!(events[0].operation_name, "checkpoint_write");
    assert_eq!(events[1].operation_name, "evidence_append");
    assert_eq!(events[2].operation_name, "hash_link_finalize");
    assert_eq!(events[2].outcome, MaskOutcome::CancelDeferred);
}

#[test]
fn custom_empty_policy_denies_all() {
    let policy = MaskPolicy {
        default_bounds: MaskBounds::default(),
        operation_bounds: std::collections::BTreeMap::new(),
        lab_mode: false,
    };
    let mut ctx = CancelMaskContext::new(policy, "t", "r");
    let err = ctx.create_mask(&checkpoint_just()).unwrap_err();
    assert!(matches!(err, MaskError::OperationNotAllowed { .. }));
}

#[test]
fn custom_policy_with_single_op_max_ops_1() {
    let mut bounds = std::collections::BTreeMap::new();
    bounds.insert("tiny_op".to_string(), MaskBounds { max_ops: 1 });
    let policy = MaskPolicy {
        default_bounds: MaskBounds::default(),
        operation_bounds: bounds,
        lab_mode: false,
    };
    let mut ctx = CancelMaskContext::new(policy, "t", "r");
    ctx.create_mask(&MaskJustification {
        operation_name: "tiny_op".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "minimal".to_string(),
    })
    .unwrap();
    // First tick hits the bound immediately
    assert!(!ctx.tick());
    assert!(!ctx.is_masked());
}

#[test]
fn bound_exceeded_then_release_does_not_double_emit() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    // bound_exceeded event already emitted
    assert_eq!(ctx.event_count(), 1);
    ctx.release_mask(false).unwrap();
    // release after bound_exceeded should NOT add another event
    assert_eq!(ctx.event_count(), 1);
}

#[test]
fn is_masked_false_when_no_mask_active() {
    let ctx = test_context();
    assert!(!ctx.is_masked());
}

#[test]
fn mask_id_increments_across_mixed_outcomes() {
    let mut ctx = test_context();
    // Mask 1: clean release
    let id1 = ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    // Mask 2: bound exceeded
    let id2 = ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    ctx.release_mask(false).unwrap();
    // Mask 3: cancel deferred
    let id3 = ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(true).unwrap();

    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);
}

#[test]
fn mask_justification_fields_accessible() {
    let just = MaskJustification {
        operation_name: "test_op".to_string(),
        expected_ops_hint: 42,
        atomicity_reason: "testing fields".to_string(),
    };
    assert_eq!(just.operation_name, "test_op");
    assert_eq!(just.expected_ops_hint, 42);
    assert_eq!(just.atomicity_reason, "testing fields");
}

#[test]
fn drain_events_clears_events() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();
    assert_eq!(ctx.event_count(), 1);

    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(ctx.event_count(), 0);

    // Second drain returns empty
    let events2 = ctx.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn release_mask_zero_ticks_clean_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    // Release immediately without any ticks
    let outcome = ctx.release_mask(false).unwrap();
    assert_eq!(outcome, MaskOutcome::CleanRelease);
    let events = ctx.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].ops_executed, 0);
}
