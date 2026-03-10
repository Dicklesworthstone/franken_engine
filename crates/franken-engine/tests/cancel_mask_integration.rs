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
