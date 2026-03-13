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

// ===========================================================================
// Enrichment tests — PearlTower 2026-03-12
// ===========================================================================

// ---------------------------------------------------------------------------
// MaskOutcome — Clone, Copy, Debug, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_outcome_clone() {
    let a = MaskOutcome::CleanRelease;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_outcome_copy() {
    let a = MaskOutcome::BoundExceeded;
    let b = a;
    // a is still usable because MaskOutcome is Copy
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_outcome_debug_clean_release() {
    let dbg = format!("{:?}", MaskOutcome::CleanRelease);
    assert!(dbg.contains("CleanRelease"));
}

#[test]
fn enrichment_mask_outcome_debug_bound_exceeded() {
    let dbg = format!("{:?}", MaskOutcome::BoundExceeded);
    assert!(dbg.contains("BoundExceeded"));
}

#[test]
fn enrichment_mask_outcome_debug_cancel_deferred() {
    let dbg = format!("{:?}", MaskOutcome::CancelDeferred);
    assert!(dbg.contains("CancelDeferred"));
}

#[test]
fn enrichment_mask_outcome_display_does_not_contain_variant_name() {
    // Display uses snake_case, Debug uses PascalCase — they must differ
    let display = MaskOutcome::CleanRelease.to_string();
    assert_eq!(display, "clean_release");
    assert!(!display.contains("CleanRelease"));
}

#[test]
fn enrichment_mask_outcome_serde_json_strings() {
    // Verify the exact JSON representation of each variant
    let json_clean = serde_json::to_string(&MaskOutcome::CleanRelease).unwrap();
    let json_bound = serde_json::to_string(&MaskOutcome::BoundExceeded).unwrap();
    let json_cancel = serde_json::to_string(&MaskOutcome::CancelDeferred).unwrap();
    assert!(json_clean.contains("CleanRelease") || json_clean.contains("clean"));
    assert!(json_bound.contains("BoundExceeded") || json_bound.contains("bound"));
    assert!(json_cancel.contains("CancelDeferred") || json_cancel.contains("cancel"));
}

#[test]
fn enrichment_mask_outcome_eq_reflexive() {
    assert_eq!(MaskOutcome::CleanRelease, MaskOutcome::CleanRelease);
    assert_eq!(MaskOutcome::BoundExceeded, MaskOutcome::BoundExceeded);
    assert_eq!(MaskOutcome::CancelDeferred, MaskOutcome::CancelDeferred);
}

#[test]
fn enrichment_mask_outcome_ne_across_variants() {
    assert_ne!(MaskOutcome::CleanRelease, MaskOutcome::BoundExceeded);
    assert_ne!(MaskOutcome::CleanRelease, MaskOutcome::CancelDeferred);
    assert_ne!(MaskOutcome::BoundExceeded, MaskOutcome::CancelDeferred);
}

// ---------------------------------------------------------------------------
// MaskError — Clone, Debug, Display, serde, std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_error_clone() {
    let a = MaskError::NestingDenied;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_error_clone_operation_not_allowed() {
    let a = MaskError::OperationNotAllowed {
        operation_name: "test_op".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_error_debug_nesting_denied() {
    let dbg = format!("{:?}", MaskError::NestingDenied);
    assert!(dbg.contains("NestingDenied"));
}

#[test]
fn enrichment_mask_error_debug_operation_not_allowed() {
    let dbg = format!(
        "{:?}",
        MaskError::OperationNotAllowed {
            operation_name: "bad_op".to_string(),
        }
    );
    assert!(dbg.contains("OperationNotAllowed"));
    assert!(dbg.contains("bad_op"));
}

#[test]
fn enrichment_mask_error_debug_already_released() {
    let dbg = format!("{:?}", MaskError::AlreadyReleased);
    assert!(dbg.contains("AlreadyReleased"));
}

#[test]
fn enrichment_mask_error_display_already_released_exact() {
    assert_eq!(
        MaskError::AlreadyReleased.to_string(),
        "mask already released"
    );
}

#[test]
fn enrichment_mask_error_display_nesting_denied_exact() {
    assert_eq!(MaskError::NestingDenied.to_string(), "mask nesting denied");
}

#[test]
fn enrichment_mask_error_display_operation_not_allowed_exact() {
    let err = MaskError::OperationNotAllowed {
        operation_name: "forbidden".to_string(),
    };
    assert_eq!(err.to_string(), "operation not allowed to mask: forbidden");
}

#[test]
fn enrichment_mask_error_std_error_source_is_none() {
    use std::error::Error;
    let err = MaskError::NestingDenied;
    assert!(err.source().is_none());
}

#[test]
fn enrichment_mask_error_serde_nesting_denied_json_field() {
    let json = serde_json::to_string(&MaskError::NestingDenied).unwrap();
    let restored: MaskError = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, MaskError::NestingDenied);
}

#[test]
fn enrichment_mask_error_serde_operation_not_allowed_preserves_name() {
    let err = MaskError::OperationNotAllowed {
        operation_name: "special_op_42".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("special_op_42"));
    let restored: MaskError = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, err);
}

#[test]
fn enrichment_mask_error_ne_across_variants() {
    assert_ne!(MaskError::NestingDenied, MaskError::AlreadyReleased);
    assert_ne!(
        MaskError::NestingDenied,
        MaskError::OperationNotAllowed {
            operation_name: "x".to_string()
        }
    );
    assert_ne!(
        MaskError::AlreadyReleased,
        MaskError::OperationNotAllowed {
            operation_name: "x".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// MaskBounds — Clone, Copy, Debug, Default, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_bounds_clone() {
    let a = MaskBounds { max_ops: 99 };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_bounds_copy() {
    let a = MaskBounds { max_ops: 7 };
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_bounds_debug() {
    let dbg = format!("{:?}", MaskBounds { max_ops: 128 });
    assert!(dbg.contains("MaskBounds"));
    assert!(dbg.contains("128"));
}

#[test]
fn enrichment_mask_bounds_default_is_64() {
    assert_eq!(MaskBounds::default().max_ops, 64);
}

#[test]
fn enrichment_mask_bounds_serde_json_field_name() {
    let bounds = MaskBounds { max_ops: 55 };
    let json = serde_json::to_string(&bounds).unwrap();
    assert!(json.contains("\"max_ops\""));
    assert!(json.contains("55"));
}

#[test]
fn enrichment_mask_bounds_eq_different_values() {
    assert_ne!(MaskBounds { max_ops: 1 }, MaskBounds { max_ops: 2 });
}

#[test]
fn enrichment_mask_bounds_zero_max_ops() {
    let b = MaskBounds { max_ops: 0 };
    let json = serde_json::to_string(&b).unwrap();
    let restored: MaskBounds = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.max_ops, 0);
}

#[test]
fn enrichment_mask_bounds_max_u64() {
    let b = MaskBounds { max_ops: u64::MAX };
    let json = serde_json::to_string(&b).unwrap();
    let restored: MaskBounds = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.max_ops, u64::MAX);
}

// ---------------------------------------------------------------------------
// MaskJustification — Clone, Debug, serde, field access
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_justification_clone() {
    let a = checkpoint_just();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_justification_debug() {
    let just = checkpoint_just();
    let dbg = format!("{:?}", just);
    assert!(dbg.contains("MaskJustification"));
    assert!(dbg.contains("checkpoint_write"));
}

#[test]
fn enrichment_mask_justification_serde_json_field_names() {
    let just = checkpoint_just();
    let json = serde_json::to_string(&just).unwrap();
    assert!(json.contains("\"operation_name\""));
    assert!(json.contains("\"expected_ops_hint\""));
    assert!(json.contains("\"atomicity_reason\""));
}

#[test]
fn enrichment_mask_justification_empty_strings() {
    let just = MaskJustification {
        operation_name: String::new(),
        expected_ops_hint: 0,
        atomicity_reason: String::new(),
    };
    let json = serde_json::to_string(&just).unwrap();
    let restored: MaskJustification = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.operation_name, "");
    assert_eq!(restored.expected_ops_hint, 0);
    assert_eq!(restored.atomicity_reason, "");
}

#[test]
fn enrichment_mask_justification_ne_different_operation() {
    let a = MaskJustification {
        operation_name: "op_a".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason".to_string(),
    };
    let b = MaskJustification {
        operation_name: "op_b".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_mask_justification_ne_different_hint() {
    let a = MaskJustification {
        operation_name: "op".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason".to_string(),
    };
    let b = MaskJustification {
        operation_name: "op".to_string(),
        expected_ops_hint: 2,
        atomicity_reason: "reason".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_mask_justification_ne_different_reason() {
    let a = MaskJustification {
        operation_name: "op".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason_a".to_string(),
    };
    let b = MaskJustification {
        operation_name: "op".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason_b".to_string(),
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// MaskPolicy — Clone, Debug, serde, custom policies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_policy_clone() {
    let a = MaskPolicy::standard();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_mask_policy_debug() {
    let dbg = format!("{:?}", MaskPolicy::standard());
    assert!(dbg.contains("MaskPolicy"));
    assert!(dbg.contains("checkpoint_write"));
}

#[test]
fn enrichment_mask_policy_serde_json_field_names() {
    let policy = MaskPolicy::standard();
    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("\"default_bounds\""));
    assert!(json.contains("\"operation_bounds\""));
    assert!(json.contains("\"lab_mode\""));
}

#[test]
fn enrichment_mask_policy_standard_has_four_ops() {
    let policy = MaskPolicy::standard();
    assert_eq!(policy.operation_bounds.len(), 4);
}

#[test]
fn enrichment_mask_policy_standard_not_lab_mode() {
    let policy = MaskPolicy::standard();
    assert!(!policy.lab_mode);
}

#[test]
fn enrichment_mask_policy_standard_default_bounds() {
    let policy = MaskPolicy::standard();
    assert_eq!(policy.default_bounds, MaskBounds::default());
    assert_eq!(policy.default_bounds.max_ops, 64);
}

#[test]
fn enrichment_mask_policy_bounds_for_returns_specific_not_default() {
    let policy = MaskPolicy::standard();
    // checkpoint_write: 32, not default 64
    let bounds = policy.bounds_for("checkpoint_write").unwrap();
    assert_eq!(bounds.max_ops, 32);
    assert_ne!(bounds, policy.default_bounds);
}

#[test]
fn enrichment_mask_policy_is_allowed_empty_string() {
    let policy = MaskPolicy::standard();
    assert!(!policy.is_allowed(""));
}

#[test]
fn enrichment_mask_policy_bounds_for_empty_string() {
    let policy = MaskPolicy::standard();
    assert_eq!(policy.bounds_for(""), None);
}

#[test]
fn enrichment_mask_policy_custom_single_operation() {
    let mut bounds = std::collections::BTreeMap::new();
    bounds.insert("my_atomic_step".to_string(), MaskBounds { max_ops: 5 });
    let policy = MaskPolicy {
        default_bounds: MaskBounds { max_ops: 100 },
        operation_bounds: bounds,
        lab_mode: false,
    };
    assert!(policy.is_allowed("my_atomic_step"));
    assert!(!policy.is_allowed("checkpoint_write"));
    assert_eq!(
        policy.bounds_for("my_atomic_step"),
        Some(MaskBounds { max_ops: 5 })
    );
}

#[test]
fn enrichment_mask_policy_ne_different_lab_mode() {
    let mut a = MaskPolicy::standard();
    let mut b = MaskPolicy::standard();
    a.lab_mode = false;
    b.lab_mode = true;
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// MaskEvent — Clone, Debug, serde, field access
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mask_event_clone() {
    let event = MaskEvent {
        trace_id: "t1".to_string(),
        region_id: "r1".to_string(),
        mask_id: 42,
        operation_name: "evidence_append".to_string(),
        ops_executed: 7,
        outcome: MaskOutcome::CancelDeferred,
    };
    let b = event.clone();
    assert_eq!(event, b);
}

#[test]
fn enrichment_mask_event_debug() {
    let event = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: 1,
        operation_name: "op".to_string(),
        ops_executed: 0,
        outcome: MaskOutcome::CleanRelease,
    };
    let dbg = format!("{:?}", event);
    assert!(dbg.contains("MaskEvent"));
    assert!(dbg.contains("CleanRelease"));
}

#[test]
fn enrichment_mask_event_serde_json_field_names() {
    let event = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: 1,
        operation_name: "op".to_string(),
        ops_executed: 0,
        outcome: MaskOutcome::CleanRelease,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"region_id\""));
    assert!(json.contains("\"mask_id\""));
    assert!(json.contains("\"operation_name\""));
    assert!(json.contains("\"ops_executed\""));
    assert!(json.contains("\"outcome\""));
}

#[test]
fn enrichment_mask_event_ne_different_outcome() {
    let a = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: 1,
        operation_name: "op".to_string(),
        ops_executed: 0,
        outcome: MaskOutcome::CleanRelease,
    };
    let mut b = a.clone();
    b.outcome = MaskOutcome::BoundExceeded;
    assert_ne!(a, b);
}

#[test]
fn enrichment_mask_event_ne_different_mask_id() {
    let a = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: 1,
        operation_name: "op".to_string(),
        ops_executed: 0,
        outcome: MaskOutcome::CleanRelease,
    };
    let mut b = a.clone();
    b.mask_id = 99;
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// CancelMaskContext — lifecycle, edge cases, error paths
// ---------------------------------------------------------------------------

#[test]
fn enrichment_context_debug() {
    let ctx = test_context();
    let dbg = format!("{:?}", ctx);
    assert!(dbg.contains("CancelMaskContext"));
}

#[test]
fn enrichment_context_fresh_event_count_zero() {
    let ctx = test_context();
    assert_eq!(ctx.event_count(), 0);
}

#[test]
fn enrichment_context_fresh_drain_empty() {
    let mut ctx = test_context();
    let events = ctx.drain_events();
    assert!(events.is_empty());
}

#[test]
fn enrichment_context_fresh_not_masked() {
    let ctx = test_context();
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_double_release_fails() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let err = ctx.release_mask(false).unwrap_err();
    assert_eq!(err, MaskError::AlreadyReleased);
}

#[test]
fn enrichment_context_nesting_with_different_ops() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    let err = ctx
        .create_mask(&MaskJustification {
            operation_name: "evidence_append".to_string(),
            expected_ops_hint: 1,
            atomicity_reason: "nested".to_string(),
        })
        .unwrap_err();
    assert_eq!(err, MaskError::NestingDenied);
}

#[test]
fn enrichment_context_create_after_bound_exceeded_no_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    // Mask is still "active" in .active_mask (bound_exceeded=true), so nesting denied
    let err = ctx.create_mask(&checkpoint_just()).unwrap_err();
    assert_eq!(err, MaskError::NestingDenied);
}

#[test]
fn enrichment_context_release_with_cancel_pending_after_bound_exceeded() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    // Even with cancel_pending=true, outcome is BoundExceeded (bound takes priority)
    let outcome = ctx.release_mask(true).unwrap();
    assert_eq!(outcome, MaskOutcome::BoundExceeded);
}

#[test]
fn enrichment_context_mask_id_starts_at_1() {
    let mut ctx = test_context();
    let id = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(id, 1);
}

#[test]
fn enrichment_context_mask_id_monotonic_across_five() {
    let mut ctx = test_context();
    for expected_id in 1..=5 {
        let id = ctx.create_mask(&checkpoint_just()).unwrap();
        assert_eq!(id, expected_id);
        ctx.release_mask(false).unwrap();
    }
}

#[test]
fn enrichment_context_tick_returns_true_within_bounds() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    // checkpoint_write: max_ops=32, so ticks 1..31 should return true
    for i in 0..31 {
        assert!(ctx.tick(), "tick {} should return true", i);
    }
}

#[test]
fn enrichment_context_tick_exact_boundary() {
    // For checkpoint_write with max_ops=32:
    // tick 1..31 -> true, tick 32 -> false (ops_executed reaches 32 == max_ops)
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..31 {
        assert!(ctx.tick());
    }
    assert!(!ctx.tick()); // exactly at boundary
}

#[test]
fn enrichment_context_is_masked_false_after_bound_exceeded() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    assert!(ctx.is_masked());
    for _ in 0..32 {
        ctx.tick();
    }
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_is_masked_false_after_clean_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    assert!(ctx.is_masked());
    ctx.release_mask(false).unwrap();
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_is_masked_false_after_cancel_deferred() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    assert!(ctx.is_masked());
    ctx.release_mask(true).unwrap();
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_events_accumulate_across_masks() {
    let mut ctx = test_context();
    for _ in 0..4 {
        ctx.create_mask(&checkpoint_just()).unwrap();
        ctx.tick();
        ctx.release_mask(false).unwrap();
    }
    assert_eq!(ctx.event_count(), 4);
    let events = ctx.drain_events();
    assert_eq!(events.len(), 4);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.mask_id, (i as u64) + 1);
        assert_eq!(event.outcome, MaskOutcome::CleanRelease);
    }
}

#[test]
fn enrichment_context_drain_then_continue() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();
    let first = ctx.drain_events();
    assert_eq!(first.len(), 1);
    assert_eq!(ctx.event_count(), 0);

    // Continue creating masks after drain
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.release_mask(true).unwrap();
    assert_eq!(ctx.event_count(), 1);
    let second = ctx.drain_events();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].outcome, MaskOutcome::CancelDeferred);
}

#[test]
fn enrichment_context_bound_exceeded_does_not_double_event_on_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..32 {
        ctx.tick();
    }
    // BoundExceeded event already emitted by tick
    assert_eq!(ctx.event_count(), 1);
    ctx.release_mask(false).unwrap();
    // release_mask should NOT add another event
    assert_eq!(ctx.event_count(), 1);
}

#[test]
fn enrichment_context_event_ops_executed_matches_tick_count() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    for _ in 0..17 {
        ctx.tick();
    }
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert_eq!(events[0].ops_executed, 17);
}

#[test]
fn enrichment_context_event_ops_executed_zero_on_immediate_release() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert_eq!(events[0].ops_executed, 0);
}

#[test]
fn enrichment_context_event_trace_region_propagated() {
    let policy = MaskPolicy::standard();
    let mut ctx = CancelMaskContext::new(policy, "my-trace-999", "region-alpha");
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert_eq!(events[0].trace_id, "my-trace-999");
    assert_eq!(events[0].region_id, "region-alpha");
}

// ---------------------------------------------------------------------------
// Lab mode edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lab_mode_set_on_custom_policy() {
    let policy = MaskPolicy {
        default_bounds: MaskBounds::default(),
        operation_bounds: std::collections::BTreeMap::new(),
        lab_mode: true,
    };
    let ctx = CancelMaskContext::new(policy, "t", "r");
    assert!(ctx.is_lab_mode());
}

#[test]
fn enrichment_lab_mode_false_by_default_standard() {
    let ctx = CancelMaskContext::new(MaskPolicy::standard(), "t", "r");
    assert!(!ctx.is_lab_mode());
}

// ---------------------------------------------------------------------------
// Custom policy scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_custom_policy_zero_max_ops_immediate_exceed() {
    let mut bounds = std::collections::BTreeMap::new();
    bounds.insert("zero_op".to_string(), MaskBounds { max_ops: 0 });
    let policy = MaskPolicy {
        default_bounds: MaskBounds::default(),
        operation_bounds: bounds,
        lab_mode: false,
    };
    let mut ctx = CancelMaskContext::new(policy, "t", "r");
    ctx.create_mask(&MaskJustification {
        operation_name: "zero_op".to_string(),
        expected_ops_hint: 0,
        atomicity_reason: "zero".to_string(),
    })
    .unwrap();
    // Very first tick should exceed bound (0 ops allowed)
    assert!(!ctx.tick());
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_custom_policy_many_operations() {
    let mut bounds = std::collections::BTreeMap::new();
    for i in 0..20 {
        bounds.insert(
            format!("op_{}", i),
            MaskBounds {
                max_ops: (i + 1) as u64,
            },
        );
    }
    let policy = MaskPolicy {
        default_bounds: MaskBounds::default(),
        operation_bounds: bounds,
        lab_mode: false,
    };
    assert!(policy.is_allowed("op_0"));
    assert!(policy.is_allowed("op_19"));
    assert!(!policy.is_allowed("op_20"));
    assert_eq!(policy.bounds_for("op_0"), Some(MaskBounds { max_ops: 1 }));
    assert_eq!(policy.bounds_for("op_19"), Some(MaskBounds { max_ops: 20 }));
}

#[test]
fn enrichment_custom_policy_serde_roundtrip() {
    let mut bounds = std::collections::BTreeMap::new();
    bounds.insert("custom_a".to_string(), MaskBounds { max_ops: 10 });
    bounds.insert("custom_b".to_string(), MaskBounds { max_ops: 20 });
    let policy = MaskPolicy {
        default_bounds: MaskBounds { max_ops: 50 },
        operation_bounds: bounds,
        lab_mode: true,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let restored: MaskPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_same_inputs_same_events() {
    let run = || -> Vec<MaskEvent> {
        let mut ctx = test_context();
        // Run 4 mask cycles with different operations
        let ops = [
            "checkpoint_write",
            "evidence_append",
            "two_phase_commit",
            "hash_link_finalize",
        ];
        for op in &ops {
            ctx.create_mask(&MaskJustification {
                operation_name: op.to_string(),
                expected_ops_hint: 1,
                atomicity_reason: "determinism test".to_string(),
            })
            .unwrap();
            ctx.tick();
            ctx.release_mask(false).unwrap();
        }
        ctx.drain_events()
    };
    let run1 = run();
    let run2 = run();
    assert_eq!(run1.len(), run2.len());
    for (a, b) in run1.iter().zip(run2.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn enrichment_determinism_bound_exceeded_events_stable() {
    let run = || -> Vec<MaskEvent> {
        let mut ctx = test_context();
        ctx.create_mask(&MaskJustification {
            operation_name: "hash_link_finalize".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "test".to_string(),
        })
        .unwrap();
        for _ in 0..8 {
            ctx.tick();
        }
        ctx.release_mask(false).unwrap();
        ctx.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_determinism_mixed_outcomes() {
    let run = || -> Vec<MaskEvent> {
        let mut ctx = test_context();
        // 1: clean release
        ctx.create_mask(&checkpoint_just()).unwrap();
        ctx.tick();
        ctx.release_mask(false).unwrap();
        // 2: cancel deferred
        ctx.create_mask(&checkpoint_just()).unwrap();
        ctx.tick();
        ctx.release_mask(true).unwrap();
        // 3: bound exceeded
        ctx.create_mask(&MaskJustification {
            operation_name: "hash_link_finalize".to_string(),
            expected_ops_hint: 4,
            atomicity_reason: "test".to_string(),
        })
        .unwrap();
        for _ in 0..8 {
            ctx.tick();
        }
        ctx.release_mask(false).unwrap();
        ctx.drain_events()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.len(), 3);
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// Serde roundtrips — compound structures
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_event_all_outcomes() {
    for outcome in &[
        MaskOutcome::CleanRelease,
        MaskOutcome::BoundExceeded,
        MaskOutcome::CancelDeferred,
    ] {
        let event = MaskEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            mask_id: 1,
            operation_name: "op".to_string(),
            ops_executed: 10,
            outcome: *outcome,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: MaskEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }
}

#[test]
fn enrichment_serde_event_large_ops_executed() {
    let event = MaskEvent {
        trace_id: "t".to_string(),
        region_id: "r".to_string(),
        mask_id: u64::MAX,
        operation_name: "op".to_string(),
        ops_executed: u64::MAX,
        outcome: MaskOutcome::BoundExceeded,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MaskEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_serde_event_empty_strings() {
    let event = MaskEvent {
        trace_id: String::new(),
        region_id: String::new(),
        mask_id: 0,
        operation_name: String::new(),
        ops_executed: 0,
        outcome: MaskOutcome::CleanRelease,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MaskEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_serde_justification_unicode() {
    let just = MaskJustification {
        operation_name: "unicode_op_\u{1F600}".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "reason_\u{00E9}\u{00FC}".to_string(),
    };
    let json = serde_json::to_string(&just).unwrap();
    let restored: MaskJustification = serde_json::from_str(&json).unwrap();
    assert_eq!(just, restored);
}

#[test]
fn enrichment_serde_policy_lab_mode_true() {
    let mut policy = MaskPolicy::standard();
    policy.lab_mode = true;
    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("true"));
    let restored: MaskPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
    assert!(restored.lab_mode);
}

// ---------------------------------------------------------------------------
// Tick behavior edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tick_exactly_one_under_bound() {
    // evidence_append: max_ops=16
    let mut ctx = test_context();
    ctx.create_mask(&MaskJustification {
        operation_name: "evidence_append".to_string(),
        expected_ops_hint: 15,
        atomicity_reason: "boundary test".to_string(),
    })
    .unwrap();
    for _ in 0..15 {
        assert!(ctx.tick());
    }
    assert!(ctx.is_masked());
    assert!(!ctx.tick()); // 16th exceeds
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_tick_many_after_bound_all_false() {
    let mut ctx = test_context();
    ctx.create_mask(&MaskJustification {
        operation_name: "hash_link_finalize".to_string(),
        expected_ops_hint: 4,
        atomicity_reason: "test".to_string(),
    })
    .unwrap();
    // max_ops=8
    for _ in 0..8 {
        ctx.tick();
    }
    for _ in 0..100 {
        assert!(!ctx.tick());
    }
}

#[test]
fn enrichment_tick_without_mask_repeated() {
    let mut ctx = test_context();
    for _ in 0..10 {
        assert!(!ctx.tick());
    }
    assert_eq!(ctx.event_count(), 0);
}

// ---------------------------------------------------------------------------
// Sequential mask lifecycle patterns
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_four_standard_ops_sequential() {
    let mut ctx = test_context();
    let ops = [
        ("checkpoint_write", 32u64),
        ("evidence_append", 16u64),
        ("two_phase_commit", 64u64),
        ("hash_link_finalize", 8u64),
    ];
    for (i, (op, max_ops)) in ops.iter().enumerate() {
        let id = ctx
            .create_mask(&MaskJustification {
                operation_name: op.to_string(),
                expected_ops_hint: 1,
                atomicity_reason: "sequential test".to_string(),
            })
            .unwrap();
        assert_eq!(id, (i as u64) + 1);
        // Tick exactly max_ops - 1 times (all true), then the max_ops'th tick (false)
        for _ in 0..(max_ops - 1) {
            assert!(ctx.tick());
        }
        assert!(!ctx.tick()); // bound exceeded
        ctx.release_mask(false).unwrap();
    }
    let events = ctx.drain_events();
    assert_eq!(events.len(), 4);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.outcome, MaskOutcome::BoundExceeded);
        assert_eq!(event.ops_executed, ops[i].1);
    }
}

#[test]
fn enrichment_alternating_clean_deferred() {
    let mut ctx = test_context();
    for i in 0..6 {
        ctx.create_mask(&checkpoint_just()).unwrap();
        ctx.tick();
        let cancel = i % 2 == 0;
        ctx.release_mask(cancel).unwrap();
    }
    let events = ctx.drain_events();
    assert_eq!(events.len(), 6);
    for (i, event) in events.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(event.outcome, MaskOutcome::CancelDeferred);
        } else {
            assert_eq!(event.outcome, MaskOutcome::CleanRelease);
        }
    }
}

// ---------------------------------------------------------------------------
// Error path coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_operation_not_allowed_preserves_long_name() {
    let mut ctx = test_context();
    let long_name = "a".repeat(500);
    let err = ctx
        .create_mask(&MaskJustification {
            operation_name: long_name.clone(),
            expected_ops_hint: 1,
            atomicity_reason: "test".to_string(),
        })
        .unwrap_err();
    match err {
        MaskError::OperationNotAllowed { operation_name } => {
            assert_eq!(operation_name, long_name);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn enrichment_error_nesting_denied_does_not_increment_mask_id() {
    let mut ctx = test_context();
    let id1 = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(id1, 1);
    // Nesting attempt should not increment counter
    let _ = ctx.create_mask(&checkpoint_just()).unwrap_err();
    ctx.release_mask(false).unwrap();
    let id2 = ctx.create_mask(&checkpoint_just()).unwrap();
    assert_eq!(id2, 2); // 2, not 3
}

#[test]
fn enrichment_error_already_released_twice() {
    let mut ctx = test_context();
    let err = ctx.release_mask(false).unwrap_err();
    assert_eq!(err, MaskError::AlreadyReleased);
    let err2 = ctx.release_mask(true).unwrap_err();
    assert_eq!(err2, MaskError::AlreadyReleased);
}

#[test]
fn enrichment_error_create_mask_returns_err_not_panic() {
    let mut ctx = test_context();
    let result = ctx.create_mask(&MaskJustification {
        operation_name: "nonexistent".to_string(),
        expected_ops_hint: 1,
        atomicity_reason: "test".to_string(),
    });
    assert!(result.is_err());
}

#[test]
fn enrichment_error_release_mask_returns_err_not_panic() {
    let mut ctx = test_context();
    let result = ctx.release_mask(false);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Context with custom trace/region ids
// ---------------------------------------------------------------------------

#[test]
fn enrichment_context_empty_trace_region() {
    let mut ctx = CancelMaskContext::new(MaskPolicy::standard(), "", "");
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert_eq!(events[0].trace_id, "");
    assert_eq!(events[0].region_id, "");
}

#[test]
fn enrichment_context_long_trace_region() {
    let long_trace = "t".repeat(1000);
    let long_region = "r".repeat(1000);
    let mut ctx = CancelMaskContext::new(
        MaskPolicy::standard(),
        long_trace.as_str(),
        long_region.as_str(),
    );
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert_eq!(events[0].trace_id, long_trace);
    assert_eq!(events[0].region_id, long_region);
}

// ---------------------------------------------------------------------------
// Drain idempotency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_drain_events_idempotent() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let first = ctx.drain_events();
    assert_eq!(first.len(), 1);
    let second = ctx.drain_events();
    assert!(second.is_empty());
    let third = ctx.drain_events();
    assert!(third.is_empty());
}

#[test]
fn enrichment_drain_events_between_masks() {
    let mut ctx = test_context();
    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.release_mask(false).unwrap();
    let batch1 = ctx.drain_events();
    assert_eq!(batch1.len(), 1);

    ctx.create_mask(&checkpoint_just()).unwrap();
    ctx.tick();
    ctx.tick();
    ctx.release_mask(false).unwrap();
    let batch2 = ctx.drain_events();
    assert_eq!(batch2.len(), 1);
    assert_eq!(batch2[0].ops_executed, 2);
    assert_eq!(batch2[0].mask_id, 2);
}

// ---------------------------------------------------------------------------
// serde JSON deserialization error paths
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_mask_bounds_reject_negative() {
    let json = r#"{"max_ops": -1}"#;
    let result: Result<MaskBounds, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_mask_bounds_reject_missing_field() {
    let json = r#"{}"#;
    let result: Result<MaskBounds, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_mask_outcome_reject_unknown() {
    let json = r#""UnknownVariant""#;
    let result: Result<MaskOutcome, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_mask_event_reject_missing_outcome() {
    let json =
        r#"{"trace_id":"t","region_id":"r","mask_id":1,"operation_name":"op","ops_executed":0}"#;
    let result: Result<MaskEvent, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_mask_justification_reject_missing_operation_name() {
    let json = r#"{"expected_ops_hint":1,"atomicity_reason":"r"}"#;
    let result: Result<MaskJustification, _> = serde_json::from_str(json);
    assert!(result.is_err());
}
