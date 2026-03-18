//! Enrichment integration tests for `cancel_mask`.
//!
//! Covers gaps: MaskOutcome Display uniqueness, MaskError Display uniqueness,
//! MaskPolicy standard operations, MaskBounds defaults, CancelMaskContext
//! lifecycle (create/tick/release), nesting denial, bound enforcement,
//! serde roundtrips, event tracking, and lab mode behavior.

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

use frankenengine_engine::cancel_mask::{
    CancelMaskContext, MaskBounds, MaskError, MaskEvent, MaskJustification, MaskOutcome, MaskPolicy,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn standard_policy() -> MaskPolicy {
    MaskPolicy::standard()
}

fn justification(op: &str) -> MaskJustification {
    MaskJustification {
        operation_name: op.to_string(),
        expected_ops_hint: 10,
        atomicity_reason: "test atomicity".to_string(),
    }
}

fn default_context() -> CancelMaskContext {
    CancelMaskContext::new(standard_policy(), "trace-001", "region-001")
}

// ===========================================================================
// MaskOutcome Display uniqueness
// ===========================================================================

#[test]
fn enrichment_mask_outcome_display_all_unique() {
    let all = [
        MaskOutcome::CleanRelease,
        MaskOutcome::BoundExceeded,
        MaskOutcome::CancelDeferred,
    ];
    let displays: BTreeSet<String> = all.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_mask_outcome_serde_roundtrip() {
    let all = [
        MaskOutcome::CleanRelease,
        MaskOutcome::BoundExceeded,
        MaskOutcome::CancelDeferred,
    ];
    for outcome in &all {
        let json = serde_json::to_string(outcome).unwrap();
        let back: MaskOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

// ===========================================================================
// MaskError Display uniqueness
// ===========================================================================

#[test]
fn enrichment_mask_error_display_all_unique() {
    let all = [
        MaskError::NestingDenied,
        MaskError::OperationNotAllowed {
            operation_name: "bad_op".to_string(),
        },
        MaskError::AlreadyReleased,
    ];
    let displays: BTreeSet<String> = all.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_mask_error_serde_roundtrip() {
    let errors = [
        MaskError::NestingDenied,
        MaskError::OperationNotAllowed {
            operation_name: "unknown".to_string(),
        },
        MaskError::AlreadyReleased,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: MaskError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// MaskPolicy: standard operations
// ===========================================================================

#[test]
fn enrichment_standard_policy_allows_checkpoint_write() {
    let policy = standard_policy();
    assert!(policy.is_allowed("checkpoint_write"));
}

#[test]
fn enrichment_standard_policy_allows_evidence_append() {
    let policy = standard_policy();
    assert!(policy.is_allowed("evidence_append"));
}

#[test]
fn enrichment_standard_policy_allows_two_phase_commit() {
    let policy = standard_policy();
    assert!(policy.is_allowed("two_phase_commit"));
}

#[test]
fn enrichment_standard_policy_allows_hash_link_finalize() {
    let policy = standard_policy();
    assert!(policy.is_allowed("hash_link_finalize"));
}

#[test]
fn enrichment_standard_policy_denies_unknown_operation() {
    let policy = standard_policy();
    assert!(!policy.is_allowed("unknown_operation"));
}

#[test]
fn enrichment_standard_policy_has_bounds() {
    let policy = standard_policy();
    let bounds = policy.bounds_for("checkpoint_write");
    assert!(bounds.is_some());
    assert!(bounds.unwrap().max_ops > 0);
}

#[test]
fn enrichment_standard_policy_no_bounds_for_unknown() {
    let policy = standard_policy();
    assert!(policy.bounds_for("nonexistent").is_none());
}

// ===========================================================================
// MaskBounds
// ===========================================================================

#[test]
fn enrichment_mask_bounds_default_positive() {
    let bounds = MaskBounds::default();
    assert!(bounds.max_ops > 0);
}

#[test]
fn enrichment_mask_bounds_serde_roundtrip() {
    let bounds = MaskBounds { max_ops: 128 };
    let json = serde_json::to_string(&bounds).unwrap();
    let back: MaskBounds = serde_json::from_str(&json).unwrap();
    assert_eq!(bounds.max_ops, back.max_ops);
}

// ===========================================================================
// CancelMaskContext: basic lifecycle
// ===========================================================================

#[test]
fn enrichment_context_not_masked_initially() {
    let ctx = default_context();
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_create_mask_sets_masked() {
    let mut ctx = default_context();
    let mask_id = ctx.create_mask(&justification("checkpoint_write")).unwrap();
    // mask_id is u64, always valid (>= 0); just verify create succeeded
    let _ = mask_id;
    assert!(ctx.is_masked());
}

#[test]
fn enrichment_context_tick_within_bounds() {
    let mut ctx = default_context();
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    let within = ctx.tick();
    assert!(within, "First tick should be within bounds");
}

#[test]
fn enrichment_context_release_mask_clean() {
    let mut ctx = default_context();
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    ctx.tick();
    let outcome = ctx.release_mask(false).unwrap();
    assert_eq!(outcome, MaskOutcome::CleanRelease);
    assert!(!ctx.is_masked());
}

#[test]
fn enrichment_context_release_mask_with_cancel_pending() {
    let mut ctx = default_context();
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    ctx.tick();
    let outcome = ctx.release_mask(true).unwrap();
    assert_eq!(outcome, MaskOutcome::CancelDeferred);
}

// ===========================================================================
// CancelMaskContext: nesting denial
// ===========================================================================

#[test]
fn enrichment_context_double_create_denied() {
    let mut ctx = default_context();
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    let result = ctx.create_mask(&justification("evidence_append"));
    assert!(result.is_err());
    match result.unwrap_err() {
        MaskError::NestingDenied => {}
        other => panic!("Expected NestingDenied, got {other}"),
    }
}

// ===========================================================================
// CancelMaskContext: unknown operation denial
// ===========================================================================

#[test]
fn enrichment_context_create_mask_unknown_op_denied() {
    let mut ctx = default_context();
    let result = ctx.create_mask(&justification("unknown_op"));
    assert!(result.is_err());
}

// ===========================================================================
// CancelMaskContext: release without mask
// ===========================================================================

#[test]
fn enrichment_context_release_without_mask_fails() {
    let mut ctx = default_context();
    let result = ctx.release_mask(false);
    assert!(result.is_err());
}

// ===========================================================================
// CancelMaskContext: bound enforcement
// ===========================================================================

#[test]
fn enrichment_context_tick_beyond_bound_returns_false() {
    let mut policy = standard_policy();
    // Override bounds to very small
    policy
        .operation_bounds
        .insert("checkpoint_write".to_string(), MaskBounds { max_ops: 3 });
    let mut ctx = CancelMaskContext::new(policy, "trace-002", "region-002");
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    assert!(ctx.tick()); // 1
    assert!(ctx.tick()); // 2
    assert!(ctx.tick()); // 3
    assert!(!ctx.tick()); // 4 — exceeded
}

// ===========================================================================
// CancelMaskContext: events
// ===========================================================================

#[test]
fn enrichment_context_events_empty_initially() {
    let ctx = default_context();
    assert_eq!(ctx.event_count(), 0);
}

#[test]
fn enrichment_context_events_after_lifecycle() {
    let mut ctx = default_context();
    ctx.create_mask(&justification("checkpoint_write")).unwrap();
    ctx.tick();
    ctx.release_mask(false).unwrap();
    let events = ctx.drain_events();
    assert!(!events.is_empty());
}

#[test]
fn enrichment_mask_event_serde_roundtrip() {
    let event = MaskEvent {
        trace_id: "trace-001".to_string(),
        region_id: "region-001".to_string(),
        mask_id: 1,
        operation_name: "checkpoint_write".to_string(),
        ops_executed: 5,
        outcome: MaskOutcome::CleanRelease,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: MaskEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.trace_id, back.trace_id);
    assert_eq!(event.outcome, back.outcome);
}

// ===========================================================================
// CancelMaskContext: lab mode
// ===========================================================================

#[test]
fn enrichment_standard_policy_not_lab_mode() {
    let ctx = default_context();
    assert!(!ctx.is_lab_mode());
}

#[test]
fn enrichment_lab_mode_policy() {
    let mut policy = standard_policy();
    policy.lab_mode = true;
    let ctx = CancelMaskContext::new(policy, "trace-lab", "region-lab");
    assert!(ctx.is_lab_mode());
}

// ===========================================================================
// MaskJustification serde roundtrip
// ===========================================================================

#[test]
fn enrichment_justification_serde_roundtrip() {
    let j = justification("checkpoint_write");
    let json = serde_json::to_string(&j).unwrap();
    let back: MaskJustification = serde_json::from_str(&json).unwrap();
    assert_eq!(j.operation_name, back.operation_name);
}

// ===========================================================================
// MaskPolicy serde roundtrip
// ===========================================================================

#[test]
fn enrichment_policy_serde_roundtrip() {
    let policy = standard_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: MaskPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.lab_mode, back.lab_mode);
}
