//! Enrichment integration tests for `containment_executor`.
//!
//! Covers gaps: State machine transition validity, ContainmentState Display
//! uniqueness, serde roundtrips for all error/state variants, receipt
//! integrity, SandboxPolicy capability checking, executor idempotent
//! registration, resume from suspended state, by_state filtering,
//! forensic snapshot generation during quarantine, and dead-state rejection.

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

use frankenengine_engine::containment_executor::{
    ContainmentContext, ContainmentError, ContainmentExecutor, ContainmentReceipt,
    ContainmentState, SandboxPolicy,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn executor() -> ContainmentExecutor {
    ContainmentExecutor::new()
}

fn default_context() -> ContainmentContext {
    ContainmentContext::default()
}

fn context_with_decision(decision_id: &str) -> ContainmentContext {
    let mut ctx = ContainmentContext::default();
    ctx.decision_id = decision_id.to_string();
    ctx
}

// ===========================================================================
// ContainmentState classification
// ===========================================================================

#[test]
fn enrichment_running_is_alive() {
    assert!(ContainmentState::Running.is_alive());
    assert!(!ContainmentState::Running.is_dead());
}

#[test]
fn enrichment_challenged_is_alive() {
    assert!(ContainmentState::Challenged.is_alive());
}

#[test]
fn enrichment_sandboxed_is_alive() {
    assert!(ContainmentState::Sandboxed.is_alive());
}

#[test]
fn enrichment_suspended_not_alive_not_dead() {
    // Suspended is a middle state
    assert!(!ContainmentState::Suspended.is_alive());
    assert!(!ContainmentState::Suspended.is_dead());
}

#[test]
fn enrichment_terminated_is_dead() {
    assert!(ContainmentState::Terminated.is_dead());
    assert!(!ContainmentState::Terminated.is_alive());
}

#[test]
fn enrichment_quarantined_is_dead() {
    assert!(ContainmentState::Quarantined.is_dead());
    assert!(!ContainmentState::Quarantined.is_alive());
}

// ===========================================================================
// ContainmentState Display uniqueness
// ===========================================================================

#[test]
fn enrichment_containment_state_display_all_unique() {
    let all = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

// ===========================================================================
// ContainmentState serde roundtrip
// ===========================================================================

#[test]
fn enrichment_containment_state_serde_roundtrip() {
    let all = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    for state in &all {
        let json = serde_json::to_string(state).unwrap();
        let back: ContainmentState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ===========================================================================
// ContainmentError Display and serde
// ===========================================================================

#[test]
fn enrichment_error_display_not_found() {
    let err = ContainmentError::ExtensionNotFound {
        extension_id: "ext1".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("ext1"));
}

#[test]
fn enrichment_error_display_already_contained() {
    let err = ContainmentError::AlreadyContained {
        extension_id: "ext1".to_string(),
        current_state: ContainmentState::Sandboxed,
    };
    let display = err.to_string();
    assert!(display.contains("ext1"));
}

#[test]
fn enrichment_error_display_invalid_transition() {
    let err = ContainmentError::InvalidTransition {
        from: ContainmentState::Terminated,
        action: ContainmentAction::Allow,
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let errors = [
        ContainmentError::ExtensionNotFound {
            extension_id: "e1".to_string(),
        },
        ContainmentError::ChallengeTimeout {
            extension_id: "e2".to_string(),
        },
        ContainmentError::GracePeriodExpired {
            extension_id: "e3".to_string(),
            elapsed_ns: 5_000_000_000,
        },
        ContainmentError::Internal {
            detail: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ContainmentError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// SandboxPolicy
// ===========================================================================

#[test]
fn enrichment_default_sandbox_policy_allows_fs_read() {
    let policy = SandboxPolicy::default();
    assert!(policy.is_allowed("fs-read"));
}

#[test]
fn enrichment_default_sandbox_policy_denies_network() {
    let policy = SandboxPolicy::default();
    assert!(!policy.allow_network);
}

#[test]
fn enrichment_default_sandbox_policy_denies_fs_write() {
    let policy = SandboxPolicy::default();
    assert!(!policy.allow_fs_write);
}

#[test]
fn enrichment_default_sandbox_policy_denies_process_spawn() {
    let policy = SandboxPolicy::default();
    assert!(!policy.allow_process_spawn);
}

#[test]
fn enrichment_custom_sandbox_policy_allows_custom_capability() {
    let policy = SandboxPolicy {
        allowed_capabilities: vec!["custom-cap".to_string()],
        allow_network: false,
        allow_fs_write: false,
        allow_process_spawn: false,
        max_memory_bytes: 1024 * 1024,
    };
    assert!(policy.is_allowed("custom-cap"));
    assert!(!policy.is_allowed("other-cap"));
}

#[test]
fn enrichment_sandbox_policy_serde_roundtrip() {
    let policy = SandboxPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.allow_network, back.allow_network);
    assert_eq!(policy.allow_fs_write, back.allow_fs_write);
}

// ===========================================================================
// ContainmentExecutor: registration
// ===========================================================================

#[test]
fn enrichment_register_and_check_state() {
    let mut exec = executor();
    exec.register("ext1");
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Running));
}

#[test]
fn enrichment_register_idempotent() {
    let mut exec = executor();
    exec.register("ext1");
    exec.register("ext1"); // Should not error
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Running));
}

#[test]
fn enrichment_unknown_extension_state_is_none() {
    let exec = executor();
    assert_eq!(exec.state("nonexistent"), None);
}

#[test]
fn enrichment_extension_count() {
    let mut exec = executor();
    exec.register("ext1");
    exec.register("ext2");
    exec.register("ext3");
    assert_eq!(exec.extension_count(), 3);
}

// ===========================================================================
// ContainmentExecutor: state transitions
// ===========================================================================

#[test]
fn enrichment_challenge_from_running() {
    let mut exec = executor();
    exec.register("ext1");
    let result = exec.execute(ContainmentAction::Challenge, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Challenged));
}

#[test]
fn enrichment_sandbox_from_running() {
    let mut exec = executor();
    exec.register("ext1");
    let result = exec.execute(ContainmentAction::Sandbox, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Sandboxed));
}

#[test]
fn enrichment_suspend_from_running() {
    let mut exec = executor();
    exec.register("ext1");
    let result = exec.execute(ContainmentAction::Suspend, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Suspended));
}

#[test]
fn enrichment_terminate_from_running() {
    let mut exec = executor();
    exec.register("ext1");
    let result = exec.execute(ContainmentAction::Terminate, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Terminated));
}

#[test]
fn enrichment_quarantine_from_running() {
    let mut exec = executor();
    exec.register("ext1");
    let result = exec.execute(ContainmentAction::Quarantine, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Quarantined));
}

#[test]
fn enrichment_allow_from_challenged() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Challenge, "ext1", &default_context())
        .unwrap();
    let result = exec.execute(ContainmentAction::Allow, "ext1", &default_context());
    assert!(result.is_ok());
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Running));
}

// ===========================================================================
// ContainmentExecutor: dead state rejection
// ===========================================================================

#[test]
fn enrichment_cannot_act_on_terminated() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Terminate, "ext1", &default_context())
        .unwrap();
    let result = exec.execute(ContainmentAction::Allow, "ext1", &default_context());
    assert!(result.is_err());
}

#[test]
fn enrichment_cannot_act_on_quarantined() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Quarantine, "ext1", &default_context())
        .unwrap();
    let result = exec.execute(ContainmentAction::Sandbox, "ext1", &default_context());
    assert!(result.is_err());
}

// ===========================================================================
// ContainmentExecutor: unknown extension
// ===========================================================================

#[test]
fn enrichment_execute_on_unknown_extension_fails() {
    let mut exec = executor();
    let result = exec.execute(ContainmentAction::Allow, "unknown", &default_context());
    assert!(result.is_err());
    match result.unwrap_err() {
        ContainmentError::ExtensionNotFound { extension_id } => {
            assert_eq!(extension_id, "unknown");
        }
        other => panic!("Expected ExtensionNotFound, got {other:?}"),
    }
}

// ===========================================================================
// ContainmentExecutor: receipt properties
// ===========================================================================

#[test]
fn enrichment_receipt_has_correct_action() {
    let mut exec = executor();
    exec.register("ext1");
    let receipt = exec
        .execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    assert_eq!(receipt.action, ContainmentAction::Sandbox);
}

#[test]
fn enrichment_receipt_records_state_transition() {
    let mut exec = executor();
    exec.register("ext1");
    let receipt = exec
        .execute(ContainmentAction::Challenge, "ext1", &default_context())
        .unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Running);
    assert_eq!(receipt.new_state, ContainmentState::Challenged);
}

#[test]
fn enrichment_receipt_integrity_check() {
    let mut exec = executor();
    exec.register("ext1");
    let receipt = exec
        .execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    assert!(receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_serde_produces_nonempty_json() {
    let mut exec = executor();
    exec.register("ext1");
    let receipt = exec
        .execute(ContainmentAction::Suspend, "ext1", &default_context())
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(
        !json.is_empty(),
        "receipt JSON serialization should be nonempty"
    );
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let mut exec = executor();
    exec.register("ext1");
    let receipt = exec
        .execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.action, back.action);
    assert_eq!(receipt.target_extension_id, back.target_extension_id);
}

// ===========================================================================
// ContainmentExecutor: receipts history
// ===========================================================================

#[test]
fn enrichment_receipts_empty_initially() {
    let mut exec = executor();
    exec.register("ext1");
    assert!(exec.receipts("ext1").is_empty());
}

#[test]
fn enrichment_receipts_accumulate() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Challenge, "ext1", &default_context())
        .unwrap();
    exec.execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    assert_eq!(exec.receipts("ext1").len(), 2);
}

// ===========================================================================
// ContainmentExecutor: by_state filtering
// ===========================================================================

#[test]
fn enrichment_by_state_running() {
    let mut exec = executor();
    exec.register("ext1");
    exec.register("ext2");
    exec.execute(ContainmentAction::Suspend, "ext2", &default_context())
        .unwrap();
    let running = exec.by_state(ContainmentState::Running);
    assert_eq!(running.len(), 1);
    assert!(running.contains(&"ext1"));
}

#[test]
fn enrichment_by_state_empty_when_no_match() {
    let mut exec = executor();
    exec.register("ext1");
    let quarantined = exec.by_state(ContainmentState::Quarantined);
    assert!(quarantined.is_empty());
}

// ===========================================================================
// ContainmentExecutor: resume
// ===========================================================================

#[test]
fn enrichment_resume_from_suspended() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Suspend, "ext1", &default_context())
        .unwrap();
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Suspended));
    let result = exec.resume("ext1", &default_context());
    assert!(result.is_ok());
    let state = exec.state("ext1").unwrap();
    // Should return to Running or Sandboxed
    assert!(state == ContainmentState::Running || state == ContainmentState::Sandboxed);
}

// ===========================================================================
// ContainmentExecutor: forensic snapshot
// ===========================================================================

#[test]
fn enrichment_forensic_snapshot_after_quarantine() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Quarantine, "ext1", &default_context())
        .unwrap();
    let snap = exec.forensic_snapshot("ext1");
    assert!(snap.is_some());
}

#[test]
fn enrichment_no_forensic_snapshot_for_running() {
    let mut exec = executor();
    exec.register("ext1");
    let snap = exec.forensic_snapshot("ext1");
    assert!(snap.is_none());
}

// ===========================================================================
// ContainmentExecutor: sandbox policy retrieval
// ===========================================================================

#[test]
fn enrichment_sandbox_policy_after_sandboxing() {
    let mut exec = executor();
    exec.register("ext1");
    exec.execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    let policy = exec.sandbox_policy("ext1");
    assert!(policy.is_some());
}

#[test]
fn enrichment_no_sandbox_policy_for_running() {
    let mut exec = executor();
    exec.register("ext1");
    let policy = exec.sandbox_policy("ext1");
    assert!(policy.is_none());
}

// ===========================================================================
// ContainmentContext defaults
// ===========================================================================

#[test]
fn enrichment_context_default_epoch_is_genesis() {
    let ctx = ContainmentContext::default();
    assert_eq!(ctx.epoch, SecurityEpoch::from_raw(0));
}

#[test]
fn enrichment_context_serde_roundtrip() {
    let ctx = context_with_decision("dec-001");
    let json = serde_json::to_string(&ctx).unwrap();
    let back: ContainmentContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx.decision_id, back.decision_id);
}

// ===========================================================================
// Multiple extensions lifecycle
// ===========================================================================

#[test]
fn enrichment_multiple_extensions_independent_states() {
    let mut exec = executor();
    exec.register("ext1");
    exec.register("ext2");
    exec.register("ext3");
    exec.execute(ContainmentAction::Sandbox, "ext1", &default_context())
        .unwrap();
    exec.execute(ContainmentAction::Terminate, "ext2", &default_context())
        .unwrap();
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Sandboxed));
    assert_eq!(exec.state("ext2"), Some(ContainmentState::Terminated));
    assert_eq!(exec.state("ext3"), Some(ContainmentState::Running));
}

#[test]
fn enrichment_escalation_chain_running_to_quarantine() {
    let mut exec = executor();
    exec.register("ext1");
    let ctx = default_context();
    exec.execute(ContainmentAction::Challenge, "ext1", &ctx)
        .unwrap();
    exec.execute(ContainmentAction::Sandbox, "ext1", &ctx)
        .unwrap();
    exec.execute(ContainmentAction::Suspend, "ext1", &ctx)
        .unwrap();
    exec.execute(ContainmentAction::Quarantine, "ext1", &ctx)
        .unwrap();
    assert_eq!(exec.state("ext1"), Some(ContainmentState::Quarantined));
    assert!(exec.state("ext1").unwrap().is_dead());
    assert_eq!(exec.receipts("ext1").len(), 4);
}
