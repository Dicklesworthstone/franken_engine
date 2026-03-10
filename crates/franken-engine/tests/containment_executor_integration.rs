//! Integration tests for the containment_executor module.

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

use frankenengine_engine::containment_executor::*;
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_context() -> ContainmentContext {
    ContainmentContext {
        decision_id: "dec-001".to_string(),
        timestamp_ns: 1_000_000,
        epoch: SecurityEpoch::GENESIS,
        evidence_refs: vec!["ev-001".to_string()],
        ..ContainmentContext::default()
    }
}

fn setup_executor() -> ContainmentExecutor {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext-001");
    executor.register("ext-002");
    executor
}

// ---------------------------------------------------------------------------
// ContainmentState lifecycle
// ---------------------------------------------------------------------------

#[test]
fn state_display_all_variants() {
    assert_eq!(ContainmentState::Running.to_string(), "running");
    assert_eq!(ContainmentState::Challenged.to_string(), "challenged");
    assert_eq!(ContainmentState::Sandboxed.to_string(), "sandboxed");
    assert_eq!(ContainmentState::Suspended.to_string(), "suspended");
    assert_eq!(ContainmentState::Terminated.to_string(), "terminated");
    assert_eq!(ContainmentState::Quarantined.to_string(), "quarantined");
}

#[test]
fn alive_states() {
    assert!(ContainmentState::Running.is_alive());
    assert!(ContainmentState::Challenged.is_alive());
    assert!(ContainmentState::Sandboxed.is_alive());
    assert!(!ContainmentState::Suspended.is_alive());
    assert!(!ContainmentState::Terminated.is_alive());
    assert!(!ContainmentState::Quarantined.is_alive());
}

#[test]
fn dead_states() {
    assert!(!ContainmentState::Running.is_dead());
    assert!(!ContainmentState::Challenged.is_dead());
    assert!(!ContainmentState::Sandboxed.is_dead());
    assert!(!ContainmentState::Suspended.is_dead());
    assert!(ContainmentState::Terminated.is_dead());
    assert!(ContainmentState::Quarantined.is_dead());
}

// ---------------------------------------------------------------------------
// Registration and state queries
// ---------------------------------------------------------------------------

#[test]
fn register_sets_running_state() {
    let executor = setup_executor();
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    assert_eq!(executor.state("ext-002"), Some(ContainmentState::Running));
}

#[test]
fn unknown_extension_returns_none() {
    let executor = setup_executor();
    assert_eq!(executor.state("ext-999"), None);
}

#[test]
fn extension_count_tracks_registrations() {
    let mut executor = ContainmentExecutor::new();
    assert_eq!(executor.extension_count(), 0);
    executor.register("ext-001");
    assert_eq!(executor.extension_count(), 1);
    executor.register("ext-002");
    assert_eq!(executor.extension_count(), 2);
}

#[test]
fn duplicate_registration_is_idempotent() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext-001");
    executor.register("ext-001");
    assert_eq!(executor.extension_count(), 1);
}

#[test]
fn by_state_filters_correctly() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let running = executor.by_state(ContainmentState::Running);
    let sandboxed = executor.by_state(ContainmentState::Sandboxed);
    assert_eq!(running.len(), 1);
    assert_eq!(sandboxed.len(), 1);
    assert!(running.contains(&"ext-002"));
    assert!(sandboxed.contains(&"ext-001"));
}

// ---------------------------------------------------------------------------
// Containment action execution
// ---------------------------------------------------------------------------

#[test]
fn challenge_from_running() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Running);
    assert_eq!(receipt.new_state, ContainmentState::Challenged);
    assert!(receipt.success);
    assert_eq!(
        executor.state("ext-001"),
        Some(ContainmentState::Challenged)
    );
}

#[test]
fn sandbox_from_running() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Sandboxed);
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Sandboxed));
}

#[test]
fn suspend_from_running() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Suspend, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Suspended);
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Suspended));
}

#[test]
fn terminate_from_running() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Terminate, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Terminated);
    assert!(executor.state("ext-001").unwrap().is_dead());
}

#[test]
fn quarantine_from_running() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Quarantined);
    assert!(executor.state("ext-001").unwrap().is_dead());
}

// ---------------------------------------------------------------------------
// Multi-step transitions
// ---------------------------------------------------------------------------

#[test]
fn challenge_then_sandbox() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Challenged);
    assert_eq!(receipt.new_state, ContainmentState::Sandboxed);
}

#[test]
fn sandbox_then_terminate() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Terminate, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Sandboxed);
    assert_eq!(receipt.new_state, ContainmentState::Terminated);
}

#[test]
fn suspend_then_quarantine() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext-001", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Suspended);
    assert_eq!(receipt.new_state, ContainmentState::Quarantined);
}

// ---------------------------------------------------------------------------
// Invalid transitions
// ---------------------------------------------------------------------------

#[test]
fn cannot_transition_from_terminated() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Terminate, "ext-001", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Sandbox, "ext-001", &ctx);
    assert!(result.is_err());
    if let Err(ContainmentError::InvalidTransition { from, action }) = result {
        assert_eq!(from, ContainmentState::Terminated);
        assert_eq!(action, ContainmentAction::Sandbox);
    }
}

#[test]
fn cannot_transition_from_quarantined() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Suspend, "ext-001", &ctx);
    assert!(result.is_err());
}

#[test]
fn sandboxed_cannot_challenge() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Challenge, "ext-001", &ctx);
    assert!(result.is_err());
}

#[test]
fn extension_not_found_error() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let result = executor.execute(ContainmentAction::Sandbox, "ext-999", &ctx);
    assert!(result.is_err());
    if let Err(ContainmentError::ExtensionNotFound { extension_id }) = result {
        assert_eq!(extension_id, "ext-999");
    }
}

// ---------------------------------------------------------------------------
// Resume from suspended
// ---------------------------------------------------------------------------

#[test]
fn resume_from_suspended() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext-001", &ctx)
        .unwrap();
    let receipt = executor.resume("ext-001", &ctx).unwrap();
    assert_eq!(receipt.previous_state, ContainmentState::Suspended);
    assert_eq!(receipt.new_state, ContainmentState::Running);
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
}

#[test]
fn resume_from_non_suspended_fails() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let result = executor.resume("ext-001", &ctx);
    assert!(result.is_err()); // Running -> cannot resume
}

#[test]
fn resume_unknown_extension_fails() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let result = executor.resume("ext-999", &ctx);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Receipt integrity
// ---------------------------------------------------------------------------

#[test]
fn receipt_has_valid_integrity_hash() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    assert!(receipt.verify_integrity());
}

#[test]
fn receipt_has_unique_id() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let r1 = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    let r2 = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn receipt_records_evidence_refs() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.evidence_refs, vec!["ev-001".to_string()]);
}

#[test]
fn receipt_records_epoch() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn receipt_metadata_includes_decision_id() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(receipt.metadata.get("decision_id").unwrap(), "dec-001");
}

// ---------------------------------------------------------------------------
// Receipts history
// ---------------------------------------------------------------------------

#[test]
fn receipts_accumulate() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let receipts = executor.receipts("ext-001");
    assert_eq!(receipts.len(), 2);
}

#[test]
fn receipts_empty_for_untouched_extension() {
    let executor = setup_executor();
    let receipts = executor.receipts("ext-001");
    assert!(receipts.is_empty());
}

#[test]
fn receipts_empty_for_unknown_extension() {
    let executor = setup_executor();
    let receipts = executor.receipts("ext-999");
    assert!(receipts.is_empty());
}

// ---------------------------------------------------------------------------
// Sandbox policy
// ---------------------------------------------------------------------------

#[test]
fn sandbox_applies_policy() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let policy = executor.sandbox_policy("ext-001").unwrap();
    assert!(policy.is_allowed("fs-read"));
    assert!(!policy.allow_network);
}

#[test]
fn sandbox_policy_none_for_non_sandboxed() {
    let executor = setup_executor();
    assert!(executor.sandbox_policy("ext-001").is_none());
}

#[test]
fn sandbox_policy_custom() {
    let mut executor = setup_executor();
    let mut ctx = test_context();
    ctx.sandbox_policy = SandboxPolicy {
        allowed_capabilities: vec!["fs-read".to_string(), "net-limited".to_string()],
        allow_network: true,
        allow_fs_write: false,
        allow_process_spawn: false,
        max_memory_bytes: 1024,
    };
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let policy = executor.sandbox_policy("ext-001").unwrap();
    assert!(policy.is_allowed("net-limited"));
    assert!(policy.allow_network);
    assert_eq!(policy.max_memory_bytes, 1024);
}

// ---------------------------------------------------------------------------
// Forensic snapshot
// ---------------------------------------------------------------------------

#[test]
fn quarantine_creates_forensic_snapshot() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    let snapshot = executor.forensic_snapshot("ext-001").unwrap();
    assert_eq!(snapshot.snapshot_ns, ctx.timestamp_ns);
}

#[test]
fn no_snapshot_for_non_quarantined() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Terminate, "ext-001", &ctx)
        .unwrap();
    assert!(executor.forensic_snapshot("ext-001").is_none());
}

// ---------------------------------------------------------------------------
// ContainmentError display
// ---------------------------------------------------------------------------

#[test]
fn error_display_extension_not_found() {
    let e = ContainmentError::ExtensionNotFound {
        extension_id: "ext-bad".to_string(),
    };
    assert!(e.to_string().contains("ext-bad"));
}

#[test]
fn error_display_already_contained() {
    let e = ContainmentError::AlreadyContained {
        extension_id: "ext-001".to_string(),
        current_state: ContainmentState::Sandboxed,
    };
    assert!(e.to_string().contains("sandboxed"));
}

#[test]
fn error_display_invalid_transition() {
    let e = ContainmentError::InvalidTransition {
        from: ContainmentState::Terminated,
        action: ContainmentAction::Sandbox,
    };
    let msg = e.to_string();
    assert!(msg.contains("terminated") || msg.contains("sandbox"));
}

#[test]
fn error_display_grace_period_expired() {
    let e = ContainmentError::GracePeriodExpired {
        extension_id: "ext-001".to_string(),
        elapsed_ns: 5_000_000_000,
    };
    assert!(e.to_string().contains("grace period"));
}

#[test]
fn error_display_internal() {
    let e = ContainmentError::Internal {
        detail: "test".to_string(),
    };
    assert!(e.to_string().contains("internal error"));
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_containment_state() {
    for state in [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ] {
        let s = serde_json::to_string(&state).unwrap();
        let back: ContainmentState = serde_json::from_str(&s).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn serde_roundtrip_sandbox_policy() {
    let policy = SandboxPolicy::default();
    let s = serde_json::to_string(&policy).unwrap();
    let back: SandboxPolicy = serde_json::from_str(&s).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn serde_roundtrip_containment_receipt() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    let s = serde_json::to_string(&receipt).unwrap();
    let back: ContainmentReceipt = serde_json::from_str(&s).unwrap();
    assert_eq!(receipt, back);
    assert!(back.verify_integrity());
}

#[test]
fn serde_roundtrip_forensic_snapshot() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    let snapshot = executor.forensic_snapshot("ext-001").unwrap().clone();
    let s = serde_json::to_string(&snapshot).unwrap();
    let back: ForensicSnapshot = serde_json::from_str(&s).unwrap();
    assert_eq!(snapshot, back);
}

#[test]
fn serde_roundtrip_containment_error() {
    let errors = vec![
        ContainmentError::ExtensionNotFound {
            extension_id: "ext-001".to_string(),
        },
        ContainmentError::AlreadyContained {
            extension_id: "ext-001".to_string(),
            current_state: ContainmentState::Sandboxed,
        },
        ContainmentError::InvalidTransition {
            from: ContainmentState::Terminated,
            action: ContainmentAction::Sandbox,
        },
        ContainmentError::GracePeriodExpired {
            extension_id: "ext-001".to_string(),
            elapsed_ns: 5_000,
        },
        ContainmentError::ChallengeTimeout {
            extension_id: "ext-001".to_string(),
        },
        ContainmentError::Internal {
            detail: "test".to_string(),
        },
    ];
    for error in errors {
        let s = serde_json::to_string(&error).unwrap();
        let back: ContainmentError = serde_json::from_str(&s).unwrap();
        assert_eq!(error, back);
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_receipt_hash_for_same_inputs() {
    let make_receipt = || {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap()
    };
    let r1 = make_receipt();
    let r2 = make_receipt();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn independent_extensions_do_not_interfere() {
    let mut executor = setup_executor();
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    assert_eq!(
        executor.state("ext-001"),
        Some(ContainmentState::Quarantined)
    );
    assert_eq!(executor.state("ext-002"), Some(ContainmentState::Running));
}

// ---------------------------------------------------------------------------
// Full lifecycle scenario
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_challenge_sandbox_suspend_terminate() {
    let mut executor = setup_executor();
    let ctx = test_context();

    // Running -> Challenged
    executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    assert_eq!(
        executor.state("ext-001"),
        Some(ContainmentState::Challenged)
    );

    // Challenged -> Sandboxed
    executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Sandboxed));

    // Sandboxed -> Suspended
    executor
        .execute(ContainmentAction::Suspend, "ext-001", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Suspended));

    // Suspended -> Terminated
    executor
        .execute(ContainmentAction::Terminate, "ext-001", &ctx)
        .unwrap();
    assert_eq!(
        executor.state("ext-001"),
        Some(ContainmentState::Terminated)
    );

    // 4 receipts total
    assert_eq!(executor.receipts("ext-001").len(), 4);
}

#[test]
fn full_lifecycle_suspend_resume_quarantine() {
    let mut executor = setup_executor();
    let ctx = test_context();

    executor
        .execute(ContainmentAction::Suspend, "ext-001", &ctx)
        .unwrap();
    executor.resume("ext-001", &ctx).unwrap();
    assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));

    executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    assert!(executor.state("ext-001").unwrap().is_dead());
    assert!(executor.forensic_snapshot("ext-001").is_some());

    assert_eq!(executor.receipts("ext-001").len(), 3);
}
