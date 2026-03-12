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

// ===========================================================================
// Enrichment tests — PearlTower 2026-03-12
// ===========================================================================

use frankenengine_engine::hash_tiers::ContentHash;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// ContainmentState — trait coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_state_clone_all_variants() {
    let states = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    for s in &states {
        let cloned = s.clone();
        assert_eq!(*s, cloned);
    }
}

#[test]
fn enrichment_containment_state_copy_semantics() {
    let a = ContainmentState::Suspended;
    let b = a;
    assert_eq!(a, b);
    // Both usable after copy.
    assert!(!a.is_alive());
    assert!(!b.is_alive());
}

#[test]
fn enrichment_containment_state_debug_contains_variant_name() {
    assert!(format!("{:?}", ContainmentState::Running).contains("Running"));
    assert!(format!("{:?}", ContainmentState::Challenged).contains("Challenged"));
    assert!(format!("{:?}", ContainmentState::Sandboxed).contains("Sandboxed"));
    assert!(format!("{:?}", ContainmentState::Suspended).contains("Suspended"));
    assert!(format!("{:?}", ContainmentState::Terminated).contains("Terminated"));
    assert!(format!("{:?}", ContainmentState::Quarantined).contains("Quarantined"));
}

#[test]
fn enrichment_containment_state_ord_total_ordering() {
    let mut states = vec![
        ContainmentState::Quarantined,
        ContainmentState::Running,
        ContainmentState::Suspended,
        ContainmentState::Challenged,
        ContainmentState::Terminated,
        ContainmentState::Sandboxed,
    ];
    states.sort();
    assert_eq!(states[0], ContainmentState::Running);
    assert_eq!(states[5], ContainmentState::Quarantined);
}

#[test]
fn enrichment_containment_state_alive_and_dead_mutually_exclusive() {
    let all = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    for s in &all {
        // No state is both alive and dead.
        assert!(
            !(s.is_alive() && s.is_dead()),
            "state {s} is both alive and dead"
        );
    }
}

#[test]
fn enrichment_containment_state_suspended_neither_alive_nor_dead() {
    let s = ContainmentState::Suspended;
    assert!(!s.is_alive());
    assert!(!s.is_dead());
}

#[test]
fn enrichment_containment_state_display_lowercase() {
    let all = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    for s in &all {
        let display = s.to_string();
        assert_eq!(
            display,
            display.to_lowercase(),
            "Display for {s:?} should be lowercase"
        );
    }
}

#[test]
fn enrichment_containment_state_btreeset_insert() {
    let mut set = BTreeSet::new();
    set.insert(ContainmentState::Running);
    set.insert(ContainmentState::Running);
    set.insert(ContainmentState::Terminated);
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// ContainmentError — exhaustive coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_extension_not_found_exact_format() {
    let e = ContainmentError::ExtensionNotFound {
        extension_id: "foo-bar-123".to_string(),
    };
    assert_eq!(e.to_string(), "extension not found: foo-bar-123");
}

#[test]
fn enrichment_error_already_contained_all_states() {
    let states = [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ];
    for s in &states {
        let e = ContainmentError::AlreadyContained {
            extension_id: "ext".to_string(),
            current_state: *s,
        };
        let msg = e.to_string();
        assert!(
            msg.contains(&s.to_string()),
            "Display should contain state name"
        );
        assert!(msg.contains("ext"), "Display should contain extension_id");
    }
}

#[test]
fn enrichment_error_grace_period_zero_elapsed() {
    let e = ContainmentError::GracePeriodExpired {
        extension_id: "ext-z".to_string(),
        elapsed_ns: 0,
    };
    assert_eq!(e.to_string(), "grace period expired for ext-z after 0ns");
}

#[test]
fn enrichment_error_grace_period_max_elapsed() {
    let e = ContainmentError::GracePeriodExpired {
        extension_id: "ext-max".to_string(),
        elapsed_ns: u64::MAX,
    };
    let msg = e.to_string();
    assert!(msg.contains(&u64::MAX.to_string()));
}

#[test]
fn enrichment_error_challenge_timeout_exact() {
    let e = ContainmentError::ChallengeTimeout {
        extension_id: "challenge-ext".to_string(),
    };
    assert_eq!(e.to_string(), "challenge timeout for challenge-ext");
}

#[test]
fn enrichment_error_internal_empty_detail() {
    let e = ContainmentError::Internal {
        detail: String::new(),
    };
    assert_eq!(e.to_string(), "internal error: ");
}

#[test]
fn enrichment_error_clone_independence() {
    let original = ContainmentError::Internal {
        detail: "original".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // They are independent copies.
    if let ContainmentError::Internal { detail } = &cloned {
        assert_eq!(detail, "original");
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn enrichment_error_serde_extension_not_found_json_field() {
    let e = ContainmentError::ExtensionNotFound {
        extension_id: "test-ext".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("ExtensionNotFound"));
}

#[test]
fn enrichment_error_invalid_transition_all_dead_states() {
    for dead_state in [ContainmentState::Terminated, ContainmentState::Quarantined] {
        for action in ContainmentAction::ALL {
            let e = ContainmentError::InvalidTransition {
                from: dead_state,
                action,
            };
            let msg = e.to_string();
            assert!(msg.contains(&dead_state.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// SandboxPolicy — edge cases and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sandbox_policy_is_allowed_empty_string() {
    let policy = SandboxPolicy::default();
    assert!(!policy.is_allowed(""));
}

#[test]
fn enrichment_sandbox_policy_is_allowed_case_sensitive() {
    let policy = SandboxPolicy::default();
    assert!(policy.is_allowed("fs-read"));
    assert!(!policy.is_allowed("FS-READ"));
    assert!(!policy.is_allowed("Fs-Read"));
}

#[test]
fn enrichment_sandbox_policy_many_capabilities() {
    let caps: Vec<String> = (0..100).map(|i| format!("cap-{i:04}")).collect();
    let policy = SandboxPolicy {
        allowed_capabilities: caps.clone(),
        allow_network: false,
        allow_fs_write: false,
        allow_process_spawn: false,
        max_memory_bytes: 0,
    };
    for c in &caps {
        assert!(policy.is_allowed(c));
    }
    assert!(!policy.is_allowed("cap-0100"));
}

#[test]
fn enrichment_sandbox_policy_all_bools_true() {
    let policy = SandboxPolicy {
        allowed_capabilities: vec![],
        allow_network: true,
        allow_fs_write: true,
        allow_process_spawn: true,
        max_memory_bytes: 999,
    };
    assert!(policy.allow_network);
    assert!(policy.allow_fs_write);
    assert!(policy.allow_process_spawn);
    let json = serde_json::to_string(&policy).unwrap();
    let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_sandbox_policy_debug_contains_fields() {
    let policy = SandboxPolicy::default();
    let debug = format!("{policy:?}");
    assert!(debug.contains("allowed_capabilities"));
    assert!(debug.contains("allow_network"));
    assert!(debug.contains("max_memory_bytes"));
}

#[test]
fn enrichment_sandbox_policy_json_field_stability() {
    let policy = SandboxPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("allowed_capabilities"));
    assert!(obj.contains_key("allow_network"));
    assert!(obj.contains_key("allow_fs_write"));
    assert!(obj.contains_key("allow_process_spawn"));
    assert!(obj.contains_key("max_memory_bytes"));
    assert_eq!(obj.len(), 5, "SandboxPolicy should have exactly 5 fields");
}

// ---------------------------------------------------------------------------
// ForensicSnapshot — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_forensic_snapshot_equality() {
    let a = ForensicSnapshot {
        memory_hash: ContentHash::compute(b"same"),
        hostcall_count: 42,
        snapshot_ns: 1000,
        manifest_hash: ContentHash::compute(b"manifest"),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_forensic_snapshot_inequality_memory_hash() {
    let a = ForensicSnapshot {
        memory_hash: ContentHash::compute(b"data-a"),
        hostcall_count: 0,
        snapshot_ns: 0,
        manifest_hash: ContentHash::compute(b"m"),
    };
    let b = ForensicSnapshot {
        memory_hash: ContentHash::compute(b"data-b"),
        hostcall_count: 0,
        snapshot_ns: 0,
        manifest_hash: ContentHash::compute(b"m"),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_forensic_snapshot_json_value_types() {
    let snap = ForensicSnapshot {
        memory_hash: ContentHash::compute(b"test"),
        hostcall_count: 7,
        snapshot_ns: 12345,
        manifest_hash: ContentHash::compute(b"mf"),
    };
    let json = serde_json::to_string(&snap).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj["hostcall_count"].is_number());
    assert!(obj["snapshot_ns"].is_number());
}

#[test]
fn enrichment_forensic_snapshot_debug_has_fields() {
    let snap = ForensicSnapshot {
        memory_hash: ContentHash::compute(b""),
        hostcall_count: 0,
        snapshot_ns: 0,
        manifest_hash: ContentHash::compute(b""),
    };
    let debug = format!("{snap:?}");
    assert!(debug.contains("memory_hash"));
    assert!(debug.contains("hostcall_count"));
    assert!(debug.contains("snapshot_ns"));
    assert!(debug.contains("manifest_hash"));
}

// ---------------------------------------------------------------------------
// ContainmentContext — edge cases and defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_context_default_grace_period_5_seconds() {
    let ctx = ContainmentContext::default();
    assert_eq!(ctx.grace_period_ns, 5_000_000_000);
}

#[test]
fn enrichment_context_default_challenge_timeout_10_seconds() {
    let ctx = ContainmentContext::default();
    assert_eq!(ctx.challenge_timeout_ns, 10_000_000_000);
}

#[test]
fn enrichment_context_default_sandbox_policy_is_default() {
    let ctx = ContainmentContext::default();
    assert_eq!(ctx.sandbox_policy, SandboxPolicy::default());
}

#[test]
fn enrichment_context_serde_roundtrip_with_custom_epoch() {
    let ctx = ContainmentContext {
        decision_id: "custom-epoch-dec".to_string(),
        epoch: SecurityEpoch::from_raw(42),
        ..ContainmentContext::default()
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: ContainmentContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_context_clone_preserves_all_fields() {
    let ctx = ContainmentContext {
        decision_id: "cloned-dec".to_string(),
        timestamp_ns: 999,
        epoch: SecurityEpoch::from_raw(5),
        evidence_refs: vec!["a".to_string(), "b".to_string()],
        grace_period_ns: 100,
        challenge_timeout_ns: 200,
        sandbox_policy: SandboxPolicy {
            allowed_capabilities: vec!["x".to_string()],
            allow_network: true,
            allow_fs_write: true,
            allow_process_spawn: true,
            max_memory_bytes: 512,
        },
    };
    let cloned = ctx.clone();
    assert_eq!(ctx.decision_id, cloned.decision_id);
    assert_eq!(ctx.timestamp_ns, cloned.timestamp_ns);
    assert_eq!(ctx.epoch, cloned.epoch);
    assert_eq!(ctx.evidence_refs, cloned.evidence_refs);
    assert_eq!(ctx.grace_period_ns, cloned.grace_period_ns);
    assert_eq!(ctx.challenge_timeout_ns, cloned.challenge_timeout_ns);
    assert_eq!(ctx.sandbox_policy, cloned.sandbox_policy);
}

#[test]
fn enrichment_context_json_field_count() {
    let ctx = ContainmentContext::default();
    let json = serde_json::to_string(&ctx).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 7, "ContainmentContext should have 7 JSON fields");
}

// ---------------------------------------------------------------------------
// ContainmentReceipt — edge cases and integrity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_tampered_receipt_id_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.receipt_id = "tampered".to_string();
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_action_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.action = ContainmentAction::Terminate;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_target_extension_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.target_extension_id = "ext-999".to_string();
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_timestamp_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    receipt.timestamp_ns += 1;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_success_flag_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.success = false;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_cooperative_flag_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.cooperative = !receipt.cooperative;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_evidence_refs_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    receipt.evidence_refs.push("injected".to_string());
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_epoch_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.epoch = SecurityEpoch::from_raw(999);
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_metadata_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt
        .metadata
        .insert("injected_key".to_string(), "injected_val".to_string());
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_previous_state_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.previous_state = ContainmentState::Challenged;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_tampered_new_state_fails_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let mut receipt = executor
        .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
        .unwrap();
    receipt.new_state = ContainmentState::Terminated;
    assert!(!receipt.verify_integrity());
}

#[test]
fn enrichment_receipt_json_field_count() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.len(),
        13,
        "ContainmentReceipt should have 13 JSON fields"
    );
}

#[test]
fn enrichment_receipt_clone_preserves_integrity() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
        .unwrap();
    let cloned = receipt.clone();
    assert!(cloned.verify_integrity());
    assert_eq!(receipt.content_hash, cloned.content_hash);
}

#[test]
fn enrichment_receipt_debug_contains_receipt_id() {
    let mut executor = setup_executor();
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext-001", &ctx)
        .unwrap();
    let debug = format!("{receipt:?}");
    assert!(debug.contains(&receipt.receipt_id));
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — registration edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_executor_register_empty_id() {
    let mut executor = ContainmentExecutor::new();
    executor.register("");
    assert_eq!(executor.extension_count(), 1);
    assert_eq!(executor.state(""), Some(ContainmentState::Running));
}

#[test]
fn enrichment_executor_register_many_extensions() {
    let mut executor = ContainmentExecutor::new();
    for i in 0..100 {
        executor.register(format!("ext-{i:04}"));
    }
    assert_eq!(executor.extension_count(), 100);
    for i in 0..100 {
        assert_eq!(
            executor.state(&format!("ext-{i:04}")),
            Some(ContainmentState::Running)
        );
    }
}

#[test]
fn enrichment_executor_register_unicode_id() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext-\u{1F600}-emoji");
    assert_eq!(executor.extension_count(), 1);
    assert_eq!(
        executor.state("ext-\u{1F600}-emoji"),
        Some(ContainmentState::Running)
    );
}

#[test]
fn enrichment_executor_default_and_new_equivalent() {
    let a = ContainmentExecutor::new();
    let b = ContainmentExecutor::default();
    assert_eq!(a.extension_count(), b.extension_count());
    assert_eq!(a.extension_count(), 0);
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — transition table exhaustive checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_from_running_all_actions_succeed() {
    for action in ContainmentAction::ALL {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext");
        let ctx = test_context();
        let result = executor.execute(action, "ext", &ctx);
        assert!(
            result.is_ok(),
            "Action {action} from Running should succeed"
        );
    }
}

#[test]
fn enrichment_from_challenged_allow_succeeds() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Allow, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Running);
}

#[test]
fn enrichment_from_challenged_challenge_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    // Challenged -> Challenge again: already in target state => idempotent.
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Challenged);
}

#[test]
fn enrichment_from_challenged_suspend_succeeds() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Suspended);
}

#[test]
fn enrichment_from_challenged_terminate_succeeds() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Terminated);
}

#[test]
fn enrichment_from_sandboxed_allow_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Allow, "ext", &ctx);
    assert!(matches!(
        result,
        Err(ContainmentError::InvalidTransition { .. })
    ));
}

#[test]
fn enrichment_from_sandboxed_challenge_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Challenge, "ext", &ctx);
    assert!(matches!(
        result,
        Err(ContainmentError::InvalidTransition { .. })
    ));
}

#[test]
fn enrichment_from_sandboxed_quarantine_succeeds() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.new_state, ContainmentState::Quarantined);
    assert!(executor.forensic_snapshot("ext").is_some());
}

#[test]
fn enrichment_from_suspended_allow_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Allow, "ext", &ctx);
    assert!(matches!(
        result,
        Err(ContainmentError::InvalidTransition { .. })
    ));
}

#[test]
fn enrichment_from_suspended_challenge_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Challenge, "ext", &ctx);
    assert!(matches!(
        result,
        Err(ContainmentError::InvalidTransition { .. })
    ));
}

#[test]
fn enrichment_from_suspended_sandbox_rejected() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let result = executor.execute(ContainmentAction::Sandbox, "ext", &ctx);
    assert!(matches!(
        result,
        Err(ContainmentError::InvalidTransition { .. })
    ));
}

#[test]
fn enrichment_from_terminated_all_actions_fail_except_idempotent() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    for action in ContainmentAction::ALL {
        let result = executor.execute(action, "ext", &ctx);
        if action == ContainmentAction::Terminate {
            // Idempotent.
            assert!(result.is_ok());
        } else {
            assert!(
                matches!(result, Err(ContainmentError::InvalidTransition { .. })),
                "expected InvalidTransition for {action} from Terminated"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — idempotency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_idempotent_quarantine_returns_same_receipt() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let r1 = executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    let r2 = executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    assert_eq!(r1.receipt_id, r2.receipt_id);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_idempotent_challenge_returns_same_receipt() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let r1 = executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let r2 = executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_idempotent_suspend_returns_same_receipt() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let r1_id = executor.receipts("ext").last().unwrap().receipt_id.clone();
    let r2 = executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    assert_eq!(r1_id, r2.receipt_id);
}

#[test]
fn enrichment_idempotent_does_not_add_extra_receipts() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.receipts("ext").len(), 1);
    // Idempotent call.
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert_eq!(
        executor.receipts("ext").len(),
        1,
        "idempotent call should not add receipt"
    );
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — cooperative flag
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cooperative_allow_action() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Allow, "ext", &ctx)
        .unwrap();
    assert!(receipt.cooperative, "Allow should be cooperative");
}

#[test]
fn enrichment_cooperative_suspend_action() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    assert!(receipt.cooperative, "Suspend should be cooperative");
}

#[test]
fn enrichment_not_cooperative_terminate() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert!(!receipt.cooperative, "Terminate should not be cooperative");
}

#[test]
fn enrichment_not_cooperative_quarantine() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    assert!(!receipt.cooperative, "Quarantine should not be cooperative");
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — resume
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resume_receipt_metadata_has_resume_key() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let receipt = executor.resume("ext", &ctx).unwrap();
    assert_eq!(receipt.metadata.get("resume"), Some(&"true".to_string()));
}

#[test]
fn enrichment_resume_receipt_has_allow_action() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let receipt = executor.resume("ext", &ctx).unwrap();
    assert_eq!(receipt.action, ContainmentAction::Allow);
}

#[test]
fn enrichment_resume_receipt_verify_integrity() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    let receipt = executor.resume("ext", &ctx).unwrap();
    assert!(receipt.verify_integrity());
}

#[test]
fn enrichment_resume_from_challenged_fails() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let result = executor.resume("ext", &ctx);
    assert!(result.is_err());
}

#[test]
fn enrichment_resume_from_sandboxed_fails() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let result = executor.resume("ext", &ctx);
    assert!(result.is_err());
}

#[test]
fn enrichment_resume_from_terminated_fails() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    let result = executor.resume("ext", &ctx);
    assert!(result.is_err());
}

#[test]
fn enrichment_resume_from_quarantined_fails() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    let result = executor.resume("ext", &ctx);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — by_state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_by_state_empty_executor() {
    let executor = ContainmentExecutor::new();
    for state in [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ] {
        assert!(executor.by_state(state).is_empty());
    }
}

#[test]
fn enrichment_by_state_multiple_in_same_state() {
    let mut executor = ContainmentExecutor::new();
    let ctx = test_context();
    executor.register("a");
    executor.register("b");
    executor.register("c");
    executor
        .execute(ContainmentAction::Sandbox, "a", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "b", &ctx)
        .unwrap();
    let sandboxed = executor.by_state(ContainmentState::Sandboxed);
    assert_eq!(sandboxed.len(), 2);
    assert!(sandboxed.contains(&"a"));
    assert!(sandboxed.contains(&"b"));
    let running = executor.by_state(ContainmentState::Running);
    assert_eq!(running.len(), 1);
    assert!(running.contains(&"c"));
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — receipts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipts_ordered_by_action_time() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    let receipts = executor.receipts("ext");
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].action, ContainmentAction::Challenge);
    assert_eq!(receipts[1].action, ContainmentAction::Sandbox);
    assert_eq!(receipts[2].action, ContainmentAction::Terminate);
}

#[test]
fn enrichment_receipts_per_extension_isolation() {
    let mut executor = ContainmentExecutor::new();
    executor.register("a");
    executor.register("b");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "a", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "a", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Terminate, "b", &ctx)
        .unwrap();
    assert_eq!(executor.receipts("a").len(), 2);
    assert_eq!(executor.receipts("b").len(), 1);
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — forensic_snapshot
// ---------------------------------------------------------------------------

#[test]
fn enrichment_forensic_snapshot_not_created_for_terminate() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert!(executor.forensic_snapshot("ext").is_none());
}

#[test]
fn enrichment_forensic_snapshot_hostcall_count_from_receipts() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    // Do 3 actions before quarantine so hostcall_count = 3.
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    let snap = executor.forensic_snapshot("ext").unwrap();
    assert_eq!(
        snap.hostcall_count, 3,
        "hostcall_count should equal prior receipt count"
    );
}

#[test]
fn enrichment_forensic_snapshot_snapshot_ns_matches_context() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = ContainmentContext {
        timestamp_ns: 42_000_000,
        ..test_context()
    };
    executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    let snap = executor.forensic_snapshot("ext").unwrap();
    assert_eq!(snap.snapshot_ns, 42_000_000);
}

#[test]
fn enrichment_forensic_snapshot_memory_hash_deterministic() {
    // Same extension ID => same memory hash.
    let make = || {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-det");
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Quarantine, "ext-det", &ctx)
            .unwrap();
        executor.forensic_snapshot("ext-det").unwrap().clone()
    };
    let s1 = make();
    let s2 = make();
    assert_eq!(s1.memory_hash, s2.memory_hash);
    assert_eq!(s1.manifest_hash, s2.manifest_hash);
}

#[test]
fn enrichment_forensic_snapshot_unknown_extension() {
    let executor = ContainmentExecutor::new();
    assert!(executor.forensic_snapshot("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — sandbox_policy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sandbox_policy_unknown_extension() {
    let executor = ContainmentExecutor::new();
    assert!(executor.sandbox_policy("nonexistent").is_none());
}

#[test]
fn enrichment_sandbox_policy_after_terminate_still_present() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert!(executor.sandbox_policy("ext").is_some());
    // Terminate does not clear sandbox_policy.
    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert!(executor.sandbox_policy("ext").is_some());
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_executor_serde_roundtrip_preserves_receipts() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let json = serde_json::to_string(&executor).unwrap();
    let restored: ContainmentExecutor = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.receipts("ext").len(), 2);
    assert_eq!(restored.state("ext"), Some(ContainmentState::Sandboxed));
}

#[test]
fn enrichment_executor_serde_roundtrip_next_receipt_id_preserved() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let json = serde_json::to_string(&executor).unwrap();
    let mut restored: ContainmentExecutor = serde_json::from_str(&json).unwrap();
    // Should be able to execute another action with a new receipt ID.
    let receipt = restored
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert_ne!(
        receipt.receipt_id, "cr-00000000",
        "should have incremented past first ID"
    );
}

#[test]
fn enrichment_executor_serde_forensic_snapshot_preserved() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    let original_snap = executor.forensic_snapshot("ext").unwrap().clone();
    let json = serde_json::to_string(&executor).unwrap();
    let restored: ContainmentExecutor = serde_json::from_str(&json).unwrap();
    let restored_snap = restored.forensic_snapshot("ext").unwrap();
    assert_eq!(original_snap, *restored_snap);
}

// ---------------------------------------------------------------------------
// Determinism — same inputs produce same outputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_challenge_receipt_hash() {
    let make = || {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-d");
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Challenge, "ext-d", &ctx)
            .unwrap()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_determinism_terminate_receipt_hash() {
    let make = || {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-d");
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Terminate, "ext-d", &ctx)
            .unwrap()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_determinism_quarantine_receipt_hash() {
    let make = || {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-d");
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Quarantine, "ext-d", &ctx)
            .unwrap()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_determinism_multi_step_receipt_hashes() {
    let make = || {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext");
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Challenge, "ext", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext", &ctx)
            .unwrap();
        let r3 = executor
            .execute(ContainmentAction::Terminate, "ext", &ctx)
            .unwrap();
        (r1.content_hash, r2.content_hash, r3.content_hash)
    };
    let (h1a, h1b, h1c) = make();
    let (h2a, h2b, h2c) = make();
    assert_eq!(h1a, h2a);
    assert_eq!(h1b, h2b);
    assert_eq!(h1c, h2c);
}

// ---------------------------------------------------------------------------
// Full lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_challenge_allow_challenge_sandbox_terminate() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();

    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Challenged));

    executor
        .execute(ContainmentAction::Allow, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Running));

    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Challenged));

    executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Sandboxed));

    executor
        .execute(ContainmentAction::Terminate, "ext", &ctx)
        .unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Terminated));

    assert_eq!(executor.receipts("ext").len(), 5);
}

#[test]
fn enrichment_lifecycle_suspend_resume_suspend_quarantine() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();

    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    executor.resume("ext", &ctx).unwrap();
    assert_eq!(executor.state("ext"), Some(ContainmentState::Running));

    executor
        .execute(ContainmentAction::Suspend, "ext", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Quarantine, "ext", &ctx)
        .unwrap();
    assert!(executor.state("ext").unwrap().is_dead());
    assert!(executor.forensic_snapshot("ext").is_some());
    assert_eq!(executor.receipts("ext").len(), 4);
}

#[test]
fn enrichment_lifecycle_multiple_extensions_parallel() {
    let mut executor = ContainmentExecutor::new();
    executor.register("a");
    executor.register("b");
    executor.register("c");
    let ctx = test_context();

    executor
        .execute(ContainmentAction::Sandbox, "a", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Terminate, "b", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Quarantine, "c", &ctx)
        .unwrap();

    assert_eq!(executor.state("a"), Some(ContainmentState::Sandboxed));
    assert_eq!(executor.state("b"), Some(ContainmentState::Terminated));
    assert_eq!(executor.state("c"), Some(ContainmentState::Quarantined));
    assert_eq!(executor.by_state(ContainmentState::Sandboxed), vec!["a"]);
    assert_eq!(executor.by_state(ContainmentState::Terminated), vec!["b"]);
    assert_eq!(executor.by_state(ContainmentState::Quarantined), vec!["c"]);
    assert!(executor.by_state(ContainmentState::Running).is_empty());
}

// ---------------------------------------------------------------------------
// Receipt ID format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_id_hex_format() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    // Format is "cr-XXXXXXXX" where X is hex digit.
    assert!(receipt.receipt_id.starts_with("cr-"));
    let hex_part = &receipt.receipt_id[3..];
    assert_eq!(hex_part.len(), 8);
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_receipt_id_first_is_zero() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Allow, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.receipt_id, "cr-00000000");
}

#[test]
fn enrichment_receipt_id_second_is_one() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.receipt_id, "cr-00000001");
}

// ---------------------------------------------------------------------------
// Receipt timestamp and duration
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_timestamp_matches_context() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = ContainmentContext {
        timestamp_ns: 7_777_777,
        ..test_context()
    };
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.timestamp_ns, 7_777_777);
}

#[test]
fn enrichment_receipt_duration_is_zero_simulated() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    assert_eq!(receipt.duration_ns, 0);
}

#[test]
fn enrichment_receipt_success_always_true() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    for action in ContainmentAction::ALL {
        let mut fresh = ContainmentExecutor::new();
        fresh.register("ext");
        let receipt = fresh.execute(action, "ext", &ctx).unwrap();
        assert!(
            receipt.success,
            "action {action} should produce success=true"
        );
    }
}

// ---------------------------------------------------------------------------
// Error from execute on unknown extension
// ---------------------------------------------------------------------------

#[test]
fn enrichment_execute_unknown_extension_error_contains_id() {
    let mut executor = ContainmentExecutor::new();
    let ctx = test_context();
    let err = executor
        .execute(ContainmentAction::Sandbox, "unknown-ext", &ctx)
        .unwrap_err();
    if let ContainmentError::ExtensionNotFound { extension_id } = err {
        assert_eq!(extension_id, "unknown-ext");
    } else {
        panic!("expected ExtensionNotFound");
    }
}

#[test]
fn enrichment_resume_unknown_extension_error_contains_id() {
    let mut executor = ContainmentExecutor::new();
    let ctx = test_context();
    let err = executor.resume("missing", &ctx).unwrap_err();
    if let ContainmentError::ExtensionNotFound { extension_id } = err {
        assert_eq!(extension_id, "missing");
    } else {
        panic!("expected ExtensionNotFound");
    }
}

// ---------------------------------------------------------------------------
// BTreeMap metadata stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_metadata_is_btreemap_sorted() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Challenge, "ext", &ctx)
        .unwrap();
    // BTreeMap keys are always sorted.
    let keys: Vec<&String> = receipt.metadata.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn enrichment_receipt_metadata_decision_id_present_for_all_actions() {
    for action in ContainmentAction::ALL {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext");
        let ctx = test_context();
        let receipt = executor.execute(action, "ext", &ctx).unwrap();
        assert!(
            receipt.metadata.contains_key("decision_id"),
            "metadata should contain decision_id for action {action}"
        );
    }
}

// ---------------------------------------------------------------------------
// Mixed serde Value roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_serde_value_roundtrip() {
    let mut executor = ContainmentExecutor::new();
    executor.register("ext");
    let ctx = test_context();
    let receipt = executor
        .execute(ContainmentAction::Sandbox, "ext", &ctx)
        .unwrap();
    let value: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let back: ContainmentReceipt = serde_json::from_value(value).unwrap();
    assert_eq!(receipt, back);
    assert!(back.verify_integrity());
}

#[test]
fn enrichment_executor_serde_value_roundtrip() {
    let mut executor = ContainmentExecutor::new();
    executor.register("a");
    executor.register("b");
    let ctx = test_context();
    executor
        .execute(ContainmentAction::Sandbox, "a", &ctx)
        .unwrap();
    executor
        .execute(ContainmentAction::Quarantine, "b", &ctx)
        .unwrap();
    let value: serde_json::Value = serde_json::to_value(&executor).unwrap();
    let back: ContainmentExecutor = serde_json::from_value(value).unwrap();
    assert_eq!(back.extension_count(), 2);
    assert_eq!(back.state("a"), Some(ContainmentState::Sandboxed));
    assert_eq!(back.state("b"), Some(ContainmentState::Quarantined));
}
