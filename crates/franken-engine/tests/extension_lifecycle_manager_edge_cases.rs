//! Edge-case integration tests for the extension_lifecycle_manager module.

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

use frankenengine_engine::extension_lifecycle_manager::{
    CancellationConfig, ExtensionLifecycleManager, ExtensionState, LifecycleError,
    LifecycleManagerEvent, LifecycleTransition, ManifestRef, ResourceBudget, TransitionRecord,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_budget() -> ResourceBudget {
    ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000)
}

fn make_manager() -> ExtensionLifecycleManager {
    ExtensionLifecycleManager::new()
}

fn register_ext(mgr: &mut ExtensionLifecycleManager, id: &str) {
    mgr.register(id, default_budget(), CancellationConfig::default())
        .unwrap();
}

fn advance_to_running(mgr: &mut ExtensionLifecycleManager, id: &str) {
    mgr.transition(id, LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Load, "t", None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Start, "t", None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Activate, "t", None)
        .unwrap();
}

// ===========================================================================
// ExtensionState serde / traits
// ===========================================================================

#[test]
fn extension_state_serde_all_11_variants() {
    let all = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    for s in &all {
        let json = serde_json::to_string(s).unwrap();
        let back: ExtensionState = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

#[test]
fn extension_state_ordering_follows_declaration_order() {
    assert!(ExtensionState::Unloaded < ExtensionState::Validating);
    assert!(ExtensionState::Validating < ExtensionState::Loading);
    assert!(ExtensionState::Loading < ExtensionState::Starting);
    assert!(ExtensionState::Starting < ExtensionState::Running);
    assert!(ExtensionState::Running < ExtensionState::Suspending);
    assert!(ExtensionState::Suspending < ExtensionState::Suspended);
    assert!(ExtensionState::Suspended < ExtensionState::Resuming);
    assert!(ExtensionState::Resuming < ExtensionState::Terminating);
    assert!(ExtensionState::Terminating < ExtensionState::Terminated);
    assert!(ExtensionState::Terminated < ExtensionState::Quarantined);
}

#[test]
fn extension_state_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    ExtensionState::Running.hash(&mut h1);
    ExtensionState::Running.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn extension_state_is_alive_boundary() {
    // Suspending is NOT alive (it's draining, not doing new work)
    assert!(!ExtensionState::Suspending.is_alive());
    // Suspended is NOT alive
    assert!(!ExtensionState::Suspended.is_alive());
    // Terminating is NOT alive
    assert!(!ExtensionState::Terminating.is_alive());
}

#[test]
fn extension_state_is_terminal_only_three() {
    let terminal_count = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ]
    .iter()
    .filter(|s| s.is_terminal())
    .count();
    assert_eq!(terminal_count, 3, "only Unloaded, Terminated, Quarantined");
}

#[test]
fn extension_state_is_executing_only_three() {
    let executing_count = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ]
    .iter()
    .filter(|s| s.is_executing())
    .count();
    assert_eq!(executing_count, 3, "only Running, Starting, Resuming");
}

#[test]
fn extension_state_display_matches_as_str() {
    let all = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    for s in &all {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

// ===========================================================================
// LifecycleTransition serde / traits
// ===========================================================================

#[test]
fn lifecycle_transition_serde_all_14_variants() {
    let all = [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
        LifecycleTransition::Suspend,
        LifecycleTransition::Freeze,
        LifecycleTransition::Resume,
        LifecycleTransition::Reactivate,
        LifecycleTransition::Terminate,
        LifecycleTransition::Finalize,
        LifecycleTransition::Quarantine,
        LifecycleTransition::RejectManifest,
        LifecycleTransition::LoadFailed,
        LifecycleTransition::StartFailed,
    ];
    for t in &all {
        let json = serde_json::to_string(t).unwrap();
        let back: LifecycleTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, t);
    }
}

#[test]
fn lifecycle_transition_display_all() {
    assert_eq!(format!("{}", LifecycleTransition::Validate), "validate");
    assert_eq!(format!("{}", LifecycleTransition::Load), "load");
    assert_eq!(format!("{}", LifecycleTransition::Start), "start");
    assert_eq!(format!("{}", LifecycleTransition::Activate), "activate");
    assert_eq!(format!("{}", LifecycleTransition::Suspend), "suspend");
    assert_eq!(format!("{}", LifecycleTransition::Freeze), "freeze");
    assert_eq!(format!("{}", LifecycleTransition::Resume), "resume");
    assert_eq!(format!("{}", LifecycleTransition::Reactivate), "reactivate");
    assert_eq!(format!("{}", LifecycleTransition::Terminate), "terminate");
    assert_eq!(format!("{}", LifecycleTransition::Finalize), "finalize");
    assert_eq!(format!("{}", LifecycleTransition::Quarantine), "quarantine");
    assert_eq!(
        format!("{}", LifecycleTransition::RejectManifest),
        "reject_manifest"
    );
    assert_eq!(
        format!("{}", LifecycleTransition::LoadFailed),
        "load_failed"
    );
    assert_eq!(
        format!("{}", LifecycleTransition::StartFailed),
        "start_failed"
    );
}

#[test]
fn lifecycle_transition_is_failure_exactly_three() {
    let failure_count = [
        LifecycleTransition::Validate,
        LifecycleTransition::Load,
        LifecycleTransition::Start,
        LifecycleTransition::Activate,
        LifecycleTransition::Suspend,
        LifecycleTransition::Freeze,
        LifecycleTransition::Resume,
        LifecycleTransition::Reactivate,
        LifecycleTransition::Terminate,
        LifecycleTransition::Finalize,
        LifecycleTransition::Quarantine,
        LifecycleTransition::RejectManifest,
        LifecycleTransition::LoadFailed,
        LifecycleTransition::StartFailed,
    ]
    .iter()
    .filter(|t| t.is_failure())
    .count();
    assert_eq!(
        failure_count, 3,
        "only RejectManifest, LoadFailed, StartFailed"
    );
}

#[test]
fn lifecycle_transition_ordering() {
    assert!(LifecycleTransition::Validate < LifecycleTransition::Load);
    assert!(LifecycleTransition::StartFailed > LifecycleTransition::Validate);
}

// ===========================================================================
// LifecycleError serde / display
// ===========================================================================

#[test]
fn lifecycle_error_serde_all_7_variants() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "ext-a".into(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Validate,
        },
        LifecycleError::ExtensionNotFound {
            extension_id: "ext-b".into(),
        },
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "ext-c".into(),
        },
        LifecycleError::BudgetExhausted {
            extension_id: "ext-d".into(),
            remaining_millionths: 42,
            required_millionths: 100,
        },
        LifecycleError::GracePeriodExpired {
            extension_id: "ext-e".into(),
            elapsed_ns: 6_000_000_000,
            budget_ns: 5_000_000_000,
        },
        LifecycleError::ManifestRejected {
            extension_id: "ext-f".into(),
            reason: "bad cap".into(),
        },
        LifecycleError::Internal {
            detail: "oops".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn lifecycle_error_display_all_variants() {
    let e1 = LifecycleError::InvalidTransition {
        extension_id: "ext-a".into(),
        current_state: ExtensionState::Running,
        attempted: LifecycleTransition::Validate,
    };
    let msg = format!("{e1}");
    assert!(msg.contains("ext-a"));
    assert!(msg.contains("running"));
    assert!(msg.contains("validate"));

    let e2 = LifecycleError::ExtensionNotFound {
        extension_id: "ext-b".into(),
    };
    assert!(format!("{e2}").contains("ext-b"));

    let e3 = LifecycleError::ExtensionAlreadyExists {
        extension_id: "ext-c".into(),
    };
    assert!(format!("{e3}").contains("ext-c"));

    let e4 = LifecycleError::BudgetExhausted {
        extension_id: "ext-d".into(),
        remaining_millionths: 42,
        required_millionths: 100,
    };
    let msg4 = format!("{e4}");
    assert!(msg4.contains("42"));
    assert!(msg4.contains("100"));

    let e5 = LifecycleError::GracePeriodExpired {
        extension_id: "ext-e".into(),
        elapsed_ns: 6_000,
        budget_ns: 5_000,
    };
    let msg5 = format!("{e5}");
    assert!(msg5.contains("6000"));
    assert!(msg5.contains("5000"));

    let e6 = LifecycleError::ManifestRejected {
        extension_id: "ext-f".into(),
        reason: "bad cap".into(),
    };
    assert!(format!("{e6}").contains("bad cap"));

    let e7 = LifecycleError::Internal {
        detail: "oops".into(),
    };
    assert!(format!("{e7}").contains("oops"));
}

#[test]
fn lifecycle_error_error_code_stability() {
    assert_eq!(
        LifecycleError::InvalidTransition {
            extension_id: "x".into(),
            current_state: ExtensionState::Unloaded,
            attempted: LifecycleTransition::Activate,
        }
        .error_code(),
        "LIFECYCLE_INVALID_TRANSITION"
    );
    assert_eq!(
        LifecycleError::ExtensionNotFound {
            extension_id: "x".into()
        }
        .error_code(),
        "LIFECYCLE_EXTENSION_NOT_FOUND"
    );
    assert_eq!(
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "x".into()
        }
        .error_code(),
        "LIFECYCLE_EXTENSION_EXISTS"
    );
    assert_eq!(
        LifecycleError::BudgetExhausted {
            extension_id: "x".into(),
            remaining_millionths: 0,
            required_millionths: 1,
        }
        .error_code(),
        "LIFECYCLE_BUDGET_EXHAUSTED"
    );
    assert_eq!(
        LifecycleError::GracePeriodExpired {
            extension_id: "x".into(),
            elapsed_ns: 0,
            budget_ns: 0,
        }
        .error_code(),
        "LIFECYCLE_GRACE_EXPIRED"
    );
    assert_eq!(
        LifecycleError::ManifestRejected {
            extension_id: "x".into(),
            reason: "r".into(),
        }
        .error_code(),
        "LIFECYCLE_MANIFEST_REJECTED"
    );
    assert_eq!(
        LifecycleError::Internal { detail: "d".into() }.error_code(),
        "LIFECYCLE_INTERNAL"
    );
}

// ===========================================================================
// ResourceBudget edge cases
// ===========================================================================

#[test]
fn resource_budget_serde_roundtrip() {
    let b = ResourceBudget::new(500_000, 2048, 42);
    let json = serde_json::to_string(&b).unwrap();
    let back: ResourceBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
}

#[test]
fn resource_budget_consume_memory() {
    let mut b = ResourceBudget::new(1_000, 1024, 10);
    assert!(b.consume_memory(512));
    assert_eq!(b.memory_remaining_bytes, 512);
    assert!(b.consume_memory(512));
    assert_eq!(b.memory_remaining_bytes, 0);
    assert!(!b.consume_memory(1));
}

#[test]
fn resource_budget_consume_exact_amount() {
    let mut b = ResourceBudget::new(100, 100, 1);
    assert!(b.consume_cpu(100));
    assert_eq!(b.cpu_remaining_millionths, 0);
    assert!(!b.consume_cpu(1));
}

#[test]
fn resource_budget_exhausted_all_dimensions() {
    // Start with budget of 1 in each dimension
    let mut b = ResourceBudget::new(1, 1, 1);
    assert!(!b.is_exhausted());

    // Exhaust CPU
    b.cpu_remaining_millionths = 0;
    assert!(b.is_exhausted());

    // Restore CPU, exhaust memory
    b.cpu_remaining_millionths = 1;
    b.memory_remaining_bytes = 0;
    assert!(b.is_exhausted());

    // Restore memory, exhaust hostcalls
    b.memory_remaining_bytes = 1;
    b.hostcall_remaining = 0;
    assert!(b.is_exhausted());
}

#[test]
fn resource_budget_utilization_half() {
    let mut b = ResourceBudget::new(2_000_000, 1024, 100);
    b.consume_cpu(1_000_000);
    // 1M used out of 2M = 500_000 millionths = 50%
    assert_eq!(b.cpu_utilization_millionths(), 500_000);
}

#[test]
fn resource_budget_zero_total_utilization() {
    let b = ResourceBudget::new(0, 0, 0);
    assert_eq!(b.cpu_utilization_millionths(), 0);
}

// ===========================================================================
// CancellationConfig edge cases
// ===========================================================================

#[test]
fn cancellation_config_clamp_exactly_at_max() {
    // 30 seconds is exactly the max
    let cfg = CancellationConfig {
        grace_period_ns: 30_000_000_000,
        force_on_timeout: true,
        propagate_to_children: true,
    }
    .clamped();
    assert_eq!(cfg.grace_period_ns, 30_000_000_000);
}

#[test]
fn cancellation_config_clamp_below_max_unchanged() {
    let cfg = CancellationConfig {
        grace_period_ns: 1_000_000_000,
        force_on_timeout: false,
        propagate_to_children: false,
    }
    .clamped();
    assert_eq!(cfg.grace_period_ns, 1_000_000_000);
}

#[test]
fn cancellation_config_clamp_zero_grace() {
    let cfg = CancellationConfig {
        grace_period_ns: 0,
        force_on_timeout: true,
        propagate_to_children: true,
    }
    .clamped();
    assert_eq!(cfg.grace_period_ns, 0);
}

#[test]
fn cancellation_config_serde_roundtrip() {
    let cfg = CancellationConfig {
        grace_period_ns: 10_000_000_000,
        force_on_timeout: false,
        propagate_to_children: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CancellationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// ManifestRef
// ===========================================================================

#[test]
fn manifest_ref_serde_roundtrip() {
    let m = ManifestRef {
        extension_id: "ext-a".into(),
        capabilities: vec!["fs.read".into(), "net.send".into()],
        max_lifetime_ns: 3_600_000_000_000,
        schema_version: 2,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ManifestRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn manifest_ref_empty_capabilities() {
    let m = ManifestRef {
        extension_id: "ext-minimal".into(),
        capabilities: vec![],
        max_lifetime_ns: 0,
        schema_version: 1,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ManifestRef = serde_json::from_str(&json).unwrap();
    assert!(back.capabilities.is_empty());
    assert_eq!(back.max_lifetime_ns, 0);
}

// ===========================================================================
// TransitionRecord / LifecycleManagerEvent serde
// ===========================================================================

#[test]
fn transition_record_serde_roundtrip() {
    let rec = TransitionRecord {
        sequence: 99,
        timestamp_ns: 42_000_000_000,
        from_state: ExtensionState::Suspended,
        to_state: ExtensionState::Resuming,
        transition: LifecycleTransition::Resume,
        trace_id: "trace-abc".into(),
        decision_id: Some("dec-123".into()),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn transition_record_no_decision_id() {
    let rec = TransitionRecord {
        sequence: 0,
        timestamp_ns: 0,
        from_state: ExtensionState::Unloaded,
        to_state: ExtensionState::Validating,
        transition: LifecycleTransition::Validate,
        trace_id: "t".into(),
        decision_id: None,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert!(back.decision_id.is_none());
}

#[test]
fn lifecycle_manager_event_serde_roundtrip() {
    let evt = LifecycleManagerEvent {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: "extension_lifecycle_manager".into(),
        event: "validate".into(),
        outcome: "ok".into(),
        error_code: Some("LIFECYCLE_INVALID_TRANSITION".into()),
        extension_id: "ext-a".into(),
        from_state: Some("running".into()),
        to_state: Some("terminating".into()),
        transition: Some("terminate".into()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: LifecycleManagerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evt);
}

// ===========================================================================
// valid_transitions exhaustive from each state
// ===========================================================================

#[test]
fn valid_transitions_from_unloaded() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Unloaded);
    assert!(valid.contains(&LifecycleTransition::Validate));
    // No other transitions should be valid from Unloaded
    assert_eq!(valid.len(), 1);
}

#[test]
fn valid_transitions_from_validating() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Validating);
    assert!(valid.contains(&LifecycleTransition::Load));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert!(valid.contains(&LifecycleTransition::RejectManifest));
    assert_eq!(valid.len(), 4);
}

#[test]
fn valid_transitions_from_loading() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Loading);
    assert!(valid.contains(&LifecycleTransition::Start));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert!(valid.contains(&LifecycleTransition::LoadFailed));
    assert_eq!(valid.len(), 4);
}

#[test]
fn valid_transitions_from_starting() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Starting);
    assert!(valid.contains(&LifecycleTransition::Activate));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert!(valid.contains(&LifecycleTransition::StartFailed));
    assert_eq!(valid.len(), 4);
}

#[test]
fn valid_transitions_from_running() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Running);
    assert!(valid.contains(&LifecycleTransition::Suspend));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert_eq!(valid.len(), 3);
}

#[test]
fn valid_transitions_from_suspending() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Suspending);
    assert!(valid.contains(&LifecycleTransition::Freeze));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert_eq!(valid.len(), 3);
}

#[test]
fn valid_transitions_from_suspended() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Suspended);
    assert!(valid.contains(&LifecycleTransition::Resume));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert_eq!(valid.len(), 3);
}

#[test]
fn valid_transitions_from_resuming() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Resuming);
    assert!(valid.contains(&LifecycleTransition::Reactivate));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert_eq!(valid.len(), 3);
}

#[test]
fn valid_transitions_from_terminating() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Terminating);
    assert!(valid.contains(&LifecycleTransition::Finalize));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert_eq!(valid.len(), 2);
}

#[test]
fn valid_transitions_from_terminated_empty() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Terminated);
    assert!(valid.is_empty());
}

#[test]
fn valid_transitions_from_quarantined_empty() {
    use frankenengine_engine::extension_lifecycle_manager::valid_transitions;
    let valid = valid_transitions(ExtensionState::Quarantined);
    assert!(valid.is_empty());
}

// ===========================================================================
// Manager: registration edge cases
// ===========================================================================

#[test]
fn register_and_reregister_after_unregister() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    // Unloaded is terminal, so we can unregister
    mgr.unregister("ext-a").unwrap();
    // Re-register should succeed
    register_ext(&mut mgr, "ext-a");
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Unloaded);
}

#[test]
fn unregister_from_terminated_state() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Finalize, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Terminated);
    mgr.unregister("ext-a").unwrap();
}

#[test]
fn unregister_from_quarantined_state() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Quarantine, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Quarantined);
    mgr.unregister("ext-a").unwrap();
}

#[test]
fn unregister_nonexistent_fails() {
    let mut mgr = make_manager();
    let err = mgr.unregister("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn unregister_running_fails() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    let err = mgr.unregister("ext-a").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
}

// ===========================================================================
// Manager: transition edge cases
// ===========================================================================

#[test]
fn transition_nonexistent_extension_fails() {
    let mut mgr = make_manager();
    let err = mgr
        .transition("ghost", LifecycleTransition::Validate, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn transition_invalid_from_terminated() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Finalize, "t", None)
        .unwrap();

    // Try to validate from Terminated — should fail
    let err = mgr
        .transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
}

#[test]
fn transition_start_fails_with_zero_cpu_budget() {
    let mut mgr = make_manager();
    // MIN_START_BUDGET_MILLIONTHS is 1_000. Give 999.
    let budget = ResourceBudget::new(999, 64 * 1024 * 1024, 10_000);
    mgr.register("ext-a", budget, CancellationConfig::default())
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Load, "t", None)
        .unwrap();
    let err = mgr
        .transition("ext-a", LifecycleTransition::Start, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
}

#[test]
fn transition_start_succeeds_with_exactly_min_budget() {
    let mut mgr = make_manager();
    // MIN_START_BUDGET_MILLIONTHS = 1_000
    let budget = ResourceBudget::new(1_000, 64 * 1024 * 1024, 10_000);
    mgr.register("ext-a", budget, CancellationConfig::default())
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Load, "t", None)
        .unwrap();
    let state = mgr
        .transition("ext-a", LifecycleTransition::Start, "t", None)
        .unwrap();
    assert_eq!(state, ExtensionState::Starting);
}

#[test]
fn quarantine_from_terminating() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    let state = mgr
        .transition("ext-a", LifecycleTransition::Quarantine, "t", None)
        .unwrap();
    assert_eq!(state, ExtensionState::Quarantined);
}

#[test]
fn all_failure_paths_return_to_unloaded() {
    let mut mgr = make_manager();

    // RejectManifest from Validating
    register_ext(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::RejectManifest, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Unloaded);

    // LoadFailed from Loading
    register_ext(&mut mgr, "ext-b");
    mgr.transition("ext-b", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext-b", LifecycleTransition::Load, "t", None)
        .unwrap();
    mgr.transition("ext-b", LifecycleTransition::LoadFailed, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-b").unwrap(), ExtensionState::Unloaded);

    // StartFailed from Starting
    register_ext(&mut mgr, "ext-c");
    mgr.transition("ext-c", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext-c", LifecycleTransition::Load, "t", None)
        .unwrap();
    mgr.transition("ext-c", LifecycleTransition::Start, "t", None)
        .unwrap();
    mgr.transition("ext-c", LifecycleTransition::StartFailed, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-c").unwrap(), ExtensionState::Unloaded);
}

// ===========================================================================
// Manager: transition log edge cases
// ===========================================================================

#[test]
fn transition_log_sequence_monotonic() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Suspend, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Freeze, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Resume, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Reactivate, "t", None)
        .unwrap();

    let log = mgr.transition_log("ext-a").unwrap();
    for (i, rec) in log.iter().enumerate() {
        assert_eq!(rec.sequence, i as u64);
    }
}

#[test]
fn transition_log_tracks_timestamps_from_clock() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    mgr.advance_clock(1_000);
    mgr.transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.advance_clock(2_000);
    mgr.transition("ext-a", LifecycleTransition::Load, "t", None)
        .unwrap();

    let log = mgr.transition_log("ext-a").unwrap();
    assert_eq!(log[0].timestamp_ns, 1_000);
    assert_eq!(log[1].timestamp_ns, 3_000);
}

#[test]
fn transition_log_with_decision_id() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    mgr.transition(
        "ext-a",
        LifecycleTransition::Validate,
        "trace-99",
        Some("decision-42"),
    )
    .unwrap();
    let log = mgr.transition_log("ext-a").unwrap();
    assert_eq!(log[0].trace_id, "trace-99");
    assert_eq!(log[0].decision_id.as_deref(), Some("decision-42"));
}

#[test]
fn transition_log_nonexistent_fails() {
    let mgr = make_manager();
    let err = mgr.transition_log("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Manager: budget enforcement edge cases
// ===========================================================================

#[test]
fn consume_cpu_on_nonexistent_fails() {
    let mut mgr = make_manager();
    let err = mgr.consume_cpu("ghost", 100).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn consume_hostcall_on_nonexistent_fails() {
    let mut mgr = make_manager();
    let err = mgr.consume_hostcall("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn consume_hostcall_exhaustion() {
    let mut mgr = make_manager();
    let budget = ResourceBudget::new(1_000_000, 1024, 2);
    mgr.register("ext-a", budget, CancellationConfig::default())
        .unwrap();
    mgr.consume_hostcall("ext-a").unwrap();
    mgr.consume_hostcall("ext-a").unwrap();
    let err = mgr.consume_hostcall("ext-a").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
}

#[test]
fn enforce_budgets_skips_non_executing_exhausted() {
    let mut mgr = make_manager();
    // Register with budget that will be exhausted after starting
    let budget = ResourceBudget::new(1_000, 0, 100); // memory=0 → exhausted
    mgr.register("ext-a", budget, CancellationConfig::default())
        .unwrap();
    advance_to_running(&mut mgr, "ext-a");
    // Suspend it so it's not executing
    mgr.transition("ext-a", LifecycleTransition::Suspend, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Freeze, "t", None)
        .unwrap();

    // Enforce budgets — ext-a is Suspended (not executing), so should NOT be contained
    let contained = mgr.enforce_budgets("trace");
    assert!(
        contained.is_empty(),
        "suspended extension should not be auto-contained"
    );
}

#[test]
fn enforce_budgets_no_exhausted_returns_empty() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    let contained = mgr.enforce_budgets("trace");
    assert!(contained.is_empty());
}

#[test]
fn enforce_budgets_multiple_exhausted() {
    let mut mgr = make_manager();
    // Both have memory=0 → exhausted
    let budget_a = ResourceBudget::new(1_000, 0, 100);
    let budget_b = ResourceBudget::new(1_000, 0, 100);
    mgr.register("ext-a", budget_a, CancellationConfig::default())
        .unwrap();
    mgr.register("ext-b", budget_b, CancellationConfig::default())
        .unwrap();
    advance_to_running(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-b");

    let contained = mgr.enforce_budgets("trace");
    assert_eq!(contained.len(), 2);
    // Both should be Terminating
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Terminating);
    assert_eq!(mgr.state("ext-b").unwrap(), ExtensionState::Terminating);
}

// ===========================================================================
// Manager: cooperative shutdown edge cases
// ===========================================================================

#[test]
fn cooperative_shutdown_already_terminating() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    // Manually transition to Terminating first
    mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
        .unwrap();

    // cooperative_shutdown from Terminating — should skip the Terminate transition
    let state = mgr
        .cooperative_shutdown("ext-a", "t-sd", 1_000_000_000, false)
        .unwrap();
    assert_eq!(state, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_at_exact_grace_boundary() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    // Default grace = 5_000_000_000 ns. elapsed == grace → within grace period (<=)
    let state = mgr
        .cooperative_shutdown("ext-a", "t-sd", 5_000_000_000, false)
        .unwrap();
    assert_eq!(state, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_one_past_grace_with_force() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    // Default: force_on_timeout=true, grace=5s. elapsed=5s+1ns → past grace
    let state = mgr
        .cooperative_shutdown("ext-a", "t-sd", 5_000_000_001, false)
        .unwrap();
    assert_eq!(state, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_past_grace_quarantine_with_force() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    let state = mgr
        .cooperative_shutdown("ext-a", "t-sd", 6_000_000_000, true)
        .unwrap();
    assert_eq!(state, ExtensionState::Quarantined);
}

#[test]
fn cooperative_shutdown_past_grace_no_force_error() {
    let mut mgr = make_manager();
    let cfg = CancellationConfig {
        grace_period_ns: 5_000_000_000,
        force_on_timeout: false,
        propagate_to_children: true,
    };
    mgr.register("ext-a", default_budget(), cfg).unwrap();
    advance_to_running(&mut mgr, "ext-a");

    let err = mgr
        .cooperative_shutdown("ext-a", "t-sd", 6_000_000_000, false)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_GRACE_EXPIRED");
}

#[test]
fn cooperative_shutdown_zero_grace_within() {
    let mut mgr = make_manager();
    let cfg = CancellationConfig {
        grace_period_ns: 0,
        force_on_timeout: true,
        propagate_to_children: true,
    };
    mgr.register("ext-a", default_budget(), cfg).unwrap();
    advance_to_running(&mut mgr, "ext-a");
    // elapsed=0, grace=0, 0<=0 → within grace
    let state = mgr.cooperative_shutdown("ext-a", "t-sd", 0, false).unwrap();
    assert_eq!(state, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_nonexistent_fails() {
    let mut mgr = make_manager();
    let err = mgr
        .cooperative_shutdown("ghost", "t", 0, false)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn cooperative_shutdown_from_suspended() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    mgr.transition("ext-a", LifecycleTransition::Suspend, "t", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Freeze, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Suspended);

    let state = mgr
        .cooperative_shutdown("ext-a", "t-sd", 1_000_000_000, false)
        .unwrap();
    assert_eq!(state, ExtensionState::Terminated);
}

// ===========================================================================
// Manager: clock edge cases
// ===========================================================================

#[test]
fn clock_starts_at_zero() {
    let mgr = make_manager();
    assert_eq!(mgr.clock_ns(), 0);
}

#[test]
fn clock_advance_zero_delta() {
    let mut mgr = make_manager();
    mgr.advance_clock(1_000);
    mgr.advance_clock(0);
    assert_eq!(mgr.clock_ns(), 1_000);
}

#[test]
fn clock_advance_saturates_at_max() {
    let mut mgr = make_manager();
    mgr.advance_clock(u64::MAX);
    assert_eq!(mgr.clock_ns(), u64::MAX);
    mgr.advance_clock(1);
    assert_eq!(mgr.clock_ns(), u64::MAX, "should saturate, not wrap");
}

// ===========================================================================
// Manager: events edge cases
// ===========================================================================

#[test]
fn register_emits_event() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    let events = mgr.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "register");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].extension_id, "ext-a");
}

#[test]
fn unregister_emits_event() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    mgr.drain_events(); // clear register event
    mgr.unregister("ext-a").unwrap();
    let events = mgr.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "unregister");
}

#[test]
fn drain_events_clears_buffer() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    assert!(!mgr.drain_events().is_empty());
    assert!(mgr.drain_events().is_empty());
}

#[test]
fn transition_events_track_from_to_state() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    mgr.drain_events();
    mgr.transition("ext-a", LifecycleTransition::Validate, "t", None)
        .unwrap();
    let events = mgr.drain_events();
    assert_eq!(events[0].from_state.as_deref(), Some("unloaded"));
    assert_eq!(events[0].to_state.as_deref(), Some("validating"));
    assert_eq!(events[0].transition.as_deref(), Some("validate"));
}

// ===========================================================================
// Manager: manifest / utility edge cases
// ===========================================================================

#[test]
fn manifest_not_set_initially() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    assert!(mgr.manifest("ext-a").unwrap().is_none());
}

#[test]
fn manifest_nonexistent_fails() {
    let mgr = make_manager();
    let err = mgr.manifest("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn set_manifest_on_nonexistent_fails() {
    let mut mgr = make_manager();
    let m = ManifestRef {
        extension_id: "ghost".into(),
        capabilities: vec![],
        max_lifetime_ns: 0,
        schema_version: 1,
    };
    let err = mgr.set_manifest("ghost", m).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn budget_nonexistent_fails() {
    let mgr = make_manager();
    let err = mgr.budget("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn cancellation_config_nonexistent_fails() {
    let mgr = make_manager();
    let err = mgr.cancellation_config("ghost").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn extension_ids_btree_sorted() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "zebra");
    register_ext(&mut mgr, "alpha");
    register_ext(&mut mgr, "mid");
    let ids = mgr.extension_ids();
    assert_eq!(ids, vec!["alpha", "mid", "zebra"]);
}

#[test]
fn extension_ids_empty_initially() {
    let mgr = make_manager();
    assert!(mgr.extension_ids().is_empty());
}

#[test]
fn count_in_state_mixed() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    register_ext(&mut mgr, "ext-b");
    register_ext(&mut mgr, "ext-c");
    advance_to_running(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-b");
    // ext-c stays Unloaded
    assert_eq!(mgr.count_in_state(ExtensionState::Running), 2);
    assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 1);
    assert_eq!(mgr.count_in_state(ExtensionState::Terminated), 0);
}

// ===========================================================================
// Manager: multiple suspend/resume cycles
// ===========================================================================

#[test]
fn multiple_suspend_resume_cycles() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");

    for _ in 0..3 {
        mgr.transition("ext-a", LifecycleTransition::Suspend, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Freeze, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Resume, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Reactivate, "t", None)
            .unwrap();
    }

    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Running);
    // 4 (to running) + 3*4 (suspend/freeze/resume/reactivate) = 16 transitions
    let log = mgr.transition_log("ext-a").unwrap();
    assert_eq!(log.len(), 16);
}

// ===========================================================================
// Manager: serde roundtrip of full manager
// ===========================================================================

#[test]
fn manager_serde_preserves_state() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    register_ext(&mut mgr, "ext-b");
    advance_to_running(&mut mgr, "ext-a");
    mgr.advance_clock(5_000);
    mgr.set_manifest(
        "ext-a",
        ManifestRef {
            extension_id: "ext-a".into(),
            capabilities: vec!["fs.read".into()],
            max_lifetime_ns: 0,
            schema_version: 1,
        },
    )
    .unwrap();
    mgr.consume_cpu("ext-a", 100_000).unwrap();

    let json = serde_json::to_string(&mgr).unwrap();
    let back: ExtensionLifecycleManager = serde_json::from_str(&json).unwrap();

    assert_eq!(back.state("ext-a").unwrap(), ExtensionState::Running);
    assert_eq!(back.state("ext-b").unwrap(), ExtensionState::Unloaded);
    assert_eq!(back.clock_ns(), 5_000);
    assert!(back.manifest("ext-a").unwrap().is_some());
    assert_eq!(
        back.budget("ext-a").unwrap().cpu_remaining_millionths,
        900_000
    );
    assert_eq!(back.transition_log("ext-a").unwrap().len(), 4);
}

// ===========================================================================
// Manager: determinism
// ===========================================================================

#[test]
fn deterministic_replay_identical_transition_logs() {
    let run = || -> Vec<TransitionRecord> {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        mgr.transition("ext-a", LifecycleTransition::Suspend, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Freeze, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Resume, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Reactivate, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
            .unwrap();
        mgr.transition("ext-a", LifecycleTransition::Finalize, "t", None)
            .unwrap();
        mgr.transition_log("ext-a").unwrap().to_vec()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_events_identical() {
    let run = || -> Vec<LifecycleManagerEvent> {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        mgr.drain_events()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Integration: full lifecycle with all paths
// ===========================================================================

#[test]
fn integration_full_lifecycle_with_manifest_and_budget_tracking() {
    let mut mgr = make_manager();
    let budget = ResourceBudget::new(500_000, 1024 * 1024, 100);
    mgr.register("ext-main", budget, CancellationConfig::default())
        .unwrap();

    // Validate
    mgr.transition("ext-main", LifecycleTransition::Validate, "trace-1", None)
        .unwrap();
    mgr.set_manifest(
        "ext-main",
        ManifestRef {
            extension_id: "ext-main".into(),
            capabilities: vec!["fs.read".into(), "net.send".into()],
            max_lifetime_ns: 3_600_000_000_000,
            schema_version: 1,
        },
    )
    .unwrap();

    // Load, Start, Activate
    mgr.transition("ext-main", LifecycleTransition::Load, "trace-1", None)
        .unwrap();
    mgr.transition("ext-main", LifecycleTransition::Start, "trace-1", None)
        .unwrap();
    mgr.transition(
        "ext-main",
        LifecycleTransition::Activate,
        "trace-1",
        Some("decision-boot"),
    )
    .unwrap();

    // Consume resources while running
    mgr.consume_cpu("ext-main", 100_000).unwrap();
    mgr.consume_hostcall("ext-main").unwrap();
    mgr.consume_hostcall("ext-main").unwrap();

    assert_eq!(
        mgr.budget("ext-main").unwrap().cpu_remaining_millionths,
        400_000
    );
    assert_eq!(mgr.budget("ext-main").unwrap().hostcall_remaining, 98);

    // Suspend/resume cycle
    mgr.transition("ext-main", LifecycleTransition::Suspend, "trace-2", None)
        .unwrap();
    mgr.transition("ext-main", LifecycleTransition::Freeze, "trace-2", None)
        .unwrap();
    mgr.transition("ext-main", LifecycleTransition::Resume, "trace-2", None)
        .unwrap();
    mgr.transition("ext-main", LifecycleTransition::Reactivate, "trace-2", None)
        .unwrap();

    // Cooperative shutdown
    let final_state = mgr
        .cooperative_shutdown("ext-main", "trace-3", 1_000_000_000, false)
        .unwrap();
    assert_eq!(final_state, ExtensionState::Terminated);

    // Verify transition log completeness
    let log = mgr.transition_log("ext-main").unwrap();
    // Validate + Load + Start + Activate + Suspend + Freeze + Resume + Reactivate + Terminate + Finalize = 10
    assert_eq!(log.len(), 10);

    // Verify first and last entries
    assert_eq!(log[0].from_state, ExtensionState::Unloaded);
    assert_eq!(log[0].to_state, ExtensionState::Validating);
    assert_eq!(log[9].from_state, ExtensionState::Terminating);
    assert_eq!(log[9].to_state, ExtensionState::Terminated);

    // Decision ID only on Activate
    assert_eq!(log[3].decision_id.as_deref(), Some("decision-boot"));
    assert!(log[0].decision_id.is_none());
}

#[test]
fn integration_budget_enforcement_with_cooperative_shutdown() {
    let mut mgr = make_manager();
    // Budget with memory=0 → already exhausted
    let budget = ResourceBudget::new(1_000, 0, 100);
    mgr.register("ext-a", budget, CancellationConfig::default())
        .unwrap();
    advance_to_running(&mut mgr, "ext-a");

    // Enforce budgets
    let contained = mgr.enforce_budgets("trace-enforce");
    assert_eq!(contained.len(), 1);
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Terminating);

    // Finalize
    mgr.transition("ext-a", LifecycleTransition::Finalize, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Terminated);

    // Unregister
    mgr.unregister("ext-a").unwrap();
    assert!(mgr.extension_ids().is_empty());
}

#[test]
fn integration_multiple_extensions_mixed_states() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");
    register_ext(&mut mgr, "ext-b");
    register_ext(&mut mgr, "ext-c");

    advance_to_running(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-b");
    // ext-c stays Unloaded

    // Quarantine ext-a
    mgr.transition("ext-a", LifecycleTransition::Quarantine, "t", None)
        .unwrap();

    // Suspend ext-b
    mgr.transition("ext-b", LifecycleTransition::Suspend, "t", None)
        .unwrap();
    mgr.transition("ext-b", LifecycleTransition::Freeze, "t", None)
        .unwrap();

    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Quarantined);
    assert_eq!(mgr.state("ext-b").unwrap(), ExtensionState::Suspended);
    assert_eq!(mgr.state("ext-c").unwrap(), ExtensionState::Unloaded);

    assert_eq!(mgr.count_in_state(ExtensionState::Quarantined), 1);
    assert_eq!(mgr.count_in_state(ExtensionState::Suspended), 1);
    assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 1);
    assert_eq!(mgr.count_in_state(ExtensionState::Running), 0);

    // Unregister ext-a (quarantined = terminal)
    mgr.unregister("ext-a").unwrap();
    assert_eq!(mgr.extension_ids().len(), 2);
}

#[test]
fn integration_retry_after_failure_path() {
    let mut mgr = make_manager();
    register_ext(&mut mgr, "ext-a");

    // First attempt: validation fails
    mgr.transition("ext-a", LifecycleTransition::Validate, "t1", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::RejectManifest, "t1", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Unloaded);

    // Second attempt: load fails
    mgr.transition("ext-a", LifecycleTransition::Validate, "t2", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Load, "t2", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::LoadFailed, "t2", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Unloaded);

    // Third attempt: success
    mgr.transition("ext-a", LifecycleTransition::Validate, "t3", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Load, "t3", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Start, "t3", None)
        .unwrap();
    mgr.transition("ext-a", LifecycleTransition::Activate, "t3", None)
        .unwrap();
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Running);

    // Transition log should have all attempts
    let log = mgr.transition_log("ext-a").unwrap();
    // 2 (validate+reject) + 3 (validate+load+loadfailed) + 4 (full happy) = 9
    assert_eq!(log.len(), 9);
}

#[test]
fn integration_cancellation_config_clamped_on_register() {
    let mut mgr = make_manager();
    let cfg = CancellationConfig {
        grace_period_ns: 999_000_000_000, // way over max
        force_on_timeout: false,
        propagate_to_children: false,
    };
    mgr.register("ext-a", default_budget(), cfg).unwrap();

    // Should be clamped to 30s max
    let stored = mgr.cancellation_config("ext-a").unwrap();
    assert_eq!(stored.grace_period_ns, 30_000_000_000);
    assert!(!stored.force_on_timeout);
    assert!(!stored.propagate_to_children);
}
