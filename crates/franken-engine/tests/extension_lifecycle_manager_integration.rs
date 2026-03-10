#![forbid(unsafe_code)]

//! Integration tests for the `extension_lifecycle_manager` module.
//!
//! Exercises the public API from outside the crate boundary, covering:
//! - ExtensionState predicates and Display
//! - LifecycleTransition predicates and Display
//! - LifecycleError variants, error codes, and Display
//! - ResourceBudget construction, consumption, utilization, exhaustion
//! - CancellationConfig defaults, clamping
//! - ManifestRef construction
//! - ExtensionLifecycleManager: register, unregister, state queries, clock,
//!   transition log, telemetry events, state machine transitions (happy path,
//!   failure paths, quarantine, terminate from all alive states), budget
//!   enforcement, cooperative shutdown, manifest attachment, consume_cpu,
//!   consume_hostcall, valid_transitions, serde round-trips.

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
    valid_transitions,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_budget() -> ResourceBudget {
    ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000)
}

fn small_budget() -> ResourceBudget {
    ResourceBudget::new(500, 1024, 5)
}

fn register(mgr: &mut ExtensionLifecycleManager, id: &str) {
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

fn advance_to_suspended(mgr: &mut ExtensionLifecycleManager, id: &str) {
    advance_to_running(mgr, id);
    mgr.transition(id, LifecycleTransition::Suspend, "t", None)
        .unwrap();
    mgr.transition(id, LifecycleTransition::Freeze, "t", None)
        .unwrap();
}

// ===========================================================================
// ExtensionState
// ===========================================================================

#[test]
fn state_is_alive_comprehensive() {
    let alive = [
        ExtensionState::Running,
        ExtensionState::Starting,
        ExtensionState::Resuming,
        ExtensionState::Loading,
        ExtensionState::Validating,
    ];
    let not_alive = [
        ExtensionState::Unloaded,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    for s in alive {
        assert!(s.is_alive(), "{s:?} should be alive");
    }
    for s in not_alive {
        assert!(!s.is_alive(), "{s:?} should not be alive");
    }
}

#[test]
fn state_is_terminal_comprehensive() {
    let terminal = [
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
        ExtensionState::Unloaded,
    ];
    let non_terminal = [
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Starting,
        ExtensionState::Running,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Resuming,
        ExtensionState::Terminating,
    ];
    for s in terminal {
        assert!(s.is_terminal(), "{s:?} should be terminal");
    }
    for s in non_terminal {
        assert!(!s.is_terminal(), "{s:?} should not be terminal");
    }
}

#[test]
fn state_is_executing_comprehensive() {
    let executing = [
        ExtensionState::Running,
        ExtensionState::Starting,
        ExtensionState::Resuming,
    ];
    let not_executing = [
        ExtensionState::Unloaded,
        ExtensionState::Validating,
        ExtensionState::Loading,
        ExtensionState::Suspending,
        ExtensionState::Suspended,
        ExtensionState::Terminating,
        ExtensionState::Terminated,
        ExtensionState::Quarantined,
    ];
    for s in executing {
        assert!(s.is_executing(), "{s:?} should be executing");
    }
    for s in not_executing {
        assert!(!s.is_executing(), "{s:?} should not be executing");
    }
}

#[test]
fn state_as_str_matches_display() {
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
    for s in all {
        assert_eq!(s.as_str(), format!("{s}"));
    }
}

#[test]
fn state_as_str_specific_values() {
    assert_eq!(ExtensionState::Unloaded.as_str(), "unloaded");
    assert_eq!(ExtensionState::Validating.as_str(), "validating");
    assert_eq!(ExtensionState::Loading.as_str(), "loading");
    assert_eq!(ExtensionState::Starting.as_str(), "starting");
    assert_eq!(ExtensionState::Running.as_str(), "running");
    assert_eq!(ExtensionState::Suspending.as_str(), "suspending");
    assert_eq!(ExtensionState::Suspended.as_str(), "suspended");
    assert_eq!(ExtensionState::Resuming.as_str(), "resuming");
    assert_eq!(ExtensionState::Terminating.as_str(), "terminating");
    assert_eq!(ExtensionState::Terminated.as_str(), "terminated");
    assert_eq!(ExtensionState::Quarantined.as_str(), "quarantined");
}

#[test]
fn state_serde_roundtrip() {
    let all = [
        ExtensionState::Unloaded,
        ExtensionState::Running,
        ExtensionState::Quarantined,
    ];
    for s in all {
        let json = serde_json::to_string(&s).unwrap();
        let back: ExtensionState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// LifecycleTransition
// ===========================================================================

#[test]
fn transition_as_str_specific_values() {
    assert_eq!(LifecycleTransition::Validate.as_str(), "validate");
    assert_eq!(LifecycleTransition::Load.as_str(), "load");
    assert_eq!(LifecycleTransition::Start.as_str(), "start");
    assert_eq!(LifecycleTransition::Activate.as_str(), "activate");
    assert_eq!(LifecycleTransition::Suspend.as_str(), "suspend");
    assert_eq!(LifecycleTransition::Freeze.as_str(), "freeze");
    assert_eq!(LifecycleTransition::Resume.as_str(), "resume");
    assert_eq!(LifecycleTransition::Reactivate.as_str(), "reactivate");
    assert_eq!(LifecycleTransition::Terminate.as_str(), "terminate");
    assert_eq!(LifecycleTransition::Finalize.as_str(), "finalize");
    assert_eq!(LifecycleTransition::Quarantine.as_str(), "quarantine");
    assert_eq!(
        LifecycleTransition::RejectManifest.as_str(),
        "reject_manifest"
    );
    assert_eq!(LifecycleTransition::LoadFailed.as_str(), "load_failed");
    assert_eq!(LifecycleTransition::StartFailed.as_str(), "start_failed");
}

#[test]
fn transition_display_matches_as_str() {
    let all = [
        LifecycleTransition::Validate,
        LifecycleTransition::Quarantine,
        LifecycleTransition::StartFailed,
    ];
    for t in all {
        assert_eq!(t.as_str(), format!("{t}"));
    }
}

#[test]
fn transition_is_failure() {
    let failures = [
        LifecycleTransition::RejectManifest,
        LifecycleTransition::LoadFailed,
        LifecycleTransition::StartFailed,
    ];
    let non_failures = [
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
    ];
    for t in failures {
        assert!(t.is_failure(), "{t:?} should be failure");
    }
    for t in non_failures {
        assert!(!t.is_failure(), "{t:?} should not be failure");
    }
}

#[test]
fn transition_serde_roundtrip() {
    let t = LifecycleTransition::Quarantine;
    let json = serde_json::to_string(&t).unwrap();
    let back: LifecycleTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ===========================================================================
// LifecycleError
// ===========================================================================

#[test]
fn error_codes_are_distinct() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            extension_id: "x".into(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Validate,
        },
        LifecycleError::ExtensionNotFound {
            extension_id: "x".into(),
        },
        LifecycleError::ExtensionAlreadyExists {
            extension_id: "x".into(),
        },
        LifecycleError::BudgetExhausted {
            extension_id: "x".into(),
            remaining_millionths: 0,
            required_millionths: 1,
        },
        LifecycleError::GracePeriodExpired {
            extension_id: "x".into(),
            elapsed_ns: 10,
            budget_ns: 5,
        },
        LifecycleError::ManifestRejected {
            extension_id: "x".into(),
            reason: "bad".into(),
        },
        LifecycleError::Internal {
            detail: "oops".into(),
        },
    ];
    let codes: Vec<&str> = errors.iter().map(|e| e.error_code()).collect();
    // All codes should be distinct.
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(codes.len(), unique.len());
}

#[test]
fn error_display_contains_extension_id() {
    let err = LifecycleError::ExtensionNotFound {
        extension_id: "my-ext".into(),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("my-ext"),
        "Display should contain extension_id"
    );
}

#[test]
fn error_display_invalid_transition() {
    let err = LifecycleError::InvalidTransition {
        extension_id: "ext1".into(),
        current_state: ExtensionState::Running,
        attempted: LifecycleTransition::Validate,
    };
    let msg = format!("{err}");
    assert!(msg.contains("ext1"));
    assert!(msg.contains("running"));
    assert!(msg.contains("validate"));
}

#[test]
fn error_display_budget_exhausted() {
    let err = LifecycleError::BudgetExhausted {
        extension_id: "ext1".into(),
        remaining_millionths: 42,
        required_millionths: 100,
    };
    let msg = format!("{err}");
    assert!(msg.contains("42"));
    assert!(msg.contains("100"));
}

#[test]
fn error_display_grace_period_expired() {
    let err = LifecycleError::GracePeriodExpired {
        extension_id: "ext1".into(),
        elapsed_ns: 10_000,
        budget_ns: 5_000,
    };
    let msg = format!("{err}");
    assert!(msg.contains("10000"));
    assert!(msg.contains("5000"));
}

#[test]
fn error_display_manifest_rejected() {
    let err = LifecycleError::ManifestRejected {
        extension_id: "ext1".into(),
        reason: "invalid schema".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("invalid schema"));
}

#[test]
fn error_display_internal() {
    let err = LifecycleError::Internal {
        detail: "something broke".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("something broke"));
}

#[test]
fn error_serde_roundtrip() {
    let err = LifecycleError::BudgetExhausted {
        extension_id: "ext1".into(),
        remaining_millionths: 0,
        required_millionths: 1000,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: LifecycleError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ===========================================================================
// ResourceBudget
// ===========================================================================

#[test]
fn budget_new_sets_total_and_remaining_equal() {
    let b = ResourceBudget::new(500_000, 1024, 100);
    assert_eq!(b.cpu_remaining_millionths, 500_000);
    assert_eq!(b.cpu_total_millionths, 500_000);
    assert_eq!(b.memory_remaining_bytes, 1024);
    assert_eq!(b.memory_total_bytes, 1024);
    assert_eq!(b.hostcall_remaining, 100);
    assert_eq!(b.hostcall_total, 100);
}

#[test]
fn budget_consume_cpu_success_and_failure() {
    let mut b = ResourceBudget::new(100, 1024, 10);
    assert!(b.consume_cpu(60));
    assert_eq!(b.cpu_remaining_millionths, 40);
    assert!(b.consume_cpu(40));
    assert_eq!(b.cpu_remaining_millionths, 0);
    assert!(!b.consume_cpu(1));
    assert_eq!(b.cpu_remaining_millionths, 0);
}

#[test]
fn budget_consume_memory_success_and_failure() {
    let mut b = ResourceBudget::new(100, 200, 10);
    assert!(b.consume_memory(150));
    assert_eq!(b.memory_remaining_bytes, 50);
    assert!(!b.consume_memory(51));
    assert_eq!(b.memory_remaining_bytes, 50);
}

#[test]
fn budget_consume_hostcall_success_and_failure() {
    let mut b = ResourceBudget::new(100, 100, 2);
    assert!(b.consume_hostcall());
    assert!(b.consume_hostcall());
    assert!(!b.consume_hostcall());
    assert_eq!(b.hostcall_remaining, 0);
}

#[test]
fn budget_is_exhausted() {
    let mut b = ResourceBudget::new(100, 100, 100);
    assert!(!b.is_exhausted());
    b.cpu_remaining_millionths = 0;
    assert!(b.is_exhausted());
    b.cpu_remaining_millionths = 100;
    b.memory_remaining_bytes = 0;
    assert!(b.is_exhausted());
    b.memory_remaining_bytes = 100;
    b.hostcall_remaining = 0;
    assert!(b.is_exhausted());
}

#[test]
fn budget_cpu_utilization_zero_total() {
    let b = ResourceBudget::new(0, 100, 100);
    assert_eq!(b.cpu_utilization_millionths(), 0);
}

#[test]
fn budget_cpu_utilization_full_usage() {
    let mut b = ResourceBudget::new(1_000_000, 100, 100);
    b.consume_cpu(1_000_000);
    assert_eq!(b.cpu_utilization_millionths(), 1_000_000);
}

#[test]
fn budget_cpu_utilization_half_usage() {
    let mut b = ResourceBudget::new(1_000_000, 100, 100);
    b.consume_cpu(500_000);
    assert_eq!(b.cpu_utilization_millionths(), 500_000);
}

#[test]
fn budget_serde_roundtrip() {
    let b = ResourceBudget::new(42, 99, 7);
    let json = serde_json::to_string(&b).unwrap();
    let back: ResourceBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// CancellationConfig
// ===========================================================================

#[test]
fn cancellation_config_default() {
    let cc = CancellationConfig::default();
    assert_eq!(cc.grace_period_ns, 5_000_000_000);
    assert!(cc.force_on_timeout);
    assert!(cc.propagate_to_children);
}

#[test]
fn cancellation_config_clamped_within_max() {
    let cc = CancellationConfig {
        grace_period_ns: 1_000,
        force_on_timeout: false,
        propagate_to_children: false,
    }
    .clamped();
    assert_eq!(cc.grace_period_ns, 1_000);
}

#[test]
fn cancellation_config_clamped_exceeds_max() {
    let cc = CancellationConfig {
        grace_period_ns: 999_000_000_000,
        force_on_timeout: true,
        propagate_to_children: true,
    }
    .clamped();
    assert_eq!(cc.grace_period_ns, 30_000_000_000);
}

#[test]
fn cancellation_config_serde_roundtrip() {
    let cc = CancellationConfig::default();
    let json = serde_json::to_string(&cc).unwrap();
    let back: CancellationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cc, back);
}

// ===========================================================================
// ManifestRef
// ===========================================================================

#[test]
fn manifest_ref_construction_and_serde() {
    let mr = ManifestRef {
        extension_id: "my-ext".into(),
        capabilities: vec!["fs.read".into(), "net.connect".into()],
        max_lifetime_ns: 60_000_000_000,
        schema_version: 1,
    };
    let json = serde_json::to_string(&mr).unwrap();
    let back: ManifestRef = serde_json::from_str(&json).unwrap();
    assert_eq!(mr, back);
}

// ===========================================================================
// valid_transitions function
// ===========================================================================

#[test]
fn valid_transitions_from_unloaded() {
    let vt = valid_transitions(ExtensionState::Unloaded);
    assert!(vt.contains(&LifecycleTransition::Validate));
    assert!(!vt.contains(&LifecycleTransition::Load));
}

#[test]
fn valid_transitions_from_running() {
    let vt = valid_transitions(ExtensionState::Running);
    assert!(vt.contains(&LifecycleTransition::Suspend));
    assert!(vt.contains(&LifecycleTransition::Terminate));
    assert!(vt.contains(&LifecycleTransition::Quarantine));
    assert!(!vt.contains(&LifecycleTransition::Validate));
    assert!(!vt.contains(&LifecycleTransition::Load));
}

#[test]
fn valid_transitions_from_terminated() {
    let vt = valid_transitions(ExtensionState::Terminated);
    assert!(vt.is_empty());
}

#[test]
fn valid_transitions_from_quarantined() {
    let vt = valid_transitions(ExtensionState::Quarantined);
    assert!(vt.is_empty());
}

#[test]
fn valid_transitions_from_terminating() {
    let vt = valid_transitions(ExtensionState::Terminating);
    assert!(vt.contains(&LifecycleTransition::Finalize));
    assert!(vt.contains(&LifecycleTransition::Quarantine));
    assert_eq!(vt.len(), 2);
}

#[test]
fn valid_transitions_from_suspended() {
    let vt = valid_transitions(ExtensionState::Suspended);
    assert!(vt.contains(&LifecycleTransition::Resume));
    assert!(vt.contains(&LifecycleTransition::Terminate));
    assert!(vt.contains(&LifecycleTransition::Quarantine));
}

// ===========================================================================
// ExtensionLifecycleManager — basic registration
// ===========================================================================

#[test]
fn manager_new_is_empty() {
    let mgr = ExtensionLifecycleManager::new();
    assert!(mgr.extension_ids().is_empty());
    assert_eq!(mgr.clock_ns(), 0);
}

#[test]
fn manager_default_is_same_as_new() {
    let a = ExtensionLifecycleManager::new();
    let b = ExtensionLifecycleManager::default();
    assert_eq!(a.clock_ns(), b.clock_ns());
    assert_eq!(a.extension_ids().len(), b.extension_ids().len());
}

#[test]
fn register_extension_and_query_state() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext-a");
    assert_eq!(mgr.state("ext-a").unwrap(), ExtensionState::Unloaded);
    assert_eq!(mgr.extension_ids(), vec!["ext-a"]);
}

#[test]
fn register_duplicate_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext-a");
    let err = mgr
        .register("ext-a", default_budget(), CancellationConfig::default())
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_EXISTS");
}

#[test]
fn state_of_unknown_extension_fails() {
    let mgr = ExtensionLifecycleManager::new();
    let err = mgr.state("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn unregister_terminal_extension() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext-a");
    // Unloaded is terminal.
    mgr.unregister("ext-a").unwrap();
    assert!(mgr.extension_ids().is_empty());
}

#[test]
fn unregister_non_terminal_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext-a");
    advance_to_running(&mut mgr, "ext-a");
    let err = mgr.unregister("ext-a").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
}

#[test]
fn unregister_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let err = mgr.unregister("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Clock
// ===========================================================================

#[test]
fn advance_clock_and_query() {
    let mut mgr = ExtensionLifecycleManager::new();
    assert_eq!(mgr.clock_ns(), 0);
    let t1 = mgr.advance_clock(1_000_000);
    assert_eq!(t1, 1_000_000);
    assert_eq!(mgr.clock_ns(), 1_000_000);
    let t2 = mgr.advance_clock(500);
    assert_eq!(t2, 1_000_500);
}

#[test]
fn advance_clock_saturates() {
    let mut mgr = ExtensionLifecycleManager::new();
    mgr.advance_clock(u64::MAX);
    let t = mgr.advance_clock(1);
    assert_eq!(t, u64::MAX);
}

// ===========================================================================
// Happy path transitions
// ===========================================================================

#[test]
fn happy_path_unloaded_to_running() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Running);
}

#[test]
fn suspend_and_resume_cycle() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    mgr.transition("ext", LifecycleTransition::Suspend, "t2", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Suspending);

    mgr.transition("ext", LifecycleTransition::Freeze, "t2", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Suspended);

    mgr.transition("ext", LifecycleTransition::Resume, "t3", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Resuming);

    mgr.transition("ext", LifecycleTransition::Reactivate, "t3", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Running);
}

#[test]
fn terminate_and_finalize() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    mgr.transition("ext", LifecycleTransition::Terminate, "t4", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Terminating);

    mgr.transition("ext", LifecycleTransition::Finalize, "t4", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Terminated);
}

// ===========================================================================
// Failure path transitions
// ===========================================================================

#[test]
fn reject_manifest_returns_to_unloaded() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::RejectManifest, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Unloaded);
}

#[test]
fn load_failed_returns_to_unloaded() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::LoadFailed, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Unloaded);
}

#[test]
fn start_failed_returns_to_unloaded() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Start, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::StartFailed, "t", None)
        .unwrap();
    assert_eq!(mgr.state("ext").unwrap(), ExtensionState::Unloaded);
}

// ===========================================================================
// Invalid transitions
// ===========================================================================

#[test]
fn invalid_transition_from_unloaded() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    let err = mgr
        .transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
}

#[test]
fn transition_on_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let err = mgr
        .transition("nope", LifecycleTransition::Validate, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Quarantine transitions from various states
// ===========================================================================

#[test]
fn quarantine_from_running() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    let s = mgr
        .transition("ext", LifecycleTransition::Quarantine, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Quarantined);
}

#[test]
fn quarantine_from_suspended() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_suspended(&mut mgr, "ext");
    let s = mgr
        .transition("ext", LifecycleTransition::Quarantine, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Quarantined);
}

#[test]
fn quarantine_from_terminating() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    let s = mgr
        .transition("ext", LifecycleTransition::Quarantine, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Quarantined);
}

// ===========================================================================
// Terminate from all alive + suspend states
// ===========================================================================

#[test]
fn terminate_from_validating() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    let s = mgr
        .transition("ext", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminating);
}

#[test]
fn terminate_from_loading() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap();
    let s = mgr
        .transition("ext", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminating);
}

#[test]
fn terminate_from_suspended() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_suspended(&mut mgr, "ext");
    let s = mgr
        .transition("ext", LifecycleTransition::Terminate, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminating);
}

// ===========================================================================
// Budget enforcement — Start precondition
// ===========================================================================

#[test]
fn start_transition_fails_with_low_budget() {
    let mut mgr = ExtensionLifecycleManager::new();
    // Budget with cpu < MIN_START_BUDGET_MILLIONTHS (1000).
    mgr.register("ext", small_budget(), CancellationConfig::default())
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap();
    let err = mgr
        .transition("ext", LifecycleTransition::Start, "t", None)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
}

#[test]
fn start_transition_succeeds_with_exact_min_budget() {
    let mut mgr = ExtensionLifecycleManager::new();
    // Exactly 1000 millionths CPU.
    mgr.register(
        "ext",
        ResourceBudget::new(1_000, 1024, 100),
        CancellationConfig::default(),
    )
    .unwrap();
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    mgr.transition("ext", LifecycleTransition::Load, "t", None)
        .unwrap();
    let s = mgr
        .transition("ext", LifecycleTransition::Start, "t", None)
        .unwrap();
    assert_eq!(s, ExtensionState::Starting);
}

// ===========================================================================
// consume_cpu, consume_hostcall via manager
// ===========================================================================

#[test]
fn consume_cpu_via_manager() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.consume_cpu("ext", 100).unwrap();
    let b = mgr.budget("ext").unwrap();
    assert_eq!(b.cpu_remaining_millionths, 1_000_000 - 100);
}

#[test]
fn consume_cpu_insufficient_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    mgr.register(
        "ext",
        ResourceBudget::new(50, 1024, 100),
        CancellationConfig::default(),
    )
    .unwrap();
    let err = mgr.consume_cpu("ext", 51).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
}

#[test]
fn consume_cpu_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let err = mgr.consume_cpu("nope", 1).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn consume_hostcall_via_manager() {
    let mut mgr = ExtensionLifecycleManager::new();
    mgr.register(
        "ext",
        ResourceBudget::new(1_000_000, 1024, 2),
        CancellationConfig::default(),
    )
    .unwrap();
    mgr.consume_hostcall("ext").unwrap();
    mgr.consume_hostcall("ext").unwrap();
    let err = mgr.consume_hostcall("ext").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
}

#[test]
fn consume_hostcall_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let err = mgr.consume_hostcall("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Transition log
// ===========================================================================

#[test]
fn transition_log_records_transitions() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.advance_clock(100);
    mgr.transition(
        "ext",
        LifecycleTransition::Validate,
        "trace-1",
        Some("dec-1"),
    )
    .unwrap();

    let log = mgr.transition_log("ext").unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].sequence, 0);
    assert_eq!(log[0].timestamp_ns, 100);
    assert_eq!(log[0].from_state, ExtensionState::Unloaded);
    assert_eq!(log[0].to_state, ExtensionState::Validating);
    assert_eq!(log[0].transition, LifecycleTransition::Validate);
    assert_eq!(log[0].trace_id, "trace-1");
    assert_eq!(log[0].decision_id, Some("dec-1".to_string()));
}

#[test]
fn transition_log_sequence_monotonic() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    let log = mgr.transition_log("ext").unwrap();
    assert_eq!(log.len(), 4);
    for (i, rec) in log.iter().enumerate() {
        assert_eq!(rec.sequence, i as u64);
    }
}

#[test]
fn transition_log_unknown_extension_fails() {
    let mgr = ExtensionLifecycleManager::new();
    let err = mgr.transition_log("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Telemetry events
// ===========================================================================

#[test]
fn drain_events_returns_and_clears() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    let events = mgr.drain_events();
    assert!(!events.is_empty());
    let events2 = mgr.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn events_include_register_and_transitions() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "t", None)
        .unwrap();
    let events = mgr.drain_events();
    assert!(events.len() >= 2);
    assert_eq!(events[0].event, "register");
    assert_eq!(events[1].event, "validate");
    assert_eq!(events[1].from_state, Some("unloaded".to_string()));
    assert_eq!(events[1].to_state, Some("validating".to_string()));
}

#[test]
fn event_component_is_correct() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    let events = mgr.drain_events();
    for ev in &events {
        assert_eq!(ev.component, "extension_lifecycle_manager");
    }
}

// ===========================================================================
// Manifest
// ===========================================================================

#[test]
fn set_and_get_manifest() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    assert!(mgr.manifest("ext").unwrap().is_none());

    let mr = ManifestRef {
        extension_id: "ext".into(),
        capabilities: vec!["fs.read".into()],
        max_lifetime_ns: 0,
        schema_version: 1,
    };
    mgr.set_manifest("ext", mr.clone()).unwrap();
    let got = mgr.manifest("ext").unwrap().unwrap();
    assert_eq!(*got, mr);
}

#[test]
fn set_manifest_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let mr = ManifestRef {
        extension_id: "nope".into(),
        capabilities: vec![],
        max_lifetime_ns: 0,
        schema_version: 1,
    };
    let err = mgr.set_manifest("nope", mr).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

#[test]
fn manifest_unknown_extension_fails() {
    let mgr = ExtensionLifecycleManager::new();
    let err = mgr.manifest("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// Cancellation config
// ===========================================================================

#[test]
fn cancellation_config_from_registration() {
    let mut mgr = ExtensionLifecycleManager::new();
    let cc = CancellationConfig {
        grace_period_ns: 2_000_000_000,
        force_on_timeout: false,
        propagate_to_children: false,
    };
    mgr.register("ext", default_budget(), cc.clone()).unwrap();
    let got = mgr.cancellation_config("ext").unwrap();
    assert_eq!(*got, cc);
}

#[test]
fn cancellation_config_clamped_on_register() {
    let mut mgr = ExtensionLifecycleManager::new();
    let cc = CancellationConfig {
        grace_period_ns: 999_000_000_000,
        force_on_timeout: true,
        propagate_to_children: true,
    };
    mgr.register("ext", default_budget(), cc).unwrap();
    let got = mgr.cancellation_config("ext").unwrap();
    assert_eq!(got.grace_period_ns, 30_000_000_000);
}

#[test]
fn cancellation_config_unknown_extension_fails() {
    let mgr = ExtensionLifecycleManager::new();
    let err = mgr.cancellation_config("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// count_in_state
// ===========================================================================

#[test]
fn count_in_state_multiple_extensions() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "a");
    register(&mut mgr, "b");
    register(&mut mgr, "c");
    assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 3);
    advance_to_running(&mut mgr, "a");
    assert_eq!(mgr.count_in_state(ExtensionState::Running), 1);
    assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 2);
}

// ===========================================================================
// Cooperative shutdown
// ===========================================================================

#[test]
fn cooperative_shutdown_within_grace_period_finalize() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    let s = mgr
        .cooperative_shutdown("ext", "t", 1_000_000_000, false)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_within_grace_quarantine() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    // Within grace period (1s < 5s default), so shutdown succeeds -> Terminated
    // (quarantine_on_timeout only applies when grace period expires)
    let s = mgr
        .cooperative_shutdown("ext", "t", 1_000_000_000, true)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_expired_force_finalize() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    // Elapsed exceeds grace period (5s default), force_on_timeout is true.
    let s = mgr
        .cooperative_shutdown("ext", "t", 6_000_000_000, false)
        .unwrap();
    assert_eq!(s, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_expired_force_quarantine() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");

    let s = mgr
        .cooperative_shutdown("ext", "t", 6_000_000_000, true)
        .unwrap();
    assert_eq!(s, ExtensionState::Quarantined);
}

#[test]
fn cooperative_shutdown_expired_no_force_returns_error() {
    let mut mgr = ExtensionLifecycleManager::new();
    let cc = CancellationConfig {
        grace_period_ns: 1_000_000_000,
        force_on_timeout: false,
        propagate_to_children: true,
    };
    mgr.register("ext", default_budget(), cc).unwrap();
    advance_to_running(&mut mgr, "ext");

    let err = mgr
        .cooperative_shutdown("ext", "t", 2_000_000_000, false)
        .unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_GRACE_EXPIRED");
}

#[test]
fn cooperative_shutdown_from_already_terminating() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Terminate, "t", None)
        .unwrap();

    // Already in Terminating, should skip the initial Terminate transition.
    let s = mgr.cooperative_shutdown("ext", "t", 100, false).unwrap();
    assert_eq!(s, ExtensionState::Terminated);
}

#[test]
fn cooperative_shutdown_unknown_extension_fails() {
    let mut mgr = ExtensionLifecycleManager::new();
    let err = mgr.cooperative_shutdown("nope", "t", 0, false).unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}

// ===========================================================================
// enforce_budgets
// ===========================================================================

#[test]
fn enforce_budgets_terminates_exhausted_running_extensions() {
    let mut mgr = ExtensionLifecycleManager::new();
    mgr.register(
        "ext",
        ResourceBudget::new(1_000_000, 1024, 100),
        CancellationConfig::default(),
    )
    .unwrap();
    advance_to_running(&mut mgr, "ext");

    // Exhaust CPU.
    mgr.consume_cpu("ext", 1_000_000).unwrap();

    let results = mgr.enforce_budgets("enforce-trace");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "ext");
    assert_eq!(results[0].1, ExtensionState::Terminating);
}

#[test]
fn enforce_budgets_ignores_non_executing_extensions() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_suspended(&mut mgr, "ext");
    // Suspended is not is_executing(), so enforce_budgets should not touch it.
    let results = mgr.enforce_budgets("t");
    assert!(results.is_empty());
}

#[test]
fn enforce_budgets_skips_healthy_extensions() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    advance_to_running(&mut mgr, "ext");
    // Budget is fine.
    let results = mgr.enforce_budgets("t");
    assert!(results.is_empty());
}

// ===========================================================================
// Serde roundtrip of manager
// ===========================================================================

#[test]
fn manager_serde_roundtrip() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext-a");
    register(&mut mgr, "ext-b");
    advance_to_running(&mut mgr, "ext-a");
    mgr.advance_clock(999);
    mgr.drain_events();

    let json = serde_json::to_string(&mgr).unwrap();
    let back: ExtensionLifecycleManager = serde_json::from_str(&json).unwrap();
    assert_eq!(back.clock_ns(), 999);
    assert_eq!(back.state("ext-a").unwrap(), ExtensionState::Running);
    assert_eq!(back.state("ext-b").unwrap(), ExtensionState::Unloaded);
}

// ===========================================================================
// TransitionRecord serde
// ===========================================================================

#[test]
fn transition_record_serde_roundtrip() {
    let rec = TransitionRecord {
        sequence: 42,
        timestamp_ns: 1_000_000,
        from_state: ExtensionState::Running,
        to_state: ExtensionState::Suspending,
        transition: LifecycleTransition::Suspend,
        trace_id: "trace-abc".into(),
        decision_id: Some("dec-xyz".into()),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ===========================================================================
// LifecycleManagerEvent serde
// ===========================================================================

#[test]
fn lifecycle_manager_event_serde_roundtrip() {
    let ev = LifecycleManagerEvent {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: "extension_lifecycle_manager".into(),
        event: "validate".into(),
        outcome: "ok".into(),
        error_code: None,
        extension_id: "ext".into(),
        from_state: Some("unloaded".into()),
        to_state: Some("validating".into()),
        transition: Some("validate".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LifecycleManagerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// Decision ID propagation in transition
// ===========================================================================

#[test]
fn transition_with_decision_id_records_it() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition(
        "ext",
        LifecycleTransition::Validate,
        "trace",
        Some("decision-42"),
    )
    .unwrap();
    let log = mgr.transition_log("ext").unwrap();
    assert_eq!(log[0].decision_id, Some("decision-42".into()));
}

#[test]
fn transition_without_decision_id_records_none() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "ext");
    mgr.transition("ext", LifecycleTransition::Validate, "trace", None)
        .unwrap();
    let log = mgr.transition_log("ext").unwrap();
    assert_eq!(log[0].decision_id, None);
}

// ===========================================================================
// Extension IDs ordered (BTreeMap)
// ===========================================================================

#[test]
fn extension_ids_sorted() {
    let mut mgr = ExtensionLifecycleManager::new();
    register(&mut mgr, "zzz");
    register(&mut mgr, "aaa");
    register(&mut mgr, "mmm");
    let ids = mgr.extension_ids();
    assert_eq!(ids, vec!["aaa", "mmm", "zzz"]);
}

// ===========================================================================
// Budget query
// ===========================================================================

#[test]
fn budget_query_unknown_extension_fails() {
    let mgr = ExtensionLifecycleManager::new();
    let err = mgr.budget("nope").unwrap_err();
    assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
}
