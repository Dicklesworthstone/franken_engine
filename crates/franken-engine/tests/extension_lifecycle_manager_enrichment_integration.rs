//! Enrichment integration tests for `extension_lifecycle_manager` module.
//!
//! Covers: ExtensionState (11 states), LifecycleTransition (14 transitions),
//! LifecycleError, ResourceBudget, ManifestRef, CancellationConfig,
//! TransitionRecord, LifecycleManagerEvent — state classification, Display
//! uniqueness, transition Display uniqueness, ResourceBudget consumption,
//! budget utilization math, CancellationConfig clamping, error code uniqueness,
//! serde roundtrips.

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

use frankenengine_engine::extension_lifecycle_manager::*;

// ── helpers ──────────────────────────────────────────────────────────────

fn all_states() -> Vec<ExtensionState> {
    vec![
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
}

fn all_transitions() -> Vec<LifecycleTransition> {
    vec![
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
}

fn all_lifecycle_errors() -> Vec<LifecycleError> {
    vec![
        LifecycleError::InvalidTransition { extension_id: "x".to_string(), current_state: ExtensionState::Running, attempted: LifecycleTransition::Validate },
        LifecycleError::ExtensionNotFound { extension_id: "x".to_string() },
        LifecycleError::ExtensionAlreadyExists { extension_id: "x".to_string() },
        LifecycleError::BudgetExhausted { extension_id: "x".to_string(), remaining_millionths: 0, required_millionths: 1 },
        LifecycleError::GracePeriodExpired { extension_id: "x".to_string(), elapsed_ns: 10, budget_ns: 5 },
        LifecycleError::ManifestRejected { extension_id: "x".to_string(), reason: "bad".to_string() },
        LifecycleError::Internal { detail: "oops".to_string() },
    ]
}

// ── test: ExtensionState is_alive classification ─────────────────────────

#[test]
fn enrichment_state_is_alive_classification() {
    let alive = [ExtensionState::Running, ExtensionState::Starting, ExtensionState::Resuming, ExtensionState::Loading, ExtensionState::Validating];
    let not_alive = [ExtensionState::Unloaded, ExtensionState::Suspended, ExtensionState::Suspending, ExtensionState::Terminating, ExtensionState::Terminated, ExtensionState::Quarantined];
    for s in &alive { assert!(s.is_alive(), "{s} should be alive"); }
    for s in &not_alive { assert!(!s.is_alive(), "{s} should not be alive"); }
}

// ── test: ExtensionState is_terminal classification ──────────────────────

#[test]
fn enrichment_state_is_terminal_classification() {
    let terminal = [ExtensionState::Terminated, ExtensionState::Quarantined, ExtensionState::Unloaded];
    let non_terminal = [ExtensionState::Running, ExtensionState::Starting, ExtensionState::Suspending, ExtensionState::Suspended, ExtensionState::Loading, ExtensionState::Validating, ExtensionState::Resuming, ExtensionState::Terminating];
    for s in &terminal { assert!(s.is_terminal(), "{s} should be terminal"); }
    for s in &non_terminal { assert!(!s.is_terminal(), "{s} should not be terminal"); }
}

// ── test: ExtensionState is_executing classification ─────────────────────

#[test]
fn enrichment_state_is_executing_classification() {
    let executing = [ExtensionState::Running, ExtensionState::Starting, ExtensionState::Resuming];
    let not_executing = [ExtensionState::Unloaded, ExtensionState::Validating, ExtensionState::Loading, ExtensionState::Suspending, ExtensionState::Suspended, ExtensionState::Terminating, ExtensionState::Terminated, ExtensionState::Quarantined];
    for s in &executing { assert!(s.is_executing(), "{s} should be executing"); }
    for s in &not_executing { assert!(!s.is_executing(), "{s} should not be executing"); }
}

// ── test: ExtensionState Display uniqueness (all 11) ─────────────────────

#[test]
fn enrichment_state_display_all_unique() {
    let strs: BTreeSet<String> = all_states().iter().map(|s| s.to_string()).collect();
    assert_eq!(strs.len(), 11);
}

// ── test: ExtensionState as_str matches Display ──────────────────────────

#[test]
fn enrichment_state_as_str_matches_display() {
    for s in all_states() {
        assert_eq!(s.as_str(), s.to_string());
    }
}

// ── test: LifecycleTransition Display uniqueness (all 14) ────────────────

#[test]
fn enrichment_transition_display_all_unique() {
    let strs: BTreeSet<String> = all_transitions().iter().map(|t| t.to_string()).collect();
    assert_eq!(strs.len(), 14);
}

// ── test: LifecycleTransition as_str matches Display ─────────────────────

#[test]
fn enrichment_transition_as_str_matches_display() {
    for t in all_transitions() {
        assert_eq!(t.as_str(), t.to_string());
    }
}

// ── test: LifecycleTransition is_failure ──────────────────────────────────

#[test]
fn enrichment_transition_is_failure() {
    let failures = [LifecycleTransition::RejectManifest, LifecycleTransition::LoadFailed, LifecycleTransition::StartFailed];
    let non_failures = [LifecycleTransition::Validate, LifecycleTransition::Load, LifecycleTransition::Start, LifecycleTransition::Activate, LifecycleTransition::Suspend, LifecycleTransition::Freeze, LifecycleTransition::Resume, LifecycleTransition::Reactivate, LifecycleTransition::Terminate, LifecycleTransition::Finalize, LifecycleTransition::Quarantine];
    for t in &failures { assert!(t.is_failure(), "{t} should be failure"); }
    for t in &non_failures { assert!(!t.is_failure(), "{t} should not be failure"); }
}

// ── test: ResourceBudget new and initial values ──────────────────────────

#[test]
fn enrichment_resource_budget_new_initial() {
    let b = ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000);
    assert_eq!(b.cpu_remaining_millionths, 1_000_000);
    assert_eq!(b.cpu_total_millionths, 1_000_000);
    assert_eq!(b.memory_remaining_bytes, 64 * 1024 * 1024);
    assert_eq!(b.memory_total_bytes, 64 * 1024 * 1024);
    assert_eq!(b.hostcall_remaining, 10_000);
    assert_eq!(b.hostcall_total, 10_000);
    assert!(!b.is_exhausted());
}

// ── test: ResourceBudget consume_cpu ─────────────────────────────────────

#[test]
fn enrichment_budget_consume_cpu() {
    let mut b = ResourceBudget::new(1_000_000, 1024, 100);
    assert!(b.consume_cpu(500_000));
    assert_eq!(b.cpu_remaining_millionths, 500_000);
    assert!(b.consume_cpu(500_000));
    assert_eq!(b.cpu_remaining_millionths, 0);
    assert!(!b.consume_cpu(1));
}

// ── test: ResourceBudget consume_memory ──────────────────────────────────

#[test]
fn enrichment_budget_consume_memory() {
    let mut b = ResourceBudget::new(1000, 1024, 100);
    assert!(b.consume_memory(512));
    assert_eq!(b.memory_remaining_bytes, 512);
    assert!(!b.consume_memory(600));
    assert_eq!(b.memory_remaining_bytes, 512);
}

// ── test: ResourceBudget consume_hostcall ────────────────────────────────

#[test]
fn enrichment_budget_consume_hostcall() {
    let mut b = ResourceBudget::new(1000, 1024, 3);
    assert!(b.consume_hostcall());
    assert!(b.consume_hostcall());
    assert!(b.consume_hostcall());
    assert!(!b.consume_hostcall());
    assert_eq!(b.hostcall_remaining, 0);
}

// ── test: ResourceBudget is_exhausted ────────────────────────────────────

#[test]
fn enrichment_budget_is_exhausted_any_dimension() {
    let mut b = ResourceBudget::new(1000, 1024, 100);
    assert!(!b.is_exhausted());

    b.cpu_remaining_millionths = 0;
    assert!(b.is_exhausted());

    b.cpu_remaining_millionths = 1;
    b.memory_remaining_bytes = 0;
    assert!(b.is_exhausted());

    b.memory_remaining_bytes = 1;
    b.hostcall_remaining = 0;
    assert!(b.is_exhausted());
}

// ── test: ResourceBudget cpu_utilization_millionths ───────────────────────

#[test]
fn enrichment_budget_cpu_utilization() {
    let mut b = ResourceBudget::new(1_000_000, 1024, 100);
    assert_eq!(b.cpu_utilization_millionths(), 0);
    b.consume_cpu(500_000);
    assert_eq!(b.cpu_utilization_millionths(), 500_000);
    b.consume_cpu(500_000);
    assert_eq!(b.cpu_utilization_millionths(), 1_000_000);
}

// ── test: ResourceBudget zero total utilization ──────────────────────────

#[test]
fn enrichment_budget_zero_total_utilization() {
    let b = ResourceBudget::new(0, 0, 0);
    assert_eq!(b.cpu_utilization_millionths(), 0);
}

// ── test: CancellationConfig default ─────────────────────────────────────

#[test]
fn enrichment_cancellation_config_default() {
    let cfg = CancellationConfig::default();
    assert_eq!(cfg.grace_period_ns, 5_000_000_000);
    assert!(cfg.force_on_timeout);
    assert!(cfg.propagate_to_children);
}

// ── test: CancellationConfig clamped ─────────────────────────────────────

#[test]
fn enrichment_cancellation_config_clamped() {
    let cfg = CancellationConfig {
        grace_period_ns: 999_000_000_000,
        force_on_timeout: true,
        propagate_to_children: true,
    }.clamped();
    assert_eq!(cfg.grace_period_ns, 30_000_000_000);
}

// ── test: CancellationConfig within range not clamped ────────────────────

#[test]
fn enrichment_cancellation_config_within_range() {
    let cfg = CancellationConfig {
        grace_period_ns: 10_000_000_000,
        force_on_timeout: false,
        propagate_to_children: false,
    }.clamped();
    assert_eq!(cfg.grace_period_ns, 10_000_000_000);
    assert!(!cfg.force_on_timeout);
}

// ── test: LifecycleError error_code uniqueness ───────────────────────────

#[test]
fn enrichment_error_code_uniqueness() {
    let codes: BTreeSet<String> = all_lifecycle_errors().iter().map(|e| e.error_code().to_string()).collect();
    assert_eq!(codes.len(), 7);
}

// ── test: LifecycleError error_code stable values ────────────────────────

#[test]
fn enrichment_error_code_stable_values() {
    assert_eq!(LifecycleError::InvalidTransition { extension_id: "x".to_string(), current_state: ExtensionState::Running, attempted: LifecycleTransition::Validate }.error_code(), "LIFECYCLE_INVALID_TRANSITION");
    assert_eq!(LifecycleError::ExtensionNotFound { extension_id: "x".to_string() }.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
    assert_eq!(LifecycleError::ExtensionAlreadyExists { extension_id: "x".to_string() }.error_code(), "LIFECYCLE_EXTENSION_EXISTS");
    assert_eq!(LifecycleError::BudgetExhausted { extension_id: "x".to_string(), remaining_millionths: 0, required_millionths: 1 }.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
    assert_eq!(LifecycleError::GracePeriodExpired { extension_id: "x".to_string(), elapsed_ns: 0, budget_ns: 0 }.error_code(), "LIFECYCLE_GRACE_EXPIRED");
    assert_eq!(LifecycleError::ManifestRejected { extension_id: "x".to_string(), reason: "b".to_string() }.error_code(), "LIFECYCLE_MANIFEST_REJECTED");
    assert_eq!(LifecycleError::Internal { detail: "d".to_string() }.error_code(), "LIFECYCLE_INTERNAL");
}

// ── test: LifecycleError Display all unique ──────────────────────────────

#[test]
fn enrichment_lifecycle_error_display_all_unique() {
    let strs: BTreeSet<String> = all_lifecycle_errors().iter().map(|e| e.to_string()).collect();
    assert_eq!(strs.len(), 7);
}

// ── test: LifecycleError Display content ─────────────────────────────────

#[test]
fn enrichment_lifecycle_error_display_content() {
    let err = LifecycleError::InvalidTransition { extension_id: "ext-a".to_string(), current_state: ExtensionState::Running, attempted: LifecycleTransition::Validate };
    let msg = err.to_string();
    assert!(msg.contains("ext-a"));
    assert!(msg.contains("running"));
    assert!(msg.contains("validate"));
}

// ── test: serde roundtrip ExtensionState all 11 ──────────────────────────

#[test]
fn enrichment_serde_extension_state_all() {
    for s in all_states() {
        let json = serde_json::to_string(&s).unwrap();
        let back: ExtensionState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── test: serde roundtrip LifecycleTransition all 14 ─────────────────────

#[test]
fn enrichment_serde_lifecycle_transition_all() {
    for t in all_transitions() {
        let json = serde_json::to_string(&t).unwrap();
        let back: LifecycleTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ── test: serde roundtrip LifecycleError all 7 ───────────────────────────

#[test]
fn enrichment_serde_lifecycle_error_all() {
    for err in all_lifecycle_errors() {
        let json = serde_json::to_string(&err).unwrap();
        let back: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ── test: serde roundtrip ResourceBudget ─────────────────────────────────

#[test]
fn enrichment_serde_resource_budget() {
    let b = ResourceBudget::new(500_000, 2048, 50);
    let json = serde_json::to_string(&b).unwrap();
    let back: ResourceBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ── test: serde roundtrip CancellationConfig ─────────────────────────────

#[test]
fn enrichment_serde_cancellation_config() {
    let cfg = CancellationConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CancellationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ── test: serde roundtrip ManifestRef ────────────────────────────────────

#[test]
fn enrichment_serde_manifest_ref() {
    let m = ManifestRef {
        extension_id: "ext-a".to_string(),
        capabilities: vec!["fs.read".to_string(), "net.send".to_string()],
        max_lifetime_ns: 3_600_000_000_000,
        schema_version: 1,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ManifestRef = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ── test: serde roundtrip TransitionRecord ───────────────────────────────

#[test]
fn enrichment_serde_transition_record() {
    let rec = TransitionRecord {
        sequence: 42,
        timestamp_ns: 1_000_000,
        from_state: ExtensionState::Running,
        to_state: ExtensionState::Suspending,
        transition: LifecycleTransition::Suspend,
        trace_id: "trace-1".to_string(),
        decision_id: Some("dec-1".to_string()),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ── test: serde roundtrip LifecycleManagerEvent ──────────────────────────

#[test]
fn enrichment_serde_lifecycle_manager_event() {
    let evt = LifecycleManagerEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "extension_lifecycle_manager".to_string(),
        event: "validate".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: "ext-a".to_string(),
        from_state: Some("unloaded".to_string()),
        to_state: Some("validating".to_string()),
        transition: Some("validate".to_string()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: LifecycleManagerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// ── test: ExtensionState ordering ────────────────────────────────────────

#[test]
fn enrichment_extension_state_ordering() {
    assert!(ExtensionState::Unloaded < ExtensionState::Validating);
    assert!(ExtensionState::Running < ExtensionState::Suspending);
    assert!(ExtensionState::Terminated < ExtensionState::Quarantined);
}

// ── test: LifecycleTransition ordering ───────────────────────────────────

#[test]
fn enrichment_lifecycle_transition_ordering() {
    assert!(LifecycleTransition::Validate < LifecycleTransition::Load);
    assert!(LifecycleTransition::Terminate < LifecycleTransition::Finalize);
}

// ── test: ResourceBudget clone independence ──────────────────────────────

#[test]
fn enrichment_budget_clone_independence() {
    let b = ResourceBudget::new(1_000_000, 1024, 100);
    let mut cloned = b.clone();
    cloned.cpu_remaining_millionths = 0;
    assert_eq!(b.cpu_remaining_millionths, 1_000_000);
    assert_eq!(cloned.cpu_remaining_millionths, 0);
}

// ── test: valid_transitions from Unloaded ────────────────────────────────

#[test]
fn enrichment_valid_transitions_from_unloaded() {
    let valid = valid_transitions(ExtensionState::Unloaded);
    assert!(valid.contains(&LifecycleTransition::Validate));
    assert!(!valid.contains(&LifecycleTransition::Activate));
}

// ── test: valid_transitions from Terminated is empty ─────────────────────

#[test]
fn enrichment_valid_transitions_from_terminated_empty() {
    let valid = valid_transitions(ExtensionState::Terminated);
    assert!(valid.is_empty());
}

// ── test: valid_transitions from Running includes Suspend/Terminate/Quarantine ──

#[test]
fn enrichment_valid_transitions_from_running() {
    let valid = valid_transitions(ExtensionState::Running);
    assert!(valid.contains(&LifecycleTransition::Suspend));
    assert!(valid.contains(&LifecycleTransition::Terminate));
    assert!(valid.contains(&LifecycleTransition::Quarantine));
    assert!(!valid.contains(&LifecycleTransition::Validate));
}
