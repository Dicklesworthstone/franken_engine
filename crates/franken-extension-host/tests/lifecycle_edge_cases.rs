use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CURRENT_ENGINE_VERSION, CancellationConfig, Capability,
    ExtensionLifecycleManager, ExtensionManifest, ExtensionState, LifecycleContext, LifecycleError,
    LifecycleTransition, ResourceBudget, allowed_lifecycle_transitions, compute_content_hash,
    lifecycle_target_state,
};
use std::collections::BTreeSet;

fn manifest() -> ExtensionManifest {
    let mut m = ExtensionManifest {
        name: "test-ext".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/main.js".to_string(),
        capabilities: BTreeSet::from([Capability::FsRead]),
        publisher_signature: Some(vec![1, 2, 3]),
        content_hash: [0; 32],
        trust_chain_ref: Some("chain/test".to_string()),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    };
    m.content_hash = compute_content_hash(&m).expect("hash");
    m
}

fn cx() -> LifecycleContext<'static> {
    LifecycleContext::new("trace-edge", "decision-edge", "policy-edge")
}

fn default_budget() -> ResourceBudget {
    ResourceBudget::new(10_000_000_000, 8 * 1024 * 1024, 1_000)
}

fn manager_at_state(state: ExtensionState) -> ExtensionLifecycleManager {
    let cx = cx();
    let mut m = ExtensionLifecycleManager::new(
        "edge-ext",
        default_budget(),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    m.set_validated_manifest(manifest()).expect("manifest");

    let steps: &[(LifecycleTransition, u64)] = match state {
        ExtensionState::Unloaded => &[],
        ExtensionState::Validating => &[(LifecycleTransition::Validate, 10)],
        ExtensionState::Loading => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
        ],
        ExtensionState::Starting => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
        ],
        ExtensionState::Running => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
        ],
        ExtensionState::Suspending => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
            (LifecycleTransition::Suspend, 50),
        ],
        ExtensionState::Suspended => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
            (LifecycleTransition::Suspend, 50),
            (LifecycleTransition::Freeze, 60),
        ],
        ExtensionState::Resuming => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
            (LifecycleTransition::Suspend, 50),
            (LifecycleTransition::Freeze, 60),
            (LifecycleTransition::Resume, 70),
        ],
        ExtensionState::Terminating => &[
            (LifecycleTransition::Validate, 10),
            (LifecycleTransition::Load, 20),
            (LifecycleTransition::Start, 30),
            (LifecycleTransition::Activate, 40),
            (LifecycleTransition::Terminate, 50),
        ],
        ExtensionState::Terminated | ExtensionState::Quarantined => {
            panic!("use explicit test setup for terminal states")
        }
    };

    for (transition, ts) in steps {
        m.apply_transition(*transition, *ts, &cx).unwrap();
    }
    assert_eq!(m.state(), state);
    m
}

// ───────────────────────────────────────────────────────────────
// lifecycle_target_state: valid transitions
// ───────────────────────────────────────────────────────────────

#[test]
fn target_state_happy_path_validate_to_terminated() {
    use ExtensionState as S;
    use LifecycleTransition as T;

    assert_eq!(
        lifecycle_target_state(S::Unloaded, T::Validate),
        Some(S::Validating)
    );
    assert_eq!(
        lifecycle_target_state(S::Validating, T::Load),
        Some(S::Loading)
    );
    assert_eq!(
        lifecycle_target_state(S::Loading, T::Start),
        Some(S::Starting)
    );
    assert_eq!(
        lifecycle_target_state(S::Starting, T::Activate),
        Some(S::Running)
    );
    assert_eq!(
        lifecycle_target_state(S::Running, T::Suspend),
        Some(S::Suspending)
    );
    assert_eq!(
        lifecycle_target_state(S::Suspending, T::Freeze),
        Some(S::Suspended)
    );
    assert_eq!(
        lifecycle_target_state(S::Suspended, T::Resume),
        Some(S::Resuming)
    );
    assert_eq!(
        lifecycle_target_state(S::Resuming, T::Reactivate),
        Some(S::Running)
    );
    assert_eq!(
        lifecycle_target_state(S::Running, T::Terminate),
        Some(S::Terminating)
    );
    assert_eq!(
        lifecycle_target_state(S::Terminating, T::Finalize),
        Some(S::Terminated)
    );
}

#[test]
fn target_state_terminate_from_any_active_state() {
    use ExtensionState as S;
    use LifecycleTransition as T;

    let terminable = [
        S::Validating,
        S::Loading,
        S::Starting,
        S::Running,
        S::Suspending,
        S::Suspended,
        S::Resuming,
    ];
    for state in terminable {
        assert_eq!(
            lifecycle_target_state(state, T::Terminate),
            Some(S::Terminating),
            "should be able to Terminate from {state:?}"
        );
    }
}

#[test]
fn target_state_quarantine_from_any_non_terminal_state() {
    use ExtensionState as S;
    use LifecycleTransition as T;

    let quarantinable = [
        S::Validating,
        S::Loading,
        S::Starting,
        S::Running,
        S::Suspending,
        S::Suspended,
        S::Resuming,
        S::Terminating,
    ];
    for state in quarantinable {
        assert_eq!(
            lifecycle_target_state(state, T::Quarantine),
            Some(S::Quarantined),
            "should be able to Quarantine from {state:?}"
        );
    }
}

#[test]
fn target_state_returns_none_for_invalid_transitions() {
    use ExtensionState as S;
    use LifecycleTransition as T;

    // Cannot load from unloaded (must validate first)
    assert_eq!(lifecycle_target_state(S::Unloaded, T::Load), None);
    // Cannot start from unloaded
    assert_eq!(lifecycle_target_state(S::Unloaded, T::Start), None);
    // Cannot validate from running
    assert_eq!(lifecycle_target_state(S::Running, T::Validate), None);
    // Cannot resume from running
    assert_eq!(lifecycle_target_state(S::Running, T::Resume), None);
    // Cannot do anything from terminal states
    assert_eq!(lifecycle_target_state(S::Terminated, T::Validate), None);
    assert_eq!(lifecycle_target_state(S::Terminated, T::Terminate), None);
    assert_eq!(lifecycle_target_state(S::Quarantined, T::Resume), None);
    assert_eq!(lifecycle_target_state(S::Quarantined, T::Terminate), None);
}

// ───────────────────────────────────────────────────────────────
// allowed_lifecycle_transitions
// ───────────────────────────────────────────────────────────────

#[test]
fn allowed_transitions_unloaded_only_validate() {
    let allowed = allowed_lifecycle_transitions(ExtensionState::Unloaded);
    assert_eq!(allowed, &[LifecycleTransition::Validate]);
}

#[test]
fn allowed_transitions_running_has_suspend_terminate_quarantine() {
    let allowed = allowed_lifecycle_transitions(ExtensionState::Running);
    assert!(allowed.contains(&LifecycleTransition::Suspend));
    assert!(allowed.contains(&LifecycleTransition::Terminate));
    assert!(allowed.contains(&LifecycleTransition::Quarantine));
    assert_eq!(allowed.len(), 3);
}

#[test]
fn allowed_transitions_terminal_states_are_empty() {
    assert!(allowed_lifecycle_transitions(ExtensionState::Terminated).is_empty());
    assert!(allowed_lifecycle_transitions(ExtensionState::Quarantined).is_empty());
}

#[test]
fn allowed_transitions_terminating_has_finalize_and_quarantine() {
    let allowed = allowed_lifecycle_transitions(ExtensionState::Terminating);
    assert!(allowed.contains(&LifecycleTransition::Finalize));
    assert!(allowed.contains(&LifecycleTransition::Quarantine));
    assert_eq!(allowed.len(), 2);
}

// ───────────────────────────────────────────────────────────────
// ExtensionState / LifecycleTransition display
// ───────────────────────────────────────────────────────────────

#[test]
fn extension_state_as_str_matches_display() {
    let states = [
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
    for state in states {
        assert_eq!(state.as_str(), format!("{state}"));
    }
}

#[test]
fn lifecycle_transition_as_str_matches_display() {
    let transitions = [
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
    for t in transitions {
        assert_eq!(t.as_str(), format!("{t}"));
    }
}

#[test]
fn budget_exhaustion_policy_as_str_matches_display() {
    assert_eq!(
        BudgetExhaustionPolicy::Suspend.as_str(),
        format!("{}", BudgetExhaustionPolicy::Suspend)
    );
    assert_eq!(
        BudgetExhaustionPolicy::Terminate.as_str(),
        format!("{}", BudgetExhaustionPolicy::Terminate)
    );
}

// ───────────────────────────────────────────────────────────────
// Invalid transition errors
// ───────────────────────────────────────────────────────────────

#[test]
fn invalid_transition_from_unloaded_returns_error() {
    let mut m = manager_at_state(ExtensionState::Unloaded);
    let err = m
        .apply_transition(LifecycleTransition::Start, 100, &cx())
        .expect_err("should fail");
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn invalid_transition_from_running_returns_error() {
    let mut m = manager_at_state(ExtensionState::Running);
    let err = m
        .apply_transition(LifecycleTransition::Validate, 100, &cx())
        .expect_err("should fail");
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ───────────────────────────────────────────────────────────────
// Non-monotonic timestamp rejection
// ───────────────────────────────────────────────────────────────

#[test]
fn non_monotonic_timestamp_is_rejected() {
    let mut m = manager_at_state(ExtensionState::Validating);
    // Validating was reached at ts=10; try ts=5
    let err = m
        .apply_transition(LifecycleTransition::Load, 5, &cx())
        .expect_err("should reject backward timestamp");
    assert!(matches!(
        err,
        LifecycleError::NonMonotonicTimestamp {
            previous: 10,
            current: 5
        }
    ));
}

#[test]
fn equal_timestamp_is_accepted() {
    let mut m = manager_at_state(ExtensionState::Validating);
    // Validating was reached at ts=10; ts=10 should be ok (>=)
    m.apply_transition(LifecycleTransition::Load, 10, &cx())
        .expect("equal timestamp should be accepted");
}

// ───────────────────────────────────────────────────────────────
// Missing manifest requirement
// ───────────────────────────────────────────────────────────────

#[test]
fn load_without_manifest_is_rejected() {
    let mut m = ExtensionLifecycleManager::new(
        "no-manifest-ext",
        default_budget(),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    // Validate doesn't require manifest
    m.apply_transition(LifecycleTransition::Validate, 10, &cx())
        .expect("validate ok without manifest");
    // Load requires manifest
    let err = m
        .apply_transition(LifecycleTransition::Load, 20, &cx())
        .expect_err("should fail without manifest");
    assert!(matches!(
        err,
        LifecycleError::MissingValidatedManifest { .. }
    ));
}

// ───────────────────────────────────────────────────────────────
// Budget exhaustion: suspend vs terminate policies
// ───────────────────────────────────────────────────────────────

#[test]
fn budget_exhaustion_with_suspend_policy_suspends_from_running() {
    let cx = cx();
    let mut m = ExtensionLifecycleManager::new(
        "budget-suspend",
        ResourceBudget::new(1_000_000, 8 * 1024 * 1024, 2),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    m.set_validated_manifest(manifest()).expect("manifest");
    m.apply_transition(LifecycleTransition::Validate, 10, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Load, 20, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Start, 30, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Activate, 40, &cx)
        .unwrap();

    assert_eq!(m.state(), ExtensionState::Running);

    // Consume first hostcall
    m.consume_hostcall(41, &cx).expect("ok");
    // Second hostcall exhausts budget (remaining=0)
    let err = m.consume_hostcall(42, &cx).expect_err("budget exhaustion");
    assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
    // Suspend policy from Running → Suspending
    assert_eq!(m.state(), ExtensionState::Suspending);
}

#[test]
fn budget_exhaustion_with_terminate_policy_terminates() {
    let cx = cx();
    let mut m = ExtensionLifecycleManager::new(
        "budget-term",
        ResourceBudget::new(1_000_000, 8 * 1024 * 1024, 2),
        BudgetExhaustionPolicy::Terminate,
        CancellationConfig::default(),
    );
    m.set_validated_manifest(manifest()).expect("manifest");
    m.apply_transition(LifecycleTransition::Validate, 10, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Load, 20, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Start, 30, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Activate, 40, &cx)
        .unwrap();

    m.consume_hostcall(41, &cx).expect("ok");
    let err = m.consume_hostcall(42, &cx).expect_err("budget exhaustion");
    assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
    assert_eq!(m.state(), ExtensionState::Terminating);
}

#[test]
fn cpu_budget_exhaustion_triggers_containment() {
    let cx = cx();
    let mut m = ExtensionLifecycleManager::new(
        "cpu-budget",
        ResourceBudget::new(100, 8 * 1024 * 1024, 1_000),
        BudgetExhaustionPolicy::Terminate,
        CancellationConfig::default(),
    );
    m.set_validated_manifest(manifest()).expect("manifest");
    m.apply_transition(LifecycleTransition::Validate, 10, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Load, 20, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Start, 30, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Activate, 40, &cx)
        .unwrap();

    // Consume 100 CPU ns, exactly exhausts budget
    let err = m
        .consume_cpu_time(100, 41, &cx)
        .expect_err("cpu exhaustion");
    assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
    assert_eq!(m.state(), ExtensionState::Terminating);
}

#[test]
fn memory_budget_exhaustion_triggers_containment() {
    let cx = cx();
    let mut m = ExtensionLifecycleManager::new(
        "mem-budget",
        ResourceBudget::new(10_000_000, 1024, 1_000),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    m.set_validated_manifest(manifest()).expect("manifest");
    m.apply_transition(LifecycleTransition::Validate, 10, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Load, 20, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Start, 30, &cx)
        .unwrap();
    m.apply_transition(LifecycleTransition::Activate, 40, &cx)
        .unwrap();

    let err = m
        .consume_memory_bytes(1024, 41, &cx)
        .expect_err("memory exhaustion");
    assert!(matches!(err, LifecycleError::BudgetExhausted { .. }));
    assert_eq!(m.state(), ExtensionState::Suspending);
}

// ───────────────────────────────────────────────────────────────
// Termination protocol
// ───────────────────────────────────────────────────────────────

#[test]
fn cooperative_termination_succeeds() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Terminating);
    // cooperative_ack=true, quarantine=false
    m.complete_termination(100, &cx, true, false)
        .expect("finalize");
    assert_eq!(m.state(), ExtensionState::Terminated);
}

#[test]
fn forced_termination_before_deadline_fails() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Terminating);
    // non-cooperative, within grace period → should fail
    let err = m
        .complete_termination(51, &cx, false, false)
        .expect_err("should fail before deadline");
    assert!(matches!(err, LifecycleError::TerminationPending { .. }));
    assert_eq!(m.state(), ExtensionState::Terminating);
}

#[test]
fn forced_termination_after_deadline_succeeds() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Terminating);
    // Wait past deadline
    let far_future = 50 + 10_000_000_001;
    m.complete_termination(far_future, &cx, false, false)
        .expect("should succeed after deadline");
    assert_eq!(m.state(), ExtensionState::Terminated);
}

#[test]
fn forced_termination_after_deadline_with_quarantine() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Terminating);
    let far_future = 50 + 10_000_000_001;
    m.complete_termination(far_future, &cx, false, true)
        .expect("quarantine after deadline");
    assert_eq!(m.state(), ExtensionState::Quarantined);
}

#[test]
fn complete_termination_from_non_terminating_state_fails() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Running);
    let err = m
        .complete_termination(100, &cx, true, false)
        .expect_err("should fail from running");
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ───────────────────────────────────────────────────────────────
// Suspend/resume cycle
// ───────────────────────────────────────────────────────────────

#[test]
fn suspend_resume_cycle_returns_to_running() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Running);

    m.apply_transition(LifecycleTransition::Suspend, 100, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Suspending);

    m.apply_transition(LifecycleTransition::Freeze, 110, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Suspended);

    m.apply_transition(LifecycleTransition::Resume, 120, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Resuming);

    m.apply_transition(LifecycleTransition::Reactivate, 130, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Running);
}

// ───────────────────────────────────────────────────────────────
// Quarantine from various states
// ───────────────────────────────────────────────────────────────

#[test]
fn quarantine_from_running() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Running);
    m.apply_transition(LifecycleTransition::Quarantine, 100, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Quarantined);
}

#[test]
fn quarantine_from_suspended() {
    let cx = cx();
    let mut m = manager_at_state(ExtensionState::Suspended);
    m.apply_transition(LifecycleTransition::Quarantine, 100, &cx)
        .unwrap();
    assert_eq!(m.state(), ExtensionState::Quarantined);
}

// ───────────────────────────────────────────────────────────────
// Transition log and telemetry
// ───────────────────────────────────────────────────────────────

#[test]
fn transition_log_records_all_transitions() {
    let m = manager_at_state(ExtensionState::Running);
    // Running = Validate(10) + Load(20) + Start(30) + Activate(40) = 4 transitions
    assert_eq!(m.transition_log().len(), 4);
}

#[test]
fn telemetry_events_match_transition_count() {
    let m = manager_at_state(ExtensionState::Running);
    assert_eq!(m.telemetry_events().len(), m.transition_log().len());
}

// ───────────────────────────────────────────────────────────────
// CancellationConfig clamping
// ───────────────────────────────────────────────────────────────

#[test]
fn cancellation_config_clamps_zero_to_one() {
    let config = CancellationConfig { grace_period_ns: 0 }.clamped();
    assert_eq!(config.grace_period_ns, 1);
}

// ───────────────────────────────────────────────────────────────
// Manager accessors
// ───────────────────────────────────────────────────────────────

#[test]
fn manager_accessors_return_expected_values() {
    let m = manager_at_state(ExtensionState::Running);
    assert_eq!(m.extension_id(), "edge-ext");
    assert_eq!(m.state(), ExtensionState::Running);
    assert!(m.validated_manifest().is_some());
    assert_eq!(m.validated_manifest().unwrap().name, "test-ext");
    assert!(m.pending_cancel_token().is_none());
}

#[test]
fn pending_cancel_token_present_in_terminating_state() {
    let m = manager_at_state(ExtensionState::Terminating);
    assert!(m.pending_cancel_token().is_some());
    assert!(m.pending_cancel_token().unwrap().starts_with("cancel:"));
}
