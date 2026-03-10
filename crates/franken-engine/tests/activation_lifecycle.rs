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

use std::collections::BTreeSet;

use frankenengine_engine::activation_lifecycle::{
    ActivationLifecycleController, ActivationValidation, ComponentDescriptor, EphemeralSecret,
    KnownGoodPin, LifecycleConfig, LifecycleError, LifecycleState, PreActivationCheck,
    RolloutPhase, TransitionTrigger,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_controller() -> ActivationLifecycleController {
    ActivationLifecycleController::new(LifecycleConfig::default(), "integration-zone")
}

fn descriptor(id: &str, version: &str) -> ComponentDescriptor {
    ComponentDescriptor {
        component_id: id.to_string(),
        version: version.to_string(),
        version_hash: format!("hash-{version}"),
        capabilities_required: BTreeSet::new(),
    }
}

fn passing_validation(id: &str, version: &str) -> ActivationValidation {
    ActivationValidation::from_checks(
        id,
        version,
        vec![
            PreActivationCheck {
                check_name: "signature".to_string(),
                passed: true,
                detail: "valid".to_string(),
            },
            PreActivationCheck {
                check_name: "revocation".to_string(),
                passed: true,
                detail: "not revoked".to_string(),
            },
        ],
    )
}

fn activate(ctrl: &mut ActivationLifecycleController, id: &str, version: &str) {
    ctrl.register(descriptor(id, version), "trace-integ")
        .unwrap();
    ctrl.begin_activation(id, &passing_validation(id, version), "trace-integ")
        .unwrap();
    ctrl.inject_secrets(
        id,
        &[EphemeralSecret::new("session_key", vec![0xAA, 0xBB])],
        "trace-integ",
    )
    .unwrap();
    ctrl.complete_activation(id, 1, "trace-integ").unwrap();
}

fn full_rollout(ctrl: &mut ActivationLifecycleController, id: &str) {
    ctrl.advance_rollout(id, "trace-integ").unwrap(); // canary
    ctrl.advance_rollout(id, "trace-integ").unwrap(); // ramp
    ctrl.advance_rollout(id, "trace-integ").unwrap(); // default
    ctrl.advance_rollout(id, "trace-integ").unwrap(); // past default -> active
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_activate_update_rollout_complete() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    // Activate v1.
    activate(&mut ctrl, "ext-a", "1.0.0");
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-a").unwrap().version, "1.0.0");

    // Update to v2 with full staged rollout.
    ctrl.set_tick(100);
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 2, "trace-integ")
        .unwrap();
    assert_eq!(
        ctrl.state("ext-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );

    ctrl.advance_rollout("ext-a", "trace-integ").unwrap();
    assert_eq!(
        ctrl.state("ext-a"),
        Some(LifecycleState::Updating(RolloutPhase::Canary))
    );

    ctrl.advance_rollout("ext-a", "trace-integ").unwrap();
    assert_eq!(
        ctrl.state("ext-a"),
        Some(LifecycleState::Updating(RolloutPhase::Ramp))
    );

    ctrl.advance_rollout("ext-a", "trace-integ").unwrap();
    assert_eq!(
        ctrl.state("ext-a"),
        Some(LifecycleState::Updating(RolloutPhase::Default))
    );

    ctrl.advance_rollout("ext-a", "trace-integ").unwrap();
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-a").unwrap().version, "2.0.0");
}

#[test]
fn crash_loop_auto_rollback_preserves_security_state() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    // Activate v1, then update to v2.
    activate(&mut ctrl, "ext-a", "1.0.0");
    ctrl.set_tick(100);
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 5, "trace-integ")
        .unwrap();
    ctrl.advance_rollout("ext-a", "trace-integ").unwrap(); // canary

    // Crash 3x to trigger auto-rollback.
    ctrl.set_tick(101);
    assert!(ctrl.report_crash("ext-a", "trace-integ").unwrap().is_none());
    ctrl.set_tick(102);
    assert!(ctrl.report_crash("ext-a", "trace-integ").unwrap().is_none());
    ctrl.set_tick(103);
    let pin = ctrl
        .report_crash("ext-a", "trace-integ")
        .unwrap()
        .expect("crash-loop should trigger rollback");

    // Verify rollback restores known-good v1.
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.component_version("ext-a"), "1.0.0");

    // Verify crash-loop event was emitted.
    let events = ctrl.drain_events();
    assert!(
        events
            .iter()
            .any(|e| e.trigger.as_deref() == Some("crash_loop"))
    );
}

#[test]
fn update_preserves_checkpoint_monotonicity() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    // Activate with checkpoint_seq=10.
    ctrl.register(descriptor("ext-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-a", &passing_validation("ext-a", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("ext-a", &[], "t").unwrap();
    ctrl.complete_activation("ext-a", 10, "t").unwrap();

    // Try update with checkpoint_seq=5 (regression) -> must fail.
    let err = ctrl
        .begin_update("ext-a", descriptor("ext-a", "2.0.0"), 5, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::CheckpointRegression { .. }));

    // Update with checkpoint_seq=15 (advancement) -> must succeed.
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 15, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("ext-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn multi_component_lifecycle_isolation() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    activate(&mut ctrl, "ext-a", "1.0.0");
    activate(&mut ctrl, "ext-b", "1.0.0");
    activate(&mut ctrl, "ext-c", "1.0.0");

    // Update ext-a, rollback ext-b, leave ext-c alone.
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 1, "t")
        .unwrap();
    full_rollout(&mut ctrl, "ext-a");

    ctrl.begin_update("ext-b", descriptor("ext-b", "2.0.0"), 1, "t")
        .unwrap();
    ctrl.rollback("ext-b", "t").unwrap();

    // Verify each component state is independent.
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-a").unwrap().version, "2.0.0");
    assert_eq!(ctrl.state("ext-b"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-b").unwrap().version, "1.0.0");
    assert_eq!(ctrl.state("ext-c"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-c").unwrap().version, "1.0.0");
    assert_eq!(ctrl.active_count(), 3);
}

#[test]
fn rollback_at_every_rollout_phase() {
    for advance_count in 0..=2 {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate(&mut ctrl, "ext-a", "1.0.0");

        ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 1, "t")
            .unwrap();
        for _ in 0..advance_count {
            ctrl.advance_rollout("ext-a", "t").unwrap();
        }

        let pin = ctrl.rollback("ext-a", "t").unwrap();
        assert_eq!(
            pin.version, "1.0.0",
            "rollback at advance_count={advance_count} must restore v1"
        );
        assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    }
}

#[test]
fn full_lifecycle_scenario_with_recovery() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    // 1. Activate ext-a v1.
    activate(&mut ctrl, "ext-a", "1.0.0");

    // 2. Update to v2, crash-loop rollback.
    ctrl.set_tick(100);
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("ext-a", "t").unwrap(); // canary
    ctrl.set_tick(101);
    ctrl.report_crash("ext-a", "t").unwrap();
    ctrl.set_tick(102);
    ctrl.report_crash("ext-a", "t").unwrap();
    ctrl.set_tick(103);
    let pin = ctrl.report_crash("ext-a", "t").unwrap().unwrap();
    assert_eq!(pin.version, "1.0.0");

    // 3. Rollback holdoff: immediate re-update fails.
    ctrl.set_tick(104);
    let err = ctrl
        .begin_update("ext-a", descriptor("ext-a", "3.0.0"), 3, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::RollbackHoldoffActive { .. }));

    // 4. Wait for holdoff, update to v3, complete rollout.
    ctrl.set_tick(103 + 30); // DEFAULT_ROLLBACK_HOLDOFF_TICKS=30
    ctrl.begin_update("ext-a", descriptor("ext-a", "3.0.0"), 3, "t")
        .unwrap();
    full_rollout(&mut ctrl, "ext-a");
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-a").unwrap().version, "3.0.0");

    // 5. Deactivate.
    ctrl.deactivate("ext-a", "t").unwrap();
    assert_eq!(ctrl.state("ext-a"), Some(LifecycleState::Inactive));
}

#[test]
fn audit_trail_covers_full_lifecycle() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    activate(&mut ctrl, "ext-a", "1.0.0");
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 1, "t")
        .unwrap();
    full_rollout(&mut ctrl, "ext-a");

    let events = ctrl.drain_events();
    // Must have: register, transition(inactive->pending), secrets, transition(pending->active),
    // update_started, transition(shadow->canary), transition(canary->ramp), transition(ramp->active).
    assert!(
        events.len() >= 8,
        "expected at least 8 events, got {}",
        events.len()
    );

    // All events have component field set to activation_lifecycle.
    assert!(events.iter().all(|e| e.component == "activation_lifecycle"));

    // All transition events have from_state and to_state.
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    for t in &transitions {
        assert!(t.from_state.is_some());
        assert!(t.to_state.is_some());
        assert!(t.trigger.is_some());
    }
}

#[test]
fn ephemeral_secret_lifecycle() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);

    ctrl.register(descriptor("ext-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-a", &passing_validation("ext-a", "1.0.0"), "t")
        .unwrap();

    let secrets = vec![
        EphemeralSecret::new("session_key", vec![0xDE, 0xAD]),
        EphemeralSecret::new("encryption_key", vec![0xBE, 0xEF]),
    ];

    // Verify secret values before injection.
    assert_eq!(secrets[0].value(), &[0xDE, 0xAD]);
    assert_eq!(secrets[1].value(), &[0xBE, 0xEF]);

    let receipt = ctrl.inject_secrets("ext-a", &secrets, "t").unwrap();
    assert_eq!(receipt.injected_keys.len(), 2);
    assert_eq!(receipt.injected_keys[0], "session_key");
    assert_eq!(receipt.injected_keys[1], "encryption_key");

    // Secret debug output is redacted.
    let debug = format!("{:?}", secrets[0]);
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("222")); // 0xDE decimal

    // Secret can be consumed via take().
    let taken = EphemeralSecret::new("temp", vec![1, 2, 3]).take();
    assert_eq!(taken, vec![1, 2, 3]);
}

#[test]
fn serde_roundtrip_lifecycle_event_stream() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "ext-a", "1.0.0");
    ctrl.begin_update("ext-a", descriptor("ext-a", "2.0.0"), 1, "t")
        .unwrap();
    ctrl.rollback("ext-a", "t").unwrap();

    let events = ctrl.drain_events();
    let json = serde_json::to_string(&events).unwrap();
    let deser: Vec<frankenengine_engine::activation_lifecycle::LifecycleEvent> =
        serde_json::from_str(&json).unwrap();
    assert_eq!(events.len(), deser.len());
    assert_eq!(events, deser);
}

#[test]
fn known_good_pin_serde_roundtrip() {
    use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
    let pin = KnownGoodPin {
        component_id: "ext-a".to_string(),
        version: "1.0.0".to_string(),
        version_hash: "hash-1.0.0".to_string(),
        activated_at: DeterministicTimestamp(100),
        health_check_passed_at: DeterministicTimestamp(101),
    };
    let json = serde_json::to_string(&pin).unwrap();
    let deser: KnownGoodPin = serde_json::from_str(&json).unwrap();
    assert_eq!(pin, deser);
}

#[test]
fn error_codes_are_stable_across_variants() {
    use frankenengine_engine::activation_lifecycle::error_code;
    assert_eq!(
        error_code(&LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        }),
        "LC_INVALID_TRANSITION"
    );
    assert_eq!(
        error_code(&LifecycleError::CrashLoopDetected {
            component_id: "x".to_string(),
            crash_count: 3,
        }),
        "LC_CRASH_LOOP"
    );
    assert_eq!(
        error_code(&LifecycleError::CheckpointRegression {
            component_id: "x".to_string(),
        }),
        "LC_CHECKPOINT_REGRESSION"
    );
    assert_eq!(
        error_code(&LifecycleError::RevocationCheckFailed {
            detail: "x".to_string(),
        }),
        "LC_REVOCATION_FAILED"
    );
}

#[test]
fn rollout_phase_ordering() {
    // Verify the rollout pipeline ordering is deterministic.
    let phases = RolloutPhase::ALL;
    assert_eq!(phases[0], RolloutPhase::Shadow);
    assert_eq!(phases[1], RolloutPhase::Canary);
    assert_eq!(phases[2], RolloutPhase::Ramp);
    assert_eq!(phases[3], RolloutPhase::Default);
    assert!(RolloutPhase::Shadow < RolloutPhase::Default);
}

#[test]
fn transition_trigger_display_stable() {
    assert_eq!(TransitionTrigger::Manual.to_string(), "manual");
    assert_eq!(TransitionTrigger::Auto.to_string(), "auto");
    assert_eq!(TransitionTrigger::CrashLoop.to_string(), "crash_loop");
}

// ---------- serde roundtrips ----------

#[test]
fn rollout_phase_serde_roundtrip() {
    for phase in RolloutPhase::ALL {
        let json = serde_json::to_string(&phase).expect("serialize");
        let recovered: RolloutPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, phase);
    }
}

#[test]
fn transition_trigger_serde_roundtrip() {
    for trigger in [
        TransitionTrigger::Manual,
        TransitionTrigger::Auto,
        TransitionTrigger::CrashLoop,
    ] {
        let json = serde_json::to_string(&trigger).expect("serialize");
        let recovered: TransitionTrigger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, trigger);
    }
}

#[test]
fn lifecycle_config_serde_roundtrip() {
    let config = LifecycleConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: LifecycleConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, config);
}

#[test]
fn lifecycle_config_default_values() {
    let config = LifecycleConfig::default();
    assert_eq!(config.crash_threshold, 3);
    assert!(config.crash_window_ticks > 0);
    assert!(config.rollback_holdoff_ticks > 0);
}

#[test]
fn component_descriptor_serde_roundtrip() {
    let desc = descriptor("ext-serde", "1.0.0");
    let json = serde_json::to_string(&desc).expect("serialize");
    let recovered: ComponentDescriptor = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component_id, "ext-serde");
    assert_eq!(recovered.version, "1.0.0");
}

#[test]
fn lifecycle_error_is_std_error() {
    let err = LifecycleError::ComponentNotFound {
        component_id: "ext-missing".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(dyn_err.to_string().contains("ext-missing"));
}

#[test]
fn lifecycle_error_display_unique_variants() {
    let errors: Vec<LifecycleError> = vec![
        LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        },
        LifecycleError::ComponentNotFound {
            component_id: "x".to_string(),
        },
        LifecycleError::CheckpointRegression {
            component_id: "x".to_string(),
        },
        LifecycleError::RevocationCheckFailed {
            detail: "x".to_string(),
        },
    ];
    let messages: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(messages.len(), errors.len());
}

#[test]
fn lifecycle_state_display() {
    assert_eq!(LifecycleState::Inactive.to_string(), "inactive");
    assert_eq!(LifecycleState::Active.to_string(), "active");
    assert_eq!(
        LifecycleState::Updating(RolloutPhase::Shadow).to_string(),
        "updating:shadow"
    );
}

#[test]
fn rollout_phase_next_pipeline() {
    assert_eq!(RolloutPhase::Shadow.next(), Some(RolloutPhase::Canary));
    assert_eq!(RolloutPhase::Canary.next(), Some(RolloutPhase::Ramp));
    assert_eq!(RolloutPhase::Ramp.next(), Some(RolloutPhase::Default));
    assert_eq!(RolloutPhase::Default.next(), None);
}

#[test]
fn pre_activation_check_serde_roundtrip() {
    let check = PreActivationCheck {
        check_name: "signature".to_string(),
        passed: true,
        detail: "valid".to_string(),
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let recovered: PreActivationCheck = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, check);
}

#[test]
fn state_returns_none_for_unknown_component() {
    let ctrl = make_controller();
    assert_eq!(ctrl.state("nonexistent"), None);
}

#[test]
fn active_count_starts_at_zero() {
    let ctrl = make_controller();
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn double_register_same_id_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-a", "1.0.0"), "t").unwrap();
    let err = ctrl
        .register(descriptor("ext-a", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::ActivationValidationFailed { .. }
    ));
}

#[test]
fn deactivate_unknown_component_fails() {
    let mut ctrl = make_controller();
    let err = ctrl.deactivate("ghost", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn rollback_unknown_component_fails() {
    let mut ctrl = make_controller();
    let err = ctrl.rollback("ghost", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn known_good_returns_none_before_activation() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-a", "1.0.0"), "t").unwrap();
    assert!(ctrl.known_good("ext-a").is_none());
}

#[test]
fn lifecycle_config_default_crash_threshold_is_three() {
    let config = LifecycleConfig::default();
    assert_eq!(config.crash_threshold, 3);
}

#[test]
fn ephemeral_secret_key_name_is_accessible() {
    let secret = EphemeralSecret::new("api_key", vec![1, 2, 3]);
    assert_eq!(secret.key_name, "api_key");
}

#[test]
fn pre_activation_check_debug_is_nonempty() {
    let check = PreActivationCheck {
        check_name: "sig".to_string(),
        passed: true,
        detail: "ok".to_string(),
    };
    assert!(!format!("{check:?}").is_empty());
}

#[test]
fn rollout_phase_debug_is_nonempty() {
    for phase in [
        RolloutPhase::Shadow,
        RolloutPhase::Canary,
        RolloutPhase::Ramp,
        RolloutPhase::Default,
    ] {
        assert!(!format!("{phase:?}").is_empty());
    }
}

#[test]
fn lifecycle_config_debug_is_nonempty() {
    let config = LifecycleConfig::default();
    assert!(!format!("{config:?}").is_empty());
}
