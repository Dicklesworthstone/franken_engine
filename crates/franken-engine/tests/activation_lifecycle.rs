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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::activation_lifecycle::{
    ActivationLifecycleController, ActivationValidation, ComponentDescriptor, CrashLoopDetector,
    EphemeralSecret, KnownGoodPin, LifecycleConfig, LifecycleError, LifecycleEvent, LifecycleState,
    PreActivationCheck, RolloutPhase, SecretInjectionReceipt, TransitionTrigger, error_code,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

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

// ===========================================================================
// Enrichment tests
// ===========================================================================

fn failing_validation(id: &str, version: &str) -> ActivationValidation {
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
                passed: false,
                detail: "revoked".to_string(),
            },
        ],
    )
}

fn descriptor_with_caps(id: &str, version: &str, caps: &[&str]) -> ComponentDescriptor {
    ComponentDescriptor {
        component_id: id.to_string(),
        version: version.to_string(),
        version_hash: format!("hash-{version}"),
        capabilities_required: caps.iter().map(|c| c.to_string()).collect(),
    }
}

// ---------------------------------------------------------------------------
// 1. Lifecycle state transitions (happy paths)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_transitions_to_inactive() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-r", "1.0.0"), "t").unwrap();
    assert_eq!(ctrl.state("ext-r"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.component_count(), 1);
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn enrichment_begin_activation_reaches_pending() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-p", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-p", &passing_validation("ext-p", "1.0.0"), "t")
        .unwrap();
    assert_eq!(ctrl.state("ext-p"), Some(LifecycleState::PendingActivation));
}

#[test]
fn enrichment_complete_activation_reaches_active() {
    let mut ctrl = make_controller();
    ctrl.set_tick(50);
    activate(&mut ctrl, "ext-c", "2.0.0");
    assert_eq!(ctrl.state("ext-c"), Some(LifecycleState::Active));
    let pin = ctrl.known_good("ext-c").unwrap();
    assert_eq!(pin.version, "2.0.0");
    assert_eq!(pin.activated_at, DeterministicTimestamp(50));
}

#[test]
fn enrichment_deactivate_returns_to_inactive() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-d", "1.0.0");
    ctrl.deactivate("ext-d", "t").unwrap();
    assert_eq!(ctrl.state("ext-d"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn enrichment_full_rollout_phases_in_order() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-ro", "1.0.0");
    ctrl.begin_update("ext-ro", descriptor("ext-ro", "2.0.0"), 2, "t")
        .unwrap();

    let expected_phases = [
        RolloutPhase::Shadow,
        RolloutPhase::Canary,
        RolloutPhase::Ramp,
        RolloutPhase::Default,
    ];

    // Currently at Shadow
    assert_eq!(
        ctrl.state("ext-ro"),
        Some(LifecycleState::Updating(expected_phases[0]))
    );

    // Advance through canary, ramp, default
    for &expected in &expected_phases[1..] {
        let phase = ctrl.advance_rollout("ext-ro", "t").unwrap();
        assert_eq!(phase, expected);
    }

    // Final advance past default -> active
    ctrl.advance_rollout("ext-ro", "t").unwrap();
    assert_eq!(ctrl.state("ext-ro"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("ext-ro").unwrap().version, "2.0.0");
}

#[test]
fn enrichment_update_then_complete_rollout_updates_known_good() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "ext-u", "1.0.0");
    assert_eq!(ctrl.known_good("ext-u").unwrap().version, "1.0.0");

    ctrl.set_tick(100);
    ctrl.begin_update("ext-u", descriptor("ext-u", "3.5.0"), 2, "t")
        .unwrap();
    full_rollout(&mut ctrl, "ext-u");
    assert_eq!(ctrl.known_good("ext-u").unwrap().version, "3.5.0");
    assert_eq!(ctrl.component_version("ext-u"), "3.5.0");
}

// ---------------------------------------------------------------------------
// 2. Invalid state transitions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_begin_activation_from_active_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-inv", "1.0.0");
    let err = ctrl
        .begin_activation("ext-inv", &passing_validation("ext-inv", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: LifecycleState::Active,
            to: LifecycleState::PendingActivation,
        }
    ));
}

#[test]
fn enrichment_begin_activation_from_pending_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-pp", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-pp", &passing_validation("ext-pp", "1.0.0"), "t")
        .unwrap();
    let err = ctrl
        .begin_activation("ext-pp", &passing_validation("ext-pp", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_complete_activation_from_inactive_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ca", "1.0.0"), "t").unwrap();
    let err = ctrl.complete_activation("ext-ca", 1, "t").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        }
    ));
}

#[test]
fn enrichment_complete_activation_from_active_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-ca2", "1.0.0");
    let err = ctrl.complete_activation("ext-ca2", 2, "t").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: LifecycleState::Active,
            to: LifecycleState::Active,
        }
    ));
}

#[test]
fn enrichment_begin_update_from_inactive_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ui", "1.0.0"), "t").unwrap();
    let err = ctrl
        .begin_update("ext-ui", descriptor("ext-ui", "2.0.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_begin_update_from_pending_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-up", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-up", &passing_validation("ext-up", "1.0.0"), "t")
        .unwrap();
    let err = ctrl
        .begin_update("ext-up", descriptor("ext-up", "2.0.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_begin_update_from_updating_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-uu", "1.0.0");
    ctrl.begin_update("ext-uu", descriptor("ext-uu", "2.0.0"), 2, "t")
        .unwrap();
    let err = ctrl
        .begin_update("ext-uu", descriptor("ext-uu", "3.0.0"), 3, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_deactivate_from_pending_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-dp", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-dp", &passing_validation("ext-dp", "1.0.0"), "t")
        .unwrap();
    let err = ctrl.deactivate("ext-dp", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_deactivate_from_updating_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-du", "1.0.0");
    ctrl.begin_update("ext-du", descriptor("ext-du", "2.0.0"), 2, "t")
        .unwrap();
    let err = ctrl.deactivate("ext-du", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_advance_rollout_from_active_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-ar", "1.0.0");
    let err = ctrl.advance_rollout("ext-ar", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_advance_rollout_from_inactive_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ari", "1.0.0"), "t").unwrap();
    let err = ctrl.advance_rollout("ext-ari", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_rollback_from_inactive_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ri", "1.0.0"), "t").unwrap();
    let err = ctrl.rollback("ext-ri", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_inject_secrets_from_inactive_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-si", "1.0.0"), "t").unwrap();
    let err = ctrl
        .inject_secrets("ext-si", &[EphemeralSecret::new("k", vec![1])], "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_inject_secrets_from_active_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-sa", "1.0.0");
    let err = ctrl
        .inject_secrets("ext-sa", &[EphemeralSecret::new("k", vec![1])], "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ---------------------------------------------------------------------------
// 3. Component-not-found errors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_begin_activation_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl
        .begin_activation("ghost", &passing_validation("ghost", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
    assert_eq!(error_code(&err), "LC_COMPONENT_NOT_FOUND");
}

#[test]
fn enrichment_inject_secrets_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.inject_secrets("ghost", &[], "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn enrichment_complete_activation_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.complete_activation("ghost", 1, "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn enrichment_begin_update_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl
        .begin_update("ghost", descriptor("ghost", "2.0.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn enrichment_advance_rollout_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.advance_rollout("ghost", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn enrichment_report_crash_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.report_crash("ghost", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

// ---------------------------------------------------------------------------
// 4. Crash loop detection and auto-rollback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_crash_below_threshold_no_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-cb", "1.0.0");
    ctrl.set_tick(10);
    assert!(ctrl.report_crash("ext-cb", "t").unwrap().is_none());
    ctrl.set_tick(11);
    assert!(ctrl.report_crash("ext-cb", "t").unwrap().is_none());
    assert_eq!(ctrl.state("ext-cb"), Some(LifecycleState::Active));
}

#[test]
fn enrichment_crash_at_threshold_triggers_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-ct", "1.0.0");
    ctrl.begin_update("ext-ct", descriptor("ext-ct", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.set_tick(10);
    ctrl.report_crash("ext-ct", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("ext-ct", "t").unwrap();
    ctrl.set_tick(12);
    let result = ctrl.report_crash("ext-ct", "t").unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().version, "1.0.0");
    assert_eq!(ctrl.state("ext-ct"), Some(LifecycleState::Active));
}

#[test]
fn enrichment_crash_loop_event_emitted() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-ce", "1.0.0");
    ctrl.begin_update("ext-ce", descriptor("ext-ce", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.drain_events();

    ctrl.set_tick(10);
    ctrl.report_crash("ext-ce", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("ext-ce", "t").unwrap();
    ctrl.set_tick(12);
    ctrl.report_crash("ext-ce", "t").unwrap();

    let events = ctrl.drain_events();
    assert!(
        events
            .iter()
            .any(|e| e.trigger.as_deref() == Some("crash_loop"))
    );
    assert!(events.iter().any(|e| e.event == "crash_reported"));
}

#[test]
fn enrichment_crashes_outside_window_do_not_accumulate() {
    let mut ctrl = make_controller(); // window = 60 ticks
    activate(&mut ctrl, "ext-cw", "1.0.0");
    ctrl.begin_update("ext-cw", descriptor("ext-cw", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(10);
    ctrl.report_crash("ext-cw", "t").unwrap();
    ctrl.set_tick(80); // 70 ticks later, outside window
    ctrl.report_crash("ext-cw", "t").unwrap();
    ctrl.set_tick(150); // 70 ticks later again
    let result = ctrl.report_crash("ext-cw", "t").unwrap();
    assert!(
        result.is_none(),
        "spaced-out crashes should not trigger loop"
    );
}

#[test]
fn enrichment_crash_loop_with_custom_threshold_two() {
    let mut ctrl = ActivationLifecycleController::new(
        LifecycleConfig {
            crash_threshold: 2,
            crash_window_ticks: 100,
            rollback_holdoff_ticks: 10,
        },
        "custom-zone",
    );
    activate(&mut ctrl, "ext-c2", "1.0.0");
    ctrl.begin_update("ext-c2", descriptor("ext-c2", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.set_tick(5);
    ctrl.report_crash("ext-c2", "t").unwrap();
    ctrl.set_tick(6);
    let result = ctrl.report_crash("ext-c2", "t").unwrap();
    assert!(result.is_some(), "threshold=2 should trigger on 2nd crash");
}

#[test]
fn enrichment_crash_loop_with_high_threshold() {
    let mut ctrl = ActivationLifecycleController::new(
        LifecycleConfig {
            crash_threshold: 5,
            crash_window_ticks: 200,
            rollback_holdoff_ticks: 10,
        },
        "custom-zone",
    );
    activate(&mut ctrl, "ext-ch", "1.0.0");
    ctrl.begin_update("ext-ch", descriptor("ext-ch", "2.0.0"), 2, "t")
        .unwrap();
    for i in 0..4 {
        ctrl.set_tick(10 + i);
        assert!(ctrl.report_crash("ext-ch", "t").unwrap().is_none());
    }
    ctrl.set_tick(14);
    let result = ctrl.report_crash("ext-ch", "t").unwrap();
    assert!(result.is_some(), "5th crash should trigger loop");
}

#[test]
fn enrichment_crash_on_inactive_component_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ci", "1.0.0"), "t").unwrap();
    let err = ctrl.report_crash("ext-ci", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_crash_loop_during_pending_no_known_good() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-cn", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-cn", &passing_validation("ext-cn", "1.0.0"), "t")
        .unwrap();

    ctrl.set_tick(1);
    ctrl.report_crash("ext-cn", "t").unwrap();
    ctrl.set_tick(2);
    ctrl.report_crash("ext-cn", "t").unwrap();
    ctrl.set_tick(3);
    let err = ctrl.report_crash("ext-cn", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
}

// ---------------------------------------------------------------------------
// 5. CrashLoopDetector standalone tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_crash_loop_detector_default_threshold() {
    let det = CrashLoopDetector::default();
    assert_eq!(det.crash_count(0), 0);
}

#[test]
fn enrichment_crash_loop_detector_record_and_check() {
    let mut det = CrashLoopDetector::new(3, 50);
    assert!(!det.record_crash(10));
    assert!(!det.record_crash(20));
    assert!(det.record_crash(30));
    assert_eq!(det.crash_count(30), 3);
}

#[test]
fn enrichment_crash_loop_detector_prune_on_record() {
    let mut det = CrashLoopDetector::new(3, 10);
    det.record_crash(1);
    det.record_crash(5);
    // At tick 20, cutoff = 10, so ticks 1 and 5 are pruned
    assert!(!det.record_crash(20));
    assert_eq!(det.crash_count(20), 1);
}

#[test]
fn enrichment_crash_loop_detector_reset_clears() {
    let mut det = CrashLoopDetector::new(3, 100);
    det.record_crash(10);
    det.record_crash(20);
    det.reset();
    assert_eq!(det.crash_count(30), 0);
    assert!(!det.record_crash(31));
}

#[test]
fn enrichment_crash_loop_detector_serde_roundtrip() {
    let mut det = CrashLoopDetector::new(4, 80);
    det.record_crash(5);
    det.record_crash(15);
    let json = serde_json::to_string(&det).unwrap();
    let rt: CrashLoopDetector = serde_json::from_str(&json).unwrap();
    assert_eq!(det, rt);
}

#[test]
fn enrichment_crash_loop_detector_count_outside_window() {
    let mut det = CrashLoopDetector::new(10, 50);
    det.record_crash(10);
    det.record_crash(20);
    det.record_crash(30);
    // At tick 1000, all are outside window
    assert_eq!(det.crash_count(1000), 0);
}

// ---------------------------------------------------------------------------
// 6. Rollback holdoff
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_holdoff_blocks_immediate_reupdate() {
    let mut ctrl = make_controller(); // holdoff = 30
    activate(&mut ctrl, "ext-rh", "1.0.0");
    ctrl.set_tick(100);
    ctrl.begin_update("ext-rh", descriptor("ext-rh", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.rollback("ext-rh", "t").unwrap();

    ctrl.set_tick(101);
    let err = ctrl
        .begin_update("ext-rh", descriptor("ext-rh", "3.0.0"), 3, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::RollbackHoldoffActive { .. }));
}

#[test]
fn enrichment_rollback_holdoff_expires_at_boundary() {
    let mut ctrl = make_controller(); // holdoff = 30
    activate(&mut ctrl, "ext-rhb", "1.0.0");
    ctrl.set_tick(100);
    ctrl.begin_update("ext-rhb", descriptor("ext-rhb", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.rollback("ext-rhb", "t").unwrap();

    ctrl.set_tick(130); // exactly at boundary
    ctrl.begin_update("ext-rhb", descriptor("ext-rhb", "3.0.0"), 3, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("ext-rhb"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn enrichment_rollback_holdoff_remaining_ticks_in_error() {
    let mut ctrl = make_controller(); // holdoff = 30
    activate(&mut ctrl, "ext-rhr", "1.0.0");
    ctrl.set_tick(100);
    ctrl.begin_update("ext-rhr", descriptor("ext-rhr", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.rollback("ext-rhr", "t").unwrap();

    ctrl.set_tick(115); // 15 ticks in, 15 remaining
    let err = ctrl
        .begin_update("ext-rhr", descriptor("ext-rhr", "3.0.0"), 3, "t")
        .unwrap_err();
    if let LifecycleError::RollbackHoldoffActive {
        remaining_ticks, ..
    } = err
    {
        assert_eq!(remaining_ticks, 15);
    } else {
        panic!("expected RollbackHoldoffActive");
    }
}

#[test]
fn enrichment_rollback_holdoff_custom_short_config() {
    let mut ctrl = ActivationLifecycleController::new(
        LifecycleConfig {
            crash_threshold: 3,
            crash_window_ticks: 60,
            rollback_holdoff_ticks: 5,
        },
        "short-holdoff-zone",
    );
    activate(&mut ctrl, "ext-rhs", "1.0.0");
    ctrl.set_tick(50);
    ctrl.begin_update("ext-rhs", descriptor("ext-rhs", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.rollback("ext-rhs", "t").unwrap();

    ctrl.set_tick(54);
    assert!(
        ctrl.begin_update("ext-rhs", descriptor("ext-rhs", "3.0.0"), 3, "t")
            .is_err()
    );
    ctrl.set_tick(55);
    assert!(
        ctrl.begin_update("ext-rhs", descriptor("ext-rhs", "3.0.0"), 3, "t")
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// 7. Checkpoint regression
// ---------------------------------------------------------------------------

#[test]
fn enrichment_checkpoint_regression_rejected() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-cr", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-cr", &passing_validation("ext-cr", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("ext-cr", &[], "t").unwrap();
    ctrl.complete_activation("ext-cr", 10, "t").unwrap();

    let err = ctrl
        .begin_update("ext-cr", descriptor("ext-cr", "2.0.0"), 5, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::CheckpointRegression { .. }));
    assert_eq!(error_code(&err), "LC_CHECKPOINT_REGRESSION");
}

#[test]
fn enrichment_checkpoint_equal_accepted() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ce2", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-ce2", &passing_validation("ext-ce2", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("ext-ce2", &[], "t").unwrap();
    ctrl.complete_activation("ext-ce2", 10, "t").unwrap();

    ctrl.begin_update("ext-ce2", descriptor("ext-ce2", "2.0.0"), 10, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("ext-ce2"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn enrichment_checkpoint_advancement_accepted() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ca3", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-ca3", &passing_validation("ext-ca3", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("ext-ca3", &[], "t").unwrap();
    ctrl.complete_activation("ext-ca3", 10, "t").unwrap();

    ctrl.begin_update("ext-ca3", descriptor("ext-ca3", "2.0.0"), 20, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("ext-ca3"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

// ---------------------------------------------------------------------------
// 8. Activation / deactivation / reactivation sequences
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deactivate_reactivate_cycle() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-dr", "1.0.0");
    ctrl.deactivate("ext-dr", "t").unwrap();
    assert_eq!(ctrl.state("ext-dr"), Some(LifecycleState::Inactive));

    ctrl.begin_activation("ext-dr", &passing_validation("ext-dr", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("ext-dr", &[EphemeralSecret::new("k2", vec![0xBB])], "t")
        .unwrap();
    ctrl.complete_activation("ext-dr", 2, "t").unwrap();
    assert_eq!(ctrl.state("ext-dr"), Some(LifecycleState::Active));
}

#[test]
fn enrichment_multiple_deactivate_reactivate_cycles() {
    let mut ctrl = make_controller();
    for cycle in 0..3u64 {
        activate(&mut ctrl, &format!("ext-mc{cycle}"), "1.0.0");
        ctrl.deactivate(&format!("ext-mc{cycle}"), "t").unwrap();
        ctrl.begin_activation(
            &format!("ext-mc{cycle}"),
            &passing_validation(&format!("ext-mc{cycle}"), "1.0.0"),
            "t",
        )
        .unwrap();
        ctrl.inject_secrets(&format!("ext-mc{cycle}"), &[], "t")
            .unwrap();
        ctrl.complete_activation(&format!("ext-mc{cycle}"), cycle + 2, "t")
            .unwrap();
        assert_eq!(
            ctrl.state(&format!("ext-mc{cycle}")),
            Some(LifecycleState::Active)
        );
    }
}

#[test]
fn enrichment_deactivation_clears_secrets_allows_fresh_injection() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ext-cs", "1.0.0");
    ctrl.deactivate("ext-cs", "t").unwrap();

    ctrl.begin_activation("ext-cs", &passing_validation("ext-cs", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl
        .inject_secrets("ext-cs", &[EphemeralSecret::new("fresh", vec![0xDD])], "t")
        .unwrap();
    assert_eq!(receipt.injected_keys, vec!["fresh"]);
}

// ---------------------------------------------------------------------------
// 9. Multi-component isolation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multi_component_independent_states() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "iso-a", "1.0.0");
    activate(&mut ctrl, "iso-b", "1.0.0");
    activate(&mut ctrl, "iso-c", "1.0.0");

    ctrl.begin_update("iso-a", descriptor("iso-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.deactivate("iso-c", "t").unwrap();

    assert_eq!(
        ctrl.state("iso-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
    assert_eq!(ctrl.state("iso-b"), Some(LifecycleState::Active));
    assert_eq!(ctrl.state("iso-c"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.active_count(), 1);
}

#[test]
fn enrichment_crash_in_one_component_does_not_affect_others() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "crash-a", "1.0.0");
    activate(&mut ctrl, "crash-b", "1.0.0");

    ctrl.begin_update("crash-a", descriptor("crash-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(10);
    ctrl.report_crash("crash-a", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("crash-a", "t").unwrap();
    ctrl.set_tick(12);
    ctrl.report_crash("crash-a", "t").unwrap(); // triggers rollback

    assert_eq!(ctrl.state("crash-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("crash-a").unwrap().version, "1.0.0");
    assert_eq!(ctrl.state("crash-b"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("crash-b").unwrap().version, "1.0.0");
}

#[test]
fn enrichment_many_components_batch_operations() {
    let mut ctrl = make_controller();
    for i in 0..20 {
        activate(&mut ctrl, &format!("batch-{i:03}"), "1.0.0");
    }
    assert_eq!(ctrl.component_count(), 20);
    assert_eq!(ctrl.active_count(), 20);

    let summary = ctrl.summary();
    assert_eq!(summary.len(), 20);
    let first_key = summary.keys().next().unwrap();
    assert_eq!(first_key, "batch-000");
}

// ---------------------------------------------------------------------------
// 10. Rollback at every phase
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_at_shadow() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "rb-s", "1.0.0");
    ctrl.begin_update("rb-s", descriptor("rb-s", "2.0.0"), 2, "t")
        .unwrap();
    let pin = ctrl.rollback("rb-s", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("rb-s"), Some(LifecycleState::Active));
}

#[test]
fn enrichment_rollback_at_canary() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "rb-c", "1.0.0");
    ctrl.begin_update("rb-c", descriptor("rb-c", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("rb-c", "t").unwrap();
    let pin = ctrl.rollback("rb-c", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
}

#[test]
fn enrichment_rollback_at_ramp() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "rb-r", "1.0.0");
    ctrl.begin_update("rb-r", descriptor("rb-r", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("rb-r", "t").unwrap(); // canary
    ctrl.advance_rollout("rb-r", "t").unwrap(); // ramp
    let pin = ctrl.rollback("rb-r", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
}

#[test]
fn enrichment_rollback_at_default() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "rb-d", "1.0.0");
    ctrl.begin_update("rb-d", descriptor("rb-d", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("rb-d", "t").unwrap(); // canary
    ctrl.advance_rollout("rb-d", "t").unwrap(); // ramp
    ctrl.advance_rollout("rb-d", "t").unwrap(); // default
    let pin = ctrl.rollback("rb-d", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("rb-d"), Some(LifecycleState::Active));
}

#[test]
fn enrichment_rollback_from_active_restores_same_version() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "rb-act", "1.0.0");
    let pin = ctrl.rollback("rb-act", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("rb-act"), Some(LifecycleState::Active));
}

// ---------------------------------------------------------------------------
// 11. Rollback without known-good
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_pending_no_known_good() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("rb-nkg", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("rb-nkg", &passing_validation("rb-nkg", "1.0.0"), "t")
        .unwrap();
    let err = ctrl.rollback("rb-nkg", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
    assert_eq!(error_code(&err), "LC_NO_KNOWN_GOOD");
}

// ---------------------------------------------------------------------------
// 12. Secret injection
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inject_multiple_secrets_receipt() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-ms", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-ms", &passing_validation("ext-ms", "1.0.0"), "t")
        .unwrap();
    let secrets = vec![
        EphemeralSecret::new("key_a", vec![1]),
        EphemeralSecret::new("key_b", vec![2]),
        EphemeralSecret::new("key_c", vec![3]),
    ];
    let receipt = ctrl.inject_secrets("ext-ms", &secrets, "t").unwrap();
    assert_eq!(receipt.injected_keys.len(), 3);
    assert_eq!(receipt.injected_keys[0], "key_a");
    assert_eq!(receipt.injected_keys[1], "key_b");
    assert_eq!(receipt.injected_keys[2], "key_c");
    assert_eq!(receipt.component_id, "ext-ms");
}

#[test]
fn enrichment_inject_empty_secrets_ok() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-es", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-es", &passing_validation("ext-es", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl.inject_secrets("ext-es", &[], "t").unwrap();
    assert!(receipt.injected_keys.is_empty());
}

#[test]
fn enrichment_inject_secrets_receipt_timestamp() {
    let mut ctrl = make_controller();
    ctrl.set_tick(999);
    ctrl.register(descriptor("ext-st", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("ext-st", &passing_validation("ext-st", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl
        .inject_secrets("ext-st", &[EphemeralSecret::new("k", vec![0])], "t")
        .unwrap();
    assert_eq!(receipt.timestamp, DeterministicTimestamp(999));
}

// ---------------------------------------------------------------------------
// 13. EphemeralSecret behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ephemeral_secret_value_accessible() {
    let secret = EphemeralSecret::new("test_key", vec![0x10, 0x20, 0x30]);
    assert_eq!(secret.value(), &[0x10, 0x20, 0x30]);
    assert_eq!(secret.key_name, "test_key");
}

#[test]
fn enrichment_ephemeral_secret_take_returns_inner() {
    let secret = EphemeralSecret::new("take_key", vec![0xAA, 0xBB]);
    let taken = secret.take();
    assert_eq!(taken, vec![0xAA, 0xBB]);
}

#[test]
fn enrichment_ephemeral_secret_debug_redacts() {
    let secret = EphemeralSecret::new("sensitive", vec![0xFF]);
    let dbg = format!("{secret:?}");
    assert!(dbg.contains("REDACTED"));
    assert!(dbg.contains("sensitive"));
    assert!(!dbg.contains("255"));
}

#[test]
fn enrichment_ephemeral_secret_hex_serde() {
    let secret = EphemeralSecret::new("hex_key", vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let json = serde_json::to_string(&secret).unwrap();
    assert!(json.contains("deadbeef"));
    let rt: EphemeralSecret = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.value(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn enrichment_ephemeral_secret_empty_value() {
    let secret = EphemeralSecret::new("empty", vec![]);
    assert!(secret.value().is_empty());
    let json = serde_json::to_string(&secret).unwrap();
    let rt: EphemeralSecret = serde_json::from_str(&json).unwrap();
    assert!(rt.value().is_empty());
}

// ---------------------------------------------------------------------------
// 14. ActivationValidation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validation_all_checks_pass() {
    let val = ActivationValidation::from_checks(
        "v-comp",
        "1.0",
        vec![
            PreActivationCheck {
                check_name: "a".into(),
                passed: true,
                detail: "ok".into(),
            },
            PreActivationCheck {
                check_name: "b".into(),
                passed: true,
                detail: "ok".into(),
            },
        ],
    );
    assert!(val.all_passed);
    assert_eq!(val.checks.len(), 2);
}

#[test]
fn enrichment_validation_one_check_fails() {
    let val = ActivationValidation::from_checks(
        "v-comp",
        "1.0",
        vec![
            PreActivationCheck {
                check_name: "a".into(),
                passed: true,
                detail: "ok".into(),
            },
            PreActivationCheck {
                check_name: "b".into(),
                passed: false,
                detail: "bad".into(),
            },
        ],
    );
    assert!(!val.all_passed);
}

#[test]
fn enrichment_validation_empty_checks_pass() {
    let val = ActivationValidation::from_checks("v-comp", "1.0", vec![]);
    assert!(val.all_passed);
}

#[test]
fn enrichment_validation_serde_roundtrip() {
    let val = passing_validation("serde-v", "2.0");
    let json = serde_json::to_string(&val).unwrap();
    let rt: ActivationValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(val, rt);
}

#[test]
fn enrichment_failing_validation_rejects_activation() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ext-fv", "1.0.0"), "t").unwrap();
    let err = ctrl
        .begin_activation("ext-fv", &failing_validation("ext-fv", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::ActivationValidationFailed { .. }
    ));
    assert!(err.to_string().contains("revocation"));
    assert_eq!(ctrl.state("ext-fv"), Some(LifecycleState::Inactive));
}

// ---------------------------------------------------------------------------
// 15. Event / audit trail
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registration_emits_event() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("ev-reg", "1.0.0"), "trace-r")
        .unwrap();
    let events = ctrl.events();
    assert!(events.iter().any(|e| e.event == "component_registered"));
    let reg = events
        .iter()
        .find(|e| e.event == "component_registered")
        .unwrap();
    assert_eq!(reg.component, "activation_lifecycle");
    assert_eq!(reg.outcome, "ok");
    assert_eq!(reg.component_id.as_deref(), Some("ev-reg"));
}

#[test]
fn enrichment_activation_emits_transition_events() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-act", "1.0.0");
    let events = ctrl.drain_events();
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    assert!(transitions.len() >= 2);
    assert!(transitions.iter().any(|e| {
        e.from_state.as_deref() == Some("inactive")
            && e.to_state.as_deref() == Some("pending_activation")
    }));
    assert!(transitions.iter().any(|e| {
        e.from_state.as_deref() == Some("pending_activation")
            && e.to_state.as_deref() == Some("active")
    }));
}

#[test]
fn enrichment_update_emits_version_event() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-upd", "1.0.0");
    ctrl.drain_events();

    ctrl.begin_update("ev-upd", descriptor("ev-upd", "2.0.0"), 2, "t")
        .unwrap();
    let events = ctrl.drain_events();
    let upd = events.iter().find(|e| e.event == "update_started").unwrap();
    assert_eq!(upd.from_version.as_deref(), Some("1.0.0"));
    assert_eq!(upd.to_version.as_deref(), Some("2.0.0"));
    assert_eq!(upd.trigger.as_deref(), Some("manual"));
}

#[test]
fn enrichment_rollback_emits_two_transition_events() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-rb", "1.0.0");
    ctrl.begin_update("ev-rb", descriptor("ev-rb", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.drain_events();

    ctrl.rollback("ev-rb", "t").unwrap();
    let events = ctrl.drain_events();
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    assert_eq!(transitions.len(), 2);
    assert!(
        transitions
            .iter()
            .any(|e| e.to_state.as_deref() == Some("rolling_back"))
    );
    assert!(transitions.iter().any(|e| {
        e.from_state.as_deref() == Some("rolling_back") && e.to_state.as_deref() == Some("active")
    }));
}

#[test]
fn enrichment_drain_events_clears_buffer() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-drain", "1.0.0");
    let first = ctrl.drain_events();
    assert!(!first.is_empty());
    let second = ctrl.drain_events();
    assert!(second.is_empty());
}

#[test]
fn enrichment_deactivation_emits_transition_event() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-deact", "1.0.0");
    ctrl.drain_events();

    ctrl.deactivate("ev-deact", "t").unwrap();
    let events = ctrl.drain_events();
    let t = events
        .iter()
        .find(|e| e.event == "lifecycle_transition")
        .unwrap();
    assert_eq!(t.from_state.as_deref(), Some("active"));
    assert_eq!(t.to_state.as_deref(), Some("inactive"));
}

// ---------------------------------------------------------------------------
// 16. Serde roundtrips for all types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_known_good_pin_serde_roundtrip() {
    let pin = KnownGoodPin {
        component_id: "serde-pin".to_string(),
        version: "3.0.0".to_string(),
        version_hash: "hash-3.0.0".to_string(),
        activated_at: DeterministicTimestamp(200),
        health_check_passed_at: DeterministicTimestamp(201),
    };
    let json = serde_json::to_string(&pin).unwrap();
    let rt: KnownGoodPin = serde_json::from_str(&json).unwrap();
    assert_eq!(pin, rt);
}

#[test]
fn enrichment_lifecycle_event_serde_roundtrip() {
    let ev = LifecycleEvent {
        trace_id: "t-enrich".to_string(),
        component: "activation_lifecycle".to_string(),
        event: "lifecycle_transition".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        component_id: Some("serde-ev".to_string()),
        from_version: Some("1.0.0".to_string()),
        to_version: Some("2.0.0".to_string()),
        from_state: Some("active".to_string()),
        to_state: Some("updating:shadow".to_string()),
        trigger: Some("manual".to_string()),
        timestamp: DeterministicTimestamp(500),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: LifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

#[test]
fn enrichment_secret_injection_receipt_serde_roundtrip() {
    let receipt = SecretInjectionReceipt {
        component_id: "serde-r".to_string(),
        injected_keys: vec!["k1".to_string(), "k2".to_string()],
        timestamp: DeterministicTimestamp(777),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let rt: SecretInjectionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, rt);
}

#[test]
fn enrichment_component_descriptor_with_caps_serde_roundtrip() {
    let desc = descriptor_with_caps("serde-d", "1.0.0", &["cap_x", "cap_y"]);
    let json = serde_json::to_string(&desc).unwrap();
    let rt: ComponentDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, rt);
    assert!(rt.capabilities_required.contains("cap_x"));
}

#[test]
fn enrichment_lifecycle_error_all_variants_serde() {
    let errors = vec![
        LifecycleError::InvalidTransition {
            from: LifecycleState::Active,
            to: LifecycleState::Inactive,
        },
        LifecycleError::ActivationValidationFailed {
            detail: "enrichment".to_string(),
        },
        LifecycleError::ComponentNotFound {
            component_id: "missing".to_string(),
        },
        LifecycleError::RolloutPhaseMismatch {
            expected: RolloutPhase::Ramp,
            actual: RolloutPhase::Shadow,
        },
        LifecycleError::NoKnownGoodVersion {
            component_id: "no-kgv".to_string(),
        },
        LifecycleError::CrashLoopDetected {
            component_id: "cl".to_string(),
            crash_count: 10,
        },
        LifecycleError::RevocationCheckFailed {
            detail: "revoked".to_string(),
        },
        LifecycleError::RollbackHoldoffActive {
            component_id: "holdoff".to_string(),
            remaining_ticks: 42,
        },
        LifecycleError::CheckpointRegression {
            component_id: "regress".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let rt: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, rt);
    }
}

// ---------------------------------------------------------------------------
// 17. Error code stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_code_all_variants() {
    assert_eq!(
        error_code(&LifecycleError::InvalidTransition {
            from: LifecycleState::Active,
            to: LifecycleState::Inactive,
        }),
        "LC_INVALID_TRANSITION"
    );
    assert_eq!(
        error_code(&LifecycleError::ActivationValidationFailed { detail: "x".into() }),
        "LC_ACTIVATION_FAILED"
    );
    assert_eq!(
        error_code(&LifecycleError::ComponentNotFound {
            component_id: "x".into()
        }),
        "LC_COMPONENT_NOT_FOUND"
    );
    assert_eq!(
        error_code(&LifecycleError::RolloutPhaseMismatch {
            expected: RolloutPhase::Shadow,
            actual: RolloutPhase::Canary,
        }),
        "LC_ROLLOUT_MISMATCH"
    );
    assert_eq!(
        error_code(&LifecycleError::NoKnownGoodVersion {
            component_id: "x".into()
        }),
        "LC_NO_KNOWN_GOOD"
    );
    assert_eq!(
        error_code(&LifecycleError::CrashLoopDetected {
            component_id: "x".into(),
            crash_count: 3
        }),
        "LC_CRASH_LOOP"
    );
    assert_eq!(
        error_code(&LifecycleError::RevocationCheckFailed { detail: "x".into() }),
        "LC_REVOCATION_FAILED"
    );
    assert_eq!(
        error_code(&LifecycleError::RollbackHoldoffActive {
            component_id: "x".into(),
            remaining_ticks: 1
        }),
        "LC_ROLLBACK_HOLDOFF"
    );
    assert_eq!(
        error_code(&LifecycleError::CheckpointRegression {
            component_id: "x".into()
        }),
        "LC_CHECKPOINT_REGRESSION"
    );
}

// ---------------------------------------------------------------------------
// 18. Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deterministic_event_stream() {
    let run = || {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate(&mut ctrl, "det-a", "1.0.0");
        ctrl.set_tick(50);
        ctrl.begin_update("det-a", descriptor("det-a", "2.0.0"), 2, "t")
            .unwrap();
        full_rollout(&mut ctrl, "det-a");
        serde_json::to_string(&ctrl.drain_events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_summary_ordering() {
    let run = || {
        let mut ctrl = make_controller();
        activate(&mut ctrl, "zzz-det", "1.0");
        activate(&mut ctrl, "aaa-det", "1.0");
        activate(&mut ctrl, "mmm-det", "1.0");
        serde_json::to_string(&ctrl.summary()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_state_after_crash_loop() {
    let run = || {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate(&mut ctrl, "det-cl", "1.0.0");
        ctrl.set_tick(100);
        ctrl.begin_update("det-cl", descriptor("det-cl", "2.0.0"), 2, "t")
            .unwrap();
        ctrl.set_tick(101);
        ctrl.report_crash("det-cl", "t").unwrap();
        ctrl.set_tick(102);
        ctrl.report_crash("det-cl", "t").unwrap();
        ctrl.set_tick(103);
        ctrl.report_crash("det-cl", "t").unwrap();
        (
            ctrl.state("det-cl"),
            ctrl.known_good("det-cl").cloned(),
            ctrl.component_version("det-cl"),
        )
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// 19. Accessors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_zone_accessor() {
    let ctrl = make_controller();
    assert_eq!(ctrl.zone(), "integration-zone");
}

#[test]
fn enrichment_config_accessor() {
    let ctrl = make_controller();
    let cfg = ctrl.config();
    assert_eq!(cfg.crash_threshold, 3);
    assert_eq!(cfg.crash_window_ticks, 60);
    assert_eq!(cfg.rollback_holdoff_ticks, 30);
}

#[test]
fn enrichment_component_version_returns_empty_for_unknown() {
    let ctrl = make_controller();
    assert_eq!(ctrl.component_version("nonexistent"), "");
}

#[test]
fn enrichment_transition_count_tracks_transitions() {
    let mut ctrl = make_controller();
    assert_eq!(ctrl.transition_count(), 0);
    activate(&mut ctrl, "tc-a", "1.0.0");
    // register(0) + inactive->pending(1) + pending->active(2)
    assert_eq!(ctrl.transition_count(), 2);
    ctrl.begin_update("tc-a", descriptor("tc-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(ctrl.transition_count(), 3);
}

#[test]
fn enrichment_summary_returns_btreemap() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "sum-b", "1.0.0");
    activate(&mut ctrl, "sum-a", "1.0.0");
    let summary: BTreeMap<String, LifecycleState> = ctrl.summary();
    let keys: Vec<_> = summary.keys().collect();
    // BTreeMap guarantees alphabetical ordering
    assert_eq!(keys, vec!["sum-a", "sum-b"]);
}

#[test]
fn enrichment_events_accessor_read_only() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ev-ro", "1.0.0");
    let events = ctrl.events();
    assert!(!events.is_empty());
    // events() does not drain
    let events2 = ctrl.events();
    assert_eq!(events.len(), events2.len());
}

// ---------------------------------------------------------------------------
// 20. Full lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_activate_update_crash_loop_holdoff_reupdate_complete() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "full-1", "1.0.0");

    // Update to v2, crash loop
    ctrl.set_tick(100);
    ctrl.begin_update("full-1", descriptor("full-1", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("full-1", "t").unwrap();
    ctrl.set_tick(101);
    ctrl.report_crash("full-1", "t").unwrap();
    ctrl.set_tick(102);
    ctrl.report_crash("full-1", "t").unwrap();
    ctrl.set_tick(103);
    let pin = ctrl.report_crash("full-1", "t").unwrap().unwrap();
    assert_eq!(pin.version, "1.0.0");

    // Holdoff blocks immediate re-update
    ctrl.set_tick(110);
    assert!(
        ctrl.begin_update("full-1", descriptor("full-1", "3.0.0"), 3, "t")
            .is_err()
    );

    // Wait for holdoff, re-update and complete
    ctrl.set_tick(133);
    ctrl.begin_update("full-1", descriptor("full-1", "3.0.0"), 3, "t")
        .unwrap();
    full_rollout(&mut ctrl, "full-1");
    assert_eq!(ctrl.state("full-1"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("full-1").unwrap().version, "3.0.0");
}

#[test]
fn enrichment_successive_updates_without_rollback() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "succ-u", "1.0.0");

    for i in 2..=5u64 {
        let ver = format!("{i}.0.0");
        ctrl.set_tick(i * 100);
        ctrl.begin_update("succ-u", descriptor("succ-u", &ver), i * 10, "t")
            .unwrap();
        full_rollout(&mut ctrl, "succ-u");
        assert_eq!(ctrl.known_good("succ-u").unwrap().version, ver);
    }
}

#[test]
fn enrichment_successive_rollbacks_with_holdoff() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "succ-rb", "1.0.0");

    for i in 2..=4u64 {
        let ver = format!("{i}.0.0");
        let tick = i * 100;
        ctrl.set_tick(tick);
        ctrl.begin_update("succ-rb", descriptor("succ-rb", &ver), tick, "t")
            .unwrap();
        ctrl.rollback("succ-rb", "t").unwrap();
        assert_eq!(ctrl.known_good("succ-rb").unwrap().version, "1.0.0");
        ctrl.set_tick(tick + 30); // wait for holdoff
    }
}

#[test]
fn enrichment_activate_deactivate_then_update_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "ad-u", "1.0.0");
    ctrl.deactivate("ad-u", "t").unwrap();
    // Cannot update an inactive component
    let err = ctrl
        .begin_update("ad-u", descriptor("ad-u", "2.0.0"), 2, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ---------------------------------------------------------------------------
// 21. LifecycleState Display coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_state_display_all_variants() {
    assert_eq!(LifecycleState::Inactive.to_string(), "inactive");
    assert_eq!(
        LifecycleState::PendingActivation.to_string(),
        "pending_activation"
    );
    assert_eq!(LifecycleState::Active.to_string(), "active");
    assert_eq!(LifecycleState::RollingBack.to_string(), "rolling_back");
    for phase in RolloutPhase::ALL {
        let expected = format!("updating:{phase}");
        assert_eq!(LifecycleState::Updating(phase).to_string(), expected);
    }
}

// ---------------------------------------------------------------------------
// 22. LifecycleError Display coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_all_variants() {
    let cases: Vec<(LifecycleError, &str)> = vec![
        (
            LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            },
            "invalid transition: inactive -> active",
        ),
        (
            LifecycleError::ActivationValidationFailed {
                detail: "bad sig".into(),
            },
            "activation validation failed: bad sig",
        ),
        (
            LifecycleError::ComponentNotFound {
                component_id: "comp-z".into(),
            },
            "component not found: comp-z",
        ),
        (
            LifecycleError::RolloutPhaseMismatch {
                expected: RolloutPhase::Canary,
                actual: RolloutPhase::Shadow,
            },
            "rollout phase mismatch: expected canary, got shadow",
        ),
        (
            LifecycleError::NoKnownGoodVersion {
                component_id: "c".into(),
            },
            "no known-good version for c",
        ),
        (
            LifecycleError::CrashLoopDetected {
                component_id: "c".into(),
                crash_count: 3,
            },
            "crash-loop detected for c: 3 crashes",
        ),
        (
            LifecycleError::RevocationCheckFailed {
                detail: "key gone".into(),
            },
            "revocation check failed: key gone",
        ),
        (
            LifecycleError::RollbackHoldoffActive {
                component_id: "c".into(),
                remaining_ticks: 5,
            },
            "rollback holdoff active for c: 5 ticks remaining",
        ),
        (
            LifecycleError::CheckpointRegression {
                component_id: "c".into(),
            },
            "checkpoint frontier would regress for c",
        ),
    ];
    for (err, expected) in &cases {
        assert_eq!(err.to_string(), *expected);
    }
}

// ---------------------------------------------------------------------------
// 23. LifecycleError is std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(LifecycleError::RevocationCheckFailed {
        detail: "key revoked".to_string(),
    });
    assert!(err.to_string().contains("key revoked"));
}

// ---------------------------------------------------------------------------
// 24. PreActivationCheck ordering and equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pre_activation_check_equality() {
    let a = PreActivationCheck {
        check_name: "sig".into(),
        passed: true,
        detail: "ok".into(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_pre_activation_check_serde_roundtrip() {
    let check = PreActivationCheck {
        check_name: "integrity_check".into(),
        passed: false,
        detail: "hash mismatch".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let rt: PreActivationCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, rt);
    assert!(!rt.passed);
}

// ---------------------------------------------------------------------------
// 25. LifecycleConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_config_custom_values() {
    let cfg = LifecycleConfig {
        crash_threshold: 10,
        crash_window_ticks: 200,
        rollback_holdoff_ticks: 50,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let rt: LifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, rt);
    assert_eq!(rt.crash_threshold, 10);
}

// ---------------------------------------------------------------------------
// 26. Version restored after rollback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_version_restored_after_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "vr-a", "1.0.0");
    assert_eq!(ctrl.component_version("vr-a"), "1.0.0");

    ctrl.begin_update("vr-a", descriptor("vr-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(ctrl.component_version("vr-a"), "2.0.0");

    ctrl.rollback("vr-a", "t").unwrap();
    assert_eq!(ctrl.component_version("vr-a"), "1.0.0");
}

// ---------------------------------------------------------------------------
// 27. Timestamp propagation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_set_tick_propagates_to_events() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1234);
    ctrl.register(descriptor("ts-a", "1.0.0"), "t").unwrap();
    let events = ctrl.events();
    assert_eq!(events[0].timestamp, DeterministicTimestamp(1234));
}

#[test]
fn enrichment_known_good_pin_has_correct_timestamp() {
    let mut ctrl = make_controller();
    ctrl.set_tick(500);
    activate(&mut ctrl, "ts-kg", "1.0.0");
    let pin = ctrl.known_good("ts-kg").unwrap();
    assert_eq!(pin.activated_at, DeterministicTimestamp(500));
    assert_eq!(pin.health_check_passed_at, DeterministicTimestamp(500));
}

// ---------------------------------------------------------------------------
// 28. Duplicate registration
// ---------------------------------------------------------------------------

#[test]
fn enrichment_double_register_same_id_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("dup-a", "1.0.0"), "t").unwrap();
    let err = ctrl
        .register(descriptor("dup-a", "2.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::ActivationValidationFailed { .. }
    ));
    assert!(err.to_string().contains("already registered"));
}
