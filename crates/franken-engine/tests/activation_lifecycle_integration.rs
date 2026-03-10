#![forbid(unsafe_code)]
//! Integration tests for the `activation_lifecycle` module.
//!
//! Exercises every public type, enum variant, method, error path, and
//! cross-concern scenario from outside the crate boundary.

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
    ActivationLifecycleController, ActivationValidation, ComponentDescriptor, CrashLoopDetector,
    EphemeralSecret, KnownGoodPin, LifecycleConfig, LifecycleError, LifecycleEvent, LifecycleState,
    PreActivationCheck, RolloutPhase, SecretInjectionReceipt, TransitionTrigger, error_code,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_controller() -> ActivationLifecycleController {
    ActivationLifecycleController::new(LifecycleConfig::default(), "integ-zone")
}

fn make_controller_with_config(
    threshold: u32,
    window: u64,
    holdoff: u64,
) -> ActivationLifecycleController {
    ActivationLifecycleController::new(
        LifecycleConfig {
            crash_threshold: threshold,
            crash_window_ticks: window,
            rollback_holdoff_ticks: holdoff,
        },
        "custom-zone",
    )
}

fn descriptor(id: &str, version: &str) -> ComponentDescriptor {
    ComponentDescriptor {
        component_id: id.to_string(),
        version: version.to_string(),
        version_hash: format!("hash-{version}"),
        capabilities_required: BTreeSet::new(),
    }
}

fn descriptor_with_caps(id: &str, version: &str, caps: &[&str]) -> ComponentDescriptor {
    ComponentDescriptor {
        component_id: id.to_string(),
        version: version.to_string(),
        version_hash: format!("hash-{version}"),
        capabilities_required: caps.iter().map(|c| c.to_string()).collect(),
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

/// Full activation: register -> begin_activation -> inject_secrets -> complete_activation.
fn activate(ctrl: &mut ActivationLifecycleController, id: &str, version: &str) {
    ctrl.register(descriptor(id, version), "t").unwrap();
    ctrl.begin_activation(id, &passing_validation(id, version), "t")
        .unwrap();
    ctrl.inject_secrets(id, &[EphemeralSecret::new("k", vec![0xAA])], "t")
        .unwrap();
    ctrl.complete_activation(id, 1, "t").unwrap();
}

// ===========================================================================
// 1. Enum variant construction, Display, and serde round-trip
// ===========================================================================

// -- LifecycleState --------------------------------------------------------

#[test]
fn lifecycle_state_inactive_display() {
    assert_eq!(LifecycleState::Inactive.to_string(), "inactive");
}

#[test]
fn lifecycle_state_pending_activation_display() {
    assert_eq!(
        LifecycleState::PendingActivation.to_string(),
        "pending_activation"
    );
}

#[test]
fn lifecycle_state_active_display() {
    assert_eq!(LifecycleState::Active.to_string(), "active");
}

#[test]
fn lifecycle_state_updating_shadow_display() {
    assert_eq!(
        LifecycleState::Updating(RolloutPhase::Shadow).to_string(),
        "updating:shadow"
    );
}

#[test]
fn lifecycle_state_updating_canary_display() {
    assert_eq!(
        LifecycleState::Updating(RolloutPhase::Canary).to_string(),
        "updating:canary"
    );
}

#[test]
fn lifecycle_state_updating_ramp_display() {
    assert_eq!(
        LifecycleState::Updating(RolloutPhase::Ramp).to_string(),
        "updating:ramp"
    );
}

#[test]
fn lifecycle_state_updating_default_display() {
    assert_eq!(
        LifecycleState::Updating(RolloutPhase::Default).to_string(),
        "updating:default"
    );
}

#[test]
fn lifecycle_state_rolling_back_display() {
    assert_eq!(LifecycleState::RollingBack.to_string(), "rolling_back");
}

#[test]
fn lifecycle_state_serde_all_variants() {
    let states = [
        LifecycleState::Inactive,
        LifecycleState::PendingActivation,
        LifecycleState::Active,
        LifecycleState::Updating(RolloutPhase::Shadow),
        LifecycleState::Updating(RolloutPhase::Canary),
        LifecycleState::Updating(RolloutPhase::Ramp),
        LifecycleState::Updating(RolloutPhase::Default),
        LifecycleState::RollingBack,
    ];
    for state in states {
        let json = serde_json::to_string(&state).unwrap();
        let rt: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, rt, "round-trip failed for {state}");
    }
}

// -- RolloutPhase ----------------------------------------------------------

#[test]
fn rollout_phase_display_all() {
    assert_eq!(RolloutPhase::Shadow.to_string(), "shadow");
    assert_eq!(RolloutPhase::Canary.to_string(), "canary");
    assert_eq!(RolloutPhase::Ramp.to_string(), "ramp");
    assert_eq!(RolloutPhase::Default.to_string(), "default");
}

#[test]
fn rollout_phase_serde_all() {
    for phase in RolloutPhase::ALL {
        let json = serde_json::to_string(&phase).unwrap();
        let rt: RolloutPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, rt);
    }
}

#[test]
fn rollout_phase_all_constant_ordering() {
    assert_eq!(RolloutPhase::ALL.len(), 4);
    assert_eq!(RolloutPhase::ALL[0], RolloutPhase::Shadow);
    assert_eq!(RolloutPhase::ALL[1], RolloutPhase::Canary);
    assert_eq!(RolloutPhase::ALL[2], RolloutPhase::Ramp);
    assert_eq!(RolloutPhase::ALL[3], RolloutPhase::Default);
}

#[test]
fn rollout_phase_next_chain() {
    assert_eq!(RolloutPhase::Shadow.next(), Some(RolloutPhase::Canary));
    assert_eq!(RolloutPhase::Canary.next(), Some(RolloutPhase::Ramp));
    assert_eq!(RolloutPhase::Ramp.next(), Some(RolloutPhase::Default));
    assert_eq!(RolloutPhase::Default.next(), None);
}

// -- TransitionTrigger -----------------------------------------------------

#[test]
fn transition_trigger_display_all() {
    assert_eq!(TransitionTrigger::Manual.to_string(), "manual");
    assert_eq!(TransitionTrigger::Auto.to_string(), "auto");
    assert_eq!(TransitionTrigger::CrashLoop.to_string(), "crash_loop");
}

#[test]
fn transition_trigger_serde_all() {
    for trigger in [
        TransitionTrigger::Manual,
        TransitionTrigger::Auto,
        TransitionTrigger::CrashLoop,
    ] {
        let json = serde_json::to_string(&trigger).unwrap();
        let rt: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, rt);
    }
}

// ===========================================================================
// 2. Public struct construction, field access, Default, serde round-trip
// ===========================================================================

// -- PreActivationCheck ----------------------------------------------------

#[test]
fn pre_activation_check_construction_and_serde() {
    let check = PreActivationCheck {
        check_name: "integrity".to_string(),
        passed: true,
        detail: "ok".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let rt: PreActivationCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, rt);
    assert!(rt.passed);
    assert_eq!(rt.check_name, "integrity");
}

// -- ActivationValidation --------------------------------------------------

#[test]
fn activation_validation_from_checks_all_pass() {
    let val = ActivationValidation::from_checks(
        "c1",
        "v1",
        vec![PreActivationCheck {
            check_name: "a".to_string(),
            passed: true,
            detail: "ok".to_string(),
        }],
    );
    assert!(val.all_passed);
    assert_eq!(val.component_id, "c1");
    assert_eq!(val.version, "v1");
    assert_eq!(val.checks.len(), 1);
}

#[test]
fn activation_validation_from_checks_one_fails() {
    let val = ActivationValidation::from_checks(
        "c1",
        "v1",
        vec![
            PreActivationCheck {
                check_name: "a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            PreActivationCheck {
                check_name: "b".to_string(),
                passed: false,
                detail: "bad".to_string(),
            },
        ],
    );
    assert!(!val.all_passed);
}

#[test]
fn activation_validation_empty_checks_passes() {
    let val = ActivationValidation::from_checks("c1", "v1", vec![]);
    assert!(val.all_passed);
}

#[test]
fn activation_validation_serde_roundtrip() {
    let val = passing_validation("comp-x", "3.2.1");
    let json = serde_json::to_string(&val).unwrap();
    let rt: ActivationValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(val, rt);
}

// -- EphemeralSecret -------------------------------------------------------

#[test]
fn ephemeral_secret_value_access() {
    let secret = EphemeralSecret::new("enc_key", vec![0x01, 0x02, 0x03]);
    assert_eq!(secret.key_name, "enc_key");
    assert_eq!(secret.value(), &[0x01, 0x02, 0x03]);
}

#[test]
fn ephemeral_secret_take_consumes() {
    let secret = EphemeralSecret::new("k", vec![0xDE, 0xAD]);
    let taken = secret.take();
    assert_eq!(taken, vec![0xDE, 0xAD]);
}

#[test]
fn ephemeral_secret_debug_redacts_value() {
    let secret = EphemeralSecret::new("my_key", vec![0xFF, 0xAA]);
    let dbg = format!("{secret:?}");
    assert!(dbg.contains("REDACTED"), "Debug must redact value");
    assert!(dbg.contains("my_key"), "Debug must show key name");
    assert!(!dbg.contains("255"), "Debug must not show raw bytes");
    assert!(!dbg.contains("170"), "Debug must not show raw bytes");
}

#[test]
fn ephemeral_secret_serde_hex_roundtrip() {
    let secret = EphemeralSecret::new("test_key", vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let json = serde_json::to_string(&secret).unwrap();
    // The hex encoding should produce a hex string
    assert!(
        json.contains("aabbccdd"),
        "hex encoding expected, got {json}"
    );
    let rt: EphemeralSecret = serde_json::from_str(&json).unwrap();
    assert_eq!(secret.key_name, rt.key_name);
    assert_eq!(secret.value(), rt.value());
}

#[test]
fn ephemeral_secret_empty_value() {
    let secret = EphemeralSecret::new("empty", vec![]);
    assert!(secret.value().is_empty());
    let json = serde_json::to_string(&secret).unwrap();
    let rt: EphemeralSecret = serde_json::from_str(&json).unwrap();
    assert!(rt.value().is_empty());
}

// -- SecretInjectionReceipt ------------------------------------------------

#[test]
fn secret_injection_receipt_serde_roundtrip() {
    let receipt = SecretInjectionReceipt {
        component_id: "comp-a".to_string(),
        injected_keys: vec!["k1".to_string(), "k2".to_string()],
        timestamp: DeterministicTimestamp(42),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let rt: SecretInjectionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, rt);
}

// -- KnownGoodPin ----------------------------------------------------------

#[test]
fn known_good_pin_construction_and_serde() {
    let pin = KnownGoodPin {
        component_id: "comp-a".to_string(),
        version: "1.0.0".to_string(),
        version_hash: "hash-1.0.0".to_string(),
        activated_at: DeterministicTimestamp(100),
        health_check_passed_at: DeterministicTimestamp(101),
    };
    let json = serde_json::to_string(&pin).unwrap();
    let rt: KnownGoodPin = serde_json::from_str(&json).unwrap();
    assert_eq!(pin, rt);
    assert_eq!(rt.component_id, "comp-a");
    assert_eq!(rt.activated_at, DeterministicTimestamp(100));
}

// -- ComponentDescriptor ---------------------------------------------------

#[test]
fn component_descriptor_serde_roundtrip() {
    let desc = descriptor_with_caps("comp-a", "1.0.0", &["cap_a", "cap_b"]);
    let json = serde_json::to_string(&desc).unwrap();
    let rt: ComponentDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, rt);
    assert!(rt.capabilities_required.contains("cap_a"));
    assert!(rt.capabilities_required.contains("cap_b"));
}

// -- LifecycleEvent --------------------------------------------------------

#[test]
fn lifecycle_event_serde_roundtrip() {
    let ev = LifecycleEvent {
        trace_id: "t-001".to_string(),
        component: "activation_lifecycle".to_string(),
        event: "lifecycle_transition".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("LC_TEST".to_string()),
        component_id: Some("comp-a".to_string()),
        from_version: Some("1.0.0".to_string()),
        to_version: Some("2.0.0".to_string()),
        from_state: Some("active".to_string()),
        to_state: Some("updating:shadow".to_string()),
        trigger: Some("manual".to_string()),
        timestamp: DeterministicTimestamp(999),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: LifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

#[test]
fn lifecycle_event_optional_fields_none() {
    let ev = LifecycleEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        component_id: None,
        from_version: None,
        to_version: None,
        from_state: None,
        to_state: None,
        trigger: None,
        timestamp: DeterministicTimestamp(0),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: LifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
    assert!(rt.error_code.is_none());
}

// -- CrashLoopDetector -----------------------------------------------------

#[test]
fn crash_loop_detector_default_values() {
    let det = CrashLoopDetector::default();
    // Default: threshold=3, window=60
    assert_eq!(det.crash_count(0), 0);
}

#[test]
fn crash_loop_detector_new_and_record() {
    let mut det = CrashLoopDetector::new(2, 10);
    assert!(!det.record_crash(5));
    assert!(det.record_crash(6)); // 2nd crash hits threshold
}

#[test]
fn crash_loop_detector_window_pruning() {
    let mut det = CrashLoopDetector::new(3, 10);
    det.record_crash(0);
    det.record_crash(5);
    // At tick 20, only crash at tick 5 would be pruned (cutoff = 20 - 10 = 10)
    // Actually both 0 and 5 are < 10, so both pruned
    assert!(!det.record_crash(20));
    assert_eq!(det.crash_count(20), 1); // only the crash at tick 20
}

#[test]
fn crash_loop_detector_crash_count() {
    let mut det = CrashLoopDetector::new(10, 50);
    det.record_crash(10);
    det.record_crash(20);
    det.record_crash(30);
    assert_eq!(det.crash_count(30), 3);
    assert_eq!(det.crash_count(100), 0); // all outside window
}

#[test]
fn crash_loop_detector_reset() {
    let mut det = CrashLoopDetector::new(3, 60);
    det.record_crash(1);
    det.record_crash(2);
    det.reset();
    assert_eq!(det.crash_count(3), 0);
    assert!(!det.record_crash(4)); // fresh start, only 1 crash
}

#[test]
fn crash_loop_detector_serde_roundtrip() {
    let mut det = CrashLoopDetector::new(5, 100);
    det.record_crash(10);
    det.record_crash(20);
    let json = serde_json::to_string(&det).unwrap();
    let rt: CrashLoopDetector = serde_json::from_str(&json).unwrap();
    assert_eq!(det, rt);
}

// -- LifecycleConfig -------------------------------------------------------

#[test]
fn lifecycle_config_default() {
    let cfg = LifecycleConfig::default();
    assert_eq!(cfg.crash_threshold, 3);
    assert_eq!(cfg.crash_window_ticks, 60);
    assert_eq!(cfg.rollback_holdoff_ticks, 30);
}

#[test]
fn lifecycle_config_serde_roundtrip() {
    let cfg = LifecycleConfig {
        crash_threshold: 7,
        crash_window_ticks: 120,
        rollback_holdoff_ticks: 45,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let rt: LifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, rt);
}

// ===========================================================================
// 3. Public methods - happy paths
// ===========================================================================

#[test]
fn register_component_initial_state_inactive() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    assert_eq!(ctrl.component_count(), 1);
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn begin_activation_transitions_to_pending() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::PendingActivation)
    );
}

#[test]
fn inject_secrets_returns_receipt() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    let secrets = vec![
        EphemeralSecret::new("session_key", vec![1, 2, 3]),
        EphemeralSecret::new("enc_key", vec![4, 5, 6]),
    ];
    let receipt = ctrl.inject_secrets("comp-a", &secrets, "t").unwrap();
    assert_eq!(receipt.component_id, "comp-a");
    assert_eq!(receipt.injected_keys.len(), 2);
    assert_eq!(receipt.injected_keys[0], "session_key");
    assert_eq!(receipt.injected_keys[1], "enc_key");
}

#[test]
fn complete_activation_transitions_to_active() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.active_count(), 1);
}

#[test]
fn complete_activation_sets_known_good() {
    let mut ctrl = make_controller();
    ctrl.set_tick(42);
    activate(&mut ctrl, "comp-a", "1.0.0");
    let pin = ctrl.known_good("comp-a").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(pin.version_hash, "hash-1.0.0");
    assert_eq!(pin.component_id, "comp-a");
}

#[test]
fn begin_update_transitions_to_updating_shadow() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn advance_rollout_shadow_to_canary() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    let phase = ctrl.advance_rollout("comp-a", "t").unwrap();
    assert_eq!(phase, RolloutPhase::Canary);
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Canary))
    );
}

#[test]
fn advance_rollout_canary_to_ramp() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap(); // shadow -> canary
    let phase = ctrl.advance_rollout("comp-a", "t").unwrap();
    assert_eq!(phase, RolloutPhase::Ramp);
}

#[test]
fn advance_rollout_ramp_to_default_finalizes_active() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    let phase = ctrl.advance_rollout("comp-a", "t").unwrap(); // default
    assert_eq!(phase, RolloutPhase::Default);
    ctrl.advance_rollout("comp-a", "t").unwrap(); // past default -> active
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("comp-a").unwrap().version, "2.0.0");
}

#[test]
fn rollback_returns_known_good_pin() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    let pin = ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

#[test]
fn deactivate_returns_to_inactive() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.deactivate("comp-a", "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn report_crash_below_threshold_returns_none() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.set_tick(10);
    let result = ctrl.report_crash("comp-a", "t").unwrap();
    assert!(result.is_none());
}

#[test]
fn report_crash_at_threshold_triggers_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.set_tick(10);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(12);
    let result = ctrl.report_crash("comp-a", "t").unwrap();
    assert!(result.is_some());
    let pin = result.unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

// ===========================================================================
// 3b. Public methods - error paths
// ===========================================================================

#[test]
fn register_duplicate_component_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl
        .register(descriptor("comp-a", "2.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::ActivationValidationFailed { .. }
    ));
    assert!(
        err.to_string()
            .contains("component already registered: comp-a")
    );
}

#[test]
fn begin_activation_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl
        .begin_activation("no-such", &passing_validation("no-such", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn begin_activation_from_active_state_fails() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    let err = ctrl
        .begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
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
fn begin_activation_with_failing_validation() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl
        .begin_activation("comp-a", &failing_validation("comp-a", "1.0.0"), "t")
        .unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::ActivationValidationFailed { .. }
    ));
    assert!(err.to_string().contains("revocation"));
    // State unchanged
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
}

#[test]
fn inject_secrets_on_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl.inject_secrets("comp-a", &[], "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn inject_secrets_on_active_fails() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    let err = ctrl.inject_secrets("comp-a", &[], "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn inject_secrets_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.inject_secrets("missing", &[], "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn complete_activation_from_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl.complete_activation("comp-a", 1, "t").unwrap_err();
    assert!(matches!(
        err,
        LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        }
    ));
}

#[test]
fn complete_activation_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.complete_activation("missing", 1, "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn begin_update_from_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl
        .begin_update("comp-a", descriptor("comp-a", "2.0.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn begin_update_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl
        .begin_update("missing", descriptor("missing", "2.0.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn advance_rollout_from_active_fails() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    let err = ctrl.advance_rollout("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn advance_rollout_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.advance_rollout("missing", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn rollback_from_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl.rollback("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn rollback_without_known_good_version() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    // PendingActivation but no known_good
    let err = ctrl.rollback("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
}

#[test]
fn rollback_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.rollback("missing", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn deactivate_from_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl.deactivate("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn deactivate_from_pending_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    let err = ctrl.deactivate("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn deactivate_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.deactivate("missing", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

#[test]
fn report_crash_on_inactive_fails() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let err = ctrl.report_crash("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

#[test]
fn report_crash_on_missing_component() {
    let mut ctrl = make_controller();
    let err = ctrl.report_crash("missing", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::ComponentNotFound { .. }));
}

// ===========================================================================
// 4. Lifecycle state machine transitions (valid and invalid)
// ===========================================================================

#[test]
fn valid_transition_inactive_to_pending_to_active() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("c", "1.0"), "t").unwrap();
    assert_eq!(ctrl.state("c"), Some(LifecycleState::Inactive));

    ctrl.begin_activation("c", &passing_validation("c", "1.0"), "t")
        .unwrap();
    assert_eq!(ctrl.state("c"), Some(LifecycleState::PendingActivation));

    ctrl.complete_activation("c", 1, "t").unwrap();
    assert_eq!(ctrl.state("c"), Some(LifecycleState::Active));
}

#[test]
fn valid_transition_active_to_updating_through_phases() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "c", "1.0");
    ctrl.begin_update("c", descriptor("c", "2.0"), 2, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("c"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
    ctrl.advance_rollout("c", "t").unwrap();
    assert_eq!(
        ctrl.state("c"),
        Some(LifecycleState::Updating(RolloutPhase::Canary))
    );
    ctrl.advance_rollout("c", "t").unwrap();
    assert_eq!(
        ctrl.state("c"),
        Some(LifecycleState::Updating(RolloutPhase::Ramp))
    );
    ctrl.advance_rollout("c", "t").unwrap();
    assert_eq!(
        ctrl.state("c"),
        Some(LifecycleState::Updating(RolloutPhase::Default))
    );
    ctrl.advance_rollout("c", "t").unwrap();
    assert_eq!(ctrl.state("c"), Some(LifecycleState::Active));
}

#[test]
fn valid_transition_active_to_inactive_via_deactivate() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "c", "1.0");
    ctrl.deactivate("c", "t").unwrap();
    assert_eq!(ctrl.state("c"), Some(LifecycleState::Inactive));
}

#[test]
fn valid_transition_updating_to_rolling_back_to_active() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "c", "1.0");
    ctrl.begin_update("c", descriptor("c", "2.0"), 2, "t")
        .unwrap();
    let pin = ctrl.rollback("c", "t").unwrap();
    assert_eq!(pin.version, "1.0");
    // Rollback transitions through RollingBack -> Active
    assert_eq!(ctrl.state("c"), Some(LifecycleState::Active));
}

#[test]
fn invalid_transition_pending_to_updating() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("c", "1.0"), "t").unwrap();
    ctrl.begin_activation("c", &passing_validation("c", "1.0"), "t")
        .unwrap();
    let err = ctrl
        .begin_update("c", descriptor("c", "2.0"), 1, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// ===========================================================================
// 5. Error variant coverage and Display formatting
// ===========================================================================

#[test]
fn error_display_invalid_transition() {
    let err = LifecycleError::InvalidTransition {
        from: LifecycleState::Inactive,
        to: LifecycleState::Active,
    };
    assert_eq!(err.to_string(), "invalid transition: inactive -> active");
}

#[test]
fn error_display_activation_validation_failed() {
    let err = LifecycleError::ActivationValidationFailed {
        detail: "bad signature".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "activation validation failed: bad signature"
    );
}

#[test]
fn error_display_component_not_found() {
    let err = LifecycleError::ComponentNotFound {
        component_id: "comp-x".to_string(),
    };
    assert_eq!(err.to_string(), "component not found: comp-x");
}

#[test]
fn error_display_rollout_phase_mismatch() {
    let err = LifecycleError::RolloutPhaseMismatch {
        expected: RolloutPhase::Canary,
        actual: RolloutPhase::Shadow,
    };
    assert_eq!(
        err.to_string(),
        "rollout phase mismatch: expected canary, got shadow"
    );
}

#[test]
fn error_display_no_known_good_version() {
    let err = LifecycleError::NoKnownGoodVersion {
        component_id: "comp-a".to_string(),
    };
    assert_eq!(err.to_string(), "no known-good version for comp-a");
}

#[test]
fn error_display_crash_loop_detected() {
    let err = LifecycleError::CrashLoopDetected {
        component_id: "comp-a".to_string(),
        crash_count: 5,
    };
    assert_eq!(err.to_string(), "crash-loop detected for comp-a: 5 crashes");
}

#[test]
fn error_display_revocation_check_failed() {
    let err = LifecycleError::RevocationCheckFailed {
        detail: "key expired".to_string(),
    };
    assert_eq!(err.to_string(), "revocation check failed: key expired");
}

#[test]
fn error_display_rollback_holdoff_active() {
    let err = LifecycleError::RollbackHoldoffActive {
        component_id: "comp-a".to_string(),
        remaining_ticks: 15,
    };
    assert_eq!(
        err.to_string(),
        "rollback holdoff active for comp-a: 15 ticks remaining"
    );
}

#[test]
fn error_display_checkpoint_regression() {
    let err = LifecycleError::CheckpointRegression {
        component_id: "comp-a".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "checkpoint frontier would regress for comp-a"
    );
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors = vec![
        LifecycleError::InvalidTransition {
            from: LifecycleState::Active,
            to: LifecycleState::PendingActivation,
        },
        LifecycleError::ActivationValidationFailed {
            detail: "d".to_string(),
        },
        LifecycleError::ComponentNotFound {
            component_id: "c".to_string(),
        },
        LifecycleError::RolloutPhaseMismatch {
            expected: RolloutPhase::Ramp,
            actual: RolloutPhase::Canary,
        },
        LifecycleError::NoKnownGoodVersion {
            component_id: "c".to_string(),
        },
        LifecycleError::CrashLoopDetected {
            component_id: "c".to_string(),
            crash_count: 7,
        },
        LifecycleError::RevocationCheckFailed {
            detail: "r".to_string(),
        },
        LifecycleError::RollbackHoldoffActive {
            component_id: "c".to_string(),
            remaining_ticks: 99,
        },
        LifecycleError::CheckpointRegression {
            component_id: "c".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let rt: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, rt);
    }
}

#[test]
fn error_code_all_variants_stable() {
    assert_eq!(
        error_code(&LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        }),
        "LC_INVALID_TRANSITION"
    );
    assert_eq!(
        error_code(&LifecycleError::ActivationValidationFailed {
            detail: "x".to_string(),
        }),
        "LC_ACTIVATION_FAILED"
    );
    assert_eq!(
        error_code(&LifecycleError::ComponentNotFound {
            component_id: "x".to_string(),
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
            component_id: "x".to_string(),
        }),
        "LC_NO_KNOWN_GOOD"
    );
    assert_eq!(
        error_code(&LifecycleError::CrashLoopDetected {
            component_id: "x".to_string(),
            crash_count: 1,
        }),
        "LC_CRASH_LOOP"
    );
    assert_eq!(
        error_code(&LifecycleError::RevocationCheckFailed {
            detail: "x".to_string(),
        }),
        "LC_REVOCATION_FAILED"
    );
    assert_eq!(
        error_code(&LifecycleError::RollbackHoldoffActive {
            component_id: "x".to_string(),
            remaining_ticks: 1,
        }),
        "LC_ROLLBACK_HOLDOFF"
    );
    assert_eq!(
        error_code(&LifecycleError::CheckpointRegression {
            component_id: "x".to_string(),
        }),
        "LC_CHECKPOINT_REGRESSION"
    );
}

// ===========================================================================
// 6. Activation/deactivation workflows
// ===========================================================================

#[test]
fn full_activate_deactivate_reactivate_cycle() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));

    ctrl.deactivate("comp-a", "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));

    // Re-activate the same component
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    ctrl.inject_secrets("comp-a", &[EphemeralSecret::new("new_k", vec![0xBB])], "t")
        .unwrap();
    ctrl.complete_activation("comp-a", 2, "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

#[test]
fn deactivation_clears_secrets_and_allows_fresh_injection() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.deactivate("comp-a", "t").unwrap();

    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl
        .inject_secrets(
            "comp-a",
            &[EphemeralSecret::new("fresh_key", vec![0xCC])],
            "t",
        )
        .unwrap();
    assert_eq!(receipt.injected_keys, vec!["fresh_key"]);
}

#[test]
fn inject_empty_secrets_ok() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl.inject_secrets("comp-a", &[], "t").unwrap();
    assert!(receipt.injected_keys.is_empty());
}

// ===========================================================================
// 7. Event emission and audit trail
// ===========================================================================

#[test]
fn events_emitted_on_registration() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "trace-reg")
        .unwrap();
    let events = ctrl.events();
    assert!(!events.is_empty());
    let reg_event = events.iter().find(|e| e.event == "component_registered");
    assert!(reg_event.is_some());
    let ev = reg_event.unwrap();
    assert_eq!(ev.trace_id, "trace-reg");
    assert_eq!(ev.component, "activation_lifecycle");
    assert_eq!(ev.outcome, "ok");
    assert_eq!(ev.component_id.as_deref(), Some("comp-a"));
}

#[test]
fn events_emitted_on_activation_flow() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    let events = ctrl.drain_events();
    // register + transition(inactive->pending) + secrets + transition(pending->active)
    assert!(events.len() >= 4);
    assert!(events.iter().any(|e| e.event == "component_registered"));
    assert!(events.iter().any(|e| e.event == "secrets_injected"));
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    assert!(transitions.len() >= 2);
    // First transition: inactive -> pending_activation
    assert!(
        transitions
            .iter()
            .any(|e| e.from_state.as_deref() == Some("inactive")
                && e.to_state.as_deref() == Some("pending_activation"))
    );
    // Second transition: pending_activation -> active
    assert!(
        transitions
            .iter()
            .any(|e| e.from_state.as_deref() == Some("pending_activation")
                && e.to_state.as_deref() == Some("active"))
    );
}

#[test]
fn events_emitted_on_update_started() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.drain_events();

    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "trace-upd")
        .unwrap();
    let events = ctrl.drain_events();
    let upd = events.iter().find(|e| e.event == "update_started");
    assert!(upd.is_some());
    let ev = upd.unwrap();
    assert_eq!(ev.from_version.as_deref(), Some("1.0.0"));
    assert_eq!(ev.to_version.as_deref(), Some("2.0.0"));
    assert_eq!(ev.trigger.as_deref(), Some("manual"));
    assert_eq!(ev.component_id.as_deref(), Some("comp-a"));
}

#[test]
fn events_emitted_on_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.drain_events();

    ctrl.rollback("comp-a", "trace-rb").unwrap();
    let events = ctrl.drain_events();
    // Rollback emits two transitions: old_state -> RollingBack, RollingBack -> Active
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
    assert!(
        transitions
            .iter()
            .any(|e| e.from_state.as_deref() == Some("rolling_back")
                && e.to_state.as_deref() == Some("active"))
    );
    // Trigger is manual
    assert!(
        transitions
            .iter()
            .all(|e| e.trigger.as_deref() == Some("manual"))
    );
}

#[test]
fn events_emitted_on_crash_loop_auto_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.drain_events();

    ctrl.set_tick(10);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(12);
    ctrl.report_crash("comp-a", "t").unwrap(); // triggers crash-loop rollback

    let events = ctrl.drain_events();
    // Should have crash_reported events and crash_loop-triggered transitions
    assert!(events.iter().any(|e| e.event == "crash_reported"));
    assert!(
        events
            .iter()
            .any(|e| e.trigger.as_deref() == Some("crash_loop"))
    );
}

#[test]
fn events_emitted_on_deactivation() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.drain_events();

    ctrl.deactivate("comp-a", "trace-deact").unwrap();
    let events = ctrl.drain_events();
    let transition = events
        .iter()
        .find(|e| e.event == "lifecycle_transition")
        .unwrap();
    assert_eq!(transition.from_state.as_deref(), Some("active"));
    assert_eq!(transition.to_state.as_deref(), Some("inactive"));
    assert_eq!(transition.trigger.as_deref(), Some("manual"));
}

#[test]
fn drain_events_clears_and_returns() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    assert!(!ctrl.events().is_empty());
    let drained = ctrl.drain_events();
    assert!(!drained.is_empty());
    assert!(ctrl.events().is_empty());
    // Second drain returns empty
    let second = ctrl.drain_events();
    assert!(second.is_empty());
}

#[test]
fn transition_events_have_all_required_fields() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    ctrl.complete_activation("comp-a", 1, "t").unwrap();
    let events = ctrl.drain_events();
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    for t in &transitions {
        assert!(t.from_state.is_some(), "must have from_state");
        assert!(t.to_state.is_some(), "must have to_state");
        assert!(t.trigger.is_some(), "must have trigger");
        assert!(t.component_id.is_some(), "must have component_id");
    }
}

// ===========================================================================
// 8. Epoch handling and freshness checks
// ===========================================================================

#[test]
fn checkpoint_regression_rejected() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    // complete_activation was called with checkpoint_seq=1
    let err = ctrl
        .begin_update("comp-a", descriptor("comp-a", "2.0.0"), 0, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::CheckpointRegression { .. }));
    assert!(err.to_string().contains("comp-a"));
}

#[test]
fn checkpoint_equal_accepted() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    // Same checkpoint_seq as activation (1) is fine
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 1, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn checkpoint_advancement_accepted() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 10, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn rollback_holdoff_prevents_immediate_reupdate() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(100);
    ctrl.rollback("comp-a", "t").unwrap();

    // Immediately after rollback
    ctrl.set_tick(101);
    let err = ctrl
        .begin_update("comp-a", descriptor("comp-a", "3.0.0"), 3, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::RollbackHoldoffActive { .. }));
    let msg = err.to_string();
    assert!(msg.contains("comp-a"));
    assert!(msg.contains("ticks remaining"));
}

#[test]
fn rollback_holdoff_expires_after_configured_ticks() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(100);
    ctrl.rollback("comp-a", "t").unwrap();

    // At exactly holdoff boundary (30 ticks)
    ctrl.set_tick(130);
    ctrl.begin_update("comp-a", descriptor("comp-a", "3.0.0"), 3, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn rollback_holdoff_custom_config() {
    let mut ctrl = make_controller_with_config(3, 60, 10);
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(50);
    ctrl.rollback("comp-a", "t").unwrap();

    // With holdoff=10, should fail at tick 59
    ctrl.set_tick(59);
    let err = ctrl
        .begin_update("comp-a", descriptor("comp-a", "3.0.0"), 3, "t")
        .unwrap_err();
    assert!(matches!(err, LifecycleError::RollbackHoldoffActive { .. }));

    // Should pass at tick 60
    ctrl.set_tick(60);
    ctrl.begin_update("comp-a", descriptor("comp-a", "3.0.0"), 3, "t")
        .unwrap();
}

#[test]
fn set_tick_and_timestamp_propagation() {
    let mut ctrl = make_controller();
    ctrl.set_tick(500);
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    let events = ctrl.drain_events();
    assert_eq!(events[0].timestamp, DeterministicTimestamp(500));
}

// ===========================================================================
// 9. Determinism: same inputs produce same outputs
// ===========================================================================

#[test]
fn deterministic_event_emission() {
    let run = || {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);
        activate(&mut ctrl, "comp-a", "1.0.0");
        ctrl.set_tick(200);
        ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap();
        ctrl.set_tick(201);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(202);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(203);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        serde_json::to_string(&ctrl.drain_events()).unwrap()
    };
    assert_eq!(
        run(),
        run(),
        "two identical runs must produce identical event JSON"
    );
}

#[test]
fn deterministic_summary_ordering() {
    let run = || {
        let mut ctrl = make_controller();
        // Register in different-looking order but same logical order
        activate(&mut ctrl, "comp-b", "1.0");
        activate(&mut ctrl, "comp-a", "1.0");
        ctrl.register(descriptor("comp-c", "1.0"), "t").unwrap();
        let summary = ctrl.summary();
        serde_json::to_string(&summary).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_state_after_identical_sequences() {
    let run = || {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate(&mut ctrl, "comp-a", "1.0.0");
        ctrl.set_tick(50);
        ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
            .unwrap();
        ctrl.advance_rollout("comp-a", "t").unwrap();
        ctrl.advance_rollout("comp-a", "t").unwrap();
        ctrl.advance_rollout("comp-a", "t").unwrap();
        (
            ctrl.state("comp-a"),
            ctrl.known_good("comp-a").cloned(),
            ctrl.transition_count(),
            ctrl.component_version("comp-a"),
        )
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// 10. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn multi_component_independent_lifecycles() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    activate(&mut ctrl, "comp-b", "1.0.0");
    activate(&mut ctrl, "comp-c", "1.0.0");

    assert_eq!(ctrl.component_count(), 3);
    assert_eq!(ctrl.active_count(), 3);

    // Update comp-a, leave others alone
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
    assert_eq!(ctrl.state("comp-b"), Some(LifecycleState::Active));
    assert_eq!(ctrl.state("comp-c"), Some(LifecycleState::Active));
    assert_eq!(ctrl.active_count(), 2);

    // Deactivate comp-b
    ctrl.deactivate("comp-b", "t").unwrap();
    assert_eq!(ctrl.state("comp-b"), Some(LifecycleState::Inactive));
    assert_eq!(ctrl.active_count(), 1);

    // Rollback comp-a
    ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.active_count(), 2);

    let summary = ctrl.summary();
    assert_eq!(summary.len(), 3);
}

#[test]
fn multi_component_isolation_crash_does_not_affect_others() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    activate(&mut ctrl, "comp-b", "1.0.0");

    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(10);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(11);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(12);
    ctrl.report_crash("comp-a", "t").unwrap(); // triggers rollback

    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("comp-a").unwrap().version, "1.0.0");
    // comp-b completely unaffected
    assert_eq!(ctrl.state("comp-b"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("comp-b").unwrap().version, "1.0.0");
}

#[test]
fn full_lifecycle_activate_update_rollback_holdoff_reupdate() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "comp-a", "1.0.0");

    // Update to v2
    ctrl.set_tick(100);
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary

    // Crash-loop rolls back to v1
    ctrl.set_tick(101);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(102);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(103);
    let pin = ctrl.report_crash("comp-a", "t").unwrap().unwrap();
    assert_eq!(pin.version, "1.0.0");

    // Wait for holdoff (30 ticks)
    ctrl.set_tick(133);
    ctrl.begin_update("comp-a", descriptor("comp-a", "3.0.0"), 3, "t")
        .unwrap();

    // Complete full rollout
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    ctrl.advance_rollout("comp-a", "t").unwrap(); // default
    ctrl.advance_rollout("comp-a", "t").unwrap(); // past default -> active
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    assert_eq!(ctrl.known_good("comp-a").unwrap().version, "3.0.0");
    assert_eq!(ctrl.component_version("comp-a"), "3.0.0");
}

#[test]
fn version_restored_after_rollback() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    assert_eq!(ctrl.component_version("comp-a"), "1.0.0");

    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(ctrl.component_version("comp-a"), "2.0.0");

    ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(ctrl.component_version("comp-a"), "1.0.0");
}

#[test]
fn component_version_returns_empty_for_missing() {
    let ctrl = make_controller();
    assert_eq!(ctrl.component_version("no-such"), "");
}

#[test]
fn state_returns_none_for_missing() {
    let ctrl = make_controller();
    assert_eq!(ctrl.state("no-such"), None);
}

#[test]
fn known_good_returns_none_for_missing() {
    let ctrl = make_controller();
    assert!(ctrl.known_good("no-such").is_none());
}

#[test]
fn known_good_returns_none_before_activation() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    assert!(ctrl.known_good("comp-a").is_none());
}

#[test]
fn transition_count_increments_correctly() {
    let mut ctrl = make_controller();
    assert_eq!(ctrl.transition_count(), 0);

    activate(&mut ctrl, "comp-a", "1.0.0");
    // register(0) + Inactive->Pending(1) + Pending->Active(2) = 2 transitions
    assert_eq!(ctrl.transition_count(), 2);

    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(ctrl.transition_count(), 3);

    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    assert_eq!(ctrl.transition_count(), 4);

    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    assert_eq!(ctrl.transition_count(), 5);

    ctrl.advance_rollout("comp-a", "t").unwrap(); // default -> active
    assert_eq!(ctrl.transition_count(), 6);
}

#[test]
fn zone_accessor() {
    let ctrl = make_controller();
    assert_eq!(ctrl.zone(), "integ-zone");
    let ctrl2 = make_controller_with_config(3, 60, 30);
    assert_eq!(ctrl2.zone(), "custom-zone");
}

#[test]
fn config_accessor() {
    let ctrl = make_controller();
    let cfg = ctrl.config();
    assert_eq!(cfg.crash_threshold, 3);
    assert_eq!(cfg.crash_window_ticks, 60);
    assert_eq!(cfg.rollback_holdoff_ticks, 30);
}

#[test]
fn summary_btreemap_deterministic_ordering() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "zzz", "1.0");
    activate(&mut ctrl, "aaa", "1.0");
    activate(&mut ctrl, "mmm", "1.0");
    let summary = ctrl.summary();
    let keys: Vec<_> = summary.keys().collect();
    assert_eq!(keys, vec!["aaa", "mmm", "zzz"]);
}

// -- Crash-loop edge cases -------------------------------------------------

#[test]
fn crashes_outside_window_do_not_trigger_loop() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(10);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(100); // far outside window (60 ticks)
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(200);
    let result = ctrl.report_crash("comp-a", "t").unwrap();
    assert!(
        result.is_none(),
        "crashes outside window should not trigger loop"
    );
}

#[test]
fn crash_loop_with_custom_threshold() {
    let mut ctrl = make_controller_with_config(2, 100, 10);
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    ctrl.set_tick(10);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(11);
    let result = ctrl.report_crash("comp-a", "t").unwrap();
    assert!(result.is_some(), "threshold=2 should trigger on 2nd crash");
}

#[test]
fn crash_during_pending_activation_no_known_good() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();

    // Crash 3 times to trigger loop, but no known-good exists
    ctrl.set_tick(1);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(2);
    ctrl.report_crash("comp-a", "t").unwrap();
    ctrl.set_tick(3);
    let err = ctrl.report_crash("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
}

// -- Rollback at every rollout phase ---------------------------------------

#[test]
fn rollback_during_shadow_phase() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
    let pin = ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

#[test]
fn rollback_during_canary_phase() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap();
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Canary))
    );
    let pin = ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
}

#[test]
fn rollback_during_ramp_phase() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    assert_eq!(
        ctrl.state("comp-a"),
        Some(LifecycleState::Updating(RolloutPhase::Ramp))
    );
    let pin = ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
}

#[test]
fn rollback_from_active_state() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    // Rollback from Active should work (there is a known-good pin)
    let pin = ctrl.rollback("comp-a", "t").unwrap();
    assert_eq!(pin.version, "1.0.0");
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

// -- Multiple updates with rollbacks ---------------------------------------

#[test]
fn successive_update_rollback_cycles() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "comp-a", "1.0.0");

    for i in 2..=5u32 {
        let version = format!("{i}.0.0");
        let tick = (i as u64) * 100;
        ctrl.set_tick(tick);
        ctrl.begin_update("comp-a", descriptor("comp-a", &version), tick, "t")
            .unwrap();
        ctrl.rollback("comp-a", "t").unwrap();
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "1.0.0");
        // Wait for holdoff
        ctrl.set_tick(tick + 30);
    }
}

// -- Advance rollout past Default (already finalized) ----------------------

#[test]
fn advance_from_default_phase_finalizes() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();

    // Advance through all phases
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    // This one reaches Default
    let phase = ctrl.advance_rollout("comp-a", "t").unwrap();
    assert_eq!(phase, RolloutPhase::Default);
    // Advance past Default -> finalizes to Active
    ctrl.advance_rollout("comp-a", "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));

    // Now we're Active, trying to advance again should fail
    let err = ctrl.advance_rollout("comp-a", "t").unwrap_err();
    assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
}

// -- LifecycleError is std::error::Error -----------------------------------

#[test]
fn lifecycle_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(LifecycleError::ComponentNotFound {
        component_id: "x".to_string(),
    });
    assert!(err.to_string().contains("component not found"));
}

// -- Large batch scenario --------------------------------------------------

#[test]
fn batch_register_and_activate_many_components() {
    let mut ctrl = make_controller();
    for i in 0..50 {
        let id = format!("comp-{i:03}");
        activate(&mut ctrl, &id, "1.0.0");
    }
    assert_eq!(ctrl.component_count(), 50);
    assert_eq!(ctrl.active_count(), 50);

    let summary = ctrl.summary();
    assert_eq!(summary.len(), 50);
    // BTreeMap guarantees ordering
    let first_key = summary.keys().next().unwrap();
    assert_eq!(first_key, "comp-000");
}

// -- Secret injection timestamp uses current_tick --------------------------

#[test]
fn secret_injection_receipt_timestamp_matches_tick() {
    let mut ctrl = make_controller();
    ctrl.set_tick(777);
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    let receipt = ctrl
        .inject_secrets("comp-a", &[EphemeralSecret::new("k", vec![1])], "t")
        .unwrap();
    assert_eq!(receipt.timestamp, DeterministicTimestamp(777));
}

// -- RolloutPhase Ord trait ------------------------------------------------

#[test]
fn rollout_phase_ord_ordering() {
    assert!(RolloutPhase::Shadow < RolloutPhase::Canary);
    assert!(RolloutPhase::Canary < RolloutPhase::Ramp);
    assert!(RolloutPhase::Ramp < RolloutPhase::Default);
}

// -- LifecycleState Ord trait ----------------------------------------------

#[test]
fn lifecycle_state_ord_ordering() {
    assert!(LifecycleState::Inactive < LifecycleState::PendingActivation);
    assert!(LifecycleState::PendingActivation < LifecycleState::Active);
}

// -- TransitionTrigger Ord trait -------------------------------------------

#[test]
fn transition_trigger_ord_ordering() {
    assert!(TransitionTrigger::Manual < TransitionTrigger::Auto);
    assert!(TransitionTrigger::Auto < TransitionTrigger::CrashLoop);
}

// -- Crash-loop detector edge: threshold=1 ---------------------------------

#[test]
fn crash_loop_detector_threshold_one() {
    let mut det = CrashLoopDetector::new(1, 100);
    assert!(det.record_crash(10)); // First crash immediately triggers
}

// -- Crash-loop detector edge: zero window ---------------------------------

#[test]
fn crash_loop_detector_zero_window() {
    let mut det = CrashLoopDetector::new(2, 0);
    det.record_crash(0);
    // With window=0, cutoff = tick.saturating_sub(0) = tick, so only crashes at exact tick count
    assert!(det.record_crash(0)); // both at tick 0, window includes tick 0
}

// -- Multiple secrets injection replaces previous --------------------------

#[test]
fn inject_secrets_replaces_previous_keys() {
    let mut ctrl = make_controller();
    ctrl.register(descriptor("comp-a", "1.0.0"), "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();

    let receipt1 = ctrl
        .inject_secrets("comp-a", &[EphemeralSecret::new("key1", vec![1])], "t")
        .unwrap();
    assert_eq!(receipt1.injected_keys, vec!["key1"]);

    let receipt2 = ctrl
        .inject_secrets(
            "comp-a",
            &[
                EphemeralSecret::new("key2", vec![2]),
                EphemeralSecret::new("key3", vec![3]),
            ],
            "t",
        )
        .unwrap();
    assert_eq!(receipt2.injected_keys, vec!["key2", "key3"]);
}

// -- Component with capabilities required ----------------------------------

#[test]
fn component_with_capabilities_lifecycle() {
    let mut ctrl = make_controller();
    let desc = descriptor_with_caps("comp-a", "1.0.0", &["net", "fs", "crypto"]);
    ctrl.register(desc, "t").unwrap();
    ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "t")
        .unwrap();
    ctrl.complete_activation("comp-a", 1, "t").unwrap();
    assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
}

// -- Stress: high transition count -----------------------------------------

#[test]
fn high_transition_count_stress() {
    let mut ctrl = make_controller();
    ctrl.set_tick(0);
    activate(&mut ctrl, "comp-a", "1.0.0");

    for i in 0..20u64 {
        let tick = (i + 1) * 100;
        ctrl.set_tick(tick);
        let version = format!("{}.0.0", i + 2);
        ctrl.begin_update("comp-a", descriptor("comp-a", &version), tick, "t")
            .unwrap();
        // Complete full rollout
        ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
        ctrl.advance_rollout("comp-a", "t").unwrap(); // default
        ctrl.advance_rollout("comp-a", "t").unwrap(); // past default -> active
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    }
    // 2 (activation) + 20 * 5 (begin_update + 4 advances) = 102 transitions
    assert_eq!(ctrl.transition_count(), 102);
    assert_eq!(ctrl.known_good("comp-a").unwrap().version, "21.0.0");
}

// -- Known good pin updated after successful full rollout ------------------

#[test]
fn known_good_pin_updated_after_full_rollout() {
    let mut ctrl = make_controller();
    ctrl.set_tick(10);
    activate(&mut ctrl, "comp-a", "1.0.0");
    let pin1 = ctrl.known_good("comp-a").unwrap().clone();
    assert_eq!(pin1.version, "1.0.0");

    ctrl.set_tick(50);
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.advance_rollout("comp-a", "t").unwrap(); // canary
    ctrl.advance_rollout("comp-a", "t").unwrap(); // ramp
    ctrl.advance_rollout("comp-a", "t").unwrap(); // default
    ctrl.advance_rollout("comp-a", "t").unwrap(); // past default -> active

    let pin2 = ctrl.known_good("comp-a").unwrap();
    assert_eq!(pin2.version, "2.0.0");
    assert_eq!(pin2.version_hash, "hash-2.0.0");
    assert_eq!(pin2.activated_at, DeterministicTimestamp(50));
}

// -- LifecycleConfig custom values -----------------------------------------

#[test]
fn lifecycle_config_custom_values() {
    let cfg = LifecycleConfig {
        crash_threshold: 10,
        crash_window_ticks: 300,
        rollback_holdoff_ticks: 100,
    };
    let ctrl = ActivationLifecycleController::new(cfg, "zone-x");
    let c = ctrl.config();
    assert_eq!(c.crash_threshold, 10);
    assert_eq!(c.crash_window_ticks, 300);
    assert_eq!(c.rollback_holdoff_ticks, 100);
    assert_eq!(ctrl.zone(), "zone-x");
}

// -- Event count: rollback emits exactly two transitions -------------------

#[test]
fn rollback_emits_exactly_two_transition_events() {
    let mut ctrl = make_controller();
    activate(&mut ctrl, "comp-a", "1.0.0");
    ctrl.begin_update("comp-a", descriptor("comp-a", "2.0.0"), 2, "t")
        .unwrap();
    ctrl.drain_events();

    ctrl.rollback("comp-a", "t").unwrap();
    let events = ctrl.drain_events();
    let transitions: Vec<_> = events
        .iter()
        .filter(|e| e.event == "lifecycle_transition")
        .collect();
    assert_eq!(
        transitions.len(),
        2,
        "rollback must emit exactly 2 transitions"
    );
}

// -- Empty controller accessors --------------------------------------------

#[test]
fn empty_controller_accessors() {
    let ctrl = make_controller();
    assert_eq!(ctrl.component_count(), 0);
    assert_eq!(ctrl.active_count(), 0);
    assert_eq!(ctrl.transition_count(), 0);
    assert!(ctrl.events().is_empty());
    assert!(ctrl.summary().is_empty());
}
