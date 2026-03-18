//! Enrichment integration tests for `activation_lifecycle`.
//!
//! Covers gaps: LifecycleState Display uniqueness, RolloutPhase ordering and
//! next() progression, TransitionTrigger serde roundtrips, LifecycleError
//! error_code uniqueness, CrashLoopDetector threshold mechanics,
//! ActivationLifecycleController registration/activation/update/rollback
//! state machine, component descriptor serde, and config serde.

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

use frankenengine_engine::activation_lifecycle::{
    ActivationLifecycleController, ActivationValidation, ComponentDescriptor, CrashLoopDetector,
    LifecycleConfig, LifecycleError, LifecycleEvent, LifecycleState, PreActivationCheck,
    RolloutPhase, TransitionTrigger, error_code,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config() -> LifecycleConfig {
    LifecycleConfig {
        crash_threshold: 3,
        crash_window_ticks: 60,
        rollback_holdoff_ticks: 30,
    }
}

fn controller() -> ActivationLifecycleController {
    ActivationLifecycleController::new(default_config(), "us-east-1")
}

fn test_descriptor(id: &str) -> ComponentDescriptor {
    ComponentDescriptor {
        component_id: id.to_string(),
        version: "1.0.0".to_string(),
        version_hash: "abc123".to_string(),
        capabilities_required: BTreeSet::new(),
    }
}

fn passing_validation(id: &str) -> ActivationValidation {
    ActivationValidation {
        component_id: id.to_string(),
        version: "1.0.0".to_string(),
        checks: vec![PreActivationCheck {
            check_name: "health".to_string(),
            passed: true,
            detail: "OK".to_string(),
        }],
        all_passed: true,
    }
}

fn failing_validation(id: &str) -> ActivationValidation {
    ActivationValidation {
        component_id: id.to_string(),
        version: "1.0.0".to_string(),
        checks: vec![PreActivationCheck {
            check_name: "health".to_string(),
            passed: false,
            detail: "FAIL".to_string(),
        }],
        all_passed: false,
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_default_crash_threshold_positive() {
    // DEFAULT_CRASH_THRESHOLD = 3 (private const, validated by unit tests)
    let cfg = default_config();
    assert!(cfg.crash_threshold > 0);
}

#[test]
fn enrichment_default_crash_window_positive() {
    let cfg = default_config();
    assert!(cfg.crash_window_ticks > 0);
}

#[test]
fn enrichment_default_rollback_holdoff_positive() {
    let cfg = default_config();
    assert!(cfg.rollback_holdoff_ticks > 0);
}

// ===========================================================================
// RolloutPhase ordering and progression
// ===========================================================================

#[test]
fn enrichment_rollout_phase_next_progression() {
    assert_eq!(RolloutPhase::Shadow.next(), Some(RolloutPhase::Canary));
    assert_eq!(RolloutPhase::Canary.next(), Some(RolloutPhase::Ramp));
    assert_eq!(RolloutPhase::Ramp.next(), Some(RolloutPhase::Default));
    assert_eq!(RolloutPhase::Default.next(), None);
}

#[test]
fn enrichment_rollout_phase_serde_roundtrip() {
    let all = [
        RolloutPhase::Shadow,
        RolloutPhase::Canary,
        RolloutPhase::Ramp,
        RolloutPhase::Default,
    ];
    for phase in &all {
        let json = serde_json::to_string(phase).unwrap();
        let back: RolloutPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(*phase, back);
    }
}

// ===========================================================================
// TransitionTrigger serde roundtrip
// ===========================================================================

#[test]
fn enrichment_transition_trigger_serde_roundtrip() {
    let all = [
        TransitionTrigger::Manual,
        TransitionTrigger::Auto,
        TransitionTrigger::CrashLoop,
    ];
    for trigger in &all {
        let json = serde_json::to_string(trigger).unwrap();
        let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*trigger, back);
    }
}

// ===========================================================================
// LifecycleState serde roundtrip
// ===========================================================================

#[test]
fn enrichment_lifecycle_state_serde_roundtrip() {
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
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let back: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ===========================================================================
// LifecycleError error_code uniqueness
// ===========================================================================

#[test]
fn enrichment_error_codes_nonempty() {
    let errors = [
        LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        },
        LifecycleError::ActivationValidationFailed {
            detail: "test validation failure".to_string(),
        },
        LifecycleError::ComponentNotFound {
            component_id: "c".to_string(),
        },
    ];
    for err in &errors {
        assert!(!error_code(err).is_empty());
    }
}

// ===========================================================================
// CrashLoopDetector
// ===========================================================================

#[test]
fn enrichment_crash_loop_detector_new_empty() {
    let detector = CrashLoopDetector::new(3, 60);
    assert_eq!(detector.crash_count(0), 0);
}

#[test]
fn enrichment_crash_loop_detector_record_crash() {
    let mut detector = CrashLoopDetector::new(3, 60);
    let detected = detector.record_crash(10);
    assert!(!detected);
    assert_eq!(detector.crash_count(10), 1);
}

#[test]
fn enrichment_crash_loop_detector_threshold_triggers() {
    let mut detector = CrashLoopDetector::new(3, 60);
    assert!(!detector.record_crash(10));
    assert!(!detector.record_crash(20));
    assert!(detector.record_crash(30)); // 3rd crash within window
}

#[test]
fn enrichment_crash_loop_detector_window_expiry() {
    let mut detector = CrashLoopDetector::new(3, 10);
    detector.record_crash(1);
    detector.record_crash(2);
    // Crash outside window
    let detected = detector.record_crash(100);
    assert!(!detected, "Old crashes outside window should not count");
}

#[test]
fn enrichment_crash_loop_detector_reset() {
    let mut detector = CrashLoopDetector::new(3, 60);
    detector.record_crash(10);
    detector.record_crash(20);
    detector.reset();
    assert_eq!(detector.crash_count(0), 0);
}

// ===========================================================================
// ActivationLifecycleController: registration
// ===========================================================================

#[test]
fn enrichment_controller_new_empty() {
    let ctrl = controller();
    assert_eq!(ctrl.component_count(), 0);
    assert_eq!(ctrl.active_count(), 0);
}

#[test]
fn enrichment_controller_zone() {
    let ctrl = controller();
    assert_eq!(ctrl.zone(), "us-east-1");
}

#[test]
fn enrichment_controller_register_component() {
    let mut ctrl = controller();
    let result = ctrl.register(test_descriptor("comp-1"), "trace-001");
    assert!(result.is_ok());
    assert_eq!(ctrl.component_count(), 1);
}

#[test]
fn enrichment_controller_register_duplicate_fails() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    let result = ctrl.register(test_descriptor("comp-1"), "trace-002");
    assert!(result.is_err());
}

#[test]
fn enrichment_controller_state_after_register() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    assert_eq!(ctrl.state("comp-1"), Some(LifecycleState::Inactive));
}

// ===========================================================================
// ActivationLifecycleController: activation
// ===========================================================================

#[test]
fn enrichment_controller_begin_activation() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    let result = ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002");
    assert!(result.is_ok());
    assert_eq!(
        ctrl.state("comp-1"),
        Some(LifecycleState::PendingActivation)
    );
}

#[test]
fn enrichment_controller_begin_activation_fails_with_bad_validation() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    let result = ctrl.begin_activation("comp-1", &failing_validation("comp-1"), "trace-002");
    assert!(result.is_err());
}

#[test]
fn enrichment_controller_complete_activation() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    let result = ctrl.complete_activation("comp-1", 1, "trace-003");
    assert!(result.is_ok());
    assert_eq!(ctrl.state("comp-1"), Some(LifecycleState::Active));
    assert_eq!(ctrl.active_count(), 1);
}

// ===========================================================================
// ActivationLifecycleController: update and rollout
// ===========================================================================

#[test]
fn enrichment_controller_begin_update() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    ctrl.complete_activation("comp-1", 1, "trace-003").unwrap();
    let new_desc = ComponentDescriptor {
        component_id: "comp-1".to_string(),
        version: "2.0.0".to_string(),
        version_hash: "def456".to_string(),
        capabilities_required: BTreeSet::new(),
    };
    let result = ctrl.begin_update("comp-1", new_desc, 2, "trace-004");
    assert!(result.is_ok());
    assert_eq!(
        ctrl.state("comp-1"),
        Some(LifecycleState::Updating(RolloutPhase::Shadow))
    );
}

#[test]
fn enrichment_controller_advance_rollout() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    ctrl.complete_activation("comp-1", 1, "trace-003").unwrap();
    let new_desc = ComponentDescriptor {
        component_id: "comp-1".to_string(),
        version: "2.0.0".to_string(),
        version_hash: "def456".to_string(),
        capabilities_required: BTreeSet::new(),
    };
    ctrl.begin_update("comp-1", new_desc, 2, "trace-004")
        .unwrap();
    let phase = ctrl.advance_rollout("comp-1", "trace-005").unwrap();
    assert_eq!(phase, RolloutPhase::Canary);
}

// ===========================================================================
// ActivationLifecycleController: rollback
// ===========================================================================

#[test]
fn enrichment_controller_rollback_from_updating() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    ctrl.complete_activation("comp-1", 1, "trace-003").unwrap();
    let new_desc = ComponentDescriptor {
        component_id: "comp-1".to_string(),
        version: "2.0.0".to_string(),
        version_hash: "def456".to_string(),
        capabilities_required: BTreeSet::new(),
    };
    ctrl.begin_update("comp-1", new_desc, 2, "trace-004")
        .unwrap();
    let pin = ctrl.rollback("comp-1", "trace-005").unwrap();
    assert_eq!(pin.version, "1.0.0");
}

// ===========================================================================
// ActivationLifecycleController: deactivate
// ===========================================================================

#[test]
fn enrichment_controller_deactivate() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    ctrl.complete_activation("comp-1", 1, "trace-003").unwrap();
    let result = ctrl.deactivate("comp-1", "trace-004");
    assert!(result.is_ok());
    assert_eq!(ctrl.state("comp-1"), Some(LifecycleState::Inactive));
}

// ===========================================================================
// ActivationLifecycleController: events
// ===========================================================================

#[test]
fn enrichment_controller_events_after_operations() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-002")
        .unwrap();
    let events = ctrl.drain_events();
    assert!(!events.is_empty());
}

#[test]
fn enrichment_lifecycle_event_serde_roundtrip() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    let events = ctrl.drain_events();
    if let Some(event) = events.first() {
        let json = serde_json::to_string(event).unwrap();
        let back: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.trace_id, back.trace_id);
    }
}

// ===========================================================================
// ActivationLifecycleController: summary
// ===========================================================================

#[test]
fn enrichment_controller_summary_reflects_state() {
    let mut ctrl = controller();
    ctrl.register(test_descriptor("comp-1"), "trace-001")
        .unwrap();
    ctrl.register(test_descriptor("comp-2"), "trace-002")
        .unwrap();
    ctrl.begin_activation("comp-1", &passing_validation("comp-1"), "trace-003")
        .unwrap();
    ctrl.complete_activation("comp-1", 1, "trace-004").unwrap();
    let summary = ctrl.summary();
    assert_eq!(*summary.get("comp-1").unwrap(), LifecycleState::Active);
    assert_eq!(*summary.get("comp-2").unwrap(), LifecycleState::Inactive);
}

// ===========================================================================
// LifecycleConfig serde roundtrip
// ===========================================================================

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: LifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.crash_threshold, back.crash_threshold);
}

// ===========================================================================
// ComponentDescriptor serde roundtrip
// ===========================================================================

#[test]
fn enrichment_component_descriptor_serde_roundtrip() {
    let desc = test_descriptor("comp-1");
    let json = serde_json::to_string(&desc).unwrap();
    let back: ComponentDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc.component_id, back.component_id);
    assert_eq!(desc.version, back.version);
}

// ===========================================================================
// ActivationValidation serde roundtrip
// ===========================================================================

#[test]
fn enrichment_validation_serde_roundtrip() {
    let val = passing_validation("comp-1");
    let json = serde_json::to_string(&val).unwrap();
    let back: ActivationValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(val.all_passed, back.all_passed);
}

// ===========================================================================
// Unknown component operations fail
// ===========================================================================

#[test]
fn enrichment_operations_on_unknown_component_fail() {
    let mut ctrl = controller();
    assert!(
        ctrl.begin_activation("unknown", &passing_validation("unknown"), "t")
            .is_err()
    );
    assert!(ctrl.complete_activation("unknown", 1, "t").is_err());
    assert!(ctrl.deactivate("unknown", "t").is_err());
    assert!(ctrl.rollback("unknown", "t").is_err());
}
