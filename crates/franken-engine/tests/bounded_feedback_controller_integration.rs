#![forbid(unsafe_code)]
//! Integration tests for the `bounded_feedback_controller` module.
//!
//! Bead: bd-1lsy.7.11.3 [RGC-611C]

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::clone_on_copy,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::bounded_feedback_controller::{
    ActuatorKind, ControlAction, ControllerConfig, ControllerMode, ControllerState,
    CoordinatorHealthSummary, FEEDBACK_BEAD_ID, FEEDBACK_SCHEMA_VERSION, FeedbackCoordinator,
    FeedbackEvidenceManifest, FeedbackPolicy, LatencyObservation, LatencyTarget, PiController,
    PolicyValidationError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn default_target() -> LatencyTarget {
    LatencyTarget::new(
        ExecutionStage::ExecutionQuantum,
        LatencyPercentile::P99,
        5_000_000,  // 5ms
        200_000,    // 200us deadband
        15_000_000, // 15ms emergency
    )
}

fn obs(ns: u64) -> LatencyObservation {
    LatencyObservation {
        stage: ExecutionStage::ExecutionQuantum,
        percentile: LatencyPercentile::P99,
        observed_ns: ns,
        sample_count: 50,
        epoch: epoch(),
    }
}

fn active_config() -> ControllerConfig {
    ControllerConfig {
        warmup_epochs: 0,
        ..Default::default()
    }
}

fn make_policy(configs: Vec<(&str, ControllerConfig)>) -> FeedbackPolicy {
    let mut policy = FeedbackPolicy::default();
    for (name, config) in configs {
        policy.controllers.insert(name.into(), config);
    }
    policy.targets.push(default_target());
    policy
}

// ---------------------------------------------------------------------------
// Schema contract
// ---------------------------------------------------------------------------

#[test]
fn schema_version_stable() {
    assert_eq!(
        FEEDBACK_SCHEMA_VERSION,
        "franken-engine.bounded-feedback-controller.v1"
    );
}

#[test]
fn bead_id_correct() {
    assert_eq!(FEEDBACK_BEAD_ID, "bd-1lsy.7.11.3");
}

// ---------------------------------------------------------------------------
// ControllerMode
// ---------------------------------------------------------------------------

#[test]
fn controller_mode_serde_roundtrip() {
    for mode in [
        ControllerMode::Active,
        ControllerMode::Observe,
        ControllerMode::Disabled,
        ControllerMode::Fallback,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ControllerMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn controller_mode_ordering() {
    assert!(ControllerMode::Active < ControllerMode::Observe);
    assert!(ControllerMode::Observe < ControllerMode::Disabled);
    assert!(ControllerMode::Disabled < ControllerMode::Fallback);
}

// ---------------------------------------------------------------------------
// ActuatorKind
// ---------------------------------------------------------------------------

#[test]
fn actuator_kind_serde_roundtrip() {
    for kind in [
        ActuatorKind::AdmissionRate,
        ActuatorKind::WorkerConcurrency,
        ActuatorKind::TierThreshold,
        ActuatorKind::GcBudget,
        ActuatorKind::BatchSize,
        ActuatorKind::CacheEvictionPressure,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ActuatorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// ControlAction
// ---------------------------------------------------------------------------

#[test]
fn control_action_serde_roundtrip() {
    let actions = vec![
        ControlAction::Increase {
            delta_millionths: 100_000,
        },
        ControlAction::Decrease {
            delta_millionths: 200_000,
        },
        ControlAction::Hold,
        ControlAction::Warmup {
            epochs_remaining: 5,
        },
        ControlAction::Bypassed {
            mode: ControllerMode::Disabled,
        },
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let back: ControlAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }
}

// ---------------------------------------------------------------------------
// LatencyTarget
// ---------------------------------------------------------------------------

#[test]
fn latency_target_serde_roundtrip() {
    let target = default_target();
    let json = serde_json::to_string(&target).unwrap();
    let back: LatencyTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(target, back);
}

#[test]
fn latency_target_fields() {
    let t = LatencyTarget::new(
        ExecutionStage::Parse,
        LatencyPercentile::P999,
        1_000_000,
        50_000,
        3_000_000,
    );
    assert_eq!(t.stage, ExecutionStage::Parse);
    assert_eq!(t.percentile, LatencyPercentile::P999);
    assert_eq!(t.target_ns, 1_000_000);
    assert_eq!(t.deadband_ns, 50_000);
    assert_eq!(t.emergency_ns, 3_000_000);
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = ControllerConfig::default();
    assert_eq!(config.schema_version, FEEDBACK_SCHEMA_VERSION);
    assert_eq!(config.mode, ControllerMode::Active);
    assert_eq!(config.kp_millionths, 500_000);
    assert_eq!(config.ki_millionths, 100_000);
    assert!(config.integrator_clamp_ns > 0);
    assert!(config.output_clamp_millionths > 0);
    assert_eq!(config.warmup_epochs, 3);
}

#[test]
fn config_content_hash_stability() {
    let c1 = ControllerConfig::default();
    let c2 = ControllerConfig::default();
    assert_eq!(c1.content_hash(), c2.content_hash());
    assert!(!c1.content_hash().is_empty());
}

#[test]
fn config_content_hash_sensitivity() {
    let base = ControllerConfig::default();
    let modified = ControllerConfig {
        ki_millionths: 200_000,
        ..base.clone()
    };
    assert_ne!(base.content_hash(), modified.content_hash());
}

// ---------------------------------------------------------------------------
// PiController — warmup
// ---------------------------------------------------------------------------

#[test]
fn warmup_produces_warmup_actions() {
    let config = ControllerConfig {
        warmup_epochs: 5,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    for i in 0..5 {
        let d = ctrl.tick(&obs(10_000_000));
        match d.action {
            ControlAction::Warmup { epochs_remaining } => {
                assert_eq!(epochs_remaining, 5 - (i + 1));
            }
            _ => panic!("expected warmup at epoch {i}"),
        }
    }
}

#[test]
fn after_warmup_produces_real_action() {
    let config = ControllerConfig {
        warmup_epochs: 2,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    ctrl.tick(&obs(10_000_000)); // warmup 1
    ctrl.tick(&obs(10_000_000)); // warmup 2
    let d = ctrl.tick(&obs(10_000_000)); // real
    assert!(!matches!(d.action, ControlAction::Warmup { .. }));
}

// ---------------------------------------------------------------------------
// PiController — proportional response
// ---------------------------------------------------------------------------

#[test]
fn over_target_triggers_decrease() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(8_000_000)); // 3ms over target
    assert!(matches!(d.action, ControlAction::Decrease { .. }));
    assert_eq!(d.error_ns, 3_000_000);
}

#[test]
fn under_target_triggers_increase() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(2_000_000)); // 3ms under target
    assert!(matches!(d.action, ControlAction::Increase { .. }));
    assert_eq!(d.error_ns, -3_000_000);
}

#[test]
fn within_deadband_holds() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(5_100_000)); // 100us over — within 200us deadband
    assert_eq!(d.action, ControlAction::Hold);
}

#[test]
fn at_target_holds() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(5_000_000));
    assert_eq!(d.action, ControlAction::Hold);
}

// ---------------------------------------------------------------------------
// PiController — integral accumulation
// ---------------------------------------------------------------------------

#[test]
fn integrator_accumulates_error() {
    let mut ctrl = PiController::new(active_config(), default_target());
    ctrl.tick(&obs(8_000_000));
    assert!(ctrl.state.integrator_ns > 0);
    ctrl.tick(&obs(8_000_000));
    assert!(ctrl.state.integrator_ns > 3_000_000); // accumulated
}

#[test]
fn integrator_does_not_accumulate_in_deadband() {
    let mut ctrl = PiController::new(active_config(), default_target());
    ctrl.tick(&obs(5_100_000)); // within deadband
    assert_eq!(ctrl.state.integrator_ns, 0);
}

#[test]
fn integrator_clamped_to_bounds() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        integrator_clamp_ns: 500_000,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    for _ in 0..50 {
        ctrl.tick(&obs(10_000_000));
    }
    assert!(ctrl.state.integrator_ns <= 500_000);
}

// ---------------------------------------------------------------------------
// PiController — output saturation
// ---------------------------------------------------------------------------

#[test]
fn output_clamped_positive() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        kp_millionths: 5_000_000, // very high gain
        ki_millionths: 0,
        output_clamp_millionths: 250_000,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(50_000_000)); // huge error
    assert_eq!(d.clamped_output_millionths, 250_000);
}

#[test]
fn output_clamped_negative() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        kp_millionths: 5_000_000,
        ki_millionths: 0,
        output_clamp_millionths: 250_000,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(100_000)); // way under target
    assert_eq!(d.clamped_output_millionths, -250_000);
}

// ---------------------------------------------------------------------------
// PiController — emergency
// ---------------------------------------------------------------------------

#[test]
fn emergency_triggered_above_threshold() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(20_000_000)); // above 15ms emergency
    assert!(d.emergency);
    assert!(ctrl.state.emergency_active);
    assert_eq!(ctrl.state.emergency_count, 1);
}

#[test]
fn emergency_not_triggered_below_threshold() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let d = ctrl.tick(&obs(14_000_000)); // below 15ms emergency
    assert!(!d.emergency);
    assert!(!ctrl.state.emergency_active);
}

#[test]
fn emergency_cleared_on_recovery() {
    let mut ctrl = PiController::new(active_config(), default_target());
    ctrl.tick(&obs(20_000_000)); // emergency
    assert!(ctrl.state.emergency_active);
    ctrl.tick(&obs(5_000_000)); // recovery
    assert!(!ctrl.state.emergency_active);
    assert_eq!(ctrl.state.emergency_count, 1);
}

#[test]
fn emergency_re_entry_increments_count() {
    let mut ctrl = PiController::new(active_config(), default_target());
    ctrl.tick(&obs(20_000_000)); // emergency 1
    ctrl.tick(&obs(5_000_000)); // recovery
    ctrl.tick(&obs(20_000_000)); // emergency 2
    assert_eq!(ctrl.state.emergency_count, 2);
}

// ---------------------------------------------------------------------------
// PiController — mode bypass
// ---------------------------------------------------------------------------

#[test]
fn disabled_mode_returns_bypassed() {
    let config = ControllerConfig {
        mode: ControllerMode::Disabled,
        warmup_epochs: 0,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(100_000_000));
    assert!(matches!(
        d.action,
        ControlAction::Bypassed {
            mode: ControllerMode::Disabled
        }
    ));
    assert!(!d.emergency); // no emergency detection in bypass
}

#[test]
fn fallback_mode_returns_bypassed() {
    let config = ControllerConfig {
        mode: ControllerMode::Fallback,
        warmup_epochs: 0,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(100_000_000));
    assert!(matches!(
        d.action,
        ControlAction::Bypassed {
            mode: ControllerMode::Fallback
        }
    ));
}

#[test]
fn observe_mode_returns_bypassed() {
    let config = ControllerConfig {
        mode: ControllerMode::Observe,
        warmup_epochs: 0,
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(8_000_000));
    assert!(matches!(
        d.action,
        ControlAction::Bypassed {
            mode: ControllerMode::Observe
        }
    ));
}

// ---------------------------------------------------------------------------
// PiController — determinism
// ---------------------------------------------------------------------------

#[test]
fn decision_hash_deterministic() {
    let mut ctrl1 = PiController::new(active_config(), default_target());
    let mut ctrl2 = PiController::new(active_config(), default_target());
    let d1 = ctrl1.tick(&obs(8_000_000));
    let d2 = ctrl2.tick(&obs(8_000_000));
    assert_eq!(d1.decision_hash, d2.decision_hash);
    assert_eq!(d1.error_ns, d2.error_ns);
    assert_eq!(d1.clamped_output_millionths, d2.clamped_output_millionths);
}

#[test]
fn different_observations_different_hashes() {
    let mut ctrl1 = PiController::new(active_config(), default_target());
    let mut ctrl2 = PiController::new(active_config(), default_target());
    let d1 = ctrl1.tick(&obs(8_000_000));
    let d2 = ctrl2.tick(&obs(3_000_000));
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

// ---------------------------------------------------------------------------
// PiController — reset
// ---------------------------------------------------------------------------

#[test]
fn reset_clears_all_state() {
    let mut ctrl = PiController::new(active_config(), default_target());
    for _ in 0..5 {
        ctrl.tick(&obs(8_000_000));
    }
    assert!(ctrl.state.epoch_count > 0);
    assert!(ctrl.state.integrator_ns > 0);
    ctrl.reset();
    assert_eq!(ctrl.state.epoch_count, 0);
    assert_eq!(ctrl.state.integrator_ns, 0);
    assert_eq!(ctrl.state.last_error_ns, 0);
    assert_eq!(ctrl.state.last_output_millionths, 0);
}

// ---------------------------------------------------------------------------
// FeedbackPolicy — validation
// ---------------------------------------------------------------------------

#[test]
fn valid_policy_passes_validation() {
    let policy = make_policy(vec![("test", active_config())]);
    assert!(policy.validate().is_ok());
}

#[test]
fn no_controllers_fails() {
    let policy = FeedbackPolicy {
        enabled: true,
        ..Default::default()
    };
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::NoControllers)
    ));
}

#[test]
fn disabled_policy_with_no_controllers_passes() {
    let policy = FeedbackPolicy {
        enabled: false,
        ..Default::default()
    };
    // Disabled policy doesn't need controllers.
    // validate() checks enabled && empty, so disabled should pass.
    // Actually the code checks if controllers.is_empty() && enabled.
    assert!(policy.validate().is_ok());
}

#[test]
fn zero_target_fails() {
    let mut policy = make_policy(vec![("test", active_config())]);
    policy.targets.push(LatencyTarget::new(
        ExecutionStage::Parse,
        LatencyPercentile::P50,
        0,
        0,
        1,
    ));
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::ZeroTarget { .. })
    ));
}

#[test]
fn emergency_below_target_fails() {
    let mut policy = make_policy(vec![("test", active_config())]);
    policy.targets.push(LatencyTarget::new(
        ExecutionStage::Parse,
        LatencyPercentile::P99,
        10_000_000,
        100_000,
        5_000_000, // below target
    ));
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::EmergencyBelowTarget { .. })
    ));
}

#[test]
fn deadband_exceeds_target_fails() {
    let mut policy = make_policy(vec![("test", active_config())]);
    policy.targets.push(LatencyTarget::new(
        ExecutionStage::Parse,
        LatencyPercentile::P99,
        5_000_000,
        5_000_000, // equals target
        10_000_000,
    ));
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::DeadbandExceedsTarget { .. })
    ));
}

#[test]
fn zero_gains_fails() {
    let config = ControllerConfig {
        kp_millionths: 0,
        ki_millionths: 0,
        warmup_epochs: 0,
        ..Default::default()
    };
    let policy = make_policy(vec![("test", config)]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::ZeroGains { .. })
    ));
}

#[test]
fn invalid_clamp_fails() {
    let config = ControllerConfig {
        output_clamp_millionths: 0,
        warmup_epochs: 0,
        ..Default::default()
    };
    let policy = make_policy(vec![("test", config)]);
    assert!(matches!(
        policy.validate(),
        Err(PolicyValidationError::InvalidClamp { .. })
    ));
}

#[test]
fn policy_content_hash_stability() {
    let p1 = make_policy(vec![("test", active_config())]);
    let p2 = make_policy(vec![("test", active_config())]);
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn policy_content_hash_sensitivity() {
    let p1 = make_policy(vec![("test", active_config())]);
    let config2 = ControllerConfig {
        kp_millionths: 999_999,
        warmup_epochs: 0,
        ..Default::default()
    };
    let p2 = make_policy(vec![("test", config2)]);
    assert_ne!(p1.content_hash(), p2.content_hash());
}

// ---------------------------------------------------------------------------
// FeedbackCoordinator
// ---------------------------------------------------------------------------

#[test]
fn coordinator_construction() {
    let policy = make_policy(vec![
        ("admission", active_config()),
        (
            "gc",
            ControllerConfig {
                actuator: ActuatorKind::GcBudget,
                warmup_epochs: 0,
                ..Default::default()
            },
        ),
    ]);
    let coordinator = FeedbackCoordinator::new(policy, epoch());
    assert_eq!(coordinator.controllers.len(), 2);
}

#[test]
fn coordinator_tick_all_produces_decisions() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    let decisions = coordinator.tick_all(&[obs(8_000_000)]);
    assert_eq!(decisions.len(), 1);
    assert!(matches!(
        decisions[0].action,
        ControlAction::Decrease { .. }
    ));
}

#[test]
fn coordinator_disabled_policy_produces_no_decisions() {
    let mut policy = make_policy(vec![("test", active_config())]);
    policy.enabled = false;
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    let decisions = coordinator.tick_all(&[obs(8_000_000)]);
    assert!(decisions.is_empty());
}

#[test]
fn coordinator_no_matching_observation_skips() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    // Observation for Parse stage, controller targets Orchestration — no match.
    let parse_obs = LatencyObservation {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        observed_ns: 8_000_000,
        sample_count: 50,
        epoch: epoch(),
    };
    let decisions = coordinator.tick_all(&[parse_obs]);
    assert!(decisions.is_empty());
}

#[test]
fn coordinator_decision_log_grows() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    for _ in 0..5 {
        coordinator.tick_all(&[obs(8_000_000)]);
    }
    assert_eq!(coordinator.decision_log.len(), 5);
}

#[test]
fn coordinator_decision_log_bounded() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.max_log_entries = 3;
    for _ in 0..10 {
        coordinator.tick_all(&[obs(8_000_000)]);
    }
    assert_eq!(coordinator.decision_log.len(), 3);
}

#[test]
fn coordinator_disable_all() {
    let policy = make_policy(vec![("a", active_config()), ("b", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.disable_all();
    for ctrl in coordinator.controllers.values() {
        assert_eq!(ctrl.config.mode, ControllerMode::Disabled);
    }
}

#[test]
fn coordinator_observe_only() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.observe_only();
    for ctrl in coordinator.controllers.values() {
        assert_eq!(ctrl.config.mode, ControllerMode::Observe);
    }
}

#[test]
fn coordinator_reset_all() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.tick_all(&[obs(8_000_000)]);
    assert!(!coordinator.decision_log.is_empty());
    coordinator.reset_all();
    assert!(coordinator.decision_log.is_empty());
    for ctrl in coordinator.controllers.values() {
        assert_eq!(ctrl.state.epoch_count, 0);
    }
}

#[test]
fn coordinator_apply_policy_preserves_matching_state() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy.clone(), epoch());
    coordinator.tick_all(&[obs(8_000_000)]);
    let old_epoch = coordinator.controllers["test"].state.epoch_count;
    coordinator.apply_policy(policy);
    assert_eq!(coordinator.controllers["test"].state.epoch_count, old_epoch);
}

#[test]
fn coordinator_apply_policy_resets_on_change() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.tick_all(&[obs(8_000_000)]);

    let mut new_policy = make_policy(vec![(
        "test",
        ControllerConfig {
            kp_millionths: 999_999,
            warmup_epochs: 0,
            ..Default::default()
        },
    )]);
    new_policy.targets.clear();
    new_policy.targets.push(default_target());
    coordinator.apply_policy(new_policy);
    assert_eq!(coordinator.controllers["test"].state.epoch_count, 0);
}

#[test]
fn coordinator_apply_policy_adds_new_controllers() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    assert_eq!(coordinator.controllers.len(), 1);

    let new_policy = make_policy(vec![
        ("test", active_config()),
        (
            "gc",
            ControllerConfig {
                actuator: ActuatorKind::GcBudget,
                warmup_epochs: 0,
                ..Default::default()
            },
        ),
    ]);
    coordinator.apply_policy(new_policy);
    assert_eq!(coordinator.controllers.len(), 2);
}

// ---------------------------------------------------------------------------
// CoordinatorHealthSummary
// ---------------------------------------------------------------------------

#[test]
fn health_summary_reports_counts() {
    let policy = make_policy(vec![
        ("a", active_config()),
        (
            "b",
            ControllerConfig {
                mode: ControllerMode::Disabled,
                warmup_epochs: 0,
                ..Default::default()
            },
        ),
    ]);
    let coordinator = FeedbackCoordinator::new(policy, epoch());
    let summary = coordinator.health_summary();
    assert_eq!(summary.total_controllers, 2);
    assert_eq!(summary.active_controllers, 1);
    assert_eq!(summary.controllers_in_emergency, 0);
}

#[test]
fn health_summary_reports_emergency() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.tick_all(&[obs(20_000_000)]); // emergency
    let summary = coordinator.health_summary();
    assert_eq!(summary.controllers_in_emergency, 1);
    assert_eq!(summary.total_emergency_activations, 1);
}

#[test]
fn health_summary_serde_roundtrip() {
    let policy = make_policy(vec![("test", active_config())]);
    let coordinator = FeedbackCoordinator::new(policy, epoch());
    let summary = coordinator.health_summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: CoordinatorHealthSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// FeedbackEvidenceManifest
// ---------------------------------------------------------------------------

#[test]
fn evidence_manifest_construction() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.tick_all(&[obs(20_000_000)]); // emergency
    let manifest = FeedbackEvidenceManifest::from_coordinator(&coordinator);
    assert_eq!(manifest.bead_id, FEEDBACK_BEAD_ID);
    assert_eq!(manifest.controller_count, 1);
    assert_eq!(manifest.decision_count, 1);
    assert_eq!(manifest.emergency_count, 1);
    assert!(!manifest.manifest_hash.is_empty());
}

#[test]
fn evidence_manifest_serde_roundtrip() {
    let policy = make_policy(vec![("test", active_config())]);
    let coordinator = FeedbackCoordinator::new(policy, epoch());
    let manifest = FeedbackEvidenceManifest::from_coordinator(&coordinator);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: FeedbackEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn evidence_manifest_hash_deterministic() {
    let policy = make_policy(vec![("test", active_config())]);
    let c1 = FeedbackCoordinator::new(policy.clone(), epoch());
    let c2 = FeedbackCoordinator::new(policy, epoch());
    let m1 = FeedbackEvidenceManifest::from_coordinator(&c1);
    let m2 = FeedbackEvidenceManifest::from_coordinator(&c2);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

// ---------------------------------------------------------------------------
// Convergence and steady-state behavior
// ---------------------------------------------------------------------------

#[test]
fn sustained_over_target_drives_output_up() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let mut last_output = 0i64;
    for _ in 0..10 {
        let d = ctrl.tick(&obs(7_000_000)); // 2ms over target
        last_output = d.clamped_output_millionths;
    }
    assert!(
        last_output > 0,
        "output should be positive (decrease), got {last_output}"
    );
}

#[test]
fn sustained_under_target_drives_output_down() {
    let mut ctrl = PiController::new(active_config(), default_target());
    let mut last_output = 0i64;
    for _ in 0..10 {
        let d = ctrl.tick(&obs(2_000_000)); // 3ms under target
        last_output = d.clamped_output_millionths;
    }
    assert!(
        last_output < 0,
        "output should be negative (increase), got {last_output}"
    );
}

#[test]
fn integrator_grows_with_sustained_error() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        integrator_clamp_ns: 100_000_000, // high clamp
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let mut prev_integrator = 0i64;
    for i in 0..5 {
        ctrl.tick(&obs(8_000_000));
        if i > 0 {
            assert!(
                ctrl.state.integrator_ns > prev_integrator,
                "integrator should grow, epoch {i}"
            );
        }
        prev_integrator = ctrl.state.integrator_ns;
    }
}

// ---------------------------------------------------------------------------
// Deadband override
// ---------------------------------------------------------------------------

#[test]
fn deadband_override_widens_deadband() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        deadband_override_ns: Some(2_000_000), // 2ms override
        ..Default::default()
    };
    let target = LatencyTarget::new(
        ExecutionStage::ExecutionQuantum,
        LatencyPercentile::P99,
        5_000_000,
        100_000, // narrow original
        15_000_000,
    );
    let mut ctrl = PiController::new(config, target);
    let d = ctrl.tick(&obs(6_500_000)); // 1.5ms over — inside 2ms override
    assert_eq!(d.action, ControlAction::Hold);
}

#[test]
fn deadband_override_does_not_prevent_large_errors() {
    let config = ControllerConfig {
        warmup_epochs: 0,
        deadband_override_ns: Some(500_000),
        ..Default::default()
    };
    let mut ctrl = PiController::new(config, default_target());
    let d = ctrl.tick(&obs(8_000_000)); // 3ms over — outside 500us override
    assert!(matches!(d.action, ControlAction::Decrease { .. }));
}

// ---------------------------------------------------------------------------
// Multi-controller coordination
// ---------------------------------------------------------------------------

#[test]
fn multi_controller_independent_decisions() {
    let policy = make_policy(vec![
        ("admission", active_config()),
        (
            "gc",
            ControllerConfig {
                actuator: ActuatorKind::GcBudget,
                warmup_epochs: 0,
                ..Default::default()
            },
        ),
    ]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    let decisions = coordinator.tick_all(&[obs(8_000_000)]);
    // Both should match because both target Orchestration stage.
    assert_eq!(decisions.len(), 2);
}

// ---------------------------------------------------------------------------
// PolicyValidationError display
// ---------------------------------------------------------------------------

#[test]
fn validation_error_display() {
    let err = PolicyValidationError::NoControllers;
    assert_eq!(err.to_string(), "no controllers configured");

    let err = PolicyValidationError::ZeroTarget {
        stage: ExecutionStage::ExecutionQuantum,
    };
    assert!(err.to_string().contains("zero target"));

    let err = PolicyValidationError::ZeroGains {
        actuator: ActuatorKind::AdmissionRate,
    };
    assert!(err.to_string().contains("Kp and Ki"));
}

#[test]
fn validation_error_serde_roundtrip() {
    let errors = vec![
        PolicyValidationError::NoControllers,
        PolicyValidationError::ZeroTarget {
            stage: ExecutionStage::Parse,
        },
        PolicyValidationError::EmergencyBelowTarget {
            stage: ExecutionStage::ExecutionQuantum,
            target_ns: 5_000_000,
            emergency_ns: 4_000_000,
        },
        PolicyValidationError::ZeroGains {
            actuator: ActuatorKind::GcBudget,
        },
        PolicyValidationError::InvalidClamp {
            actuator: ActuatorKind::BatchSize,
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let back: PolicyValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ---------------------------------------------------------------------------
// Full serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn feedback_coordinator_serde_roundtrip() {
    let policy = make_policy(vec![("test", active_config())]);
    let mut coordinator = FeedbackCoordinator::new(policy, epoch());
    coordinator.tick_all(&[obs(8_000_000)]);
    let json = serde_json::to_string(&coordinator).unwrap();
    let back: FeedbackCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(coordinator.controllers.len(), back.controllers.len());
    assert_eq!(coordinator.decision_log.len(), back.decision_log.len());
}

#[test]
fn controller_state_default() {
    let state = ControllerState::default();
    assert_eq!(state.integrator_ns, 0);
    assert_eq!(state.epoch_count, 0);
    assert_eq!(state.last_error_ns, 0);
    assert_eq!(state.last_output_millionths, 0);
    assert!(!state.emergency_active);
    assert_eq!(state.emergency_count, 0);
}

#[test]
fn latency_observation_serde_roundtrip() {
    let o = obs(5_000_000);
    let json = serde_json::to_string(&o).unwrap();
    let back: LatencyObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}
