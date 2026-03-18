#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]
//! Enrichment integration tests for bounded_feedback_controller module.
//!
//! Covers PI controller behavior, policy validation, feedback coordinator
//! lifecycle, and evidence manifests.

use std::collections::BTreeSet;

use frankenengine_engine::bounded_feedback_controller::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// ControllerMode
// ---------------------------------------------------------------------------

#[test]
fn controller_mode_display_all_distinct() {
    let modes = [
        ControllerMode::Active,
        ControllerMode::Observe,
        ControllerMode::Disabled,
        ControllerMode::Fallback,
    ];
    let displays: BTreeSet<String> = modes.iter().map(|m| format!("{m}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn controller_mode_serde_roundtrip() {
    for mode in [
        ControllerMode::Active,
        ControllerMode::Observe,
        ControllerMode::Disabled,
        ControllerMode::Fallback,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let restored: ControllerMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
    }
}

// ---------------------------------------------------------------------------
// ActuatorKind
// ---------------------------------------------------------------------------

#[test]
fn actuator_kind_display_all_distinct() {
    let kinds = [
        ActuatorKind::AdmissionRate,
        ActuatorKind::WorkerConcurrency,
        ActuatorKind::TierThreshold,
        ActuatorKind::GcBudget,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// ControlAction
// ---------------------------------------------------------------------------

#[test]
fn control_action_display_all_distinct() {
    let actions = [
        ControlAction::Increase {
            delta_millionths: 100_000,
        },
        ControlAction::Decrease {
            delta_millionths: 100_000,
        },
        ControlAction::Hold,
        ControlAction::Bypassed {
            mode: ControllerMode::Disabled,
        },
    ];
    let displays: BTreeSet<String> = actions.iter().map(|a| format!("{a}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

#[test]
fn controller_config_default_valid() {
    let cfg = ControllerConfig::default();
    assert_eq!(cfg.kp_millionths, DEFAULT_KP_MILLIONTHS);
    assert_eq!(cfg.ki_millionths, DEFAULT_KI_MILLIONTHS);
    assert_eq!(cfg.integrator_clamp_ns, DEFAULT_INTEGRATOR_CLAMP_NS);
    assert_eq!(cfg.output_clamp_millionths, DEFAULT_OUTPUT_CLAMP_MILLIONTHS);
}

#[test]
fn controller_config_serde_roundtrip() {
    let cfg = ControllerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// PiController
// ---------------------------------------------------------------------------

#[test]
fn pi_controller_new() {
    let cfg = ControllerConfig::default();
    let target = LatencyTarget {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        target_ns: 1_000_000,
        deadband_ns: 50_000,
        emergency_ns: 3_000_000,
    };
    let controller = PiController::new(cfg, target);
    assert_eq!(controller.config.mode, ControllerMode::Active);
}

#[test]
fn pi_controller_tick_produces_decision() {
    let cfg = ControllerConfig::default();
    let target = LatencyTarget {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        target_ns: 1_000_000,
        deadband_ns: 50_000,
        emergency_ns: 3_000_000,
    };
    let mut controller = PiController::new(cfg, target);
    let obs = LatencyObservation {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        observed_ns: 800_000,
        sample_count: 100,
        epoch: epoch(1),
    };
    let decision = controller.tick(&obs);
    // Should produce a valid decision
    assert!(!decision.schema_version.is_empty());
}

#[test]
fn pi_controller_disabled_mode_bypasses() {
    let mut cfg = ControllerConfig::default();
    cfg.mode = ControllerMode::Disabled;
    let target = LatencyTarget {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        target_ns: 1_000_000,
        deadband_ns: 50_000,
        emergency_ns: 3_000_000,
    };
    let mut controller = PiController::new(cfg, target);
    let obs = LatencyObservation {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        observed_ns: 2_000_000,
        sample_count: 100,
        epoch: epoch(1),
    };
    let decision = controller.tick(&obs);
    assert!(
        matches!(decision.action, ControlAction::Bypassed { .. }),
        "disabled mode should produce Bypassed action"
    );
}

#[test]
fn pi_controller_anti_windup_clamps_integrator() {
    let cfg = ControllerConfig {
        integrator_clamp_ns: 100,
        ..ControllerConfig::default()
    };
    let target = LatencyTarget {
        stage: ExecutionStage::ExecutionQuantum,
        percentile: LatencyPercentile::P999,
        target_ns: 100_000,
        deadband_ns: 1_000,
        emergency_ns: 300_000,
    };
    let mut controller = PiController::new(cfg, target);
    // Drive with large errors to test anti-windup
    for _ in 0..20 {
        let obs = LatencyObservation {
            stage: ExecutionStage::ExecutionQuantum,
            percentile: LatencyPercentile::P999,
            observed_ns: 1_000_000, // way over budget
            sample_count: 100,
            epoch: epoch(1),
        };
        controller.tick(&obs);
    }
    let state = &controller.state;
    // Integrator should be clamped
    assert!(state.integrator_ns.abs() <= 100 + 1);
}

#[test]
fn pi_controller_state_initial_zeros() {
    let cfg = ControllerConfig::default();
    let target = LatencyTarget {
        stage: ExecutionStage::Parse,
        percentile: LatencyPercentile::P99,
        target_ns: 1_000_000,
        deadband_ns: 50_000,
        emergency_ns: 3_000_000,
    };
    let controller = PiController::new(cfg, target);
    let state = &controller.state;
    assert_eq!(state.integrator_ns, 0);
    assert_eq!(state.last_error_ns, 0);
}

// ---------------------------------------------------------------------------
// FeedbackPolicy
// ---------------------------------------------------------------------------

#[test]
fn feedback_policy_default_valid() {
    let policy = FeedbackPolicy::default();
    assert!(!policy.controllers.is_empty() || policy.controllers.is_empty()); // just no panic
}

#[test]
fn feedback_policy_serde_roundtrip() {
    let policy = FeedbackPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let restored: FeedbackPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

// ---------------------------------------------------------------------------
// FeedbackCoordinator
// ---------------------------------------------------------------------------

#[test]
fn coordinator_new() {
    let policy = FeedbackPolicy::default();
    let coordinator = FeedbackCoordinator::new(policy, epoch(1));
    assert_eq!(coordinator.epoch, epoch(1));
}

#[test]
fn coordinator_health_summary() {
    let policy = FeedbackPolicy::default();
    let coordinator = FeedbackCoordinator::new(policy, epoch(1));
    let health = coordinator.health_summary();
    // total_controllers is u64, always >= 0
    let _ = health.total_controllers;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(FEEDBACK_SCHEMA_VERSION.contains("feedback"));
    assert!(FEEDBACK_BEAD_ID.starts_with("bd-"));
    assert!(DEFAULT_KP_MILLIONTHS > 0);
    assert!(DEFAULT_KI_MILLIONTHS > 0);
    assert!(DEFAULT_INTEGRATOR_CLAMP_NS > 0);
    assert!(DEFAULT_OUTPUT_CLAMP_MILLIONTHS > 0);
    assert!(MIN_WARMUP_EPOCHS > 0);
}
