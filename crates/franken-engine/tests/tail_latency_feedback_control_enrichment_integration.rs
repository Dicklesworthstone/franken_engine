//! Enrichment integration tests for `tail_latency_feedback_control`.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tail_latency_feedback_control::*;

const MILLIONTHS: u64 = 1_000_000;

fn make_target(percentile: u64, budget_nanos: u64, tolerance: u64) -> LatencyTarget {
    LatencyTarget::new(percentile, budget_nanos, tolerance)
}

fn make_sample(id: &str, latency_nanos: u64) -> LatencySample {
    LatencySample::new(id, 1000, latency_nanos, 990_000, "test")
}

// ---------------------------------------------------------------------------
// ControlAction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_control_action_display_shed() {
    assert_eq!(format!("{}", ControlAction::Shed(500)), "shed(500)");
}

#[test]
fn enrichment_control_action_display_scale_down() {
    assert_eq!(
        format!("{}", ControlAction::ScaleDown(200)),
        "scale_down(200)"
    );
}

#[test]
fn enrichment_control_action_ord() {
    assert!(ControlAction::Hold < ControlAction::ScaleUp(1));
}

// ---------------------------------------------------------------------------
// LatencyTarget
// ---------------------------------------------------------------------------

#[test]
fn enrichment_latency_target_upper_bound_large_tolerance() {
    let target = make_target(990_000, 1_000_000, 500_000);
    // tolerance_nanos = 1_000_000 * 500_000 / 1_000_000 = 500_000
    assert_eq!(target.upper_bound_nanos(), 1_500_000);
}

#[test]
fn enrichment_latency_target_display() {
    let target = make_target(990_000, 1_000_000, 50_000);
    let display = format!("{target}");
    assert!(display.contains("990000"));
    assert!(display.contains("1000000"));
}

#[test]
fn enrichment_latency_target_clone_eq() {
    let t1 = make_target(990_000, 100, 0);
    let t2 = t1.clone();
    assert_eq!(t1, t2);
}

// ---------------------------------------------------------------------------
// ControllerConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_controller_config_default_gains_positive() {
    let cfg = ControllerConfig::default_config();
    assert!(cfg.proportional_gain_millionths > 0);
    assert!(cfg.integral_gain_millionths > 0);
    assert!(cfg.derivative_gain_millionths > 0);
}

#[test]
fn enrichment_controller_config_default_window_size() {
    let cfg = ControllerConfig::default();
    assert_eq!(cfg.sample_window_size, 100);
}

#[test]
fn enrichment_controller_config_display() {
    let cfg = ControllerConfig::default();
    let display = format!("{cfg}");
    assert!(display.contains("PID("));
    assert!(display.contains("window="));
}

#[test]
fn enrichment_controller_config_serde_roundtrip() {
    let cfg = ControllerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// ControllerState
// ---------------------------------------------------------------------------

#[test]
fn enrichment_controller_state_initial_hold() {
    let state = ControllerState::new("init", SecurityEpoch::from_raw(1));
    assert_eq!(state.current_action, ControlAction::Hold);
    assert_eq!(state.sample_count, 0);
    assert_eq!(state.error_integral, 0);
}

#[test]
fn enrichment_controller_state_display() {
    let state = ControllerState::new("x", SecurityEpoch::from_raw(5));
    let display = format!("{state}");
    assert!(display.contains("epoch=5"));
    assert!(display.contains("samples=0"));
}

#[test]
fn enrichment_controller_state_rehash_changes_hash() {
    let mut state = ControllerState::new("test", SecurityEpoch::from_raw(1));
    let h1 = state.content_hash;
    state.error_integral = 999;
    state.rehash();
    assert_ne!(h1, state.content_hash);
}

// ---------------------------------------------------------------------------
// LatencySample
// ---------------------------------------------------------------------------

#[test]
fn enrichment_latency_sample_new() {
    let s = LatencySample::new("s1", 100, 42_000, 990_000, "parse");
    assert_eq!(s.sample_id, "s1");
    assert_eq!(s.latency_nanos, 42_000);
    assert_eq!(s.stage, "parse");
}

#[test]
fn enrichment_latency_sample_display() {
    let s = LatencySample::new("s1", 100, 42_000, 990_000, "parse");
    let display = format!("{s}");
    assert!(display.contains("42000ns"));
    assert!(display.contains("stage=parse"));
}

#[test]
fn enrichment_latency_sample_serde_roundtrip() {
    let s = LatencySample::new("s1", 100, 42_000, 990_000, "exec");
    let json = serde_json::to_string(&s).unwrap();
    let back: LatencySample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// compute_error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compute_error_double_budget() {
    let target = make_target(990_000, 500_000, 0);
    let err = compute_error(&target, 1_000_000);
    assert_eq!(err, 1_000_000);
}

#[test]
fn enrichment_compute_error_half_budget() {
    let target = make_target(990_000, 1_000_000, 0);
    let err = compute_error(&target, 500_000);
    assert_eq!(err, -500_000);
}

// ---------------------------------------------------------------------------
// action_from_output
// ---------------------------------------------------------------------------

#[test]
fn enrichment_action_from_output_boundary_scale_up() {
    assert_eq!(action_from_output(100_000), ControlAction::ScaleUp(100_000));
}

#[test]
fn enrichment_action_from_output_boundary_shed() {
    assert_eq!(
        action_from_output(1_000_000),
        ControlAction::Shed(1_000_000)
    );
}

#[test]
fn enrichment_action_from_output_boundary_emergency() {
    assert_eq!(action_from_output(2_000_000), ControlAction::EmergencyBrake);
}

// ---------------------------------------------------------------------------
// is_in_violation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_is_in_violation_exact_upper_bound_not_violated() {
    let target = make_target(990_000, 1_000_000, 100_000);
    assert!(!is_in_violation(&target, 1_100_000));
}

#[test]
fn enrichment_is_in_violation_one_over_upper_bound() {
    let target = make_target(990_000, 1_000_000, 100_000);
    assert!(is_in_violation(&target, 1_100_001));
}

// ---------------------------------------------------------------------------
// estimate_percentile
// ---------------------------------------------------------------------------

#[test]
fn enrichment_estimate_percentile_two_samples() {
    let samples = vec![make_sample("a", 100), make_sample("b", 200)];
    let p50 = estimate_percentile(&samples, 500_000);
    assert_eq!(p50, 100);
}

#[test]
fn enrichment_estimate_percentile_all_same() {
    let samples: Vec<LatencySample> = (0..10).map(|i| make_sample(&format!("s{i}"), 42)).collect();
    assert_eq!(estimate_percentile(&samples, 990_000), 42);
}

// ---------------------------------------------------------------------------
// build_feedback_report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_report_content_hash_deterministic() {
    let cfg = ControllerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let targets = vec![make_target(990_000, 100_000, 0)];
    let samples: Vec<LatencySample> = (1..=10)
        .map(|i| make_sample(&format!("s{i}"), 50_000))
        .collect();

    let mut s1 = ControllerState::new("det", epoch);
    let r1 = build_feedback_report(&targets, &samples, &cfg, &mut s1, &epoch);

    let mut s2 = ControllerState::new("det", epoch);
    let r2 = build_feedback_report(&targets, &samples, &cfg, &mut s2, &epoch);

    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_build_report_with_two_violations() {
    let cfg = ControllerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let targets = vec![
        make_target(500_000, 10_000, 0),
        make_target(990_000, 10_000, 0),
    ];
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), 100_000))
        .collect();

    let mut state = ControllerState::new("viol", epoch);
    let report = build_feedback_report(&targets, &samples, &cfg, &mut state, &epoch);
    assert_eq!(report.violations_count, 2);
    assert_eq!(report.compliance_rate_millionths, 0);
}

// ---------------------------------------------------------------------------
// PolicyOverride
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_override_display() {
    let ov = PolicyOverride::new(
        "ov-1",
        ControlAction::Shed(100),
        "test",
        SecurityEpoch::from_raw(10),
    );
    let display = format!("{ov}");
    assert!(display.contains("ov-1"));
    assert!(display.contains("shed(100)"));
}

#[test]
fn enrichment_policy_override_at_exact_expiry_applies() {
    let epoch = SecurityEpoch::from_raw(10);
    let mut state = ControllerState::new("test", epoch);
    let ov = PolicyOverride::new(
        "ov-1",
        ControlAction::EmergencyBrake,
        "reason",
        SecurityEpoch::from_raw(10),
    );
    apply_override(&mut state, &ov);
    assert_eq!(state.current_action, ControlAction::EmergencyBrake);
}

// ---------------------------------------------------------------------------
// reset_controller
// ---------------------------------------------------------------------------

#[test]
fn enrichment_reset_preserves_action() {
    let cfg = ControllerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ControllerState::new("test", epoch);
    pid_step(&cfg, &mut state, 500_000);
    let action_before = state.current_action;
    reset_controller(&mut state);
    assert_eq!(state.current_action, action_before);
}

// ---------------------------------------------------------------------------
// franken_engine_feedback_control_manifest
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_compliance_full() {
    let manifest = franken_engine_feedback_control_manifest();
    assert_eq!(manifest.compliance_rate_millionths, MILLIONTHS);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let manifest = franken_engine_feedback_control_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: FeedbackControlReport = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.report_id, back.report_id);
}

// ---------------------------------------------------------------------------
// ControlDecision Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_control_decision_display_contains_action() {
    let cfg = ControllerConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ControllerState::new("test", epoch);
    let d = pid_step(&cfg, &mut state, 0);
    let display = format!("{d}");
    assert!(display.contains("Decision("));
    assert!(display.contains("action="));
}

// ---------------------------------------------------------------------------
// FeedbackControlReport Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feedback_report_display_contains_epoch() {
    let manifest = franken_engine_feedback_control_manifest();
    let display = format!("{manifest}");
    assert!(display.contains("FeedbackControlReport("));
    assert!(display.contains("epoch="));
}
