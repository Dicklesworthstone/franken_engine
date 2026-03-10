//! Integration tests for tail_latency_feedback_control module: PID feedback
//! controller, latency targets, discrete control actions, percentile estimation,
//! policy overrides, and audit-trail content hashing.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tail_latency_feedback_control::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: u64 = 1_000_000;

fn make_target(percentile: u64, budget_nanos: u64, tolerance: u64) -> LatencyTarget {
    LatencyTarget::new(percentile, budget_nanos, tolerance)
}

fn make_sample(id: &str, latency_nanos: u64) -> LatencySample {
    LatencySample::new(id, 1_000, latency_nanos, 990_000, "integration-test")
}

fn make_sample_at(id: &str, latency_nanos: u64, percentile: u64, stage: &str) -> LatencySample {
    LatencySample::new(id, 1_000, latency_nanos, percentile, stage)
}

/// Proportional-only config (I=0, D=0), wide output range.
fn proportional_only_config(p_gain: u64) -> ControllerConfig {
    ControllerConfig {
        proportional_gain_millionths: p_gain,
        integral_gain_millionths: 0,
        derivative_gain_millionths: 0,
        max_integral_windup: 10_000_000,
        min_control_output: -10_000_000,
        max_control_output: 10_000_000,
        sample_window_size: 100,
    }
}

/// Integral-only config.
fn integral_only_config(i_gain: u64, windup_limit: i64) -> ControllerConfig {
    ControllerConfig {
        proportional_gain_millionths: 0,
        integral_gain_millionths: i_gain,
        derivative_gain_millionths: 0,
        max_integral_windup: windup_limit,
        min_control_output: -10_000_000,
        max_control_output: 10_000_000,
        sample_window_size: 100,
    }
}

/// Derivative-only config.
fn derivative_only_config(d_gain: u64) -> ControllerConfig {
    ControllerConfig {
        proportional_gain_millionths: 0,
        integral_gain_millionths: 0,
        derivative_gain_millionths: d_gain,
        max_integral_windup: 10_000_000,
        min_control_output: -10_000_000,
        max_control_output: 10_000_000,
        sample_window_size: 100,
    }
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_schema_version_present() {
    assert!(FEEDBACK_CONTROL_SCHEMA_VERSION.contains("tail-latency-feedback-control"));
    assert!(FEEDBACK_CONTROL_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn constants_bead_id_nonempty() {
    assert!(!FEEDBACK_CONTROL_BEAD_ID.is_empty());
    assert!(FEEDBACK_CONTROL_BEAD_ID.starts_with("bd-"));
}

#[test]
fn constants_policy_id_nonempty() {
    assert!(!FEEDBACK_CONTROL_POLICY_ID.is_empty());
    assert!(FEEDBACK_CONTROL_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn constants_component_matches_module_name() {
    assert_eq!(COMPONENT, "tail_latency_feedback_control");
}

// ===========================================================================
// 2. ControlAction
// ===========================================================================

#[test]
fn control_action_display_hold() {
    assert_eq!(format!("{}", ControlAction::Hold), "hold");
}

#[test]
fn control_action_display_scale_up() {
    assert_eq!(format!("{}", ControlAction::ScaleUp(42)), "scale_up(42)");
}

#[test]
fn control_action_display_scale_down() {
    assert_eq!(
        format!("{}", ControlAction::ScaleDown(99)),
        "scale_down(99)"
    );
}

#[test]
fn control_action_display_shed() {
    assert_eq!(format!("{}", ControlAction::Shed(500)), "shed(500)");
}

#[test]
fn control_action_display_emergency_brake() {
    assert_eq!(
        format!("{}", ControlAction::EmergencyBrake),
        "emergency_brake"
    );
}

#[test]
fn control_action_serde_roundtrip_all_variants() {
    let variants = vec![
        ControlAction::Hold,
        ControlAction::ScaleUp(123_456),
        ControlAction::ScaleDown(789_000),
        ControlAction::Shed(1_500_000),
        ControlAction::EmergencyBrake,
    ];
    for action in &variants {
        let json = serde_json::to_string(action).unwrap();
        let decoded: ControlAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, decoded, "roundtrip failed for {action}");
    }
}

#[test]
fn control_action_ord_ordering() {
    // Enum-derived Ord: Hold < ScaleUp < ScaleDown < Shed < EmergencyBrake
    assert!(ControlAction::Hold < ControlAction::ScaleUp(0));
    assert!(ControlAction::ScaleUp(0) < ControlAction::ScaleDown(0));
    assert!(ControlAction::ScaleDown(0) < ControlAction::Shed(0));
    assert!(ControlAction::Shed(0) < ControlAction::EmergencyBrake);
}

// ===========================================================================
// 3. LatencyTarget
// ===========================================================================

#[test]
fn latency_target_new_stores_fields() {
    let t = LatencyTarget::new(990_000, 5_000_000, 50_000);
    assert_eq!(t.percentile_millionths, 990_000);
    assert_eq!(t.budget_nanos, 5_000_000);
    assert_eq!(t.tolerance_millionths, 50_000);
}

#[test]
fn latency_target_upper_bound_with_tolerance() {
    // budget=1_000_000, tolerance=100_000 (10%)
    // tolerance_nanos = 1_000_000 * 100_000 / 1_000_000 = 100_000
    let t = make_target(990_000, 1_000_000, 100_000);
    assert_eq!(t.upper_bound_nanos(), 1_100_000);
}

#[test]
fn latency_target_upper_bound_zero_tolerance() {
    let t = make_target(990_000, 2_000_000, 0);
    assert_eq!(t.upper_bound_nanos(), 2_000_000);
}

#[test]
fn latency_target_display_format() {
    let t = make_target(990_000, 500_000, 50_000);
    let s = format!("{t}");
    assert!(s.contains("990000"));
    assert!(s.contains("500000"));
    assert!(s.contains("50000"));
}

#[test]
fn latency_target_serde_roundtrip() {
    let t = make_target(950_000, 10_000_000, 25_000);
    let json = serde_json::to_string(&t).unwrap();
    let decoded: LatencyTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(t, decoded);
}

// ===========================================================================
// 4. ControllerConfig
// ===========================================================================

#[test]
fn controller_config_default_has_reasonable_gains() {
    let cfg = ControllerConfig::default_config();
    assert!(cfg.proportional_gain_millionths > 0);
    assert!(cfg.integral_gain_millionths > 0);
    assert!(cfg.derivative_gain_millionths > 0);
    assert!(cfg.max_integral_windup > 0);
    assert!(cfg.min_control_output < 0);
    assert!(cfg.max_control_output > 0);
    assert!(cfg.sample_window_size > 0);
}

#[test]
fn controller_config_serde_roundtrip() {
    let cfg = ControllerConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

#[test]
fn controller_config_display_contains_gains() {
    let cfg = ControllerConfig::default_config();
    let s = format!("{cfg}");
    assert!(s.contains("PID("));
    assert!(s.contains(&cfg.proportional_gain_millionths.to_string()));
}

// ===========================================================================
// 5. ControllerState
// ===========================================================================

#[test]
fn controller_state_new_initial_values() {
    let state = ControllerState::new("ctrl-1", epoch(5));
    assert_eq!(state.state_id, "ctrl-1");
    assert_eq!(state.epoch, epoch(5));
    assert_eq!(state.error_integral, 0);
    assert_eq!(state.previous_error, 0);
    assert_eq!(state.sample_count, 0);
    assert_eq!(state.current_action, ControlAction::Hold);
    assert_eq!(state.last_latency_nanos, 0);
}

#[test]
fn controller_state_rehash_deterministic() {
    let mut s1 = ControllerState::new("det", epoch(10));
    let mut s2 = ControllerState::new("det", epoch(10));
    s1.rehash();
    s2.rehash();
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn controller_state_initial_action_is_hold() {
    let state = ControllerState::new("test", epoch(1));
    assert_eq!(state.current_action, ControlAction::Hold);
}

#[test]
fn controller_state_content_hash_differs_for_different_ids() {
    let s1 = ControllerState::new("alpha", epoch(1));
    let s2 = ControllerState::new("beta", epoch(1));
    assert_ne!(s1.content_hash, s2.content_hash);
}

#[test]
fn controller_state_serde_roundtrip() {
    let state = ControllerState::new("serde-test", epoch(42));
    let json = serde_json::to_string(&state).unwrap();
    let decoded: ControllerState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, decoded);
}

// ===========================================================================
// 6. compute_error
// ===========================================================================

#[test]
fn compute_error_exact_match_returns_zero() {
    let t = make_target(990_000, 1_000_000, 0);
    assert_eq!(compute_error(&t, 1_000_000), 0);
}

#[test]
fn compute_error_over_budget_returns_positive() {
    let t = make_target(990_000, 1_000_000, 0);
    // Observed = 1.5M => diff = 500K => (500K * 1M) / 1M = 500_000
    let err = compute_error(&t, 1_500_000);
    assert_eq!(err, 500_000);
}

#[test]
fn compute_error_under_budget_returns_negative() {
    let t = make_target(990_000, 1_000_000, 0);
    let err = compute_error(&t, 750_000);
    assert_eq!(err, -250_000);
}

#[test]
fn compute_error_zero_budget_nonzero_observed_returns_max() {
    let t = make_target(990_000, 0, 0);
    assert_eq!(compute_error(&t, 1), i64::MAX);
}

#[test]
fn compute_error_zero_budget_zero_observed_returns_zero() {
    let t = make_target(990_000, 0, 0);
    assert_eq!(compute_error(&t, 0), 0);
}

// ===========================================================================
// 7. pid_step
// ===========================================================================

#[test]
fn pid_step_proportional_only_maps_error_directly() {
    let cfg = proportional_only_config(MILLION); // gain=1.0
    let mut state = ControllerState::new("p-only", epoch(1));

    let dec = pid_step(&cfg, &mut state, 500_000);
    assert_eq!(dec.proportional, 500_000);
    assert_eq!(dec.integral, 0);
    assert_eq!(dec.derivative, 0);
    assert_eq!(dec.raw_output, 500_000);
}

#[test]
fn pid_step_integral_accumulates_across_steps() {
    let cfg = integral_only_config(MILLION, 10_000_000);
    let mut state = ControllerState::new("i-accum", epoch(1));

    let d1 = pid_step(&cfg, &mut state, 300_000);
    assert_eq!(d1.integral, 300_000);

    let d2 = pid_step(&cfg, &mut state, 200_000);
    // integral = 300_000 + 200_000 = 500_000
    assert_eq!(d2.integral, 500_000);

    let d3 = pid_step(&cfg, &mut state, -100_000);
    // integral = 500_000 + (-100_000) = 400_000
    assert_eq!(d3.integral, 400_000);
}

#[test]
fn pid_step_anti_windup_clamps_integral() {
    let cfg = integral_only_config(MILLION, 1_000_000); // windup limit = 1M
    let mut state = ControllerState::new("windup", epoch(1));

    // Push integral far past the limit
    pid_step(&cfg, &mut state, 5_000_000);
    assert_eq!(state.error_integral, 1_000_000); // clamped

    pid_step(&cfg, &mut state, 5_000_000);
    assert_eq!(state.error_integral, 1_000_000); // still clamped

    // Negative windup clamp
    let mut state2 = ControllerState::new("windup-neg", epoch(1));
    pid_step(&cfg, &mut state2, -5_000_000);
    assert_eq!(state2.error_integral, -1_000_000);
}

#[test]
fn pid_step_derivative_tracks_error_change() {
    let cfg = derivative_only_config(MILLION); // gain=1.0
    let mut state = ControllerState::new("d-test", epoch(1));

    // First step: derivative = (error - 0) = error
    let d1 = pid_step(&cfg, &mut state, 400_000);
    assert_eq!(d1.derivative, 400_000);

    // Second step: derivative = (200_000 - 400_000) = -200_000
    let d2 = pid_step(&cfg, &mut state, 200_000);
    assert_eq!(d2.derivative, -200_000);

    // Third step: derivative = (200_000 - 200_000) = 0
    let d3 = pid_step(&cfg, &mut state, 200_000);
    assert_eq!(d3.derivative, 0);
}

#[test]
fn pid_step_output_clamping_upper() {
    let cfg = ControllerConfig {
        proportional_gain_millionths: MILLION,
        integral_gain_millionths: 0,
        derivative_gain_millionths: 0,
        max_integral_windup: 10_000_000,
        min_control_output: -500_000,
        max_control_output: 500_000,
        sample_window_size: 100,
    };
    let mut state = ControllerState::new("clamp-up", epoch(1));

    let dec = pid_step(&cfg, &mut state, 3_000_000);
    assert_eq!(dec.raw_output, 3_000_000);
    assert_eq!(dec.clamped_output, 500_000);
}

#[test]
fn pid_step_output_clamping_lower() {
    let cfg = ControllerConfig {
        proportional_gain_millionths: MILLION,
        integral_gain_millionths: 0,
        derivative_gain_millionths: 0,
        max_integral_windup: 10_000_000,
        min_control_output: -500_000,
        max_control_output: 500_000,
        sample_window_size: 100,
    };
    let mut state = ControllerState::new("clamp-lo", epoch(1));

    let dec = pid_step(&cfg, &mut state, -3_000_000);
    assert_eq!(dec.raw_output, -3_000_000);
    assert_eq!(dec.clamped_output, -500_000);
}

#[test]
fn pid_step_emergency_brake_at_high_error() {
    // With default config, error=4M should produce high output => emergency brake
    let cfg = ControllerConfig {
        proportional_gain_millionths: MILLION,
        integral_gain_millionths: 0,
        derivative_gain_millionths: 0,
        max_integral_windup: 10_000_000,
        min_control_output: -10_000_000,
        max_control_output: 10_000_000,
        sample_window_size: 100,
    };
    let mut state = ControllerState::new("ebrake", epoch(1));

    let dec = pid_step(&cfg, &mut state, 4_000_000);
    // raw_output = 4_000_000, clamped = 4_000_000 (within range)
    // 4_000_000 >= 2_000_000 => EmergencyBrake
    assert_eq!(dec.action, ControlAction::EmergencyBrake);
}

#[test]
fn pid_step_updates_sample_count_and_previous_error() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("track", epoch(1));

    assert_eq!(state.sample_count, 0);
    assert_eq!(state.previous_error, 0);

    pid_step(&cfg, &mut state, 123_456);
    assert_eq!(state.sample_count, 1);
    assert_eq!(state.previous_error, 123_456);

    pid_step(&cfg, &mut state, 789_000);
    assert_eq!(state.sample_count, 2);
    assert_eq!(state.previous_error, 789_000);
}

// ===========================================================================
// 8. action_from_output
// ===========================================================================

#[test]
fn action_from_output_hold_range() {
    assert_eq!(action_from_output(0), ControlAction::Hold);
    assert_eq!(action_from_output(99_999), ControlAction::Hold);
    assert_eq!(action_from_output(-99_999), ControlAction::Hold);
    assert_eq!(action_from_output(1), ControlAction::Hold);
    assert_eq!(action_from_output(-1), ControlAction::Hold);
}

#[test]
fn action_from_output_scale_up_boundary() {
    assert_eq!(action_from_output(100_000), ControlAction::ScaleUp(100_000));
    assert_eq!(action_from_output(999_999), ControlAction::ScaleUp(999_999));
}

#[test]
fn action_from_output_scale_down_boundary() {
    assert_eq!(
        action_from_output(-100_000),
        ControlAction::ScaleDown(100_000)
    );
    assert_eq!(
        action_from_output(-500_000),
        ControlAction::ScaleDown(500_000)
    );
}

#[test]
fn action_from_output_shed_boundary() {
    assert_eq!(
        action_from_output(1_000_000),
        ControlAction::Shed(1_000_000)
    );
    assert_eq!(
        action_from_output(1_999_999),
        ControlAction::Shed(1_999_999)
    );
}

#[test]
fn action_from_output_emergency_brake_boundary() {
    assert_eq!(action_from_output(2_000_000), ControlAction::EmergencyBrake);
    assert_eq!(action_from_output(5_000_000), ControlAction::EmergencyBrake);
    assert_eq!(action_from_output(i64::MAX), ControlAction::EmergencyBrake);
}

// ===========================================================================
// 9. is_in_violation
// ===========================================================================

#[test]
fn is_in_violation_within_target_returns_false() {
    let t = make_target(990_000, 1_000_000, 50_000);
    // upper_bound = 1_000_000 + 1_000_000*50_000/1_000_000 = 1_050_000
    assert!(!is_in_violation(&t, 900_000));
    assert!(!is_in_violation(&t, 1_000_000));
}

#[test]
fn is_in_violation_exactly_at_boundary_returns_false() {
    let t = make_target(990_000, 1_000_000, 50_000);
    // upper_bound = 1_050_000; exactly at boundary => not in violation (> not >=)
    assert!(!is_in_violation(&t, 1_050_000));
}

#[test]
fn is_in_violation_exceeds_boundary_returns_true() {
    let t = make_target(990_000, 1_000_000, 50_000);
    assert!(is_in_violation(&t, 1_050_001));
    assert!(is_in_violation(&t, 2_000_000));
}

// ===========================================================================
// 10. estimate_percentile
// ===========================================================================

#[test]
fn estimate_percentile_empty_returns_zero() {
    assert_eq!(estimate_percentile(&[], 990_000), 0);
}

#[test]
fn estimate_percentile_single_sample_any_percentile() {
    let samples = vec![make_sample("only", 42_000)];
    assert_eq!(estimate_percentile(&samples, 500_000), 42_000); // p50
    assert_eq!(estimate_percentile(&samples, 990_000), 42_000); // p99
    assert_eq!(estimate_percentile(&samples, MILLION), 42_000); // p100
}

#[test]
fn estimate_percentile_p99_from_100_samples() {
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), i * 1_000))
        .collect();
    // p99 = 990_000 millionths => rank = ceil(0.99 * 100) = 99 => value = 99_000
    assert_eq!(estimate_percentile(&samples, 990_000), 99_000);
}

#[test]
fn estimate_percentile_p50_from_100_samples() {
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), i * 1_000))
        .collect();
    // p50 = 500_000 millionths => rank = ceil(0.50 * 100) = 50 => value = 50_000
    assert_eq!(estimate_percentile(&samples, 500_000), 50_000);
}

#[test]
fn estimate_percentile_unsorted_input_produces_correct_result() {
    let samples = vec![
        make_sample("a", 90_000),
        make_sample("b", 10_000),
        make_sample("c", 50_000),
        make_sample("d", 30_000),
        make_sample("e", 70_000),
    ];
    // sorted: [10K, 30K, 50K, 70K, 90K]
    // p50 => rank = ceil(0.5 * 5) = 3 => 50_000
    assert_eq!(estimate_percentile(&samples, 500_000), 50_000);
}

#[test]
fn estimate_percentile_p100_returns_max() {
    let samples: Vec<LatencySample> = (1..=10)
        .map(|i| make_sample(&format!("s{i}"), i * 100))
        .collect();
    // p100 => rank = ceil(1.0 * 10) = 10 => max = 1000
    assert_eq!(estimate_percentile(&samples, MILLION), 1_000);
}

// ===========================================================================
// 11. build_feedback_report
// ===========================================================================

#[test]
fn build_feedback_report_empty_targets_full_compliance() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("rpt-empty", epoch(1));

    let report = build_feedback_report(&[], &[], &cfg, &mut state, &epoch(1));
    assert_eq!(report.violations_count, 0);
    assert_eq!(report.compliance_rate_millionths, MILLION);
    assert!(report.decisions.is_empty());
    assert!(report.targets.is_empty());
}

#[test]
fn build_feedback_report_detects_violations() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("rpt-viol", epoch(1));
    let targets = vec![make_target(990_000, 100_000, 0)];
    // All samples at 200K, far above 100K budget with 0 tolerance
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), 200_000))
        .collect();

    let report = build_feedback_report(&targets, &samples, &cfg, &mut state, &epoch(1));
    assert_eq!(report.violations_count, 1);
    assert_eq!(report.decisions.len(), 1);
    assert!(report.decisions[0].error_millionths > 0);
    // 0 of 1 target compliant => 0 compliance
    assert_eq!(report.compliance_rate_millionths, 0);
}

#[test]
fn build_feedback_report_compliance_rate_partial() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("rpt-partial", epoch(1));
    // Two targets: p50 at 500K (easy to meet), p99 at 50K (will violate)
    let targets = vec![
        make_target(500_000, 500_000, 0), // p50 budget=500K
        make_target(990_000, 50_000, 0),  // p99 budget=50K (will violate)
    ];
    // Uniform samples at 100K each
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), 100_000))
        .collect();

    let report = build_feedback_report(&targets, &samples, &cfg, &mut state, &epoch(1));
    // p50 estimate = 100K <= 500K budget => compliant
    // p99 estimate = 100K > 50K budget => violation
    assert_eq!(report.violations_count, 1);
    assert_eq!(report.decisions.len(), 2);
    // 1 of 2 compliant => 500_000 millionths
    assert_eq!(report.compliance_rate_millionths, 500_000);
}

#[test]
fn build_feedback_report_deterministic_content_hash() {
    let cfg = ControllerConfig::default_config();
    let targets = vec![make_target(990_000, 1_000_000, 50_000)];
    let samples: Vec<LatencySample> = (1..=10)
        .map(|i| make_sample(&format!("s{i}"), i * 10_000))
        .collect();

    let mut state1 = ControllerState::new("det", epoch(7));
    let r1 = build_feedback_report(&targets, &samples, &cfg, &mut state1, &epoch(7));

    let mut state2 = ControllerState::new("det", epoch(7));
    let r2 = build_feedback_report(&targets, &samples, &cfg, &mut state2, &epoch(7));

    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.report_id, r2.report_id);
}

#[test]
fn build_feedback_report_updates_state_epoch() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("epoch-track", epoch(1));
    let targets = vec![make_target(990_000, 1_000_000, 0)];

    let report = build_feedback_report(&targets, &[], &cfg, &mut state, &epoch(5));
    assert_eq!(state.epoch, epoch(5));
    assert_eq!(report.epoch, epoch(5));
}

// ===========================================================================
// 12. apply_override
// ===========================================================================

#[test]
fn apply_override_forces_action_within_epoch() {
    let mut state = ControllerState::new("ov-test", epoch(5));
    assert_eq!(state.current_action, ControlAction::Hold);

    let over = PolicyOverride::new(
        "ov-1",
        ControlAction::EmergencyBrake,
        "safety drill",
        epoch(10),
    );
    apply_override(&mut state, &over);
    assert_eq!(state.current_action, ControlAction::EmergencyBrake);
}

#[test]
fn apply_override_ignores_expired_override() {
    let mut state = ControllerState::new("ov-expired", epoch(15));
    let original_hash = state.content_hash.clone();

    let over = PolicyOverride::new(
        "ov-old",
        ControlAction::Shed(999),
        "stale override",
        epoch(10), // expired — state is at epoch 15
    );
    apply_override(&mut state, &over);
    assert_eq!(state.current_action, ControlAction::Hold);
    assert_eq!(state.content_hash, original_hash);
}

#[test]
fn apply_override_at_exact_expiry_epoch_still_applies() {
    let mut state = ControllerState::new("ov-exact", epoch(10));
    let over = PolicyOverride::new(
        "ov-edge",
        ControlAction::ScaleDown(42),
        "edge case",
        epoch(10), // exact match
    );
    apply_override(&mut state, &over);
    assert_eq!(state.current_action, ControlAction::ScaleDown(42));
}

// ===========================================================================
// 13. reset_controller
// ===========================================================================

#[test]
fn reset_controller_clears_integral_and_derivative() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("reset-test", epoch(1));

    // Accumulate state
    pid_step(&cfg, &mut state, 800_000);
    pid_step(&cfg, &mut state, 400_000);
    assert_ne!(state.error_integral, 0);
    assert_ne!(state.previous_error, 0);

    reset_controller(&mut state);
    assert_eq!(state.error_integral, 0);
    assert_eq!(state.previous_error, 0);
}

#[test]
fn reset_controller_preserves_sample_count_and_action() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("reset-preserve", epoch(1));

    pid_step(&cfg, &mut state, 200_000);
    pid_step(&cfg, &mut state, 100_000);
    let count_before = state.sample_count;
    let action_before = state.current_action;

    reset_controller(&mut state);
    assert_eq!(state.sample_count, count_before);
    assert_eq!(state.current_action, action_before);
}

#[test]
fn reset_controller_rehashes_state() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("reset-hash", epoch(1));
    pid_step(&cfg, &mut state, 500_000);
    let hash_before = state.content_hash.clone();

    reset_controller(&mut state);
    // Hash should change because integral and previous_error changed
    assert_ne!(state.content_hash, hash_before);
}

// ===========================================================================
// 14. Manifest
// ===========================================================================

#[test]
fn manifest_is_nonempty_and_valid() {
    let m = franken_engine_feedback_control_manifest();
    assert!(!m.report_id.is_empty());
    assert!(m.targets.is_empty());
    assert!(m.decisions.is_empty());
    assert_eq!(m.violations_count, 0);
    assert_eq!(m.compliance_rate_millionths, MILLION);
    assert_eq!(m.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn manifest_deterministic_across_calls() {
    let m1 = franken_engine_feedback_control_manifest();
    let m2 = franken_engine_feedback_control_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.report_id, m2.report_id);
    assert_eq!(m1.current_state, m2.current_state);
}

// ===========================================================================
// 15. PolicyOverride
// ===========================================================================

#[test]
fn policy_override_new_computes_hash() {
    let over = PolicyOverride::new("po-1", ControlAction::Hold, "no action", epoch(5));
    assert_eq!(over.override_id, "po-1");
    assert_eq!(over.action, ControlAction::Hold);
    assert_eq!(over.reason, "no action");
    assert_eq!(over.expires_epoch, epoch(5));
    // hash should be non-zero
    assert_ne!(over.content_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn policy_override_deterministic_hash() {
    let o1 = PolicyOverride::new("x", ControlAction::Shed(100), "r", epoch(3));
    let o2 = PolicyOverride::new("x", ControlAction::Shed(100), "r", epoch(3));
    assert_eq!(o1.content_hash, o2.content_hash);
}

#[test]
fn policy_override_different_actions_different_hash() {
    let o1 = PolicyOverride::new("x", ControlAction::Hold, "r", epoch(3));
    let o2 = PolicyOverride::new("x", ControlAction::EmergencyBrake, "r", epoch(3));
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn policy_override_serde_roundtrip() {
    let over = PolicyOverride::new("po-serde", ControlAction::ScaleUp(42), "test", epoch(99));
    let json = serde_json::to_string(&over).unwrap();
    let decoded: PolicyOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(over, decoded);
}

#[test]
fn policy_override_display() {
    let over = PolicyOverride::new("po-disp", ControlAction::Shed(10), "reason", epoch(7));
    let s = format!("{over}");
    assert!(s.contains("po-disp"));
    assert!(s.contains("shed(10)"));
    assert!(s.contains("7"));
}

// ===========================================================================
// 16. LatencySample
// ===========================================================================

#[test]
fn latency_sample_new_stores_fields() {
    let s = LatencySample::new("ls-1", 5_000, 12_000, 990_000, "parse");
    assert_eq!(s.sample_id, "ls-1");
    assert_eq!(s.timestamp_nanos, 5_000);
    assert_eq!(s.latency_nanos, 12_000);
    assert_eq!(s.percentile_millionths, 990_000);
    assert_eq!(s.stage, "parse");
}

#[test]
fn latency_sample_display() {
    let s = make_sample("disp-1", 42_000);
    let d = format!("{s}");
    assert!(d.contains("disp-1"));
    assert!(d.contains("42000"));
}

#[test]
fn latency_sample_serde_roundtrip() {
    let s = make_sample_at("serde-ls", 77_000, 950_000, "codegen");
    let json = serde_json::to_string(&s).unwrap();
    let decoded: LatencySample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, decoded);
}

// ===========================================================================
// 17. ControlDecision audit trail
// ===========================================================================

#[test]
fn control_decision_has_nonempty_rationale() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("rationale", epoch(1));
    let dec = pid_step(&cfg, &mut state, 250_000);
    assert!(!dec.rationale.is_empty());
    assert!(dec.rationale.contains("PID step"));
}

#[test]
fn control_decision_content_hash_deterministic() {
    let cfg = ControllerConfig::default_config();

    let mut s1 = ControllerState::new("det-dec", epoch(1));
    let d1 = pid_step(&cfg, &mut s1, 300_000);

    let mut s2 = ControllerState::new("det-dec", epoch(1));
    let d2 = pid_step(&cfg, &mut s2, 300_000);

    assert_eq!(d1.content_hash, d2.content_hash);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn control_decision_serde_roundtrip() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("serde-dec", epoch(1));
    let dec = pid_step(&cfg, &mut state, 100_000);

    let json = serde_json::to_string(&dec).unwrap();
    let decoded: ControlDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, decoded);
}

#[test]
fn control_decision_display_contains_key_fields() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("disp-dec", epoch(1));
    let dec = pid_step(&cfg, &mut state, 500_000);
    let s = format!("{dec}");
    assert!(s.contains("Decision("));
    assert!(s.contains("err="));
    assert!(s.contains("action="));
}

// ===========================================================================
// 18. FeedbackControlReport serde
// ===========================================================================

#[test]
fn feedback_report_serde_roundtrip() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("serde-rpt", epoch(2));
    let targets = vec![make_target(990_000, 1_000_000, 50_000)];
    let samples: Vec<LatencySample> = (1..=20)
        .map(|i| make_sample(&format!("s{i}"), i * 5_000))
        .collect();

    let report = build_feedback_report(&targets, &samples, &cfg, &mut state, &epoch(2));
    let json = serde_json::to_string(&report).unwrap();
    let decoded: FeedbackControlReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}

// ===========================================================================
// 19. End-to-end scenario: rising latency triggers escalation
// ===========================================================================

#[test]
fn scenario_rising_latency_escalates_through_actions() {
    let cfg = proportional_only_config(MILLION); // gain=1.0, wide output
    let mut state = ControllerState::new("escalation", epoch(1));
    let target = make_target(990_000, 100_000, 0);

    // Phase 1: within budget => Hold
    let err1 = compute_error(&target, 100_000); // 0 error
    let d1 = pid_step(&cfg, &mut state, err1);
    assert_eq!(d1.action, ControlAction::Hold);

    // Phase 2: 20% over budget => ScaleUp
    let err2 = compute_error(&target, 120_000); // 200_000 error
    let d2 = pid_step(&cfg, &mut state, err2);
    assert_eq!(d2.action, ControlAction::ScaleUp(200_000));

    // Phase 3: 2x budget => Shed
    let err3 = compute_error(&target, 200_000); // 1_000_000 error
    let d3 = pid_step(&cfg, &mut state, err3);
    assert_eq!(d3.action, ControlAction::Shed(1_000_000));

    // Phase 4: 3x budget => EmergencyBrake
    let err4 = compute_error(&target, 300_000); // 2_000_000 error
    let d4 = pid_step(&cfg, &mut state, err4);
    assert_eq!(d4.action, ControlAction::EmergencyBrake);
}

// ===========================================================================
// 20. End-to-end scenario: override then reset
// ===========================================================================

#[test]
fn scenario_override_then_reset_returns_to_clean_state() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("ov-reset", epoch(1));

    // Accumulate some PID state
    pid_step(&cfg, &mut state, 500_000);
    pid_step(&cfg, &mut state, 300_000);
    assert_ne!(state.error_integral, 0);

    // Apply override
    let over = PolicyOverride::new("ov-1", ControlAction::EmergencyBrake, "drill", epoch(100));
    apply_override(&mut state, &over);
    assert_eq!(state.current_action, ControlAction::EmergencyBrake);

    // Reset controller
    reset_controller(&mut state);
    assert_eq!(state.error_integral, 0);
    assert_eq!(state.previous_error, 0);
    // Action is preserved through reset (EmergencyBrake still)
    assert_eq!(state.current_action, ControlAction::EmergencyBrake);
    // But sample count is also preserved
    assert_eq!(state.sample_count, 2);
}

// ===========================================================================
// 21. Multi-target report with mixed compliance
// ===========================================================================

#[test]
fn build_feedback_report_multiple_targets_mixed() {
    let cfg = ControllerConfig::default_config();
    let mut state = ControllerState::new("multi", epoch(3));

    // Three targets with varying budgets
    let targets = vec![
        make_target(500_000, 1_000_000, 0), // p50 at 1ms — generous
        make_target(990_000, 200_000, 0),   // p99 at 200us — tight
        make_target(999_000, 100_000, 0),   // p99.9 at 100us — very tight
    ];

    // Samples: latencies from 50K to 500K nanos (linearly)
    let samples: Vec<LatencySample> = (1..=100)
        .map(|i| make_sample(&format!("s{i}"), 50_000 + i * 4_500))
        .collect();

    let report = build_feedback_report(&targets, &samples, &cfg, &mut state, &epoch(3));
    assert_eq!(report.decisions.len(), 3);
    assert_eq!(report.targets.len(), 3);
    // At least one violation should occur (p99.9 at 100K is tight)
    assert!(report.violations_count >= 1);
    // Report should embed the state snapshot
    assert_eq!(report.current_state.state_id, "multi");
}
