#![forbid(unsafe_code)]
//! Integration tests for the `optimal_stopping` module.
//!
//! Exercises every public type, constant, enum variant, method, error path,
//! and cross-concern lifecycle scenario from outside the crate boundary.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::optimal_stopping::{
    CusumChart, EscalationPolicy, GittinsArm, GittinsIndexComputer, Observation,
    OptimalStoppingCertificate, STOPPING_SCHEMA_VERSION, SecretarySelector, SnellEnvelope,
    StoppingDecision, StoppingError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn obs(llr: i64, risk: i64, ts: u64) -> Observation {
    Observation {
        llr_millionths: llr,
        risk_score_millionths: risk,
        timestamp_us: ts,
        source: "integ".to_string(),
    }
}

fn obs_with_source(llr: i64, risk: i64, ts: u64, src: &str) -> Observation {
    Observation {
        llr_millionths: llr,
        risk_score_millionths: risk,
        timestamp_us: ts,
        source: src.to_string(),
    }
}

// ===========================================================================
// Section 1 — Constants
// ===========================================================================

#[test]
fn schema_version_non_empty() {
    assert!(!STOPPING_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_version_starts_with_franken_engine() {
    assert!(STOPPING_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ===========================================================================
// Section 2 — StoppingError
// ===========================================================================

#[test]
fn stopping_error_display_horizon_too_large() {
    let err = StoppingError::HorizonTooLarge {
        horizon: 20_000,
        max: 10_000,
    };
    let s = err.to_string();
    assert!(s.contains("20000"));
    assert!(s.contains("10000"));
}

#[test]
fn stopping_error_display_invalid_threshold() {
    let err = StoppingError::InvalidThreshold { threshold: -99 };
    let s = err.to_string();
    assert!(s.contains("-99"));
}

#[test]
fn stopping_error_display_invalid_discount() {
    let err = StoppingError::InvalidDiscount {
        discount: 2_000_000,
    };
    let s = err.to_string();
    assert!(s.contains("2000000"));
}

#[test]
fn stopping_error_display_empty_observations() {
    let err = StoppingError::EmptyObservations;
    assert!(!err.to_string().is_empty());
}

#[test]
fn stopping_error_display_degenerate_kl() {
    let err = StoppingError::DegenerateKL;
    let s = err.to_string();
    assert!(s.contains("KL"));
}

#[test]
fn stopping_error_display_index_oob() {
    let err = StoppingError::IndexOutOfBounds { index: 5, size: 3 };
    let s = err.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("3"));
}

#[test]
fn stopping_error_all_display_unique() {
    let errs = [
        StoppingError::HorizonTooLarge { horizon: 1, max: 0 },
        StoppingError::InvalidThreshold { threshold: 0 },
        StoppingError::InvalidDiscount { discount: 0 },
        StoppingError::EmptyObservations,
        StoppingError::DegenerateKL,
        StoppingError::IndexOutOfBounds { index: 0, size: 0 },
    ];
    let uniq: BTreeSet<String> = errs.iter().map(|e| e.to_string()).collect();
    assert_eq!(uniq.len(), 6);
}

#[test]
fn stopping_error_serde_roundtrip_all_variants() {
    let variants = vec![
        StoppingError::HorizonTooLarge {
            horizon: 50_000,
            max: 10_000,
        },
        StoppingError::InvalidThreshold { threshold: -1 },
        StoppingError::InvalidDiscount { discount: -42 },
        StoppingError::EmptyObservations,
        StoppingError::DegenerateKL,
        StoppingError::IndexOutOfBounds { index: 7, size: 3 },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: StoppingError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn stopping_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(StoppingError::EmptyObservations);
    assert!(!err.to_string().is_empty());
    assert!(std::error::Error::source(err.as_ref()).is_none());
}

// ===========================================================================
// Section 3 — StoppingDecision
// ===========================================================================

#[test]
fn stopping_decision_display() {
    assert_eq!(StoppingDecision::Continue.to_string(), "continue");
    assert_eq!(StoppingDecision::Stop.to_string(), "stop");
}

#[test]
fn stopping_decision_ord() {
    assert!(StoppingDecision::Continue < StoppingDecision::Stop);
}

#[test]
fn stopping_decision_serde_roundtrip() {
    for d in [StoppingDecision::Continue, StoppingDecision::Stop] {
        let json = serde_json::to_string(&d).unwrap();
        let back: StoppingDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn stopping_decision_clone_eq() {
    let a = StoppingDecision::Stop;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Section 4 — Observation
// ===========================================================================

#[test]
fn observation_construction_and_fields() {
    let o = obs(500_000, 700_000, 42);
    assert_eq!(o.llr_millionths, 500_000);
    assert_eq!(o.risk_score_millionths, 700_000);
    assert_eq!(o.timestamp_us, 42);
    assert_eq!(o.source, "integ");
}

#[test]
fn observation_serde_roundtrip() {
    let o = obs_with_source(123_456, 789_012, 99, "sensor-alpha");
    let json = serde_json::to_string(&o).unwrap();
    let back: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

#[test]
fn observation_clone_eq() {
    let a = obs(1, 2, 3);
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Section 5 — CusumChart
// ===========================================================================

#[test]
fn cusum_new_valid() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    assert_eq!(chart.statistic_millionths, 0);
    assert_eq!(chart.threshold_millionths, 5_000_000);
    assert_eq!(chart.reference_millionths, 500_000);
    assert_eq!(chart.observations, 0);
    assert_eq!(chart.high_water_mark_millionths, 0);
    assert!(!chart.signaled);
    assert_eq!(chart.signal_round, 0);
}

#[test]
fn cusum_invalid_threshold_zero() {
    let err = CusumChart::new(0, 500_000).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::InvalidThreshold { threshold: 0 }
    ));
}

#[test]
fn cusum_invalid_threshold_negative() {
    let err = CusumChart::new(-10, 500_000).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::InvalidThreshold { threshold: -10 }
    ));
}

#[test]
fn cusum_with_defaults_valid_state() {
    let chart = CusumChart::with_defaults();
    assert!(chart.threshold_millionths > 0);
    assert!(chart.reference_millionths >= 0);
    assert!(!chart.signaled);
    assert_eq!(chart.observations, 0);
}

#[test]
fn cusum_signals_on_sustained_anomaly() {
    let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
    let mut stopped = false;
    for i in 0u64..20 {
        let d = chart.observe(&obs(1_000_000, 800_000, i));
        if d == StoppingDecision::Stop {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    assert!(chart.signaled);
    assert!(chart.signal_round > 0);
    assert!(chart.high_water_mark_millionths >= chart.threshold_millionths);
}

#[test]
fn cusum_continues_on_benign_traffic() {
    let mut chart = CusumChart::new(5_000_000, 500_000).unwrap();
    for i in 0u64..50 {
        let d = chart.observe(&obs(100_000, 100_000, i));
        assert_eq!(d, StoppingDecision::Continue);
    }
    assert!(!chart.signaled);
    assert_eq!(chart.observations, 50);
}

#[test]
fn cusum_statistic_never_goes_negative() {
    let mut chart = CusumChart::new(5_000_000, 500_000).unwrap();
    for i in 0u64..10 {
        chart.observe(&obs(-5_000_000, 0, i));
    }
    assert!(chart.statistic_millionths >= 0);
}

#[test]
fn cusum_extreme_negative_llr_no_overflow() {
    let mut chart = CusumChart::new(1_000_000, 500_000).unwrap();
    let d = chart.observe(&obs(i64::MIN, 0, 0));
    assert_eq!(d, StoppingDecision::Continue);
    assert_eq!(chart.statistic_millionths, 0);
}

#[test]
fn cusum_reset_clears_signal_but_keeps_observation_count() {
    let mut chart = CusumChart::new(2_000_000, 500_000).unwrap();
    for i in 0u64..10 {
        chart.observe(&obs(1_000_000, 800_000, i));
    }
    assert!(chart.signaled);
    let obs_before = chart.observations;
    let hwm_before = chart.high_water_mark_millionths;
    chart.reset();
    assert!(!chart.signaled);
    assert_eq!(chart.statistic_millionths, 0);
    assert_eq!(chart.signal_round, 0);
    // Observations and high_water_mark preserved for audit.
    assert_eq!(chart.observations, obs_before);
    assert_eq!(chart.high_water_mark_millionths, hwm_before);
}

#[test]
fn cusum_keeps_signaling_stop_after_trigger() {
    let mut chart = CusumChart::new(1_000_000, 0).unwrap();
    // First observation triggers.
    let d1 = chart.observe(&obs(2_000_000, 500_000, 0));
    assert_eq!(d1, StoppingDecision::Stop);
    // All subsequent observations also Stop.
    let d2 = chart.observe(&obs(100, 100, 1));
    assert_eq!(d2, StoppingDecision::Stop);
}

#[test]
fn cusum_arl0_lower_bound_positive_mean() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    let arl0 = chart.arl0_lower_bound(MILLION);
    assert!(arl0 > MILLION);
}

#[test]
fn cusum_arl0_lower_bound_zero_mean() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    let arl0 = chart.arl0_lower_bound(0);
    assert_eq!(arl0, i64::MAX);
}

#[test]
fn cusum_arl0_lower_bound_negative_mean() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    let arl0 = chart.arl0_lower_bound(-1);
    assert_eq!(arl0, i64::MAX);
}

#[test]
fn cusum_serde_roundtrip() {
    let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
    chart.observe(&obs(1_000_000, 500_000, 0));
    let json = serde_json::to_string(&chart).unwrap();
    let back: CusumChart = serde_json::from_str(&json).unwrap();
    assert_eq!(chart, back);
}

#[test]
fn cusum_high_water_mark_tracks_peak() {
    let mut chart = CusumChart::new(10_000_000, 0).unwrap();
    chart.observe(&obs(3_000_000, 0, 0));
    let hwm1 = chart.high_water_mark_millionths;
    chart.observe(&obs(-5_000_000, 0, 1)); // statistic drops to 0
    // High-water mark stays at peak.
    assert_eq!(chart.high_water_mark_millionths, hwm1);
}

// ===========================================================================
// Section 6 — GittinsIndexComputer / GittinsArm
// ===========================================================================

#[test]
fn gittins_new_valid() {
    let gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
    assert_eq!(gc.arms.len(), 2);
    assert_eq!(gc.discount_millionths, 900_000);
    assert_eq!(gc.horizon, 100);
    assert_eq!(gc.arms[0].arm_id, "a");
    assert_eq!(gc.arms[1].arm_id, "b");
    // Prior Gittins index = 0.5.
    assert_eq!(gc.arms[0].gittins_index_millionths, MILLION / 2);
}

#[test]
fn gittins_empty_arms_error() {
    let err = GittinsIndexComputer::new(vec![], 900_000, 100).unwrap_err();
    assert!(matches!(err, StoppingError::EmptyObservations));
}

#[test]
fn gittins_invalid_discount_zero() {
    let err = GittinsIndexComputer::new(vec!["a".into()], 0, 100).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::InvalidDiscount { discount: 0 }
    ));
}

#[test]
fn gittins_invalid_discount_million() {
    let err = GittinsIndexComputer::new(vec!["a".into()], MILLION, 100).unwrap_err();
    assert!(matches!(err, StoppingError::InvalidDiscount { .. }));
}

#[test]
fn gittins_invalid_discount_negative() {
    let err = GittinsIndexComputer::new(vec!["a".into()], -1, 100).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::InvalidDiscount { discount: -1 }
    ));
}

#[test]
fn gittins_horizon_too_large() {
    let err = GittinsIndexComputer::new(vec!["a".into()], 900_000, 10_001).unwrap_err();
    assert!(matches!(err, StoppingError::HorizonTooLarge { .. }));
}

#[test]
fn gittins_observe_success_increases_index() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
    let initial = gc.arms[0].gittins_index_millionths;
    for _ in 0..5 {
        gc.observe(0, true).unwrap();
    }
    assert!(gc.arms[0].gittins_index_millionths > initial);
    assert!(gc.arms[0].successes == 5);
    assert!(gc.arms[0].failures == 0);
}

#[test]
fn gittins_observe_failure_decreases_index() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
    let initial = gc.arms[0].gittins_index_millionths;
    for _ in 0..5 {
        gc.observe(0, false).unwrap();
    }
    assert!(gc.arms[0].gittins_index_millionths < initial);
}

#[test]
fn gittins_observe_oob_error() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
    let err = gc.observe(5, true).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::IndexOutOfBounds { index: 5, size: 1 }
    ));
}

#[test]
fn gittins_select_arm_picks_highest_index() {
    let mut gc =
        GittinsIndexComputer::new(vec!["a".into(), "b".into(), "c".into()], 900_000, 100).unwrap();
    // Give arm 1 many successes.
    for _ in 0..20 {
        gc.observe(1, true).unwrap();
    }
    assert_eq!(gc.select_arm(), 1);
}

#[test]
fn gittins_ranked_arms_descending_order() {
    let mut gc =
        GittinsIndexComputer::new(vec!["a".into(), "b".into(), "c".into()], 900_000, 100).unwrap();
    for _ in 0..10 {
        gc.observe(2, true).unwrap();
        gc.observe(0, false).unwrap();
    }
    let ranked = gc.ranked_arms();
    assert_eq!(ranked.len(), 3);
    for w in ranked.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn gittins_arm_serde_roundtrip() {
    let gc = GittinsIndexComputer::new(vec!["arm_x".into()], 800_000, 50).unwrap();
    let arm = &gc.arms[0];
    let json = serde_json::to_string(arm).unwrap();
    let back: GittinsArm = serde_json::from_str(&json).unwrap();
    assert_eq!(*arm, back);
}

#[test]
fn gittins_computer_serde_roundtrip() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
    gc.observe(0, true).unwrap();
    gc.observe(1, false).unwrap();
    let json = serde_json::to_string(&gc).unwrap();
    let back: GittinsIndexComputer = serde_json::from_str(&json).unwrap();
    assert_eq!(gc, back);
}

#[test]
fn gittins_index_stays_in_range() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into()], 999_999, 100).unwrap();
    for _ in 0..100 {
        gc.observe(0, true).unwrap();
    }
    let idx = gc.arms[0].gittins_index_millionths;
    assert!((0..=MILLION).contains(&idx));
}

// ===========================================================================
// Section 7 — SnellEnvelope
// ===========================================================================

#[test]
fn snell_simple_peak_in_middle() {
    let payoffs = vec![1_000_000, 3_000_000, 2_000_000];
    let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
    assert_eq!(env.optimal_stopping_time, 1);
    assert_eq!(env.optimal_value_millionths, 3_000_000);
}

#[test]
fn snell_monotone_increasing_stop_at_end() {
    let payoffs = vec![1_000_000, 2_000_000, 3_000_000, 4_000_000];
    let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
    assert_eq!(env.optimal_stopping_time, 3);
}

#[test]
fn snell_monotone_decreasing_stop_at_start() {
    let payoffs = vec![5_000_000, 4_000_000, 3_000_000];
    let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
    assert_eq!(env.optimal_stopping_time, 0);
    assert_eq!(env.optimal_value_millionths, 5_000_000);
}

#[test]
fn snell_single_payoff() {
    let env = SnellEnvelope::compute(vec![7_000_000], MILLION).unwrap();
    assert_eq!(env.optimal_stopping_time, 0);
    assert_eq!(env.optimal_value_millionths, 7_000_000);
    assert!(env.should_stop_at(0));
}

#[test]
fn snell_with_heavy_discount() {
    // Payoffs [1, 100]. With discount 0.001 => continuation = 0.001 * 100 = 0.1 < 1.
    // So stop immediately.
    let payoffs = vec![1_000_000, 100_000_000];
    let env = SnellEnvelope::compute(payoffs, 1_000).unwrap(); // gamma = 0.001
    assert_eq!(env.optimal_stopping_time, 0);
}

#[test]
fn snell_with_moderate_discount() {
    // Payoffs [1, 10]. With discount 0.5 => continuation = 0.5 * 10 = 5 > 1.
    let payoffs = vec![1_000_000, 10_000_000];
    let env = SnellEnvelope::compute(payoffs, 500_000).unwrap();
    assert_eq!(env.optimal_stopping_time, 1);
}

#[test]
fn snell_empty_rejected() {
    let err = SnellEnvelope::compute(vec![], MILLION).unwrap_err();
    assert!(matches!(err, StoppingError::EmptyObservations));
}

#[test]
fn snell_discount_negative_rejected() {
    let err = SnellEnvelope::compute(vec![1_000_000], -1).unwrap_err();
    assert!(matches!(
        err,
        StoppingError::InvalidDiscount { discount: -1 }
    ));
}

#[test]
fn snell_discount_above_one_rejected() {
    let err = SnellEnvelope::compute(vec![1_000_000], MILLION + 1).unwrap_err();
    assert!(matches!(err, StoppingError::InvalidDiscount { .. }));
}

#[test]
fn snell_should_stop_past_horizon() {
    let env = SnellEnvelope::compute(vec![1_000_000, 2_000_000], MILLION).unwrap();
    // Past the end => must stop.
    assert!(env.should_stop_at(100));
}

#[test]
fn snell_envelope_values_dominate_payoffs() {
    let payoffs = vec![1_000_000, 5_000_000, 2_000_000, 1_000_000];
    let env = SnellEnvelope::compute(payoffs.clone(), MILLION).unwrap();
    for (u, g) in env.envelope_millionths.iter().zip(payoffs.iter()) {
        assert!(*u >= *g);
    }
}

#[test]
fn snell_serde_roundtrip() {
    let env = SnellEnvelope::compute(vec![1_000_000, 3_000_000, 2_000_000], MILLION).unwrap();
    let json = serde_json::to_string(&env).unwrap();
    let back: SnellEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn snell_discount_zero_all_immediate() {
    // With discount = 0, continuation value is always 0, so stop at first non-negative payoff.
    let payoffs = vec![1_000_000, 999_000_000];
    let env = SnellEnvelope::compute(payoffs, 0).unwrap();
    // Should stop at 0 because discounted continuation = 0 * anything = 0 <= 1.
    assert_eq!(env.optimal_stopping_time, 0);
}

// ===========================================================================
// Section 8 — SecretarySelector
// ===========================================================================

#[test]
fn secretary_exploration_length_100_items() {
    let sel = SecretarySelector::new(100);
    // floor(100/e) ~ 36
    assert!(sel.exploration_length >= 35 && sel.exploration_length <= 38);
    assert_eq!(sel.total_items, 100);
    assert_eq!(sel.observed, 0);
    assert!(!sel.exploration_complete);
    assert!(!sel.selected);
    assert!(sel.selected_index.is_none());
}

#[test]
fn secretary_zero_items() {
    let sel = SecretarySelector::new(0);
    assert_eq!(sel.exploration_length, 0);
    assert_eq!(sel.total_items, 0);
}

#[test]
fn secretary_one_item() {
    let mut sel = SecretarySelector::new(1);
    assert_eq!(sel.exploration_length, 0);
    let d = sel.observe(500_000);
    assert_eq!(d, StoppingDecision::Stop);
    assert!(sel.selected);
    assert_eq!(sel.selected_index, Some(0));
}

#[test]
fn secretary_two_items() {
    let mut sel = SecretarySelector::new(2);
    assert!(sel.exploration_length >= 1);
    // First item: exploration.
    assert_eq!(sel.observe(100_000), StoppingDecision::Continue);
    // Second item exceeds exploration best => select.
    let d = sel.observe(200_000);
    assert_eq!(d, StoppingDecision::Stop);
    assert!(sel.selected);
}

#[test]
fn secretary_explores_then_selects_on_better_score() {
    let mut sel = SecretarySelector::new(10);
    let elen = sel.exploration_length;
    for i in 0..elen {
        let score = (i as i64 + 1) * 100_000;
        assert_eq!(sel.observe(score), StoppingDecision::Continue);
    }
    assert!(sel.exploration_complete);
    let best = sel.exploration_best_millionths;
    // Present something better.
    let d = sel.observe(best + 1);
    assert_eq!(d, StoppingDecision::Stop);
    assert!(sel.selected);
}

#[test]
fn secretary_forced_selection_at_end() {
    let mut sel = SecretarySelector::new(5);
    // Feed decreasing scores so nothing in selection phase beats exploration best.
    for i in 0..5 {
        sel.observe(500_000 - i * 100_000);
    }
    assert!(sel.selected);
    assert_eq!(sel.selected_index, Some(4)); // last item forced
}

#[test]
fn secretary_already_selected_stays_stop() {
    let mut sel = SecretarySelector::new(1);
    assert_eq!(sel.observe(500_000), StoppingDecision::Stop);
    // Additional observations still return Stop.
    assert_eq!(sel.observe(900_000), StoppingDecision::Stop);
}

#[test]
fn secretary_optimal_probability() {
    let prob = SecretarySelector::optimal_selection_probability_millionths();
    assert!((prob - 367_879).abs() < 1000);
}

#[test]
fn secretary_serde_roundtrip() {
    let mut sel = SecretarySelector::new(20);
    sel.observe(100_000);
    let json = serde_json::to_string(&sel).unwrap();
    let back: SecretarySelector = serde_json::from_str(&json).unwrap();
    assert_eq!(sel, back);
}

// ===========================================================================
// Section 9 — EscalationPolicy
// ===========================================================================

#[test]
fn escalation_policy_creation() {
    let p = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
    assert!(p.cusum_enabled);
    assert!(p.secretary_enabled);
    assert_eq!(p.total_observations, 0);
    assert!(p.trigger_source.is_none());
}

#[test]
fn escalation_policy_invalid_threshold_propagates() {
    let err = EscalationPolicy::new(0, 500_000, 100).unwrap_err();
    assert!(matches!(err, StoppingError::InvalidThreshold { .. }));
}

#[test]
fn escalation_policy_cusum_triggers() {
    let mut p = EscalationPolicy::new(2_000_000, 500_000, 100).unwrap();
    p.secretary_enabled = false;
    let mut triggered = false;
    for i in 0u64..20 {
        if p.observe(&obs(1_000_000, 800_000, i)) == StoppingDecision::Stop {
            triggered = true;
            break;
        }
    }
    assert!(triggered);
    assert_eq!(p.trigger_source.as_deref(), Some("cusum"));
}

#[test]
fn escalation_policy_secretary_triggers() {
    let mut p = EscalationPolicy::new(100_000_000, 500_000, 5).unwrap();
    p.cusum_enabled = false;
    // Feed increasing risk scores.
    let mut decisions = Vec::new();
    for i in 0..5 {
        decisions.push(p.observe(&obs(0, (i + 1) * 200_000, i as u64)));
    }
    assert!(p.secretary.selected);
    assert!(decisions.contains(&StoppingDecision::Stop));
}

#[test]
fn escalation_policy_once_triggered_stays_stop() {
    let mut p = EscalationPolicy::new(1_000_000, 0, 100).unwrap();
    p.secretary_enabled = false;
    // Trigger cusum.
    assert_eq!(
        p.observe(&obs(2_000_000, 500_000, 0)),
        StoppingDecision::Stop
    );
    // All subsequent are Stop.
    assert_eq!(p.observe(&obs(0, 0, 1)), StoppingDecision::Stop);
}

#[test]
fn escalation_policy_both_disabled_always_continue() {
    let mut p = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
    p.cusum_enabled = false;
    p.secretary_enabled = false;
    for i in 0u64..20 {
        assert_eq!(
            p.observe(&obs(10_000_000, 10_000_000, i)),
            StoppingDecision::Continue
        );
    }
}

#[test]
fn escalation_policy_serde_roundtrip() {
    let mut p = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
    p.observe(&obs(100_000, 100_000, 0));
    let json = serde_json::to_string(&p).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn escalation_policy_observation_count_increments() {
    let mut p = EscalationPolicy::new(100_000_000, 500_000, 100).unwrap();
    for i in 0u64..5 {
        p.observe(&obs(100_000, 100_000, i));
    }
    assert_eq!(p.total_observations, 5);
}

// ===========================================================================
// Section 10 — OptimalStoppingCertificate
// ===========================================================================

#[test]
fn certificate_construction_and_fields() {
    let cert = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "cusum".to_string(),
        observations_before_stop: 42,
        cusum_statistic_millionths: Some(5_500_000),
        arl0_lower_bound: Some(1000 * MILLION),
        snell_optimal_value_millionths: None,
        gittins_index_millionths: None,
        epoch: SecurityEpoch::from_raw(7),
        certificate_hash: ContentHash::compute(b"test_cert"),
    };
    assert_eq!(cert.schema, STOPPING_SCHEMA_VERSION);
    assert_eq!(cert.algorithm, "cusum");
    assert_eq!(cert.observations_before_stop, 42);
    assert_eq!(cert.cusum_statistic_millionths, Some(5_500_000));
    assert!(cert.snell_optimal_value_millionths.is_none());
}

#[test]
fn certificate_serde_roundtrip() {
    let cert = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "snell".to_string(),
        observations_before_stop: 10,
        cusum_statistic_millionths: None,
        arl0_lower_bound: None,
        snell_optimal_value_millionths: Some(3_000_000),
        gittins_index_millionths: Some(750_000),
        epoch: SecurityEpoch::from_raw(99),
        certificate_hash: ContentHash::compute(b"roundtrip"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: OptimalStoppingCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn certificate_json_contains_expected_fields() {
    let cert = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "gittins".to_string(),
        observations_before_stop: 5,
        cusum_statistic_millionths: None,
        arl0_lower_bound: None,
        snell_optimal_value_millionths: None,
        gittins_index_millionths: Some(800_000),
        epoch: SecurityEpoch::from_raw(1),
        certificate_hash: ContentHash::compute(b"fields"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("schema"));
    assert!(json.contains("algorithm"));
    assert!(json.contains("observations_before_stop"));
    assert!(json.contains("epoch"));
    assert!(json.contains("certificate_hash"));
    assert!(json.contains("gittins_index_millionths"));
}

// ===========================================================================
// Section 11 — Lifecycle / Cross-concern integration
// ===========================================================================

#[test]
fn lifecycle_cusum_reset_and_reuse() {
    let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
    // First cycle: trigger.
    for i in 0u64..20 {
        if chart.observe(&obs(1_000_000, 800_000, i)) == StoppingDecision::Stop {
            break;
        }
    }
    assert!(chart.signaled);
    let round1 = chart.signal_round;

    // Reset and trigger again.
    chart.reset();
    assert!(!chart.signaled);
    for i in 20u64..40 {
        if chart.observe(&obs(1_000_000, 800_000, i)) == StoppingDecision::Stop {
            break;
        }
    }
    assert!(chart.signaled);
    assert!(chart.signal_round > round1);
}

#[test]
fn lifecycle_gittins_multi_round_learning() {
    let mut gc =
        GittinsIndexComputer::new(vec!["threat_a".into(), "threat_b".into()], 900_000, 100)
            .unwrap();

    // Round 1: arm 0 gets mixed evidence, arm 1 pure failure.
    for _ in 0..10 {
        gc.observe(0, true).unwrap();
        gc.observe(1, false).unwrap();
    }
    // Arm 0 has 10/0 (successes/failures), arm 1 has 0/10.
    assert_eq!(gc.select_arm(), 0);
    assert!(gc.arms[0].gittins_index_millionths > gc.arms[1].gittins_index_millionths);

    // Round 2: arm 1 recovers with a long success streak.
    for _ in 0..30 {
        gc.observe(1, true).unwrap();
    }
    // Arm 1 now has 30 successes vs 10 failures, posterior mean ~31/42 ~0.738.
    // Arm 0 has 10 successes vs 0 failures, posterior mean ~11/12 ~0.917.
    // Arm 0 still dominates.
    assert_eq!(gc.select_arm(), 0);
    // But arm 1's index should have increased from the failures-only state.
    let ranked = gc.ranked_arms();
    assert!(ranked[0].1 >= ranked[1].1);
}

#[test]
fn lifecycle_escalation_policy_full_scenario() {
    // Set cusum threshold high so secretary triggers first.
    let mut p = EscalationPolicy::new(100_000_000, 500_000, 10).unwrap();
    let mut result = StoppingDecision::Continue;
    for i in 0..10 {
        let o = obs(100_000, (i + 1) * 100_000, i as u64);
        result = p.observe(&o);
        if result == StoppingDecision::Stop {
            break;
        }
    }
    assert_eq!(result, StoppingDecision::Stop);
    assert!(p.total_observations > 0);
    // At least one trigger source must be set.
    assert!(p.trigger_source.is_some());
}

#[test]
fn lifecycle_snell_envelope_all_negative_payoffs() {
    // All negative: still picks the "least bad" option.
    let payoffs = vec![-3_000_000, -1_000_000, -5_000_000];
    let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
    // Optimal is t=1 (payoff -1M is the best).
    assert_eq!(env.optimal_stopping_time, 1);
    assert_eq!(env.optimal_value_millionths, -1_000_000);
}

#[test]
fn lifecycle_certificate_from_cusum_run() {
    let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
    for i in 0u64..20 {
        if chart.observe(&obs(1_000_000, 800_000, i)) == StoppingDecision::Stop {
            break;
        }
    }
    let arl0 = chart.arl0_lower_bound(1_000_000);
    let cert = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "cusum".to_string(),
        observations_before_stop: chart.signal_round,
        cusum_statistic_millionths: Some(chart.statistic_millionths),
        arl0_lower_bound: Some(arl0),
        snell_optimal_value_millionths: None,
        gittins_index_millionths: None,
        epoch: SecurityEpoch::from_raw(1),
        certificate_hash: ContentHash::compute(b"cusum_cert"),
    };
    assert!(cert.observations_before_stop > 0);
    assert!(cert.cusum_statistic_millionths.unwrap() >= 3_000_000);
    // Roundtrip the certificate.
    let json = serde_json::to_string(&cert).unwrap();
    let back: OptimalStoppingCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}
