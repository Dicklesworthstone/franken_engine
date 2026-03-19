//! Enrichment integration tests for `optimal_stopping`.
//!
//! Focuses on: CUSUM chart edge cases, Gittins index convergence,
//! Snell envelope boundary conditions, Secretary problem forced selection,
//! EscalationPolicy composite behavior, certificate construction,
//! serde roundtrips for all types, deterministic replay, Display uniqueness,
//! and error variant coverage.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::optimal_stopping::{
    CusumChart, EscalationPolicy, GittinsIndexComputer, Observation, OptimalStoppingCertificate,
    STOPPING_SCHEMA_VERSION, SecretarySelector, SnellEnvelope, StoppingDecision, StoppingError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Constants / Helpers
// ===========================================================================

const MILLION: i64 = 1_000_000;

fn obs(llr: i64, risk: i64, ts: u64) -> Observation {
    Observation {
        llr_millionths: llr,
        risk_score_millionths: risk,
        timestamp_us: ts,
        source: "enrich".to_string(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

// --- CUSUM ---

#[test]
fn enrichment_cusum_creation_and_defaults() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    assert_eq!(chart.statistic_millionths, 0);
    assert!(!chart.signaled);
    assert_eq!(chart.observations, 0);
    assert_eq!(chart.high_water_mark_millionths, 0);
    assert_eq!(chart.signal_round, 0);

    let defaults = CusumChart::with_defaults();
    assert!(defaults.threshold_millionths > 0);
    assert!(!defaults.signaled);
}

#[test]
fn enrichment_cusum_invalid_thresholds_rejected() {
    assert!(matches!(
        CusumChart::new(0, 500_000),
        Err(StoppingError::InvalidThreshold { threshold: 0 })
    ));
    assert!(matches!(
        CusumChart::new(-100, 500_000),
        Err(StoppingError::InvalidThreshold { threshold: -100 })
    ));
}

#[test]
fn enrichment_cusum_signals_after_sustained_anomaly() {
    let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
    let mut signaled_round = 0u64;
    for i in 0..20u64 {
        let d = chart.observe(&obs(1_000_000, 800_000, i));
        if d == StoppingDecision::Stop {
            signaled_round = chart.signal_round;
            break;
        }
    }
    assert!(chart.signaled);
    assert!(signaled_round > 0);
    assert!(signaled_round <= 10);
}

#[test]
fn enrichment_cusum_continues_on_benign() {
    let mut chart = CusumChart::new(5_000_000, 500_000).unwrap();
    for i in 0..50u64 {
        assert_eq!(
            chart.observe(&obs(100_000, 50_000, i)),
            StoppingDecision::Continue
        );
    }
    assert!(!chart.signaled);
}

#[test]
fn enrichment_cusum_statistic_never_negative_and_high_water_mark() {
    let mut chart = CusumChart::new(50_000_000, 500_000).unwrap();
    chart.observe(&obs(3_000_000, 500_000, 0));
    chart.observe(&obs(3_000_000, 500_000, 1));
    let peak = chart.statistic_millionths;
    assert!(peak > 0);
    for i in 2..30u64 {
        chart.observe(&obs(-2_000_000, 0, i));
        assert!(chart.statistic_millionths >= 0);
    }
    assert_eq!(chart.statistic_millionths, 0);
    assert_eq!(chart.high_water_mark_millionths, peak);
}

#[test]
fn enrichment_cusum_post_signal_keeps_returning_stop() {
    let mut chart = CusumChart::new(1_000_000, 0).unwrap();
    chart.observe(&obs(2_000_000, 500_000, 0));
    assert!(chart.signaled);
    for i in 1..5u64 {
        assert_eq!(chart.observe(&obs(-500_000, 0, i)), StoppingDecision::Stop);
    }
}

#[test]
fn enrichment_cusum_reset_clears_signal_preserves_observations() {
    let mut chart = CusumChart::new(1_000_000, 0).unwrap();
    chart.observe(&obs(2_000_000, 500_000, 0));
    assert!(chart.signaled);
    let obs_before = chart.observations;
    chart.reset();
    assert!(!chart.signaled);
    assert_eq!(chart.statistic_millionths, 0);
    assert_eq!(chart.signal_round, 0);
    assert_eq!(chart.observations, obs_before);
}

#[test]
fn enrichment_cusum_arl0_edge_cases() {
    let chart = CusumChart::new(5_000_000, 500_000).unwrap();
    assert_eq!(chart.arl0_lower_bound(0), i64::MAX);
    assert_eq!(chart.arl0_lower_bound(-1), i64::MAX);
    assert!(chart.arl0_lower_bound(MILLION) > MILLION);
}

#[test]
fn enrichment_cusum_extreme_negative_llr_no_overflow() {
    let mut chart = CusumChart::new(MILLION, 500_000).unwrap();
    let d = chart.observe(&obs(i64::MIN, 0, 0));
    assert_eq!(d, StoppingDecision::Continue);
    assert_eq!(chart.statistic_millionths, 0);
}

// --- Gittins Index ---

#[test]
fn enrichment_gittins_creation_and_validation() {
    let gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
    assert_eq!(gc.arms.len(), 2);
    assert_eq!(gc.discount_millionths, 900_000);

    assert!(matches!(
        GittinsIndexComputer::new(vec![], 900_000, 100),
        Err(StoppingError::EmptyObservations)
    ));
    assert!(matches!(
        GittinsIndexComputer::new(vec!["a".into()], 0, 100),
        Err(StoppingError::InvalidDiscount { .. })
    ));
    assert!(matches!(
        GittinsIndexComputer::new(vec!["a".into()], MILLION, 100),
        Err(StoppingError::InvalidDiscount { .. })
    ));
    assert!(matches!(
        GittinsIndexComputer::new(vec!["a".into()], 900_000, 10_001),
        Err(StoppingError::HorizonTooLarge { .. })
    ));
}

#[test]
fn enrichment_gittins_success_increases_failure_decreases_index() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
    let initial = gc.arms[0].gittins_index_millionths;
    gc.observe(0, true).unwrap();
    assert!(gc.arms[0].gittins_index_millionths >= initial);

    let mut gc2 = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
    let initial2 = gc2.arms[0].gittins_index_millionths;
    for _ in 0..10 {
        gc2.observe(0, false).unwrap();
    }
    assert!(gc2.arms[0].gittins_index_millionths < initial2);
}

#[test]
fn enrichment_gittins_select_arm_and_ranked_arms() {
    let mut gc =
        GittinsIndexComputer::new(vec!["a".into(), "b".into(), "c".into()], 900_000, 100).unwrap();
    for _ in 0..10 {
        gc.observe(0, true).unwrap();
        gc.observe(1, false).unwrap();
    }
    assert_eq!(gc.select_arm(), 0);

    for _ in 0..5 {
        gc.observe(2, true).unwrap();
    }
    let ranked = gc.ranked_arms();
    assert!(ranked[0].1 >= ranked[1].1);
    assert!(ranked[1].1 >= ranked[2].1);
}

#[test]
fn enrichment_gittins_out_of_bounds_rejected() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
    assert!(matches!(
        gc.observe(5, true),
        Err(StoppingError::IndexOutOfBounds { index: 5, size: 1 })
    ));
}

// --- Snell Envelope ---

#[test]
fn enrichment_snell_optimal_stopping_scenarios() {
    // Peak in middle
    let env = SnellEnvelope::compute(vec![1_000_000, 5_000_000, 2_000_000], MILLION).unwrap();
    assert_eq!(env.optimal_stopping_time, 1);
    assert_eq!(env.optimal_value_millionths, 5_000_000);

    // Monotone increasing -> wait till end
    let env2 =
        SnellEnvelope::compute(vec![1_000_000, 2_000_000, 3_000_000, 4_000_000], MILLION).unwrap();
    assert_eq!(env2.optimal_stopping_time, 3);

    // Monotone decreasing -> stop immediately
    let env3 = SnellEnvelope::compute(vec![5_000_000, 4_000_000, 3_000_000], MILLION).unwrap();
    assert_eq!(env3.optimal_stopping_time, 0);

    // Single payoff
    let env4 = SnellEnvelope::compute(vec![42_000_000], MILLION).unwrap();
    assert_eq!(env4.optimal_stopping_time, 0);
    assert!(env4.should_stop_at(0));
}

#[test]
fn enrichment_snell_validation_errors() {
    assert!(matches!(
        SnellEnvelope::compute(vec![], MILLION),
        Err(StoppingError::EmptyObservations)
    ));
    assert!(matches!(
        SnellEnvelope::compute(vec![MILLION], -1),
        Err(StoppingError::InvalidDiscount { .. })
    ));
    assert!(matches!(
        SnellEnvelope::compute(vec![MILLION], MILLION + 1),
        Err(StoppingError::InvalidDiscount { .. })
    ));
}

#[test]
fn enrichment_snell_should_stop_at_past_horizon() {
    let env = SnellEnvelope::compute(vec![MILLION, 2 * MILLION], MILLION).unwrap();
    assert!(env.should_stop_at(100));
    assert!(env.should_stop_at(usize::MAX));
}

#[test]
fn enrichment_snell_zero_discount_selects_max_payoff() {
    let env = SnellEnvelope::compute(vec![-1_000_000, 3_000_000, -500_000], 0).unwrap();
    assert_eq!(env.optimal_value_millionths, 3_000_000);
}

// --- Secretary Problem ---

#[test]
fn enrichment_secretary_exploration_and_selection() {
    let sel = SecretarySelector::new(100);
    assert!(sel.exploration_length >= 35 && sel.exploration_length <= 38);

    let mut sel2 = SecretarySelector::new(1);
    assert_eq!(sel2.exploration_length, 0);
    assert_eq!(sel2.observe(500_000), StoppingDecision::Stop);
    assert!(sel2.selected);
}

#[test]
fn enrichment_secretary_two_items_flow() {
    let mut sel = SecretarySelector::new(2);
    assert_eq!(sel.exploration_length, 1);
    assert_eq!(sel.observe(500_000), StoppingDecision::Continue);
    assert!(sel.exploration_complete);
    assert_eq!(sel.observe(600_000), StoppingDecision::Stop);
    assert!(sel.selected);
}

#[test]
fn enrichment_secretary_forced_selection_at_end() {
    let mut sel = SecretarySelector::new(5);
    for i in 0..5 {
        sel.observe((5 - i as i64) * 100_000);
    }
    assert!(sel.selected);
    assert_eq!(sel.selected_index, Some(4));
}

#[test]
fn enrichment_secretary_zero_items_and_probability() {
    let sel = SecretarySelector::new(0);
    assert_eq!(sel.exploration_length, 0);
    assert_eq!(sel.total_items, 0);

    let prob = SecretarySelector::optimal_selection_probability_millionths();
    assert!((prob - 367_879).abs() < 1000);
}

#[test]
fn enrichment_secretary_already_selected_returns_stop() {
    let mut sel = SecretarySelector::new(1);
    sel.observe(500_000);
    assert!(sel.selected);
    assert_eq!(sel.observe(999_999), StoppingDecision::Stop);
}

// --- EscalationPolicy ---

#[test]
fn enrichment_escalation_creation_and_cusum_trigger() {
    let policy = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
    assert!(policy.cusum_enabled);
    assert!(policy.secretary_enabled);
    assert_eq!(policy.total_observations, 0);
    assert!(policy.trigger_source.is_none());

    let mut policy2 = EscalationPolicy::new(2_000_000, 500_000, 100).unwrap();
    policy2.secretary_enabled = false;
    let mut triggered = false;
    for i in 0..20u64 {
        if policy2.observe(&obs(1_000_000, 800_000, i)) == StoppingDecision::Stop {
            triggered = true;
            break;
        }
    }
    assert!(triggered);
    assert_eq!(policy2.trigger_source.as_deref(), Some("cusum"));
}

#[test]
fn enrichment_escalation_invalid_threshold_propagates() {
    assert!(matches!(
        EscalationPolicy::new(0, 500_000, 100),
        Err(StoppingError::InvalidThreshold { .. })
    ));
}

// --- StoppingDecision ---

#[test]
fn enrichment_stopping_decision_display_ord_copy() {
    let set: BTreeSet<String> = [StoppingDecision::Continue, StoppingDecision::Stop]
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(set.len(), 2);

    assert!(StoppingDecision::Continue < StoppingDecision::Stop);

    let a = StoppingDecision::Stop;
    let b = a;
    assert_eq!(a, b);
}

// --- StoppingError ---

#[test]
fn enrichment_stopping_error_display_unique_and_std_error() {
    let errors = [
        StoppingError::HorizonTooLarge {
            horizon: 20_000,
            max: 10_000,
        },
        StoppingError::InvalidThreshold { threshold: -1 },
        StoppingError::InvalidDiscount { discount: 0 },
        StoppingError::EmptyObservations,
        StoppingError::DegenerateKL,
        StoppingError::IndexOutOfBounds { index: 5, size: 3 },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 6);

    let err: Box<dyn std::error::Error> = Box::new(StoppingError::DegenerateKL);
    assert!(!err.to_string().is_empty());
    assert!(std::error::Error::source(err.as_ref()).is_none());
}

#[test]
fn enrichment_stopping_error_serde_all_variants() {
    let variants = [
        StoppingError::HorizonTooLarge {
            horizon: 50_000,
            max: 10_000,
        },
        StoppingError::InvalidThreshold { threshold: -42 },
        StoppingError::InvalidDiscount {
            discount: 2_000_000,
        },
        StoppingError::EmptyObservations,
        StoppingError::DegenerateKL,
        StoppingError::IndexOutOfBounds {
            index: 99,
            size: 10,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: StoppingError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// --- Serde roundtrips ---

#[test]
fn enrichment_serde_observation_and_cusum() {
    let o = obs(500_000, 700_000, 42);
    let json = serde_json::to_string(&o).unwrap();
    let back: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);

    let mut chart = CusumChart::with_defaults();
    chart.observe(&obs(200_000, 100_000, 0));
    let json2 = serde_json::to_string(&chart).unwrap();
    let back2: CusumChart = serde_json::from_str(&json2).unwrap();
    assert_eq!(chart, back2);
}

#[test]
fn enrichment_serde_gittins_and_snell() {
    let mut gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
    gc.observe(0, true).unwrap();
    let json = serde_json::to_string(&gc).unwrap();
    let back: GittinsIndexComputer = serde_json::from_str(&json).unwrap();
    assert_eq!(gc, back);

    let env = SnellEnvelope::compute(vec![1_000_000, 3_000_000, 2_000_000], MILLION).unwrap();
    let json2 = serde_json::to_string(&env).unwrap();
    let back2: SnellEnvelope = serde_json::from_str(&json2).unwrap();
    assert_eq!(env, back2);
}

#[test]
fn enrichment_serde_secretary_and_escalation() {
    let sel = SecretarySelector::new(50);
    let json = serde_json::to_string(&sel).unwrap();
    let back: SecretarySelector = serde_json::from_str(&json).unwrap();
    assert_eq!(sel, back);

    let mut policy = EscalationPolicy::new(5_000_000, 500_000, 50).unwrap();
    policy.observe(&obs(100_000, 50_000, 0));
    let json2 = serde_json::to_string(&policy).unwrap();
    let back2: EscalationPolicy = serde_json::from_str(&json2).unwrap();
    assert_eq!(policy, back2);
}

#[test]
fn enrichment_serde_certificate() {
    let cert = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "cusum".to_string(),
        observations_before_stop: 42,
        cusum_statistic_millionths: Some(5_500_000),
        arl0_lower_bound: Some(1000 * MILLION),
        snell_optimal_value_millionths: None,
        gittins_index_millionths: None,
        epoch: SecurityEpoch::from_raw(7),
        certificate_hash: ContentHash::compute(b"enrich_cert"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: OptimalStoppingCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// --- Determinism ---

#[test]
fn enrichment_cusum_deterministic_replay() {
    let run = || {
        let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
        let mut decisions = Vec::new();
        for i in 0..15u64 {
            decisions.push(chart.observe(&obs(800_000, 500_000, i)));
        }
        (decisions, chart.signaled, chart.statistic_millionths)
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_secretary_deterministic_replay() {
    let run = || {
        let mut sel = SecretarySelector::new(10);
        let mut decisions = Vec::new();
        for i in 0..10 {
            decisions.push(sel.observe((i + 1) * 100_000));
        }
        (decisions, sel.selected, sel.selected_index)
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_schema_version_constant() {
    assert_eq!(
        STOPPING_SCHEMA_VERSION,
        "franken-engine.optimal-stopping.v1"
    );
}
