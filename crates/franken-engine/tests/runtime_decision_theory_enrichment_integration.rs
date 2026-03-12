#![forbid(unsafe_code)]
//! Enrichment integration tests for `runtime_decision_theory`.
//!
//! Adds config default exact values, Display exactness, Debug distinctness,
//! JSON field-name stability, initial-state checks, and serde roundtrips
//! beyond the existing 47 integration tests.

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

use frankenengine_engine::runtime_decision_theory::{
    BudgetConfig, BudgetController, BudgetEvent, BudgetEventKind, BudgetStatus,
    CalibrationLedgerEntry, ConformalCalibrator, ConformalConfig, CvarCheckResult, CvarConfig,
    CvarGuardrail, DecisionContext, DecisionContextConfig, DecisionOutcome, DecisionState,
    DecisionTrace, DemotionReason, DriftCheckResult, DriftConfig, DriftDetector, FallbackMetrics,
    FallbackTriggerEvent, LaneAction, LaneId, LatencyQuantiles, PolicyBundle, RegimeLabel,
    RiskFactor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// 1) CvarConfig — default exact values
// ===========================================================================

#[test]
fn cvar_config_default_alpha() {
    let c = CvarConfig::default();
    assert_eq!(c.alpha_millionths, 950_000);
}

#[test]
fn cvar_config_default_max_cvar() {
    let c = CvarConfig::default();
    assert_eq!(c.max_cvar_millionths, 50_000_000);
}

#[test]
fn cvar_config_default_min_observations() {
    let c = CvarConfig::default();
    assert_eq!(c.min_observations, 30);
}

// ===========================================================================
// 2) ConformalConfig — default exact values
// ===========================================================================

#[test]
fn conformal_config_default_alpha() {
    let c = ConformalConfig::default();
    assert_eq!(c.alpha_millionths, 100_000);
}

#[test]
fn conformal_config_default_min_calibration() {
    let c = ConformalConfig::default();
    assert_eq!(c.min_calibration_observations, 50);
}

#[test]
fn conformal_config_default_max_consecutive() {
    let c = ConformalConfig::default();
    assert_eq!(c.max_consecutive_violations, 5);
}

// ===========================================================================
// 3) DriftConfig — default exact values
// ===========================================================================

#[test]
fn drift_config_default_kl_threshold() {
    let c = DriftConfig::default();
    assert_eq!(c.kl_threshold_millionths, 100_000);
}

#[test]
fn drift_config_default_reference_window() {
    let c = DriftConfig::default();
    assert_eq!(c.reference_window, 100);
}

#[test]
fn drift_config_default_test_window() {
    let c = DriftConfig::default();
    assert_eq!(c.test_window, 50);
}

#[test]
fn drift_config_default_min_samples() {
    let c = DriftConfig::default();
    assert_eq!(c.min_samples, 20);
}

// ===========================================================================
// 4) BudgetConfig — default exact values
// ===========================================================================

#[test]
fn budget_config_default_compute_budget() {
    let c = BudgetConfig::default();
    assert_eq!(c.compute_budget_us, 50_000);
}

#[test]
fn budget_config_default_memory_budget() {
    let c = BudgetConfig::default();
    assert_eq!(c.memory_budget_bytes, 128 * 1024 * 1024);
}

#[test]
fn budget_config_default_warning_threshold() {
    let c = BudgetConfig::default();
    assert_eq!(c.warning_threshold_millionths, 800_000);
}

#[test]
fn budget_config_default_deterministic_fallback() {
    let c = BudgetConfig::default();
    assert!(c.deterministic_fallback_on_exhaust);
}

// ===========================================================================
// 5) DecisionContextConfig — default lanes and risk_weights
// ===========================================================================

#[test]
fn decision_context_config_default_lanes() {
    let c = DecisionContextConfig::default();
    assert_eq!(c.lanes.len(), 2);
    assert_eq!(c.lanes[0].to_string(), "baseline_deterministic_profile");
    assert_eq!(c.lanes[1].to_string(), "baseline_throughput_profile");
}

#[test]
fn decision_context_config_default_risk_weights() {
    let c = DecisionContextConfig::default();
    assert_eq!(c.risk_weights.len(), 4);
    assert_eq!(c.risk_weights[&RiskFactor::Compatibility], 300_000);
    assert_eq!(c.risk_weights[&RiskFactor::Latency], 300_000);
    assert_eq!(c.risk_weights[&RiskFactor::Memory], 200_000);
    assert_eq!(c.risk_weights[&RiskFactor::IncidentSeverity], 200_000);
}

// ===========================================================================
// 6) RiskFactor — Display exact values
// ===========================================================================

#[test]
fn risk_factor_display_compatibility() {
    assert_eq!(RiskFactor::Compatibility.to_string(), "compatibility");
}

#[test]
fn risk_factor_display_latency() {
    assert_eq!(RiskFactor::Latency.to_string(), "latency");
}

#[test]
fn risk_factor_display_memory() {
    assert_eq!(RiskFactor::Memory.to_string(), "memory");
}

#[test]
fn risk_factor_display_incident_severity() {
    assert_eq!(
        RiskFactor::IncidentSeverity.to_string(),
        "incident_severity"
    );
}

// ===========================================================================
// 7) RegimeLabel — Display exact values
// ===========================================================================

#[test]
fn regime_label_display_normal() {
    assert_eq!(RegimeLabel::Normal.to_string(), "normal");
}

#[test]
fn regime_label_display_elevated() {
    assert_eq!(RegimeLabel::Elevated.to_string(), "elevated");
}

#[test]
fn regime_label_display_attack() {
    assert_eq!(RegimeLabel::Attack.to_string(), "attack");
}

#[test]
fn regime_label_display_degraded() {
    assert_eq!(RegimeLabel::Degraded.to_string(), "degraded");
}

#[test]
fn regime_label_display_recovery() {
    assert_eq!(RegimeLabel::Recovery.to_string(), "recovery");
}

// ===========================================================================
// 8) DemotionReason — Display exact values
// ===========================================================================

#[test]
fn demotion_reason_display_cvar_exceeded() {
    assert_eq!(DemotionReason::CvarExceeded.to_string(), "cvar_exceeded");
}

#[test]
fn demotion_reason_display_drift_detected() {
    assert_eq!(DemotionReason::DriftDetected.to_string(), "drift_detected");
}

#[test]
fn demotion_reason_display_budget_exhausted() {
    assert_eq!(
        DemotionReason::BudgetExhausted.to_string(),
        "budget_exhausted"
    );
}

#[test]
fn demotion_reason_display_guardrail_triggered() {
    assert_eq!(
        DemotionReason::GuardrailTriggered.to_string(),
        "guardrail_triggered"
    );
}

#[test]
fn demotion_reason_display_coverage_violation() {
    assert_eq!(
        DemotionReason::CoverageViolation.to_string(),
        "coverage_violation"
    );
}

#[test]
fn demotion_reason_display_operator_override() {
    assert_eq!(
        DemotionReason::OperatorOverride.to_string(),
        "operator_override"
    );
}

// ===========================================================================
// 9) BudgetEventKind — Display exact values
// ===========================================================================

#[test]
fn budget_event_kind_display_warning() {
    assert_eq!(BudgetEventKind::Warning.to_string(), "warning");
}

#[test]
fn budget_event_kind_display_exhausted() {
    assert_eq!(BudgetEventKind::Exhausted.to_string(), "exhausted");
}

#[test]
fn budget_event_kind_display_epoch_reset() {
    assert_eq!(BudgetEventKind::EpochReset.to_string(), "epoch_reset");
}

// ===========================================================================
// 10) LaneAction — Display exact values
// ===========================================================================

#[test]
fn lane_action_display_route_to() {
    let action = LaneAction::RouteTo(LaneId("main".into()));
    assert_eq!(action.to_string(), "route_to:main");
}

#[test]
fn lane_action_display_fallback_safe() {
    assert_eq!(LaneAction::FallbackSafe.to_string(), "fallback_safe");
}

#[test]
fn lane_action_display_suspend_adaptive() {
    assert_eq!(LaneAction::SuspendAdaptive.to_string(), "suspend_adaptive");
}

#[test]
fn lane_action_display_demote() {
    let action = LaneAction::Demote {
        from_lane: LaneId("v8".into()),
        reason: DemotionReason::CvarExceeded,
    };
    let s = action.to_string();
    assert!(s.contains("demote"), "should contain 'demote': {s}");
    assert!(s.contains("v8"), "should contain lane id: {s}");
    assert!(s.contains("cvar_exceeded"), "should contain reason: {s}");
}

// ===========================================================================
// 11) Debug distinctness — RiskFactor
// ===========================================================================

#[test]
fn debug_distinct_risk_factor() {
    let variants: Vec<String> = RiskFactor::ALL.iter().map(|r| format!("{r:?}")).collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 12) Debug distinctness — RegimeLabel
// ===========================================================================

#[test]
fn debug_distinct_regime_label() {
    let variants = [
        format!("{:?}", RegimeLabel::Normal),
        format!("{:?}", RegimeLabel::Elevated),
        format!("{:?}", RegimeLabel::Attack),
        format!("{:?}", RegimeLabel::Degraded),
        format!("{:?}", RegimeLabel::Recovery),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 13) Debug distinctness — DemotionReason
// ===========================================================================

#[test]
fn debug_distinct_demotion_reason() {
    let variants = [
        format!("{:?}", DemotionReason::CvarExceeded),
        format!("{:?}", DemotionReason::DriftDetected),
        format!("{:?}", DemotionReason::BudgetExhausted),
        format!("{:?}", DemotionReason::GuardrailTriggered),
        format!("{:?}", DemotionReason::CoverageViolation),
        format!("{:?}", DemotionReason::OperatorOverride),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 14) Debug distinctness — BudgetEventKind
// ===========================================================================

#[test]
fn debug_distinct_budget_event_kind() {
    let variants = [
        format!("{:?}", BudgetEventKind::Warning),
        format!("{:?}", BudgetEventKind::Exhausted),
        format!("{:?}", BudgetEventKind::EpochReset),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 15) CvarGuardrail — initial state
// ===========================================================================

#[test]
fn cvar_guardrail_initial_not_triggered() {
    let g = CvarGuardrail::new(CvarConfig::default());
    assert!(!g.is_triggered());
    assert!(g.trigger_epoch().is_none());
    assert_eq!(g.observation_count(), 0);
}

#[test]
fn cvar_guardrail_initial_cvar_none() {
    let g = CvarGuardrail::new(CvarConfig::default());
    assert!(g.cvar().is_none());
}

#[test]
fn cvar_guardrail_initial_var_none() {
    let g = CvarGuardrail::new(CvarConfig::default());
    assert!(g.var().is_none());
}

// ===========================================================================
// 16) ConformalCalibrator — initial state
// ===========================================================================

#[test]
fn conformal_calibrator_initial_state() {
    let c = ConformalCalibrator::new(ConformalConfig::default());
    assert!(!c.violation_flagged());
    assert_eq!(c.total_predictions(), 0);
    assert_eq!(c.covered_predictions(), 0);
    assert!(c.ledger().is_empty());
}

// ===========================================================================
// 17) DriftDetector — initial state
// ===========================================================================

#[test]
fn drift_detector_initial_state() {
    let d = DriftDetector::new(DriftConfig::default());
    assert!(!d.is_drift_detected());
    assert!(d.last_kl_millionths().is_none());
    assert!(d.drift_epoch().is_none());
    assert_eq!(d.observation_count(), 0);
}

// ===========================================================================
// 18) BudgetController — initial state
// ===========================================================================

#[test]
fn budget_controller_initial_state() {
    let b = BudgetController::new(BudgetConfig::default(), SecurityEpoch::from_raw(1));
    assert!(!b.is_fallback_active());
    assert_eq!(b.compute_consumed_us(), 0);
    assert_eq!(b.memory_consumed_bytes(), 0);
    assert!(b.events().is_empty());
}

// ===========================================================================
// 19) JSON field-name stability — LatencyQuantiles
// ===========================================================================

#[test]
fn json_fields_latency_quantiles() {
    let lq = LatencyQuantiles {
        p50_us: 100,
        p95_us: 500,
        p99_us: 1000,
        p999_us: 5000,
    };
    let v: serde_json::Value = serde_json::to_value(&lq).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["p50_us", "p95_us", "p99_us", "p999_us"] {
        assert!(
            obj.contains_key(key),
            "LatencyQuantiles missing field: {key}"
        );
    }
}

// ===========================================================================
// 20) JSON field-name stability — FallbackMetrics
// ===========================================================================

#[test]
fn json_fields_fallback_metrics() {
    let fm = FallbackMetrics {
        cvar_millionths: Some(100_000),
        drift_kl_millionths: None,
        budget_remaining_millionths: 500_000,
        coverage_millionths: 900_000,
        e_value_millionths: 1_000_000,
    };
    let v: serde_json::Value = serde_json::to_value(&fm).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cvar_millionths",
        "drift_kl_millionths",
        "budget_remaining_millionths",
        "coverage_millionths",
        "e_value_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "FallbackMetrics missing field: {key}"
        );
    }
}

// ===========================================================================
// 21) Serde roundtrips — FallbackMetrics
// ===========================================================================

#[test]
fn serde_roundtrip_fallback_metrics() {
    let fm = FallbackMetrics {
        cvar_millionths: Some(200_000),
        drift_kl_millionths: Some(50_000),
        budget_remaining_millionths: 300_000,
        coverage_millionths: 850_000,
        e_value_millionths: 1_200_000,
    };
    let json = serde_json::to_string(&fm).unwrap();
    let rt: FallbackMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(fm, rt);
}

// ===========================================================================
// 22) Serde roundtrips — BudgetEvent
// ===========================================================================

#[test]
fn serde_roundtrip_budget_event() {
    let be = BudgetEvent {
        epoch: SecurityEpoch::from_raw(5),
        kind: BudgetEventKind::Warning,
        compute_consumed_us: 40_000,
        memory_consumed_bytes: 100_000_000,
    };
    let json = serde_json::to_string(&be).unwrap();
    let rt: BudgetEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(be, rt);
}

// ===========================================================================
// 23) LaneId — Display and serde
// ===========================================================================

#[test]
fn lane_id_display_forwards_string() {
    let id = LaneId("my_lane".into());
    assert_eq!(id.to_string(), "my_lane");
}

#[test]
fn serde_roundtrip_lane_id() {
    let id = LaneId("test_lane".into());
    let json = serde_json::to_string(&id).unwrap();
    let rt: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, rt);
}

// ===========================================================================
// 24) RiskFactor — ALL constant
// ===========================================================================

#[test]
fn risk_factor_all_has_four() {
    assert_eq!(RiskFactor::ALL.len(), 4);
}

// ===========================================================================
// 25) CvarGuardrail — observe populates observations
// ===========================================================================

#[test]
fn cvar_guardrail_observe_increments_count() {
    let mut g = CvarGuardrail::new(CvarConfig::default());
    g.observe(1_000_000);
    assert_eq!(g.observation_count(), 1);
    g.observe(2_000_000);
    assert_eq!(g.observation_count(), 2);
}

#[test]
fn cvar_guardrail_cvar_returns_some_after_min_observations() {
    let config = CvarConfig {
        min_observations: 5,
        ..Default::default()
    };
    let mut g = CvarGuardrail::new(config);
    for i in 0..5 {
        g.observe(i * 1_000_000);
    }
    assert!(g.cvar().is_some());
}

#[test]
fn cvar_guardrail_var_returns_some_after_min_observations() {
    let config = CvarConfig {
        min_observations: 5,
        ..Default::default()
    };
    let mut g = CvarGuardrail::new(config);
    for i in 0..5 {
        g.observe(i * 1_000_000);
    }
    assert!(g.var().is_some());
}

#[test]
fn cvar_guardrail_check_insufficient_then_within_bounds() {
    let config = CvarConfig {
        alpha_millionths: 950_000,
        max_cvar_millionths: 500_000_000,
        min_observations: 10,
    };
    let mut g = CvarGuardrail::new(config);
    // Insufficient data with 5 obs
    for i in 0..5 {
        g.observe(i * 1_000_000);
    }
    let r = g.check(SecurityEpoch::from_raw(1));
    assert!(
        matches!(r, CvarCheckResult::InsufficientData { .. }),
        "expected InsufficientData, got {r:?}"
    );
    // Add more to reach 10
    for i in 5..10 {
        g.observe(i * 1_000_000);
    }
    let r2 = g.check(SecurityEpoch::from_raw(2));
    assert!(
        matches!(r2, CvarCheckResult::WithinBounds { .. }),
        "expected WithinBounds, got {r2:?}"
    );
}

#[test]
fn cvar_guardrail_check_exceeded_sets_trigger_epoch() {
    let config = CvarConfig {
        alpha_millionths: 500_000,
        max_cvar_millionths: 1,
        min_observations: 3,
    };
    let mut g = CvarGuardrail::new(config);
    g.observe(10_000_000);
    g.observe(20_000_000);
    g.observe(30_000_000);
    let ep = SecurityEpoch::from_raw(42);
    let r = g.check(ep);
    assert!(matches!(r, CvarCheckResult::Exceeded { .. }));
    assert_eq!(g.trigger_epoch(), Some(ep));
    assert!(g.is_triggered());
}

#[test]
fn cvar_guardrail_reset_clears_all_state() {
    let config = CvarConfig {
        alpha_millionths: 500_000,
        max_cvar_millionths: 1,
        min_observations: 2,
    };
    let mut g = CvarGuardrail::new(config);
    g.observe(100_000_000);
    g.observe(200_000_000);
    g.check(SecurityEpoch::from_raw(1));
    assert!(g.is_triggered());
    g.reset();
    assert!(!g.is_triggered());
    assert!(g.trigger_epoch().is_none());
    assert_eq!(g.observation_count(), 0);
    assert!(g.cvar().is_none());
    assert!(g.var().is_none());
}

#[test]
fn cvar_guardrail_cvar_is_mean_of_tail() {
    // With alpha=0.5, CVaR = mean of top 50% of observations
    let config = CvarConfig {
        alpha_millionths: 500_000,
        max_cvar_millionths: 1_000_000_000,
        min_observations: 4,
    };
    let mut g = CvarGuardrail::new(config);
    // Sorted: [1M, 2M, 3M, 4M]. alpha=0.5 => var_index = floor(4*0.5) = 2
    // Tail = obs[2..] = [3M, 4M], CVaR = (3M + 4M) / 2 = 3_500_000
    g.observe(2_000_000);
    g.observe(4_000_000);
    g.observe(1_000_000);
    g.observe(3_000_000);
    let cvar = g.cvar().unwrap();
    assert_eq!(cvar, 3_500_000);
}

#[test]
fn cvar_guardrail_var_at_alpha_quantile() {
    let config = CvarConfig {
        alpha_millionths: 800_000,
        max_cvar_millionths: 1_000_000_000,
        min_observations: 5,
    };
    let mut g = CvarGuardrail::new(config);
    // Sorted: [0, 1M, 2M, 3M, 4M]. alpha=0.8 => var_index = floor(5*0.8) = 4
    // VaR = obs[4] = 4_000_000
    for i in 0..5 {
        g.observe(i * 1_000_000);
    }
    let var = g.var().unwrap();
    assert_eq!(var, 4_000_000);
}

// ===========================================================================
// 26) ConformalCalibrator — coverage computation
// ===========================================================================

#[test]
fn conformal_calibrator_coverage_exact_half() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        ..Default::default()
    };
    let mut c = ConformalCalibrator::new(config);
    c.record(SecurityEpoch::from_raw(1), true);
    c.record(SecurityEpoch::from_raw(2), false);
    // 1 covered / 2 total = 500_000 millionths
    assert_eq!(c.coverage_millionths(), 500_000);
}

#[test]
fn conformal_calibrator_is_calibrated_with_insufficient_data() {
    let config = ConformalConfig {
        min_calibration_observations: 100,
        ..Default::default()
    };
    let mut c = ConformalCalibrator::new(config);
    // Even with all misses, insufficient data returns calibrated=true
    for i in 0..10 {
        c.record(SecurityEpoch::from_raw(i), false);
    }
    assert!(c.is_calibrated());
}

#[test]
fn conformal_calibrator_is_calibrated_exact_threshold() {
    // alpha=100_000 (10%), so target coverage = 1M - 100_000 = 900_000 (90%)
    let config = ConformalConfig {
        alpha_millionths: 100_000,
        min_calibration_observations: 10,
        max_consecutive_violations: 100,
    };
    let mut c = ConformalCalibrator::new(config);
    // 9 covered, 1 miss = 900_000 millionths = exactly 90%
    for i in 0..9 {
        c.record(SecurityEpoch::from_raw(i), true);
    }
    c.record(SecurityEpoch::from_raw(9), false);
    assert!(c.is_calibrated());
}

#[test]
fn conformal_calibrator_not_calibrated_below_threshold() {
    let config = ConformalConfig {
        alpha_millionths: 100_000,
        min_calibration_observations: 10,
        max_consecutive_violations: 100,
    };
    let mut c = ConformalCalibrator::new(config);
    // 8 covered, 2 miss = 800_000 millionths = 80% < 90%
    for i in 0..8 {
        c.record(SecurityEpoch::from_raw(i), true);
    }
    c.record(SecurityEpoch::from_raw(8), false);
    c.record(SecurityEpoch::from_raw(9), false);
    assert!(!c.is_calibrated());
}

#[test]
fn conformal_calibrator_violation_requires_min_observations() {
    let config = ConformalConfig {
        alpha_millionths: 100_000,
        min_calibration_observations: 10,
        max_consecutive_violations: 3,
    };
    let mut c = ConformalCalibrator::new(config);
    // 5 consecutive misses but only 5 total < min 10
    for i in 0..5 {
        c.record(SecurityEpoch::from_raw(i), false);
    }
    assert!(!c.violation_flagged());
}

#[test]
fn conformal_calibrator_violation_flagged_at_threshold() {
    let config = ConformalConfig {
        alpha_millionths: 100_000,
        min_calibration_observations: 5,
        max_consecutive_violations: 3,
    };
    let mut c = ConformalCalibrator::new(config);
    // 3 hits then 3 consecutive misses with total >= 5
    for i in 0..3 {
        c.record(SecurityEpoch::from_raw(i), true);
    }
    for i in 3..6 {
        c.record(SecurityEpoch::from_raw(i), false);
    }
    assert!(c.violation_flagged());
}

#[test]
fn conformal_calibrator_consecutive_resets_on_hit() {
    let config = ConformalConfig {
        alpha_millionths: 100_000,
        min_calibration_observations: 5,
        max_consecutive_violations: 3,
    };
    let mut c = ConformalCalibrator::new(config);
    // 5 hits, then 2 misses, then 1 hit, then 2 misses
    // consecutive never reaches 3
    for i in 0..5 {
        c.record(SecurityEpoch::from_raw(i), true);
    }
    c.record(SecurityEpoch::from_raw(5), false);
    c.record(SecurityEpoch::from_raw(6), false);
    c.record(SecurityEpoch::from_raw(7), true); // resets consecutive
    c.record(SecurityEpoch::from_raw(8), false);
    c.record(SecurityEpoch::from_raw(9), false);
    assert!(!c.violation_flagged());
}

#[test]
fn conformal_calibrator_e_value_grows_monotonically_on_misses() {
    let mut c = ConformalCalibrator::new(ConformalConfig::default());
    let mut prev = c.e_value_millionths();
    for i in 1..=5 {
        c.record(SecurityEpoch::from_raw(i), false);
        let curr = c.e_value_millionths();
        assert!(
            curr >= prev,
            "e-value should not decrease on miss: step {i}"
        );
        prev = curr;
    }
}

#[test]
fn conformal_calibrator_e_value_stable_on_all_hits() {
    let mut c = ConformalCalibrator::new(ConformalConfig::default());
    for i in 1..=10 {
        c.record(SecurityEpoch::from_raw(i), true);
        // e-value LR = 1.0 for hits, so product stays at 1M
        assert_eq!(c.e_value_millionths(), 1_000_000);
    }
}

#[test]
fn conformal_calibrator_ledger_length_matches_records() {
    let mut c = ConformalCalibrator::new(ConformalConfig::default());
    for i in 0..20 {
        c.record(SecurityEpoch::from_raw(i), i % 3 != 0);
    }
    assert_eq!(c.ledger().len(), 20);
    assert_eq!(c.total_predictions(), 20);
}

#[test]
fn conformal_calibrator_reset_clears_all() {
    let mut c = ConformalCalibrator::new(ConformalConfig {
        min_calibration_observations: 3,
        max_consecutive_violations: 2,
        ..Default::default()
    });
    for i in 0..5 {
        c.record(SecurityEpoch::from_raw(i), false);
    }
    assert!(c.violation_flagged());
    c.reset();
    assert_eq!(c.total_predictions(), 0);
    assert_eq!(c.covered_predictions(), 0);
    assert!(!c.violation_flagged());
    assert_eq!(c.e_value_millionths(), 1_000_000);
    assert!(c.ledger().is_empty());
}

#[test]
fn conformal_calibrator_vacuous_coverage_when_empty() {
    let c = ConformalCalibrator::new(ConformalConfig::default());
    assert_eq!(c.coverage_millionths(), 1_000_000);
}

// ===========================================================================
// 27) DriftDetector — behavior tests
// ===========================================================================

#[test]
fn drift_detector_observe_increments_count() {
    let mut d = DriftDetector::new(DriftConfig::default());
    d.observe(100);
    d.observe(200);
    d.observe(300);
    assert_eq!(d.observation_count(), 3);
}

#[test]
fn drift_detector_check_no_drift_identical_values() {
    let config = DriftConfig {
        reference_window: 5,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 100_000,
    };
    let mut d = DriftDetector::new(config);
    for _ in 0..10 {
        d.observe(1_000_000);
    }
    let r = d.check(SecurityEpoch::from_raw(1));
    assert!(
        matches!(r, DriftCheckResult::NoDrift { .. }),
        "identical data should not drift: {r:?}"
    );
}

#[test]
fn drift_detector_check_detects_shift() {
    let config = DriftConfig {
        reference_window: 10,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 1, // extremely low threshold
    };
    let mut d = DriftDetector::new(config);
    for _ in 0..10 {
        d.observe(1_000_000);
    }
    for _ in 0..5 {
        d.observe(500_000_000);
    }
    let r = d.check(SecurityEpoch::from_raw(1));
    assert!(
        matches!(r, DriftCheckResult::DriftDetected { .. }),
        "shift should be detected: {r:?}"
    );
    assert!(d.is_drift_detected());
    assert!(d.last_kl_millionths().is_some());
    assert_eq!(d.drift_epoch(), Some(SecurityEpoch::from_raw(1)));
}

#[test]
fn drift_detector_last_kl_populated_after_check() {
    let config = DriftConfig {
        reference_window: 5,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 999_999_999,
    };
    let mut d = DriftDetector::new(config);
    for i in 0..10 {
        d.observe(i * 1_000_000);
    }
    d.check(SecurityEpoch::from_raw(1));
    assert!(d.last_kl_millionths().is_some());
}

#[test]
fn drift_detector_observation_window_bounded() {
    let config = DriftConfig {
        reference_window: 10,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 100_000,
    };
    let mut d = DriftDetector::new(config);
    for i in 0..500 {
        d.observe(i);
    }
    // ref + test + margin(50) = 65
    assert!(d.observation_count() <= 65);
}

#[test]
fn drift_detector_reset_clears_all() {
    let config = DriftConfig {
        reference_window: 5,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 1,
    };
    let mut d = DriftDetector::new(config);
    for _ in 0..5 {
        d.observe(1_000_000);
    }
    for _ in 0..5 {
        d.observe(100_000_000);
    }
    d.check(SecurityEpoch::from_raw(1));
    assert!(d.is_drift_detected());
    d.reset();
    assert!(!d.is_drift_detected());
    assert!(d.last_kl_millionths().is_none());
    assert!(d.drift_epoch().is_none());
    assert_eq!(d.observation_count(), 0);
}

// ===========================================================================
// 28) BudgetController — behavior tests
// ===========================================================================

#[test]
fn budget_controller_record_memory_tracking() {
    let mut b = BudgetController::new(BudgetConfig::default(), SecurityEpoch::from_raw(1));
    b.record_memory(1024);
    assert_eq!(b.memory_consumed_bytes(), 1024);
}

#[test]
fn budget_controller_compute_warning_threshold() {
    let config = BudgetConfig {
        compute_budget_us: 1000,
        warning_threshold_millionths: 800_000,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    let status = b.record_compute(850); // 85% > 80%
    assert!(matches!(status, BudgetStatus::Warning { .. }));
}

#[test]
fn budget_controller_memory_warning() {
    let config = BudgetConfig {
        memory_budget_bytes: 1000,
        warning_threshold_millionths: 800_000,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    let status = b.record_memory(850);
    assert!(matches!(status, BudgetStatus::Warning { .. }));
}

#[test]
fn budget_controller_compute_exhaustion_activates_fallback() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: true,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_compute(100);
    assert!(b.is_fallback_active());
    assert_eq!(b.events().len(), 1);
    assert!(matches!(b.events()[0].kind, BudgetEventKind::Exhausted));
}

#[test]
fn budget_controller_memory_exhaustion_activates_fallback() {
    let config = BudgetConfig {
        memory_budget_bytes: 500,
        deterministic_fallback_on_exhaust: true,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_memory(500);
    assert!(b.is_fallback_active());
}

#[test]
fn budget_controller_no_fallback_when_disabled() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: false,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_compute(200);
    assert!(!b.is_fallback_active());
    assert!(b.events().is_empty());
}

#[test]
fn budget_controller_double_exhaust_no_duplicate_event() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: true,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_compute(100);
    b.record_compute(50); // second call after already exhausted
    // Should only have 1 Exhausted event (guard prevents duplicate)
    let exhausted_count = b
        .events()
        .iter()
        .filter(|e| matches!(e.kind, BudgetEventKind::Exhausted))
        .count();
    assert_eq!(exhausted_count, 1);
}

#[test]
fn budget_controller_remaining_decreases_linearly() {
    let config = BudgetConfig {
        compute_budget_us: 1000,
        memory_budget_bytes: 1_000_000,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    let r0 = b.budget_remaining_millionths();
    assert_eq!(r0, 1_000_000);
    b.record_compute(500); // 50%
    let r1 = b.budget_remaining_millionths();
    assert_eq!(r1, 500_000);
}

#[test]
fn budget_controller_remaining_never_negative() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_compute(200); // 200% usage
    assert!(b.budget_remaining_millionths() >= 0);
}

#[test]
fn budget_controller_epoch_reset_clears_and_records_event() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: true,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    b.record_compute(100);
    assert!(b.is_fallback_active());
    b.reset_epoch(SecurityEpoch::from_raw(2));
    assert!(!b.is_fallback_active());
    assert_eq!(b.compute_consumed_us(), 0);
    assert_eq!(b.memory_consumed_bytes(), 0);
    // Should have Exhausted + EpochReset events
    let reset_events: Vec<_> = b
        .events()
        .iter()
        .filter(|e| matches!(e.kind, BudgetEventKind::EpochReset))
        .collect();
    assert_eq!(reset_events.len(), 1);
}

#[test]
fn budget_controller_zero_budget_immediate_exhaust() {
    let config = BudgetConfig {
        compute_budget_us: 0,
        memory_budget_bytes: 0,
        deterministic_fallback_on_exhaust: true,
        ..Default::default()
    };
    let mut b = BudgetController::new(config, SecurityEpoch::from_raw(1));
    let status = b.record_compute(1);
    assert!(matches!(status, BudgetStatus::Exhausted { .. }));
}

// ===========================================================================
// 29) DecisionContext — orchestration tests
// ===========================================================================

fn make_state(regime: RegimeLabel, safe_mode: bool) -> DecisionState {
    let mut risk = std::collections::BTreeMap::new();
    risk.insert(RiskFactor::Compatibility, 100_000);
    risk.insert(RiskFactor::Latency, 100_000);
    risk.insert(RiskFactor::Memory, 100_000);
    risk.insert(RiskFactor::IncidentSeverity, 100_000);
    DecisionState {
        epoch: SecurityEpoch::from_raw(1),
        regime,
        risk_belief_millionths: risk,
        latency_quantiles_us: LatencyQuantiles {
            p50_us: 1000,
            p95_us: 5000,
            p99_us: 10000,
            p999_us: 50000,
        },
        budget_remaining_millionths: 1_000_000,
        decisions_in_epoch: 0,
        safe_mode_active: safe_mode,
    }
}

#[test]
fn context_normal_routes_to_throughput_lane() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_throughput_profile");
    } else {
        panic!("expected RouteTo");
    }
    assert!(outcome.demotion.is_none());
}

#[test]
fn context_elevated_routes_to_throughput_lane() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Elevated, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_throughput_profile");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_attack_routes_to_deterministic_lane() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Attack, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_deterministic_profile");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_degraded_routes_to_deterministic_lane() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Degraded, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_deterministic_profile");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_recovery_routes_to_deterministic_lane() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Recovery, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_deterministic_profile");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_safe_mode_overrides_regime() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    // Normal regime but safe_mode=true should still go to deterministic
    let state = make_state(RegimeLabel::Normal, true);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "baseline_deterministic_profile");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_guardrail_priority_budget_before_cvar() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 10,
            deterministic_fallback_on_exhaust: true,
            ..Default::default()
        },
        cvar_config: CvarConfig {
            alpha_millionths: 500_000,
            max_cvar_millionths: 1,
            min_observations: 2,
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    ctx.record_compute(10);
    ctx.observe_loss(100_000_000, SecurityEpoch::from_raw(1));
    ctx.observe_loss(200_000_000, SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    // Budget exhaustion has highest priority
    assert_eq!(outcome.action, LaneAction::SuspendAdaptive);
    assert_eq!(outcome.demotion, Some(DemotionReason::BudgetExhausted));
}

#[test]
fn context_guardrail_priority_cvar_before_drift() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            alpha_millionths: 500_000,
            max_cvar_millionths: 1,
            min_observations: 2,
        },
        drift_config: DriftConfig {
            reference_window: 5,
            test_window: 5,
            min_samples: 5,
            kl_threshold_millionths: 1,
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    // Trigger both cvar and drift
    for _ in 0..5 {
        ctx.observe_loss(1_000_000, SecurityEpoch::from_raw(1));
    }
    for _ in 0..5 {
        ctx.observe_loss(500_000_000, SecurityEpoch::from_raw(1));
    }
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    assert_eq!(outcome.demotion, Some(DemotionReason::CvarExceeded));
}

#[test]
fn context_observe_loss_updates_cvar_and_drift() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    ctx.observe_loss(42_000, SecurityEpoch::from_raw(1));
    assert_eq!(ctx.cvar().observation_count(), 1);
    assert_eq!(ctx.drift().observation_count(), 1);
}

#[test]
fn context_observe_calibration_updates_calibrator() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    ctx.observe_calibration(SecurityEpoch::from_raw(1), true);
    ctx.observe_calibration(SecurityEpoch::from_raw(2), false);
    assert_eq!(ctx.calibrator().total_predictions(), 2);
    assert_eq!(ctx.calibrator().covered_predictions(), 1);
}

#[test]
fn context_record_compute_returns_status() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 1000,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    let status = ctx.record_compute(100);
    assert!(matches!(status, BudgetStatus::Normal { .. }));
}

#[test]
fn context_record_memory_returns_status() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            memory_budget_bytes: 10_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    let status = ctx.record_memory(1000);
    assert!(matches!(status, BudgetStatus::Normal { .. }));
}

#[test]
fn context_advance_epoch_resets_budget_and_sequence() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    ctx.decide(&state);
    ctx.decide(&state);
    assert_eq!(ctx.traces().len(), 2);
    ctx.advance_epoch(SecurityEpoch::from_raw(2));
    ctx.decide(&state);
    // Third trace should have sequence=1 (reset)
    assert_eq!(ctx.traces()[2].sequence, 1);
    assert_eq!(ctx.traces()[2].epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn context_traces_accumulate_across_decisions() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    for _ in 0..5 {
        ctx.decide(&state);
    }
    assert_eq!(ctx.traces().len(), 5);
    for (i, trace) in ctx.traces().iter().enumerate() {
        assert_eq!(trace.sequence, (i + 1) as u64);
    }
}

#[test]
fn context_fallback_events_recorded_on_cvar() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            alpha_millionths: 500_000,
            max_cvar_millionths: 1,
            min_observations: 2,
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    ctx.observe_loss(100_000_000, SecurityEpoch::from_raw(1));
    ctx.observe_loss(200_000_000, SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    ctx.decide(&state);
    assert_eq!(ctx.fallback_events().len(), 1);
    assert_eq!(
        ctx.fallback_events()[0].trigger,
        DemotionReason::CvarExceeded
    );
    assert_eq!(ctx.fallback_events()[0].to_action, LaneAction::FallbackSafe);
}

#[test]
fn context_fallback_events_recorded_on_drift() {
    let config = DecisionContextConfig {
        drift_config: DriftConfig {
            reference_window: 5,
            test_window: 5,
            min_samples: 5,
            kl_threshold_millionths: 1,
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    for _ in 0..5 {
        ctx.observe_loss(1_000_000, SecurityEpoch::from_raw(1));
    }
    for _ in 0..5 {
        ctx.observe_loss(500_000_000, SecurityEpoch::from_raw(1));
    }
    let state = make_state(RegimeLabel::Normal, false);
    ctx.decide(&state);
    assert_eq!(ctx.fallback_events().len(), 1);
    assert_eq!(
        ctx.fallback_events()[0].trigger,
        DemotionReason::DriftDetected
    );
}

#[test]
fn context_fallback_event_on_coverage_violation() {
    let config = DecisionContextConfig {
        conformal_config: ConformalConfig {
            alpha_millionths: 100_000,
            min_calibration_observations: 3,
            max_consecutive_violations: 2,
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    for i in 0..5 {
        ctx.observe_calibration(SecurityEpoch::from_raw(i + 1), false);
    }
    let state = make_state(RegimeLabel::Normal, false);
    ctx.decide(&state);
    assert_eq!(ctx.fallback_events().len(), 1);
    assert_eq!(
        ctx.fallback_events()[0].trigger,
        DemotionReason::CoverageViolation
    );
}

#[test]
fn context_empty_lanes_routes_to_fallback() {
    let config = DecisionContextConfig {
        lanes: vec![],
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.0, "fallback");
    } else {
        panic!("expected RouteTo");
    }
}

#[test]
fn context_single_lane_always_uses_it() {
    let config = DecisionContextConfig {
        lanes: vec![LaneId("only_lane".into())],
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    // All regimes should route to the single lane
    for regime in [
        RegimeLabel::Normal,
        RegimeLabel::Elevated,
        RegimeLabel::Attack,
        RegimeLabel::Degraded,
        RegimeLabel::Recovery,
    ] {
        let state = make_state(regime, false);
        let outcome = ctx.decide(&state);
        if let LaneAction::RouteTo(lane) = &outcome.action {
            assert_eq!(lane.0, "only_lane", "regime={regime}: wrong lane");
        }
    }
}

// ===========================================================================
// 30) PolicyBundle — field-level tests
// ===========================================================================

#[test]
fn policy_bundle_version_is_1_0_0() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    assert_eq!(bundle.version, "1.0.0");
}

#[test]
fn policy_bundle_epoch_matches_context() {
    let ep = SecurityEpoch::from_raw(42);
    let ctx = DecisionContext::new(DecisionContextConfig::default(), ep);
    let bundle = ctx.policy_bundle();
    assert_eq!(bundle.epoch, ep);
}

#[test]
fn policy_bundle_lanes_match_config() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    assert_eq!(bundle.lanes.len(), 2);
}

#[test]
fn policy_bundle_default_action_is_route_to_first_lane() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    assert!(matches!(bundle.default_action, LaneAction::RouteTo(_)));
}

#[test]
fn policy_bundle_fallback_action_is_fallback_safe() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    assert_eq!(bundle.fallback_action, LaneAction::FallbackSafe);
}

#[test]
fn policy_bundle_risk_weights_sum_to_million() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    let total: i64 = bundle.risk_weights.values().sum();
    assert_eq!(total, 1_000_000);
}

#[test]
fn policy_bundle_serde_roundtrip() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: PolicyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn policy_bundle_empty_lanes_fallback_default_action() {
    let config = DecisionContextConfig {
        lanes: vec![],
        ..Default::default()
    };
    let ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    if let LaneAction::RouteTo(lane) = &bundle.default_action {
        assert_eq!(lane.0, "fallback");
    }
}

// ===========================================================================
// 31) DecisionState — JSON field stability
// ===========================================================================

#[test]
fn json_fields_decision_state() {
    let state = make_state(RegimeLabel::Normal, false);
    let v: serde_json::Value = serde_json::to_value(&state).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "epoch",
        "regime",
        "risk_belief_millionths",
        "latency_quantiles_us",
        "budget_remaining_millionths",
        "decisions_in_epoch",
        "safe_mode_active",
    ] {
        assert!(obj.contains_key(key), "DecisionState missing field: {key}");
    }
}

#[test]
fn decision_state_serde_roundtrip() {
    let state = make_state(RegimeLabel::Elevated, true);
    let json = serde_json::to_string(&state).unwrap();
    let back: DecisionState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ===========================================================================
// 32) DecisionTrace — JSON field stability
// ===========================================================================

#[test]
fn json_fields_decision_trace() {
    let trace = DecisionTrace {
        sequence: 1,
        epoch: SecurityEpoch::from_raw(1),
        state: make_state(RegimeLabel::Normal, false),
        action: LaneAction::FallbackSafe,
        expected_loss_millionths: 42_000,
        cvar_millionths: Some(10_000),
        drift_kl_millionths: None,
        budget_remaining_millionths: 500_000,
        guardrail_active: false,
        reason: "test".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&trace).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "sequence",
        "epoch",
        "state",
        "action",
        "expected_loss_millionths",
        "cvar_millionths",
        "drift_kl_millionths",
        "budget_remaining_millionths",
        "guardrail_active",
        "reason",
    ] {
        assert!(obj.contains_key(key), "DecisionTrace missing field: {key}");
    }
}

// ===========================================================================
// 33) FallbackTriggerEvent — JSON field stability
// ===========================================================================

#[test]
fn json_fields_fallback_trigger_event() {
    let event = FallbackTriggerEvent {
        epoch: SecurityEpoch::from_raw(1),
        trigger: DemotionReason::CvarExceeded,
        from_action: None,
        to_action: LaneAction::FallbackSafe,
        metrics: FallbackMetrics {
            cvar_millionths: None,
            drift_kl_millionths: None,
            budget_remaining_millionths: 1_000_000,
            coverage_millionths: 1_000_000,
            e_value_millionths: 1_000_000,
        },
    };
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["epoch", "trigger", "from_action", "to_action", "metrics"] {
        assert!(
            obj.contains_key(key),
            "FallbackTriggerEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 34) LaneId — legacy label canonicalization
// ===========================================================================

#[test]
fn lane_id_deterministic_profile_label() {
    let lane = LaneId::deterministic_profile();
    assert_eq!(lane.to_string(), "baseline_deterministic_profile");
}

#[test]
fn lane_id_throughput_profile_label() {
    let lane = LaneId::throughput_profile();
    assert_eq!(lane.to_string(), "baseline_throughput_profile");
}

#[test]
fn lane_id_custom_label_passthrough() {
    let lane = LaneId("my_custom_lane".into());
    assert_eq!(lane.stable_label(), "my_custom_lane");
}

#[test]
fn lane_id_serde_roundtrip_custom() {
    let lane = LaneId("custom".into());
    let json = serde_json::to_string(&lane).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

#[test]
fn lane_id_deserialize_legacy_v8() {
    let back: LaneId = serde_json::from_str("\"v8_inspired_native\"").unwrap();
    assert_eq!(back, LaneId::throughput_profile());
}

// ===========================================================================
// 35) DecisionOutcome — serde
// ===========================================================================

#[test]
fn decision_outcome_serde_roundtrip_with_demotion() {
    let outcome = DecisionOutcome {
        action: LaneAction::Demote {
            from_lane: LaneId("test".into()),
            reason: DemotionReason::DriftDetected,
        },
        trace: DecisionTrace {
            sequence: 5,
            epoch: SecurityEpoch::from_raw(3),
            state: make_state(RegimeLabel::Normal, false),
            action: LaneAction::FallbackSafe,
            expected_loss_millionths: 0,
            cvar_millionths: None,
            drift_kl_millionths: Some(200_000),
            budget_remaining_millionths: 1_000_000,
            guardrail_active: true,
            reason: "drift".into(),
        },
        demotion: Some(DemotionReason::DriftDetected),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: DecisionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ===========================================================================
// 36) BudgetStatus — variant field checks
// ===========================================================================

#[test]
fn budget_status_normal_fields() {
    let s = BudgetStatus::Normal {
        compute_fraction_millionths: 100_000,
        memory_fraction_millionths: 50_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: BudgetStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn budget_status_warning_fields() {
    let s = BudgetStatus::Warning {
        compute_fraction_millionths: 850_000,
        memory_fraction_millionths: 700_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: BudgetStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn budget_status_exhausted_fields() {
    let s = BudgetStatus::Exhausted {
        compute_fraction_millionths: 1_000_000,
        memory_fraction_millionths: 1_200_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: BudgetStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// 37) CvarCheckResult — serde per variant
// ===========================================================================

#[test]
fn cvar_check_result_insufficient_serde() {
    let r = CvarCheckResult::InsufficientData {
        observations: 3,
        required: 30,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn cvar_check_result_within_bounds_serde() {
    let r = CvarCheckResult::WithinBounds {
        cvar_millionths: 5_000_000,
        threshold_millionths: 50_000_000,
        headroom_millionths: 45_000_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn cvar_check_result_exceeded_serde() {
    let r = CvarCheckResult::Exceeded {
        cvar_millionths: 60_000_000,
        threshold_millionths: 50_000_000,
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 38) DriftCheckResult — serde per variant
// ===========================================================================

#[test]
fn drift_check_result_insufficient_serde() {
    let r = DriftCheckResult::InsufficientData {
        observations: 5,
        required: 150,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DriftCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn drift_check_result_no_drift_serde() {
    let r = DriftCheckResult::NoDrift {
        kl_millionths: 50_000,
        threshold_millionths: 100_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DriftCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn drift_check_result_detected_serde() {
    let r = DriftCheckResult::DriftDetected {
        kl_millionths: 300_000,
        threshold_millionths: 100_000,
        epoch: SecurityEpoch::from_raw(99),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DriftCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 39) CalibrationLedgerEntry — field stability
// ===========================================================================

#[test]
fn json_fields_calibration_ledger_entry() {
    let entry = CalibrationLedgerEntry {
        epoch: SecurityEpoch::from_raw(1),
        prediction_covered: true,
        running_coverage_millionths: 900_000,
        e_value_millionths: 1_000_000,
        violation: false,
    };
    let v: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "epoch",
        "prediction_covered",
        "running_coverage_millionths",
        "e_value_millionths",
        "violation",
    ] {
        assert!(
            obj.contains_key(key),
            "CalibrationLedgerEntry missing field: {key}"
        );
    }
}

// ===========================================================================
// 40) Context — multi-epoch lifecycle
// ===========================================================================

#[test]
fn context_multi_epoch_lifecycle() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);

    // Epoch 1: two decisions
    ctx.decide(&state);
    ctx.decide(&state);
    assert_eq!(ctx.traces().len(), 2);

    // Epoch 2: reset and new decisions
    ctx.advance_epoch(SecurityEpoch::from_raw(2));
    ctx.decide(&state);
    assert_eq!(ctx.traces().len(), 3);
    assert_eq!(ctx.traces()[2].sequence, 1);
    assert_eq!(ctx.traces()[2].epoch, SecurityEpoch::from_raw(2));

    // Budget should be reset
    assert_eq!(ctx.budget().compute_consumed_us(), 0);
}

// ===========================================================================
// 41) Context — trace guardrail_active flag
// ===========================================================================

#[test]
fn context_trace_guardrail_active_false_when_clear() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    assert!(!outcome.trace.guardrail_active);
}

#[test]
fn context_trace_guardrail_active_true_on_budget_exhaust() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 10,
            deterministic_fallback_on_exhaust: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ctx = DecisionContext::new(config, SecurityEpoch::from_raw(1));
    ctx.record_compute(10);
    let state = make_state(RegimeLabel::Normal, false);
    let outcome = ctx.decide(&state);
    assert!(outcome.trace.guardrail_active);
}

// ===========================================================================
// 42) DecisionContextConfig — serde roundtrip
// ===========================================================================

#[test]
fn decision_context_config_serde_roundtrip() {
    let config = DecisionContextConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: DecisionContextConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// 43) Context — serde roundtrip preserves state
// ===========================================================================

#[test]
fn context_serde_roundtrip_preserves_observations() {
    let mut ctx =
        DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    ctx.observe_loss(42_000, SecurityEpoch::from_raw(1));
    ctx.observe_calibration(SecurityEpoch::from_raw(1), true);
    let state = make_state(RegimeLabel::Normal, false);
    ctx.decide(&state);

    let json = serde_json::to_string(&ctx).unwrap();
    let back: DecisionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(
        ctx.cvar().observation_count(),
        back.cvar().observation_count()
    );
    assert_eq!(
        ctx.calibrator().total_predictions(),
        back.calibrator().total_predictions()
    );
    assert_eq!(ctx.traces().len(), back.traces().len());
}

// ===========================================================================
// 44) FallbackMetrics — field value assertions
// ===========================================================================

#[test]
fn fallback_metrics_none_fields_serialize_as_null() {
    let fm = FallbackMetrics {
        cvar_millionths: None,
        drift_kl_millionths: None,
        budget_remaining_millionths: 1_000_000,
        coverage_millionths: 1_000_000,
        e_value_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&fm).unwrap();
    assert!(json.contains("null"));
    let back: FallbackMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(fm, back);
}

// ===========================================================================
// 45) BudgetEvent — JSON field stability
// ===========================================================================

#[test]
fn json_fields_budget_event() {
    let be = BudgetEvent {
        epoch: SecurityEpoch::from_raw(1),
        kind: BudgetEventKind::Warning,
        compute_consumed_us: 1000,
        memory_consumed_bytes: 2000,
    };
    let v: serde_json::Value = serde_json::to_value(&be).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "epoch",
        "kind",
        "compute_consumed_us",
        "memory_consumed_bytes",
    ] {
        assert!(obj.contains_key(key), "BudgetEvent missing field: {key}");
    }
}

// ===========================================================================
// 46) PolicyBundle — JSON field stability
// ===========================================================================

#[test]
fn json_fields_policy_bundle() {
    let ctx = DecisionContext::new(DecisionContextConfig::default(), SecurityEpoch::from_raw(1));
    let bundle = ctx.policy_bundle();
    let v: serde_json::Value = serde_json::to_value(&bundle).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "version",
        "epoch",
        "lanes",
        "cvar_config",
        "conformal_config",
        "drift_config",
        "budget_config",
        "risk_weights",
        "default_action",
        "fallback_action",
    ] {
        assert!(obj.contains_key(key), "PolicyBundle missing field: {key}");
    }
}

// ===========================================================================
// 47) LaneAction — Demote display exact format
// ===========================================================================

#[test]
fn lane_action_demote_display_exact() {
    let action = LaneAction::Demote {
        from_lane: LaneId("my_lane".into()),
        reason: DemotionReason::OperatorOverride,
    };
    assert_eq!(action.to_string(), "demote:my_lane:operator_override");
}

// ===========================================================================
// 48) CvarGuardrail — serde preserves observations
// ===========================================================================

#[test]
fn cvar_guardrail_serde_preserves_triggered_state() {
    let config = CvarConfig {
        alpha_millionths: 500_000,
        max_cvar_millionths: 1,
        min_observations: 2,
    };
    let mut g = CvarGuardrail::new(config);
    g.observe(100_000_000);
    g.observe(200_000_000);
    g.check(SecurityEpoch::from_raw(5));
    assert!(g.is_triggered());

    let json = serde_json::to_string(&g).unwrap();
    let back: CvarGuardrail = serde_json::from_str(&json).unwrap();
    assert!(back.is_triggered());
    assert_eq!(back.trigger_epoch(), Some(SecurityEpoch::from_raw(5)));
    assert_eq!(back.observation_count(), 2);
}

// ===========================================================================
// 49) DriftDetector — serde preserves drift state
// ===========================================================================

#[test]
fn drift_detector_serde_preserves_drift_state() {
    let config = DriftConfig {
        reference_window: 5,
        test_window: 5,
        min_samples: 5,
        kl_threshold_millionths: 1,
    };
    let mut d = DriftDetector::new(config);
    for _ in 0..5 {
        d.observe(1_000_000);
    }
    for _ in 0..5 {
        d.observe(500_000_000);
    }
    d.check(SecurityEpoch::from_raw(3));
    assert!(d.is_drift_detected());

    let json = serde_json::to_string(&d).unwrap();
    let back: DriftDetector = serde_json::from_str(&json).unwrap();
    assert!(back.is_drift_detected());
    assert_eq!(back.drift_epoch(), Some(SecurityEpoch::from_raw(3)));
}
