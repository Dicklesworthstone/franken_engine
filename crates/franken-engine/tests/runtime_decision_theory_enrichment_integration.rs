#![forbid(unsafe_code)]
//! Enrichment integration tests for `runtime_decision_theory`.
//!
//! Adds config default exact values, Display exactness, Debug distinctness,
//! JSON field-name stability, initial-state checks, and serde roundtrips
//! beyond the existing 47 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::runtime_decision_theory::{
    BudgetConfig, BudgetController, BudgetEvent, BudgetEventKind, ConformalCalibrator,
    ConformalConfig, CvarConfig, CvarGuardrail, DecisionContextConfig, DemotionReason, DriftConfig,
    DriftDetector, FallbackMetrics, LaneAction, LaneId, LatencyQuantiles, RegimeLabel, RiskFactor,
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
