#![forbid(unsafe_code)]
//! Integration tests for the `runtime_decision_theory` module.
//!
//! Exercises CVaR guardrails, conformal calibration, drift detection,
//! budget control, decision context orchestration, lane selection, and
//! serde round-trips from outside the crate boundary.

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

use std::collections::BTreeMap;

use frankenengine_engine::runtime_decision_theory::{
    BudgetConfig, BudgetController, BudgetStatus, CalibrationLedgerEntry, ConformalCalibrator,
    ConformalConfig, CvarCheckResult, CvarConfig, CvarGuardrail, DecisionContext,
    DecisionContextConfig, DecisionOutcome, DecisionState, DecisionTrace, DemotionReason,
    DriftCheckResult, DriftConfig, DriftDetector, FallbackMetrics, FallbackTriggerEvent,
    LaneAction, LaneId, LatencyQuantiles, PolicyBundle, RegimeLabel, RiskFactor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_latency() -> LatencyQuantiles {
    LatencyQuantiles {
        p50_us: 1_000,
        p95_us: 5_000,
        p99_us: 10_000,
        p999_us: 50_000,
    }
}

fn uniform_risk() -> BTreeMap<RiskFactor, i64> {
    let mut m = BTreeMap::new();
    m.insert(RiskFactor::Compatibility, 250_000);
    m.insert(RiskFactor::Latency, 250_000);
    m.insert(RiskFactor::Memory, 250_000);
    m.insert(RiskFactor::IncidentSeverity, 250_000);
    m
}

fn default_state() -> DecisionState {
    DecisionState {
        epoch: epoch(1),
        regime: RegimeLabel::Normal,
        risk_belief_millionths: uniform_risk(),
        latency_quantiles_us: default_latency(),
        budget_remaining_millionths: 1_000_000,
        decisions_in_epoch: 0,
        safe_mode_active: false,
    }
}

fn default_ctx_config() -> DecisionContextConfig {
    DecisionContextConfig::default()
}

// ===========================================================================
// 1. LaneId — display, serde
// ===========================================================================

#[test]
fn lane_id_display() {
    let lid = LaneId("test_lane".into());
    assert_eq!(lid.to_string(), "test_lane");
}

#[test]
fn lane_id_serde_round_trip() {
    let lid = LaneId("test_lane".into());
    let json = serde_json::to_string(&lid).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lid);
}

// ===========================================================================
// 2. RiskFactor, RegimeLabel, DemotionReason — display, serde
// ===========================================================================

#[test]
fn risk_factor_all_variants() {
    assert_eq!(RiskFactor::ALL.len(), 4);
    for rf in RiskFactor::ALL {
        assert!(!rf.to_string().is_empty());
    }
}

#[test]
fn risk_factor_serde_round_trip() {
    for rf in RiskFactor::ALL {
        let json = serde_json::to_string(&rf).unwrap();
        let back: RiskFactor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rf);
    }
}

#[test]
fn regime_label_display() {
    let labels = [
        RegimeLabel::Normal,
        RegimeLabel::Elevated,
        RegimeLabel::Attack,
        RegimeLabel::Degraded,
        RegimeLabel::Recovery,
    ];
    for l in &labels {
        assert!(!l.to_string().is_empty());
    }
}

#[test]
fn regime_label_serde_round_trip() {
    let labels = [
        RegimeLabel::Normal,
        RegimeLabel::Elevated,
        RegimeLabel::Attack,
        RegimeLabel::Degraded,
        RegimeLabel::Recovery,
    ];
    for l in &labels {
        let json = serde_json::to_string(l).unwrap();
        let back: RegimeLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *l);
    }
}

#[test]
fn demotion_reason_display() {
    let reasons = [
        DemotionReason::CvarExceeded,
        DemotionReason::DriftDetected,
        DemotionReason::BudgetExhausted,
        DemotionReason::GuardrailTriggered,
        DemotionReason::CoverageViolation,
        DemotionReason::OperatorOverride,
    ];
    for r in &reasons {
        assert!(!r.to_string().is_empty());
    }
}

// ===========================================================================
// 3. LaneAction — display, serde
// ===========================================================================

#[test]
fn lane_action_variants_display() {
    let actions = [
        LaneAction::RouteTo(LaneId("lane_a".into())),
        LaneAction::FallbackSafe,
        LaneAction::Demote {
            from_lane: LaneId("lane_a".into()),
            reason: DemotionReason::CvarExceeded,
        },
        LaneAction::SuspendAdaptive,
    ];
    for a in &actions {
        assert!(!a.to_string().is_empty());
    }
}

#[test]
fn lane_action_serde_round_trip() {
    let actions = [
        LaneAction::RouteTo(LaneId("lane_a".into())),
        LaneAction::FallbackSafe,
        LaneAction::Demote {
            from_lane: LaneId("lane_a".into()),
            reason: DemotionReason::DriftDetected,
        },
        LaneAction::SuspendAdaptive,
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let back: LaneAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *a);
    }
}

// ===========================================================================
// 4. CVaR Guardrail
// ===========================================================================

#[test]
fn cvar_insufficient_data_initially() {
    let mut cvar = CvarGuardrail::new(CvarConfig::default());
    let result = cvar.check(epoch(1));
    assert!(matches!(result, CvarCheckResult::InsufficientData { .. }));
}

#[test]
fn cvar_within_bounds_low_losses() {
    let config = CvarConfig {
        min_observations: 5,
        ..CvarConfig::default()
    };
    let mut cvar = CvarGuardrail::new(config);
    for _ in 0..10 {
        cvar.observe(100_000); // small loss
    }
    let result = cvar.check(epoch(1));
    assert!(matches!(result, CvarCheckResult::WithinBounds { .. }));
    assert!(!cvar.is_triggered());
}

#[test]
fn cvar_exceeds_threshold_high_tail() {
    let config = CvarConfig {
        alpha_millionths: 950_000,
        max_cvar_millionths: 500_000, // low threshold
        min_observations: 5,
    };
    let mut cvar = CvarGuardrail::new(config);
    // Push a mix, but several very high losses in the tail
    for _ in 0..10 {
        cvar.observe(100_000);
    }
    for _ in 0..10 {
        cvar.observe(5_000_000); // huge loss
    }
    let result = cvar.check(epoch(1));
    assert!(matches!(result, CvarCheckResult::Exceeded { .. }));
    assert!(cvar.is_triggered());
}

#[test]
fn cvar_reset_clears_state() {
    let config = CvarConfig {
        min_observations: 3,
        ..CvarConfig::default()
    };
    let mut cvar = CvarGuardrail::new(config);
    for _ in 0..5 {
        cvar.observe(100_000);
    }
    assert_eq!(cvar.observation_count(), 5);
    cvar.reset();
    assert_eq!(cvar.observation_count(), 0);
}

// ===========================================================================
// 5. Conformal Calibrator
// ===========================================================================

#[test]
fn conformal_starts_calibrated() {
    let cal = ConformalCalibrator::new(ConformalConfig::default());
    // Vacuously calibrated before any observations
    assert!(cal.is_calibrated());
    assert_eq!(cal.total_predictions(), 0);
}

#[test]
fn conformal_perfect_coverage() {
    let config = ConformalConfig {
        min_calibration_observations: 5,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    for i in 0..10 {
        cal.record(epoch(i + 1), true); // all covered
    }
    assert!(cal.is_calibrated());
    assert_eq!(cal.covered_predictions(), 10);
    assert!(!cal.violation_flagged());
}

#[test]
fn conformal_all_misses_violation() {
    let config = ConformalConfig {
        min_calibration_observations: 3,
        max_consecutive_violations: 3,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    for i in 0..10 {
        cal.record(epoch(i + 1), false); // all misses
    }
    assert!(cal.violation_flagged());
}

#[test]
fn conformal_ledger_recorded() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    cal.record(epoch(1), true);
    cal.record(epoch(2), false);
    let ledger = cal.ledger();
    assert_eq!(ledger.len(), 2);
    assert!(ledger[0].prediction_covered);
    assert!(!ledger[1].prediction_covered);
}

#[test]
fn calibration_ledger_entry_serde() {
    let entry = CalibrationLedgerEntry {
        epoch: epoch(1),
        prediction_covered: true,
        running_coverage_millionths: 1_000_000,
        e_value_millionths: 1_000_000,
        violation: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: CalibrationLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 6. Drift Detector
// ===========================================================================

#[test]
fn drift_insufficient_data_initially() {
    let mut drift = DriftDetector::new(DriftConfig::default());
    let result = drift.check(epoch(1));
    assert!(matches!(result, DriftCheckResult::InsufficientData { .. }));
}

#[test]
fn drift_no_drift_uniform_data() {
    let config = DriftConfig {
        reference_window: 20,
        test_window: 10,
        min_samples: 5,
        ..DriftConfig::default()
    };
    let mut drift = DriftDetector::new(config);
    // All same value → no distribution shift
    for _ in 0..40 {
        drift.observe(500_000);
    }
    let result = drift.check(epoch(1));
    assert!(
        matches!(result, DriftCheckResult::NoDrift { .. }),
        "expected NoDrift, got {:?}",
        result
    );
    assert!(!drift.is_drift_detected());
}

#[test]
fn drift_detected_distribution_shift() {
    let config = DriftConfig {
        kl_threshold_millionths: 10_000, // very low threshold
        reference_window: 20,
        test_window: 10,
        min_samples: 5,
    };
    let mut drift = DriftDetector::new(config);
    // Reference window: low values
    for _ in 0..25 {
        drift.observe(100_000);
    }
    // Test window: dramatically different values
    for _ in 0..15 {
        drift.observe(900_000);
    }
    let result = drift.check(epoch(1));
    assert!(
        matches!(result, DriftCheckResult::DriftDetected { .. }),
        "expected DriftDetected, got {:?}",
        result
    );
    assert!(drift.is_drift_detected());
}

#[test]
fn drift_reset_clears_state() {
    let config = DriftConfig {
        min_samples: 3,
        ..DriftConfig::default()
    };
    let mut drift = DriftDetector::new(config);
    for _ in 0..10 {
        drift.observe(500_000);
    }
    assert!(drift.observation_count() > 0);
    drift.reset();
    assert_eq!(drift.observation_count(), 0);
}

// ===========================================================================
// 7. Budget Controller
// ===========================================================================

#[test]
fn budget_starts_normal() {
    let budget = BudgetController::new(BudgetConfig::default(), epoch(1));
    assert!(!budget.is_fallback_active());
    assert_eq!(budget.compute_consumed_us(), 0);
    assert_eq!(budget.memory_consumed_bytes(), 0);
}

#[test]
fn budget_compute_tracking() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    let status = budget.record_compute(30_000);
    assert!(matches!(status, BudgetStatus::Normal { .. }));
    assert_eq!(budget.compute_consumed_us(), 30_000);
}

#[test]
fn budget_warning_at_threshold() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        warning_threshold_millionths: 800_000, // 80%
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    let status = budget.record_compute(85_000); // 85% consumed
    assert!(matches!(status, BudgetStatus::Warning { .. }));
}

#[test]
fn budget_exhaustion_triggers_fallback() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        deterministic_fallback_on_exhaust: true,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    let status = budget.record_compute(200_000); // over budget
    assert!(matches!(status, BudgetStatus::Exhausted { .. }));
    assert!(budget.is_fallback_active());
}

#[test]
fn budget_epoch_reset() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_compute(50_000);
    budget.reset_epoch(epoch(2));
    assert_eq!(budget.compute_consumed_us(), 0);
    assert!(!budget.is_fallback_active());
}

#[test]
fn budget_events_recorded() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        warning_threshold_millionths: 800_000,
        deterministic_fallback_on_exhaust: true,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_compute(200_000); // triggers warning + exhaustion
    let events = budget.events();
    assert!(!events.is_empty());
}

// ===========================================================================
// 8. DecisionContext — basic lifecycle
// ===========================================================================

#[test]
fn decision_context_initial_decide_routes() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = default_state();
    let outcome = ctx.decide(&state);
    // Normal regime with no guardrail triggers → should route to a lane
    assert!(
        matches!(outcome.action, LaneAction::RouteTo(_)),
        "expected RouteTo, got {:?}",
        outcome.action
    );
    assert_eq!(outcome.demotion, None);
}

#[test]
fn decision_context_traces_accumulate() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = default_state();
    ctx.decide(&state);
    ctx.decide(&state);
    ctx.decide(&state);
    assert_eq!(ctx.traces().len(), 3);
}

#[test]
fn decision_context_advance_epoch() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = default_state();
    ctx.decide(&state);
    ctx.advance_epoch(epoch(2));
    let state2 = DecisionState {
        epoch: epoch(2),
        ..default_state()
    };
    ctx.decide(&state2);
    // Should have 2 traces total
    assert_eq!(ctx.traces().len(), 2);
}

// ===========================================================================
// 9. DecisionContext — guardrail priority
// ===========================================================================

#[test]
fn decision_context_attack_regime_forces_safe() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = DecisionState {
        regime: RegimeLabel::Attack,
        ..default_state()
    };
    let outcome = ctx.decide(&state);
    // Attack regime should select the safe (first) lane
    if let LaneAction::RouteTo(lane) = &outcome.action {
        // First lane in default config
        assert!(
            ctx.policy_bundle()
                .lanes
                .first()
                .is_some_and(|l| *l == *lane)
        );
    }
    // FallbackSafe is also acceptable
}

#[test]
fn decision_context_safe_mode_forces_safe_lane() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = DecisionState {
        safe_mode_active: true,
        ..default_state()
    };
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert!(
            ctx.policy_bundle()
                .lanes
                .first()
                .is_some_and(|l| *l == *lane)
        );
    }
    // FallbackSafe also acceptable
}

// ===========================================================================
// 10. DecisionContext — budget exhaustion triggers fallback
// ===========================================================================

#[test]
fn decision_context_budget_exhaustion_fallback() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..BudgetConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    // Exhaust the budget
    ctx.record_compute(200);
    let outcome = ctx.decide(&default_state());
    // Should trigger budget-related fallback or demotion
    assert!(
        outcome.demotion.is_some() || matches!(outcome.action, LaneAction::FallbackSafe),
        "expected fallback after budget exhaustion, got {:?}",
        outcome.action
    );
}

// ===========================================================================
// 11. PolicyBundle — serde
// ===========================================================================

#[test]
fn policy_bundle_serde_round_trip() {
    let ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let bundle = ctx.policy_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: PolicyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

#[test]
fn policy_bundle_reflects_config() {
    let config = default_ctx_config();
    let ctx = DecisionContext::new(config.clone(), epoch(1));
    let bundle = ctx.policy_bundle();
    assert_eq!(bundle.lanes, config.lanes);
    assert!(!bundle.version.is_empty());
}

// ===========================================================================
// 12. DecisionTrace — serde
// ===========================================================================

#[test]
fn decision_trace_serde_round_trip() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    ctx.decide(&default_state());
    let trace = &ctx.traces()[0];
    let json = serde_json::to_string(trace).unwrap();
    let back: DecisionTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(back, *trace);
}

// ===========================================================================
// 13. DecisionOutcome — serde
// ===========================================================================

#[test]
fn decision_outcome_serde_round_trip() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let outcome = ctx.decide(&default_state());
    let json = serde_json::to_string(&outcome).unwrap();
    let back: DecisionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

// ===========================================================================
// 14. Config types — serde
// ===========================================================================

#[test]
fn cvar_config_serde_round_trip() {
    let cfg = CvarConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CvarConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn conformal_config_serde_round_trip() {
    let cfg = ConformalConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ConformalConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn drift_config_serde_round_trip() {
    let cfg = DriftConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DriftConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn budget_config_serde_round_trip() {
    let cfg = BudgetConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: BudgetConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn decision_context_config_serde_round_trip() {
    let cfg = default_ctx_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DecisionContextConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 15. LatencyQuantiles, DecisionState — serde
// ===========================================================================

#[test]
fn latency_quantiles_serde_round_trip() {
    let lq = default_latency();
    let json = serde_json::to_string(&lq).unwrap();
    let back: LatencyQuantiles = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lq);
}

#[test]
fn decision_state_serde_round_trip() {
    let state = default_state();
    let json = serde_json::to_string(&state).unwrap();
    let back: DecisionState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, state);
}

// ===========================================================================
// 16. FallbackTriggerEvent — serde
// ===========================================================================

#[test]
fn fallback_trigger_event_serde_round_trip() {
    let evt = FallbackTriggerEvent {
        epoch: epoch(1),
        trigger: DemotionReason::CvarExceeded,
        from_action: Some(LaneAction::RouteTo(LaneId("lane_a".into()))),
        to_action: LaneAction::FallbackSafe,
        metrics: FallbackMetrics {
            cvar_millionths: Some(600_000),
            drift_kl_millionths: Some(50_000),
            budget_remaining_millionths: 200_000,
            coverage_millionths: 900_000,
            e_value_millionths: 1_200_000,
        },
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evt);
}

// ===========================================================================
// 17. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_decision_context() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            min_observations: 5,
            ..CvarConfig::default()
        },
        conformal_config: ConformalConfig {
            min_calibration_observations: 3,
            ..ConformalConfig::default()
        },
        drift_config: DriftConfig {
            min_samples: 5,
            ..DriftConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));

    // Seed observations
    for _ in 0..10 {
        ctx.observe_loss(100_000, epoch(1));
        ctx.observe_calibration(epoch(1), true);
    }

    // Make decisions
    for i in 0..5 {
        let state = DecisionState {
            decisions_in_epoch: i,
            ..default_state()
        };
        let outcome = ctx.decide(&state);
        assert!(
            matches!(outcome.action, LaneAction::RouteTo(_)),
            "round {i}: expected RouteTo, got {:?}",
            outcome.action
        );
    }

    // Verify traces
    assert_eq!(ctx.traces().len(), 5);

    // Advance epoch
    ctx.advance_epoch(epoch(2));

    // Policy bundle
    let bundle = ctx.policy_bundle();
    assert!(!bundle.version.is_empty());
    assert!(!bundle.lanes.is_empty());

    // Serde the entire context
    let json = serde_json::to_string(&ctx).unwrap();
    assert!(!json.is_empty());
}

// ===========================================================================
// 18. CVaR — VaR computation and trigger_epoch
// ===========================================================================

#[test]
fn cvar_var_returns_none_insufficient_data() {
    let config = CvarConfig {
        min_observations: 10,
        ..CvarConfig::default()
    };
    let cvar = CvarGuardrail::new(config);
    assert!(cvar.var().is_none());
}

#[test]
fn cvar_var_returns_quantile_value() {
    let config = CvarConfig {
        alpha_millionths: 800_000, // 80th percentile
        min_observations: 5,
        ..CvarConfig::default()
    };
    let mut cvar = CvarGuardrail::new(config);
    for i in 0..10 {
        cvar.observe(i * 100_000);
    }
    let var = cvar.var().unwrap();
    // VaR at 80%: index = floor(10 * 0.8) = 8 → obs[8] = 800_000
    assert_eq!(var, 800_000);
}

#[test]
fn cvar_trigger_epoch_initially_none() {
    let cvar = CvarGuardrail::new(CvarConfig::default());
    assert!(cvar.trigger_epoch().is_none());
}

#[test]
fn cvar_trigger_epoch_set_on_exceeded() {
    let config = CvarConfig {
        alpha_millionths: 500_000,
        max_cvar_millionths: 1,
        min_observations: 3,
    };
    let mut cvar = CvarGuardrail::new(config);
    for _ in 0..5 {
        cvar.observe(1_000_000);
    }
    cvar.check(epoch(42));
    assert_eq!(cvar.trigger_epoch(), Some(epoch(42)));
}

#[test]
fn cvar_cvar_value_increases_with_tail() {
    let config = CvarConfig {
        alpha_millionths: 900_000,
        max_cvar_millionths: 100_000_000,
        min_observations: 5,
    };
    let mut cvar_low = CvarGuardrail::new(config.clone());
    let mut cvar_high = CvarGuardrail::new(config);

    for _ in 0..10 {
        cvar_low.observe(100_000);
        cvar_high.observe(100_000);
    }
    // Add heavy tail to high
    for _ in 0..5 {
        cvar_high.observe(10_000_000);
    }
    let low_val = cvar_low.cvar().unwrap();
    let high_val = cvar_high.cvar().unwrap();
    assert!(high_val > low_val, "heavy tail should increase CVaR");
}

// ===========================================================================
// 19. CvarCheckResult — serde round-trip
// ===========================================================================

#[test]
fn cvar_check_result_insufficient_serde() {
    let result = CvarCheckResult::InsufficientData {
        observations: 3,
        required: 10,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn cvar_check_result_within_bounds_serde() {
    let result = CvarCheckResult::WithinBounds {
        cvar_millionths: 200_000,
        threshold_millionths: 500_000,
        headroom_millionths: 300_000,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

#[test]
fn cvar_check_result_exceeded_serde() {
    let result = CvarCheckResult::Exceeded {
        cvar_millionths: 600_000,
        threshold_millionths: 500_000,
        epoch: epoch(7),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CvarCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 20. Conformal — coverage, e-value, reset
// ===========================================================================

#[test]
fn conformal_coverage_millionths_correct() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    cal.record(epoch(1), true);
    cal.record(epoch(2), false);
    // 1 out of 2 covered = 500_000 millionths
    assert_eq!(cal.coverage_millionths(), 500_000);
}

#[test]
fn conformal_e_value_grows_on_misses() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        max_consecutive_violations: 10,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    let initial = cal.e_value_millionths();
    // Record a miss
    cal.record(epoch(1), false);
    let after_miss = cal.e_value_millionths();
    assert!(
        after_miss > initial,
        "e-value should grow on misses: {} vs {}",
        after_miss,
        initial
    );
}

#[test]
fn conformal_e_value_stable_on_hits() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    cal.record(epoch(1), true);
    // e-value should stay at 1.0 (1_000_000) when all covered
    assert_eq!(cal.e_value_millionths(), 1_000_000);
}

#[test]
fn conformal_reset_clears_all() {
    let config = ConformalConfig {
        min_calibration_observations: 2,
        max_consecutive_violations: 2,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    for i in 0..5 {
        cal.record(epoch(i + 1), false);
    }
    assert!(cal.violation_flagged());
    assert!(cal.total_predictions() > 0);
    cal.reset();
    assert!(!cal.violation_flagged());
    assert_eq!(cal.total_predictions(), 0);
    assert_eq!(cal.covered_predictions(), 0);
    assert!(cal.ledger().is_empty());
}

#[test]
fn conformal_is_calibrated_respects_min_observations() {
    let config = ConformalConfig {
        min_calibration_observations: 100,
        ..ConformalConfig::default()
    };
    let mut cal = ConformalCalibrator::new(config);
    // Record all misses but below min threshold
    for i in 0..10 {
        cal.record(epoch(i + 1), false);
    }
    // Should still be "calibrated" due to insufficient data
    assert!(cal.is_calibrated());
}

// ===========================================================================
// 21. Drift — last_kl, drift_epoch
// ===========================================================================

#[test]
fn drift_last_kl_initially_none() {
    let drift = DriftDetector::new(DriftConfig::default());
    assert!(drift.last_kl_millionths().is_none());
}

#[test]
fn drift_last_kl_populated_after_check() {
    let config = DriftConfig {
        reference_window: 10,
        test_window: 5,
        min_samples: 5,
        ..DriftConfig::default()
    };
    let mut drift = DriftDetector::new(config);
    for _ in 0..20 {
        drift.observe(500_000);
    }
    drift.check(epoch(1));
    assert!(drift.last_kl_millionths().is_some());
}

#[test]
fn drift_epoch_initially_none() {
    let drift = DriftDetector::new(DriftConfig::default());
    assert!(drift.drift_epoch().is_none());
}

#[test]
fn drift_epoch_set_when_detected() {
    let config = DriftConfig {
        kl_threshold_millionths: 1, // very low threshold
        reference_window: 10,
        test_window: 5,
        min_samples: 5,
    };
    let mut drift = DriftDetector::new(config);
    // Reference: low values
    for _ in 0..12 {
        drift.observe(100_000);
    }
    // Test: high values
    for _ in 0..8 {
        drift.observe(900_000);
    }
    drift.check(epoch(99));
    if drift.is_drift_detected() {
        assert_eq!(drift.drift_epoch(), Some(epoch(99)));
    }
}

// ===========================================================================
// 22. DriftCheckResult — serde round-trip
// ===========================================================================

#[test]
fn drift_check_result_all_variants_serde() {
    let variants: Vec<DriftCheckResult> = vec![
        DriftCheckResult::InsufficientData {
            observations: 5,
            required: 30,
        },
        DriftCheckResult::NoDrift {
            kl_millionths: 50_000,
            threshold_millionths: 100_000,
        },
        DriftCheckResult::DriftDetected {
            kl_millionths: 200_000,
            threshold_millionths: 100_000,
            epoch: epoch(3),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: DriftCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

// ===========================================================================
// 23. BudgetController — memory tracking, remaining budget
// ===========================================================================

#[test]
fn budget_memory_tracking() {
    let config = BudgetConfig {
        memory_budget_bytes: 1_000_000,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_memory(500_000);
    assert_eq!(budget.memory_consumed_bytes(), 500_000);
}

#[test]
fn budget_memory_exhaustion_triggers_fallback() {
    let config = BudgetConfig {
        memory_budget_bytes: 1_000,
        deterministic_fallback_on_exhaust: true,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    let status = budget.record_memory(2_000); // over budget
    assert!(matches!(status, BudgetStatus::Exhausted { .. }));
    assert!(budget.is_fallback_active());
}

#[test]
fn budget_remaining_decreases_with_usage() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    let initial = budget.budget_remaining_millionths();
    budget.record_compute(50_000);
    let after = budget.budget_remaining_millionths();
    assert!(
        after < initial,
        "remaining should decrease: {} vs {}",
        after,
        initial
    );
}

#[test]
fn budget_remaining_zero_when_exhausted() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: true,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_compute(200);
    assert_eq!(budget.budget_remaining_millionths(), 0);
}

// ===========================================================================
// 24. BudgetStatus — serde round-trip
// ===========================================================================

#[test]
fn budget_status_all_variants_serde() {
    let variants: Vec<BudgetStatus> = vec![
        BudgetStatus::Normal {
            compute_fraction_millionths: 200_000,
            memory_fraction_millionths: 100_000,
        },
        BudgetStatus::Warning {
            compute_fraction_millionths: 850_000,
            memory_fraction_millionths: 300_000,
        },
        BudgetStatus::Exhausted {
            compute_fraction_millionths: 1_200_000,
            memory_fraction_millionths: 500_000,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BudgetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

// ===========================================================================
// 25. BudgetEvent / BudgetEventKind — serde and display
// ===========================================================================

#[test]
fn budget_event_kind_display() {
    use frankenengine_engine::runtime_decision_theory::BudgetEventKind;
    assert_eq!(BudgetEventKind::Warning.to_string(), "warning");
    assert_eq!(BudgetEventKind::Exhausted.to_string(), "exhausted");
    assert_eq!(BudgetEventKind::EpochReset.to_string(), "epoch_reset");
}

#[test]
fn budget_event_serde_round_trip() {
    use frankenengine_engine::runtime_decision_theory::{BudgetEvent, BudgetEventKind};
    let event = BudgetEvent {
        epoch: epoch(3),
        kind: BudgetEventKind::Exhausted,
        compute_consumed_us: 50_000,
        memory_consumed_bytes: 1_024,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: BudgetEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn budget_epoch_reset_emits_event() {
    let config = BudgetConfig {
        compute_budget_us: 100_000,
        deterministic_fallback_on_exhaust: true,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_compute(50_000);
    budget.reset_epoch(epoch(2));
    let events = budget.events();
    assert!(!events.is_empty());
    // Last event should be EpochReset
    use frankenengine_engine::runtime_decision_theory::BudgetEventKind;
    assert!(matches!(
        events.last().unwrap().kind,
        BudgetEventKind::EpochReset
    ));
}

// ===========================================================================
// 26. DecisionContext — guardrail-triggered fallbacks
// ===========================================================================

#[test]
fn decision_context_cvar_triggered_produces_fallback() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            alpha_millionths: 500_000,
            max_cvar_millionths: 1,
            min_observations: 3,
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    // Feed huge losses to trigger CVaR
    for _ in 0..5 {
        ctx.observe_loss(10_000_000, epoch(1));
    }
    let outcome = ctx.decide(&default_state());
    assert_eq!(outcome.demotion, Some(DemotionReason::CvarExceeded));
    assert!(matches!(outcome.action, LaneAction::FallbackSafe));
}

#[test]
fn decision_context_drift_triggered_produces_fallback() {
    let config = DecisionContextConfig {
        drift_config: DriftConfig {
            kl_threshold_millionths: 1,
            reference_window: 10,
            test_window: 5,
            min_samples: 5,
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    // Reference: low values
    for _ in 0..12 {
        ctx.observe_loss(100_000, epoch(1));
    }
    // Test: high values (causes drift)
    for _ in 0..8 {
        ctx.observe_loss(9_000_000, epoch(1));
    }
    let outcome = ctx.decide(&default_state());
    if ctx.drift().is_drift_detected() {
        assert_eq!(outcome.demotion, Some(DemotionReason::DriftDetected));
        assert!(matches!(outcome.action, LaneAction::FallbackSafe));
    }
}

#[test]
fn decision_context_conformal_violation_produces_fallback() {
    let config = DecisionContextConfig {
        conformal_config: ConformalConfig {
            min_calibration_observations: 3,
            max_consecutive_violations: 3,
            alpha_millionths: 100_000,
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    // Record all misses to trigger conformal violation
    for i in 0..10 {
        ctx.observe_calibration(epoch(i + 1), false);
    }
    let outcome = ctx.decide(&default_state());
    assert_eq!(outcome.demotion, Some(DemotionReason::CoverageViolation));
    assert!(matches!(outcome.action, LaneAction::FallbackSafe));
}

// ===========================================================================
// 27. DecisionContext — accessor methods
// ===========================================================================

#[test]
fn decision_context_accessors_return_live_state() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            min_observations: 3,
            ..CvarConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));

    // Feed some data
    ctx.observe_loss(100_000, epoch(1));
    ctx.observe_calibration(epoch(1), true);
    ctx.record_compute(1_000);

    // Accessors should reflect state
    assert_eq!(ctx.cvar().observation_count(), 1);
    assert_eq!(ctx.calibrator().total_predictions(), 1);
    assert_eq!(ctx.calibrator().covered_predictions(), 1);
    assert!(ctx.drift().observation_count() > 0);
    assert_eq!(ctx.budget().compute_consumed_us(), 1_000);
}

// ===========================================================================
// 28. DecisionContext — fallback_events recorded
// ===========================================================================

#[test]
fn decision_context_fallback_events_populated() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..BudgetConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    ctx.record_compute(200);
    ctx.decide(&default_state());
    let events = ctx.fallback_events();
    assert!(!events.is_empty(), "fallback events should be recorded");
    assert_eq!(events[0].trigger, DemotionReason::BudgetExhausted);
}

#[test]
fn decision_context_fallback_event_metrics_populated() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..BudgetConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    ctx.record_compute(200);
    ctx.decide(&default_state());
    let event = &ctx.fallback_events()[0];
    // Metrics should be populated
    assert_eq!(event.metrics.budget_remaining_millionths, 0);
    assert!(event.metrics.coverage_millionths > 0);
    assert!(event.metrics.e_value_millionths > 0);
}

// ===========================================================================
// 29. DecisionTrace — property checks
// ===========================================================================

#[test]
fn decision_trace_guardrail_active_false_when_normal() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    ctx.decide(&default_state());
    let trace = &ctx.traces()[0];
    assert!(!trace.guardrail_active);
    assert!(!trace.reason.is_empty());
}

#[test]
fn decision_trace_guardrail_active_true_when_triggered() {
    let config = DecisionContextConfig {
        budget_config: BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..BudgetConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    ctx.record_compute(200);
    ctx.decide(&default_state());
    let trace = &ctx.traces()[0];
    assert!(trace.guardrail_active);
}

#[test]
fn decision_trace_sequence_increases() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    ctx.decide(&default_state());
    ctx.decide(&default_state());
    ctx.decide(&default_state());
    let traces = ctx.traces();
    assert_eq!(traces[0].sequence, 1);
    assert_eq!(traces[1].sequence, 2);
    assert_eq!(traces[2].sequence, 3);
}

#[test]
fn decision_trace_epoch_matches_context() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(42));
    ctx.decide(&default_state());
    assert_eq!(ctx.traces()[0].epoch, epoch(42));
}

// ===========================================================================
// 30. LaneId — canonical normalization
// ===========================================================================

#[test]
fn lane_id_legacy_quickjs_normalizes() {
    let legacy_json = "\"quickjs_inspired_native\"";
    let lane: LaneId = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(lane, LaneId::deterministic_profile());
}

#[test]
fn lane_id_legacy_v8_normalizes() {
    let legacy_json = "\"V8\"";
    let lane: LaneId = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(lane, LaneId::throughput_profile());
}

#[test]
fn lane_id_unknown_label_preserved() {
    let custom_json = "\"my_custom_lane\"";
    let lane: LaneId = serde_json::from_str(custom_json).unwrap();
    assert_eq!(lane.to_string(), "my_custom_lane");
}

// ===========================================================================
// 31. Edge cases — empty and degenerate configs
// ===========================================================================

#[test]
fn decision_context_single_lane_always_routes_to_it() {
    let mut config = default_ctx_config();
    config.lanes = vec![LaneId("only_lane".into())];
    let mut ctx = DecisionContext::new(config, epoch(1));
    let outcome = ctx.decide(&default_state());
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(lane.to_string(), "only_lane");
    }
}

#[test]
fn decision_context_zero_risk_belief() {
    let mut state = default_state();
    state.risk_belief_millionths = BTreeMap::new();
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let outcome = ctx.decide(&state);
    // Should still route successfully
    assert!(
        matches!(outcome.action, LaneAction::RouteTo(_)),
        "zero risk should still route: {:?}",
        outcome.action
    );
}

#[test]
fn decision_context_degraded_regime_routes_to_safe_lane() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = DecisionState {
        regime: RegimeLabel::Degraded,
        ..default_state()
    };
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        // Degraded/Recovery should route to first (safe) lane
        assert_eq!(
            *lane,
            ctx.policy_bundle().lanes[0],
            "degraded should route to safe lane"
        );
    }
}

#[test]
fn decision_context_recovery_regime_routes_to_safe_lane() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = DecisionState {
        regime: RegimeLabel::Recovery,
        ..default_state()
    };
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        assert_eq!(
            *lane,
            ctx.policy_bundle().lanes[0],
            "recovery should route to safe lane"
        );
    }
}

#[test]
fn decision_context_elevated_regime_routes_to_perf_lane() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    let state = DecisionState {
        regime: RegimeLabel::Elevated,
        ..default_state()
    };
    let outcome = ctx.decide(&state);
    if let LaneAction::RouteTo(lane) = &outcome.action {
        // Elevated should still route to performance (second) lane
        assert_eq!(
            *lane,
            ctx.policy_bundle().lanes[1],
            "elevated should route to perf lane"
        );
    }
}

// ===========================================================================
// 32. DecisionContext — serde round-trip
// ===========================================================================

#[test]
fn decision_context_serde_round_trip() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    ctx.observe_loss(100_000, epoch(1));
    ctx.observe_calibration(epoch(1), true);
    ctx.decide(&default_state());
    let json = serde_json::to_string(&ctx).unwrap();
    let back: DecisionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back.traces().len(), ctx.traces().len());
    assert_eq!(
        back.cvar().observation_count(),
        ctx.cvar().observation_count()
    );
}

// ===========================================================================
// 33. Budget — no-fallback mode
// ===========================================================================

#[test]
fn budget_no_fallback_mode() {
    let config = BudgetConfig {
        compute_budget_us: 100,
        deterministic_fallback_on_exhaust: false,
        ..BudgetConfig::default()
    };
    let mut budget = BudgetController::new(config, epoch(1));
    budget.record_compute(200);
    // Budget exhausted but fallback not activated
    assert!(!budget.is_fallback_active());
}

// ===========================================================================
// 34. DemotionReason — serde round-trip
// ===========================================================================

#[test]
fn demotion_reason_all_variants_serde() {
    let reasons = [
        DemotionReason::CvarExceeded,
        DemotionReason::DriftDetected,
        DemotionReason::BudgetExhausted,
        DemotionReason::GuardrailTriggered,
        DemotionReason::CoverageViolation,
        DemotionReason::OperatorOverride,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: DemotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *r);
    }
}

// ===========================================================================
// 35. FallbackMetrics — serde
// ===========================================================================

#[test]
fn fallback_metrics_serde_round_trip() {
    let metrics = FallbackMetrics {
        cvar_millionths: None,
        drift_kl_millionths: None,
        budget_remaining_millionths: 500_000,
        coverage_millionths: 900_000,
        e_value_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let back: FallbackMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, metrics);
}

// ===========================================================================
// 36. Guardrail priority order
// ===========================================================================

#[test]
fn budget_exhaustion_takes_priority_over_cvar() {
    let config = DecisionContextConfig {
        cvar_config: CvarConfig {
            alpha_millionths: 500_000,
            max_cvar_millionths: 1,
            min_observations: 3,
        },
        budget_config: BudgetConfig {
            compute_budget_us: 100,
            deterministic_fallback_on_exhaust: true,
            ..BudgetConfig::default()
        },
        ..default_ctx_config()
    };
    let mut ctx = DecisionContext::new(config, epoch(1));
    // Trigger both CVaR and budget
    for _ in 0..5 {
        ctx.observe_loss(10_000_000, epoch(1));
    }
    ctx.record_compute(200);
    let outcome = ctx.decide(&default_state());
    // Budget has highest priority
    assert_eq!(outcome.demotion, Some(DemotionReason::BudgetExhausted));
    assert!(matches!(outcome.action, LaneAction::SuspendAdaptive));
}

// ===========================================================================
// 37. Advance epoch resets sequence
// ===========================================================================

#[test]
fn advance_epoch_resets_sequence_counter() {
    let mut ctx = DecisionContext::new(default_ctx_config(), epoch(1));
    ctx.decide(&default_state());
    ctx.decide(&default_state());
    ctx.advance_epoch(epoch(2));
    let state2 = DecisionState {
        epoch: epoch(2),
        ..default_state()
    };
    ctx.decide(&state2);
    let traces = ctx.traces();
    // After advance, sequence should restart from 1
    assert_eq!(traces.last().unwrap().sequence, 1);
}
