#![forbid(unsafe_code)]
//! Integration tests for the `runtime_decision_theory` module.
//!
//! Exercises CVaR guardrails, conformal calibration, drift detection,
//! budget control, decision context orchestration, lane selection, and
//! serde round-trips from outside the crate boundary.

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
