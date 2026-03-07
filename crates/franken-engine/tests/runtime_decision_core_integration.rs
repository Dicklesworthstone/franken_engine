#![forbid(unsafe_code)]
//! Integration tests for the `runtime_decision_core` module.
//!
//! Exercises LaneId, RiskDimension, RoutingAction, LaneRoutingState,
//! RegimeEstimate, AsymmetricLossPolicy, CVaRConstraint, ConformalCalibrationLayer,
//! DemotionPolicy, AdaptiveBudget, RuntimeDecisionCore.decide(),
//! PolicyBundle, DecisionTraceEntry, and full lifecycle.

use std::collections::BTreeMap;

use frankenengine_engine::runtime_decision_core::{
    AdaptiveBudget, AsymmetricLossPolicy, CVaRConstraint, CalibrationLedgerEntry,
    ConformalCalibrationLayer, DECISION_CORE_SCHEMA_VERSION, DecisionCoreError, DecisionTraceEntry,
    DemotionPolicy, FallbackReason, FallbackTriggerEvent, LaneId, LaneRoutingState, PolicyBundle,
    RegimeEstimate, RiskDimension, RoutingAction, RoutingDecisionInput, RuntimeDecisionCore,
    default_routing_loss_policy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn low_risk_posteriors() -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    m.insert("compatibility".into(), 100_000); // 10%
    m.insert("latency".into(), 100_000);
    m.insert("memory".into(), 100_000);
    m.insert("incident_severity".into(), 100_000);
    m
}

fn normal_input(ts: u64) -> RoutingDecisionInput {
    RoutingDecisionInput {
        observed_latency_us: 500,
        risk_posteriors: low_risk_posteriors(),
        regime: RegimeEstimate::Normal,
        confidence_millionths: 800_000,
        is_adverse: false,
        nonconformity_score_millionths: 300_000,
        calibration_covered: true,
        compute_ms: 2,
        memory_mb: 10,
        epoch: epoch(1),
        timestamp_ns: ts,
    }
}

fn standard_lanes() -> Vec<LaneId> {
    vec![
        LaneId::quickjs_native(),
        LaneId::v8_native(),
        LaneId::safe_mode(),
    ]
}

// ===========================================================================
// 1. LaneId
// ===========================================================================

#[test]
fn lane_id_display() {
    assert_eq!(
        LaneId::quickjs_native().to_string(),
        "baseline_deterministic_profile"
    );
    assert_eq!(
        LaneId::v8_native().to_string(),
        "baseline_throughput_profile"
    );
    assert_eq!(LaneId::safe_mode().to_string(), "safe_mode");
}

#[test]
fn lane_id_serde_round_trip() {
    let lanes = [
        LaneId::quickjs_native(),
        LaneId::v8_native(),
        LaneId::safe_mode(),
    ];
    for lane in &lanes {
        let json = serde_json::to_string(lane).unwrap();
        let back: LaneId = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, lane);
    }
}

#[test]
fn lane_id_custom() {
    let lane = LaneId("custom-lane".into());
    assert_eq!(lane.to_string(), "custom-lane");
}

// ===========================================================================
// 2. RiskDimension
// ===========================================================================

#[test]
fn risk_dimension_all() {
    assert_eq!(RiskDimension::ALL.len(), 4);
    assert_eq!(RiskDimension::ALL[0], RiskDimension::Compatibility);
    assert_eq!(RiskDimension::ALL[3], RiskDimension::IncidentSeverity);
}

#[test]
fn risk_dimension_display() {
    assert_eq!(RiskDimension::Compatibility.to_string(), "compatibility");
    assert_eq!(RiskDimension::Latency.to_string(), "latency");
    assert_eq!(RiskDimension::Memory.to_string(), "memory");
    assert_eq!(
        RiskDimension::IncidentSeverity.to_string(),
        "incident_severity"
    );
}

#[test]
fn risk_dimension_serde() {
    for dim in RiskDimension::ALL {
        let json = serde_json::to_string(&dim).unwrap();
        let back: RiskDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
    }
}

// ===========================================================================
// 3. RoutingAction
// ===========================================================================

#[test]
fn routing_action_display() {
    assert_eq!(
        RoutingAction::SelectLane(LaneId::v8_native()).to_string(),
        "select:baseline_throughput_profile"
    );
    assert_eq!(
        RoutingAction::FallbackSafeMode.to_string(),
        "fallback:safe_mode"
    );
    assert_eq!(
        RoutingAction::EscalateToOperator.to_string(),
        "escalate:operator"
    );
    assert_eq!(RoutingAction::Hold.to_string(), "hold");
}

#[test]
fn routing_action_serde() {
    let actions = [
        RoutingAction::SelectLane(LaneId::quickjs_native()),
        RoutingAction::FallbackSafeMode,
        RoutingAction::EscalateToOperator,
        RoutingAction::Hold,
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let back: RoutingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, a);
    }
}

// ===========================================================================
// 4. RegimeEstimate
// ===========================================================================

#[test]
fn regime_estimate_all_variants() {
    let regimes = [
        RegimeEstimate::Normal,
        RegimeEstimate::Elevated,
        RegimeEstimate::Attack,
        RegimeEstimate::Degraded,
        RegimeEstimate::Recovery,
    ];
    for r in &regimes {
        let json = serde_json::to_string(r).unwrap();
        let back: RegimeEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
    }
}

#[test]
fn regime_estimate_display() {
    assert_eq!(RegimeEstimate::Normal.to_string(), "normal");
    assert_eq!(RegimeEstimate::Attack.to_string(), "attack");
    assert_eq!(RegimeEstimate::Degraded.to_string(), "degraded");
}

// ===========================================================================
// 5. LaneRoutingState
// ===========================================================================

#[test]
fn lane_routing_state_initial() {
    let state = LaneRoutingState::initial(LaneId::quickjs_native(), epoch(1));
    assert_eq!(state.active_lane, LaneId::quickjs_native());
    assert_eq!(state.confidence_millionths, 500_000);
    assert_eq!(state.regime, RegimeEstimate::Normal);
    assert_eq!(state.decision_count, 0);
    assert!(!state.safe_mode_active);
    assert!(state.recent_latencies_us.is_empty());

    // All 4 risk dimensions initialized to 10%
    assert_eq!(state.risk_posteriors.len(), 4);
    for val in state.risk_posteriors.values() {
        assert_eq!(*val, 100_000);
    }
}

#[test]
fn lane_routing_state_serde() {
    let state = LaneRoutingState::initial(LaneId::v8_native(), epoch(5));
    let json = serde_json::to_string(&state).unwrap();
    let back: LaneRoutingState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, state);
}

// ===========================================================================
// 6. AsymmetricLossPolicy
// ===========================================================================

#[test]
fn loss_policy_new_is_empty() {
    let policy = AsymmetricLossPolicy::new("test-policy");
    assert_eq!(policy.policy_id, "test-policy");
    assert!(policy.entries.is_empty());
    assert!(policy.regime_multipliers.is_empty());
}

#[test]
fn loss_policy_expected_loss_basic() {
    let mut policy = AsymmetricLossPolicy::new("test");
    policy.add_entry("action-a", RiskDimension::Compatibility, 500_000);
    policy.add_entry("action-a", RiskDimension::Latency, 200_000);

    let mut posteriors = BTreeMap::new();
    posteriors.insert("compatibility".into(), 500_000); // 50%
    posteriors.insert("latency".into(), 200_000); // 20%

    let loss = policy.expected_loss("action-a", &posteriors, RegimeEstimate::Normal);
    // loss = (500k * 500k / 1M * 1M/1M) + (200k * 200k / 1M * 1M/1M)
    // = 250k * 1 + 40k * 1 = 290k
    assert_eq!(loss, 290_000);
}

#[test]
fn loss_policy_regime_multiplier() {
    let mut policy = AsymmetricLossPolicy::new("test");
    policy.add_entry("action-a", RiskDimension::Compatibility, 500_000);
    policy.set_regime_multiplier(RegimeEstimate::Attack, 3_000_000); // 3x

    let mut posteriors = BTreeMap::new();
    posteriors.insert("compatibility".into(), 500_000);

    let loss_normal = policy.expected_loss("action-a", &posteriors, RegimeEstimate::Normal);
    let loss_attack = policy.expected_loss("action-a", &posteriors, RegimeEstimate::Attack);
    // Attack should amplify loss by 3x
    assert_eq!(loss_attack, loss_normal * 3);
}

#[test]
fn loss_policy_select_min_loss_action() {
    let policy = default_routing_loss_policy();
    let posteriors = low_risk_posteriors();
    let candidates = vec![
        "select:baseline_deterministic_profile".into(),
        "select:baseline_throughput_profile".into(),
        "fallback:safe_mode".into(),
        "hold".into(),
    ];

    let result = policy
        .select_min_loss_action(&candidates, &posteriors, RegimeEstimate::Normal)
        .unwrap();
    // Should pick the lowest-loss action
    assert!(!result.0.is_empty());
    assert!(result.1 >= 0);
}

#[test]
fn loss_policy_select_min_loss_empty_candidates() {
    let policy = default_routing_loss_policy();
    let posteriors = low_risk_posteriors();
    let result = policy.select_min_loss_action(&[], &posteriors, RegimeEstimate::Normal);
    assert!(result.is_none());
}

#[test]
fn default_routing_loss_policy_has_entries() {
    let policy = default_routing_loss_policy();
    assert!(!policy.entries.is_empty());
    assert!(!policy.regime_multipliers.is_empty());
}

#[test]
fn loss_policy_serde() {
    let policy = default_routing_loss_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: AsymmetricLossPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 7. CVaRConstraint
// ===========================================================================

#[test]
fn cvar_empty_is_satisfied() {
    let cvar = CVaRConstraint::default_p99();
    let result = cvar.evaluate();
    assert!(result.satisfied);
    assert_eq!(result.cvar_us, 0);
    assert_eq!(result.sample_count, 0);
}

#[test]
fn cvar_low_latencies_satisfied() {
    let mut cvar = CVaRConstraint::new("test", 990_000, 10_000);
    for i in 0..100 {
        cvar.observe(100 + i);
    }
    let result = cvar.evaluate();
    assert!(result.satisfied);
    assert!(result.cvar_us < 10_000);
    assert_eq!(result.sample_count, 100);
}

#[test]
fn cvar_high_tail_violated() {
    let mut cvar = CVaRConstraint::new("test", 990_000, 1_000);
    // 99 low samples and 1 extremely high
    for _ in 0..99 {
        cvar.observe(100);
    }
    cvar.observe(100_000); // massive tail
    let result = cvar.evaluate();
    // CVaR at p99 should be ≥ 100_000 and thus violated
    assert!(!result.satisfied);
}

#[test]
fn cvar_is_violated_helper() {
    let mut cvar = CVaRConstraint::new("test", 990_000, 100);
    for _ in 0..100 {
        cvar.observe(200);
    }
    assert!(cvar.is_violated()); // all 200 > max 100
}

#[test]
fn cvar_serde() {
    let mut cvar = CVaRConstraint::default_p99();
    cvar.observe(500);
    cvar.observe(1000);
    let json = serde_json::to_string(&cvar).unwrap();
    let back: CVaRConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cvar);
}

// ===========================================================================
// 8. ConformalCalibrationLayer
// ===========================================================================

#[test]
fn calibration_initial_coverage() {
    let layer = ConformalCalibrationLayer::new("cal-1", 950_000);
    assert_eq!(layer.empirical_coverage_millionths(), 1_000_000); // 100% when empty
    assert!(!layer.is_undercovering());
}

#[test]
fn calibration_perfect_coverage() {
    let mut layer = ConformalCalibrationLayer::new("cal-1", 950_000);
    for _ in 0..100 {
        layer.observe(300_000, true);
    }
    assert_eq!(layer.empirical_coverage_millionths(), 1_000_000);
    assert!(!layer.is_undercovering());
}

#[test]
fn calibration_low_coverage_detected() {
    let mut layer = ConformalCalibrationLayer::new("cal-1", 950_000);
    // 80% coverage
    for _ in 0..80 {
        layer.observe(300_000, true);
    }
    for _ in 0..20 {
        layer.observe(900_000, false);
    }
    assert_eq!(layer.empirical_coverage_millionths(), 800_000);
    assert!(layer.is_undercovering());
}

#[test]
fn calibration_e_value_tracks() {
    let mut layer = ConformalCalibrationLayer::new("cal-1", 950_000);
    let initial = layer.e_value_millionths;
    layer.observe(200_000, true);
    // After a covered observation, e_value should change
    assert_ne!(layer.e_value_millionths, initial);
}

#[test]
fn calibration_serde() {
    let mut layer = ConformalCalibrationLayer::new("cal-1", 950_000);
    layer.observe(300_000, true);
    let json = serde_json::to_string(&layer).unwrap();
    let back: ConformalCalibrationLayer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, layer);
}

// ===========================================================================
// 9. DemotionPolicy
// ===========================================================================

#[test]
fn demotion_attack_regime() {
    let mut policy = DemotionPolicy::new("dp-1");
    let result = policy.evaluate(RegimeEstimate::Attack, 800_000, false);
    assert_eq!(result, Some(LaneId::safe_mode()));
}

#[test]
fn demotion_degraded_regime() {
    let mut policy = DemotionPolicy::new("dp-1");
    let result = policy.evaluate(RegimeEstimate::Degraded, 800_000, false);
    assert_eq!(result, Some(LaneId::quickjs_native()));
}

#[test]
fn demotion_normal_regime_no_demotion() {
    let mut policy = DemotionPolicy::new("dp-1");
    let result = policy.evaluate(RegimeEstimate::Normal, 800_000, false);
    assert!(result.is_none());
}

#[test]
fn demotion_low_confidence() {
    let mut policy = DemotionPolicy::new("dp-1");
    let result = policy.evaluate(RegimeEstimate::Normal, 100_000, false);
    assert_eq!(result, Some(LaneId::safe_mode()));
}

#[test]
fn demotion_consecutive_adverse() {
    let mut policy = DemotionPolicy::new("dp-1");
    // Default threshold is 3
    assert!(
        policy
            .evaluate(RegimeEstimate::Normal, 800_000, true)
            .is_none()
    );
    assert!(
        policy
            .evaluate(RegimeEstimate::Normal, 800_000, true)
            .is_none()
    );
    let result = policy.evaluate(RegimeEstimate::Normal, 800_000, true);
    assert_eq!(result, Some(LaneId::quickjs_native()));
}

#[test]
fn demotion_reset_clears_counter() {
    let mut policy = DemotionPolicy::new("dp-1");
    policy.evaluate(RegimeEstimate::Normal, 800_000, true);
    policy.evaluate(RegimeEstimate::Normal, 800_000, true);
    policy.reset();
    // After reset, counter should be at 0, so 3 more needed
    assert!(
        policy
            .evaluate(RegimeEstimate::Normal, 800_000, true)
            .is_none()
    );
}

#[test]
fn demotion_non_adverse_resets_counter() {
    let mut policy = DemotionPolicy::new("dp-1");
    policy.evaluate(RegimeEstimate::Normal, 800_000, true);
    policy.evaluate(RegimeEstimate::Normal, 800_000, true);
    // Non-adverse resets counter
    policy.evaluate(RegimeEstimate::Normal, 800_000, false);
    assert!(
        policy
            .evaluate(RegimeEstimate::Normal, 800_000, true)
            .is_none()
    );
}

#[test]
fn demotion_serde() {
    let policy = DemotionPolicy::new("dp-1");
    let json = serde_json::to_string(&policy).unwrap();
    let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 10. AdaptiveBudget
// ===========================================================================

#[test]
fn budget_initial_not_exhausted() {
    let budget = AdaptiveBudget::new("b-1", epoch(1));
    assert!(!budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 50); // DEFAULT_COMPUTE_BUDGET_MS
}

#[test]
fn budget_record_consumption() {
    let mut budget = AdaptiveBudget::new("b-1", epoch(1));
    budget.record(10, 20);
    assert_eq!(budget.compute_consumed_ms, 10);
    assert_eq!(budget.peak_memory_mb, 20);
    assert!(!budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 40);
}

#[test]
fn budget_exhausted_by_compute() {
    let mut budget = AdaptiveBudget::new("b-1", epoch(1));
    budget.record(50, 10);
    assert!(budget.is_exhausted());
}

#[test]
fn budget_exhausted_by_memory() {
    let mut budget = AdaptiveBudget::new("b-1", epoch(1));
    budget.record(5, 128);
    assert!(budget.is_exhausted());
}

#[test]
fn budget_reset() {
    let mut budget = AdaptiveBudget::new("b-1", epoch(1));
    budget.record(50, 128);
    assert!(budget.is_exhausted());

    budget.reset(epoch(2));
    assert!(!budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 50);
    assert_eq!(budget.reset_epoch, epoch(2));
}

#[test]
fn budget_serde() {
    let budget = AdaptiveBudget::new("b-1", epoch(1));
    let json = serde_json::to_string(&budget).unwrap();
    let back: AdaptiveBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(back, budget);
}

// ===========================================================================
// 11. DecisionCoreError
// ===========================================================================

#[test]
fn decision_core_error_no_lanes() {
    let result = RuntimeDecisionCore::new("core-1", vec![], LaneId::safe_mode(), epoch(1));
    assert!(result.is_err());
    match result.unwrap_err() {
        DecisionCoreError::NoLanesConfigured => {}
        other => panic!("expected NoLanesConfigured, got {other:?}"),
    }
}

#[test]
fn decision_core_error_epoch_regression() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(5),
    )
    .unwrap();

    let mut input = normal_input(1);
    input.epoch = epoch(3); // regression

    let result = core.decide(&input);
    assert!(result.is_err());
    match result.unwrap_err() {
        DecisionCoreError::EpochRegression { current, received } => {
            assert_eq!(current, 5);
            assert_eq!(received, 3);
        }
        other => panic!("expected EpochRegression, got {other:?}"),
    }
}

// ===========================================================================
// 12. RuntimeDecisionCore — construction
// ===========================================================================

#[test]
fn core_construction() {
    let core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    assert_eq!(core.core_id, "core-1");
    assert_eq!(core.state.active_lane, LaneId::quickjs_native());
    assert_eq!(core.state.epoch, epoch(1));
    assert_eq!(core.available_lanes.len(), 3);
    assert_eq!(core.decision_seq, 0);
}

#[test]
fn schema_version() {
    assert!(DECISION_CORE_SCHEMA_VERSION.contains("runtime-decision-core"));
}

// ===========================================================================
// 13. RuntimeDecisionCore — decide (normal path)
// ===========================================================================

#[test]
fn decide_normal_returns_action() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    let output = core.decide(&normal_input(1_000_000)).unwrap();
    assert!(!output.fallback_triggered);
    assert!(output.fallback_reason.is_none());
    assert_eq!(output.decision_seq, 0);
}

#[test]
fn decide_increments_decision_count() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    core.decide(&normal_input(1)).unwrap();
    core.decide(&normal_input(2)).unwrap();

    assert_eq!(core.state.decision_count, 2);
    assert_eq!(core.decision_seq, 2);
}

#[test]
fn decide_records_trace() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    core.decide(&normal_input(1)).unwrap();

    assert_eq!(core.trace.len(), 1);
    let entry = &core.trace[0];
    assert_eq!(entry.seq, 0);
    assert!(!entry.fallback_triggered);
}

#[test]
fn decide_records_calibration_ledger() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    core.decide(&normal_input(1)).unwrap();
    assert_eq!(core.calibration_ledger.len(), 1);
}

// ===========================================================================
// 14. RuntimeDecisionCore — fallback triggers
// ===========================================================================

#[test]
fn decide_fallback_on_budget_exhaustion() {
    let mut core =
        RuntimeDecisionCore::new("core-1", standard_lanes(), LaneId::v8_native(), epoch(1))
            .unwrap();

    // Exhaust the budget
    let mut input = normal_input(1);
    input.compute_ms = 100; // exceeds 50ms default
    input.memory_mb = 200; // exceeds 128MB default

    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::BudgetExhausted { .. })
    ));
}

#[test]
fn decide_fallback_on_cvar_violation() {
    let mut core =
        RuntimeDecisionCore::new("core-1", standard_lanes(), LaneId::v8_native(), epoch(1))
            .unwrap();

    // Feed many high-latency samples to trigger CVaR violation
    for i in 0..100 {
        let mut input = normal_input(i);
        input.observed_latency_us = 50_000; // 50ms, well above 10ms cap
        let _ = core.decide(&input);
    }

    // Check that at least one fallback event was recorded
    assert!(!core.fallback_events.is_empty());
}

#[test]
fn decide_fallback_on_attack_regime() {
    let mut core =
        RuntimeDecisionCore::new("core-1", standard_lanes(), LaneId::v8_native(), epoch(1))
            .unwrap();

    let mut input = normal_input(1);
    input.regime = RegimeEstimate::Attack;

    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    // Attack regime should trigger demotion to safe_mode
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::RegimeChange(_))
    ));
}

#[test]
fn decide_fallback_on_low_confidence() {
    let mut core =
        RuntimeDecisionCore::new("core-1", standard_lanes(), LaneId::v8_native(), epoch(1))
            .unwrap();

    let mut input = normal_input(1);
    input.confidence_millionths = 50_000; // 5%, well below 20% threshold

    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::LowConfidence { .. })
    ));
}

// ===========================================================================
// 15. RuntimeDecisionCore — epoch advancement
// ===========================================================================

#[test]
fn decide_allows_same_epoch() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    let mut input = normal_input(1);
    input.epoch = epoch(1);
    assert!(core.decide(&input).is_ok());
}

#[test]
fn decide_allows_epoch_advancement() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    let mut input = normal_input(1);
    input.epoch = epoch(5);
    assert!(core.decide(&input).is_ok());
    assert_eq!(core.state.epoch, epoch(5));
}

// ===========================================================================
// 16. FallbackReason
// ===========================================================================

#[test]
fn fallback_reason_display() {
    let reasons = [
        (
            FallbackReason::RegimeChange("attack".into()),
            "regime_change:attack",
        ),
        (
            FallbackReason::CVaRViolation {
                cvar_us: 15000,
                max_us: 10000,
            },
            "cvar_violation:15000us>10000us",
        ),
        (
            FallbackReason::BudgetExhausted {
                compute_ms: 60,
                memory_mb: 200,
            },
            "budget_exhausted:compute=60ms,mem=200mb",
        ),
        (
            FallbackReason::LowConfidence {
                confidence_millionths: 50000,
            },
            "low_confidence:50000",
        ),
    ];
    for (reason, expected) in &reasons {
        assert_eq!(reason.to_string(), *expected);
    }
}

#[test]
fn fallback_reason_serde() {
    let reason = FallbackReason::RegimeChange("attack".into());
    let json = serde_json::to_string(&reason).unwrap();
    let back: FallbackReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reason);
}

// ===========================================================================
// 17. PolicyBundle
// ===========================================================================

#[test]
fn policy_bundle_serde() {
    let policy = default_routing_loss_policy();
    let bundle = PolicyBundle {
        schema_version: DECISION_CORE_SCHEMA_VERSION.into(),
        bundle_id: "bundle-1".into(),
        loss_policy: policy,
        cvar_quantile_millionths: 990_000,
        cvar_max_us: 10_000,
        regime_demotions: BTreeMap::new(),
        compute_budget_ms: 50,
        memory_budget_mb: 128,
        calibration_target_coverage_millionths: 950_000,
        epoch: epoch(1),
        timestamp_ns: 1_000_000,
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: PolicyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

// ===========================================================================
// 18. DecisionTraceEntry
// ===========================================================================

#[test]
fn decision_trace_entry_serde() {
    let entry = DecisionTraceEntry {
        seq: 0,
        state_before: LaneRoutingState::initial(LaneId::quickjs_native(), epoch(1)),
        action: RoutingAction::SelectLane(LaneId::v8_native()),
        expected_loss_millionths: 150_000,
        cvar_us: 500,
        fallback_triggered: false,
        fallback_reason: None,
        epoch: epoch(1),
        timestamp_ns: 1_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DecisionTraceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 19. CalibrationLedgerEntry
// ===========================================================================

#[test]
fn calibration_ledger_entry_serde() {
    let entry = CalibrationLedgerEntry {
        seq: 0,
        empirical_coverage_millionths: 960_000,
        target_coverage_millionths: 950_000,
        threshold_millionths: 500_000,
        e_value_millionths: 1_050_000,
        recalibration_triggered: false,
        epoch: epoch(1),
        timestamp_ns: 1_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: CalibrationLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 20. FallbackTriggerEvent
// ===========================================================================

#[test]
fn fallback_trigger_event_serde() {
    let event = FallbackTriggerEvent {
        seq: 0,
        reason: FallbackReason::RegimeChange("attack".into()),
        from_lane: LaneId::v8_native(),
        to_lane: LaneId::safe_mode(),
        regime: RegimeEstimate::Attack,
        confidence_millionths: 800_000,
        epoch: epoch(1),
        timestamp_ns: 1_000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// 21. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_multiple_decisions() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    // Phase 1: Normal operation — several decisions
    for i in 0..10 {
        let mut input = normal_input(i * 1_000_000);
        input.observed_latency_us = 200 + (i * 10);
        let output = core.decide(&input).unwrap();
        assert!(!output.fallback_triggered);
    }
    assert_eq!(core.state.decision_count, 10);
    assert_eq!(core.trace.len(), 10);
    assert_eq!(core.calibration_ledger.len(), 10);

    // Phase 2: Regime change → Attack → fallback triggered
    let mut input = normal_input(20_000_000);
    input.regime = RegimeEstimate::Attack;
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(!core.fallback_events.is_empty());

    // Phase 3: Recovery — back to normal
    let mut input = normal_input(30_000_000);
    input.regime = RegimeEstimate::Normal;
    input.confidence_millionths = 900_000;
    let _output = core.decide(&input).unwrap();
    // Should still work
    assert_eq!(core.state.decision_count, 12);
}

#[test]
fn serde_round_trip_after_decisions() {
    let mut core = RuntimeDecisionCore::new(
        "core-1",
        standard_lanes(),
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap();

    for i in 0..5 {
        core.decide(&normal_input(i * 1000)).unwrap();
    }

    let json = serde_json::to_string(&core).unwrap();
    let back: RuntimeDecisionCore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.core_id, core.core_id);
    assert_eq!(back.decision_seq, core.decision_seq);
    assert_eq!(back.trace.len(), core.trace.len());
}
