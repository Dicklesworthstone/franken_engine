//! Enrichment integration tests for `runtime_decision_core`.
//!
//! Covers Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior, edge cases, deterministic hash behavior, builder patterns,
//! CVaR tail-risk guardrails, conformal calibration, demotion policy,
//! adaptive budget, and the full `RuntimeDecisionCore` orchestrator.

use std::collections::BTreeSet;

use frankenengine_engine::runtime_decision_core::{
    AdaptiveBudget, AsymmetricLossPolicy, CVaRConstraint, CVaRResult, CalibrationLedgerEntry,
    ConformalCalibrationLayer, DECISION_CORE_SCHEMA_VERSION, DecisionCoreError, DecisionTraceEntry,
    DemotionPolicy, FallbackReason, FallbackTriggerEvent, LaneId, LaneRoutingState,
    LossPolicyEntry, PolicyBundle, RegimeEstimate, RiskDimension, RoutingAction,
    RoutingDecisionInput, RoutingDecisionOutput, RuntimeDecisionCore, default_routing_loss_policy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_risk_posteriors() -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    for dim in RiskDimension::ALL {
        m.insert(dim.to_string(), 100_000); // 10%
    }
    m
}

fn high_risk_posteriors() -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    m.insert(RiskDimension::Compatibility.to_string(), 800_000);
    m.insert(RiskDimension::Latency.to_string(), 600_000);
    m.insert(RiskDimension::Memory.to_string(), 700_000);
    m.insert(RiskDimension::IncidentSeverity.to_string(), 900_000);
    m
}

fn make_input(
    latency_us: u64,
    regime: RegimeEstimate,
    confidence: i64,
    is_adverse: bool,
    epoch_val: u64,
) -> RoutingDecisionInput {
    RoutingDecisionInput {
        observed_latency_us: latency_us,
        risk_posteriors: default_risk_posteriors(),
        regime,
        confidence_millionths: confidence,
        is_adverse,
        nonconformity_score_millionths: 300_000,
        calibration_covered: true,
        compute_ms: 5,
        memory_mb: 32,
        epoch: epoch(epoch_val),
        timestamp_ns: epoch_val * 1_000_000,
    }
}

fn make_core() -> RuntimeDecisionCore {
    RuntimeDecisionCore::new(
        "test-core",
        vec![LaneId::quickjs_native(), LaneId::v8_native()],
        LaneId::quickjs_native(),
        epoch(1),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Display uniqueness tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_dimension_display_uniqueness() {
    let mut set = BTreeSet::new();
    for dim in &RiskDimension::ALL {
        let s = dim.to_string();
        assert!(!s.is_empty());
        set.insert(s);
    }
    assert_eq!(
        set.len(),
        4,
        "all 4 RiskDimension variants must have unique Display"
    );
}

#[test]
fn enrichment_regime_estimate_display_uniqueness() {
    let variants = [
        RegimeEstimate::Normal,
        RegimeEstimate::Elevated,
        RegimeEstimate::Attack,
        RegimeEstimate::Degraded,
        RegimeEstimate::Recovery,
    ];
    let mut set = BTreeSet::new();
    for v in &variants {
        set.insert(v.to_string());
    }
    assert_eq!(
        set.len(),
        5,
        "all 5 RegimeEstimate variants must have unique Display"
    );
}

#[test]
fn enrichment_routing_action_display_uniqueness() {
    let variants = [
        RoutingAction::SelectLane(LaneId::deterministic_profile()),
        RoutingAction::SelectLane(LaneId::throughput_profile()),
        RoutingAction::SelectLane(LaneId::safe_mode()),
        RoutingAction::FallbackSafeMode,
        RoutingAction::EscalateToOperator,
        RoutingAction::Hold,
    ];
    let mut set = BTreeSet::new();
    for v in &variants {
        set.insert(v.to_string());
    }
    assert_eq!(
        set.len(),
        variants.len(),
        "all RoutingAction variants must have unique Display"
    );
}

#[test]
fn enrichment_decision_core_error_display_uniqueness() {
    let variants = [
        DecisionCoreError::NoLanesConfigured,
        DecisionCoreError::EmptyActionSet,
        DecisionCoreError::BudgetExhaustedNoFallback,
        DecisionCoreError::EpochRegression {
            current: 5,
            received: 3,
        },
        DecisionCoreError::InvalidConfig("x".into()),
    ];
    let mut set = BTreeSet::new();
    for v in &variants {
        set.insert(v.to_string());
    }
    assert_eq!(
        set.len(),
        5,
        "all DecisionCoreError variants must have unique Display"
    );
}

#[test]
fn enrichment_fallback_reason_display_uniqueness_all_7() {
    let variants: Vec<FallbackReason> = vec![
        FallbackReason::RegimeChange("attack".into()),
        FallbackReason::CVaRViolation {
            cvar_us: 5000,
            max_us: 1000,
        },
        FallbackReason::CalibrationUndercoverage {
            coverage_millionths: 800_000,
        },
        FallbackReason::BudgetExhausted {
            compute_ms: 60,
            memory_mb: 200,
        },
        FallbackReason::LowConfidence {
            confidence_millionths: 100_000,
        },
        FallbackReason::EProcessTriggered {
            guardrail_id: "g1".into(),
        },
        FallbackReason::ConsecutiveAdverse { count: 3 },
    ];
    let mut set = BTreeSet::new();
    for v in &variants {
        set.insert(v.to_string());
    }
    assert_eq!(
        set.len(),
        7,
        "all 7 FallbackReason variants must have unique Display"
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_dimension_serde_roundtrip_all() {
    for dim in &RiskDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: RiskDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn enrichment_regime_estimate_serde_roundtrip_all() {
    let variants = [
        RegimeEstimate::Normal,
        RegimeEstimate::Elevated,
        RegimeEstimate::Attack,
        RegimeEstimate::Degraded,
        RegimeEstimate::Recovery,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: RegimeEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_routing_action_serde_roundtrip_all_variants() {
    let variants = vec![
        RoutingAction::SelectLane(LaneId::deterministic_profile()),
        RoutingAction::SelectLane(LaneId::throughput_profile()),
        RoutingAction::SelectLane(LaneId::safe_mode()),
        RoutingAction::SelectLane(LaneId(String::from("custom_lane"))),
        RoutingAction::FallbackSafeMode,
        RoutingAction::EscalateToOperator,
        RoutingAction::Hold,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: RoutingAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_lane_id_serde_roundtrip_deterministic() {
    let lane = LaneId::deterministic_profile();
    let json = serde_json::to_string(&lane).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

#[test]
fn enrichment_lane_id_serde_roundtrip_throughput() {
    let lane = LaneId::throughput_profile();
    let json = serde_json::to_string(&lane).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

#[test]
fn enrichment_lane_id_serde_roundtrip_safe_mode() {
    let lane = LaneId::safe_mode();
    let json = serde_json::to_string(&lane).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

#[test]
fn enrichment_lane_id_serde_custom_label_preserved() {
    let lane = LaneId(String::from("my_custom_lane_xyz"));
    let json = serde_json::to_string(&lane).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
    assert_eq!(back.0, "my_custom_lane_xyz");
}

#[test]
fn enrichment_lane_routing_state_serde_roundtrip() {
    let state = LaneRoutingState::initial(LaneId::throughput_profile(), epoch(42));
    let json = serde_json::to_string(&state).unwrap();
    let back: LaneRoutingState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn enrichment_asymmetric_loss_policy_serde_roundtrip() {
    let policy = default_routing_loss_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: AsymmetricLossPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_cvar_constraint_serde_roundtrip_with_samples() {
    let mut cvar = CVaRConstraint::new("enrichment-test", 950_000, 5_000);
    for i in 0..20 {
        cvar.observe(i * 100);
    }
    let json = serde_json::to_string(&cvar).unwrap();
    let back: CVaRConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(cvar, back);
}

#[test]
fn enrichment_cvar_result_serde_roundtrip() {
    let result = CVaRResult {
        cvar_us: 12345,
        satisfied: false,
        var_us: 10000,
        sample_count: 500,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: CVaRResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_conformal_calibration_layer_serde_roundtrip() {
    let mut cal = ConformalCalibrationLayer::new("enrichment-cal", 900_000);
    for i in 0..30 {
        cal.observe(i * 10_000, i % 3 != 0);
    }
    let json = serde_json::to_string(&cal).unwrap();
    let back: ConformalCalibrationLayer = serde_json::from_str(&json).unwrap();
    assert_eq!(cal.total_count, back.total_count);
    assert_eq!(cal.covered_count, back.covered_count);
    assert_eq!(cal.layer_id, back.layer_id);
}

#[test]
fn enrichment_demotion_policy_serde_roundtrip() {
    let policy = DemotionPolicy::new("enrichment-demotion");
    let json = serde_json::to_string(&policy).unwrap();
    let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_adaptive_budget_serde_roundtrip() {
    let mut budget = AdaptiveBudget::new("enrichment-budget", epoch(7));
    budget.record(10, 50);
    let json = serde_json::to_string(&budget).unwrap();
    let back: AdaptiveBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn enrichment_policy_bundle_serde_roundtrip() {
    let core = make_core();
    let bundle = core.export_policy_bundle(99_999);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: PolicyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.bundle_id, back.bundle_id);
    assert_eq!(bundle.schema_version, back.schema_version);
    assert_eq!(bundle.epoch, back.epoch);
    assert_eq!(bundle.timestamp_ns, back.timestamp_ns);
}

#[test]
fn enrichment_calibration_ledger_entry_serde_roundtrip() {
    let entry = CalibrationLedgerEntry {
        seq: 42,
        empirical_coverage_millionths: 960_000,
        target_coverage_millionths: 950_000,
        threshold_millionths: 400_000,
        e_value_millionths: 1_000_000,
        recalibration_triggered: true,
        epoch: epoch(5),
        timestamp_ns: 123_456,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: CalibrationLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_fallback_trigger_event_serde_roundtrip() {
    let event = FallbackTriggerEvent {
        seq: 7,
        reason: FallbackReason::CVaRViolation {
            cvar_us: 20_000,
            max_us: 10_000,
        },
        from_lane: LaneId::throughput_profile(),
        to_lane: LaneId::safe_mode(),
        regime: RegimeEstimate::Elevated,
        confidence_millionths: 400_000,
        epoch: epoch(3),
        timestamp_ns: 7_000_000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: FallbackTriggerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_decision_trace_entry_serde_roundtrip() {
    let entry = DecisionTraceEntry {
        seq: 10,
        state_before: LaneRoutingState::initial(LaneId::safe_mode(), epoch(2)),
        action: RoutingAction::FallbackSafeMode,
        expected_loss_millionths: 123_456,
        cvar_us: 999,
        fallback_triggered: true,
        fallback_reason: Some(FallbackReason::BudgetExhausted {
            compute_ms: 100,
            memory_mb: 256,
        }),
        epoch: epoch(2),
        timestamp_ns: 2_000_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DecisionTraceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_routing_decision_input_serde_roundtrip() {
    let input = make_input(5_000, RegimeEstimate::Recovery, 600_000, true, 10);
    let json = serde_json::to_string(&input).unwrap();
    let back: RoutingDecisionInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn enrichment_routing_decision_output_serde_roundtrip() {
    let output = RoutingDecisionOutput {
        action: RoutingAction::SelectLane(LaneId::throughput_profile()),
        expected_loss_millionths: 77_000,
        fallback_triggered: true,
        fallback_reason: Some(FallbackReason::LowConfidence {
            confidence_millionths: 50_000,
        }),
        cvar_result: CVaRResult {
            cvar_us: 8000,
            satisfied: true,
            var_us: 7000,
            sample_count: 200,
        },
        decision_seq: 42,
    };
    let json = serde_json::to_string(&output).unwrap();
    let back: RoutingDecisionOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn enrichment_decision_core_error_serde_roundtrip_all() {
    let variants: Vec<DecisionCoreError> = vec![
        DecisionCoreError::NoLanesConfigured,
        DecisionCoreError::EmptyActionSet,
        DecisionCoreError::BudgetExhaustedNoFallback,
        DecisionCoreError::EpochRegression {
            current: 100,
            received: 50,
        },
        DecisionCoreError::InvalidConfig("missing field foo".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: DecisionCoreError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_fallback_reason_serde_roundtrip_all_7() {
    let variants: Vec<FallbackReason> = vec![
        FallbackReason::RegimeChange("degraded".into()),
        FallbackReason::CVaRViolation {
            cvar_us: 50_000,
            max_us: 10_000,
        },
        FallbackReason::CalibrationUndercoverage {
            coverage_millionths: 750_000,
        },
        FallbackReason::BudgetExhausted {
            compute_ms: 200,
            memory_mb: 512,
        },
        FallbackReason::LowConfidence {
            confidence_millionths: 150_000,
        },
        FallbackReason::EProcessTriggered {
            guardrail_id: "ep-guardrail-42".into(),
        },
        FallbackReason::ConsecutiveAdverse { count: 7 },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_runtime_decision_core_serde_roundtrip() {
    let mut core = make_core();
    let input = make_input(2_000, RegimeEstimate::Normal, 750_000, false, 1);
    core.decide(&input).unwrap();
    let json = serde_json::to_string(&core).unwrap();
    let back: RuntimeDecisionCore = serde_json::from_str(&json).unwrap();
    assert_eq!(core.decision_seq, back.decision_seq);
    assert_eq!(core.core_id, back.core_id);
    assert_eq!(core.state.decision_count, back.state.decision_count);
}

// ---------------------------------------------------------------------------
// LaneId method behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lane_id_quickjs_native_equals_deterministic_profile() {
    assert_eq!(LaneId::quickjs_native(), LaneId::deterministic_profile());
}

#[test]
fn enrichment_lane_id_v8_native_equals_throughput_profile() {
    assert_eq!(LaneId::v8_native(), LaneId::throughput_profile());
}

#[test]
fn enrichment_lane_id_stable_label_canonical() {
    assert_eq!(
        LaneId::deterministic_profile().stable_label(),
        "baseline_deterministic_profile"
    );
    assert_eq!(
        LaneId::throughput_profile().stable_label(),
        "baseline_throughput_profile"
    );
    assert_eq!(LaneId::safe_mode().stable_label(), "safe_mode");
}

#[test]
fn enrichment_lane_id_custom_stable_label_is_self() {
    let lane = LaneId(String::from("my_custom"));
    assert_eq!(lane.stable_label(), "my_custom");
}

#[test]
fn enrichment_lane_id_display_uses_stable_label() {
    let lane = LaneId::safe_mode();
    assert_eq!(lane.to_string(), lane.stable_label());
}

#[test]
fn enrichment_lane_id_ordering_deterministic() {
    let a = LaneId::deterministic_profile();
    let b = LaneId::throughput_profile();
    let c = LaneId::safe_mode();
    let mut lanes = [c.clone(), a.clone(), b.clone()];
    lanes.sort();
    // Sorted lexicographically by internal string
    let sorted_strings: Vec<String> = lanes.iter().map(|l| l.0.clone()).collect();
    for i in 0..sorted_strings.len() - 1 {
        assert!(sorted_strings[i] <= sorted_strings[i + 1]);
    }
}

#[test]
fn enrichment_lane_id_legacy_quickjs_deserialization() {
    let back: LaneId = serde_json::from_str("\"quickjs_inspired_native\"").unwrap();
    assert_eq!(back, LaneId::deterministic_profile());
}

#[test]
fn enrichment_lane_id_legacy_v8_deserialization() {
    let back: LaneId = serde_json::from_str("\"v8_inspired_native\"").unwrap();
    assert_eq!(back, LaneId::throughput_profile());
}

// ---------------------------------------------------------------------------
// RiskDimension tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_dimension_all_constant_length() {
    assert_eq!(RiskDimension::ALL.len(), 4);
}

#[test]
fn enrichment_risk_dimension_all_order_matches_enum_order() {
    // ALL should follow the enum declaration order
    assert_eq!(RiskDimension::ALL[0], RiskDimension::Compatibility);
    assert_eq!(RiskDimension::ALL[1], RiskDimension::Latency);
    assert_eq!(RiskDimension::ALL[2], RiskDimension::Memory);
    assert_eq!(RiskDimension::ALL[3], RiskDimension::IncidentSeverity);
}

// ---------------------------------------------------------------------------
// AsymmetricLossPolicy tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_loss_policy_new_empty() {
    let policy = AsymmetricLossPolicy::new("empty-policy");
    assert_eq!(policy.policy_id, "empty-policy");
    assert!(policy.entries.is_empty());
    assert!(policy.regime_multipliers.is_empty());
}

#[test]
fn enrichment_loss_policy_add_entry_and_query() {
    let mut policy = AsymmetricLossPolicy::new("test-policy");
    policy.add_entry("test_action", RiskDimension::Latency, 500_000);
    assert_eq!(policy.entries.len(), 1);

    let mut posteriors = BTreeMap::new();
    posteriors.insert("latency".into(), 500_000); // 50%
    let loss = policy.expected_loss("test_action", &posteriors, RegimeEstimate::Normal);
    // 500_000 * 500_000 / 1_000_000 = 250_000, regime_mult defaults to MILLION (1.0)
    assert_eq!(loss, 250_000);
}

#[test]
fn enrichment_loss_policy_regime_multiplier_amplifies_loss() {
    let mut policy = AsymmetricLossPolicy::new("amplified");
    policy.add_entry("action_a", RiskDimension::Memory, 400_000);
    policy.set_regime_multiplier(RegimeEstimate::Attack, 3_000_000); // 3x

    let mut posteriors = BTreeMap::new();
    posteriors.insert("memory".into(), 200_000); // 20%

    let normal_loss = policy.expected_loss("action_a", &posteriors, RegimeEstimate::Normal);
    let attack_loss = policy.expected_loss("action_a", &posteriors, RegimeEstimate::Attack);
    assert!(attack_loss > normal_loss);
    // Normal: 400_000 * 200_000 / 1M = 80_000, then * 1M / 1M = 80_000
    assert_eq!(normal_loss, 80_000);
    // Attack: 80_000 * 3_000_000 / 1M = 240_000
    assert_eq!(attack_loss, 240_000);
}

#[test]
fn enrichment_loss_policy_select_min_loss_action_empty_returns_none() {
    let policy = default_routing_loss_policy();
    let result =
        policy.select_min_loss_action(&[], &default_risk_posteriors(), RegimeEstimate::Normal);
    assert!(result.is_none());
}

#[test]
fn enrichment_loss_policy_select_min_loss_single_candidate() {
    let policy = default_routing_loss_policy();
    let candidates = vec!["hold".to_string()];
    let result = policy
        .select_min_loss_action(
            &candidates,
            &default_risk_posteriors(),
            RegimeEstimate::Normal,
        )
        .unwrap();
    assert_eq!(result.0, "hold");
}

#[test]
fn enrichment_loss_policy_expected_loss_unknown_action_is_zero() {
    let policy = default_routing_loss_policy();
    let loss = policy.expected_loss(
        "totally_unknown_action",
        &default_risk_posteriors(),
        RegimeEstimate::Normal,
    );
    assert_eq!(loss, 0, "unknown action should have zero loss entries");
}

#[test]
fn enrichment_loss_policy_default_has_16_entries() {
    let policy = default_routing_loss_policy();
    assert_eq!(policy.entries.len(), 16, "4 actions * 4 dimensions = 16");
}

#[test]
fn enrichment_loss_policy_default_has_5_regime_multipliers() {
    let policy = default_routing_loss_policy();
    assert_eq!(policy.regime_multipliers.len(), 5);
}

// ---------------------------------------------------------------------------
// CVaRConstraint tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cvar_default_p99_configuration() {
    let cvar = CVaRConstraint::default_p99();
    assert_eq!(cvar.constraint_id, "cvar-p99-default");
    assert_eq!(cvar.quantile_millionths, 990_000);
    assert_eq!(cvar.max_cvar_us, 10_000);
    assert!(cvar.samples.is_empty());
}

#[test]
fn enrichment_cvar_empty_is_satisfied() {
    let cvar = CVaRConstraint::new("empty", 990_000, 5_000);
    let result = cvar.evaluate();
    assert!(result.satisfied);
    assert_eq!(result.cvar_us, 0);
    assert_eq!(result.var_us, 0);
    assert_eq!(result.sample_count, 0);
}

#[test]
fn enrichment_cvar_single_sample_below_threshold() {
    let mut cvar = CVaRConstraint::new("single", 990_000, 10_000);
    cvar.observe(3_000);
    let result = cvar.evaluate();
    assert!(result.satisfied);
    assert_eq!(result.cvar_us, 3_000);
    assert_eq!(result.sample_count, 1);
}

#[test]
fn enrichment_cvar_single_sample_above_threshold() {
    let mut cvar = CVaRConstraint::new("single-above", 990_000, 1_000);
    cvar.observe(5_000);
    assert!(cvar.is_violated());
}

#[test]
fn enrichment_cvar_tail_risk_captures_worst() {
    let mut cvar = CVaRConstraint::new("tail", 900_000, 100_000);
    // 90 low-latency, 10 high-latency
    for _ in 0..90 {
        cvar.observe(1_000);
    }
    for _ in 0..10 {
        cvar.observe(50_000);
    }
    let result = cvar.evaluate();
    assert_eq!(result.var_us, 50_000);
    assert_eq!(result.cvar_us, 50_000);
}

#[test]
fn enrichment_cvar_respects_max_samples_window() {
    let mut cvar = CVaRConstraint::new("window", 990_000, 100_000);
    cvar.max_samples = 50;
    for i in 0..200 {
        cvar.observe(i * 10);
    }
    assert_eq!(cvar.samples.len(), 50, "should trim to max_samples");
}

#[test]
fn enrichment_cvar_quantile_clamped_to_million() {
    let cvar = CVaRConstraint::new("clamped", 2_000_000, 10_000);
    assert_eq!(
        cvar.quantile_millionths, 1_000_000,
        "should clamp to MILLION"
    );
}

#[test]
fn enrichment_cvar_quantile_clamped_negative_to_zero() {
    let cvar = CVaRConstraint::new("neg", -500, 10_000);
    assert_eq!(cvar.quantile_millionths, 0);
}

// ---------------------------------------------------------------------------
// ConformalCalibrationLayer tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_calibration_initial_full_coverage() {
    let cal = ConformalCalibrationLayer::new("init", 950_000);
    assert_eq!(cal.empirical_coverage_millionths(), 1_000_000);
    assert!(!cal.is_undercovering());
}

#[test]
fn enrichment_calibration_all_covered_stays_at_full() {
    let mut cal = ConformalCalibrationLayer::new("full", 950_000);
    for _ in 0..50 {
        cal.observe(100_000, true);
    }
    assert_eq!(cal.empirical_coverage_millionths(), 1_000_000);
    assert!(!cal.is_undercovering());
}

#[test]
fn enrichment_calibration_undercoverage_detected() {
    let mut cal = ConformalCalibrationLayer::new("under", 950_000);
    // 70% coverage < 95% target
    for _ in 0..70 {
        cal.observe(100_000, true);
    }
    for _ in 0..30 {
        cal.observe(900_000, false);
    }
    assert!(cal.is_undercovering());
    assert_eq!(cal.empirical_coverage_millionths(), 700_000);
}

#[test]
fn enrichment_calibration_e_value_decays_on_miss() {
    let mut cal = ConformalCalibrationLayer::new("decay", 950_000);
    assert_eq!(cal.e_value_millionths, 1_000_000);
    cal.observe(100_000, false);
    assert_eq!(cal.e_value_millionths, 0, "miss multiplies by 0");
}

#[test]
fn enrichment_calibration_e_value_grows_on_hit() {
    let mut cal = ConformalCalibrationLayer::new("grow", 950_000);
    let initial = cal.e_value_millionths;
    cal.observe(100_000, true);
    // hit multiplies by MILLION / target = 1_000_000 / 950_000 ~ 1.0526
    assert!(
        cal.e_value_millionths >= initial,
        "e-value should grow or stay on hit"
    );
}

#[test]
fn enrichment_calibration_threshold_adapts_over_many_observations() {
    let mut cal = ConformalCalibrationLayer::new("adapt", 950_000);
    let initial_threshold = cal.threshold_millionths;
    for i in 0..200 {
        cal.observe(i * 5_000, true);
    }
    assert_ne!(cal.threshold_millionths, initial_threshold);
}

#[test]
fn enrichment_calibration_recent_scores_capped() {
    let mut cal = ConformalCalibrationLayer::new("capped", 950_000);
    assert_eq!(cal.max_scores, 1_000);
    for i in 0..2_000 {
        cal.observe(i, true);
    }
    assert_eq!(cal.recent_scores.len(), 1_000);
}

// ---------------------------------------------------------------------------
// DemotionPolicy tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_demotion_attack_triggers_safe_mode() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    let result = policy.evaluate(RegimeEstimate::Attack, 900_000, false);
    assert_eq!(result, Some(LaneId::safe_mode()));
}

#[test]
fn enrichment_demotion_degraded_triggers_deterministic() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    let result = policy.evaluate(RegimeEstimate::Degraded, 900_000, false);
    assert_eq!(result, Some(LaneId::deterministic_profile()));
}

#[test]
fn enrichment_demotion_normal_no_demotion_high_confidence() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    let result = policy.evaluate(RegimeEstimate::Normal, 900_000, false);
    assert!(result.is_none());
}

#[test]
fn enrichment_demotion_low_confidence_triggers_safe_mode() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    // min_confidence_millionths default is 200_000 (20%)
    let result = policy.evaluate(RegimeEstimate::Normal, 100_000, false);
    assert_eq!(result, Some(LaneId::safe_mode()));
}

#[test]
fn enrichment_demotion_consecutive_adverse_threshold() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    policy.demotion_threshold = 4;
    for _ in 0..3 {
        assert!(
            policy
                .evaluate(RegimeEstimate::Normal, 900_000, true)
                .is_none()
        );
    }
    // 4th adverse triggers
    let result = policy.evaluate(RegimeEstimate::Normal, 900_000, true);
    assert_eq!(result, Some(LaneId::deterministic_profile()));
}

#[test]
fn enrichment_demotion_good_observation_resets_adverse_counter() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    policy.demotion_threshold = 3;
    // Two adverse
    policy.evaluate(RegimeEstimate::Normal, 900_000, true);
    policy.evaluate(RegimeEstimate::Normal, 900_000, true);
    assert_eq!(policy.consecutive_adverse, 2);
    // One good resets
    policy.evaluate(RegimeEstimate::Normal, 900_000, false);
    assert_eq!(policy.consecutive_adverse, 0);
}

#[test]
fn enrichment_demotion_reset_clears_counter() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    policy.evaluate(RegimeEstimate::Normal, 900_000, true);
    policy.evaluate(RegimeEstimate::Normal, 900_000, true);
    policy.reset();
    assert_eq!(policy.consecutive_adverse, 0);
}

#[test]
fn enrichment_demotion_elevated_regime_no_mandatory_demotion() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    let result = policy.evaluate(RegimeEstimate::Elevated, 900_000, false);
    assert!(
        result.is_none(),
        "Elevated regime has no mandatory demotion"
    );
}

#[test]
fn enrichment_demotion_recovery_regime_no_mandatory_demotion() {
    let mut policy = DemotionPolicy::new("enrich-demo");
    let result = policy.evaluate(RegimeEstimate::Recovery, 900_000, false);
    assert!(
        result.is_none(),
        "Recovery regime has no mandatory demotion"
    );
}

// ---------------------------------------------------------------------------
// AdaptiveBudget tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_initial_state() {
    let budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    assert!(!budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 50); // DEFAULT_COMPUTE_BUDGET_MS
    assert_eq!(budget.compute_consumed_ms, 0);
    assert_eq!(budget.peak_memory_mb, 0);
}

#[test]
fn enrichment_budget_compute_exhaustion() {
    let mut budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    budget.record(30, 10);
    assert!(!budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 20);
    budget.record(25, 10);
    assert!(budget.is_exhausted());
    assert_eq!(budget.remaining_compute_ms(), 0);
}

#[test]
fn enrichment_budget_memory_exhaustion() {
    let mut budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    budget.record(1, 200); // 200MB > 128MB default
    assert!(budget.is_exhausted());
}

#[test]
fn enrichment_budget_peak_memory_tracks_max() {
    let mut budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    budget.record(1, 50);
    budget.record(1, 30);
    budget.record(1, 80);
    assert_eq!(
        budget.peak_memory_mb, 80,
        "peak should track highest observed"
    );
}

#[test]
fn enrichment_budget_reset_clears_all() {
    let mut budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    budget.record(100, 200);
    assert!(budget.is_exhausted());
    budget.reset(epoch(2));
    assert!(!budget.is_exhausted());
    assert_eq!(budget.compute_consumed_ms, 0);
    assert_eq!(budget.peak_memory_mb, 0);
    assert_eq!(budget.reset_epoch, epoch(2));
}

#[test]
fn enrichment_budget_saturating_add_no_overflow() {
    let mut budget = AdaptiveBudget::new("enrich-budget", epoch(1));
    budget.record(u64::MAX - 1, 0);
    budget.record(10, 0);
    assert_eq!(budget.compute_consumed_ms, u64::MAX);
}

// ---------------------------------------------------------------------------
// LaneRoutingState tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lane_routing_state_initial_values() {
    let state = LaneRoutingState::initial(LaneId::throughput_profile(), epoch(5));
    assert_eq!(state.active_lane, LaneId::throughput_profile());
    assert_eq!(state.confidence_millionths, 500_000);
    assert_eq!(state.regime, RegimeEstimate::Normal);
    assert_eq!(state.risk_posteriors.len(), 4);
    assert!(state.recent_latencies_us.is_empty());
    assert_eq!(state.decision_count, 0);
    assert_eq!(state.epoch, epoch(5));
    assert!(!state.safe_mode_active);
}

#[test]
fn enrichment_lane_routing_state_risk_posteriors_initialized_to_10_percent() {
    let state = LaneRoutingState::initial(LaneId::deterministic_profile(), epoch(1));
    for dim in RiskDimension::ALL {
        let val = state
            .risk_posteriors
            .get(&dim.to_string())
            .copied()
            .unwrap();
        assert_eq!(val, 100_000, "initial risk posterior should be 10%");
    }
}

// ---------------------------------------------------------------------------
// RuntimeDecisionCore orchestrator tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_core_creation_with_empty_lanes_fails() {
    let result = RuntimeDecisionCore::new("fail", vec![], LaneId::safe_mode(), epoch(1));
    assert_eq!(result.unwrap_err(), DecisionCoreError::NoLanesConfigured);
}

#[test]
fn enrichment_core_initial_state() {
    let core = make_core();
    assert_eq!(core.decision_count(), 0);
    assert!(!core.is_fallback_active());
    assert_eq!(core.current_coverage_millionths(), 1_000_000);
    let cvar = core.current_cvar();
    assert!(cvar.satisfied);
    assert_eq!(cvar.sample_count, 0);
}

#[test]
fn enrichment_core_normal_decision_no_fallback() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(!output.fallback_triggered);
    assert!(output.fallback_reason.is_none());
    assert_eq!(output.decision_seq, 0);
    assert_eq!(core.decision_count(), 1);
}

#[test]
fn enrichment_core_epoch_regression_rejected() {
    let mut core = make_core();
    let input1 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 10);
    core.decide(&input1).unwrap();
    let input2 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 5);
    let err = core.decide(&input2).unwrap_err();
    assert!(matches!(err, DecisionCoreError::EpochRegression { .. }));
}

#[test]
fn enrichment_core_attack_regime_triggers_fallback_with_regime_change_reason() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::RegimeChange(_))
    ));
    assert!(core.is_fallback_active());
}

#[test]
fn enrichment_core_degraded_regime_triggers_demotion() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Degraded, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
}

#[test]
fn enrichment_core_low_confidence_triggers_safe_mode_fallback() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Normal, 50_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::LowConfidence { .. })
    ));
}

#[test]
fn enrichment_core_budget_exhaustion_triggers_fallback() {
    let mut core = make_core();
    core.budget.record(100, 0); // exhaust compute budget
    let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::BudgetExhausted { .. })
    ));
}

#[test]
fn enrichment_core_cvar_violation_triggers_fallback() {
    let mut core = make_core();
    core.cvar_constraint.max_cvar_us = 500; // very low cap
    core.budget.compute_budget_ms = 100_000; // raise budget to avoid exhaustion

    // Feed high-latency samples
    for i in 1..=20 {
        let input = make_input(50_000, RegimeEstimate::Normal, 800_000, false, i);
        let _ = core.decide(&input);
    }

    let input = make_input(50_000, RegimeEstimate::Normal, 800_000, false, 21);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::CVaRViolation { .. })
    ));
}

#[test]
fn enrichment_core_consecutive_adverse_triggers_fallback() {
    let mut core = make_core();
    core.demotion_policy.demotion_threshold = 2;

    let input1 = make_input(1_000, RegimeEstimate::Normal, 800_000, true, 1);
    let out1 = core.decide(&input1).unwrap();
    assert!(!out1.fallback_triggered);

    let input2 = make_input(1_000, RegimeEstimate::Normal, 800_000, true, 2);
    let out2 = core.decide(&input2).unwrap();
    assert!(out2.fallback_triggered);
    assert!(matches!(
        out2.fallback_reason,
        Some(FallbackReason::ConsecutiveAdverse { .. })
    ));
}

#[test]
fn enrichment_core_trace_grows_with_decisions() {
    let mut core = make_core();
    core.budget.compute_budget_ms = 100_000;
    for i in 1..=10 {
        let input = make_input(500, RegimeEstimate::Normal, 800_000, false, i);
        core.decide(&input).unwrap();
    }
    assert_eq!(core.trace.len(), 10);
    assert_eq!(core.decision_seq, 10);
}

#[test]
fn enrichment_core_calibration_ledger_grows_with_decisions() {
    let mut core = make_core();
    core.budget.compute_budget_ms = 100_000;
    for i in 1..=7 {
        let input = make_input(500, RegimeEstimate::Normal, 800_000, false, i);
        core.decide(&input).unwrap();
    }
    assert_eq!(core.calibration_ledger.len(), 7);
    assert_eq!(core.calibration_seq, 7);
}

#[test]
fn enrichment_core_fallback_events_recorded_on_trigger() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 1);
    core.decide(&input).unwrap();
    assert_eq!(core.fallback_events.len(), 1);
    assert_eq!(core.fallback_events[0].regime, RegimeEstimate::Attack);
    assert_eq!(core.fallback_seq, 1);
}

#[test]
fn enrichment_core_export_policy_bundle_structure() {
    let core = make_core();
    let bundle = core.export_policy_bundle(42_000);
    assert_eq!(bundle.schema_version, DECISION_CORE_SCHEMA_VERSION);
    assert!(bundle.bundle_id.starts_with("test-core-bundle-"));
    assert!(!bundle.loss_policy.entries.is_empty());
    assert_eq!(bundle.timestamp_ns, 42_000);
    assert_eq!(bundle.epoch, epoch(1));
    assert_eq!(bundle.compute_budget_ms, 50);
    assert_eq!(bundle.memory_budget_mb, 128);
    assert_eq!(bundle.calibration_target_coverage_millionths, 950_000);
}

#[test]
fn enrichment_core_reset_budget_clears_exhaustion() {
    let mut core = make_core();
    core.budget.record(200, 300);
    assert!(core.budget.is_exhausted());
    core.reset_budget(epoch(10));
    assert!(!core.budget.is_exhausted());
    assert_eq!(core.budget.reset_epoch, epoch(10));
}

#[test]
fn enrichment_core_regime_transition_normal_attack_recovery() {
    let mut core = make_core();

    // Normal
    let input = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 1);
    let out = core.decide(&input).unwrap();
    assert!(!out.fallback_triggered);

    // Attack
    let input = make_input(1_000, RegimeEstimate::Attack, 800_000, false, 2);
    let out = core.decide(&input).unwrap();
    assert!(out.fallback_triggered);
    assert!(core.is_fallback_active());

    // Recovery
    let input = make_input(1_000, RegimeEstimate::Recovery, 800_000, false, 3);
    let out = core.decide(&input).unwrap();
    assert!(!out.fallback_triggered);
    assert!(!core.is_fallback_active());
}

#[test]
fn enrichment_core_decision_seq_increments() {
    let mut core = make_core();
    core.budget.compute_budget_ms = 100_000;
    for i in 1..=5 {
        let input = make_input(500, RegimeEstimate::Normal, 800_000, false, i);
        let output = core.decide(&input).unwrap();
        assert_eq!(output.decision_seq, i - 1);
    }
    assert_eq!(core.decision_count(), 5);
}

#[test]
fn enrichment_core_same_epoch_accepted() {
    let mut core = make_core();
    let input1 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 5);
    core.decide(&input1).unwrap();
    // Same epoch again should be accepted (not a regression)
    let input2 = make_input(1_000, RegimeEstimate::Normal, 800_000, false, 5);
    let result = core.decide(&input2);
    assert!(result.is_ok());
}

#[test]
fn enrichment_core_elevated_regime_no_mandatory_fallback() {
    let mut core = make_core();
    let input = make_input(1_000, RegimeEstimate::Elevated, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(!output.fallback_triggered);
}

// ---------------------------------------------------------------------------
// Deterministic hash behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_risk_dimension_hash_deterministic() {
    use std::hash::{Hash, Hasher};
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    RiskDimension::Latency.hash(&mut hasher1);
    RiskDimension::Latency.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

#[test]
fn enrichment_regime_estimate_hash_deterministic() {
    use std::hash::{Hash, Hasher};
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    RegimeEstimate::Attack.hash(&mut hasher1);
    RegimeEstimate::Attack.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

#[test]
fn enrichment_lane_id_hash_deterministic() {
    use std::hash::{Hash, Hasher};
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    LaneId::safe_mode().hash(&mut hasher1);
    LaneId::safe_mode().hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_loss_policy_zero_posteriors_yields_zero_loss() {
    let policy = default_routing_loss_policy();
    let empty = BTreeMap::new();
    let loss = policy.expected_loss("hold", &empty, RegimeEstimate::Normal);
    assert_eq!(loss, 0);
}

#[test]
fn enrichment_loss_policy_high_risk_increases_loss_monotonically() {
    let policy = default_routing_loss_policy();
    let low = default_risk_posteriors();
    let high = high_risk_posteriors();
    let action = format!("select:{}", LaneId::throughput_profile().stable_label());
    let low_loss = policy.expected_loss(&action, &low, RegimeEstimate::Normal);
    let high_loss = policy.expected_loss(&action, &high, RegimeEstimate::Normal);
    assert!(high_loss > low_loss);
}

#[test]
fn enrichment_decision_core_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(DecisionCoreError::EmptyActionSet);
    assert_eq!(err.to_string(), "empty action set");
}

#[test]
fn enrichment_schema_version_constant_format() {
    assert!(DECISION_CORE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(DECISION_CORE_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_loss_policy_canonical_action_labels_normalized() {
    // Legacy QuickJs label should match deterministic profile
    let mut policy = AsymmetricLossPolicy::new("canon-test");
    policy.add_entry(
        "select:quickjs_inspired_native",
        RiskDimension::Latency,
        100_000,
    );

    let mut posteriors = BTreeMap::new();
    posteriors.insert("latency".into(), 500_000);

    // Query with canonical label should find the entry
    let canonical_action = format!("select:{}", LaneId::deterministic_profile().stable_label());
    let loss = policy.expected_loss(&canonical_action, &posteriors, RegimeEstimate::Normal);
    assert!(loss > 0, "canonical label should match legacy entry");
}

#[test]
fn enrichment_calibration_undercoverage_not_triggered_with_few_observations() {
    // The core only triggers calibration undercoverage after >= 20 observations
    let mut core = make_core();
    core.budget.compute_budget_ms = 100_000;

    // Feed 10 uncovered observations (below the 20 threshold in the core)
    for i in 1..=10 {
        let mut input = make_input(500, RegimeEstimate::Normal, 800_000, false, i);
        input.calibration_covered = false;
        input.nonconformity_score_millionths = 900_000;
        let out = core.decide(&input).unwrap();
        // Should not trigger calibration undercoverage because total < 20
        if let Some(ref reason) = out.fallback_reason {
            assert!(
                !matches!(reason, FallbackReason::CalibrationUndercoverage { .. }),
                "calibration undercoverage should not trigger with < 20 observations"
            );
        }
    }
}

#[test]
fn enrichment_fallback_priority_budget_over_cvar() {
    let mut core = make_core();
    core.cvar_constraint.max_cvar_us = 500;
    // Exhaust budget first
    core.budget.record(200, 0);

    // Also feed high latency
    for _ in 0..5 {
        core.cvar_constraint.observe(50_000);
    }

    let input = make_input(50_000, RegimeEstimate::Normal, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(output.fallback_triggered);
    // Budget exhaustion has higher priority than CVaR
    assert!(matches!(
        output.fallback_reason,
        Some(FallbackReason::BudgetExhausted { .. })
    ));
}

#[test]
fn enrichment_loss_policy_entry_serde_roundtrip() {
    let entry = LossPolicyEntry {
        action_label: "hold".into(),
        dimension: "memory".into(),
        loss_millionths: 333_333,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: LossPolicyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_core_multiple_lanes_selects_min_loss() {
    let mut core = RuntimeDecisionCore::new(
        "multi-lane",
        vec![
            LaneId::deterministic_profile(),
            LaneId::throughput_profile(),
            LaneId::safe_mode(),
        ],
        LaneId::deterministic_profile(),
        epoch(1),
    )
    .unwrap();
    core.budget.compute_budget_ms = 100_000;

    let input = make_input(500, RegimeEstimate::Normal, 800_000, false, 1);
    let output = core.decide(&input).unwrap();
    assert!(!output.fallback_triggered);
    // The action should be one of the available lanes or hold
    match &output.action {
        RoutingAction::SelectLane(_) | RoutingAction::Hold => {}
        other => panic!("unexpected action: {other}"),
    }
}
