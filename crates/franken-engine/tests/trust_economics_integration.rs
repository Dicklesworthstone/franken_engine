#![forbid(unsafe_code)]
//! Integration tests for the `trust_economics` module.
//!
//! Exercises the full public API from outside the crate:
//! enums, structs, construction, display, serde round-trips,
//! validation, ROI computation, fleet summary, and determinism.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_economics::{
    ActionCost, AttackerCostModel, AttackerRoiAssessment, BlastRadiusEstimate, ContainmentAction,
    ContainmentCostModel, DecomposedLossMatrix, FleetRoiSummary, MILLIONTHS, RoiAlertLevel,
    RoiTrend, StrategyCostAdjustment, SubLoss, TrueState, TrustEconomicsError,
    TrustEconomicsModelInputs, classify_roi_alert_level, classify_roi_trend,
    default_conservative_loss_matrix, summarize_fleet_roi,
};

// =========================================================================
// Helpers
// =========================================================================

fn sample_attacker_model() -> AttackerCostModel {
    let mut adjustments = BTreeMap::new();
    adjustments.insert(
        "supply_chain".to_string(),
        StrategyCostAdjustment {
            strategy_name: "supply_chain".to_string(),
            discovery_delta: 500_000,
            development_delta: 1_000_000,
            evasion_delta: 200_000,
            justification: "Supply chain attacks require higher upfront investment".into(),
        },
    );
    AttackerCostModel {
        discovery_cost: 2_000_000,
        development_cost: 3_000_000,
        deployment_cost: 1_000_000,
        persistence_cost: 500_000,
        evasion_cost: 1_500_000,
        expected_gain: 20_000_000,
        strategy_adjustments: adjustments,
        version: 1,
        calibration_source: "manual".into(),
    }
}

fn sample_containment_model() -> ContainmentCostModel {
    let mut m = ContainmentCostModel::new(1, "enterprise", "manual");
    m.set(
        ContainmentAction::Allow,
        ActionCost {
            execution_latency_us: 0,
            resource_consumption: 0,
            collateral_impact: 0,
            operator_burden: 0,
            reversibility_cost: 0,
        },
    );
    m.set(
        ContainmentAction::Quarantine,
        ActionCost {
            execution_latency_us: 50_000,
            resource_consumption: 200_000,
            collateral_impact: 100_000,
            operator_burden: 500_000,
            reversibility_cost: 300_000,
        },
    );
    m
}

fn sample_model_inputs() -> TrustEconomicsModelInputs {
    TrustEconomicsModelInputs {
        loss_matrix: default_conservative_loss_matrix(),
        attacker_cost: sample_attacker_model(),
        containment_cost: sample_containment_model(),
        model_version: 1,
        epoch: SecurityEpoch::from_raw(5),
        calibration_timestamp_ns: 1_700_000_000_000_000_000,
        calibration_source: "manual".into(),
        provenance_chain: vec!["v0-initial".into()],
    }
}

// =========================================================================
// Section 1 — Display impls
// =========================================================================

#[test]
fn true_state_display_all_variants() {
    assert_eq!(TrueState::Benign.to_string(), "benign");
    assert_eq!(TrueState::Suspicious.to_string(), "suspicious");
    assert_eq!(TrueState::Malicious.to_string(), "malicious");
    assert_eq!(TrueState::Compromised.to_string(), "compromised");
}

#[test]
fn containment_action_display_all_variants() {
    assert_eq!(ContainmentAction::Allow.to_string(), "allow");
    assert_eq!(ContainmentAction::Warn.to_string(), "warn");
    assert_eq!(ContainmentAction::Challenge.to_string(), "challenge");
    assert_eq!(ContainmentAction::Sandbox.to_string(), "sandbox");
    assert_eq!(ContainmentAction::Suspend.to_string(), "suspend");
    assert_eq!(ContainmentAction::Terminate.to_string(), "terminate");
    assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
}

#[test]
fn roi_alert_level_display() {
    assert_eq!(RoiAlertLevel::Unprofitable.to_string(), "unprofitable");
    assert_eq!(RoiAlertLevel::Neutral.to_string(), "neutral");
    assert_eq!(RoiAlertLevel::Profitable.to_string(), "profitable");
    assert_eq!(
        RoiAlertLevel::HighlyProfitable.to_string(),
        "highly_profitable"
    );
}

#[test]
fn roi_trend_display() {
    assert_eq!(RoiTrend::Rising.to_string(), "rising");
    assert_eq!(RoiTrend::Stable.to_string(), "stable");
    assert_eq!(RoiTrend::Falling.to_string(), "falling");
}

#[test]
fn trust_economics_error_display_all_variants() {
    let err = TrustEconomicsError::IncompleteLossMatrix {
        populated: 7,
        expected: 28,
    };
    assert_eq!(
        err.to_string(),
        "incomplete loss matrix: 7/28 cells populated"
    );

    let err = TrustEconomicsError::CascadeProbabilityOutOfRange { value: -42 };
    assert!(err.to_string().contains("-42"));

    let err = TrustEconomicsError::ZeroAttackerCost;
    assert_eq!(err.to_string(), "attacker cost model has zero total cost");

    let err = TrustEconomicsError::AsymmetryViolation {
        action: "allow".into(),
        benign_loss: 100,
        malicious_loss: 50,
    };
    assert!(err.to_string().contains("allow"));
    assert!(err.to_string().contains("100"));
    assert!(err.to_string().contains("50"));

    let err = TrustEconomicsError::VersionRegression {
        current: 10,
        attempted: 3,
    };
    assert_eq!(
        err.to_string(),
        "model version regression: current=10, attempted=3"
    );
}

// =========================================================================
// Section 2 — Enum constants and ordering
// =========================================================================

#[test]
fn true_state_all_has_four_variants_in_deterministic_order() {
    assert_eq!(TrueState::ALL.len(), 4);
    assert_eq!(TrueState::ALL[0], TrueState::Benign);
    assert_eq!(TrueState::ALL[1], TrueState::Suspicious);
    assert_eq!(TrueState::ALL[2], TrueState::Malicious);
    assert_eq!(TrueState::ALL[3], TrueState::Compromised);
}

#[test]
fn containment_action_all_has_seven_variants_in_severity_order() {
    assert_eq!(ContainmentAction::ALL.len(), 7);
    assert_eq!(ContainmentAction::ALL[0], ContainmentAction::Allow);
    assert_eq!(ContainmentAction::ALL[6], ContainmentAction::Quarantine);
}

#[test]
fn millionths_constant_equals_one_million() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// =========================================================================
// Section 3 — SubLoss
// =========================================================================

#[test]
fn sub_loss_zero_returns_all_zeroes() {
    let z = SubLoss::zero();
    assert_eq!(z.direct_damage, 0);
    assert_eq!(z.operational_disruption, 0);
    assert_eq!(z.trust_damage, 0);
    assert_eq!(z.containment_cost, 0);
    assert_eq!(z.false_action_cost, 0);
    assert_eq!(z.total(), 0);
}

#[test]
fn sub_loss_total_sums_all_fields() {
    let sl = SubLoss {
        direct_damage: 100_000,
        operational_disruption: 200_000,
        trust_damage: 300_000,
        containment_cost: 50_000,
        false_action_cost: 150_000,
    };
    assert_eq!(sl.total(), 800_000);
}

#[test]
fn sub_loss_total_saturates_on_overflow() {
    let sl = SubLoss {
        direct_damage: i64::MAX,
        operational_disruption: 1,
        trust_damage: 1,
        containment_cost: 1,
        false_action_cost: 1,
    };
    assert_eq!(sl.total(), i64::MAX);
}

#[test]
fn sub_loss_negative_values_handled() {
    let sl = SubLoss {
        direct_damage: -500_000,
        operational_disruption: 200_000,
        trust_damage: 0,
        containment_cost: 0,
        false_action_cost: 0,
    };
    assert_eq!(sl.total(), -300_000);
}

#[test]
fn sub_loss_serde_round_trip() {
    let sl = SubLoss {
        direct_damage: 1_000_000,
        operational_disruption: 2_000_000,
        trust_damage: 3_000_000,
        containment_cost: 4_000_000,
        false_action_cost: 5_000_000,
    };
    let json = serde_json::to_string(&sl).expect("serialize");
    let restored: SubLoss = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sl, restored);
}

// =========================================================================
// Section 4 — DecomposedLossMatrix
// =========================================================================

#[test]
fn loss_matrix_new_is_empty() {
    let m = DecomposedLossMatrix::new(1, "test", "empty matrix");
    assert_eq!(m.cell_count(), 0);
    assert!(!m.is_complete());
    assert_eq!(m.version, 1);
    assert_eq!(m.deployment_context, "test");
    assert_eq!(m.justification, "empty matrix");
}

#[test]
fn loss_matrix_set_and_get() {
    let mut m = DecomposedLossMatrix::new(1, "ctx", "just");
    let sl = SubLoss {
        direct_damage: 42,
        operational_disruption: 0,
        trust_damage: 0,
        containment_cost: 0,
        false_action_cost: 0,
    };
    m.set(TrueState::Benign, ContainmentAction::Allow, sl);
    assert_eq!(
        m.get(TrueState::Benign, ContainmentAction::Allow),
        Some(&sl)
    );
    assert_eq!(m.get(TrueState::Malicious, ContainmentAction::Allow), None);
    assert_eq!(m.cell_count(), 1);
}

#[test]
fn loss_matrix_total_loss_for_missing_cell_is_zero() {
    let m = DecomposedLossMatrix::new(1, "t", "j");
    assert_eq!(
        m.total_loss(TrueState::Benign, ContainmentAction::Quarantine),
        0
    );
}

#[test]
fn loss_matrix_total_loss_for_populated_cell() {
    let mut m = DecomposedLossMatrix::new(1, "t", "j");
    m.set(
        TrueState::Malicious,
        ContainmentAction::Sandbox,
        SubLoss {
            direct_damage: 500_000,
            operational_disruption: 300_000,
            trust_damage: 200_000,
            containment_cost: 100_000,
            false_action_cost: 0,
        },
    );
    assert_eq!(
        m.total_loss(TrueState::Malicious, ContainmentAction::Sandbox),
        1_100_000
    );
}

#[test]
fn loss_matrix_is_complete_when_all_28_cells_populated() {
    let mut m = DecomposedLossMatrix::new(1, "t", "j");
    for &state in &TrueState::ALL {
        for &action in &ContainmentAction::ALL {
            m.set(state, action, SubLoss::zero());
        }
    }
    assert!(m.is_complete());
    assert_eq!(m.cell_count(), 28);
}

#[test]
fn loss_matrix_overwrite_cell() {
    let mut m = DecomposedLossMatrix::new(1, "t", "j");
    m.set(TrueState::Benign, ContainmentAction::Allow, SubLoss::zero());
    assert_eq!(m.total_loss(TrueState::Benign, ContainmentAction::Allow), 0);

    m.set(
        TrueState::Benign,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 100,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        },
    );
    assert_eq!(
        m.total_loss(TrueState::Benign, ContainmentAction::Allow),
        100
    );
    assert_eq!(m.cell_count(), 1);
}

#[test]
fn loss_matrix_to_scalar_totals_matches_individual_lookups() {
    let m = default_conservative_loss_matrix();
    let totals = m.to_scalar_totals();
    for &state in &TrueState::ALL {
        for &action in &ContainmentAction::ALL {
            let expected = m.total_loss(state, action);
            let actual = *totals.get(&(state, action)).unwrap();
            assert_eq!(expected, actual, "mismatch at ({state}, {action})");
        }
    }
}

#[test]
fn loss_matrix_asymmetry_violations_empty_for_valid_matrix() {
    let m = default_conservative_loss_matrix();
    let violations = m.asymmetry_violations();
    assert!(
        violations.is_empty(),
        "default conservative matrix should have no violations: {violations:?}"
    );
}

#[test]
fn loss_matrix_asymmetry_violations_detects_inverted_allow_cell() {
    let mut m = DecomposedLossMatrix::new(1, "t", "j");
    // Set Benign+Allow to high cost and Malicious+Allow to low cost (inverted)
    m.set(
        TrueState::Benign,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 10_000_000,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        },
    );
    m.set(
        TrueState::Malicious,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 1_000,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        },
    );
    let violations = m.asymmetry_violations();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0, ContainmentAction::Allow);
}

#[test]
fn loss_matrix_serde_round_trip() {
    let m = default_conservative_loss_matrix();
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: DecomposedLossMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

// =========================================================================
// Section 5 — Default conservative matrix properties
// =========================================================================

#[test]
fn default_conservative_matrix_is_complete_28_cells() {
    let m = default_conservative_loss_matrix();
    assert!(m.is_complete());
    assert_eq!(m.cell_count(), 28);
}

#[test]
fn default_conservative_matrix_benign_allow_is_zero_loss() {
    let m = default_conservative_loss_matrix();
    let sl = m.get(TrueState::Benign, ContainmentAction::Allow).unwrap();
    assert_eq!(sl.total(), 0);
}

#[test]
fn default_conservative_matrix_malicious_allow_is_most_expensive() {
    let m = default_conservative_loss_matrix();
    let malicious_allow = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
    for &action in &ContainmentAction::ALL {
        if action != ContainmentAction::Allow {
            let other = m.total_loss(TrueState::Malicious, action);
            assert!(
                malicious_allow >= other,
                "malicious+allow ({malicious_allow}) should >= malicious+{action} ({other})"
            );
        }
    }
}

#[test]
fn default_conservative_compromised_exceeds_malicious_for_allow() {
    let m = default_conservative_loss_matrix();
    let mal = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
    let comp = m.total_loss(TrueState::Compromised, ContainmentAction::Allow);
    assert!(comp > mal, "compromised ({comp}) > malicious ({mal})");
}

#[test]
fn default_conservative_quarantine_cheapest_for_malicious() {
    let m = default_conservative_loss_matrix();
    let quarantine = m.total_loss(TrueState::Malicious, ContainmentAction::Quarantine);
    let allow = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
    assert!(quarantine < allow);
}

#[test]
fn default_conservative_benign_allow_cheapest_for_benign() {
    let m = default_conservative_loss_matrix();
    let allow = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
    for &action in &ContainmentAction::ALL {
        if action != ContainmentAction::Allow {
            let cost = m.total_loss(TrueState::Benign, action);
            assert!(
                cost >= allow,
                "benign+{action} ({cost}) should >= benign+allow ({allow})"
            );
        }
    }
}

#[test]
fn default_conservative_metadata() {
    let m = default_conservative_loss_matrix();
    assert_eq!(m.version, 1);
    assert_eq!(m.deployment_context, "default");
}

// =========================================================================
// Section 6 — AttackerCostModel
// =========================================================================

#[test]
fn attacker_total_base_cost_sums_five_components() {
    let m = sample_attacker_model();
    // 2M + 3M + 1M + 0.5M + 1.5M = 8M
    assert_eq!(m.total_base_cost(), 8_000_000);
}

#[test]
fn attacker_adjusted_cost_adds_strategy_deltas() {
    let m = sample_attacker_model();
    // base 8M + 500K + 1M + 200K = 9.7M
    assert_eq!(m.adjusted_cost("supply_chain"), Some(9_700_000));
}

#[test]
fn attacker_adjusted_cost_unknown_strategy_returns_none() {
    let m = sample_attacker_model();
    assert_eq!(m.adjusted_cost("phishing"), None);
}

#[test]
fn attacker_expected_roi_positive() {
    let m = sample_attacker_model();
    // (20M - 8M) * 1M / 8M = 1_500_000 (1.5x)
    assert_eq!(m.expected_roi(), Some(1_500_000));
}

#[test]
fn attacker_expected_roi_negative_when_gain_less_than_cost() {
    let m = AttackerCostModel {
        discovery_cost: 10_000_000,
        development_cost: 10_000_000,
        deployment_cost: 5_000_000,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 5_000_000,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "test".into(),
    };
    let roi = m.expected_roi().unwrap();
    assert!(roi < 0, "expected negative ROI, got {roi}");
}

#[test]
fn attacker_zero_cost_roi_returns_none() {
    let m = AttackerCostModel {
        discovery_cost: 0,
        development_cost: 0,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 10_000_000,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "test".into(),
    };
    assert_eq!(m.expected_roi(), None);
}

#[test]
fn attacker_strategy_roi_computed_correctly() {
    let m = sample_attacker_model();
    // (20M - 9.7M) * 1M / 9.7M = 10.3M/9.7M ~ 1.0619x => ~1_061_855
    let roi = m.strategy_roi("supply_chain").unwrap();
    assert!(roi > 1_000_000 && roi < 1_100_000, "roi was {roi}");
}

#[test]
fn attacker_strategy_roi_returns_none_for_unknown() {
    let m = sample_attacker_model();
    assert_eq!(m.strategy_roi("unknown"), None);
}

#[test]
fn attacker_strategy_roi_returns_none_for_zero_adjusted_cost() {
    let mut adjustments = BTreeMap::new();
    adjustments.insert(
        "zero_adj".to_string(),
        StrategyCostAdjustment {
            strategy_name: "zero_adj".to_string(),
            discovery_delta: 0,
            development_delta: 0,
            evasion_delta: 0,
            justification: "no adjustment".into(),
        },
    );
    let m = AttackerCostModel {
        discovery_cost: 0,
        development_cost: 0,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 5_000_000,
        strategy_adjustments: adjustments,
        version: 1,
        calibration_source: "test".into(),
    };
    assert_eq!(m.strategy_roi("zero_adj"), None);
}

#[test]
fn attacker_model_serde_round_trip() {
    let m = sample_attacker_model();
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: AttackerCostModel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

#[test]
fn attacker_model_multiple_strategies() {
    let mut adjustments = BTreeMap::new();
    adjustments.insert(
        "phishing".to_string(),
        StrategyCostAdjustment {
            strategy_name: "phishing".to_string(),
            discovery_delta: -200_000,
            development_delta: -500_000,
            evasion_delta: 0,
            justification: "Phishing is cheaper to discover and develop".into(),
        },
    );
    adjustments.insert(
        "zero_day".to_string(),
        StrategyCostAdjustment {
            strategy_name: "zero_day".to_string(),
            discovery_delta: 5_000_000,
            development_delta: 3_000_000,
            evasion_delta: 1_000_000,
            justification: "Zero-day exploits are very expensive".into(),
        },
    );
    let m = AttackerCostModel {
        discovery_cost: 1_000_000,
        development_cost: 1_000_000,
        deployment_cost: 500_000,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 10_000_000,
        strategy_adjustments: adjustments,
        version: 2,
        calibration_source: "adversarial".into(),
    };

    // phishing: base 2.5M + (-200K) + (-500K) + 0 = 1.8M
    assert_eq!(m.adjusted_cost("phishing"), Some(1_800_000));
    // zero_day: base 2.5M + 5M + 3M + 1M = 11.5M
    assert_eq!(m.adjusted_cost("zero_day"), Some(11_500_000));

    // phishing ROI: (10M - 1.8M) * 1M / 1.8M = ~4_555_555
    let phishing_roi = m.strategy_roi("phishing").unwrap();
    assert!(phishing_roi > 4_000_000, "phishing roi = {phishing_roi}");

    // zero_day ROI: (10M - 11.5M) * 1M / 11.5M < 0
    let zero_day_roi = m.strategy_roi("zero_day").unwrap();
    assert!(zero_day_roi < 0, "zero_day roi = {zero_day_roi}");
}

// =========================================================================
// Section 7 — ROI classification
// =========================================================================

#[test]
fn classify_roi_alert_level_highly_profitable() {
    assert_eq!(
        classify_roi_alert_level(2_000_001),
        RoiAlertLevel::HighlyProfitable
    );
    assert_eq!(
        classify_roi_alert_level(5_000_000),
        RoiAlertLevel::HighlyProfitable
    );
}

#[test]
fn classify_roi_alert_level_profitable() {
    assert_eq!(
        classify_roi_alert_level(1_500_000),
        RoiAlertLevel::Profitable
    );
    assert_eq!(
        classify_roi_alert_level(1_000_001),
        RoiAlertLevel::Profitable
    );
}

#[test]
fn classify_roi_alert_level_neutral() {
    assert_eq!(classify_roi_alert_level(500_000), RoiAlertLevel::Neutral);
    assert_eq!(classify_roi_alert_level(999_999), RoiAlertLevel::Neutral);
    assert_eq!(classify_roi_alert_level(1_000_000), RoiAlertLevel::Neutral);
}

#[test]
fn classify_roi_alert_level_unprofitable() {
    assert_eq!(
        classify_roi_alert_level(499_999),
        RoiAlertLevel::Unprofitable
    );
    assert_eq!(classify_roi_alert_level(0), RoiAlertLevel::Unprofitable);
    assert_eq!(
        classify_roi_alert_level(-1_000_000),
        RoiAlertLevel::Unprofitable
    );
}

#[test]
fn classify_roi_alert_level_boundary_2x() {
    // Exactly 2.0x (2_000_000) is NOT highly profitable (> 2.0x required)
    assert_eq!(
        classify_roi_alert_level(2_000_000),
        RoiAlertLevel::Profitable
    );
}

#[test]
fn classify_roi_alert_level_boundary_1x() {
    // Exactly 1.0x (1_000_000) is neutral (> 1.0x required for profitable)
    assert_eq!(classify_roi_alert_level(1_000_000), RoiAlertLevel::Neutral);
}

#[test]
fn classify_roi_alert_level_boundary_half() {
    // Exactly 0.5x (500_000) is neutral (< 500_000 required for unprofitable)
    assert_eq!(classify_roi_alert_level(500_000), RoiAlertLevel::Neutral);
}

// =========================================================================
// Section 8 — ROI trend classification
// =========================================================================

#[test]
fn classify_roi_trend_empty_is_stable() {
    assert_eq!(classify_roi_trend(&[]), RoiTrend::Stable);
}

#[test]
fn classify_roi_trend_single_value_is_stable() {
    assert_eq!(classify_roi_trend(&[1_500_000]), RoiTrend::Stable);
}

#[test]
fn classify_roi_trend_rising() {
    // delta = 80_001 > 50_000 threshold
    assert_eq!(classify_roi_trend(&[900_000, 980_001]), RoiTrend::Rising);
}

#[test]
fn classify_roi_trend_falling() {
    // delta = -80_001 < -50_000 threshold
    assert_eq!(classify_roi_trend(&[980_001, 900_000]), RoiTrend::Falling);
}

#[test]
fn classify_roi_trend_stable_within_dead_zone() {
    // delta = 40_000 which is within [-50_000, 50_000]
    assert_eq!(classify_roi_trend(&[900_000, 940_000]), RoiTrend::Stable);
}

#[test]
fn classify_roi_trend_boundary_exactly_50001_rising() {
    assert_eq!(classify_roi_trend(&[0, 50_001]), RoiTrend::Rising);
}

#[test]
fn classify_roi_trend_boundary_exactly_50000_stable() {
    assert_eq!(classify_roi_trend(&[0, 50_000]), RoiTrend::Stable);
}

#[test]
fn classify_roi_trend_uses_first_and_last_not_intermediate() {
    // Middle values should not affect classification
    // first=100_000, last=200_000, delta=100_000 -> Rising
    assert_eq!(
        classify_roi_trend(&[100_000, 50_000, 30_000, 200_000]),
        RoiTrend::Rising
    );
}

// =========================================================================
// Section 9 — AttackerRoiAssessment
// =========================================================================

#[test]
fn attacker_roi_assessment_new_computes_alert_and_trend() {
    let a = AttackerRoiAssessment::new("ext-alpha", 2_500_000, &[1_000_000, 2_500_000]);
    assert_eq!(a.extension_id, "ext-alpha");
    assert_eq!(a.roi_millionths, 2_500_000);
    assert_eq!(a.alert, RoiAlertLevel::HighlyProfitable);
    assert_eq!(a.trend, RoiTrend::Rising);
}

#[test]
fn attacker_roi_assessment_falling_trend() {
    let a = AttackerRoiAssessment::new("ext-beta", 300_000, &[800_000, 300_000]);
    assert_eq!(a.alert, RoiAlertLevel::Unprofitable);
    assert_eq!(a.trend, RoiTrend::Falling);
}

#[test]
fn attacker_roi_assessment_stable_empty_history() {
    let a = AttackerRoiAssessment::new("ext-gamma", 700_000, &[]);
    assert_eq!(a.alert, RoiAlertLevel::Neutral);
    assert_eq!(a.trend, RoiTrend::Stable);
}

#[test]
fn attacker_roi_assessment_serde_round_trip() {
    let a = AttackerRoiAssessment::new("ext-delta", 1_500_000, &[1_000_000, 1_500_000]);
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: AttackerRoiAssessment = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

// =========================================================================
// Section 10 — Fleet ROI summary
// =========================================================================

#[test]
fn fleet_roi_summary_empty_is_zeroed() {
    let summary = summarize_fleet_roi(&BTreeMap::new());
    assert_eq!(summary.extension_count, 0);
    assert_eq!(summary.profitable_extensions, 0);
    assert_eq!(summary.highly_profitable_extensions, 0);
    assert_eq!(summary.average_roi_millionths, 0);
    assert_eq!(summary.min_roi_millionths, 0);
    assert_eq!(summary.max_roi_millionths, 0);
}

#[test]
fn fleet_roi_summary_single_extension() {
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-a".to_string(),
        AttackerRoiAssessment::new("ext-a", 1_500_000, &[1_000_000, 1_500_000]),
    );
    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.extension_count, 1);
    assert_eq!(summary.profitable_extensions, 1);
    assert_eq!(summary.highly_profitable_extensions, 0);
    assert_eq!(summary.average_roi_millionths, 1_500_000);
    assert_eq!(summary.min_roi_millionths, 1_500_000);
    assert_eq!(summary.max_roi_millionths, 1_500_000);
}

#[test]
fn fleet_roi_summary_multiple_extensions() {
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-a".to_string(),
        AttackerRoiAssessment::new("ext-a", 2_500_000, &[]),
    );
    assessments.insert(
        "ext-b".to_string(),
        AttackerRoiAssessment::new("ext-b", 1_100_000, &[]),
    );
    assessments.insert(
        "ext-c".to_string(),
        AttackerRoiAssessment::new("ext-c", 400_000, &[]),
    );
    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.extension_count, 3);
    assert_eq!(summary.profitable_extensions, 1); // ext-b
    assert_eq!(summary.highly_profitable_extensions, 1); // ext-a
    assert_eq!(summary.min_roi_millionths, 400_000);
    assert_eq!(summary.max_roi_millionths, 2_500_000);
    // Average: (2_500_000 + 1_100_000 + 400_000) / 3 = 1_333_333
    assert_eq!(summary.average_roi_millionths, 1_333_333);
}

#[test]
fn fleet_roi_summary_serde_round_trip() {
    let summary = FleetRoiSummary {
        extension_count: 5,
        profitable_extensions: 2,
        highly_profitable_extensions: 1,
        average_roi_millionths: 1_200_000,
        min_roi_millionths: 300_000,
        max_roi_millionths: 3_000_000,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let restored: FleetRoiSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, restored);
}

// =========================================================================
// Section 11 — ActionCost & ContainmentCostModel
// =========================================================================

#[test]
fn action_cost_total_monetary_excludes_latency() {
    let c = ActionCost {
        execution_latency_us: 100_000,
        resource_consumption: 100,
        collateral_impact: 200,
        operator_burden: 300,
        reversibility_cost: 400,
    };
    assert_eq!(c.total_monetary_cost(), 1000);
}

#[test]
fn action_cost_serde_round_trip() {
    let c = ActionCost {
        execution_latency_us: 50_000,
        resource_consumption: 200_000,
        collateral_impact: 100_000,
        operator_burden: 500_000,
        reversibility_cost: 300_000,
    };
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: ActionCost = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

#[test]
fn containment_cost_model_new_is_empty() {
    let m = ContainmentCostModel::new(3, "consumer", "production-derived");
    assert_eq!(m.version, 3);
    assert_eq!(m.deployment_context, "consumer");
    assert_eq!(m.calibration_source, "production-derived");
    assert!(m.action_costs.is_empty());
}

#[test]
fn containment_cost_model_set_get() {
    let m = sample_containment_model();
    assert!(m.get(ContainmentAction::Allow).is_some());
    assert!(m.get(ContainmentAction::Quarantine).is_some());
    assert!(m.get(ContainmentAction::Sandbox).is_none());
}

#[test]
fn containment_cost_model_total_cost() {
    let m = sample_containment_model();
    assert_eq!(m.total_cost(ContainmentAction::Allow), 0);
    // 200K + 100K + 500K + 300K = 1.1M
    assert_eq!(m.total_cost(ContainmentAction::Quarantine), 1_100_000);
    // Missing action returns 0
    assert_eq!(m.total_cost(ContainmentAction::Sandbox), 0);
}

#[test]
fn containment_cost_model_serde_round_trip() {
    let m = sample_containment_model();
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: ContainmentCostModel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

// =========================================================================
// Section 12 — BlastRadiusEstimate
// =========================================================================

#[test]
fn blast_radius_total_affected_entities() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
        affected_data: ["data-1".into()].into_iter().collect(),
        affected_nodes: ["node-a".into(), "node-b".into(), "node-c".into()]
            .into_iter()
            .collect(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    assert_eq!(br.total_affected_entities(), 6);
}

#[test]
fn blast_radius_empty_has_zero_entities() {
    let br = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    assert_eq!(br.total_affected_entities(), 0);
    assert_eq!(br.radius_at_time(100), 0);
}

#[test]
fn blast_radius_at_time_zero_no_cascade() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into()].into_iter().collect(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    // base = 1 * 1M = 1M; cascade_factor = 1M + 0 = 1M; result = 1M * 1M / 1M = 1M
    assert_eq!(br.radius_at_time(0), 1_000_000);
}

#[test]
fn blast_radius_grows_linearly_with_time() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into()].into_iter().collect(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 500_000,
    };
    let r0 = br.radius_at_time(0);
    let r5 = br.radius_at_time(5);
    let r10 = br.radius_at_time(10);
    assert!(r5 > r0);
    assert!(r10 > r5);
}

#[test]
fn blast_radius_cascade_amplifies_result() {
    let base = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    let amplified = BlastRadiusEstimate {
        cascade_probability: 500_000, // 50%
        ..base.clone()
    };
    let r_base = base.radius_at_time(0);
    let r_amplified = amplified.radius_at_time(0);
    // 1.5x amplification
    assert_eq!(r_base, 2_000_000);
    assert_eq!(r_amplified, 3_000_000);
}

#[test]
fn blast_radius_validate_valid() {
    let br = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    assert!(br.validate().is_ok());

    let br2 = BlastRadiusEstimate {
        cascade_probability: MILLIONTHS,
        ..br
    };
    assert!(br2.validate().is_ok());
}

#[test]
fn blast_radius_validate_negative_probability() {
    let br = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: -1,
        growth_rate_per_sec: 0,
    };
    assert!(matches!(
        br.validate(),
        Err(TrustEconomicsError::CascadeProbabilityOutOfRange { value: -1 })
    ));
}

#[test]
fn blast_radius_validate_over_maximum() {
    let br = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: MILLIONTHS + 1,
        growth_rate_per_sec: 0,
    };
    assert!(matches!(
        br.validate(),
        Err(TrustEconomicsError::CascadeProbabilityOutOfRange { .. })
    ));
}

#[test]
fn blast_radius_serde_round_trip() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
        affected_data: ["data-1".into()].into_iter().collect(),
        affected_nodes: ["node-1".into()].into_iter().collect(),
        cascade_probability: 250_000,
        growth_rate_per_sec: 100_000,
    };
    let json = serde_json::to_string(&br).expect("serialize");
    let restored: BlastRadiusEstimate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(br, restored);
}

// =========================================================================
// Section 13 — TrustEconomicsModelInputs
// =========================================================================

#[test]
fn model_inputs_validate_passes_for_complete_valid_model() {
    let m = sample_model_inputs();
    assert!(m.validate().is_ok());
}

#[test]
fn model_inputs_validate_incomplete_loss_matrix() {
    let m = TrustEconomicsModelInputs {
        loss_matrix: DecomposedLossMatrix::new(1, "test", "test"),
        attacker_cost: sample_attacker_model(),
        containment_cost: sample_containment_model(),
        model_version: 1,
        epoch: SecurityEpoch::from_raw(1),
        calibration_timestamp_ns: 0,
        calibration_source: "test".into(),
        provenance_chain: vec![],
    };
    match m.validate() {
        Err(TrustEconomicsError::IncompleteLossMatrix {
            populated,
            expected,
        }) => {
            assert_eq!(populated, 0);
            assert_eq!(expected, 28);
        }
        other => panic!("expected IncompleteLossMatrix, got {other:?}"),
    }
}

#[test]
fn model_inputs_validate_zero_attacker_cost() {
    let mut m = sample_model_inputs();
    m.attacker_cost.discovery_cost = 0;
    m.attacker_cost.development_cost = 0;
    m.attacker_cost.deployment_cost = 0;
    m.attacker_cost.persistence_cost = 0;
    m.attacker_cost.evasion_cost = 0;
    assert!(matches!(
        m.validate(),
        Err(TrustEconomicsError::ZeroAttackerCost)
    ));
}

#[test]
fn model_inputs_validate_asymmetry_violation() {
    let mut m = sample_model_inputs();
    // Invert the Benign+Allow and Malicious+Allow values
    m.loss_matrix.set(
        TrueState::Benign,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 20_000_000,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        },
    );
    m.loss_matrix.set(
        TrueState::Malicious,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 1_000,
            operational_disruption: 0,
            trust_damage: 0,
            containment_cost: 0,
            false_action_cost: 0,
        },
    );
    assert!(matches!(
        m.validate(),
        Err(TrustEconomicsError::AsymmetryViolation { .. })
    ));
}

#[test]
fn model_inputs_version_update_valid() {
    let m = sample_model_inputs();
    assert!(m.validate_version_update(2).is_ok());
    assert!(m.validate_version_update(100).is_ok());
}

#[test]
fn model_inputs_version_regression_equal() {
    let m = sample_model_inputs();
    match m.validate_version_update(1) {
        Err(TrustEconomicsError::VersionRegression { current, attempted }) => {
            assert_eq!(current, 1);
            assert_eq!(attempted, 1);
        }
        other => panic!("expected VersionRegression, got {other:?}"),
    }
}

#[test]
fn model_inputs_version_regression_lower() {
    let m = sample_model_inputs();
    assert!(matches!(
        m.validate_version_update(0),
        Err(TrustEconomicsError::VersionRegression { .. })
    ));
}

#[test]
fn model_inputs_serde_round_trip() {
    let m = sample_model_inputs();
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: TrustEconomicsModelInputs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

#[test]
fn model_inputs_provenance_chain_preserved() {
    let m = sample_model_inputs();
    assert_eq!(m.provenance_chain.len(), 1);
    assert_eq!(m.provenance_chain[0], "v0-initial");
}

#[test]
fn model_inputs_epoch_preserved() {
    let m = sample_model_inputs();
    assert_eq!(m.epoch, SecurityEpoch::from_raw(5));
}

// =========================================================================
// Section 14 — TrustEconomicsError serde
// =========================================================================

#[test]
fn trust_economics_error_serde_round_trip_all_variants() {
    let errors = vec![
        TrustEconomicsError::IncompleteLossMatrix {
            populated: 5,
            expected: 28,
        },
        TrustEconomicsError::CascadeProbabilityOutOfRange { value: -1 },
        TrustEconomicsError::ZeroAttackerCost,
        TrustEconomicsError::AsymmetryViolation {
            action: "allow".into(),
            benign_loss: 100,
            malicious_loss: 50,
        },
        TrustEconomicsError::VersionRegression {
            current: 3,
            attempted: 1,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: TrustEconomicsError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// Section 15 — Deterministic replay
// =========================================================================

#[test]
fn deterministic_model_inputs_serialization() {
    let m1 = sample_model_inputs();
    let m2 = sample_model_inputs();
    let json1 = serde_json::to_string(&m1).expect("serialize 1");
    let json2 = serde_json::to_string(&m2).expect("serialize 2");
    assert_eq!(json1, json2);
}

#[test]
fn deterministic_loss_matrix_iteration_order() {
    let m = default_conservative_loss_matrix();
    let totals1 = m.to_scalar_totals();
    let totals2 = m.to_scalar_totals();
    let keys1: Vec<_> = totals1.keys().collect();
    let keys2: Vec<_> = totals2.keys().collect();
    assert_eq!(keys1, keys2);
}

#[test]
fn deterministic_fleet_roi_summary_order() {
    let mut assessments = BTreeMap::new();
    for i in 0..10 {
        let name = format!("ext-{i:03}");
        assessments.insert(
            name.clone(),
            AttackerRoiAssessment::new(&name, (i + 1) as i64 * 200_000, &[]),
        );
    }
    let summary1 = summarize_fleet_roi(&assessments);
    let summary2 = summarize_fleet_roi(&assessments);
    assert_eq!(summary1, summary2);
}

#[test]
fn deterministic_default_conservative_matrix() {
    let m1 = default_conservative_loss_matrix();
    let m2 = default_conservative_loss_matrix();
    let json1 = serde_json::to_string(&m1).expect("s1");
    let json2 = serde_json::to_string(&m2).expect("s2");
    assert_eq!(json1, json2);
}

// =========================================================================
// Section 16 — StrategyCostAdjustment
// =========================================================================

#[test]
fn strategy_cost_adjustment_serde_round_trip() {
    let adj = StrategyCostAdjustment {
        strategy_name: "insider_threat".into(),
        discovery_delta: -100_000,
        development_delta: 500_000,
        evasion_delta: 200_000,
        justification: "Insider has lower discovery but higher development cost".into(),
    };
    let json = serde_json::to_string(&adj).expect("serialize");
    let restored: StrategyCostAdjustment = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(adj, restored);
}

#[test]
fn strategy_cost_adjustment_negative_deltas() {
    let adj = StrategyCostAdjustment {
        strategy_name: "opportunistic".into(),
        discovery_delta: -500_000,
        development_delta: -300_000,
        evasion_delta: -100_000,
        justification: "Opportunistic attacker saves costs".into(),
    };
    // Total delta is -900_000
    let total_delta = adj
        .discovery_delta
        .saturating_add(adj.development_delta)
        .saturating_add(adj.evasion_delta);
    assert_eq!(total_delta, -900_000);
}

// =========================================================================
// Section 17 — Edge cases
// =========================================================================

#[test]
fn containment_action_ordering_matches_severity() {
    // Allow < Warn < Challenge < Sandbox < Suspend < Terminate < Quarantine
    let all = ContainmentAction::ALL;
    for window in all.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn true_state_ordering_matches_risk() {
    // Benign < Suspicious < Malicious < Compromised
    let all = TrueState::ALL;
    for window in all.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn loss_matrix_scalar_totals_empty_matrix() {
    let m = DecomposedLossMatrix::new(1, "t", "j");
    let totals = m.to_scalar_totals();
    assert!(totals.is_empty());
}

#[test]
fn blast_radius_with_large_time_saturates_gracefully() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into()].into_iter().collect(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 500_000,
        growth_rate_per_sec: i64::MAX / 2,
    };
    // Should not panic even with very large time
    let _ = br.radius_at_time(1000);
}

#[test]
fn containment_cost_model_full_population() {
    let mut m = ContainmentCostModel::new(1, "test", "test");
    for &action in &ContainmentAction::ALL {
        m.set(
            action,
            ActionCost {
                execution_latency_us: 100,
                resource_consumption: 100,
                collateral_impact: 100,
                operator_burden: 100,
                reversibility_cost: 100,
            },
        );
    }
    assert_eq!(m.action_costs.len(), 7);
    for &action in &ContainmentAction::ALL {
        assert_eq!(m.total_cost(action), 400);
    }
}

#[test]
fn action_cost_total_monetary_saturates_on_overflow() {
    let c = ActionCost {
        execution_latency_us: 0,
        resource_consumption: i64::MAX,
        collateral_impact: 1,
        operator_burden: 0,
        reversibility_cost: 0,
    };
    assert_eq!(c.total_monetary_cost(), i64::MAX);
}
