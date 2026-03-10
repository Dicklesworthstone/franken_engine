//! Integration tests for `trust_economics` — edge cases and gaps
//! not covered by inline unit tests.

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ===========================================================================
// TrueState — serde, ordering, hash
// ===========================================================================

#[test]
fn true_state_serde_all_variants() {
    for v in &TrueState::ALL {
        let json = serde_json::to_string(v).unwrap();
        let restored: TrueState = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn true_state_ordering() {
    assert!(TrueState::Benign < TrueState::Suspicious);
    assert!(TrueState::Suspicious < TrueState::Malicious);
    assert!(TrueState::Malicious < TrueState::Compromised);
}

#[test]
fn true_state_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    TrueState::Malicious.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    TrueState::Malicious.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn true_state_display_all() {
    assert_eq!(TrueState::Benign.to_string(), "benign");
    assert_eq!(TrueState::Suspicious.to_string(), "suspicious");
    assert_eq!(TrueState::Malicious.to_string(), "malicious");
    assert_eq!(TrueState::Compromised.to_string(), "compromised");
}

// ===========================================================================
// ContainmentAction — serde, ordering, hash
// ===========================================================================

#[test]
fn containment_action_serde_all_variants() {
    for v in &ContainmentAction::ALL {
        let json = serde_json::to_string(v).unwrap();
        let restored: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn containment_action_ordering() {
    assert!(ContainmentAction::Allow < ContainmentAction::Warn);
    assert!(ContainmentAction::Warn < ContainmentAction::Challenge);
    assert!(ContainmentAction::Challenge < ContainmentAction::Sandbox);
    assert!(ContainmentAction::Sandbox < ContainmentAction::Suspend);
    assert!(ContainmentAction::Suspend < ContainmentAction::Terminate);
    assert!(ContainmentAction::Terminate < ContainmentAction::Quarantine);
}

#[test]
fn containment_action_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    ContainmentAction::Quarantine.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    ContainmentAction::Quarantine.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn containment_action_display_all() {
    let expected = [
        "allow",
        "warn",
        "challenge",
        "sandbox",
        "suspend",
        "terminate",
        "quarantine",
    ];
    for (v, e) in ContainmentAction::ALL.iter().zip(expected.iter()) {
        assert_eq!(v.to_string(), *e);
    }
}

// ===========================================================================
// SubLoss — serde, negative values, zero
// ===========================================================================

#[test]
fn sub_loss_serde_roundtrip() {
    let sl = SubLoss {
        direct_damage: 100_000,
        operational_disruption: 200_000,
        trust_damage: 50_000,
        containment_cost: 10_000,
        false_action_cost: 300_000,
    };
    let json = serde_json::to_string(&sl).unwrap();
    let restored: SubLoss = serde_json::from_str(&json).unwrap();
    assert_eq!(sl, restored);
}

#[test]
fn sub_loss_negative_values() {
    let sl = SubLoss {
        direct_damage: -100,
        operational_disruption: -200,
        trust_damage: -300,
        containment_cost: -400,
        false_action_cost: -500,
    };
    assert_eq!(sl.total(), -1500);
}

#[test]
fn sub_loss_zero_serde() {
    let sl = SubLoss::zero();
    let json = serde_json::to_string(&sl).unwrap();
    let restored: SubLoss = serde_json::from_str(&json).unwrap();
    assert_eq!(sl, restored);
    assert_eq!(restored.total(), 0);
}

// ===========================================================================
// RoiAlertLevel — serde, display
// ===========================================================================

#[test]
fn roi_alert_level_serde_all_variants() {
    let variants = [
        RoiAlertLevel::Unprofitable,
        RoiAlertLevel::Neutral,
        RoiAlertLevel::Profitable,
        RoiAlertLevel::HighlyProfitable,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: RoiAlertLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn roi_alert_level_display_all() {
    assert_eq!(RoiAlertLevel::Unprofitable.to_string(), "unprofitable");
    assert_eq!(RoiAlertLevel::Neutral.to_string(), "neutral");
    assert_eq!(RoiAlertLevel::Profitable.to_string(), "profitable");
    assert_eq!(
        RoiAlertLevel::HighlyProfitable.to_string(),
        "highly_profitable"
    );
}

// ===========================================================================
// RoiTrend — serde, display
// ===========================================================================

#[test]
fn roi_trend_serde_all_variants() {
    let variants = [RoiTrend::Rising, RoiTrend::Stable, RoiTrend::Falling];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: RoiTrend = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn roi_trend_display_all() {
    assert_eq!(RoiTrend::Rising.to_string(), "rising");
    assert_eq!(RoiTrend::Stable.to_string(), "stable");
    assert_eq!(RoiTrend::Falling.to_string(), "falling");
}

// ===========================================================================
// classify_roi_alert_level — boundary values
// ===========================================================================

#[test]
fn classify_roi_boundary_exactly_500_000() {
    // 500_000 is NOT < 500_000, so it should be Neutral.
    assert_eq!(classify_roi_alert_level(500_000), RoiAlertLevel::Neutral);
}

#[test]
fn classify_roi_boundary_exactly_1_000_001() {
    // > 1_000_000, so Profitable.
    assert_eq!(
        classify_roi_alert_level(1_000_001),
        RoiAlertLevel::Profitable
    );
}

#[test]
fn classify_roi_boundary_exactly_2_000_000() {
    // 2_000_000 is NOT > 2_000_000, so Profitable.
    assert_eq!(
        classify_roi_alert_level(2_000_000),
        RoiAlertLevel::Profitable
    );
}

#[test]
fn classify_roi_negative() {
    assert_eq!(
        classify_roi_alert_level(-1_000_000),
        RoiAlertLevel::Unprofitable
    );
}

#[test]
fn classify_roi_zero() {
    assert_eq!(classify_roi_alert_level(0), RoiAlertLevel::Unprofitable);
}

// ===========================================================================
// classify_roi_trend — additional patterns
// ===========================================================================

#[test]
fn classify_roi_trend_many_values_rising() {
    // First=100_000, last=200_000, delta=100_000 > 50_000 → Rising.
    let history = vec![100_000, 120_000, 150_000, 180_000, 200_000];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Rising);
}

#[test]
fn classify_roi_trend_many_values_falling() {
    // First=500_000, last=400_000, delta=-100_000 < -50_000 → Falling.
    let history = vec![500_000, 480_000, 460_000, 430_000, 400_000];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Falling);
}

#[test]
fn classify_roi_trend_within_dead_zone() {
    // First=100_000, last=140_000, delta=40_000 < 50_000 → Stable.
    let history = vec![100_000, 110_000, 130_000, 140_000];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Stable);
}

#[test]
fn classify_roi_trend_exactly_at_threshold() {
    // delta=50_001 > 50_000 → Rising.
    assert_eq!(classify_roi_trend(&[0, 50_001]), RoiTrend::Rising);
    // delta=50_000 NOT > 50_000 → Stable.
    assert_eq!(classify_roi_trend(&[0, 50_000]), RoiTrend::Stable);
    // delta=-50_001 < -50_000 → Falling.
    assert_eq!(classify_roi_trend(&[50_001, 0]), RoiTrend::Falling);
}

// ===========================================================================
// StrategyCostAdjustment — serde
// ===========================================================================

#[test]
fn strategy_cost_adjustment_serde() {
    let adj = StrategyCostAdjustment {
        strategy_name: "phishing".to_string(),
        discovery_delta: 100_000,
        development_delta: -50_000,
        evasion_delta: 300_000,
        justification: "Low dev cost, high evasion".to_string(),
    };
    let json = serde_json::to_string(&adj).unwrap();
    let restored: StrategyCostAdjustment = serde_json::from_str(&json).unwrap();
    assert_eq!(adj, restored);
}

// ===========================================================================
// AttackerRoiAssessment — serde
// ===========================================================================

#[test]
fn attacker_roi_assessment_serde_roundtrip() {
    let a = AttackerRoiAssessment::new("ext-test", 1_500_000, &[1_000_000, 1_500_000]);
    let json = serde_json::to_string(&a).unwrap();
    let restored: AttackerRoiAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, restored);
}

#[test]
fn attacker_roi_assessment_unprofitable() {
    let a = AttackerRoiAssessment::new("ext-safe", 100_000, &[200_000, 100_000]);
    assert_eq!(a.alert, RoiAlertLevel::Unprofitable);
    assert_eq!(a.trend, RoiTrend::Falling);
}

// ===========================================================================
// FleetRoiSummary — serde
// ===========================================================================

#[test]
fn fleet_roi_summary_serde_roundtrip() {
    let summary = FleetRoiSummary {
        extension_count: 3,
        profitable_extensions: 1,
        highly_profitable_extensions: 0,
        average_roi_millionths: 800_000,
        min_roi_millionths: 200_000,
        max_roi_millionths: 1_500_000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: FleetRoiSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// ===========================================================================
// summarize_fleet_roi — single extension, all profitable, all unprofitable
// ===========================================================================

#[test]
fn summarize_fleet_roi_single_extension() {
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
fn summarize_fleet_roi_all_unprofitable() {
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-a".to_string(),
        AttackerRoiAssessment::new("ext-a", 100_000, &[]),
    );
    assessments.insert(
        "ext-b".to_string(),
        AttackerRoiAssessment::new("ext-b", 200_000, &[]),
    );
    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.profitable_extensions, 0);
    assert_eq!(summary.highly_profitable_extensions, 0);
    assert_eq!(summary.min_roi_millionths, 100_000);
    assert_eq!(summary.max_roi_millionths, 200_000);
}

#[test]
fn summarize_fleet_roi_all_highly_profitable() {
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-a".to_string(),
        AttackerRoiAssessment::new("ext-a", 3_000_000, &[]),
    );
    assessments.insert(
        "ext-b".to_string(),
        AttackerRoiAssessment::new("ext-b", 5_000_000, &[]),
    );
    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.profitable_extensions, 0); // These are HighlyProfitable, not Profitable.
    assert_eq!(summary.highly_profitable_extensions, 2);
}

// ===========================================================================
// ActionCost — serde, saturating arithmetic
// ===========================================================================

#[test]
fn action_cost_serde_roundtrip() {
    let c = ActionCost {
        execution_latency_us: 100_000,
        resource_consumption: 500_000,
        collateral_impact: 200_000,
        operator_burden: 300_000,
        reversibility_cost: 150_000,
    };
    let json = serde_json::to_string(&c).unwrap();
    let restored: ActionCost = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn action_cost_total_excludes_latency() {
    let c = ActionCost {
        execution_latency_us: 999_999,
        resource_consumption: 100,
        collateral_impact: 200,
        operator_burden: 300,
        reversibility_cost: 400,
    };
    // Latency is NOT included in total_monetary_cost.
    assert_eq!(c.total_monetary_cost(), 1000);
}

// ===========================================================================
// DecomposedLossMatrix — asymmetry violations
// ===========================================================================

#[test]
fn loss_matrix_asymmetry_violations_none_on_conservative() {
    let m = default_conservative_loss_matrix();
    let violations = m.asymmetry_violations();
    assert!(
        violations.is_empty(),
        "conservative matrix should have no asymmetry violations, got {violations:?}"
    );
}

#[test]
fn loss_matrix_asymmetry_violations_detected() {
    let mut m = DecomposedLossMatrix::new(1, "test", "broken asymmetry");
    // Set malicious+allow cheaper than benign+allow (violation for Allow).
    m.set(
        TrueState::Benign,
        ContainmentAction::Allow,
        SubLoss {
            direct_damage: 500_000,
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
            direct_damage: 100_000,
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

// ===========================================================================
// DecomposedLossMatrix — overwrite cell
// ===========================================================================

#[test]
fn loss_matrix_overwrite_cell() {
    let mut m = DecomposedLossMatrix::new(1, "test", "overwrite");
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
    // Cell count should still be 1.
    assert_eq!(m.cell_count(), 1);
}

// ===========================================================================
// ContainmentCostModel — missing action returns 0
// ===========================================================================

#[test]
fn containment_cost_model_missing_action_zero() {
    let m = ContainmentCostModel::new(1, "test", "test");
    assert_eq!(m.total_cost(ContainmentAction::Sandbox), 0);
    assert!(m.get(ContainmentAction::Sandbox).is_none());
}

// ===========================================================================
// TrustEconomicsError — display all variants, std::error::Error
// ===========================================================================

#[test]
fn trust_economics_error_display_all() {
    let errors = vec![
        TrustEconomicsError::IncompleteLossMatrix {
            populated: 10,
            expected: 28,
        },
        TrustEconomicsError::CascadeProbabilityOutOfRange { value: -5 },
        TrustEconomicsError::ZeroAttackerCost,
        TrustEconomicsError::AsymmetryViolation {
            action: "allow".to_string(),
            benign_loss: 500,
            malicious_loss: 100,
        },
        TrustEconomicsError::VersionRegression {
            current: 3,
            attempted: 1,
        },
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
    assert!(errors[0].to_string().contains("10/28"));
    assert!(errors[1].to_string().contains("-5"));
    assert!(errors[2].to_string().contains("zero total cost"));
    assert!(errors[3].to_string().contains("allow"));
    assert!(errors[4].to_string().contains("current=3"));
}

#[test]
fn trust_economics_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(TrustEconomicsError::ZeroAttackerCost);
    assert!(!e.to_string().is_empty());
}

#[test]
fn trust_economics_error_serde_all_variants() {
    let errors: Vec<TrustEconomicsError> = vec![
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
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: TrustEconomicsError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

// ===========================================================================
// BlastRadiusEstimate — radius_at_time with cascade
// ===========================================================================

#[test]
fn blast_radius_at_time_with_cascade_and_growth() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
        affected_data: ["data-1".into()].into_iter().collect(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 500_000, // 50%
        growth_rate_per_sec: 100_000,
    };
    // base = 3 * 1M = 3_000_000, growth = 100_000 * 10 = 1_000_000
    // total = 4_000_000, cascade_factor = 1_000_000 + 500_000 = 1_500_000
    // radius = 4_000_000 * 1_500_000 / 1_000_000 = 6_000_000
    assert_eq!(br.radius_at_time(10), 6_000_000);
}

#[test]
fn blast_radius_at_time_zero_growth_zero_cascade() {
    let br = BlastRadiusEstimate {
        affected_extensions: ["ext-a".into()].into_iter().collect(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    // base = 1 * 1M = 1_000_000, factor = 1M, result = 1_000_000.
    assert_eq!(br.radius_at_time(0), 1_000_000);
    assert_eq!(br.radius_at_time(100), 1_000_000);
}

#[test]
fn blast_radius_validate_boundary_values() {
    // Exactly 0: valid.
    let br = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 0,
        growth_rate_per_sec: 0,
    };
    assert!(br.validate().is_ok());

    // Exactly MILLIONTHS: valid.
    let br2 = BlastRadiusEstimate {
        cascade_probability: MILLIONTHS,
        ..br.clone()
    };
    assert!(br2.validate().is_ok());
}

// ===========================================================================
// TrustEconomicsModelInputs — validation edge cases
// ===========================================================================

#[test]
fn model_inputs_validate_version_same_is_regression() {
    let m = sample_model_inputs();
    // Same version (1) should be a regression.
    assert!(matches!(
        m.validate_version_update(1),
        Err(TrustEconomicsError::VersionRegression {
            current: 1,
            attempted: 1
        })
    ));
}

#[test]
fn model_inputs_validate_version_zero_is_regression() {
    let m = sample_model_inputs();
    assert!(matches!(
        m.validate_version_update(0),
        Err(TrustEconomicsError::VersionRegression {
            current: 1,
            attempted: 0
        })
    ));
}

#[test]
fn model_inputs_validate_version_increment_ok() {
    let m = sample_model_inputs();
    assert!(m.validate_version_update(2).is_ok());
    assert!(m.validate_version_update(100).is_ok());
}

// ===========================================================================
// TrustEconomicsModelInputs — serde
// ===========================================================================

#[test]
fn model_inputs_serde_roundtrip_full() {
    let m = sample_model_inputs();
    let json = serde_json::to_string(&m).unwrap();
    let restored: TrustEconomicsModelInputs = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

#[test]
fn model_inputs_serde_deterministic() {
    let m1 = sample_model_inputs();
    let m2 = sample_model_inputs();
    let json1 = serde_json::to_string(&m1).unwrap();
    let json2 = serde_json::to_string(&m2).unwrap();
    assert_eq!(json1, json2);
}

// ===========================================================================
// AttackerCostModel — strategy ROI edge cases
// ===========================================================================

#[test]
fn attacker_strategy_roi_zero_adjusted_cost() {
    let m = AttackerCostModel {
        discovery_cost: 0,
        development_cost: 0,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 10_000_000,
        strategy_adjustments: {
            let mut map = BTreeMap::new();
            map.insert(
                "zero_cost".to_string(),
                StrategyCostAdjustment {
                    strategy_name: "zero_cost".to_string(),
                    discovery_delta: 0,
                    development_delta: 0,
                    evasion_delta: 0,
                    justification: "test".to_string(),
                },
            );
            map
        },
        version: 1,
        calibration_source: "test".into(),
    };
    // adjusted_cost = 0 + 0 + 0 + 0 = 0 → strategy_roi returns None.
    assert_eq!(m.strategy_roi("zero_cost"), None);
}

#[test]
fn attacker_strategy_roi_unknown_strategy() {
    let m = sample_attacker_model();
    assert_eq!(m.strategy_roi("nonexistent"), None);
    assert_eq!(m.adjusted_cost("nonexistent"), None);
}

#[test]
fn attacker_roi_break_even() {
    let m = AttackerCostModel {
        discovery_cost: 5_000_000,
        development_cost: 5_000_000,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 10_000_000, // gain == cost
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "test".into(),
    };
    // ROI = (10M - 10M) * 1M / 10M = 0.
    assert_eq!(m.expected_roi(), Some(0));
}

// ===========================================================================
// Integration — full model pipeline
// ===========================================================================

#[test]
fn integration_build_validate_compute_roi() {
    let inputs = sample_model_inputs();

    // Validate model.
    inputs.validate().unwrap();

    // Compute attacker ROI.
    let roi = inputs.attacker_cost.expected_roi().unwrap();
    assert!(roi > 0, "expected positive ROI with sample model");

    // Classify alert level.
    let alert = classify_roi_alert_level(roi);
    assert_eq!(alert, RoiAlertLevel::Profitable);

    // Verify loss matrix completeness.
    assert!(inputs.loss_matrix.is_complete());
    assert_eq!(inputs.loss_matrix.cell_count(), 28);
}

#[test]
fn integration_fleet_assessment_pipeline() {
    let model = sample_attacker_model();
    let roi = model.expected_roi().unwrap();

    // Build assessments for multiple extensions.
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-1".to_string(),
        AttackerRoiAssessment::new("ext-1", roi, &[roi - 200_000, roi]),
    );
    assessments.insert(
        "ext-2".to_string(),
        AttackerRoiAssessment::new("ext-2", 100_000, &[200_000, 100_000]),
    );
    assessments.insert(
        "ext-3".to_string(),
        AttackerRoiAssessment::new("ext-3", 3_000_000, &[2_000_000, 3_000_000]),
    );

    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.extension_count, 3);
    assert!(summary.max_roi_millionths >= summary.min_roi_millionths);
    assert!(summary.highly_profitable_extensions >= 1);
}

#[test]
fn integration_conservative_matrix_benign_allow_cheapest() {
    let m = default_conservative_loss_matrix();
    let benign_allow = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
    // For benign extensions, "allow" should always be the cheapest action.
    for action in &ContainmentAction::ALL {
        let cost = m.total_loss(TrueState::Benign, *action);
        assert!(
            cost >= benign_allow,
            "benign+{action} ({cost}) should be >= benign+allow ({benign_allow})"
        );
    }
}

#[test]
fn integration_conservative_matrix_compromised_worst_false_negative() {
    let m = default_conservative_loss_matrix();
    // Compromised+Allow should be the worst possible outcome.
    let worst = m.total_loss(TrueState::Compromised, ContainmentAction::Allow);
    for state in &TrueState::ALL {
        for action in &ContainmentAction::ALL {
            let cost = m.total_loss(*state, *action);
            assert!(
                worst >= cost,
                "compromised+allow ({worst}) should be >= {state}+{action} ({cost})"
            );
        }
    }
}

#[test]
fn integration_model_version_lifecycle() {
    let m = sample_model_inputs();
    // Version 1 — upgrade to 2 should be ok.
    m.validate_version_update(2).unwrap();
    // But downgrade/same should fail.
    assert!(m.validate_version_update(1).is_err());
    assert!(m.validate_version_update(0).is_err());
}
