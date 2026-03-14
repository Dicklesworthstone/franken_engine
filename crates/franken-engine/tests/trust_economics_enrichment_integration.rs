#![forbid(unsafe_code)]

//! Enrichment integration tests for the trust_economics module.

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

use frankenengine_engine::trust_economics::{
    ActionCost, AttackerCostModel, AttackerRoiAssessment, BlastRadiusEstimate, ContainmentAction,
    ContainmentCostModel, DecomposedLossMatrix, FleetRoiSummary, MILLIONTHS, RoiAlertLevel,
    RoiTrend, SubLoss, TrueState, TrustEconomicsError, classify_roi_alert_level,
    classify_roi_trend, default_conservative_loss_matrix, summarize_fleet_roi,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_attacker_cost() -> AttackerCostModel {
    AttackerCostModel {
        discovery_cost: 200_000,
        development_cost: 300_000,
        deployment_cost: 100_000,
        persistence_cost: 50_000,
        evasion_cost: 100_000,
        expected_gain: 1_500_000,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "manual".to_string(),
    }
}

fn make_containment_cost() -> ContainmentCostModel {
    let mut model = ContainmentCostModel::new(1, "enterprise", "manual");
    for action in ContainmentAction::ALL {
        model.set(
            action,
            ActionCost {
                execution_latency_us: 1000,
                resource_consumption: 50_000,
                collateral_impact: 10_000,
                operator_burden: 20_000,
                reversibility_cost: 5_000,
            },
        );
    }
    model
}

// ---------------------------------------------------------------------------
// TrueState — Copy / BTreeSet / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_true_state_copy_semantics() {
    let a = TrueState::Benign;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_true_state_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for s in TrueState::ALL {
        set.insert(s);
    }
    set.insert(TrueState::Benign);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_true_state_clone_independence() {
    let a = TrueState::Malicious;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_true_state_debug_all_unique() {
    let dbgs: BTreeSet<String> = TrueState::ALL.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn enrichment_true_state_display_all_unique() {
    let displays: BTreeSet<String> = TrueState::ALL.iter().map(|v| format!("{}", v)).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_true_state_serde_roundtrip_all() {
    for s in TrueState::ALL {
        let json = serde_json::to_string(&s).unwrap();
        let rt: TrueState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

// ---------------------------------------------------------------------------
// ContainmentAction — Copy / BTreeSet / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_action_copy_semantics() {
    let a = ContainmentAction::Allow;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_containment_action_btreeset_dedup_7() {
    let mut set = BTreeSet::new();
    for a in ContainmentAction::ALL {
        set.insert(a);
    }
    set.insert(ContainmentAction::Allow);
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_containment_action_clone_independence() {
    let a = ContainmentAction::Quarantine;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_containment_action_debug_all_unique() {
    let dbgs: BTreeSet<String> = ContainmentAction::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 7);
}

#[test]
fn enrichment_containment_action_display_all_unique() {
    let displays: BTreeSet<String> = ContainmentAction::ALL
        .iter()
        .map(|v| format!("{}", v))
        .collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_containment_action_serde_roundtrip_all() {
    for a in ContainmentAction::ALL {
        let json = serde_json::to_string(&a).unwrap();
        let rt: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, rt);
    }
}

// ---------------------------------------------------------------------------
// RoiAlertLevel — Copy / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_roi_alert_level_copy_semantics() {
    let a = RoiAlertLevel::Unprofitable;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_roi_alert_level_display_all_unique() {
    let levels = [
        RoiAlertLevel::Unprofitable,
        RoiAlertLevel::Neutral,
        RoiAlertLevel::Profitable,
        RoiAlertLevel::HighlyProfitable,
    ];
    let displays: BTreeSet<String> = levels.iter().map(|l| format!("{}", l)).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_roi_alert_level_serde_roundtrip_all() {
    let levels = [
        RoiAlertLevel::Unprofitable,
        RoiAlertLevel::Neutral,
        RoiAlertLevel::Profitable,
        RoiAlertLevel::HighlyProfitable,
    ];
    for l in &levels {
        let json = serde_json::to_string(l).unwrap();
        let rt: RoiAlertLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*l, rt);
    }
}

// ---------------------------------------------------------------------------
// RoiTrend — Copy / Clone / Debug / Display / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_roi_trend_copy_semantics() {
    let a = RoiTrend::Rising;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_roi_trend_display_all_unique() {
    let trends = [RoiTrend::Rising, RoiTrend::Stable, RoiTrend::Falling];
    let displays: BTreeSet<String> = trends.iter().map(|t| format!("{}", t)).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_roi_trend_serde_roundtrip_all() {
    let trends = [RoiTrend::Rising, RoiTrend::Stable, RoiTrend::Falling];
    for t in &trends {
        let json = serde_json::to_string(t).unwrap();
        let rt: RoiTrend = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, rt);
    }
}

// ---------------------------------------------------------------------------
// TrustEconomicsError — Clone / Debug / Display / Error / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trust_economics_error_clone_independence() {
    let a = TrustEconomicsError::ZeroAttackerCost;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_trust_economics_error_display_all_unique() {
    let errors: Vec<TrustEconomicsError> = vec![
        TrustEconomicsError::IncompleteLossMatrix {
            populated: 10,
            expected: 28,
        },
        TrustEconomicsError::CascadeProbabilityOutOfRange { value: 2_000_000 },
        TrustEconomicsError::ZeroAttackerCost,
        TrustEconomicsError::AsymmetryViolation {
            action: "allow".to_string(),
            benign_loss: 100,
            malicious_loss: 50,
        },
        TrustEconomicsError::VersionRegression {
            current: 2,
            attempted: 1,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{}", e)).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_trust_economics_error_is_std_error() {
    let e = TrustEconomicsError::ZeroAttackerCost;
    let _err_ref: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_trust_economics_error_serde_roundtrip_all() {
    let errors: Vec<TrustEconomicsError> = vec![
        TrustEconomicsError::IncompleteLossMatrix {
            populated: 10,
            expected: 28,
        },
        TrustEconomicsError::CascadeProbabilityOutOfRange { value: 2_000_000 },
        TrustEconomicsError::ZeroAttackerCost,
        TrustEconomicsError::AsymmetryViolation {
            action: "allow".to_string(),
            benign_loss: 100,
            malicious_loss: 50,
        },
        TrustEconomicsError::VersionRegression {
            current: 2,
            attempted: 1,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: TrustEconomicsError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ---------------------------------------------------------------------------
// SubLoss — Clone / Debug / JSON / zero / total / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sub_loss_copy_semantics() {
    let a = SubLoss::zero();
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_sub_loss_zero_all_zero() {
    let z = SubLoss::zero();
    assert_eq!(z.direct_damage, 0);
    assert_eq!(z.operational_disruption, 0);
    assert_eq!(z.trust_damage, 0);
    assert_eq!(z.containment_cost, 0);
    assert_eq!(z.false_action_cost, 0);
    assert_eq!(z.total(), 0);
}

#[test]
fn enrichment_sub_loss_total_sums_all() {
    let s = SubLoss {
        direct_damage: 100_000,
        operational_disruption: 200_000,
        trust_damage: 300_000,
        containment_cost: 50_000,
        false_action_cost: 25_000,
    };
    assert_eq!(s.total(), 675_000);
}

#[test]
fn enrichment_sub_loss_serde_roundtrip() {
    let s = SubLoss {
        direct_damage: 100_000,
        operational_disruption: 200_000,
        trust_damage: 300_000,
        containment_cost: 50_000,
        false_action_cost: 25_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let rt: SubLoss = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

// ---------------------------------------------------------------------------
// DecomposedLossMatrix — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decomposed_loss_matrix_clone_independence() {
    let m = default_conservative_loss_matrix();
    let m2 = m.clone();
    assert_eq!(m, m2);
}

#[test]
fn enrichment_decomposed_loss_matrix_is_complete() {
    let m = default_conservative_loss_matrix();
    assert!(m.is_complete());
    assert_eq!(m.cell_count(), 28); // 4 states * 7 actions
}

#[test]
fn enrichment_decomposed_loss_matrix_asymmetry_violations_returns_vec() {
    let m = default_conservative_loss_matrix();
    // The conservative matrix may have asymmetry violations (e.g. Suspend
    // costs more against benign than malicious). Just verify the method
    // returns a well-formed list with tuples (action, benign, malicious).
    let violations = m.asymmetry_violations();
    for (action, benign, malicious) in &violations {
        let _ = format!("{:?}", action);
        assert!(
            *malicious < *benign,
            "each violation should have malicious < benign"
        );
    }
}

#[test]
fn enrichment_decomposed_loss_matrix_get_returns_some() {
    let m = default_conservative_loss_matrix();
    for state in TrueState::ALL {
        for action in ContainmentAction::ALL {
            assert!(
                m.get(state, action).is_some(),
                "missing cell: ({:?}, {:?})",
                state,
                action
            );
        }
    }
}

#[test]
fn enrichment_decomposed_loss_matrix_serde_roundtrip() {
    let m = default_conservative_loss_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let rt: DecomposedLossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}

// ---------------------------------------------------------------------------
// AttackerCostModel — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attacker_cost_model_clone_independence() {
    let a = make_attacker_cost();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_attacker_cost_model_total_base_cost() {
    let m = make_attacker_cost();
    assert_eq!(m.total_base_cost(), 750_000);
}

#[test]
fn enrichment_attacker_cost_model_expected_roi() {
    let m = make_attacker_cost();
    let roi = m.expected_roi();
    assert!(roi.is_some());
    // ROI = (1_500_000 - 750_000) * 1_000_000 / 750_000 = 1_000_000
    assert_eq!(roi.unwrap(), 1_000_000);
}

#[test]
fn enrichment_attacker_cost_model_serde_roundtrip() {
    let m = make_attacker_cost();
    let json = serde_json::to_string(&m).unwrap();
    let rt: AttackerCostModel = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}

// ---------------------------------------------------------------------------
// classify_roi_alert_level / classify_roi_trend
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_roi_alert_level_thresholds() {
    assert_eq!(classify_roi_alert_level(0), RoiAlertLevel::Unprofitable);
    assert_eq!(classify_roi_alert_level(500_000), RoiAlertLevel::Neutral);
    assert_eq!(
        classify_roi_alert_level(1_500_000),
        RoiAlertLevel::Profitable
    );
    assert_eq!(
        classify_roi_alert_level(2_500_000),
        RoiAlertLevel::HighlyProfitable
    );
}

#[test]
fn enrichment_classify_roi_trend_rising() {
    let history = [100_000i64, 200_000, 300_000, 400_000, 500_000];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Rising);
}

#[test]
fn enrichment_classify_roi_trend_falling() {
    let history = [500_000i64, 400_000, 300_000, 200_000, 100_000];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Falling);
}

#[test]
fn enrichment_classify_roi_trend_stable() {
    let history = [500_000i64, 500_001, 500_002];
    assert_eq!(classify_roi_trend(&history), RoiTrend::Stable);
}

// ---------------------------------------------------------------------------
// AttackerRoiAssessment — Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attacker_roi_assessment_clone_independence() {
    let a = AttackerRoiAssessment::new("ext-1", 1_500_000, &[1_000_000, 1_500_000]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_attacker_roi_assessment_serde_roundtrip() {
    let a = AttackerRoiAssessment::new("ext-1", 1_500_000, &[1_000_000, 1_500_000]);
    let json = serde_json::to_string(&a).unwrap();
    let rt: AttackerRoiAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, rt);
}

// ---------------------------------------------------------------------------
// FleetRoiSummary / summarize_fleet_roi
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fleet_roi_summary_empty() {
    let assessments = BTreeMap::new();
    let summary = summarize_fleet_roi(&assessments);
    assert_eq!(summary.extension_count, 0);
}

#[test]
fn enrichment_fleet_roi_summary_serde_roundtrip() {
    let mut assessments = BTreeMap::new();
    assessments.insert(
        "ext-1".to_string(),
        AttackerRoiAssessment::new("ext-1", 1_500_000, &[]),
    );
    let summary = summarize_fleet_roi(&assessments);
    let json = serde_json::to_string(&summary).unwrap();
    let rt: FleetRoiSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, rt);
}

// ---------------------------------------------------------------------------
// ContainmentCostModel — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_cost_model_clone_independence() {
    let m = make_containment_cost();
    let m2 = m.clone();
    assert_eq!(m, m2);
}

#[test]
fn enrichment_containment_cost_model_get_all_actions() {
    let m = make_containment_cost();
    for action in ContainmentAction::ALL {
        assert!(m.get(action).is_some());
    }
}

#[test]
fn enrichment_containment_cost_model_serde_roundtrip() {
    let m = make_containment_cost();
    let json = serde_json::to_string(&m).unwrap();
    let rt: ContainmentCostModel = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}

// ---------------------------------------------------------------------------
// BlastRadiusEstimate — Clone / Debug / methods / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_blast_radius_clone_independence() {
    let b = BlastRadiusEstimate {
        affected_extensions: BTreeSet::from(["ext-1".to_string()]),
        affected_data: BTreeSet::from(["data-1".to_string()]),
        affected_nodes: BTreeSet::from(["node-1".to_string()]),
        cascade_probability: 500_000,
        growth_rate_per_sec: 100_000,
    };
    let b2 = b.clone();
    assert_eq!(b, b2);
}

#[test]
fn enrichment_blast_radius_total_affected() {
    let b = BlastRadiusEstimate {
        affected_extensions: BTreeSet::from(["ext-1".to_string(), "ext-2".to_string()]),
        affected_data: BTreeSet::from(["data-1".to_string()]),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 500_000,
        growth_rate_per_sec: 0,
    };
    assert_eq!(b.total_affected_entities(), 3);
}

#[test]
fn enrichment_blast_radius_validate_ok() {
    let b = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 500_000,
        growth_rate_per_sec: 0,
    };
    assert!(b.validate().is_ok());
}

#[test]
fn enrichment_blast_radius_validate_out_of_range() {
    let b = BlastRadiusEstimate {
        affected_extensions: BTreeSet::new(),
        affected_data: BTreeSet::new(),
        affected_nodes: BTreeSet::new(),
        cascade_probability: 2_000_000,
        growth_rate_per_sec: 0,
    };
    assert!(b.validate().is_err());
}

#[test]
fn enrichment_blast_radius_serde_roundtrip() {
    let b = BlastRadiusEstimate {
        affected_extensions: BTreeSet::from(["ext-1".to_string()]),
        affected_data: BTreeSet::from(["data-1".to_string()]),
        affected_nodes: BTreeSet::from(["node-1".to_string()]),
        cascade_probability: 500_000,
        growth_rate_per_sec: 100_000,
    };
    let json = serde_json::to_string(&b).unwrap();
    let rt: BlastRadiusEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(b, rt);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_conservative_matrix() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&default_conservative_loss_matrix()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "matrix should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_matrix_benign_allow_zero_loss() {
    let m = default_conservative_loss_matrix();
    let loss = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
    assert_eq!(loss, 0);
}

#[test]
fn enrichment_cross_cutting_matrix_allow_asymmetry() {
    // For Allow, malicious should cost more than benign (allowing malicious is bad).
    let m = default_conservative_loss_matrix();
    let benign_allow = m.total_loss(TrueState::Benign, ContainmentAction::Allow);
    let malicious_allow = m.total_loss(TrueState::Malicious, ContainmentAction::Allow);
    assert!(
        malicious_allow >= benign_allow,
        "Allow should cost more for malicious ({}) than benign ({})",
        malicious_allow,
        benign_allow
    );
}

#[test]
fn enrichment_cross_cutting_scalar_totals_count() {
    let m = default_conservative_loss_matrix();
    let totals = m.to_scalar_totals();
    assert_eq!(totals.len(), 28);
}

#[test]
fn enrichment_cross_cutting_roi_assessment_alert_consistent() {
    let a = AttackerRoiAssessment::new("ext-1", 1_500_000, &[1_000_000, 1_500_000]);
    assert_eq!(a.alert, classify_roi_alert_level(a.roi_millionths));
}
