//! Enrichment integration tests for `moonshot_contract`.
//!
//! Covers: serde round-trips for all types, boundary conditions on validation,
//! deterministic serialization, EV model computations, kill criteria evaluation,
//! stage obligation checking, Display implementations, clone independence,
//! and stress scenarios.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeMap;

use frankenengine_engine::moonshot_contract::{
    ArtifactObligation, ArtifactType, ContractError, ContractVersion, DistributionType, EvModel,
    Hypothesis, KillCriterion, KillTrigger, MeasurementMethod, MetricDirection, MoonshotContract,
    MoonshotStage, RiskBudget, RiskDimension, RollbackPlan, RollbackStep, TargetMetric,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_hypothesis() -> Hypothesis {
    Hypothesis {
        problem: "High detection latency".into(),
        mechanism: "Fleet-wide evidence sharing".into(),
        expected_outcome: "50% latency reduction".into(),
        falsification_criteria: vec!["No improvement after 90 days".into()],
    }
}

fn make_metrics() -> Vec<TargetMetric> {
    vec![TargetMetric {
        metric_id: "latency_p50".into(),
        description: "Median detection latency".into(),
        threshold_millionths: 250_000_000,
        direction: MetricDirection::LowerIsBetter,
        measurement_method: MeasurementMethod::FleetTelemetry,
        evaluation_cadence_ns: 86_400_000_000_000,
    }]
}

fn make_ev_model() -> EvModel {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 600_000i64);
    EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 500_000,
        benefit_on_success_millionths: 5_000_000,
        harm_on_failure_millionths: -200_000,
    }
}

fn make_risk_budget() -> RiskBudget {
    let mut caps = BTreeMap::new();
    caps.insert(RiskDimension::SecurityRegression, 50_000u64);
    RiskBudget {
        dimension_caps: caps,
    }
}

fn make_obligations() -> Vec<ArtifactObligation> {
    vec![ArtifactObligation {
        obligation_id: "proof-research".into(),
        required_at_stage: MoonshotStage::Research,
        artifact_type: ArtifactType::Proof,
        description: "Proof of concept".into(),
        blocking: true,
    }]
}

fn make_kill_criteria() -> Vec<KillCriterion> {
    vec![
        KillCriterion {
            criterion_id: "time-kill".into(),
            trigger: KillTrigger::TimeExpiry,
            condition: "180 days without promotion".into(),
            threshold_millionths: None,
            max_duration_ns: Some(15_552_000_000_000_000),
        },
        KillCriterion {
            criterion_id: "regression-kill".into(),
            trigger: KillTrigger::MetricRegression,
            condition: "Latency > 500ms".into(),
            threshold_millionths: Some(500_000_000),
            max_duration_ns: None,
        },
    ]
}

fn make_rollback() -> RollbackPlan {
    RollbackPlan {
        steps: vec![RollbackStep {
            step_number: 1,
            description: "Revert policy".into(),
            verification: "frankenctl revert".into(),
        }],
        artifact_references: vec!["checkpoint-1".into()],
        expected_state_after_rollback: "Pre-moonshot state restored".into(),
    }
}

fn make_contract() -> MoonshotContract {
    MoonshotContract {
        contract_id: "mc-test-001".into(),
        version: ContractVersion { major: 1, minor: 0 },
        hypothesis: make_hypothesis(),
        target_metrics: make_metrics(),
        ev_model: make_ev_model(),
        risk_budget: make_risk_budget(),
        artifact_obligations: make_obligations(),
        kill_criteria: make_kill_criteria(),
        rollback_plan: make_rollback(),
        current_stage: MoonshotStage::Research,
        epoch: ep(1),
        governance_signature: Some("sig:gov-001".into()),
        metadata: BTreeMap::new(),
    }
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_contract_serde_roundtrip() {
    let c = make_contract();
    let json = serde_json::to_string(&c).unwrap();
    let back: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn integ_contract_serde_pretty_roundtrip() {
    let c = make_contract();
    let json = serde_json::to_string_pretty(&c).unwrap();
    let back: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn integ_hypothesis_serde_roundtrip() {
    let h = make_hypothesis();
    let json = serde_json::to_string(&h).unwrap();
    let back: Hypothesis = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn integ_ev_model_serde_roundtrip() {
    let ev = make_ev_model();
    let json = serde_json::to_string(&ev).unwrap();
    let back: EvModel = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn integ_risk_budget_serde_roundtrip() {
    let rb = make_risk_budget();
    let json = serde_json::to_string(&rb).unwrap();
    let back: RiskBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, back);
}

#[test]
fn integ_rollback_plan_serde_roundtrip() {
    let rp = make_rollback();
    let json = serde_json::to_string(&rp).unwrap();
    let back: RollbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(rp, back);
}

#[test]
fn integ_all_moonshot_stages_serde_roundtrip() {
    for stage in MoonshotStage::all() {
        let json = serde_json::to_string(stage).unwrap();
        let back: MoonshotStage = serde_json::from_str(&json).unwrap();
        assert_eq!(*stage, back);
    }
}

#[test]
fn integ_all_distribution_types_serde_roundtrip() {
    for dt in [
        DistributionType::PointEstimate,
        DistributionType::Uniform,
        DistributionType::Beta,
        DistributionType::LogNormal,
    ] {
        let json = serde_json::to_string(&dt).unwrap();
        let back: DistributionType = serde_json::from_str(&json).unwrap();
        assert_eq!(dt, back);
    }
}

#[test]
fn integ_all_risk_dimensions_serde_roundtrip() {
    for dim in [
        RiskDimension::SecurityRegression,
        RiskDimension::PerformanceRegression,
        RiskDimension::OperationalBurden,
        RiskDimension::CrossInitiativeInterference,
    ] {
        let json = serde_json::to_string(&dim).unwrap();
        let back: RiskDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(dim, back);
    }
}

#[test]
fn integ_all_artifact_types_serde_roundtrip() {
    for at in [
        ArtifactType::Proof,
        ArtifactType::BenchmarkResult,
        ArtifactType::ConformanceEvidence,
        ArtifactType::OperatorDocumentation,
        ArtifactType::RiskAssessment,
    ] {
        let json = serde_json::to_string(&at).unwrap();
        let back: ArtifactType = serde_json::from_str(&json).unwrap();
        assert_eq!(at, back);
    }
}

#[test]
fn integ_all_kill_triggers_serde_roundtrip() {
    for kt in [
        KillTrigger::BudgetExhaustedNoSignal,
        KillTrigger::MetricRegression,
        KillTrigger::ReproducibilityFailure,
        KillTrigger::RiskConstraintViolation,
        KillTrigger::TimeExpiry,
    ] {
        let json = serde_json::to_string(&kt).unwrap();
        let back: KillTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(kt, back);
    }
}

#[test]
fn integ_all_measurement_methods_serde_roundtrip() {
    for mm in [
        MeasurementMethod::Benchmark,
        MeasurementMethod::EvidenceQuery,
        MeasurementMethod::FleetTelemetry,
        MeasurementMethod::OperatorReview,
    ] {
        let json = serde_json::to_string(&mm).unwrap();
        let back: MeasurementMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(mm, back);
    }
}

#[test]
fn integ_contract_error_serde_all_variants() {
    let errors = [
        ContractError::EmptyContractId,
        ContractError::InvalidHypothesis {
            reason: "bad".into(),
        },
        ContractError::EmptyTargetMetrics,
        ContractError::InvalidEvModel {
            reason: "bad".into(),
        },
        ContractError::InvalidRiskBudget {
            reason: "bad".into(),
        },
        ContractError::EmptyKillCriteria,
        ContractError::InvalidRollback {
            reason: "bad".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// Determinism tests
// ===========================================================================

#[test]
fn integ_contract_deterministic_serialization() {
    let c1 = make_contract();
    let c2 = make_contract();
    assert_eq!(
        serde_json::to_string(&c1).unwrap(),
        serde_json::to_string(&c2).unwrap()
    );
}

#[test]
fn integ_contract_metadata_deterministic_regardless_of_insert_order() {
    let mut c1 = make_contract();
    c1.metadata.insert("alpha".into(), "a".into());
    c1.metadata.insert("beta".into(), "b".into());
    c1.metadata.insert("gamma".into(), "c".into());

    let mut c2 = make_contract();
    c2.metadata.insert("gamma".into(), "c".into());
    c2.metadata.insert("alpha".into(), "a".into());
    c2.metadata.insert("beta".into(), "b".into());

    assert_eq!(
        serde_json::to_string(&c1).unwrap(),
        serde_json::to_string(&c2).unwrap()
    );
}

#[test]
fn integ_deterministic_validate_replay() {
    let c = make_contract();
    let r1 = c.validate();
    let r2 = c.validate();
    assert_eq!(r1, r2);
}

#[test]
fn integ_deterministic_kill_criteria_replay() {
    let c = make_contract();
    let metrics = BTreeMap::new();
    let t1 = c.check_kill_criteria(&metrics, 20_000_000_000_000_000, 950_000);
    let t2 = c.check_kill_criteria(&metrics, 20_000_000_000_000_000, 950_000);
    assert_eq!(t1.len(), t2.len());
    for (a, b) in t1.iter().zip(t2.iter()) {
        assert_eq!(a.criterion_id, b.criterion_id);
    }
}

// ===========================================================================
// Validation tests
// ===========================================================================

#[test]
fn integ_contract_validates_ok() {
    make_contract().validate().unwrap();
}

#[test]
fn integ_contract_rejects_empty_contract_id() {
    let mut c = make_contract();
    c.contract_id = String::new();
    assert!(matches!(c.validate(), Err(ContractError::EmptyContractId)));
}

#[test]
fn integ_hypothesis_rejects_empty_problem() {
    let mut c = make_contract();
    c.hypothesis.problem = String::new();
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidHypothesis { .. })
    ));
}

#[test]
fn integ_hypothesis_rejects_empty_mechanism() {
    let mut c = make_contract();
    c.hypothesis.mechanism = String::new();
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidHypothesis { .. })
    ));
}

#[test]
fn integ_hypothesis_rejects_empty_outcome() {
    let mut c = make_contract();
    c.hypothesis.expected_outcome = String::new();
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidHypothesis { .. })
    ));
}

#[test]
fn integ_hypothesis_rejects_empty_falsification() {
    let mut c = make_contract();
    c.hypothesis.falsification_criteria = vec![];
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidHypothesis { .. })
    ));
}

#[test]
fn integ_contract_rejects_empty_metrics() {
    let mut c = make_contract();
    c.target_metrics = vec![];
    assert!(matches!(
        c.validate(),
        Err(ContractError::EmptyTargetMetrics)
    ));
}

#[test]
fn integ_contract_rejects_empty_kill_criteria() {
    let mut c = make_contract();
    c.kill_criteria = vec![];
    assert!(matches!(
        c.validate(),
        Err(ContractError::EmptyKillCriteria)
    ));
}

#[test]
fn integ_rollback_rejects_empty_steps() {
    let mut c = make_contract();
    c.rollback_plan.steps = vec![];
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidRollback { .. })
    ));
}

#[test]
fn integ_rollback_rejects_empty_expected_state() {
    let mut c = make_contract();
    c.rollback_plan.expected_state_after_rollback = String::new();
    assert!(matches!(
        c.validate(),
        Err(ContractError::InvalidRollback { .. })
    ));
}

// ===========================================================================
// EV model tests
// ===========================================================================

#[test]
fn integ_ev_model_validates_ok() {
    make_ev_model().validate().unwrap();
}

#[test]
fn integ_ev_model_rejects_zero_cost() {
    let mut ev = make_ev_model();
    ev.cost_millionths = 0;
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_model_rejects_negative_cost() {
    let mut ev = make_ev_model();
    ev.cost_millionths = -100;
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_model_point_estimate_requires_value() {
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_model_beta_requires_alpha_beta() {
    let ev = EvModel {
        success_distribution: DistributionType::Beta,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_model_uniform_requires_low_high() {
    let ev = EvModel {
        success_distribution: DistributionType::Uniform,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_model_lognormal_requires_mu_sigma() {
    let ev = EvModel {
        success_distribution: DistributionType::LogNormal,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    assert!(matches!(
        ev.validate(),
        Err(ContractError::InvalidEvModel { .. })
    ));
}

#[test]
fn integ_ev_net_ev_point_estimate_basic() {
    let ev = make_ev_model();
    // P=0.6, benefit=5.0, harm=0.2, cost=0.5
    // EV = 0.6*5.0 - 0.4*0.2 - 0.5 = 3.0 - 0.08 - 0.5 = 2.42
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, 2_420_000);
}

#[test]
fn integ_ev_net_ev_zero_probability() {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 0i64);
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 500_000,
        benefit_on_success_millionths: 5_000_000,
        harm_on_failure_millionths: -200_000,
    };
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, -700_000);
}

#[test]
fn integ_ev_net_ev_certainty() {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 1_000_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 500_000,
        benefit_on_success_millionths: 5_000_000,
        harm_on_failure_millionths: -200_000,
    };
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, 4_500_000);
}

#[test]
fn integ_ev_net_ev_rejects_non_point_estimate() {
    let mut ev = make_ev_model();
    ev.success_distribution = DistributionType::Beta;
    ev.distribution_params.insert("alpha".into(), 2_000_000);
    ev.distribution_params.insert("beta".into(), 3_000_000);
    assert!(ev.net_ev_point_estimate().is_err());
}

#[test]
fn integ_ev_net_ev_large_values_no_overflow() {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 999_999i64);
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: i64::MAX / 2,
        benefit_on_success_millionths: i64::MAX / 2,
        harm_on_failure_millionths: i64::MIN / 2,
    };
    let _net = ev.net_ev_point_estimate().unwrap();
}

// ===========================================================================
// Stage obligation tests
// ===========================================================================

#[test]
fn integ_stage_obligations_met_when_completed() {
    let c = make_contract();
    assert!(c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
}

#[test]
fn integ_stage_obligations_not_met_when_missing() {
    let c = make_contract();
    assert!(!c.stage_obligations_met(MoonshotStage::Research, &[]));
}

#[test]
fn integ_stage_obligations_met_no_obligations_for_stage() {
    let c = make_contract();
    assert!(c.stage_obligations_met(MoonshotStage::Production, &[]));
}

#[test]
fn integ_stage_obligations_non_blocking_ignored() {
    let mut c = make_contract();
    c.artifact_obligations.push(ArtifactObligation {
        obligation_id: "optional-doc".into(),
        required_at_stage: MoonshotStage::Research,
        artifact_type: ArtifactType::OperatorDocumentation,
        description: "Optional".into(),
        blocking: false,
    });
    assert!(c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
}

// ===========================================================================
// Kill criteria tests
// ===========================================================================

#[test]
fn integ_kill_time_expiry_triggered() {
    let c = make_contract();
    let metrics = BTreeMap::new();
    let triggered = c.check_kill_criteria(&metrics, 17_280_000_000_000_000, 0);
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
}

#[test]
fn integ_kill_time_expiry_not_triggered_at_boundary() {
    let c = make_contract();
    let metrics = BTreeMap::new();
    let triggered = c.check_kill_criteria(&metrics, 15_552_000_000_000_000, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
}

#[test]
fn integ_kill_metric_regression_triggered() {
    let c = make_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("latency_p50".into(), 600_000_000i64);
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
}

#[test]
fn integ_kill_no_trigger_improving_metric() {
    let c = make_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("latency_p50".into(), 100_000_000i64);
    let triggered = c.check_kill_criteria(&metrics, 1_000_000_000, 50_000);
    assert!(triggered.is_empty());
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_moonshot_stage_display_all_unique() {
    let mut displays = std::collections::BTreeSet::new();
    for stage in MoonshotStage::all() {
        displays.insert(stage.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn integ_distribution_type_display_all_unique() {
    let types = [
        DistributionType::PointEstimate,
        DistributionType::Uniform,
        DistributionType::Beta,
        DistributionType::LogNormal,
    ];
    let mut displays = std::collections::BTreeSet::new();
    for t in &types {
        displays.insert(t.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn integ_contract_error_display_all_unique() {
    let errors = [
        ContractError::EmptyContractId,
        ContractError::InvalidHypothesis { reason: "a".into() },
        ContractError::EmptyTargetMetrics,
        ContractError::InvalidEvModel { reason: "b".into() },
        ContractError::InvalidRiskBudget { reason: "c".into() },
        ContractError::EmptyKillCriteria,
        ContractError::InvalidRollback { reason: "d".into() },
    ];
    let mut displays = std::collections::BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(displays.len(), 7);
}

#[test]
fn integ_contract_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ContractError::EmptyContractId);
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

#[test]
fn integ_contract_version_display() {
    let v = ContractVersion { major: 3, minor: 7 };
    assert_eq!(v.to_string(), "3.7");
}

// ===========================================================================
// Clone independence tests
// ===========================================================================

#[test]
fn integ_contract_clone_independence() {
    let mut c = make_contract();
    let cloned = c.clone();
    c.contract_id = "mutated".into();
    c.metadata.insert("new".into(), "val".into());
    assert_ne!(c.contract_id, cloned.contract_id);
    assert!(cloned.metadata.is_empty());
}

#[test]
fn integ_hypothesis_clone_independence() {
    let mut h = make_hypothesis();
    let cloned = h.clone();
    h.problem = "mutated".into();
    assert_ne!(h.problem, cloned.problem);
}

#[test]
fn integ_ev_model_clone_independence() {
    let mut ev = make_ev_model();
    let cloned = ev.clone();
    ev.cost_millionths = 999_999;
    assert_ne!(ev.cost_millionths, cloned.cost_millionths);
}

// ===========================================================================
// Boundary and stress tests
// ===========================================================================

#[test]
fn integ_contract_with_many_obligations_validates() {
    let mut c = make_contract();
    for i in 0..50 {
        c.artifact_obligations.push(ArtifactObligation {
            obligation_id: format!("stress-{i}"),
            required_at_stage: MoonshotStage::all()[i % 4],
            artifact_type: ArtifactType::Proof,
            description: format!("Stress obligation {i}"),
            blocking: i % 2 == 0,
        });
    }
    c.validate().unwrap();
}

#[test]
fn integ_contract_with_many_metadata_entries_serde() {
    let mut c = make_contract();
    for i in 0..50 {
        c.metadata.insert(format!("key-{i:03}"), format!("val-{i}"));
    }
    let json = serde_json::to_string(&c).unwrap();
    let back: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn integ_contract_no_governance_signature() {
    let mut c = make_contract();
    c.governance_signature = None;
    c.validate().unwrap();
    let json = serde_json::to_string(&c).unwrap();
    let back: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert!(back.governance_signature.is_none());
}

#[test]
fn integ_contract_all_stages_cycle() {
    for stage in MoonshotStage::all() {
        let mut c = make_contract();
        c.current_stage = *stage;
        c.validate().unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: MoonshotContract = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_stage, *stage);
    }
}

#[test]
fn integ_risk_budget_all_dimensions() {
    let mut caps = BTreeMap::new();
    caps.insert(RiskDimension::SecurityRegression, 50_000u64);
    caps.insert(RiskDimension::PerformanceRegression, 100_000);
    caps.insert(RiskDimension::OperationalBurden, 75_000);
    caps.insert(RiskDimension::CrossInitiativeInterference, 25_000);
    let rb = RiskBudget {
        dimension_caps: caps,
    };
    rb.validate().unwrap();
    let json = serde_json::to_string(&rb).unwrap();
    let back: RiskBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, back);
    assert_eq!(back.dimension_caps.len(), 4);
}

#[test]
fn integ_contract_version_ordering() {
    let v1 = ContractVersion { major: 1, minor: 0 };
    let v2 = ContractVersion { major: 1, minor: 1 };
    let v3 = ContractVersion { major: 2, minor: 0 };
    assert!(v1 < v2);
    assert!(v2 < v3);
}

#[test]
fn integ_ev_model_beta_valid() {
    let mut params = BTreeMap::new();
    params.insert("alpha".into(), 2_000_000i64);
    params.insert("beta".into(), 3_000_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::Beta,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    ev.validate().unwrap();
}

#[test]
fn integ_ev_model_uniform_valid() {
    let mut params = BTreeMap::new();
    params.insert("low".into(), 100_000i64);
    params.insert("high".into(), 900_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::Uniform,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    ev.validate().unwrap();
}

#[test]
fn integ_ev_model_lognormal_valid() {
    let mut params = BTreeMap::new();
    params.insert("mu".into(), 0i64);
    params.insert("sigma".into(), 500_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::LogNormal,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 1_000_000,
        harm_on_failure_millionths: -50_000,
    };
    ev.validate().unwrap();
}
