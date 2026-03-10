//! Integration tests for the `moonshot_contract` module.
//!
//! Exercises the public API from outside the crate: Display impls, enum
//! ordering, construction, validation, EV model arithmetic, stage obligation
//! checks, kill criteria evaluation, serde round-trips, deterministic
//! serialization, and edge cases.

#![forbid(unsafe_code)]
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

use frankenengine_engine::moonshot_contract::{
    ArtifactObligation, ArtifactType, ContractError, ContractVersion, DistributionType, EvModel,
    Hypothesis, KillCriterion, KillTrigger, MeasurementMethod, MetricDirection, MoonshotContract,
    MoonshotStage, RiskBudget, RiskDimension, RollbackPlan, RollbackStep, TargetMetric,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn valid_hypothesis() -> Hypothesis {
    Hypothesis {
        problem: "Excessive false-positive rate in supply-chain detection".into(),
        mechanism: "Bayesian posterior filtering with fleet evidence".into(),
        expected_outcome: "False positive rate drops below 1%".into(),
        falsification_criteria: vec![
            "No improvement after 60-day canary".into(),
            "Detection recall drops below 90%".into(),
        ],
    }
}

fn valid_metrics() -> Vec<TargetMetric> {
    vec![
        TargetMetric {
            metric_id: "fp_rate".into(),
            description: "False positive rate".into(),
            threshold_millionths: 10_000, // 1%
            direction: MetricDirection::LowerIsBetter,
            measurement_method: MeasurementMethod::EvidenceQuery,
            evaluation_cadence_ns: 86_400_000_000_000,
        },
        TargetMetric {
            metric_id: "recall".into(),
            description: "Detection recall".into(),
            threshold_millionths: 900_000, // 90%
            direction: MetricDirection::HigherIsBetter,
            measurement_method: MeasurementMethod::Benchmark,
            evaluation_cadence_ns: 604_800_000_000_000, // weekly
        },
    ]
}

fn valid_ev_model() -> EvModel {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 700_000i64); // 0.7 probability
    EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 1_000_000,                // 1.0
        benefit_on_success_millionths: 10_000_000, // 10.0
        harm_on_failure_millionths: -500_000,      // -0.5
    }
}

fn valid_risk_budget() -> RiskBudget {
    let mut caps = BTreeMap::new();
    caps.insert(RiskDimension::SecurityRegression, 50_000);
    caps.insert(RiskDimension::PerformanceRegression, 100_000);
    caps.insert(RiskDimension::OperationalBurden, 200_000);
    RiskBudget {
        dimension_caps: caps,
    }
}

fn valid_obligations() -> Vec<ArtifactObligation> {
    vec![
        ArtifactObligation {
            obligation_id: "proof-research".into(),
            required_at_stage: MoonshotStage::Research,
            artifact_type: ArtifactType::Proof,
            description: "Research-phase proof of concept".into(),
            blocking: true,
        },
        ArtifactObligation {
            obligation_id: "bench-shadow".into(),
            required_at_stage: MoonshotStage::Shadow,
            artifact_type: ArtifactType::BenchmarkResult,
            description: "Shadow benchmarks".into(),
            blocking: true,
        },
        ArtifactObligation {
            obligation_id: "docs-canary".into(),
            required_at_stage: MoonshotStage::Canary,
            artifact_type: ArtifactType::OperatorDocumentation,
            description: "Operator docs for canary stage".into(),
            blocking: false,
        },
        ArtifactObligation {
            obligation_id: "risk-canary".into(),
            required_at_stage: MoonshotStage::Canary,
            artifact_type: ArtifactType::RiskAssessment,
            description: "Risk report before production".into(),
            blocking: true,
        },
    ]
}

fn valid_kill_criteria() -> Vec<KillCriterion> {
    vec![
        KillCriterion {
            criterion_id: "budget-kill".into(),
            trigger: KillTrigger::BudgetExhaustedNoSignal,
            condition: "Budget 90% exhausted with no signal".into(),
            threshold_millionths: None,
            max_duration_ns: None,
        },
        KillCriterion {
            criterion_id: "time-kill".into(),
            trigger: KillTrigger::TimeExpiry,
            condition: "120 days without stage promotion".into(),
            threshold_millionths: None,
            max_duration_ns: Some(10_368_000_000_000_000), // 120 days in ns
        },
        KillCriterion {
            criterion_id: "regression-kill".into(),
            trigger: KillTrigger::MetricRegression,
            condition: "FP rate exceeds 5%".into(),
            threshold_millionths: Some(50_000), // 5% threshold
            max_duration_ns: None,
        },
        KillCriterion {
            criterion_id: "risk-violation".into(),
            trigger: KillTrigger::RiskConstraintViolation,
            condition: "Security risk budget breached".into(),
            threshold_millionths: None,
            max_duration_ns: None,
        },
        KillCriterion {
            criterion_id: "repro-fail".into(),
            trigger: KillTrigger::ReproducibilityFailure,
            condition: "Key results not reproducible".into(),
            threshold_millionths: None,
            max_duration_ns: None,
        },
    ]
}

fn valid_rollback() -> RollbackPlan {
    RollbackPlan {
        steps: vec![
            RollbackStep {
                step_number: 1,
                description: "Disable Bayesian filter".into(),
                verification: "frankenctl filter disable bayes".into(),
            },
            RollbackStep {
                step_number: 2,
                description: "Restore legacy detection policy".into(),
                verification: "frankenctl policy revert --to cp-42".into(),
            },
        ],
        artifact_references: vec!["cp-42".into(), "snapshot-abc".into()],
        expected_state_after_rollback: "Pre-moonshot detection pipeline restored".into(),
    }
}

fn valid_contract() -> MoonshotContract {
    MoonshotContract {
        contract_id: "mc-bayes-filter-001".into(),
        version: ContractVersion { major: 1, minor: 0 },
        hypothesis: valid_hypothesis(),
        target_metrics: valid_metrics(),
        ev_model: valid_ev_model(),
        risk_budget: valid_risk_budget(),
        artifact_obligations: valid_obligations(),
        kill_criteria: valid_kill_criteria(),
        rollback_plan: valid_rollback(),
        current_stage: MoonshotStage::Research,
        epoch: SecurityEpoch::from_raw(5),
        governance_signature: Some("sig:governance-abc".into()),
        metadata: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. MoonshotStage — Display, ordering, all()
// ---------------------------------------------------------------------------

#[test]
fn stage_display_all_variants() {
    assert_eq!(MoonshotStage::Research.to_string(), "research");
    assert_eq!(MoonshotStage::Shadow.to_string(), "shadow");
    assert_eq!(MoonshotStage::Canary.to_string(), "canary");
    assert_eq!(MoonshotStage::Production.to_string(), "production");
}

#[test]
fn stage_ordering_is_linear() {
    assert!(MoonshotStage::Research < MoonshotStage::Shadow);
    assert!(MoonshotStage::Shadow < MoonshotStage::Canary);
    assert!(MoonshotStage::Canary < MoonshotStage::Production);
}

#[test]
fn stage_all_returns_four_in_order() {
    let all = MoonshotStage::all();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], MoonshotStage::Research);
    assert_eq!(all[1], MoonshotStage::Shadow);
    assert_eq!(all[2], MoonshotStage::Canary);
    assert_eq!(all[3], MoonshotStage::Production);
}

#[test]
fn stage_clone_and_copy() {
    let s = MoonshotStage::Canary;
    let s2 = s;
    assert_eq!(s, s2);
}

#[test]
fn stage_serde_round_trip_all_variants() {
    for stage in MoonshotStage::all() {
        let json = serde_json::to_string(stage).unwrap();
        let decoded: MoonshotStage = serde_json::from_str(&json).unwrap();
        assert_eq!(*stage, decoded);
    }
}

// ---------------------------------------------------------------------------
// 2. MeasurementMethod — Display
// ---------------------------------------------------------------------------

#[test]
fn measurement_method_display_all_variants() {
    assert_eq!(MeasurementMethod::Benchmark.to_string(), "benchmark");
    assert_eq!(
        MeasurementMethod::EvidenceQuery.to_string(),
        "evidence_query"
    );
    assert_eq!(
        MeasurementMethod::FleetTelemetry.to_string(),
        "fleet_telemetry"
    );
    assert_eq!(
        MeasurementMethod::OperatorReview.to_string(),
        "operator_review"
    );
}

#[test]
fn measurement_method_ordering() {
    assert!(MeasurementMethod::Benchmark < MeasurementMethod::EvidenceQuery);
    assert!(MeasurementMethod::EvidenceQuery < MeasurementMethod::FleetTelemetry);
    assert!(MeasurementMethod::FleetTelemetry < MeasurementMethod::OperatorReview);
}

// ---------------------------------------------------------------------------
// 3. MetricDirection — construction
// ---------------------------------------------------------------------------

#[test]
fn metric_direction_equality() {
    assert_eq!(
        MetricDirection::HigherIsBetter,
        MetricDirection::HigherIsBetter
    );
    assert_ne!(
        MetricDirection::HigherIsBetter,
        MetricDirection::LowerIsBetter
    );
}

#[test]
fn metric_direction_serde_round_trip() {
    let dirs = [
        MetricDirection::HigherIsBetter,
        MetricDirection::LowerIsBetter,
    ];
    for d in &dirs {
        let json = serde_json::to_string(d).unwrap();
        let decoded: MetricDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, decoded);
    }
}

// ---------------------------------------------------------------------------
// 4. DistributionType — Display
// ---------------------------------------------------------------------------

#[test]
fn distribution_type_display_all_variants() {
    assert_eq!(
        DistributionType::PointEstimate.to_string(),
        "point_estimate"
    );
    assert_eq!(DistributionType::Uniform.to_string(), "uniform");
    assert_eq!(DistributionType::Beta.to_string(), "beta");
    assert_eq!(DistributionType::LogNormal.to_string(), "log_normal");
}

#[test]
fn distribution_type_ordering() {
    // Ord follows declaration order: PointEstimate, Uniform, Beta, LogNormal.
    assert!(DistributionType::PointEstimate < DistributionType::Uniform);
    assert!(DistributionType::Uniform < DistributionType::Beta);
    assert!(DistributionType::Beta < DistributionType::LogNormal);
}

// ---------------------------------------------------------------------------
// 5. RiskDimension — Display
// ---------------------------------------------------------------------------

#[test]
fn risk_dimension_display_all_variants() {
    assert_eq!(
        RiskDimension::SecurityRegression.to_string(),
        "security_regression"
    );
    assert_eq!(
        RiskDimension::PerformanceRegression.to_string(),
        "performance_regression"
    );
    assert_eq!(
        RiskDimension::OperationalBurden.to_string(),
        "operational_burden"
    );
    assert_eq!(
        RiskDimension::CrossInitiativeInterference.to_string(),
        "cross_initiative_interference"
    );
}

// ---------------------------------------------------------------------------
// 6. ArtifactType — Display
// ---------------------------------------------------------------------------

#[test]
fn artifact_type_display_all_variants() {
    assert_eq!(ArtifactType::Proof.to_string(), "proof");
    assert_eq!(
        ArtifactType::BenchmarkResult.to_string(),
        "benchmark_result"
    );
    assert_eq!(
        ArtifactType::ConformanceEvidence.to_string(),
        "conformance_evidence"
    );
    assert_eq!(
        ArtifactType::OperatorDocumentation.to_string(),
        "operator_documentation"
    );
    assert_eq!(ArtifactType::RiskAssessment.to_string(), "risk_assessment");
}

// ---------------------------------------------------------------------------
// 7. KillTrigger — Display
// ---------------------------------------------------------------------------

#[test]
fn kill_trigger_display_all_variants() {
    assert_eq!(
        KillTrigger::BudgetExhaustedNoSignal.to_string(),
        "budget_exhausted_no_signal"
    );
    assert_eq!(
        KillTrigger::MetricRegression.to_string(),
        "metric_regression"
    );
    assert_eq!(
        KillTrigger::ReproducibilityFailure.to_string(),
        "reproducibility_failure"
    );
    assert_eq!(
        KillTrigger::RiskConstraintViolation.to_string(),
        "risk_constraint_violation"
    );
    assert_eq!(KillTrigger::TimeExpiry.to_string(), "time_expiry");
}

// ---------------------------------------------------------------------------
// 8. ContractVersion — Display
// ---------------------------------------------------------------------------

#[test]
fn contract_version_display() {
    assert_eq!(ContractVersion { major: 1, minor: 0 }.to_string(), "1.0");
    assert_eq!(
        ContractVersion {
            major: 3,
            minor: 14
        }
        .to_string(),
        "3.14"
    );
    assert_eq!(ContractVersion { major: 0, minor: 0 }.to_string(), "0.0");
}

#[test]
fn contract_version_ordering() {
    let v1 = ContractVersion { major: 1, minor: 0 };
    let v2 = ContractVersion { major: 1, minor: 1 };
    let v3 = ContractVersion { major: 2, minor: 0 };
    assert!(v1 < v2);
    assert!(v2 < v3);
}

#[test]
fn contract_version_serde_round_trip() {
    let v = ContractVersion { major: 5, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ContractVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ---------------------------------------------------------------------------
// 9. ContractError — Display and std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn contract_error_display_empty_contract_id() {
    assert_eq!(
        ContractError::EmptyContractId.to_string(),
        "contract ID is empty"
    );
}

#[test]
fn contract_error_display_invalid_hypothesis() {
    let err = ContractError::InvalidHypothesis {
        reason: "missing mechanism".into(),
    };
    assert_eq!(err.to_string(), "invalid hypothesis: missing mechanism");
}

#[test]
fn contract_error_display_empty_target_metrics() {
    assert_eq!(
        ContractError::EmptyTargetMetrics.to_string(),
        "target metrics must not be empty"
    );
}

#[test]
fn contract_error_display_invalid_ev_model() {
    let err = ContractError::InvalidEvModel {
        reason: "cost <= 0".into(),
    };
    assert_eq!(err.to_string(), "invalid EV model: cost <= 0");
}

#[test]
fn contract_error_display_invalid_risk_budget() {
    let err = ContractError::InvalidRiskBudget {
        reason: "empty".into(),
    };
    assert_eq!(err.to_string(), "invalid risk budget: empty");
}

#[test]
fn contract_error_display_empty_kill_criteria() {
    assert_eq!(
        ContractError::EmptyKillCriteria.to_string(),
        "kill criteria must not be empty"
    );
}

#[test]
fn contract_error_display_invalid_rollback() {
    let err = ContractError::InvalidRollback {
        reason: "no steps".into(),
    };
    assert_eq!(err.to_string(), "invalid rollback plan: no steps");
}

#[test]
fn contract_error_serde_round_trip_all_variants() {
    let errors = vec![
        ContractError::EmptyContractId,
        ContractError::InvalidHypothesis {
            reason: "test".into(),
        },
        ContractError::EmptyTargetMetrics,
        ContractError::InvalidEvModel {
            reason: "bad".into(),
        },
        ContractError::InvalidRiskBudget {
            reason: "none".into(),
        },
        ContractError::EmptyKillCriteria,
        ContractError::InvalidRollback {
            reason: "empty".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn contract_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ContractError::EmptyContractId);
    assert!(err.to_string().contains("empty"));
}

// ---------------------------------------------------------------------------
// 10. Hypothesis — validation
// ---------------------------------------------------------------------------

#[test]
fn hypothesis_validates_ok() {
    valid_hypothesis().validate().unwrap();
}

#[test]
fn hypothesis_rejects_empty_problem() {
    let mut h = valid_hypothesis();
    h.problem = String::new();
    let err = h.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
    assert!(err.to_string().contains("problem"));
}

#[test]
fn hypothesis_rejects_empty_mechanism() {
    let mut h = valid_hypothesis();
    h.mechanism = String::new();
    let err = h.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
    assert!(err.to_string().contains("mechanism"));
}

#[test]
fn hypothesis_rejects_empty_expected_outcome() {
    let mut h = valid_hypothesis();
    h.expected_outcome = String::new();
    let err = h.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
    assert!(err.to_string().contains("expected outcome"));
}

#[test]
fn hypothesis_rejects_empty_falsification_criteria() {
    let mut h = valid_hypothesis();
    h.falsification_criteria = vec![];
    let err = h.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
    assert!(err.to_string().contains("falsification"));
}

#[test]
fn hypothesis_serde_round_trip() {
    let h = valid_hypothesis();
    let json = serde_json::to_string(&h).unwrap();
    let decoded: Hypothesis = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

// ---------------------------------------------------------------------------
// 11. EvModel — validation and net_ev_point_estimate
// ---------------------------------------------------------------------------

#[test]
fn ev_model_validates_ok() {
    valid_ev_model().validate().unwrap();
}

#[test]
fn ev_model_rejects_zero_cost() {
    let mut ev = valid_ev_model();
    ev.cost_millionths = 0;
    let err = ev.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidEvModel { .. }));
    assert!(err.to_string().contains("cost"));
}

#[test]
fn ev_model_rejects_negative_cost() {
    let mut ev = valid_ev_model();
    ev.cost_millionths = -100;
    let err = ev.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidEvModel { .. }));
}

#[test]
fn ev_model_point_estimate_requires_value_param() {
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    let err = ev.validate().unwrap_err();
    assert!(err.to_string().contains("value"));
}

#[test]
fn ev_model_beta_requires_alpha_and_beta() {
    let mut params = BTreeMap::new();
    params.insert("alpha".into(), 2_000_000i64);
    // Missing "beta".
    let ev = EvModel {
        success_distribution: DistributionType::Beta,
        distribution_params: params,
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    let err = ev.validate().unwrap_err();
    assert!(err.to_string().contains("alpha") || err.to_string().contains("beta"));
}

#[test]
fn ev_model_beta_validates_when_both_present() {
    let mut params = BTreeMap::new();
    params.insert("alpha".into(), 2_000_000i64);
    params.insert("beta".into(), 3_000_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::Beta,
        distribution_params: params,
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    ev.validate().unwrap();
}

#[test]
fn ev_model_uniform_requires_low_and_high() {
    let mut params = BTreeMap::new();
    params.insert("low".into(), 100_000i64);
    // Missing "high".
    let ev = EvModel {
        success_distribution: DistributionType::Uniform,
        distribution_params: params,
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    let err = ev.validate().unwrap_err();
    assert!(err.to_string().contains("low") || err.to_string().contains("high"));
}

#[test]
fn ev_model_uniform_validates_when_both_present() {
    let mut params = BTreeMap::new();
    params.insert("low".into(), 100_000i64);
    params.insert("high".into(), 900_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::Uniform,
        distribution_params: params,
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    ev.validate().unwrap();
}

#[test]
fn ev_model_lognormal_requires_mu_and_sigma() {
    let ev = EvModel {
        success_distribution: DistributionType::LogNormal,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    let err = ev.validate().unwrap_err();
    assert!(err.to_string().contains("mu") || err.to_string().contains("sigma"));
}

#[test]
fn ev_model_lognormal_validates_when_both_present() {
    let mut params = BTreeMap::new();
    params.insert("mu".into(), 500_000i64);
    params.insert("sigma".into(), 100_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::LogNormal,
        distribution_params: params,
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    ev.validate().unwrap();
}

#[test]
fn net_ev_point_estimate_arithmetic() {
    let ev = valid_ev_model();
    // P=0.7, benefit=10.0, harm=0.5, cost=1.0
    // net_EV = 0.7 * 10.0 - 0.3 * 0.5 - 1.0
    //        = 7.0 - 0.15 - 1.0 = 5.85
    // In millionths: 5_850_000
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, 5_850_000);
}

#[test]
fn net_ev_point_estimate_zero_probability() {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 0i64); // P=0
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 5_000_000,
        harm_on_failure_millionths: -200_000,
    };
    // net = 0 - 1.0*0.2 - 0.1 = -0.3 => -300_000
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, -300_000);
}

#[test]
fn net_ev_point_estimate_full_probability() {
    let mut params = BTreeMap::new();
    params.insert("value".into(), 1_000_000i64); // P=1.0
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 5_000_000,
        harm_on_failure_millionths: -200_000,
    };
    // net = 1.0*5.0 - 0*0.2 - 0.1 = 4.9 => 4_900_000
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, 4_900_000);
}

#[test]
fn net_ev_rejects_non_point_estimate() {
    let mut params = BTreeMap::new();
    params.insert("alpha".into(), 2_000_000i64);
    params.insert("beta".into(), 3_000_000i64);
    let ev = EvModel {
        success_distribution: DistributionType::Beta,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 500_000,
        harm_on_failure_millionths: -50_000,
    };
    let err = ev.net_ev_point_estimate().unwrap_err();
    assert!(err.to_string().contains("PointEstimate"));
}

#[test]
fn net_ev_point_estimate_missing_value() {
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: BTreeMap::new(),
        cost_millionths: 100,
        benefit_on_success_millionths: 1_000,
        harm_on_failure_millionths: -50,
    };
    let err = ev.net_ev_point_estimate().unwrap_err();
    assert!(err.to_string().contains("value"));
}

#[test]
fn ev_model_serde_round_trip() {
    let ev = valid_ev_model();
    let json = serde_json::to_string(&ev).unwrap();
    let decoded: EvModel = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, decoded);
}

// ---------------------------------------------------------------------------
// 12. RiskBudget — validation
// ---------------------------------------------------------------------------

#[test]
fn risk_budget_validates_ok() {
    valid_risk_budget().validate().unwrap();
}

#[test]
fn risk_budget_rejects_empty_dimension_caps() {
    let rb = RiskBudget {
        dimension_caps: BTreeMap::new(),
    };
    let err = rb.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidRiskBudget { .. }));
}

#[test]
fn risk_budget_serde_round_trip() {
    let rb = valid_risk_budget();
    let json = serde_json::to_string(&rb).unwrap();
    let decoded: RiskBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, decoded);
}

// ---------------------------------------------------------------------------
// 13. RollbackPlan — validation
// ---------------------------------------------------------------------------

#[test]
fn rollback_validates_ok() {
    valid_rollback().validate().unwrap();
}

#[test]
fn rollback_rejects_empty_steps() {
    let rb = RollbackPlan {
        steps: vec![],
        artifact_references: vec!["ref-1".into()],
        expected_state_after_rollback: "clean state".into(),
    };
    let err = rb.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidRollback { .. }));
    assert!(err.to_string().contains("step"));
}

#[test]
fn rollback_rejects_empty_expected_state() {
    let rb = RollbackPlan {
        steps: vec![RollbackStep {
            step_number: 1,
            description: "revert".into(),
            verification: "check".into(),
        }],
        artifact_references: vec![],
        expected_state_after_rollback: String::new(),
    };
    let err = rb.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidRollback { .. }));
    assert!(err.to_string().contains("expected state"));
}

#[test]
fn rollback_serde_round_trip() {
    let rb = valid_rollback();
    let json = serde_json::to_string(&rb).unwrap();
    let decoded: RollbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, decoded);
}

// ---------------------------------------------------------------------------
// 14. MoonshotContract — full validation
// ---------------------------------------------------------------------------

#[test]
fn contract_validates_ok() {
    valid_contract().validate().unwrap();
}

#[test]
fn contract_rejects_empty_id() {
    let mut c = valid_contract();
    c.contract_id = String::new();
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::EmptyContractId));
}

#[test]
fn contract_rejects_invalid_hypothesis() {
    let mut c = valid_contract();
    c.hypothesis.problem = String::new();
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
}

#[test]
fn contract_rejects_empty_target_metrics() {
    let mut c = valid_contract();
    c.target_metrics = vec![];
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::EmptyTargetMetrics));
}

#[test]
fn contract_rejects_invalid_ev_model() {
    let mut c = valid_contract();
    c.ev_model.cost_millionths = 0;
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidEvModel { .. }));
}

#[test]
fn contract_rejects_invalid_risk_budget() {
    let mut c = valid_contract();
    c.risk_budget.dimension_caps = BTreeMap::new();
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidRiskBudget { .. }));
}

#[test]
fn contract_rejects_empty_kill_criteria() {
    let mut c = valid_contract();
    c.kill_criteria = vec![];
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::EmptyKillCriteria));
}

#[test]
fn contract_rejects_invalid_rollback_plan() {
    let mut c = valid_contract();
    c.rollback_plan.steps = vec![];
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidRollback { .. }));
}

// ---------------------------------------------------------------------------
// 15. stage_obligations_met
// ---------------------------------------------------------------------------

#[test]
fn stage_obligations_met_when_all_blocking_completed() {
    let c = valid_contract();
    assert!(c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
}

#[test]
fn stage_obligations_not_met_when_blocking_missing() {
    let c = valid_contract();
    assert!(!c.stage_obligations_met(MoonshotStage::Research, &[]));
}

#[test]
fn stage_obligations_met_when_no_blocking_for_stage() {
    let c = valid_contract();
    // Production has no obligations defined in our test data.
    assert!(c.stage_obligations_met(MoonshotStage::Production, &[]));
}

#[test]
fn stage_obligations_met_ignores_non_blocking() {
    let c = valid_contract();
    // Canary has "docs-canary" (non-blocking) and "risk-canary" (blocking).
    // Providing only risk-canary should suffice.
    assert!(c.stage_obligations_met(MoonshotStage::Canary, &["risk-canary".into()]));
}

#[test]
fn stage_obligations_met_superset_of_required_ok() {
    let c = valid_contract();
    assert!(c.stage_obligations_met(
        MoonshotStage::Research,
        &["proof-research".into(), "extra-artifact".into()]
    ));
}

#[test]
fn stage_obligations_met_shadow_stage() {
    let c = valid_contract();
    assert!(!c.stage_obligations_met(MoonshotStage::Shadow, &[]));
    assert!(c.stage_obligations_met(MoonshotStage::Shadow, &["bench-shadow".into()]));
}

// ---------------------------------------------------------------------------
// 16. check_kill_criteria — time expiry
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_time_expiry_triggered() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    // 130 days > 120 days max.
    let elapsed_ns = 130 * 86_400_000_000_000u64;
    let triggered = c.check_kill_criteria(&metrics, elapsed_ns, 0);
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
}

#[test]
fn kill_criteria_time_expiry_not_triggered_under_limit() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    let elapsed_ns = 100 * 86_400_000_000_000u64; // 100 days < 120 days
    let triggered = c.check_kill_criteria(&metrics, elapsed_ns, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
}

#[test]
fn kill_criteria_time_expiry_exact_boundary_not_triggered() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    // Exactly 120 days = max_duration_ns; must exceed, not equal.
    let elapsed_ns = 10_368_000_000_000_000u64;
    let triggered = c.check_kill_criteria(&metrics, elapsed_ns, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
}

// ---------------------------------------------------------------------------
// 17. check_kill_criteria — budget exhausted no signal
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_budget_exhausted_triggered_when_no_metrics_improving() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    // Both metrics worse than threshold (higher than threshold for lower-is-better).
    metrics.insert("fp_rate".into(), 20_000i64); // 2% > 1% threshold
    metrics.insert("recall".into(), 800_000i64); // 80% < 90% threshold
    let triggered = c.check_kill_criteria(&metrics, 0, 950_000); // 95% budget
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
    );
}

#[test]
fn kill_criteria_budget_exhausted_not_triggered_when_one_metric_improving() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("fp_rate".into(), 5_000i64); // 0.5% < 1% threshold => improving
    metrics.insert("recall".into(), 800_000i64); // below threshold
    // Budget > 90% but at least one metric improving, so not triggered.
    let triggered = c.check_kill_criteria(&metrics, 0, 950_000);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
    );
}

#[test]
fn kill_criteria_budget_exhausted_not_triggered_when_budget_below_90_percent() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("fp_rate".into(), 20_000i64);
    metrics.insert("recall".into(), 800_000i64);
    // Budget at 89% < 90%.
    let triggered = c.check_kill_criteria(&metrics, 0, 890_000);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
    );
}

#[test]
fn kill_criteria_budget_boundary_at_exactly_90_percent() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("fp_rate".into(), 20_000i64);
    metrics.insert("recall".into(), 800_000i64);
    // Budget exactly at 90% => triggered (>= 900_000).
    let triggered = c.check_kill_criteria(&metrics, 0, 900_000);
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
    );
}

// ---------------------------------------------------------------------------
// 18. check_kill_criteria — metric regression
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_metric_regression_triggered_lower_is_better() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    // fp_rate at 60_000 (6%) > regression threshold 50_000 (5%) for lower-is-better.
    metrics.insert("fp_rate".into(), 60_000i64);
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
}

#[test]
fn kill_criteria_metric_regression_not_triggered_when_under_threshold() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    // fp_rate at 40_000 (4%) < regression threshold 50_000 (5%) => OK.
    metrics.insert("fp_rate".into(), 40_000i64);
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
}

#[test]
fn kill_criteria_metric_regression_exact_boundary() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    // Exactly at threshold: 50_000 not > 50_000 for lower-is-better => not regressed.
    metrics.insert("fp_rate".into(), 50_000i64);
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
}

// ---------------------------------------------------------------------------
// 19. check_kill_criteria — external triggers not auto-evaluated
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_risk_violation_not_auto_triggered() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    // Even with extreme inputs, RiskConstraintViolation is external-only.
    let triggered = c.check_kill_criteria(&metrics, u64::MAX, u64::MAX);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::RiskConstraintViolation)
    );
}

#[test]
fn kill_criteria_reproducibility_failure_not_auto_triggered() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    let triggered = c.check_kill_criteria(&metrics, u64::MAX, u64::MAX);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::ReproducibilityFailure)
    );
}

// ---------------------------------------------------------------------------
// 20. check_kill_criteria — multiple triggers simultaneously
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_multiple_triggers_simultaneously() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    // All metrics worse => budget exhausted check will fire.
    metrics.insert("fp_rate".into(), 60_000i64); // > regression threshold 50_000
    metrics.insert("recall".into(), 800_000i64); // < target 900_000
    let elapsed_ns = 200 * 86_400_000_000_000u64; // > 120 days
    let triggered = c.check_kill_criteria(&metrics, elapsed_ns, 950_000);
    // Should trigger: TimeExpiry, BudgetExhaustedNoSignal, MetricRegression
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::TimeExpiry)
    );
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
    );
    assert!(
        triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
    assert!(triggered.len() >= 3);
}

#[test]
fn kill_criteria_no_triggers_when_all_ok() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("fp_rate".into(), 5_000i64); // 0.5% < 1% target, < 5% regression
    metrics.insert("recall".into(), 950_000i64); // 95% > 90% target
    let triggered = c.check_kill_criteria(
        &metrics,
        50 * 86_400_000_000_000, // 50 days < 120 days
        500_000,                 // 50% budget < 90%
    );
    assert!(triggered.is_empty());
}

// ---------------------------------------------------------------------------
// 21. MoonshotContract — serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn contract_serde_json_round_trip() {
    let c = valid_contract();
    let json = serde_json::to_string(&c).unwrap();
    let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
}

#[test]
fn contract_serde_pretty_json_round_trip() {
    let c = valid_contract();
    let json = serde_json::to_string_pretty(&c).unwrap();
    let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
}

// ---------------------------------------------------------------------------
// 22. Deterministic serialization
// ---------------------------------------------------------------------------

#[test]
fn deterministic_serialization_identical_contracts() {
    let c1 = valid_contract();
    let c2 = valid_contract();
    assert_eq!(
        serde_json::to_string(&c1).unwrap(),
        serde_json::to_string(&c2).unwrap()
    );
}

#[test]
fn deterministic_serialization_metadata_ordering() {
    let mut c1 = valid_contract();
    c1.metadata.insert("alpha".into(), "1".into());
    c1.metadata.insert("beta".into(), "2".into());
    c1.metadata.insert("gamma".into(), "3".into());

    let mut c2 = valid_contract();
    // Insert in reverse order — BTreeMap guarantees same iteration order.
    c2.metadata.insert("gamma".into(), "3".into());
    c2.metadata.insert("beta".into(), "2".into());
    c2.metadata.insert("alpha".into(), "1".into());

    assert_eq!(
        serde_json::to_string(&c1).unwrap(),
        serde_json::to_string(&c2).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 23. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn contract_with_no_governance_signature() {
    let mut c = valid_contract();
    c.governance_signature = None;
    c.validate().unwrap();
    let json = serde_json::to_string(&c).unwrap();
    let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
    assert!(decoded.governance_signature.is_none());
}

#[test]
fn contract_with_metadata() {
    let mut c = valid_contract();
    c.metadata.insert("owner".into(), "team-security".into());
    c.metadata.insert("priority".into(), "high".into());
    c.validate().unwrap();
    let json = serde_json::to_string(&c).unwrap();
    let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c.metadata, decoded.metadata);
}

#[test]
fn contract_at_production_stage() {
    let mut c = valid_contract();
    c.current_stage = MoonshotStage::Production;
    c.validate().unwrap();
}

#[test]
fn contract_with_genesis_epoch() {
    let mut c = valid_contract();
    c.epoch = SecurityEpoch::GENESIS;
    c.validate().unwrap();
    assert_eq!(c.epoch.as_u64(), 0);
}

#[test]
fn contract_epoch_round_trip() {
    let c = valid_contract();
    assert_eq!(c.epoch.as_u64(), 5);
    let json = serde_json::to_string(&c).unwrap();
    let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.epoch.as_u64(), 5);
}

#[test]
fn target_metric_serde_round_trip() {
    let metrics = valid_metrics();
    for m in &metrics {
        let json = serde_json::to_string(m).unwrap();
        let decoded: TargetMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, decoded);
    }
}

#[test]
fn artifact_obligation_serde_round_trip() {
    let obligations = valid_obligations();
    for o in &obligations {
        let json = serde_json::to_string(o).unwrap();
        let decoded: ArtifactObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, decoded);
    }
}

#[test]
fn kill_criterion_serde_round_trip() {
    let criteria = valid_kill_criteria();
    for k in &criteria {
        let json = serde_json::to_string(k).unwrap();
        let decoded: KillCriterion = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, decoded);
    }
}

#[test]
fn rollback_step_serde_round_trip() {
    let step = RollbackStep {
        step_number: 42,
        description: "Revert deployment".into(),
        verification: "verify --status".into(),
    };
    let json = serde_json::to_string(&step).unwrap();
    let decoded: RollbackStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, decoded);
}

#[test]
fn stage_obligations_empty_obligations_list() {
    let mut c = valid_contract();
    c.artifact_obligations = vec![];
    // No obligations => all stages trivially met.
    for stage in MoonshotStage::all() {
        assert!(c.stage_obligations_met(*stage, &[]));
    }
}

#[test]
fn kill_criteria_empty_metrics_map() {
    let c = valid_contract();
    let metrics = BTreeMap::new();
    // With no metrics, budget below 90%, and time within limit:
    // no triggers.
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(triggered.is_empty());
}

#[test]
fn kill_criteria_with_unknown_metric_ids() {
    let c = valid_contract();
    let mut metrics = BTreeMap::new();
    metrics.insert("nonexistent_metric".into(), 999_999i64);
    // Unknown metric IDs are simply ignored.
    let triggered = c.check_kill_criteria(&metrics, 0, 0);
    assert!(
        !triggered
            .iter()
            .any(|k| k.trigger == KillTrigger::MetricRegression)
    );
}

#[test]
fn net_ev_positive_harm_value() {
    // harm_on_failure_millionths is negative by convention but
    // the code uses unsigned_abs(), so a positive value is handled as well.
    let mut params = BTreeMap::new();
    params.insert("value".into(), 500_000i64); // P=0.5
    let ev = EvModel {
        success_distribution: DistributionType::PointEstimate,
        distribution_params: params,
        cost_millionths: 100_000,
        benefit_on_success_millionths: 2_000_000,
        harm_on_failure_millionths: 300_000, // positive, unsigned_abs => 300_000
    };
    // net = 0.5*2.0 - 0.5*0.3 - 0.1 = 1.0 - 0.15 - 0.1 = 0.75
    let net = ev.net_ev_point_estimate().unwrap();
    assert_eq!(net, 750_000);
}

// ---------------------------------------------------------------------------
// 24. Clone and equality
// ---------------------------------------------------------------------------

#[test]
fn contract_clone_equals_original() {
    let c = valid_contract();
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn contract_modified_clone_not_equal() {
    let c = valid_contract();
    let mut c2 = c.clone();
    c2.contract_id = "different-id".into();
    assert_ne!(c, c2);
}

// ---------------------------------------------------------------------------
// 25. Validation order — first error wins
// ---------------------------------------------------------------------------

#[test]
fn validation_stops_at_first_error_empty_id_before_hypothesis() {
    let mut c = valid_contract();
    c.contract_id = String::new();
    c.hypothesis.problem = String::new(); // also invalid
    // EmptyContractId should be returned first.
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::EmptyContractId));
}

#[test]
fn validation_stops_at_hypothesis_before_metrics() {
    let mut c = valid_contract();
    c.hypothesis.mechanism = String::new();
    c.target_metrics = vec![]; // also invalid
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidHypothesis { .. }));
}

#[test]
fn validation_stops_at_metrics_before_ev_model() {
    let mut c = valid_contract();
    c.target_metrics = vec![];
    c.ev_model.cost_millionths = 0; // also invalid
    let err = c.validate().unwrap_err();
    assert!(matches!(err, ContractError::EmptyTargetMetrics));
}
