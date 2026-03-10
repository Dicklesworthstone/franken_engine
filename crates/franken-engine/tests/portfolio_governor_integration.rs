#![forbid(unsafe_code)]
//! Integration tests for the `portfolio_governor` module.
//!
//! Exercises every public type, enum variant, method, error path, and
//! cross-concern scenario from outside the crate boundary.

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
    ArtifactObligation, ArtifactType, ContractVersion, DistributionType, EvModel, Hypothesis,
    KillCriterion, KillTrigger, MeasurementMethod, MetricDirection, MoonshotContract,
    MoonshotStage, RiskBudget, RiskDimension, RollbackPlan, RollbackStep, TargetMetric,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::GovernanceLedgerConfig;
use frankenengine_engine::portfolio_governor::{
    ArtifactEvidence, GovernorConfig, GovernorDecision, GovernorDecisionKind, GovernorError,
    MetricObservation, MoonshotState, MoonshotStatus, PortfolioGovernor, Scorecard,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_hypothesis() -> Hypothesis {
    Hypothesis {
        problem: "Detection latency too high".into(),
        mechanism: "Fleet evidence sharing".into(),
        expected_outcome: "50% latency reduction".into(),
        falsification_criteria: vec!["No improvement in 90 days".into()],
    }
}

fn test_metrics() -> Vec<TargetMetric> {
    vec![TargetMetric {
        metric_id: "latency_p50".into(),
        description: "Median latency".into(),
        threshold_millionths: 250_000_000,
        direction: MetricDirection::LowerIsBetter,
        measurement_method: MeasurementMethod::FleetTelemetry,
        evaluation_cadence_ns: 86_400_000_000_000,
    }]
}

fn test_ev_model() -> EvModel {
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

fn test_risk_budget() -> RiskBudget {
    let mut caps = BTreeMap::new();
    caps.insert(RiskDimension::SecurityRegression, 50_000u64);
    RiskBudget {
        dimension_caps: caps,
    }
}

fn test_obligations() -> Vec<ArtifactObligation> {
    vec![
        ArtifactObligation {
            obligation_id: "proof-research".into(),
            required_at_stage: MoonshotStage::Research,
            artifact_type: ArtifactType::Proof,
            description: "Proof of concept".into(),
            blocking: true,
        },
        ArtifactObligation {
            obligation_id: "bench-shadow".into(),
            required_at_stage: MoonshotStage::Shadow,
            artifact_type: ArtifactType::BenchmarkResult,
            description: "Shadow benchmarks".into(),
            blocking: true,
        },
    ]
}

fn test_kill_criteria() -> Vec<KillCriterion> {
    vec![
        KillCriterion {
            criterion_id: "time-kill".into(),
            trigger: KillTrigger::TimeExpiry,
            condition: "180 days without promotion".into(),
            threshold_millionths: None,
            max_duration_ns: Some(15_552_000_000_000_000),
        },
        KillCriterion {
            criterion_id: "budget-kill".into(),
            trigger: KillTrigger::BudgetExhaustedNoSignal,
            condition: "Budget exhausted without signal".into(),
            threshold_millionths: None,
            max_duration_ns: None,
        },
    ]
}

fn test_rollback() -> RollbackPlan {
    RollbackPlan {
        steps: vec![RollbackStep {
            step_number: 1,
            description: "Revert to previous policy".into(),
            verification: "frankenctl verify".into(),
        }],
        artifact_references: vec!["checkpoint-1".into()],
        expected_state_after_rollback: "Pre-moonshot state".into(),
    }
}

fn test_contract() -> MoonshotContract {
    test_contract_with_id("mc-integ-001")
}

fn test_contract_with_id(id: &str) -> MoonshotContract {
    MoonshotContract {
        contract_id: id.into(),
        version: ContractVersion { major: 1, minor: 0 },
        hypothesis: test_hypothesis(),
        target_metrics: test_metrics(),
        ev_model: test_ev_model(),
        risk_budget: test_risk_budget(),
        artifact_obligations: test_obligations(),
        kill_criteria: test_kill_criteria(),
        rollback_plan: test_rollback(),
        current_stage: MoonshotStage::Research,
        epoch: SecurityEpoch::from_raw(1),
        governance_signature: Some("sig:gov".into()),
        metadata: BTreeMap::new(),
    }
}

/// Contract with no obligations -- enables promotion without artifact submission.
fn test_contract_no_obligations(id: &str) -> MoonshotContract {
    let mut c = test_contract_with_id(id);
    c.artifact_obligations.clear();
    // Use a very long time-expiry kill criterion so it doesn't trigger during tests.
    c.kill_criteria = vec![KillCriterion {
        criterion_id: "time-kill-long".into(),
        trigger: KillTrigger::TimeExpiry,
        condition: "10 years without promotion".into(),
        threshold_millionths: None,
        max_duration_ns: Some(315_360_000_000_000_000), // ~10 years
    }];
    c
}

fn test_governor() -> PortfolioGovernor {
    PortfolioGovernor::new(GovernorConfig::default(), SecurityEpoch::from_raw(1))
}

fn make_evidence(artifact_id: &str, obligation_id: &str) -> ArtifactEvidence {
    ArtifactEvidence {
        artifact_id: artifact_id.into(),
        obligation_id: obligation_id.into(),
        artifact_type: ArtifactType::Proof,
        submitted_at_ns: 2_000_000_000,
        content_hash: format!("hash-{artifact_id}"),
    }
}

fn make_observation(metric_id: &str, value: i64, at_ns: u64) -> MetricObservation {
    MetricObservation {
        metric_id: metric_id.into(),
        value_millionths: value,
        observed_at_ns: at_ns,
    }
}

/// Record `n` good metric observations for the latency_p50 metric.
fn record_n_good_metrics(gov: &mut PortfolioGovernor, id: &str, n: u64) {
    for i in 0..n {
        gov.record_metric(
            id,
            make_observation("latency_p50", 200_000_000, (i + 1) * 1_000_000_000),
        )
        .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Section 1: Scorecard construction and risk_adjusted_ev
// ---------------------------------------------------------------------------

#[test]
fn scorecard_construction_and_field_access() {
    let sc = Scorecard {
        moonshot_id: "m1".into(),
        ev_millionths: 3_000_000,
        confidence_millionths: 900_000,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 50_000,
        cross_initiative_interference_millionths: 20_000,
        operational_burden_millionths: 30_000,
        computed_at_ns: 1_000,
        epoch: SecurityEpoch::from_raw(5),
    };
    assert_eq!(sc.moonshot_id, "m1");
    assert_eq!(sc.ev_millionths, 3_000_000);
    assert_eq!(sc.confidence_millionths, 900_000);
    assert_eq!(sc.computed_at_ns, 1_000);
    assert_eq!(sc.epoch, SecurityEpoch::from_raw(5));
}

#[test]
fn scorecard_risk_adjusted_ev_formula() {
    // ev * conf / 1M - risk*2 - interference - friction - burden
    let sc = Scorecard {
        moonshot_id: "test".into(),
        ev_millionths: 2_000_000,
        confidence_millionths: 800_000,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 50_000,
        cross_initiative_interference_millionths: 30_000,
        operational_burden_millionths: 20_000,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    // = 2M * 800K / 1M - 200K - 30K - 50K - 20K = 1_600_000 - 300_000 = 1_300_000
    assert_eq!(sc.risk_adjusted_ev(), 1_300_000);
}

#[test]
fn scorecard_risk_adjusted_ev_zero_confidence() {
    let sc = Scorecard {
        moonshot_id: "z".into(),
        ev_millionths: 5_000_000,
        confidence_millionths: 0,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    // ev * 0 / 1M - 200K = -200_000
    assert_eq!(sc.risk_adjusted_ev(), -200_000);
}

#[test]
fn scorecard_risk_adjusted_ev_negative_ev() {
    let sc = Scorecard {
        moonshot_id: "neg".into(),
        ev_millionths: -1_000_000,
        confidence_millionths: 1_000_000,
        risk_of_harm_millionths: 0,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    // -1M * 1M / 1M = -1M
    assert_eq!(sc.risk_adjusted_ev(), -1_000_000);
}

#[test]
fn scorecard_serde_roundtrip() {
    let sc = Scorecard {
        moonshot_id: "serde-test".into(),
        ev_millionths: 1_234_567,
        confidence_millionths: 777_000,
        risk_of_harm_millionths: 55_000,
        implementation_friction_millionths: 12_000,
        cross_initiative_interference_millionths: 8_000,
        operational_burden_millionths: 3_000,
        computed_at_ns: 999,
        epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&sc).unwrap();
    let decoded: Scorecard = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, decoded);
}

// ---------------------------------------------------------------------------
// Section 2: ArtifactEvidence
// ---------------------------------------------------------------------------

#[test]
fn artifact_evidence_construction() {
    let e = ArtifactEvidence {
        artifact_id: "a1".into(),
        obligation_id: "o1".into(),
        artifact_type: ArtifactType::BenchmarkResult,
        submitted_at_ns: 42,
        content_hash: "deadbeef".into(),
    };
    assert_eq!(e.artifact_id, "a1");
    assert_eq!(e.obligation_id, "o1");
    assert_eq!(e.submitted_at_ns, 42);
}

#[test]
fn artifact_evidence_serde_roundtrip() {
    let e = make_evidence("art-serde", "obl-serde");
    let json = serde_json::to_string(&e).unwrap();
    let decoded: ArtifactEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, decoded);
}

// ---------------------------------------------------------------------------
// Section 3: MetricObservation
// ---------------------------------------------------------------------------

#[test]
fn metric_observation_construction() {
    let obs = MetricObservation {
        metric_id: "latency".into(),
        value_millionths: -500,
        observed_at_ns: 100,
    };
    assert_eq!(obs.metric_id, "latency");
    assert_eq!(obs.value_millionths, -500);
}

#[test]
fn metric_observation_serde_roundtrip() {
    let obs = make_observation("m1", 42_000, 999);
    let json = serde_json::to_string(&obs).unwrap();
    let decoded: MetricObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, decoded);
}

// ---------------------------------------------------------------------------
// Section 4: GovernorDecisionKind Display
// ---------------------------------------------------------------------------

#[test]
fn decision_kind_display_promote() {
    let k = GovernorDecisionKind::Promote {
        from: MoonshotStage::Research,
        to: MoonshotStage::Shadow,
    };
    assert_eq!(k.to_string(), "promote(research->shadow)");
}

#[test]
fn decision_kind_display_hold() {
    let k = GovernorDecisionKind::Hold {
        reason: "waiting".into(),
    };
    assert_eq!(k.to_string(), "hold(waiting)");
}

#[test]
fn decision_kind_display_kill() {
    let k = GovernorDecisionKind::Kill {
        triggered_criteria: vec!["c1".into()],
    };
    assert_eq!(k.to_string(), "kill");
}

#[test]
fn decision_kind_display_pause() {
    let k = GovernorDecisionKind::Pause {
        reason: "resources".into(),
    };
    assert_eq!(k.to_string(), "pause(resources)");
}

#[test]
fn decision_kind_display_resume() {
    let k = GovernorDecisionKind::Resume;
    assert_eq!(k.to_string(), "resume");
}

#[test]
fn decision_kind_serde_all_variants() {
    let variants: Vec<GovernorDecisionKind> = vec![
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Shadow,
            to: MoonshotStage::Canary,
        },
        GovernorDecisionKind::Hold {
            reason: "test".into(),
        },
        GovernorDecisionKind::Kill {
            triggered_criteria: vec!["k1".into(), "k2".into()],
        },
        GovernorDecisionKind::Pause { reason: "r".into() },
        GovernorDecisionKind::Resume,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let decoded: GovernorDecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 5: MoonshotStatus Display and serde
// ---------------------------------------------------------------------------

#[test]
fn moonshot_status_display() {
    assert_eq!(MoonshotStatus::Active.to_string(), "active");
    assert_eq!(
        MoonshotStatus::Paused {
            reason: "x".into(),
            paused_at_ns: 0
        }
        .to_string(),
        "paused"
    );
    assert_eq!(
        MoonshotStatus::Killed {
            reason: "y".into(),
            killed_at_ns: 0
        }
        .to_string(),
        "killed"
    );
    assert_eq!(
        MoonshotStatus::Completed { completed_at_ns: 0 }.to_string(),
        "completed"
    );
}

#[test]
fn moonshot_status_serde_roundtrip() {
    let statuses = vec![
        MoonshotStatus::Active,
        MoonshotStatus::Paused {
            reason: "r".into(),
            paused_at_ns: 100,
        },
        MoonshotStatus::Killed {
            reason: "k".into(),
            killed_at_ns: 200,
        },
        MoonshotStatus::Completed {
            completed_at_ns: 300,
        },
    ];
    for s in statuses {
        let json = serde_json::to_string(&s).unwrap();
        let decoded: MoonshotStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 6: GovernorConfig
// ---------------------------------------------------------------------------

#[test]
fn governor_config_default_values() {
    let c = GovernorConfig::default();
    assert_eq!(c.promotion_confidence_threshold_millionths, 750_000);
    assert_eq!(c.promotion_risk_threshold_millionths, 200_000);
    assert_eq!(c.hold_confidence_below_millionths, 500_000);
    assert_eq!(c.scoring_cadence_ns, 604_800_000_000_000);
}

#[test]
fn governor_config_serde_roundtrip() {
    let c = GovernorConfig {
        promotion_confidence_threshold_millionths: 900_000,
        promotion_risk_threshold_millionths: 100_000,
        hold_confidence_below_millionths: 400_000,
        scoring_cadence_ns: 1_000_000_000,
    };
    let json = serde_json::to_string(&c).unwrap();
    let decoded: GovernorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
}

// ---------------------------------------------------------------------------
// Section 7: GovernorError Display
// ---------------------------------------------------------------------------

#[test]
fn governor_error_display_all_variants() {
    let errors: Vec<GovernorError> = vec![
        GovernorError::MoonshotNotFound { id: "m1".into() },
        GovernorError::MoonshotNotActive { id: "m2".into() },
        GovernorError::InvalidContract {
            reason: "bad".into(),
        },
        GovernorError::InvalidTransition {
            from: MoonshotStage::Research,
            to: MoonshotStage::Research,
        },
        GovernorError::AlreadyRegistered { id: "m3".into() },
        GovernorError::NotPaused { id: "m4".into() },
        GovernorError::LedgerConfig {
            reason: "invalid".into(),
        },
        GovernorError::LedgerWriteFailed {
            decision_id: "d1".into(),
            reason: "fail".into(),
        },
        GovernorError::InvalidGovernanceActor {
            actor_id: "".into(),
        },
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
    // Spot-check specific formats.
    assert!(errors[0].to_string().contains("m1"));
    assert!(errors[4].to_string().contains("already registered"));
    assert!(errors[5].to_string().contains("not paused"));
}

#[test]
fn governor_error_serde_roundtrip() {
    let e = GovernorError::MoonshotNotFound {
        id: "test-id".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let decoded: GovernorError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, decoded);
}

// ---------------------------------------------------------------------------
// Section 8: PortfolioGovernor construction
// ---------------------------------------------------------------------------

#[test]
fn governor_new_empty_portfolio() {
    let gov = test_governor();
    assert!(gov.moonshots.is_empty());
    assert_eq!(gov.epoch, SecurityEpoch::from_raw(1));
}

// ---------------------------------------------------------------------------
// Section 9: Registration
// ---------------------------------------------------------------------------

#[test]
fn register_moonshot_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 1_000_000_000)
        .unwrap();
    assert_eq!(gov.moonshots.len(), 1);
    let state = &gov.moonshots["mc-integ-001"];
    assert!(state.is_active());
    assert_eq!(state.started_at_ns, 1_000_000_000);
    assert_eq!(state.budget_spent_fraction_millionths, 0);
}

#[test]
fn register_duplicate_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 1_000).unwrap();
    let err = gov.register_moonshot(test_contract(), 2_000).unwrap_err();
    assert!(matches!(err, GovernorError::AlreadyRegistered { .. }));
}

#[test]
fn register_invalid_contract_empty_id() {
    let mut gov = test_governor();
    let mut c = test_contract();
    c.contract_id = String::new();
    let err = gov.register_moonshot(c, 0).unwrap_err();
    assert!(matches!(err, GovernorError::InvalidContract { .. }));
}

// ---------------------------------------------------------------------------
// Section 10: Artifact submission
// ---------------------------------------------------------------------------

#[test]
fn submit_artifact_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    assert_eq!(gov.moonshots["mc-integ-001"].completed_artifacts.len(), 1);
}

#[test]
fn submit_artifact_not_found_fails() {
    let mut gov = test_governor();
    let err = gov
        .submit_artifact("nope", make_evidence("a1", "o1"))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn submit_artifact_not_active_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.pause_moonshot("mc-integ-001", "test", 100).unwrap();
    let err = gov
        .submit_artifact("mc-integ-001", make_evidence("a1", "o1"))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

// ---------------------------------------------------------------------------
// Section 11: Metric recording
// ---------------------------------------------------------------------------

#[test]
fn record_metric_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 200_000_000, 1_000),
    )
    .unwrap();
    assert_eq!(gov.moonshots["mc-integ-001"].metric_history.len(), 1);
}

#[test]
fn record_metric_not_found_fails() {
    let mut gov = test_governor();
    let err = gov
        .record_metric("nope", make_observation("m", 0, 0))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn record_metric_killed_moonshot_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    // Trigger a kill via time expiry.
    let started = gov.moonshots["mc-integ-001"].started_at_ns;
    let far_future = started + 17_280_000_000_000_000; // 200 days
    let _ = gov.check_kill_criteria("mc-integ-001", far_future);
    let err = gov
        .record_metric("mc-integ-001", make_observation("m", 0, far_future + 1))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

// ---------------------------------------------------------------------------
// Section 12: Budget updates
// ---------------------------------------------------------------------------

#[test]
fn update_budget_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.update_budget("mc-integ-001", 350_000).unwrap();
    assert_eq!(
        gov.moonshots["mc-integ-001"].budget_spent_fraction_millionths,
        350_000
    );
}

#[test]
fn update_budget_not_found_fails() {
    let mut gov = test_governor();
    let err = gov.update_budget("nope", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn update_budget_not_active_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.pause_moonshot("mc-integ-001", "test", 0).unwrap();
    let err = gov.update_budget("mc-integ-001", 100).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

// ---------------------------------------------------------------------------
// Section 13: Scorecard computation
// ---------------------------------------------------------------------------

#[test]
fn compute_scorecard_no_metrics() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    let sc = gov.compute_scorecard("mc-integ-001", 1_000).unwrap();
    assert_eq!(sc.moonshot_id, "mc-integ-001");
    assert_eq!(sc.confidence_millionths, 0); // no metrics -> 0
    assert_eq!(sc.computed_at_ns, 1_000);
    assert_eq!(sc.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn compute_scorecard_with_metrics_builds_confidence() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    record_n_good_metrics(&mut gov, "mc-integ-001", 10);
    let sc = gov
        .compute_scorecard("mc-integ-001", 11_000_000_000)
        .unwrap();
    // 10 * 100_000 = 1_000_000 (capped at 1M)
    assert_eq!(sc.confidence_millionths, 1_000_000);
}

#[test]
fn compute_scorecard_confidence_caps_at_one_million() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    // 15 metrics: 15 * 100_000 = 1_500_000 but capped at 1M
    record_n_good_metrics(&mut gov, "mc-integ-001", 15);
    let sc = gov
        .compute_scorecard("mc-integ-001", 20_000_000_000)
        .unwrap();
    assert_eq!(sc.confidence_millionths, 1_000_000);
}

#[test]
fn compute_scorecard_not_found_fails() {
    let gov = test_governor();
    let err = gov.compute_scorecard("nope", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn compute_scorecard_interference_proportional_to_active_count() {
    let mut gov = test_governor();
    // Register 3 active moonshots.
    for i in 1..=3 {
        gov.register_moonshot(test_contract_with_id(&format!("mc-{i}")), 0)
            .unwrap();
    }
    let sc = gov.compute_scorecard("mc-1", 1_000).unwrap();
    // 3 active => interference = (3-1) * 50_000 = 100_000
    assert_eq!(sc.cross_initiative_interference_millionths, 100_000);
}

#[test]
fn compute_scorecard_friction_inverse_of_completion() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    // 2 obligations, 0 completed => friction = 1_000_000
    let sc1 = gov.compute_scorecard("mc-integ-001", 100).unwrap();
    assert_eq!(sc1.implementation_friction_millionths, 1_000_000);

    // Submit 1 of 2 => friction = 500_000
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    let sc2 = gov.compute_scorecard("mc-integ-001", 200).unwrap();
    assert_eq!(sc2.implementation_friction_millionths, 500_000);
}

#[test]
fn compute_scorecard_budget_reflected_in_burden() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.update_budget("mc-integ-001", 750_000).unwrap();
    let sc = gov.compute_scorecard("mc-integ-001", 100).unwrap();
    assert_eq!(sc.operational_burden_millionths, 750_000);
}

// ---------------------------------------------------------------------------
// Section 14: Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_gate_hold_no_artifacts() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    record_n_good_metrics(&mut gov, "mc-integ-001", 10);
    let d = gov.evaluate_gate("mc-integ-001", 11_000_000_000).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Hold { .. }));
    assert!(d.rationale.contains("obligation"));
}

#[test]
fn evaluate_gate_hold_low_confidence() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    // Only 2 metrics => confidence = 200_000 (< 500_000 hold threshold)
    record_n_good_metrics(&mut gov, "mc-integ-001", 2);
    let d = gov.evaluate_gate("mc-integ-001", 3_000_000_000).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Hold { .. }));
    assert!(d.rationale.contains("Confidence"));
}

#[test]
fn evaluate_gate_hold_risk_too_high() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    // High budget consumption => high risk score.
    gov.update_budget("mc-integ-001", 800_000).unwrap();
    // Record bad metric that misses threshold.
    for i in 0..8 {
        gov.record_metric(
            "mc-integ-001",
            make_observation("latency_p50", 300_000_000, (i + 1) * 1_000_000_000),
        )
        .unwrap();
    }
    let d = gov.evaluate_gate("mc-integ-001", 9_000_000_000).unwrap();
    // Should hold due to risk exceeding threshold.
    assert!(matches!(d.kind, GovernorDecisionKind::Hold { .. }));
}

#[test]
fn evaluate_gate_promote_research_to_shadow() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    record_n_good_metrics(&mut gov, "mc-integ-001", 8);
    let d = gov.evaluate_gate("mc-integ-001", 9_000_000_000).unwrap();
    assert!(matches!(
        d.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow
        }
    ));
    assert_eq!(
        gov.moonshots["mc-integ-001"].contract.current_stage,
        MoonshotStage::Shadow
    );
}

#[test]
fn evaluate_gate_hold_at_production_stage() {
    let mut gov = test_governor();
    let mut c = test_contract();
    c.current_stage = MoonshotStage::Production;
    gov.register_moonshot(c, 0).unwrap();
    let d = gov.evaluate_gate("mc-integ-001", 1_000).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Hold { .. }));
    assert!(d.rationale.contains("production"));
}

#[test]
fn evaluate_gate_hold_confidence_between_hold_and_promotion_threshold() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    // 6 metrics => confidence = 600_000 which is above hold (500K) but below promotion (750K)
    record_n_good_metrics(&mut gov, "mc-integ-001", 6);
    let d = gov.evaluate_gate("mc-integ-001", 7_000_000_000).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Hold { .. }));
    assert!(d.rationale.contains("below promotion"));
}

// ---------------------------------------------------------------------------
// Section 15: Kill criteria
// ---------------------------------------------------------------------------

#[test]
fn kill_criteria_time_expiry() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 1_000_000_000)
        .unwrap();
    let far_future = 1_000_000_000 + 17_280_000_000_000_000; // 200 days
    let kill = gov
        .check_kill_criteria("mc-integ-001", far_future)
        .unwrap()
        .expect("should trigger kill");
    assert!(matches!(kill.kind, GovernorDecisionKind::Kill { .. }));
    assert!(matches!(
        gov.moonshots["mc-integ-001"].status,
        MoonshotStatus::Killed { .. }
    ));
}

#[test]
fn kill_criteria_budget_exhausted_no_signal() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.update_budget("mc-integ-001", 950_000).unwrap();
    // Record bad metric above threshold (not meeting target).
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 300_000_000, 2_000_000_000),
    )
    .unwrap();
    let kill = gov
        .check_kill_criteria("mc-integ-001", 3_000_000_000)
        .unwrap()
        .expect("should trigger kill");
    assert!(matches!(kill.kind, GovernorDecisionKind::Kill { .. }));
}

#[test]
fn no_kill_when_under_thresholds() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    let result = gov
        .check_kill_criteria("mc-integ-001", 2_000_000_000)
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn kill_criteria_not_active_returns_none() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.pause_moonshot("mc-integ-001", "test", 100).unwrap();
    let result = gov.check_kill_criteria("mc-integ-001", 200).unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Section 16: Pause and resume
// ---------------------------------------------------------------------------

#[test]
fn pause_moonshot_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    let d = gov
        .pause_moonshot("mc-integ-001", "resource reallocation", 1_000)
        .unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Pause { .. }));
    assert!(matches!(
        gov.moonshots["mc-integ-001"].status,
        MoonshotStatus::Paused { .. }
    ));
}

#[test]
fn resume_moonshot_success() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.pause_moonshot("mc-integ-001", "test", 100).unwrap();
    let d = gov.resume_moonshot("mc-integ-001", 200).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Resume));
    assert!(gov.moonshots["mc-integ-001"].is_active());
}

#[test]
fn pause_not_active_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    // Kill the moonshot first.
    let started = gov.moonshots["mc-integ-001"].started_at_ns;
    let _ = gov.check_kill_criteria("mc-integ-001", started + 17_280_000_000_000_000);
    let err = gov.pause_moonshot("mc-integ-001", "test", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

#[test]
fn resume_not_paused_fails() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    let err = gov.resume_moonshot("mc-integ-001", 0).unwrap_err();
    assert!(matches!(err, GovernorError::NotPaused { .. }));
}

#[test]
fn pause_not_found_fails() {
    let mut gov = test_governor();
    let err = gov.pause_moonshot("nope", "test", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Section 17: Portfolio ranking
// ---------------------------------------------------------------------------

#[test]
fn rank_portfolio_single_entry() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    let rankings = gov.rank_portfolio(1_000);
    assert_eq!(rankings.len(), 1);
    assert_eq!(rankings[0].0, "mc-integ-001");
}

#[test]
fn rank_portfolio_sorted_descending() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract_with_id("mc-low"), 0)
        .unwrap();
    let mut high_ev = test_contract_with_id("mc-high");
    high_ev.ev_model.benefit_on_success_millionths = 10_000_000;
    gov.register_moonshot(high_ev, 0).unwrap();
    // Add metrics so confidence > 0.
    for id in ["mc-low", "mc-high"] {
        record_n_good_metrics(&mut gov, id, 10);
    }
    let rankings = gov.rank_portfolio(11_000_000_000);
    assert_eq!(rankings.len(), 2);
    assert_eq!(rankings[0].0, "mc-high");
    assert!(rankings[0].1 > rankings[1].1);
}

#[test]
fn rank_portfolio_excludes_non_active() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.pause_moonshot("mc-integ-001", "test", 100).unwrap();
    let rankings = gov.rank_portfolio(200);
    assert!(rankings.is_empty());
}

#[test]
fn rank_portfolio_empty() {
    let gov = test_governor();
    let rankings = gov.rank_portfolio(0);
    assert!(rankings.is_empty());
}

// ---------------------------------------------------------------------------
// Section 18: Latest scorecard and decisions accessors
// ---------------------------------------------------------------------------

#[test]
fn latest_scorecard_none_before_evaluation() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    assert!(gov.latest_scorecard("mc-integ-001").is_none());
}

#[test]
fn latest_scorecard_after_evaluation() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.evaluate_gate("mc-integ-001", 1_000).unwrap();
    let sc = gov.latest_scorecard("mc-integ-001").unwrap();
    assert_eq!(sc.moonshot_id, "mc-integ-001");
}

#[test]
fn decisions_tracked() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.evaluate_gate("mc-integ-001", 1_000).unwrap();
    gov.evaluate_gate("mc-integ-001", 2_000).unwrap();
    let decisions = gov.decisions("mc-integ-001").unwrap();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].decision_id, "gov-1");
    assert_eq!(decisions[1].decision_id, "gov-2");
}

#[test]
fn decisions_none_for_unknown() {
    let gov = test_governor();
    assert!(gov.decisions("nope").is_none());
}

// ---------------------------------------------------------------------------
// Section 19: MoonshotState helper methods
// ---------------------------------------------------------------------------

#[test]
fn moonshot_state_latest_metric() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 100_000, 1_000),
    )
    .unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 200_000, 2_000),
    )
    .unwrap();
    let state = &gov.moonshots["mc-integ-001"];
    let latest = state.latest_metric("latency_p50").unwrap();
    assert_eq!(latest.value_millionths, 200_000);
    assert!(state.latest_metric("nonexistent").is_none());
}

#[test]
fn moonshot_state_completed_obligation_ids() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.submit_artifact("mc-integ-001", make_evidence("a1", "proof-research"))
        .unwrap();
    let state = &gov.moonshots["mc-integ-001"];
    let ids = state.completed_obligation_ids();
    assert_eq!(ids, vec!["proof-research".to_string()]);
}

#[test]
fn moonshot_state_metric_snapshot() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 100_000, 1_000),
    )
    .unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("latency_p50", 200_000, 2_000),
    )
    .unwrap();
    gov.record_metric(
        "mc-integ-001",
        make_observation("throughput", 500_000, 3_000),
    )
    .unwrap();
    let state = &gov.moonshots["mc-integ-001"];
    let snapshot = state.metric_snapshot();
    // BTreeMap last-wins for same key, so latency_p50 -> 200_000
    assert_eq!(snapshot["latency_p50"], 200_000);
    assert_eq!(snapshot["throughput"], 500_000);
    assert_eq!(snapshot.len(), 2);
}

#[test]
fn moonshot_state_is_active() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    assert!(gov.moonshots["mc-integ-001"].is_active());
    gov.pause_moonshot("mc-integ-001", "test", 100).unwrap();
    assert!(!gov.moonshots["mc-integ-001"].is_active());
}

// ---------------------------------------------------------------------------
// Section 20: Governance audit ledger integration
// ---------------------------------------------------------------------------

#[test]
fn enable_governance_ledger_success() {
    let mut gov = test_governor();
    gov.enable_governance_audit_ledger(
        GovernanceLedgerConfig {
            checkpoint_interval: 2,
            signer_key: b"test-key".to_vec(),
            policy_id: "policy-v1".into(),
        },
        "system-actor",
    )
    .unwrap();
    assert!(gov.governance_audit_ledger().is_some());
}

#[test]
fn enable_governance_ledger_empty_actor_fails() {
    let mut gov = test_governor();
    let err = gov
        .enable_governance_audit_ledger(GovernanceLedgerConfig::default(), "")
        .unwrap_err();
    assert!(matches!(err, GovernorError::InvalidGovernanceActor { .. }));
}

#[test]
fn enable_governance_ledger_whitespace_actor_fails() {
    let mut gov = test_governor();
    let err = gov
        .enable_governance_audit_ledger(GovernanceLedgerConfig::default(), "   ")
        .unwrap_err();
    assert!(matches!(err, GovernorError::InvalidGovernanceActor { .. }));
}

#[test]
fn governance_ledger_records_decisions() {
    let mut gov = test_governor();
    gov.enable_governance_audit_ledger(
        GovernanceLedgerConfig {
            checkpoint_interval: 10,
            signer_key: b"test-key".to_vec(),
            policy_id: "policy-test".into(),
        },
        "gov-system",
    )
    .unwrap();
    gov.register_moonshot(test_contract(), 0).unwrap();
    // Evaluate gate (produces a Hold decision).
    gov.evaluate_gate("mc-integ-001", 1_000).unwrap();
    let ledger = gov.governance_audit_ledger().unwrap();
    assert_eq!(ledger.entries().len(), 1);
    assert_eq!(ledger.entries()[0].decision_id, "gov-1");
    assert_eq!(ledger.entries()[0].actor.actor_id(), "gov-system");
}

#[test]
fn governance_ledger_not_enabled_by_default() {
    let gov = test_governor();
    assert!(gov.governance_audit_ledger().is_none());
}

// ---------------------------------------------------------------------------
// Section 21: Full lifecycle tests
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_research_to_production() {
    let mut gov = test_governor();
    let c = test_contract_no_obligations("mc-lifecycle");
    gov.register_moonshot(c, 0).unwrap();

    // Research -> Shadow
    record_n_good_metrics(&mut gov, "mc-lifecycle", 8);
    let d1 = gov.evaluate_gate("mc-lifecycle", 9_000_000_000).unwrap();
    assert!(matches!(
        d1.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow
        }
    ));

    // Shadow -> Canary
    record_n_good_metrics(&mut gov, "mc-lifecycle", 8);
    let d2 = gov.evaluate_gate("mc-lifecycle", 18_000_000_000).unwrap();
    assert!(matches!(
        d2.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Shadow,
            to: MoonshotStage::Canary
        }
    ));

    // Canary -> Production
    record_n_good_metrics(&mut gov, "mc-lifecycle", 8);
    let d3 = gov.evaluate_gate("mc-lifecycle", 27_000_000_000).unwrap();
    assert!(matches!(
        d3.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Canary,
            to: MoonshotStage::Production
        }
    ));

    // Should be completed now.
    assert!(matches!(
        gov.moonshots["mc-lifecycle"].status,
        MoonshotStatus::Completed { .. }
    ));

    // Trying to evaluate gate at Production yields Hold.
    let d4 = gov.evaluate_gate("mc-lifecycle", 30_000_000_000).unwrap();
    assert!(matches!(d4.kind, GovernorDecisionKind::Hold { .. }));
}

#[test]
fn lifecycle_pause_resume_then_promote() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract_no_obligations("mc-pr"), 0)
        .unwrap();

    // Pause.
    let pd = gov.pause_moonshot("mc-pr", "headcount", 1_000).unwrap();
    assert!(matches!(pd.kind, GovernorDecisionKind::Pause { .. }));

    // Cannot submit artifact while paused.
    let err = gov
        .submit_artifact("mc-pr", make_evidence("a1", "o1"))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));

    // Resume.
    let rd = gov.resume_moonshot("mc-pr", 2_000).unwrap();
    assert!(matches!(rd.kind, GovernorDecisionKind::Resume));

    // Now can proceed -- record metrics and promote.
    record_n_good_metrics(&mut gov, "mc-pr", 8);
    let d = gov.evaluate_gate("mc-pr", 10_000_000_000).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Promote { .. }));
}

#[test]
fn lifecycle_kill_via_evaluate_gate() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 1_000).unwrap();
    // evaluate_gate checks kill criteria first.
    let far_future = 1_000 + 17_280_000_000_000_000;
    let d = gov.evaluate_gate("mc-integ-001", far_future).unwrap();
    assert!(matches!(d.kind, GovernorDecisionKind::Kill { .. }));
    assert!(matches!(
        gov.moonshots["mc-integ-001"].status,
        MoonshotStatus::Killed { .. }
    ));
}

// ---------------------------------------------------------------------------
// Section 22: GovernorDecision serde
// ---------------------------------------------------------------------------

#[test]
fn governor_decision_serde_roundtrip() {
    let d = GovernorDecision {
        decision_id: "d1".into(),
        moonshot_id: "m1".into(),
        kind: GovernorDecisionKind::Hold {
            reason: "waiting".into(),
        },
        scorecard: Scorecard {
            moonshot_id: "m1".into(),
            ev_millionths: 100,
            confidence_millionths: 200,
            risk_of_harm_millionths: 300,
            implementation_friction_millionths: 400,
            cross_initiative_interference_millionths: 500,
            operational_burden_millionths: 600,
            computed_at_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        },
        timestamp_ns: 999,
        epoch: SecurityEpoch::from_raw(1),
        rationale: "test rationale".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: GovernorDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

// ---------------------------------------------------------------------------
// Section 23: Governor serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn governor_serde_roundtrip() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    record_n_good_metrics(&mut gov, "mc-integ-001", 5);
    gov.evaluate_gate("mc-integ-001", 6_000_000_000).unwrap();
    let json = serde_json::to_string(&gov).unwrap();
    let decoded: PortfolioGovernor = serde_json::from_str(&json).unwrap();
    assert_eq!(gov, decoded);
}

// ---------------------------------------------------------------------------
// Section 24: MoonshotState serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn moonshot_state_serde_roundtrip() {
    let state = MoonshotState {
        contract: test_contract(),
        status: MoonshotStatus::Active,
        scorecard_history: Vec::new(),
        completed_artifacts: Vec::new(),
        metric_history: Vec::new(),
        decisions: Vec::new(),
        started_at_ns: 42,
        budget_spent_fraction_millionths: 100_000,
    };
    let json = serde_json::to_string(&state).unwrap();
    let decoded: MoonshotState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, decoded);
}

// ---------------------------------------------------------------------------
// Section 25: Decision counter monotonicity
// ---------------------------------------------------------------------------

#[test]
fn decision_ids_are_monotonically_increasing() {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 0).unwrap();
    gov.evaluate_gate("mc-integ-001", 1_000).unwrap();
    gov.evaluate_gate("mc-integ-001", 2_000).unwrap();
    gov.evaluate_gate("mc-integ-001", 3_000).unwrap();
    let decisions = gov.decisions("mc-integ-001").unwrap();
    assert_eq!(decisions.len(), 3);
    assert_eq!(decisions[0].decision_id, "gov-1");
    assert_eq!(decisions[1].decision_id, "gov-2");
    assert_eq!(decisions[2].decision_id, "gov-3");
}
