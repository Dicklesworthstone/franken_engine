//! Edge-case integration tests for the portfolio_governor module.

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
use frankenengine_engine::portfolio_governor::{
    ArtifactEvidence, GovernorConfig, GovernorDecisionKind, GovernorError, MetricObservation,
    MoonshotStatus, PortfolioGovernor, Scorecard,
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
    MoonshotContract {
        contract_id: "mc-test-001".into(),
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

fn test_governor() -> PortfolioGovernor {
    PortfolioGovernor::new(GovernorConfig::default(), SecurityEpoch::from_raw(1))
}

fn register_test_moonshot(gov: &mut PortfolioGovernor) {
    gov.register_moonshot(test_contract(), 1_000_000_000)
        .unwrap();
}

fn add_metrics(gov: &mut PortfolioGovernor, id: &str, count: usize) {
    for i in 0..count {
        gov.record_metric(
            id,
            MetricObservation {
                metric_id: "latency_p50".into(),
                value_millionths: 200_000_000, // below 250M threshold = good
                observed_at_ns: ((i + 1) as u64) * 1_000_000_000,
            },
        )
        .unwrap();
    }
}

fn submit_research_artifact(gov: &mut PortfolioGovernor, id: &str) {
    gov.submit_artifact(
        id,
        ArtifactEvidence {
            artifact_id: "art-proof".into(),
            obligation_id: "proof-research".into(),
            artifact_type: ArtifactType::Proof,
            submitted_at_ns: 1_000_000_000,
            content_hash: "hash-proof".into(),
        },
    )
    .unwrap();
}

// ===========================================================================
// Scorecard edge cases
// ===========================================================================

#[test]
fn scorecard_serde_roundtrip() {
    let sc = Scorecard {
        moonshot_id: "mc-001".into(),
        ev_millionths: -500_000,
        confidence_millionths: 800_000,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 50_000,
        cross_initiative_interference_millionths: 30_000,
        operational_burden_millionths: 20_000,
        computed_at_ns: 42_000_000_000,
        epoch: SecurityEpoch::from_raw(3),
    };
    let json = serde_json::to_string(&sc).unwrap();
    let back: Scorecard = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sc);
}

#[test]
fn scorecard_risk_adjusted_ev_negative_ev() {
    let sc = Scorecard {
        moonshot_id: "test".into(),
        ev_millionths: -2_000_000,
        confidence_millionths: 1_000_000,
        risk_of_harm_millionths: 0,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    // ev * conf / 1M = -2M * 1M / 1M = -2M
    assert_eq!(sc.risk_adjusted_ev(), -2_000_000);
}

#[test]
fn scorecard_risk_adjusted_ev_zero_confidence() {
    let sc = Scorecard {
        moonshot_id: "test".into(),
        ev_millionths: 10_000_000,
        confidence_millionths: 0,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 50_000,
        cross_initiative_interference_millionths: 30_000,
        operational_burden_millionths: 20_000,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    // ev * 0 / 1M - risk*2 - interference - friction - burden
    // = 0 - 200K - 30K - 50K - 20K = -300_000
    assert_eq!(sc.risk_adjusted_ev(), -300_000);
}

#[test]
fn scorecard_risk_adjusted_ev_all_zero() {
    let sc = Scorecard {
        moonshot_id: "test".into(),
        ev_millionths: 0,
        confidence_millionths: 0,
        risk_of_harm_millionths: 0,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    assert_eq!(sc.risk_adjusted_ev(), 0);
}

// ===========================================================================
// GovernorDecisionKind serde / display
// ===========================================================================

#[test]
fn governor_decision_kind_serde_all_variants() {
    let kinds = vec![
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        GovernorDecisionKind::Hold {
            reason: "more data needed".into(),
        },
        GovernorDecisionKind::Kill {
            triggered_criteria: vec!["time-kill".into(), "budget-kill".into()],
        },
        GovernorDecisionKind::Pause {
            reason: "resource reallocation".into(),
        },
        GovernorDecisionKind::Resume,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: GovernorDecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kind);
    }
}

#[test]
fn governor_decision_kind_display_all() {
    assert_eq!(
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Shadow,
            to: MoonshotStage::Canary,
        }
        .to_string(),
        "promote(shadow->canary)"
    );
    assert_eq!(
        GovernorDecisionKind::Hold {
            reason: "test".into()
        }
        .to_string(),
        "hold(test)"
    );
    assert_eq!(
        GovernorDecisionKind::Kill {
            triggered_criteria: vec!["a".into()]
        }
        .to_string(),
        "kill"
    );
    assert_eq!(
        GovernorDecisionKind::Pause { reason: "r".into() }.to_string(),
        "pause(r)"
    );
    assert_eq!(GovernorDecisionKind::Resume.to_string(), "resume");
}

// ===========================================================================
// MoonshotStatus serde / display
// ===========================================================================

#[test]
fn moonshot_status_serde_all_variants() {
    let statuses = vec![
        MoonshotStatus::Active,
        MoonshotStatus::Paused {
            reason: "resources".into(),
            paused_at_ns: 42,
        },
        MoonshotStatus::Killed {
            reason: "time expired".into(),
            killed_at_ns: 99,
        },
        MoonshotStatus::Completed {
            completed_at_ns: 100,
        },
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: MoonshotStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

#[test]
fn moonshot_status_display_all() {
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
            reason: "x".into(),
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

// ===========================================================================
// GovernorError serde / display / std::error
// ===========================================================================

#[test]
fn governor_error_serde_all_variants() {
    let errors: Vec<GovernorError> = vec![
        GovernorError::MoonshotNotFound { id: "a".into() },
        GovernorError::MoonshotNotActive { id: "b".into() },
        GovernorError::InvalidContract {
            reason: "bad".into(),
        },
        GovernorError::InvalidTransition {
            from: MoonshotStage::Research,
            to: MoonshotStage::Research,
        },
        GovernorError::AlreadyRegistered { id: "c".into() },
        GovernorError::NotPaused { id: "d".into() },
        GovernorError::LedgerConfig {
            reason: "missing key".into(),
        },
        GovernorError::LedgerWriteFailed {
            decision_id: "gov-1".into(),
            reason: "io error".into(),
        },
        GovernorError::InvalidGovernanceActor {
            actor_id: "".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: GovernorError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn governor_error_display_all() {
    let e1 = GovernorError::MoonshotNotFound { id: "a".into() };
    assert!(format!("{e1}").contains("a"));

    let e2 = GovernorError::MoonshotNotActive { id: "b".into() };
    assert!(format!("{e2}").contains("b"));

    let e3 = GovernorError::InvalidContract {
        reason: "bad".into(),
    };
    assert!(format!("{e3}").contains("bad"));

    let e4 = GovernorError::InvalidTransition {
        from: MoonshotStage::Research,
        to: MoonshotStage::Canary,
    };
    let msg4 = format!("{e4}");
    assert!(msg4.contains("research"));
    assert!(msg4.contains("canary"));

    let e5 = GovernorError::AlreadyRegistered { id: "c".into() };
    assert!(format!("{e5}").contains("c"));

    let e6 = GovernorError::NotPaused { id: "d".into() };
    assert!(format!("{e6}").contains("d"));

    let e7 = GovernorError::LedgerConfig {
        reason: "missing".into(),
    };
    assert!(format!("{e7}").contains("missing"));

    let e8 = GovernorError::LedgerWriteFailed {
        decision_id: "gov-1".into(),
        reason: "io".into(),
    };
    let msg8 = format!("{e8}");
    assert!(msg8.contains("gov-1"));
    assert!(msg8.contains("io"));

    let e9 = GovernorError::InvalidGovernanceActor {
        actor_id: "bad".into(),
    };
    assert!(format!("{e9}").contains("bad"));
}

#[test]
fn governor_error_implements_std_error() {
    let err = GovernorError::MoonshotNotFound { id: "x".into() };
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// GovernorConfig
// ===========================================================================

#[test]
fn governor_config_serde_roundtrip() {
    let cfg = GovernorConfig {
        promotion_confidence_threshold_millionths: 900_000,
        promotion_risk_threshold_millionths: 100_000,
        hold_confidence_below_millionths: 600_000,
        scoring_cadence_ns: 86_400_000_000_000,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GovernorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn governor_config_default_values() {
    let cfg = GovernorConfig::default();
    assert_eq!(cfg.promotion_confidence_threshold_millionths, 750_000);
    assert_eq!(cfg.promotion_risk_threshold_millionths, 200_000);
    assert_eq!(cfg.hold_confidence_below_millionths, 500_000);
    assert_eq!(cfg.scoring_cadence_ns, 604_800_000_000_000);
}

// ===========================================================================
// ArtifactEvidence / MetricObservation serde
// ===========================================================================

#[test]
fn artifact_evidence_serde_roundtrip() {
    let ae = ArtifactEvidence {
        artifact_id: "art-1".into(),
        obligation_id: "proof-research".into(),
        artifact_type: ArtifactType::Proof,
        submitted_at_ns: 42_000_000_000,
        content_hash: "sha256:abc123".into(),
    };
    let json = serde_json::to_string(&ae).unwrap();
    let back: ArtifactEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ae);
}

#[test]
fn metric_observation_serde_roundtrip() {
    let obs = MetricObservation {
        metric_id: "latency_p99".into(),
        value_millionths: -500_000,
        observed_at_ns: 99_000_000_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: MetricObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, obs);
}

// ===========================================================================
// MoonshotState helpers
// ===========================================================================

#[test]
fn moonshot_state_latest_metric_not_found() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    assert!(
        gov.moonshots["mc-test-001"]
            .latest_metric("nonexistent")
            .is_none()
    );
}

#[test]
fn moonshot_state_latest_metric_returns_last() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    gov.record_metric(
        "mc-test-001",
        MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 300_000_000,
            observed_at_ns: 1_000_000_000,
        },
    )
    .unwrap();
    gov.record_metric(
        "mc-test-001",
        MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 200_000_000,
            observed_at_ns: 2_000_000_000,
        },
    )
    .unwrap();
    let latest = gov.moonshots["mc-test-001"]
        .latest_metric("latency_p50")
        .unwrap();
    assert_eq!(latest.value_millionths, 200_000_000);
}

#[test]
fn moonshot_state_completed_obligation_ids() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    let ids = gov.moonshots["mc-test-001"].completed_obligation_ids();
    assert_eq!(ids, vec!["proof-research"]);
}

#[test]
fn moonshot_state_metric_snapshot_overwrites() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    // Two observations for same metric — snapshot should keep latest
    gov.record_metric(
        "mc-test-001",
        MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 300_000_000,
            observed_at_ns: 1_000_000_000,
        },
    )
    .unwrap();
    gov.record_metric(
        "mc-test-001",
        MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 200_000_000,
            observed_at_ns: 2_000_000_000,
        },
    )
    .unwrap();
    let snapshot = gov.moonshots["mc-test-001"].metric_snapshot();
    // BTreeMap insert overwrites, so the last value wins
    assert_eq!(snapshot["latency_p50"], 200_000_000);
}

#[test]
fn moonshot_state_is_active_only_for_active() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    assert!(gov.moonshots["mc-test-001"].is_active());

    // Pause and check
    gov.pause_moonshot("mc-test-001", "test", 2_000_000_000)
        .unwrap();
    assert!(!gov.moonshots["mc-test-001"].is_active());
}

// ===========================================================================
// Scorecard computation edge cases
// ===========================================================================

#[test]
fn scorecard_confidence_caps_at_one_million() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    // 15 metrics → 15*100_000 = 1_500_000 → capped to 1_000_000
    add_metrics(&mut gov, "mc-test-001", 15);
    let sc = gov
        .compute_scorecard("mc-test-001", 20_000_000_000)
        .unwrap();
    assert_eq!(sc.confidence_millionths, 1_000_000);
}

#[test]
fn scorecard_interference_scales_with_active_count() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);

    // 1 active moonshot → interference = 0
    let sc1 = gov.compute_scorecard("mc-test-001", 2_000_000_000).unwrap();
    assert_eq!(sc1.cross_initiative_interference_millionths, 0);

    // Add second moonshot
    let mut c2 = test_contract();
    c2.contract_id = "mc-test-002".into();
    gov.register_moonshot(c2, 1_000_000_000).unwrap();

    // 2 active moonshots → interference = (2-1)*50_000 = 50_000
    let sc2 = gov.compute_scorecard("mc-test-001", 2_000_000_000).unwrap();
    assert_eq!(sc2.cross_initiative_interference_millionths, 50_000);
}

#[test]
fn scorecard_interference_caps_at_500k() {
    let mut gov = test_governor();
    // Register 12 moonshots for max interference
    for i in 0..12 {
        let mut c = test_contract();
        c.contract_id = format!("mc-{i:03}");
        gov.register_moonshot(c, 1_000_000_000).unwrap();
    }
    // 12 active → (12-1)*50_000 = 550_000 → capped to 500_000
    let sc = gov.compute_scorecard("mc-000", 2_000_000_000).unwrap();
    assert_eq!(sc.cross_initiative_interference_millionths, 500_000);
}

#[test]
fn scorecard_burden_from_budget() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    gov.update_budget("mc-test-001", 300_000).unwrap();
    let sc = gov.compute_scorecard("mc-test-001", 2_000_000_000).unwrap();
    assert_eq!(sc.operational_burden_millionths, 300_000);
}

// ===========================================================================
// Gate evaluation edge cases
// ===========================================================================

#[test]
fn gate_hold_risk_too_high() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    add_metrics(&mut gov, "mc-test-001", 8); // high confidence
    // Set very high budget consumption to increase risk score
    gov.update_budget("mc-test-001", 1_000_000).unwrap();
    // Add metric above threshold to further increase risk
    gov.record_metric(
        "mc-test-001",
        MetricObservation {
            metric_id: "latency_p50".into(),
            value_millionths: 300_000_000, // above 250M threshold
            observed_at_ns: 100_000_000_000,
        },
    )
    .unwrap();

    let decision = gov.evaluate_gate("mc-test-001", 101_000_000_000).unwrap();
    // Should be Hold due to high risk or Kill from kill criteria
    match &decision.kind {
        GovernorDecisionKind::Hold { reason } => {
            assert!(reason.contains("risk") || reason.contains("confidence"));
        }
        GovernorDecisionKind::Kill { .. } => {
            // kill criteria may fire from budget exhaustion
        }
        other => panic!("expected Hold or Kill, got: {other}"),
    }
}

#[test]
fn gate_hold_confidence_between_hold_and_promotion() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    // 6 metrics → 600_000 confidence (between 500K hold and 750K promotion)
    add_metrics(&mut gov, "mc-test-001", 6);

    let decision = gov.evaluate_gate("mc-test-001", 7_000_000_000).unwrap();
    assert!(matches!(decision.kind, GovernorDecisionKind::Hold { .. }));
}

#[test]
fn gate_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov.evaluate_gate("ghost", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

// ===========================================================================
// Multi-stage promotion
// ===========================================================================

#[test]
fn promote_research_to_shadow() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    add_metrics(&mut gov, "mc-test-001", 8);

    let decision = gov.evaluate_gate("mc-test-001", 10_000_000_000).unwrap();
    assert!(matches!(
        decision.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow
        }
    ));
    assert_eq!(
        gov.moonshots["mc-test-001"].contract.current_stage,
        MoonshotStage::Shadow
    );
}

#[test]
fn promote_shadow_to_canary() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    add_metrics(&mut gov, "mc-test-001", 8);

    // Promote Research → Shadow
    gov.evaluate_gate("mc-test-001", 10_000_000_000).unwrap();
    assert_eq!(
        gov.moonshots["mc-test-001"].contract.current_stage,
        MoonshotStage::Shadow
    );

    // Submit shadow obligation
    gov.submit_artifact(
        "mc-test-001",
        ArtifactEvidence {
            artifact_id: "art-bench".into(),
            obligation_id: "bench-shadow".into(),
            artifact_type: ArtifactType::BenchmarkResult,
            submitted_at_ns: 11_000_000_000,
            content_hash: "hash-bench".into(),
        },
    )
    .unwrap();

    // Promote Shadow → Canary
    let decision = gov.evaluate_gate("mc-test-001", 12_000_000_000).unwrap();
    assert!(matches!(
        decision.kind,
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Shadow,
            to: MoonshotStage::Canary
        }
    ));
}

// ===========================================================================
// Kill criteria edge cases
// ===========================================================================

#[test]
fn kill_criteria_not_checked_on_killed() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    // Manually kill it
    gov.moonshots.get_mut("mc-test-001").unwrap().status = MoonshotStatus::Killed {
        reason: "manual".into(),
        killed_at_ns: 0,
    };
    let result = gov
        .check_kill_criteria("mc-test-001", 999_000_000_000_000_000)
        .unwrap();
    assert!(result.is_none(), "killed moonshot should not trigger again");
}

#[test]
fn kill_criteria_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov.check_kill_criteria("ghost", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

// ===========================================================================
// Pause/Resume edge cases
// ===========================================================================

#[test]
fn pause_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov.pause_moonshot("ghost", "reason", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn resume_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov.resume_moonshot("ghost", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn resume_active_fails() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    let err = gov.resume_moonshot("mc-test-001", 0).unwrap_err();
    assert!(matches!(err, GovernorError::NotPaused { .. }));
}

#[test]
fn pause_resume_cycle_decision_ids_increment() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    let d1 = gov
        .pause_moonshot("mc-test-001", "need resources", 2_000_000_000)
        .unwrap();
    let d2 = gov.resume_moonshot("mc-test-001", 3_000_000_000).unwrap();
    assert_eq!(d1.decision_id, "gov-1");
    assert_eq!(d2.decision_id, "gov-2");
}

#[test]
fn submit_artifact_to_paused_fails() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    gov.pause_moonshot("mc-test-001", "test", 2_000_000_000)
        .unwrap();
    let err = gov
        .submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-x".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: 3_000_000_000,
                content_hash: "hash".into(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

#[test]
fn record_metric_to_paused_fails() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    gov.pause_moonshot("mc-test-001", "test", 2_000_000_000)
        .unwrap();
    let err = gov
        .record_metric(
            "mc-test-001",
            MetricObservation {
                metric_id: "x".into(),
                value_millionths: 0,
                observed_at_ns: 0,
            },
        )
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

#[test]
fn update_budget_to_killed_fails() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    gov.moonshots.get_mut("mc-test-001").unwrap().status = MoonshotStatus::Killed {
        reason: "test".into(),
        killed_at_ns: 0,
    };
    let err = gov.update_budget("mc-test-001", 100_000).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

// ===========================================================================
// Portfolio ranking edge cases
// ===========================================================================

#[test]
fn rank_portfolio_empty() {
    let gov = test_governor();
    let rankings = gov.rank_portfolio(0);
    assert!(rankings.is_empty());
}

#[test]
fn rank_portfolio_excludes_paused_and_killed() {
    let mut gov = test_governor();
    // Register 3 moonshots
    register_test_moonshot(&mut gov);
    let mut c2 = test_contract();
    c2.contract_id = "mc-002".into();
    gov.register_moonshot(c2, 1_000_000_000).unwrap();
    let mut c3 = test_contract();
    c3.contract_id = "mc-003".into();
    gov.register_moonshot(c3, 1_000_000_000).unwrap();

    // Kill one, pause another
    gov.moonshots.get_mut("mc-002").unwrap().status = MoonshotStatus::Killed {
        reason: "test".into(),
        killed_at_ns: 0,
    };
    gov.pause_moonshot("mc-003", "test", 2_000_000_000).unwrap();

    let rankings = gov.rank_portfolio(3_000_000_000);
    assert_eq!(rankings.len(), 1);
    assert_eq!(rankings[0].0, "mc-test-001");
}

#[test]
fn rank_portfolio_descending_order() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    let mut c2 = test_contract();
    c2.contract_id = "mc-002".into();
    c2.ev_model.benefit_on_success_millionths = 10_000_000;
    gov.register_moonshot(c2, 1_000_000_000).unwrap();

    // Add metrics for nonzero confidence
    add_metrics(&mut gov, "mc-test-001", 10);
    add_metrics(&mut gov, "mc-002", 10);

    let rankings = gov.rank_portfolio(12_000_000_000);
    assert_eq!(rankings.len(), 2);
    // mc-002 has higher benefit → higher EV → ranked first
    assert!(rankings[0].1 >= rankings[1].1);
}

// ===========================================================================
// Decision tracking edge cases
// ===========================================================================

#[test]
fn decision_counter_increments_across_moonshots() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    let mut c2 = test_contract();
    c2.contract_id = "mc-002".into();
    gov.register_moonshot(c2, 1_000_000_000).unwrap();

    // Evaluate both — counter should be shared
    gov.evaluate_gate("mc-test-001", 2_000_000_000).unwrap();
    gov.evaluate_gate("mc-002", 3_000_000_000).unwrap();

    let d1 = gov.decisions("mc-test-001").unwrap();
    let d2 = gov.decisions("mc-002").unwrap();
    assert_eq!(d1[0].decision_id, "gov-1");
    assert_eq!(d2[0].decision_id, "gov-2");
}

#[test]
fn latest_scorecard_none_initially() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    assert!(gov.latest_scorecard("mc-test-001").is_none());
}

#[test]
fn latest_scorecard_none_for_nonexistent() {
    let gov = test_governor();
    assert!(gov.latest_scorecard("ghost").is_none());
}

#[test]
fn decisions_none_for_nonexistent() {
    let gov = test_governor();
    assert!(gov.decisions("ghost").is_none());
}

// ===========================================================================
// Governor serde with complex state
// ===========================================================================

#[test]
fn governor_serde_after_full_lifecycle() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    add_metrics(&mut gov, "mc-test-001", 8);
    gov.update_budget("mc-test-001", 200_000).unwrap();

    // Evaluate gate
    gov.evaluate_gate("mc-test-001", 10_000_000_000).unwrap();

    let json = serde_json::to_string(&gov).unwrap();
    let back: PortfolioGovernor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, gov);
    assert_eq!(back.moonshots.len(), 1);
}

#[test]
fn governor_deterministic_serialization() {
    let run = || -> String {
        let mut gov = test_governor();
        register_test_moonshot(&mut gov);
        submit_research_artifact(&mut gov, "mc-test-001");
        add_metrics(&mut gov, "mc-test-001", 3);
        serde_json::to_string(&gov).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Integration: full lifecycle
// ===========================================================================

#[test]
fn integration_pause_resume_then_promote() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);
    submit_research_artifact(&mut gov, "mc-test-001");
    add_metrics(&mut gov, "mc-test-001", 4);

    // Pause
    gov.pause_moonshot("mc-test-001", "reallocation", 5_000_000_000)
        .unwrap();
    assert!(!gov.moonshots["mc-test-001"].is_active());

    // Resume
    gov.resume_moonshot("mc-test-001", 6_000_000_000).unwrap();
    assert!(gov.moonshots["mc-test-001"].is_active());

    // Add more metrics for promotion
    add_metrics(&mut gov, "mc-test-001", 4); // total now 8+

    // Evaluate — should promote (artifacts met, 8+ metrics = 800k confidence)
    let decision = gov.evaluate_gate("mc-test-001", 12_000_000_000).unwrap();
    assert!(matches!(
        decision.kind,
        GovernorDecisionKind::Promote { .. }
    ));
}

#[test]
fn integration_kill_then_cannot_submit() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);

    // Time-based kill: 200 days
    let elapsed = 17_280_000_000_000_000u64;
    let now = gov.moonshots["mc-test-001"].started_at_ns + elapsed;
    let kill = gov.check_kill_criteria("mc-test-001", now).unwrap();
    assert!(kill.is_some());
    assert!(matches!(
        gov.moonshots["mc-test-001"].status,
        MoonshotStatus::Killed { .. }
    ));

    // Cannot submit artifacts to killed moonshot
    let err = gov
        .submit_artifact(
            "mc-test-001",
            ArtifactEvidence {
                artifact_id: "art-x".into(),
                obligation_id: "proof-research".into(),
                artifact_type: ArtifactType::Proof,
                submitted_at_ns: now + 1,
                content_hash: "hash".into(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotActive { .. }));
}

#[test]
fn integration_friction_decreases_with_artifact_completion() {
    let mut gov = test_governor();
    register_test_moonshot(&mut gov);

    // No artifacts → high friction
    let sc1 = gov.compute_scorecard("mc-test-001", 1_000_000_000).unwrap();

    // Submit one of two obligations
    submit_research_artifact(&mut gov, "mc-test-001");

    // Friction should decrease
    let sc2 = gov.compute_scorecard("mc-test-001", 2_000_000_000).unwrap();
    assert!(sc2.implementation_friction_millionths < sc1.implementation_friction_millionths);
}
