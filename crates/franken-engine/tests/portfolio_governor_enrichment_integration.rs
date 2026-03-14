#![forbid(unsafe_code)]

//! Enrichment integration tests for the portfolio_governor module.

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

use frankenengine_engine::moonshot_contract::{
    ArtifactObligation, ArtifactType, ContractVersion, DistributionType, EvModel, Hypothesis,
    KillCriterion, KillTrigger, MeasurementMethod, MetricDirection, MoonshotContract,
    MoonshotStage, RiskBudget, RiskDimension, RollbackPlan, RollbackStep, TargetMetric,
};
use frankenengine_engine::portfolio_governor::{
    ArtifactEvidence, GovernorConfig, GovernorDecision, GovernorDecisionKind, GovernorError,
    MetricObservation, MoonshotStatus, PortfolioGovernor, Scorecard,
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
    vec![ArtifactObligation {
        obligation_id: "poc-research".into(),
        required_at_stage: MoonshotStage::Research,
        artifact_type: ArtifactType::Proof,
        description: "Proof of concept".into(),
        blocking: true,
    }]
}

fn test_kill_criteria() -> Vec<KillCriterion> {
    vec![KillCriterion {
        criterion_id: "time-kill".into(),
        trigger: KillTrigger::TimeExpiry,
        condition: "180 days without promotion".into(),
        threshold_millionths: None,
        max_duration_ns: Some(15_552_000_000_000_000),
    }]
}

fn test_rollback() -> RollbackPlan {
    RollbackPlan {
        steps: vec![RollbackStep {
            step_number: 1,
            description: "Revert".into(),
            verification: "verify".into(),
        }],
        artifact_references: vec!["checkpoint-1".into()],
        expected_state_after_rollback: "Pre-moonshot".into(),
    }
}

fn test_contract() -> MoonshotContract {
    MoonshotContract {
        contract_id: "mc-enrich-001".into(),
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

fn governor_with_moonshot() -> PortfolioGovernor {
    let mut gov = test_governor();
    gov.register_moonshot(test_contract(), 1_000_000_000)
        .unwrap();
    gov
}

fn make_evidence(artifact_id: &str, obligation_id: &str) -> ArtifactEvidence {
    ArtifactEvidence {
        artifact_id: artifact_id.into(),
        obligation_id: obligation_id.into(),
        artifact_type: ArtifactType::Proof,
        submitted_at_ns: 2_000_000_000,
        content_hash: "sha256:abc".into(),
    }
}

fn make_observation(metric_id: &str, value: i64, at_ns: u64) -> MetricObservation {
    MetricObservation {
        metric_id: metric_id.into(),
        value_millionths: value,
        observed_at_ns: at_ns,
    }
}

// ---------------------------------------------------------------------------
// Scorecard — Clone / Debug / risk_adjusted_ev / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scorecard_clone_independence() {
    let a = Scorecard {
        moonshot_id: "m1".into(),
        ev_millionths: 1_000_000,
        confidence_millionths: 800_000,
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 50_000,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 1_000,
        epoch: SecurityEpoch::from_raw(1),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_scorecard_debug_nonempty() {
    let s = Scorecard {
        moonshot_id: "m1".into(),
        ev_millionths: 0,
        confidence_millionths: 0,
        risk_of_harm_millionths: 0,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    assert!(!format!("{:?}", s).is_empty());
}

#[test]
fn enrichment_scorecard_json_field_names() {
    let s = Scorecard {
        moonshot_id: "m1".into(),
        ev_millionths: 0,
        confidence_millionths: 0,
        risk_of_harm_millionths: 0,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&s).unwrap();
    for field in &[
        "moonshot_id",
        "ev_millionths",
        "confidence_millionths",
        "risk_of_harm_millionths",
        "implementation_friction_millionths",
        "cross_initiative_interference_millionths",
        "operational_burden_millionths",
        "computed_at_ns",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_scorecard_risk_adjusted_ev_positive() {
    let s = Scorecard {
        moonshot_id: "m1".into(),
        ev_millionths: 2_000_000,
        confidence_millionths: 500_000, // 0.5
        risk_of_harm_millionths: 100_000,
        implementation_friction_millionths: 0,
        cross_initiative_interference_millionths: 0,
        operational_burden_millionths: 0,
        computed_at_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
    };
    let rev = s.risk_adjusted_ev();
    // confidence * ev = 0.5 * 2.0 = 1.0 (1_000_000), minus penalties
    assert!(rev > 0);
}

// ---------------------------------------------------------------------------
// ArtifactEvidence — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_evidence_clone_independence() {
    let a = make_evidence("art-1", "obl-1");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_evidence_debug_nonempty() {
    assert!(!format!("{:?}", make_evidence("a", "o")).is_empty());
}

#[test]
fn enrichment_artifact_evidence_json_field_names() {
    let e = make_evidence("art-1", "obl-1");
    let json = serde_json::to_string(&e).unwrap();
    for field in &[
        "artifact_id",
        "obligation_id",
        "artifact_type",
        "submitted_at_ns",
        "content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// MetricObservation — Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_metric_observation_clone_independence() {
    let a = make_observation("latency", 100_000, 1_000);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_metric_observation_debug_nonempty() {
    assert!(!format!("{:?}", make_observation("m", 0, 0)).is_empty());
}

// ---------------------------------------------------------------------------
// GovernorDecisionKind — Clone / Debug / Display unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_kind_clone_independence() {
    let a = GovernorDecisionKind::Hold {
        reason: "low signal".into(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_decision_kind_debug_all_unique() {
    let kinds: Vec<GovernorDecisionKind> = vec![
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        GovernorDecisionKind::Hold { reason: "r".into() },
        GovernorDecisionKind::Kill {
            triggered_criteria: vec!["c".into()],
        },
        GovernorDecisionKind::Pause { reason: "p".into() },
        GovernorDecisionKind::Resume,
    ];
    let dbgs: BTreeSet<String> = kinds.iter().map(|k| format!("{:?}", k)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_decision_kind_display_all_unique() {
    let kinds: Vec<GovernorDecisionKind> = vec![
        GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        GovernorDecisionKind::Hold { reason: "r".into() },
        GovernorDecisionKind::Kill {
            triggered_criteria: vec!["c".into()],
        },
        GovernorDecisionKind::Pause { reason: "p".into() },
        GovernorDecisionKind::Resume,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{}", k)).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// MoonshotStatus — Clone / Debug / Display unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_moonshot_status_clone_independence() {
    let a = MoonshotStatus::Active;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_moonshot_status_debug_all_unique() {
    let statuses: Vec<MoonshotStatus> = vec![
        MoonshotStatus::Active,
        MoonshotStatus::Paused {
            reason: "r".into(),
            paused_at_ns: 0,
        },
        MoonshotStatus::Killed {
            reason: "k".into(),
            killed_at_ns: 0,
        },
        MoonshotStatus::Completed { completed_at_ns: 0 },
    ];
    let dbgs: BTreeSet<String> = statuses.iter().map(|s| format!("{:?}", s)).collect();
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn enrichment_moonshot_status_display_all_unique() {
    let statuses: Vec<MoonshotStatus> = vec![
        MoonshotStatus::Active,
        MoonshotStatus::Paused {
            reason: "r".into(),
            paused_at_ns: 0,
        },
        MoonshotStatus::Killed {
            reason: "k".into(),
            killed_at_ns: 0,
        },
        MoonshotStatus::Completed { completed_at_ns: 0 },
    ];
    let displays: BTreeSet<String> = statuses.iter().map(|s| format!("{}", s)).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// GovernorError — Clone / Debug / Display unique / std::error::Error / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governor_error_clone_independence() {
    let a = GovernorError::MoonshotNotFound { id: "m1".into() };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_governor_error_debug_all_unique() {
    let errors: Vec<GovernorError> = vec![
        GovernorError::MoonshotNotFound { id: "a".into() },
        GovernorError::MoonshotNotActive { id: "b".into() },
        GovernorError::InvalidContract { reason: "c".into() },
        GovernorError::InvalidTransition {
            from: MoonshotStage::Research,
            to: MoonshotStage::Research,
        },
        GovernorError::AlreadyRegistered { id: "d".into() },
        GovernorError::NotPaused { id: "e".into() },
        GovernorError::LedgerConfig { reason: "f".into() },
        GovernorError::LedgerWriteFailed {
            decision_id: "g".into(),
            reason: "h".into(),
        },
        GovernorError::InvalidGovernanceActor {
            actor_id: "i".into(),
        },
    ];
    let dbgs: BTreeSet<String> = errors.iter().map(|e| format!("{:?}", e)).collect();
    assert_eq!(dbgs.len(), 9);
}

#[test]
fn enrichment_governor_error_display_all_unique() {
    let errors: Vec<GovernorError> = vec![
        GovernorError::MoonshotNotFound { id: "a".into() },
        GovernorError::MoonshotNotActive { id: "b".into() },
        GovernorError::InvalidContract { reason: "c".into() },
        GovernorError::InvalidTransition {
            from: MoonshotStage::Research,
            to: MoonshotStage::Research,
        },
        GovernorError::AlreadyRegistered { id: "d".into() },
        GovernorError::NotPaused { id: "e".into() },
        GovernorError::LedgerConfig { reason: "f".into() },
        GovernorError::LedgerWriteFailed {
            decision_id: "g".into(),
            reason: "h".into(),
        },
        GovernorError::InvalidGovernanceActor {
            actor_id: "i".into(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{}", e)).collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn enrichment_governor_error_is_std_error() {
    let e = GovernorError::MoonshotNotFound { id: "x".into() };
    let _err_ref: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_governor_error_serde_roundtrip_all() {
    let errors: Vec<GovernorError> = vec![
        GovernorError::MoonshotNotFound { id: "a".into() },
        GovernorError::MoonshotNotActive { id: "b".into() },
        GovernorError::InvalidContract { reason: "c".into() },
        GovernorError::InvalidTransition {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        GovernorError::AlreadyRegistered { id: "d".into() },
        GovernorError::NotPaused { id: "e".into() },
        GovernorError::LedgerConfig { reason: "f".into() },
        GovernorError::LedgerWriteFailed {
            decision_id: "g".into(),
            reason: "h".into(),
        },
        GovernorError::InvalidGovernanceActor {
            actor_id: "i".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: GovernorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ---------------------------------------------------------------------------
// GovernorConfig — Clone / Debug / Default values / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governor_config_clone_independence() {
    let a = GovernorConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_governor_config_debug_nonempty() {
    assert!(!format!("{:?}", GovernorConfig::default()).is_empty());
}

#[test]
fn enrichment_governor_config_default_exact_values() {
    let cfg = GovernorConfig::default();
    assert_eq!(cfg.promotion_confidence_threshold_millionths, 750_000);
    assert_eq!(cfg.promotion_risk_threshold_millionths, 200_000);
    assert_eq!(cfg.hold_confidence_below_millionths, 500_000);
    assert_eq!(cfg.scoring_cadence_ns, 604_800_000_000_000);
}

#[test]
fn enrichment_governor_config_serde_roundtrip() {
    let cfg = GovernorConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let rt: GovernorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, rt);
}

// ---------------------------------------------------------------------------
// GovernorDecision — Clone / Debug / JSON fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governor_decision_clone_independence() {
    let d = GovernorDecision {
        decision_id: "d-1".into(),
        moonshot_id: "m-1".into(),
        kind: GovernorDecisionKind::Resume,
        scorecard: Scorecard {
            moonshot_id: "m-1".into(),
            ev_millionths: 0,
            confidence_millionths: 0,
            risk_of_harm_millionths: 0,
            implementation_friction_millionths: 0,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 0,
            computed_at_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        },
        timestamp_ns: 1_000,
        epoch: SecurityEpoch::from_raw(1),
        rationale: "test".into(),
    };
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn enrichment_governor_decision_debug_nonempty() {
    let d = GovernorDecision {
        decision_id: "d-1".into(),
        moonshot_id: "m-1".into(),
        kind: GovernorDecisionKind::Resume,
        scorecard: Scorecard {
            moonshot_id: "m-1".into(),
            ev_millionths: 0,
            confidence_millionths: 0,
            risk_of_harm_millionths: 0,
            implementation_friction_millionths: 0,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 0,
            computed_at_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        },
        timestamp_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
        rationale: "r".into(),
    };
    assert!(!format!("{:?}", d).is_empty());
}

#[test]
fn enrichment_governor_decision_json_field_names() {
    let d = GovernorDecision {
        decision_id: "d-1".into(),
        moonshot_id: "m-1".into(),
        kind: GovernorDecisionKind::Resume,
        scorecard: Scorecard {
            moonshot_id: "m-1".into(),
            ev_millionths: 0,
            confidence_millionths: 0,
            risk_of_harm_millionths: 0,
            implementation_friction_millionths: 0,
            cross_initiative_interference_millionths: 0,
            operational_burden_millionths: 0,
            computed_at_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        },
        timestamp_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
        rationale: "r".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    for field in &[
        "decision_id",
        "moonshot_id",
        "kind",
        "scorecard",
        "timestamp_ns",
        "rationale",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_governor_decision_serde_roundtrip() {
    let d = GovernorDecision {
        decision_id: "d-1".into(),
        moonshot_id: "m-1".into(),
        kind: GovernorDecisionKind::Hold {
            reason: "insufficient data".into(),
        },
        scorecard: Scorecard {
            moonshot_id: "m-1".into(),
            ev_millionths: 500_000,
            confidence_millionths: 300_000,
            risk_of_harm_millionths: 50_000,
            implementation_friction_millionths: 10_000,
            cross_initiative_interference_millionths: 5_000,
            operational_burden_millionths: 20_000,
            computed_at_ns: 1_000,
            epoch: SecurityEpoch::from_raw(1),
        },
        timestamp_ns: 2_000,
        epoch: SecurityEpoch::from_raw(1),
        rationale: "need more data".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let rt: GovernorDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, rt);
}

// ---------------------------------------------------------------------------
// MoonshotState — methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_moonshot_state_is_active_when_active() {
    let gov = governor_with_moonshot();
    let state = &gov.moonshots["mc-enrich-001"];
    assert!(state.is_active());
}

#[test]
fn enrichment_moonshot_state_latest_metric_none_initially() {
    let gov = governor_with_moonshot();
    let state = &gov.moonshots["mc-enrich-001"];
    assert!(state.latest_metric("latency-p99").is_none());
}

#[test]
fn enrichment_moonshot_state_latest_metric_after_record() {
    let mut gov = governor_with_moonshot();
    gov.record_metric(
        "mc-enrich-001",
        make_observation("latency-p99", 150_000, 1_000),
    )
    .unwrap();
    gov.record_metric(
        "mc-enrich-001",
        make_observation("latency-p99", 120_000, 2_000),
    )
    .unwrap();
    let state = &gov.moonshots["mc-enrich-001"];
    let latest = state.latest_metric("latency-p99").unwrap();
    assert_eq!(latest.value_millionths, 120_000);
}

#[test]
fn enrichment_moonshot_state_completed_obligation_ids_empty() {
    let gov = governor_with_moonshot();
    let state = &gov.moonshots["mc-enrich-001"];
    assert!(state.completed_obligation_ids().is_empty());
}

#[test]
fn enrichment_moonshot_state_completed_obligation_ids_after_submit() {
    let mut gov = governor_with_moonshot();
    gov.submit_artifact("mc-enrich-001", make_evidence("art-1", "poc-research"))
        .unwrap();
    let ids = gov.moonshots["mc-enrich-001"].completed_obligation_ids();
    assert_eq!(ids, vec!["poc-research"]);
}

#[test]
fn enrichment_moonshot_state_metric_snapshot_empty() {
    let gov = governor_with_moonshot();
    let snap = gov.moonshots["mc-enrich-001"].metric_snapshot();
    assert!(snap.is_empty());
}

#[test]
fn enrichment_moonshot_state_metric_snapshot_latest_only() {
    let mut gov = governor_with_moonshot();
    gov.record_metric("mc-enrich-001", make_observation("m1", 100, 1_000))
        .unwrap();
    gov.record_metric("mc-enrich-001", make_observation("m1", 200, 2_000))
        .unwrap();
    gov.record_metric("mc-enrich-001", make_observation("m2", 300, 3_000))
        .unwrap();
    let snap = gov.moonshots["mc-enrich-001"].metric_snapshot();
    assert_eq!(snap.len(), 2);
    assert_eq!(snap["m1"], 200);
    assert_eq!(snap["m2"], 300);
}

// ---------------------------------------------------------------------------
// PortfolioGovernor — new / register / compute_scorecard / evaluate_gate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governor_new_empty() {
    let gov = test_governor();
    assert!(gov.moonshots.is_empty());
    assert_eq!(gov.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_governor_clone_independence() {
    let gov = governor_with_moonshot();
    let gov2 = gov.clone();
    assert_eq!(gov, gov2);
}

#[test]
fn enrichment_governor_debug_nonempty() {
    assert!(!format!("{:?}", test_governor()).is_empty());
}

#[test]
fn enrichment_governor_register_then_has_moonshot() {
    let gov = governor_with_moonshot();
    assert!(gov.moonshots.contains_key("mc-enrich-001"));
    assert_eq!(gov.moonshots.len(), 1);
}

#[test]
fn enrichment_governor_register_duplicate_fails() {
    let mut gov = governor_with_moonshot();
    let err = gov
        .register_moonshot(test_contract(), 2_000_000_000)
        .unwrap_err();
    assert!(matches!(err, GovernorError::AlreadyRegistered { .. }));
}

#[test]
fn enrichment_governor_submit_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov
        .submit_artifact("nonexistent", make_evidence("a", "o"))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn enrichment_governor_record_metric_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov
        .record_metric("nonexistent", make_observation("m", 0, 0))
        .unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn enrichment_governor_compute_scorecard() {
    let mut gov = governor_with_moonshot();
    // Add some metrics so scorecard has data
    for i in 0..5 {
        gov.record_metric(
            "mc-enrich-001",
            make_observation(
                "latency-p99",
                100_000 + i * 10_000,
                1_000 + i as u64 * 1_000,
            ),
        )
        .unwrap();
    }
    let sc = gov.compute_scorecard("mc-enrich-001", 10_000_000).unwrap();
    assert_eq!(sc.moonshot_id, "mc-enrich-001");
    assert_eq!(sc.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_governor_compute_scorecard_nonexistent_fails() {
    let gov = test_governor();
    let err = gov.compute_scorecard("nonexistent", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn enrichment_governor_evaluate_gate_hold() {
    let mut gov = governor_with_moonshot();
    // No metrics, low confidence → hold
    let decision = gov.evaluate_gate("mc-enrich-001", 2_000_000_000).unwrap();
    assert!(
        matches!(decision.kind, GovernorDecisionKind::Hold { .. }),
        "expected Hold, got {:?}",
        decision.kind
    );
}

#[test]
fn enrichment_governor_pause_and_resume() {
    let mut gov = governor_with_moonshot();
    let d1 = gov
        .pause_moonshot("mc-enrich-001", "maintenance", 5_000_000_000)
        .unwrap();
    assert!(matches!(d1.kind, GovernorDecisionKind::Pause { .. }));
    assert!(!gov.moonshots["mc-enrich-001"].is_active());

    let d2 = gov.resume_moonshot("mc-enrich-001", 6_000_000_000).unwrap();
    assert!(matches!(d2.kind, GovernorDecisionKind::Resume));
    assert!(gov.moonshots["mc-enrich-001"].is_active());
}

#[test]
fn enrichment_governor_pause_nonexistent_fails() {
    let mut gov = test_governor();
    let err = gov.pause_moonshot("ghost", "r", 0).unwrap_err();
    assert!(matches!(err, GovernorError::MoonshotNotFound { .. }));
}

#[test]
fn enrichment_governor_resume_active_fails() {
    let mut gov = governor_with_moonshot();
    let err = gov.resume_moonshot("mc-enrich-001", 0).unwrap_err();
    assert!(matches!(err, GovernorError::NotPaused { .. }));
}

#[test]
fn enrichment_governor_update_budget() {
    let mut gov = governor_with_moonshot();
    gov.update_budget("mc-enrich-001", 250_000).unwrap();
    assert_eq!(
        gov.moonshots["mc-enrich-001"].budget_spent_fraction_millionths,
        250_000
    );
}

#[test]
fn enrichment_governor_rank_portfolio_empty() {
    let gov = test_governor();
    assert!(gov.rank_portfolio(0).is_empty());
}

#[test]
fn enrichment_governor_rank_portfolio_single() {
    let gov = governor_with_moonshot();
    let ranked = gov.rank_portfolio(1_000_000_000);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].0, "mc-enrich-001");
}

#[test]
fn enrichment_governor_latest_scorecard_none_initially() {
    let gov = governor_with_moonshot();
    assert!(gov.latest_scorecard("mc-enrich-001").is_none());
}

#[test]
fn enrichment_governor_decisions_empty_initially() {
    let gov = governor_with_moonshot();
    let decisions = gov.decisions("mc-enrich-001").unwrap();
    assert!(decisions.is_empty());
}

#[test]
fn enrichment_governor_decisions_nonexistent_none() {
    let gov = test_governor();
    assert!(gov.decisions("nonexistent").is_none());
}

#[test]
fn enrichment_governor_decisions_after_gate() {
    let mut gov = governor_with_moonshot();
    gov.evaluate_gate("mc-enrich-001", 2_000_000_000).unwrap();
    let decisions = gov.decisions("mc-enrich-001").unwrap();
    assert_eq!(decisions.len(), 1);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_governor() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&governor_with_moonshot()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "governor should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_evaluate_gate() {
    let decisions: Vec<String> = (0..5)
        .map(|_| {
            let mut gov = governor_with_moonshot();
            let d = gov.evaluate_gate("mc-enrich-001", 2_000_000_000).unwrap();
            serde_json::to_string(&d).unwrap()
        })
        .collect();
    for d in &decisions[1..] {
        assert_eq!(*d, decisions[0], "gate decisions should be deterministic");
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_governor_epoch_matches_config() {
    let gov = test_governor();
    assert_eq!(gov.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_cross_cutting_registered_moonshot_active() {
    let gov = governor_with_moonshot();
    let state = &gov.moonshots["mc-enrich-001"];
    assert!(matches!(state.status, MoonshotStatus::Active));
    assert!(state.is_active());
}

#[test]
fn enrichment_cross_cutting_decision_ids_increment() {
    let mut gov = governor_with_moonshot();
    let d1 = gov.evaluate_gate("mc-enrich-001", 1_000_000_000).unwrap();
    let d2 = gov.evaluate_gate("mc-enrich-001", 2_000_000_000).unwrap();
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn enrichment_cross_cutting_decision_has_correct_moonshot_id() {
    let mut gov = governor_with_moonshot();
    let d = gov.evaluate_gate("mc-enrich-001", 1_000_000_000).unwrap();
    assert_eq!(d.moonshot_id, "mc-enrich-001");
}

#[test]
fn enrichment_cross_cutting_decision_has_correct_epoch() {
    let mut gov = governor_with_moonshot();
    let d = gov.evaluate_gate("mc-enrich-001", 1_000_000_000).unwrap();
    assert_eq!(d.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_cross_cutting_scorecard_has_correct_epoch() {
    let gov = governor_with_moonshot();
    let sc = gov
        .compute_scorecard("mc-enrich-001", 1_000_000_000)
        .unwrap();
    assert_eq!(sc.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_cross_cutting_governor_serde_roundtrip() {
    let mut gov = governor_with_moonshot();
    gov.evaluate_gate("mc-enrich-001", 2_000_000_000).unwrap();
    let json = serde_json::to_string(&gov).unwrap();
    let rt: PortfolioGovernor = serde_json::from_str(&json).unwrap();
    assert_eq!(gov, rt);
}
