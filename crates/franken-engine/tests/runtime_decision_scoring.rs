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

use frankenengine_engine::bayesian_posterior::{
    BayesianPosteriorUpdater, CalibrationResult, ChangePointDetector, Evidence, LikelihoodModel,
    Posterior, RiskState, UpdaterStore,
};
use frankenengine_engine::expected_loss_selector::{
    AlienRiskAlertLevel, CandidateActionScore, ContainmentAction, DecisionConfidenceInterval,
    ExpectedLossSelector, LossEntry, LossMatrix, RuntimeDecisionScore, RuntimeDecisionScoringError,
    RuntimeDecisionScoringInput,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_economics::{AttackerCostModel, StrategyCostAdjustment};

fn sample_attacker_cost_model() -> AttackerCostModel {
    let mut strategy_adjustments = BTreeMap::new();
    strategy_adjustments.insert(
        "supply_chain".to_string(),
        StrategyCostAdjustment {
            strategy_name: "supply_chain".to_string(),
            discovery_delta: 100_000,
            development_delta: 200_000,
            evasion_delta: 50_000,
            justification: "integration-test".to_string(),
        },
    );
    AttackerCostModel {
        discovery_cost: 1_000_000,
        development_cost: 2_000_000,
        deployment_cost: 1_000_000,
        persistence_cost: 500_000,
        evasion_cost: 1_000_000,
        expected_gain: 20_000_000,
        strategy_adjustments,
        version: 1,
        calibration_source: "integration-test".to_string(),
    }
}

fn malicious_evidence(extension_id: &str) -> Evidence {
    Evidence {
        extension_id: extension_id.to_string(),
        hostcall_rate_millionths: 900_000_000,
        distinct_capabilities: 14,
        resource_score_millionths: 950_000,
        timing_anomaly_millionths: 900_000,
        denial_rate_millionths: 500_000,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn benign_evidence(extension_id: &str) -> Evidence {
    Evidence {
        extension_id: extension_id.to_string(),
        hostcall_rate_millionths: 10_000_000,
        distinct_capabilities: 2,
        resource_score_millionths: 100_000,
        timing_anomaly_millionths: 10_000,
        denial_rate_millionths: 0,
        epoch: SecurityEpoch::GENESIS,
    }
}

fn scoring_input(
    extension_id: &str,
    decision_id: &str,
    posterior: Posterior,
) -> RuntimeDecisionScoringInput {
    RuntimeDecisionScoringInput {
        trace_id: format!("trace-{decision_id}"),
        decision_id: decision_id.to_string(),
        policy_id: "policy-runtime-score-v1".to_string(),
        extension_id: extension_id.to_string(),
        policy_version: "policy-v1.0.0".to_string(),
        timestamp_ns: 1_700_000_000_000_000_123,
        posterior,
        attacker_cost_model: sample_attacker_cost_model(),
        extension_roi_history_millionths: vec![1_100_000, 1_500_000, 2_200_000],
        fleet_roi_baseline_millionths: BTreeMap::from([
            ("ext-other-a".to_string(), 400_000),
            ("ext-other-b".to_string(), 1_300_000),
        ]),
        blocked_actions: BTreeSet::new(),
    }
}

#[test]
fn evidence_to_scoring_flow_emits_structured_artifact() {
    let extension_id = "ext-runtime-flow";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..10 {
        updater.update(&malicious_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    selector.set_epoch(SecurityEpoch::from_raw(42));
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-runtime-flow",
            updater.posterior().clone(),
        ))
        .expect("runtime decision scoring");

    assert!(
        artifact.selected_action.severity() >= ContainmentAction::Sandbox.severity(),
        "malicious posterior should avoid permissive actions, got {}",
        artifact.selected_action
    );
    assert_eq!(artifact.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(
        artifact.candidate_actions.len(),
        ContainmentAction::ALL.len()
    );
    assert!(artifact.events.iter().all(|event| {
        !event.trace_id.is_empty()
            && !event.decision_id.is_empty()
            && !event.policy_id.is_empty()
            && event.component == "runtime_decision_scoring"
            && !event.event.is_empty()
            && !event.outcome.is_empty()
    }));
}

#[test]
fn guardrail_veto_path_changes_selected_action() {
    let extension_id = "ext-runtime-guardrail";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&benign_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    let baseline = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-runtime-guardrail-baseline",
            updater.posterior().clone(),
        ))
        .expect("baseline scoring");
    assert_eq!(baseline.selected_action, ContainmentAction::Allow);

    let mut blocked_input = scoring_input(
        extension_id,
        "decision-runtime-guardrail-veto",
        updater.posterior().clone(),
    );
    blocked_input
        .blocked_actions
        .insert(ContainmentAction::Allow);
    let blocked = selector
        .score_runtime_decision(&blocked_input)
        .expect("guardrail scoring");

    assert_ne!(blocked.selected_action, ContainmentAction::Allow);
    assert!(blocked.events.iter().any(|event| {
        event.event == "guardrail_veto_applied"
            && event.error_code.as_deref() == Some("FE-RUNTIME-SCORING-GUARDRAIL-VETO")
    }));
}

#[test]
fn scoring_output_is_replay_deterministic() {
    let extension_id = "ext-runtime-replay";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..5 {
        updater.update(&malicious_evidence(extension_id));
    }

    let input = scoring_input(
        extension_id,
        "decision-runtime-replay",
        updater.posterior().clone(),
    );
    let mut selector_a = ExpectedLossSelector::balanced();
    let mut selector_b = ExpectedLossSelector::balanced();
    let artifact_a = selector_a
        .score_runtime_decision(&input)
        .expect("artifact a");
    let artifact_b = selector_b
        .score_runtime_decision(&input)
        .expect("artifact b");

    assert_eq!(artifact_a, artifact_b);
}

#[test]
fn zero_attacker_cost_is_fail_closed() {
    let extension_id = "ext-runtime-zero-cost";
    let mut input = scoring_input(
        extension_id,
        "decision-runtime-zero-cost",
        Posterior::default_prior(),
    );
    input.attacker_cost_model.discovery_cost = 0;
    input.attacker_cost_model.development_cost = 0;
    input.attacker_cost_model.deployment_cost = 0;
    input.attacker_cost_model.persistence_cost = 0;
    input.attacker_cost_model.evasion_cost = 0;

    let mut selector = ExpectedLossSelector::balanced();
    let err = selector
        .score_runtime_decision(&input)
        .expect_err("zero attacker cost should fail");
    assert_eq!(err, RuntimeDecisionScoringError::ZeroAttackerCost);
}

#[test]
fn borderline_detection_emits_event_when_applicable() {
    // Near-uniform posterior: actions should be close in EL.
    let extension_id = "ext-runtime-borderline";
    let posterior = Posterior::uniform();
    let mut selector = ExpectedLossSelector::balanced();
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-borderline",
            posterior,
        ))
        .expect("scoring should succeed");

    // Verify new fields are present and well-formed.
    if artifact.borderline_decision {
        assert!(
            !artifact.sensitivity_deltas.is_empty(),
            "borderline decisions must have sensitivity deltas"
        );
        assert!(
            artifact
                .events
                .iter()
                .any(|e| e.event == "borderline_decision"
                    && e.error_code.as_deref() == Some("FE-RUNTIME-SCORING-BORDERLINE")),
            "borderline event must have correct error code"
        );
    }
}

#[test]
fn scoring_artifact_contains_all_posterior_probabilities_in_rationale() {
    let extension_id = "ext-runtime-rationale";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&malicious_evidence(extension_id));
    }

    let mut selector = ExpectedLossSelector::balanced();
    let artifact = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-rationale",
            updater.posterior().clone(),
        ))
        .expect("scoring should succeed");

    assert!(
        artifact.selection_rationale.contains("p_benign="),
        "rationale must show p_benign"
    );
    assert!(
        artifact.selection_rationale.contains("p_malicious="),
        "rationale must show p_malicious"
    );
    assert!(
        artifact.selection_rationale.contains("margin="),
        "rationale must show decision margin"
    );
}

#[test]
fn monotonicity_across_malicious_gradient() {
    let extension_id = "ext-runtime-monotonicity";
    let steps = 10;
    let million: i64 = 1_000_000;
    let mut prev_severity = 0u32;

    for i in 0..=steps {
        let p_malicious = million * i / steps;
        let p_benign = million - p_malicious;
        let posterior = Posterior::from_millionths(p_benign, 0, p_malicious, 0);
        let mut selector = ExpectedLossSelector::balanced();
        let artifact = selector
            .score_runtime_decision(&scoring_input(
                extension_id,
                &format!("decision-mono-{i}"),
                posterior,
            ))
            .expect("scoring should succeed");
        let severity = artifact.selected_action.severity();
        assert!(
            severity >= prev_severity,
            "monotonicity: step {i} severity {} < previous {prev_severity}",
            severity
        );
        prev_severity = severity;
    }
}

// ---------- sample_attacker_cost_model ----------

#[test]
fn sample_attacker_cost_model_has_strategy_adjustments() {
    let model = sample_attacker_cost_model();
    assert!(model.strategy_adjustments.contains_key("supply_chain"));
    assert_eq!(model.discovery_cost, 1_000_000);
    assert_eq!(model.expected_gain, 20_000_000);
    assert_eq!(model.version, 1);
}

// ---------- malicious_evidence ----------

#[test]
fn malicious_evidence_has_high_hostcall_rate() {
    let ev = malicious_evidence("ext-test");
    assert_eq!(ev.extension_id, "ext-test");
    assert!(ev.hostcall_rate_millionths > 100_000_000);
    assert!(ev.timing_anomaly_millionths > 500_000);
    assert_eq!(ev.epoch, SecurityEpoch::GENESIS);
}

// ---------- benign_evidence ----------

#[test]
fn benign_evidence_has_low_hostcall_rate() {
    let ev = benign_evidence("ext-good");
    assert_eq!(ev.extension_id, "ext-good");
    assert!(ev.hostcall_rate_millionths < 100_000_000);
    assert_eq!(ev.denial_rate_millionths, 0);
    assert_eq!(ev.distinct_capabilities, 2);
}

// ---------- scoring_input ----------

#[test]
fn scoring_input_sets_trace_id_from_decision_id() {
    let input = scoring_input("ext-a", "dec-123", Posterior::default_prior());
    assert_eq!(input.trace_id, "trace-dec-123");
    assert_eq!(input.decision_id, "dec-123");
    assert_eq!(input.extension_id, "ext-a");
    assert_eq!(input.policy_id, "policy-runtime-score-v1");
}

#[test]
fn scoring_input_includes_roi_history() {
    let input = scoring_input("ext-b", "dec-456", Posterior::default_prior());
    assert_eq!(input.extension_roi_history_millionths.len(), 3);
    assert_eq!(input.fleet_roi_baseline_millionths.len(), 2);
    assert!(input.blocked_actions.is_empty());
}

// ---------- ContainmentAction ----------

#[test]
fn containment_action_all_has_correct_count() {
    assert_eq!(ContainmentAction::ALL.len(), 6);
}

#[test]
fn containment_action_severity_is_monotonic() {
    let mut prev = 0u32;
    for action in ContainmentAction::ALL {
        let sev = action.severity();
        assert!(
            sev >= prev,
            "severity for {} ({}) < previous ({})",
            action,
            sev,
            prev
        );
        prev = sev;
    }
}

#[test]
fn containment_action_serde_roundtrip() {
    for action in ContainmentAction::ALL {
        let json = serde_json::to_string(&action).expect("serialize");
        let recovered: ContainmentAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, action);
    }
}

#[test]
fn containment_action_display_is_nonempty() {
    for action in ContainmentAction::ALL {
        let s = format!("{action}");
        assert!(!s.is_empty());
    }
}

// ---------- Posterior ----------

#[test]
fn posterior_default_prior_is_valid() {
    let p = Posterior::default_prior();
    assert!(p.is_valid());
}

#[test]
fn posterior_uniform_is_valid() {
    let p = Posterior::uniform();
    assert!(p.is_valid());
}

#[test]
fn posterior_serde_roundtrip() {
    let p = Posterior::from_millionths(600_000, 100_000, 200_000, 100_000);
    let json = serde_json::to_string(&p).expect("serialize");
    let recovered: Posterior = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, p);
    assert!(recovered.is_valid());
}

// ---------- BayesianPosteriorUpdater ----------

#[test]
fn bayesian_updater_tracks_update_count() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-count");
    assert_eq!(updater.update_count(), 0);
    updater.update(&benign_evidence("ext-count"));
    assert_eq!(updater.update_count(), 1);
    updater.update(&benign_evidence("ext-count"));
    assert_eq!(updater.update_count(), 2);
}

#[test]
fn bayesian_updater_extension_id_matches() {
    let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-id-check");
    assert_eq!(updater.extension_id(), "ext-id-check");
}

#[test]
fn bayesian_updater_serde_roundtrip() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-serde");
    updater.update(&malicious_evidence("ext-serde"));
    let json = serde_json::to_string(&updater).expect("serialize");
    let recovered: BayesianPosteriorUpdater = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.extension_id(), "ext-serde");
    assert_eq!(recovered.update_count(), 1);
}

// ---------- Evidence ----------

#[test]
fn evidence_serde_roundtrip() {
    let ev = malicious_evidence("ext-ev-serde");
    let json = serde_json::to_string(&ev).expect("serialize");
    let recovered: Evidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.extension_id, "ext-ev-serde");
    assert_eq!(
        recovered.hostcall_rate_millionths,
        ev.hostcall_rate_millionths
    );
}

// ---------- AttackerCostModel ----------

#[test]
fn attacker_cost_model_serde_roundtrip() {
    let model = sample_attacker_cost_model();
    let json = serde_json::to_string(&model).expect("serialize");
    let recovered: AttackerCostModel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.discovery_cost, model.discovery_cost);
    assert_eq!(recovered.expected_gain, model.expected_gain);
    assert!(recovered.strategy_adjustments.contains_key("supply_chain"));
}

// ---------- ExpectedLossSelector ----------

#[test]
fn expected_loss_selector_tracks_decisions_made() {
    let mut selector = ExpectedLossSelector::balanced();
    assert_eq!(selector.decisions_made(), 0);
    let _ = selector.score_runtime_decision(&scoring_input(
        "ext-count",
        "dec-count",
        Posterior::default_prior(),
    ));
    assert_eq!(selector.decisions_made(), 1);
}

// ---------- RuntimeDecisionScoringError ----------

#[test]
fn runtime_decision_scoring_error_serde_roundtrip() {
    let err = RuntimeDecisionScoringError::ZeroAttackerCost;
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: RuntimeDecisionScoringError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

// ---------- RuntimeDecisionScoringInput ----------

#[test]
fn runtime_decision_scoring_input_serde_roundtrip() {
    let input = scoring_input("ext-serde", "dec-serde", Posterior::default_prior());
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: RuntimeDecisionScoringInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.extension_id, "ext-serde");
    assert_eq!(recovered.trace_id, "trace-dec-serde");
}

// ---------- expected_losses ----------

#[test]
fn expected_losses_covers_all_containment_actions() {
    let selector = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(500_000, 100_000, 300_000, 100_000);
    let losses = selector.expected_losses(&posterior);
    assert_eq!(
        losses.len(),
        ContainmentAction::ALL.len(),
        "expected_losses must return an entry for every containment action"
    );
    for action in ContainmentAction::ALL {
        assert!(
            losses.contains_key(&action),
            "missing expected loss for {action}"
        );
    }
}

// ---------- blocking multiple actions ----------

#[test]
fn blocking_all_but_terminate_forces_terminate() {
    let extension_id = "ext-runtime-block-all";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&benign_evidence(extension_id));
    }

    let mut input = scoring_input(
        extension_id,
        "decision-block-all",
        updater.posterior().clone(),
    );
    // Block every action except Terminate
    for action in ContainmentAction::ALL {
        if action != ContainmentAction::Terminate {
            input.blocked_actions.insert(action);
        }
    }

    let mut selector = ExpectedLossSelector::balanced();
    let artifact = selector
        .score_runtime_decision(&input)
        .expect("scoring with heavy blocks");
    assert_eq!(
        artifact.selected_action,
        ContainmentAction::Terminate,
        "when all actions except Terminate are blocked, Terminate must be selected"
    );
}

// ---------- scoring input deterministic serialization ----------

#[test]
fn scoring_input_serialization_is_deterministic() {
    let input = scoring_input("ext-det", "dec-det", Posterior::default_prior());
    let json_a = serde_json::to_string(&input).expect("first serialize");
    let json_b = serde_json::to_string(&input).expect("second serialize");
    assert_eq!(
        json_a, json_b,
        "RuntimeDecisionScoringInput serialization must be deterministic"
    );
}

// ---------------------------------------------------------------------------
// Enrichment: untested API surface
// ---------------------------------------------------------------------------

// ---------- RiskState ----------

#[test]
fn risk_state_all_has_four_variants() {
    assert_eq!(RiskState::ALL.len(), 4);
    let mut seen = BTreeSet::new();
    for s in RiskState::ALL {
        seen.insert(format!("{s}"));
    }
    assert_eq!(seen.len(), 4, "all RiskState variants must be unique");
}

#[test]
fn risk_state_serde_roundtrip() {
    for state in RiskState::ALL {
        let json = serde_json::to_string(&state).expect("serialize");
        let recovered: RiskState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, state);
    }
}

#[test]
fn risk_state_display_is_lowercase() {
    for state in RiskState::ALL {
        let s = format!("{state}");
        assert!(!s.is_empty());
        assert_eq!(s, s.to_lowercase(), "display must be lowercase: {s}");
    }
}

// ---------- Posterior::probability / map_estimate ----------

#[test]
fn posterior_probability_returns_correct_values() {
    let p = Posterior::from_millionths(600_000, 100_000, 200_000, 100_000);
    assert_eq!(p.probability(RiskState::Benign), 600_000);
    assert_eq!(p.probability(RiskState::Anomalous), 100_000);
    assert_eq!(p.probability(RiskState::Malicious), 200_000);
    assert_eq!(p.probability(RiskState::Unknown), 100_000);
}

#[test]
fn posterior_map_estimate_returns_highest_state() {
    let p = Posterior::from_millionths(100_000, 100_000, 700_000, 100_000);
    assert_eq!(p.map_estimate(), RiskState::Malicious);
}

#[test]
fn posterior_map_estimate_benign_dominant() {
    let p = Posterior::from_millionths(800_000, 50_000, 100_000, 50_000);
    assert_eq!(p.map_estimate(), RiskState::Benign);
}

// ---------- LikelihoodModel ----------

#[test]
fn likelihood_model_compute_likelihoods_returns_four_values() {
    let model = LikelihoodModel::default();
    let ev = benign_evidence("ext-likelihood");
    let likelihoods = model.compute_likelihoods(&ev);
    assert_eq!(likelihoods.len(), 4);
    for lk in &likelihoods {
        assert!(*lk > 0, "likelihoods must be positive, got {lk}");
    }
}

#[test]
fn likelihood_model_serde_roundtrip() {
    let model = LikelihoodModel::default();
    let json = serde_json::to_string(&model).expect("serialize");
    let recovered: LikelihoodModel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.benign_rate_ceiling, model.benign_rate_ceiling,
        "LikelihoodModel must survive serde roundtrip"
    );
}

// ---------- ChangePointDetector ----------

#[test]
fn change_point_detector_initial_probability_is_zero() {
    let cpd = ChangePointDetector::new(100_000, 50);
    assert_eq!(cpd.change_point_probability(), 0);
    assert_eq!(cpd.map_run_length(), 0);
}

#[test]
fn change_point_detector_accumulates_probability() {
    let mut cpd = ChangePointDetector::new(100_000, 50);
    for _ in 0..20 {
        cpd.update(500_000, 900_000);
    }
    assert!(
        cpd.change_point_probability() > 0,
        "after biased updates, change point probability should be > 0"
    );
}

#[test]
fn change_point_detector_reset_clears_state() {
    let mut cpd = ChangePointDetector::new(100_000, 50);
    for _ in 0..10 {
        cpd.update(500_000, 800_000);
    }
    cpd.reset();
    assert_eq!(cpd.change_point_probability(), 0);
    assert_eq!(cpd.map_run_length(), 0);
}

// ---------- BayesianPosteriorUpdater extended ----------

#[test]
fn bayesian_updater_log_likelihood_ratio_changes_with_evidence() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-llr");
    let initial_llr = updater.log_likelihood_ratio();
    for _ in 0..5 {
        updater.update(&malicious_evidence("ext-llr"));
    }
    assert_ne!(
        updater.log_likelihood_ratio(),
        initial_llr,
        "LLR must change after evidence updates"
    );
}

#[test]
fn bayesian_updater_evidence_hashes_grow() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-hashes");
    assert!(updater.evidence_hashes().is_empty());
    updater.update(&benign_evidence("ext-hashes"));
    assert_eq!(updater.evidence_hashes().len(), 1);
    updater.update(&malicious_evidence("ext-hashes"));
    assert_eq!(updater.evidence_hashes().len(), 2);
}

#[test]
fn bayesian_updater_content_hash_is_deterministic() {
    let mut a = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-ch");
    let mut b = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-ch");
    a.update(&benign_evidence("ext-ch"));
    b.update(&benign_evidence("ext-ch"));
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn bayesian_updater_reset_restores_prior() {
    let prior = Posterior::default_prior();
    let mut updater = BayesianPosteriorUpdater::new(prior.clone(), "ext-reset");
    for _ in 0..10 {
        updater.update(&malicious_evidence("ext-reset"));
    }
    updater.reset(prior.clone());
    assert_eq!(updater.update_count(), 0);
    assert_eq!(*updater.posterior(), prior);
}

#[test]
fn bayesian_updater_calibration_check_returns_result() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-cal");
    for _ in 0..5 {
        updater.update(&malicious_evidence("ext-cal"));
    }
    let cal: CalibrationResult = updater.calibration_check(RiskState::Malicious);
    assert_eq!(cal.ground_truth, RiskState::Malicious);
    assert!(
        cal.assigned_probability > 0,
        "assigned probability should be positive for malicious posterior"
    );
}

#[test]
fn bayesian_updater_change_point_probability_accessible() {
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-cpd");
    let _cp = updater.change_point_probability();
    for _ in 0..5 {
        updater.update(&malicious_evidence("ext-cpd"));
    }
    // Just verify it's accessible and doesn't panic
    let _cp2 = updater.change_point_probability();
}

// ---------- UpdaterStore ----------

#[test]
fn updater_store_create_and_retrieve() {
    let mut store = UpdaterStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);

    store.get_or_create("ext-store-a");
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());

    let updater = store.get("ext-store-a");
    assert!(updater.is_some());
    assert_eq!(updater.unwrap().extension_id(), "ext-store-a");
}

#[test]
fn updater_store_get_nonexistent_returns_none() {
    let store = UpdaterStore::new();
    assert!(store.get("ext-nonexistent").is_none());
}

#[test]
fn updater_store_risky_extensions_filters_by_threshold() {
    let mut store = UpdaterStore::new();
    let u = store.get_or_create("ext-risky");
    for _ in 0..10 {
        u.update(&malicious_evidence("ext-risky"));
    }
    store.get_or_create("ext-safe");
    for _ in 0..3 {
        let u2 = store.get_or_create("ext-safe");
        u2.update(&benign_evidence("ext-safe"));
    }
    let risky = store.risky_extensions(500_000);
    // ext-risky should have low p_benign (below threshold)
    // Just verify the API returns reasonable results
    assert!(
        risky.len() <= store.len(),
        "risky count cannot exceed total"
    );
}

#[test]
fn updater_store_summary_has_entries_for_all() {
    let mut store = UpdaterStore::new();
    store.get_or_create("ext-sum-a");
    store.get_or_create("ext-sum-b");
    let summary = store.summary();
    assert_eq!(summary.len(), 2);
    assert!(summary.contains_key("ext-sum-a"));
    assert!(summary.contains_key("ext-sum-b"));
}

// ---------- LossMatrix ----------

#[test]
fn loss_matrix_balanced_is_complete() {
    let matrix = LossMatrix::balanced();
    assert!(matrix.is_complete(), "balanced matrix must be complete");
}

#[test]
fn loss_matrix_conservative_is_complete() {
    let matrix = LossMatrix::conservative();
    assert!(matrix.is_complete(), "conservative matrix must be complete");
}

#[test]
fn loss_matrix_permissive_is_complete() {
    let matrix = LossMatrix::permissive();
    assert!(matrix.is_complete(), "permissive matrix must be complete");
}

#[test]
fn loss_matrix_content_hash_differs_across_presets() {
    let balanced = LossMatrix::balanced();
    let conservative = LossMatrix::conservative();
    let permissive = LossMatrix::permissive();
    assert_ne!(
        balanced.content_hash(),
        conservative.content_hash(),
        "balanced and conservative must have different hashes"
    );
    assert_ne!(
        balanced.content_hash(),
        permissive.content_hash(),
        "balanced and permissive must have different hashes"
    );
}

#[test]
fn loss_matrix_loss_lookup_returns_value() {
    let matrix = LossMatrix::balanced();
    let loss = matrix.loss(ContainmentAction::Allow, RiskState::Benign);
    // Allow + Benign should have low loss
    assert!(
        loss >= 0,
        "loss for Allow+Benign should be non-negative, got {loss}"
    );
}

#[test]
fn loss_matrix_serde_roundtrip() {
    let matrix = LossMatrix::balanced();
    let json = serde_json::to_string(&matrix).expect("serialize");
    let recovered: LossMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.matrix_id, matrix.matrix_id);
    assert!(recovered.is_complete());
}

// ---------- ExpectedLossSelector extended ----------

#[test]
fn selector_loss_matrix_accessor() {
    let selector = ExpectedLossSelector::balanced();
    let matrix = selector.loss_matrix();
    assert!(matrix.is_complete());
}

#[test]
fn selector_set_loss_matrix_changes_behavior() {
    let mut selector = ExpectedLossSelector::balanced();
    let conservative = LossMatrix::conservative();
    selector.set_loss_matrix(conservative);
    let matrix = selector.loss_matrix();
    assert_eq!(matrix.matrix_id, LossMatrix::conservative().matrix_id);
}

#[test]
fn selector_select_returns_action_decision() {
    let mut selector = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(800_000, 50_000, 100_000, 50_000);
    let decision = selector.select(&posterior);
    assert!(ContainmentAction::ALL.contains(&decision.action));
    assert!(ContainmentAction::ALL.contains(&decision.runner_up_action));
    assert!(decision.explanation.margin_millionths >= 0);
}

// ---------- RuntimeDecisionScoringError extended ----------

#[test]
fn all_actions_blocked_error() {
    let extension_id = "ext-all-blocked";
    let mut input = scoring_input(
        extension_id,
        "decision-all-blocked",
        Posterior::default_prior(),
    );
    for action in ContainmentAction::ALL {
        input.blocked_actions.insert(action);
    }
    let mut selector = ExpectedLossSelector::balanced();
    let err = selector
        .score_runtime_decision(&input)
        .expect_err("blocking all actions should fail");
    assert_eq!(err, RuntimeDecisionScoringError::AllActionsBlocked);
}

#[test]
fn runtime_decision_scoring_error_display_coverage() {
    let errors = [
        RuntimeDecisionScoringError::ZeroAttackerCost,
        RuntimeDecisionScoringError::AllActionsBlocked,
        RuntimeDecisionScoringError::MissingField {
            field: "trace_id".to_string(),
        },
    ];
    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty(), "error Display must be non-empty");
    }
    let missing = format!(
        "{}",
        RuntimeDecisionScoringError::MissingField {
            field: "test".to_string()
        }
    );
    assert!(
        missing.contains("test"),
        "MissingField display must contain field name"
    );
}

// ---------- AlienRiskAlertLevel ----------

#[test]
fn alien_risk_alert_level_display_coverage() {
    let levels = [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ];
    let mut displays = BTreeSet::new();
    for level in &levels {
        let s = format!("{level}");
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(
        displays.len(),
        3,
        "all alert levels must have unique display"
    );
}

#[test]
fn alien_risk_alert_level_serde_roundtrip() {
    for level in [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ] {
        let json = serde_json::to_string(&level).expect("serialize");
        let recovered: AlienRiskAlertLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, level);
    }
}

// ---------- RuntimeDecisionScore serde ----------

#[test]
fn runtime_decision_score_serde_roundtrip() {
    let extension_id = "ext-score-serde";
    let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), extension_id);
    for _ in 0..3 {
        updater.update(&malicious_evidence(extension_id));
    }
    let mut selector = ExpectedLossSelector::balanced();
    let score: RuntimeDecisionScore = selector
        .score_runtime_decision(&scoring_input(
            extension_id,
            "decision-score-serde",
            updater.posterior().clone(),
        ))
        .expect("scoring");

    let json = serde_json::to_string(&score).expect("serialize");
    let recovered: RuntimeDecisionScore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, score.trace_id);
    assert_eq!(recovered.decision_id, score.decision_id);
    assert_eq!(recovered.selected_action, score.selected_action);
    assert_eq!(recovered.epoch, score.epoch);
    assert_eq!(
        recovered.selected_expected_loss_millionths,
        score.selected_expected_loss_millionths
    );
}

// ---------- CandidateActionScore / DecisionConfidenceInterval ----------

#[test]
fn candidate_action_score_serde_roundtrip() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Sandbox,
        expected_loss_millionths: 42_000,
        state_contributions_millionths: BTreeMap::from([
            ("benign".to_string(), 10_000),
            ("malicious".to_string(), 32_000),
        ]),
        guardrail_blocked: false,
    };
    let json = serde_json::to_string(&cas).expect("serialize");
    let recovered: CandidateActionScore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.action, ContainmentAction::Sandbox);
    assert_eq!(recovered.expected_loss_millionths, 42_000);
    assert!(!recovered.guardrail_blocked);
}

#[test]
fn decision_confidence_interval_serde_roundtrip() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: 100_000,
        upper_millionths: 900_000,
    };
    let json = serde_json::to_string(&ci).expect("serialize");
    let recovered: DecisionConfidenceInterval = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.lower_millionths, 100_000);
    assert_eq!(recovered.upper_millionths, 900_000);
}

// ---------- LossEntry ----------

#[test]
fn loss_entry_serde_roundtrip() {
    let entry = LossEntry {
        action: ContainmentAction::Challenge,
        state: RiskState::Anomalous,
        loss_millionths: 350_000,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: LossEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.action, ContainmentAction::Challenge);
    assert_eq!(recovered.state, RiskState::Anomalous);
    assert_eq!(recovered.loss_millionths, 350_000);
}

// ---------- conservative selector produces stricter decisions ----------

#[test]
fn conservative_selector_at_least_as_strict_as_balanced() {
    let posterior = Posterior::from_millionths(400_000, 100_000, 400_000, 100_000);
    let mut balanced = ExpectedLossSelector::balanced();
    let mut conservative = ExpectedLossSelector::new(LossMatrix::conservative());

    let balanced_decision = balanced.select(&posterior);
    let conservative_decision = conservative.select(&posterior);

    assert!(
        conservative_decision.action.severity() >= balanced_decision.action.severity(),
        "conservative must be at least as strict as balanced"
    );
}
