//! Integration edge-case tests for the `expected_loss_selector` module.
//!
//! Covers ContainmentAction types, LossMatrix operations, ExpectedLossSelector
//! selection and expected-loss computation, runtime decision scoring, error
//! variants, and guardrail-aware selection.

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

use frankenengine_engine::bayesian_posterior::{Posterior, RiskState};
use frankenengine_engine::expected_loss_selector::{
    ActionDecision, CandidateActionScore, ContainmentAction, DecisionConfidenceInterval,
    DecisionExplanation, ExpectedLossSelector, LossEntry, LossMatrix, RuntimeDecisionScore,
    RuntimeDecisionScoreEvent, RuntimeDecisionScoringError, RuntimeDecisionScoringInput,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_economics::{AttackerCostModel, StrategyCostAdjustment};

// ===========================================================================
// Helpers
// ===========================================================================

const MILLION: i64 = 1_000_000;

fn certain_benign() -> Posterior {
    Posterior::from_millionths(MILLION, 0, 0, 0)
}

fn certain_malicious() -> Posterior {
    Posterior::from_millionths(0, 0, MILLION, 0)
}

fn uniform() -> Posterior {
    Posterior::uniform()
}

fn attacker_cost_model() -> AttackerCostModel {
    let mut strats = BTreeMap::new();
    strats.insert(
        "supply_chain".to_string(),
        StrategyCostAdjustment {
            strategy_name: "supply_chain".to_string(),
            discovery_delta: 100_000,
            development_delta: 200_000,
            evasion_delta: 50_000,
            justification: "test".to_string(),
        },
    );
    AttackerCostModel {
        discovery_cost: 1_000_000,
        development_cost: 2_000_000,
        deployment_cost: 1_000_000,
        persistence_cost: 500_000,
        evasion_cost: 1_000_000,
        expected_gain: 20_000_000,
        strategy_adjustments: strats,
        version: 1,
        calibration_source: "unit-test".to_string(),
    }
}

fn sample_input(posterior: Posterior) -> RuntimeDecisionScoringInput {
    RuntimeDecisionScoringInput {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        extension_id: "ext-001".to_string(),
        policy_version: "v1.0.0".to_string(),
        timestamp_ns: 1_700_000_000_000_000_000,
        posterior,
        attacker_cost_model: attacker_cost_model(),
        extension_roi_history_millionths: vec![1_000_000, 1_500_000],
        fleet_roi_baseline_millionths: BTreeMap::from([("ext-other".into(), 300_000)]),
        blocked_actions: BTreeSet::new(),
    }
}

fn le(action: ContainmentAction, state: RiskState, loss: i64) -> LossEntry {
    LossEntry {
        action,
        state,
        loss_millionths: loss,
    }
}

fn all_pairs_matrix(loss: i64) -> LossMatrix {
    let entries: Vec<LossEntry> = ContainmentAction::ALL
        .iter()
        .flat_map(|action| {
            RiskState::ALL
                .iter()
                .map(move |state| le(*action, *state, loss))
        })
        .collect();
    LossMatrix::new("uniform-loss", entries)
}

// ===========================================================================
// ContainmentAction
// ===========================================================================

#[test]
fn containment_action_display_all() {
    let expected = [
        "allow",
        "challenge",
        "sandbox",
        "suspend",
        "terminate",
        "quarantine",
    ];
    for (action, name) in ContainmentAction::ALL.iter().zip(&expected) {
        assert_eq!(action.to_string(), *name);
    }
}

#[test]
fn containment_action_serde_all() {
    for action in &ContainmentAction::ALL {
        let json = serde_json::to_string(action).unwrap();
        let restored: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, restored);
    }
}

#[test]
fn containment_action_severity_monotonic() {
    for pair in ContainmentAction::ALL.windows(2) {
        assert!(
            pair[0].severity() < pair[1].severity(),
            "{} severity {} should be < {} severity {}",
            pair[0],
            pair[0].severity(),
            pair[1],
            pair[1].severity(),
        );
    }
}

#[test]
fn containment_action_ordering() {
    assert!(ContainmentAction::Allow < ContainmentAction::Quarantine);
}

#[test]
fn containment_action_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(ContainmentAction::Allow);
    s.insert(ContainmentAction::Allow);
    s.insert(ContainmentAction::Sandbox);
    assert_eq!(s.len(), 2);
}

#[test]
fn containment_action_all_has_six() {
    assert_eq!(ContainmentAction::ALL.len(), 6);
}

// ===========================================================================
// LossEntry
// ===========================================================================

#[test]
fn loss_entry_serde() {
    let entry = le(ContainmentAction::Terminate, RiskState::Malicious, 500_000);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: LossEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn loss_entry_negative_loss() {
    let entry = le(ContainmentAction::Allow, RiskState::Benign, -1_000_000);
    assert_eq!(entry.loss_millionths, -1_000_000);
}

// ===========================================================================
// LossMatrix
// ===========================================================================

#[test]
fn balanced_matrix_complete() {
    assert!(LossMatrix::balanced().is_complete());
}

#[test]
fn conservative_matrix_complete() {
    assert!(LossMatrix::conservative().is_complete());
}

#[test]
fn permissive_matrix_complete() {
    assert!(LossMatrix::permissive().is_complete());
}

#[test]
fn loss_matrix_serde_roundtrip() {
    let m = LossMatrix::balanced();
    let json = serde_json::to_string(&m).unwrap();
    let restored: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

#[test]
fn loss_matrix_content_hash_deterministic() {
    assert_eq!(
        LossMatrix::balanced().content_hash(),
        LossMatrix::balanced().content_hash()
    );
}

#[test]
fn different_matrices_different_hashes() {
    assert_ne!(
        LossMatrix::balanced().content_hash(),
        LossMatrix::conservative().content_hash()
    );
    assert_ne!(
        LossMatrix::balanced().content_hash(),
        LossMatrix::permissive().content_hash()
    );
}

#[test]
fn loss_lookup_specific_values() {
    let m = LossMatrix::balanced();
    assert_eq!(m.loss(ContainmentAction::Allow, RiskState::Benign), 0);
    assert_eq!(
        m.loss(ContainmentAction::Allow, RiskState::Malicious),
        100_000_000
    );
    assert_eq!(
        m.loss(ContainmentAction::Quarantine, RiskState::Malicious),
        200_000
    );
}

#[test]
fn loss_lookup_known_values() {
    let m = LossMatrix::balanced();
    // Verify specific known values from the balanced matrix.
    assert_eq!(m.loss(ContainmentAction::Allow, RiskState::Benign), 0);
    assert_eq!(
        m.loss(ContainmentAction::Terminate, RiskState::Malicious),
        500_000
    );
    assert_eq!(
        m.loss(ContainmentAction::Quarantine, RiskState::Malicious),
        200_000
    );
}

#[test]
fn uniform_loss_matrix_complete() {
    let m = all_pairs_matrix(MILLION);
    assert!(m.is_complete());
}

#[test]
fn matrix_id_preserved() {
    assert_eq!(LossMatrix::balanced().matrix_id, "balanced-v1");
    assert_eq!(LossMatrix::conservative().matrix_id, "conservative-v1");
    assert_eq!(LossMatrix::permissive().matrix_id, "permissive-v1");
}

// ===========================================================================
// ExpectedLossSelector — construction
// ===========================================================================

#[test]
fn selector_balanced_constructor() {
    let s = ExpectedLossSelector::balanced();
    assert_eq!(s.decisions_made(), 0);
    assert_eq!(s.loss_matrix().matrix_id, "balanced-v1");
}

#[test]
fn selector_custom_matrix() {
    let m = all_pairs_matrix(MILLION);
    let s = ExpectedLossSelector::new(m);
    assert_eq!(s.loss_matrix().matrix_id, "uniform-loss");
}

#[test]
fn selector_serde_roundtrip() {
    let mut s = ExpectedLossSelector::balanced();
    s.select(&uniform());
    let json = serde_json::to_string(&s).unwrap();
    let restored: ExpectedLossSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.decisions_made(), 1);
}

// ===========================================================================
// ExpectedLossSelector — expected losses
// ===========================================================================

#[test]
fn expected_losses_all_six_actions() {
    let s = ExpectedLossSelector::balanced();
    let losses = s.expected_losses(&uniform());
    assert_eq!(losses.len(), 6);
}

#[test]
fn expected_losses_deterministic() {
    let s = ExpectedLossSelector::balanced();
    let p = uniform();
    assert_eq!(s.expected_losses(&p), s.expected_losses(&p));
}

#[test]
fn expected_losses_certain_benign_allow_is_minimum() {
    let s = ExpectedLossSelector::balanced();
    let losses = s.expected_losses(&certain_benign());
    let allow_loss = *losses.get(&ContainmentAction::Allow).unwrap();
    // Allow should have the minimum expected loss when posterior is heavily benign.
    for loss in losses.values() {
        assert!(allow_loss <= *loss);
    }
}

#[test]
fn expected_losses_certain_malicious_quarantine_lowest() {
    let s = ExpectedLossSelector::balanced();
    let losses = s.expected_losses(&certain_malicious());
    let quarantine_loss = *losses.get(&ContainmentAction::Quarantine).unwrap();
    for (action, loss) in &losses {
        assert!(
            quarantine_loss <= *loss,
            "quarantine loss {} should be <= {} loss {}",
            quarantine_loss,
            action,
            loss
        );
    }
}

// ===========================================================================
// ExpectedLossSelector — select
// ===========================================================================

#[test]
fn select_benign_chooses_allow() {
    let mut s = ExpectedLossSelector::balanced();
    assert_eq!(s.select(&certain_benign()).action, ContainmentAction::Allow);
}

#[test]
fn select_malicious_chooses_severe() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&certain_malicious());
    assert!(d.action == ContainmentAction::Quarantine || d.action == ContainmentAction::Terminate);
}

#[test]
fn select_returns_runner_up() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    assert_ne!(d.action, d.runner_up_action);
    assert!(d.runner_up_loss_millionths >= d.expected_loss_millionths);
}

#[test]
fn select_margin_is_nonnegative() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    assert!(d.explanation.margin_millionths >= 0);
}

#[test]
fn select_increments_decisions_made() {
    let mut s = ExpectedLossSelector::balanced();
    assert_eq!(s.decisions_made(), 0);
    s.select(&uniform());
    assert_eq!(s.decisions_made(), 1);
    s.select(&certain_benign());
    assert_eq!(s.decisions_made(), 2);
}

#[test]
fn select_epoch_stamped() {
    let mut s = ExpectedLossSelector::balanced();
    s.set_epoch(SecurityEpoch::from_raw(99));
    let d = s.select(&uniform());
    assert_eq!(d.epoch, SecurityEpoch::from_raw(99));
}

#[test]
fn select_explanation_loss_matrix_id() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    assert_eq!(d.explanation.loss_matrix_id, "balanced-v1");
}

#[test]
fn select_explanation_all_losses_present() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    assert_eq!(d.explanation.all_expected_losses.len(), 6);
}

// ===========================================================================
// Tie-breaking
// ===========================================================================

#[test]
fn tie_breaking_prefers_less_severe() {
    let m = all_pairs_matrix(MILLION);
    let mut s = ExpectedLossSelector::new(m);
    let d = s.select(&uniform());
    assert_eq!(d.action, ContainmentAction::Allow);
}

// ===========================================================================
// Property: selected is minimum
// ===========================================================================

#[test]
fn selected_action_has_minimum_loss() {
    let mut s = ExpectedLossSelector::balanced();
    for p in [certain_benign(), certain_malicious(), uniform()] {
        let d = s.select(&p);
        let losses = s.expected_losses(&p);
        for loss in losses.values() {
            assert!(d.expected_loss_millionths <= *loss);
        }
    }
}

// ===========================================================================
// Matrix swap
// ===========================================================================

#[test]
fn changing_matrix_changes_decision() {
    let mut s = ExpectedLossSelector::new(LossMatrix::permissive());
    let d1 = s.select(&uniform());
    s.set_loss_matrix(LossMatrix::conservative());
    let d2 = s.select(&uniform());
    assert_ne!(d1.expected_loss_millionths, d2.expected_loss_millionths);
}

// ===========================================================================
// Serde roundtrips — decision types
// ===========================================================================

#[test]
fn action_decision_serde() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    let json = serde_json::to_string(&d).unwrap();
    let restored: ActionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn decision_explanation_serde() {
    let mut s = ExpectedLossSelector::balanced();
    let d = s.select(&uniform());
    let json = serde_json::to_string(&d.explanation).unwrap();
    let restored: DecisionExplanation = serde_json::from_str(&json).unwrap();
    assert_eq!(d.explanation, restored);
}

#[test]
fn decision_confidence_interval_serde() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: -500,
        upper_millionths: 500,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let restored: DecisionConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
}

#[test]
fn candidate_action_score_serde() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Sandbox,
        expected_loss_millionths: 5_000_000,
        state_contributions_millionths: BTreeMap::from([
            ("benign".into(), 1_000_000),
            ("malicious".into(), 4_000_000),
        ]),
        guardrail_blocked: false,
    };
    let json = serde_json::to_string(&cas).unwrap();
    let restored: CandidateActionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(cas, restored);
}

#[test]
fn runtime_decision_score_event_serde() {
    let evt = RuntimeDecisionScoreEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "comp".into(),
        event: "ev".into(),
        outcome: "ok".into(),
        error_code: Some("E001".into()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let restored: RuntimeDecisionScoreEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, restored);
}

// ===========================================================================
// RuntimeDecisionScoringError
// ===========================================================================

#[test]
fn error_missing_field_display() {
    let e = RuntimeDecisionScoringError::MissingField {
        field: "trace_id".into(),
    };
    assert!(e.to_string().contains("trace_id"));
}

#[test]
fn error_zero_attacker_cost_display() {
    let e = RuntimeDecisionScoringError::ZeroAttackerCost;
    assert!(e.to_string().contains("zero"));
}

#[test]
fn error_all_actions_blocked_display() {
    let e = RuntimeDecisionScoringError::AllActionsBlocked;
    assert!(e.to_string().contains("blocked"));
}

#[test]
fn error_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(RuntimeDecisionScoringError::ZeroAttackerCost);
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_serde_all() {
    let errors = [
        RuntimeDecisionScoringError::MissingField { field: "x".into() },
        RuntimeDecisionScoringError::ZeroAttackerCost,
        RuntimeDecisionScoringError::AllActionsBlocked,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: RuntimeDecisionScoringError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &restored);
    }
}

// ===========================================================================
// Runtime decision scoring — valid
// ===========================================================================

#[test]
fn runtime_scoring_valid_benign() {
    let mut s = ExpectedLossSelector::balanced();
    s.set_epoch(SecurityEpoch::from_raw(5));
    let input = sample_input(certain_benign());
    let score = s.score_runtime_decision(&input).unwrap();
    assert_eq!(score.trace_id, "trace-001");
    assert_eq!(score.decision_id, "decision-001");
    assert_eq!(score.selected_action, ContainmentAction::Allow);
    assert_eq!(score.epoch, SecurityEpoch::from_raw(5));
    assert_eq!(score.loss_matrix_version, "balanced-v1");
    assert_eq!(score.candidate_actions.len(), 6);
}

#[test]
fn runtime_scoring_candidate_actions_sorted() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    for pair in score.candidate_actions.windows(2) {
        assert!(pair[0].expected_loss_millionths <= pair[1].expected_loss_millionths);
    }
}

#[test]
fn runtime_scoring_confidence_interval_wellformed() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    assert!(score.confidence_interval.lower_millionths <= score.selected_expected_loss_millionths);
    assert!(score.confidence_interval.upper_millionths >= score.selected_expected_loss_millionths);
}

#[test]
fn runtime_scoring_events_has_decision_scored() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    assert!(score.events.iter().any(|e| e.event == "decision_scored"));
}

#[test]
fn runtime_scoring_state_contributions_per_action() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    for ca in &score.candidate_actions {
        assert_eq!(ca.state_contributions_millionths.len(), 4);
    }
}

#[test]
fn runtime_scoring_deterministic() {
    let mut s = ExpectedLossSelector::balanced();
    let input = sample_input(uniform());
    let r1 = s.score_runtime_decision(&input).unwrap();
    let r2 = s.score_runtime_decision(&input).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn runtime_scoring_serde_roundtrip() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    let json = serde_json::to_string(&score).unwrap();
    let restored: RuntimeDecisionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, restored);
}

#[test]
fn runtime_scoring_increments_decisions_made() {
    let mut s = ExpectedLossSelector::balanced();
    assert_eq!(s.decisions_made(), 0);
    s.score_runtime_decision(&sample_input(uniform())).unwrap();
    assert_eq!(s.decisions_made(), 1);
}

// ===========================================================================
// Runtime decision scoring — guardrails
// ===========================================================================

#[test]
fn runtime_scoring_guardrail_blocks_optimal() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(certain_benign());
    input.blocked_actions.insert(ContainmentAction::Allow);
    let score = s.score_runtime_decision(&input).unwrap();
    assert_ne!(score.selected_action, ContainmentAction::Allow);
    assert!(
        score
            .events
            .iter()
            .any(|e| e.event == "guardrail_veto_applied")
    );
}

#[test]
fn runtime_scoring_all_blocked_error() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.blocked_actions = ContainmentAction::ALL.into_iter().collect();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert_eq!(err, RuntimeDecisionScoringError::AllActionsBlocked);
}

#[test]
fn runtime_scoring_multiple_blocked_skips_all() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(certain_malicious());
    input.blocked_actions.insert(ContainmentAction::Quarantine);
    input.blocked_actions.insert(ContainmentAction::Terminate);
    input.blocked_actions.insert(ContainmentAction::Suspend);
    let score = s.score_runtime_decision(&input).unwrap();
    assert!(!input.blocked_actions.contains(&score.selected_action));
}

#[test]
fn runtime_scoring_blocked_actions_flagged_in_candidates() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.blocked_actions.insert(ContainmentAction::Allow);
    let score = s.score_runtime_decision(&input).unwrap();
    let allow_candidate = score
        .candidate_actions
        .iter()
        .find(|c| c.action == ContainmentAction::Allow)
        .unwrap();
    assert!(allow_candidate.guardrail_blocked);
}

// ===========================================================================
// Runtime decision scoring — validation errors
// ===========================================================================

#[test]
fn runtime_scoring_missing_trace_id() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.trace_id.clear();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "trace_id"
    ));
}

#[test]
fn runtime_scoring_missing_decision_id() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.decision_id.clear();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "decision_id"
    ));
}

#[test]
fn runtime_scoring_missing_policy_id() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.policy_id.clear();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "policy_id"
    ));
}

#[test]
fn runtime_scoring_missing_extension_id() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.extension_id.clear();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "extension_id"
    ));
}

#[test]
fn runtime_scoring_missing_policy_version() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.policy_version.clear();
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "policy_version"
    ));
}

#[test]
fn runtime_scoring_whitespace_only_trace_id_fails() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.trace_id = "   ".into();
    assert!(s.score_runtime_decision(&input).is_err());
}

#[test]
fn runtime_scoring_zero_attacker_cost() {
    let mut s = ExpectedLossSelector::balanced();
    let mut input = sample_input(uniform());
    input.attacker_cost_model = AttackerCostModel {
        discovery_cost: 0,
        development_cost: 0,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 0,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "test".into(),
    };
    let err = s.score_runtime_decision(&input).unwrap_err();
    assert_eq!(err, RuntimeDecisionScoringError::ZeroAttackerCost);
}

// ===========================================================================
// Runtime decision scoring — borderline + sensitivity
// ===========================================================================

#[test]
fn non_borderline_has_empty_sensitivity() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s
        .score_runtime_decision(&sample_input(certain_malicious()))
        .unwrap();
    assert!(!score.borderline_decision);
    assert!(score.sensitivity_deltas.is_empty());
}

#[test]
fn runtime_scoring_rationale_contains_posterior() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    assert!(score.selection_rationale.contains("p_benign="));
    assert!(score.selection_rationale.contains("p_malicious="));
    assert!(score.selection_rationale.contains("margin="));
}

// ===========================================================================
// Runtime decision scoring — fleet ROI
// ===========================================================================

#[test]
fn runtime_scoring_fleet_roi_includes_extension() {
    let mut s = ExpectedLossSelector::balanced();
    let score = s.score_runtime_decision(&sample_input(uniform())).unwrap();
    assert_eq!(score.fleet_roi_summary.extension_count, 2);
    assert_eq!(score.attacker_roi.extension_id, "ext-001");
}

#[test]
fn runtime_scoring_receipt_hash_deterministic() {
    let mut s = ExpectedLossSelector::balanced();
    let input = sample_input(uniform());
    let r1 = s.score_runtime_decision(&input).unwrap();
    let r2 = s.score_runtime_decision(&input).unwrap();
    assert_eq!(r1.receipt_preimage_hash, r2.receipt_preimage_hash);
}

// ===========================================================================
// Monotonicity property
// ===========================================================================

#[test]
fn increasing_malicious_never_relaxes_action() {
    let mut s = ExpectedLossSelector::balanced();
    let mut prev_severity = 0u32;
    for i in 0..=10 {
        let p_mal = MILLION * i / 10;
        let p_ben = MILLION - p_mal;
        let d = s.select(&Posterior::from_millionths(p_ben, 0, p_mal, 0));
        assert!(
            d.action.severity() >= prev_severity,
            "monotonicity violation at step {i}"
        );
        prev_severity = d.action.severity();
    }
}

// ===========================================================================
// LossMatrix with private entries field — test via deserialization
// ===========================================================================

#[test]
fn loss_matrix_deserialized_preserves_entries() {
    let original = LossMatrix::balanced();
    let json = serde_json::to_string(&original).unwrap();
    let restored: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
    assert!(restored.is_complete());
    assert_eq!(
        restored.loss(ContainmentAction::Allow, RiskState::Malicious),
        100_000_000
    );
}
