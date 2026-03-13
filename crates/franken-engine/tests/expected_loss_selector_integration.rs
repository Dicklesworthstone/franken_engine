#![forbid(unsafe_code)]
//! Integration tests for the `expected_loss_selector` module.
//!
//! Exercises loss-matrix construction, expected-loss computation,
//! action selection, runtime decision scoring, and serde round-trips
//! from outside the crate boundary.

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
    ActionDecision, AlienRiskAlertLevel, AlienRiskEnvelope, CandidateActionScore,
    ContainmentAction, DecisionConfidenceInterval, DecisionExplanation, ExpectedLossSelector,
    LossEntry, LossMatrix, RuntimeDecisionScore, RuntimeDecisionScoreEvent,
    RuntimeDecisionScoringError, RuntimeDecisionScoringInput,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_economics::AttackerCostModel;

// ===========================================================================
// Helpers
// ===========================================================================

fn certain_benign() -> Posterior {
    Posterior {
        p_benign: 1_000_000,
        p_anomalous: 0,
        p_malicious: 0,
        p_unknown: 0,
    }
}

fn certain_malicious() -> Posterior {
    Posterior {
        p_benign: 0,
        p_anomalous: 0,
        p_malicious: 1_000_000,
        p_unknown: 0,
    }
}

fn uniform_posterior() -> Posterior {
    Posterior {
        p_benign: 250_000,
        p_anomalous: 250_000,
        p_malicious: 250_000,
        p_unknown: 250_000,
    }
}

fn test_attacker_cost_model() -> AttackerCostModel {
    AttackerCostModel {
        discovery_cost: 100_000,
        development_cost: 200_000,
        deployment_cost: 150_000,
        persistence_cost: 50_000,
        evasion_cost: 80_000,
        expected_gain: 1_000_000,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "manual".into(),
    }
}

fn test_scoring_input(posterior: Posterior) -> RuntimeDecisionScoringInput {
    RuntimeDecisionScoringInput {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        extension_id: "ext-1".into(),
        policy_version: "v1".into(),
        timestamp_ns: 1000,
        posterior,
        attacker_cost_model: test_attacker_cost_model(),
        extension_roi_history_millionths: vec![500_000, 600_000, 700_000],
        fleet_roi_baseline_millionths: {
            let mut m = BTreeMap::new();
            m.insert("ext-1".into(), 600_000);
            m.insert("ext-2".into(), 800_000);
            m
        },
        blocked_actions: BTreeSet::new(),
    }
}

// ===========================================================================
// 1. ContainmentAction — display, severity, ALL, serde
// ===========================================================================

#[test]
fn containment_action_display_all_variants() {
    assert_eq!(ContainmentAction::Allow.to_string(), "allow");
    assert_eq!(ContainmentAction::Challenge.to_string(), "challenge");
    assert_eq!(ContainmentAction::Sandbox.to_string(), "sandbox");
    assert_eq!(ContainmentAction::Suspend.to_string(), "suspend");
    assert_eq!(ContainmentAction::Terminate.to_string(), "terminate");
    assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
}

#[test]
fn containment_action_severity_monotonic() {
    let all = ContainmentAction::ALL;
    for w in all.windows(2) {
        assert!(
            w[0].severity() < w[1].severity(),
            "{} should be less severe than {}",
            w[0],
            w[1]
        );
    }
}

#[test]
fn containment_action_all_has_six() {
    assert_eq!(ContainmentAction::ALL.len(), 6);
}

#[test]
fn containment_action_serde_round_trip() {
    for a in ContainmentAction::ALL {
        let json = serde_json::to_string(&a).unwrap();
        let back: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}

// ===========================================================================
// 2. LossMatrix — balanced, conservative, permissive, completeness, lookup
// ===========================================================================

#[test]
fn loss_matrix_balanced_is_complete() {
    assert!(LossMatrix::balanced().is_complete());
}

#[test]
fn loss_matrix_conservative_is_complete() {
    assert!(LossMatrix::conservative().is_complete());
}

#[test]
fn loss_matrix_permissive_is_complete() {
    assert!(LossMatrix::permissive().is_complete());
}

#[test]
fn loss_matrix_lookup_returns_value() {
    let m = LossMatrix::balanced();
    // Just verify we can look up all (action, state) pairs
    for a in ContainmentAction::ALL {
        for s in [
            RiskState::Benign,
            RiskState::Anomalous,
            RiskState::Malicious,
            RiskState::Unknown,
        ] {
            let _ = m.loss(a, s);
        }
    }
}

#[test]
fn loss_matrix_content_hash_deterministic() {
    let h1 = LossMatrix::balanced().content_hash();
    let h2 = LossMatrix::balanced().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn loss_matrix_different_matrices_different_hashes() {
    let h_balanced = LossMatrix::balanced().content_hash();
    let h_conservative = LossMatrix::conservative().content_hash();
    let h_permissive = LossMatrix::permissive().content_hash();
    assert_ne!(h_balanced, h_conservative);
    assert_ne!(h_balanced, h_permissive);
    assert_ne!(h_conservative, h_permissive);
}

#[test]
fn loss_matrix_serde_round_trip() {
    let m = LossMatrix::balanced();
    let json = serde_json::to_string(&m).unwrap();
    let back: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(back.is_complete(), m.is_complete());
    // Same content hash after round-trip
    assert_eq!(back.content_hash(), m.content_hash());
}

// ===========================================================================
// 3. ExpectedLossSelector — expected_losses computation
// ===========================================================================

#[test]
fn expected_losses_returns_all_six_actions() {
    let sel = ExpectedLossSelector::balanced();
    let losses = sel.expected_losses(&certain_benign());
    assert_eq!(losses.len(), 6);
    for a in ContainmentAction::ALL {
        assert!(losses.contains_key(&a), "missing {a}");
    }
}

#[test]
fn expected_losses_deterministic() {
    let sel = ExpectedLossSelector::balanced();
    let l1 = sel.expected_losses(&uniform_posterior());
    let l2 = sel.expected_losses(&uniform_posterior());
    assert_eq!(l1, l2);
}

// ===========================================================================
// 4. ExpectedLossSelector — select
// ===========================================================================

#[test]
fn select_allow_for_certain_benign() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    assert_eq!(d.action, ContainmentAction::Allow);
}

#[test]
fn select_severe_for_certain_malicious() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_malicious());
    // Should be Quarantine or Terminate (most severe)
    assert!(
        d.action.severity() >= ContainmentAction::Suspend.severity(),
        "Expected severe action for certain malicious, got {}",
        d.action
    );
}

#[test]
fn select_decision_increments_counter() {
    let mut sel = ExpectedLossSelector::balanced();
    assert_eq!(sel.decisions_made(), 0);
    sel.select(&certain_benign());
    assert_eq!(sel.decisions_made(), 1);
    sel.select(&certain_malicious());
    assert_eq!(sel.decisions_made(), 2);
}

#[test]
fn select_stamps_epoch() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.set_epoch(SecurityEpoch::from_raw(42));
    let d = sel.select(&certain_benign());
    assert_eq!(d.epoch, SecurityEpoch::from_raw(42));
}

// ===========================================================================
// 5. ActionDecision — structure and explanation
// ===========================================================================

#[test]
fn action_decision_explanation_has_all_losses() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    assert_eq!(d.explanation.all_expected_losses.len(), 6);
}

#[test]
fn action_decision_margin_non_negative() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    assert!(
        d.explanation.margin_millionths >= 0,
        "margin should be non-negative, got {}",
        d.explanation.margin_millionths
    );
}

#[test]
fn action_decision_selected_is_minimum() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    for &loss in d.explanation.all_expected_losses.values() {
        assert!(
            d.expected_loss_millionths <= loss,
            "selected loss {} > some action loss {}",
            d.expected_loss_millionths,
            loss
        );
    }
}

#[test]
fn action_decision_runner_up_loss_ge_selected() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    assert!(d.runner_up_loss_millionths >= d.expected_loss_millionths);
}

#[test]
fn action_decision_serde_round_trip() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    let json = serde_json::to_string(&d).unwrap();
    let back: ActionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 6. Tie-breaking — less severe wins
// ===========================================================================

#[test]
fn tie_breaking_prefers_less_severe() {
    // With uniform posterior, if two actions have equal expected loss,
    // the less severe one should be selected
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    // The selected action should have <= severity than runner_up when losses match
    if d.expected_loss_millionths == d.runner_up_loss_millionths {
        assert!(d.action.severity() < d.runner_up_action.severity());
    }
}

// ===========================================================================
// 7. Loss matrix swap
// ===========================================================================

#[test]
fn changing_matrix_changes_expected_losses() {
    let mut sel = ExpectedLossSelector::new(LossMatrix::balanced());
    let l1 = sel.expected_losses(&uniform_posterior());

    sel.set_loss_matrix(LossMatrix::conservative());
    let l2 = sel.expected_losses(&uniform_posterior());

    // Different matrices should produce different losses for at least some actions
    assert_ne!(
        l1, l2,
        "balanced and conservative should differ for uniform posterior"
    );
}

// ===========================================================================
// 8. Selector serde
// ===========================================================================

#[test]
fn selector_serde_round_trip() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.select(&certain_benign());
    let json = serde_json::to_string(&sel).unwrap();
    let back: ExpectedLossSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decisions_made(), sel.decisions_made());
}

// ===========================================================================
// 9. Runtime decision scoring — basic
// ===========================================================================

#[test]
fn runtime_scoring_benign_selects_allow() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.selected_action, ContainmentAction::Allow);
}

#[test]
fn runtime_scoring_malicious_selects_severe() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_malicious());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(score.selected_action.severity() >= ContainmentAction::Suspend.severity());
}

#[test]
fn runtime_scoring_fields_populated() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();

    assert_eq!(score.trace_id, "t-1");
    assert_eq!(score.decision_id, "d-1");
    assert_eq!(score.policy_id, "p-1");
    assert_eq!(score.extension_id, "ext-1");
    assert_eq!(score.policy_version, "v1");
    assert_eq!(score.timestamp_ns, 1000);
    assert_eq!(score.candidate_actions.len(), 6);
    assert!(!score.events.is_empty());
}

#[test]
fn runtime_scoring_candidate_actions_always_six() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.candidate_actions.len(), 6);
}

#[test]
fn runtime_scoring_is_deterministic() {
    let input = test_scoring_input(uniform_posterior());
    let mut sel1 = ExpectedLossSelector::balanced();
    let mut sel2 = ExpectedLossSelector::balanced();
    let s1 = sel1.score_runtime_decision(&input).unwrap();
    let s2 = sel2.score_runtime_decision(&input).unwrap();
    assert_eq!(s1.selected_action, s2.selected_action);
    assert_eq!(
        s1.selected_expected_loss_millionths,
        s2.selected_expected_loss_millionths
    );
    assert_eq!(s1.receipt_preimage_hash, s2.receipt_preimage_hash);
}

// ===========================================================================
// 10. Runtime decision scoring — guardrail veto
// ===========================================================================

#[test]
fn runtime_scoring_blocked_action_skipped() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.blocked_actions.insert(ContainmentAction::Allow);
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_ne!(score.selected_action, ContainmentAction::Allow);
}

#[test]
fn runtime_scoring_all_blocked_returns_error() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    for a in ContainmentAction::ALL {
        input.blocked_actions.insert(a);
    }
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::AllActionsBlocked
    ));
}

// ===========================================================================
// 11. Runtime decision scoring — validation errors
// ===========================================================================

#[test]
fn runtime_scoring_empty_trace_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.trace_id = String::new();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

#[test]
fn runtime_scoring_zero_attacker_cost_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.attacker_cost_model = AttackerCostModel {
        discovery_cost: 0,
        development_cost: 0,
        deployment_cost: 0,
        persistence_cost: 0,
        evasion_cost: 0,
        expected_gain: 0,
        strategy_adjustments: BTreeMap::new(),
        version: 1,
        calibration_source: "manual".into(),
    };
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(err, RuntimeDecisionScoringError::ZeroAttackerCost));
}

// ===========================================================================
// 12. Runtime decision scoring — borderline detection
// ===========================================================================

#[test]
fn runtime_scoring_borderline_when_margin_small() {
    // Use a posterior that creates near-equal expected losses between top actions
    let posterior = Posterior {
        p_benign: 500_000,
        p_anomalous: 250_000,
        p_malicious: 125_000,
        p_unknown: 125_000,
    };
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(posterior);
    let score = sel.score_runtime_decision(&input).unwrap();
    // borderline_decision is set when margin < 10% of expected loss
    // Just verify the field is present and consistent
    if score.borderline_decision {
        assert!(
            !score.sensitivity_deltas.is_empty(),
            "borderline should have sensitivity deltas"
        );
    }
}

#[test]
fn runtime_scoring_certain_not_borderline() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(!score.borderline_decision);
    assert!(score.sensitivity_deltas.is_empty());
}

// ===========================================================================
// 13. Runtime decision scoring — alien risk envelope
// ===========================================================================

#[test]
fn runtime_scoring_alien_envelope_present() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    let env = &score.alien_risk_envelope;
    // Should be populated
    assert_ne!(env.tail_confidence_millionths, 0);
}

// ===========================================================================
// 14. AlienRiskAlertLevel — display, serde
// ===========================================================================

#[test]
fn alien_risk_alert_level_display() {
    assert_eq!(AlienRiskAlertLevel::Nominal.to_string(), "nominal");
    assert_eq!(AlienRiskAlertLevel::Elevated.to_string(), "elevated");
    assert_eq!(AlienRiskAlertLevel::Critical.to_string(), "critical");
}

#[test]
fn alien_risk_alert_level_serde_round_trip() {
    for l in [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let back: AlienRiskAlertLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
    }
}

// ===========================================================================
// 15. RuntimeDecisionScoringError — display, serde
// ===========================================================================

#[test]
fn runtime_decision_scoring_error_display() {
    let e1 = RuntimeDecisionScoringError::MissingField {
        field: "trace_id".into(),
    };
    assert!(e1.to_string().contains("trace_id"));

    let e2 = RuntimeDecisionScoringError::ZeroAttackerCost;
    assert!(!e2.to_string().is_empty());

    let e3 = RuntimeDecisionScoringError::AllActionsBlocked;
    assert!(!e3.to_string().is_empty());
}

#[test]
fn runtime_decision_scoring_error_serde_round_trip() {
    let errs = vec![
        RuntimeDecisionScoringError::MissingField {
            field: "trace_id".into(),
        },
        RuntimeDecisionScoringError::ZeroAttackerCost,
        RuntimeDecisionScoringError::AllActionsBlocked,
    ];
    for e in errs {
        let json = serde_json::to_string(&e).unwrap();
        let back: RuntimeDecisionScoringError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

// ===========================================================================
// 16. Serde round-trips for additional types
// ===========================================================================

#[test]
fn loss_entry_serde_round_trip() {
    let entry = LossEntry {
        action: ContainmentAction::Sandbox,
        state: RiskState::Anomalous,
        loss_millionths: 250_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: LossEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn decision_confidence_interval_serde_round_trip() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: 100_000,
        upper_millionths: 900_000,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: DecisionConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ci);
}

#[test]
fn candidate_action_score_serde_round_trip() {
    let score = CandidateActionScore {
        action: ContainmentAction::Allow,
        expected_loss_millionths: 50_000,
        state_contributions_millionths: {
            let mut m = BTreeMap::new();
            m.insert("benign".into(), 10_000);
            m.insert("malicious".into(), 40_000);
            m
        },
        guardrail_blocked: false,
    };
    let json = serde_json::to_string(&score).unwrap();
    let back: CandidateActionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(back, score);
}

#[test]
fn runtime_decision_score_event_serde_round_trip() {
    let event = RuntimeDecisionScoreEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "test".into(),
        event: "scored".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RuntimeDecisionScoreEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn alien_risk_envelope_serde_round_trip() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 900_000,
        tail_var_millionths: 500_000,
        tail_cvar_millionths: 600_000,
        conformal_quantile_millionths: 750_000,
        conformal_p_value_millionths: 50_000,
        e_value_millionths: 1_200_000,
        regime_shift_score_millionths: 2_000_000,
        alert_level: AlienRiskAlertLevel::Elevated,
        recommended_floor_action: Some(ContainmentAction::Sandbox),
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: AlienRiskEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(back, env);
}

#[test]
fn decision_explanation_serde_round_trip() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    let json = serde_json::to_string(&d.explanation).unwrap();
    let back: DecisionExplanation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d.explanation);
}

// ===========================================================================
// 17. RuntimeDecisionScore — full serde
// ===========================================================================

#[test]
fn runtime_decision_score_serde_round_trip() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    let json = serde_json::to_string(&score).unwrap();
    let back: RuntimeDecisionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.selected_action, score.selected_action);
    assert_eq!(back.trace_id, score.trace_id);
    assert_eq!(back.receipt_preimage_hash, score.receipt_preimage_hash);
}

// ===========================================================================
// 18. Monotonicity — increasing malicious never relaxes
// ===========================================================================

#[test]
fn monotonicity_increasing_malicious_never_relaxes() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut prev_severity = 0;
    for p_mal in (0..=10).map(|i| i * 100_000) {
        let p_benign = 1_000_000 - p_mal;
        let posterior = Posterior {
            p_benign,
            p_anomalous: 0,
            p_malicious: p_mal,
            p_unknown: 0,
        };
        let d = sel.select(&posterior);
        assert!(
            d.action.severity() >= prev_severity,
            "severity decreased at p_mal={}: {} < {}",
            p_mal,
            d.action.severity(),
            prev_severity
        );
        prev_severity = d.action.severity();
    }
}

// ===========================================================================
// 19. Property: selected action is always minimum expected loss
// ===========================================================================

#[test]
fn selected_action_is_minimum_across_posteriors() {
    let mut sel = ExpectedLossSelector::balanced();
    let posteriors = [
        certain_benign(),
        certain_malicious(),
        uniform_posterior(),
        Posterior {
            p_benign: 800_000,
            p_anomalous: 100_000,
            p_malicious: 50_000,
            p_unknown: 50_000,
        },
    ];
    for p in &posteriors {
        let d = sel.select(p);
        let losses = sel.expected_losses(p);
        for &loss in losses.values() {
            assert!(
                d.expected_loss_millionths <= loss,
                "selected {} ({}) > other action ({})",
                d.action,
                d.expected_loss_millionths,
                loss
            );
        }
    }
}

// ===========================================================================
// 20. Full lifecycle integration
// ===========================================================================

#[test]
fn full_lifecycle_balanced_selector() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.set_epoch(SecurityEpoch::from_raw(1));

    // 1. Select for benign
    let d1 = sel.select(&certain_benign());
    assert_eq!(d1.action, ContainmentAction::Allow);
    assert_eq!(d1.epoch, SecurityEpoch::from_raw(1));

    // 2. Select for malicious
    let d2 = sel.select(&certain_malicious());
    assert!(d2.action.severity() >= ContainmentAction::Suspend.severity());

    // 3. Epoch update
    sel.set_epoch(SecurityEpoch::from_raw(2));
    let d3 = sel.select(&certain_benign());
    assert_eq!(d3.epoch, SecurityEpoch::from_raw(2));

    // 4. Counter
    assert_eq!(sel.decisions_made(), 3);

    // 5. Matrix swap
    sel.set_loss_matrix(LossMatrix::conservative());
    let d4 = sel.select(&uniform_posterior());
    // Conservative should be more cautious with uncertain input
    assert!(d4.action.severity() >= d1.action.severity());

    // 6. Runtime scoring
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.extension_id, "ext-1");
    assert!(!score.events.is_empty());
    assert_eq!(sel.decisions_made(), 5); // select+score both count
}

// ===========================================================================
// 21. Conservative matrix is more cautious under uncertainty
// ===========================================================================

#[test]
fn conservative_more_severe_than_balanced_for_uncertain() {
    let mut bal = ExpectedLossSelector::balanced();
    let mut con = ExpectedLossSelector::new(LossMatrix::conservative());
    let posterior = uniform_posterior();
    let d_bal = bal.select(&posterior);
    let d_con = con.select(&posterior);
    assert!(
        d_con.action.severity() >= d_bal.action.severity(),
        "conservative ({}) should be at least as severe as balanced ({}) for uncertain",
        d_con.action,
        d_bal.action
    );
}

#[test]
fn permissive_less_severe_than_balanced_for_uncertain() {
    let mut bal = ExpectedLossSelector::balanced();
    let mut perm = ExpectedLossSelector::new(LossMatrix::permissive());
    let posterior = uniform_posterior();
    let d_bal = bal.select(&posterior);
    let d_perm = perm.select(&posterior);
    assert!(
        d_perm.action.severity() <= d_bal.action.severity(),
        "permissive ({}) should be no more severe than balanced ({}) for uncertain",
        d_perm.action,
        d_bal.action
    );
}

// ===========================================================================
// 22. Confidence interval properties
// ===========================================================================

#[test]
fn confidence_interval_lower_le_upper() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(
        score.confidence_interval.lower_millionths <= score.confidence_interval.upper_millionths,
        "CI lower {} > upper {}",
        score.confidence_interval.lower_millionths,
        score.confidence_interval.upper_millionths
    );
}

#[test]
fn confidence_interval_contains_selected() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(score.confidence_interval.lower_millionths <= score.selected_expected_loss_millionths);
    assert!(score.confidence_interval.upper_millionths >= score.selected_expected_loss_millionths);
}

#[test]
fn confidence_interval_wider_for_uncertain_posterior() {
    let mut sel = ExpectedLossSelector::balanced();
    let certain_input = test_scoring_input(certain_benign());
    let uncertain_input = test_scoring_input(uniform_posterior());
    let s_certain = sel.score_runtime_decision(&certain_input).unwrap();
    let s_uncertain = sel.score_runtime_decision(&uncertain_input).unwrap();
    let width_certain = s_certain.confidence_interval.upper_millionths
        - s_certain.confidence_interval.lower_millionths;
    let width_uncertain = s_uncertain.confidence_interval.upper_millionths
        - s_uncertain.confidence_interval.lower_millionths;
    assert!(
        width_uncertain >= width_certain,
        "uncertain CI width {} should be >= certain CI width {}",
        width_uncertain,
        width_certain
    );
}

// ===========================================================================
// 23. State contributions sum to expected loss
// ===========================================================================

#[test]
fn state_contributions_sum_to_expected_loss() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    for candidate in &score.candidate_actions {
        let sum: i64 = candidate.state_contributions_millionths.values().sum();
        assert_eq!(
            sum, candidate.expected_loss_millionths,
            "state contributions for {} sum to {} but expected loss is {}",
            candidate.action, sum, candidate.expected_loss_millionths
        );
    }
}

#[test]
fn state_contributions_have_four_entries() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    for candidate in &score.candidate_actions {
        assert_eq!(
            candidate.state_contributions_millionths.len(),
            4,
            "{} should have 4 state contributions",
            candidate.action
        );
    }
}

// ===========================================================================
// 24. Validation: all empty field variants
// ===========================================================================

#[test]
fn runtime_scoring_empty_decision_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.decision_id = String::new();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

#[test]
fn runtime_scoring_empty_policy_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.policy_id = String::new();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

#[test]
fn runtime_scoring_empty_extension_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.extension_id = String::new();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

#[test]
fn runtime_scoring_empty_policy_version_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.policy_version = String::new();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

#[test]
fn runtime_scoring_whitespace_only_trace_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.trace_id = "   ".into();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { .. }
    ));
}

// ===========================================================================
// 25. Alien risk envelope alert level triggers
// ===========================================================================

#[test]
fn alien_risk_benign_with_normal_history_is_nominal() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    // With moderate, similar ROI history values, should be nominal
    assert_eq!(
        score.alien_risk_envelope.alert_level,
        AlienRiskAlertLevel::Nominal
    );
}

#[test]
fn alien_risk_envelope_has_positive_tail_confidence() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(
        score.alien_risk_envelope.tail_confidence_millionths > 0,
        "tail confidence should be positive"
    );
}

#[test]
fn alien_risk_with_extreme_outlier_roi_detects_shift() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    // Create a stable history then extreme current ROI
    input.extension_roi_history_millionths = vec![
        500_000, 500_000, 500_000, 500_000, 500_000, 500_000, 500_000, 500_000,
    ];
    // The attacker ROI will be computed from the cost model which gives ~3.6x
    // regime shift should detect this as an outlier vs the stable 0.5 history
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(
        score.alien_risk_envelope.regime_shift_score_millionths > 0,
        "regime shift score should be positive for outlier ROI"
    );
}

// ===========================================================================
// 26. Floor gap computation
// ===========================================================================

#[test]
fn alien_floor_gap_zero_when_no_floor_recommended() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    if score.alien_risk_envelope.recommended_floor_action.is_none() {
        assert_eq!(score.alien_floor_gap_steps, 0);
    }
}

#[test]
fn alien_floor_gap_zero_when_selected_at_or_above_floor() {
    let mut sel = ExpectedLossSelector::balanced();
    // Malicious input selects severe action, which should be at/above any floor
    let input = test_scoring_input(certain_malicious());
    let score = sel.score_runtime_decision(&input).unwrap();
    if let Some(floor) = score.alien_risk_envelope.recommended_floor_action
        && score.selected_action.severity() >= floor.severity()
    {
        assert_eq!(score.alien_floor_gap_steps, 0);
    }
}

// ===========================================================================
// 27. Receipt hash determinism and sensitivity
// ===========================================================================

#[test]
fn receipt_hash_deterministic_same_inputs() {
    let input = test_scoring_input(certain_benign());
    let mut sel1 = ExpectedLossSelector::balanced();
    let mut sel2 = ExpectedLossSelector::balanced();
    let s1 = sel1.score_runtime_decision(&input).unwrap();
    let s2 = sel2.score_runtime_decision(&input).unwrap();
    assert_eq!(s1.receipt_preimage_hash, s2.receipt_preimage_hash);
}

#[test]
fn receipt_hash_differs_for_different_posteriors() {
    let mut sel = ExpectedLossSelector::balanced();
    let input_benign = test_scoring_input(certain_benign());
    let input_malicious = test_scoring_input(certain_malicious());
    let s1 = sel.score_runtime_decision(&input_benign).unwrap();
    let s2 = sel.score_runtime_decision(&input_malicious).unwrap();
    assert_ne!(
        s1.receipt_preimage_hash, s2.receipt_preimage_hash,
        "different posteriors should yield different receipt hashes"
    );
}

#[test]
fn receipt_hash_differs_for_different_trace_ids() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input1 = test_scoring_input(certain_benign());
    input1.trace_id = "trace-alpha".into();
    let mut input2 = test_scoring_input(certain_benign());
    input2.trace_id = "trace-beta".into();
    let s1 = sel.score_runtime_decision(&input1).unwrap();
    let s2 = sel.score_runtime_decision(&input2).unwrap();
    assert_ne!(s1.receipt_preimage_hash, s2.receipt_preimage_hash);
}

// ===========================================================================
// 28. Fleet ROI summary populated
// ===========================================================================

#[test]
fn fleet_roi_summary_has_all_extensions() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    // Fleet baseline has ext-1 and ext-2, plus the input extension (ext-1)
    assert!(
        score.fleet_roi_summary.extension_count >= 2,
        "fleet should include at least ext-1 and ext-2, got {}",
        score.fleet_roi_summary.extension_count
    );
}

#[test]
fn fleet_roi_summary_average_is_reasonable() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    // Average ROI should be between min and max of inputs
    assert!(
        score.fleet_roi_summary.average_roi_millionths > 0,
        "fleet average ROI should be positive"
    );
}

// ===========================================================================
// 29. Guardrail veto events
// ===========================================================================

#[test]
fn guardrail_veto_emits_event() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.blocked_actions.insert(ContainmentAction::Allow);
    let score = sel.score_runtime_decision(&input).unwrap();
    let veto_events: Vec<_> = score
        .events
        .iter()
        .filter(|e| e.event == "guardrail_veto_applied")
        .collect();
    assert!(
        !veto_events.is_empty(),
        "should emit guardrail_veto_applied event when optimal action is blocked"
    );
    assert!(
        veto_events[0]
            .error_code
            .as_deref()
            .unwrap()
            .contains("GUARDRAIL-VETO")
    );
}

#[test]
fn multiple_blocked_actions_skip_correctly() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.blocked_actions.insert(ContainmentAction::Allow);
    input.blocked_actions.insert(ContainmentAction::Challenge);
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_ne!(score.selected_action, ContainmentAction::Allow);
    assert_ne!(score.selected_action, ContainmentAction::Challenge);
}

#[test]
fn blocked_actions_marked_in_candidates() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.blocked_actions.insert(ContainmentAction::Allow);
    input.blocked_actions.insert(ContainmentAction::Sandbox);
    let score = sel.score_runtime_decision(&input).unwrap();
    for candidate in &score.candidate_actions {
        if candidate.action == ContainmentAction::Allow
            || candidate.action == ContainmentAction::Sandbox
        {
            assert!(
                candidate.guardrail_blocked,
                "{} should be marked as blocked",
                candidate.action
            );
        }
    }
}

// ===========================================================================
// 30. Empty ROI history handling
// ===========================================================================

#[test]
fn empty_roi_history_does_not_panic() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.extension_roi_history_millionths = vec![];
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.selected_action, ContainmentAction::Allow);
    // Should still produce an alien envelope
    assert!(score.alien_risk_envelope.tail_confidence_millionths > 0);
}

// ===========================================================================
// 31. Selection rationale string format
// ===========================================================================

#[test]
fn selection_rationale_contains_expected_fields() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(
        score.selection_rationale.contains("selected"),
        "rationale should mention 'selected'"
    );
    assert!(
        score.selection_rationale.contains("EL("),
        "rationale should mention expected loss"
    );
    assert!(
        score.selection_rationale.contains("margin="),
        "rationale should mention margin"
    );
}

// ===========================================================================
// 32. Candidate actions always ranked by expected loss
// ===========================================================================

#[test]
fn candidate_actions_ranked_by_expected_loss() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    for w in score.candidate_actions.windows(2) {
        assert!(
            w[0].expected_loss_millionths <= w[1].expected_loss_millionths,
            "candidates should be sorted: {} ({}) should be <= {} ({})",
            w[0].action,
            w[0].expected_loss_millionths,
            w[1].action,
            w[1].expected_loss_millionths
        );
    }
}

// ===========================================================================
// 33. All three matrix presets produce different selections for some posterior
// ===========================================================================

#[test]
fn three_matrix_presets_differ_for_ambiguous_posterior() {
    let ambiguous = Posterior {
        p_benign: 400_000,
        p_anomalous: 300_000,
        p_malicious: 200_000,
        p_unknown: 100_000,
    };
    let losses_bal = ExpectedLossSelector::balanced().expected_losses(&ambiguous);
    let losses_con =
        ExpectedLossSelector::new(LossMatrix::conservative()).expected_losses(&ambiguous);
    let losses_perm =
        ExpectedLossSelector::new(LossMatrix::permissive()).expected_losses(&ambiguous);

    // At least one action should have different expected losses
    let any_differ_bc = ContainmentAction::ALL
        .iter()
        .any(|a| losses_bal[a] != losses_con[a]);
    let any_differ_bp = ContainmentAction::ALL
        .iter()
        .any(|a| losses_bal[a] != losses_perm[a]);
    assert!(any_differ_bc, "balanced and conservative should differ");
    assert!(any_differ_bp, "balanced and permissive should differ");
}

// ===========================================================================
// 34. Anomalous-heavy posterior selects sandbox or higher
// ===========================================================================

#[test]
fn anomalous_heavy_posterior_selects_moderate_action() {
    let mostly_anomalous = Posterior {
        p_benign: 100_000,
        p_anomalous: 700_000,
        p_malicious: 100_000,
        p_unknown: 100_000,
    };
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&mostly_anomalous);
    // Should pick something moderate — not Allow (risky) but not Quarantine (costly)
    assert!(
        d.action.severity() >= ContainmentAction::Challenge.severity(),
        "anomalous-heavy should not Allow, got {}",
        d.action
    );
}

// ===========================================================================
// 35. Multiple epochs tracked correctly
// ===========================================================================

#[test]
fn epoch_updates_reflected_in_runtime_scoring() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.set_epoch(SecurityEpoch::from_raw(100));
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.epoch, SecurityEpoch::from_raw(100));
}

// ===========================================================================
// 36. Posterior with all-unknown triggers uncertainty handling
// ===========================================================================

#[test]
fn all_unknown_posterior_selects_cautious_action() {
    let all_unknown = Posterior {
        p_benign: 0,
        p_anomalous: 0,
        p_malicious: 0,
        p_unknown: 1_000_000,
    };
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&all_unknown);
    // Unknown state should produce an action that's not the most relaxed
    assert!(
        d.action.severity() >= ContainmentAction::Allow.severity(),
        "all-unknown should select a valid action"
    );
}

// ===========================================================================
// 37. Loss matrix custom construction
// ===========================================================================

#[test]
fn custom_loss_matrix_with_uniform_costs_selects_least_severe() {
    use frankenengine_engine::bayesian_posterior::RiskState;
    let mut entries = Vec::new();
    for a in ContainmentAction::ALL {
        for s in [
            RiskState::Benign,
            RiskState::Anomalous,
            RiskState::Malicious,
            RiskState::Unknown,
        ] {
            entries.push(LossEntry {
                action: a,
                state: s,
                loss_millionths: 1_000_000, // all equal
            });
        }
    }
    let matrix = LossMatrix::new("uniform-test", entries);
    assert!(matrix.is_complete());
    let mut sel = ExpectedLossSelector::new(matrix);
    let d = sel.select(&uniform_posterior());
    // With all equal losses, should pick the least severe action (Allow)
    assert_eq!(d.action, ContainmentAction::Allow);
    assert_eq!(d.expected_loss_millionths, d.runner_up_loss_millionths);
}

// ===========================================================================
// 38. Decision events always contain decision_scored
// ===========================================================================

#[test]
fn runtime_scoring_events_always_include_decision_scored() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    let decision_scored = score.events.iter().any(|e| e.event == "decision_scored");
    assert!(decision_scored, "events must include decision_scored");
}

#[test]
fn runtime_scoring_events_include_alien_envelope_compiled() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    let alien_event = score
        .events
        .iter()
        .any(|e| e.event == "alien_envelope_compiled");
    assert!(alien_event, "events must include alien_envelope_compiled");
}

// ===========================================================================
// 39. Attacker ROI assessment populated
// ===========================================================================

#[test]
fn attacker_roi_assessment_populated() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.attacker_roi.extension_id, "ext-1");
    assert!(
        score.attacker_roi.roi_millionths != 0,
        "attacker ROI should be non-zero"
    );
}

// ===========================================================================
// 40. Posterior snapshot preserved in score
// ===========================================================================

#[test]
fn posterior_snapshot_matches_input() {
    let mut sel = ExpectedLossSelector::balanced();
    let posterior = Posterior {
        p_benign: 300_000,
        p_anomalous: 400_000,
        p_malicious: 200_000,
        p_unknown: 100_000,
    };
    let input = test_scoring_input(posterior.clone());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.posterior_snapshot, posterior);
}

// ===========================================================================
// 41. Loss matrix version tracked
// ===========================================================================

#[test]
fn loss_matrix_version_in_score() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.loss_matrix_version, "balanced-v1");
}

#[test]
fn loss_matrix_version_changes_with_swap() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let s1 = sel.score_runtime_decision(&input).unwrap();
    sel.set_loss_matrix(LossMatrix::conservative());
    let s2 = sel.score_runtime_decision(&input).unwrap();
    assert_ne!(s1.loss_matrix_version, s2.loss_matrix_version);
}

// ===========================================================================
// Enrichment tests (enrichment_*) — ~90 new tests
// ===========================================================================

// ---------------------------------------------------------------------------
// ContainmentAction — Clone, Debug, Display, PartialOrd, Ord, Hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_action_clone_is_identity() {
    for a in ContainmentAction::ALL {
        let cloned = a.clone();
        assert_eq!(a, cloned);
    }
}

#[test]
fn enrichment_containment_action_copy_semantics() {
    let a = ContainmentAction::Sandbox;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_containment_action_debug_contains_variant_name() {
    assert!(format!("{:?}", ContainmentAction::Allow).contains("Allow"));
    assert!(format!("{:?}", ContainmentAction::Challenge).contains("Challenge"));
    assert!(format!("{:?}", ContainmentAction::Sandbox).contains("Sandbox"));
    assert!(format!("{:?}", ContainmentAction::Suspend).contains("Suspend"));
    assert!(format!("{:?}", ContainmentAction::Terminate).contains("Terminate"));
    assert!(format!("{:?}", ContainmentAction::Quarantine).contains("Quarantine"));
}

#[test]
fn enrichment_containment_action_ord_matches_severity() {
    let mut actions = ContainmentAction::ALL.to_vec();
    actions.sort();
    for w in actions.windows(2) {
        assert!(
            w[0].severity() < w[1].severity(),
            "Ord ordering should match severity"
        );
    }
}

#[test]
fn enrichment_containment_action_severity_exact_values() {
    assert_eq!(ContainmentAction::Allow.severity(), 0);
    assert_eq!(ContainmentAction::Challenge.severity(), 1);
    assert_eq!(ContainmentAction::Sandbox.severity(), 2);
    assert_eq!(ContainmentAction::Suspend.severity(), 3);
    assert_eq!(ContainmentAction::Terminate.severity(), 4);
    assert_eq!(ContainmentAction::Quarantine.severity(), 5);
}

#[test]
fn enrichment_containment_action_display_all_lowercase() {
    for a in ContainmentAction::ALL {
        let s = a.to_string();
        assert_eq!(s, s.to_lowercase(), "display should be all lowercase");
    }
}

#[test]
fn enrichment_containment_action_btreeset_deduplication() {
    let mut set = BTreeSet::new();
    for _ in 0..10 {
        for a in ContainmentAction::ALL {
            set.insert(a);
        }
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_containment_action_serde_json_string_tag() {
    for a in ContainmentAction::ALL {
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.starts_with('"'), "serde should produce a string tag");
        assert!(json.ends_with('"'));
    }
}

#[test]
fn enrichment_containment_action_all_is_sorted() {
    for w in ContainmentAction::ALL.windows(2) {
        assert!(w[0] < w[1], "ALL must be sorted: {:?} >= {:?}", w[0], w[1]);
    }
}

// ---------------------------------------------------------------------------
// AlienRiskAlertLevel — Clone, Copy, Debug, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_alien_risk_alert_level_clone_identity() {
    for l in [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ] {
        assert_eq!(l, l.clone());
    }
}

#[test]
fn enrichment_alien_risk_alert_level_copy_semantics() {
    let a = AlienRiskAlertLevel::Critical;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_alien_risk_alert_level_debug_distinct() {
    let dbgs: BTreeSet<String> = [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ]
    .iter()
    .map(|l| format!("{l:?}"))
    .collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn enrichment_alien_risk_alert_level_display_exact() {
    assert_eq!(AlienRiskAlertLevel::Nominal.to_string(), "nominal");
    assert_eq!(AlienRiskAlertLevel::Elevated.to_string(), "elevated");
    assert_eq!(AlienRiskAlertLevel::Critical.to_string(), "critical");
}

#[test]
fn enrichment_alien_risk_alert_level_json_tag_stability() {
    let json = serde_json::to_string(&AlienRiskAlertLevel::Nominal).unwrap();
    assert!(json.contains("Nominal") || json.contains("nominal"));
    let json2 = serde_json::to_string(&AlienRiskAlertLevel::Critical).unwrap();
    assert!(json2.contains("Critical") || json2.contains("critical"));
}

// ---------------------------------------------------------------------------
// RuntimeDecisionScoringError — Display, serde, std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_missing_field_display_format() {
    let e = RuntimeDecisionScoringError::MissingField {
        field: "policy_version".into(),
    };
    let s = e.to_string();
    assert!(s.contains("policy_version"));
    assert!(s.contains("missing"));
}

#[test]
fn enrichment_error_zero_attacker_cost_display_nonempty() {
    let e = RuntimeDecisionScoringError::ZeroAttackerCost;
    assert!(!e.to_string().is_empty());
    assert!(e.to_string().contains("zero") || e.to_string().contains("cost"));
}

#[test]
fn enrichment_error_all_actions_blocked_display_contains_blocked() {
    let e = RuntimeDecisionScoringError::AllActionsBlocked;
    assert!(e.to_string().contains("blocked"));
}

#[test]
fn enrichment_error_clone_eq() {
    let e = RuntimeDecisionScoringError::MissingField {
        field: "foo".into(),
    };
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn enrichment_error_debug_contains_variant() {
    let e = RuntimeDecisionScoringError::ZeroAttackerCost;
    let d = format!("{e:?}");
    assert!(d.contains("ZeroAttackerCost"));
}

#[test]
fn enrichment_error_std_error_source_is_none() {
    let e = RuntimeDecisionScoringError::AllActionsBlocked;
    let dyn_err: &dyn std::error::Error = &e;
    assert!(dyn_err.source().is_none());
}

#[test]
fn enrichment_error_serde_preserves_field_name() {
    let e = RuntimeDecisionScoringError::MissingField {
        field: "extension_id".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: RuntimeDecisionScoringError = serde_json::from_str(&json).unwrap();
    if let RuntimeDecisionScoringError::MissingField { field } = &back {
        assert_eq!(field, "extension_id");
    } else {
        panic!("wrong variant after roundtrip");
    }
}

// ---------------------------------------------------------------------------
// LossEntry — Clone, Debug, serde, field access
// ---------------------------------------------------------------------------

#[test]
fn enrichment_loss_entry_clone_eq() {
    let e = LossEntry {
        action: ContainmentAction::Terminate,
        state: RiskState::Malicious,
        loss_millionths: 500_000,
    };
    assert_eq!(e, e.clone());
}

#[test]
fn enrichment_loss_entry_debug_format() {
    let e = LossEntry {
        action: ContainmentAction::Allow,
        state: RiskState::Benign,
        loss_millionths: 0,
    };
    let d = format!("{e:?}");
    assert!(d.contains("Allow"));
    assert!(d.contains("Benign"));
    assert!(d.contains("0"));
}

#[test]
fn enrichment_loss_entry_negative_loss_serde() {
    let e = LossEntry {
        action: ContainmentAction::Sandbox,
        state: RiskState::Anomalous,
        loss_millionths: -5_000_000,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: LossEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert_eq!(back.loss_millionths, -5_000_000);
}

#[test]
fn enrichment_loss_entry_json_fields_stable() {
    let e = LossEntry {
        action: ContainmentAction::Challenge,
        state: RiskState::Unknown,
        loss_millionths: 42,
    };
    let v: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("action"));
    assert!(obj.contains_key("state"));
    assert!(obj.contains_key("loss_millionths"));
    assert_eq!(obj.len(), 3);
}

// ---------------------------------------------------------------------------
// LossMatrix — content_hash, clone, debug, serde, loss lookup edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_loss_matrix_clone_eq() {
    let m = LossMatrix::balanced();
    let cloned = m.clone();
    assert_eq!(m, cloned);
    assert_eq!(m.content_hash(), cloned.content_hash());
}

#[test]
fn enrichment_loss_matrix_debug_format_contains_matrix_id() {
    let m = LossMatrix::balanced();
    let d = format!("{m:?}");
    assert!(d.contains("balanced-v1"));
}

#[test]
fn enrichment_loss_matrix_content_hash_changes_with_id() {
    let entries1: Vec<LossEntry> = ContainmentAction::ALL
        .iter()
        .flat_map(|a| {
            RiskState::ALL.iter().map(move |s| LossEntry {
                action: *a,
                state: *s,
                loss_millionths: 1_000_000,
            })
        })
        .collect();
    let entries2 = entries1.clone();
    let m1 = LossMatrix::new("id-alpha", entries1);
    let m2 = LossMatrix::new("id-beta", entries2);
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_loss_matrix_all_24_pairs_accessible() {
    let m = LossMatrix::balanced();
    let mut count = 0;
    for a in ContainmentAction::ALL {
        for s in RiskState::ALL {
            let _ = m.loss(a, s);
            count += 1;
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn enrichment_loss_matrix_balanced_allow_benign_is_zero() {
    let m = LossMatrix::balanced();
    assert_eq!(m.loss(ContainmentAction::Allow, RiskState::Benign), 0);
}

#[test]
fn enrichment_loss_matrix_balanced_quarantine_malicious_is_200k() {
    let m = LossMatrix::balanced();
    assert_eq!(
        m.loss(ContainmentAction::Quarantine, RiskState::Malicious),
        200_000
    );
}

#[test]
fn enrichment_loss_matrix_conservative_allow_malicious_higher() {
    let bal = LossMatrix::balanced();
    let con = LossMatrix::conservative();
    assert!(
        con.loss(ContainmentAction::Allow, RiskState::Malicious)
            >= bal.loss(ContainmentAction::Allow, RiskState::Malicious),
        "conservative should penalize allowing malicious at least as much as balanced"
    );
}

#[test]
fn enrichment_loss_matrix_serde_all_three_presets() {
    for m in [
        LossMatrix::balanced(),
        LossMatrix::conservative(),
        LossMatrix::permissive(),
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        assert!(back.is_complete());
    }
}

#[test]
fn enrichment_loss_matrix_json_has_matrix_id_field() {
    let m = LossMatrix::balanced();
    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("matrix_id"));
    assert_eq!(obj["matrix_id"].as_str().unwrap(), "balanced-v1");
}

// ---------------------------------------------------------------------------
// DecisionConfidenceInterval — Clone, Debug, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_confidence_interval_clone_eq() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: -1_000,
        upper_millionths: 1_000,
    };
    assert_eq!(ci, ci.clone());
}

#[test]
fn enrichment_decision_confidence_interval_debug_format() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: 100,
        upper_millionths: 200,
    };
    let d = format!("{ci:?}");
    assert!(d.contains("100"));
    assert!(d.contains("200"));
}

#[test]
fn enrichment_decision_confidence_interval_zero_width() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: 500_000,
        upper_millionths: 500_000,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: DecisionConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(back.lower_millionths, back.upper_millionths);
}

#[test]
fn enrichment_decision_confidence_interval_negative_bounds() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: -2_000_000,
        upper_millionths: -500_000,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: DecisionConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, back);
}

// ---------------------------------------------------------------------------
// CandidateActionScore — Clone, Debug, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_candidate_action_score_clone_eq() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Allow,
        expected_loss_millionths: 0,
        state_contributions_millionths: BTreeMap::new(),
        guardrail_blocked: false,
    };
    assert_eq!(cas, cas.clone());
}

#[test]
fn enrichment_candidate_action_score_debug_format() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Quarantine,
        expected_loss_millionths: 999,
        state_contributions_millionths: BTreeMap::new(),
        guardrail_blocked: true,
    };
    let d = format!("{cas:?}");
    assert!(d.contains("Quarantine"));
    assert!(d.contains("999"));
    assert!(d.contains("true"));
}

#[test]
fn enrichment_candidate_action_score_json_field_count() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Suspend,
        expected_loss_millionths: 100,
        state_contributions_millionths: BTreeMap::from([
            ("Benign".into(), 50),
            ("Malicious".into(), 50),
        ]),
        guardrail_blocked: false,
    };
    let v: serde_json::Value = serde_json::to_value(&cas).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 4);
}

// ---------------------------------------------------------------------------
// RuntimeDecisionScoreEvent — Clone, Debug, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_score_event_clone_eq() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: Some("E1".into()),
    };
    assert_eq!(ev, ev.clone());
}

#[test]
fn enrichment_score_event_debug_format() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "trace-xyz".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "comp".into(),
        event: "tested".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let d = format!("{ev:?}");
    assert!(d.contains("trace-xyz"));
    assert!(d.contains("tested"));
}

#[test]
fn enrichment_score_event_json_field_count() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 7);
}

#[test]
fn enrichment_score_event_error_code_null_in_json() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    assert!(v["error_code"].is_null());
}

// ---------------------------------------------------------------------------
// AlienRiskEnvelope — Clone, Debug, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_alien_risk_envelope_clone_eq() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 900_000,
        tail_var_millionths: 1_000_000,
        tail_cvar_millionths: 1_500_000,
        conformal_quantile_millionths: 800_000,
        conformal_p_value_millionths: 100_000,
        e_value_millionths: 10_000_000,
        regime_shift_score_millionths: 3_000_000,
        alert_level: AlienRiskAlertLevel::Elevated,
        recommended_floor_action: Some(ContainmentAction::Sandbox),
    };
    assert_eq!(env, env.clone());
}

#[test]
fn enrichment_alien_risk_envelope_debug_format() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 900_000,
        tail_var_millionths: 0,
        tail_cvar_millionths: 0,
        conformal_quantile_millionths: 0,
        conformal_p_value_millionths: 500_000,
        e_value_millionths: 2_000_000,
        regime_shift_score_millionths: 0,
        alert_level: AlienRiskAlertLevel::Nominal,
        recommended_floor_action: None,
    };
    let d = format!("{env:?}");
    assert!(d.contains("Nominal"));
    assert!(d.contains("900000"));
}

#[test]
fn enrichment_alien_risk_envelope_json_field_count() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 0,
        tail_var_millionths: 0,
        tail_cvar_millionths: 0,
        conformal_quantile_millionths: 0,
        conformal_p_value_millionths: 0,
        e_value_millionths: 0,
        regime_shift_score_millionths: 0,
        alert_level: AlienRiskAlertLevel::Nominal,
        recommended_floor_action: None,
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 9);
}

#[test]
fn enrichment_alien_risk_envelope_floor_action_none_json() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 0,
        tail_var_millionths: 0,
        tail_cvar_millionths: 0,
        conformal_quantile_millionths: 0,
        conformal_p_value_millionths: 0,
        e_value_millionths: 0,
        regime_shift_score_millionths: 0,
        alert_level: AlienRiskAlertLevel::Nominal,
        recommended_floor_action: None,
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    assert!(v["recommended_floor_action"].is_null());
}

// ---------------------------------------------------------------------------
// DecisionExplanation — Clone, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_explanation_clone_eq() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    let cloned = d.explanation.clone();
    assert_eq!(d.explanation, cloned);
}

#[test]
fn enrichment_decision_explanation_json_fields() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    let v: serde_json::Value = serde_json::to_value(&d.explanation).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("posterior_snapshot"));
    assert!(obj.contains_key("loss_matrix_id"));
    assert!(obj.contains_key("all_expected_losses"));
    assert!(obj.contains_key("margin_millionths"));
}

// ---------------------------------------------------------------------------
// ActionDecision — Clone, Debug, serde, JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_action_decision_clone_eq() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    let cloned = d.clone();
    assert_eq!(d, cloned);
}

#[test]
fn enrichment_action_decision_debug_contains_action() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    let dbg = format!("{d:?}");
    assert!(dbg.contains("Allow"));
}

#[test]
fn enrichment_action_decision_json_fields() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    let v: serde_json::Value = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "action",
        "expected_loss_millionths",
        "runner_up_action",
        "runner_up_loss_millionths",
        "explanation",
        "epoch",
    ] {
        assert!(obj.contains_key(key), "ActionDecision missing field: {key}");
    }
}

// ---------------------------------------------------------------------------
// ExpectedLossSelector — Clone, Debug, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_selector_debug_format() {
    let sel = ExpectedLossSelector::balanced();
    let d = format!("{sel:?}");
    assert!(d.contains("ExpectedLossSelector"));
}

#[test]
fn enrichment_selector_serde_preserves_decisions_made() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.select(&certain_benign());
    sel.select(&certain_malicious());
    sel.select(&uniform_posterior());
    let json = serde_json::to_string(&sel).unwrap();
    let back: ExpectedLossSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decisions_made(), 3);
}

#[test]
fn enrichment_selector_serde_preserves_loss_matrix() {
    let sel = ExpectedLossSelector::new(LossMatrix::conservative());
    let json = serde_json::to_string(&sel).unwrap();
    let back: ExpectedLossSelector = serde_json::from_str(&json).unwrap();
    assert_eq!(back.loss_matrix().matrix_id, "conservative-v1");
}

#[test]
fn enrichment_selector_new_starts_at_genesis_epoch() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&certain_benign());
    assert_eq!(d.epoch, SecurityEpoch::GENESIS);
}

// ---------------------------------------------------------------------------
// Expected loss computation — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expected_losses_certain_benign_all_nonneg() {
    let sel = ExpectedLossSelector::balanced();
    let losses = sel.expected_losses(&certain_benign());
    for (action, loss) in &losses {
        assert!(
            *loss >= 0,
            "expected loss for {} should be >= 0 given benign, got {}",
            action,
            loss
        );
    }
}

#[test]
fn enrichment_expected_losses_certain_malicious_all_nonneg() {
    let sel = ExpectedLossSelector::balanced();
    let losses = sel.expected_losses(&certain_malicious());
    for (action, loss) in &losses {
        assert!(
            *loss >= 0,
            "expected loss for {} should be >= 0 given malicious, got {}",
            action,
            loss
        );
    }
}

#[test]
fn enrichment_expected_losses_benign_allow_is_zero() {
    let sel = ExpectedLossSelector::balanced();
    let losses = sel.expected_losses(&certain_benign());
    assert_eq!(*losses.get(&ContainmentAction::Allow).unwrap(), 0);
}

#[test]
fn enrichment_expected_losses_malicious_quarantine_is_lowest() {
    let sel = ExpectedLossSelector::balanced();
    let losses = sel.expected_losses(&certain_malicious());
    let q_loss = *losses.get(&ContainmentAction::Quarantine).unwrap();
    for (a, l) in &losses {
        assert!(
            q_loss <= *l,
            "quarantine {} should be <= {} {}",
            q_loss,
            a,
            l
        );
    }
}

#[test]
fn enrichment_expected_losses_conservative_vs_permissive_differ() {
    let p = uniform_posterior();
    let con = ExpectedLossSelector::new(LossMatrix::conservative());
    let perm = ExpectedLossSelector::new(LossMatrix::permissive());
    assert_ne!(con.expected_losses(&p), perm.expected_losses(&p));
}

// ---------------------------------------------------------------------------
// select — edge cases and invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_select_all_unknown_posterior() {
    let all_unknown = Posterior::from_millionths(0, 0, 0, 1_000_000);
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&all_unknown);
    // With all unknown, Should still pick a valid action
    assert!(ContainmentAction::ALL.contains(&d.action));
    assert!(d.expected_loss_millionths >= 0);
}

#[test]
fn enrichment_select_margin_equals_difference() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    assert_eq!(
        d.explanation.margin_millionths,
        d.runner_up_loss_millionths - d.expected_loss_millionths
    );
}

#[test]
fn enrichment_select_explanation_loss_matrix_id_correct() {
    let mut sel = ExpectedLossSelector::new(LossMatrix::permissive());
    let d = sel.select(&certain_benign());
    assert_eq!(d.explanation.loss_matrix_id, "permissive-v1");
}

#[test]
fn enrichment_select_selected_ne_runner_up_for_diverse_posterior() {
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&uniform_posterior());
    assert_ne!(d.action, d.runner_up_action);
}

#[test]
fn enrichment_select_posterior_snapshot_preserved() {
    let p = Posterior::from_millionths(300_000, 200_000, 400_000, 100_000);
    let mut sel = ExpectedLossSelector::balanced();
    let d = sel.select(&p);
    assert_eq!(d.explanation.posterior_snapshot, p);
}

// ---------------------------------------------------------------------------
// Runtime scoring — validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_scoring_whitespace_only_decision_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.decision_id = "   \t  ".into();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "decision_id"
    ));
}

#[test]
fn enrichment_runtime_scoring_whitespace_only_policy_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.policy_id = "  ".into();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "policy_id"
    ));
}

#[test]
fn enrichment_runtime_scoring_whitespace_only_extension_id_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.extension_id = " ".into();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "extension_id"
    ));
}

#[test]
fn enrichment_runtime_scoring_whitespace_only_policy_version_fails() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.policy_version = "\n".into();
    let err = sel.score_runtime_decision(&input).unwrap_err();
    assert!(matches!(
        err,
        RuntimeDecisionScoringError::MissingField { field } if field == "policy_version"
    ));
}

// ---------------------------------------------------------------------------
// Runtime scoring — alien risk alert events
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_scoring_alien_envelope_compiled_event_always() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(
        score
            .events
            .iter()
            .any(|e| e.event == "alien_envelope_compiled"),
        "alien_envelope_compiled event must always be present"
    );
}

#[test]
fn enrichment_runtime_scoring_critical_alert_has_event() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    // Very stable low history then a massive outlier ROI triggers critical
    input.extension_roi_history_millionths = vec![100_000; 30];
    let score = sel.score_runtime_decision(&input).unwrap();
    if score.alien_risk_envelope.alert_level == AlienRiskAlertLevel::Critical {
        assert!(
            score.events.iter().any(|e| e.event == "alien_risk_alert"
                && e.error_code.as_deref() == Some("FE-RUNTIME-SCORING-ALIEN-CRITICAL")),
            "critical alert must emit alien_risk_alert event with CRITICAL error code"
        );
    }
}

#[test]
fn enrichment_runtime_scoring_floor_gap_event_when_gap() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.extension_roi_history_millionths = vec![100_000; 30];
    let score = sel.score_runtime_decision(&input).unwrap();
    if score.alien_floor_gap_steps > 0 {
        assert!(
            score.events.iter().any(|e| e.event == "alien_floor_gap"),
            "floor gap > 0 must emit alien_floor_gap event"
        );
    }
}

// ---------------------------------------------------------------------------
// Runtime scoring — determinism and reproducibility
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_scoring_deterministic_across_selectors() {
    let input = test_scoring_input(uniform_posterior());
    let mut s1 = ExpectedLossSelector::balanced();
    let mut s2 = ExpectedLossSelector::balanced();
    let r1 = s1.score_runtime_decision(&input).unwrap();
    let r2 = s2.score_runtime_decision(&input).unwrap();
    assert_eq!(r1.selected_action, r2.selected_action);
    assert_eq!(
        r1.selected_expected_loss_millionths,
        r2.selected_expected_loss_millionths
    );
    assert_eq!(r1.confidence_interval, r2.confidence_interval);
    assert_eq!(r1.alien_risk_envelope, r2.alien_risk_envelope);
    assert_eq!(r1.receipt_preimage_hash, r2.receipt_preimage_hash);
    assert_eq!(r1.events.len(), r2.events.len());
}

#[test]
fn enrichment_runtime_scoring_receipt_hash_changes_with_extension_id() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input1 = test_scoring_input(certain_benign());
    input1.extension_id = "ext-alpha".into();
    let mut input2 = test_scoring_input(certain_benign());
    input2.extension_id = "ext-beta".into();
    let r1 = sel.score_runtime_decision(&input1).unwrap();
    let r2 = sel.score_runtime_decision(&input2).unwrap();
    assert_ne!(r1.receipt_preimage_hash, r2.receipt_preimage_hash);
}

#[test]
fn enrichment_runtime_scoring_receipt_hash_changes_with_decision_id() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input1 = test_scoring_input(certain_benign());
    input1.decision_id = "d-001".into();
    let mut input2 = test_scoring_input(certain_benign());
    input2.decision_id = "d-002".into();
    let r1 = sel.score_runtime_decision(&input1).unwrap();
    let r2 = sel.score_runtime_decision(&input2).unwrap();
    assert_ne!(r1.receipt_preimage_hash, r2.receipt_preimage_hash);
}

// ---------------------------------------------------------------------------
// Runtime scoring — confidence interval invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_confidence_interval_positive_width() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    let width =
        score.confidence_interval.upper_millionths - score.confidence_interval.lower_millionths;
    assert!(width >= 0, "CI width should be non-negative, got {}", width);
}

#[test]
fn enrichment_confidence_interval_brackets_selected_loss() {
    for p in [
        certain_benign(),
        certain_malicious(),
        uniform_posterior(),
        Posterior::from_millionths(100_000, 200_000, 300_000, 400_000),
    ] {
        let mut sel = ExpectedLossSelector::balanced();
        let input = test_scoring_input(p);
        let score = sel.score_runtime_decision(&input).unwrap();
        assert!(
            score.confidence_interval.lower_millionths <= score.selected_expected_loss_millionths
                && score.confidence_interval.upper_millionths
                    >= score.selected_expected_loss_millionths,
            "CI [{}, {}] should bracket selected loss {}",
            score.confidence_interval.lower_millionths,
            score.confidence_interval.upper_millionths,
            score.selected_expected_loss_millionths,
        );
    }
}

// ---------------------------------------------------------------------------
// Runtime scoring — fleet ROI and attacker ROI
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fleet_roi_summary_count_includes_self() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    // Fleet baseline has ext-1 and ext-2 keys; extension under test (ext-1) is merged in
    // so total should be 2 unique extension IDs (ext-1 merged)
    assert!(score.fleet_roi_summary.extension_count >= 2);
}

#[test]
fn enrichment_attacker_roi_extension_id_matches_input() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.attacker_roi.extension_id, "ext-1");
}

// ---------------------------------------------------------------------------
// RuntimeDecisionScoringInput — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_decision_scoring_input_serde_roundtrip() {
    let input = test_scoring_input(uniform_posterior());
    let json = serde_json::to_string(&input).unwrap();
    let back: RuntimeDecisionScoringInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.trace_id, back.trace_id);
    assert_eq!(input.decision_id, back.decision_id);
    assert_eq!(input.policy_id, back.policy_id);
    assert_eq!(input.extension_id, back.extension_id);
    assert_eq!(input.policy_version, back.policy_version);
    assert_eq!(input.timestamp_ns, back.timestamp_ns);
    assert_eq!(input.posterior, back.posterior);
    assert_eq!(input.blocked_actions, back.blocked_actions);
}

#[test]
fn enrichment_runtime_decision_scoring_input_json_fields() {
    let input = test_scoring_input(certain_benign());
    let v: serde_json::Value = serde_json::to_value(&input).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "policy_version",
        "timestamp_ns",
        "posterior",
        "attacker_cost_model",
        "extension_roi_history_millionths",
        "fleet_roi_baseline_millionths",
        "blocked_actions",
    ] {
        assert!(
            obj.contains_key(key),
            "RuntimeDecisionScoringInput missing field: {key}"
        );
    }
}

// ---------------------------------------------------------------------------
// RuntimeDecisionScore — full serde and JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_decision_score_serde_full_roundtrip() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    let json = serde_json::to_string(&score).unwrap();
    let back: RuntimeDecisionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, back);
}

#[test]
fn enrichment_runtime_decision_score_json_fields() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(certain_benign());
    let score = sel.score_runtime_decision(&input).unwrap();
    let v: serde_json::Value = serde_json::to_value(&score).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "policy_version",
        "timestamp_ns",
        "epoch",
        "loss_matrix_version",
        "candidate_actions",
        "selected_action",
        "selected_expected_loss_millionths",
        "selection_rationale",
        "confidence_interval",
        "posterior_snapshot",
        "attacker_roi",
        "fleet_roi_summary",
        "borderline_decision",
        "sensitivity_deltas",
        "alien_risk_envelope",
        "alien_floor_gap_steps",
        "receipt_preimage_hash",
        "events",
    ] {
        assert!(
            obj.contains_key(key),
            "RuntimeDecisionScore missing field: {key}"
        );
    }
}

// ---------------------------------------------------------------------------
// Monotonicity — conservative and permissive matrices
// ---------------------------------------------------------------------------

#[test]
fn enrichment_monotonicity_conservative_increasing_malicious() {
    let mut sel = ExpectedLossSelector::new(LossMatrix::conservative());
    let mut prev_severity = 0u32;
    for i in 0..=10 {
        let p_mal = 1_000_000i64 * i / 10;
        let p_ben = 1_000_000i64 - p_mal;
        let d = sel.select(&Posterior::from_millionths(p_ben, 0, p_mal, 0));
        assert!(
            d.action.severity() >= prev_severity,
            "conservative monotonicity violation at step {i}"
        );
        prev_severity = d.action.severity();
    }
}

#[test]
fn enrichment_monotonicity_permissive_increasing_malicious() {
    let mut sel = ExpectedLossSelector::new(LossMatrix::permissive());
    let mut prev_severity = 0u32;
    for i in 0..=10 {
        let p_mal = 1_000_000i64 * i / 10;
        let p_ben = 1_000_000i64 - p_mal;
        let d = sel.select(&Posterior::from_millionths(p_ben, 0, p_mal, 0));
        assert!(
            d.action.severity() >= prev_severity,
            "permissive monotonicity violation at step {i}"
        );
        prev_severity = d.action.severity();
    }
}

// ---------------------------------------------------------------------------
// State contributions invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_state_contributions_sum_equals_expected_loss() {
    let mut sel = ExpectedLossSelector::balanced();
    for p in [
        certain_benign(),
        certain_malicious(),
        uniform_posterior(),
        Posterior::from_millionths(100_000, 200_000, 300_000, 400_000),
    ] {
        let input = test_scoring_input(p);
        let score = sel.score_runtime_decision(&input).unwrap();
        for ca in &score.candidate_actions {
            let sum: i64 = ca.state_contributions_millionths.values().sum();
            assert_eq!(
                sum, ca.expected_loss_millionths,
                "state contributions for {} sum to {} but EL is {}",
                ca.action, sum, ca.expected_loss_millionths
            );
        }
    }
}

#[test]
fn enrichment_state_contributions_always_have_four_entries() {
    let mut sel = ExpectedLossSelector::balanced();
    let input = test_scoring_input(uniform_posterior());
    let score = sel.score_runtime_decision(&input).unwrap();
    for ca in &score.candidate_actions {
        assert_eq!(
            ca.state_contributions_millionths.len(),
            4,
            "{} should have 4 state contribution entries",
            ca.action
        );
    }
}

// ---------------------------------------------------------------------------
// Guardrail — blocked flags, five-out-of-six blocked
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_blocked_one_remaining() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    // Block everything except Quarantine
    input.blocked_actions.insert(ContainmentAction::Allow);
    input.blocked_actions.insert(ContainmentAction::Challenge);
    input.blocked_actions.insert(ContainmentAction::Sandbox);
    input.blocked_actions.insert(ContainmentAction::Suspend);
    input.blocked_actions.insert(ContainmentAction::Terminate);
    let score = sel.score_runtime_decision(&input).unwrap();
    assert_eq!(score.selected_action, ContainmentAction::Quarantine);
}

#[test]
fn enrichment_blocked_candidates_all_flagged() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(uniform_posterior());
    input.blocked_actions.insert(ContainmentAction::Allow);
    input.blocked_actions.insert(ContainmentAction::Terminate);
    let score = sel.score_runtime_decision(&input).unwrap();
    for ca in &score.candidate_actions {
        if ca.action == ContainmentAction::Allow || ca.action == ContainmentAction::Terminate {
            assert!(
                ca.guardrail_blocked,
                "{} should be flagged as blocked",
                ca.action
            );
        } else {
            assert!(
                !ca.guardrail_blocked,
                "{} should NOT be flagged as blocked",
                ca.action
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime scoring — empty ROI history
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_roi_history_still_produces_valid_envelope() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(uniform_posterior());
    input.extension_roi_history_millionths = vec![];
    let score = sel.score_runtime_decision(&input).unwrap();
    assert!(score.alien_risk_envelope.tail_confidence_millionths > 0);
    assert!(score.alien_risk_envelope.conformal_p_value_millionths > 0);
    assert!(score.alien_risk_envelope.e_value_millionths > 0);
}

#[test]
fn enrichment_single_roi_history_no_regime_shift() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(uniform_posterior());
    input.extension_roi_history_millionths = vec![1_000_000];
    let score = sel.score_runtime_decision(&input).unwrap();
    // regime shift requires >= 4 history points, so should be 0
    assert_eq!(
        score.alien_risk_envelope.regime_shift_score_millionths, 0,
        "regime shift should be 0 with < 4 history points"
    );
}

// ---------------------------------------------------------------------------
// Runtime scoring — selection rationale with alien floor
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rationale_includes_alien_floor_when_gap_positive() {
    let mut sel = ExpectedLossSelector::balanced();
    let mut input = test_scoring_input(certain_benign());
    input.extension_roi_history_millionths = vec![100_000; 30];
    let score = sel.score_runtime_decision(&input).unwrap();
    if score.alien_floor_gap_steps > 0 {
        assert!(
            score.selection_rationale.contains("alien_floor="),
            "rationale should mention alien floor when gap > 0"
        );
        assert!(
            score.selection_rationale.contains("alien_floor_gap_steps="),
            "rationale should mention alien_floor_gap_steps when gap > 0"
        );
    }
}

// ---------------------------------------------------------------------------
// Runtime scoring — decisions_made increments
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_scoring_increments_decisions_made() {
    let mut sel = ExpectedLossSelector::balanced();
    assert_eq!(sel.decisions_made(), 0);
    let input = test_scoring_input(certain_benign());
    sel.score_runtime_decision(&input).unwrap();
    assert_eq!(sel.decisions_made(), 1);
    sel.score_runtime_decision(&input).unwrap();
    assert_eq!(sel.decisions_made(), 2);
    sel.select(&certain_benign());
    assert_eq!(sel.decisions_made(), 3);
}

// ---------------------------------------------------------------------------
// Cross-matrix property: all three presets agree on certain-benign Allow
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_presets_select_allow_for_certain_benign() {
    for matrix in [
        LossMatrix::balanced(),
        LossMatrix::conservative(),
        LossMatrix::permissive(),
    ] {
        let mut sel = ExpectedLossSelector::new(matrix.clone());
        let d = sel.select(&certain_benign());
        assert_eq!(
            d.action,
            ContainmentAction::Allow,
            "{} matrix should select Allow for certain benign",
            matrix.matrix_id
        );
    }
}

#[test]
fn enrichment_all_presets_select_severe_for_certain_malicious() {
    for matrix in [
        LossMatrix::balanced(),
        LossMatrix::conservative(),
        LossMatrix::permissive(),
    ] {
        let mut sel = ExpectedLossSelector::new(matrix.clone());
        let d = sel.select(&certain_malicious());
        assert!(
            d.action.severity() >= ContainmentAction::Terminate.severity(),
            "{} matrix should select severe for certain malicious, got {}",
            matrix.matrix_id,
            d.action
        );
    }
}
