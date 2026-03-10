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
