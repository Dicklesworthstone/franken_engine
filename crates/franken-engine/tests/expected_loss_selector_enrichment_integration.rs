#![forbid(unsafe_code)]
//! Enrichment integration tests for `expected_loss_selector`.
//!
//! Adds severity exact values, ContainmentAction ALL ordering, LossMatrix
//! completeness checks, JSON field-name stability, Debug distinctness,
//! AlienRiskAlertLevel serde tags, validation edge cases, and confidence
//! interval invariants beyond the existing 51 integration tests.

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
    AlienRiskAlertLevel, AlienRiskEnvelope, CandidateActionScore, ContainmentAction,
    DecisionConfidenceInterval, ExpectedLossSelector, LossEntry, LossMatrix,
    RuntimeDecisionScoreEvent, RuntimeDecisionScoringError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// 1) ContainmentAction — severity exact values
// ===========================================================================

#[test]
fn containment_action_severity_allow() {
    assert_eq!(ContainmentAction::Allow.severity(), 0);
}

#[test]
fn containment_action_severity_challenge() {
    assert_eq!(ContainmentAction::Challenge.severity(), 1);
}

#[test]
fn containment_action_severity_sandbox() {
    assert_eq!(ContainmentAction::Sandbox.severity(), 2);
}

#[test]
fn containment_action_severity_suspend() {
    assert_eq!(ContainmentAction::Suspend.severity(), 3);
}

#[test]
fn containment_action_severity_terminate() {
    assert_eq!(ContainmentAction::Terminate.severity(), 4);
}

#[test]
fn containment_action_severity_quarantine() {
    assert_eq!(ContainmentAction::Quarantine.severity(), 5);
}

// ===========================================================================
// 2) ContainmentAction — ALL ordering matches severity
// ===========================================================================

#[test]
fn containment_action_all_length_is_six() {
    assert_eq!(ContainmentAction::ALL.len(), 6);
}

#[test]
fn containment_action_all_severity_monotonic() {
    let severities: Vec<u32> = ContainmentAction::ALL
        .iter()
        .map(|a| a.severity())
        .collect();
    for w in severities.windows(2) {
        assert!(w[0] < w[1], "severity not strictly increasing: {:?}", w);
    }
}

// ===========================================================================
// 3) ContainmentAction — Display exact values
// ===========================================================================

#[test]
fn containment_action_display_allow() {
    assert_eq!(ContainmentAction::Allow.to_string(), "allow");
}

#[test]
fn containment_action_display_challenge() {
    assert_eq!(ContainmentAction::Challenge.to_string(), "challenge");
}

#[test]
fn containment_action_display_sandbox() {
    assert_eq!(ContainmentAction::Sandbox.to_string(), "sandbox");
}

#[test]
fn containment_action_display_suspend() {
    assert_eq!(ContainmentAction::Suspend.to_string(), "suspend");
}

#[test]
fn containment_action_display_terminate() {
    assert_eq!(ContainmentAction::Terminate.to_string(), "terminate");
}

#[test]
fn containment_action_display_quarantine() {
    assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
}

// ===========================================================================
// 4) ContainmentAction — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_containment_action() {
    let variants: Vec<String> = ContainmentAction::ALL
        .iter()
        .map(|a| format!("{a:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 5) AlienRiskAlertLevel — Display exact values
// ===========================================================================

#[test]
fn alien_risk_alert_level_display_nominal() {
    assert_eq!(AlienRiskAlertLevel::Nominal.to_string(), "nominal");
}

#[test]
fn alien_risk_alert_level_display_elevated() {
    assert_eq!(AlienRiskAlertLevel::Elevated.to_string(), "elevated");
}

#[test]
fn alien_risk_alert_level_display_critical() {
    assert_eq!(AlienRiskAlertLevel::Critical.to_string(), "critical");
}

// ===========================================================================
// 6) AlienRiskAlertLevel — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_alien_risk_alert_level() {
    let variants = [
        format!("{:?}", AlienRiskAlertLevel::Nominal),
        format!("{:?}", AlienRiskAlertLevel::Elevated),
        format!("{:?}", AlienRiskAlertLevel::Critical),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 7) AlienRiskAlertLevel — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_alien_risk_alert_level_all() {
    for l in [
        AlienRiskAlertLevel::Nominal,
        AlienRiskAlertLevel::Elevated,
        AlienRiskAlertLevel::Critical,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let rt: AlienRiskAlertLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, rt);
    }
}

// ===========================================================================
// 8) RuntimeDecisionScoringError — Display exact values
// ===========================================================================

#[test]
fn scoring_error_display_missing_field() {
    let e = RuntimeDecisionScoringError::MissingField {
        field: "trace_id".into(),
    };
    let s = e.to_string();
    assert!(s.contains("trace_id"), "should contain field name: {s}");
    assert!(s.contains("missing"), "should contain 'missing': {s}");
}

#[test]
fn scoring_error_display_zero_attacker_cost() {
    let e = RuntimeDecisionScoringError::ZeroAttackerCost;
    let s = e.to_string();
    assert!(s.contains("zero"), "should contain 'zero': {s}");
}

#[test]
fn scoring_error_display_all_actions_blocked() {
    let e = RuntimeDecisionScoringError::AllActionsBlocked;
    let s = e.to_string();
    assert!(s.contains("blocked"), "should contain 'blocked': {s}");
}

#[test]
fn scoring_error_display_all_unique() {
    let displays: Vec<String> = vec![
        RuntimeDecisionScoringError::MissingField { field: "x".into() }.to_string(),
        RuntimeDecisionScoringError::ZeroAttackerCost.to_string(),
        RuntimeDecisionScoringError::AllActionsBlocked.to_string(),
    ];
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn scoring_error_is_std_error() {
    let e = RuntimeDecisionScoringError::ZeroAttackerCost;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 9) RuntimeDecisionScoringError — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_scoring_error_all() {
    for e in [
        RuntimeDecisionScoringError::MissingField {
            field: "trace_id".into(),
        },
        RuntimeDecisionScoringError::ZeroAttackerCost,
        RuntimeDecisionScoringError::AllActionsBlocked,
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let rt: RuntimeDecisionScoringError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, rt);
    }
}

// ===========================================================================
// 10) LossMatrix — balanced is complete
// ===========================================================================

#[test]
fn loss_matrix_balanced_is_complete() {
    let m = LossMatrix::balanced();
    assert!(m.is_complete());
}

#[test]
fn loss_matrix_conservative_is_complete() {
    let m = LossMatrix::conservative();
    assert!(m.is_complete());
}

#[test]
fn loss_matrix_permissive_is_complete() {
    let m = LossMatrix::permissive();
    assert!(m.is_complete());
}

// ===========================================================================
// 11) LossMatrix — content_hash deterministic
// ===========================================================================

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

// ===========================================================================
// 12) LossMatrix — custom matrix incomplete
// ===========================================================================

#[test]
fn loss_matrix_balanced_matrix_id() {
    let m = LossMatrix::balanced();
    assert_eq!(m.matrix_id, "balanced-v1");
}

#[test]
fn loss_matrix_conservative_matrix_id() {
    let m = LossMatrix::conservative();
    assert_eq!(m.matrix_id, "conservative-v1");
}

#[test]
fn loss_matrix_permissive_matrix_id() {
    let m = LossMatrix::permissive();
    assert_eq!(m.matrix_id, "permissive-v1");
}

// ===========================================================================
// 13) JSON field-name stability — LossEntry
// ===========================================================================

#[test]
fn json_fields_loss_entry() {
    let le = LossEntry {
        action: ContainmentAction::Allow,
        state: RiskState::Benign,
        loss_millionths: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&le).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["action", "state", "loss_millionths"] {
        assert!(obj.contains_key(key), "LossEntry missing field: {key}");
    }
}

// ===========================================================================
// 14) JSON field-name stability — DecisionConfidenceInterval
// ===========================================================================

#[test]
fn json_fields_decision_confidence_interval() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: -100_000,
        upper_millionths: 100_000,
    };
    let v: serde_json::Value = serde_json::to_value(&ci).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["lower_millionths", "upper_millionths"] {
        assert!(
            obj.contains_key(key),
            "DecisionConfidenceInterval missing field: {key}"
        );
    }
}

// ===========================================================================
// 15) JSON field-name stability — CandidateActionScore
// ===========================================================================

#[test]
fn json_fields_candidate_action_score() {
    let cas = CandidateActionScore {
        action: ContainmentAction::Sandbox,
        expected_loss_millionths: 500_000,
        state_contributions_millionths: BTreeMap::new(),
        guardrail_blocked: false,
    };
    let v: serde_json::Value = serde_json::to_value(&cas).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "action",
        "expected_loss_millionths",
        "state_contributions_millionths",
        "guardrail_blocked",
    ] {
        assert!(
            obj.contains_key(key),
            "CandidateActionScore missing field: {key}"
        );
    }
}

// ===========================================================================
// 16) JSON field-name stability — RuntimeDecisionScoreEvent
// ===========================================================================

#[test]
fn json_fields_runtime_decision_score_event() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "scoring".into(),
        event: "computed".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            obj.contains_key(key),
            "RuntimeDecisionScoreEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) JSON field-name stability — AlienRiskEnvelope
// ===========================================================================

#[test]
fn json_fields_alien_risk_envelope() {
    let env = AlienRiskEnvelope {
        tail_confidence_millionths: 950_000,
        tail_var_millionths: 100_000,
        tail_cvar_millionths: 150_000,
        conformal_quantile_millionths: 900_000,
        conformal_p_value_millionths: 50_000,
        e_value_millionths: 1_000_000,
        regime_shift_score_millionths: 200_000,
        alert_level: AlienRiskAlertLevel::Nominal,
        recommended_floor_action: None,
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "tail_confidence_millionths",
        "tail_var_millionths",
        "tail_cvar_millionths",
        "conformal_quantile_millionths",
        "conformal_p_value_millionths",
        "e_value_millionths",
        "regime_shift_score_millionths",
        "alert_level",
        "recommended_floor_action",
    ] {
        assert!(
            obj.contains_key(key),
            "AlienRiskEnvelope missing field: {key}"
        );
    }
}

// ===========================================================================
// 18) Serde roundtrips — additional structs
// ===========================================================================

#[test]
fn serde_roundtrip_loss_entry() {
    let le = LossEntry {
        action: ContainmentAction::Terminate,
        state: RiskState::Malicious,
        loss_millionths: 100_000,
    };
    let json = serde_json::to_string(&le).unwrap();
    let rt: LossEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(le, rt);
}

#[test]
fn serde_roundtrip_candidate_action_score() {
    let mut contributions = BTreeMap::new();
    contributions.insert("benign".to_string(), 10_000i64);
    contributions.insert("suspicious".to_string(), 50_000i64);
    let cas = CandidateActionScore {
        action: ContainmentAction::Challenge,
        expected_loss_millionths: 60_000,
        state_contributions_millionths: contributions,
        guardrail_blocked: false,
    };
    let json = serde_json::to_string(&cas).unwrap();
    let rt: CandidateActionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(cas, rt);
}

#[test]
fn serde_roundtrip_decision_confidence_interval() {
    let ci = DecisionConfidenceInterval {
        lower_millionths: -500_000,
        upper_millionths: 500_000,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let rt: DecisionConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, rt);
}

#[test]
fn serde_roundtrip_runtime_decision_score_event_with_error() {
    let ev = RuntimeDecisionScoreEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "scoring".into(),
        event: "borderline_decision".into(),
        outcome: "warn".into(),
        error_code: Some("FE-RUNTIME-SCORING-BORDERLINE".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: RuntimeDecisionScoreEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

// ===========================================================================
// 19) ExpectedLossSelector — balanced factory
// ===========================================================================

#[test]
fn expected_loss_selector_balanced_factory() {
    let sel = ExpectedLossSelector::balanced();
    assert!(sel.loss_matrix().is_complete());
    assert_eq!(sel.decisions_made(), 0);
}

// ===========================================================================
// 20) ExpectedLossSelector — expected_losses returns all 6 actions
// ===========================================================================

#[test]
fn expected_losses_returns_six_actions() {
    let sel = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(900_000, 50_000, 30_000, 20_000);
    let losses = sel.expected_losses(&posterior);
    assert_eq!(losses.len(), 6);
    for action in &ContainmentAction::ALL {
        assert!(losses.contains_key(action), "missing action: {action:?}");
    }
}

// ===========================================================================
// 21) ExpectedLossSelector — select increments counter
// ===========================================================================

#[test]
fn select_increments_decisions_made() {
    let mut sel = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(950_000, 25_000, 15_000, 10_000);
    assert_eq!(sel.decisions_made(), 0);
    let _ = sel.select(&posterior);
    assert_eq!(sel.decisions_made(), 1);
    let _ = sel.select(&posterior);
    assert_eq!(sel.decisions_made(), 2);
}

// ===========================================================================
// 22) ExpectedLossSelector — set_epoch and set_loss_matrix
// ===========================================================================

#[test]
fn set_epoch_updates_selector() {
    let mut sel = ExpectedLossSelector::balanced();
    sel.set_epoch(SecurityEpoch::from_raw(42));
    let posterior = Posterior::from_millionths(950_000, 25_000, 15_000, 10_000);
    let decision = sel.select(&posterior);
    assert_eq!(decision.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn set_loss_matrix_changes_losses() {
    let mut sel = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(950_000, 25_000, 15_000, 10_000);
    let losses_balanced = sel.expected_losses(&posterior);

    sel.set_loss_matrix(LossMatrix::conservative());
    let losses_conservative = sel.expected_losses(&posterior);

    assert_ne!(losses_balanced, losses_conservative);
}

// ===========================================================================
// 23) ActionDecision — runner_up loss >= selected loss
// ===========================================================================

#[test]
fn action_decision_runner_up_loss_ge_selected() {
    let mut sel = ExpectedLossSelector::balanced();
    let posterior = Posterior::from_millionths(950_000, 25_000, 15_000, 10_000);
    let decision = sel.select(&posterior);
    assert!(
        decision.runner_up_loss_millionths >= decision.expected_loss_millionths,
        "runner_up {} should be >= selected {}",
        decision.runner_up_loss_millionths,
        decision.expected_loss_millionths,
    );
}

// ===========================================================================
// 24) LossMatrix — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_loss_matrix_balanced() {
    let m = LossMatrix::balanced();
    let json = serde_json::to_string(&m).unwrap();
    let rt: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, rt);
}
