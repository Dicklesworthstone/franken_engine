//! Integration tests for the policy_controller module.
//!
//! Covers LossMatrix, Posterior, Guardrail, ControllerConfig,
//! PolicyControllerError, ActionSelection, and PolicyController lifecycle
//! including expected-loss computation, guardrail blocking, safe-default
//! fallback, evidence emission, decision tracking, and loss-matrix updates.

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

use frankenengine_engine::evidence_ledger::DecisionType;
use frankenengine_engine::policy_controller::{
    ActionSelection, ControllerConfig, Guardrail, LossMatrix, PolicyController,
    PolicyControllerError, Posterior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn monitoring_config() -> ControllerConfig {
    ControllerConfig {
        controller_id: "mon-ctrl".to_string(),
        domain: "monitoring_intensity".to_string(),
        action_set: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
        safe_default: "high".to_string(),
        policy_id: "policy-v1".to_string(),
    }
}

fn monitoring_matrix() -> LossMatrix {
    let mut m = LossMatrix::new();
    m.set("normal", "low", 100_000);
    m.set("normal", "medium", 300_000);
    m.set("normal", "high", 800_000);
    m.set("anomalous", "low", 5_000_000);
    m.set("anomalous", "medium", 1_000_000);
    m.set("anomalous", "high", 200_000);
    m
}

fn monitoring_controller() -> PolicyController {
    PolicyController::new(monitoring_config(), monitoring_matrix()).expect("create controller")
}

fn normal_posterior() -> Posterior {
    let mut probs = BTreeMap::new();
    probs.insert("normal".to_string(), 900_000);
    probs.insert("anomalous".to_string(), 100_000);
    Posterior::new(probs)
}

fn anomalous_posterior() -> Posterior {
    let mut probs = BTreeMap::new();
    probs.insert("normal".to_string(), 200_000);
    probs.insert("anomalous".to_string(), 800_000);
    Posterior::new(probs)
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// LossMatrix
// ===========================================================================

#[test]
fn loss_matrix_new_is_empty() {
    let m = LossMatrix::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn loss_matrix_default_is_empty() {
    let m = LossMatrix::default();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn loss_matrix_set_and_get() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", 500_000);
    assert_eq!(m.get("s1", "a1"), Some(500_000));
    assert_eq!(m.len(), 1);
    assert!(!m.is_empty());
}

#[test]
fn loss_matrix_get_missing_returns_none() {
    let m = LossMatrix::new();
    assert_eq!(m.get("s1", "a1"), None);
}

#[test]
fn loss_matrix_overwrite_entry() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", 100);
    m.set("s1", "a1", 999);
    assert_eq!(m.get("s1", "a1"), Some(999));
    assert_eq!(m.len(), 1);
}

#[test]
fn loss_matrix_multiple_entries() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", 100);
    m.set("s1", "a2", 200);
    m.set("s2", "a1", 300);
    assert_eq!(m.len(), 3);
    assert_eq!(m.get("s1", "a1"), Some(100));
    assert_eq!(m.get("s1", "a2"), Some(200));
    assert_eq!(m.get("s2", "a1"), Some(300));
    assert_eq!(m.get("s2", "a2"), None);
}

#[test]
fn loss_matrix_negative_values() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", -500_000);
    assert_eq!(m.get("s1", "a1"), Some(-500_000));
}

#[test]
fn loss_matrix_serde_round_trip() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", 100);
    m.set("s2", "a2", 200);
    m.set("s1", "a2", -50);
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: LossMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

#[test]
fn loss_matrix_serde_json_structure() {
    let mut m = LossMatrix::new();
    m.set("state_a", "act_x", 42);
    let json = serde_json::to_string(&m).expect("serialize");
    // Custom serde serializes as vec of {state, action, loss}.
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let entries = v["entries"].as_array().expect("array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["state"], "state_a");
    assert_eq!(entries[0]["action"], "act_x");
    assert_eq!(entries[0]["loss"], 42);
}

#[test]
fn loss_matrix_serde_empty() {
    let m = LossMatrix::new();
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: LossMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
    assert!(restored.is_empty());
}

// ===========================================================================
// Posterior
// ===========================================================================

#[test]
fn posterior_known_state_probability() {
    let p = normal_posterior();
    assert_eq!(p.probability("normal"), 900_000);
    assert_eq!(p.probability("anomalous"), 100_000);
}

#[test]
fn posterior_unknown_state_returns_zero() {
    let p = normal_posterior();
    assert_eq!(p.probability("nonexistent"), 0);
}

#[test]
fn posterior_empty() {
    let p = Posterior::new(BTreeMap::new());
    assert_eq!(p.probability("any"), 0);
    assert_eq!(p.states().count(), 0);
}

#[test]
fn posterior_states_deterministic_order() {
    let p = normal_posterior();
    let states: Vec<&str> = p.states().collect();
    // BTreeMap: alphabetical order.
    assert_eq!(states, vec!["anomalous", "normal"]);
}

#[test]
fn posterior_serde_round_trip() {
    let p = normal_posterior();
    let json = serde_json::to_string(&p).expect("serialize");
    let restored: Posterior = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, restored);
}

// ===========================================================================
// Guardrail
// ===========================================================================

#[test]
fn guardrail_blocks_listed_action() {
    let gr = Guardrail {
        id: "g1".to_string(),
        description: "test guardrail".to_string(),
        blocked_actions: vec!["low".to_string(), "medium".to_string()],
    };
    assert!(gr.blocks("low"));
    assert!(gr.blocks("medium"));
    assert!(!gr.blocks("high"));
}

#[test]
fn guardrail_empty_blocks_nothing() {
    let gr = Guardrail {
        id: "g-empty".to_string(),
        description: "empty".to_string(),
        blocked_actions: vec![],
    };
    assert!(!gr.blocks("any"));
}

#[test]
fn guardrail_serde_round_trip() {
    let gr = Guardrail {
        id: "g1".to_string(),
        description: "desc".to_string(),
        blocked_actions: vec!["a".to_string(), "b".to_string()],
    };
    let json = serde_json::to_string(&gr).expect("serialize");
    let restored: Guardrail = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(gr, restored);
}

// ===========================================================================
// ControllerConfig
// ===========================================================================

#[test]
fn controller_config_serde_round_trip() {
    let config = monitoring_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: ControllerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

// ===========================================================================
// PolicyControllerError
// ===========================================================================

#[test]
fn error_empty_action_set_display() {
    let err = PolicyControllerError::EmptyActionSet;
    assert_eq!(err.to_string(), "action set is empty");
}

#[test]
fn error_no_loss_entries_display() {
    let err = PolicyControllerError::NoLossEntries;
    assert_eq!(err.to_string(), "no loss entries for any action");
}

#[test]
fn error_safe_default_not_in_action_set_display() {
    let err = PolicyControllerError::SafeDefaultNotInActionSet {
        safe_default: "missing".to_string(),
    };
    assert_eq!(err.to_string(), "safe default 'missing' not in action set");
}

#[test]
fn error_evidence_emission_failed_display() {
    let err = PolicyControllerError::EvidenceEmissionFailed {
        reason: "test failure".to_string(),
    };
    assert_eq!(err.to_string(), "evidence emission failed: test failure");
}

#[test]
fn error_is_std_error() {
    let err = PolicyControllerError::EmptyActionSet;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_all_variants() {
    let errors = vec![
        PolicyControllerError::EmptyActionSet,
        PolicyControllerError::NoLossEntries,
        PolicyControllerError::SafeDefaultNotInActionSet {
            safe_default: "x".to_string(),
        },
        PolicyControllerError::EvidenceEmissionFailed {
            reason: "r".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: PolicyControllerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// ActionSelection
// ===========================================================================

#[test]
fn action_selection_serde_round_trip() {
    let sel = ActionSelection {
        action: "medium".to_string(),
        expected_loss: 370_000,
        is_safe_default: false,
        guardrail_rejections: vec![("low".to_string(), "cost-cap".to_string())],
        decision_id: "mon-ctrl-000001".to_string(),
    };
    let json = serde_json::to_string(&sel).expect("serialize");
    let restored: ActionSelection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sel, restored);
}

#[test]
fn action_selection_serde_empty_rejections() {
    let sel = ActionSelection {
        action: "high".to_string(),
        expected_loss: 0,
        is_safe_default: true,
        guardrail_rejections: vec![],
        decision_id: "d-1".to_string(),
    };
    let json = serde_json::to_string(&sel).expect("serialize");
    let restored: ActionSelection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sel, restored);
}

// ===========================================================================
// PolicyController — construction validation
// ===========================================================================

#[test]
fn controller_rejects_empty_action_set() {
    let config = ControllerConfig {
        controller_id: "c".to_string(),
        domain: "d".to_string(),
        action_set: vec![],
        safe_default: "x".to_string(),
        policy_id: "p".to_string(),
    };
    let err = PolicyController::new(config, LossMatrix::new()).unwrap_err();
    assert_eq!(err, PolicyControllerError::EmptyActionSet);
}

#[test]
fn controller_rejects_safe_default_not_in_action_set() {
    let config = ControllerConfig {
        controller_id: "c".to_string(),
        domain: "d".to_string(),
        action_set: vec!["a".to_string(), "b".to_string()],
        safe_default: "missing".to_string(),
        policy_id: "p".to_string(),
    };
    let err = PolicyController::new(config, LossMatrix::new()).unwrap_err();
    match err {
        PolicyControllerError::SafeDefaultNotInActionSet { safe_default } => {
            assert_eq!(safe_default, "missing");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn controller_accepts_valid_config() {
    let ctrl = monitoring_controller();
    assert_eq!(ctrl.config().controller_id, "mon-ctrl");
    assert_eq!(ctrl.config().domain, "monitoring_intensity");
    assert_eq!(ctrl.config().action_set.len(), 3);
    assert_eq!(ctrl.config().safe_default, "high");
    assert_eq!(ctrl.config().policy_id, "policy-v1");
    assert_eq!(ctrl.decision_count(), 0);
    assert!(ctrl.decisions().is_empty());
}

#[test]
fn controller_accepts_empty_loss_matrix() {
    // Valid config with empty matrix — select_action returns 0 expected loss.
    let config = ControllerConfig {
        controller_id: "c".to_string(),
        domain: "d".to_string(),
        action_set: vec!["a".to_string()],
        safe_default: "a".to_string(),
        policy_id: "p".to_string(),
    };
    let ctrl = PolicyController::new(config, LossMatrix::new());
    assert!(ctrl.is_ok());
}

// ===========================================================================
// PolicyController — action selection under different posteriors
// ===========================================================================

#[test]
fn selects_medium_in_normal_state() {
    let mut ctrl = monitoring_controller();
    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-1")
        .expect("select");

    // E[L(low)]    = 0.9*100_000 + 0.1*5_000_000 = 590_000
    // E[L(medium)] = 0.9*300_000 + 0.1*1_000_000 = 370_000
    // E[L(high)]   = 0.9*800_000 + 0.1*200_000   = 740_000
    assert_eq!(sel.action, "medium");
    assert_eq!(sel.expected_loss, 370_000);
    assert!(!sel.is_safe_default);
    assert!(sel.guardrail_rejections.is_empty());
}

#[test]
fn selects_high_in_anomalous_state() {
    let mut ctrl = monitoring_controller();
    let sel = ctrl
        .select_action(&anomalous_posterior(), epoch(1), "t-2")
        .expect("select");

    // E[L(low)]    = 0.2*100_000 + 0.8*5_000_000 = 4_020_000
    // E[L(medium)] = 0.2*300_000 + 0.8*1_000_000 = 860_000
    // E[L(high)]   = 0.2*800_000 + 0.8*200_000   = 320_000
    assert_eq!(sel.action, "high");
    assert_eq!(sel.expected_loss, 320_000);
    assert!(!sel.is_safe_default);
}

#[test]
fn selection_with_empty_posterior() {
    let mut ctrl = monitoring_controller();
    let empty = Posterior::new(BTreeMap::new());
    let sel = ctrl
        .select_action(&empty, epoch(1), "t-empty")
        .expect("select");
    // All expected losses are 0 when posterior has no states.
    assert_eq!(sel.expected_loss, 0);
    // Picks first action with min expected loss (all tied at 0).
    assert!(!sel.is_safe_default);
}

#[test]
fn selection_with_empty_loss_matrix() {
    let config = monitoring_config();
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).expect("create");
    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-no-loss")
        .expect("select");
    // All expected losses are 0 (missing entries default to 0).
    assert_eq!(sel.expected_loss, 0);
}

#[test]
fn expected_loss_computation_fixed_point() {
    // Verify precise fixed-point arithmetic:
    // P(s) = 500_000 (0.5), L(s, a) = 600_000 (0.6)
    // E[L(a)] = (500_000 * 600_000) / 1_000_000 = 300_000
    let mut m = LossMatrix::new();
    m.set("s", "a", 600_000);
    let config = ControllerConfig {
        controller_id: "c".to_string(),
        domain: "d".to_string(),
        action_set: vec!["a".to_string()],
        safe_default: "a".to_string(),
        policy_id: "p".to_string(),
    };
    let mut ctrl = PolicyController::new(config, m).expect("create");
    let mut probs = BTreeMap::new();
    probs.insert("s".to_string(), 500_000);
    let posterior = Posterior::new(probs);
    let sel = ctrl
        .select_action(&posterior, epoch(1), "t-fp")
        .expect("select");
    assert_eq!(sel.expected_loss, 300_000);
}

#[test]
fn expected_loss_sums_across_states() {
    // Two states with known probabilities.
    let mut m = LossMatrix::new();
    m.set("s1", "a", 1_000_000); // loss = 1.0
    m.set("s2", "a", 2_000_000); // loss = 2.0
    let config = ControllerConfig {
        controller_id: "c".to_string(),
        domain: "d".to_string(),
        action_set: vec!["a".to_string()],
        safe_default: "a".to_string(),
        policy_id: "p".to_string(),
    };
    let mut ctrl = PolicyController::new(config, m).expect("create");
    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 300_000); // 0.3
    probs.insert("s2".to_string(), 700_000); // 0.7
    let posterior = Posterior::new(probs);
    let sel = ctrl
        .select_action(&posterior, epoch(1), "t-sum")
        .expect("select");
    // E = 0.3 * 1.0 + 0.7 * 2.0 = 0.3 + 1.4 = 1.7 = 1_700_000 millionths
    assert_eq!(sel.expected_loss, 1_700_000);
}

// ===========================================================================
// PolicyController — guardrail blocking
// ===========================================================================

#[test]
fn guardrail_blocks_best_action_picks_next() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "cost-cap".to_string(),
        description: "cost limit".to_string(),
        blocked_actions: vec!["medium".to_string()],
    });

    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-gr")
        .expect("select");

    // Medium blocked; next best is low (590_000) vs high (740_000).
    assert_eq!(sel.action, "low");
    assert!(!sel.is_safe_default);
    assert_eq!(sel.guardrail_rejections.len(), 1);
    assert_eq!(sel.guardrail_rejections[0].0, "medium");
    assert_eq!(sel.guardrail_rejections[0].1, "cost-cap");
}

#[test]
fn multiple_guardrails_block_multiple_actions() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "gr1".to_string(),
        description: "block low".to_string(),
        blocked_actions: vec!["low".to_string()],
    });
    ctrl.add_guardrail(Guardrail {
        id: "gr2".to_string(),
        description: "block medium".to_string(),
        blocked_actions: vec!["medium".to_string()],
    });

    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-multi-gr")
        .expect("select");

    // Only high remains.
    assert_eq!(sel.action, "high");
    assert!(!sel.is_safe_default);
    assert_eq!(sel.guardrail_rejections.len(), 2);
}

#[test]
fn all_actions_blocked_falls_back_to_safe_default() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "block-all".to_string(),
        description: "block everything".to_string(),
        blocked_actions: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
    });

    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-all-blocked")
        .expect("select");

    assert_eq!(sel.action, "high"); // safe default
    assert!(sel.is_safe_default);
    assert_eq!(sel.guardrail_rejections.len(), 3);
}

#[test]
fn guardrail_that_blocks_irrelevant_actions_has_no_effect() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "irrelevant".to_string(),
        description: "blocks unknown action".to_string(),
        blocked_actions: vec!["nonexistent_action".to_string()],
    });

    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t-irr")
        .expect("select");

    assert_eq!(sel.action, "medium"); // Same as no guardrail.
    assert!(sel.guardrail_rejections.is_empty());
}

// ===========================================================================
// PolicyController — determinism
// ===========================================================================

#[test]
fn selection_is_deterministic_across_instances() {
    let mut ctrl1 = monitoring_controller();
    let mut ctrl2 = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let s1 = ctrl1.select_action(&posterior, e, "t").expect("s1");
    let s2 = ctrl2.select_action(&posterior, e, "t").expect("s2");
    assert_eq!(s1.action, s2.action);
    assert_eq!(s1.expected_loss, s2.expected_loss);
    assert_eq!(s1.is_safe_default, s2.is_safe_default);
}

#[test]
fn repeated_selections_are_consistent() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let s1 = ctrl.select_action(&posterior, e, "t1").expect("s1");
    let s2 = ctrl.select_action(&posterior, e, "t2").expect("s2");
    assert_eq!(s1.action, s2.action);
    assert_eq!(s1.expected_loss, s2.expected_loss);
}

// ===========================================================================
// PolicyController — decision tracking
// ===========================================================================

#[test]
fn decision_count_starts_at_zero() {
    let ctrl = monitoring_controller();
    assert_eq!(ctrl.decision_count(), 0);
    assert!(ctrl.decisions().is_empty());
}

#[test]
fn decision_count_increments_per_selection() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    ctrl.select_action(&posterior, e, "t1").unwrap();
    assert_eq!(ctrl.decision_count(), 1);
    assert_eq!(ctrl.decisions().len(), 1);

    ctrl.select_action(&posterior, e, "t2").unwrap();
    assert_eq!(ctrl.decision_count(), 2);
    assert_eq!(ctrl.decisions().len(), 2);
}

#[test]
fn decision_id_format() {
    let mut ctrl = monitoring_controller();
    let sel = ctrl
        .select_action(&normal_posterior(), epoch(1), "t")
        .expect("select");
    assert_eq!(sel.decision_id, "mon-ctrl-000001");

    let sel2 = ctrl
        .select_action(&normal_posterior(), epoch(1), "t")
        .expect("select");
    assert_eq!(sel2.decision_id, "mon-ctrl-000002");
}

#[test]
fn decisions_history_matches_selections() {
    let mut ctrl = monitoring_controller();
    let e = epoch(1);

    let s1 = ctrl
        .select_action(&normal_posterior(), e, "t1")
        .expect("s1");
    let s2 = ctrl
        .select_action(&anomalous_posterior(), e, "t2")
        .expect("s2");

    let history = ctrl.decisions();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0], s1);
    assert_eq!(history[1], s2);
}

// ===========================================================================
// PolicyController — loss matrix update
// ===========================================================================

#[test]
fn update_loss_matrix_changes_selection() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let sel1 = ctrl.select_action(&posterior, e, "t1").expect("s1");
    assert_eq!(sel1.action, "medium");

    // Make high always cheapest.
    let mut new_matrix = LossMatrix::new();
    new_matrix.set("normal", "low", 999_000);
    new_matrix.set("normal", "medium", 999_000);
    new_matrix.set("normal", "high", 1_000);
    new_matrix.set("anomalous", "low", 999_000);
    new_matrix.set("anomalous", "medium", 999_000);
    new_matrix.set("anomalous", "high", 1_000);
    ctrl.update_loss_matrix(new_matrix);

    let sel2 = ctrl.select_action(&posterior, e, "t2").expect("s2");
    assert_eq!(sel2.action, "high");
    assert_ne!(sel1.action, sel2.action);
}

// ===========================================================================
// PolicyController — evidence emission
// ===========================================================================

#[test]
fn evidence_entry_basic_fields() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let sel = ctrl
        .select_action(&posterior, e, "trace-ev")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "trace-ev")
        .expect("evidence");

    assert_eq!(entry.trace_id, "trace-ev");
    assert_eq!(entry.decision_id, sel.decision_id);
    assert_eq!(entry.policy_id, "policy-v1");
    assert_eq!(entry.epoch_id, e);
    assert_eq!(entry.decision_type, DecisionType::CapabilityDecision);
}

#[test]
fn evidence_entry_has_all_candidates() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(entry.candidates.len(), 3);
    let names: Vec<&str> = entry
        .candidates
        .iter()
        .map(|c| c.action_name.as_str())
        .collect();
    assert!(names.contains(&"low"));
    assert!(names.contains(&"medium"));
    assert!(names.contains(&"high"));

    // All unfiltered when no guardrails.
    for c in &entry.candidates {
        assert!(!c.filtered);
        assert!(c.filter_reason.is_none());
    }
}

#[test]
fn evidence_entry_chosen_action_matches_selection() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(entry.chosen_action.action_name, sel.action);
    assert_eq!(
        entry.chosen_action.expected_loss_millionths,
        sel.expected_loss
    );
    assert_eq!(entry.chosen_action.rationale, "minimum expected loss");
}

#[test]
fn evidence_entry_metadata() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);

    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(entry.metadata["controller_id"], "mon-ctrl");
    assert_eq!(entry.metadata["domain"], "monitoring_intensity");
}

#[test]
fn evidence_with_guardrail_shows_filtered_candidate() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "cost-cap".to_string(),
        description: "cost limit".to_string(),
        blocked_actions: vec!["medium".to_string()],
    });

    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    let medium = entry
        .candidates
        .iter()
        .find(|c| c.action_name == "medium")
        .expect("medium candidate");
    assert!(medium.filtered);
    assert!(medium.filter_reason.as_ref().unwrap().contains("cost-cap"));

    // Other candidates not filtered.
    let low = entry
        .candidates
        .iter()
        .find(|c| c.action_name == "low")
        .expect("low candidate");
    assert!(!low.filtered);
}

#[test]
fn evidence_with_guardrail_shows_constraint() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "cost-cap".to_string(),
        description: "cost limit".to_string(),
        blocked_actions: vec!["medium".to_string()],
    });

    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(entry.constraints.len(), 1);
    assert_eq!(entry.constraints[0].constraint_id, "cost-cap");
    assert_eq!(entry.constraints[0].description, "cost limit");
    assert!(entry.constraints[0].active); // medium is in action_set.
}

#[test]
fn evidence_safe_default_rationale() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "block-all".to_string(),
        description: "block".to_string(),
        blocked_actions: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
    });

    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(
        entry.chosen_action.rationale,
        "safe default (all actions guardrail-blocked)"
    );
}

#[test]
fn evidence_no_guardrails_has_empty_constraints() {
    let mut ctrl = monitoring_controller();
    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");
    assert!(entry.constraints.is_empty());
}

#[test]
fn evidence_inactive_constraint_for_irrelevant_guardrail() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "irr-guard".to_string(),
        description: "blocks nothing relevant".to_string(),
        blocked_actions: vec!["nonexistent".to_string()],
    });

    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");

    assert_eq!(entry.constraints.len(), 1);
    assert!(!entry.constraints[0].active); // No blocked action in action_set.
}

#[test]
fn evidence_entry_serde_round_trip() {
    let mut ctrl = monitoring_controller();
    ctrl.add_guardrail(Guardrail {
        id: "gr1".to_string(),
        description: "d".to_string(),
        blocked_actions: vec!["low".to_string()],
    });
    let posterior = normal_posterior();
    let e = epoch(1);
    let sel = ctrl.select_action(&posterior, e, "t").expect("select");
    let entry = ctrl
        .build_evidence(&sel, &posterior, e, "t")
        .expect("evidence");
    let json = serde_json::to_string(&entry).expect("serialize");
    let _: serde_json::Value = serde_json::from_str(&json).expect("valid json");
}

// ===========================================================================
// PolicyController — config accessor
// ===========================================================================

#[test]
fn config_accessor_returns_original_config() {
    let ctrl = monitoring_controller();
    let config = ctrl.config();
    assert_eq!(config.controller_id, "mon-ctrl");
    assert_eq!(config.domain, "monitoring_intensity");
    assert_eq!(config.action_set, vec!["low", "medium", "high"]);
    assert_eq!(config.safe_default, "high");
    assert_eq!(config.policy_id, "policy-v1");
}

// ===========================================================================
// PolicyController — single-action controller
// ===========================================================================

#[test]
fn single_action_controller_always_selects_it() {
    let mut m = LossMatrix::new();
    m.set("s1", "only_action", 500_000);
    let config = ControllerConfig {
        controller_id: "single".to_string(),
        domain: "test".to_string(),
        action_set: vec!["only_action".to_string()],
        safe_default: "only_action".to_string(),
        policy_id: "p".to_string(),
    };
    let mut ctrl = PolicyController::new(config, m).expect("create");
    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 1_000_000);
    let posterior = Posterior::new(probs);

    let sel = ctrl
        .select_action(&posterior, epoch(1), "t")
        .expect("select");
    assert_eq!(sel.action, "only_action");
    assert!(!sel.is_safe_default);
}

// ===========================================================================
// Stress test
// ===========================================================================

#[test]
fn stress_many_decisions() {
    let mut ctrl = monitoring_controller();
    let e = epoch(1);

    for i in 0..50 {
        let mut probs = BTreeMap::new();
        let normal_prob = (i * 20_000) % 1_000_001;
        let anomalous_prob = 1_000_000 - normal_prob;
        probs.insert("normal".to_string(), normal_prob);
        probs.insert("anomalous".to_string(), anomalous_prob);
        let posterior = Posterior::new(probs);

        let sel = ctrl
            .select_action(&posterior, e, &format!("t-{i}"))
            .expect("select");
        assert!(!sel.action.is_empty());
        assert!(!sel.decision_id.is_empty());
    }

    assert_eq!(ctrl.decision_count(), 50);
    assert_eq!(ctrl.decisions().len(), 50);

    // All decision IDs unique.
    let ids: Vec<&str> = ctrl
        .decisions()
        .iter()
        .map(|d| d.decision_id.as_str())
        .collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 50);
}
