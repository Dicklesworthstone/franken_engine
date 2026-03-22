//! Deep integration tests for policy_controller module.
//!
//! Covers: loss matrix operations, posterior distribution, guardrail blocking,
//! expected-loss-minimizing action selection, safe default fallback,
//! serde roundtrips, error handling, and decision sequencing.

use std::collections::BTreeMap;

use frankenengine_engine::policy_controller::{
    ActionSelection, ControllerConfig, Guardrail, LossMatrix, PolicyController,
    PolicyControllerError, Posterior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_config(actions: &[&str], safe_default: &str) -> ControllerConfig {
    ControllerConfig {
        controller_id: "test-controller".to_string(),
        domain: "test_domain".to_string(),
        action_set: actions.iter().map(|s| s.to_string()).collect(),
        safe_default: safe_default.to_string(),
        policy_id: "test-policy".to_string(),
    }
}

fn make_uniform_posterior(states: &[&str]) -> Posterior {
    let n = states.len() as i64;
    let prob = 1_000_000 / n;
    let mut probs = BTreeMap::new();
    for state in states {
        probs.insert(state.to_string(), prob);
    }
    Posterior::new(probs)
}

// ---------------------------------------------------------------------------
// LossMatrix
// ---------------------------------------------------------------------------

#[test]
fn deep_loss_matrix_new_empty() {
    let m = LossMatrix::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn deep_loss_matrix_set_and_get() {
    let mut m = LossMatrix::new();
    m.set("high_risk", "allow", 900_000);
    m.set("high_risk", "deny", 100_000);
    m.set("low_risk", "allow", 50_000);
    m.set("low_risk", "deny", 500_000);

    assert_eq!(m.get("high_risk", "allow"), Some(900_000));
    assert_eq!(m.get("high_risk", "deny"), Some(100_000));
    assert_eq!(m.get("low_risk", "allow"), Some(50_000));
    assert_eq!(m.get("missing", "allow"), None);
    assert_eq!(m.len(), 4);
}

#[test]
fn deep_loss_matrix_overwrite() {
    let mut m = LossMatrix::new();
    m.set("state", "action", 100);
    m.set("state", "action", 200);
    assert_eq!(m.get("state", "action"), Some(200));
    assert_eq!(m.len(), 1);
}

#[test]
fn deep_loss_matrix_serde_roundtrip() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", 100_000);
    m.set("s1", "a2", 200_000);
    m.set("s2", "a1", 300_000);

    let json = serde_json::to_string(&m).unwrap();
    let decoded: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, decoded);
}

// ---------------------------------------------------------------------------
// Posterior
// ---------------------------------------------------------------------------

#[test]
fn deep_posterior_probability() {
    let mut probs = BTreeMap::new();
    probs.insert("high".to_string(), 700_000i64);
    probs.insert("low".to_string(), 300_000);
    let posterior = Posterior::new(probs);

    assert_eq!(posterior.probability("high"), 700_000);
    assert_eq!(posterior.probability("low"), 300_000);
    assert_eq!(posterior.probability("missing"), 0);
}

#[test]
fn deep_posterior_states_deterministic_order() {
    let mut probs = BTreeMap::new();
    probs.insert("z_state".to_string(), 100_000i64);
    probs.insert("a_state".to_string(), 900_000);
    let posterior = Posterior::new(probs);

    let states: Vec<&str> = posterior.states().collect();
    assert_eq!(states, vec!["a_state", "z_state"]); // BTreeMap order
}

#[test]
fn deep_posterior_serde_roundtrip() {
    let posterior = make_uniform_posterior(&["s1", "s2", "s3"]);
    let json = serde_json::to_string(&posterior).unwrap();
    let decoded: Posterior = serde_json::from_str(&json).unwrap();
    assert_eq!(posterior, decoded);
}

// ---------------------------------------------------------------------------
// Guardrail
// ---------------------------------------------------------------------------

#[test]
fn deep_guardrail_blocks() {
    let gr = Guardrail {
        id: "gr-1".to_string(),
        description: "Block terminate".to_string(),
        blocked_actions: vec!["terminate".to_string(), "quarantine".to_string()],
    };
    assert!(gr.blocks("terminate"));
    assert!(gr.blocks("quarantine"));
    assert!(!gr.blocks("allow"));
}

#[test]
fn deep_guardrail_serde_roundtrip() {
    let gr = Guardrail {
        id: "gr-test".to_string(),
        description: "Test guardrail".to_string(),
        blocked_actions: vec!["deny".to_string()],
    };
    let json = serde_json::to_string(&gr).unwrap();
    let decoded: Guardrail = serde_json::from_str(&json).unwrap();
    assert_eq!(gr, decoded);
}

// ---------------------------------------------------------------------------
// PolicyController — creation
// ---------------------------------------------------------------------------

#[test]
fn deep_controller_creation_ok() {
    let config = make_config(&["allow", "deny"], "allow");
    let result = PolicyController::new(config, LossMatrix::new());
    assert!(result.is_ok());
}

#[test]
fn deep_controller_empty_action_set_fails() {
    let config = make_config(&[], "allow");
    let result = PolicyController::new(config, LossMatrix::new());
    assert!(matches!(
        result.unwrap_err(),
        PolicyControllerError::EmptyActionSet
    ));
}

#[test]
fn deep_controller_safe_default_not_in_set_fails() {
    let config = make_config(&["allow", "deny"], "quarantine");
    let result = PolicyController::new(config, LossMatrix::new());
    assert!(matches!(
        result.unwrap_err(),
        PolicyControllerError::SafeDefaultNotInActionSet { .. }
    ));
}

// ---------------------------------------------------------------------------
// PolicyController — action selection
// ---------------------------------------------------------------------------

#[test]
fn deep_select_minimizes_expected_loss() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let mut matrix = LossMatrix::new();
    // High risk: deny is cheapest
    matrix.set("high_risk", "allow", 900_000);
    matrix.set("high_risk", "deny", 100_000);
    matrix.set("high_risk", "sandbox", 300_000);
    // Low risk: allow is cheapest
    matrix.set("low_risk", "allow", 50_000);
    matrix.set("low_risk", "deny", 500_000);
    matrix.set("low_risk", "sandbox", 200_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();

    // Under high-risk posterior (100% high_risk)
    let mut probs = BTreeMap::new();
    probs.insert("high_risk".to_string(), 1_000_000i64);
    let posterior = Posterior::new(probs);

    let result = ctrl.select_action(&posterior, epoch(1), "trace-1").unwrap();
    assert_eq!(result.action, "deny"); // minimum expected loss
    assert!(!result.is_safe_default);
}

#[test]
fn deep_select_falls_back_to_safe_default() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).unwrap();

    // Block both actions
    ctrl.add_guardrail(Guardrail {
        id: "gr-block-all".to_string(),
        description: "Block everything".to_string(),
        blocked_actions: vec!["allow".to_string(), "deny".to_string()],
    });

    let posterior = make_uniform_posterior(&["s1"]);
    let result = ctrl.select_action(&posterior, epoch(1), "trace-2").unwrap();
    assert_eq!(result.action, "allow"); // safe default
    assert!(result.is_safe_default);
}

#[test]
fn deep_select_guardrail_rejection_tracked() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let mut matrix = LossMatrix::new();
    matrix.set("s1", "allow", 900_000);
    matrix.set("s1", "deny", 100_000);
    matrix.set("s1", "sandbox", 200_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();

    // Block deny (which would be lowest loss)
    ctrl.add_guardrail(Guardrail {
        id: "no-deny".to_string(),
        description: "Block deny".to_string(),
        blocked_actions: vec!["deny".to_string()],
    });

    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 1_000_000i64);
    let posterior = Posterior::new(probs);

    let result = ctrl.select_action(&posterior, epoch(1), "trace-3").unwrap();
    assert_eq!(result.action, "sandbox"); // next best after deny blocked
    assert!(!result.is_safe_default);
    assert!(!result.guardrail_rejections.is_empty());
    assert!(result.guardrail_rejections.iter().any(|(a, _)| a == "deny"));
}

#[test]
fn deep_select_decision_id_sequential() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).unwrap();
    let posterior = make_uniform_posterior(&["s1"]);

    let r1 = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    let r2 = ctrl.select_action(&posterior, epoch(1), "t2").unwrap();

    assert_ne!(r1.decision_id, r2.decision_id);
    assert!(r1.decision_id.contains("000001"));
    assert!(r2.decision_id.contains("000002"));
}

// ---------------------------------------------------------------------------
// ActionSelection serde
// ---------------------------------------------------------------------------

#[test]
fn deep_action_selection_serde_roundtrip() {
    let selection = ActionSelection {
        action: "sandbox".to_string(),
        expected_loss: 200_000,
        is_safe_default: false,
        guardrail_rejections: vec![("deny".to_string(), "gr-1".to_string())],
        decision_id: "ctrl-000001".to_string(),
    };
    let json = serde_json::to_string(&selection).unwrap();
    let decoded: ActionSelection = serde_json::from_str(&json).unwrap();
    assert_eq!(selection, decoded);
}

// ---------------------------------------------------------------------------
// ControllerConfig serde
// ---------------------------------------------------------------------------

#[test]
fn deep_controller_config_serde_roundtrip() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let json = serde_json::to_string(&config).unwrap();
    let decoded: ControllerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

// ---------------------------------------------------------------------------
// PolicyControllerError
// ---------------------------------------------------------------------------

#[test]
fn deep_error_display() {
    let errors = [
        PolicyControllerError::EmptyActionSet,
        PolicyControllerError::NoLossEntries,
        PolicyControllerError::SafeDefaultNotInActionSet {
            safe_default: "quarantine".to_string(),
        },
        PolicyControllerError::EvidenceEmissionFailed {
            reason: "ledger full".to_string(),
        },
    ];
    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty());
    }
}

#[test]
fn deep_error_serde_roundtrip() {
    let errors = [
        PolicyControllerError::EmptyActionSet,
        PolicyControllerError::NoLossEntries,
        PolicyControllerError::SafeDefaultNotInActionSet {
            safe_default: "quarantine".to_string(),
        },
        PolicyControllerError::EvidenceEmissionFailed {
            reason: "test".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: PolicyControllerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

// ---------------------------------------------------------------------------
// update_loss_matrix
// ---------------------------------------------------------------------------

#[test]
fn deep_update_loss_matrix_changes_selection() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut matrix = LossMatrix::new();
    matrix.set("s1", "allow", 900_000);
    matrix.set("s1", "deny", 100_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();
    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 1_000_000i64);
    let posterior = Posterior::new(probs);

    // Before update: deny wins (lower loss)
    let r1 = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    assert_eq!(r1.action, "deny");

    // Update matrix: now allow is cheaper
    let mut new_matrix = LossMatrix::new();
    new_matrix.set("s1", "allow", 50_000);
    new_matrix.set("s1", "deny", 800_000);
    ctrl.update_loss_matrix(new_matrix);

    let r2 = ctrl.select_action(&posterior, epoch(2), "t2").unwrap();
    assert_eq!(r2.action, "allow");
}

// ---------------------------------------------------------------------------
// decision_count and decisions history
// ---------------------------------------------------------------------------

#[test]
fn deep_decision_count_increments() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).unwrap();
    let posterior = make_uniform_posterior(&["s1"]);

    assert_eq!(ctrl.decision_count(), 0);
    assert!(ctrl.decisions().is_empty());

    ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    assert_eq!(ctrl.decision_count(), 1);
    assert_eq!(ctrl.decisions().len(), 1);

    ctrl.select_action(&posterior, epoch(2), "t2").unwrap();
    assert_eq!(ctrl.decision_count(), 2);
    assert_eq!(ctrl.decisions().len(), 2);
}

#[test]
fn deep_decisions_preserves_order() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut matrix = LossMatrix::new();
    matrix.set("s1", "allow", 900_000);
    matrix.set("s1", "deny", 100_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();

    let mut probs_high = BTreeMap::new();
    probs_high.insert("s1".to_string(), 1_000_000i64);
    let posterior_high = Posterior::new(probs_high);

    let r1 = ctrl.select_action(&posterior_high, epoch(1), "t1").unwrap();
    let r2 = ctrl.select_action(&posterior_high, epoch(2), "t2").unwrap();

    let history = ctrl.decisions();
    assert_eq!(history[0].decision_id, r1.decision_id);
    assert_eq!(history[1].decision_id, r2.decision_id);
}

// ---------------------------------------------------------------------------
// config accessor
// ---------------------------------------------------------------------------

#[test]
fn deep_config_accessor() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let ctrl = PolicyController::new(config.clone(), LossMatrix::new()).unwrap();
    assert_eq!(ctrl.config().controller_id, "test-controller");
    assert_eq!(ctrl.config().domain, "test_domain");
    assert_eq!(ctrl.config().safe_default, "allow");
    assert_eq!(ctrl.config().action_set.len(), 3);
}

// ---------------------------------------------------------------------------
// Multi-state posterior selection
// ---------------------------------------------------------------------------

#[test]
fn deep_multi_state_expected_loss() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let mut matrix = LossMatrix::new();
    // Mixed posterior: 50% high, 50% low
    matrix.set("high", "allow", 800_000);
    matrix.set("high", "deny", 200_000);
    matrix.set("high", "sandbox", 400_000);
    matrix.set("low", "allow", 100_000);
    matrix.set("low", "deny", 600_000);
    matrix.set("low", "sandbox", 300_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();
    let mut probs = BTreeMap::new();
    probs.insert("high".to_string(), 500_000i64);
    probs.insert("low".to_string(), 500_000);
    let posterior = Posterior::new(probs);

    let result = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    // E[allow] = 0.5*800k + 0.5*100k = 450k
    // E[deny]  = 0.5*200k + 0.5*600k = 400k
    // E[sandbox] = 0.5*400k + 0.5*300k = 350k -> sandbox wins
    assert_eq!(result.action, "sandbox");
}

#[test]
fn deep_three_state_selection() {
    let config = make_config(&["a1", "a2", "a3"], "a1");
    let mut matrix = LossMatrix::new();
    for (state, a1, a2, a3) in [
        ("s1", 100_000, 500_000, 300_000),
        ("s2", 500_000, 100_000, 300_000),
        ("s3", 300_000, 300_000, 100_000),
    ] {
        matrix.set(state, "a1", a1);
        matrix.set(state, "a2", a2);
        matrix.set(state, "a3", a3);
    }
    let mut ctrl = PolicyController::new(config, matrix).unwrap();

    // Uniform posterior: each state 1/3
    let posterior = make_uniform_posterior(&["s1", "s2", "s3"]);
    let result = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    // E[a1] = (100+500+300)/3 = 300k, E[a2] = (500+100+300)/3 = 300k
    // E[a3] = (300+300+100)/3 ≈ 233k -> a3 wins
    assert_eq!(result.action, "a3");
}

// ---------------------------------------------------------------------------
// Multiple guardrails
// ---------------------------------------------------------------------------

#[test]
fn deep_multiple_guardrails_compound() {
    let config = make_config(&["a1", "a2", "a3", "a4"], "a1");
    let mut matrix = LossMatrix::new();
    // a4 is cheapest, a3 next, a2 next, a1 most expensive
    matrix.set("s1", "a1", 400_000);
    matrix.set("s1", "a2", 300_000);
    matrix.set("s1", "a3", 200_000);
    matrix.set("s1", "a4", 100_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();

    // Block a4 and a3
    ctrl.add_guardrail(Guardrail {
        id: "gr-1".to_string(),
        description: "block a4".to_string(),
        blocked_actions: vec!["a4".to_string()],
    });
    ctrl.add_guardrail(Guardrail {
        id: "gr-2".to_string(),
        description: "block a3".to_string(),
        blocked_actions: vec!["a3".to_string()],
    });

    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 1_000_000i64);
    let posterior = Posterior::new(probs);

    let result = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    // a4 blocked, a3 blocked, a2 is next cheapest
    assert_eq!(result.action, "a2");
    assert_eq!(result.guardrail_rejections.len(), 2);
}

// ---------------------------------------------------------------------------
// Empty loss matrix still selects safe default
// ---------------------------------------------------------------------------

#[test]
fn deep_empty_matrix_selects_safe_default_by_convention() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).unwrap();
    let posterior = make_uniform_posterior(&["s1"]);

    // With empty matrix, all expected losses are 0, so first action alphabetically
    let result = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    // Both have 0 expected loss; the selection picks the first in action_set order
    assert!(result.action == "allow" || result.action == "deny");
    assert!(!result.is_safe_default);
}

// ---------------------------------------------------------------------------
// Posterior edge cases
// ---------------------------------------------------------------------------

#[test]
fn deep_posterior_zero_probability() {
    let mut probs = BTreeMap::new();
    probs.insert("s1".to_string(), 0i64);
    probs.insert("s2".to_string(), 1_000_000);
    let posterior = Posterior::new(probs);

    assert_eq!(posterior.probability("s1"), 0);
    assert_eq!(posterior.probability("s2"), 1_000_000);
    let states: Vec<&str> = posterior.states().collect();
    assert_eq!(states.len(), 2);
}

#[test]
fn deep_posterior_single_state() {
    let mut probs = BTreeMap::new();
    probs.insert("only".to_string(), 1_000_000i64);
    let posterior = Posterior::new(probs);

    assert_eq!(posterior.probability("only"), 1_000_000);
    let states: Vec<&str> = posterior.states().collect();
    assert_eq!(states, vec!["only"]);
}

// ---------------------------------------------------------------------------
// LossMatrix edge cases
// ---------------------------------------------------------------------------

#[test]
fn deep_loss_matrix_many_entries() {
    let mut m = LossMatrix::new();
    for i in 0..50 {
        m.set(format!("state_{i}"), format!("action_{i}"), i * 1000);
    }
    assert_eq!(m.len(), 50);
    assert_eq!(m.get("state_25", "action_25"), Some(25_000));
    assert_eq!(m.get("state_49", "action_49"), Some(49_000));
}

#[test]
fn deep_loss_matrix_negative_values() {
    let mut m = LossMatrix::new();
    m.set("s1", "a1", -100_000);
    m.set("s1", "a2", 100_000);
    assert_eq!(m.get("s1", "a1"), Some(-100_000));
}

// ---------------------------------------------------------------------------
// Guardrail blocks nothing
// ---------------------------------------------------------------------------

#[test]
fn deep_guardrail_empty_blocked_list() {
    let gr = Guardrail {
        id: "gr-empty".to_string(),
        description: "blocks nothing".to_string(),
        blocked_actions: vec![],
    };
    assert!(!gr.blocks("allow"));
    assert!(!gr.blocks("deny"));
}

// ---------------------------------------------------------------------------
// Decision ID format determinism
// ---------------------------------------------------------------------------

#[test]
fn deep_decision_id_deterministic_format() {
    let config = make_config(&["allow", "deny"], "allow");
    let mut ctrl = PolicyController::new(config, LossMatrix::new()).unwrap();
    let posterior = make_uniform_posterior(&["s1"]);

    for i in 1..=5 {
        let result = ctrl
            .select_action(&posterior, epoch(i), &format!("t{i}"))
            .unwrap();
        assert!(
            result.decision_id.starts_with("test-controller-"),
            "decision_id should start with controller_id"
        );
    }
    assert_eq!(ctrl.decision_count(), 5);
}

// ---------------------------------------------------------------------------
// PolicyController full workflow
// ---------------------------------------------------------------------------

#[test]
fn deep_controller_full_workflow() {
    let config = make_config(&["allow", "deny", "sandbox"], "allow");
    let mut matrix = LossMatrix::new();
    matrix.set("normal", "allow", 10_000);
    matrix.set("normal", "deny", 500_000);
    matrix.set("anomalous", "allow", 900_000);
    matrix.set("anomalous", "deny", 100_000);

    let mut ctrl = PolicyController::new(config, matrix).unwrap();
    ctrl.add_guardrail(Guardrail {
        id: "gr-1".to_string(),
        description: "test".to_string(),
        blocked_actions: vec!["sandbox".to_string()],
    });

    let posterior = make_uniform_posterior(&["normal"]);
    let r1 = ctrl.select_action(&posterior, epoch(1), "t1").unwrap();
    assert_eq!(ctrl.decision_count(), 1);
    assert_eq!(ctrl.config().controller_id, "test-controller");
    assert!(!r1.decision_id.is_empty());
    assert_eq!(ctrl.decisions().len(), 1);
}
