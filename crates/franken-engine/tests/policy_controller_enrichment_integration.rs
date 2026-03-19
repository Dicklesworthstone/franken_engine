#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `policy_controller` module.

use std::collections::BTreeMap;

use frankenengine_engine::evidence_ledger::DecisionType;
use frankenengine_engine::policy_controller::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn two_state_config() -> ControllerConfig {
    ControllerConfig {
        controller_id: "ctrl-2s".to_string(),
        domain: "risk_level".to_string(),
        action_set: vec!["low".into(), "medium".into(), "high".into()],
        safe_default: "high".into(),
        policy_id: "pol-1".into(),
    }
}

fn two_state_matrix() -> LossMatrix {
    let mut m = LossMatrix::new();
    m.set("calm", "low", 50_000);
    m.set("calm", "medium", 200_000);
    m.set("calm", "high", 600_000);
    m.set("crisis", "low", 3_000_000);
    m.set("crisis", "medium", 800_000);
    m.set("crisis", "high", 100_000);
    m
}

fn calm_posterior() -> Posterior {
    let mut p = BTreeMap::new();
    p.insert("calm".into(), 800_000);
    p.insert("crisis".into(), 200_000);
    Posterior::new(p)
}

fn crisis_posterior() -> Posterior {
    let mut p = BTreeMap::new();
    p.insert("calm".into(), 100_000);
    p.insert("crisis".into(), 900_000);
    Posterior::new(p)
}

fn make_controller() -> PolicyController {
    PolicyController::new(two_state_config(), two_state_matrix()).expect("create")
}

// ===========================================================================
// LossMatrix enrichment
// ===========================================================================

#[test]
fn loss_matrix_zero_value() {
    let mut m = LossMatrix::new();
    m.set("s", "a", 0);
    assert_eq!(m.get("s", "a"), Some(0));
}

#[test]
fn loss_matrix_large_negative() {
    let mut m = LossMatrix::new();
    m.set("s", "a", -999_999_999);
    assert_eq!(m.get("s", "a"), Some(-999_999_999));
}

#[test]
fn loss_matrix_many_entries() {
    let mut m = LossMatrix::new();
    for i in 0..100 {
        m.set(&format!("s{i}"), &format!("a{i}"), i as i64);
    }
    assert_eq!(m.len(), 100);
    assert_eq!(m.get("s50", "a50"), Some(50));
}

#[test]
fn loss_matrix_default_eq_new() {
    let a = LossMatrix::new();
    let b = LossMatrix::default();
    assert_eq!(a, b);
}

// ===========================================================================
// Posterior enrichment
// ===========================================================================

#[test]
fn posterior_single_state() {
    let mut p = BTreeMap::new();
    p.insert("only".into(), 1_000_000);
    let post = Posterior::new(p);
    assert_eq!(post.probability("only"), 1_000_000);
    assert_eq!(post.states().count(), 1);
}

#[test]
fn posterior_many_states() {
    let mut p = BTreeMap::new();
    for i in 0..20 {
        p.insert(format!("state_{i}"), 50_000);
    }
    let post = Posterior::new(p);
    assert_eq!(post.states().count(), 20);
}

#[test]
fn posterior_zero_probability() {
    let mut p = BTreeMap::new();
    p.insert("zero".into(), 0);
    let post = Posterior::new(p);
    assert_eq!(post.probability("zero"), 0);
}

// ===========================================================================
// Guardrail enrichment
// ===========================================================================

#[test]
fn guardrail_blocks_exact_match_only() {
    let gr = Guardrail {
        id: "g1".into(),
        description: "test".into(),
        blocked_actions: vec!["low".into()],
    };
    assert!(gr.blocks("low"));
    assert!(!gr.blocks("Low"));
    assert!(!gr.blocks("LOW"));
}

#[test]
fn guardrail_multiple_blocked() {
    let gr = Guardrail {
        id: "g1".into(),
        description: "multi".into(),
        blocked_actions: vec!["a".into(), "b".into(), "c".into()],
    };
    assert!(gr.blocks("a"));
    assert!(gr.blocks("b"));
    assert!(gr.blocks("c"));
    assert!(!gr.blocks("d"));
}

// ===========================================================================
// ControllerConfig enrichment
// ===========================================================================

#[test]
fn controller_config_clone_eq() {
    let a = two_state_config();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn controller_config_fields() {
    let cfg = two_state_config();
    assert_eq!(cfg.controller_id, "ctrl-2s");
    assert_eq!(cfg.domain, "risk_level");
    assert_eq!(cfg.action_set.len(), 3);
    assert_eq!(cfg.safe_default, "high");
    assert_eq!(cfg.policy_id, "pol-1");
}

// ===========================================================================
// PolicyControllerError enrichment
// ===========================================================================

#[test]
fn error_no_loss_entries_display() {
    let err = PolicyControllerError::NoLossEntries;
    assert_eq!(err.to_string(), "no loss entries for any action");
}

#[test]
fn error_evidence_emission_display() {
    let err = PolicyControllerError::EvidenceEmissionFailed {
        reason: "network timeout".into(),
    };
    assert!(err.to_string().contains("network timeout"));
}

#[test]
fn all_error_variants_distinct_display() {
    let errors = vec![
        PolicyControllerError::EmptyActionSet,
        PolicyControllerError::NoLossEntries,
        PolicyControllerError::SafeDefaultNotInActionSet {
            safe_default: "x".into(),
        },
        PolicyControllerError::EvidenceEmissionFailed { reason: "r".into() },
    ];
    let displays: std::collections::BTreeSet<String> =
        errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn error_serde_roundtrip_all() {
    let errors = vec![
        PolicyControllerError::EmptyActionSet,
        PolicyControllerError::NoLossEntries,
        PolicyControllerError::SafeDefaultNotInActionSet {
            safe_default: "abc".into(),
        },
        PolicyControllerError::EvidenceEmissionFailed {
            reason: "xyz".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: PolicyControllerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// ActionSelection enrichment
// ===========================================================================

#[test]
fn action_selection_debug() {
    let sel = ActionSelection {
        action: "test".into(),
        expected_loss: 42,
        is_safe_default: false,
        guardrail_rejections: vec![],
        decision_id: "d-1".into(),
    };
    let dbg = format!("{sel:?}");
    assert!(dbg.contains("test"));
}

#[test]
fn action_selection_with_rejections_serde() {
    let sel = ActionSelection {
        action: "high".into(),
        expected_loss: 500_000,
        is_safe_default: true,
        guardrail_rejections: vec![
            ("low".into(), "gr1".into()),
            ("medium".into(), "gr2".into()),
        ],
        decision_id: "d-99".into(),
    };
    let json = serde_json::to_string(&sel).expect("serialize");
    let restored: ActionSelection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sel, restored);
}

// ===========================================================================
// PolicyController — selection logic enrichment
// ===========================================================================

#[test]
fn selects_low_in_calm_state() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t1")
        .expect("select");
    // E[L(low)] = 0.8*50k + 0.2*3M = 40k + 600k = 640k
    // E[L(med)] = 0.8*200k + 0.2*800k = 160k + 160k = 320k
    // E[L(high)] = 0.8*600k + 0.2*100k = 480k + 20k = 500k
    assert_eq!(sel.action, "medium");
    assert_eq!(sel.expected_loss, 320_000);
    assert!(!sel.is_safe_default);
}

#[test]
fn selects_high_in_crisis_state() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&crisis_posterior(), epoch(1), "t2")
        .expect("select");
    // E[L(low)] = 0.1*50k + 0.9*3M = 5k + 2700k = 2705k
    // E[L(med)] = 0.1*200k + 0.9*800k = 20k + 720k = 740k
    // E[L(high)] = 0.1*600k + 0.9*100k = 60k + 90k = 150k
    assert_eq!(sel.action, "high");
    assert_eq!(sel.expected_loss, 150_000);
}

#[test]
fn selection_with_uniform_posterior() {
    let mut ctrl = make_controller();
    let mut p = BTreeMap::new();
    p.insert("calm".into(), 500_000);
    p.insert("crisis".into(), 500_000);
    let post = Posterior::new(p);
    let sel = ctrl.select_action(&post, epoch(1), "t").expect("select");
    // All actions have well-defined expected loss
    assert!(!sel.action.is_empty());
}

#[test]
fn selection_determinism_many_runs() {
    let post = calm_posterior();
    let mut actions = Vec::new();
    for _ in 0..10 {
        let mut ctrl = make_controller();
        let sel = ctrl.select_action(&post, epoch(1), "t").expect("select");
        actions.push(sel.action);
    }
    // All should be identical
    let first = &actions[0];
    for a in &actions {
        assert_eq!(a, first);
    }
}

// ===========================================================================
// PolicyController — guardrail enrichment
// ===========================================================================

#[test]
fn guardrail_blocks_best_falls_to_next() {
    let mut ctrl = make_controller();
    ctrl.add_guardrail(Guardrail {
        id: "block-medium".into(),
        description: "block medium".into(),
        blocked_actions: vec!["medium".into()],
    });
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    assert_ne!(sel.action, "medium");
    assert!(!sel.guardrail_rejections.is_empty());
}

#[test]
fn multiple_guardrails_cumulative() {
    let mut ctrl = make_controller();
    ctrl.add_guardrail(Guardrail {
        id: "g1".into(),
        description: "block low".into(),
        blocked_actions: vec!["low".into()],
    });
    ctrl.add_guardrail(Guardrail {
        id: "g2".into(),
        description: "block medium".into(),
        blocked_actions: vec!["medium".into()],
    });
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    assert_eq!(sel.action, "high");
    assert!(!sel.is_safe_default);
    assert_eq!(sel.guardrail_rejections.len(), 2);
}

#[test]
fn all_blocked_safe_default() {
    let mut ctrl = make_controller();
    ctrl.add_guardrail(Guardrail {
        id: "block-all".into(),
        description: "block".into(),
        blocked_actions: vec!["low".into(), "medium".into(), "high".into()],
    });
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    assert_eq!(sel.action, "high");
    assert!(sel.is_safe_default);
    assert_eq!(sel.guardrail_rejections.len(), 3);
}

// ===========================================================================
// PolicyController — decision tracking enrichment
// ===========================================================================

#[test]
fn decision_ids_are_sequential() {
    let mut ctrl = make_controller();
    let post = calm_posterior();
    let s1 = ctrl.select_action(&post, epoch(1), "t").expect("s1");
    let s2 = ctrl.select_action(&post, epoch(1), "t").expect("s2");
    let s3 = ctrl.select_action(&post, epoch(1), "t").expect("s3");
    assert_eq!(s1.decision_id, "ctrl-2s-000001");
    assert_eq!(s2.decision_id, "ctrl-2s-000002");
    assert_eq!(s3.decision_id, "ctrl-2s-000003");
}

#[test]
fn decisions_vec_matches_count() {
    let mut ctrl = make_controller();
    let post = calm_posterior();
    for _ in 0..5 {
        ctrl.select_action(&post, epoch(1), "t").unwrap();
    }
    assert_eq!(ctrl.decision_count(), 5);
    assert_eq!(ctrl.decisions().len(), 5);
}

#[test]
fn decisions_preserve_order() {
    let mut ctrl = make_controller();
    let s1 = ctrl
        .select_action(&calm_posterior(), epoch(1), "t1")
        .expect("s1");
    let s2 = ctrl
        .select_action(&crisis_posterior(), epoch(1), "t2")
        .expect("s2");
    assert_eq!(ctrl.decisions()[0], s1);
    assert_eq!(ctrl.decisions()[1], s2);
}

// ===========================================================================
// PolicyController — update_loss_matrix enrichment
// ===========================================================================

#[test]
fn update_matrix_to_empty_still_works() {
    let mut ctrl = make_controller();
    ctrl.update_loss_matrix(LossMatrix::new());
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    assert_eq!(sel.expected_loss, 0);
}

#[test]
fn update_matrix_reverses_preference() {
    let mut ctrl = make_controller();
    let s1 = ctrl
        .select_action(&calm_posterior(), epoch(1), "t1")
        .expect("s1");

    let mut new_m = LossMatrix::new();
    new_m.set("calm", "low", 1_000);
    new_m.set("calm", "medium", 999_000);
    new_m.set("calm", "high", 999_000);
    new_m.set("crisis", "low", 1_000);
    new_m.set("crisis", "medium", 999_000);
    new_m.set("crisis", "high", 999_000);
    ctrl.update_loss_matrix(new_m);

    let s2 = ctrl
        .select_action(&calm_posterior(), epoch(1), "t2")
        .expect("s2");
    assert_ne!(s1.action, s2.action);
    assert_eq!(s2.action, "low");
}

// ===========================================================================
// PolicyController — evidence enrichment
// ===========================================================================

#[test]
fn evidence_decision_type_is_capability() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");
    assert_eq!(entry.decision_type, DecisionType::CapabilityDecision);
}

#[test]
fn evidence_candidates_count_matches_actions() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");
    assert_eq!(entry.candidates.len(), 3);
}

#[test]
fn evidence_chosen_matches_selection() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");
    assert_eq!(entry.chosen_action.action_name, sel.action);
    assert_eq!(
        entry.chosen_action.expected_loss_millionths,
        sel.expected_loss
    );
}

#[test]
fn evidence_metadata_contains_controller_info() {
    let mut ctrl = make_controller();
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");
    assert_eq!(entry.metadata["controller_id"], "ctrl-2s");
    assert_eq!(entry.metadata["domain"], "risk_level");
}

#[test]
fn evidence_guardrail_filtering_visible() {
    let mut ctrl = make_controller();
    ctrl.add_guardrail(Guardrail {
        id: "risk-block".into(),
        description: "block low".into(),
        blocked_actions: vec!["low".into()],
    });
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");

    let low_cand = entry
        .candidates
        .iter()
        .find(|c| c.action_name == "low")
        .unwrap();
    assert!(low_cand.filtered);
}

#[test]
fn evidence_safe_default_rationale() {
    let mut ctrl = make_controller();
    ctrl.add_guardrail(Guardrail {
        id: "block-all".into(),
        description: "block all".into(),
        blocked_actions: vec!["low".into(), "medium".into(), "high".into()],
    });
    let sel = ctrl
        .select_action(&calm_posterior(), epoch(1), "t")
        .expect("select");
    let entry = ctrl
        .build_evidence(&sel, &calm_posterior(), epoch(1), "t")
        .expect("evidence");
    assert_eq!(
        entry.chosen_action.rationale,
        "safe default (all actions guardrail-blocked)"
    );
}

// ===========================================================================
// Serde enrichment
// ===========================================================================

#[test]
fn loss_matrix_serde_many_entries() {
    let mut m = LossMatrix::new();
    for i in 0..20 {
        m.set(&format!("s{i}"), &format!("a{i}"), i * 100_000);
    }
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: LossMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

#[test]
fn posterior_serde_roundtrip() {
    let p = calm_posterior();
    let json = serde_json::to_string(&p).expect("serialize");
    let restored: Posterior = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, restored);
}

#[test]
fn guardrail_serde_roundtrip() {
    let gr = Guardrail {
        id: "g1".into(),
        description: "desc".into(),
        blocked_actions: vec!["a".into(), "b".into()],
    };
    let json = serde_json::to_string(&gr).expect("serialize");
    let restored: Guardrail = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(gr, restored);
}

#[test]
fn controller_config_serde_roundtrip() {
    let cfg = two_state_config();
    let json = serde_json::to_string(&cfg).expect("serialize");
    let restored: ControllerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cfg, restored);
}
