//! Enrichment integration tests for `safety_decision_router`.
//!
//! Covers: SafetyAction all() ordering stability, SafetyVerdict edge cases,
//! SafetyContract loss-matrix asymmetry, router evaluation with varied
//! calibration/e-process/CI thresholds, budget arithmetic edge cases,
//! observe convergence, cross-action posterior isolation, event ordering,
//! evidence accumulation, summary_by_action correctness, deterministic
//! replay with observations, serde field stability, and error formatting.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::control_plane::{
    DecisionContract, FallbackPolicy, Posterior,
    mocks::{MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed},
};
use frankenengine_engine::safety_decision_router::{
    ActionSummary, SafetyAction, SafetyContract, SafetyDecisionEvent, SafetyDecisionRequest,
    SafetyDecisionResult, SafetyDecisionRouter, SafetyRouterError, SafetyVerdict,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(budget_ms))
}

fn cx_seed(seed: u64, budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(seed), MockBudget::new(budget_ms))
}

fn req(action: SafetyAction, seed: u64) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        action,
        extension_id: format!("ext-{seed}"),
        target_extension_id: None,
        decision_id: decision_id_from_seed(seed),
        policy_id: policy_id_from_seed(seed),
        ts_unix_ms: 1_700_000_000_000 + seed,
        calibration_score_bps: 9_400,
        e_process_milli: 110,
        ci_width_milli: 45,
    }
}

fn req_cal(action: SafetyAction, seed: u64, cal: u16) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        calibration_score_bps: cal,
        ..req(action, seed)
    }
}

fn req_eprocess(action: SafetyAction, seed: u64, ep: u32) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        e_process_milli: ep,
        ..req(action, seed)
    }
}

fn req_ciwidth(action: SafetyAction, seed: u64, ci: u32) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        ci_width_milli: ci,
        ..req(action, seed)
    }
}

fn router_defaults() -> SafetyDecisionRouter {
    let mut r = SafetyDecisionRouter::new();
    r.register_all_defaults();
    r
}

fn shift_safe(r: &mut SafetyDecisionRouter, action: SafetyAction, n: usize) {
    for _ in 0..n {
        r.observe(action, 0).unwrap();
    }
}

// =========================================================================
// 1. SafetyAction — all() ordering and uniqueness
// =========================================================================

#[test]
fn enrichment_safety_action_all_six_unique() {
    let all = SafetyAction::all();
    let set: BTreeSet<SafetyAction> = all.iter().copied().collect();
    assert_eq!(all.len(), 6);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_safety_action_all_sorted() {
    let all = SafetyAction::all();
    let mut sorted = all.to_vec();
    sorted.sort();
    assert_eq!(all, sorted.as_slice());
}

#[test]
fn enrichment_safety_action_as_str_snake_case() {
    for &a in SafetyAction::all() {
        let s = a.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_safety_action_debug_format() {
    for &a in SafetyAction::all() {
        let d = format!("{a:?}");
        assert!(!d.is_empty());
    }
}

// =========================================================================
// 2. SafetyVerdict — edge cases
// =========================================================================

#[test]
fn enrichment_verdict_allow_is_allow() {
    assert!(SafetyVerdict::Allow.is_allow());
}

#[test]
fn enrichment_verdict_deny_is_not_allow() {
    assert!(!SafetyVerdict::Deny { reason: "r".into() }.is_allow());
}

#[test]
fn enrichment_verdict_fallback_is_not_allow() {
    assert!(!SafetyVerdict::Fallback { reason: "r".into() }.is_allow());
}

#[test]
fn enrichment_verdict_outcome_str_values() {
    assert_eq!(SafetyVerdict::Allow.outcome_str(), "allow");
    assert_eq!(
        SafetyVerdict::Deny { reason: "x".into() }.outcome_str(),
        "deny"
    );
    assert_eq!(
        SafetyVerdict::Fallback { reason: "y".into() }.outcome_str(),
        "fallback"
    );
}

#[test]
fn enrichment_verdict_display_deny_includes_reason() {
    let v = SafetyVerdict::Deny {
        reason: "blocked".into(),
    };
    let s = v.to_string();
    assert!(s.contains("deny"));
    assert!(s.contains("blocked"));
}

#[test]
fn enrichment_verdict_display_fallback_includes_reason() {
    let v = SafetyVerdict::Fallback {
        reason: "drift".into(),
    };
    let s = v.to_string();
    assert!(s.contains("fallback"));
    assert!(s.contains("drift"));
}

// =========================================================================
// 3. SafetyContract — loss matrix properties
// =========================================================================

#[test]
fn enrichment_contract_default_for_all_actions_has_two_states() {
    for &a in SafetyAction::all() {
        let c = SafetyContract::default_for(a);
        assert_eq!(c.state_space().len(), 2);
    }
}

#[test]
fn enrichment_contract_action_type_roundtrip() {
    for &a in SafetyAction::all() {
        let c = SafetyContract::default_for(a);
        assert_eq!(c.action_type(), a);
    }
}

#[test]
fn enrichment_contract_name_matches_action_str() {
    for &a in SafetyAction::all() {
        let c = SafetyContract::default_for(a);
        assert_eq!(c.name(), a.as_str());
    }
}

#[test]
fn enrichment_contract_loss_matrix_unsafe_allow_higher_than_safe_deny() {
    for &a in SafetyAction::all() {
        let c = SafetyContract::default_for(a);
        let lm = c.loss_matrix();
        // loss_matrix row-major: [safe-allow=0, safe-deny=0.1, unsafe-allow=0.9, unsafe-deny=0]
        let loss_unsafe_allow = lm.get(1, 0);
        let loss_safe_deny = lm.get(0, 1);
        assert!(loss_unsafe_allow > loss_safe_deny);
    }
}

#[test]
fn enrichment_contract_uniform_prior_always_denies() {
    for &a in SafetyAction::all() {
        let c = SafetyContract::default_for(a);
        let posterior = Posterior::uniform(2);
        let idx = c.choose_action(&posterior);
        assert_eq!(c.action_set()[idx], "deny");
    }
}

#[test]
fn enrichment_contract_strong_safe_posterior_allows() {
    let c = SafetyContract::default_for(SafetyAction::ExtensionQuarantine);
    let posterior = Posterior::new(vec![0.99, 0.01]).unwrap();
    let idx = c.choose_action(&posterior);
    assert_eq!(c.action_set()[idx], "allow");
}

// =========================================================================
// 4. Router — registration
// =========================================================================

#[test]
fn enrichment_router_new_is_empty() {
    let r = SafetyDecisionRouter::new();
    assert_eq!(r.contract_count(), 0);
    assert_eq!(r.decision_count(), 0);
    assert!(r.results().is_empty());
    assert!(r.evidence().is_empty());
}

#[test]
fn enrichment_router_register_all_defaults_six_contracts() {
    let r = router_defaults();
    assert_eq!(r.contract_count(), 6);
    for &a in SafetyAction::all() {
        assert!(r.has_contract(a));
    }
}

#[test]
fn enrichment_router_register_replaces_contract() {
    let mut r = SafetyDecisionRouter::new();
    r.register(SafetyContract::default_for(SafetyAction::BudgetOverride));
    r.register(SafetyContract::new(
        SafetyAction::BudgetOverride,
        0.5,
        0.5,
        FallbackPolicy::default(),
    ));
    assert_eq!(r.contract_count(), 1);
}

// =========================================================================
// 5. Router — evaluate basic verdicts
// =========================================================================

#[test]
fn enrichment_evaluate_uniform_prior_denies() {
    let mut r = router_defaults();
    let mut c = cx(100);
    let result = r
        .evaluate(&mut c, &req(SafetyAction::ForcedTermination, 1))
        .unwrap();
    assert!(matches!(result.verdict, SafetyVerdict::Deny { .. }));
}

#[test]
fn enrichment_evaluate_after_safe_observations_allows() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::CapabilityRevocation, 30);
    let mut c = cx(100);
    let result = r
        .evaluate(&mut c, &req(SafetyAction::CapabilityRevocation, 1))
        .unwrap();
    assert!(result.verdict.is_allow());
}

#[test]
fn enrichment_evaluate_all_actions_succeed() {
    let mut r = router_defaults();
    let mut c = cx(200);
    for (i, &a) in SafetyAction::all().iter().enumerate() {
        let result = r.evaluate(&mut c, &req(a, i as u64));
        assert!(result.is_ok());
    }
    assert_eq!(r.decision_count(), 6);
}

// =========================================================================
// 6. Budget — exhaustion
// =========================================================================

#[test]
fn enrichment_budget_exact_two_ms_succeeds() {
    let mut r = router_defaults();
    let mut c = cx(2);
    assert!(
        r.evaluate(&mut c, &req(SafetyAction::ExtensionQuarantine, 1))
            .is_ok()
    );
}

#[test]
fn enrichment_budget_one_ms_fails() {
    let mut r = router_defaults();
    let mut c = cx(1);
    let err = r
        .evaluate(&mut c, &req(SafetyAction::ExtensionQuarantine, 1))
        .unwrap_err();
    assert!(matches!(err, SafetyRouterError::BudgetExhausted { .. }));
}

#[test]
fn enrichment_budget_zero_ms_fails() {
    let mut r = router_defaults();
    let mut c = cx(0);
    let err = r
        .evaluate(&mut c, &req(SafetyAction::BudgetOverride, 1))
        .unwrap_err();
    assert!(matches!(err, SafetyRouterError::BudgetExhausted { .. }));
}

#[test]
fn enrichment_budget_exhaustion_still_increments_decision_count() {
    let mut r = router_defaults();
    let mut c = cx(0);
    let _ = r.evaluate(&mut c, &req(SafetyAction::ForcedTermination, 1));
    assert_eq!(r.decision_count(), 1);
    assert_eq!(r.deny_count(), 1);
}

#[test]
fn enrichment_budget_exhaustion_stores_fallback_active_result() {
    let mut r = router_defaults();
    let mut c = cx(0);
    let _ = r.evaluate(&mut c, &req(SafetyAction::ForcedTermination, 1));
    let results = r.results();
    assert_eq!(results.len(), 1);
    assert!(results[0].fallback_active);
}

// =========================================================================
// 7. No contract registered
// =========================================================================

#[test]
fn enrichment_no_contract_returns_error() {
    let mut r = SafetyDecisionRouter::new();
    let mut c = cx(100);
    let err = r
        .evaluate(&mut c, &req(SafetyAction::BudgetOverride, 1))
        .unwrap_err();
    assert!(matches!(err, SafetyRouterError::NoContract { .. }));
}

#[test]
fn enrichment_no_contract_emits_event_with_error_code() {
    let mut r = SafetyDecisionRouter::new();
    let mut c = cx(100);
    let _ = r.evaluate(&mut c, &req(SafetyAction::BudgetOverride, 1));
    let events = r.drain_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].error_code.as_deref(), Some("no_contract"));
}

// =========================================================================
// 8. Fallback triggering
// =========================================================================

#[test]
fn enrichment_low_calibration_triggers_fallback() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::ExtensionQuarantine, 30);
    let mut c = cx(100);
    let result = r
        .evaluate(
            &mut c,
            &req_cal(SafetyAction::ExtensionQuarantine, 1, 4_000),
        )
        .unwrap();
    assert!(matches!(result.verdict, SafetyVerdict::Fallback { .. }));
    assert!(result.fallback_active);
}

#[test]
fn enrichment_high_eprocess_triggers_fallback() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::PrivilegeEscalation, 30);
    let mut c = cx(100);
    let result = r
        .evaluate(
            &mut c,
            &req_eprocess(SafetyAction::PrivilegeEscalation, 1, 25_000),
        )
        .unwrap();
    assert!(matches!(result.verdict, SafetyVerdict::Fallback { .. }));
}

#[test]
fn enrichment_wide_ci_triggers_fallback() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::CrossExtensionShare, 30);
    let mut c = cx(100);
    let result = r
        .evaluate(
            &mut c,
            &req_ciwidth(SafetyAction::CrossExtensionShare, 1, 700),
        )
        .unwrap();
    assert!(matches!(result.verdict, SafetyVerdict::Fallback { .. }));
}

#[test]
fn enrichment_fallback_increments_fallback_count() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::BudgetOverride, 30);
    let mut c = cx(100);
    r.evaluate(&mut c, &req_cal(SafetyAction::BudgetOverride, 1, 3_000))
        .unwrap();
    assert_eq!(r.fallback_count(), 1);
}

// =========================================================================
// 9. Observe — posterior shifting
// =========================================================================

#[test]
fn enrichment_observe_safe_increases_safe_probability() {
    let mut r = router_defaults();
    let before = r
        .posterior(SafetyAction::ForcedTermination)
        .unwrap()
        .probs()[0];
    r.observe(SafetyAction::ForcedTermination, 0).unwrap();
    let after = r
        .posterior(SafetyAction::ForcedTermination)
        .unwrap()
        .probs()[0];
    assert!(after > before);
}

#[test]
fn enrichment_observe_unsafe_increases_unsafe_probability() {
    let mut r = router_defaults();
    r.observe(SafetyAction::BudgetOverride, 1).unwrap();
    let probs = r.posterior(SafetyAction::BudgetOverride).unwrap().probs();
    assert!(probs[1] > probs[0]);
}

#[test]
fn enrichment_observe_no_contract_is_error() {
    let mut r = SafetyDecisionRouter::new();
    let err = r.observe(SafetyAction::ForcedTermination, 0).unwrap_err();
    assert!(matches!(err, SafetyRouterError::NoContract { .. }));
}

// =========================================================================
// 10. Cross-action isolation
// =========================================================================

#[test]
fn enrichment_observe_one_action_does_not_affect_other() {
    let mut r = router_defaults();
    shift_safe(&mut r, SafetyAction::ExtensionQuarantine, 30);

    let ft_probs = r
        .posterior(SafetyAction::ForcedTermination)
        .unwrap()
        .probs()
        .to_vec();
    assert!((ft_probs[0] - 0.5).abs() < 1e-9);

    let eq_probs = r
        .posterior(SafetyAction::ExtensionQuarantine)
        .unwrap()
        .probs()
        .to_vec();
    assert!(eq_probs[0] > 0.9);
}

// =========================================================================
// 11. Event emission
// =========================================================================

#[test]
fn enrichment_evaluate_emits_one_event() {
    let mut r = router_defaults();
    let mut c = cx(100);
    r.evaluate(&mut c, &req(SafetyAction::ExtensionQuarantine, 1))
        .unwrap();
    let events = r.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].component, "safety_decision_router");
    assert_eq!(events[0].event, "evaluate");
}

#[test]
fn enrichment_drain_events_clears() {
    let mut r = router_defaults();
    let mut c = cx(100);
    r.evaluate(&mut c, &req(SafetyAction::ExtensionQuarantine, 1))
        .unwrap();
    assert_eq!(r.drain_events().len(), 1);
    assert!(r.drain_events().is_empty());
}

#[test]
fn enrichment_event_sequence_monotonic() {
    let mut r = router_defaults();
    let mut c = cx(200);
    for i in 0..5 {
        let _ = r.evaluate(&mut c, &req(SafetyAction::BudgetOverride, i));
    }
    let events = r.drain_events();
    for w in events.windows(2) {
        assert!(w[1].seq > w[0].seq);
    }
}

// =========================================================================
// 12. Evidence accumulation
// =========================================================================

#[test]
fn enrichment_evidence_one_per_successful_eval() {
    let mut r = router_defaults();
    let mut c = cx(100);
    for i in 0..4 {
        r.evaluate(&mut c, &req(SafetyAction::ExtensionQuarantine, i))
            .unwrap();
    }
    assert_eq!(r.evidence().len(), 4);
}

#[test]
fn enrichment_budget_exhaustion_no_evidence() {
    let mut r = router_defaults();
    let mut c = cx(0);
    let _ = r.evaluate(&mut c, &req(SafetyAction::ForcedTermination, 1));
    assert!(r.evidence().is_empty());
}

// =========================================================================
// 13. summary_by_action
// =========================================================================

#[test]
fn enrichment_summary_empty_router() {
    let r = router_defaults();
    assert!(r.summary_by_action().is_empty());
}

#[test]
fn enrichment_summary_tracks_correct_counts() {
    let mut r = router_defaults();
    let mut c = cx(200);
    // Two evaluations for same action (both will deny with uniform prior)
    for i in 0..2 {
        r.evaluate(&mut c, &req(SafetyAction::ForcedTermination, i))
            .unwrap();
    }
    let summary = r.summary_by_action();
    let ft = &summary[&SafetyAction::ForcedTermination];
    assert_eq!(ft.total, 2);
    assert_eq!(ft.denials, 2);
    assert_eq!(ft.allows, 0);
    assert_eq!(ft.fallbacks, 0);
}

// =========================================================================
// 14. Deterministic replay
// =========================================================================

#[test]
fn enrichment_deterministic_replay_with_observations() {
    let run = || {
        let mut r = router_defaults();
        for _ in 0..10 {
            r.observe(SafetyAction::CapabilityRevocation, 0).unwrap();
        }
        let mut c = cx_seed(42, 100);
        r.evaluate(&mut c, &req(SafetyAction::CapabilityRevocation, 7))
            .unwrap()
    };
    assert_eq!(run(), run());
}

// =========================================================================
// 15. Serde roundtrips
// =========================================================================

#[test]
fn enrichment_safety_action_serde_all() {
    for &a in SafetyAction::all() {
        let json = serde_json::to_string(&a).unwrap();
        let back: SafetyAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

#[test]
fn enrichment_safety_verdict_serde_all_variants() {
    let verdicts = [
        SafetyVerdict::Allow,
        SafetyVerdict::Deny {
            reason: "test".into(),
        },
        SafetyVerdict::Fallback {
            reason: "drift".into(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: SafetyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_safety_decision_request_serde() {
    let r = req(SafetyAction::CrossExtensionShare, 99);
    let json = serde_json::to_string(&r).unwrap();
    let back: SafetyDecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_safety_decision_result_serde() {
    let result = SafetyDecisionResult {
        action: SafetyAction::BudgetOverride,
        verdict: SafetyVerdict::Allow,
        extension_id: "ext-1".into(),
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        expected_loss_milli: 250,
        fallback_active: false,
        budget_consumed_ms: 2,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: SafetyDecisionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_safety_decision_event_serde() {
    let event = SafetyDecisionEvent {
        seq: 5,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "safety_decision_router".into(),
        event: "evaluate".into(),
        outcome: "deny".into(),
        error_code: Some("budget_exhausted".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SafetyDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_safety_router_error_serde_all_variants() {
    let errors = [
        SafetyRouterError::BudgetExhausted {
            action: SafetyAction::ForcedTermination,
            requested_ms: 2,
            remaining_ms: 0,
        },
        SafetyRouterError::NoContract {
            action: SafetyAction::BudgetOverride,
        },
        SafetyRouterError::InvalidActionIndex {
            action: SafetyAction::PrivilegeEscalation,
            index: 5,
            max: 2,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: SafetyRouterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_action_summary_serde() {
    let s = ActionSummary {
        total: 50,
        allows: 10,
        denials: 30,
        fallbacks: 10,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: ActionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// =========================================================================
// 16. Error Display formatting
// =========================================================================

#[test]
fn enrichment_error_display_budget_exhausted() {
    let e = SafetyRouterError::BudgetExhausted {
        action: SafetyAction::ExtensionQuarantine,
        requested_ms: 2,
        remaining_ms: 1,
    };
    let s = e.to_string();
    assert!(s.contains("budget exhausted"));
    assert!(s.contains("extension_quarantine"));
}

#[test]
fn enrichment_error_display_no_contract() {
    let e = SafetyRouterError::NoContract {
        action: SafetyAction::PrivilegeEscalation,
    };
    let s = e.to_string();
    assert!(s.contains("no decision contract"));
    assert!(s.contains("privilege_escalation"));
}

#[test]
fn enrichment_error_display_invalid_action_index() {
    let e = SafetyRouterError::InvalidActionIndex {
        action: SafetyAction::CrossExtensionShare,
        index: 10,
        max: 2,
    };
    let s = e.to_string();
    assert!(s.contains("invalid action index"));
    assert!(s.contains("10"));
}

#[test]
fn enrichment_error_is_std_error() {
    let e = SafetyRouterError::NoContract {
        action: SafetyAction::ForcedTermination,
    };
    let _: &dyn std::error::Error = &e;
}

// =========================================================================
// 17. Sequence number monotonicity across evaluations
// =========================================================================

#[test]
fn enrichment_sequence_numbers_monotonically_increasing() {
    let mut r = router_defaults();
    let mut c = cx(200);
    let mut last_seq = 0;
    for i in 0..5 {
        let result = r
            .evaluate(&mut c, &req(SafetyAction::CapabilityRevocation, i))
            .unwrap();
        assert!(result.sequence_number > last_seq);
        last_seq = result.sequence_number;
    }
}
