//! Integration tests for the `safety_decision_router` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! router construction, contract registration, decision evaluation,
//! posterior updates via observe, fallback triggering, budget exhaustion,
//! structured event emission, evidence ledger accumulation, serde
//! round-trips, deterministic replay, and summary statistics.

#![forbid(unsafe_code)]
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

fn test_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(budget_ms))
}

fn test_cx_with_seed(seed: u64, budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(seed), MockBudget::new(budget_ms))
}

fn test_request(action: SafetyAction, seed: u64) -> SafetyDecisionRequest {
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

fn test_request_with_calibration(
    action: SafetyAction,
    seed: u64,
    calibration_bps: u16,
) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        calibration_score_bps: calibration_bps,
        ..test_request(action, seed)
    }
}

fn test_request_with_eprocess(
    action: SafetyAction,
    seed: u64,
    e_process_milli: u32,
) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        e_process_milli,
        ..test_request(action, seed)
    }
}

fn test_request_with_ci_width(
    action: SafetyAction,
    seed: u64,
    ci_width_milli: u32,
) -> SafetyDecisionRequest {
    SafetyDecisionRequest {
        ci_width_milli,
        ..test_request(action, seed)
    }
}

fn router_with_defaults() -> SafetyDecisionRouter {
    let mut r = SafetyDecisionRouter::new();
    r.register_all_defaults();
    r
}

// ---------------------------------------------------------------------------
// 1. SafetyAction enum coverage
// ---------------------------------------------------------------------------

#[test]
fn safety_action_all_returns_exactly_six_variants() {
    let all = SafetyAction::all();
    assert_eq!(all.len(), 6);
    let unique: BTreeSet<SafetyAction> = all.iter().copied().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn safety_action_as_str_stable_across_calls() {
    for &action in SafetyAction::all() {
        let first = action.as_str();
        let second = action.as_str();
        assert_eq!(first, second);
        assert!(
            !first.is_empty(),
            "as_str should not be empty for {action:?}"
        );
    }
}

#[test]
fn safety_action_display_matches_as_str_for_all_variants() {
    for &action in SafetyAction::all() {
        assert_eq!(format!("{action}"), action.as_str());
    }
}

#[test]
fn safety_action_default_fallback_is_deny_for_all_variants() {
    for &action in SafetyAction::all() {
        let fb = action.default_fallback();
        assert!(
            matches!(fb, SafetyVerdict::Deny { .. }),
            "expected Deny for {action}, got {fb}"
        );
    }
}

#[test]
fn safety_action_default_fallback_reason_contains_action_name() {
    for &action in SafetyAction::all() {
        if let SafetyVerdict::Deny { reason } = action.default_fallback() {
            assert!(
                reason.contains(action.as_str()),
                "reason '{reason}' must mention action '{}'",
                action.as_str()
            );
        }
    }
}

#[test]
fn safety_action_serde_round_trip_all_variants() {
    for &action in SafetyAction::all() {
        let json = serde_json::to_string(&action).unwrap();
        let restored: SafetyAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }
}

#[test]
fn safety_action_ordering_is_deterministic_and_stable() {
    let mut actions = SafetyAction::all().to_vec();
    actions.sort();
    assert_eq!(actions.as_slice(), SafetyAction::all());
}

#[test]
fn safety_action_copy_semantics() {
    let a = SafetyAction::ForcedTermination;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 2. SafetyVerdict coverage
// ---------------------------------------------------------------------------

#[test]
fn safety_verdict_is_allow_only_for_allow_variant() {
    assert!(SafetyVerdict::Allow.is_allow());
    assert!(!SafetyVerdict::Deny { reason: "r".into() }.is_allow());
    assert!(!SafetyVerdict::Fallback { reason: "r".into() }.is_allow());
}

#[test]
fn safety_verdict_outcome_str_values() {
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
fn safety_verdict_display_format() {
    assert_eq!(SafetyVerdict::Allow.to_string(), "allow");

    let deny = SafetyVerdict::Deny {
        reason: "bad actor".into(),
    };
    assert_eq!(deny.to_string(), "deny: bad actor");

    let fb = SafetyVerdict::Fallback {
        reason: "drift".into(),
    };
    assert_eq!(fb.to_string(), "fallback: drift");
}

#[test]
fn safety_verdict_serde_round_trip_all_variants() {
    let verdicts = vec![
        SafetyVerdict::Allow,
        SafetyVerdict::Deny {
            reason: "test deny".into(),
        },
        SafetyVerdict::Fallback {
            reason: "test fallback".into(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let restored: SafetyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// ---------------------------------------------------------------------------
// 3. SafetyContract coverage
// ---------------------------------------------------------------------------

#[test]
fn safety_contract_default_for_has_two_states_and_two_actions() {
    for &action in SafetyAction::all() {
        let c = SafetyContract::default_for(action);
        assert_eq!(c.state_space().len(), 2);
        assert_eq!(c.action_set().len(), 2);
        assert_eq!(c.state_space(), &["safe", "unsafe"]);
        assert_eq!(c.action_set(), &["allow", "deny"]);
    }
}

#[test]
fn safety_contract_name_matches_action_type_as_str() {
    for &action in SafetyAction::all() {
        let c = SafetyContract::default_for(action);
        assert_eq!(c.name(), action.as_str());
        assert_eq!(c.action_type(), action);
    }
}

#[test]
fn safety_contract_fallback_action_is_deny_index() {
    for &action in SafetyAction::all() {
        let c = SafetyContract::default_for(action);
        assert_eq!(c.fallback_action(), 1, "fallback must be deny (index 1)");
    }
}

#[test]
fn safety_contract_loss_matrix_asymmetric_toward_deny() {
    let c = SafetyContract::default_for(SafetyAction::PrivilegeEscalation);
    let lm = c.loss_matrix();
    // loss(unsafe, allow) = 0.9 >> loss(safe, deny) = 0.1
    let loss_unsafe_allow = lm.get(1, 0);
    let loss_safe_deny = lm.get(0, 1);
    assert!(
        loss_unsafe_allow > loss_safe_deny,
        "allow_cost ({loss_unsafe_allow}) must exceed deny_cost ({loss_safe_deny})"
    );
}

#[test]
fn safety_contract_bayes_action_with_uniform_prior_is_deny() {
    for &action in SafetyAction::all() {
        let c = SafetyContract::default_for(action);
        let posterior = Posterior::uniform(2);
        let idx = c.choose_action(&posterior);
        assert_eq!(
            c.action_set()[idx],
            "deny",
            "uniform prior must yield deny for {action}"
        );
    }
}

#[test]
fn safety_contract_bayes_action_with_strong_safe_posterior_is_allow() {
    let c = SafetyContract::default_for(SafetyAction::BudgetOverride);
    let posterior = Posterior::new(vec![0.99, 0.01]).unwrap();
    let idx = c.choose_action(&posterior);
    assert_eq!(c.action_set()[idx], "allow");
}

#[test]
fn safety_contract_update_posterior_shifts_toward_observed_state() {
    let c = SafetyContract::default_for(SafetyAction::ExtensionQuarantine);
    let mut posterior = Posterior::uniform(2);
    let before_safe = posterior.probs()[0];
    c.update_posterior(&mut posterior, 0); // observe "safe"
    assert!(
        posterior.probs()[0] > before_safe,
        "P(safe) must increase after safe observation"
    );
}

#[test]
fn safety_contract_update_posterior_unsafe_observation() {
    let c = SafetyContract::default_for(SafetyAction::ForcedTermination);
    let mut posterior = Posterior::uniform(2);
    c.update_posterior(&mut posterior, 1); // observe "unsafe"
    assert!(posterior.probs()[1] > posterior.probs()[0]);
}

#[test]
fn safety_contract_serde_round_trip() {
    let c = SafetyContract::default_for(SafetyAction::CrossExtensionShare);
    let json = serde_json::to_string(&c).unwrap();
    let restored: SafetyContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c.action_type(), restored.action_type());
    assert_eq!(c.name(), restored.name());
    assert_eq!(c.state_space(), restored.state_space());
    assert_eq!(c.action_set(), restored.action_set());
}

#[test]
fn safety_contract_custom_loss_symmetric() {
    let c = SafetyContract::new(
        SafetyAction::CrossExtensionShare,
        0.5,
        0.5,
        FallbackPolicy::default(),
    );
    let posterior = Posterior::uniform(2);
    let idx = c.choose_action(&posterior);
    // With symmetric loss and uniform prior, first action (allow, index 0) wins
    assert_eq!(c.action_set()[idx], "allow");
}

#[test]
fn safety_contract_highly_asymmetric_always_denies() {
    let c = SafetyContract::new(
        SafetyAction::ForcedTermination,
        100.0,
        0.001,
        FallbackPolicy::default(),
    );
    // Even with strong safe prior
    let posterior = Posterior::new(vec![0.99, 0.01]).unwrap();
    let idx = c.choose_action(&posterior);
    assert_eq!(c.action_set()[idx], "deny");
}

// ---------------------------------------------------------------------------
// 4. SafetyDecisionRouter — construction and registration
// ---------------------------------------------------------------------------

#[test]
fn router_new_starts_empty() {
    let r = SafetyDecisionRouter::new();
    assert_eq!(r.contract_count(), 0);
    assert_eq!(r.decision_count(), 0);
    assert_eq!(r.deny_count(), 0);
    assert_eq!(r.fallback_count(), 0);
    assert!(r.results().is_empty());
    assert!(r.evidence().is_empty());
}

#[test]
fn router_default_is_same_as_new() {
    let r = SafetyDecisionRouter::default();
    assert_eq!(r.contract_count(), 0);
    assert_eq!(r.decision_count(), 0);
}

#[test]
fn router_register_individual_contract() {
    let mut r = SafetyDecisionRouter::new();
    r.register(SafetyContract::default_for(
        SafetyAction::ExtensionQuarantine,
    ));
    assert_eq!(r.contract_count(), 1);
    assert!(r.has_contract(SafetyAction::ExtensionQuarantine));
    assert!(!r.has_contract(SafetyAction::ForcedTermination));
}

#[test]
fn router_register_all_defaults_covers_all_actions() {
    let r = router_with_defaults();
    assert_eq!(r.contract_count(), 6);
    for &action in SafetyAction::all() {
        assert!(r.has_contract(action), "must have contract for {action}");
    }
}

#[test]
fn router_register_replaces_existing_contract() {
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

#[test]
fn router_posterior_available_after_registration() {
    let r = router_with_defaults();
    for &action in SafetyAction::all() {
        let p = r.posterior(action);
        assert!(p.is_some(), "posterior must exist for {action}");
        // Should be uniform (0.5, 0.5)
        let probs = p.unwrap().probs();
        assert!((probs[0] - 0.5).abs() < 1e-9);
        assert!((probs[1] - 0.5).abs() < 1e-9);
    }
}

#[test]
fn router_posterior_none_for_unregistered_action() {
    let r = SafetyDecisionRouter::new();
    assert!(r.posterior(SafetyAction::ForcedTermination).is_none());
}

// ---------------------------------------------------------------------------
// 5. Router evaluation — basic verdict
// ---------------------------------------------------------------------------

#[test]
fn evaluate_with_uniform_prior_yields_deny() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        matches!(result.verdict, SafetyVerdict::Deny { .. }),
        "uniform prior must deny, got {:?}",
        result.verdict
    );
}

#[test]
fn evaluate_populates_all_result_fields() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::CapabilityRevocation, 42);
    let result = r.evaluate(&mut cx, &req).unwrap();

    assert_eq!(result.action, SafetyAction::CapabilityRevocation);
    assert_eq!(result.extension_id, "ext-42");
    assert!(!result.trace_id.is_empty());
    assert!(!result.decision_id.is_empty());
    assert!(!result.policy_id.is_empty());
    assert_eq!(result.budget_consumed_ms, 2);
    assert_eq!(result.sequence_number, 1);
}

#[test]
fn evaluate_after_many_safe_observations_yields_allow() {
    let mut r = router_with_defaults();
    // Shift posterior strongly toward "safe"
    for _ in 0..30 {
        r.observe(SafetyAction::BudgetOverride, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::BudgetOverride, 10);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        result.verdict.is_allow(),
        "expected allow after many safe observations"
    );
}

#[test]
fn evaluate_all_action_types_succeed_with_defaults() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(200);
    for (i, &action) in SafetyAction::all().iter().enumerate() {
        let req = test_request(action, i as u64);
        let result = r.evaluate(&mut cx, &req);
        assert!(result.is_ok(), "evaluation must succeed for {action}");
    }
    assert_eq!(r.decision_count(), 6);
}

// ---------------------------------------------------------------------------
// 6. Budget consumption and exhaustion
// ---------------------------------------------------------------------------

#[test]
fn evaluate_consumes_two_ms_from_budget() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ForcedTermination, 1);
    r.evaluate(&mut cx, &req).unwrap();
    assert_eq!(cx.budget_state().remaining_ms(), 98);
}

#[test]
fn evaluate_budget_exhaustion_returns_error() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(1); // Only 1ms, need 2ms
    let req = test_request(SafetyAction::CrossExtensionShare, 1);
    let err = r.evaluate(&mut cx, &req).unwrap_err();
    assert!(matches!(err, SafetyRouterError::BudgetExhausted { .. }));
}

#[test]
fn evaluate_budget_exhaustion_tracks_deny_count() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(1);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    let _ = r.evaluate(&mut cx, &req);
    assert_eq!(r.deny_count(), 1);
    assert_eq!(r.decision_count(), 1);
}

#[test]
fn evaluate_budget_exhaustion_emits_event() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(0);
    let req = test_request(SafetyAction::BudgetOverride, 1);
    let _ = r.evaluate(&mut cx, &req);
    let events = r.drain_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].outcome, "budget_exhausted");
}

#[test]
fn evaluate_budget_exhaustion_stores_result_with_fallback_active() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(0);
    let req = test_request(SafetyAction::ForcedTermination, 1);
    let _ = r.evaluate(&mut cx, &req);
    let results = r.results();
    assert_eq!(results.len(), 1);
    assert!(results[0].fallback_active);
}

#[test]
fn evaluate_exact_budget_succeeds_then_next_fails() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(2); // Exactly enough for one evaluation
    let req1 = test_request(SafetyAction::ExtensionQuarantine, 1);
    assert!(r.evaluate(&mut cx, &req1).is_ok());

    let req2 = test_request(SafetyAction::ExtensionQuarantine, 2);
    assert!(r.evaluate(&mut cx, &req2).is_err());
}

#[test]
fn evaluate_multiple_until_budget_exhausted() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(10); // Enough for 5 evaluations at 2ms each
    let mut success_count = 0u64;
    for i in 0..10 {
        let req = test_request(SafetyAction::CapabilityRevocation, i);
        if r.evaluate(&mut cx, &req).is_ok() {
            success_count += 1;
        }
    }
    assert_eq!(success_count, 5);
}

// ---------------------------------------------------------------------------
// 7. No contract registered
// ---------------------------------------------------------------------------

#[test]
fn evaluate_no_contract_returns_error() {
    let mut r = SafetyDecisionRouter::new();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ForcedTermination, 1);
    let err = r.evaluate(&mut cx, &req).unwrap_err();
    assert!(matches!(err, SafetyRouterError::NoContract { .. }));
}

#[test]
fn evaluate_no_contract_emits_event_with_error_code() {
    let mut r = SafetyDecisionRouter::new();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::BudgetOverride, 1);
    let _ = r.evaluate(&mut cx, &req);
    let events = r.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].error_code.as_deref(), Some("no_contract"));
}

// ---------------------------------------------------------------------------
// 8. Evidence emission
// ---------------------------------------------------------------------------

#[test]
fn evaluate_emits_one_evidence_entry_per_success() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    for i in 0..3 {
        let req = test_request(SafetyAction::ExtensionQuarantine, i);
        r.evaluate(&mut cx, &req).unwrap();
    }
    assert_eq!(r.evidence().len(), 3);
}

#[test]
fn budget_exhaustion_does_not_emit_evidence() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(0);
    let req = test_request(SafetyAction::ForcedTermination, 1);
    let _ = r.evaluate(&mut cx, &req);
    assert!(r.evidence().is_empty());
}

// ---------------------------------------------------------------------------
// 9. Structured event emission
// ---------------------------------------------------------------------------

#[test]
fn evaluate_emits_event_with_correct_component() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::PrivilegeEscalation, 1);
    r.evaluate(&mut cx, &req).unwrap();
    let events = r.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].component, "safety_decision_router");
    assert_eq!(events[0].event, "evaluate");
    assert!(events[0].error_code.is_none());
}

#[test]
fn drain_events_clears_buffer() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    r.evaluate(&mut cx, &req).unwrap();
    let first = r.drain_events();
    assert_eq!(first.len(), 1);
    let second = r.drain_events();
    assert!(second.is_empty());
}

#[test]
fn event_sequence_numbers_are_monotonic() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    for i in 0..5 {
        let req = test_request(SafetyAction::BudgetOverride, i);
        let _ = r.evaluate(&mut cx, &req);
    }
    let events = r.drain_events();
    for window in events.windows(2) {
        assert!(window[1].seq > window[0].seq);
    }
}

// ---------------------------------------------------------------------------
// 10. Trace ID propagation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_propagates_trace_id_from_context() {
    let mut r = router_with_defaults();
    let mut cx = test_cx_with_seed(99, 100);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(!result.trace_id.is_empty(), "trace_id must be populated");
    // Verify it contains the seed-derived prefix (seed 99 -> deterministic)
    let result2 = {
        let mut cx2 = test_cx_with_seed(99, 100);
        r.evaluate(&mut cx2, &req).unwrap()
    };
    assert_eq!(
        result.trace_id, result2.trace_id,
        "same seed should produce same trace_id"
    );
}

// ---------------------------------------------------------------------------
// 11. Posterior observation via observe()
// ---------------------------------------------------------------------------

#[test]
fn observe_shifts_posterior_toward_safe_state() {
    let mut r = router_with_defaults();
    let before = r
        .posterior(SafetyAction::ExtensionQuarantine)
        .unwrap()
        .probs()
        .to_vec();
    r.observe(SafetyAction::ExtensionQuarantine, 0).unwrap();
    let after = r
        .posterior(SafetyAction::ExtensionQuarantine)
        .unwrap()
        .probs()
        .to_vec();
    assert!(after[0] > before[0], "P(safe) must increase");
}

#[test]
fn observe_shifts_posterior_toward_unsafe_state() {
    let mut r = router_with_defaults();
    r.observe(SafetyAction::ForcedTermination, 1).unwrap();
    let after = r
        .posterior(SafetyAction::ForcedTermination)
        .unwrap()
        .probs()
        .to_vec();
    assert!(after[1] > after[0], "P(unsafe) must exceed P(safe)");
}

#[test]
fn observe_no_contract_returns_error() {
    let mut r = SafetyDecisionRouter::new();
    let err = r.observe(SafetyAction::BudgetOverride, 0).unwrap_err();
    assert!(matches!(err, SafetyRouterError::NoContract { .. }));
}

#[test]
fn observe_many_safe_then_evaluate_flips_deny_to_allow() {
    let mut r = router_with_defaults();
    for _ in 0..30 {
        r.observe(SafetyAction::CapabilityRevocation, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::CapabilityRevocation, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(result.verdict.is_allow());
}

#[test]
fn observe_many_unsafe_reinforces_deny() {
    let mut r = router_with_defaults();
    for _ in 0..20 {
        r.observe(SafetyAction::ExtensionQuarantine, 1).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(matches!(result.verdict, SafetyVerdict::Deny { .. }));
}

// ---------------------------------------------------------------------------
// 12. Fallback triggering
// ---------------------------------------------------------------------------

#[test]
fn low_calibration_triggers_fallback() {
    let mut r = router_with_defaults();
    // Shift to safe so normal eval would allow
    for _ in 0..30 {
        r.observe(SafetyAction::BudgetOverride, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request_with_calibration(SafetyAction::BudgetOverride, 1, 5_000); // 0.50
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        matches!(result.verdict, SafetyVerdict::Fallback { .. }),
        "expected fallback on low calibration, got {:?}",
        result.verdict
    );
    assert!(result.fallback_active);
}

#[test]
fn high_e_process_triggers_fallback() {
    let mut r = router_with_defaults();
    for _ in 0..30 {
        r.observe(SafetyAction::PrivilegeEscalation, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request_with_eprocess(SafetyAction::PrivilegeEscalation, 1, 25_000); // 25.0
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        matches!(result.verdict, SafetyVerdict::Fallback { .. }),
        "expected fallback on high e-process, got {:?}",
        result.verdict
    );
}

#[test]
fn wide_ci_triggers_fallback() {
    let mut r = router_with_defaults();
    for _ in 0..30 {
        r.observe(SafetyAction::CrossExtensionShare, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request_with_ci_width(SafetyAction::CrossExtensionShare, 1, 700); // 0.7 > threshold 0.5
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        matches!(result.verdict, SafetyVerdict::Fallback { .. }),
        "expected fallback on wide CI, got {:?}",
        result.verdict
    );
}

#[test]
fn fallback_increments_fallback_count() {
    let mut r = router_with_defaults();
    for _ in 0..30 {
        r.observe(SafetyAction::BudgetOverride, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request_with_calibration(SafetyAction::BudgetOverride, 1, 4_000);
    r.evaluate(&mut cx, &req).unwrap();
    assert_eq!(r.fallback_count(), 1);
}

#[test]
fn fallback_reason_mentions_action_name() {
    let mut r = router_with_defaults();
    for _ in 0..30 {
        r.observe(SafetyAction::ExtensionQuarantine, 0).unwrap();
    }
    let mut cx = test_cx(100);
    let req = test_request_with_calibration(SafetyAction::ExtensionQuarantine, 1, 3_000);
    let result = r.evaluate(&mut cx, &req).unwrap();
    if let SafetyVerdict::Fallback { reason } = &result.verdict {
        assert!(
            reason.contains("extension_quarantine"),
            "fallback reason '{reason}' must mention action name"
        );
    } else {
        panic!("expected fallback verdict");
    }
}

// ---------------------------------------------------------------------------
// 13. Statistics and summary
// ---------------------------------------------------------------------------

#[test]
fn decision_count_increments_on_each_evaluation() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    for i in 0..3 {
        let req = test_request(SafetyAction::ForcedTermination, i);
        r.evaluate(&mut cx, &req).unwrap();
    }
    assert_eq!(r.decision_count(), 3);
}

#[test]
fn deny_count_tracks_deny_verdicts() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    // Uniform prior -> deny
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    r.evaluate(&mut cx, &req).unwrap();
    assert!(r.deny_count() >= 1);
}

#[test]
fn results_accumulate_in_order() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let actions = [
        SafetyAction::ExtensionQuarantine,
        SafetyAction::ForcedTermination,
        SafetyAction::BudgetOverride,
    ];
    for (i, &action) in actions.iter().enumerate() {
        let req = test_request(action, i as u64);
        r.evaluate(&mut cx, &req).unwrap();
    }
    let results = r.results();
    assert_eq!(results.len(), 3);
    for (i, &action) in actions.iter().enumerate() {
        assert_eq!(results[i].action, action);
    }
}

#[test]
fn summary_by_action_aggregates_correctly() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(200);
    // Evaluate quarantine twice, termination once
    for i in 0..2 {
        let req = test_request(SafetyAction::ExtensionQuarantine, i);
        r.evaluate(&mut cx, &req).unwrap();
    }
    let req = test_request(SafetyAction::ForcedTermination, 10);
    r.evaluate(&mut cx, &req).unwrap();

    let summary = r.summary_by_action();
    assert_eq!(summary[&SafetyAction::ExtensionQuarantine].total, 2);
    assert_eq!(summary[&SafetyAction::ForcedTermination].total, 1);
    assert!(!summary.contains_key(&SafetyAction::BudgetOverride));
}

#[test]
fn summary_by_action_empty_router_returns_empty_map() {
    let r = router_with_defaults();
    let summary = r.summary_by_action();
    assert!(summary.is_empty());
}

// ---------------------------------------------------------------------------
// 14. Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn identical_inputs_produce_identical_results() {
    let run = || {
        let mut r = router_with_defaults();
        let mut cx = test_cx(100);
        let req = test_request(SafetyAction::CapabilityRevocation, 7);
        r.evaluate(&mut cx, &req).unwrap()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_across_all_action_types() {
    let run = || {
        let mut r = router_with_defaults();
        let mut cx = test_cx(200);
        let mut results = Vec::new();
        for (i, &action) in SafetyAction::all().iter().enumerate() {
            let req = test_request(action, i as u64);
            results.push(r.evaluate(&mut cx, &req).unwrap());
        }
        results
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// 15. Serde round-trips for result/request/event/error types
// ---------------------------------------------------------------------------

#[test]
fn safety_decision_request_serde_round_trip() {
    let req = test_request(SafetyAction::CrossExtensionShare, 77);
    let json = serde_json::to_string(&req).unwrap();
    let restored: SafetyDecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}

#[test]
fn safety_decision_request_with_target_serde_round_trip() {
    let mut req = test_request(SafetyAction::CrossExtensionShare, 88);
    req.target_extension_id = Some("ext-target-99".into());
    let json = serde_json::to_string(&req).unwrap();
    let restored: SafetyDecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}

#[test]
fn safety_decision_result_serde_round_trip() {
    let result = SafetyDecisionResult {
        action: SafetyAction::ForcedTermination,
        verdict: SafetyVerdict::Deny {
            reason: "test deny".into(),
        },
        extension_id: "ext-1".into(),
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        expected_loss_milli: 450,
        fallback_active: false,
        budget_consumed_ms: 2,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: SafetyDecisionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn safety_decision_event_serde_round_trip() {
    let event = SafetyDecisionEvent {
        seq: 42,
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "safety_decision_router".into(),
        event: "evaluate".into(),
        outcome: "deny".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: SafetyDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn safety_decision_event_with_error_code_serde_round_trip() {
    let event = SafetyDecisionEvent {
        seq: 1,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "evaluate".into(),
        outcome: "no_contract".into(),
        error_code: Some("no_contract".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: SafetyDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn safety_router_error_budget_exhausted_serde_round_trip() {
    let e = SafetyRouterError::BudgetExhausted {
        action: SafetyAction::BudgetOverride,
        requested_ms: 2,
        remaining_ms: 1,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: SafetyRouterError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn safety_router_error_no_contract_serde_round_trip() {
    let e = SafetyRouterError::NoContract {
        action: SafetyAction::ForcedTermination,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: SafetyRouterError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn safety_router_error_invalid_action_index_serde_round_trip() {
    let e = SafetyRouterError::InvalidActionIndex {
        action: SafetyAction::PrivilegeEscalation,
        index: 5,
        max: 2,
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: SafetyRouterError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn action_summary_serde_round_trip() {
    let s = ActionSummary {
        total: 100,
        allows: 30,
        denials: 50,
        fallbacks: 20,
    };
    let json = serde_json::to_string(&s).unwrap();
    let restored: ActionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn action_summary_default_is_all_zeros() {
    let s = ActionSummary::default();
    assert_eq!(s.total, 0);
    assert_eq!(s.allows, 0);
    assert_eq!(s.denials, 0);
    assert_eq!(s.fallbacks, 0);
}

// ---------------------------------------------------------------------------
// 16. SafetyRouterError Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_budget_exhausted_contains_action_and_amounts() {
    let e = SafetyRouterError::BudgetExhausted {
        action: SafetyAction::ExtensionQuarantine,
        requested_ms: 2,
        remaining_ms: 1,
    };
    let s = e.to_string();
    assert!(s.contains("budget exhausted"));
    assert!(s.contains("extension_quarantine"));
    assert!(s.contains("2"));
    assert!(s.contains("1"));
}

#[test]
fn error_display_no_contract_contains_action() {
    let e = SafetyRouterError::NoContract {
        action: SafetyAction::ForcedTermination,
    };
    let s = e.to_string();
    assert!(s.contains("no decision contract"));
    assert!(s.contains("forced_termination"));
}

#[test]
fn error_display_invalid_action_index() {
    let e = SafetyRouterError::InvalidActionIndex {
        action: SafetyAction::PrivilegeEscalation,
        index: 5,
        max: 2,
    };
    let s = e.to_string();
    assert!(s.contains("invalid action index"));
    assert!(s.contains("5"));
    assert!(s.contains("2"));
}

#[test]
fn safety_router_error_is_std_error() {
    let e = SafetyRouterError::NoContract {
        action: SafetyAction::BudgetOverride,
    };
    let _err_ref: &dyn std::error::Error = &e;
}

// ---------------------------------------------------------------------------
// 17. Cross-action isolation
// ---------------------------------------------------------------------------

#[test]
fn observe_on_one_action_does_not_affect_another() {
    let mut r = router_with_defaults();
    // Observe many safe for quarantine
    for _ in 0..30 {
        r.observe(SafetyAction::ExtensionQuarantine, 0).unwrap();
    }
    // ForcedTermination posterior should still be uniform
    let ft_probs = r
        .posterior(SafetyAction::ForcedTermination)
        .unwrap()
        .probs()
        .to_vec();
    assert!(
        (ft_probs[0] - 0.5).abs() < 1e-9,
        "ForcedTermination posterior must remain uniform"
    );

    // Quarantine should be shifted
    let eq_probs = r
        .posterior(SafetyAction::ExtensionQuarantine)
        .unwrap()
        .probs()
        .to_vec();
    assert!(eq_probs[0] > 0.9, "Quarantine P(safe) must be > 0.9");
}

// ---------------------------------------------------------------------------
// 18. Custom contract integration
// ---------------------------------------------------------------------------

#[test]
fn custom_symmetric_contract_with_uniform_prior_allows() {
    let mut r = SafetyDecisionRouter::new();
    let contract = SafetyContract::new(
        SafetyAction::CrossExtensionShare,
        0.5,
        0.5,
        FallbackPolicy::default(),
    );
    r.register(contract);
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::CrossExtensionShare, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    assert!(
        result.verdict.is_allow(),
        "symmetric loss with uniform prior must allow"
    );
}

// ---------------------------------------------------------------------------
// 19. Multiple-evaluation workflows
// ---------------------------------------------------------------------------

#[test]
fn sequence_of_evaluations_produces_increasing_sequence_numbers() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(200);
    let mut last_seq = 0;
    for i in 0..5 {
        let req = test_request(SafetyAction::ExtensionQuarantine, i);
        let result = r.evaluate(&mut cx, &req).unwrap();
        assert!(
            result.sequence_number > last_seq,
            "sequence must be monotonically increasing"
        );
        last_seq = result.sequence_number;
    }
}

#[test]
fn mixed_actions_all_tracked_in_results() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(200);
    let actions = [
        SafetyAction::ExtensionQuarantine,
        SafetyAction::CapabilityRevocation,
        SafetyAction::ForcedTermination,
        SafetyAction::PrivilegeEscalation,
    ];
    for (i, &action) in actions.iter().enumerate() {
        let req = test_request(action, i as u64);
        r.evaluate(&mut cx, &req).unwrap();
    }
    assert_eq!(r.results().len(), 4);
    assert_eq!(r.decision_count(), 4);
}

// ---------------------------------------------------------------------------
// 20. Expected loss is recorded
// ---------------------------------------------------------------------------

#[test]
fn expected_loss_milli_is_recorded_in_result() {
    let mut r = router_with_defaults();
    let mut cx = test_cx(100);
    let req = test_request(SafetyAction::ExtensionQuarantine, 1);
    let result = r.evaluate(&mut cx, &req).unwrap();
    // expected_loss_milli should be a reasonable positive value (not zero, not huge)
    assert!(
        result.expected_loss_milli > 0 && result.expected_loss_milli < 500,
        "expected_loss_milli={} should be in (0, 500) range",
        result.expected_loss_milli
    );
}
