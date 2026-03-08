#![forbid(unsafe_code)]
//! Integration tests for the `cx_threading` module.
//!
//! Exercises every public type, enum variant, method, constant, error path,
//! receipt field, serde round-trip, and cross-concern scenario from outside
//! the crate boundary.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::control_plane::ContextAdapter;
use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::cx_threading::{
    CxThreadedEvent, CxThreadedGateway, CxThreadingError, EffectAuditLog, EffectCategory,
    HOSTCALL_BUDGET_COST_MS, HostcallDescriptor, HostcallReceipt, HostcallRegistration,
    LIFECYCLE_TRANSITION_BUDGET_COST_MS, LifecyclePhase, LifecycleReceipt,
    POLICY_CHECK_BUDGET_COST_MS, PolicyCheckDescriptor, PolicyCheckResult, PolicyVerdict,
    TELEMETRY_EMIT_BUDGET_COST_MS, TelemetryDescriptor, TelemetryLevel, TelemetryReceipt,
    run_full_lifecycle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_cx(seed: u64, budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(seed), MockBudget::new(budget_ms))
}

fn make_gateway(seed: u64, budget_ms: u64) -> CxThreadedGateway<MockCx> {
    CxThreadedGateway::new(make_cx(seed, budget_ms))
}

fn hostcall(name: &str) -> HostcallDescriptor {
    HostcallDescriptor::new(name, "integ-ext-001")
}

fn policy_check(name: &str) -> PolicyCheckDescriptor {
    PolicyCheckDescriptor::new(name, "integ-policy-001", "integ-scope")
}

fn telemetry(event_name: &str) -> TelemetryDescriptor {
    TelemetryDescriptor::new("integ-emitter", event_name, TelemetryLevel::Info)
}

/// Drive gateway through Unloaded -> Loaded -> Running.
fn advance_to_running(gw: &mut CxThreadedGateway<MockCx>) {
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
}

// ===========================================================================
// Section 1 -- Constants
// ===========================================================================

#[test]
fn constants_are_positive_and_ordered() {
    const { assert!(HOSTCALL_BUDGET_COST_MS > 0) };
    const { assert!(POLICY_CHECK_BUDGET_COST_MS > 0) };
    const { assert!(LIFECYCLE_TRANSITION_BUDGET_COST_MS > 0) };
    const { assert!(TELEMETRY_EMIT_BUDGET_COST_MS > 0) };
    // Lifecycle transitions are the most expensive
    const { assert!(LIFECYCLE_TRANSITION_BUDGET_COST_MS >= HOSTCALL_BUDGET_COST_MS) };
    const { assert!(LIFECYCLE_TRANSITION_BUDGET_COST_MS >= POLICY_CHECK_BUDGET_COST_MS) };
    const { assert!(LIFECYCLE_TRANSITION_BUDGET_COST_MS >= TELEMETRY_EMIT_BUDGET_COST_MS) };
}

// ===========================================================================
// Section 2 -- EffectCategory
// ===========================================================================

#[test]
fn effect_category_budget_cost_ms_matches_constants() {
    assert_eq!(
        EffectCategory::Hostcall.budget_cost_ms(),
        HOSTCALL_BUDGET_COST_MS
    );
    assert_eq!(
        EffectCategory::PolicyCheck.budget_cost_ms(),
        POLICY_CHECK_BUDGET_COST_MS
    );
    assert_eq!(
        EffectCategory::LifecycleTransition.budget_cost_ms(),
        LIFECYCLE_TRANSITION_BUDGET_COST_MS
    );
    assert_eq!(
        EffectCategory::TelemetryEmit.budget_cost_ms(),
        TELEMETRY_EMIT_BUDGET_COST_MS
    );
}

#[test]
fn effect_category_display_all_distinct() {
    let all = [
        EffectCategory::Hostcall,
        EffectCategory::PolicyCheck,
        EffectCategory::LifecycleTransition,
        EffectCategory::TelemetryEmit,
    ];
    let mut set = BTreeSet::new();
    for c in &all {
        let s = c.to_string();
        assert!(!s.is_empty());
        set.insert(s);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn effect_category_ord_is_stable() {
    assert!(EffectCategory::Hostcall < EffectCategory::PolicyCheck);
    assert!(EffectCategory::PolicyCheck < EffectCategory::LifecycleTransition);
    assert!(EffectCategory::LifecycleTransition < EffectCategory::TelemetryEmit);
}

#[test]
fn effect_category_serde_roundtrip() {
    for c in [
        EffectCategory::Hostcall,
        EffectCategory::PolicyCheck,
        EffectCategory::LifecycleTransition,
        EffectCategory::TelemetryEmit,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: EffectCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ===========================================================================
// Section 3 -- LifecyclePhase
// ===========================================================================

#[test]
fn lifecycle_phase_is_terminal_only_for_terminated() {
    let non_terminal = [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
    ];
    for p in &non_terminal {
        assert!(!p.is_terminal(), "{p} should not be terminal");
    }
    assert!(LifecyclePhase::Terminated.is_terminal());
}

#[test]
fn lifecycle_phase_display_all_distinct() {
    let all = [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ];
    let mut set = BTreeSet::new();
    for p in &all {
        set.insert(p.to_string());
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn lifecycle_phase_display_values() {
    assert_eq!(LifecyclePhase::Unloaded.to_string(), "unloaded");
    assert_eq!(LifecyclePhase::Loaded.to_string(), "loaded");
    assert_eq!(LifecyclePhase::Running.to_string(), "running");
    assert_eq!(LifecyclePhase::Suspended.to_string(), "suspended");
    assert_eq!(LifecyclePhase::Quarantined.to_string(), "quarantined");
    assert_eq!(LifecyclePhase::Unloading.to_string(), "unloading");
    assert_eq!(LifecyclePhase::Terminated.to_string(), "terminated");
}

#[test]
fn lifecycle_phase_ord_monotonic() {
    assert!(LifecyclePhase::Unloaded < LifecyclePhase::Loaded);
    assert!(LifecyclePhase::Loaded < LifecyclePhase::Running);
    assert!(LifecyclePhase::Running < LifecyclePhase::Suspended);
    assert!(LifecyclePhase::Suspended < LifecyclePhase::Quarantined);
    assert!(LifecyclePhase::Quarantined < LifecyclePhase::Unloading);
    assert!(LifecyclePhase::Unloading < LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_phase_serde_roundtrip() {
    for p in [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: LifecyclePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

// ===========================================================================
// Section 4 -- TelemetryLevel
// ===========================================================================

#[test]
fn telemetry_level_display_values() {
    assert_eq!(TelemetryLevel::Debug.to_string(), "debug");
    assert_eq!(TelemetryLevel::Info.to_string(), "info");
    assert_eq!(TelemetryLevel::Warn.to_string(), "warn");
    assert_eq!(TelemetryLevel::Error.to_string(), "error");
}

#[test]
fn telemetry_level_ord_severity() {
    assert!(TelemetryLevel::Debug < TelemetryLevel::Info);
    assert!(TelemetryLevel::Info < TelemetryLevel::Warn);
    assert!(TelemetryLevel::Warn < TelemetryLevel::Error);
}

#[test]
fn telemetry_level_serde_roundtrip() {
    for l in [
        TelemetryLevel::Debug,
        TelemetryLevel::Info,
        TelemetryLevel::Warn,
        TelemetryLevel::Error,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let back: TelemetryLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }
}

// ===========================================================================
// Section 5 -- PolicyVerdict
// ===========================================================================

#[test]
fn policy_verdict_display() {
    assert_eq!(PolicyVerdict::Allow.to_string(), "allow");
    let deny = PolicyVerdict::Deny {
        reason: "rate limit".into(),
    };
    assert!(deny.to_string().contains("deny"));
    assert!(deny.to_string().contains("rate limit"));
    let esc = PolicyVerdict::Escalate {
        reason: "human review".into(),
    };
    assert!(esc.to_string().contains("escalate"));
    assert!(esc.to_string().contains("human review"));
}

#[test]
fn policy_verdict_serde_roundtrip() {
    let variants = [
        PolicyVerdict::Allow,
        PolicyVerdict::Deny {
            reason: "blocked".into(),
        },
        PolicyVerdict::Escalate {
            reason: "needs review".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: PolicyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Section 6 -- CxThreadingError
// ===========================================================================

#[test]
fn error_codes_are_stable_and_unique() {
    let errors = vec![
        CxThreadingError::BudgetExhausted {
            operation: "op".into(),
            requested_ms: 10,
            remaining_ms: 0,
        },
        CxThreadingError::HostcallRejected {
            hostcall_name: "hc".into(),
            reason: "r".into(),
        },
        CxThreadingError::PolicyDenied {
            check_name: "chk".into(),
            verdict: "v".into(),
        },
        CxThreadingError::LifecycleViolation {
            from: LifecyclePhase::Running,
            to: LifecyclePhase::Loaded,
            reason: "r".into(),
        },
        CxThreadingError::TelemetryFailed {
            emitter: "e".into(),
            reason: "r".into(),
        },
        CxThreadingError::Cancelled {
            operation: "o".into(),
        },
    ];
    let mut codes = BTreeSet::new();
    for e in &errors {
        codes.insert(e.error_code());
    }
    assert_eq!(codes.len(), 6, "all error codes must be unique");
}

#[test]
fn error_display_contains_key_fields() {
    let be = CxThreadingError::BudgetExhausted {
        operation: "fs_read".into(),
        requested_ms: 10,
        remaining_ms: 3,
    };
    let s = be.to_string();
    assert!(s.contains("fs_read"));
    assert!(s.contains("10"));
    assert!(s.contains("3"));

    let hr = CxThreadingError::HostcallRejected {
        hostcall_name: "net_out".into(),
        reason: "disabled".into(),
    };
    assert!(hr.to_string().contains("net_out"));
    assert!(hr.to_string().contains("disabled"));

    let pd = CxThreadingError::PolicyDenied {
        check_name: "auth".into(),
        verdict: "denied".into(),
    };
    assert!(pd.to_string().contains("auth"));

    let lv = CxThreadingError::LifecycleViolation {
        from: LifecyclePhase::Unloaded,
        to: LifecyclePhase::Running,
        reason: "skip".into(),
    };
    assert!(lv.to_string().contains("unloaded"));
    assert!(lv.to_string().contains("running"));

    let tf = CxThreadingError::TelemetryFailed {
        emitter: "span".into(),
        reason: "full".into(),
    };
    assert!(tf.to_string().contains("span"));

    let ca = CxThreadingError::Cancelled {
        operation: "gc".into(),
    };
    assert!(ca.to_string().contains("gc"));
}

#[test]
fn error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CxThreadingError::Cancelled {
        operation: "x".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors = vec![
        CxThreadingError::BudgetExhausted {
            operation: "op".into(),
            requested_ms: 5,
            remaining_ms: 2,
        },
        CxThreadingError::HostcallRejected {
            hostcall_name: "hc".into(),
            reason: "disabled".into(),
        },
        CxThreadingError::PolicyDenied {
            check_name: "chk".into(),
            verdict: "deny".into(),
        },
        CxThreadingError::LifecycleViolation {
            from: LifecyclePhase::Loaded,
            to: LifecyclePhase::Terminated,
            reason: "invalid".into(),
        },
        CxThreadingError::TelemetryFailed {
            emitter: "em".into(),
            reason: "sink full".into(),
        },
        CxThreadingError::Cancelled {
            operation: "op".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: CxThreadingError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// Section 7 -- Descriptors
// ===========================================================================

#[test]
fn hostcall_descriptor_new_and_with_budget_cost() {
    let desc = HostcallDescriptor::new("fs_read", "ext-001");
    assert_eq!(desc.name, "fs_read");
    assert_eq!(desc.extension_id, "ext-001");
    assert!(desc.budget_cost_override_ms.is_none());

    let desc2 = desc.with_budget_cost(42);
    assert_eq!(desc2.budget_cost_override_ms, Some(42));
    assert_eq!(desc2.name, "fs_read");
}

#[test]
fn hostcall_descriptor_serde_roundtrip() {
    let desc = HostcallDescriptor::new("kv_get", "ext-002").with_budget_cost(10);
    let json = serde_json::to_string(&desc).unwrap();
    let back: HostcallDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

#[test]
fn policy_check_descriptor_construction_and_serde() {
    let desc = PolicyCheckDescriptor::new("pre_call", "policy-A", "scope-X");
    assert_eq!(desc.check_name, "pre_call");
    assert_eq!(desc.policy_id, "policy-A");
    assert_eq!(desc.scope, "scope-X");

    let json = serde_json::to_string(&desc).unwrap();
    let back: PolicyCheckDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

#[test]
fn telemetry_descriptor_construction_and_serde() {
    let desc = TelemetryDescriptor::new("em", "evt", TelemetryLevel::Error);
    assert_eq!(desc.emitter, "em");
    assert_eq!(desc.event_name, "evt");
    assert_eq!(desc.level, TelemetryLevel::Error);

    let json = serde_json::to_string(&desc).unwrap();
    let back: TelemetryDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

// ===========================================================================
// Section 8 -- Gateway creation and accessors
// ===========================================================================

#[test]
fn gateway_starts_in_unloaded_with_zero_counters() {
    let gw = make_gateway(1, 500);
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
    assert_eq!(gw.hostcall_count(), 0);
    assert_eq!(gw.policy_check_count(), 0);
    assert_eq!(gw.lifecycle_transition_count(), 0);
    assert_eq!(gw.telemetry_count(), 0);
    assert!(gw.events().is_empty());
}

#[test]
fn gateway_cx_accessor_returns_correct_trace_id() {
    let seed = 42;
    let gw = make_gateway(seed, 500);
    let expected_tid = trace_id_from_seed(seed);
    assert_eq!(gw.cx().trace_id(), expected_tid);
}

#[test]
fn gateway_cx_mut_can_consume_budget_directly() {
    let mut gw = make_gateway(1, 100);
    gw.cx_mut().consume_budget(10).unwrap();
    assert_eq!(gw.cx().budget().remaining_ms(), 90);
}

#[test]
fn gateway_drain_events_empties_and_returns() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(gw.events().len(), 1);

    let drained = gw.drain_events();
    assert_eq!(drained.len(), 1);
    assert!(gw.events().is_empty());
}

// ===========================================================================
// Section 9 -- Hostcall gateway
// ===========================================================================

#[test]
fn hostcall_dispatch_success_returns_receipt() {
    let mut gw = make_gateway(10, 100);
    gw.register_hostcall("fs_read", None);
    let receipt = gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    assert_eq!(receipt.hostcall_name, "fs_read");
    assert_eq!(receipt.extension_id, "integ-ext-001");
    assert_eq!(receipt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(gw.hostcall_count(), 1);
}

#[test]
fn hostcall_dispatch_unregistered_fails() {
    let mut gw = make_gateway(11, 100);
    let err = gw
        .dispatch_hostcall(&hostcall("not_registered"))
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::HostcallRejected { .. }));
    assert_eq!(err.error_code(), "cx_hostcall_rejected");
    // Event should still be emitted
    assert_eq!(gw.events().len(), 1);
    assert_eq!(gw.events()[0].outcome, "rejected");
}

#[test]
fn hostcall_dispatch_disabled_fails() {
    let mut gw = make_gateway(12, 100);
    gw.register_hostcall("dangerous", None);
    assert!(gw.disable_hostcall("dangerous"));
    let err = gw.dispatch_hostcall(&hostcall("dangerous")).unwrap_err();
    assert!(matches!(err, CxThreadingError::HostcallRejected { .. }));
    assert!(err.to_string().contains("disabled"));
}

#[test]
fn disable_nonexistent_hostcall_returns_false() {
    let mut gw = make_gateway(13, 100);
    assert!(!gw.disable_hostcall("nonexistent"));
}

#[test]
fn hostcall_budget_cost_priority_descriptor_over_registration() {
    // Registration has override=10, descriptor has override=5.
    // Descriptor override takes priority.
    let mut gw = make_gateway(14, 100);
    gw.register_hostcall("op", Some(10));
    let desc = hostcall("op").with_budget_cost(5);
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 5);
    assert_eq!(gw.cx().budget().remaining_ms(), 95);
}

#[test]
fn hostcall_budget_cost_falls_back_to_registration_override() {
    // Registration has override=10, descriptor has no override.
    let mut gw = make_gateway(15, 100);
    gw.register_hostcall("op", Some(10));
    let desc = hostcall("op"); // no budget_cost_override_ms
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 10);
}

#[test]
fn hostcall_budget_cost_falls_back_to_global_default() {
    // Neither registration nor descriptor has override.
    let mut gw = make_gateway(16, 100);
    gw.register_hostcall("op", None);
    let desc = hostcall("op");
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
}

#[test]
fn hostcall_dispatch_budget_exhaustion() {
    let mut gw = make_gateway(17, 0);
    gw.register_hostcall("op", None);
    let err = gw.dispatch_hostcall(&hostcall("op")).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    assert_eq!(gw.hostcall_count(), 0);
}

#[test]
fn hostcall_multiple_dispatches_increment_sequence() {
    let mut gw = make_gateway(18, 100);
    for i in 0..5 {
        let name = format!("op_{i}");
        gw.register_hostcall(&name, None);
    }
    for i in 0..5 {
        let name = format!("op_{i}");
        let receipt = gw.dispatch_hostcall(&hostcall(&name)).unwrap();
        assert_eq!(receipt.sequence_number, (i + 1) as u64);
    }
    assert_eq!(gw.hostcall_count(), 5);
    assert_eq!(
        gw.cx().budget().remaining_ms(),
        100 - 5 * HOSTCALL_BUDGET_COST_MS
    );
}

#[test]
fn hostcall_event_fields_are_correct() {
    let mut gw = make_gateway(19, 100);
    gw.register_hostcall("kv_get", None);
    gw.dispatch_hostcall(&hostcall("kv_get")).unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::Hostcall);
    assert_eq!(evt.operation, "kv_get");
    assert_eq!(evt.outcome, "dispatched");
    assert!(evt.error_code.is_none());
    assert_eq!(evt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
}

// ===========================================================================
// Section 10 -- Policy check gateway
// ===========================================================================

#[test]
fn policy_check_allow_returns_result() {
    let mut gw = make_gateway(20, 100);
    let desc = policy_check("pre_call");
    let result = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(result.check_name, "pre_call");
    assert_eq!(result.policy_id, "integ-policy-001");
    assert_eq!(result.verdict, PolicyVerdict::Allow);
    assert_eq!(result.budget_consumed_ms, POLICY_CHECK_BUDGET_COST_MS);
    assert_eq!(result.sequence_number, 1);
    assert_eq!(gw.policy_check_count(), 1);
}

#[test]
fn policy_check_deny_returns_error_but_consumes_budget() {
    let mut gw = make_gateway(21, 100);
    let err = gw
        .evaluate_policy_check(&policy_check("limit"), |_| PolicyVerdict::Deny {
            reason: "over limit".into(),
        })
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::PolicyDenied { .. }));
    assert_eq!(err.error_code(), "cx_policy_denied");
    // Budget consumed even on deny
    assert_eq!(
        gw.cx().budget().remaining_ms(),
        100 - POLICY_CHECK_BUDGET_COST_MS
    );
    // Policy check count still incremented
    assert_eq!(gw.policy_check_count(), 1);
}

#[test]
fn policy_check_escalate_returns_ok() {
    let mut gw = make_gateway(22, 100);
    let result = gw
        .evaluate_policy_check(&policy_check("esc"), |_| PolicyVerdict::Escalate {
            reason: "review".into(),
        })
        .unwrap();
    assert!(matches!(result.verdict, PolicyVerdict::Escalate { .. }));
}

#[test]
fn policy_check_budget_exhaustion() {
    let mut gw = make_gateway(23, 1); // 1ms < POLICY_CHECK_BUDGET_COST_MS (2ms)
    let err = gw
        .evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn policy_check_closure_receives_descriptor() {
    let mut gw = make_gateway(24, 100);
    let desc = policy_check("special");
    let result = gw
        .evaluate_policy_check(&desc, |d| {
            if d.check_name == "special" {
                PolicyVerdict::Allow
            } else {
                PolicyVerdict::Deny {
                    reason: "unexpected".into(),
                }
            }
        })
        .unwrap();
    assert_eq!(result.verdict, PolicyVerdict::Allow);
}

#[test]
fn policy_check_event_outcome_matches_verdict() {
    let mut gw = make_gateway(25, 100);
    gw.evaluate_policy_check(&policy_check("a"), |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(gw.events()[0].outcome, "allow");

    // deny also emits event (before returning error)
    let _ = gw.evaluate_policy_check(&policy_check("b"), |_| PolicyVerdict::Deny {
        reason: "no".into(),
    });
    assert_eq!(gw.events()[1].outcome, "deny");

    gw.evaluate_policy_check(&policy_check("c"), |_| PolicyVerdict::Escalate {
        reason: "up".into(),
    })
    .unwrap();
    assert_eq!(gw.events()[2].outcome, "escalate");
}

// ===========================================================================
// Section 11 -- Lifecycle transition gateway
// ===========================================================================

#[test]
fn lifecycle_unloaded_to_loaded() {
    let mut gw = make_gateway(30, 100);
    let receipt = gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(receipt.from, LifecyclePhase::Unloaded);
    assert_eq!(receipt.to, LifecyclePhase::Loaded);
    assert_eq!(
        receipt.budget_consumed_ms,
        LIFECYCLE_TRANSITION_BUDGET_COST_MS
    );
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Loaded);
}

#[test]
fn lifecycle_full_happy_path() {
    let mut gw = make_gateway(31, 200);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
    assert_eq!(gw.lifecycle_transition_count(), 4);
    assert_eq!(
        gw.cx().budget().remaining_ms(),
        200 - 4 * LIFECYCLE_TRANSITION_BUDGET_COST_MS,
    );
}

#[test]
fn lifecycle_suspend_resume_cycle() {
    let mut gw = make_gateway(32, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Running);
}

#[test]
fn lifecycle_quarantine_then_unload() {
    let mut gw = make_gateway(33, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Quarantined)
        .unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_quarantine_then_terminate_directly() {
    let mut gw = make_gateway(34, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Quarantined)
        .unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_invalid_transition_rejected() {
    let mut gw = make_gateway(35, 200);
    // Cannot go directly from Unloaded to Running
    let err = gw
        .transition_lifecycle(LifecyclePhase::Running)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
}

#[test]
fn lifecycle_terminal_blocks_all_further_transitions() {
    let mut gw = make_gateway(36, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    // Try every possible target
    for target in [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ] {
        let err = gw.transition_lifecycle(target).unwrap_err();
        assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
        assert!(err.to_string().contains("terminal"));
    }
}

#[test]
fn lifecycle_budget_exhaustion_does_not_change_phase() {
    let mut gw = make_gateway(37, 2);
    // LIFECYCLE_TRANSITION_BUDGET_COST_MS = 3, only have 2
    let err = gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
}

#[test]
fn lifecycle_loaded_to_unloading_valid() {
    let mut gw = make_gateway(38, 200);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloading);
}

#[test]
fn lifecycle_loaded_to_terminated_valid() {
    let mut gw = make_gateway(39, 200);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_suspended_to_terminated_valid() {
    let mut gw = make_gateway(40, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_suspended_to_unloading_valid() {
    let mut gw = make_gateway(41, 200);
    advance_to_running(&mut gw);
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloading);
}

// ===========================================================================
// Section 12 -- Telemetry emission gateway
// ===========================================================================

#[test]
fn telemetry_emit_success_returns_receipt() {
    let mut gw = make_gateway(50, 100);
    let desc = TelemetryDescriptor::new("my-em", "metric_flush", TelemetryLevel::Warn);
    let receipt = gw.emit_telemetry(&desc, "payload-xyz").unwrap();
    assert_eq!(receipt.emitter, "my-em");
    assert_eq!(receipt.event_name, "metric_flush");
    assert_eq!(receipt.level, TelemetryLevel::Warn);
    assert_eq!(receipt.payload_len, "payload-xyz".len());
    assert_eq!(receipt.budget_consumed_ms, TELEMETRY_EMIT_BUDGET_COST_MS);
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(gw.telemetry_count(), 1);
}

#[test]
fn telemetry_emit_empty_payload() {
    let mut gw = make_gateway(51, 100);
    let receipt = gw.emit_telemetry(&telemetry("empty_evt"), "").unwrap();
    assert_eq!(receipt.payload_len, 0);
}

#[test]
fn telemetry_emit_budget_exhaustion() {
    let mut gw = make_gateway(52, 0);
    let err = gw
        .emit_telemetry(&telemetry("should_fail"), "data")
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    assert_eq!(gw.telemetry_count(), 0);
}

#[test]
fn telemetry_emit_event_fields() {
    let mut gw = make_gateway(53, 100);
    gw.emit_telemetry(&telemetry("evidence_log"), "data")
        .unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::TelemetryEmit);
    assert_eq!(evt.operation, "evidence_log");
    assert_eq!(evt.outcome, "emitted");
    assert!(evt.error_code.is_none());
}

// ===========================================================================
// Section 13 -- Audit log
// ===========================================================================

#[test]
fn audit_log_reflects_all_operations() {
    let mut gw = make_gateway(60, 500);
    advance_to_running(&mut gw);
    gw.register_hostcall("fs_read", None);
    gw.register_hostcall("kv_get", None);
    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    gw.dispatch_hostcall(&hostcall("kv_get")).unwrap();
    gw.evaluate_policy_check(&policy_check("limit"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    let log = gw.audit_log();
    assert_eq!(log.hostcall_count, 2);
    assert_eq!(log.policy_check_count, 1);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.telemetry_count, 1);
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    // 4 lifecycle + 2 hostcall + 1 policy + 1 telemetry = 8
    assert_eq!(log.events.len(), 8);
    assert_eq!(log.total_events, 8);
}

#[test]
fn audit_log_total_budget_consumed_excludes_errors() {
    let mut gw = make_gateway(61, 100);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    // Attempt unregistered -> error event with 0 cost
    let _ = gw.dispatch_hostcall(&hostcall("not_registered"));

    let log = gw.audit_log();
    // Only the successful hostcall cost should be counted
    assert_eq!(log.total_budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
}

#[test]
fn audit_log_trace_id_consistency() {
    let seed = 62;
    let mut gw = make_gateway(seed, 100);
    let tid = trace_id_from_seed(seed).to_string();
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    let log = gw.audit_log();
    assert_eq!(log.trace_id, tid);
    for evt in &log.events {
        assert_eq!(evt.trace_id, tid);
    }
}

// ===========================================================================
// Section 14 -- run_full_lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_happy_path() {
    let mut gw = make_gateway(70, 500);
    gw.register_hostcall("fs_read", None);
    gw.register_hostcall("kv_get", Some(2));

    let hostcalls = vec![hostcall("fs_read"), hostcall("kv_get")];
    let checks = vec![policy_check("pre"), policy_check("post")];
    let tels = vec![telemetry("evidence"), telemetry("metric")];

    let log = run_full_lifecycle(&mut gw, &hostcalls, &checks, &tels).unwrap();
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    assert_eq!(log.hostcall_count, 2);
    assert_eq!(log.policy_check_count, 2);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.telemetry_count, 2);
}

#[test]
fn full_lifecycle_empty_operations() {
    let mut gw = make_gateway(71, 500);
    let log = run_full_lifecycle(&mut gw, &[], &[], &[]).unwrap();
    assert_eq!(log.hostcall_count, 0);
    assert_eq!(log.policy_check_count, 0);
    assert_eq!(log.telemetry_count, 0);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
}

#[test]
fn full_lifecycle_budget_exhaustion_mid_flight() {
    // Budget = 8: load(3) + run(3) = 6, leaves 2. First hostcall needs 1, second needs 1,
    // third needs 1 but only 0 remaining => fail on 3rd.
    // Actually: 6 used, 2 remaining. op1(1)=7, op2(1)=8, op3(1) -> budget exhausted
    let mut gw = make_gateway(72, 8);
    gw.register_hostcall("op1", None);
    gw.register_hostcall("op2", None);
    gw.register_hostcall("op3", None);

    let hostcalls = vec![hostcall("op1"), hostcall("op2"), hostcall("op3")];
    let err = run_full_lifecycle(&mut gw, &hostcalls, &[], &[]).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

// ===========================================================================
// Section 15 -- Receipt serde round-trips
// ===========================================================================

#[test]
fn hostcall_receipt_serde_roundtrip() {
    let receipt = HostcallReceipt {
        hostcall_name: "kv_get".into(),
        extension_id: "ext-001".into(),
        trace_id: "trace-001".into(),
        budget_consumed_ms: 1,
        sequence_number: 5,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: HostcallReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn policy_check_result_serde_roundtrip() {
    let result = PolicyCheckResult {
        check_name: "pre_call".into(),
        policy_id: "pol-1".into(),
        verdict: PolicyVerdict::Allow,
        trace_id: "t-1".into(),
        budget_consumed_ms: 2,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: PolicyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn lifecycle_receipt_serde_roundtrip() {
    let receipt = LifecycleReceipt {
        from: LifecyclePhase::Running,
        to: LifecyclePhase::Suspended,
        trace_id: "t-2".into(),
        budget_consumed_ms: 3,
        sequence_number: 2,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: LifecycleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn telemetry_receipt_serde_roundtrip() {
    let receipt = TelemetryReceipt {
        emitter: "span".into(),
        event_name: "metric".into(),
        level: TelemetryLevel::Info,
        payload_len: 42,
        trace_id: "t-3".into(),
        budget_consumed_ms: 1,
        sequence_number: 3,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: TelemetryReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn cx_threaded_event_serde_roundtrip() {
    let event = CxThreadedEvent {
        trace_id: "t-001".into(),
        category: EffectCategory::Hostcall,
        component: "cx_threading".into(),
        operation: "fs_read".into(),
        outcome: "dispatched".into(),
        budget_consumed_ms: 1,
        budget_remaining_ms: 99,
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CxThreadedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn cx_threaded_event_with_error_code_serde() {
    let event = CxThreadedEvent {
        trace_id: "t-002".into(),
        category: EffectCategory::PolicyCheck,
        component: "cx_threading".into(),
        operation: "check_a".into(),
        outcome: "budget_exhausted".into(),
        budget_consumed_ms: 0,
        budget_remaining_ms: 0,
        error_code: Some("cx_budget_exhausted".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: CxThreadedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn effect_audit_log_serde_roundtrip() {
    let log = EffectAuditLog {
        trace_id: "t-003".into(),
        total_events: 2,
        hostcall_count: 1,
        policy_check_count: 1,
        lifecycle_transition_count: 0,
        telemetry_count: 0,
        total_budget_consumed_ms: 3,
        final_lifecycle_phase: LifecyclePhase::Running,
        events: vec![],
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: EffectAuditLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// ===========================================================================
// Section 16 -- HostcallRegistration
// ===========================================================================

#[test]
fn hostcall_registration_serde_roundtrip() {
    let reg = HostcallRegistration {
        name: "fs_read".into(),
        budget_cost_override_ms: Some(10),
        enabled: true,
    };
    let json = serde_json::to_string(&reg).unwrap();
    let back: HostcallRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn hostcall_registration_disabled_serde() {
    let reg = HostcallRegistration {
        name: "net_egress".into(),
        budget_cost_override_ms: None,
        enabled: false,
    };
    let json = serde_json::to_string(&reg).unwrap();
    let back: HostcallRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
    assert!(!back.enabled);
}

// ===========================================================================
// Section 17 -- Cross-concern / mixed operation scenarios
// ===========================================================================

#[test]
fn interleaved_operations_produce_correct_event_sequence() {
    let mut gw = make_gateway(80, 500);
    advance_to_running(&mut gw);
    gw.register_hostcall("op", None);

    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();

    let events = gw.events();
    // 2 lifecycle + 1 hostcall + 1 policy + 1 telemetry = 5
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].category, EffectCategory::LifecycleTransition);
    assert_eq!(events[1].category, EffectCategory::LifecycleTransition);
    assert_eq!(events[2].category, EffectCategory::Hostcall);
    assert_eq!(events[3].category, EffectCategory::PolicyCheck);
    assert_eq!(events[4].category, EffectCategory::TelemetryEmit);
}

#[test]
fn receipt_trace_ids_all_match_context() {
    let seed = 81;
    let mut gw = make_gateway(seed, 500);
    let tid = trace_id_from_seed(seed).to_string();

    advance_to_running(&mut gw);
    gw.register_hostcall("op", None);

    let hc = gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(hc.trace_id, tid);

    let pc = gw
        .evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(pc.trace_id, tid);

    let tel = gw.emit_telemetry(&telemetry("evt"), "data").unwrap();
    assert_eq!(tel.trace_id, tid);

    let lc = gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    assert_eq!(lc.trace_id, tid);
}

#[test]
fn budget_accounting_precise_full_scenario() {
    // 4 lifecycle * 3ms = 12ms
    // 3 hostcalls * 1ms = 3ms
    // 2 policy checks * 2ms = 4ms
    // 1 telemetry * 1ms = 1ms
    // Total = 20ms
    let mut gw = make_gateway(82, 20);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();

    for i in 0..3 {
        let name = format!("op_{i}");
        gw.register_hostcall(&name, None);
        gw.dispatch_hostcall(&hostcall(&name)).unwrap();
    }
    for i in 0..2 {
        gw.evaluate_policy_check(&policy_check(&format!("chk_{i}")), |_| PolicyVerdict::Allow)
            .unwrap();
    }
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    assert_eq!(gw.cx().budget().remaining_ms(), 0);
    let log = gw.audit_log();
    assert_eq!(log.total_budget_consumed_ms, 20);
}

#[test]
fn drain_events_does_not_affect_counters() {
    let mut gw = make_gateway(83, 500);
    advance_to_running(&mut gw);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();

    let count_before = gw.hostcall_count();
    let lc_before = gw.lifecycle_transition_count();
    let _ = gw.drain_events();
    assert_eq!(gw.hostcall_count(), count_before);
    assert_eq!(gw.lifecycle_transition_count(), lc_before);
    assert!(gw.events().is_empty());
}

#[test]
fn multiple_gateways_are_independent() {
    let mut gw1 = make_gateway(90, 200);
    let mut gw2 = make_gateway(91, 200);

    gw1.register_hostcall("op", None);
    gw2.register_hostcall("op", None);

    advance_to_running(&mut gw1);
    gw1.dispatch_hostcall(&hostcall("op")).unwrap();

    assert_eq!(gw1.hostcall_count(), 1);
    assert_eq!(gw2.hostcall_count(), 0);
    assert_eq!(gw2.lifecycle_phase(), LifecyclePhase::Unloaded);
}

#[test]
fn event_budget_remaining_decreases_monotonically() {
    let mut gw = make_gateway(84, 500);
    advance_to_running(&mut gw);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();

    let events = gw.events();
    for window in events.windows(2) {
        assert!(
            window[0].budget_remaining_ms >= window[1].budget_remaining_ms,
            "budget_remaining should not increase"
        );
    }
}

// ===========================================================================
// Section 18 -- Edge cases
// ===========================================================================

#[test]
fn hostcall_reregistration_overwrites_previous() {
    let mut gw = make_gateway(85, 200);
    gw.register_hostcall("op", Some(10));
    gw.register_hostcall("op", Some(20)); // re-register with different cost

    let desc = hostcall("op");
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 20);
}

#[test]
fn lifecycle_self_transition_rejected() {
    let mut gw = make_gateway(86, 200);
    // Unloaded -> Unloaded is not valid
    let err = gw
        .transition_lifecycle(LifecyclePhase::Unloaded)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));

    advance_to_running(&mut gw);
    let err = gw
        .transition_lifecycle(LifecyclePhase::Running)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
}

#[test]
fn effect_category_clone_and_copy() {
    let c = EffectCategory::Hostcall;
    let c2 = c;
    let c3 = c;
    assert_eq!(c, c2);
    assert_eq!(c, c3);
}

#[test]
fn lifecycle_phase_clone_and_copy() {
    let p = LifecyclePhase::Running;
    let p2 = p;
    let p3 = p;
    assert_eq!(p, p2);
    assert_eq!(p, p3);
}

#[test]
fn telemetry_level_clone_and_copy() {
    let l = TelemetryLevel::Warn;
    let l2 = l;
    let l3 = l;
    assert_eq!(l, l2);
    assert_eq!(l, l3);
}

#[test]
fn effect_category_hash_usable_in_btreemap() {
    let mut map = BTreeMap::new();
    map.insert(EffectCategory::Hostcall, 1);
    map.insert(EffectCategory::PolicyCheck, 2);
    map.insert(EffectCategory::LifecycleTransition, 3);
    map.insert(EffectCategory::TelemetryEmit, 4);
    assert_eq!(map.len(), 4);
    assert_eq!(map[&EffectCategory::Hostcall], 1);
}

#[test]
fn lifecycle_phase_hash_usable_in_btreemap() {
    let mut map = BTreeMap::new();
    for (i, p) in [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ]
    .iter()
    .enumerate()
    {
        map.insert(*p, i);
    }
    assert_eq!(map.len(), 7);
}

#[test]
fn telemetry_level_hash_usable_in_btreemap() {
    let mut map = BTreeMap::new();
    map.insert(TelemetryLevel::Debug, "d");
    map.insert(TelemetryLevel::Info, "i");
    map.insert(TelemetryLevel::Warn, "w");
    map.insert(TelemetryLevel::Error, "e");
    assert_eq!(map.len(), 4);
}
