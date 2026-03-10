//! Integration edge-case tests for `cx_threading` module.
//!
//! Covers: EffectCategory, LifecyclePhase, TelemetryLevel, PolicyVerdict,
//! CxThreadingError, CxThreadedGateway (hostcall/policy/lifecycle/telemetry
//! dispatch, budget accounting, event tracking, audit log), receipt types,
//! run_full_lifecycle helper, and cross-cutting integration scenarios.

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
    HostcallDescriptor::new(name, "test-ext")
}

fn policy_check(name: &str) -> PolicyCheckDescriptor {
    PolicyCheckDescriptor::new(name, "pol-001", "scope-a")
}

fn telemetry(event_name: &str) -> TelemetryDescriptor {
    TelemetryDescriptor::new("emitter", event_name, TelemetryLevel::Info)
}

// ===========================================================================
// EffectCategory
// ===========================================================================

#[test]
fn effect_category_serde_all_variants() {
    for cat in [
        EffectCategory::Hostcall,
        EffectCategory::PolicyCheck,
        EffectCategory::LifecycleTransition,
        EffectCategory::TelemetryEmit,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: EffectCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn effect_category_display_all_variants() {
    assert_eq!(EffectCategory::Hostcall.to_string(), "hostcall");
    assert_eq!(EffectCategory::PolicyCheck.to_string(), "policy_check");
    assert_eq!(
        EffectCategory::LifecycleTransition.to_string(),
        "lifecycle_transition"
    );
    assert_eq!(EffectCategory::TelemetryEmit.to_string(), "telemetry_emit");
}

#[test]
fn effect_category_budget_costs() {
    assert_eq!(EffectCategory::Hostcall.budget_cost_ms(), 1);
    assert_eq!(EffectCategory::PolicyCheck.budget_cost_ms(), 2);
    assert_eq!(EffectCategory::LifecycleTransition.budget_cost_ms(), 3);
    assert_eq!(EffectCategory::TelemetryEmit.budget_cost_ms(), 1);
}

#[test]
fn effect_category_ordering() {
    assert!(EffectCategory::Hostcall < EffectCategory::PolicyCheck);
    assert!(EffectCategory::PolicyCheck < EffectCategory::LifecycleTransition);
    assert!(EffectCategory::LifecycleTransition < EffectCategory::TelemetryEmit);
}

#[test]
fn effect_category_hash_is_implemented() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(EffectCategory::Hostcall);
    set.insert(EffectCategory::Hostcall);
    assert_eq!(set.len(), 1);
    set.insert(EffectCategory::PolicyCheck);
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// LifecyclePhase
// ===========================================================================

#[test]
fn lifecycle_phase_serde_all_variants() {
    for phase in [
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ] {
        let json = serde_json::to_string(&phase).unwrap();
        let back: LifecyclePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }
}

#[test]
fn lifecycle_phase_display_all_variants() {
    let displays = [
        (LifecyclePhase::Unloaded, "unloaded"),
        (LifecyclePhase::Loaded, "loaded"),
        (LifecyclePhase::Running, "running"),
        (LifecyclePhase::Suspended, "suspended"),
        (LifecyclePhase::Quarantined, "quarantined"),
        (LifecyclePhase::Unloading, "unloading"),
        (LifecyclePhase::Terminated, "terminated"),
    ];
    for (phase, expected) in displays {
        assert_eq!(phase.to_string(), expected);
    }
}

#[test]
fn lifecycle_phase_is_terminal_only_terminated() {
    assert!(!LifecyclePhase::Unloaded.is_terminal());
    assert!(!LifecyclePhase::Loaded.is_terminal());
    assert!(!LifecyclePhase::Running.is_terminal());
    assert!(!LifecyclePhase::Suspended.is_terminal());
    assert!(!LifecyclePhase::Quarantined.is_terminal());
    assert!(!LifecyclePhase::Unloading.is_terminal());
    assert!(LifecyclePhase::Terminated.is_terminal());
}

#[test]
fn lifecycle_phase_ordering() {
    assert!(LifecyclePhase::Unloaded < LifecyclePhase::Loaded);
    assert!(LifecyclePhase::Loaded < LifecyclePhase::Running);
    assert!(LifecyclePhase::Running < LifecyclePhase::Terminated);
}

// ===========================================================================
// TelemetryLevel
// ===========================================================================

#[test]
fn telemetry_level_serde_all_variants() {
    for level in [
        TelemetryLevel::Debug,
        TelemetryLevel::Info,
        TelemetryLevel::Warn,
        TelemetryLevel::Error,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: TelemetryLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

#[test]
fn telemetry_level_display_all_variants() {
    assert_eq!(TelemetryLevel::Debug.to_string(), "debug");
    assert_eq!(TelemetryLevel::Info.to_string(), "info");
    assert_eq!(TelemetryLevel::Warn.to_string(), "warn");
    assert_eq!(TelemetryLevel::Error.to_string(), "error");
}

#[test]
fn telemetry_level_ordering() {
    assert!(TelemetryLevel::Debug < TelemetryLevel::Info);
    assert!(TelemetryLevel::Info < TelemetryLevel::Warn);
    assert!(TelemetryLevel::Warn < TelemetryLevel::Error);
}

// ===========================================================================
// PolicyVerdict
// ===========================================================================

#[test]
fn policy_verdict_serde_all_variants() {
    let verdicts = [
        PolicyVerdict::Allow,
        PolicyVerdict::Deny {
            reason: "rate limit".to_string(),
        },
        PolicyVerdict::Escalate {
            reason: "review".to_string(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: PolicyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn policy_verdict_display() {
    assert_eq!(PolicyVerdict::Allow.to_string(), "allow");
    assert_eq!(
        PolicyVerdict::Deny {
            reason: "rate limit".to_string()
        }
        .to_string(),
        "deny: rate limit"
    );
    assert_eq!(
        PolicyVerdict::Escalate {
            reason: "review".to_string()
        }
        .to_string(),
        "escalate: review"
    );
}

// ===========================================================================
// CxThreadingError
// ===========================================================================

#[test]
fn cx_threading_error_serde_all_variants() {
    let errors = [
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
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CxThreadingError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn cx_threading_error_display_all_variants() {
    let err = CxThreadingError::BudgetExhausted {
        operation: "op_x".into(),
        requested_ms: 10,
        remaining_ms: 3,
    };
    let s = err.to_string();
    assert!(s.contains("budget exhausted"), "{s}");
    assert!(s.contains("op_x"), "{s}");
    assert!(s.contains("10"), "{s}");
    assert!(s.contains("3"), "{s}");

    let err = CxThreadingError::HostcallRejected {
        hostcall_name: "fs_write".into(),
        reason: "cap denied".into(),
    };
    let s = err.to_string();
    assert!(s.contains("fs_write"), "{s}");
    assert!(s.contains("cap denied"), "{s}");

    let err = CxThreadingError::PolicyDenied {
        check_name: "chk_a".into(),
        verdict: "deny".into(),
    };
    let s = err.to_string();
    assert!(s.contains("chk_a"), "{s}");

    let err = CxThreadingError::LifecycleViolation {
        from: LifecyclePhase::Running,
        to: LifecyclePhase::Loaded,
        reason: "bad".into(),
    };
    let s = err.to_string();
    assert!(s.contains("running"), "{s}");
    assert!(s.contains("loaded"), "{s}");

    let err = CxThreadingError::TelemetryFailed {
        emitter: "em1".into(),
        reason: "full".into(),
    };
    let s = err.to_string();
    assert!(s.contains("em1"), "{s}");

    let err = CxThreadingError::Cancelled {
        operation: "cancel_me".into(),
    };
    let s = err.to_string();
    assert!(s.contains("cancel_me"), "{s}");
}

#[test]
fn cx_threading_error_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CxThreadingError::Cancelled {
        operation: "x".into(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn cx_threading_error_codes_stable() {
    let pairs = [
        (
            CxThreadingError::BudgetExhausted {
                operation: "x".into(),
                requested_ms: 1,
                remaining_ms: 0,
            },
            "cx_budget_exhausted",
        ),
        (
            CxThreadingError::HostcallRejected {
                hostcall_name: "x".into(),
                reason: "y".into(),
            },
            "cx_hostcall_rejected",
        ),
        (
            CxThreadingError::PolicyDenied {
                check_name: "x".into(),
                verdict: "y".into(),
            },
            "cx_policy_denied",
        ),
        (
            CxThreadingError::LifecycleViolation {
                from: LifecyclePhase::Running,
                to: LifecyclePhase::Loaded,
                reason: "y".into(),
            },
            "cx_lifecycle_violation",
        ),
        (
            CxThreadingError::TelemetryFailed {
                emitter: "x".into(),
                reason: "y".into(),
            },
            "cx_telemetry_failed",
        ),
        (
            CxThreadingError::Cancelled {
                operation: "x".into(),
            },
            "cx_cancelled",
        ),
    ];
    for (err, code) in &pairs {
        assert_eq!(err.error_code(), *code);
    }
}

// ===========================================================================
// Descriptor types serde
// ===========================================================================

#[test]
fn hostcall_descriptor_serde() {
    let desc = HostcallDescriptor::new("fs_read", "ext-001").with_budget_cost(5);
    let json = serde_json::to_string(&desc).unwrap();
    let back: HostcallDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
    assert_eq!(back.budget_cost_override_ms, Some(5));
}

#[test]
fn hostcall_descriptor_default_no_override() {
    let desc = HostcallDescriptor::new("op", "ext");
    assert_eq!(desc.name, "op");
    assert_eq!(desc.extension_id, "ext");
    assert_eq!(desc.budget_cost_override_ms, None);
}

#[test]
fn policy_check_descriptor_serde() {
    let desc = PolicyCheckDescriptor::new("pre_call", "pol-1", "scope");
    let json = serde_json::to_string(&desc).unwrap();
    let back: PolicyCheckDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

#[test]
fn telemetry_descriptor_serde() {
    let desc = TelemetryDescriptor::new("em", "evt", TelemetryLevel::Warn);
    let json = serde_json::to_string(&desc).unwrap();
    let back: TelemetryDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

// ===========================================================================
// Receipt types serde
// ===========================================================================

#[test]
fn hostcall_receipt_serde() {
    let r = HostcallReceipt {
        hostcall_name: "fs_read".into(),
        extension_id: "ext".into(),
        trace_id: "t".into(),
        budget_consumed_ms: 1,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: HostcallReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn policy_check_result_serde() {
    let r = PolicyCheckResult {
        check_name: "chk".into(),
        policy_id: "pol".into(),
        verdict: PolicyVerdict::Allow,
        trace_id: "t".into(),
        budget_consumed_ms: 2,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn lifecycle_receipt_serde() {
    let r = LifecycleReceipt {
        from: LifecyclePhase::Unloaded,
        to: LifecyclePhase::Loaded,
        trace_id: "t".into(),
        budget_consumed_ms: 3,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: LifecycleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn telemetry_receipt_serde() {
    let r = TelemetryReceipt {
        emitter: "em".into(),
        event_name: "evt".into(),
        level: TelemetryLevel::Error,
        payload_len: 42,
        trace_id: "t".into(),
        budget_consumed_ms: 1,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: TelemetryReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn cx_threaded_event_serde() {
    let evt = CxThreadedEvent {
        trace_id: "t".into(),
        category: EffectCategory::Hostcall,
        component: "cx_threading".into(),
        operation: "fs_read".into(),
        outcome: "dispatched".into(),
        budget_consumed_ms: 1,
        budget_remaining_ms: 99,
        error_code: None,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: CxThreadedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn hostcall_registration_serde() {
    let reg = HostcallRegistration {
        name: "fs_read".into(),
        budget_cost_override_ms: Some(5),
        enabled: true,
    };
    let json = serde_json::to_string(&reg).unwrap();
    let back: HostcallRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn effect_audit_log_serde() {
    let log = EffectAuditLog {
        trace_id: "t".into(),
        total_events: 0,
        hostcall_count: 0,
        policy_check_count: 0,
        lifecycle_transition_count: 0,
        telemetry_count: 0,
        total_budget_consumed_ms: 0,
        final_lifecycle_phase: LifecyclePhase::Unloaded,
        events: vec![],
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: EffectAuditLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// ===========================================================================
// Gateway creation
// ===========================================================================

#[test]
fn gateway_starts_unloaded_empty() {
    let gw = make_gateway(1, 100);
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
    assert_eq!(gw.hostcall_count(), 0);
    assert_eq!(gw.policy_check_count(), 0);
    assert_eq!(gw.lifecycle_transition_count(), 0);
    assert_eq!(gw.telemetry_count(), 0);
    assert!(gw.events().is_empty());
}

#[test]
fn gateway_cx_accessor() {
    let gw = make_gateway(42, 500);
    assert_eq!(gw.cx().trace_id(), trace_id_from_seed(42));
    assert_eq!(gw.cx().budget().remaining_ms(), 500);
}

#[test]
fn gateway_cx_mut_accessor() {
    let mut gw = make_gateway(10, 200);
    gw.cx_mut()
        .consume_budget(5)
        .expect("consume through cx_mut");
    assert_eq!(gw.cx().budget().remaining_ms(), 195);
}

// ===========================================================================
// Lifecycle transitions (via gateway)
// ===========================================================================

#[test]
fn lifecycle_valid_happy_path() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Loaded);
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Running);
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
    assert_eq!(gw.lifecycle_transition_count(), 4);
}

#[test]
fn lifecycle_invalid_transition_returns_error() {
    let mut gw = make_gateway(1, 100);
    // Unloaded -> Running is not valid (must go through Loaded)
    let err = gw
        .transition_lifecycle(LifecyclePhase::Running)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
    assert_eq!(err.error_code(), "cx_lifecycle_violation");
}

#[test]
fn lifecycle_transition_from_terminal_fails() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    let err = gw
        .transition_lifecycle(LifecyclePhase::Unloaded)
        .unwrap_err();
    match &err {
        CxThreadingError::LifecycleViolation { reason, .. } => {
            assert!(reason.contains("terminal"), "{reason}");
        }
        other => panic!("expected LifecycleViolation, got {other:?}"),
    }
}

#[test]
fn lifecycle_suspend_resume_cycle() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Suspended);
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Running);
    assert_eq!(gw.lifecycle_transition_count(), 4);
}

#[test]
fn lifecycle_quarantine_path() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Quarantined)
        .unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Quarantined);
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_transition_count(), 5);
}

#[test]
fn lifecycle_quarantine_direct_terminate() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Quarantined)
        .unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn lifecycle_loaded_to_unloading() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_transition_count(), 3);
}

#[test]
fn lifecycle_suspended_to_unloading() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_transition_count(), 5);
}

#[test]
fn lifecycle_suspended_to_terminated() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_transition_count(), 4);
}

#[test]
fn lifecycle_receipt_fields() {
    let mut gw = make_gateway(5, 100);
    let receipt = gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(receipt.from, LifecyclePhase::Unloaded);
    assert_eq!(receipt.to, LifecyclePhase::Loaded);
    assert_eq!(
        receipt.budget_consumed_ms,
        LIFECYCLE_TRANSITION_BUDGET_COST_MS
    );
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(receipt.trace_id, trace_id_from_seed(5).to_string());
}

#[test]
fn lifecycle_budget_exhaustion() {
    // Each lifecycle transition costs 3ms. Budget = 5 → second transition fails.
    let mut gw = make_gateway(1, 5);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    let err = gw
        .transition_lifecycle(LifecyclePhase::Running)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    assert_eq!(err.error_code(), "cx_budget_exhausted");
}

// ===========================================================================
// Hostcall dispatch
// ===========================================================================

#[test]
fn hostcall_dispatch_registered() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("fs_read", None);
    let receipt = gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    assert_eq!(receipt.hostcall_name, "fs_read");
    assert_eq!(receipt.extension_id, "test-ext");
    assert_eq!(receipt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(gw.hostcall_count(), 1);
}

#[test]
fn hostcall_dispatch_unregistered_rejected() {
    let mut gw = make_gateway(1, 100);
    let err = gw
        .dispatch_hostcall(&hostcall("not_registered"))
        .unwrap_err();
    match &err {
        CxThreadingError::HostcallRejected { reason, .. } => {
            assert!(reason.contains("not registered"), "{reason}");
        }
        other => panic!("expected HostcallRejected, got {other:?}"),
    }
    assert_eq!(gw.hostcall_count(), 0);
}

#[test]
fn hostcall_dispatch_disabled_rejected() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("fs_read", None);
    assert!(gw.disable_hostcall("fs_read"));
    let err = gw.dispatch_hostcall(&hostcall("fs_read")).unwrap_err();
    match &err {
        CxThreadingError::HostcallRejected { reason, .. } => {
            assert!(reason.contains("disabled"), "{reason}");
        }
        other => panic!("expected HostcallRejected, got {other:?}"),
    }
}

#[test]
fn hostcall_disable_nonexistent_returns_false() {
    let mut gw = make_gateway(1, 100);
    assert!(!gw.disable_hostcall("nonexistent"));
}

#[test]
fn hostcall_custom_budget_from_descriptor() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("expensive", None);
    let desc = HostcallDescriptor::new("expensive", "ext").with_budget_cost(10);
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 10);
    assert_eq!(gw.cx().budget().remaining_ms(), 90);
}

#[test]
fn hostcall_custom_budget_from_registration() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", Some(7));
    let receipt = gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 7);
    assert_eq!(gw.cx().budget().remaining_ms(), 93);
}

#[test]
fn hostcall_descriptor_override_takes_precedence() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", Some(7));
    let desc = HostcallDescriptor::new("op", "ext").with_budget_cost(15);
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 15);
}

#[test]
fn hostcall_budget_exhaustion() {
    let mut gw = make_gateway(1, 0);
    gw.register_hostcall("op", None);
    let err = gw.dispatch_hostcall(&hostcall("op")).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn hostcall_sequence_numbers_increment() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("a", None);
    gw.register_hostcall("b", None);
    let r1 = gw.dispatch_hostcall(&hostcall("a")).unwrap();
    let r2 = gw.dispatch_hostcall(&hostcall("b")).unwrap();
    let r3 = gw.dispatch_hostcall(&hostcall("a")).unwrap();
    assert_eq!(r1.sequence_number, 1);
    assert_eq!(r2.sequence_number, 2);
    assert_eq!(r3.sequence_number, 3);
}

#[test]
fn hostcall_re_register_resets_state() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", Some(5));
    gw.disable_hostcall("op");
    // Re-registering should reset enabled=true and new budget
    gw.register_hostcall("op", Some(2));
    let receipt = gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 2);
}

// ===========================================================================
// Policy check dispatch
// ===========================================================================

#[test]
fn policy_check_allow() {
    let mut gw = make_gateway(1, 100);
    let desc = policy_check("pre_call");
    let result = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(result.check_name, "pre_call");
    assert_eq!(result.policy_id, "pol-001");
    assert_eq!(result.verdict, PolicyVerdict::Allow);
    assert_eq!(result.budget_consumed_ms, POLICY_CHECK_BUDGET_COST_MS);
    assert_eq!(result.sequence_number, 1);
    assert_eq!(gw.policy_check_count(), 1);
}

#[test]
fn policy_check_deny_returns_error() {
    let mut gw = make_gateway(1, 100);
    let desc = policy_check("limit");
    let err = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Deny {
            reason: "exceeded".into(),
        })
        .unwrap_err();
    match &err {
        CxThreadingError::PolicyDenied {
            check_name,
            verdict,
        } => {
            assert_eq!(check_name, "limit");
            assert_eq!(verdict, "exceeded");
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
    // Budget is still consumed even on deny
    assert_eq!(
        gw.cx().budget().remaining_ms(),
        100 - POLICY_CHECK_BUDGET_COST_MS
    );
    // Counter still increments
    assert_eq!(gw.policy_check_count(), 1);
}

#[test]
fn policy_check_escalate_returns_ok() {
    let mut gw = make_gateway(1, 100);
    let desc = policy_check("review");
    let result = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Escalate {
            reason: "needs review".into(),
        })
        .unwrap();
    assert_eq!(
        result.verdict,
        PolicyVerdict::Escalate {
            reason: "needs review".into()
        }
    );
}

#[test]
fn policy_check_budget_exhaustion() {
    let mut gw = make_gateway(1, 1);
    let desc = policy_check("chk");
    let err = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Allow)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn policy_check_sequence_numbers_increment() {
    let mut gw = make_gateway(1, 100);
    let r1 = gw
        .evaluate_policy_check(&policy_check("a"), |_| PolicyVerdict::Allow)
        .unwrap();
    let r2 = gw
        .evaluate_policy_check(&policy_check("b"), |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(r1.sequence_number, 1);
    assert_eq!(r2.sequence_number, 2);
}

// ===========================================================================
// Telemetry emission
// ===========================================================================

#[test]
fn telemetry_emit_success() {
    let mut gw = make_gateway(1, 100);
    let desc = telemetry("metric");
    let receipt = gw.emit_telemetry(&desc, "payload_data").unwrap();
    assert_eq!(receipt.emitter, "emitter");
    assert_eq!(receipt.event_name, "metric");
    assert_eq!(receipt.level, TelemetryLevel::Info);
    assert_eq!(receipt.payload_len, "payload_data".len());
    assert_eq!(receipt.budget_consumed_ms, TELEMETRY_EMIT_BUDGET_COST_MS);
    assert_eq!(receipt.sequence_number, 1);
    assert_eq!(gw.telemetry_count(), 1);
}

#[test]
fn telemetry_budget_exhaustion() {
    let mut gw = make_gateway(1, 0);
    let err = gw.emit_telemetry(&telemetry("evt"), "data").unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn telemetry_sequence_numbers_increment() {
    let mut gw = make_gateway(1, 100);
    let r1 = gw.emit_telemetry(&telemetry("a"), "d").unwrap();
    let r2 = gw.emit_telemetry(&telemetry("b"), "d").unwrap();
    let r3 = gw.emit_telemetry(&telemetry("c"), "d").unwrap();
    assert_eq!(r1.sequence_number, 1);
    assert_eq!(r2.sequence_number, 2);
    assert_eq!(r3.sequence_number, 3);
}

#[test]
fn telemetry_with_all_levels() {
    let mut gw = make_gateway(1, 100);
    for (i, level) in [
        TelemetryLevel::Debug,
        TelemetryLevel::Info,
        TelemetryLevel::Warn,
        TelemetryLevel::Error,
    ]
    .iter()
    .enumerate()
    {
        let desc = TelemetryDescriptor::new("em", format!("evt_{i}"), *level);
        let receipt = gw.emit_telemetry(&desc, "data").unwrap();
        assert_eq!(receipt.level, *level);
    }
    assert_eq!(gw.telemetry_count(), 4);
}

// ===========================================================================
// Event tracking and drain
// ===========================================================================

#[test]
fn events_accumulate_across_operations() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", None);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("evt"), "d").unwrap();
    assert_eq!(gw.events().len(), 5);
}

#[test]
fn drain_events_clears_and_returns() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(gw.events().len(), 1);
    let drained = gw.drain_events();
    assert_eq!(drained.len(), 1);
    assert!(gw.events().is_empty());
    // Counters are NOT reset by drain
    assert_eq!(gw.lifecycle_transition_count(), 1);
}

#[test]
fn event_fields_for_hostcall() {
    let mut gw = make_gateway(5, 100);
    gw.register_hostcall("fs_read", None);
    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::Hostcall);
    assert_eq!(evt.operation, "fs_read");
    assert_eq!(evt.outcome, "dispatched");
    assert_eq!(evt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
    assert_eq!(evt.component, "cx_threading");
    assert_eq!(evt.trace_id, trace_id_from_seed(5).to_string());
    assert!(evt.error_code.is_none());
}

#[test]
fn event_fields_for_rejected_hostcall() {
    let mut gw = make_gateway(1, 100);
    let _ = gw.dispatch_hostcall(&hostcall("not_registered"));
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::Hostcall);
    assert_eq!(evt.outcome, "rejected");
    assert!(evt.error_code.is_some());
}

#[test]
fn event_fields_for_policy_check() {
    let mut gw = make_gateway(1, 100);
    gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::PolicyCheck);
    assert_eq!(evt.operation, "chk");
    assert_eq!(evt.outcome, "allow");
}

#[test]
fn event_fields_for_denied_policy() {
    let mut gw = make_gateway(1, 100);
    let _ = gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Deny {
        reason: "no".into(),
    });
    let evt = &gw.events()[0];
    assert_eq!(evt.outcome, "deny");
}

#[test]
fn event_fields_for_lifecycle_transition() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::LifecycleTransition);
    assert!(evt.operation.contains("unloaded"));
    assert!(evt.operation.contains("loaded"));
    assert_eq!(evt.outcome, "transitioned");
}

#[test]
fn event_fields_for_telemetry() {
    let mut gw = make_gateway(1, 100);
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();
    let evt = &gw.events()[0];
    assert_eq!(evt.category, EffectCategory::TelemetryEmit);
    assert_eq!(evt.operation, "metric");
    assert_eq!(evt.outcome, "emitted");
}

#[test]
fn event_budget_remaining_decreases() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("a", None);
    gw.register_hostcall("b", None);
    gw.dispatch_hostcall(&hostcall("a")).unwrap();
    gw.dispatch_hostcall(&hostcall("b")).unwrap();
    let e1 = &gw.events()[0];
    let e2 = &gw.events()[1];
    assert!(e1.budget_remaining_ms > e2.budget_remaining_ms);
}

#[test]
fn budget_exhaustion_event_has_error_code() {
    let mut gw = make_gateway(1, 0);
    gw.register_hostcall("op", None);
    let _ = gw.dispatch_hostcall(&hostcall("op"));
    let evt = &gw.events()[0];
    assert_eq!(evt.outcome, "budget_exhausted");
    assert_eq!(evt.error_code.as_deref(), Some("cx_budget_exhausted"));
    assert_eq!(evt.budget_consumed_ms, 0);
}

// ===========================================================================
// Audit log
// ===========================================================================

#[test]
fn audit_log_summarizes_all_operations() {
    let mut gw = make_gateway(7, 100);
    gw.register_hostcall("op", None);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    gw.evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("evt"), "d").unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    let log = gw.audit_log();
    assert_eq!(log.trace_id, trace_id_from_seed(7).to_string());
    assert_eq!(log.hostcall_count, 1);
    assert_eq!(log.policy_check_count, 1);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.telemetry_count, 1);
    assert_eq!(log.total_events, 7);
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    // Budget: 4*3 (lifecycle) + 1 (hostcall) + 2 (policy) + 1 (telemetry) = 16
    assert_eq!(log.total_budget_consumed_ms, 16);
    assert_eq!(log.events.len(), 7);
}

#[test]
fn audit_log_excludes_error_events_from_budget_sum() {
    let mut gw = make_gateway(1, 5);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap(); // consumes 1ms
    // Now 4ms remain, not enough for hostcall (still 1ms? yes enough)
    // Actually let's use budget 2, dispatch once succeeds (1ms), second fails (1ms)
    let mut gw = make_gateway(1, 1);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap(); // consumes 1ms
    let _ = gw.dispatch_hostcall(&hostcall("op")); // fails
    let log = gw.audit_log();
    // Only the successful dispatch's budget should be counted
    assert_eq!(log.total_budget_consumed_ms, 1);
    assert_eq!(log.total_events, 2);
}

#[test]
fn audit_log_trace_id_consistency() {
    let seed = 99;
    let mut gw = make_gateway(seed, 100);
    gw.register_hostcall("op", None);
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    let log = gw.audit_log();
    let expected_tid = trace_id_from_seed(seed).to_string();
    assert_eq!(log.trace_id, expected_tid);
    for evt in &log.events {
        assert_eq!(evt.trace_id, expected_tid);
    }
}

// ===========================================================================
// run_full_lifecycle
// ===========================================================================

#[test]
fn run_full_lifecycle_happy_path() {
    let mut gw = make_gateway(1, 500);
    gw.register_hostcall("op1", None);
    gw.register_hostcall("op2", None);

    let log = run_full_lifecycle(
        &mut gw,
        &[hostcall("op1"), hostcall("op2")],
        &[policy_check("chk")],
        &[telemetry("evt")],
    )
    .unwrap();

    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    assert_eq!(log.hostcall_count, 2);
    assert_eq!(log.policy_check_count, 1);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.telemetry_count, 1);
}

#[test]
fn run_full_lifecycle_no_operations() {
    let mut gw = make_gateway(1, 100);
    let log = run_full_lifecycle(&mut gw, &[], &[], &[]).unwrap();
    assert_eq!(log.hostcall_count, 0);
    assert_eq!(log.policy_check_count, 0);
    assert_eq!(log.telemetry_count, 0);
    assert_eq!(log.lifecycle_transition_count, 4);
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    // 4 lifecycle transitions × 3ms = 12ms
    assert_eq!(log.total_budget_consumed_ms, 12);
}

#[test]
fn run_full_lifecycle_budget_exhaustion_mid_hostcall() {
    // Budget: 2 lifecycle transitions (6ms) + 1 hostcall (1ms) = 7ms needed
    // Give 8ms so 2 transitions + 1 hostcall succeed, then 2nd hostcall fails
    let mut gw = make_gateway(1, 8);
    gw.register_hostcall("op1", None);
    gw.register_hostcall("op2", None);
    gw.register_hostcall("op3", None);

    let err = run_full_lifecycle(
        &mut gw,
        &[hostcall("op1"), hostcall("op2"), hostcall("op3")],
        &[],
        &[],
    )
    .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

// ===========================================================================
// Budget accounting precision
// ===========================================================================

#[test]
fn budget_accounting_exact() {
    // 4 lifecycle × 3ms = 12ms
    // 3 hostcalls × 1ms = 3ms
    // 2 policy checks × 2ms = 4ms
    // 1 telemetry × 1ms = 1ms
    // Total = 20ms
    let mut gw = make_gateway(1, 20);

    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    for i in 0..3 {
        let name = format!("op_{i}");
        gw.register_hostcall(&name, None);
        gw.dispatch_hostcall(&HostcallDescriptor::new(&name, "ext"))
            .unwrap();
    }
    for i in 0..2 {
        gw.evaluate_policy_check(&policy_check(&format!("chk_{i}")), |_| PolicyVerdict::Allow)
            .unwrap();
    }
    gw.emit_telemetry(&telemetry("metric"), "data").unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    assert_eq!(gw.cx().budget().remaining_ms(), 0);
    assert_eq!(gw.lifecycle_transition_count(), 4);
    assert_eq!(gw.hostcall_count(), 3);
    assert_eq!(gw.policy_check_count(), 2);
    assert_eq!(gw.telemetry_count(), 1);
}

#[test]
fn budget_exactly_sufficient() {
    // Exactly 3ms for one lifecycle transition
    let mut gw = make_gateway(1, 3);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(gw.cx().budget().remaining_ms(), 0);
}

#[test]
fn budget_one_short() {
    // 2ms is not enough for lifecycle transition (needs 3ms)
    let mut gw = make_gateway(1, 2);
    let err = gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap_err();
    match &err {
        CxThreadingError::BudgetExhausted {
            requested_ms,
            remaining_ms,
            ..
        } => {
            assert_eq!(*requested_ms, 3);
            assert_eq!(*remaining_ms, 2);
        }
        other => panic!("expected BudgetExhausted, got {other:?}"),
    }
}

// ===========================================================================
// Cross-cutting integration scenarios
// ===========================================================================

#[test]
fn mixed_operations_interleaved() {
    let mut gw = make_gateway(1, 500);
    gw.register_hostcall("fs_read", None);
    gw.register_hostcall("kv_get", None);

    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();

    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    gw.evaluate_policy_check(&policy_check("mid_check"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.dispatch_hostcall(&hostcall("kv_get")).unwrap();
    gw.emit_telemetry(&telemetry("trace_span"), "data").unwrap();
    gw.evaluate_policy_check(&policy_check("post_check"), |_| PolicyVerdict::Allow)
        .unwrap();

    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();

    assert_eq!(gw.hostcall_count(), 2);
    assert_eq!(gw.policy_check_count(), 2);
    assert_eq!(gw.telemetry_count(), 1);
    assert_eq!(gw.lifecycle_transition_count(), 4);
    assert_eq!(gw.events().len(), 9);
}

#[test]
fn deterministic_replay_produces_identical_audit_logs() {
    fn run_scenario(seed: u64) -> EffectAuditLog {
        let mut gw = make_gateway(seed, 500);
        gw.register_hostcall("op", None);
        run_full_lifecycle(
            &mut gw,
            &[hostcall("op")],
            &[policy_check("chk")],
            &[telemetry("evt")],
        )
        .unwrap()
    }

    let log1 = run_scenario(42);
    let log2 = run_scenario(42);

    assert_eq!(log1.trace_id, log2.trace_id);
    assert_eq!(log1.total_budget_consumed_ms, log2.total_budget_consumed_ms);
    assert_eq!(log1.hostcall_count, log2.hostcall_count);
    assert_eq!(log1.policy_check_count, log2.policy_check_count);
    assert_eq!(
        log1.lifecycle_transition_count,
        log2.lifecycle_transition_count
    );
    assert_eq!(log1.telemetry_count, log2.telemetry_count);
    assert_eq!(log1.events.len(), log2.events.len());
    for (e1, e2) in log1.events.iter().zip(log2.events.iter()) {
        assert_eq!(e1, e2);
    }
}

#[test]
fn many_hostcalls_high_throughput() {
    let mut gw = make_gateway(1, 10_000);
    for i in 0..100 {
        let name = format!("hc_{i}");
        gw.register_hostcall(&name, None);
    }
    for i in 0..100 {
        let name = format!("hc_{i}");
        gw.dispatch_hostcall(&HostcallDescriptor::new(&name, "ext"))
            .unwrap();
    }
    assert_eq!(gw.hostcall_count(), 100);
    assert_eq!(gw.events().len(), 100);
    assert_eq!(gw.cx().budget().remaining_ms(), 10_000 - 100);
}

#[test]
fn hostcall_after_policy_deny_still_works() {
    let mut gw = make_gateway(1, 100);
    gw.register_hostcall("op", None);
    let _ = gw.evaluate_policy_check(&policy_check("deny_me"), |_| PolicyVerdict::Deny {
        reason: "nope".into(),
    });
    // Hostcall should still work after a policy deny
    let receipt = gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(receipt.sequence_number, 1);
}

#[test]
fn suspend_resume_preserves_counters_and_budget() {
    let mut gw = make_gateway(1, 200);
    gw.register_hostcall("op", None);

    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    let budget_before_suspend = gw.cx().budget().remaining_ms();
    let hc_count_before = gw.hostcall_count();

    gw.transition_lifecycle(LifecyclePhase::Suspended).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();

    // Budget reduced by 2 lifecycle transitions (6ms)
    assert_eq!(
        gw.cx().budget().remaining_ms(),
        budget_before_suspend - 2 * LIFECYCLE_TRANSITION_BUDGET_COST_MS
    );
    // Hostcall count unchanged
    assert_eq!(gw.hostcall_count(), hc_count_before);

    gw.dispatch_hostcall(&hostcall("op")).unwrap();
    assert_eq!(gw.hostcall_count(), hc_count_before + 1);
}

#[test]
fn multiple_drains_are_idempotent() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    let first = gw.drain_events();
    assert_eq!(first.len(), 1);
    let second = gw.drain_events();
    assert!(second.is_empty());
    let third = gw.drain_events();
    assert!(third.is_empty());
}

#[test]
fn audit_log_after_drain_reflects_only_remaining_events() {
    let mut gw = make_gateway(1, 100);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.drain_events();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    let log = gw.audit_log();
    // Only the Running transition event remains
    assert_eq!(log.events.len(), 1);
    // But counters still reflect all transitions
    assert_eq!(log.lifecycle_transition_count, 2);
}

#[test]
fn zero_budget_gateway_rejects_everything() {
    let mut gw = make_gateway(1, 0);
    gw.register_hostcall("op", None);

    let err = gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));

    let err = gw.dispatch_hostcall(&hostcall("op")).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));

    let err = gw
        .evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));

    let err = gw.emit_telemetry(&telemetry("evt"), "d").unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn empty_payload_telemetry() {
    let mut gw = make_gateway(1, 100);
    let receipt = gw.emit_telemetry(&telemetry("evt"), "").unwrap();
    assert_eq!(receipt.payload_len, 0);
}

#[test]
fn large_payload_telemetry() {
    let mut gw = make_gateway(1, 100);
    let payload = "x".repeat(1_000_000);
    let receipt = gw.emit_telemetry(&telemetry("evt"), &payload).unwrap();
    assert_eq!(receipt.payload_len, 1_000_000);
}
