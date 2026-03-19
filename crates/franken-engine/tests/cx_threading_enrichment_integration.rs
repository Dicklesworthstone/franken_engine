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

//! Enrichment integration tests for the cx_threading module.

use std::collections::BTreeSet;

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
    HostcallDescriptor::new(name, "test-ext-001")
}

fn policy_check(name: &str) -> PolicyCheckDescriptor {
    PolicyCheckDescriptor::new(name, "test-policy-001", "ext-scope")
}

fn telemetry(event_name: &str) -> TelemetryDescriptor {
    TelemetryDescriptor::new("test-emitter", event_name, TelemetryLevel::Info)
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn cx_threading_error_serde_all_variants() {
    let errors = vec![
        CxThreadingError::BudgetExhausted {
            operation: "hostcall".to_string(),
            requested_ms: 10,
            remaining_ms: 5,
        },
        CxThreadingError::HostcallRejected {
            hostcall_name: "fs_read".to_string(),
            reason: "not registered".to_string(),
        },
        CxThreadingError::PolicyDenied {
            check_name: "pre_call".to_string(),
            verdict: "denied".to_string(),
        },
        CxThreadingError::LifecycleViolation {
            from: LifecyclePhase::Unloaded,
            to: LifecyclePhase::Running,
            reason: "invalid".to_string(),
        },
        CxThreadingError::TelemetryFailed {
            emitter: "e".to_string(),
            reason: "r".to_string(),
        },
        CxThreadingError::Cancelled {
            operation: "op".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: CxThreadingError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn policy_verdict_serde_all_variants() {
    let verdicts = vec![
        PolicyVerdict::Allow,
        PolicyVerdict::Deny {
            reason: "risk".to_string(),
        },
        PolicyVerdict::Escalate {
            reason: "review".to_string(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let decoded: PolicyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn hostcall_receipt_serde_roundtrip() {
    let receipt = HostcallReceipt {
        hostcall_name: "fs_read".to_string(),
        extension_id: "ext-1".to_string(),
        trace_id: "trace-1".to_string(),
        budget_consumed_ms: 1,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: HostcallReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

#[test]
fn lifecycle_receipt_serde_roundtrip() {
    let receipt = LifecycleReceipt {
        from: LifecyclePhase::Unloaded,
        to: LifecyclePhase::Loaded,
        trace_id: "trace-1".to_string(),
        budget_consumed_ms: 3,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: LifecycleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

#[test]
fn telemetry_receipt_serde_roundtrip() {
    let receipt = TelemetryReceipt {
        emitter: "test".to_string(),
        event_name: "event1".to_string(),
        level: TelemetryLevel::Warn,
        payload_len: 42,
        trace_id: "trace-1".to_string(),
        budget_consumed_ms: 1,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: TelemetryReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

#[test]
fn policy_check_result_serde_roundtrip() {
    let result = PolicyCheckResult {
        check_name: "pre_call".to_string(),
        policy_id: "pol-1".to_string(),
        verdict: PolicyVerdict::Allow,
        trace_id: "trace-1".to_string(),
        budget_consumed_ms: 2,
        sequence_number: 1,
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: PolicyCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

#[test]
fn cx_threaded_event_serde_roundtrip() {
    let event = CxThreadedEvent {
        trace_id: "t1".to_string(),
        category: EffectCategory::Hostcall,
        component: "cx_threading".to_string(),
        operation: "fs_read".to_string(),
        outcome: "dispatched".to_string(),
        budget_consumed_ms: 1,
        budget_remaining_ms: 99,
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: CxThreadedEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn effect_audit_log_serde_roundtrip() {
    let log = EffectAuditLog {
        trace_id: "t1".to_string(),
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
    let decoded: EffectAuditLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, decoded);
}

// ---------------------------------------------------------------------------
// Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn effect_category_display_all_distinct() {
    let categories = vec![
        EffectCategory::Hostcall,
        EffectCategory::PolicyCheck,
        EffectCategory::LifecycleTransition,
        EffectCategory::TelemetryEmit,
    ];
    let displays: BTreeSet<String> = categories.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), categories.len());
}

#[test]
fn lifecycle_phase_display_all_distinct() {
    let phases = vec![
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
        LifecyclePhase::Terminated,
    ];
    let displays: BTreeSet<String> = phases.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), phases.len());
}

#[test]
fn telemetry_level_display_all_distinct() {
    let levels = vec![
        TelemetryLevel::Debug,
        TelemetryLevel::Info,
        TelemetryLevel::Warn,
        TelemetryLevel::Error,
    ];
    let displays: BTreeSet<String> = levels.iter().map(|l| l.to_string()).collect();
    assert_eq!(displays.len(), levels.len());
}

#[test]
fn policy_verdict_display_all_distinct() {
    let verdicts = vec![
        PolicyVerdict::Allow,
        PolicyVerdict::Deny {
            reason: "a".to_string(),
        },
        PolicyVerdict::Escalate {
            reason: "b".to_string(),
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), verdicts.len());
}

#[test]
fn cx_threading_error_display_all_distinct() {
    let errors = vec![
        CxThreadingError::BudgetExhausted {
            operation: "op".to_string(),
            requested_ms: 10,
            remaining_ms: 0,
        },
        CxThreadingError::HostcallRejected {
            hostcall_name: "h".to_string(),
            reason: "r".to_string(),
        },
        CxThreadingError::PolicyDenied {
            check_name: "p".to_string(),
            verdict: "v".to_string(),
        },
        CxThreadingError::LifecycleViolation {
            from: LifecyclePhase::Unloaded,
            to: LifecyclePhase::Running,
            reason: "invalid".to_string(),
        },
        CxThreadingError::TelemetryFailed {
            emitter: "e".to_string(),
            reason: "r".to_string(),
        },
        CxThreadingError::Cancelled {
            operation: "c".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[test]
fn cx_threading_error_codes_all_distinct() {
    let errors = vec![
        CxThreadingError::BudgetExhausted {
            operation: "x".to_string(),
            requested_ms: 1,
            remaining_ms: 0,
        },
        CxThreadingError::HostcallRejected {
            hostcall_name: "x".to_string(),
            reason: "x".to_string(),
        },
        CxThreadingError::PolicyDenied {
            check_name: "x".to_string(),
            verdict: "x".to_string(),
        },
        CxThreadingError::LifecycleViolation {
            from: LifecyclePhase::Unloaded,
            to: LifecyclePhase::Running,
            reason: "x".to_string(),
        },
        CxThreadingError::TelemetryFailed {
            emitter: "x".to_string(),
            reason: "x".to_string(),
        },
        CxThreadingError::Cancelled {
            operation: "x".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), errors.len());
}

// ---------------------------------------------------------------------------
// EffectCategory budget costs
// ---------------------------------------------------------------------------

#[test]
fn effect_category_budget_costs_match_constants() {
    assert_eq!(EffectCategory::Hostcall.budget_cost_ms(), HOSTCALL_BUDGET_COST_MS);
    assert_eq!(EffectCategory::PolicyCheck.budget_cost_ms(), POLICY_CHECK_BUDGET_COST_MS);
    assert_eq!(
        EffectCategory::LifecycleTransition.budget_cost_ms(),
        LIFECYCLE_TRANSITION_BUDGET_COST_MS
    );
    assert_eq!(EffectCategory::TelemetryEmit.budget_cost_ms(), TELEMETRY_EMIT_BUDGET_COST_MS);
}

// ---------------------------------------------------------------------------
// LifecyclePhase terminal detection
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_phase_terminal_only_terminated() {
    assert!(LifecyclePhase::Terminated.is_terminal());
    for phase in &[
        LifecyclePhase::Unloaded,
        LifecyclePhase::Loaded,
        LifecyclePhase::Running,
        LifecyclePhase::Suspended,
        LifecyclePhase::Quarantined,
        LifecyclePhase::Unloading,
    ] {
        assert!(!phase.is_terminal());
    }
}

// ---------------------------------------------------------------------------
// Gateway: hostcall registration and dispatch enrichment
// ---------------------------------------------------------------------------

#[test]
fn gateway_dispatch_unregistered_hostcall_rejected() {
    let mut gw = make_gateway(1, 1000);
    let desc = hostcall("unregistered_call");
    let err = gw.dispatch_hostcall(&desc).unwrap_err();
    assert!(matches!(err, CxThreadingError::HostcallRejected { .. }));
}

#[test]
fn gateway_dispatch_disabled_hostcall_rejected() {
    let mut gw = make_gateway(2, 1000);
    gw.register_hostcall("fs_read", None);
    gw.disable_hostcall("fs_read");
    let desc = hostcall("fs_read");
    let err = gw.dispatch_hostcall(&desc).unwrap_err();
    assert!(matches!(err, CxThreadingError::HostcallRejected { .. }));
    assert!(err.to_string().contains("disabled"));
}

#[test]
fn gateway_hostcall_with_budget_override() {
    let mut gw = make_gateway(3, 1000);
    gw.register_hostcall("expensive", Some(10));
    let desc = HostcallDescriptor::new("expensive", "ext-1").with_budget_cost(10);
    let receipt = gw.dispatch_hostcall(&desc).unwrap();
    assert_eq!(receipt.budget_consumed_ms, 10);
}

#[test]
fn gateway_hostcall_budget_exhausted() {
    let mut gw = make_gateway(4, 0);
    gw.register_hostcall("fs_read", None);
    let desc = hostcall("fs_read");
    let err = gw.dispatch_hostcall(&desc).unwrap_err();
    assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
}

#[test]
fn gateway_hostcall_count_increments() {
    let mut gw = make_gateway(5, 1000);
    gw.register_hostcall("fs_read", None);
    assert_eq!(gw.hostcall_count(), 0);
    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    assert_eq!(gw.hostcall_count(), 1);
    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    assert_eq!(gw.hostcall_count(), 2);
}

// ---------------------------------------------------------------------------
// Gateway: policy check enrichment
// ---------------------------------------------------------------------------

#[test]
fn gateway_policy_check_allow() {
    let mut gw = make_gateway(6, 1000);
    let desc = policy_check("pre_hostcall");
    let result = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Allow)
        .unwrap();
    assert_eq!(result.verdict, PolicyVerdict::Allow);
    assert_eq!(gw.policy_check_count(), 1);
}

#[test]
fn gateway_policy_check_deny_returns_error() {
    let mut gw = make_gateway(7, 1000);
    let desc = policy_check("pre_hostcall");
    let err = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Deny {
            reason: "too risky".to_string(),
        })
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::PolicyDenied { .. }));
}

#[test]
fn gateway_policy_check_escalate_succeeds() {
    let mut gw = make_gateway(8, 1000);
    let desc = policy_check("resource_limit");
    let result = gw
        .evaluate_policy_check(&desc, |_| PolicyVerdict::Escalate {
            reason: "needs review".to_string(),
        })
        .unwrap();
    assert!(matches!(result.verdict, PolicyVerdict::Escalate { .. }));
}

// ---------------------------------------------------------------------------
// Gateway: lifecycle transitions enrichment
// ---------------------------------------------------------------------------

#[test]
fn gateway_lifecycle_full_valid_sequence() {
    let mut gw = make_gateway(9, 1000);
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Loaded);
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
}

#[test]
fn gateway_lifecycle_invalid_transition_rejected() {
    let mut gw = make_gateway(10, 1000);
    let err = gw
        .transition_lifecycle(LifecyclePhase::Running)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
}

#[test]
fn gateway_lifecycle_terminal_rejects_further_transitions() {
    let mut gw = make_gateway(11, 1000);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
    let err = gw
        .transition_lifecycle(LifecyclePhase::Loaded)
        .unwrap_err();
    assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
    assert!(err.to_string().contains("terminal"));
}

// ---------------------------------------------------------------------------
// Gateway: telemetry enrichment
// ---------------------------------------------------------------------------

#[test]
fn gateway_telemetry_emission_increments_count() {
    let mut gw = make_gateway(12, 1000);
    assert_eq!(gw.telemetry_count(), 0);
    let desc = telemetry("event1");
    gw.emit_telemetry(&desc, "payload1").unwrap();
    assert_eq!(gw.telemetry_count(), 1);
}

#[test]
fn gateway_telemetry_receipt_has_payload_len() {
    let mut gw = make_gateway(13, 1000);
    let desc = telemetry("event1");
    let receipt = gw.emit_telemetry(&desc, "hello world").unwrap();
    assert_eq!(receipt.payload_len, "hello world".len());
    assert_eq!(receipt.level, TelemetryLevel::Info);
}

// ---------------------------------------------------------------------------
// Gateway: drain_events and audit_log
// ---------------------------------------------------------------------------

#[test]
fn gateway_drain_events_clears_log() {
    let mut gw = make_gateway(14, 1000);
    gw.register_hostcall("fs_read", None);
    gw.dispatch_hostcall(&hostcall("fs_read")).unwrap();
    assert!(!gw.events().is_empty());
    let drained = gw.drain_events();
    assert!(!drained.is_empty());
    assert!(gw.events().is_empty());
}

#[test]
fn gateway_audit_log_tracks_all_operations() {
    let mut gw = make_gateway(15, 1000);
    gw.register_hostcall("hc1", None);
    gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
    gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
    gw.dispatch_hostcall(&hostcall("hc1")).unwrap();
    gw.evaluate_policy_check(&policy_check("pc1"), |_| PolicyVerdict::Allow)
        .unwrap();
    gw.emit_telemetry(&telemetry("t1"), "data").unwrap();

    let log = gw.audit_log();
    assert_eq!(log.hostcall_count, 1);
    assert_eq!(log.policy_check_count, 1);
    assert_eq!(log.lifecycle_transition_count, 2);
    assert_eq!(log.telemetry_count, 1);
    assert!(log.total_budget_consumed_ms > 0);
}

// ---------------------------------------------------------------------------
// run_full_lifecycle enrichment
// ---------------------------------------------------------------------------

#[test]
fn run_full_lifecycle_produces_complete_audit() {
    let mut gw = make_gateway(16, 1000);
    gw.register_hostcall("fs_read", None);
    let log = run_full_lifecycle(
        &mut gw,
        &[hostcall("fs_read")],
        &[policy_check("pre_call")],
        &[telemetry("checkpoint")],
    )
    .unwrap();
    assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    assert!(log.lifecycle_transition_count >= 4); // Loaded, Running, Unloading, Terminated
    assert_eq!(log.hostcall_count, 1);
    assert_eq!(log.policy_check_count, 1);
    assert_eq!(log.telemetry_count, 1);
}

#[test]
fn run_full_lifecycle_budget_exhaustion_fails() {
    let mut gw = make_gateway(17, 2); // only 2ms budget
    gw.register_hostcall("fs_read", None);
    // First lifecycle transitions consume 3ms each => should fail
    let result = run_full_lifecycle(
        &mut gw,
        &[hostcall("fs_read")],
        &[],
        &[],
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// HostcallDescriptor enrichment
// ---------------------------------------------------------------------------

#[test]
fn hostcall_descriptor_with_budget_cost() {
    let desc = HostcallDescriptor::new("fs_read", "ext-1").with_budget_cost(5);
    assert_eq!(desc.budget_cost_override_ms, Some(5));
}

#[test]
fn hostcall_descriptor_serde_roundtrip() {
    let desc = HostcallDescriptor::new("fs_read", "ext-1").with_budget_cost(5);
    let json = serde_json::to_string(&desc).unwrap();
    let decoded: HostcallDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, decoded);
}

// ---------------------------------------------------------------------------
// Hostcall registration serde
// ---------------------------------------------------------------------------

#[test]
fn hostcall_registration_serde_roundtrip() {
    let reg = HostcallRegistration {
        name: "fs_read".to_string(),
        budget_cost_override_ms: Some(5),
        enabled: true,
    };
    let json = serde_json::to_string(&reg).unwrap();
    let decoded: HostcallRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, decoded);
}

// ---------------------------------------------------------------------------
// PolicyCheckDescriptor and TelemetryDescriptor serde
// ---------------------------------------------------------------------------

#[test]
fn policy_check_descriptor_serde_roundtrip() {
    let desc = PolicyCheckDescriptor::new("pre_call", "pol-1", "ext-scope");
    let json = serde_json::to_string(&desc).unwrap();
    let decoded: PolicyCheckDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, decoded);
}

#[test]
fn telemetry_descriptor_serde_roundtrip() {
    let desc = TelemetryDescriptor::new("emitter", "event", TelemetryLevel::Error);
    let json = serde_json::to_string(&desc).unwrap();
    let decoded: TelemetryDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, decoded);
}

// ---------------------------------------------------------------------------
// Deterministic: same operations produce same audit logs
// ---------------------------------------------------------------------------

#[test]
fn audit_log_deterministic_50_times() {
    let mut audit_jsons = BTreeSet::new();
    for _i in 0..50 {
        let mut gw = make_gateway(100, 10000);
        gw.register_hostcall("hc", None);
        gw.transition_lifecycle(LifecyclePhase::Loaded).unwrap();
        gw.transition_lifecycle(LifecyclePhase::Running).unwrap();
        gw.dispatch_hostcall(&hostcall("hc")).unwrap();
        gw.transition_lifecycle(LifecyclePhase::Unloading).unwrap();
        gw.transition_lifecycle(LifecyclePhase::Terminated).unwrap();
        let log = gw.audit_log();
        // Compare the structural counts (trace_ids are the same since seed=100)
        let key = format!(
            "{}-{}-{}-{}-{}",
            log.hostcall_count,
            log.policy_check_count,
            log.lifecycle_transition_count,
            log.telemetry_count,
            log.total_budget_consumed_ms
        );
        audit_jsons.insert(key);
    }
    assert_eq!(audit_jsons.len(), 1, "audit log counts should be deterministic");
}
