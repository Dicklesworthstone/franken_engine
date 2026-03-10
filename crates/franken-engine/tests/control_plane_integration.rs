//! Integration tests for the `control_plane` adapter module.

use frankenengine_engine::control_plane::mocks::{
    MockBudget, MockCx, MockDecisionContract, MockEvidenceEmitter, MockFailureMode,
    decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
};
use frankenengine_engine::control_plane::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_request(seed: u64) -> DecisionRequest {
    DecisionRequest {
        decision_id: decision_id_from_seed(seed),
        policy_id: policy_id_from_seed(seed),
        trace_id: trace_id_from_seed(seed),
        ts_unix_ms: 1_700_000_000_000 + seed,
        calibration_score_bps: 9_400,
        e_process_milli: 110,
        ci_width_milli: 45,
    }
}

fn make_evidence(ts: u64, action: &str) -> EvidenceLedger {
    EvidenceLedgerBuilder::new()
        .ts_unix_ms(ts)
        .component("control_plane_integration_test")
        .action(action)
        .posterior(vec![0.7, 0.3])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.2)
        .expected_loss("timeout", 0.3)
        .chosen_expected_loss(0.1)
        .calibration_score(0.94)
        .fallback_active(false)
        .build()
        .expect("valid evidence")
}

// ---------------------------------------------------------------------------
// DecisionVerdict serde / Debug
// ---------------------------------------------------------------------------

#[test]
fn verdict_allow_serde_roundtrip() {
    let v = DecisionVerdict::Allow;
    let json = serde_json::to_string(&v).unwrap();
    let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_deny_serde_roundtrip() {
    let v = DecisionVerdict::Deny;
    let json = serde_json::to_string(&v).unwrap();
    let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_timeout_serde_roundtrip() {
    let v = DecisionVerdict::Timeout;
    let json = serde_json::to_string(&v).unwrap();
    let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_debug_contains_variant_name() {
    assert!(format!("{:?}", DecisionVerdict::Allow).contains("Allow"));
    assert!(format!("{:?}", DecisionVerdict::Deny).contains("Deny"));
    assert!(format!("{:?}", DecisionVerdict::Timeout).contains("Timeout"));
}

#[test]
fn verdict_clone_and_copy_semantics() {
    let v = DecisionVerdict::Deny;
    let cloned = v.clone();
    let copied = v;
    assert_eq!(v, cloned);
    assert_eq!(v, copied);
}

#[test]
fn verdict_equality_same_variant() {
    assert_eq!(DecisionVerdict::Allow, DecisionVerdict::Allow);
    assert_eq!(DecisionVerdict::Deny, DecisionVerdict::Deny);
    assert_eq!(DecisionVerdict::Timeout, DecisionVerdict::Timeout);
}

#[test]
fn verdict_inequality_different_variants() {
    assert_ne!(DecisionVerdict::Allow, DecisionVerdict::Deny);
    assert_ne!(DecisionVerdict::Deny, DecisionVerdict::Timeout);
    assert_ne!(DecisionVerdict::Allow, DecisionVerdict::Timeout);
}

#[test]
fn verdict_serde_json_string_form() {
    // Verify the JSON encoding is a quoted string, not a number
    let json = serde_json::to_string(&DecisionVerdict::Allow).unwrap();
    assert!(json.starts_with('"'));
}

// ---------------------------------------------------------------------------
// DecisionRequest construction and fields
// ---------------------------------------------------------------------------

#[test]
fn decision_request_fields_match_seed() {
    let req = make_request(42);
    assert_eq!(req.ts_unix_ms, 1_700_000_000_042);
    assert_eq!(req.calibration_score_bps, 9_400);
    assert_eq!(req.e_process_milli, 110);
    assert_eq!(req.ci_width_milli, 45);
}

#[test]
fn decision_request_serde_roundtrip() {
    let req = make_request(99);
    let json = serde_json::to_string(&req).unwrap();
    let back: DecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn decision_request_clone_equality() {
    let req = make_request(7);
    let cloned = req.clone();
    assert_eq!(req, cloned);
}

#[test]
fn decision_request_different_seeds_differ() {
    let r1 = make_request(1);
    let r2 = make_request(2);
    assert_ne!(r1.decision_id, r2.decision_id);
    assert_ne!(r1.trace_id, r2.trace_id);
}

#[test]
fn decision_request_zero_seed() {
    let req = make_request(0);
    assert_eq!(req.ts_unix_ms, 1_700_000_000_000);
}

#[test]
fn decision_request_debug_not_empty() {
    let req = make_request(5);
    let dbg = format!("{:?}", req);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("DecisionRequest"));
}

// ---------------------------------------------------------------------------
// AdapterEvent construction and serde
// ---------------------------------------------------------------------------

#[test]
fn adapter_event_construction_and_fields() {
    let evt = AdapterEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "test_component".to_string(),
        event: "eval".to_string(),
        outcome: "allow".to_string(),
        error_code: None,
    };
    assert_eq!(evt.trace_id, "trace-1");
    assert_eq!(evt.component, "test_component");
    assert!(evt.error_code.is_none());
}

#[test]
fn adapter_event_with_error_code() {
    let evt = AdapterEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "error".to_string(),
        error_code: Some("gateway_fail".to_string()),
    };
    assert_eq!(evt.error_code.as_deref(), Some("gateway_fail"));
}

#[test]
fn adapter_event_serde_roundtrip() {
    let evt = AdapterEvent {
        trace_id: "trace-42".to_string(),
        decision_id: "dec-42".to_string(),
        policy_id: "pol-42".to_string(),
        component: "adapter".to_string(),
        event: "decision_eval".to_string(),
        outcome: "allow".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: AdapterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn adapter_event_serde_with_error_code_roundtrip() {
    let evt = AdapterEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "error".to_string(),
        error_code: Some("evidence_fail".to_string()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: AdapterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn adapter_event_clone_equality() {
    let evt = AdapterEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    assert_eq!(evt, evt.clone());
}

// ---------------------------------------------------------------------------
// ControlPlaneAdapterError Display and error_code
// ---------------------------------------------------------------------------

#[test]
fn error_budget_exhausted_display() {
    let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 100 };
    let msg = err.to_string();
    assert!(msg.contains("budget exhausted"));
    assert!(msg.contains("100"));
}

#[test]
fn error_budget_exhausted_error_code() {
    let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 5 };
    assert_eq!(err.error_code(), "budget_exhausted");
}

#[test]
fn error_decision_gateway_display() {
    let err = ControlPlaneAdapterError::DecisionGateway { code: "gw_err" };
    let msg = err.to_string();
    assert!(msg.contains("decision gateway failure"));
    assert!(msg.contains("gw_err"));
}

#[test]
fn error_decision_gateway_error_code() {
    let err = ControlPlaneAdapterError::DecisionGateway { code: "timeout_gw" };
    assert_eq!(err.error_code(), "timeout_gw");
}

#[test]
fn error_evidence_emission_display() {
    let err = ControlPlaneAdapterError::EvidenceEmission { code: "emit_err" };
    let msg = err.to_string();
    assert!(msg.contains("evidence emission failure"));
    assert!(msg.contains("emit_err"));
}

#[test]
fn error_evidence_emission_error_code() {
    let err = ControlPlaneAdapterError::EvidenceEmission { code: "sink_full" };
    assert_eq!(err.error_code(), "sink_full");
}

#[test]
fn error_variants_are_clone_and_eq() {
    let e1 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 10 };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn error_variants_differ() {
    let e1 = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 10 };
    let e2 = ControlPlaneAdapterError::DecisionGateway { code: "x" };
    assert_ne!(e1, e2);
}

// ---------------------------------------------------------------------------
// Re-exported types availability
// ---------------------------------------------------------------------------

#[test]
fn re_exported_decision_contract_is_available() {
    // DecisionContract is a trait re-exported from franken_decision
    fn _assert_trait<T: DecisionContract>() {}
}

#[test]
fn re_exported_evidence_ledger_builder_creates_ledger() {
    let ledger = make_evidence(1_700_000_000_000, "allow");
    let _ = format!("{:?}", ledger);
}

#[test]
fn re_exported_budget_constructible() {
    let b = Budget::new(5_000);
    assert_eq!(b.remaining_ms(), 5_000);
}

#[test]
fn re_exported_cx_types_available() {
    // Verify the types are importable (compile-time check)
    let _: fn() -> DecisionId = || decision_id_from_seed(0);
    let _: fn() -> PolicyId = || policy_id_from_seed(0);
    let _: fn() -> TraceId = || trace_id_from_seed(0);
}

#[test]
fn re_exported_schema_version_available() {
    let sv = SchemaVersion::new(1, 0, 0);
    let _ = format!("{:?}", sv);
}

// ---------------------------------------------------------------------------
// Mock context integration
// ---------------------------------------------------------------------------

#[test]
fn mock_cx_budget_consumption_tracking() {
    let tid = trace_id_from_seed(10);
    let mut cx = MockCx::new(tid, MockBudget::new(100));
    cx.consume_budget(30).unwrap();
    assert_eq!(cx.budget().remaining_ms(), 70);
    cx.consume_budget(70).unwrap();
    assert_eq!(cx.budget().remaining_ms(), 0);
    let err = cx.consume_budget(1).unwrap_err();
    assert_eq!(err.error_code(), "budget_exhausted");
}

#[test]
fn mock_cx_trace_id_determinism() {
    let t1 = trace_id_from_seed(42);
    let t2 = trace_id_from_seed(42);
    assert_eq!(t1, t2);
}

// ---------------------------------------------------------------------------
// Mock decision adapter integration
// ---------------------------------------------------------------------------

#[test]
fn mock_decision_exhausts_to_timeout() {
    let req = make_request(1);
    let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
    assert_eq!(adapter.evaluate(&req).unwrap(), DecisionVerdict::Allow);
    // After exhausting pre-configured responses, returns Timeout
    assert_eq!(adapter.evaluate(&req).unwrap(), DecisionVerdict::Timeout);
}

#[test]
fn mock_decision_records_events() {
    let req = make_request(1);
    let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Deny]);
    adapter.evaluate(&req).unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "deny");
}

#[test]
fn mock_decision_fail_always_records_error_event() {
    let req = make_request(1);
    let mut adapter =
        MockDecisionContract::new(vec![]).with_failure_mode(MockFailureMode::FailAlways {
            code: "always_fail",
        });
    let err = adapter.evaluate(&req).unwrap_err();
    assert!(matches!(
        err,
        ControlPlaneAdapterError::DecisionGateway {
            code: "always_fail"
        }
    ));
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("always_fail"));
}

// ---------------------------------------------------------------------------
// InMemoryEvidenceEmitter integration
// ---------------------------------------------------------------------------

#[test]
fn in_memory_emitter_multiple_emissions() {
    let req = make_request(5);
    let mut emitter = InMemoryEvidenceEmitter::new();
    for i in 0..5 {
        emitter
            .emit(&req, make_evidence(req.ts_unix_ms + i, "allow"))
            .unwrap();
    }
    assert_eq!(emitter.entries().len(), 5);
    assert_eq!(emitter.events().len(), 5);
}

#[test]
fn in_memory_emitter_events_have_correct_component() {
    let req = make_request(10);
    let mut emitter = InMemoryEvidenceEmitter::new();
    emitter
        .emit(&req, make_evidence(req.ts_unix_ms, "deny"))
        .unwrap();
    let evt = &emitter.events()[0];
    assert_eq!(evt.component, "control_plane_adapter");
    assert_eq!(evt.event, "evidence_emit");
}

// ---------------------------------------------------------------------------
// Mock evidence emitter with failure injection
// ---------------------------------------------------------------------------

#[test]
fn mock_evidence_emitter_fail_after_n() {
    let req = make_request(3);
    let mut emitter = MockEvidenceEmitter::new().with_failure_mode(MockFailureMode::FailAfterN {
        remaining_successes: 2,
        code: "fail_after_2",
    });
    emitter
        .emit(&req, make_evidence(req.ts_unix_ms, "allow"))
        .unwrap();
    emitter
        .emit(&req, make_evidence(req.ts_unix_ms + 1, "allow"))
        .unwrap();
    let err = emitter
        .emit(&req, make_evidence(req.ts_unix_ms + 2, "allow"))
        .unwrap_err();
    assert!(matches!(
        err,
        ControlPlaneAdapterError::EvidenceEmission {
            code: "fail_after_2"
        }
    ));
    assert_eq!(emitter.entries().len(), 2);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn decision_request_max_calibration_bps() {
    let mut req = make_request(0);
    req.calibration_score_bps = u16::MAX;
    let json = serde_json::to_string(&req).unwrap();
    let back: DecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.calibration_score_bps, u16::MAX);
}

#[test]
fn decision_request_zero_fields() {
    let req = DecisionRequest {
        decision_id: decision_id_from_seed(0),
        policy_id: policy_id_from_seed(0),
        trace_id: trace_id_from_seed(0),
        ts_unix_ms: 0,
        calibration_score_bps: 0,
        e_process_milli: 0,
        ci_width_milli: 0,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: DecisionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn adapter_event_empty_strings() {
    let evt = AdapterEvent {
        trace_id: String::new(),
        decision_id: String::new(),
        policy_id: String::new(),
        component: String::new(),
        event: String::new(),
        outcome: String::new(),
        error_code: Some(String::new()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: AdapterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

#[test]
fn budget_exhausted_zero_ms() {
    let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 0 };
    assert!(err.to_string().contains("0"));
    assert_eq!(err.error_code(), "budget_exhausted");
}
