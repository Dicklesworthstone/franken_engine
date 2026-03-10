#![forbid(unsafe_code)]

//! Integration tests for the quarantine_mesh_gate module.
//!
//! Covers:
//! 1. Every public enum variant (construction, Display, serde round-trip)
//! 2. Every public struct (construction, field access, serde round-trip)
//! 3. Every public method (happy path, error paths, edge cases)
//! 4. Quarantine gate evaluation and mesh decisions
//! 5. Error variant coverage and Display formatting
//! 6. Determinism: same inputs produce same outputs
//! 7. Cross-concern integration scenarios

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

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::quarantine_mesh_gate::{
    CriterionResult, FaultScenario, FaultScenarioResult, FaultType, GateValidationEvent,
    GateValidationResult, QuarantineMeshGateRunner,
};

// ===========================================================================
// Section 1: FaultType — enum variant coverage
// ===========================================================================

#[test]
fn fault_type_all_variants_constructible() {
    let variants = [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ];
    assert_eq!(variants.len(), 5);
}

#[test]
fn fault_type_display_network_partition() {
    assert_eq!(
        format!("{}", FaultType::NetworkPartition),
        "network_partition"
    );
}

#[test]
fn fault_type_display_byzantine_behavior() {
    assert_eq!(
        format!("{}", FaultType::ByzantineBehavior),
        "byzantine_behavior"
    );
}

#[test]
fn fault_type_display_cascading_failure() {
    assert_eq!(
        format!("{}", FaultType::CascadingFailure),
        "cascading_failure"
    );
}

#[test]
fn fault_type_display_resource_exhaustion() {
    assert_eq!(
        format!("{}", FaultType::ResourceExhaustion),
        "resource_exhaustion"
    );
}

#[test]
fn fault_type_display_clock_skew() {
    assert_eq!(format!("{}", FaultType::ClockSkew), "clock_skew");
}

#[test]
fn fault_type_display_all_lowercase_underscore() {
    let variants = [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "FaultType Display should be lowercase_underscore: {s}"
        );
    }
}

#[test]
fn fault_type_serde_roundtrip_all_variants() {
    let variants = [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FaultType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn fault_type_copy_semantics() {
    let original = FaultType::ByzantineBehavior;
    let copied1 = original;
    let copied2 = original;
    assert_eq!(copied1, copied2);
    assert_eq!(original, copied1);
}

#[test]
fn fault_type_eq_and_ord() {
    // Verify that ordering is consistent with variant declaration order.
    assert!(FaultType::NetworkPartition < FaultType::ByzantineBehavior);
    assert!(FaultType::ByzantineBehavior < FaultType::CascadingFailure);
    assert!(FaultType::CascadingFailure < FaultType::ResourceExhaustion);
    assert!(FaultType::ResourceExhaustion < FaultType::ClockSkew);
}

#[test]
fn fault_type_debug_contains_variant_name() {
    let debug = format!("{:?}", FaultType::ClockSkew);
    assert!(debug.contains("ClockSkew"));
}

// ===========================================================================
// Section 2: FaultScenario — struct construction and serde
// ===========================================================================

fn make_scenario(fault_type: FaultType, expect_quarantine: bool) -> FaultScenario {
    FaultScenario {
        scenario_id: "test-scenario".to_string(),
        fault_type,
        target_extension: "ext-test-001".to_string(),
        detection_latency_ns: 100_000_000,
        expect_quarantine,
        seed: 42,
    }
}

#[test]
fn fault_scenario_construction_and_field_access() {
    let s = make_scenario(FaultType::NetworkPartition, true);
    assert_eq!(s.scenario_id, "test-scenario");
    assert_eq!(s.fault_type, FaultType::NetworkPartition);
    assert_eq!(s.target_extension, "ext-test-001");
    assert_eq!(s.detection_latency_ns, 100_000_000);
    assert!(s.expect_quarantine);
    assert_eq!(s.seed, 42);
}

#[test]
fn fault_scenario_serde_roundtrip() {
    let s = make_scenario(FaultType::ByzantineBehavior, true);
    let json = serde_json::to_string(&s).unwrap();
    let back: FaultScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn fault_scenario_serde_roundtrip_each_fault_type() {
    for ft in [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ] {
        let s = make_scenario(ft, false);
        let json = serde_json::to_string(&s).unwrap();
        let back: FaultScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back, "serde roundtrip failed for {ft}");
    }
}

#[test]
fn fault_scenario_clone_preserves_all_fields() {
    let s = make_scenario(FaultType::CascadingFailure, true);
    let c = s.clone();
    assert_eq!(s, c);
}

#[test]
fn fault_scenario_equality() {
    let a = make_scenario(FaultType::ClockSkew, true);
    let b = make_scenario(FaultType::ClockSkew, true);
    assert_eq!(a, b);
}

#[test]
fn fault_scenario_inequality_on_different_fault_type() {
    let a = make_scenario(FaultType::ClockSkew, true);
    let mut b = make_scenario(FaultType::ClockSkew, true);
    b.fault_type = FaultType::NetworkPartition;
    assert_ne!(a, b);
}

// ===========================================================================
// Section 3: CriterionResult — struct coverage
// ===========================================================================

fn make_criterion(name: &str, passed: bool) -> CriterionResult {
    CriterionResult {
        name: name.to_string(),
        passed,
        detail: format!("detail for {name}"),
    }
}

#[test]
fn criterion_result_construction_and_field_access() {
    let c = make_criterion("sla_check", true);
    assert_eq!(c.name, "sla_check");
    assert!(c.passed);
    assert!(c.detail.contains("sla_check"));
}

#[test]
fn criterion_result_serde_roundtrip() {
    let c = make_criterion("isolation", false);
    let json = serde_json::to_string(&c).unwrap();
    let back: CriterionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn criterion_result_passed_true_and_false() {
    let pass = make_criterion("a", true);
    let fail = make_criterion("b", false);
    assert!(pass.passed);
    assert!(!fail.passed);
}

#[test]
fn criterion_result_clone_preserves_all_fields() {
    let c = make_criterion("recovery", true);
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

// ===========================================================================
// Section 4: FaultScenarioResult — struct coverage
// ===========================================================================

fn make_scenario_result(passed: bool) -> FaultScenarioResult {
    FaultScenarioResult {
        scenario_id: "scenario-x".to_string(),
        fault_type: FaultType::ResourceExhaustion,
        passed,
        criteria: vec![
            make_criterion("detection_within_sla", true),
            make_criterion("containment_action_correct", passed),
        ],
        receipts_emitted: if passed { 1 } else { 0 },
        final_state: Some(ContainmentState::Quarantined),
        detection_latency_ns: 150_000_000,
        isolation_verified: true,
        recovery_verified: passed,
    }
}

#[test]
fn fault_scenario_result_construction_and_field_access() {
    let r = make_scenario_result(true);
    assert_eq!(r.scenario_id, "scenario-x");
    assert_eq!(r.fault_type, FaultType::ResourceExhaustion);
    assert!(r.passed);
    assert_eq!(r.criteria.len(), 2);
    assert_eq!(r.receipts_emitted, 1);
    assert_eq!(r.final_state, Some(ContainmentState::Quarantined));
    assert_eq!(r.detection_latency_ns, 150_000_000);
    assert!(r.isolation_verified);
    assert!(r.recovery_verified);
}

#[test]
fn fault_scenario_result_serde_roundtrip() {
    let r = make_scenario_result(true);
    let json = serde_json::to_string(&r).unwrap();
    let back: FaultScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn fault_scenario_result_with_none_final_state() {
    let r = FaultScenarioResult {
        scenario_id: "none-state".to_string(),
        fault_type: FaultType::ClockSkew,
        passed: false,
        criteria: vec![],
        receipts_emitted: 0,
        final_state: None,
        detection_latency_ns: 0,
        isolation_verified: false,
        recovery_verified: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: FaultScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert!(r.final_state.is_none());
}

#[test]
fn fault_scenario_result_clone_preserves_all_fields() {
    let r = make_scenario_result(false);
    let c = r.clone();
    assert_eq!(r, c);
}

// ===========================================================================
// Section 5: GateValidationEvent — struct coverage
// ===========================================================================

fn make_event() -> GateValidationEvent {
    GateValidationEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-v1".to_string(),
        component: "quarantine_mesh_gate".to_string(),
        event: "fault_scenario_complete".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        fault_type: Some(FaultType::NetworkPartition),
        target_component: Some("ext-target".to_string()),
        quarantine_action: None,
        latency_ns: Some(100_000_000),
        isolation_verified: Some(true),
        receipt_hash: None,
    }
}

#[test]
fn gate_validation_event_construction_and_field_access() {
    let e = make_event();
    assert_eq!(e.trace_id, "trace-001");
    assert_eq!(e.decision_id, "decision-001");
    assert_eq!(e.policy_id, "policy-v1");
    assert_eq!(e.component, "quarantine_mesh_gate");
    assert_eq!(e.event, "fault_scenario_complete");
    assert_eq!(e.outcome, "pass");
    assert!(e.error_code.is_none());
    assert_eq!(e.fault_type, Some(FaultType::NetworkPartition));
    assert_eq!(e.target_component.as_deref(), Some("ext-target"));
    assert!(e.quarantine_action.is_none());
    assert_eq!(e.latency_ns, Some(100_000_000));
    assert_eq!(e.isolation_verified, Some(true));
    assert!(e.receipt_hash.is_none());
}

#[test]
fn gate_validation_event_serde_roundtrip() {
    let e = make_event();
    let json = serde_json::to_string(&e).unwrap();
    let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn gate_validation_event_with_all_optional_fields_populated() {
    let e = GateValidationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: Some("ERR_001".to_string()),
        fault_type: Some(FaultType::ByzantineBehavior),
        target_component: Some("ext".to_string()),
        quarantine_action: Some("quarantine".to_string()),
        latency_ns: Some(42),
        isolation_verified: Some(false),
        receipt_hash: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn gate_validation_event_with_all_optional_fields_none() {
    let e = GateValidationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        fault_type: None,
        target_component: None,
        quarantine_action: None,
        latency_ns: None,
        isolation_verified: None,
        receipt_hash: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn gate_validation_event_clone_preserves_all_fields() {
    let e = make_event();
    let c = e.clone();
    assert_eq!(e, c);
}

// ===========================================================================
// Section 6: GateValidationResult — struct coverage
// ===========================================================================

fn run_gate(seed: u64) -> GateValidationResult {
    let mut runner = QuarantineMeshGateRunner::new(seed);
    runner.run_all()
}

#[test]
fn gate_validation_result_field_access() {
    let r = run_gate(42);
    assert_eq!(r.seed, 42);
    assert!(!r.scenarios.is_empty());
    assert!(!r.result_digest.is_empty());
    assert!(r.total_scenarios > 0);
    assert!(r.passed_scenarios <= r.total_scenarios);
    assert!(!r.events.is_empty());
}

#[test]
fn gate_validation_result_serde_roundtrip() {
    let r = run_gate(42);
    let json = serde_json::to_string(&r).unwrap();
    let back: GateValidationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn gate_validation_result_clone_preserves_all_fields() {
    let r = run_gate(42);
    let c = r.clone();
    assert_eq!(r, c);
}

// ===========================================================================
// Section 7: GateValidationResult methods — is_blocked, summary
// ===========================================================================

#[test]
fn is_blocked_returns_false_when_passed() {
    let r = run_gate(42);
    assert!(r.passed);
    assert!(!r.is_blocked());
}

#[test]
fn is_blocked_returns_true_when_not_passed() {
    // Manually construct a failed result.
    let r = GateValidationResult {
        seed: 0,
        scenarios: vec![],
        passed: false,
        total_scenarios: 1,
        passed_scenarios: 0,
        events: vec![],
        result_digest: "0000000000000000".to_string(),
    };
    assert!(r.is_blocked());
}

#[test]
fn summary_starts_with_pass_when_all_passed() {
    let r = run_gate(42);
    assert!(r.passed);
    let s = r.summary();
    assert!(s.starts_with("PASS:"), "expected PASS prefix, got: {s}");
}

#[test]
fn summary_contains_scenario_counts_when_passed() {
    let r = run_gate(42);
    let s = r.summary();
    let expected = format!("{}/{}", r.passed_scenarios, r.total_scenarios);
    assert!(s.contains(&expected), "summary should contain counts: {s}");
}

#[test]
fn summary_starts_with_blocked_when_failed() {
    let failed_scenario = FaultScenarioResult {
        scenario_id: "fail-scenario".to_string(),
        fault_type: FaultType::ByzantineBehavior,
        passed: false,
        criteria: vec![],
        receipts_emitted: 0,
        final_state: None,
        detection_latency_ns: 999_999_999,
        isolation_verified: false,
        recovery_verified: false,
    };
    let r = GateValidationResult {
        seed: 0,
        scenarios: vec![failed_scenario],
        passed: false,
        total_scenarios: 1,
        passed_scenarios: 0,
        events: vec![],
        result_digest: "0000000000000000".to_string(),
    };
    let s = r.summary();
    assert!(
        s.starts_with("BLOCKED:"),
        "expected BLOCKED prefix, got: {s}"
    );
}

#[test]
fn summary_blocked_lists_failed_scenario_ids() {
    let failed_scenario = FaultScenarioResult {
        scenario_id: "my-failed-one".to_string(),
        fault_type: FaultType::CascadingFailure,
        passed: false,
        criteria: vec![],
        receipts_emitted: 0,
        final_state: None,
        detection_latency_ns: 0,
        isolation_verified: false,
        recovery_verified: false,
    };
    let r = GateValidationResult {
        seed: 0,
        scenarios: vec![failed_scenario],
        passed: false,
        total_scenarios: 1,
        passed_scenarios: 0,
        events: vec![],
        result_digest: "0000000000000000".to_string(),
    };
    let s = r.summary();
    assert!(
        s.contains("my-failed-one"),
        "blocked summary should list failed scenario: {s}"
    );
    assert!(
        s.contains("cascading_failure"),
        "blocked summary should list fault type: {s}"
    );
}

// ===========================================================================
// Section 8: QuarantineMeshGateRunner — construction and run
// ===========================================================================

#[test]
fn runner_new_creates_with_given_seed() {
    let runner = QuarantineMeshGateRunner::new(12345);
    // We verify through the result seed field.
    let mut runner = runner;
    let result = runner.run_all();
    assert_eq!(result.seed, 12345);
}

#[test]
fn runner_run_all_produces_seven_scenarios() {
    let result = run_gate(42);
    // 5 fault types + 1 degraded coordinator + 1 benign = 7
    assert_eq!(result.total_scenarios, 7);
    assert_eq!(result.scenarios.len(), 7);
}

#[test]
fn runner_run_all_passes_all_scenarios() {
    let result = run_gate(42);
    assert!(
        result.passed,
        "all scenarios should pass: {}",
        result.summary()
    );
    assert_eq!(result.passed_scenarios, result.total_scenarios);
}

#[test]
fn runner_scenarios_cover_all_fault_types() {
    let result = run_gate(42);
    let fault_types: std::collections::BTreeSet<FaultType> =
        result.scenarios.iter().map(|s| s.fault_type).collect();
    assert!(fault_types.contains(&FaultType::NetworkPartition));
    assert!(fault_types.contains(&FaultType::ByzantineBehavior));
    assert!(fault_types.contains(&FaultType::CascadingFailure));
    assert!(fault_types.contains(&FaultType::ResourceExhaustion));
    assert!(fault_types.contains(&FaultType::ClockSkew));
}

#[test]
fn runner_scenarios_include_specific_scenario_ids() {
    let result = run_gate(42);
    let ids: Vec<&str> = result
        .scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert!(ids.contains(&"partition-ext-a"));
    assert!(ids.contains(&"byzantine-ext-b"));
    assert!(ids.contains(&"cascade-ext-c"));
    assert!(ids.contains(&"exhaustion-ext-d"));
    assert!(ids.contains(&"skew-ext-e"));
    assert!(ids.contains(&"degraded-coordinator"));
    assert!(ids.contains(&"benign-no-quarantine"));
}

// ===========================================================================
// Section 9: Individual scenario validation
// ===========================================================================

#[test]
fn partition_scenario_quarantines_target() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "partition-ext-a")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::NetworkPartition);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
    assert!(s.receipts_emitted > 0);
    assert!(s.isolation_verified);
    assert!(s.recovery_verified);
}

#[test]
fn byzantine_scenario_quarantines_target() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "byzantine-ext-b")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::ByzantineBehavior);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
    assert!(s.receipts_emitted > 0);
}

#[test]
fn cascading_scenario_quarantines_target() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "cascade-ext-c")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::CascadingFailure);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
}

#[test]
fn exhaustion_scenario_quarantines_target() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "exhaustion-ext-d")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::ResourceExhaustion);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
}

#[test]
fn clock_skew_scenario_quarantines_target() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "skew-ext-e")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::ClockSkew);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
}

#[test]
fn degraded_coordinator_quarantines_under_tightened_threshold() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "degraded-coordinator")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.fault_type, FaultType::NetworkPartition);
    assert_eq!(s.final_state, Some(ContainmentState::Quarantined));
    // 400ms detection should be within 500ms SLA.
    assert!(s.detection_latency_ns <= 500_000_000);
}

#[test]
fn benign_extension_remains_running() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    assert!(s.passed);
    assert_eq!(s.final_state, Some(ContainmentState::Running));
    assert_eq!(s.receipts_emitted, 0);
    assert!(s.isolation_verified);
    assert!(s.recovery_verified);
}

// ===========================================================================
// Section 10: SLA / detection latency
// ===========================================================================

const DETECTION_SLA_NS: u64 = 500_000_000;

#[test]
fn all_scenarios_within_detection_sla() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.detection_latency_ns <= DETECTION_SLA_NS,
            "{} latency {}ns exceeds SLA {}ns",
            s.scenario_id,
            s.detection_latency_ns,
            DETECTION_SLA_NS,
        );
    }
}

#[test]
fn partition_detection_latency_100ms() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "partition-ext-a")
        .unwrap();
    assert_eq!(s.detection_latency_ns, 100_000_000);
}

#[test]
fn byzantine_detection_latency_200ms() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "byzantine-ext-b")
        .unwrap();
    assert_eq!(s.detection_latency_ns, 200_000_000);
}

#[test]
fn cascading_detection_latency_300ms() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "cascade-ext-c")
        .unwrap();
    assert_eq!(s.detection_latency_ns, 300_000_000);
}

#[test]
fn degraded_detection_latency_400ms() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "degraded-coordinator")
        .unwrap();
    assert_eq!(s.detection_latency_ns, 400_000_000);
}

#[test]
fn benign_detection_latency_zero() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    assert_eq!(s.detection_latency_ns, 0);
}

// ===========================================================================
// Section 11: Isolation invariant
// ===========================================================================

#[test]
fn all_scenarios_verify_isolation_invariant() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.isolation_verified,
            "{}: isolation should hold",
            s.scenario_id,
        );
    }
}

// ===========================================================================
// Section 12: Recovery / forensic verification
// ===========================================================================

#[test]
fn quarantined_scenarios_verify_recovery() {
    let result = run_gate(42);
    for s in &result.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            assert!(
                s.recovery_verified,
                "{}: quarantined should have forensic snapshot verified",
                s.scenario_id,
            );
        }
    }
}

#[test]
fn benign_scenario_verifies_recovery_as_running() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    assert!(s.recovery_verified);
    assert_eq!(s.final_state, Some(ContainmentState::Running));
}

// ===========================================================================
// Section 13: Criteria coverage
// ===========================================================================

#[test]
fn quarantine_scenarios_have_at_least_five_criteria() {
    let result = run_gate(42);
    for s in &result.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            // detection_within_sla, containment_action_correct, receipt_signed,
            // isolation_invariant, recovery_or_forensic = 5
            assert!(
                s.criteria.len() >= 5,
                "{}: quarantined scenario has only {} criteria",
                s.scenario_id,
                s.criteria.len()
            );
        }
    }
}

#[test]
fn benign_scenario_has_at_least_four_criteria() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    // detection_within_sla, containment_action_correct, isolation_invariant, recovery_or_forensic
    assert!(
        s.criteria.len() >= 4,
        "benign scenario has only {} criteria",
        s.criteria.len()
    );
}

#[test]
fn all_criteria_pass_in_passing_gate() {
    let result = run_gate(42);
    assert!(result.passed);
    for s in &result.scenarios {
        for c in &s.criteria {
            assert!(
                c.passed,
                "{}:{} should pass: {}",
                s.scenario_id, c.name, c.detail,
            );
        }
    }
}

#[test]
fn criteria_names_include_detection_sla() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.criteria.iter().any(|c| c.name == "detection_within_sla"),
            "{} missing detection_within_sla criterion",
            s.scenario_id,
        );
    }
}

#[test]
fn criteria_names_include_containment_action_correct() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.criteria
                .iter()
                .any(|c| c.name == "containment_action_correct"),
            "{} missing containment_action_correct criterion",
            s.scenario_id,
        );
    }
}

#[test]
fn criteria_names_include_isolation_invariant() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.criteria.iter().any(|c| c.name == "isolation_invariant"),
            "{} missing isolation_invariant criterion",
            s.scenario_id,
        );
    }
}

#[test]
fn criteria_names_include_recovery_or_forensic() {
    let result = run_gate(42);
    for s in &result.scenarios {
        assert!(
            s.criteria.iter().any(|c| c.name == "recovery_or_forensic"),
            "{} missing recovery_or_forensic criterion",
            s.scenario_id,
        );
    }
}

#[test]
fn quarantine_scenarios_have_receipt_signed_criterion() {
    let result = run_gate(42);
    for s in &result.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            assert!(
                s.criteria.iter().any(|c| c.name == "receipt_signed"),
                "{}: quarantined scenario missing receipt_signed criterion",
                s.scenario_id,
            );
        }
    }
}

// ===========================================================================
// Section 14: Receipts
// ===========================================================================

#[test]
fn quarantine_scenarios_emit_at_least_one_receipt() {
    let result = run_gate(42);
    for s in &result.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            assert!(
                s.receipts_emitted > 0,
                "{}: quarantined should emit receipts",
                s.scenario_id,
            );
        }
    }
}

#[test]
fn benign_scenario_emits_zero_receipts() {
    let result = run_gate(42);
    let s = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    assert_eq!(s.receipts_emitted, 0);
}

// ===========================================================================
// Section 15: Structured events
// ===========================================================================

#[test]
fn gate_emits_at_least_eight_events() {
    let result = run_gate(42);
    // 7 per-scenario + 1 gate_validation_complete
    assert!(
        result.events.len() >= 8,
        "expected >=8 events, got {}",
        result.events.len()
    );
}

#[test]
fn events_all_have_required_tracing_fields() {
    let result = run_gate(42);
    for e in &result.events {
        assert!(!e.trace_id.is_empty(), "trace_id should not be empty");
        assert!(!e.decision_id.is_empty(), "decision_id should not be empty");
        assert!(!e.policy_id.is_empty(), "policy_id should not be empty");
        assert_eq!(e.component, "quarantine_mesh_gate");
    }
}

#[test]
fn events_trace_id_contains_seed_hex() {
    let result = run_gate(42);
    let expected_suffix = format!("{:016x}", 42u64);
    for e in &result.events {
        assert!(
            e.trace_id.contains(&expected_suffix),
            "trace_id should contain seed hex: {}",
            e.trace_id,
        );
    }
}

#[test]
fn events_decision_id_contains_seed_hex() {
    let result = run_gate(42);
    let expected_suffix = format!("{:016x}", 42u64);
    for e in &result.events {
        assert!(
            e.decision_id.contains(&expected_suffix),
            "decision_id should contain seed hex: {}",
            e.decision_id,
        );
    }
}

#[test]
fn events_policy_id_is_quarantine_mesh_gate_v1() {
    let result = run_gate(42);
    for e in &result.events {
        assert_eq!(e.policy_id, "quarantine-mesh-gate-v1");
    }
}

#[test]
fn final_event_is_gate_validation_complete() {
    let result = run_gate(42);
    let last = result.events.last().unwrap();
    assert_eq!(last.event, "gate_validation_complete");
}

#[test]
fn final_event_outcome_pass_when_gate_passes() {
    let result = run_gate(42);
    assert!(result.passed);
    let last = result.events.last().unwrap();
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
}

#[test]
fn per_scenario_events_have_fault_type_and_target() {
    let result = run_gate(42);
    let scenario_events: Vec<&GateValidationEvent> = result
        .events
        .iter()
        .filter(|e| e.event == "fault_scenario_complete")
        .collect();
    assert_eq!(scenario_events.len(), 7);
    for e in &scenario_events {
        assert!(
            e.fault_type.is_some(),
            "scenario event should have fault_type"
        );
        assert!(
            e.target_component.is_some(),
            "scenario event should have target_component"
        );
    }
}

#[test]
fn scenario_pass_events_have_no_error_code() {
    let result = run_gate(42);
    assert!(result.passed);
    let pass_events: Vec<&GateValidationEvent> = result
        .events
        .iter()
        .filter(|e| e.event == "fault_scenario_complete" && e.outcome == "pass")
        .collect();
    assert!(!pass_events.is_empty());
    for e in &pass_events {
        assert!(
            e.error_code.is_none(),
            "pass event should have no error_code"
        );
    }
}

// ===========================================================================
// Section 16: Digest properties
// ===========================================================================

#[test]
fn digest_is_16_hex_chars() {
    let result = run_gate(42);
    assert_eq!(result.result_digest.len(), 16);
    assert!(result.result_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn digest_is_lowercase_hex() {
    let result = run_gate(42);
    assert!(
        result
            .result_digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
}

#[test]
fn digest_different_for_different_seeds() {
    let r1 = run_gate(1);
    let r2 = run_gate(2);
    assert_ne!(r1.result_digest, r2.result_digest);
}

#[test]
fn digest_non_empty() {
    let r = run_gate(0);
    assert!(!r.result_digest.is_empty());
}

// ===========================================================================
// Section 17: Determinism
// ===========================================================================

#[test]
fn deterministic_same_seed_same_result() {
    let r1 = run_gate(42);
    let r2 = run_gate(42);
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_digest_across_runs() {
    let r1 = run_gate(77);
    let r2 = run_gate(77);
    assert_eq!(r1.result_digest, r2.result_digest);
}

#[test]
fn deterministic_scenario_order_across_runs() {
    let r1 = run_gate(100);
    let r2 = run_gate(100);
    let ids1: Vec<&str> = r1
        .scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    let ids2: Vec<&str> = r2
        .scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert_eq!(ids1, ids2);
}

#[test]
fn deterministic_event_count_across_runs() {
    let r1 = run_gate(999);
    let r2 = run_gate(999);
    assert_eq!(r1.events.len(), r2.events.len());
}

#[test]
fn deterministic_criteria_across_runs() {
    let r1 = run_gate(55);
    let r2 = run_gate(55);
    for (s1, s2) in r1.scenarios.iter().zip(r2.scenarios.iter()) {
        assert_eq!(
            s1.criteria, s2.criteria,
            "criteria differ for {}",
            s1.scenario_id
        );
    }
}

// ===========================================================================
// Section 18: Multiple seeds all pass
// ===========================================================================

#[test]
fn many_seeds_all_pass() {
    for seed in [
        0,
        1,
        42,
        100,
        255,
        999,
        12345,
        54321,
        u64::MAX,
        u64::MAX - 1,
    ] {
        let result = run_gate(seed);
        assert!(
            result.passed,
            "seed {seed} should pass: {}",
            result.summary()
        );
    }
}

#[test]
fn seed_zero_passes() {
    let result = run_gate(0);
    assert!(result.passed);
    assert_eq!(result.seed, 0);
}

#[test]
fn seed_max_passes() {
    let result = run_gate(u64::MAX);
    assert!(result.passed);
    assert_eq!(result.seed, u64::MAX);
}

#[test]
fn seed_max_wrapping_add_does_not_panic() {
    // The runner uses wrapping_add for scenario seeds, verify u64::MAX works.
    let result = run_gate(u64::MAX);
    assert_eq!(result.total_scenarios, 7);
    assert!(result.passed);
}

// ===========================================================================
// Section 19: Cross-concern integration
// ===========================================================================

#[test]
fn gate_result_serde_json_roundtrip_preserves_all_nested_structures() {
    let r = run_gate(42);
    let json = serde_json::to_string_pretty(&r).unwrap();
    let back: GateValidationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(r.seed, back.seed);
    assert_eq!(r.passed, back.passed);
    assert_eq!(r.total_scenarios, back.total_scenarios);
    assert_eq!(r.passed_scenarios, back.passed_scenarios);
    assert_eq!(r.result_digest, back.result_digest);
    assert_eq!(r.scenarios.len(), back.scenarios.len());
    assert_eq!(r.events.len(), back.events.len());

    for (orig, restored) in r.scenarios.iter().zip(back.scenarios.iter()) {
        assert_eq!(orig, restored);
    }
    for (orig, restored) in r.events.iter().zip(back.events.iter()) {
        assert_eq!(orig, restored);
    }
}

#[test]
fn gate_integration_quarantine_isolation_does_not_affect_peers() {
    // Run gate and confirm that for every scenario that quarantines a target,
    // the peer extension stays Running (verified via isolation_verified field).
    let r = run_gate(42);
    for s in &r.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            assert!(
                s.isolation_verified,
                "{}: quarantine should not affect peers",
                s.scenario_id,
            );
        }
    }
}

#[test]
fn gate_integration_benign_not_escalated() {
    let r = run_gate(42);
    let benign = r
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    // Benign should not be quarantined, terminated, or suspended.
    assert_eq!(benign.final_state, Some(ContainmentState::Running));
    assert_eq!(benign.receipts_emitted, 0);
}

#[test]
fn gate_integration_degraded_mode_uses_tighter_thresholds() {
    // The degraded-coordinator scenario uses 400ms latency which is within SLA.
    // It should still be quarantined because thresholds are halved in degraded mode.
    let r = run_gate(42);
    let degraded = r
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "degraded-coordinator")
        .unwrap();
    assert!(degraded.passed);
    assert_eq!(degraded.final_state, Some(ContainmentState::Quarantined));
    assert!(degraded.receipts_emitted > 0);
}

#[test]
fn gate_integration_all_fault_types_produce_quarantine_when_expected() {
    let r = run_gate(42);
    for s in &r.scenarios {
        // All scenarios with expect_quarantine (everything except benign) should be quarantined.
        if s.scenario_id != "benign-no-quarantine" {
            assert_eq!(
                s.final_state,
                Some(ContainmentState::Quarantined),
                "{} should be quarantined",
                s.scenario_id,
            );
        }
    }
}

#[test]
fn gate_summary_and_is_blocked_consistent() {
    let r = run_gate(42);
    if r.passed {
        assert!(!r.is_blocked());
        assert!(r.summary().starts_with("PASS:"));
    } else {
        assert!(r.is_blocked());
        assert!(r.summary().starts_with("BLOCKED:"));
    }
}

#[test]
fn gate_total_scenarios_matches_scenarios_vec_len() {
    let r = run_gate(42);
    assert_eq!(r.total_scenarios, r.scenarios.len());
}

#[test]
fn gate_passed_scenarios_count_matches() {
    let r = run_gate(42);
    let actual_passed = r.scenarios.iter().filter(|s| s.passed).count();
    assert_eq!(r.passed_scenarios, actual_passed);
}

#[test]
fn gate_passed_flag_matches_scenario_counts() {
    let r = run_gate(42);
    assert_eq!(r.passed, r.passed_scenarios == r.total_scenarios);
}

// ===========================================================================
// Section 20: Serde edge cases for optional fields
// ===========================================================================

#[test]
fn fault_scenario_result_all_containment_states_serde() {
    for state in [
        ContainmentState::Running,
        ContainmentState::Challenged,
        ContainmentState::Sandboxed,
        ContainmentState::Suspended,
        ContainmentState::Terminated,
        ContainmentState::Quarantined,
    ] {
        let r = FaultScenarioResult {
            scenario_id: format!("test-{state}"),
            fault_type: FaultType::NetworkPartition,
            passed: true,
            criteria: vec![],
            receipts_emitted: 0,
            final_state: Some(state),
            detection_latency_ns: 0,
            isolation_verified: true,
            recovery_verified: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: FaultScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back, "serde roundtrip failed for state {state}");
    }
}

#[test]
fn gate_validation_event_serde_with_each_fault_type() {
    for ft in [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ] {
        let e = GateValidationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            fault_type: Some(ft),
            target_component: None,
            quarantine_action: None,
            latency_ns: None,
            isolation_verified: None,
            receipt_hash: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back, "serde roundtrip failed for fault type {ft}");
    }
}

// ===========================================================================
// Section 21: Debug formatting
// ===========================================================================

#[test]
fn runner_debug_does_not_panic() {
    let runner = QuarantineMeshGateRunner::new(42);
    let debug = format!("{:?}", runner);
    assert!(debug.contains("QuarantineMeshGateRunner"));
}

#[test]
fn gate_validation_result_debug_does_not_panic() {
    let r = run_gate(42);
    let debug = format!("{:?}", r);
    assert!(!debug.is_empty());
}

#[test]
fn fault_scenario_result_debug_does_not_panic() {
    let r = make_scenario_result(true);
    let debug = format!("{:?}", r);
    assert!(debug.contains("scenario-x"));
}
