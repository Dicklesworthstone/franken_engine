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
    clippy::identity_op
)]

//! Enrichment integration tests for the `quarantine_mesh_gate` module.

use std::collections::BTreeSet;

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::quarantine_mesh_gate::*;

// ===========================================================================
// FaultType Display uniqueness
// ===========================================================================

#[test]
fn enrichment_fault_type_display_all_unique() {
    let displays: BTreeSet<String> = [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ]
    .iter()
    .map(|ft| ft.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// FaultType serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_fault_type_serde_all_variants() {
    let variants = [
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ];
    for ft in &variants {
        let json = serde_json::to_string(ft).unwrap();
        let back: FaultType = serde_json::from_str(&json).unwrap();
        assert_eq!(*ft, back);
    }
}

// ===========================================================================
// FaultType ordering deterministic
// ===========================================================================

#[test]
fn enrichment_fault_type_ordering_deterministic() {
    let mut variants = vec![
        FaultType::ClockSkew,
        FaultType::NetworkPartition,
        FaultType::ResourceExhaustion,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
    ];
    let mut variants2 = variants.clone();
    variants.sort();
    variants2.sort();
    assert_eq!(variants, variants2);
    assert_eq!(variants[0], FaultType::NetworkPartition);
    assert_eq!(variants[4], FaultType::ClockSkew);
}

// ===========================================================================
// FaultScenario serde roundtrip
// ===========================================================================

#[test]
fn enrichment_fault_scenario_serde_roundtrip() {
    let scenario = FaultScenario {
        scenario_id: "test-sc".to_string(),
        fault_type: FaultType::ByzantineBehavior,
        target_extension: "ext-test-001".to_string(),
        detection_latency_ns: 250_000_000,
        expect_quarantine: true,
        seed: 42,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let back: FaultScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, back);
}

#[test]
fn enrichment_fault_scenario_no_quarantine_serde() {
    let scenario = FaultScenario {
        scenario_id: "benign-test".to_string(),
        fault_type: FaultType::NetworkPartition,
        target_extension: "ext-benign".to_string(),
        detection_latency_ns: 0,
        expect_quarantine: false,
        seed: 0,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let back: FaultScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, back);
}

// ===========================================================================
// FaultScenarioResult serde roundtrip
// ===========================================================================

#[test]
fn enrichment_fault_scenario_result_serde_roundtrip() {
    let result = FaultScenarioResult {
        scenario_id: "test-res".to_string(),
        fault_type: FaultType::CascadingFailure,
        passed: true,
        criteria: vec![
            CriterionResult {
                name: "sla".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            CriterionResult {
                name: "containment".to_string(),
                passed: true,
                detail: "quarantined".to_string(),
            },
        ],
        receipts_emitted: 1,
        final_state: Some(ContainmentState::Quarantined),
        detection_latency_ns: 300_000_000,
        isolation_verified: true,
        recovery_verified: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FaultScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// CriterionResult serde roundtrip
// ===========================================================================

#[test]
fn enrichment_criterion_result_serde_roundtrip() {
    let cr = CriterionResult {
        name: "isolation_invariant".to_string(),
        passed: false,
        detail: "peer was quarantined".to_string(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CriterionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

// ===========================================================================
// GateValidationEvent serde roundtrip - all optionals populated
// ===========================================================================

#[test]
fn enrichment_gate_event_all_fields_serde() {
    let event = GateValidationEvent {
        trace_id: "trace-full".to_string(),
        decision_id: "dec-full".to_string(),
        policy_id: "pol-full".to_string(),
        component: "quarantine_mesh_gate".to_string(),
        event: "full_event".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("E001".to_string()),
        fault_type: Some(FaultType::ByzantineBehavior),
        target_component: Some("ext-target".to_string()),
        quarantine_action: Some("isolate".to_string()),
        latency_ns: Some(100_000_000),
        isolation_verified: Some(true),
        receipt_hash: Some("abcdef01".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// GateValidationEvent serde roundtrip - all optionals None
// ===========================================================================

#[test]
fn enrichment_gate_event_all_nones_serde() {
    let event = GateValidationEvent {
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
    let json = serde_json::to_string(&event).unwrap();
    let back: GateValidationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// GateValidationResult serde roundtrip
// ===========================================================================

#[test]
fn enrichment_gate_validation_result_serde_roundtrip() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let json = serde_json::to_string(&result).unwrap();
    let back: GateValidationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// Gate passes for multiple seeds
// ===========================================================================

#[test]
fn enrichment_gate_passes_across_seeds() {
    for seed in [0u64, 1, 42, 100, 999, u64::MAX] {
        let mut runner = QuarantineMeshGateRunner::new(seed);
        let result = runner.run_all();
        assert!(
            result.passed,
            "seed {seed} should pass: {}",
            result.summary()
        );
        assert_eq!(result.seed, seed);
    }
}

// ===========================================================================
// Determinism: same seed produces identical results
// ===========================================================================

#[test]
fn enrichment_deterministic_across_100_runs() {
    let run = || {
        let mut runner = QuarantineMeshGateRunner::new(42);
        runner.run_all()
    };
    let baseline = run();
    for _ in 0..100 {
        let result = run();
        assert_eq!(result.result_digest, baseline.result_digest);
        assert_eq!(result.passed, baseline.passed);
        assert_eq!(result.total_scenarios, baseline.total_scenarios);
    }
}

// ===========================================================================
// Different seeds produce different digests
// ===========================================================================

#[test]
fn enrichment_different_seeds_different_digests() {
    let mut digests = BTreeSet::new();
    for seed in 0..10 {
        let mut runner = QuarantineMeshGateRunner::new(seed);
        let result = runner.run_all();
        digests.insert(result.result_digest);
    }
    assert_eq!(
        digests.len(),
        10,
        "10 different seeds should produce 10 different digests"
    );
}

// ===========================================================================
// Total scenarios = 7
// ===========================================================================

#[test]
fn enrichment_total_scenarios_is_seven() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    assert_eq!(result.total_scenarios, 7);
    assert_eq!(result.scenarios.len(), 7);
}

// ===========================================================================
// All quarantine scenarios end in Quarantined state
// ===========================================================================

#[test]
fn enrichment_quarantine_scenarios_end_quarantined() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for s in &result.scenarios {
        if s.scenario_id != "benign-no-quarantine" {
            assert_eq!(
                s.final_state,
                Some(ContainmentState::Quarantined),
                "{} should be quarantined",
                s.scenario_id
            );
        }
    }
}

// ===========================================================================
// Benign scenario stays Running
// ===========================================================================

#[test]
fn enrichment_benign_scenario_stays_running() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let benign = result
        .scenarios
        .iter()
        .find(|s| s.scenario_id == "benign-no-quarantine")
        .unwrap();
    assert!(benign.passed);
    assert_eq!(benign.final_state, Some(ContainmentState::Running));
    assert_eq!(benign.receipts_emitted, 0);
    assert_eq!(benign.detection_latency_ns, 0);
}

// ===========================================================================
// All scenarios verify isolation
// ===========================================================================

#[test]
fn enrichment_all_scenarios_verify_isolation() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for s in &result.scenarios {
        assert!(
            s.isolation_verified,
            "{} should verify isolation",
            s.scenario_id
        );
    }
}

// ===========================================================================
// Quarantine scenarios emit exactly one receipt
// ===========================================================================

#[test]
fn enrichment_quarantine_scenarios_emit_one_receipt() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for s in &result.scenarios {
        if s.final_state == Some(ContainmentState::Quarantined) {
            assert_eq!(
                s.receipts_emitted, 1,
                "{} should emit exactly 1 receipt",
                s.scenario_id
            );
        }
    }
}

// ===========================================================================
// Each scenario has at least 4 criteria
// ===========================================================================

#[test]
fn enrichment_each_scenario_has_criteria() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for s in &result.scenarios {
        assert!(
            s.criteria.len() >= 4,
            "{} should have at least 4 criteria, has {}",
            s.scenario_id,
            s.criteria.len()
        );
    }
}

// ===========================================================================
// All criteria have non-empty names and details
// ===========================================================================

#[test]
fn enrichment_criteria_have_nonempty_name_and_detail() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for s in &result.scenarios {
        for c in &s.criteria {
            assert!(
                !c.name.is_empty(),
                "criterion name empty in {}",
                s.scenario_id
            );
            assert!(
                !c.detail.is_empty(),
                "criterion detail empty in {}",
                s.scenario_id
            );
        }
    }
}

// ===========================================================================
// Summary format: PASS includes scenario count
// ===========================================================================

#[test]
fn enrichment_passing_summary_format() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let summary = result.summary();
    assert!(summary.starts_with("PASS:"), "summary = {summary}");
    assert!(summary.contains("7/7"), "summary = {summary}");
}

// ===========================================================================
// Blocked summary includes failed scenario IDs
// ===========================================================================

#[test]
fn enrichment_blocked_summary_includes_failed_ids() {
    let result = GateValidationResult {
        seed: 99,
        scenarios: vec![
            FaultScenarioResult {
                scenario_id: "fail-x".to_string(),
                fault_type: FaultType::NetworkPartition,
                passed: false,
                criteria: vec![],
                receipts_emitted: 0,
                final_state: None,
                detection_latency_ns: 0,
                isolation_verified: false,
                recovery_verified: false,
            },
            FaultScenarioResult {
                scenario_id: "pass-y".to_string(),
                fault_type: FaultType::ClockSkew,
                passed: true,
                criteria: vec![],
                receipts_emitted: 0,
                final_state: None,
                detection_latency_ns: 0,
                isolation_verified: true,
                recovery_verified: true,
            },
        ],
        passed: false,
        total_scenarios: 2,
        passed_scenarios: 1,
        events: vec![],
        result_digest: "0000000000000000".to_string(),
    };
    let summary = result.summary();
    assert!(summary.starts_with("BLOCKED:"));
    assert!(summary.contains("fail-x"));
    assert!(!summary.contains("pass-y"));
}

// ===========================================================================
// is_blocked correctness
// ===========================================================================

#[test]
fn enrichment_is_blocked_when_failed() {
    let result = GateValidationResult {
        seed: 0,
        scenarios: vec![],
        passed: false,
        total_scenarios: 0,
        passed_scenarios: 0,
        events: vec![],
        result_digest: "0000000000000000".to_string(),
    };
    assert!(result.is_blocked());
}

#[test]
fn enrichment_not_blocked_when_passed() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    assert!(!result.is_blocked());
}

// ===========================================================================
// Digest is 16 hex chars
// ===========================================================================

#[test]
fn enrichment_digest_is_16_hex_chars() {
    for seed in [0u64, 1, 42, u64::MAX] {
        let mut runner = QuarantineMeshGateRunner::new(seed);
        let result = runner.run_all();
        assert_eq!(result.result_digest.len(), 16, "seed={seed}");
        assert!(
            result.result_digest.chars().all(|c| c.is_ascii_hexdigit()),
            "seed={seed}, digest={}",
            result.result_digest
        );
    }
}

// ===========================================================================
// Events: per-scenario events carry fault_type and target
// ===========================================================================

#[test]
fn enrichment_per_scenario_events_carry_metadata() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let scenario_events: Vec<_> = result
        .events
        .iter()
        .filter(|e| e.event == "fault_scenario_complete")
        .collect();
    assert_eq!(scenario_events.len(), 7);
    for ev in &scenario_events {
        assert!(ev.fault_type.is_some());
        assert!(ev.target_component.is_some());
    }
}

// ===========================================================================
// Events: final event is gate_validation_complete
// ===========================================================================

#[test]
fn enrichment_final_event_is_gate_complete() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let final_event = result.events.last().unwrap();
    assert_eq!(final_event.event, "gate_validation_complete");
    assert_eq!(final_event.outcome, "pass");
    assert!(final_event.error_code.is_none());
}

// ===========================================================================
// Events: all events share same trace_id and decision_id
// ===========================================================================

#[test]
fn enrichment_events_consistent_trace_and_decision() {
    let mut runner = QuarantineMeshGateRunner::new(99);
    let result = runner.run_all();
    let trace = &result.events[0].trace_id;
    let decision = &result.events[0].decision_id;
    for ev in &result.events {
        assert_eq!(&ev.trace_id, trace);
        assert_eq!(&ev.decision_id, decision);
    }
}

// ===========================================================================
// Events: policy_id is constant v1
// ===========================================================================

#[test]
fn enrichment_events_policy_id_constant() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    for ev in &result.events {
        assert_eq!(ev.policy_id, "quarantine-mesh-gate-v1");
    }
}

// ===========================================================================
// Trace ID contains seed in hex
// ===========================================================================

#[test]
fn enrichment_trace_id_contains_hex_seed() {
    let mut runner = QuarantineMeshGateRunner::new(0xCAFE);
    let result = runner.run_all();
    let trace = &result.events[0].trace_id;
    assert!(
        trace.contains("cafe"),
        "trace_id should contain hex seed: {trace}"
    );
}

// ===========================================================================
// GateValidationResult clone equality
// ===========================================================================

#[test]
fn enrichment_gate_result_clone_equality() {
    let mut runner = QuarantineMeshGateRunner::new(42);
    let result = runner.run_all();
    let cloned = result.clone();
    assert_eq!(result, cloned);
}
