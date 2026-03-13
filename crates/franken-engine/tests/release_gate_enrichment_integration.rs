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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::lab_runtime::Verdict;
use frankenengine_engine::release_gate::{
    ExceptionPolicy, GateCheckKind, GateCheckResult, GateConfig, GateEvent, GateFailureDetail,
    GateFailureReport, IdempotencyVerification, ReleaseGate, ReleaseGateResult,
};

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(99), MockBudget::new(budget_ms))
}

// =========================================================================
// A. BTreeSet ordering and dedup for GateCheckKind
// =========================================================================

#[test]
fn enrichment_gate_check_kind_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(GateCheckKind::FrankenlabScenario);
    set.insert(GateCheckKind::EvidenceReplay);
    set.insert(GateCheckKind::ObligationTracking);
    set.insert(GateCheckKind::EvidenceCompleteness);
    set.insert(GateCheckKind::FrankenlabScenario); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_gate_check_kind_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let kinds = [
        GateCheckKind::FrankenlabScenario,
        GateCheckKind::EvidenceReplay,
        GateCheckKind::ObligationTracking,
        GateCheckKind::EvidenceCompleteness,
    ];
    for kind in &kinds {
        let mut h1 = DefaultHasher::new();
        kind.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// =========================================================================
// C. Display values distinct
// =========================================================================

#[test]
fn enrichment_gate_check_kind_display_distinct() {
    let displays: BTreeSet<String> = [
        GateCheckKind::FrankenlabScenario,
        GateCheckKind::EvidenceReplay,
        GateCheckKind::ObligationTracking,
        GateCheckKind::EvidenceCompleteness,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// D. Debug nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", GateCheckKind::FrankenlabScenario).is_empty());
    assert!(!format!("{:?}", GateCheckKind::EvidenceCompleteness).is_empty());

    let config = GateConfig::default();
    assert!(!format!("{config:?}").is_empty());

    let policy = ExceptionPolicy::default();
    assert!(!format!("{policy:?}").is_empty());

    let detail = GateFailureDetail {
        item_id: "s1".to_string(),
        failure_type: "assertion_failed".to_string(),
        expected: "true".to_string(),
        actual: "false".to_string(),
    };
    assert!(!format!("{detail:?}").is_empty());

    let event = GateEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: BTreeMap::new(),
    };
    assert!(!format!("{event:?}").is_empty());

    let check = GateCheckResult {
        kind: GateCheckKind::EvidenceReplay,
        passed: true,
        summary: "ok".to_string(),
        failure_details: Vec::new(),
        items_checked: 1,
        items_passed: 1,
    };
    assert!(!format!("{check:?}").is_empty());

    let gate = ReleaseGate::new(42);
    assert!(!format!("{gate:?}").is_empty());
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_gate_config() {
    let original = GateConfig::default();
    let mut cloned = original.clone();
    cloned.timeout_budget_ms = 999;
    cloned.required_check_kinds.clear();
    assert_eq!(original.timeout_budget_ms, 600_000);
    assert_eq!(original.required_check_kinds.len(), 4);
}

#[test]
fn enrichment_clone_independence_exception_policy() {
    let original = ExceptionPolicy::default();
    let mut cloned = original.clone();
    cloned.allow_exceptions = true;
    cloned.max_exception_hours = 999;
    assert!(!original.allow_exceptions);
    assert_eq!(original.max_exception_hours, 72);
    assert!(cloned.allow_exceptions);
    assert_eq!(cloned.max_exception_hours, 999);
}

#[test]
fn enrichment_clone_independence_release_gate_result() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let mut cloned = result.clone();
    cloned.exception_applied = true;
    cloned.exception_justification = "override".to_string();
    assert!(!result.exception_applied);
    assert!(result.exception_justification.is_empty());
}

// =========================================================================
// F. Serde roundtrips
// =========================================================================

#[test]
fn enrichment_gate_check_result_serde_roundtrip() {
    let check = GateCheckResult {
        kind: GateCheckKind::FrankenlabScenario,
        passed: false,
        summary: "2/3 passed".to_string(),
        failure_details: vec![GateFailureDetail {
            item_id: "scenario-1".to_string(),
            failure_type: "assertion_failed".to_string(),
            expected: "true".to_string(),
            actual: "budget exceeded".to_string(),
        }],
        items_checked: 3,
        items_passed: 2,
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: GateCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn enrichment_gate_failure_detail_serde_roundtrip() {
    let detail = GateFailureDetail {
        item_id: "replay-check-1".to_string(),
        failure_type: "divergence".to_string(),
        expected: "matching".to_string(),
        actual: "diverged".to_string(),
    };
    let json = serde_json::to_string(&detail).unwrap();
    let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, back);
}

#[test]
fn enrichment_gate_event_serde_roundtrip() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    let event = GateEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: "release-gate-v1".to_string(),
        component: "release_gate".to_string(),
        event: "frankenlab_scenarios_checked".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FRANKENLAB_SCENARIO_FAILED".to_string()),
        metadata,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_gate_event_no_error_code_serde() {
    let event = GateEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.error_code.is_none());
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_exception_policy_serde_roundtrip() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: true,
        max_exception_hours: 24,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_idempotency_verification_serde_roundtrip() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "abc123".to_string(),
        second_digest: "abc123".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert!(back.is_hermetic());
}

#[test]
fn enrichment_gate_failure_report_serde_roundtrip() {
    let report = GateFailureReport {
        blocked: true,
        failing_gates: vec![GateCheckKind::EvidenceReplay],
        details: vec![GateFailureDetail {
            item_id: "r1".to_string(),
            failure_type: "divergence".to_string(),
            expected: "zero".to_string(),
            actual: "one".to_string(),
        }],
        summary: "BLOCKED: 1 gate(s) failed: evidence_replay".to_string(),
        seed: 42,
        result_digest: "abc".to_string(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateFailureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_release_gate_result_serde_roundtrip() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// =========================================================================
// G. Default values
// =========================================================================

#[test]
fn enrichment_gate_config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.timeout_budget_ms, 600_000);
    assert_eq!(config.required_check_kinds.len(), 4);
    assert!(
        config
            .required_check_kinds
            .contains(&GateCheckKind::FrankenlabScenario)
    );
    assert!(
        config
            .required_check_kinds
            .contains(&GateCheckKind::EvidenceReplay)
    );
    assert!(
        config
            .required_check_kinds
            .contains(&GateCheckKind::ObligationTracking)
    );
    assert!(
        config
            .required_check_kinds
            .contains(&GateCheckKind::EvidenceCompleteness)
    );
}

#[test]
fn enrichment_exception_policy_default_values() {
    let policy = ExceptionPolicy::default();
    assert!(!policy.allow_exceptions);
    assert!(policy.requires_adr_reference);
    assert!(policy.requires_security_review);
    assert_eq!(policy.max_exception_hours, 72);
}

// =========================================================================
// H. Infrastructure validation (fail-closed)
// =========================================================================

#[test]
fn enrichment_empty_required_checks_is_infrastructure_failure() {
    let config = GateConfig {
        timeout_budget_ms: 100_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
        }
        _ => panic!("expected Fail verdict"),
    }
}

#[test]
fn enrichment_zero_timeout_is_infrastructure_failure() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
        }
        _ => panic!("expected Fail verdict"),
    }
}

// =========================================================================
// I. Exception policy enforcement
// =========================================================================

#[test]
fn enrichment_exception_denied_when_not_allowed() {
    let gate = ReleaseGate::new(42);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    let err = gate
        .apply_exception(&mut result, "override reason", Some("ADR-001"))
        .unwrap_err();
    assert!(err.contains("does not allow"));
}

#[test]
fn enrichment_exception_denied_without_adr_when_required() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    let err = gate
        .apply_exception(&mut result, "reason", None)
        .unwrap_err();
    assert!(err.contains("ADR reference"));
}

#[test]
fn enrichment_exception_denied_with_empty_justification() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    let err = gate.apply_exception(&mut result, "", None).unwrap_err();
    assert!(err.contains("justification"));
}

#[test]
fn enrichment_exception_succeeds_when_policy_allows() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "emergency hotfix", None)
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.exception_justification, "emergency hotfix");
    assert_eq!(result.verdict, Verdict::Pass);
    // Digest should have been recomputed
    assert_ne!(result.result_digest, "orig");
}

// =========================================================================
// J. Failure report structure
// =========================================================================

#[test]
fn enrichment_failure_report_passing_gate() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert!(!report.blocked);
    assert!(report.failing_gates.is_empty());
    assert!(report.details.is_empty());
    assert_eq!(report.summary, "all gates passed");
}

#[test]
fn enrichment_failure_report_infrastructure_failure() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert!(report.blocked);
    assert!(report.summary.contains("BLOCKED"));
}

// =========================================================================
// K. Idempotency verification
// =========================================================================

#[test]
fn enrichment_idempotency_verification_is_hermetic() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "same".to_string(),
        second_digest: "same".to_string(),
    };
    assert!(v.is_hermetic());
}

#[test]
fn enrichment_idempotency_not_hermetic_when_digests_differ() {
    let v = IdempotencyVerification {
        digests_match: false,
        verdicts_match: true,
        checks_match: true,
        first_digest: "a".to_string(),
        second_digest: "b".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn enrichment_idempotency_not_hermetic_when_verdicts_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: false,
        checks_match: true,
        first_digest: "same".to_string(),
        second_digest: "same".to_string(),
    };
    assert!(!v.is_hermetic());
}

// =========================================================================
// L. Gate events are emitted
// =========================================================================

#[test]
fn enrichment_gate_events_present_after_evaluation() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // At least one event per check + final evaluation event
    assert!(result.gate_events.len() >= 5);
    // All events have non-empty trace_id
    for event in &result.gate_events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
    }
}

#[test]
fn enrichment_gate_events_contain_final_evaluation() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let final_event = result
        .gate_events
        .iter()
        .find(|e| e.event == "release_gate_evaluated");
    assert!(final_event.is_some());
}

// =========================================================================
// M. Result digest is deterministic
// =========================================================================

#[test]
fn enrichment_result_digest_deterministic_same_seed() {
    let mut gate1 = ReleaseGate::new(42);
    let mut cx1 = mock_cx(200_000);
    let result1 = gate1.evaluate(&mut cx1);

    let mut gate2 = ReleaseGate::new(42);
    let mut cx2 = mock_cx(200_000);
    let result2 = gate2.evaluate(&mut cx2);

    assert_eq!(result1.result_digest, result2.result_digest);
}

#[test]
fn enrichment_result_digest_nonempty() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.result_digest.is_empty());
}

// =========================================================================
// N. Copy semantics for GateCheckKind
// =========================================================================

#[test]
fn enrichment_copy_semantics_gate_check_kind() {
    let a = GateCheckKind::EvidenceReplay;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// O. Constructor variants
// =========================================================================

#[test]
fn enrichment_with_config_and_policy_constructor() {
    let config = GateConfig {
        timeout_budget_ms: 300_000,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 12,
    };
    let mut gate = ReleaseGate::with_config_and_policy(99, config.clone(), policy.clone());
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 99);
}
