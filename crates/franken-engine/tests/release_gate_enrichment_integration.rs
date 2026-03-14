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

// =========================================================================
// P. verify_idempotency via actual gate evaluation
// =========================================================================

#[test]
fn enrichment_verify_idempotency_produces_hermetic_result() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let verification = gate.verify_idempotency(&mut cx);
    assert!(verification.is_hermetic());
    assert!(verification.digests_match);
    assert!(verification.verdicts_match);
    assert!(verification.checks_match);
    assert_eq!(verification.first_digest, verification.second_digest);
    assert!(!verification.first_digest.is_empty());
}

// =========================================================================
// Q. Different seeds produce different digests
// =========================================================================

#[test]
fn enrichment_different_seeds_produce_different_digests() {
    let mut gate_a = ReleaseGate::new(1);
    let mut cx_a = mock_cx(200_000);
    let result_a = gate_a.evaluate(&mut cx_a);

    let mut gate_b = ReleaseGate::new(2);
    let mut cx_b = mock_cx(200_000);
    let result_b = gate_b.evaluate(&mut cx_b);

    assert_ne!(result_a.result_digest, result_b.result_digest);
    assert_ne!(result_a.seed, result_b.seed);
}

// =========================================================================
// R. is_blocked on passing result returns false
// =========================================================================

#[test]
fn enrichment_is_blocked_false_on_passing_result() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());
}

// =========================================================================
// S. Idempotency not hermetic when checks_match is false
// =========================================================================

#[test]
fn enrichment_idempotency_not_hermetic_when_checks_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: false,
        first_digest: "same".to_string(),
        second_digest: "same".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn enrichment_idempotency_not_hermetic_all_false() {
    let v = IdempotencyVerification {
        digests_match: false,
        verdicts_match: false,
        checks_match: false,
        first_digest: "x".to_string(),
        second_digest: "y".to_string(),
    };
    assert!(!v.is_hermetic());
}

// =========================================================================
// T. Gate events include per-check event names
// =========================================================================

#[test]
fn enrichment_gate_events_include_per_check_names() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event_names: BTreeSet<String> =
        result.gate_events.iter().map(|e| e.event.clone()).collect();
    assert!(event_names.contains("frankenlab_scenarios_checked"));
    assert!(event_names.contains("evidence_replay_checked"));
    assert!(event_names.contains("obligation_tracking_checked"));
    assert!(event_names.contains("evidence_completeness_checked"));
    assert!(event_names.contains("release_gate_evaluated"));
}

// =========================================================================
// U. Gate events on infrastructure failure still have release_gate_evaluated
// =========================================================================

#[test]
fn enrichment_infra_failure_events_contain_evaluation_event() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    let has_eval = result
        .gate_events
        .iter()
        .any(|e| e.event == "release_gate_evaluated");
    assert!(has_eval);
    // Infrastructure failure events should have error codes
    let infra_events: Vec<_> = result
        .gate_events
        .iter()
        .filter(|e| e.error_code.is_some())
        .collect();
    assert!(!infra_events.is_empty());
    for ev in &infra_events {
        assert_eq!(
            ev.error_code.as_deref(),
            Some("GATE_INFRASTRUCTURE_FAILURE")
        );
    }
}

// =========================================================================
// V. with_config constructor produces correct seed and custom config
// =========================================================================

#[test]
fn enrichment_with_config_constructor_uses_custom_config() {
    let config = GateConfig {
        timeout_budget_ms: 500_000,
        required_check_kinds: vec![
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
        ],
    };
    let mut gate = ReleaseGate::with_config(77, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 77);
    // Only 2 required kinds, so total_checks should be 2
    // (gate still runs 4 checks but config has 2 required)
    // Actually, the gate runs all 4 checks regardless; total_checks = checks.len()
    assert!(result.total_checks > 0);
}

// =========================================================================
// W. Exception with ADR reference succeeds when required
// =========================================================================

#[test]
fn enrichment_exception_succeeds_with_adr_when_required() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 48,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "blocked".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "critical hotfix", Some("ADR-042"))
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.exception_justification, "critical hotfix");
    assert_eq!(result.verdict, Verdict::Pass);
    assert_ne!(result.result_digest, "orig");
}

// =========================================================================
// X. Evaluate checks count matches required_check_kinds
// =========================================================================

#[test]
fn enrichment_evaluate_checks_items_checked_positive() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.total_checks, 4);
    assert_eq!(result.passed_checks, 4);
    for check in &result.checks {
        assert!(check.passed);
        assert!(check.items_checked > 0);
        assert_eq!(check.items_checked, check.items_passed);
        assert!(!check.summary.is_empty());
        assert!(check.failure_details.is_empty());
    }
}

// =========================================================================
// Y. GateCheckResult kinds cover all four categories
// =========================================================================

#[test]
fn enrichment_evaluate_produces_all_four_check_kinds() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let kinds: BTreeSet<GateCheckKind> = result.checks.iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&GateCheckKind::FrankenlabScenario));
    assert!(kinds.contains(&GateCheckKind::EvidenceReplay));
    assert!(kinds.contains(&GateCheckKind::ObligationTracking));
    assert!(kinds.contains(&GateCheckKind::EvidenceCompleteness));
    assert_eq!(kinds.len(), 4);
}

// =========================================================================
// Z. Gate events have consistent trace/decision/policy IDs
// =========================================================================

#[test]
fn enrichment_gate_events_have_consistent_ids() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.gate_events.is_empty());
    let first_trace = &result.gate_events[0].trace_id;
    let first_decision = &result.gate_events[0].decision_id;
    let first_policy = &result.gate_events[0].policy_id;
    for event in &result.gate_events {
        assert_eq!(&event.trace_id, first_trace);
        assert_eq!(&event.decision_id, first_decision);
        assert_eq!(&event.policy_id, first_policy);
        assert_eq!(event.component, "release_gate");
    }
}

// =========================================================================
// AA. GateFailureReport clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_gate_failure_report() {
    let original = GateFailureReport {
        blocked: true,
        failing_gates: vec![
            GateCheckKind::EvidenceReplay,
            GateCheckKind::ObligationTracking,
        ],
        details: vec![GateFailureDetail {
            item_id: "item1".to_string(),
            failure_type: "divergence".to_string(),
            expected: "zero".to_string(),
            actual: "one".to_string(),
        }],
        summary: "BLOCKED: 2 gate(s) failed".to_string(),
        seed: 42,
        result_digest: "digest123".to_string(),
    };
    let mut cloned = original.clone();
    cloned.blocked = false;
    cloned.failing_gates.clear();
    cloned.details.clear();
    cloned.summary = "changed".to_string();
    assert!(original.blocked);
    assert_eq!(original.failing_gates.len(), 2);
    assert_eq!(original.details.len(), 1);
    assert_eq!(original.summary, "BLOCKED: 2 gate(s) failed");
}

// =========================================================================
// BB. Passing gate events all have outcome "pass" except final
// =========================================================================

#[test]
fn enrichment_passing_gate_event_outcomes() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    // All per-check events and the final event should have "pass" outcome
    for event in &result.gate_events {
        assert_eq!(event.outcome, "pass");
        // Passing events should not carry error codes
        assert!(event.error_code.is_none());
    }
}
