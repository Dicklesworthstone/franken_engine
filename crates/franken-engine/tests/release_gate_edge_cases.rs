//! Edge-case tests for `release_gate` module.
//!
//! Covers: GateCheckKind, GateCheckResult, GateFailureDetail, GateConfig,
//! ReleaseGateResult, GateFailureReport, GateEvent, ExceptionPolicy,
//! ReleaseGate, IdempotencyVerification, fail-closed infrastructure
//! validation, timeout handling, exception policy enforcement,
//! failure_report behaviour, determinism, and content-addressable digests.

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

use std::collections::{BTreeMap, HashSet};

use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use frankenengine_engine::lab_runtime::Verdict;
use frankenengine_engine::release_gate::{
    ExceptionPolicy, GateCheckKind, GateCheckResult, GateConfig, GateEvent, GateFailureDetail,
    GateFailureReport, IdempotencyVerification, ReleaseGate, ReleaseGateResult,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(trace_id_from_seed(99), MockBudget::new(budget_ms))
}

// ---------------------------------------------------------------------------
// GateCheckKind — Copy, Hash, Serde, Display, Ordering
// ---------------------------------------------------------------------------

#[test]
fn gate_check_kind_is_copy() {
    let a = GateCheckKind::FrankenlabScenario;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn gate_check_kind_hash_four_distinct() {
    let mut set = HashSet::new();
    set.insert(GateCheckKind::FrankenlabScenario);
    set.insert(GateCheckKind::EvidenceReplay);
    set.insert(GateCheckKind::ObligationTracking);
    set.insert(GateCheckKind::EvidenceCompleteness);
    assert_eq!(set.len(), 4);
}

#[test]
fn gate_check_kind_serde_all_four() {
    let kinds = [
        GateCheckKind::FrankenlabScenario,
        GateCheckKind::EvidenceReplay,
        GateCheckKind::ObligationTracking,
        GateCheckKind::EvidenceCompleteness,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: GateCheckKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn gate_check_kind_serde_stable_strings() {
    assert_eq!(
        serde_json::to_string(&GateCheckKind::FrankenlabScenario).unwrap(),
        "\"FrankenlabScenario\""
    );
    assert_eq!(
        serde_json::to_string(&GateCheckKind::EvidenceReplay).unwrap(),
        "\"EvidenceReplay\""
    );
    assert_eq!(
        serde_json::to_string(&GateCheckKind::ObligationTracking).unwrap(),
        "\"ObligationTracking\""
    );
    assert_eq!(
        serde_json::to_string(&GateCheckKind::EvidenceCompleteness).unwrap(),
        "\"EvidenceCompleteness\""
    );
}

#[test]
fn gate_check_kind_display_frankenlab() {
    assert_eq!(
        format!("{}", GateCheckKind::FrankenlabScenario),
        "frankenlab_scenario"
    );
}

#[test]
fn gate_check_kind_display_evidence_replay() {
    assert_eq!(
        format!("{}", GateCheckKind::EvidenceReplay),
        "evidence_replay"
    );
}

#[test]
fn gate_check_kind_display_obligation() {
    assert_eq!(
        format!("{}", GateCheckKind::ObligationTracking),
        "obligation_tracking"
    );
}

#[test]
fn gate_check_kind_display_completeness() {
    assert_eq!(
        format!("{}", GateCheckKind::EvidenceCompleteness),
        "evidence_completeness"
    );
}

#[test]
fn gate_check_kind_ordering_exhaustive() {
    let mut kinds = [
        GateCheckKind::EvidenceCompleteness,
        GateCheckKind::FrankenlabScenario,
        GateCheckKind::ObligationTracking,
        GateCheckKind::EvidenceReplay,
    ];
    kinds.sort();
    // Derive ordering: declaration order in enum.
    assert_eq!(kinds[0], GateCheckKind::FrankenlabScenario);
    assert_eq!(kinds[1], GateCheckKind::EvidenceReplay);
    assert_eq!(kinds[2], GateCheckKind::ObligationTracking);
    assert_eq!(kinds[3], GateCheckKind::EvidenceCompleteness);
}

// ---------------------------------------------------------------------------
// GateCheckResult — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn gate_check_result_serde_passing() {
    let check = GateCheckResult {
        kind: GateCheckKind::FrankenlabScenario,
        passed: true,
        summary: "7/7 passed".to_string(),
        failure_details: Vec::new(),
        items_checked: 7,
        items_passed: 7,
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: GateCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn gate_check_result_serde_failing_with_details() {
    let check = GateCheckResult {
        kind: GateCheckKind::EvidenceReplay,
        passed: false,
        summary: "1 violation".to_string(),
        failure_details: vec![GateFailureDetail {
            item_id: "entry-001".to_string(),
            failure_type: "chain_hash_mismatch".to_string(),
            expected: "no violation".to_string(),
            actual: "hash mismatch".to_string(),
        }],
        items_checked: 1,
        items_passed: 0,
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: GateCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn gate_check_result_clone() {
    let check = GateCheckResult {
        kind: GateCheckKind::ObligationTracking,
        passed: true,
        summary: "ok".to_string(),
        failure_details: Vec::new(),
        items_checked: 3,
        items_passed: 3,
    };
    let cloned = check.clone();
    assert_eq!(check, cloned);
}

// ---------------------------------------------------------------------------
// GateFailureDetail — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn gate_failure_detail_serde() {
    let detail = GateFailureDetail {
        item_id: "scenario_x".to_string(),
        failure_type: "assertion_failed".to_string(),
        expected: "true".to_string(),
        actual: "false".to_string(),
    };
    let json = serde_json::to_string(&detail).unwrap();
    let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, back);
}

#[test]
fn gate_failure_detail_clone() {
    let detail = GateFailureDetail {
        item_id: "id".to_string(),
        failure_type: "type".to_string(),
        expected: "exp".to_string(),
        actual: "act".to_string(),
    };
    assert_eq!(detail, detail.clone());
}

// ---------------------------------------------------------------------------
// GateConfig — Default, Serde
// ---------------------------------------------------------------------------

#[test]
fn gate_config_default_timeout() {
    let config = GateConfig::default();
    assert_eq!(config.timeout_budget_ms, 600_000);
}

#[test]
fn gate_config_default_has_four_required_checks() {
    let config = GateConfig::default();
    assert_eq!(config.required_check_kinds.len(), 4);
}

#[test]
fn gate_config_default_required_check_content() {
    let config = GateConfig::default();
    let kinds: HashSet<GateCheckKind> = config.required_check_kinds.iter().copied().collect();
    assert!(kinds.contains(&GateCheckKind::FrankenlabScenario));
    assert!(kinds.contains(&GateCheckKind::EvidenceReplay));
    assert!(kinds.contains(&GateCheckKind::ObligationTracking));
    assert!(kinds.contains(&GateCheckKind::EvidenceCompleteness));
}

#[test]
fn gate_config_serde() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn gate_config_custom_serde() {
    let config = GateConfig {
        timeout_budget_ms: 42,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// ExceptionPolicy — Default, Serde
// ---------------------------------------------------------------------------

#[test]
fn exception_policy_default_disallows() {
    let policy = ExceptionPolicy::default();
    assert!(!policy.allow_exceptions);
}

#[test]
fn exception_policy_default_requires_adr() {
    let policy = ExceptionPolicy::default();
    assert!(policy.requires_adr_reference);
}

#[test]
fn exception_policy_default_requires_security_review() {
    let policy = ExceptionPolicy::default();
    assert!(policy.requires_security_review);
}

#[test]
fn exception_policy_default_max_hours_72() {
    let policy = ExceptionPolicy::default();
    assert_eq!(policy.max_exception_hours, 72);
}

#[test]
fn exception_policy_serde_default() {
    let policy = ExceptionPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn exception_policy_serde_permissive() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 0,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ---------------------------------------------------------------------------
// GateEvent — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn gate_event_serde_no_error() {
    let event = GateEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "release_gate".to_string(),
        event: "check_done".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn gate_event_serde_with_error_code() {
    let event = GateEvent {
        trace_id: "t-2".to_string(),
        decision_id: "d-2".to_string(),
        policy_id: "p-2".to_string(),
        component: "release_gate".to_string(),
        event: "infra_fail".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("GATE_INFRASTRUCTURE_FAILURE".to_string()),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn gate_event_serde_with_metadata() {
    let mut meta = BTreeMap::new();
    meta.insert("key1".to_string(), "val1".to_string());
    meta.insert("key2".to_string(), "val2".to_string());
    let event = GateEvent {
        trace_id: "t-3".to_string(),
        decision_id: "d-3".to_string(),
        policy_id: "p-3".to_string(),
        component: "release_gate".to_string(),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: meta,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn gate_event_clone() {
    let event = GateEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: Some("code".to_string()),
        metadata: BTreeMap::new(),
    };
    assert_eq!(event, event.clone());
}

// ---------------------------------------------------------------------------
// GateFailureReport — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn gate_failure_report_serde_blocked() {
    let report = GateFailureReport {
        blocked: true,
        failing_gates: vec![
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
        ],
        details: vec![GateFailureDetail {
            item_id: "item1".to_string(),
            failure_type: "ft".to_string(),
            expected: "e".to_string(),
            actual: "a".to_string(),
        }],
        summary: "BLOCKED: 2 gate(s) failed".to_string(),
        seed: 99,
        result_digest: "abc123".to_string(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateFailureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn gate_failure_report_serde_not_blocked() {
    let report = GateFailureReport {
        blocked: false,
        failing_gates: Vec::new(),
        details: Vec::new(),
        summary: "all gates passed".to_string(),
        seed: 42,
        result_digest: "digest123".to_string(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateFailureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn gate_failure_report_clone() {
    let report = GateFailureReport {
        blocked: true,
        failing_gates: vec![GateCheckKind::ObligationTracking],
        details: Vec::new(),
        summary: "blocked".to_string(),
        seed: 1,
        result_digest: "d".to_string(),
    };
    assert_eq!(report, report.clone());
}

// ---------------------------------------------------------------------------
// IdempotencyVerification — Serde, is_hermetic
// ---------------------------------------------------------------------------

#[test]
fn idempotency_verification_serde() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "aaaa".to_string(),
        second_digest: "aaaa".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn idempotency_is_hermetic_all_true() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "x".to_string(),
        second_digest: "x".to_string(),
    };
    assert!(v.is_hermetic());
}

#[test]
fn idempotency_not_hermetic_digests_differ() {
    let v = IdempotencyVerification {
        digests_match: false,
        verdicts_match: true,
        checks_match: true,
        first_digest: "x".to_string(),
        second_digest: "y".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn idempotency_not_hermetic_verdicts_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: false,
        checks_match: true,
        first_digest: "x".to_string(),
        second_digest: "x".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn idempotency_not_hermetic_checks_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: false,
        first_digest: "x".to_string(),
        second_digest: "x".to_string(),
    };
    assert!(!v.is_hermetic());
}

// ---------------------------------------------------------------------------
// ReleaseGateResult — is_blocked, failure_report
// ---------------------------------------------------------------------------

#[test]
fn result_is_blocked_on_fail_verdict() {
    let result = ReleaseGateResult {
        seed: 1,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    assert!(result.is_blocked());
}

#[test]
fn result_not_blocked_on_pass_verdict() {
    let result = ReleaseGateResult {
        seed: 1,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    assert!(!result.is_blocked());
}

#[test]
fn failure_report_all_pass_summary() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: vec![GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: true,
            summary: "ok".to_string(),
            failure_details: Vec::new(),
            items_checked: 1,
            items_passed: 1,
        }],
        verdict: Verdict::Pass,
        total_checks: 1,
        passed_checks: 1,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "d".to_string(),
    };
    let report = result.failure_report();
    assert!(!report.blocked);
    assert!(report.failing_gates.is_empty());
    assert!(report.details.is_empty());
    assert!(report.summary.contains("all gates passed"));
}

#[test]
fn failure_report_infrastructure_fail_no_checks() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "GATE_INFRASTRUCTURE_FAILURE: empty checks".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "d".to_string(),
    };
    let report = result.failure_report();
    assert!(report.blocked);
    assert!(report.failing_gates.is_empty());
    assert!(report.summary.contains("BLOCKED"));
    assert!(report.summary.contains("GATE_INFRASTRUCTURE_FAILURE"));
}

#[test]
fn failure_report_one_failing_gate() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: vec![
            GateCheckResult {
                kind: GateCheckKind::FrankenlabScenario,
                passed: true,
                summary: "ok".to_string(),
                failure_details: Vec::new(),
                items_checked: 7,
                items_passed: 7,
            },
            GateCheckResult {
                kind: GateCheckKind::EvidenceReplay,
                passed: false,
                summary: "fail".to_string(),
                failure_details: vec![GateFailureDetail {
                    item_id: "e1".to_string(),
                    failure_type: "divergence".to_string(),
                    expected: "none".to_string(),
                    actual: "found".to_string(),
                }],
                items_checked: 1,
                items_passed: 0,
            },
        ],
        verdict: Verdict::Fail {
            reason: "1 of 2 failed".to_string(),
        },
        total_checks: 2,
        passed_checks: 1,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "d".to_string(),
    };
    let report = result.failure_report();
    assert!(report.blocked);
    assert_eq!(report.failing_gates.len(), 1);
    assert_eq!(report.failing_gates[0], GateCheckKind::EvidenceReplay);
    assert_eq!(report.details.len(), 1);
    assert!(report.summary.contains("1 gate(s) failed"));
    assert!(report.summary.contains("evidence_replay"));
}

#[test]
fn failure_report_multiple_failing_gates_aggregates_details() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: vec![
            GateCheckResult {
                kind: GateCheckKind::FrankenlabScenario,
                passed: false,
                summary: "fail".to_string(),
                failure_details: vec![
                    GateFailureDetail {
                        item_id: "s1".to_string(),
                        failure_type: "assertion".to_string(),
                        expected: "e".to_string(),
                        actual: "a".to_string(),
                    },
                    GateFailureDetail {
                        item_id: "s2".to_string(),
                        failure_type: "assertion".to_string(),
                        expected: "e".to_string(),
                        actual: "a".to_string(),
                    },
                ],
                items_checked: 7,
                items_passed: 5,
            },
            GateCheckResult {
                kind: GateCheckKind::EvidenceReplay,
                passed: true,
                summary: "ok".to_string(),
                failure_details: Vec::new(),
                items_checked: 1,
                items_passed: 1,
            },
            GateCheckResult {
                kind: GateCheckKind::EvidenceCompleteness,
                passed: false,
                summary: "fail".to_string(),
                failure_details: vec![GateFailureDetail {
                    item_id: "c1".to_string(),
                    failure_type: "no_evidence".to_string(),
                    expected: "events".to_string(),
                    actual: "none".to_string(),
                }],
                items_checked: 7,
                items_passed: 6,
            },
        ],
        verdict: Verdict::Fail {
            reason: "2 of 3 failed".to_string(),
        },
        total_checks: 3,
        passed_checks: 1,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "d".to_string(),
    };
    let report = result.failure_report();
    assert!(report.blocked);
    assert_eq!(report.failing_gates.len(), 2);
    // Details aggregated from both failing checks: 2 + 1 = 3.
    assert_eq!(report.details.len(), 3);
    assert!(report.summary.contains("2 gate(s) failed"));
}

#[test]
fn failure_report_seed_and_digest_preserved() {
    let result = ReleaseGateResult {
        seed: 999,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "mydigest".to_string(),
    };
    let report = result.failure_report();
    assert_eq!(report.seed, 999);
    assert_eq!(report.result_digest, "mydigest");
}

// ---------------------------------------------------------------------------
// ReleaseGateResult — Serde
// ---------------------------------------------------------------------------

#[test]
fn release_gate_result_serde_pass() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: vec![GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: true,
            summary: "ok".to_string(),
            failure_details: Vec::new(),
            items_checked: 7,
            items_passed: 7,
        }],
        verdict: Verdict::Pass,
        total_checks: 1,
        passed_checks: 1,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "abc".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn release_gate_result_serde_fail_with_exception() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 1,
        passed_checks: 0,
        exception_applied: true,
        exception_justification: "hotfix".to_string(),
        gate_events: Vec::new(),
        result_digest: "abc".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// ReleaseGate — Construction
// ---------------------------------------------------------------------------

#[test]
fn release_gate_new_sets_seed() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 42);
}

#[test]
fn release_gate_new_uses_default_config() {
    let mut gate = ReleaseGate::new(1);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.total_checks, 4);
}

#[test]
fn release_gate_with_exception_policy_preserves_seed() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let mut gate = ReleaseGate::with_exception_policy(77, policy);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 77);
}

#[test]
fn release_gate_with_config_uses_custom_timeout() {
    let config = GateConfig {
        timeout_budget_ms: 1_000_000,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(55, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 55);
}

#[test]
fn release_gate_with_config_and_policy() {
    let config = GateConfig {
        timeout_budget_ms: 500_000,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 48,
    };
    let mut gate = ReleaseGate::with_config_and_policy(88, config, policy);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 88);
    assert_eq!(result.total_checks, 4);
}

// ---------------------------------------------------------------------------
// ReleaseGate — evaluate (happy path)
// ---------------------------------------------------------------------------

#[test]
fn evaluate_all_pass_verdict() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());
}

#[test]
fn evaluate_four_checks_returned() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.checks.len(), 4);
}

#[test]
fn evaluate_all_checks_pass() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.passed_checks, result.total_checks);
    for check in &result.checks {
        assert!(check.passed, "check {:?} should pass", check.kind);
    }
}

#[test]
fn evaluate_no_exception_applied() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.exception_applied);
    assert!(result.exception_justification.is_empty());
}

#[test]
fn evaluate_check_kinds_in_expected_order() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let kinds: Vec<GateCheckKind> = result.checks.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        vec![
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceCompleteness,
        ]
    );
}

#[test]
fn evaluate_summaries_non_empty() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        assert!(!check.summary.is_empty(), "{:?} summary empty", check.kind);
    }
}

#[test]
fn evaluate_no_failure_details_on_pass() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        assert!(
            check.failure_details.is_empty(),
            "{:?} should have no failure details",
            check.kind
        );
    }
}

// ---------------------------------------------------------------------------
// ReleaseGate — evaluate (infrastructure failures, fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn infra_failure_empty_required_checks() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    assert!(result.checks.is_empty());
    assert_eq!(result.total_checks, 0);
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
            assert!(reason.contains("misconfigured"));
        }
        _ => panic!("expected fail verdict"),
    }
}

#[test]
fn infra_failure_zero_timeout() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
            assert!(reason.contains("zero"));
        }
        _ => panic!("expected fail verdict"),
    }
}

#[test]
fn infra_failure_emits_gate_event() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let infra_events: Vec<_> = result
        .gate_events
        .iter()
        .filter(|e| e.error_code.as_deref() == Some("GATE_INFRASTRUCTURE_FAILURE"))
        .collect();
    assert!(
        !infra_events.is_empty(),
        "infrastructure failure must emit GATE_INFRASTRUCTURE_FAILURE event"
    );
}

#[test]
fn infra_failure_has_non_empty_digest() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.result_digest.is_empty());
    assert_eq!(result.result_digest.len(), 16);
}

// ---------------------------------------------------------------------------
// ReleaseGate — evaluate (timeout)
// ---------------------------------------------------------------------------

#[test]
fn timeout_on_tight_budget() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_TIMEOUT"));
        }
        _ => panic!("expected timeout fail verdict"),
    }
}

#[test]
fn timeout_preserves_partial_checks() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // At least some checks should have completed before timeout.
    assert!(!result.checks.is_empty());
}

#[test]
fn timeout_emits_gate_timeout_event() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let timeout_events: Vec<_> = result
        .gate_events
        .iter()
        .filter(|e| e.error_code.as_deref() == Some("GATE_TIMEOUT"))
        .collect();
    assert!(!timeout_events.is_empty());
}

#[test]
fn timeout_has_non_empty_digest() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.result_digest.is_empty());
    assert_eq!(result.result_digest.len(), 16);
}

#[test]
fn generous_budget_does_not_timeout() {
    let config = GateConfig {
        timeout_budget_ms: 1_000_000,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());
}

// ---------------------------------------------------------------------------
// ReleaseGate — apply_exception
// ---------------------------------------------------------------------------

fn make_failed_result() -> ReleaseGateResult {
    ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test failure".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    }
}

#[test]
fn exception_rejected_by_default_policy() {
    let gate = ReleaseGate::new(42);
    let mut result = make_failed_result();
    let err = gate
        .apply_exception(&mut result, "justification", Some("ADR-001"))
        .unwrap_err();
    assert!(err.contains("does not allow"));
    assert!(!result.exception_applied);
}

#[test]
fn exception_rejected_missing_adr_when_required() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    let err = gate
        .apply_exception(&mut result, "need to ship", None)
        .unwrap_err();
    assert!(err.contains("ADR reference"));
    assert!(!result.exception_applied);
}

#[test]
fn exception_rejected_empty_justification() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 0,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    let err = gate.apply_exception(&mut result, "", None).unwrap_err();
    assert!(err.contains("justification"));
    assert!(!result.exception_applied);
}

#[test]
fn exception_succeeds_with_valid_inputs() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    gate.apply_exception(&mut result, "Critical hotfix", Some("ADR-2026-002"))
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.exception_justification, "Critical hotfix");
}

#[test]
fn exception_succeeds_without_adr_when_not_required() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 0,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    gate.apply_exception(&mut result, "emergency", None)
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn exception_changes_digest() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 0,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    result.result_digest = "original_digest".to_string();
    let before = result.result_digest.clone();
    gate.apply_exception(&mut result, "hotfix", None).unwrap();
    assert_ne!(result.result_digest, before);
}

#[test]
fn exception_validation_order_allow_first() {
    // Even with valid ADR + justification, if allow_exceptions is false, it's rejected first.
    let policy = ExceptionPolicy {
        allow_exceptions: false,
        requires_adr_reference: true,
        requires_security_review: true,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    let err = gate
        .apply_exception(&mut result, "valid justification", Some("ADR-001"))
        .unwrap_err();
    assert!(err.contains("does not allow"));
}

#[test]
fn exception_validation_order_adr_before_justification() {
    // When allowed but ADR required and missing, ADR error takes precedence over justification.
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = make_failed_result();
    let err = gate.apply_exception(&mut result, "", None).unwrap_err();
    // ADR check comes before justification check.
    assert!(err.contains("ADR reference"));
}

// ---------------------------------------------------------------------------
// ReleaseGate — verify_idempotency
// ---------------------------------------------------------------------------

#[test]
fn verify_idempotency_is_hermetic() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let v = gate.verify_idempotency(&mut cx);
    assert!(v.is_hermetic());
    assert!(v.digests_match);
    assert!(v.verdicts_match);
    assert!(v.checks_match);
    assert_eq!(v.first_digest, v.second_digest);
}

#[test]
fn verify_idempotency_digests_are_hex() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let v = gate.verify_idempotency(&mut cx);
    assert_eq!(v.first_digest.len(), 16);
    assert!(v.first_digest.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(v.second_digest.len(), 16);
    assert!(v.second_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn verify_idempotency_different_seeds_same_hermeticity() {
    for seed in [1, 42, 100, 999] {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(400_000);
        let v = gate.verify_idempotency(&mut cx);
        assert!(v.is_hermetic(), "seed {seed} should be hermetic");
    }
}

// ---------------------------------------------------------------------------
// Gate meta-evidence events
// ---------------------------------------------------------------------------

#[test]
fn evaluate_emits_at_least_five_events() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // 4 individual checks + 1 final verdict = 5 minimum.
    assert!(
        result.gate_events.len() >= 5,
        "expected ≥5 events, got {}",
        result.gate_events.len()
    );
}

#[test]
fn evaluate_final_event_is_release_gate_evaluated() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let last = result.gate_events.last().unwrap();
    assert_eq!(last.event, "release_gate_evaluated");
    assert_eq!(last.outcome, "pass");
}

#[test]
fn evaluate_all_events_have_trace_ids() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert_eq!(event.component, "release_gate");
    }
}

#[test]
fn evaluate_events_include_individual_check_names() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event_names: Vec<&str> = result
        .gate_events
        .iter()
        .map(|e| e.event.as_str())
        .collect();
    assert!(event_names.contains(&"frankenlab_scenarios_checked"));
    assert!(event_names.contains(&"evidence_replay_checked"));
    assert!(event_names.contains(&"obligation_tracking_checked"));
    assert!(event_names.contains(&"evidence_completeness_checked"));
}

#[test]
fn evaluate_passing_events_have_no_error_code() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        if event.outcome == "pass" {
            assert!(
                event.error_code.is_none(),
                "passing event should have no error code: {:?}",
                event
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Content-addressable digest
// ---------------------------------------------------------------------------

#[test]
fn digest_is_16_hex_chars() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.result_digest.len(), 16);
    assert!(result.result_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn different_seeds_produce_different_digests() {
    let mut gate1 = ReleaseGate::new(1);
    let mut cx1 = mock_cx(200_000);
    let r1 = gate1.evaluate(&mut cx1);

    let mut gate2 = ReleaseGate::new(2);
    let mut cx2 = mock_cx(200_000);
    let r2 = gate2.evaluate(&mut cx2);

    assert_ne!(r1.result_digest, r2.result_digest);
}

#[test]
fn same_seed_produces_same_digest() {
    let mut gate1 = ReleaseGate::new(42);
    let mut cx1 = mock_cx(200_000);
    let r1 = gate1.evaluate(&mut cx1);

    let mut gate2 = ReleaseGate::new(42);
    let mut cx2 = mock_cx(200_000);
    let r2 = gate2.evaluate(&mut cx2);

    assert_eq!(r1.result_digest, r2.result_digest);
}

// ---------------------------------------------------------------------------
// Determinism — 100 iterations
// ---------------------------------------------------------------------------

#[test]
fn deterministic_100_iterations_same_seed() {
    let mut reference_digest = None;
    let mut reference_verdict = None;
    for _ in 0..100 {
        let mut gate = ReleaseGate::new(42);
        let mut cx = mock_cx(200_000);
        let result = gate.evaluate(&mut cx);
        if let Some(ref d) = reference_digest {
            assert_eq!(&result.result_digest, d);
        } else {
            reference_digest = Some(result.result_digest.clone());
        }
        if let Some(ref v) = reference_verdict {
            assert_eq!(&result.verdict, v);
        } else {
            reference_verdict = Some(result.verdict.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Multiple seeds all pass
// ---------------------------------------------------------------------------

#[test]
fn multiple_seeds_all_pass() {
    for seed in [0, 1, 42, 100, 999, 12345, u64::MAX] {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(200_000);
        let result = gate.evaluate(&mut cx);
        assert_eq!(result.verdict, Verdict::Pass, "seed {seed} should pass");
        assert_eq!(result.total_checks, 4);
    }
}

// ---------------------------------------------------------------------------
// Individual check details
// ---------------------------------------------------------------------------

#[test]
fn frankenlab_check_has_seven_scenarios() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::FrankenlabScenario)
        .unwrap();
    assert!(check.passed);
    assert_eq!(check.items_checked, 7);
    assert_eq!(check.items_passed, 7);
}

#[test]
fn evidence_replay_check_items_checked_is_one() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceReplay)
        .unwrap();
    assert!(check.passed);
    assert_eq!(check.items_checked, 1);
    assert_eq!(check.items_passed, 1);
}

#[test]
fn obligation_check_summary_contains_scenarios() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::ObligationTracking)
        .unwrap();
    assert!(check.passed);
    assert!(check.summary.contains("obligation tracking"));
}

#[test]
fn evidence_completeness_summary_contains_evidence() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceCompleteness)
        .unwrap();
    assert!(check.passed);
    assert!(check.summary.contains("evidence completeness"));
}

// ---------------------------------------------------------------------------
// Serde roundtrip of full evaluate result
// ---------------------------------------------------------------------------

#[test]
fn full_evaluate_result_serde_roundtrip() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn infra_failure_result_serde_roundtrip() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn timeout_result_serde_roundtrip() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Edge cases — trace/decision/policy IDs
// ---------------------------------------------------------------------------

#[test]
fn trace_id_contains_seed_hex() {
    let mut gate = ReleaseGate::new(255);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event = &result.gate_events[0];
    assert!(event.trace_id.contains("00000000000000ff"));
}

#[test]
fn decision_id_contains_seed_hex() {
    let mut gate = ReleaseGate::new(255);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event = &result.gate_events[0];
    assert!(event.decision_id.contains("00000000000000ff"));
}

#[test]
fn policy_id_is_release_gate_v1() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event = &result.gate_events[0];
    assert_eq!(event.policy_id, "release-gate-v1");
}

// ---------------------------------------------------------------------------
// Edge cases — exception on already-passing result
// ---------------------------------------------------------------------------

#[test]
fn exception_on_passing_result_still_sets_fields() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 0,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 1,
        passed_checks: 1,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "pre".to_string(),
    };
    gate.apply_exception(&mut result, "preemptive", None)
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.exception_justification, "preemptive");
    assert_eq!(result.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// Integration — full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn integration_full_lifecycle() {
    // 1. Create gate, evaluate, verify pass.
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.is_blocked());

    // 2. Failure report shows no issues.
    let report = result.failure_report();
    assert!(!report.blocked);
    assert!(report.summary.contains("all gates passed"));

    // 3. Serde roundtrip of full result.
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);

    // 4. Verify digest properties.
    assert_eq!(result.result_digest.len(), 16);
    assert!(result.result_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn integration_infra_failure_then_exception_rejected() {
    // Infrastructure failure cannot be overridden because default policy disallows exceptions.
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let mut result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());

    let gate2 = ReleaseGate::new(42);
    let err = gate2
        .apply_exception(&mut result, "override", Some("ADR-001"))
        .unwrap_err();
    assert!(err.contains("does not allow"));
}

#[test]
fn integration_exception_overrides_failure() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);

    // Start with a failed result.
    let mut result = make_failed_result();
    assert!(result.is_blocked());

    // Apply exception.
    gate.apply_exception(&mut result, "Critical hotfix P0", Some("ADR-2026-003"))
        .unwrap();
    assert!(!result.is_blocked());
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);

    // Serde roundtrip after exception.
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn integration_idempotency_across_seeds() {
    for seed in [1, 42, 100] {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(400_000);
        let v = gate.verify_idempotency(&mut cx);
        assert!(
            v.is_hermetic(),
            "seed {seed}: expected hermetic idempotency"
        );
    }
}
