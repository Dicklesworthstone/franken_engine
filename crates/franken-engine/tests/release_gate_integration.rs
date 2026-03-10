#![forbid(unsafe_code)]
//! Integration tests for the `release_gate` module.
//!
//! Covers full evaluation lifecycle, infrastructure validation (fail-closed),
//! timeout budget handling, exception policy enforcement, failure reports,
//! idempotency verification, deterministic reproducibility, structured gate
//! events (meta-evidence), content-addressable digests, serde roundtrips
//! for all public types, and multi-operation composition scenarios.

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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

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

// ===========================================================================
// Section 1: Full evaluation lifecycle — happy path
// ===========================================================================

#[test]
fn evaluate_happy_path_verdict_is_pass() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());
}

#[test]
fn evaluate_happy_path_checks_count_four() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.total_checks, 4);
    assert_eq!(result.passed_checks, 4);
    assert_eq!(result.checks.len(), 4);
}

#[test]
fn evaluate_happy_path_all_checks_pass() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        assert!(check.passed, "check {:?} should pass", check.kind);
        assert!(check.failure_details.is_empty());
    }
}

#[test]
fn evaluate_happy_path_no_exception_applied() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.exception_applied);
    assert!(result.exception_justification.is_empty());
}

#[test]
fn evaluate_happy_path_seed_preserved() {
    let mut gate = ReleaseGate::new(7777);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 7777);
}

#[test]
fn evaluate_happy_path_digest_is_16_hex() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.result_digest.len(), 16);
    assert!(result.result_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===========================================================================
// Section 2: Individual check kinds present in evaluation
// ===========================================================================

#[test]
fn evaluate_contains_frankenlab_scenario_check() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::FrankenlabScenario);
    assert!(check.is_some());
    let check = check.unwrap();
    assert!(check.passed);
    assert_eq!(check.items_checked, 7);
    assert_eq!(check.items_passed, 7);
}

#[test]
fn evaluate_contains_evidence_replay_check() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceReplay);
    assert!(check.is_some());
    assert!(check.unwrap().passed);
}

#[test]
fn evaluate_contains_obligation_tracking_check() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::ObligationTracking);
    assert!(check.is_some());
    assert!(check.unwrap().passed);
}

#[test]
fn evaluate_contains_evidence_completeness_check() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceCompleteness);
    assert!(check.is_some());
    assert!(check.unwrap().passed);
}

#[test]
fn evaluate_check_kinds_are_all_four_unique() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let kinds: BTreeSet<GateCheckKind> = result.checks.iter().map(|c| c.kind).collect();
    assert_eq!(kinds.len(), 4);
}

// ===========================================================================
// Section 3: Infrastructure failure — fail-closed
// ===========================================================================

#[test]
fn infra_failure_empty_required_checks_blocks() {
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
        _ => panic!("expected Fail verdict"),
    }
}

#[test]
fn infra_failure_zero_timeout_blocks() {
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
        _ => panic!("expected Fail verdict"),
    }
}

#[test]
fn infra_failure_emits_structured_event() {
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
        "should emit GATE_INFRASTRUCTURE_FAILURE event"
    );
}

#[test]
fn infra_failure_has_nonempty_digest() {
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

// ===========================================================================
// Section 4: Timeout budget handling
// ===========================================================================

#[test]
fn timeout_with_tight_budget_blocks() {
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
        _ => panic!("expected timeout verdict"),
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
    // All 4 checks ran but budget was exceeded after accumulation.
    assert!(!result.checks.is_empty());
    assert_eq!(
        result.passed_checks,
        result.checks.iter().filter(|c| c.passed).count()
    );
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
    let timeout_event = result
        .gate_events
        .iter()
        .any(|e| e.error_code.as_deref() == Some("GATE_TIMEOUT"));
    assert!(timeout_event, "should emit GATE_TIMEOUT event");
}

#[test]
fn generous_budget_does_not_timeout() {
    let config = GateConfig {
        timeout_budget_ms: 10_000_000,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.is_blocked());
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn exact_budget_boundary_does_not_timeout() {
    // First, measure exact budget needed.
    let mut probe = ReleaseGate::new(42);
    let mut cx_probe = mock_cx(200_000);
    let probe_result = probe.evaluate(&mut cx_probe);
    let exact_budget: u64 = probe_result
        .checks
        .iter()
        .map(|c| (c.items_checked as u64).saturating_mul(10))
        .sum();

    let config = GateConfig {
        timeout_budget_ms: exact_budget,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // Exact budget should not trigger timeout (budget_consumed <= budget, not strictly <).
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(
                !reason.contains("GATE_TIMEOUT"),
                "exact budget should not timeout: {reason}"
            );
        }
        Verdict::Pass => {} // fine
    }
}

// ===========================================================================
// Section 5: Exception policy enforcement
// ===========================================================================

#[test]
fn default_exception_policy_rejects_override() {
    let gate = ReleaseGate::new(42);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    let err = gate
        .apply_exception(&mut result, "urgent", Some("ADR-001"))
        .unwrap_err();
    assert!(err.contains("does not allow"));
    assert!(!result.exception_applied);
}

#[test]
fn exception_requires_adr_reference_when_policy_set() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 72,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    let err = gate
        .apply_exception(&mut result, "urgent", None)
        .unwrap_err();
    assert!(err.contains("ADR reference"));
}

#[test]
fn exception_requires_nonempty_justification() {
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
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    let err = gate.apply_exception(&mut result, "", None).unwrap_err();
    assert!(err.contains("justification"));
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
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    gate.apply_exception(&mut result, "Critical CVE fix", Some("ADR-2026-002"))
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.exception_justification, "Critical CVE fix");
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
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "original_digest".to_string(),
    };
    let before = result.result_digest.clone();
    gate.apply_exception(&mut result, "hotfix", None).unwrap();
    assert_ne!(result.result_digest, before);
    // New digest should be 16-char hex.
    assert_eq!(result.result_digest.len(), 16);
}

#[test]
fn exception_on_passing_result_still_sets_flag() {
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
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "cosmetic override", None)
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);
}

// ===========================================================================
// Section 6: Failure report generation
// ===========================================================================

#[test]
fn passing_gate_failure_report_not_blocked() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert!(!report.blocked);
    assert!(report.failing_gates.is_empty());
    assert!(report.details.is_empty());
    assert!(report.summary.contains("all gates passed"));
    assert_eq!(report.seed, 42);
    assert_eq!(report.result_digest, result.result_digest);
}

#[test]
fn failure_report_identifies_multiple_failing_gates() {
    let checks = vec![
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
                item_id: "entry-001".to_string(),
                failure_type: "hash_mismatch".to_string(),
                expected: "no violation".to_string(),
                actual: "hash_mismatch".to_string(),
            }],
            items_checked: 1,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: false,
            summary: "unresolved".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "obligation-007".to_string(),
                failure_type: "unresolved".to_string(),
                expected: "resolved".to_string(),
                actual: "pending".to_string(),
            }],
            items_checked: 5,
            items_passed: 4,
        },
        GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: true,
            summary: "ok".to_string(),
            failure_details: Vec::new(),
            items_checked: 7,
            items_passed: 7,
        },
    ];
    let result = ReleaseGateResult {
        seed: 99,
        checks,
        verdict: Verdict::Fail {
            reason: "2 of 4 gate checks failed".to_string(),
        },
        total_checks: 4,
        passed_checks: 2,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "abc123".to_string(),
    };
    let report = result.failure_report();
    assert!(report.blocked);
    assert_eq!(report.failing_gates.len(), 2);
    assert!(
        report
            .failing_gates
            .contains(&GateCheckKind::EvidenceReplay)
    );
    assert!(
        report
            .failing_gates
            .contains(&GateCheckKind::ObligationTracking)
    );
    assert_eq!(report.details.len(), 2);
    assert!(report.summary.contains("2 gate(s) failed"));
}

#[test]
fn failure_report_on_infrastructure_failure_mentions_blocked() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert!(report.blocked);
    assert!(report.summary.contains("BLOCKED"));
    assert!(report.summary.contains("GATE_INFRASTRUCTURE_FAILURE"));
}

// ===========================================================================
// Section 7: Structured gate events (meta-evidence)
// ===========================================================================

#[test]
fn evaluate_emits_at_least_five_events() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // 4 individual checks + 1 final verdict event = at least 5.
    assert!(
        result.gate_events.len() >= 5,
        "got {} events",
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
fn evaluate_events_have_structured_fields() {
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
fn evaluate_events_trace_id_contains_seed() {
    let mut gate = ReleaseGate::new(0xDEADBEEF);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        assert!(
            event.trace_id.contains("deadbeef"),
            "trace_id should contain hex seed: {}",
            event.trace_id
        );
    }
}

// ===========================================================================
// Section 8: Deterministic reproducibility
// ===========================================================================

#[test]
fn deterministic_same_seed_same_result() {
    let mut gate1 = ReleaseGate::new(77);
    let mut cx1 = mock_cx(200_000);
    let r1 = gate1.evaluate(&mut cx1);

    let mut gate2 = ReleaseGate::new(77);
    let mut cx2 = mock_cx(200_000);
    let r2 = gate2.evaluate(&mut cx2);

    assert_eq!(r1.verdict, r2.verdict);
    assert_eq!(r1.total_checks, r2.total_checks);
    assert_eq!(r1.passed_checks, r2.passed_checks);
    assert_eq!(r1.result_digest, r2.result_digest);
    assert_eq!(r1.checks, r2.checks);
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
fn many_seeds_all_pass_and_unique_digests() {
    let seeds: Vec<u64> = (1..=20).collect();
    let mut digests = BTreeSet::new();
    for seed in &seeds {
        let mut gate = ReleaseGate::new(*seed);
        let mut cx = mock_cx(200_000);
        let result = gate.evaluate(&mut cx);
        assert_eq!(result.verdict, Verdict::Pass, "seed {} should pass", seed);
        digests.insert(result.result_digest.clone());
    }
    assert_eq!(
        digests.len(),
        seeds.len(),
        "each seed produces unique digest"
    );
}

// ===========================================================================
// Section 9: Idempotency verification
// ===========================================================================

#[test]
fn idempotency_verification_is_hermetic() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let verification = gate.verify_idempotency(&mut cx);
    assert!(verification.is_hermetic());
    assert!(verification.digests_match);
    assert!(verification.verdicts_match);
    assert!(verification.checks_match);
    assert_eq!(verification.first_digest, verification.second_digest);
}

#[test]
fn idempotency_digests_are_16_hex() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let verification = gate.verify_idempotency(&mut cx);
    assert_eq!(verification.first_digest.len(), 16);
    assert_eq!(verification.second_digest.len(), 16);
    assert!(
        verification
            .first_digest
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn idempotency_non_hermetic_when_digests_differ() {
    let v = IdempotencyVerification {
        digests_match: false,
        verdicts_match: true,
        checks_match: true,
        first_digest: "aaaa".to_string(),
        second_digest: "bbbb".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn idempotency_non_hermetic_when_verdicts_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: false,
        checks_match: true,
        first_digest: "same".to_string(),
        second_digest: "same".to_string(),
    };
    assert!(!v.is_hermetic());
}

#[test]
fn idempotency_non_hermetic_when_checks_differ() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: false,
        first_digest: "same".to_string(),
        second_digest: "same".to_string(),
    };
    assert!(!v.is_hermetic());
}

// ===========================================================================
// Section 10: Constructor variants
// ===========================================================================

#[test]
fn with_exception_policy_preserves_seed() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let mut gate = ReleaseGate::with_exception_policy(99, policy);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 99);
}

#[test]
fn with_config_preserves_seed() {
    let config = GateConfig {
        timeout_budget_ms: 1_000_000,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(555, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 555);
}

#[test]
fn with_config_and_policy_both_applied() {
    let config = GateConfig {
        timeout_budget_ms: 999_999,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 48,
    };
    let mut gate = ReleaseGate::with_config_and_policy(42, config, policy);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.is_blocked());

    // Now test that exception policy is also applied.
    let mut fail_result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    gate.apply_exception(&mut fail_result, "override", None)
        .unwrap();
    assert!(fail_result.exception_applied);
}

// ===========================================================================
// Section 11: Serde roundtrips for all public types
// ===========================================================================

#[test]
fn serde_gate_check_kind_all_variants() {
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
fn serde_gate_config_default() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn serde_exception_policy_default() {
    let policy = ExceptionPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn serde_gate_failure_detail() {
    let detail = GateFailureDetail {
        item_id: "scenario-boot".to_string(),
        failure_type: "assertion_failed".to_string(),
        expected: "true".to_string(),
        actual: "false".to_string(),
    };
    let json = serde_json::to_string(&detail).unwrap();
    let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, back);
}

#[test]
fn serde_gate_check_result_with_failures() {
    let check = GateCheckResult {
        kind: GateCheckKind::FrankenlabScenario,
        passed: false,
        summary: "2/7 failed".to_string(),
        failure_details: vec![
            GateFailureDetail {
                item_id: "startup".to_string(),
                failure_type: "assert".to_string(),
                expected: "true".to_string(),
                actual: "false".to_string(),
            },
            GateFailureDetail {
                item_id: "shutdown".to_string(),
                failure_type: "timeout".to_string(),
                expected: "< 1000ms".to_string(),
                actual: "5000ms".to_string(),
            },
        ],
        items_checked: 7,
        items_passed: 5,
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: GateCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn serde_gate_event_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("env".to_string(), "staging".to_string());
    metadata.insert("version".to_string(), "1.2.3".to_string());
    let event = GateEvent {
        trace_id: "t-100".to_string(),
        decision_id: "d-200".to_string(),
        policy_id: "release-gate-v1".to_string(),
        component: "release_gate".to_string(),
        event: "frankenlab_scenarios_checked".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_gate_event_with_error_code() {
    let event = GateEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "release_gate".to_string(),
        event: "infrastructure_failure".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("GATE_INFRASTRUCTURE_FAILURE".to_string()),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(
        back.error_code.as_deref(),
        Some("GATE_INFRASTRUCTURE_FAILURE")
    );
}

#[test]
fn serde_gate_failure_report() {
    let report = GateFailureReport {
        blocked: true,
        failing_gates: vec![
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceCompleteness,
        ],
        details: vec![GateFailureDetail {
            item_id: "test".to_string(),
            failure_type: "err".to_string(),
            expected: "a".to_string(),
            actual: "b".to_string(),
        }],
        summary: "BLOCKED: 2 gate(s) failed".to_string(),
        seed: 42,
        result_digest: "abcdef0123456789".to_string(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: GateFailureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn serde_release_gate_result_full_evaluation() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_idempotency_verification() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "0123456789abcdef".to_string(),
        second_digest: "0123456789abcdef".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// Section 12: GateCheckKind — Display, Ord
// ===========================================================================

#[test]
fn gate_check_kind_display_values() {
    assert_eq!(
        GateCheckKind::FrankenlabScenario.to_string(),
        "frankenlab_scenario"
    );
    assert_eq!(GateCheckKind::EvidenceReplay.to_string(), "evidence_replay");
    assert_eq!(
        GateCheckKind::ObligationTracking.to_string(),
        "obligation_tracking"
    );
    assert_eq!(
        GateCheckKind::EvidenceCompleteness.to_string(),
        "evidence_completeness"
    );
}

#[test]
fn gate_check_kind_ord_declaration_order() {
    assert!(GateCheckKind::FrankenlabScenario < GateCheckKind::EvidenceReplay);
    assert!(GateCheckKind::EvidenceReplay < GateCheckKind::ObligationTracking);
    assert!(GateCheckKind::ObligationTracking < GateCheckKind::EvidenceCompleteness);
}

#[test]
fn gate_check_kind_display_all_unique() {
    let mut displays = BTreeSet::new();
    for kind in [
        GateCheckKind::FrankenlabScenario,
        GateCheckKind::EvidenceReplay,
        GateCheckKind::ObligationTracking,
        GateCheckKind::EvidenceCompleteness,
    ] {
        displays.insert(kind.to_string());
    }
    assert_eq!(displays.len(), 4);
}

// ===========================================================================
// Section 13: Default values
// ===========================================================================

#[test]
fn default_gate_config_values() {
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
fn default_exception_policy_values() {
    let policy = ExceptionPolicy::default();
    assert!(!policy.allow_exceptions);
    assert!(policy.requires_adr_reference);
    assert!(policy.requires_security_review);
    assert_eq!(policy.max_exception_hours, 72);
}

// ===========================================================================
// Section 14: Full lifecycle composition
// ===========================================================================

#[test]
fn lifecycle_evaluate_then_exception_override() {
    // Create a gate with tight budget to force timeout failure.
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let mut gate = ReleaseGate::with_config_and_policy(42, config, policy);
    let mut cx = mock_cx(200_000);
    let mut result = gate.evaluate(&mut cx);

    // Should be blocked due to timeout.
    assert!(result.is_blocked());

    // Apply exception override.
    gate.apply_exception(&mut result, "Emergency deploy", Some("ADR-2026-E1"))
        .unwrap();
    assert!(result.exception_applied);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());

    // Generate failure report on the now-passing result.
    let report = result.failure_report();
    assert!(!report.blocked);
    assert!(report.summary.contains("all gates passed"));
}

#[test]
fn lifecycle_evaluate_generate_report_serde() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);

    let report = result.failure_report();
    let report_json = serde_json::to_string(&report).unwrap();
    let report_back: GateFailureReport = serde_json::from_str(&report_json).unwrap();
    assert_eq!(report, report_back);

    let result_json = serde_json::to_string(&result).unwrap();
    let result_back: ReleaseGateResult = serde_json::from_str(&result_json).unwrap();
    assert_eq!(result, result_back);
}

#[test]
fn lifecycle_idempotency_then_report() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let verification = gate.verify_idempotency(&mut cx);
    assert!(verification.is_hermetic());

    // Serialize the verification itself.
    let json = serde_json::to_string(&verification).unwrap();
    let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(verification, back);
}

// ===========================================================================
// Section 15: is_blocked helper
// ===========================================================================

#[test]
fn is_blocked_true_on_fail_verdict() {
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
fn is_blocked_false_on_pass_verdict() {
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
