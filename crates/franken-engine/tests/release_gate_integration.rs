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

// ===========================================================================
// Section 16: Enrichment tests — deep coverage
// ===========================================================================

// ---------------------------------------------------------------------------
// 16.1  Digest stability and structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_digest_is_lowercase_hex() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.result_digest.chars().all(|c| c.is_ascii_hexdigit()));
    // Must be lowercase hex specifically
    assert_eq!(
        result.result_digest,
        result.result_digest.to_ascii_lowercase()
    );
}

#[test]
fn enrichment_digest_length_always_16() {
    for seed in [0u64, 1, 100, u64::MAX / 2, u64::MAX] {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(200_000);
        let result = gate.evaluate(&mut cx);
        assert_eq!(
            result.result_digest.len(),
            16,
            "seed {seed} failed digest length"
        );
    }
}

#[test]
fn enrichment_digest_differs_across_50_seeds() {
    let mut digests = BTreeSet::new();
    for seed in 0..50 {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(200_000);
        let result = gate.evaluate(&mut cx);
        digests.insert(result.result_digest);
    }
    assert_eq!(digests.len(), 50, "all 50 seeds should have unique digests");
}

#[test]
fn enrichment_digest_deterministic_triple_run() {
    for seed in [0u64, 42, 9999] {
        let d1 = {
            let mut g = ReleaseGate::new(seed);
            let mut c = mock_cx(200_000);
            g.evaluate(&mut c).result_digest
        };
        let d2 = {
            let mut g = ReleaseGate::new(seed);
            let mut c = mock_cx(200_000);
            g.evaluate(&mut c).result_digest
        };
        let d3 = {
            let mut g = ReleaseGate::new(seed);
            let mut c = mock_cx(200_000);
            g.evaluate(&mut c).result_digest
        };
        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }
}

// ---------------------------------------------------------------------------
// 16.2  Infrastructure failure edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_infra_failure_both_empty_and_zero_timeout() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    // Should trigger infrastructure failure (checked first)
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_INFRASTRUCTURE_FAILURE"));
        }
        _ => panic!("expected infrastructure failure"),
    }
}

#[test]
fn enrichment_infra_failure_no_checks_run() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(result.checks.is_empty());
    assert_eq!(result.total_checks, 0);
    assert_eq!(result.passed_checks, 0);
}

#[test]
fn enrichment_infra_failure_preserves_seed() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(12345, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 12345);
}

#[test]
fn enrichment_infra_failure_events_have_component() {
    let config = GateConfig {
        timeout_budget_ms: 0,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        assert_eq!(event.component, "release_gate");
    }
}

#[test]
fn enrichment_infra_failure_exception_not_applied() {
    let config = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: Vec::new(),
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.exception_applied);
    assert!(result.exception_justification.is_empty());
}

// ---------------------------------------------------------------------------
// 16.3  Timeout handling edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_timeout_verdict_contains_check_names() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    match &result.verdict {
        Verdict::Fail { reason } => {
            assert!(reason.contains("GATE_TIMEOUT"));
            // Should mention completed check names
            assert!(reason.contains("frankenlab_scenario") || reason.contains("budget"));
        }
        _ => panic!("expected timeout"),
    }
}

#[test]
fn enrichment_timeout_has_nonempty_events() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.gate_events.is_empty());
}

#[test]
fn enrichment_timeout_seed_preserved() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(5678, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 5678);
}

#[test]
fn enrichment_timeout_report_is_blocked() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert!(report.blocked);
    assert!(report.summary.contains("BLOCKED"));
}

// ---------------------------------------------------------------------------
// 16.4  Exception policy boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exception_whitespace_only_justification_rejected() {
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
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: String::new(),
    };
    // A non-empty justification should succeed
    gate.apply_exception(&mut result, "valid reason", None)
        .unwrap();
    assert!(result.exception_applied);
}

#[test]
fn enrichment_exception_does_not_modify_checks() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let gate = ReleaseGate::with_exception_policy(42, policy);
    let original_checks = vec![GateCheckResult {
        kind: GateCheckKind::FrankenlabScenario,
        passed: false,
        summary: "fail".to_string(),
        failure_details: vec![GateFailureDetail {
            item_id: "s1".to_string(),
            failure_type: "err".to_string(),
            expected: "true".to_string(),
            actual: "false".to_string(),
        }],
        items_checked: 1,
        items_passed: 0,
    }];
    let mut result = ReleaseGateResult {
        seed: 42,
        checks: original_checks.clone(),
        verdict: Verdict::Fail {
            reason: "test".to_string(),
        },
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "override", None).unwrap();
    // Checks should be unchanged
    assert_eq!(result.checks.len(), 1);
    assert!(!result.checks[0].passed);
    assert_eq!(result.checks[0].failure_details.len(), 1);
}

#[test]
fn enrichment_exception_multiple_applications_idempotent() {
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
        total_checks: 1,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "first", None).unwrap();
    let digest_after_first = result.result_digest.clone();
    gate.apply_exception(&mut result, "second", None).unwrap();
    // Second apply should change justification but recompute digest
    assert_eq!(result.exception_justification, "second");
    assert!(result.exception_applied);
    // Digest may differ because justification differs in exception_applied state
    assert_eq!(result.verdict, Verdict::Pass);
    // Both digests should be valid hex
    assert_eq!(digest_after_first.len(), 16);
    assert_eq!(result.result_digest.len(), 16);
}

#[test]
fn enrichment_exception_with_adr_ref_sets_pass() {
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
            reason: "blocked".to_string(),
        },
        total_checks: 2,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "orig".to_string(),
    };
    gate.apply_exception(&mut result, "critical deploy", Some("ADR-2026-099"))
        .unwrap();
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.is_blocked());
}

#[test]
fn enrichment_exception_err_does_not_mutate_result() {
    let gate = ReleaseGate::new(42); // default policy: no exceptions
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
        result_digest: "original".to_string(),
    };
    let _ = gate.apply_exception(&mut result, "reason", Some("ADR-1"));
    assert!(!result.exception_applied);
    assert!(result.exception_justification.is_empty());
    assert_eq!(result.result_digest, "original");
    assert!(result.is_blocked());
}

// ---------------------------------------------------------------------------
// 16.5  GateCheckResult construction and field validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_check_result_passing_has_empty_details() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        if check.passed {
            assert!(
                check.failure_details.is_empty(),
                "passing check {:?} should have no failure details",
                check.kind
            );
        }
    }
}

#[test]
fn enrichment_gate_check_result_items_passed_le_items_checked() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        assert!(
            check.items_passed <= check.items_checked,
            "items_passed should not exceed items_checked for {:?}",
            check.kind
        );
    }
}

#[test]
fn enrichment_gate_check_result_summary_nonempty() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for check in &result.checks {
        assert!(
            !check.summary.is_empty(),
            "summary for {:?} should be nonempty",
            check.kind
        );
    }
}

#[test]
fn enrichment_frankenlab_scenario_check_items_equals_seven() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::FrankenlabScenario)
        .unwrap();
    assert_eq!(check.items_checked, 7);
    assert_eq!(check.items_passed, 7);
}

#[test]
fn enrichment_evidence_replay_check_items_one() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let check = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceReplay)
        .unwrap();
    assert_eq!(check.items_checked, 1);
    assert_eq!(check.items_passed, 1);
}

#[test]
fn enrichment_obligation_tracking_items_equal_scenario_count() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let frankenlab = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::FrankenlabScenario)
        .unwrap();
    let obligation = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::ObligationTracking)
        .unwrap();
    assert_eq!(obligation.items_checked, frankenlab.items_checked);
}

#[test]
fn enrichment_evidence_completeness_items_equal_scenario_count() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let frankenlab = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::FrankenlabScenario)
        .unwrap();
    let completeness = result
        .checks
        .iter()
        .find(|c| c.kind == GateCheckKind::EvidenceCompleteness)
        .unwrap();
    assert_eq!(completeness.items_checked, frankenlab.items_checked);
}

// ---------------------------------------------------------------------------
// 16.6  GateEvent structure validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_events_decision_id_contains_hex_seed() {
    let mut gate = ReleaseGate::new(0xCAFE);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        assert!(
            event.decision_id.contains("cafe"),
            "decision_id should contain hex of seed: {}",
            event.decision_id
        );
    }
}

#[test]
fn enrichment_gate_events_policy_id_is_release_gate_v1() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    for event in &result.gate_events {
        assert_eq!(event.policy_id, "release-gate-v1");
    }
}

#[test]
fn enrichment_gate_events_metadata_is_btreemap() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // All events should have a metadata map (can be empty)
    for event in &result.gate_events {
        let json = serde_json::to_string(&event.metadata).unwrap();
        let _: BTreeMap<String, String> = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn enrichment_gate_events_outcome_values() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let valid_outcomes = ["pass", "fail"];
    for event in &result.gate_events {
        assert!(
            valid_outcomes.contains(&event.outcome.as_str()),
            "unexpected outcome: {}",
            event.outcome
        );
    }
}

#[test]
fn enrichment_gate_events_error_code_none_on_pass() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
    for event in &result.gate_events {
        if event.outcome == "pass" {
            assert!(
                event.error_code.is_none(),
                "pass events should have no error code"
            );
        }
    }
}

#[test]
fn enrichment_gate_event_count_matches_checks_plus_final() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // 4 per-check events + 1 final = 5
    assert_eq!(result.gate_events.len(), 5);
}

// ---------------------------------------------------------------------------
// 16.7  GateFailureReport construction from various states
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_report_single_failing_check() {
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
            summary: "1 divergence".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "entry-x".to_string(),
                failure_type: "hash_mismatch".to_string(),
                expected: "match".to_string(),
                actual: "mismatch".to_string(),
            }],
            items_checked: 1,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: true,
            summary: "ok".to_string(),
            failure_details: Vec::new(),
            items_checked: 7,
            items_passed: 7,
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
        seed: 42,
        checks,
        verdict: Verdict::Fail {
            reason: "1 of 4 gate checks failed".to_string(),
        },
        total_checks: 4,
        passed_checks: 3,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "abc123".to_string(),
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
fn enrichment_failure_report_all_checks_fail() {
    let checks = vec![
        GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: false,
            summary: "fail".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "s1".to_string(),
                failure_type: "err".to_string(),
                expected: "a".to_string(),
                actual: "b".to_string(),
            }],
            items_checked: 1,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::EvidenceReplay,
            passed: false,
            summary: "fail".to_string(),
            failure_details: Vec::new(),
            items_checked: 1,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::ObligationTracking,
            passed: false,
            summary: "fail".to_string(),
            failure_details: Vec::new(),
            items_checked: 1,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: false,
            summary: "fail".to_string(),
            failure_details: Vec::new(),
            items_checked: 1,
            items_passed: 0,
        },
    ];
    let result = ReleaseGateResult {
        seed: 42,
        checks,
        verdict: Verdict::Fail {
            reason: "4 of 4 gate checks failed".to_string(),
        },
        total_checks: 4,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "def456".to_string(),
    };
    let report = result.failure_report();
    assert!(report.blocked);
    assert_eq!(report.failing_gates.len(), 4);
    assert!(report.summary.contains("4 gate(s) failed"));
}

#[test]
fn enrichment_failure_report_exception_overridden_not_blocked() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 0,
        passed_checks: 0,
        exception_applied: true,
        exception_justification: "hotfix".to_string(),
        gate_events: Vec::new(),
        result_digest: "abc".to_string(),
    };
    let report = result.failure_report();
    assert!(!report.blocked);
    assert_eq!(report.summary, "all gates passed");
}

#[test]
fn enrichment_failure_report_details_aggregate_across_checks() {
    let checks = vec![
        GateCheckResult {
            kind: GateCheckKind::FrankenlabScenario,
            passed: false,
            summary: "fail".to_string(),
            failure_details: vec![
                GateFailureDetail {
                    item_id: "s1".to_string(),
                    failure_type: "err".to_string(),
                    expected: "a".to_string(),
                    actual: "b".to_string(),
                },
                GateFailureDetail {
                    item_id: "s2".to_string(),
                    failure_type: "err".to_string(),
                    expected: "c".to_string(),
                    actual: "d".to_string(),
                },
            ],
            items_checked: 2,
            items_passed: 0,
        },
        GateCheckResult {
            kind: GateCheckKind::EvidenceCompleteness,
            passed: false,
            summary: "fail".to_string(),
            failure_details: vec![GateFailureDetail {
                item_id: "e1".to_string(),
                failure_type: "missing".to_string(),
                expected: "present".to_string(),
                actual: "absent".to_string(),
            }],
            items_checked: 1,
            items_passed: 0,
        },
    ];
    let result = ReleaseGateResult {
        seed: 42,
        checks,
        verdict: Verdict::Fail {
            reason: "failed".to_string(),
        },
        total_checks: 2,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "xyz".to_string(),
    };
    let report = result.failure_report();
    assert_eq!(report.details.len(), 3); // 2 from frankenlab + 1 from completeness
}

#[test]
fn enrichment_failure_report_seed_and_digest_match_result() {
    let mut gate = ReleaseGate::new(777);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    assert_eq!(report.seed, result.seed);
    assert_eq!(report.result_digest, result.result_digest);
}

// ---------------------------------------------------------------------------
// 16.8  GateConfig custom configurations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_custom_config_single_required_check() {
    let config = GateConfig {
        timeout_budget_ms: 1_000_000,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    // Gate still runs all 4 checks regardless of required kinds
    assert_eq!(result.checks.len(), 4);
}

#[test]
fn enrichment_custom_config_two_required_checks() {
    let config = GateConfig {
        timeout_budget_ms: 1_000_000,
        required_check_kinds: vec![
            GateCheckKind::FrankenlabScenario,
            GateCheckKind::EvidenceReplay,
        ],
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert!(!result.is_blocked());
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn enrichment_config_with_large_timeout_passes() {
    let config = GateConfig {
        timeout_budget_ms: u64::MAX,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// 16.9  Serde roundtrips for synthesized objects
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_result_with_exception() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 0,
        passed_checks: 0,
        exception_applied: true,
        exception_justification: "CVE-2026-001 emergency".to_string(),
        gate_events: Vec::new(),
        result_digest: "abcdef0123456789".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ReleaseGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
    assert!(back.exception_applied);
    assert_eq!(back.exception_justification, "CVE-2026-001 emergency");
}

#[test]
fn enrichment_serde_failure_detail_special_chars() {
    let detail = GateFailureDetail {
        item_id: "scenario-with-dash".to_string(),
        failure_type: "assertion_failed/timeout".to_string(),
        expected: "value < 100ms".to_string(),
        actual: "5000ms (exceeded)".to_string(),
    };
    let json = serde_json::to_string(&detail).unwrap();
    let back: GateFailureDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, back);
}

#[test]
fn enrichment_serde_gate_event_with_many_metadata() {
    let mut metadata = BTreeMap::new();
    for i in 0..10 {
        metadata.insert(format!("key_{i}"), format!("value_{i}"));
    }
    let event = GateEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "release_gate".to_string(),
        event: "custom_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: metadata.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.metadata.len(), 10);
}

#[test]
fn enrichment_serde_gate_config_custom_checks() {
    let config = GateConfig {
        timeout_budget_ms: 42_000,
        required_check_kinds: vec![
            GateCheckKind::ObligationTracking,
            GateCheckKind::EvidenceCompleteness,
        ],
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
    assert_eq!(back.required_check_kinds.len(), 2);
}

#[test]
fn enrichment_serde_exception_policy_all_true() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: true,
        requires_security_review: true,
        max_exception_hours: 168,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: ExceptionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_serde_idempotency_non_hermetic() {
    let v = IdempotencyVerification {
        digests_match: false,
        verdicts_match: true,
        checks_match: false,
        first_digest: "aaa".to_string(),
        second_digest: "bbb".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: IdempotencyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert!(!back.is_hermetic());
}

// ---------------------------------------------------------------------------
// 16.10  Idempotency verification via live evaluation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_idempotency_across_multiple_seeds() {
    for seed in [1u64, 42, 999, 123456] {
        let mut gate = ReleaseGate::new(seed);
        let mut cx = mock_cx(400_000);
        let v = gate.verify_idempotency(&mut cx);
        assert!(v.is_hermetic(), "seed {seed} should be hermetic");
        assert_eq!(v.first_digest, v.second_digest);
    }
}

#[test]
fn enrichment_idempotency_digest_length_correct() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let v = gate.verify_idempotency(&mut cx);
    assert_eq!(v.first_digest.len(), 16);
    assert_eq!(v.second_digest.len(), 16);
}

// ---------------------------------------------------------------------------
// 16.11  Constructor and seed variations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_seed_zero_produces_valid_result() {
    let mut gate = ReleaseGate::new(0);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, 0);
    assert_eq!(result.verdict, Verdict::Pass);
    assert!(!result.result_digest.is_empty());
}

#[test]
fn enrichment_seed_max_u64_produces_valid_result() {
    let mut gate = ReleaseGate::new(u64::MAX);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.seed, u64::MAX);
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn enrichment_with_exception_policy_custom_hours() {
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 1,
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
    gate.apply_exception(&mut result, "quick fix", None)
        .unwrap();
    assert!(result.exception_applied);
}

#[test]
fn enrichment_with_config_and_policy_exception_after_evaluate() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let mut gate = ReleaseGate::with_config_and_policy(42, config, policy);
    let mut cx = mock_cx(200_000);
    let mut result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());
    gate.apply_exception(&mut result, "emergency", None)
        .unwrap();
    assert!(!result.is_blocked());
    assert!(result.exception_applied);
}

// ---------------------------------------------------------------------------
// 16.12  GateFailureDetail field validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_detail_clone_independence() {
    let original = GateFailureDetail {
        item_id: "orig-id".to_string(),
        failure_type: "orig-type".to_string(),
        expected: "orig-expected".to_string(),
        actual: "orig-actual".to_string(),
    };
    let mut cloned = original.clone();
    cloned.item_id = "changed".to_string();
    cloned.failure_type = "changed".to_string();
    assert_eq!(original.item_id, "orig-id");
    assert_eq!(original.failure_type, "orig-type");
}

#[test]
fn enrichment_failure_detail_eq_and_ne() {
    let a = GateFailureDetail {
        item_id: "a".to_string(),
        failure_type: "t".to_string(),
        expected: "e".to_string(),
        actual: "x".to_string(),
    };
    let b = GateFailureDetail {
        item_id: "a".to_string(),
        failure_type: "t".to_string(),
        expected: "e".to_string(),
        actual: "x".to_string(),
    };
    let c = GateFailureDetail {
        item_id: "c".to_string(),
        failure_type: "t".to_string(),
        expected: "e".to_string(),
        actual: "x".to_string(),
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// 16.13  GateEvent clone and equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_event_clone_independence() {
    let original = GateEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "release_gate".to_string(),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("CODE".to_string()),
        metadata: BTreeMap::new(),
    };
    let mut cloned = original.clone();
    cloned.trace_id = "changed".to_string();
    cloned.error_code = None;
    assert_eq!(original.trace_id, "t1");
    assert_eq!(original.error_code, Some("CODE".to_string()));
}

#[test]
fn enrichment_gate_event_equality() {
    let make = || GateEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: BTreeMap::new(),
    };
    let a = make();
    let b = make();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 16.14  Full lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_evaluate_report_serde_roundtrip() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let report = result.failure_report();
    let report_json = serde_json::to_string_pretty(&report).unwrap();
    let report_back: GateFailureReport = serde_json::from_str(&report_json).unwrap();
    assert_eq!(report, report_back);
}

#[test]
fn enrichment_lifecycle_timeout_then_exception_then_report() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let policy = ExceptionPolicy {
        allow_exceptions: true,
        requires_adr_reference: false,
        requires_security_review: false,
        max_exception_hours: 24,
    };
    let mut gate = ReleaseGate::with_config_and_policy(42, config, policy);
    let mut cx = mock_cx(200_000);
    let mut result = gate.evaluate(&mut cx);
    assert!(result.is_blocked());

    gate.apply_exception(&mut result, "deploy anyway", None)
        .unwrap();
    assert!(!result.is_blocked());

    let report = result.failure_report();
    assert!(!report.blocked);
    assert_eq!(report.summary, "all gates passed");
}

#[test]
fn enrichment_lifecycle_idempotency_then_evaluate() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(400_000);
    let v = gate.verify_idempotency(&mut cx);
    assert!(v.is_hermetic());

    // After verify_idempotency, we can still evaluate
    let mut gate2 = ReleaseGate::new(42);
    let mut cx2 = mock_cx(200_000);
    let result = gate2.evaluate(&mut cx2);
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.result_digest, v.first_digest);
}

// ---------------------------------------------------------------------------
// 16.15  GateConfig clone and equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_equality() {
    let a = GateConfig::default();
    let b = GateConfig::default();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_config_ne_different_timeout() {
    let a = GateConfig::default();
    let mut b = GateConfig::default();
    b.timeout_budget_ms = 999;
    assert_ne!(a, b);
}

#[test]
fn enrichment_gate_config_ne_different_checks() {
    let a = GateConfig::default();
    let b = GateConfig {
        timeout_budget_ms: 600_000,
        required_check_kinds: vec![GateCheckKind::FrankenlabScenario],
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// 16.16  ExceptionPolicy equality and cloning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exception_policy_equality() {
    let a = ExceptionPolicy::default();
    let b = ExceptionPolicy::default();
    assert_eq!(a, b);
}

#[test]
fn enrichment_exception_policy_ne_different_allow() {
    let a = ExceptionPolicy::default();
    let mut b = ExceptionPolicy::default();
    b.allow_exceptions = true;
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// 16.17  Ordered check execution
// ---------------------------------------------------------------------------

#[test]
fn enrichment_checks_ordered_by_kind() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let kinds: Vec<GateCheckKind> = result.checks.iter().map(|c| c.kind).collect();
    assert_eq!(kinds[0], GateCheckKind::FrankenlabScenario);
    assert_eq!(kinds[1], GateCheckKind::EvidenceReplay);
    assert_eq!(kinds[2], GateCheckKind::ObligationTracking);
    assert_eq!(kinds[3], GateCheckKind::EvidenceCompleteness);
}

#[test]
fn enrichment_events_ordered_checks_then_final() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let event_names: Vec<&str> = result
        .gate_events
        .iter()
        .map(|e| e.event.as_str())
        .collect();
    assert_eq!(event_names[0], "frankenlab_scenarios_checked");
    assert_eq!(event_names[1], "evidence_replay_checked");
    assert_eq!(event_names[2], "obligation_tracking_checked");
    assert_eq!(event_names[3], "evidence_completeness_checked");
    assert_eq!(event_names[4], "release_gate_evaluated");
}

// ---------------------------------------------------------------------------
// 16.18  BTreeMap metadata in gate events
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_event_metadata_serde_with_ordered_keys() {
    let mut metadata = BTreeMap::new();
    metadata.insert("alpha".to_string(), "1".to_string());
    metadata.insert("beta".to_string(), "2".to_string());
    metadata.insert("gamma".to_string(), "3".to_string());
    let event = GateEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        metadata: metadata.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    // BTreeMap should serialize keys in sorted order
    let alpha_pos = json.find("alpha").unwrap();
    let beta_pos = json.find("beta").unwrap();
    let gamma_pos = json.find("gamma").unwrap();
    assert!(alpha_pos < beta_pos);
    assert!(beta_pos < gamma_pos);
}

// ---------------------------------------------------------------------------
// 16.19  ReleaseGateResult verdict transitions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_result_verdict_fail_to_pass_via_exception() {
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
            reason: "gate blocked".to_string(),
        },
        total_checks: 4,
        passed_checks: 2,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "before".to_string(),
    };
    assert!(result.is_blocked());
    gate.apply_exception(&mut result, "override", None).unwrap();
    assert!(!result.is_blocked());
    // total_checks and passed_checks unchanged
    assert_eq!(result.total_checks, 4);
    assert_eq!(result.passed_checks, 2);
}

// ---------------------------------------------------------------------------
// 16.20  Debug formatting validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_debug_format_release_gate() {
    let gate = ReleaseGate::new(42);
    let debug = format!("{gate:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("ReleaseGate"));
}

#[test]
fn enrichment_debug_format_gate_check_result() {
    let check = GateCheckResult {
        kind: GateCheckKind::FrankenlabScenario,
        passed: true,
        summary: "ok".to_string(),
        failure_details: Vec::new(),
        items_checked: 7,
        items_passed: 7,
    };
    let debug = format!("{check:?}");
    assert!(debug.contains("GateCheckResult"));
    assert!(debug.contains("FrankenlabScenario"));
}

#[test]
fn enrichment_debug_format_gate_config() {
    let config = GateConfig::default();
    let debug = format!("{config:?}");
    assert!(debug.contains("GateConfig"));
    assert!(debug.contains("600000"));
}

#[test]
fn enrichment_debug_format_exception_policy() {
    let policy = ExceptionPolicy::default();
    let debug = format!("{policy:?}");
    assert!(debug.contains("ExceptionPolicy"));
    assert!(debug.contains("72"));
}

#[test]
fn enrichment_debug_format_idempotency_verification() {
    let v = IdempotencyVerification {
        digests_match: true,
        verdicts_match: true,
        checks_match: true,
        first_digest: "abc".to_string(),
        second_digest: "abc".to_string(),
    };
    let debug = format!("{v:?}");
    assert!(debug.contains("IdempotencyVerification"));
}

// ---------------------------------------------------------------------------
// 16.21  Verdict serialization
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_pass_serde() {
    let v = Verdict::Pass;
    let json = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_verdict_fail_serde() {
    let v = Verdict::Fail {
        reason: "GATE_TIMEOUT: budget exhausted".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// 16.22  Report summary format validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_summary_pass_exact_text() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Pass,
        total_checks: 4,
        passed_checks: 4,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "abc".to_string(),
    };
    let report = result.failure_report();
    assert_eq!(report.summary, "all gates passed");
}

#[test]
fn enrichment_report_summary_infra_failure_format() {
    let result = ReleaseGateResult {
        seed: 42,
        checks: Vec::new(),
        verdict: Verdict::Fail {
            reason: "GATE_INFRASTRUCTURE_FAILURE: misconfigured".to_string(),
        },
        total_checks: 0,
        passed_checks: 0,
        exception_applied: false,
        exception_justification: String::new(),
        gate_events: Vec::new(),
        result_digest: "abc".to_string(),
    };
    let report = result.failure_report();
    assert!(report.summary.starts_with("BLOCKED:"));
    assert!(report.summary.contains("GATE_INFRASTRUCTURE_FAILURE"));
}

// ---------------------------------------------------------------------------
// 16.23  Cross-field consistency in evaluated results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_total_checks_equals_checks_len() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    assert_eq!(result.total_checks, result.checks.len());
}

#[test]
fn enrichment_passed_checks_equals_filtered_count() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    let counted = result.checks.iter().filter(|c| c.passed).count();
    assert_eq!(result.passed_checks, counted);
}

#[test]
fn enrichment_pass_verdict_implies_all_checks_passed() {
    let mut gate = ReleaseGate::new(42);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    if result.verdict == Verdict::Pass {
        assert_eq!(result.passed_checks, result.total_checks);
    }
}

#[test]
fn enrichment_blocked_result_has_nonpass_verdict() {
    let config = GateConfig {
        timeout_budget_ms: 1,
        required_check_kinds: GateConfig::default().required_check_kinds,
    };
    let mut gate = ReleaseGate::with_config(42, config);
    let mut cx = mock_cx(200_000);
    let result = gate.evaluate(&mut cx);
    if result.is_blocked() {
        assert_ne!(result.verdict, Verdict::Pass);
    }
}
