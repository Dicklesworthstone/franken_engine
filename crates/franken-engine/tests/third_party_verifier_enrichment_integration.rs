//! Enrichment integration tests for `third_party_verifier`.

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

use std::collections::BTreeMap;

use frankenengine_engine::third_party_verifier::*;

// ---------------------------------------------------------------------------
// VerificationVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_verified_exit_code() {
    assert_eq!(VerificationVerdict::Verified.exit_code(), EXIT_CODE_VERIFIED);
}

#[test]
fn enrichment_verdict_partially_verified_exit_code() {
    assert_eq!(
        VerificationVerdict::PartiallyVerified.exit_code(),
        EXIT_CODE_PARTIALLY_VERIFIED
    );
}

#[test]
fn enrichment_verdict_failed_exit_code() {
    assert_eq!(VerificationVerdict::Failed.exit_code(), EXIT_CODE_FAILED);
}

#[test]
fn enrichment_verdict_inconclusive_exit_code() {
    assert_eq!(
        VerificationVerdict::Inconclusive.exit_code(),
        EXIT_CODE_INCONCLUSIVE
    );
}

#[test]
fn enrichment_verdict_serde_roundtrip() {
    for v in [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: VerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Exit code constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exit_codes_distinct() {
    let codes = [
        EXIT_CODE_VERIFIED,
        EXIT_CODE_PARTIALLY_VERIFIED,
        EXIT_CODE_FAILED,
        EXIT_CODE_INCONCLUSIVE,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for code in codes {
        assert!(seen.insert(code), "duplicate exit code: {code}");
    }
}

#[test]
fn enrichment_verified_exit_code_is_zero() {
    assert_eq!(EXIT_CODE_VERIFIED, 0);
}

// ---------------------------------------------------------------------------
// Component constant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_component_non_empty() {
    assert!(!THIRD_PARTY_VERIFIER_COMPONENT.is_empty());
}

#[test]
fn enrichment_containment_sla_positive() {
    assert!(DEFAULT_CONTAINMENT_LATENCY_SLA_NS > 0);
}

// ---------------------------------------------------------------------------
// VerificationCheckResult serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_check_result_serde_roundtrip() {
    let check = VerificationCheckResult {
        name: "test_check".to_string(),
        passed: true,
        error_code: None,
        detail: "all good".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}

#[test]
fn enrichment_check_result_with_error_code() {
    let check = VerificationCheckResult {
        name: "failing".to_string(),
        passed: false,
        error_code: Some("ERR-001".to_string()),
        detail: "failed".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(check.error_code, back.error_code);
}

// ---------------------------------------------------------------------------
// VerifierEvent serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verifier_event_serde_roundtrip() {
    let event = VerifierEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "started".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: VerifierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// ThirdPartyVerificationReport
// ---------------------------------------------------------------------------

fn make_report(verdict: VerificationVerdict) -> ThirdPartyVerificationReport {
    ThirdPartyVerificationReport {
        claim_type: "benchmark".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        verdict,
        confidence_statement: "high confidence".to_string(),
        scope_limitations: vec!["limited to unit tests".to_string()],
        checks: vec![VerificationCheckResult {
            name: "check1".to_string(),
            passed: true,
            error_code: None,
            detail: "ok".to_string(),
        }],
        events: vec![],
    }
}

#[test]
fn enrichment_report_exit_code_matches_verdict() {
    let report = make_report(VerificationVerdict::Failed);
    assert_eq!(report.exit_code(), EXIT_CODE_FAILED);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let report = make_report(VerificationVerdict::Verified);
    let json = serde_json::to_string(&report).unwrap();
    let back: ThirdPartyVerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.verdict, back.verdict);
    assert_eq!(report.claim_type, back.claim_type);
}

// ---------------------------------------------------------------------------
// render_report_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_report_summary_contains_verdict() {
    let report = make_report(VerificationVerdict::Verified);
    let summary = render_report_summary(&report);
    assert!(summary.contains("Verified"));
}

#[test]
fn enrichment_render_report_summary_contains_claim_type() {
    let report = make_report(VerificationVerdict::Verified);
    let summary = render_report_summary(&report);
    assert!(summary.contains("benchmark"));
}

#[test]
fn enrichment_render_report_summary_contains_checks_count() {
    let report = make_report(VerificationVerdict::Verified);
    let summary = render_report_summary(&report);
    assert!(summary.contains("checks=1"));
}

// ---------------------------------------------------------------------------
// ContainmentClaimBundle serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_claim_serde() {
    let bundle = ContainmentClaimBundle {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        result: frankenengine_engine::quarantine_mesh_gate::GateValidationResult {
            seed: 42,
            scenarios: vec![],
            passed: true,
            total_scenarios: 0,
            passed_scenarios: 0,
            events: vec![],
            result_digest: "digest".to_string(),
        },
        detection_latency_sla_ns: DEFAULT_CONTAINMENT_LATENCY_SLA_NS,
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ContainmentClaimBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.trace_id, back.trace_id);
}

// ---------------------------------------------------------------------------
// VerificationAttestation serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attestation_serde_roundtrip() {
    let report = make_report(VerificationVerdict::Verified);
    let attestation = VerificationAttestation {
        claim_type: "benchmark".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        verdict: VerificationVerdict::Verified,
        issued_at_utc: "2026-01-01T00:00:00Z".to_string(),
        verifier_name: "test-verifier".to_string(),
        verifier_version: "1.0.0".to_string(),
        verifier_environment: "test".to_string(),
        methodology: "automated".to_string(),
        scope_limitations: vec![],
        report_digest_hex: "abc123".to_string(),
        statement: "verified".to_string(),
        signer_verification_key_hex: None,
        signature_hex: None,
        report,
    };
    let json = serde_json::to_string(&attestation).unwrap();
    let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(attestation.claim_type, back.claim_type);
}

// ---------------------------------------------------------------------------
// render_attestation_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_attestation_summary_non_empty() {
    let report = make_report(VerificationVerdict::Verified);
    let attestation = VerificationAttestation {
        claim_type: "benchmark".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        verdict: VerificationVerdict::Verified,
        issued_at_utc: "2026-01-01T00:00:00Z".to_string(),
        verifier_name: "verifier".to_string(),
        verifier_version: "1.0.0".to_string(),
        verifier_environment: "prod".to_string(),
        methodology: "automated".to_string(),
        scope_limitations: vec![],
        report_digest_hex: "abc".to_string(),
        statement: "ok".to_string(),
        signer_verification_key_hex: None,
        signature_hex: None,
        report,
    };
    let summary = render_attestation_summary(&attestation);
    assert!(!summary.is_empty());
    assert!(summary.contains("verifier"));
}

// ---------------------------------------------------------------------------
// VerificationAttestationInput serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attestation_input_serde_roundtrip() {
    let report = make_report(VerificationVerdict::Verified);
    let input = VerificationAttestationInput {
        report,
        issued_at_utc: "2026-01-01T00:00:00Z".to_string(),
        verifier_name: "test".to_string(),
        verifier_version: "1.0.0".to_string(),
        verifier_environment: "test".to_string(),
        methodology: "automated".to_string(),
        scope_limitations: vec![],
        signing_key_hex: None,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: VerificationAttestationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input.verifier_name, back.verifier_name);
}

// ---------------------------------------------------------------------------
// ClaimedBenchmarkOutcome serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_claimed_benchmark_outcome_serde() {
    let outcome = ClaimedBenchmarkOutcome {
        score_vs_node: 1.5,
        score_vs_bun: 2.0,
        publish_allowed: true,
        blockers: vec![],
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ClaimedBenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome.publish_allowed, back.publish_allowed);
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_failed_exit_code_matches() {
    let report = make_report(VerificationVerdict::Failed);
    assert_eq!(report.exit_code(), EXIT_CODE_FAILED);
}

#[test]
fn enrichment_report_inconclusive_exit_code_matches() {
    let report = make_report(VerificationVerdict::Inconclusive);
    assert_eq!(report.exit_code(), EXIT_CODE_INCONCLUSIVE);
}

#[test]
fn enrichment_report_partially_verified_exit_code_matches() {
    let report = make_report(VerificationVerdict::PartiallyVerified);
    assert_eq!(report.exit_code(), EXIT_CODE_PARTIALLY_VERIFIED);
}

#[test]
fn enrichment_report_scope_limitations_preserved() {
    let report = make_report(VerificationVerdict::Verified);
    assert_eq!(report.scope_limitations.len(), 1);
}

#[test]
fn enrichment_report_component_matches() {
    let report = make_report(VerificationVerdict::Verified);
    assert_eq!(report.component, THIRD_PARTY_VERIFIER_COMPONENT);
}

#[test]
fn enrichment_check_result_passed_true() {
    let check = VerificationCheckResult {
        name: "pass_check".to_string(),
        passed: true,
        error_code: None,
        detail: "all good".to_string(),
    };
    assert!(check.passed);
    assert!(check.error_code.is_none());
}

#[test]
fn enrichment_check_result_failed_has_code() {
    let check = VerificationCheckResult {
        name: "fail_check".to_string(),
        passed: false,
        error_code: Some("ERR-001".to_string()),
        detail: "broke".to_string(),
    };
    assert!(!check.passed);
    assert!(check.error_code.is_some());
}

#[test]
fn enrichment_containment_sla_500ms() {
    assert_eq!(DEFAULT_CONTAINMENT_LATENCY_SLA_NS, 500_000_000);
}

#[test]
fn enrichment_claimed_benchmark_with_blockers() {
    let outcome = ClaimedBenchmarkOutcome {
        score_vs_node: 0.5,
        score_vs_bun: 0.8,
        publish_allowed: false,
        blockers: vec!["perf regression".to_string()],
    };
    assert!(!outcome.publish_allowed);
    assert_eq!(outcome.blockers.len(), 1);
}

#[test]
fn enrichment_render_summary_contains_exit_code() {
    let report = make_report(VerificationVerdict::Failed);
    let summary = render_report_summary(&report);
    assert!(summary.contains("exit_code=25"));
}
