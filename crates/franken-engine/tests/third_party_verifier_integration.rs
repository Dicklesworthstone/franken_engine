#![forbid(unsafe_code)]

//! Integration tests for the `third_party_verifier` module.
//!
//! Covers:
//! 1. All public constants (value checks, non-empty, distinctness)
//! 2. VerificationVerdict enum (exit_code, serde, all variants)
//! 3. VerificationCheckResult struct (construction, serde, fields)
//! 4. VerifierEvent struct (construction, serde, fields)
//! 5. ThirdPartyVerificationReport struct (construction, serde, exit_code delegation)
//! 6. ClaimedBenchmarkOutcome struct (construction, serde, defaults)
//! 7. BenchmarkClaimBundle struct (construction, serde)
//! 8. ContainmentClaimBundle struct (construction, serde, default SLA)
//! 9. VerificationAttestationInput struct (construction, serde)
//! 10. VerificationAttestation struct (construction, serde)
//! 11. verify_benchmark_claim (happy path, mismatched scores, mismatched blockers, fairness)
//! 12. verify_containment_claim (all pass, count mismatch, passed mismatch, flag mismatch,
//!     criteria consistency, SLA exceeded, isolation/recovery invariants)
//! 13. generate_attestation (unsigned, signed, empty-field errors, scope limitations)
//! 14. verify_attestation (unsigned partially-verified, signed verified, tampered fields)
//! 15. render_report_summary / render_attestation_summary
//! 16. End-to-end lifecycle: containment -> attestation -> verify
//! 17. End-to-end lifecycle: benchmark -> attestation -> verify

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

use frankenengine_engine::benchmark_denominator::{
    BenchmarkCase, NativeCoveragePoint, PublicationGateInput,
};
use frankenengine_engine::quarantine_mesh_gate::{
    CriterionResult, FaultScenarioResult, FaultType, GateValidationResult,
};
use frankenengine_engine::signature_preimage::{SIGNATURE_LEN, SIGNING_KEY_LEN, SigningKey};
use frankenengine_engine::third_party_verifier::*;

// ===========================================================================
// Helpers
// ===========================================================================

fn make_scenario(id: &str, passed: bool, latency_ns: u64) -> FaultScenarioResult {
    let criteria = vec![CriterionResult {
        name: "crit_a".to_string(),
        passed,
        detail: "detail".to_string(),
    }];
    FaultScenarioResult {
        scenario_id: id.to_string(),
        fault_type: FaultType::NetworkPartition,
        passed,
        criteria,
        receipts_emitted: 1,
        final_state: None,
        detection_latency_ns: latency_ns,
        isolation_verified: passed,
        recovery_verified: passed,
    }
}

fn make_gate_result(scenarios: Vec<FaultScenarioResult>) -> GateValidationResult {
    let total = scenarios.len();
    let passed_count = scenarios.iter().filter(|s| s.passed).count();
    let all_pass = passed_count == total;
    GateValidationResult {
        seed: 42,
        scenarios,
        passed: all_pass,
        total_scenarios: total,
        passed_scenarios: passed_count,
        events: Vec::new(),
        result_digest: "digest-test".to_string(),
    }
}

fn make_containment_bundle(result: GateValidationResult) -> ContainmentClaimBundle {
    ContainmentClaimBundle {
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        result,
        detection_latency_sla_ns: DEFAULT_CONTAINMENT_LATENCY_SLA_NS,
    }
}

fn make_report(verdict: VerificationVerdict) -> ThirdPartyVerificationReport {
    ThirdPartyVerificationReport {
        claim_type: "containment".to_string(),
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        verdict,
        confidence_statement: "all checks passed".to_string(),
        scope_limitations: Vec::new(),
        checks: vec![VerificationCheckResult {
            name: "check1".to_string(),
            passed: true,
            error_code: None,
            detail: "ok".to_string(),
        }],
        events: Vec::new(),
    }
}

fn make_attestation_input(
    report: ThirdPartyVerificationReport,
    signing_key_hex: Option<String>,
) -> VerificationAttestationInput {
    VerificationAttestationInput {
        report,
        issued_at_utc: "2026-02-27T12:00:00Z".to_string(),
        verifier_name: "integ-verifier".to_string(),
        verifier_version: "2.0.0".to_string(),
        verifier_environment: "ci-sandbox".to_string(),
        methodology: "deterministic-replay".to_string(),
        scope_limitations: Vec::new(),
        signing_key_hex,
    }
}

fn signing_key_hex() -> String {
    let key = SigningKey::from_bytes([55u8; SIGNING_KEY_LEN]);
    hex::encode(key.as_bytes())
}

/// Build a valid BenchmarkClaimBundle whose claimed outcome matches what
/// evaluate_publication_gate will recompute, so verify_benchmark_claim returns Verified.
fn make_valid_benchmark_bundle() -> BenchmarkClaimBundle {
    // Both runtimes have the same workload set.
    let node_cases = vec![BenchmarkCase {
        workload_id: "w1".to_string(),
        throughput_franken_tps: 1000.0,
        throughput_baseline_tps: 800.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }];
    let bun_cases = vec![BenchmarkCase {
        workload_id: "w1".to_string(),
        throughput_franken_tps: 1100.0,
        throughput_baseline_tps: 900.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }];
    let coverage = vec![NativeCoveragePoint {
        recorded_at_utc: "2026-02-27T00:00:00Z".to_string(),
        native_slots: 80,
        total_slots: 100,
    }];
    let input = PublicationGateInput {
        node_cases,
        bun_cases,
        native_coverage_progression: coverage,
        replacement_lineage_ids: vec!["lineage-1".to_string()],
    };

    // Pre-compute the expected scores by calling the gate ourselves.
    use frankenengine_engine::benchmark_denominator::{
        PublicationContext, evaluate_publication_gate,
    };
    let ctx = PublicationContext::new("t-bench", "d-bench", "p-bench");
    let decision = evaluate_publication_gate(&input, &ctx).expect("gate should succeed");

    BenchmarkClaimBundle {
        trace_id: "t-bench".to_string(),
        decision_id: "d-bench".to_string(),
        policy_id: "p-bench".to_string(),
        input,
        claimed: ClaimedBenchmarkOutcome {
            score_vs_node: decision.score_vs_node,
            score_vs_bun: decision.score_vs_bun,
            publish_allowed: decision.publish_allowed,
            blockers: decision.blockers.clone(),
        },
    }
}

// ===========================================================================
// Section 1: Public constants
// ===========================================================================

#[test]
fn constant_component_name_is_non_empty() {
    assert!(!THIRD_PARTY_VERIFIER_COMPONENT.is_empty());
    assert_eq!(THIRD_PARTY_VERIFIER_COMPONENT, "third_party_verifier");
}

#[test]
fn constant_default_containment_sla_ns() {
    assert_eq!(DEFAULT_CONTAINMENT_LATENCY_SLA_NS, 500_000_000);
}

#[test]
fn constant_exit_codes_are_correct() {
    assert_eq!(EXIT_CODE_VERIFIED, 0);
    assert_eq!(EXIT_CODE_PARTIALLY_VERIFIED, 24);
    assert_eq!(EXIT_CODE_FAILED, 25);
    assert_eq!(EXIT_CODE_INCONCLUSIVE, 26);
}

#[test]
fn constant_exit_codes_are_all_distinct() {
    let mut codes = vec![
        EXIT_CODE_VERIFIED,
        EXIT_CODE_PARTIALLY_VERIFIED,
        EXIT_CODE_FAILED,
        EXIT_CODE_INCONCLUSIVE,
    ];
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), 4);
}

// ===========================================================================
// Section 2: VerificationVerdict enum
// ===========================================================================

#[test]
fn verdict_exit_code_all_variants() {
    assert_eq!(
        VerificationVerdict::Verified.exit_code(),
        EXIT_CODE_VERIFIED
    );
    assert_eq!(
        VerificationVerdict::PartiallyVerified.exit_code(),
        EXIT_CODE_PARTIALLY_VERIFIED
    );
    assert_eq!(VerificationVerdict::Failed.exit_code(), EXIT_CODE_FAILED);
    assert_eq!(
        VerificationVerdict::Inconclusive.exit_code(),
        EXIT_CODE_INCONCLUSIVE
    );
}

#[test]
fn verdict_serde_roundtrip_all_variants() {
    for verdict in [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: VerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, verdict, "roundtrip failed for {verdict:?}");
    }
}

#[test]
fn verdict_serde_snake_case_format() {
    let json = serde_json::to_string(&VerificationVerdict::PartiallyVerified).unwrap();
    assert_eq!(json, "\"partially_verified\"");
    let json = serde_json::to_string(&VerificationVerdict::Verified).unwrap();
    assert_eq!(json, "\"verified\"");
}

#[test]
fn verdict_serde_all_variants_produce_distinct_json() {
    let variants = [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ];
    let jsons: Vec<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    let mut deduped = jsons.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(jsons.len(), deduped.len());
}

#[test]
fn verdict_copy_clone() {
    let v = VerificationVerdict::Verified;
    let v2 = v;
    assert_eq!(v, v2);
}

// ===========================================================================
// Section 3: VerificationCheckResult struct
// ===========================================================================

#[test]
fn check_result_construction_and_fields() {
    let check = VerificationCheckResult {
        name: "my_check".to_string(),
        passed: true,
        error_code: None,
        detail: "all good".to_string(),
    };
    assert_eq!(check.name, "my_check");
    assert!(check.passed);
    assert!(check.error_code.is_none());
    assert_eq!(check.detail, "all good");
}

#[test]
fn check_result_failed_with_error_code() {
    let check = VerificationCheckResult {
        name: "sla_check".to_string(),
        passed: false,
        error_code: Some("SLA_EXCEEDED".to_string()),
        detail: "latency too high".to_string(),
    };
    assert!(!check.passed);
    assert_eq!(check.error_code.as_deref(), Some("SLA_EXCEEDED"));
}

#[test]
fn check_result_serde_roundtrip() {
    let check = VerificationCheckResult {
        name: "integrity".to_string(),
        passed: false,
        error_code: Some("ERR-99".to_string()),
        detail: "hash mismatch".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

// ===========================================================================
// Section 4: VerifierEvent struct
// ===========================================================================

#[test]
fn verifier_event_construction_and_serde() {
    let ev = VerifierEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "check_started".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: VerifierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
    assert_eq!(back.component, THIRD_PARTY_VERIFIER_COMPONENT);
}

#[test]
fn verifier_event_with_error_code() {
    let ev = VerifierEvent {
        trace_id: "t2".to_string(),
        decision_id: "d2".to_string(),
        policy_id: "p2".to_string(),
        component: "custom_comp".to_string(),
        event: "check_failed:latency".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TPV-CONT-0003".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: VerifierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("FE-TPV-CONT-0003".to_string()));
}

// ===========================================================================
// Section 5: ThirdPartyVerificationReport struct
// ===========================================================================

#[test]
fn report_construction_and_exit_code_delegation() {
    let report = make_report(VerificationVerdict::Failed);
    assert_eq!(report.exit_code(), EXIT_CODE_FAILED);
    assert_eq!(report.exit_code(), report.verdict.exit_code());
}

#[test]
fn report_serde_roundtrip() {
    let report = make_report(VerificationVerdict::Verified);
    let json = serde_json::to_string(&report).unwrap();
    let back: ThirdPartyVerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn report_scope_limitations_default_empty() {
    // scope_limitations has #[serde(default)]
    let json = r#"{
        "claim_type": "test",
        "trace_id": "t",
        "decision_id": "d",
        "policy_id": "p",
        "component": "c",
        "verdict": "verified",
        "checks": [],
        "events": []
    }"#;
    let report: ThirdPartyVerificationReport = serde_json::from_str(json).unwrap();
    assert!(report.scope_limitations.is_empty());
    assert!(report.confidence_statement.is_empty());
}

// ===========================================================================
// Section 6: ClaimedBenchmarkOutcome struct
// ===========================================================================

#[test]
fn claimed_benchmark_outcome_serde_with_defaults() {
    let json = r#"{"score_vs_node": 1.25, "score_vs_bun": 1.10, "publish_allowed": true}"#;
    let outcome: ClaimedBenchmarkOutcome = serde_json::from_str(json).unwrap();
    assert!(outcome.blockers.is_empty());
    assert!(outcome.publish_allowed);
    assert!((outcome.score_vs_node - 1.25).abs() < 1e-12);
}

#[test]
fn claimed_benchmark_outcome_serde_roundtrip_with_blockers() {
    let outcome = ClaimedBenchmarkOutcome {
        score_vs_node: 0.8,
        score_vs_bun: 0.75,
        publish_allowed: false,
        blockers: vec!["perf-regression".to_string(), "coverage-gap".to_string()],
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ClaimedBenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back.blockers.len(), 2);
    assert!(!back.publish_allowed);
}

// ===========================================================================
// Section 7: ContainmentClaimBundle struct & default SLA
// ===========================================================================

#[test]
fn containment_bundle_serde_roundtrip() {
    let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
    let bundle = make_containment_bundle(result);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ContainmentClaimBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

#[test]
fn containment_bundle_default_sla_from_json() {
    let json = r#"{
        "trace_id": "t",
        "decision_id": "d",
        "policy_id": "p",
        "result": {
            "seed": 0,
            "scenarios": [],
            "passed": true,
            "total_scenarios": 0,
            "passed_scenarios": 0,
            "events": [],
            "result_digest": ""
        }
    }"#;
    let bundle: ContainmentClaimBundle = serde_json::from_str(json).unwrap();
    assert_eq!(
        bundle.detection_latency_sla_ns,
        DEFAULT_CONTAINMENT_LATENCY_SLA_NS
    );
}

// ===========================================================================
// Section 8: verify_containment_claim
// ===========================================================================

#[test]
fn containment_all_pass_yields_verified() {
    let scenarios = vec![
        make_scenario("s1", true, 100_000),
        make_scenario("s2", true, 200_000),
    ];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert_eq!(report.claim_type, "containment");
    assert!(report.checks.iter().all(|c| c.passed));
    assert_eq!(report.component, THIRD_PARTY_VERIFIER_COMPONENT);
    assert_eq!(report.trace_id, "t-integ");
}

#[test]
fn containment_empty_scenarios_yields_failed() {
    // Empty scenarios now fail-closed (containment verification requires
    // at least one scenario result).
    let result = make_gate_result(Vec::new());
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
}

#[test]
fn containment_scenario_count_mismatch_fails() {
    let scenarios = vec![make_scenario("s1", true, 100_000)];
    let mut result = make_gate_result(scenarios);
    result.total_scenarios = 5; // wrong
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "scenario_count_matches")
        .unwrap();
    assert!(!failed.passed);
    assert!(failed.error_code.is_some());
}

#[test]
fn containment_passed_count_mismatch_fails() {
    let scenarios = vec![make_scenario("s1", true, 100_000)];
    let mut result = make_gate_result(scenarios);
    result.passed_scenarios = 0; // wrong
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "passed_count_matches")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn containment_overall_pass_flag_mismatch_fails() {
    let scenarios = vec![make_scenario("s1", true, 100_000)];
    let mut result = make_gate_result(scenarios);
    result.passed = false; // wrong: 1/1 pass but overall says false
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
}

#[test]
fn containment_empty_scenarios_fail_closed() {
    let bundle = make_containment_bundle(make_gate_result(Vec::new()));
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "scenario_set_non_empty")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn containment_criteria_consistency_mismatch_fails() {
    let mut scenario = make_scenario("s1", true, 100_000);
    scenario.criteria = vec![CriterionResult {
        name: "bad_crit".to_string(),
        passed: false, // inconsistent with scenario.passed = true
        detail: "failed".to_string(),
    }];
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "criteria_consistency:s1")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn containment_latency_sla_exceeded_fails() {
    let scenarios = vec![make_scenario("s1", true, 999_999_999)]; // over 500ms SLA
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn containment_latency_sla_within_limit_passes() {
    let scenarios = vec![make_scenario("s1", true, 100_000_000)]; // 100ms < 500ms
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn containment_custom_sla_enforced() {
    let mut bundle = make_containment_bundle(make_gate_result(vec![make_scenario("s1", true, 50)]));
    bundle.detection_latency_sla_ns = 10; // very tight
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
}

#[test]
fn containment_isolation_not_verified_fails() {
    let mut scenario = make_scenario("s1", true, 100_000);
    scenario.isolation_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "isolation_verified:s1")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn containment_recovery_not_verified_fails() {
    let mut scenario = make_scenario("s1", true, 100_000);
    scenario.recovery_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
}

#[test]
fn containment_failed_scenario_still_checks_sla_and_invariants() {
    let mut scenario = make_scenario("s1", false, 999_999_999);
    scenario.isolation_verified = false;
    scenario.recovery_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let sla = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    assert!(!sla.passed);
    let iso = report
        .checks
        .iter()
        .find(|c| c.name == "isolation_verified:s1")
        .unwrap();
    assert!(!iso.passed);
    let rec = report
        .checks
        .iter()
        .find(|c| c.name == "recovery_verified:s1")
        .unwrap();
    assert!(!rec.passed);
}

#[test]
fn containment_report_has_events() {
    let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert!(report.events.len() >= 2); // started + completed
    assert_eq!(report.events[0].component, THIRD_PARTY_VERIFIER_COMPONENT);
}

#[test]
fn containment_failed_report_has_failure_events() {
    let mut result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
    result.total_scenarios = 99; // mismatch
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failure_events: Vec<_> = report
        .events
        .iter()
        .filter(|e| e.event.starts_with("check_failed:"))
        .collect();
    assert!(!failure_events.is_empty());
}

// ===========================================================================
// Section 9: verify_benchmark_claim
// ===========================================================================

#[test]
fn benchmark_valid_claim_yields_verified() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert_eq!(report.claim_type, "benchmark");
    assert!(report.checks.iter().all(|c| c.passed));
}

#[test]
fn benchmark_mismatched_score_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.score_vs_node = 999.0; // wrong
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "score_vs_node_matches")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn benchmark_mismatched_publish_allowed_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.publish_allowed = !bundle.claimed.publish_allowed;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "publish_allowed_matches")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn benchmark_mismatched_blockers_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.blockers.push("fake-blocker".to_string());
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "blocker_set_matches")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn benchmark_workload_fairness_mismatch_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    // Add an extra workload to node_cases only, creating asymmetry.
    bundle.input.node_cases.push(BenchmarkCase {
        workload_id: "w_extra".to_string(),
        throughput_franken_tps: 500.0,
        throughput_baseline_tps: 400.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    });
    let report = verify_benchmark_claim(&bundle);
    // At minimum the fairness check fails
    let fairness = report
        .checks
        .iter()
        .find(|c| c.name == "cross_runtime_workload_set_matches");
    if let Some(check) = fairness {
        assert!(!check.passed);
    }
}

#[test]
fn benchmark_report_has_events_and_trace_context() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert!(report.events.len() >= 2);
    assert_eq!(report.trace_id, "t-bench");
    assert_eq!(report.decision_id, "d-bench");
    assert_eq!(report.policy_id, "p-bench");
}

// ===========================================================================
// Section 10: generate_attestation
// ===========================================================================

#[test]
fn generate_attestation_unsigned_succeeds() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report.clone(), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.claim_type, "containment");
    assert_eq!(attestation.verdict, VerificationVerdict::Verified);
    assert_eq!(attestation.verifier_name, "integ-verifier");
    assert_eq!(attestation.verifier_version, "2.0.0");
    assert!(!attestation.report_digest_hex.is_empty());
    assert!(attestation.signature_hex.is_none());
    assert!(attestation.signer_verification_key_hex.is_none());
    assert_eq!(attestation.report, report);
}

#[test]
fn generate_attestation_signed_succeeds() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report, Some(signing_key_hex()));
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.signature_hex.is_some());
    assert!(attestation.signer_verification_key_hex.is_some());
}

#[test]
fn generate_attestation_empty_verifier_name_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.verifier_name = "".to_string();
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("verifier_name"), "err: {err}");
}

#[test]
fn generate_attestation_empty_issued_at_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.issued_at_utc = "  ".to_string();
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("issued_at_utc"), "err: {err}");
}

#[test]
fn generate_attestation_empty_verifier_version_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.verifier_version = "".to_string();
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("verifier_version"), "err: {err}");
}

#[test]
fn generate_attestation_empty_methodology_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.methodology = "".to_string();
    assert!(generate_attestation(&input).is_err());
}

#[test]
fn generate_attestation_empty_environment_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.verifier_environment = "".to_string();
    assert!(generate_attestation(&input).is_err());
}

#[test]
fn generate_attestation_invalid_signing_key_hex_error() {
    let input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some("not-hex!!!".to_string()),
    );
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("signing key"), "err: {err}");
}

#[test]
fn generate_attestation_wrong_length_signing_key_error() {
    let input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(hex::encode([0u8; 16])), // 16 bytes, not 32
    );
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("bytes"), "err: {err}");
}

#[test]
fn generate_attestation_scope_limitations_in_statement() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.scope_limitations = vec!["no-crypto-audit".to_string(), "sandbox-only".to_string()];
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.statement.contains("no-crypto-audit"));
    assert!(attestation.statement.contains("sandbox-only"));
    assert_eq!(attestation.scope_limitations.len(), 2);
}

#[test]
fn generate_attestation_statement_has_none_for_no_limitations() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.statement.contains("Scope limitations: none"));
}

#[test]
fn generate_attestation_digest_deterministic() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report, None);
    let a1 = generate_attestation(&input).unwrap();
    let a2 = generate_attestation(&input).unwrap();
    assert_eq!(a1.report_digest_hex, a2.report_digest_hex);
}

#[test]
fn generate_attestation_digest_changes_with_report_content() {
    let a1 = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let a2 = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Failed),
        None,
    ))
    .unwrap();
    assert_ne!(a1.report_digest_hex, a2.report_digest_hex);
}

// ===========================================================================
// Section 11: verify_attestation
// ===========================================================================

#[test]
fn verify_attestation_unsigned_yields_partially_verified() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
    assert!(verification.checks.iter().all(|c| c.passed));
    assert!(!verification.scope_limitations.is_empty());
}

#[test]
fn verify_attestation_signed_yields_verified() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
    assert!(verification.checks.iter().all(|c| c.passed));
}

#[test]
fn verify_attestation_mismatched_claim_type_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.claim_type = "wrong".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn verify_attestation_mismatched_verdict_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.verdict = VerificationVerdict::Failed;
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn verify_attestation_mismatched_trace_id_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.trace_id = "wrong-trace".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    let failed = verification
        .checks
        .iter()
        .find(|c| c.name == "context_matches_report")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn verify_attestation_tampered_digest_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.report_digest_hex = "0000000000000000".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn verify_attestation_tampered_statement_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.statement = "tampered".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn verify_attestation_empty_required_field_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.verifier_name = "".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    let failed = verification
        .checks
        .iter()
        .find(|c| c.name == "attestation_required_fields")
        .unwrap();
    assert!(!failed.passed);
}

#[test]
fn verify_attestation_inconsistent_sig_presence_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    // Set only key, no signature
    attestation.signer_verification_key_hex = Some("abcd".to_string());
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn verify_attestation_tampered_signature_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    attestation.signature_hex = Some(hex::encode([0u8; SIGNATURE_LEN]));
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    let failed = verification
        .checks
        .iter()
        .find(|c| c.name == "signature_valid")
        .unwrap();
    assert!(!failed.passed);
}

// ===========================================================================
// Section 12: render functions
// ===========================================================================

#[test]
fn render_report_summary_contains_key_fields() {
    let mut report = make_report(VerificationVerdict::Verified);
    report.checks.push(VerificationCheckResult {
        name: "bad".to_string(),
        passed: false,
        error_code: Some("ERR".to_string()),
        detail: "fail".to_string(),
    });
    let summary = render_report_summary(&report);
    assert!(
        summary.contains("claim_type=containment"),
        "summary: {summary}"
    );
    assert!(summary.contains("checks=2"), "summary: {summary}");
    assert!(summary.contains("failed=1"), "summary: {summary}");
    assert!(summary.contains("exit_code="), "summary: {summary}");
}

#[test]
fn render_attestation_summary_unsigned() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let summary = render_attestation_summary(&attestation);
    assert!(summary.contains("signed=false"), "summary: {summary}");
    assert!(
        summary.contains("verifier=integ-verifier@2.0.0"),
        "summary: {summary}"
    );
}

#[test]
fn render_attestation_summary_signed() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let summary = render_attestation_summary(&attestation);
    assert!(summary.contains("signed=true"), "summary: {summary}");
}

// ===========================================================================
// Section 13: End-to-end lifecycle
// ===========================================================================

#[test]
fn e2e_containment_unsigned_attestation_lifecycle() {
    // Step 1: Verify containment claim
    let result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);

    // Step 2: Generate unsigned attestation
    let input = make_attestation_input(report, None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.verdict, VerificationVerdict::Verified);

    // Step 3: Verify attestation (unsigned -> PartiallyVerified)
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
    assert!(verification.checks.iter().all(|c| c.passed));
}

#[test]
fn e2e_containment_signed_attestation_lifecycle() {
    let result = make_gate_result(vec![
        make_scenario("s1", true, 100_000),
        make_scenario("s2", true, 200_000),
    ]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);

    let input = make_attestation_input(report, Some(signing_key_hex()));
    let attestation = generate_attestation(&input).unwrap();

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
    assert!(verification.checks.iter().all(|c| c.passed));
}

#[test]
fn e2e_benchmark_signed_attestation_lifecycle() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);

    let input = make_attestation_input(report, Some(signing_key_hex()));
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.claim_type, "benchmark");

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
    assert!(verification.checks.iter().all(|c| c.passed));
}

// ===========================================================================
// Section 14: Serde roundtrips for all major types
// ===========================================================================

#[test]
fn attestation_input_serde_roundtrip() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let json = serde_json::to_string(&input).unwrap();
    let back: VerificationAttestationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
}

#[test]
fn attestation_unsigned_serde_roundtrip() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let json = serde_json::to_string(&attestation).unwrap();
    let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, attestation);
}

#[test]
fn attestation_signed_serde_roundtrip() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let json = serde_json::to_string(&attestation).unwrap();
    let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, attestation);
}

#[test]
fn benchmark_claim_bundle_serde_roundtrip() {
    let bundle = make_valid_benchmark_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: BenchmarkClaimBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, bundle.trace_id);
    assert_eq!(back.claimed.publish_allowed, bundle.claimed.publish_allowed);
}

// ===========================================================================
// Section 15: Enrichment tests
// ===========================================================================

// ---------- Benchmark verification enrichment ----------

#[test]
fn enrichment_benchmark_score_vs_bun_tampered_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.score_vs_bun = 777.7;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failed = report
        .checks
        .iter()
        .find(|c| c.name == "score_vs_bun_matches")
        .unwrap();
    assert!(!failed.passed);
    assert!(failed.error_code.is_some());
}

#[test]
fn enrichment_benchmark_both_scores_tampered_both_fail() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.score_vs_node = 0.0;
    bundle.claimed.score_vs_bun = 0.0;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let node_check = report
        .checks
        .iter()
        .find(|c| c.name == "score_vs_node_matches")
        .unwrap();
    let bun_check = report
        .checks
        .iter()
        .find(|c| c.name == "score_vs_bun_matches")
        .unwrap();
    assert!(!node_check.passed);
    assert!(!bun_check.passed);
}

#[test]
fn enrichment_benchmark_report_claim_type_is_benchmark() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.claim_type, "benchmark");
}

#[test]
fn enrichment_benchmark_report_component_is_third_party_verifier() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.component, THIRD_PARTY_VERIFIER_COMPONENT);
}

#[test]
fn enrichment_benchmark_verified_report_has_no_scope_limitations() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert!(report.scope_limitations.is_empty());
}

#[test]
fn enrichment_benchmark_verified_confidence_contains_checks_passed() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert!(
        report.confidence_statement.contains("checks passed"),
        "confidence: {}",
        report.confidence_statement
    );
}

#[test]
fn enrichment_benchmark_failed_confidence_contains_failed_count() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.score_vs_node = 999.9;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    assert!(
        report.confidence_statement.contains("failed"),
        "confidence: {}",
        report.confidence_statement
    );
}

#[test]
fn enrichment_benchmark_publish_allowed_false_when_should_be_true_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    // The gate result will compute publish_allowed; flip the claimed value
    let expected = bundle.claimed.publish_allowed;
    bundle.claimed.publish_allowed = !expected;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "publish_allowed_matches")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_benchmark_empty_blockers_match_when_both_empty() {
    let bundle = make_valid_benchmark_bundle();
    // By default the valid bundle has matching blockers
    let report = verify_benchmark_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "blocker_set_matches")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_benchmark_extra_blocker_in_claim_fails() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.blockers.push("phantom-blocker".to_string());
    let report = verify_benchmark_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "blocker_set_matches")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_benchmark_fairness_passes_when_workloads_identical() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "cross_runtime_workload_set_matches")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_benchmark_fairness_fails_extra_bun_workload() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.input.bun_cases.push(BenchmarkCase {
        workload_id: "extra-bun-only".to_string(),
        throughput_franken_tps: 100.0,
        throughput_baseline_tps: 80.0,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    });
    let report = verify_benchmark_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "cross_runtime_workload_set_matches")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_benchmark_started_and_completed_events_present() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert!(
        report
            .events
            .iter()
            .any(|e| e.event == "benchmark_verification_started")
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| e.event == "benchmark_verification_completed")
    );
}

#[test]
fn enrichment_benchmark_failed_report_has_check_failed_events() {
    let mut bundle = make_valid_benchmark_bundle();
    bundle.claimed.score_vs_node = 123.456;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let failure_events: Vec<_> = report
        .events
        .iter()
        .filter(|e| e.event.starts_with("check_failed:"))
        .collect();
    assert!(!failure_events.is_empty());
    assert!(failure_events.iter().all(|e| e.outcome == "fail"));
}

#[test]
fn enrichment_benchmark_report_exit_code_delegates_to_verdict() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.exit_code(), report.verdict.exit_code());
}

// ---------- Containment verification enrichment ----------

#[test]
fn enrichment_containment_multiple_scenarios_all_pass() {
    let scenarios = vec![
        make_scenario("a", true, 10_000),
        make_scenario("b", true, 20_000),
        make_scenario("c", true, 30_000),
    ];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert!(report.checks.iter().all(|c| c.passed));
}

#[test]
fn enrichment_containment_mixed_pass_fail_reports_failed() {
    let scenarios = vec![
        make_scenario("pass-1", true, 10_000),
        make_scenario("fail-1", false, 10_000),
    ];
    // make_gate_result computes correctly
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    // overall_pass_flag should reflect partial failure
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "overall_pass_flag_matches" && c.passed)
    );
    // criteria consistency for the failed scenario should still pass (criteria match scenario.passed)
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "criteria_consistency:fail-1" && c.passed)
    );
}

#[test]
fn enrichment_containment_sla_at_exact_boundary_passes() {
    // Latency exactly equals SLA
    let scenarios = vec![make_scenario(
        "exact-sla",
        true,
        DEFAULT_CONTAINMENT_LATENCY_SLA_NS,
    )];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:exact-sla")
        .unwrap();
    // Exactly at boundary: detection_latency_ns == sla_ns, so condition
    // `detection_latency_ns > sla_ns` is false -> passes
    assert!(check.passed);
}

#[test]
fn enrichment_containment_sla_one_over_boundary_fails() {
    let scenarios = vec![make_scenario(
        "over-sla",
        true,
        DEFAULT_CONTAINMENT_LATENCY_SLA_NS + 1,
    )];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:over-sla")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_containment_sla_one_under_boundary_passes() {
    let scenarios = vec![make_scenario(
        "under-sla",
        true,
        DEFAULT_CONTAINMENT_LATENCY_SLA_NS - 1,
    )];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:under-sla")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_containment_zero_latency_passes() {
    let scenarios = vec![make_scenario("zero-lat", true, 0)];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:zero-lat")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_containment_max_latency_on_failed_scenario_fails_sla_check() {
    let mut scenario = make_scenario("max-lat-fail", false, u64::MAX);
    scenario.isolation_verified = false;
    scenario.recovery_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:max-lat-fail")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_containment_report_trace_context_matches_bundle() {
    let result = make_gate_result(vec![make_scenario("ctx", true, 100)]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.trace_id, bundle.trace_id);
    assert_eq!(report.decision_id, bundle.decision_id);
    assert_eq!(report.policy_id, bundle.policy_id);
}

#[test]
fn enrichment_containment_multiple_criteria_all_pass_scenario_passes() {
    let criteria = vec![
        CriterionResult {
            name: "c1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
        CriterionResult {
            name: "c2".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
        CriterionResult {
            name: "c3".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
    ];
    let mut scenario = make_scenario("multi-crit", true, 100);
    scenario.criteria = criteria;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "criteria_consistency:multi-crit")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_containment_one_criterion_fails_consistency_check_fails() {
    let criteria = vec![
        CriterionResult {
            name: "c1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        },
        CriterionResult {
            name: "c2".to_string(),
            passed: false, // inconsistent with scenario.passed=true
            detail: "bad".to_string(),
        },
    ];
    let mut scenario = make_scenario("mixed-crit", true, 100);
    scenario.criteria = criteria;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "criteria_consistency:mixed-crit")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_containment_empty_criteria_on_passed_scenario_fails() {
    let mut scenario = make_scenario("empty-crit", true, 100);
    scenario.criteria = Vec::new();
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "criteria_consistency:empty-crit")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_containment_custom_sla_zero_any_latency_fails() {
    let mut bundle = make_containment_bundle(make_gate_result(vec![make_scenario("s1", true, 1)]));
    bundle.detection_latency_sla_ns = 0;
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_containment_custom_sla_zero_with_zero_latency_passes() {
    let mut bundle = make_containment_bundle(make_gate_result(vec![make_scenario("s1", true, 0)]));
    bundle.detection_latency_sla_ns = 0;
    let report = verify_containment_claim(&bundle);
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    // 0 > 0 is false, so passes
    assert!(check.passed);
}

#[test]
fn enrichment_containment_serde_default_sla_is_stable() {
    let json = r#"{
        "trace_id": "t-default",
        "decision_id": "d-default",
        "policy_id": "p-default",
        "result": {
            "seed": 0,
            "scenarios": [],
            "passed": true,
            "total_scenarios": 0,
            "passed_scenarios": 0,
            "events": [],
            "result_digest": "d"
        }
    }"#;
    let bundle: ContainmentClaimBundle = serde_json::from_str(json).unwrap();
    assert_eq!(bundle.detection_latency_sla_ns, 500_000_000);
}

#[test]
fn enrichment_containment_both_isolation_and_recovery_false_on_passed_scenario_fails() {
    let mut scenario = make_scenario("both-fail", true, 100);
    scenario.isolation_verified = false;
    scenario.recovery_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    let iso = report
        .checks
        .iter()
        .find(|c| c.name == "isolation_verified:both-fail")
        .unwrap();
    let rec = report
        .checks
        .iter()
        .find(|c| c.name == "recovery_verified:both-fail")
        .unwrap();
    assert!(!iso.passed);
    assert!(!rec.passed);
}

// ---------- Attestation generation enrichment ----------

#[test]
fn enrichment_attestation_claim_type_matches_report() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report.clone(), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.claim_type, report.claim_type);
}

#[test]
fn enrichment_attestation_verdict_matches_report() {
    let report = make_report(VerificationVerdict::Failed);
    let input = make_attestation_input(report.clone(), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.verdict, report.verdict);
}

#[test]
fn enrichment_attestation_context_fields_match_report() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report.clone(), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.trace_id, report.trace_id);
    assert_eq!(attestation.decision_id, report.decision_id);
    assert_eq!(attestation.policy_id, report.policy_id);
}

#[test]
fn enrichment_attestation_verifier_fields_from_input() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.verifier_name, "integ-verifier");
    assert_eq!(attestation.verifier_version, "2.0.0");
    assert_eq!(attestation.verifier_environment, "ci-sandbox");
    assert_eq!(attestation.methodology, "deterministic-replay");
}

#[test]
fn enrichment_attestation_statement_contains_verifier_name() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("integ-verifier"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_statement_contains_methodology() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("deterministic-replay"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_statement_contains_trace_id() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("t-integ"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_statement_contains_issued_at() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("2026-02-27T12:00:00Z"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_statement_contains_verdict_label() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("verified"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_failed_verdict_in_statement() {
    let input = make_attestation_input(make_report(VerificationVerdict::Failed), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(
        attestation.statement.contains("failed"),
        "statement: {}",
        attestation.statement
    );
}

#[test]
fn enrichment_attestation_scope_limitations_propagated() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.scope_limitations = vec![
        "no-hardware-attestation".to_string(),
        "sandbox-only".to_string(),
    ];
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.scope_limitations.len(), 2);
    assert!(
        attestation
            .scope_limitations
            .iter()
            .any(|l| l == "no-hardware-attestation")
    );
}

#[test]
fn enrichment_attestation_embedded_report_equals_original() {
    let report = make_report(VerificationVerdict::Verified);
    let input = make_attestation_input(report.clone(), None);
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.report, report);
}

#[test]
fn enrichment_attestation_digest_hex_is_hex_and_nonempty() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(!attestation.report_digest_hex.is_empty());
    // Should be valid hex
    assert!(hex::decode(&attestation.report_digest_hex).is_ok());
}

#[test]
fn enrichment_attestation_signed_has_both_key_and_signature() {
    let input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    );
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.signer_verification_key_hex.is_some());
    assert!(attestation.signature_hex.is_some());
    // Both should be valid hex
    assert!(hex::decode(attestation.signer_verification_key_hex.as_ref().unwrap()).is_ok());
    assert!(hex::decode(attestation.signature_hex.as_ref().unwrap()).is_ok());
}

#[test]
fn enrichment_attestation_unsigned_has_neither_key_nor_signature() {
    let input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.signer_verification_key_hex.is_none());
    assert!(attestation.signature_hex.is_none());
}

#[test]
fn enrichment_attestation_short_signing_key_error() {
    let input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(hex::encode([0u8; 8])), // 8 bytes, not 32
    );
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("bytes"), "err: {err}");
}

#[test]
fn enrichment_attestation_long_signing_key_error() {
    let input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(hex::encode([0u8; 64])), // 64 bytes, not 32
    );
    let err = generate_attestation(&input).unwrap_err();
    assert!(err.contains("bytes"), "err: {err}");
}

#[test]
fn enrichment_attestation_whitespace_only_verifier_name_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.verifier_name = "   ".to_string();
    assert!(generate_attestation(&input).is_err());
}

#[test]
fn enrichment_attestation_whitespace_only_methodology_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.methodology = " \t ".to_string();
    assert!(generate_attestation(&input).is_err());
}

#[test]
fn enrichment_attestation_whitespace_only_environment_error() {
    let mut input = make_attestation_input(make_report(VerificationVerdict::Verified), None);
    input.verifier_environment = "  ".to_string();
    assert!(generate_attestation(&input).is_err());
}

// ---------- Attestation verification enrichment ----------

#[test]
fn enrichment_verify_attestation_report_contains_claim_type_attestation() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.claim_type, "attestation");
}

#[test]
fn enrichment_verify_attestation_context_matches_report_check_passes() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    let check = verification
        .checks
        .iter()
        .find(|c| c.name == "context_matches_report")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_verify_attestation_mismatched_decision_id_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.decision_id = "wrong-decision".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    let check = verification
        .checks
        .iter()
        .find(|c| c.name == "context_matches_report")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_verify_attestation_mismatched_policy_id_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.policy_id = "wrong-policy".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_empty_claim_type_fails_required_fields() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.claim_type = "".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    let check = verification
        .checks
        .iter()
        .find(|c| c.name == "attestation_required_fields")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_verify_attestation_empty_trace_id_fails_required_fields() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.trace_id = "".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_empty_issued_at_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.issued_at_utc = "".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_empty_methodology_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.methodology = "".to_string();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_digest_check_name() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert!(
        verification
            .checks
            .iter()
            .any(|c| c.name == "report_digest_matches")
    );
}

#[test]
fn enrichment_verify_attestation_statement_template_check_passes() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    let check = verification
        .checks
        .iter()
        .find(|c| c.name == "statement_matches_canonical_template")
        .unwrap();
    assert!(check.passed);
}

#[test]
fn enrichment_verify_attestation_tampered_statement_template_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    attestation.statement = format!("{} EXTRA", attestation.statement);
    let verification = verify_attestation(&attestation);
    let check = verification
        .checks
        .iter()
        .find(|c| c.name == "statement_matches_canonical_template")
        .unwrap();
    assert!(!check.passed);
}

#[test]
fn enrichment_verify_attestation_signature_only_without_key_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    // Remove key but keep signature
    attestation.signer_verification_key_hex = None;
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_key_only_without_signature_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    // Set key but no signature
    attestation.signer_verification_key_hex = Some(hex::encode([99u8; 32]));
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_invalid_verification_key_hex_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    attestation.signer_verification_key_hex = Some("not-valid-hex!!!".to_string());
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_invalid_signature_hex_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    attestation.signature_hex = Some("zzz-not-hex".to_string());
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_wrong_length_signature_fails() {
    let mut attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    attestation.signature_hex = Some(hex::encode([0u8; 16])); // wrong length
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
}

#[test]
fn enrichment_verify_attestation_signed_all_checks_pass() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
    assert!(
        verification.checks.iter().all(|c| c.passed),
        "failing checks: {:?}",
        verification
            .checks
            .iter()
            .filter(|c| !c.passed)
            .collect::<Vec<_>>()
    );
}

#[test]
fn enrichment_verify_attestation_has_started_and_completed_events() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert!(
        verification
            .events
            .iter()
            .any(|e| e.event == "attestation_verification_started")
    );
    assert!(
        verification
            .events
            .iter()
            .any(|e| e.event == "attestation_verification_completed")
    );
}

#[test]
fn enrichment_verify_attestation_partially_verified_has_scope_limitations() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
    assert!(!verification.scope_limitations.is_empty());
}

#[test]
fn enrichment_verify_attestation_confidence_statement_scope_limitation() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let verification = verify_attestation(&attestation);
    assert!(
        verification
            .confidence_statement
            .contains("scope limitation")
            || verification
                .confidence_statement
                .contains("partially constrained"),
        "confidence: {}",
        verification.confidence_statement
    );
}

// ---------- Render function enrichment ----------

#[test]
fn enrichment_render_report_summary_contains_exit_code() {
    let report = make_report(VerificationVerdict::Verified);
    let summary = render_report_summary(&report);
    assert!(summary.contains("exit_code=0"), "summary: {summary}");
}

#[test]
fn enrichment_render_report_summary_failed_has_nonzero_failed() {
    let mut report = make_report(VerificationVerdict::Failed);
    report.checks.push(VerificationCheckResult {
        name: "fail_check".to_string(),
        passed: false,
        error_code: Some("ERR".to_string()),
        detail: "bad".to_string(),
    });
    let summary = render_report_summary(&report);
    assert!(summary.contains("failed=1"), "summary: {summary}");
}

#[test]
fn enrichment_render_report_summary_contains_confidence() {
    let report = make_report(VerificationVerdict::Verified);
    let summary = render_report_summary(&report);
    assert!(summary.contains("confidence="), "summary: {summary}");
}

#[test]
fn enrichment_render_attestation_summary_contains_claim_type() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let summary = render_attestation_summary(&attestation);
    assert!(
        summary.contains("claim_type=containment"),
        "summary: {summary}"
    );
}

#[test]
fn enrichment_render_attestation_summary_contains_issued_at() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        None,
    ))
    .unwrap();
    let summary = render_attestation_summary(&attestation);
    assert!(summary.contains("issued_at="), "summary: {summary}");
}

#[test]
fn enrichment_render_attestation_summary_signed_shows_true() {
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let summary = render_attestation_summary(&attestation);
    assert!(summary.contains("signed=true"), "summary: {summary}");
}

// ---------- Serde roundtrip enrichment ----------

#[test]
fn enrichment_verification_check_result_with_error_code_serde() {
    let check = VerificationCheckResult {
        name: "enrichment_check".to_string(),
        passed: false,
        error_code: Some("FE-TPV-BENCH-0001".to_string()),
        detail: "recompute mismatch".to_string(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: VerificationCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

#[test]
fn enrichment_verifier_event_with_all_fields_serde() {
    let event = VerifierEvent {
        trace_id: "t-enrich".to_string(),
        decision_id: "d-enrich".to_string(),
        policy_id: "p-enrich".to_string(),
        component: "enrichment_comp".to_string(),
        event: "check_failed:score_vs_node_matches".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TPV-BENCH-0002".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: VerifierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn enrichment_containment_claim_bundle_explicit_sla_serde() {
    let result = make_gate_result(vec![make_scenario("s1", true, 1000)]);
    let mut bundle = make_containment_bundle(result);
    bundle.detection_latency_sla_ns = 999_999;
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ContainmentClaimBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back.detection_latency_sla_ns, 999_999);
}

#[test]
fn enrichment_verification_report_with_scope_limitations_serde() {
    let mut report = make_report(VerificationVerdict::PartiallyVerified);
    report.scope_limitations = vec!["unsigned attestation".to_string(), "sandbox".to_string()];
    report.confidence_statement = "partial confidence".to_string();
    let json = serde_json::to_string(&report).unwrap();
    let back: ThirdPartyVerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.scope_limitations.len(), 2);
    assert_eq!(back.confidence_statement, "partial confidence");
}

#[test]
fn enrichment_attestation_with_scope_limitations_serde() {
    let mut input = make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    );
    input.scope_limitations = vec!["limited-env".to_string()];
    let attestation = generate_attestation(&input).unwrap();
    let json = serde_json::to_string(&attestation).unwrap();
    let back: VerificationAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.scope_limitations, attestation.scope_limitations);
    assert_eq!(back.signature_hex, attestation.signature_hex);
}

// ---------- End-to-end lifecycle enrichment ----------

#[test]
fn enrichment_e2e_benchmark_unsigned_lifecycle() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);

    let input = make_attestation_input(report, None);
    let attestation = generate_attestation(&input).unwrap();
    assert!(attestation.signature_hex.is_none());

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
    assert!(verification.checks.iter().all(|c| c.passed));
}

#[test]
fn enrichment_e2e_containment_failed_claim_attestation() {
    // Containment fails due to latency violation
    let scenarios = vec![make_scenario("s-slow", true, 999_999_999)];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);

    // Attestation for a failed report still generates
    let input = make_attestation_input(report, Some(signing_key_hex()));
    let attestation = generate_attestation(&input).unwrap();
    assert_eq!(attestation.verdict, VerificationVerdict::Failed);

    // Verification of the attestation should still succeed (attestation itself is consistent)
    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
}

#[test]
fn enrichment_e2e_attestation_of_attestation_verification_report() {
    // Create an attestation, verify it, then attest that verification
    let attestation = generate_attestation(&make_attestation_input(
        make_report(VerificationVerdict::Verified),
        Some(signing_key_hex()),
    ))
    .unwrap();
    let verification_report = verify_attestation(&attestation);
    assert_eq!(verification_report.verdict, VerificationVerdict::Verified);

    // Use the verification report as input for another attestation
    let input2 = make_attestation_input(verification_report, Some(signing_key_hex()));
    let attestation2 = generate_attestation(&input2).unwrap();
    assert_eq!(attestation2.claim_type, "attestation");

    let verification2 = verify_attestation(&attestation2);
    assert_eq!(verification2.verdict, VerificationVerdict::Verified);
}

#[test]
fn enrichment_e2e_different_signing_keys_produce_different_signatures() {
    let report = make_report(VerificationVerdict::Verified);

    let key1 = SigningKey::from_bytes([55u8; SIGNING_KEY_LEN]);
    let key2 = SigningKey::from_bytes([66u8; SIGNING_KEY_LEN]);

    let a1 = generate_attestation(&make_attestation_input(
        report.clone(),
        Some(hex::encode(key1.as_bytes())),
    ))
    .unwrap();
    let a2 = generate_attestation(&make_attestation_input(
        report,
        Some(hex::encode(key2.as_bytes())),
    ))
    .unwrap();

    assert_ne!(a1.signature_hex, a2.signature_hex);
    assert_ne!(
        a1.signer_verification_key_hex,
        a2.signer_verification_key_hex
    );
}

// ---------- Verdict and exit code enrichment ----------

#[test]
fn enrichment_verdict_copy_semantics() {
    let v = VerificationVerdict::Inconclusive;
    let v2 = v;
    let v3 = v;
    assert_eq!(v2, v3);
    assert_eq!(v2, VerificationVerdict::Inconclusive);
}

#[test]
fn enrichment_verdict_all_exit_codes_are_non_negative() {
    for verdict in [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ] {
        assert!(
            verdict.exit_code() >= 0,
            "verdict {:?} has negative exit code",
            verdict
        );
    }
}

#[test]
fn enrichment_verdict_verified_is_zero() {
    assert_eq!(VerificationVerdict::Verified.exit_code(), 0);
}

#[test]
fn enrichment_verdict_non_verified_are_nonzero() {
    assert_ne!(VerificationVerdict::PartiallyVerified.exit_code(), 0);
    assert_ne!(VerificationVerdict::Failed.exit_code(), 0);
    assert_ne!(VerificationVerdict::Inconclusive.exit_code(), 0);
}

#[test]
fn enrichment_verdict_serde_rejects_unknown_variant() {
    let result = serde_json::from_str::<VerificationVerdict>("\"unknown_verdict\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_verdict_debug_format_nonempty() {
    for verdict in [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ] {
        let debug = format!("{verdict:?}");
        assert!(!debug.is_empty());
    }
}

// ---------- Report structure enrichment ----------

#[test]
fn enrichment_report_checks_are_ordered() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    // Checks should preserve insertion order -- at minimum they are non-empty
    assert!(!report.checks.is_empty());
    // First check should be about score or benchmark computation
    assert!(
        report.checks[0].name.contains("score")
            || report.checks[0].name.contains("benchmark")
            || report.checks[0].name.contains("publish")
            || report.checks[0].name.contains("blocker")
            || report.checks[0].name.contains("cross_runtime"),
        "first check: {}",
        report.checks[0].name
    );
}

#[test]
fn enrichment_report_events_first_is_started() {
    let bundle = make_valid_benchmark_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert!(
        report.events[0].event.contains("started"),
        "first event: {}",
        report.events[0].event
    );
}

#[test]
fn enrichment_containment_report_per_scenario_checks_present() {
    let scenarios = vec![
        make_scenario("alpha", true, 100),
        make_scenario("beta", true, 200),
    ];
    let result = make_gate_result(scenarios);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);

    // Each scenario should generate criteria_consistency, latency_sla,
    // isolation_verified, and recovery_verified checks
    for id in &["alpha", "beta"] {
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == format!("criteria_consistency:{id}")),
            "missing criteria_consistency:{id}"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == format!("latency_sla:{id}")),
            "missing latency_sla:{id}"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == format!("isolation_verified:{id}")),
            "missing isolation_verified:{id}"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == format!("recovery_verified:{id}")),
            "missing recovery_verified:{id}"
        );
    }
}

#[test]
fn enrichment_containment_report_has_scenario_count_and_passed_count_checks() {
    let result = make_gate_result(vec![make_scenario("s1", true, 100)]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "scenario_count_matches")
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "passed_count_matches")
    );
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "overall_pass_flag_matches")
    );
}

// ---------- Additional edge case enrichment ----------

#[test]
fn enrichment_benchmark_claim_with_many_workloads_verifies() {
    use frankenengine_engine::benchmark_denominator::{
        PublicationContext, evaluate_publication_gate,
    };

    let mut node_cases = Vec::new();
    let mut bun_cases = Vec::new();
    for i in 0..10 {
        let wid = format!("workload-{i}");
        node_cases.push(BenchmarkCase {
            workload_id: wid.clone(),
            throughput_franken_tps: 1000.0 + (i as f64) * 100.0,
            throughput_baseline_tps: 800.0 + (i as f64) * 50.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        });
        bun_cases.push(BenchmarkCase {
            workload_id: wid,
            throughput_franken_tps: 1100.0 + (i as f64) * 100.0,
            throughput_baseline_tps: 900.0 + (i as f64) * 50.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        });
    }
    let input = PublicationGateInput {
        node_cases,
        bun_cases,
        native_coverage_progression: vec![NativeCoveragePoint {
            recorded_at_utc: "2026-03-01T00:00:00Z".to_string(),
            native_slots: 80,
            total_slots: 100,
        }],
        replacement_lineage_ids: vec!["lineage-multi".to_string()],
    };

    let ctx = PublicationContext::new("t-multi", "d-multi", "p-multi");
    let decision = evaluate_publication_gate(&input, &ctx).expect("gate should succeed");
    let bundle = BenchmarkClaimBundle {
        trace_id: "t-multi".to_string(),
        decision_id: "d-multi".to_string(),
        policy_id: "p-multi".to_string(),
        input,
        claimed: ClaimedBenchmarkOutcome {
            score_vs_node: decision.score_vs_node,
            score_vs_bun: decision.score_vs_bun,
            publish_allowed: decision.publish_allowed,
            blockers: decision.blockers.clone(),
        },
    };
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
}

#[test]
fn enrichment_containment_all_fault_types_verify() {
    let fault_types = vec![
        FaultType::NetworkPartition,
        FaultType::ByzantineBehavior,
        FaultType::CascadingFailure,
        FaultType::ResourceExhaustion,
        FaultType::ClockSkew,
    ];
    for (i, ft) in fault_types.into_iter().enumerate() {
        let mut scenario = make_scenario(&format!("ft-{i}"), true, 100);
        scenario.fault_type = ft;
        let result = make_gate_result(vec![scenario]);
        let bundle = make_containment_bundle(result);
        let report = verify_containment_claim(&bundle);
        assert_eq!(
            report.verdict,
            VerificationVerdict::Verified,
            "failed for fault type index {i}"
        );
    }
}

#[test]
fn enrichment_attestation_different_verdicts_produce_different_digests() {
    let verdicts = [
        VerificationVerdict::Verified,
        VerificationVerdict::Failed,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Inconclusive,
    ];
    let mut digests = Vec::new();
    for v in &verdicts {
        let a = generate_attestation(&make_attestation_input(make_report(*v), None)).unwrap();
        digests.push(a.report_digest_hex);
    }
    // All should be distinct since the report content differs
    let mut deduped = digests.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(digests.len(), deduped.len());
}

#[test]
fn enrichment_multiple_containment_failures_all_reflected_in_events() {
    let mut result = make_gate_result(vec![make_scenario("s1", true, 100_000)]);
    result.total_scenarios = 99; // mismatch count
    result.passed_scenarios = 77; // mismatch passed
    result.passed = false; // mismatch overall
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);

    let failure_events: Vec<_> = report
        .events
        .iter()
        .filter(|e| e.event.starts_with("check_failed:"))
        .collect();
    // Should have at least 3 failure events (count, passed, overall)
    assert!(
        failure_events.len() >= 3,
        "expected >= 3 failure events, got {}",
        failure_events.len()
    );
}
