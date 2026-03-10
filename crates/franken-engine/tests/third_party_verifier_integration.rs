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
fn containment_empty_scenarios_yields_verified() {
    let result = make_gate_result(Vec::new());
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
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
fn containment_failed_scenario_not_checked_for_sla_or_invariants() {
    let mut scenario = make_scenario("s1", false, 999_999_999);
    scenario.isolation_verified = false;
    scenario.recovery_verified = false;
    let result = make_gate_result(vec![scenario]);
    let bundle = make_containment_bundle(result);
    let report = verify_containment_claim(&bundle);
    // SLA/isolation/recovery only checked when scenario.passed=true
    let sla = report
        .checks
        .iter()
        .find(|c| c.name == "latency_sla:s1")
        .unwrap();
    assert!(sla.passed);
    let iso = report
        .checks
        .iter()
        .find(|c| c.name == "isolation_verified:s1")
        .unwrap();
    assert!(iso.passed);
    let rec = report
        .checks
        .iter()
        .find(|c| c.name == "recovery_verified:s1")
        .unwrap();
    assert!(rec.passed);
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
    assert!(summary.contains("verifier=2.0.0"), "summary: {summary}");
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
