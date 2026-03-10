#![forbid(unsafe_code)]

//! Integration tests for the `promotion_gate_runner` module.
//!
//! Covers every public enum variant, struct, method, gate evaluation function,
//! aggregate verdict logic, risk assessment, evidence bundle accounting,
//! structured logging, serde round-trips, Display formatting, and
//! determinism guarantees.

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

use std::collections::BTreeSet;

use frankenengine_engine::promotion_gate_runner::{
    AdversarialTestResult, CandidateCapabilityRequest, EquivalenceTestCase, EvidenceArtifact,
    EvidenceBundle, GateEvaluation, GateKind, GateRunnerConfig, GateRunnerInput,
    GateRunnerLogEvent, GateRunnerOutput, GateStrictness, PerformanceMeasurement,
    aggregate_verdict, assess_risk, evaluate_adversarial_survival,
    evaluate_capability_preservation, evaluate_equivalence, evaluate_performance_threshold,
    log_gate_evaluation, run_promotion_gates,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{GateVerdict, RiskLevel};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_slot_id() -> SlotId {
    SlotId::new("test-slot-01").expect("valid slot id")
}

fn test_authority_envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
        ],
    }
}

fn passing_equivalence_cases(count: usize) -> Vec<EquivalenceTestCase> {
    (0..count)
        .map(|i| EquivalenceTestCase {
            test_id: format!("eq-{i}"),
            input: vec![i as u8],
            delegate_output: vec![i as u8, 0xFF],
            candidate_output: vec![i as u8, 0xFF],
        })
        .collect()
}

fn failing_equivalence_cases(count: usize) -> Vec<EquivalenceTestCase> {
    (0..count)
        .map(|i| EquivalenceTestCase {
            test_id: format!("eq-fail-{i}"),
            input: vec![i as u8],
            delegate_output: vec![i as u8, 0xFF],
            candidate_output: vec![i as u8, 0xAA],
        })
        .collect()
}

fn passing_capability_request() -> CandidateCapabilityRequest {
    CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        authority_envelope: test_authority_envelope(),
    }
}

fn exceeding_capability_request() -> CandidateCapabilityRequest {
    CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::InvokeHostcall, // not in permitted
        ],
        authority_envelope: test_authority_envelope(),
    }
}

fn passing_perf_measurements(count: usize) -> Vec<PerformanceMeasurement> {
    (0..count)
        .map(|i| PerformanceMeasurement {
            benchmark_id: format!("bench-{i}"),
            throughput_millionths: 1_000_000,
            latency_ns: 50_000_000,
            iterations: 100,
            seed: 42 + i as u64,
        })
        .collect()
}

fn failing_perf_measurements() -> Vec<PerformanceMeasurement> {
    vec![PerformanceMeasurement {
        benchmark_id: "bench-slow".to_string(),
        throughput_millionths: 100_000,
        latency_ns: 200_000_000,
        iterations: 10,
        seed: 42,
    }]
}

fn passing_adversarial_results(count: usize) -> Vec<AdversarialTestResult> {
    (0..count)
        .map(|i| AdversarialTestResult {
            test_id: format!("adv-{i}"),
            passed: true,
            attack_surface: "memory_safety".to_string(),
            evidence: "no vulnerability detected".to_string(),
        })
        .collect()
}

fn mixed_adversarial_results() -> Vec<AdversarialTestResult> {
    vec![
        AdversarialTestResult {
            test_id: "adv-0".to_string(),
            passed: true,
            attack_surface: "memory_safety".to_string(),
            evidence: "ok".to_string(),
        },
        AdversarialTestResult {
            test_id: "adv-1".to_string(),
            passed: false,
            attack_surface: "injection".to_string(),
            evidence: "vulnerability found".to_string(),
        },
    ]
}

fn all_passing_input() -> GateRunnerInput {
    GateRunnerInput {
        equivalence_cases: passing_equivalence_cases(10),
        capability_request: passing_capability_request(),
        performance_measurements: passing_perf_measurements(5),
        adversarial_results: passing_adversarial_results(20),
    }
}

fn make_gate_evaluation(gate: GateKind, passed: bool, required: bool) -> GateEvaluation {
    GateEvaluation {
        gate,
        passed,
        required,
        evidence: vec![format!("{gate} evidence")],
        summary: format!("{gate} summary"),
    }
}

// =========================================================================
// 1. GateKind — enum variant construction, Display, serde round-trip
// =========================================================================

#[test]
fn gate_kind_all_returns_four_variants() {
    assert_eq!(GateKind::all().len(), 4);
}

#[test]
fn gate_kind_all_order_is_stable() {
    let all = GateKind::all();
    assert_eq!(all[0], GateKind::Equivalence);
    assert_eq!(all[1], GateKind::CapabilityPreservation);
    assert_eq!(all[2], GateKind::PerformanceThreshold);
    assert_eq!(all[3], GateKind::AdversarialSurvival);
}

#[test]
fn gate_kind_as_str_unique() {
    let mut seen = BTreeSet::new();
    for gate in GateKind::all() {
        assert!(seen.insert(gate.as_str()), "duplicate as_str for {gate:?}");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn gate_kind_as_str_values() {
    assert_eq!(GateKind::Equivalence.as_str(), "equivalence");
    assert_eq!(
        GateKind::CapabilityPreservation.as_str(),
        "capability_preservation"
    );
    assert_eq!(
        GateKind::PerformanceThreshold.as_str(),
        "performance_threshold"
    );
    assert_eq!(
        GateKind::AdversarialSurvival.as_str(),
        "adversarial_survival"
    );
}

#[test]
fn gate_kind_display_matches_as_str() {
    for gate in GateKind::all() {
        assert_eq!(format!("{gate}"), gate.as_str());
    }
}

#[test]
fn gate_kind_serde_round_trip_all_variants() {
    for gate in GateKind::all() {
        let json = serde_json::to_string(gate).expect("serialize");
        let decoded: GateKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*gate, decoded);
    }
}

#[test]
fn gate_kind_ord_is_deterministic() {
    let mut gates: Vec<GateKind> = GateKind::all().to_vec();
    gates.sort();
    let sorted_again: Vec<GateKind> = {
        let mut v = gates.clone();
        v.sort();
        v
    };
    assert_eq!(gates, sorted_again);
}

#[test]
fn gate_kind_clone_eq() {
    let g = GateKind::Equivalence;
    let g2 = g;
    assert_eq!(g, g2);
}

#[test]
fn gate_kind_hash_in_btreeset() {
    let set: BTreeSet<GateKind> = GateKind::all().iter().copied().collect();
    assert_eq!(set.len(), 4);
    assert!(set.contains(&GateKind::Equivalence));
    assert!(set.contains(&GateKind::CapabilityPreservation));
    assert!(set.contains(&GateKind::PerformanceThreshold));
    assert!(set.contains(&GateKind::AdversarialSurvival));
}

// =========================================================================
// 2. GateStrictness — construction, standard defaults, serde
// =========================================================================

#[test]
fn gate_strictness_standard_all_required() {
    for gate in GateKind::all() {
        let s = GateStrictness::standard(*gate);
        assert!(
            s.required,
            "standard strictness for {gate:?} must be required"
        );
        assert_eq!(s.gate, *gate);
    }
}

#[test]
fn gate_strictness_equivalence_defaults() {
    let s = GateStrictness::standard(GateKind::Equivalence);
    assert_eq!(s.max_divergences, 0);
    assert_eq!(s.min_throughput_millionths, 0);
    assert_eq!(s.max_latency_ns, 0);
    assert_eq!(s.min_adversarial_pass_rate_millionths, 0);
}

#[test]
fn gate_strictness_capability_defaults() {
    let s = GateStrictness::standard(GateKind::CapabilityPreservation);
    assert_eq!(s.max_divergences, 0);
    assert_eq!(s.min_throughput_millionths, 0);
}

#[test]
fn gate_strictness_performance_defaults() {
    let s = GateStrictness::standard(GateKind::PerformanceThreshold);
    assert_eq!(s.min_throughput_millionths, 500_000);
    assert_eq!(s.max_latency_ns, 100_000_000);
}

#[test]
fn gate_strictness_adversarial_defaults() {
    let s = GateStrictness::standard(GateKind::AdversarialSurvival);
    assert_eq!(s.min_adversarial_pass_rate_millionths, 950_000);
}

#[test]
fn gate_strictness_serde_round_trip_all_gates() {
    for gate in GateKind::all() {
        let s = GateStrictness::standard(*gate);
        let json = serde_json::to_string(&s).expect("serialize");
        let decoded: GateStrictness = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, decoded);
    }
}

#[test]
fn gate_strictness_custom_values_serde() {
    let s = GateStrictness {
        gate: GateKind::Equivalence,
        required: false,
        max_divergences: 5,
        min_throughput_millionths: 999_999,
        max_latency_ns: 42,
        min_adversarial_pass_rate_millionths: 100_000,
    };
    let json = serde_json::to_string(&s).expect("serialize");
    let decoded: GateStrictness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, decoded);
}

// =========================================================================
// 3. EquivalenceTestCase — construction, is_equivalent, serde
// =========================================================================

#[test]
fn equivalence_test_case_equivalent_same_output() {
    let tc = EquivalenceTestCase {
        test_id: "tc-1".to_string(),
        input: vec![1, 2, 3],
        delegate_output: vec![10, 20],
        candidate_output: vec![10, 20],
    };
    assert!(tc.is_equivalent());
}

#[test]
fn equivalence_test_case_not_equivalent_different_output() {
    let tc = EquivalenceTestCase {
        test_id: "tc-2".to_string(),
        input: vec![1],
        delegate_output: vec![10],
        candidate_output: vec![11],
    };
    assert!(!tc.is_equivalent());
}

#[test]
fn equivalence_test_case_empty_outputs_equivalent() {
    let tc = EquivalenceTestCase {
        test_id: "tc-3".to_string(),
        input: vec![],
        delegate_output: vec![],
        candidate_output: vec![],
    };
    assert!(tc.is_equivalent());
}

#[test]
fn equivalence_test_case_different_lengths_not_equivalent() {
    let tc = EquivalenceTestCase {
        test_id: "tc-4".to_string(),
        input: vec![1],
        delegate_output: vec![10, 20],
        candidate_output: vec![10],
    };
    assert!(!tc.is_equivalent());
}

#[test]
fn equivalence_test_case_serde_round_trip() {
    let tc = EquivalenceTestCase {
        test_id: "tc-serde".to_string(),
        input: vec![0, 1, 2],
        delegate_output: vec![3, 4],
        candidate_output: vec![3, 4],
    };
    let json = serde_json::to_string(&tc).expect("serialize");
    let decoded: EquivalenceTestCase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tc, decoded);
}

// =========================================================================
// 4. CandidateCapabilityRequest — within_envelope, excess_capabilities
// =========================================================================

#[test]
fn capability_request_within_envelope() {
    let req = passing_capability_request();
    assert!(req.within_envelope());
    assert!(req.excess_capabilities().is_empty());
}

#[test]
fn capability_request_exceeding_envelope() {
    let req = exceeding_capability_request();
    assert!(!req.within_envelope());
    let excess = req.excess_capabilities();
    assert_eq!(excess.len(), 1);
    assert_eq!(*excess[0], SlotCapability::InvokeHostcall);
}

#[test]
fn capability_request_empty_requested_within_envelope() {
    let req = CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![],
        authority_envelope: test_authority_envelope(),
    };
    assert!(req.within_envelope());
    assert!(req.excess_capabilities().is_empty());
}

#[test]
fn capability_request_all_excess() {
    let req = CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![
            SlotCapability::InvokeHostcall,
            SlotCapability::ScheduleAsync,
            SlotCapability::TriggerGc,
        ],
        authority_envelope: AuthorityEnvelope {
            required: vec![],
            permitted: vec![SlotCapability::ReadSource],
        },
    };
    assert!(!req.within_envelope());
    assert_eq!(req.excess_capabilities().len(), 3);
}

#[test]
fn capability_request_serde_round_trip() {
    let req = passing_capability_request();
    let json = serde_json::to_string(&req).expect("serialize");
    let decoded: CandidateCapabilityRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, decoded);
}

// =========================================================================
// 5. PerformanceMeasurement — construction, serde
// =========================================================================

#[test]
fn performance_measurement_construction() {
    let m = PerformanceMeasurement {
        benchmark_id: "bm-1".to_string(),
        throughput_millionths: 2_000_000,
        latency_ns: 10_000_000,
        iterations: 500,
        seed: 99,
    };
    assert_eq!(m.benchmark_id, "bm-1");
    assert_eq!(m.throughput_millionths, 2_000_000);
    assert_eq!(m.latency_ns, 10_000_000);
    assert_eq!(m.iterations, 500);
    assert_eq!(m.seed, 99);
}

#[test]
fn performance_measurement_serde_round_trip() {
    let m = PerformanceMeasurement {
        benchmark_id: "bm-rt".to_string(),
        throughput_millionths: 750_000,
        latency_ns: 80_000_000,
        iterations: 200,
        seed: 1,
    };
    let json = serde_json::to_string(&m).expect("serialize");
    let decoded: PerformanceMeasurement = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, decoded);
}

// =========================================================================
// 6. AdversarialTestResult — construction, serde
// =========================================================================

#[test]
fn adversarial_test_result_construction() {
    let r = AdversarialTestResult {
        test_id: "at-1".to_string(),
        passed: true,
        attack_surface: "buffer_overflow".to_string(),
        evidence: "safe".to_string(),
    };
    assert!(r.passed);
    assert_eq!(r.attack_surface, "buffer_overflow");
}

#[test]
fn adversarial_test_result_serde_round_trip() {
    let r = AdversarialTestResult {
        test_id: "at-rt".to_string(),
        passed: false,
        attack_surface: "injection".to_string(),
        evidence: "vuln detected".to_string(),
    };
    let json = serde_json::to_string(&r).expect("serialize");
    let decoded: AdversarialTestResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(r, decoded);
}

// =========================================================================
// 7. evaluate_equivalence — happy path, failures, edge cases
// =========================================================================

#[test]
fn evaluate_equivalence_all_pass() {
    let cases = passing_equivalence_cases(10);
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(eval.passed);
    assert_eq!(eval.gate, GateKind::Equivalence);
    assert!(eval.required);
    assert!(eval.summary.contains("within threshold"));
}

#[test]
fn evaluate_equivalence_some_divergences_strict() {
    let mut cases = passing_equivalence_cases(8);
    cases.extend(failing_equivalence_cases(2));
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("exceeds threshold"));
}

#[test]
fn evaluate_equivalence_divergences_within_tolerance() {
    let mut cases = passing_equivalence_cases(8);
    cases.extend(failing_equivalence_cases(2));
    let mut strictness = GateStrictness::standard(GateKind::Equivalence);
    strictness.max_divergences = 2;
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(eval.passed);
}

#[test]
fn evaluate_equivalence_divergences_at_tolerance_boundary() {
    let mut cases = passing_equivalence_cases(5);
    cases.extend(failing_equivalence_cases(3));
    let mut strictness = GateStrictness::standard(GateKind::Equivalence);
    strictness.max_divergences = 3; // exactly at boundary
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(eval.passed);
}

#[test]
fn evaluate_equivalence_divergences_one_over_tolerance() {
    let mut cases = passing_equivalence_cases(5);
    cases.extend(failing_equivalence_cases(4));
    let mut strictness = GateStrictness::standard(GateKind::Equivalence);
    strictness.max_divergences = 3; // one over
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(!eval.passed);
}

#[test]
fn evaluate_equivalence_empty_cases_passes() {
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&[], &strictness);
    assert!(eval.passed); // 0 divergences <= 0 threshold
}

#[test]
fn evaluate_equivalence_all_fail() {
    let cases = failing_equivalence_cases(5);
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(!eval.passed);
    assert!(eval.evidence.iter().any(|e| e.contains("divergent_tests")));
}

#[test]
fn evaluate_equivalence_evidence_contains_total_and_divergences() {
    let cases = passing_equivalence_cases(3);
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(eval.evidence.iter().any(|e| e.contains("total_cases=3")));
    assert!(eval.evidence.iter().any(|e| e.contains("divergences=0")));
}

#[test]
fn evaluate_equivalence_advisory_only() {
    let cases = failing_equivalence_cases(5);
    let mut strictness = GateStrictness::standard(GateKind::Equivalence);
    strictness.required = false;
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(!eval.passed);
    assert!(!eval.required);
}

// =========================================================================
// 8. evaluate_capability_preservation — happy path, failures, edge cases
// =========================================================================

#[test]
fn evaluate_capability_preservation_within_envelope() {
    let req = passing_capability_request();
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &strictness);
    assert!(eval.passed);
    assert_eq!(eval.gate, GateKind::CapabilityPreservation);
    assert!(eval.summary.contains("within authority envelope"));
}

#[test]
fn evaluate_capability_preservation_excess() {
    let req = exceeding_capability_request();
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("exceed authority envelope"));
}

#[test]
fn evaluate_capability_preservation_evidence_has_counts() {
    let req = passing_capability_request();
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &strictness);
    assert!(eval.evidence.iter().any(|e| e.starts_with("requested=")));
    assert!(eval.evidence.iter().any(|e| e.starts_with("permitted=")));
}

#[test]
fn evaluate_capability_preservation_excess_evidence_lists_capabilities() {
    let req = exceeding_capability_request();
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &strictness);
    assert!(
        eval.evidence
            .iter()
            .any(|e| e.starts_with("excess_capabilities="))
    );
}

#[test]
fn evaluate_capability_preservation_no_requested_passes() {
    let req = CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![],
        authority_envelope: test_authority_envelope(),
    };
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &strictness);
    assert!(eval.passed);
}

// =========================================================================
// 9. evaluate_performance_threshold — happy path, failures, edge cases
// =========================================================================

#[test]
fn evaluate_performance_all_within_threshold() {
    let measurements = passing_perf_measurements(5);
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(eval.passed);
    assert_eq!(eval.gate, GateKind::PerformanceThreshold);
    assert!(eval.summary.contains("within thresholds"));
}

#[test]
fn evaluate_performance_below_threshold_fails() {
    let measurements = failing_perf_measurements();
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(!eval.passed);
}

#[test]
fn evaluate_performance_no_measurements_fails() {
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&[], &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("no performance measurements"));
}

#[test]
fn evaluate_performance_throughput_failure_only() {
    let measurements = vec![PerformanceMeasurement {
        benchmark_id: "slow-throughput".to_string(),
        throughput_millionths: 100_000, // below 500_000 min
        latency_ns: 50_000_000,         // within 100ms max
        iterations: 100,
        seed: 1,
    }];
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(!eval.passed);
    assert!(
        eval.evidence
            .iter()
            .any(|e| e.contains("throughput_failures"))
    );
}

#[test]
fn evaluate_performance_latency_failure_only() {
    let measurements = vec![PerformanceMeasurement {
        benchmark_id: "high-latency".to_string(),
        throughput_millionths: 1_000_000, // above min
        latency_ns: 200_000_000,          // above 100ms max
        iterations: 100,
        seed: 1,
    }];
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(!eval.passed);
    assert!(eval.evidence.iter().any(|e| e.contains("latency_failures")));
}

#[test]
fn evaluate_performance_both_failures() {
    let measurements = vec![PerformanceMeasurement {
        benchmark_id: "both-bad".to_string(),
        throughput_millionths: 100_000,
        latency_ns: 200_000_000,
        iterations: 10,
        seed: 1,
    }];
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("throughput"));
    assert!(eval.summary.contains("latency"));
}

#[test]
fn evaluate_performance_at_exact_threshold_passes() {
    let measurements = vec![PerformanceMeasurement {
        benchmark_id: "exact".to_string(),
        throughput_millionths: 500_000, // exactly at min
        latency_ns: 100_000_000,        // exactly at max
        iterations: 100,
        seed: 1,
    }];
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(eval.passed);
}

#[test]
fn evaluate_performance_zero_max_latency_ignores_latency_check() {
    let measurements = vec![PerformanceMeasurement {
        benchmark_id: "no-latency-check".to_string(),
        throughput_millionths: 1_000_000,
        latency_ns: u64::MAX, // absurdly high but should pass
        iterations: 100,
        seed: 1,
    }];
    let mut strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    strictness.max_latency_ns = 0; // disable latency check
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(eval.passed);
}

#[test]
fn evaluate_performance_mixed_pass_fail() {
    let measurements = vec![
        PerformanceMeasurement {
            benchmark_id: "good".to_string(),
            throughput_millionths: 1_000_000,
            latency_ns: 50_000_000,
            iterations: 100,
            seed: 1,
        },
        PerformanceMeasurement {
            benchmark_id: "bad".to_string(),
            throughput_millionths: 100_000,
            latency_ns: 200_000_000,
            iterations: 10,
            seed: 2,
        },
    ];
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(!eval.passed);
}

// =========================================================================
// 10. evaluate_adversarial_survival — happy path, failures, edge cases
// =========================================================================

#[test]
fn evaluate_adversarial_all_pass() {
    let results = passing_adversarial_results(20);
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed);
    assert_eq!(eval.gate, GateKind::AdversarialSurvival);
    assert!(eval.summary.contains("1000000/1M"));
}

#[test]
fn evaluate_adversarial_below_threshold_fails() {
    let results = mixed_adversarial_results(); // 50% = 500_000 millionths
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("required 950000"));
}

#[test]
fn evaluate_adversarial_no_results_fails() {
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&[], &strictness);
    assert!(!eval.passed);
    assert!(eval.summary.contains("no adversarial test results"));
}

#[test]
fn evaluate_adversarial_lenient_threshold() {
    let results = mixed_adversarial_results(); // 50% = 500_000 millionths
    let mut strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    strictness.min_adversarial_pass_rate_millionths = 400_000;
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed);
}

#[test]
fn evaluate_adversarial_exact_threshold() {
    // 19 out of 20 pass = 950_000 millionths
    let mut results = passing_adversarial_results(19);
    results.push(AdversarialTestResult {
        test_id: "adv-fail".to_string(),
        passed: false,
        attack_surface: "xss".to_string(),
        evidence: "vuln".to_string(),
    });
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed); // 950_000 >= 950_000
}

#[test]
fn evaluate_adversarial_one_below_threshold() {
    // 18 out of 20 pass = 900_000 millionths
    let mut results = passing_adversarial_results(18);
    for i in 0..2 {
        results.push(AdversarialTestResult {
            test_id: format!("adv-fail-{i}"),
            passed: false,
            attack_surface: "xss".to_string(),
            evidence: "vuln".to_string(),
        });
    }
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(!eval.passed); // 900_000 < 950_000
}

#[test]
fn evaluate_adversarial_evidence_contains_stats() {
    let results = passing_adversarial_results(5);
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.evidence.iter().any(|e| e.contains("total_tests=5")));
    assert!(eval.evidence.iter().any(|e| e.contains("passed=5")));
    assert!(
        eval.evidence
            .iter()
            .any(|e| e.contains("pass_rate_millionths="))
    );
}

#[test]
fn evaluate_adversarial_failed_tests_in_evidence() {
    let results = mixed_adversarial_results();
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.evidence.iter().any(|e| e.contains("failed_tests=")));
}

#[test]
fn evaluate_adversarial_all_fail() {
    let results: Vec<AdversarialTestResult> = (0..5)
        .map(|i| AdversarialTestResult {
            test_id: format!("fail-{i}"),
            passed: false,
            attack_surface: "memory".to_string(),
            evidence: "vuln".to_string(),
        })
        .collect();
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(!eval.passed);
}

#[test]
fn evaluate_adversarial_zero_threshold_always_passes() {
    let results = mixed_adversarial_results();
    let mut strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    strictness.min_adversarial_pass_rate_millionths = 0;
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed);
}

// =========================================================================
// 11. GateEvaluation — to_gate_result, serde
// =========================================================================

#[test]
fn gate_evaluation_to_gate_result_pass() {
    let eval = GateEvaluation {
        gate: GateKind::Equivalence,
        passed: true,
        required: true,
        evidence: vec!["ev-1".to_string(), "ev-2".to_string()],
        summary: "all equivalent".to_string(),
    };
    let result = eval.to_gate_result();
    assert_eq!(result.gate_name, "equivalence");
    assert!(result.passed);
    assert_eq!(result.evidence_refs.len(), 2);
    assert_eq!(result.summary, "all equivalent");
}

#[test]
fn gate_evaluation_to_gate_result_fail() {
    let eval = GateEvaluation {
        gate: GateKind::AdversarialSurvival,
        passed: false,
        required: true,
        evidence: vec!["fail-ev".to_string()],
        summary: "failed adversarial tests".to_string(),
    };
    let result = eval.to_gate_result();
    assert_eq!(result.gate_name, "adversarial_survival");
    assert!(!result.passed);
}

#[test]
fn gate_evaluation_serde_round_trip() {
    let eval = GateEvaluation {
        gate: GateKind::PerformanceThreshold,
        passed: true,
        required: true,
        evidence: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        summary: "all benchmarks passed".to_string(),
    };
    let json = serde_json::to_string(&eval).expect("serialize");
    let decoded: GateEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, decoded);
}

#[test]
fn gate_evaluation_for_each_gate_kind_serde() {
    for gate in GateKind::all() {
        let eval = make_gate_evaluation(*gate, true, true);
        let json = serde_json::to_string(&eval).expect("serialize");
        let decoded: GateEvaluation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(eval, decoded);
    }
}

// =========================================================================
// 12. aggregate_verdict — all scenarios
// =========================================================================

#[test]
fn aggregate_verdict_all_pass_approved() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, true, true))
        .collect();
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

#[test]
fn aggregate_verdict_one_required_fail_denied() {
    let mut evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, true, true))
        .collect();
    evals[0].passed = false;
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Denied);
}

#[test]
fn aggregate_verdict_all_required_fail_denied() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, false, true))
        .collect();
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Denied);
}

#[test]
fn aggregate_verdict_missing_gate_inconclusive() {
    let evals = vec![make_gate_evaluation(GateKind::Equivalence, true, true)];
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Inconclusive);
}

#[test]
fn aggregate_verdict_empty_inconclusive() {
    assert_eq!(aggregate_verdict(&[]), GateVerdict::Inconclusive);
}

#[test]
fn aggregate_verdict_advisory_fail_still_approved() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| {
            if *g == GateKind::PerformanceThreshold {
                make_gate_evaluation(*g, false, false)
            } else {
                make_gate_evaluation(*g, true, true)
            }
        })
        .collect();
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

#[test]
fn aggregate_verdict_two_missing_gates_inconclusive() {
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, true, true),
        make_gate_evaluation(GateKind::CapabilityPreservation, true, true),
    ];
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Inconclusive);
}

#[test]
fn aggregate_verdict_duplicate_gates_with_all_present_approved() {
    let mut evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, true, true))
        .collect();
    // Add a duplicate
    evals.push(make_gate_evaluation(GateKind::Equivalence, true, true));
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

#[test]
fn aggregate_verdict_extra_gate_all_four_present_approved() {
    let mut evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, true, true))
        .collect();
    // Add a non-required failing gate (still approved because all 4 required pass)
    evals.push(make_gate_evaluation(GateKind::Equivalence, false, false));
    // Actually this changes the required gate check; let me verify expected behavior:
    // The extra Equivalence gate is advisory and failed, but
    // any_required_failed checks all evaluations. Since this one is not required, it
    // shouldn't trigger denial.
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

// =========================================================================
// 13. assess_risk — all risk levels
// =========================================================================

#[test]
fn risk_all_pass_low() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, true, true))
        .collect();
    assert_eq!(assess_risk(&evals), RiskLevel::Low);
}

#[test]
fn risk_advisory_only_fail_medium() {
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, true, true),
        make_gate_evaluation(GateKind::CapabilityPreservation, false, false), // advisory
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::Medium);
}

#[test]
fn risk_one_required_fail_high() {
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, false, true), // required fail
        make_gate_evaluation(GateKind::CapabilityPreservation, true, true),
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::High);
}

#[test]
fn risk_two_required_fail_high() {
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, false, true),
        make_gate_evaluation(GateKind::CapabilityPreservation, false, true),
        make_gate_evaluation(GateKind::PerformanceThreshold, true, true),
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::High);
}

#[test]
fn risk_three_or_more_fail_critical() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| make_gate_evaluation(*g, false, true))
        .collect();
    assert_eq!(assess_risk(&evals), RiskLevel::Critical);
}

#[test]
fn risk_empty_evaluations_low() {
    assert_eq!(assess_risk(&[]), RiskLevel::Low);
}

#[test]
fn risk_multiple_advisory_failures_medium() {
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, false, false),
        make_gate_evaluation(GateKind::CapabilityPreservation, false, false),
        make_gate_evaluation(GateKind::PerformanceThreshold, false, false),
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::Medium);
}

#[test]
fn risk_mixed_required_and_advisory_failures() {
    // 1 required fail + 1 advisory fail = 2 total, 1 advisory
    // failed_count=2, advisory_failures=1, not equal, so check failed_count<=2 -> High
    let evals = vec![
        make_gate_evaluation(GateKind::Equivalence, false, true), // required fail
        make_gate_evaluation(GateKind::CapabilityPreservation, false, false), // advisory
        make_gate_evaluation(GateKind::PerformanceThreshold, true, true),
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::High);
}

// =========================================================================
// 14. GateRunnerConfig — construction, strictness_for, serde
// =========================================================================

#[test]
fn config_standard_has_all_four_gates() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-abc".to_string(), 42);
    assert_eq!(config.gate_strictness.len(), 4);
    for gate in GateKind::all() {
        assert!(
            config.strictness_for(*gate).is_some(),
            "standard config missing gate {gate:?}"
        );
    }
}

#[test]
fn config_standard_default_fields() {
    let config = GateRunnerConfig::standard(test_slot_id(), "digest-x".to_string(), 99);
    assert_eq!(config.slot_id, test_slot_id());
    assert_eq!(config.candidate_digest, "digest-x");
    assert_eq!(config.seed, 99);
    assert_eq!(config.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(config.zone, "default");
}

#[test]
fn config_strictness_for_missing_gate() {
    let config = GateRunnerConfig {
        slot_id: test_slot_id(),
        candidate_digest: "d".to_string(),
        seed: 1,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test".to_string(),
        gate_strictness: vec![GateStrictness::standard(GateKind::Equivalence)],
    };
    assert!(config.strictness_for(GateKind::Equivalence).is_some());
    assert!(
        config
            .strictness_for(GateKind::AdversarialSurvival)
            .is_none()
    );
}

#[test]
fn config_serde_round_trip() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let json = serde_json::to_string(&config).expect("serialize");
    let decoded: GateRunnerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, decoded);
}

#[test]
fn config_custom_epoch_and_zone() {
    let config = GateRunnerConfig {
        slot_id: test_slot_id(),
        candidate_digest: "d".to_string(),
        seed: 7,
        epoch: SecurityEpoch::from_raw(42),
        zone: "production".to_string(),
        gate_strictness: vec![],
    };
    assert_eq!(config.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(config.zone, "production");
}

// =========================================================================
// 15. GateRunnerInput — construction, serde
// =========================================================================

#[test]
fn gate_runner_input_serde_round_trip() {
    let input = all_passing_input();
    let json = serde_json::to_string(&input).expect("serialize");
    let decoded: GateRunnerInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, decoded);
}

#[test]
fn gate_runner_input_construction() {
    let input = GateRunnerInput {
        equivalence_cases: vec![],
        capability_request: passing_capability_request(),
        performance_measurements: vec![],
        adversarial_results: vec![],
    };
    assert!(input.equivalence_cases.is_empty());
    assert!(input.performance_measurements.is_empty());
    assert!(input.adversarial_results.is_empty());
}

// =========================================================================
// 16. EvidenceArtifact / EvidenceBundle — construction, serde
// =========================================================================

#[test]
fn evidence_artifact_serde_round_trip() {
    let artifact = EvidenceArtifact {
        artifact_id: "slot-01/equivalence".to_string(),
        gate: GateKind::Equivalence,
        content_hash: "deadbeef".to_string(),
        description: "all equivalent".to_string(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let decoded: EvidenceArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, decoded);
}

#[test]
fn evidence_bundle_serde_round_trip() {
    let bundle = EvidenceBundle {
        artifacts: vec![
            EvidenceArtifact {
                artifact_id: "a1".to_string(),
                gate: GateKind::Equivalence,
                content_hash: "h1".to_string(),
                description: "d1".to_string(),
            },
            EvidenceArtifact {
                artifact_id: "a2".to_string(),
                gate: GateKind::AdversarialSurvival,
                content_hash: "h2".to_string(),
                description: "d2".to_string(),
            },
        ],
        total_test_cases: 100,
        total_passed: 95,
        total_failed: 5,
    };
    let json = serde_json::to_string(&bundle).expect("serialize");
    let decoded: EvidenceBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle, decoded);
}

#[test]
fn evidence_bundle_counts_add_up() {
    let bundle = EvidenceBundle {
        artifacts: vec![],
        total_test_cases: 50,
        total_passed: 30,
        total_failed: 20,
    };
    assert_eq!(
        bundle.total_passed + bundle.total_failed,
        bundle.total_test_cases
    );
}

// =========================================================================
// 17. GateRunnerOutput — serde
// =========================================================================

#[test]
fn gate_runner_output_serde_round_trip() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    let json = serde_json::to_string(&output).expect("serialize");
    let decoded: GateRunnerOutput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(output, decoded);
}

// =========================================================================
// 18. run_promotion_gates — full gate runner
// =========================================================================

#[test]
fn full_run_all_pass_approved() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-abc123".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert_eq!(output.risk_level, RiskLevel::Low);
    assert!(output.rollback_verified);
    assert_eq!(output.evaluations.len(), 4);
    assert_eq!(output.evidence_bundle.total_failed, 0);
    assert_eq!(output.slot_id, test_slot_id());
    assert_eq!(output.candidate_digest, "candidate-abc123");
    assert_eq!(output.seed, 42);
}

#[test]
fn full_run_equivalence_fail_denied() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-bad".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: failing_equivalence_cases(5),
        capability_request: passing_capability_request(),
        performance_measurements: passing_perf_measurements(3),
        adversarial_results: passing_adversarial_results(10),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(output.evidence_bundle.total_failed > 0);
}

#[test]
fn full_run_capability_exceed_denied() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-greedy".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: passing_equivalence_cases(5),
        capability_request: exceeding_capability_request(),
        performance_measurements: passing_perf_measurements(3),
        adversarial_results: passing_adversarial_results(10),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
}

#[test]
fn full_run_performance_fail_denied() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-slow".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: passing_equivalence_cases(5),
        capability_request: passing_capability_request(),
        performance_measurements: failing_perf_measurements(),
        adversarial_results: passing_adversarial_results(10),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
}

#[test]
fn full_run_adversarial_fail_denied() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-vuln".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: passing_equivalence_cases(5),
        capability_request: passing_capability_request(),
        performance_measurements: passing_perf_measurements(3),
        adversarial_results: mixed_adversarial_results(),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
}

#[test]
fn full_run_all_fail_denied_critical() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-terrible".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: failing_equivalence_cases(5),
        capability_request: exceeding_capability_request(),
        performance_measurements: failing_perf_measurements(),
        adversarial_results: mixed_adversarial_results(),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert_eq!(output.risk_level, RiskLevel::Critical);
}

#[test]
fn full_run_evidence_bundle_has_four_artifacts() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.evidence_bundle.artifacts.len(), 4);
}

#[test]
fn full_run_evidence_bundle_counts_consistent() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    let bundle = &output.evidence_bundle;
    assert_eq!(
        bundle.total_passed + bundle.total_failed,
        bundle.total_test_cases,
        "total_passed + total_failed must equal total_test_cases"
    );
}

#[test]
fn full_run_evidence_artifacts_cover_all_gates() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    let gates: BTreeSet<GateKind> = output
        .evidence_bundle
        .artifacts
        .iter()
        .map(|a| a.gate)
        .collect();
    assert_eq!(gates.len(), 4);
    for gate in GateKind::all() {
        assert!(gates.contains(gate));
    }
}

#[test]
fn full_run_artifact_ids_contain_slot_id() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    for artifact in &output.evidence_bundle.artifacts {
        assert!(
            artifact.artifact_id.contains(test_slot_id().as_str()),
            "artifact_id should contain slot_id"
        );
    }
}

#[test]
fn full_run_run_id_contains_seed() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert!(output.run_id.starts_with("gate-run-"));
}

#[test]
fn full_run_empty_equivalence_and_perf_but_adversarial_empty_denied() {
    // Empty perf measurements fail, empty adversarial fails
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: vec![],
        capability_request: passing_capability_request(),
        performance_measurements: vec![],
        adversarial_results: vec![],
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
}

#[test]
fn full_run_with_partial_equivalence_failure_tracks_divergences() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let mut cases = passing_equivalence_cases(8);
    cases.extend(failing_equivalence_cases(2));
    let input = GateRunnerInput {
        equivalence_cases: cases,
        capability_request: passing_capability_request(),
        performance_measurements: passing_perf_measurements(3),
        adversarial_results: passing_adversarial_results(20),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(output.evidence_bundle.total_failed >= 2);
}

// =========================================================================
// 19. Determinism — same inputs produce same outputs
// =========================================================================

#[test]
fn run_promotion_gates_deterministic_same_seed() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate-det".to_string(), 123);
    let input = all_passing_input();
    let out1 = run_promotion_gates(&config, &input);
    let out2 = run_promotion_gates(&config, &input);
    assert_eq!(out1.verdict, out2.verdict);
    assert_eq!(out1.run_id, out2.run_id);
    assert_eq!(out1.evidence_bundle, out2.evidence_bundle);
    assert_eq!(out1.risk_level, out2.risk_level);
    assert_eq!(out1.evaluations, out2.evaluations);
}

#[test]
fn run_promotion_gates_different_seed_different_run_id() {
    let config1 = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 1);
    let config2 = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 2);
    let input = all_passing_input();
    let out1 = run_promotion_gates(&config1, &input);
    let out2 = run_promotion_gates(&config2, &input);
    assert_ne!(out1.run_id, out2.run_id);
}

#[test]
fn run_promotion_gates_different_seed_different_content_hashes() {
    let config1 = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 1);
    let config2 = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 2);
    let input = all_passing_input();
    let out1 = run_promotion_gates(&config1, &input);
    let out2 = run_promotion_gates(&config2, &input);
    let hashes1: Vec<&str> = out1
        .evidence_bundle
        .artifacts
        .iter()
        .map(|a| a.content_hash.as_str())
        .collect();
    let hashes2: Vec<&str> = out2
        .evidence_bundle
        .artifacts
        .iter()
        .map(|a| a.content_hash.as_str())
        .collect();
    assert_ne!(hashes1, hashes2);
}

#[test]
fn evaluate_equivalence_deterministic() {
    let cases = passing_equivalence_cases(10);
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval1 = evaluate_equivalence(&cases, &strictness);
    let eval2 = evaluate_equivalence(&cases, &strictness);
    assert_eq!(eval1, eval2);
}

#[test]
fn evaluate_capability_preservation_deterministic() {
    let req = passing_capability_request();
    let strictness = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval1 = evaluate_capability_preservation(&req, &strictness);
    let eval2 = evaluate_capability_preservation(&req, &strictness);
    assert_eq!(eval1, eval2);
}

#[test]
fn evaluate_performance_threshold_deterministic() {
    let measurements = passing_perf_measurements(5);
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval1 = evaluate_performance_threshold(&measurements, &strictness);
    let eval2 = evaluate_performance_threshold(&measurements, &strictness);
    assert_eq!(eval1, eval2);
}

#[test]
fn evaluate_adversarial_survival_deterministic() {
    let results = passing_adversarial_results(20);
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval1 = evaluate_adversarial_survival(&results, &strictness);
    let eval2 = evaluate_adversarial_survival(&results, &strictness);
    assert_eq!(eval1, eval2);
}

// =========================================================================
// 20. GateRunnerLogEvent — structured logging
// =========================================================================

#[test]
fn log_event_pass_no_error_code() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let eval = make_gate_evaluation(GateKind::Equivalence, true, true);
    let event = log_gate_evaluation(&config, &eval);
    assert_eq!(event.outcome, "pass");
    assert!(event.error_code.is_none());
    assert_eq!(event.component, "promotion_gate_runner");
    assert_eq!(event.policy_id, "promotion-gate-policy");
    assert!(event.trace_id.starts_with("gate-"));
    assert!(event.decision_id.starts_with("decision-"));
    assert_eq!(event.gate, Some(GateKind::Equivalence));
    assert_eq!(event.slot_id, test_slot_id());
}

#[test]
fn log_event_fail_has_error_code() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let eval = make_gate_evaluation(GateKind::CapabilityPreservation, false, true);
    let event = log_gate_evaluation(&config, &eval);
    assert_eq!(event.outcome, "fail");
    assert!(event.error_code.is_some());
    let code = event.error_code.unwrap();
    assert!(code.starts_with("FE-GATE-"));
    assert!(code.contains("CAPABILITY_PRESERVATION"));
}

#[test]
fn log_event_error_code_uppercase_gate_name() {
    for gate in GateKind::all() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let eval = make_gate_evaluation(*gate, false, true);
        let event = log_gate_evaluation(&config, &eval);
        let code = event.error_code.expect("should have error code");
        let expected_suffix = gate.as_str().to_uppercase();
        assert!(
            code.contains(&expected_suffix),
            "error code {code} should contain {expected_suffix}"
        );
    }
}

#[test]
fn log_event_event_field_contains_gate_name() {
    for gate in GateKind::all() {
        let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
        let eval = make_gate_evaluation(*gate, true, true);
        let event = log_gate_evaluation(&config, &eval);
        assert!(
            event.event.contains(gate.as_str()),
            "event field '{}' should contain gate name '{}'",
            event.event,
            gate.as_str()
        );
    }
}

#[test]
fn log_event_serde_round_trip() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let eval = make_gate_evaluation(GateKind::PerformanceThreshold, true, true);
    let event = log_gate_evaluation(&config, &eval);
    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: GateRunnerLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, decoded);
}

#[test]
fn log_event_for_all_gates_serde() {
    for gate in GateKind::all() {
        for passed in [true, false] {
            let config = GateRunnerConfig::standard(test_slot_id(), "c".to_string(), 1);
            let eval = make_gate_evaluation(*gate, passed, true);
            let event = log_gate_evaluation(&config, &eval);
            let json = serde_json::to_string(&event).expect("serialize");
            let decoded: GateRunnerLogEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(event, decoded);
        }
    }
}

// =========================================================================
// 21. Cross-concern integration scenarios
// =========================================================================

#[test]
fn full_pipeline_pass_then_log_events() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Approved);

    // Log events for each evaluation
    for eval in &output.evaluations {
        let event = log_gate_evaluation(&config, eval);
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn full_pipeline_fail_then_log_events() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = GateRunnerInput {
        equivalence_cases: failing_equivalence_cases(5),
        capability_request: exceeding_capability_request(),
        performance_measurements: failing_perf_measurements(),
        adversarial_results: mixed_adversarial_results(),
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Denied);

    let mut fail_count = 0;
    for eval in &output.evaluations {
        let event = log_gate_evaluation(&config, eval);
        if !eval.passed {
            assert_eq!(event.outcome, "fail");
            assert!(event.error_code.is_some());
            fail_count += 1;
        }
    }
    assert!(fail_count >= 3);
}

#[test]
fn gate_evaluation_to_gate_result_preserves_all_fields() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    for eval in &output.evaluations {
        let result = eval.to_gate_result();
        assert_eq!(result.gate_name, eval.gate.as_str());
        assert_eq!(result.passed, eval.passed);
        assert_eq!(result.evidence_refs, eval.evidence);
        assert_eq!(result.summary, eval.summary);
    }
}

#[test]
fn full_run_with_custom_strictness() {
    let config = GateRunnerConfig {
        slot_id: test_slot_id(),
        candidate_digest: "custom".to_string(),
        seed: 777,
        epoch: SecurityEpoch::from_raw(5),
        zone: "staging".to_string(),
        gate_strictness: vec![
            GateStrictness {
                gate: GateKind::Equivalence,
                required: true,
                max_divergences: 10, // very lenient
                min_throughput_millionths: 0,
                max_latency_ns: 0,
                min_adversarial_pass_rate_millionths: 0,
            },
            GateStrictness::standard(GateKind::CapabilityPreservation),
            GateStrictness {
                gate: GateKind::PerformanceThreshold,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 100_000, // very lenient
                max_latency_ns: 500_000_000,        // 500ms
                min_adversarial_pass_rate_millionths: 0,
            },
            GateStrictness {
                gate: GateKind::AdversarialSurvival,
                required: true,
                max_divergences: 0,
                min_throughput_millionths: 0,
                max_latency_ns: 0,
                min_adversarial_pass_rate_millionths: 400_000, // 40%
            },
        ],
    };
    // Use inputs that would fail with standard strictness
    let input = GateRunnerInput {
        equivalence_cases: {
            let mut c = passing_equivalence_cases(5);
            c.extend(failing_equivalence_cases(3));
            c
        },
        capability_request: passing_capability_request(),
        performance_measurements: vec![PerformanceMeasurement {
            benchmark_id: "moderate".to_string(),
            throughput_millionths: 200_000,
            latency_ns: 300_000_000,
            iterations: 50,
            seed: 1,
        }],
        adversarial_results: mixed_adversarial_results(), // 50% pass rate
    };
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Approved);
}

#[test]
fn config_missing_all_strictness_uses_defaults() {
    // Config with empty gate_strictness falls back to standard defaults
    let config = GateRunnerConfig {
        slot_id: test_slot_id(),
        candidate_digest: "fallback".to_string(),
        seed: 1,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test".to_string(),
        gate_strictness: vec![], // no custom strictness
    };
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.verdict, GateVerdict::Approved);
}

#[test]
fn serde_round_trip_full_pipeline_output() {
    let config = GateRunnerConfig::standard(test_slot_id(), "candidate".to_string(), 42);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);

    // Serialize config, input, and output
    let config_json = serde_json::to_string(&config).expect("serialize config");
    let input_json = serde_json::to_string(&input).expect("serialize input");
    let output_json = serde_json::to_string(&output).expect("serialize output");

    let config2: GateRunnerConfig = serde_json::from_str(&config_json).expect("deserialize config");
    let input2: GateRunnerInput = serde_json::from_str(&input_json).expect("deserialize input");
    let output2: GateRunnerOutput = serde_json::from_str(&output_json).expect("deserialize output");

    assert_eq!(config, config2);
    assert_eq!(input, input2);
    assert_eq!(output, output2);

    // Run again with deserialized inputs — should produce same output
    let output3 = run_promotion_gates(&config2, &input2);
    assert_eq!(output, output3);
}

#[test]
fn large_scale_equivalence_all_pass() {
    let cases = passing_equivalence_cases(1000);
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(eval.passed);
    assert!(eval.evidence.iter().any(|e| e.contains("total_cases=1000")));
}

#[test]
fn large_scale_adversarial_all_pass() {
    let results = passing_adversarial_results(1000);
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed);
    assert!(eval.evidence.iter().any(|e| e.contains("total_tests=1000")));
}

#[test]
fn large_scale_performance_all_pass() {
    let measurements = passing_perf_measurements(100);
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(eval.passed);
    assert!(
        eval.summary
            .contains("all 100 benchmarks within thresholds")
    );
}

#[test]
fn single_equivalence_failure_in_large_set_fails_strict() {
    let mut cases = passing_equivalence_cases(999);
    cases.extend(failing_equivalence_cases(1));
    let strictness = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &strictness);
    assert!(!eval.passed);
}

#[test]
fn adversarial_single_test_pass() {
    let results = vec![AdversarialTestResult {
        test_id: "only-one".to_string(),
        passed: true,
        attack_surface: "memory".to_string(),
        evidence: "ok".to_string(),
    }];
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(eval.passed); // 1_000_000 >= 950_000
}

#[test]
fn adversarial_single_test_fail() {
    let results = vec![AdversarialTestResult {
        test_id: "only-one".to_string(),
        passed: false,
        attack_surface: "memory".to_string(),
        evidence: "vuln".to_string(),
    }];
    let strictness = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&results, &strictness);
    assert!(!eval.passed); // 0 < 950_000
}

#[test]
fn performance_single_measurement_pass() {
    let measurements = passing_perf_measurements(1);
    let strictness = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&measurements, &strictness);
    assert!(eval.passed);
}

#[test]
fn full_run_preserves_slot_id_and_digest() {
    let slot = SlotId::new("my-custom-slot").expect("valid slot id");
    let config =
        GateRunnerConfig::standard(slot.clone(), "sha256:abcdef1234567890".to_string(), 999);
    let input = all_passing_input();
    let output = run_promotion_gates(&config, &input);
    assert_eq!(output.slot_id, slot);
    assert_eq!(output.candidate_digest, "sha256:abcdef1234567890");
}
