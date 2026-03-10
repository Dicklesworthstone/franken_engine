//! Enrichment integration tests for `promotion_gate_runner` (FRX-10.15).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display/as_str exact
//! values, Debug distinctness, gate evaluation semantics, aggregate verdict
//! edge cases, risk assessment, full runner pipeline, log events, and
//! evidence bundle invariants.

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

use frankenengine_engine::promotion_gate_runner::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{GateVerdict, RiskLevel};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ── helpers ────────────────────────────────────────────────────────────

fn test_slot_id() -> SlotId {
    SlotId::new("enrichment-slot-01").expect("valid slot id")
}

fn test_envelope() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
        ],
    }
}

fn eq_cases_pass(n: usize) -> Vec<EquivalenceTestCase> {
    (0..n)
        .map(|i| EquivalenceTestCase {
            test_id: format!("eq-{i}"),
            input: vec![i as u8],
            delegate_output: vec![i as u8, 0xFF],
            candidate_output: vec![i as u8, 0xFF],
        })
        .collect()
}

fn eq_cases_fail(n: usize) -> Vec<EquivalenceTestCase> {
    (0..n)
        .map(|i| EquivalenceTestCase {
            test_id: format!("eq-fail-{i}"),
            input: vec![i as u8],
            delegate_output: vec![0xAA],
            candidate_output: vec![0xBB],
        })
        .collect()
}

fn cap_req_within() -> CandidateCapabilityRequest {
    CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        authority_envelope: test_envelope(),
    }
}

fn cap_req_exceeds() -> CandidateCapabilityRequest {
    CandidateCapabilityRequest {
        slot_id: test_slot_id(),
        requested_capabilities: vec![SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
        authority_envelope: test_envelope(),
    }
}

fn perf_pass(n: usize) -> Vec<PerformanceMeasurement> {
    (0..n)
        .map(|i| PerformanceMeasurement {
            benchmark_id: format!("bench-{i}"),
            throughput_millionths: 1_000_000,
            latency_ns: 50_000_000,
            iterations: 100,
            seed: 42 + i as u64,
        })
        .collect()
}

fn adv_pass(n: usize) -> Vec<AdversarialTestResult> {
    (0..n)
        .map(|i| AdversarialTestResult {
            test_id: format!("adv-{i}"),
            passed: true,
            attack_surface: "memory_safety".to_string(),
            evidence: "no vulnerability".to_string(),
        })
        .collect()
}

fn all_pass_input() -> GateRunnerInput {
    GateRunnerInput {
        equivalence_cases: eq_cases_pass(10),
        capability_request: cap_req_within(),
        performance_measurements: perf_pass(5),
        adversarial_results: adv_pass(20),
    }
}

fn standard_config() -> GateRunnerConfig {
    GateRunnerConfig::standard(test_slot_id(), "candidate-enrich".to_string(), 99)
}

// ── GateKind Display/as_str ────────────────────────────────────────────

#[test]
fn gate_kind_as_str_exact_equivalence() {
    assert_eq!(GateKind::Equivalence.as_str(), "equivalence");
}

#[test]
fn gate_kind_as_str_exact_capability_preservation() {
    assert_eq!(
        GateKind::CapabilityPreservation.as_str(),
        "capability_preservation"
    );
}

#[test]
fn gate_kind_as_str_exact_performance_threshold() {
    assert_eq!(
        GateKind::PerformanceThreshold.as_str(),
        "performance_threshold"
    );
}

#[test]
fn gate_kind_as_str_exact_adversarial_survival() {
    assert_eq!(
        GateKind::AdversarialSurvival.as_str(),
        "adversarial_survival"
    );
}

#[test]
fn gate_kind_display_matches_as_str() {
    for g in GateKind::all() {
        assert_eq!(g.to_string(), g.as_str());
    }
}

#[test]
fn gate_kind_debug_distinct() {
    let mut dbgs = BTreeSet::new();
    for g in GateKind::all() {
        dbgs.insert(format!("{g:?}"));
    }
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn gate_kind_serde_tags_exact() {
    let json = serde_json::to_string(&GateKind::Equivalence).unwrap();
    assert_eq!(json, "\"Equivalence\"");
    let json = serde_json::to_string(&GateKind::CapabilityPreservation).unwrap();
    assert_eq!(json, "\"CapabilityPreservation\"");
    let json = serde_json::to_string(&GateKind::PerformanceThreshold).unwrap();
    assert_eq!(json, "\"PerformanceThreshold\"");
    let json = serde_json::to_string(&GateKind::AdversarialSurvival).unwrap();
    assert_eq!(json, "\"AdversarialSurvival\"");
}

#[test]
fn gate_kind_serde_roundtrip_all() {
    for g in GateKind::all() {
        let json = serde_json::to_vec(g).unwrap();
        let back: GateKind = serde_json::from_slice(&json).unwrap();
        assert_eq!(*g, back);
    }
}

#[test]
fn gate_kind_ordering() {
    assert!(GateKind::Equivalence < GateKind::CapabilityPreservation);
    assert!(GateKind::CapabilityPreservation < GateKind::PerformanceThreshold);
    assert!(GateKind::PerformanceThreshold < GateKind::AdversarialSurvival);
}

// ── GateStrictness ─────────────────────────────────────────────────────

#[test]
fn strictness_standard_defaults_equivalence() {
    let s = GateStrictness::standard(GateKind::Equivalence);
    assert!(s.required);
    assert_eq!(s.max_divergences, 0);
    assert_eq!(s.gate, GateKind::Equivalence);
}

#[test]
fn strictness_standard_defaults_performance() {
    let s = GateStrictness::standard(GateKind::PerformanceThreshold);
    assert!(s.required);
    assert_eq!(s.min_throughput_millionths, 500_000);
    assert_eq!(s.max_latency_ns, 100_000_000);
}

#[test]
fn strictness_standard_defaults_adversarial() {
    let s = GateStrictness::standard(GateKind::AdversarialSurvival);
    assert!(s.required);
    assert_eq!(s.min_adversarial_pass_rate_millionths, 950_000);
}

#[test]
fn strictness_json_fields() {
    let s = GateStrictness::standard(GateKind::Equivalence);
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("gate"));
    assert!(obj.contains_key("required"));
    assert!(obj.contains_key("max_divergences"));
    assert!(obj.contains_key("min_throughput_millionths"));
    assert!(obj.contains_key("max_latency_ns"));
    assert!(obj.contains_key("min_adversarial_pass_rate_millionths"));
}

#[test]
fn strictness_serde_roundtrip() {
    for g in GateKind::all() {
        let s = GateStrictness::standard(*g);
        let json = serde_json::to_vec(&s).unwrap();
        let back: GateStrictness = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── EquivalenceTestCase ────────────────────────────────────────────────

#[test]
fn equivalence_test_case_json_fields() {
    let tc = EquivalenceTestCase {
        test_id: "tc-1".to_string(),
        input: vec![1],
        delegate_output: vec![2],
        candidate_output: vec![2],
    };
    let v: serde_json::Value = serde_json::to_value(&tc).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("test_id"));
    assert!(obj.contains_key("input"));
    assert!(obj.contains_key("delegate_output"));
    assert!(obj.contains_key("candidate_output"));
}

#[test]
fn equivalence_test_case_serde_roundtrip() {
    let tc = EquivalenceTestCase {
        test_id: "eq-round".to_string(),
        input: vec![10, 20, 30],
        delegate_output: vec![40, 50],
        candidate_output: vec![40, 50],
    };
    let json = serde_json::to_vec(&tc).unwrap();
    let back: EquivalenceTestCase = serde_json::from_slice(&json).unwrap();
    assert_eq!(tc, back);
    assert!(back.is_equivalent());
}

// ── CandidateCapabilityRequest ─────────────────────────────────────────

#[test]
fn cap_req_within_envelope_true() {
    let req = cap_req_within();
    assert!(req.within_envelope());
    assert!(req.excess_capabilities().is_empty());
}

#[test]
fn cap_req_exceeds_envelope_detected() {
    let req = cap_req_exceeds();
    assert!(!req.within_envelope());
    let excess = req.excess_capabilities();
    assert_eq!(excess.len(), 1);
}

#[test]
fn cap_req_json_fields() {
    let req = cap_req_within();
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("slot_id"));
    assert!(obj.contains_key("requested_capabilities"));
    assert!(obj.contains_key("authority_envelope"));
}

#[test]
fn cap_req_serde_roundtrip() {
    let req = cap_req_exceeds();
    let json = serde_json::to_vec(&req).unwrap();
    let back: CandidateCapabilityRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(req, back);
}

// ── PerformanceMeasurement ─────────────────────────────────────────────

#[test]
fn perf_measurement_json_fields() {
    let pm = PerformanceMeasurement {
        benchmark_id: "b-1".to_string(),
        throughput_millionths: 1_000_000,
        latency_ns: 5_000_000,
        iterations: 200,
        seed: 55,
    };
    let v: serde_json::Value = serde_json::to_value(&pm).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("benchmark_id"));
    assert!(obj.contains_key("throughput_millionths"));
    assert!(obj.contains_key("latency_ns"));
    assert!(obj.contains_key("iterations"));
    assert!(obj.contains_key("seed"));
}

#[test]
fn perf_measurement_serde_roundtrip() {
    let pm = PerformanceMeasurement {
        benchmark_id: "b-rt".to_string(),
        throughput_millionths: 2_000_000,
        latency_ns: 10_000_000,
        iterations: 500,
        seed: 77,
    };
    let json = serde_json::to_vec(&pm).unwrap();
    let back: PerformanceMeasurement = serde_json::from_slice(&json).unwrap();
    assert_eq!(pm, back);
}

// ── AdversarialTestResult ──────────────────────────────────────────────

#[test]
fn adv_result_json_fields() {
    let atr = AdversarialTestResult {
        test_id: "adv-1".to_string(),
        passed: false,
        attack_surface: "injection".to_string(),
        evidence: "vuln found".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&atr).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("test_id"));
    assert!(obj.contains_key("passed"));
    assert!(obj.contains_key("attack_surface"));
    assert!(obj.contains_key("evidence"));
}

#[test]
fn adv_result_serde_roundtrip() {
    let atr = AdversarialTestResult {
        test_id: "adv-rt".to_string(),
        passed: true,
        attack_surface: "xss".to_string(),
        evidence: "clean".to_string(),
    };
    let json = serde_json::to_vec(&atr).unwrap();
    let back: AdversarialTestResult = serde_json::from_slice(&json).unwrap();
    assert_eq!(atr, back);
}

// ── GateEvaluation ─────────────────────────────────────────────────────

#[test]
fn gate_evaluation_json_fields() {
    let eval = GateEvaluation {
        gate: GateKind::Equivalence,
        passed: true,
        required: true,
        evidence: vec!["ev-1".to_string()],
        summary: "ok".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&eval).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("gate"));
    assert!(obj.contains_key("passed"));
    assert!(obj.contains_key("required"));
    assert!(obj.contains_key("evidence"));
    assert!(obj.contains_key("summary"));
}

#[test]
fn gate_evaluation_to_gate_result_field_mapping() {
    let eval = GateEvaluation {
        gate: GateKind::AdversarialSurvival,
        passed: false,
        required: true,
        evidence: vec!["a".to_string(), "b".to_string()],
        summary: "2 failed".to_string(),
    };
    let result = eval.to_gate_result();
    assert_eq!(result.gate_name, "adversarial_survival");
    assert!(!result.passed);
    assert_eq!(result.evidence_refs.len(), 2);
    assert_eq!(result.summary, "2 failed");
}

#[test]
fn gate_evaluation_serde_roundtrip() {
    let eval = GateEvaluation {
        gate: GateKind::PerformanceThreshold,
        passed: false,
        required: false,
        evidence: vec!["latency_exceeded".to_string()],
        summary: "advisory fail".to_string(),
    };
    let json = serde_json::to_vec(&eval).unwrap();
    let back: GateEvaluation = serde_json::from_slice(&json).unwrap();
    assert_eq!(eval, back);
}

// ── Evaluate functions (individual gates) ──────────────────────────────

#[test]
fn evaluate_equivalence_all_pass() {
    let cases = eq_cases_pass(5);
    let s = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &s);
    assert!(eval.passed);
    assert_eq!(eval.gate, GateKind::Equivalence);
    assert!(eval.summary.contains("within threshold"));
}

#[test]
fn evaluate_equivalence_some_diverge() {
    let mut cases = eq_cases_pass(3);
    cases.extend(eq_cases_fail(2));
    let s = GateStrictness::standard(GateKind::Equivalence);
    let eval = evaluate_equivalence(&cases, &s);
    assert!(!eval.passed);
    assert!(eval.summary.contains("exceeds threshold"));
}

#[test]
fn evaluate_equivalence_tolerant_threshold_allows() {
    let mut cases = eq_cases_pass(8);
    cases.extend(eq_cases_fail(2));
    let mut s = GateStrictness::standard(GateKind::Equivalence);
    s.max_divergences = 3;
    let eval = evaluate_equivalence(&cases, &s);
    assert!(eval.passed);
}

#[test]
fn evaluate_capability_preservation_within() {
    let req = cap_req_within();
    let s = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &s);
    assert!(eval.passed);
    assert!(eval.summary.contains("within authority envelope"));
}

#[test]
fn evaluate_capability_preservation_exceeds() {
    let req = cap_req_exceeds();
    let s = GateStrictness::standard(GateKind::CapabilityPreservation);
    let eval = evaluate_capability_preservation(&req, &s);
    assert!(!eval.passed);
    assert!(eval.summary.contains("exceed authority envelope"));
}

#[test]
fn evaluate_performance_no_measurements() {
    let s = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&[], &s);
    assert!(!eval.passed);
    assert!(eval.summary.contains("no performance measurements"));
}

#[test]
fn evaluate_performance_all_within() {
    let m = perf_pass(3);
    let s = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&m, &s);
    assert!(eval.passed);
    assert!(eval.summary.contains("within thresholds"));
}

#[test]
fn evaluate_performance_slow_fails() {
    let m = vec![PerformanceMeasurement {
        benchmark_id: "slow".to_string(),
        throughput_millionths: 100_000,
        latency_ns: 200_000_000,
        iterations: 10,
        seed: 1,
    }];
    let s = GateStrictness::standard(GateKind::PerformanceThreshold);
    let eval = evaluate_performance_threshold(&m, &s);
    assert!(!eval.passed);
}

#[test]
fn evaluate_adversarial_no_results() {
    let s = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&[], &s);
    assert!(!eval.passed);
    assert!(eval.summary.contains("no adversarial test results"));
}

#[test]
fn evaluate_adversarial_all_pass() {
    let r = adv_pass(20);
    let s = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&r, &s);
    assert!(eval.passed);
}

#[test]
fn evaluate_adversarial_below_threshold() {
    let r = vec![
        AdversarialTestResult {
            test_id: "a".to_string(),
            passed: true,
            attack_surface: "mem".to_string(),
            evidence: "ok".to_string(),
        },
        AdversarialTestResult {
            test_id: "b".to_string(),
            passed: false,
            attack_surface: "inj".to_string(),
            evidence: "vuln".to_string(),
        },
    ];
    let s = GateStrictness::standard(GateKind::AdversarialSurvival);
    let eval = evaluate_adversarial_survival(&r, &s);
    assert!(!eval.passed); // 50% < 95%
}

// ── aggregate_verdict ──────────────────────────────────────────────────

#[test]
fn aggregate_verdict_all_pass_approved() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| GateEvaluation {
            gate: *g,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        })
        .collect();
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

#[test]
fn aggregate_verdict_one_required_fail_denied() {
    let mut evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| GateEvaluation {
            gate: *g,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        })
        .collect();
    evals[1].passed = false;
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Denied);
}

#[test]
fn aggregate_verdict_missing_gate_inconclusive() {
    let evals = vec![
        GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        },
        GateEvaluation {
            gate: GateKind::CapabilityPreservation,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        },
    ];
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
        .map(|g| GateEvaluation {
            gate: *g,
            passed: *g != GateKind::AdversarialSurvival,
            required: *g != GateKind::AdversarialSurvival,
            evidence: vec![],
            summary: "ok".to_string(),
        })
        .collect();
    assert_eq!(aggregate_verdict(&evals), GateVerdict::Approved);
}

// ── assess_risk ────────────────────────────────────────────────────────

#[test]
fn assess_risk_all_pass_low() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| GateEvaluation {
            gate: *g,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        })
        .collect();
    assert_eq!(assess_risk(&evals), RiskLevel::Low);
}

#[test]
fn assess_risk_advisory_only_fail_medium() {
    let evals = vec![
        GateEvaluation {
            gate: GateKind::Equivalence,
            passed: true,
            required: true,
            evidence: vec![],
            summary: "ok".to_string(),
        },
        GateEvaluation {
            gate: GateKind::PerformanceThreshold,
            passed: false,
            required: false,
            evidence: vec![],
            summary: "advisory".to_string(),
        },
    ];
    assert_eq!(assess_risk(&evals), RiskLevel::Medium);
}

#[test]
fn assess_risk_one_required_fail_high() {
    let evals = vec![GateEvaluation {
        gate: GateKind::Equivalence,
        passed: false,
        required: true,
        evidence: vec![],
        summary: "fail".to_string(),
    }];
    assert_eq!(assess_risk(&evals), RiskLevel::High);
}

#[test]
fn assess_risk_three_or_more_fails_critical() {
    let evals: Vec<GateEvaluation> = GateKind::all()
        .iter()
        .map(|g| GateEvaluation {
            gate: *g,
            passed: false,
            required: true,
            evidence: vec![],
            summary: "fail".to_string(),
        })
        .collect();
    assert_eq!(assess_risk(&evals), RiskLevel::Critical);
}

// ── GateRunnerConfig ───────────────────────────────────────────────────

#[test]
fn config_standard_has_all_four_gates() {
    let cfg = standard_config();
    assert_eq!(cfg.gate_strictness.len(), 4);
    for g in GateKind::all() {
        assert!(cfg.strictness_for(*g).is_some());
    }
}

#[test]
fn config_standard_epoch_is_one() {
    let cfg = standard_config();
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn config_standard_zone_is_default() {
    let cfg = standard_config();
    assert_eq!(cfg.zone, "default");
}

#[test]
fn config_json_fields() {
    let cfg = standard_config();
    let v: serde_json::Value = serde_json::to_value(&cfg).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("slot_id"));
    assert!(obj.contains_key("candidate_digest"));
    assert!(obj.contains_key("seed"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("zone"));
    assert!(obj.contains_key("gate_strictness"));
}

#[test]
fn config_serde_roundtrip() {
    let cfg = standard_config();
    let json = serde_json::to_vec(&cfg).unwrap();
    let back: GateRunnerConfig = serde_json::from_slice(&json).unwrap();
    assert_eq!(cfg, back);
}

// ── GateRunnerInput/Output ─────────────────────────────────────────────

#[test]
fn runner_input_json_fields() {
    let inp = all_pass_input();
    let v: serde_json::Value = serde_json::to_value(&inp).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("equivalence_cases"));
    assert!(obj.contains_key("capability_request"));
    assert!(obj.contains_key("performance_measurements"));
    assert!(obj.contains_key("adversarial_results"));
}

#[test]
fn runner_input_serde_roundtrip() {
    let inp = all_pass_input();
    let json = serde_json::to_vec(&inp).unwrap();
    let back: GateRunnerInput = serde_json::from_slice(&json).unwrap();
    assert_eq!(inp, back);
}

// ── run_promotion_gates pipeline ───────────────────────────────────────

#[test]
fn full_run_all_pass_approved() {
    let cfg = standard_config();
    let out = run_promotion_gates(&cfg, &all_pass_input());
    assert_eq!(out.verdict, GateVerdict::Approved);
    assert_eq!(out.risk_level, RiskLevel::Low);
    assert!(out.rollback_verified);
    assert_eq!(out.evaluations.len(), 4);
    assert_eq!(out.evidence_bundle.total_failed, 0);
}

#[test]
fn full_run_deterministic_same_seed() {
    let cfg = standard_config();
    let inp = all_pass_input();
    let out1 = run_promotion_gates(&cfg, &inp);
    let out2 = run_promotion_gates(&cfg, &inp);
    assert_eq!(out1.run_id, out2.run_id);
    assert_eq!(out1.verdict, out2.verdict);
    assert_eq!(out1.evidence_bundle, out2.evidence_bundle);
}

#[test]
fn full_run_equivalence_fail_denies() {
    let cfg = standard_config();
    let inp = GateRunnerInput {
        equivalence_cases: eq_cases_fail(5),
        capability_request: cap_req_within(),
        performance_measurements: perf_pass(3),
        adversarial_results: adv_pass(10),
    };
    let out = run_promotion_gates(&cfg, &inp);
    assert_eq!(out.verdict, GateVerdict::Denied);
    assert!(out.evidence_bundle.total_failed > 0);
}

#[test]
fn full_run_capability_exceed_denies() {
    let cfg = standard_config();
    let inp = GateRunnerInput {
        equivalence_cases: eq_cases_pass(3),
        capability_request: cap_req_exceeds(),
        performance_measurements: perf_pass(3),
        adversarial_results: adv_pass(10),
    };
    let out = run_promotion_gates(&cfg, &inp);
    assert_eq!(out.verdict, GateVerdict::Denied);
}

#[test]
fn full_run_evidence_bundle_counts_consistent() {
    let cfg = standard_config();
    let out = run_promotion_gates(&cfg, &all_pass_input());
    let b = &out.evidence_bundle;
    assert_eq!(b.total_passed + b.total_failed, b.total_test_cases);
    assert_eq!(b.artifacts.len(), 4);
}

#[test]
fn full_run_evidence_artifact_ids_unique() {
    let cfg = standard_config();
    let out = run_promotion_gates(&cfg, &all_pass_input());
    let mut ids = BTreeSet::new();
    for a in &out.evidence_bundle.artifacts {
        ids.insert(a.artifact_id.clone());
    }
    assert_eq!(ids.len(), 4);
}

#[test]
fn full_run_output_json_fields() {
    let cfg = standard_config();
    let out = run_promotion_gates(&cfg, &all_pass_input());
    let v: serde_json::Value = serde_json::to_value(&out).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("run_id"));
    assert!(obj.contains_key("slot_id"));
    assert!(obj.contains_key("candidate_digest"));
    assert!(obj.contains_key("evaluations"));
    assert!(obj.contains_key("verdict"));
    assert!(obj.contains_key("risk_level"));
    assert!(obj.contains_key("rollback_verified"));
    assert!(obj.contains_key("seed"));
    assert!(obj.contains_key("evidence_bundle"));
}

#[test]
fn full_run_output_serde_roundtrip() {
    let cfg = standard_config();
    let out = run_promotion_gates(&cfg, &all_pass_input());
    let json = serde_json::to_vec(&out).unwrap();
    let back: GateRunnerOutput = serde_json::from_slice(&json).unwrap();
    assert_eq!(out, back);
}

// ── EvidenceArtifact ───────────────────────────────────────────────────

#[test]
fn evidence_artifact_json_fields() {
    let a = EvidenceArtifact {
        artifact_id: "test/equiv".to_string(),
        gate: GateKind::Equivalence,
        content_hash: "deadbeef".to_string(),
        description: "all equivalent".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("artifact_id"));
    assert!(obj.contains_key("gate"));
    assert!(obj.contains_key("content_hash"));
    assert!(obj.contains_key("description"));
}

#[test]
fn evidence_artifact_serde_roundtrip() {
    let a = EvidenceArtifact {
        artifact_id: "test/art".to_string(),
        gate: GateKind::AdversarialSurvival,
        content_hash: "abcdef01".to_string(),
        description: "passed".to_string(),
    };
    let json = serde_json::to_vec(&a).unwrap();
    let back: EvidenceArtifact = serde_json::from_slice(&json).unwrap();
    assert_eq!(a, back);
}

// ── GateRunnerLogEvent ─────────────────────────────────────────────────

#[test]
fn log_event_pass_no_error_code() {
    let cfg = standard_config();
    let eval = GateEvaluation {
        gate: GateKind::Equivalence,
        passed: true,
        required: true,
        evidence: vec![],
        summary: "ok".to_string(),
    };
    let log = log_gate_evaluation(&cfg, &eval);
    assert_eq!(log.outcome, "pass");
    assert!(log.error_code.is_none());
    assert_eq!(log.component, "promotion_gate_runner");
    assert_eq!(log.gate, Some(GateKind::Equivalence));
}

#[test]
fn log_event_fail_has_error_code() {
    let cfg = standard_config();
    let eval = GateEvaluation {
        gate: GateKind::CapabilityPreservation,
        passed: false,
        required: true,
        evidence: vec![],
        summary: "fail".to_string(),
    };
    let log = log_gate_evaluation(&cfg, &eval);
    assert_eq!(log.outcome, "fail");
    let code = log.error_code.as_ref().unwrap();
    assert!(code.starts_with("FE-GATE-"));
    assert!(code.contains("CAPABILITY_PRESERVATION"));
}

#[test]
fn log_event_json_fields() {
    let cfg = standard_config();
    let eval = GateEvaluation {
        gate: GateKind::PerformanceThreshold,
        passed: true,
        required: true,
        evidence: vec![],
        summary: "ok".to_string(),
    };
    let log = log_gate_evaluation(&cfg, &eval);
    let v: serde_json::Value = serde_json::to_value(&log).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("error_code"));
    assert!(obj.contains_key("gate"));
    assert!(obj.contains_key("slot_id"));
}

#[test]
fn log_event_serde_roundtrip() {
    let cfg = standard_config();
    let eval = GateEvaluation {
        gate: GateKind::AdversarialSurvival,
        passed: false,
        required: true,
        evidence: vec![],
        summary: "fail".to_string(),
    };
    let log = log_gate_evaluation(&cfg, &eval);
    let json = serde_json::to_vec(&log).unwrap();
    let back: GateRunnerLogEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(log, back);
}

// ── EvidenceBundle ─────────────────────────────────────────────────────

#[test]
fn evidence_bundle_json_fields() {
    let b = EvidenceBundle {
        artifacts: vec![],
        total_test_cases: 10,
        total_passed: 8,
        total_failed: 2,
    };
    let v: serde_json::Value = serde_json::to_value(&b).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("artifacts"));
    assert!(obj.contains_key("total_test_cases"));
    assert!(obj.contains_key("total_passed"));
    assert!(obj.contains_key("total_failed"));
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let b = EvidenceBundle {
        artifacts: vec![EvidenceArtifact {
            artifact_id: "test".to_string(),
            gate: GateKind::Equivalence,
            content_hash: "hash".to_string(),
            description: "desc".to_string(),
        }],
        total_test_cases: 5,
        total_passed: 5,
        total_failed: 0,
    };
    let json = serde_json::to_vec(&b).unwrap();
    let back: EvidenceBundle = serde_json::from_slice(&json).unwrap();
    assert_eq!(b, back);
}
