#![forbid(unsafe_code)]

//! Enrichment integration tests for the `specialization_lane_gate` module.
//!
//! Covers Display uniqueness, serde roundtrips, gate evaluation behavior,
//! performance delta computation, receipt coverage auditing, fallback injection
//! logic, evidence bundle determinism, blocker accumulation, log entry
//! generation, and edge cases for every public type and method.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_lane_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn digest(s: &str) -> ContentHash {
    ContentHash::compute(s.as_bytes())
}

fn make_metrics(
    workload_id: &str,
    lane: LaneType,
    throughput: u64,
    latency_p95: u64,
    memory: u64,
    digest_tag: &str,
) -> WorkloadMetrics {
    WorkloadMetrics {
        workload_id: workload_id.to_string(),
        lane_type: lane,
        output_digest: digest(digest_tag),
        throughput_ops_per_sec: throughput,
        latency_p50_ns: latency_p95 / 2,
        latency_p95_ns: latency_p95,
        latency_p99_ns: latency_p95 * 2,
        memory_peak_bytes: memory,
        sample_count: 10,
    }
}

fn make_receipt(id: &str, verified: bool) -> ReceiptRef {
    ReceiptRef {
        receipt_id: id.to_string(),
        optimization_class: "hostcall_dispatch".to_string(),
        receipt_hash: digest(id),
        signature_verified: verified,
        issued_epoch: epoch(1),
    }
}

fn make_fallback_pass(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
    let canonical = digest("canonical_output");
    FallbackTestResult {
        workload_id: workload_id.to_string(),
        injection_kind: kind,
        correct_output: true,
        fallback_receipt_emitted: true,
        crash_or_hang: false,
        fallback_output_digest: canonical,
        expected_output_digest: canonical,
        fallback_latency_ns: 1000,
        ambient_latency_ns: 1000,
    }
}

fn make_fallback_fail(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
    FallbackTestResult {
        workload_id: workload_id.to_string(),
        injection_kind: kind,
        correct_output: false,
        fallback_receipt_emitted: true,
        crash_or_hang: false,
        fallback_output_digest: digest("wrong"),
        expected_output_digest: digest("canonical_output"),
        fallback_latency_ns: 1000,
        ambient_latency_ns: 1000,
    }
}

fn specialized_metrics(n: usize) -> Vec<WorkloadMetrics> {
    (0..n)
        .map(|i| {
            make_metrics(
                &format!("workload_{i}"),
                LaneType::ProofSpecialized,
                1200,
                800,
                4000,
                "canonical",
            )
        })
        .collect()
}

fn ambient_metrics(n: usize) -> Vec<WorkloadMetrics> {
    (0..n)
        .map(|i| {
            make_metrics(
                &format!("workload_{i}"),
                LaneType::AmbientAuthority,
                1000,
                1000,
                5000,
                "canonical",
            )
        })
        .collect()
}

fn verified_receipts(n: u64) -> Vec<ReceiptRef> {
    (0..n)
        .map(|i| make_receipt(&format!("receipt_{i}"), true))
        .collect()
}

fn all_fallbacks() -> Vec<FallbackTestResult> {
    vec![
        make_fallback_pass("workload_0", InjectionKind::ProofFailure),
        make_fallback_pass("workload_1", InjectionKind::CapabilityRevocation),
        make_fallback_pass("workload_2", InjectionKind::EpochTransition),
        make_fallback_pass("workload_3", InjectionKind::ProofExpiry),
    ]
}

fn passing_input<'a>(
    spec: &'a [WorkloadMetrics],
    amb: &'a [WorkloadMetrics],
    receipts: &'a [ReceiptRef],
    fallbacks: &'a [FallbackTestResult],
) -> GateInput<'a> {
    GateInput {
        run_id: "enrichment-run",
        trace_id: "enrichment-trace",
        epoch: epoch(1),
        specialized_metrics: spec,
        ambient_metrics: amb,
        receipts,
        total_specialization_decisions: receipts.len() as u64,
        fallback_results: fallbacks,
        significance_threshold_millionths: DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_component_constant() {
    assert_eq!(GATE_COMPONENT, "specialization_lane_gate");
    assert!(!GATE_COMPONENT.is_empty());
}

#[test]
fn enrichment_gate_schema_version_constant() {
    assert_eq!(
        GATE_SCHEMA_VERSION,
        "franken-engine.specialization-lane-gate.v1"
    );
    assert!(GATE_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_min_workload_count_constant() {
    assert_eq!(MIN_WORKLOAD_COUNT, 10);
}

#[test]
fn enrichment_min_sample_count_constant() {
    assert_eq!(MIN_SAMPLE_COUNT, 5);
}

#[test]
fn enrichment_required_coverage_millionths_constant() {
    assert_eq!(REQUIRED_COVERAGE_MILLIONTHS, 1_000_000);
}

#[test]
fn enrichment_default_significance_threshold_constant() {
    assert_eq!(DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS, 50_000);
}

// ---------------------------------------------------------------------------
// LaneType — Display, as_str, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lane_type_display_uniqueness() {
    let mut displays = BTreeSet::new();
    let variants = [
        LaneType::ProofSpecialized,
        LaneType::AmbientAuthority,
        LaneType::Fallback,
    ];
    for v in &variants {
        displays.insert(v.to_string());
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_lane_type_as_str_values() {
    assert_eq!(LaneType::ProofSpecialized.as_str(), "proof_specialized");
    assert_eq!(LaneType::AmbientAuthority.as_str(), "ambient_authority");
    assert_eq!(LaneType::Fallback.as_str(), "fallback");
}

#[test]
fn enrichment_lane_type_display_matches_as_str() {
    let variants = [
        LaneType::ProofSpecialized,
        LaneType::AmbientAuthority,
        LaneType::Fallback,
    ];
    for v in &variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_lane_type_serde_roundtrip_all_variants() {
    let variants = [
        LaneType::ProofSpecialized,
        LaneType::AmbientAuthority,
        LaneType::Fallback,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: LaneType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_lane_type_ordering() {
    assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
    assert!(LaneType::AmbientAuthority < LaneType::Fallback);
}

#[test]
fn enrichment_lane_type_clone_eq() {
    let lt = LaneType::ProofSpecialized;
    let lt2 = lt;
    assert_eq!(lt, lt2);
}

#[test]
fn enrichment_lane_type_debug_not_empty() {
    let dbg = format!("{:?}", LaneType::Fallback);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Fallback"));
}

// ---------------------------------------------------------------------------
// InjectionKind — Display, as_str, all(), serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_injection_kind_display_uniqueness() {
    let mut displays = BTreeSet::new();
    for k in InjectionKind::all() {
        displays.insert(k.to_string());
    }
    assert_eq!(displays.len(), InjectionKind::all().len());
}

#[test]
fn enrichment_injection_kind_as_str_values() {
    assert_eq!(InjectionKind::ProofFailure.as_str(), "proof_failure");
    assert_eq!(
        InjectionKind::CapabilityRevocation.as_str(),
        "capability_revocation"
    );
    assert_eq!(InjectionKind::EpochTransition.as_str(), "epoch_transition");
    assert_eq!(InjectionKind::ProofExpiry.as_str(), "proof_expiry");
}

#[test]
fn enrichment_injection_kind_display_matches_as_str() {
    for k in InjectionKind::all() {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn enrichment_injection_kind_all_returns_four_variants() {
    assert_eq!(InjectionKind::all().len(), 4);
}

#[test]
fn enrichment_injection_kind_all_contains_every_variant() {
    let all = InjectionKind::all();
    assert!(all.contains(&InjectionKind::ProofFailure));
    assert!(all.contains(&InjectionKind::CapabilityRevocation));
    assert!(all.contains(&InjectionKind::EpochTransition));
    assert!(all.contains(&InjectionKind::ProofExpiry));
}

#[test]
fn enrichment_injection_kind_serde_roundtrip_all() {
    for k in InjectionKind::all() {
        let json = serde_json::to_string(k).unwrap();
        let back: InjectionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_injection_kind_ordering() {
    assert!(InjectionKind::ProofFailure < InjectionKind::CapabilityRevocation);
    assert!(InjectionKind::CapabilityRevocation < InjectionKind::EpochTransition);
    assert!(InjectionKind::EpochTransition < InjectionKind::ProofExpiry);
}

#[test]
fn enrichment_injection_kind_clone_eq() {
    let k = InjectionKind::EpochTransition;
    let k2 = k;
    assert_eq!(k, k2);
}

// ---------------------------------------------------------------------------
// GateOutcome — Display, is_pass, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_outcome_display_uniqueness() {
    let mut displays = BTreeSet::new();
    displays.insert(GateOutcome::Pass.to_string());
    displays.insert(GateOutcome::Fail.to_string());
    assert_eq!(displays.len(), 2);
}

#[test]
fn enrichment_gate_outcome_display_values() {
    assert_eq!(GateOutcome::Pass.to_string(), "PASS");
    assert_eq!(GateOutcome::Fail.to_string(), "FAIL");
}

#[test]
fn enrichment_gate_outcome_is_pass() {
    assert!(GateOutcome::Pass.is_pass());
    assert!(!GateOutcome::Fail.is_pass());
}

#[test]
fn enrichment_gate_outcome_serde_roundtrip() {
    for outcome in &[GateOutcome::Pass, GateOutcome::Fail] {
        let json = serde_json::to_string(outcome).unwrap();
        let back: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

#[test]
fn enrichment_gate_outcome_ordering() {
    assert!(GateOutcome::Pass < GateOutcome::Fail);
}

// ---------------------------------------------------------------------------
// WorkloadMetrics — construction, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_metrics_construction() {
    let wm = make_metrics("wl-1", LaneType::ProofSpecialized, 500, 200, 8000, "out");
    assert_eq!(wm.workload_id, "wl-1");
    assert_eq!(wm.lane_type, LaneType::ProofSpecialized);
    assert_eq!(wm.throughput_ops_per_sec, 500);
    assert_eq!(wm.latency_p50_ns, 100);
    assert_eq!(wm.latency_p95_ns, 200);
    assert_eq!(wm.latency_p99_ns, 400);
    assert_eq!(wm.memory_peak_bytes, 8000);
    assert_eq!(wm.sample_count, 10);
}

#[test]
fn enrichment_workload_metrics_serde_roundtrip() {
    let wm = make_metrics("wl-2", LaneType::AmbientAuthority, 1000, 500, 4000, "out");
    let json = serde_json::to_string(&wm).unwrap();
    let back: WorkloadMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(wm, back);
}

#[test]
fn enrichment_workload_metrics_debug_not_empty() {
    let wm = make_metrics("wl-3", LaneType::Fallback, 100, 50, 1000, "dbg");
    let dbg = format!("{:?}", wm);
    assert!(dbg.contains("wl-3"));
}

// ---------------------------------------------------------------------------
// ReceiptRef — construction, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_ref_construction() {
    let r = make_receipt("rcpt-1", true);
    assert_eq!(r.receipt_id, "rcpt-1");
    assert_eq!(r.optimization_class, "hostcall_dispatch");
    assert!(r.signature_verified);
    assert_eq!(r.issued_epoch, epoch(1));
}

#[test]
fn enrichment_receipt_ref_serde_roundtrip() {
    let r = make_receipt("rcpt-2", false);
    let json = serde_json::to_string(&r).unwrap();
    let back: ReceiptRef = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_receipt_ref_ordering() {
    let r1 = make_receipt("aaa", true);
    let r2 = make_receipt("bbb", true);
    assert!(r1 < r2);
}

// ---------------------------------------------------------------------------
// FallbackTestResult — passed, performance_regressed, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fallback_test_result_passed_all_criteria() {
    let fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    assert!(fb.passed());
}

#[test]
fn enrichment_fallback_test_result_fails_incorrect_output() {
    let fb = make_fallback_fail("w1", InjectionKind::ProofFailure);
    assert!(!fb.passed());
}

#[test]
fn enrichment_fallback_test_result_fails_crash_or_hang() {
    let mut fb = make_fallback_pass("w1", InjectionKind::CapabilityRevocation);
    fb.crash_or_hang = true;
    assert!(!fb.passed());
}

#[test]
fn enrichment_fallback_test_result_fails_no_receipt_emitted() {
    let mut fb = make_fallback_pass("w1", InjectionKind::EpochTransition);
    fb.fallback_receipt_emitted = false;
    assert!(!fb.passed());
}

#[test]
fn enrichment_fallback_test_result_fails_digest_mismatch() {
    let mut fb = make_fallback_pass("w1", InjectionKind::ProofExpiry);
    fb.fallback_output_digest = digest("diverged");
    assert!(!fb.passed());
}

#[test]
fn enrichment_fallback_performance_regressed_above_10pct() {
    let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 1200; // 20% regression
    assert!(fb.performance_regressed());
}

#[test]
fn enrichment_fallback_performance_not_regressed_within_10pct() {
    let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 1050; // 5% is within 10%
    assert!(!fb.performance_regressed());
}

#[test]
fn enrichment_fallback_performance_exactly_at_10pct_boundary() {
    let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 1100; // exactly 10%
    assert!(!fb.performance_regressed()); // threshold is > 10%, not >=
}

#[test]
fn enrichment_fallback_performance_zero_ambient_no_regression() {
    let mut fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 0;
    fb.fallback_latency_ns = 5000;
    assert!(!fb.performance_regressed());
}

#[test]
fn enrichment_fallback_performance_equal_latency_no_regression() {
    let fb = make_fallback_pass("w1", InjectionKind::ProofFailure);
    assert!(!fb.performance_regressed());
}

#[test]
fn enrichment_fallback_test_result_serde_roundtrip() {
    let fb = make_fallback_pass("w1", InjectionKind::CapabilityRevocation);
    let json = serde_json::to_string(&fb).unwrap();
    let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn enrichment_fallback_test_result_fail_serde_roundtrip() {
    let fb = make_fallback_fail("w2", InjectionKind::EpochTransition);
    let json = serde_json::to_string(&fb).unwrap();
    let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

// ---------------------------------------------------------------------------
// PerformanceDelta — compute, has_positive_delta
// ---------------------------------------------------------------------------

#[test]
fn enrichment_performance_delta_positive_throughput() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.workload_id, "w1");
    assert_eq!(delta.throughput_delta_millionths, 200_000);
    assert!(delta.has_positive_delta());
    assert!(delta.output_equivalent);
}

#[test]
fn enrichment_performance_delta_negative_throughput() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 800, 1200, 6000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, -200_000);
    // Latency worse and memory worse — no positive delta on any dimension
    assert!(!delta.has_positive_delta());
}

#[test]
fn enrichment_performance_delta_zero_ambient_yields_zero() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 500, 3000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 0, 0, 0, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, 0);
    assert_eq!(delta.latency_p95_improvement_millionths, 0);
    assert_eq!(delta.memory_improvement_millionths, 0);
}

#[test]
fn enrichment_performance_delta_latency_improvement() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 500, 5000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.latency_p95_improvement_millionths, 500_000); // 50%
}

#[test]
fn enrichment_performance_delta_memory_improvement() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 2500, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.memory_improvement_millionths, 500_000); // 50% less
}

#[test]
fn enrichment_performance_delta_neutral_not_positive() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 5000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert!(!delta.has_positive_delta());
    assert_eq!(delta.throughput_delta_millionths, 0);
    assert_eq!(delta.latency_p95_improvement_millionths, 0);
    assert_eq!(delta.memory_improvement_millionths, 0);
}

#[test]
fn enrichment_performance_delta_output_divergence() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out_a");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out_b");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert!(!delta.output_equivalent);
}

#[test]
fn enrichment_performance_delta_serde_roundtrip() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    let json = serde_json::to_string(&delta).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, back);
}

#[test]
fn enrichment_performance_delta_positive_only_on_memory() {
    // Throughput and latency equal, but memory improved
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 3000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, 0);
    assert_eq!(delta.latency_p95_improvement_millionths, 0);
    assert!(delta.memory_improvement_millionths > 0);
    assert!(delta.has_positive_delta());
}

#[test]
fn enrichment_performance_delta_positive_only_on_latency() {
    let spec = make_metrics("w1", LaneType::ProofSpecialized, 1000, 700, 5000, "out");
    let amb = make_metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, 0);
    assert!(delta.latency_p95_improvement_millionths > 0);
    assert_eq!(delta.memory_improvement_millionths, 0);
    assert!(delta.has_positive_delta());
}

// ---------------------------------------------------------------------------
// GateBlocker — Display uniqueness, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_blocker_display_uniqueness() {
    let blockers = vec![
        GateBlocker::InsufficientWorkloads {
            required: 10,
            actual: 3,
        },
        GateBlocker::OutputDivergence {
            workload_id: "w1".to_string(),
        },
        GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths: 500_000,
        },
        GateBlocker::UnverifiedReceipt {
            receipt_id: "r1".to_string(),
        },
        GateBlocker::NoPositiveDelta {
            mean_throughput_delta_millionths: -10_000,
        },
        GateBlocker::FallbackTestFailed {
            workload_id: "w2".to_string(),
            injection_kind: InjectionKind::ProofFailure,
            reason: "crash".to_string(),
        },
        GateBlocker::FallbackPerformanceRegression {
            workload_id: "w3".to_string(),
            injection_kind: InjectionKind::EpochTransition,
        },
        GateBlocker::InsufficientSamples {
            workload_id: "w4".to_string(),
            lane_type: LaneType::ProofSpecialized,
            sample_count: 2,
        },
        GateBlocker::WorkloadMismatch {
            missing_workload_ids: vec!["w5".to_string()],
        },
    ];
    let mut displays = BTreeSet::new();
    for b in &blockers {
        displays.insert(b.to_string());
    }
    assert_eq!(displays.len(), blockers.len());
}

#[test]
fn enrichment_gate_blocker_display_insufficient_workloads() {
    let b = GateBlocker::InsufficientWorkloads {
        required: 10,
        actual: 3,
    };
    assert_eq!(b.to_string(), "insufficient workloads: 3/10");
}

#[test]
fn enrichment_gate_blocker_display_output_divergence() {
    let b = GateBlocker::OutputDivergence {
        workload_id: "wl-42".to_string(),
    };
    let display = b.to_string();
    assert!(display.contains("output divergence"));
    assert!(display.contains("wl-42"));
}

#[test]
fn enrichment_gate_blocker_display_insufficient_receipt_coverage() {
    let b = GateBlocker::InsufficientReceiptCoverage {
        coverage_millionths: 750_000,
    };
    let display = b.to_string();
    assert!(display.contains("750000"));
    assert!(display.contains("1000000"));
}

#[test]
fn enrichment_gate_blocker_display_unverified_receipt() {
    let b = GateBlocker::UnverifiedReceipt {
        receipt_id: "rcpt-bad".to_string(),
    };
    let display = b.to_string();
    assert!(display.contains("unverified"));
    assert!(display.contains("rcpt-bad"));
}

#[test]
fn enrichment_gate_blocker_display_no_positive_delta() {
    let b = GateBlocker::NoPositiveDelta {
        mean_throughput_delta_millionths: -50_000,
    };
    let display = b.to_string();
    assert!(display.contains("-50000"));
}

#[test]
fn enrichment_gate_blocker_display_fallback_test_failed() {
    let b = GateBlocker::FallbackTestFailed {
        workload_id: "w1".to_string(),
        injection_kind: InjectionKind::CapabilityRevocation,
        reason: "incorrect output".to_string(),
    };
    let display = b.to_string();
    assert!(display.contains("w1"));
    assert!(display.contains("capability_revocation"));
    assert!(display.contains("incorrect output"));
}

#[test]
fn enrichment_gate_blocker_display_fallback_performance_regression() {
    let b = GateBlocker::FallbackPerformanceRegression {
        workload_id: "w2".to_string(),
        injection_kind: InjectionKind::ProofExpiry,
    };
    let display = b.to_string();
    assert!(display.contains("performance regression"));
    assert!(display.contains("w2"));
    assert!(display.contains("proof_expiry"));
}

#[test]
fn enrichment_gate_blocker_display_insufficient_samples() {
    let b = GateBlocker::InsufficientSamples {
        workload_id: "w3".to_string(),
        lane_type: LaneType::AmbientAuthority,
        sample_count: 2,
    };
    let display = b.to_string();
    assert!(display.contains("w3"));
    assert!(display.contains("ambient_authority"));
    assert!(display.contains("2"));
}

#[test]
fn enrichment_gate_blocker_display_workload_mismatch() {
    let b = GateBlocker::WorkloadMismatch {
        missing_workload_ids: vec!["m1".to_string(), "m2".to_string()],
    };
    let display = b.to_string();
    assert!(display.contains("workload mismatch"));
    assert!(display.contains("m1"));
    assert!(display.contains("m2"));
}

#[test]
fn enrichment_gate_blocker_serde_roundtrip_all_variants() {
    let blockers = vec![
        GateBlocker::InsufficientWorkloads {
            required: 10,
            actual: 5,
        },
        GateBlocker::OutputDivergence {
            workload_id: "w1".to_string(),
        },
        GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths: 800_000,
        },
        GateBlocker::UnverifiedReceipt {
            receipt_id: "r1".to_string(),
        },
        GateBlocker::NoPositiveDelta {
            mean_throughput_delta_millionths: -1000,
        },
        GateBlocker::FallbackTestFailed {
            workload_id: "w2".to_string(),
            injection_kind: InjectionKind::ProofFailure,
            reason: "crash".to_string(),
        },
        GateBlocker::FallbackPerformanceRegression {
            workload_id: "w3".to_string(),
            injection_kind: InjectionKind::EpochTransition,
        },
        GateBlocker::InsufficientSamples {
            workload_id: "w4".to_string(),
            lane_type: LaneType::Fallback,
            sample_count: 1,
        },
        GateBlocker::WorkloadMismatch {
            missing_workload_ids: vec!["w5".to_string()],
        },
    ];
    for b in &blockers {
        let json = serde_json::to_string(b).unwrap();
        let back: GateBlocker = serde_json::from_str(&json).unwrap();
        assert_eq!(*b, back);
    }
}

// ---------------------------------------------------------------------------
// GateError — Display uniqueness, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_error_display_uniqueness() {
    let errors = vec![
        GateError::EmptyWorkloads,
        GateError::WorkloadSetMismatch {
            detail: "x".to_string(),
        },
        GateError::EmptyReceipts,
        GateError::InvalidMetric {
            workload_id: "w1".to_string(),
            detail: "neg".to_string(),
        },
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_gate_error_display_empty_workloads() {
    assert_eq!(GateError::EmptyWorkloads.to_string(), "no workloads provided");
}

#[test]
fn enrichment_gate_error_display_workload_set_mismatch() {
    let e = GateError::WorkloadSetMismatch {
        detail: "specialized has extra".to_string(),
    };
    let display = e.to_string();
    assert!(display.contains("workload set mismatch"));
    assert!(display.contains("specialized has extra"));
}

#[test]
fn enrichment_gate_error_display_empty_receipts() {
    let e = GateError::EmptyReceipts;
    assert_eq!(
        e.to_string(),
        "no receipts provided for coverage audit"
    );
}

#[test]
fn enrichment_gate_error_display_invalid_metric() {
    let e = GateError::InvalidMetric {
        workload_id: "w7".to_string(),
        detail: "negative throughput".to_string(),
    };
    let display = e.to_string();
    assert!(display.contains("w7"));
    assert!(display.contains("negative throughput"));
}

#[test]
fn enrichment_gate_error_serde_roundtrip_all() {
    let errors = vec![
        GateError::EmptyWorkloads,
        GateError::WorkloadSetMismatch {
            detail: "mismatch".to_string(),
        },
        GateError::EmptyReceipts,
        GateError::InvalidMetric {
            workload_id: "w1".to_string(),
            detail: "bad".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: GateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// GateLogEntry — construction, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_log_entry_construction_all_fields() {
    let entry = GateLogEntry {
        trace_id: "t-123".to_string(),
        component: GATE_COMPONENT.to_string(),
        lane_type: Some(LaneType::ProofSpecialized),
        event: "workload_delta".to_string(),
        outcome: "positive".to_string(),
        workload_id: Some("w1".to_string()),
        optimization_pass: Some("inline_dispatch".to_string()),
        proof_status: Some("verified".to_string()),
        capability_witness_ref: Some("cw-ref".to_string()),
        specialization_receipt_hash: Some("hash-abc".to_string()),
        fallback_triggered: Some(false),
        wall_time_ns: Some(5000),
        memory_peak_bytes: Some(65536),
        error_code: None,
    };
    assert_eq!(entry.trace_id, "t-123");
    assert_eq!(entry.lane_type, Some(LaneType::ProofSpecialized));
    assert_eq!(entry.wall_time_ns, Some(5000));
}

#[test]
fn enrichment_gate_log_entry_construction_minimal() {
    let entry = GateLogEntry {
        trace_id: "t-min".to_string(),
        component: GATE_COMPONENT.to_string(),
        lane_type: None,
        event: "gate_evaluation_complete".to_string(),
        outcome: "PASS".to_string(),
        workload_id: None,
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: None,
        wall_time_ns: None,
        memory_peak_bytes: None,
        error_code: None,
    };
    assert!(entry.lane_type.is_none());
    assert!(entry.error_code.is_none());
}

#[test]
fn enrichment_gate_log_entry_serde_roundtrip() {
    let entry = GateLogEntry {
        trace_id: "t-serde".to_string(),
        component: GATE_COMPONENT.to_string(),
        lane_type: Some(LaneType::Fallback),
        event: "fallback_test_proof_failure".to_string(),
        outcome: "pass".to_string(),
        workload_id: Some("w99".to_string()),
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: Some(true),
        wall_time_ns: Some(3000),
        memory_peak_bytes: None,
        error_code: Some("FALLBACK_FAILED".to_string()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: GateLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// GateSummary — construction, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_summary_construction() {
    let summary = GateSummary {
        mean_throughput_delta_millionths: 200_000,
        mean_latency_p95_improvement_millionths: 100_000,
        mean_memory_improvement_millionths: 50_000,
        workloads_with_positive_delta: 10,
        total_workloads: 12,
        fallback_tests_passed: 4,
        fallback_tests_total: 4,
    };
    assert_eq!(summary.mean_throughput_delta_millionths, 200_000);
    assert_eq!(summary.total_workloads, 12);
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let summary = GateSummary {
        mean_throughput_delta_millionths: -10_000,
        mean_latency_p95_improvement_millionths: 0,
        mean_memory_improvement_millionths: 300_000,
        workloads_with_positive_delta: 5,
        total_workloads: 10,
        fallback_tests_passed: 3,
        fallback_tests_total: 4,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// ReceiptCoverageReport — construction, serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_coverage_report_construction() {
    let rpt = ReceiptCoverageReport {
        total_decisions: 10,
        covered_decisions: 8,
        coverage_millionths: 800_000,
        unverified_receipts: vec!["bad-1".to_string()],
        receipt_refs: vec![make_receipt("r1", true)],
    };
    assert_eq!(rpt.total_decisions, 10);
    assert_eq!(rpt.covered_decisions, 8);
    assert_eq!(rpt.unverified_receipts.len(), 1);
}

#[test]
fn enrichment_receipt_coverage_report_serde_roundtrip() {
    let rpt = ReceiptCoverageReport {
        total_decisions: 5,
        covered_decisions: 5,
        coverage_millionths: 1_000_000,
        unverified_receipts: vec![],
        receipt_refs: verified_receipts(3),
    };
    let json = serde_json::to_string(&rpt).unwrap();
    let back: ReceiptCoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(rpt, back);
}

// ---------------------------------------------------------------------------
// evaluate_gate — passing case
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_passes_with_all_criteria_met() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(result.outcome.is_pass());
    assert!(result.blockers.is_empty());
    assert_eq!(result.workload_count, 12);
    assert_eq!(result.schema_version, GATE_SCHEMA_VERSION);
    assert_eq!(result.run_id, "enrichment-run");
    assert_eq!(result.epoch, epoch(1));
}

#[test]
fn enrichment_gate_evidence_hash_deterministic() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);

    let r1 = evaluate_gate(&input).unwrap();
    let r2 = evaluate_gate(&input).unwrap();
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn enrichment_gate_different_run_ids_different_hashes() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();

    let input1 = GateInput {
        run_id: "run-A",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let input2 = GateInput {
        run_id: "run-B",
        ..input1
    };

    let r1 = evaluate_gate(&input1).unwrap();
    let r2 = evaluate_gate(&input2).unwrap();
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn enrichment_gate_summary_statistics_correct() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert_eq!(result.summary.total_workloads, 12);
    assert_eq!(result.summary.workloads_with_positive_delta, 12);
    assert_eq!(result.summary.fallback_tests_passed, 4);
    assert_eq!(result.summary.fallback_tests_total, 4);
    // 1200 vs 1000 = 200/1000 = 200_000 millionths
    assert_eq!(result.summary.mean_throughput_delta_millionths, 200_000);
}

#[test]
fn enrichment_gate_receipt_coverage_report_on_pass() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert_eq!(result.receipt_coverage.total_decisions, 5);
    assert_eq!(result.receipt_coverage.covered_decisions, 5);
    assert_eq!(result.receipt_coverage.coverage_millionths, 1_000_000);
    assert!(result.receipt_coverage.unverified_receipts.is_empty());
    assert_eq!(result.receipt_coverage.receipt_refs.len(), 5);
}

// ---------------------------------------------------------------------------
// evaluate_gate — failure cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_error_empty_specialized_metrics() {
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "err-test",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &[],
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let err = evaluate_gate(&input).unwrap_err();
    assert!(matches!(err, GateError::EmptyWorkloads));
}

#[test]
fn enrichment_gate_error_empty_ambient_metrics() {
    let spec = specialized_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "err-test",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &[],
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let err = evaluate_gate(&input).unwrap_err();
    assert!(matches!(err, GateError::EmptyWorkloads));
}

#[test]
fn enrichment_gate_fails_insufficient_workloads() {
    let spec = specialized_metrics(5); // below MIN_WORKLOAD_COUNT (10)
    let amb = ambient_metrics(5);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientWorkloads {
            required: 10,
            actual: 5
        }
    )));
}

#[test]
fn enrichment_gate_fails_output_divergence() {
    let mut spec = specialized_metrics(12);
    spec[3].output_digest = digest("diverged");
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::OutputDivergence { workload_id } if workload_id == "workload_3"
    )));
}

#[test]
fn enrichment_gate_fails_workload_mismatch() {
    let mut spec = specialized_metrics(12);
    spec[0].workload_id = "extra_workload".to_string();
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::WorkloadMismatch { missing_workload_ids }
            if missing_workload_ids.contains(&"extra_workload".to_string())
    )));
}

#[test]
fn enrichment_gate_fails_insufficient_samples_specialized() {
    let mut spec = specialized_metrics(12);
    spec[0].sample_count = 2; // below MIN_SAMPLE_COUNT (5)
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientSamples {
            lane_type: LaneType::ProofSpecialized,
            sample_count: 2,
            ..
        }
    )));
}

#[test]
fn enrichment_gate_fails_insufficient_samples_ambient() {
    let spec = specialized_metrics(12);
    let mut amb = ambient_metrics(12);
    amb[5].sample_count = 1;
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientSamples {
            lane_type: LaneType::AmbientAuthority,
            sample_count: 1,
            ..
        }
    )));
}

#[test]
fn enrichment_gate_fails_no_positive_delta() {
    // Same throughput/latency/memory — no improvement
    let spec: Vec<WorkloadMetrics> = (0..12)
        .map(|i| {
            make_metrics(
                &format!("workload_{i}"),
                LaneType::ProofSpecialized,
                1000,
                1000,
                5000,
                "canonical",
            )
        })
        .collect();
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result
        .blockers
        .iter()
        .any(|b| matches!(b, GateBlocker::NoPositiveDelta { .. })));
}

#[test]
fn enrichment_gate_fails_insufficient_receipt_coverage() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(3); // only 3 for 10 decisions
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "test",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 10,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths
        } if *coverage_millionths == 300_000
    )));
}

#[test]
fn enrichment_gate_fails_unverified_receipt() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let mut receipts = verified_receipts(5);
    receipts[2].signature_verified = false;
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "test",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result
        .blockers
        .iter()
        .any(|b| matches!(b, GateBlocker::UnverifiedReceipt { .. })));
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientReceiptCoverage { .. }
    )));
}

#[test]
fn enrichment_gate_fails_fallback_test_incorrect_output() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = vec![make_fallback_fail("workload_0", InjectionKind::ProofFailure)];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::FallbackTestFailed { reason, .. } if reason == "incorrect output"
    )));
}

#[test]
fn enrichment_gate_fails_fallback_test_crash() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let mut fb = make_fallback_pass("workload_0", InjectionKind::ProofFailure);
    fb.crash_or_hang = true;
    let fallbacks = vec![fb];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::FallbackTestFailed { reason, .. } if reason == "crash or hang"
    )));
}

#[test]
fn enrichment_gate_fails_fallback_test_no_receipt() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let mut fb = make_fallback_pass("workload_0", InjectionKind::ProofFailure);
    fb.fallback_receipt_emitted = false;
    let fallbacks = vec![fb];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::FallbackTestFailed { reason, .. } if reason == "no fallback receipt"
    )));
}

#[test]
fn enrichment_gate_fails_fallback_test_digest_mismatch() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let mut fb = make_fallback_pass("workload_0", InjectionKind::ProofFailure);
    fb.correct_output = true;
    fb.fallback_receipt_emitted = true;
    fb.crash_or_hang = false;
    fb.fallback_output_digest = digest("different_output");
    // expected_output_digest stays as "canonical_output"
    let fallbacks = vec![fb];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::FallbackTestFailed { reason, .. } if reason == "output digest mismatch"
    )));
}

#[test]
fn enrichment_gate_fails_fallback_performance_regression() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let mut fb = make_fallback_pass("workload_0", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 2000; // 100% slower
    let fallbacks = vec![fb];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::FallbackPerformanceRegression { .. }
    )));
}

// ---------------------------------------------------------------------------
// evaluate_gate — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_zero_specialization_decisions_vacuous_coverage() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts: Vec<ReceiptRef> = Vec::new();
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "vacuous",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 0,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();
    assert_eq!(
        result.receipt_coverage.coverage_millionths,
        REQUIRED_COVERAGE_MILLIONTHS
    );
}

#[test]
fn enrichment_gate_significance_threshold_blocks_marginal_improvement() {
    // 1% improvement, but threshold is 5%
    let spec: Vec<WorkloadMetrics> = (0..12)
        .map(|i| {
            make_metrics(
                &format!("workload_{i}"),
                LaneType::ProofSpecialized,
                1010,
                990,
                4950,
                "canonical",
            )
        })
        .collect();
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "marginal",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 50_000, // 5%
    };
    let result = evaluate_gate(&input).unwrap();
    assert!(!result.outcome.is_pass());
}

#[test]
fn enrichment_gate_significance_threshold_zero_allows_any_positive_delta() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = GateInput {
        run_id: "zero-threshold",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();
    assert!(result.outcome.is_pass());
}

#[test]
fn enrichment_gate_multiple_blockers_accumulated() {
    let mut spec = specialized_metrics(3);
    spec[0].output_digest = digest("diverged");
    let amb = ambient_metrics(3);
    let receipts: Vec<ReceiptRef> = Vec::new();
    let fallbacks = vec![make_fallback_fail("w1", InjectionKind::ProofFailure)];
    let input = GateInput {
        run_id: "multi-fail",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 10,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    // Should have at least: InsufficientWorkloads, OutputDivergence,
    // InsufficientReceiptCoverage, FallbackTestFailed
    assert!(result.blockers.len() >= 4);
}

#[test]
fn enrichment_gate_no_fallback_results_still_evaluates() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks: Vec<FallbackTestResult> = Vec::new();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert_eq!(result.summary.fallback_tests_total, 0);
    assert_eq!(result.summary.fallback_tests_passed, 0);
    assert!(result.fallback_results.is_empty());
}

#[test]
fn enrichment_gate_performance_deltas_count_matches_matched_workloads() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert_eq!(result.performance_deltas.len(), 12);
}

#[test]
fn enrichment_gate_mismatched_workloads_reduce_delta_count() {
    let mut spec = specialized_metrics(12);
    spec[0].workload_id = "unknown_workload".to_string();
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    // Only 11 of 12 specialized workloads match ambient workloads
    assert_eq!(result.performance_deltas.len(), 11);
}

// ---------------------------------------------------------------------------
// passes_release_gate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_passes_release_gate_on_pass() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    assert!(passes_release_gate(&result));
}

#[test]
fn enrichment_passes_release_gate_on_fail() {
    let spec = specialized_metrics(3);
    let amb = ambient_metrics(3);
    let receipts = verified_receipts(3);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    assert!(!passes_release_gate(&result));
}

// ---------------------------------------------------------------------------
// generate_log_entries
// ---------------------------------------------------------------------------

#[test]
fn enrichment_log_entries_summary_entry_first() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-enrich", &result);

    assert!(!entries.is_empty());
    assert_eq!(entries[0].event, "gate_evaluation_complete");
    assert_eq!(entries[0].outcome, "PASS");
    assert_eq!(entries[0].component, GATE_COMPONENT);
    assert_eq!(entries[0].trace_id, "trace-enrich");
    assert!(entries[0].lane_type.is_none());
    assert!(entries[0].error_code.is_none());
}

#[test]
fn enrichment_log_entries_per_workload_delta() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &result);

    let delta_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event == "workload_delta")
        .collect();
    assert_eq!(delta_entries.len(), 12);
    for de in &delta_entries {
        assert_eq!(de.lane_type, Some(LaneType::ProofSpecialized));
        assert_eq!(de.outcome, "positive");
        assert!(de.workload_id.is_some());
    }
}

#[test]
fn enrichment_log_entries_fallback_entries() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-fb", &result);

    let fb_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event.starts_with("fallback_test_"))
        .collect();
    assert_eq!(fb_entries.len(), 4);
    for fe in &fb_entries {
        assert_eq!(fe.lane_type, Some(LaneType::Fallback));
        assert_eq!(fe.fallback_triggered, Some(true));
        assert!(fe.wall_time_ns.is_some());
    }
}

#[test]
fn enrichment_log_entries_count_summary_plus_deltas_plus_fallbacks() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-count", &result);

    // 1 summary + 12 deltas + 4 fallbacks = 17
    assert_eq!(entries.len(), 17);
}

#[test]
fn enrichment_log_entries_failure_has_gate_failed_error_code() {
    let spec = specialized_metrics(3);
    let amb = ambient_metrics(3);
    let receipts = verified_receipts(3);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-fail", &result);

    assert_eq!(entries[0].outcome, "FAIL");
    assert_eq!(entries[0].error_code, Some("GATE_FAILED".to_string()));
}

#[test]
fn enrichment_log_entries_negative_delta_outcome() {
    // All neutral — no positive delta
    let spec: Vec<WorkloadMetrics> = (0..12)
        .map(|i| {
            make_metrics(
                &format!("workload_{i}"),
                LaneType::ProofSpecialized,
                1000,
                1000,
                5000,
                "canonical",
            )
        })
        .collect();
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-neutral", &result);

    let delta_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event == "workload_delta")
        .collect();
    for de in &delta_entries {
        assert_eq!(de.outcome, "neutral_or_negative");
    }
}

#[test]
fn enrichment_log_entries_failed_fallback_has_error_code() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = vec![make_fallback_fail("workload_0", InjectionKind::ProofFailure)];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-fb-fail", &result);

    let fb_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event.starts_with("fallback_test_"))
        .collect();
    assert_eq!(fb_entries.len(), 1);
    assert_eq!(fb_entries[0].outcome, "fail");
    assert_eq!(
        fb_entries[0].error_code,
        Some("FALLBACK_FAILED".to_string())
    );
}

#[test]
fn enrichment_log_entries_no_fallbacks_only_summary_and_deltas() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks: Vec<FallbackTestResult> = Vec::new();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-no-fb", &result);

    // 1 summary + 12 deltas + 0 fallbacks = 13
    assert_eq!(entries.len(), 13);
}

// ---------------------------------------------------------------------------
// GateEvidenceBundle — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_evidence_bundle_serde_roundtrip() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_gate_evidence_bundle_failing_serde_roundtrip() {
    let spec = specialized_metrics(3);
    let amb = ambient_metrics(3);
    let receipts = verified_receipts(3);
    let fallbacks = vec![make_fallback_fail("workload_0", InjectionKind::ProofFailure)];
    let input = passing_input(&spec, &amb, &receipts, &fallbacks);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Cross-cutting: evidence hash stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_hash_changes_with_epoch() {
    let spec = specialized_metrics(12);
    let amb = ambient_metrics(12);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();

    let input1 = GateInput {
        run_id: "run",
        trace_id: "t",
        epoch: epoch(1),
        specialized_metrics: &spec,
        ambient_metrics: &amb,
        receipts: &receipts,
        total_specialization_decisions: 5,
        fallback_results: &fallbacks,
        significance_threshold_millionths: 0,
    };
    let input2 = GateInput {
        epoch: epoch(2),
        ..input1
    };

    let r1 = evaluate_gate(&input1).unwrap();
    let r2 = evaluate_gate(&input2).unwrap();
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn enrichment_evidence_hash_changes_with_outcome() {
    let spec_pass = specialized_metrics(12);
    let spec_fail = specialized_metrics(3);
    let amb_pass = ambient_metrics(12);
    let amb_fail = ambient_metrics(3);
    let receipts = verified_receipts(5);
    let fallbacks = all_fallbacks();

    let input_pass = passing_input(&spec_pass, &amb_pass, &receipts, &fallbacks);
    let input_fail = passing_input(&spec_fail, &amb_fail, &receipts, &fallbacks);

    let r_pass = evaluate_gate(&input_pass).unwrap();
    let r_fail = evaluate_gate(&input_fail).unwrap();

    assert!(r_pass.outcome.is_pass());
    assert!(!r_fail.outcome.is_pass());
    assert_ne!(r_pass.evidence_hash, r_fail.evidence_hash);
}
