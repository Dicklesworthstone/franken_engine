//! Integration test wiring the measured Node/Bun denominator bundle
//! (`docs/perf/e2_denominator_bundle_v1/`, bd-fqlfw.2.6) through the real
//! `benchmark_freshness_gate` so that the bead's acceptance criterion —
//! "stale denominators are rejected by the freshness gate" — is enforced by an
//! executable, not by prose.
//!
//! The freshness gate's `DEFAULT_MIN_ACQUISITION_SAMPLES` (10) is exactly the
//! sample floor the denominator must clear; these tests show a denominator that
//! meets the floor stays admissible while a stale / under-sampled / drifted one
//! is downgraded and has rollout blocked.

use std::path::PathBuf;
use std::process::Command;

use frankenengine_engine::benchmark_freshness_gate::{
    AcquisitionEvidence, AcquisitionStatus, BenchmarkClaim, ClaimSurface,
    DEFAULT_MIN_ACQUISITION_SAMPLES, FIXED_ONE, FreshnessGate, FreshnessLevel, ShiftAlarm,
    ShiftDomain, ShiftSeverity,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

const PERF_DOMAIN: ShiftDomain = ShiftDomain::General;

fn perf_claim(epoch: SecurityEpoch) -> BenchmarkClaim {
    BenchmarkClaim::new(
        "FE-CLAIM-010",
        ClaimSurface::Performance,
        FIXED_ONE, // original confidence = 1.0 in millionths
        epoch,
        "Node/Bun denominator throughput floor (>= 3x)",
    )
    .with_domain(PERF_DOMAIN)
}

/// A denominator with no detected workload shift is fresh: full confidence,
/// rollout permitted. (Low epoch keeps the silence tracker quiet without any
/// recorded signal.)
#[test]
fn fresh_denominator_claim_is_full_confidence() {
    let epoch = SecurityEpoch::from_raw(5);
    let mut gate = FreshnessGate::new(epoch);
    let claim = perf_claim(epoch);

    let verdict = gate.evaluate_claim(&claim);

    assert_eq!(verdict.freshness, FreshnessLevel::Fresh, "{verdict:?}");
    assert!(verdict.is_full_confidence());
    assert!(!verdict.is_downgraded());
    assert_eq!(verdict.adjusted_confidence, claim.original_confidence);
    assert!(
        verdict.rollout_permitted,
        "fresh denominator must permit rollout"
    );
}

/// A denominator whose corpus has shifted (Warning) but whose acquisition
/// response is BELOW the sample floor is stale: downgraded and rollout-blocked.
/// This is the "stale denominator is rejected" path.
#[test]
fn undersampled_denominator_is_rejected() {
    let epoch = SecurityEpoch::from_raw(10);
    let mut gate = FreshnessGate::new(epoch);

    gate.record_alarm(ShiftAlarm::new(
        "shift-perf-1",
        PERF_DOMAIN,
        ShiftSeverity::Warning,
        epoch,
        600_000,
        "workload regime drift in the denominator corpus",
    ));
    // Acquisition response gathered only 3 samples — under the 10-sample floor.
    let undersampled = AcquisitionEvidence::new(
        PERF_DOMAIN,
        3,
        DEFAULT_MIN_ACQUISITION_SAMPLES,
        AcquisitionStatus::Active,
        epoch,
        1_000_000,
    );
    assert!(
        !undersampled.supports_freshness(DEFAULT_MIN_ACQUISITION_SAMPLES),
        "3 samples must not clear the floor"
    );
    gate.record_acquisition(undersampled);

    let verdict = gate.evaluate_claim(&perf_claim(epoch));

    assert_eq!(verdict.freshness, FreshnessLevel::Stale, "{verdict:?}");
    assert!(verdict.is_downgraded());
    assert!(
        !verdict.rollout_permitted,
        "a stale/under-sampled denominator must NOT permit rollout"
    );
}

/// The same shift, but the acquisition response now MEETS the sample floor
/// (10 measured iterations — exactly what the committed bundle records): the
/// claim recovers to aging (downgraded but rollout-conditional), proving the
/// floor is the load-bearing knob.
#[test]
fn floor_sampled_denominator_recovers_to_aging() {
    let epoch = SecurityEpoch::from_raw(10);
    let mut gate = FreshnessGate::new(epoch);

    gate.record_alarm(ShiftAlarm::new(
        "shift-perf-2",
        PERF_DOMAIN,
        ShiftSeverity::Warning,
        epoch,
        600_000,
        "workload regime drift in the denominator corpus",
    ));
    let floor_sampled = AcquisitionEvidence::new(
        PERF_DOMAIN,
        DEFAULT_MIN_ACQUISITION_SAMPLES, // exactly the floor (== measured_iterations)
        DEFAULT_MIN_ACQUISITION_SAMPLES,
        AcquisitionStatus::Active,
        epoch,
        1_000_000,
    );
    assert!(floor_sampled.supports_freshness(DEFAULT_MIN_ACQUISITION_SAMPLES));
    gate.record_acquisition(floor_sampled);

    let verdict = gate.evaluate_claim(&perf_claim(epoch));

    assert_eq!(verdict.freshness, FreshnessLevel::Aging, "{verdict:?}");
    assert!(verdict.is_downgraded());
    assert!(
        verdict.rollout_permitted,
        "a floor-sampled aging denominator is rollout-conditional"
    );
}

/// A fundamental (Emergency) workload shift with no acquisition response
/// invalidates the claim outright: zero confidence, rollout blocked.
#[test]
fn emergency_drift_invalidates_denominator() {
    let epoch = SecurityEpoch::from_raw(10);
    let mut gate = FreshnessGate::new(epoch);

    gate.record_alarm(ShiftAlarm::new(
        "shift-perf-3",
        PERF_DOMAIN,
        ShiftSeverity::Emergency,
        epoch,
        1_000_000,
        "complete regime change — denominator no longer representative",
    ));

    let verdict = gate.evaluate_claim(&perf_claim(epoch));

    assert_eq!(verdict.freshness, FreshnessLevel::Invalid, "{verdict:?}");
    assert_eq!(verdict.adjusted_confidence, 0);
    assert!(!verdict.rollout_permitted);
}

/// Silence (no signals for longer than the timeout) is itself stale.
#[test]
fn silent_gate_is_stale() {
    // No recorded signal + current epoch far past the silence timeout (50).
    let mut gate = FreshnessGate::new(SecurityEpoch::from_raw(500));
    let verdict = gate.evaluate_claim(&perf_claim(SecurityEpoch::from_raw(500)));
    assert_eq!(verdict.freshness, FreshnessLevel::Stale, "{verdict:?}");
    assert!(!verdict.rollout_permitted);
}

fn bundle_denominator_path() -> PathBuf {
    // CARGO_MANIFEST_DIR == crates/franken-engine
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/perf/e2_denominator_bundle_v1/denominator.json")
}

/// The committed denominator bundle clears the freshness sample floor and
/// carries an honest (present) meets_3x_floor verdict for both baselines.
#[test]
fn committed_bundle_clears_sample_floor() {
    let path = bundle_denominator_path();
    if !path.is_file() {
        // Bundle not generated in this checkout (e.g. partial clone); the
        // synthetic tests above still enforce the gate contract.
        eprintln!(
            "skipping: committed bundle not present at {}",
            path.display()
        );
        return;
    }
    let text = std::fs::read_to_string(&path).expect("read denominator.json");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("parse denominator.json");

    let samples = doc["measurement"]["measured_iterations"]
        .as_u64()
        .expect("measured_iterations present");
    assert!(
        samples >= DEFAULT_MIN_ACQUISITION_SAMPLES,
        "committed denominator measured {samples} iterations; floor is {DEFAULT_MIN_ACQUISITION_SAMPLES}"
    );

    // Model the committed denominator as an acquisition record and confirm it
    // supports freshness at the gate's configured floor.
    let evidence = AcquisitionEvidence::new(
        PERF_DOMAIN,
        samples,
        DEFAULT_MIN_ACQUISITION_SAMPLES,
        AcquisitionStatus::Complete,
        SecurityEpoch::from_raw(1),
        1_000_000,
    );
    assert!(evidence.supports_freshness(DEFAULT_MIN_ACQUISITION_SAMPLES));

    // The matrix-relevant verdict must be present (honest), regardless of value.
    assert!(
        doc["node_denominator"]["meets_3x_floor"].is_boolean()
            || doc["node_denominator"]["meets_3x_floor"].is_null(),
        "node meets_3x_floor must be a present verdict field"
    );
    assert!(
        doc["bun_denominator"]["meets_3x_floor"].is_boolean()
            || doc["bun_denominator"]["meets_3x_floor"].is_null(),
        "bun meets_3x_floor must be a present verdict field"
    );

    // For a published bundle the status must be explicit.
    let status = doc["bundle_status"].as_str().unwrap_or("");
    assert!(
        status == "published" || status == "degraded",
        "bundle_status must be published|degraded, got {status}"
    );
}

/// The v3 bundle builder must not trust producer-declared iteration counts or
/// lifecycle equivalence. Exercise its Python validator entirely in memory so
/// this test creates no replacement bundle or temporary evidence files.
#[test]
fn v3_builder_rejects_truncated_or_inconsistent_raw_measurements() {
    let builder = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/build_e2_denominator_bundle.py");
    let program = r#"
import copy
import runpy
import sys

builder = runpy.run_path(sys.argv[1])
validator = builder["validate_v3_report"]
interpretation_lines = builder["interpretation_lines"]
build_correctness_verdicts = builder["build_correctness_verdicts"]
correctness_verdict_hash = builder["correctness_verdict_hash"]
measurement_evidence_view = builder["measurement_evidence_view"]
reproduction_perf_command = builder["reproduction_perf_command"]
digest = "a" * 64

def lane(name):
    result = {
        "backend": name,
        "status": "measured",
        "preparation_ns": 1,
        "warmup_ns": [10],
        "measured_ns": [20, 21],
        "warmup_observation_sha256": [digest],
        "measured_observation_sha256": [digest, digest],
        "observations_complete": True,
        "stats": {
            "sample_count": 2,
            "mean_ns": 20,
            "stddev_ns": 1,
            "cv_millionths": 50000,
            "ci95_lower_ns": 19,
            "ci95_upper_ns": 21,
            "min_ns": 20,
            "max_ns": 21,
        },
        "diagnostics": [],
    }
    return result

engine = lane("franken_engine")
engine["engine_kind"] = "quick_js_inspired_native"
engine["route_reason"] = "default_quick_js_path"
case = {
    "case_id": "fixture",
    "source_sha256": "0" * 64,
    "behavior_equivalent": True,
    "measured_lifecycle_equivalent": True,
    "measured_lifecycle_detail": "fixture",
    "engine": engine,
    "node": lane("node_lts"),
    "bun": lane("bun_stable"),
    "node_over_engine_speedup_millionths": 1000000,
    "bun_over_engine_speedup_millionths": 1000000,
    "admitted": True,
    "exclusion_reasons": [],
}
denominator = {
    "baseline": "node",
    "admitted_cases": 1,
    "excluded_cases": 0,
    "geomean_speedup_millionths": None,
    "meets_3x_floor": None,
    "status": "degraded",
    "degraded_reasons": ["lifecycle asymmetry"],
}
report = {
    "environment": {
        "engine_execution_lifecycle": "prepare_once_fresh_router_and_interpreter_core_per_iteration",
        "external_execution_lifecycle": "new_function_once_single_process_shared_realm_and_jit_state",
        "warmup_iterations": 1,
        "measured_iterations": 2,
        "max_cv_millionths": 150000,
        "corpus_case_count": 1,
    },
    "fairness": {"compliant": False, "violations": ["asymmetric"]},
    "cases": [case],
    "node_denominator": copy.deepcopy(denominator),
    "bun_denominator": copy.deepcopy(denominator),
}
report["bun_denominator"]["baseline"] = "bun"
assert validator(report) == [], validator(report)
repro_command = reproduction_perf_command(
    "benchmarks/runtime_comparison/manifest.json",
    "release-perf",
    report["environment"],
    report["cases"],
)
assert repro_command.startswith("target/release-perf/frankenctl "), repro_command
assert repro_command.endswith("--case fixture"), repro_command
degraded_interpretation = " ".join(
    interpretation_lines(report["node_denominator"], report["bun_denominator"])
)
assert "NOT EVALUABLE" in degraded_interpretation, degraded_interpretation
assert "backed by real numbers" not in degraded_interpretation, degraded_interpretation

# Timing/CV admission is measurement evidence, not correctness identity.
admission_flipped = copy.deepcopy(case)
admission_flipped["admitted"] = False
original_verdicts = build_correctness_verdicts([case])
flipped_verdicts = build_correctness_verdicts([admission_flipped])
assert "admitted" not in original_verdicts[0], original_verdicts
assert correctness_verdict_hash(original_verdicts) == correctness_verdict_hash(flipped_verdicts)
assert measurement_evidence_view([case])[0]["admitted"] is True
assert measurement_evidence_view([admission_flipped])[0]["admitted"] is False

truncated = copy.deepcopy(report)
truncated["cases"][0]["node"]["measured_ns"].pop()
assert any("count" in error or "lengths differ" in error for error in validator(truncated))

changing = copy.deepcopy(report)
changing["cases"][0]["node"]["measured_observation_sha256"][1] = "b" * 64
assert any("disagrees with raw observations" in error for error in validator(changing))

malformed = copy.deepcopy(report)
malformed["cases"][0]["bun"]["measured_observation_sha256"][0] = "not-a-digest"
assert any("lowercase hex64" in error for error in validator(malformed))

# Baseline admission is intentionally asymmetric: a noisy Bun lane does not
# remove an otherwise valid Node comparison.
asymmetric = copy.deepcopy(report)
asymmetric_case = asymmetric["cases"][0]
asymmetric_case["bun"]["measured_ns"] = [20, 40]
asymmetric_case["bun"]["stats"] = {
    "sample_count": 2,
    "mean_ns": 30,
    "stddev_ns": 14,
    "cv_millionths": 466666,
    "ci95_lower_ns": 11,
    "ci95_upper_ns": 49,
    "min_ns": 20,
    "max_ns": 40,
}
asymmetric_case["bun_over_engine_speedup_millionths"] = 1500000
asymmetric_case["admitted"] = False
asymmetric["node_denominator"]["admitted_cases"] = 1
asymmetric["node_denominator"]["excluded_cases"] = 0
asymmetric["bun_denominator"]["admitted_cases"] = 0
asymmetric["bun_denominator"]["excluded_cases"] = 1
asymmetric["bun_denominator"]["degraded_reasons"] = ["no admissible Bun cases"]
assert validator(asymmetric) == [], validator(asymmetric)

fabricated_publication = copy.deepcopy(report)
fabricated_publication["fairness"] = {"compliant": True, "violations": []}
for name in ("node_denominator", "bun_denominator"):
    fabricated_publication[name]["status"] = "published"
    fabricated_publication[name]["geomean_speedup_millionths"] = 1000000
    fabricated_publication[name]["meets_3x_floor"] = False
assert any("fairness-degraded" in error for error in validator(fabricated_publication))
"#;

    let output = Command::new("python3")
        .arg("-c")
        .arg(program)
        .arg(&builder)
        .output()
        .expect("python3 must be available for the denominator builder gate");
    assert!(
        output.status.success(),
        "v3 validator self-check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
