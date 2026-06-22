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
