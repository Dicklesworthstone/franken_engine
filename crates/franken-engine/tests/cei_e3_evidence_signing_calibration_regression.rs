//! CEI E.3 (`bd-sde5e.5.3`): regression locks for the two E-track correctness
//! fixes, asserted from *outside* the implementing modules so a silent revert of
//! the fix can no longer also "adjust" a co-located unit test.
//!
//!  * E.2 (`bd-sde5e.5.2`): change-point / divergence evidence must never be
//!    emitted unsigned — every emitted `ChangeDetected` carries a 64-byte
//!    detached Ed25519 signature, and the signing facility reports wired.
//!  * E.1 (`bd-sde5e.5.1`): conformal calibration must fail **closed** on
//!    insufficient data — `is_calibrated()` is conservative and the tri-state
//!    `CalibrationStatus` distinguishes "not enough data" from "measured and out
//!    of tolerance".
//!
//! Full cryptographic verification of the signature against the engine's shared
//! key lives in the module's inline test (the verification key is `pub(crate)`);
//! these external locks assert the structural property the bead names — evidence
//! is never emitted unsigned — plus the calibration fail-closed contract.

use frankenengine_engine::change_point_detector::{
    ChangePointDetector, ChangePointVerdict, CompositeAlternative,
};
use frankenengine_engine::runtime_decision_theory::{
    CalibrationStatus, ConformalCalibrator, ConformalConfig,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SIGNATURE_LEN;

// ---------------------------------------------------------------------------
// E.2 — change-point / divergence evidence is never emitted unsigned
// ---------------------------------------------------------------------------

/// A normal mean-shift alternative that detects quickly under a sustained shift.
fn quick_detect_detector() -> ChangePointDetector {
    ChangePointDetector::new(
        "cei-e3-regression",
        CompositeAlternative::NormalMeanShift {
            pre_change_mean_millionths: 0,
            variance_millionths_squared: 1_000_000,
            mean_range_millionths: (500_000, 2_000_000),
        },
        500_000, // low CUSUM threshold for a quick, deterministic detection
        SecurityEpoch::from_raw(1),
    )
}

/// Drive the detector to a real detection and return the emitted verdict.
fn drive_to_detection() -> ChangePointVerdict {
    let mut detector = quick_detect_detector();
    for i in 1..=32u64 {
        let verdict = detector
            .process_observation(2_000_000, i * 1_000_000)
            .expect("process_observation must succeed");
        if verdict.is_change_detected() {
            return verdict;
        }
    }
    panic!("a sustained mean shift must trigger a change-point detection");
}

#[test]
fn change_point_signing_facility_stays_wired() {
    assert!(
        ChangePointVerdict::evidence_signing_wired(),
        "regression: change-point evidence signing must stay wired (E.2 / bd-k2bz7)"
    );
}

#[test]
fn emitted_change_point_evidence_is_never_unsigned() {
    let verdict = drive_to_detection();
    let ChangePointVerdict::ChangeDetected {
        signed_evidence, ..
    } = verdict
    else {
        panic!("expected ChangeDetected");
    };

    let sig = signed_evidence.expect("regression: emitted detection must carry signed_evidence");
    assert_eq!(
        sig.len(),
        SIGNATURE_LEN,
        "regression: signature must be a {SIGNATURE_LEN}-byte detached Ed25519 signature"
    );
    assert!(
        sig.iter().any(|&b| b != 0),
        "regression: signature must not be an all-zero placeholder"
    );
}

// ---------------------------------------------------------------------------
// E.1 — conformal calibration fails closed on insufficient data
// ---------------------------------------------------------------------------

fn calibrator() -> (ConformalCalibrator, u64) {
    let config = ConformalConfig::default();
    let min = config.min_calibration_observations;
    (ConformalCalibrator::new(config), min)
}

#[test]
fn calibration_fails_closed_on_insufficient_data() {
    let (mut cal, min) = calibrator();
    assert!(min >= 1, "min_calibration_observations should be positive");

    // Record fewer than `min` perfectly-covered predictions: even though every
    // one was covered, coverage cannot be *asserted* on too little data.
    for i in 0..(min - 1) {
        cal.record(SecurityEpoch::from_raw(i + 1), true);
    }
    assert!(
        !cal.is_calibrated(),
        "regression: is_calibrated() must fail closed below min observations (E.1)"
    );
    assert_eq!(
        cal.calibration_status(),
        CalibrationStatus::InsufficientData,
        "regression: status must be InsufficientData below min observations (E.1)"
    );
}

#[test]
fn calibration_tri_state_distinguishes_measured_outcomes() {
    let alpha = ConformalConfig::default().alpha_millionths;
    assert!(alpha > 0 && alpha < 1_000_000, "alpha must be a fraction");

    // Enough data, perfect coverage -> measured pass.
    let (mut good, min) = calibrator();
    let n = min + 50;
    for i in 0..n {
        good.record(SecurityEpoch::from_raw(i + 1), true);
    }
    assert_eq!(good.calibration_status(), CalibrationStatus::Calibrated);
    assert!(good.is_calibrated(), "measured-good must be calibrated");

    // Enough data, deliberately poor coverage (~50%) -> measured failure that is
    // NOT mistaken for InsufficientData.
    let (mut bad, _) = calibrator();
    for i in 0..n {
        bad.record(SecurityEpoch::from_raw(i + 1), i % 2 == 0);
    }
    assert_eq!(
        bad.calibration_status(),
        CalibrationStatus::OutOfTolerance,
        "regression: enough data + poor coverage is OutOfTolerance, not InsufficientData (E.1)"
    );
    assert!(
        !bad.is_calibrated(),
        "regression: is_calibrated() stays conservative when out of tolerance (E.1)"
    );
}
