#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_engine::runtime_decision_theory::{ConformalCalibrator, ConformalConfig};
use frankenengine_engine::security_epoch::SecurityEpoch;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_EVENTS: usize = 512;
const MILLION: i64 = 1_000_000;
const MAX_E_VALUE_MILLIONTHS: i64 = 1_000_000_000_000;

#[derive(Debug)]
struct FuzzConfig {
    alpha_millionths: i64,
    min_calibration_observations: u64,
    max_consecutive_violations: u64,
}

#[derive(Debug)]
struct FuzzCase {
    config: FuzzConfig,
    events: Vec<bool>,
    reset_points: Vec<u16>,
}

impl<'a> Arbitrary<'a> for FuzzConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            alpha_millionths: i64::arbitrary(u)?,
            min_calibration_observations: u64::arbitrary(u)?,
            max_consecutive_violations: u64::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for FuzzCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            config: FuzzConfig::arbitrary(u)?,
            events: Vec::<bool>::arbitrary(u)?,
            reset_points: Vec::<u16>::arbitrary(u)?,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(case) = FuzzCase::arbitrary(&mut unstructured) else {
        return;
    };

    exercise_case(normalize_case(case));
});

fn normalize_case(mut case: FuzzCase) -> FuzzCase {
    case.config.alpha_millionths = normalize_alpha(case.config.alpha_millionths);
    case.config.min_calibration_observations = case
        .config
        .min_calibration_observations
        .min(MAX_EVENTS as u64);
    case.config.max_consecutive_violations = case
        .config
        .max_consecutive_violations
        .clamp(1, MAX_EVENTS as u64);
    case.events.truncate(MAX_EVENTS);
    case.reset_points.truncate(MAX_EVENTS);
    case.reset_points.sort_unstable();
    case.reset_points.dedup();
    case
}

fn normalize_alpha(raw: i64) -> i64 {
    let bounded = raw.rem_euclid(MILLION - 1);
    bounded + 1
}

fn exercise_case(case: FuzzCase) {
    let config = ConformalConfig {
        alpha_millionths: case.config.alpha_millionths,
        min_calibration_observations: case.config.min_calibration_observations,
        max_consecutive_violations: case.config.max_consecutive_violations,
    };
    let mut calibrator = ConformalCalibrator::new(config.clone());
    let mut expected_total = 0_u64;
    let mut expected_covered = 0_u64;

    assert_calibrator_invariants(&calibrator, expected_total, expected_covered, &config);

    for (index, covered) in case.events.iter().copied().enumerate() {
        if case.reset_points.binary_search(&(index as u16)).is_ok() {
            calibrator.reset();
            expected_total = 0;
            expected_covered = 0;
            assert_calibrator_invariants(&calibrator, expected_total, expected_covered, &config);
        }

        calibrator.record(SecurityEpoch::from_raw(index as u64 + 1), covered);
        expected_total = expected_total.saturating_add(1);
        if covered {
            expected_covered = expected_covered.saturating_add(1);
        }

        assert_calibrator_invariants(&calibrator, expected_total, expected_covered, &config);

        let encoded = serde_json::to_vec(&calibrator).expect("conformal calibrator serializes");
        let decoded: ConformalCalibrator =
            serde_json::from_slice(&encoded).expect("conformal calibrator re-parses");
        assert_calibrator_invariants(&decoded, expected_total, expected_covered, &config);
        assert_eq!(
            decoded.coverage_millionths(),
            calibrator.coverage_millionths()
        );
        assert_eq!(
            decoded.e_value_millionths(),
            calibrator.e_value_millionths()
        );
        assert_eq!(decoded.violation_flagged(), calibrator.violation_flagged());
        assert_eq!(decoded.ledger(), calibrator.ledger());
    }
}

fn assert_calibrator_invariants(
    calibrator: &ConformalCalibrator,
    expected_total: u64,
    expected_covered: u64,
    config: &ConformalConfig,
) {
    assert_eq!(calibrator.total_predictions(), expected_total);
    assert_eq!(calibrator.covered_predictions(), expected_covered);
    assert!(calibrator.covered_predictions() <= calibrator.total_predictions());
    assert!(calibrator.ledger().len() <= calibrator.total_predictions() as usize);
    assert!((0..=MILLION).contains(&calibrator.coverage_millionths()));
    assert!((0..=MAX_E_VALUE_MILLIONTHS).contains(&calibrator.e_value_millionths()));

    let expected_coverage = if expected_total == 0 {
        MILLION
    } else {
        (expected_covered as i64).saturating_mul(MILLION) / expected_total as i64
    };
    assert_eq!(calibrator.coverage_millionths(), expected_coverage);

    let target_coverage = MILLION - config.alpha_millionths;
    if expected_total < config.min_calibration_observations {
        assert!(calibrator.is_calibrated());
    } else {
        assert_eq!(
            calibrator.is_calibrated(),
            calibrator.coverage_millionths() >= target_coverage
        );
    }

    for entry in calibrator.ledger() {
        assert!((0..=MILLION).contains(&entry.running_coverage_millionths));
        assert!((0..=MAX_E_VALUE_MILLIONTHS).contains(&entry.e_value_millionths));
        if entry.violation {
            assert!(calibrator.violation_flagged());
        }
    }
}
