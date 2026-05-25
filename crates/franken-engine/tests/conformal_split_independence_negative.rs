//! GG.4 negative test (bd-cixqu.33.4): the conformal publish gate must
//! **refuse** a `1-α` claim whose calibration sample is not an independent
//! held-out draw from the test set.
//!
//! The calibration–test independence assumption is load-bearing: conformal
//! coverage is only valid when the test observation did not contribute its own
//! score to the calibration sample. These tests prove that
//! [`verify_split_independence`] / [`gate_publish`] refuse leaked splits, that
//! the strictly-causal ledger split (`calibrate_over_ledger`) produces an
//! *independent* split (positive control), and that breaking that split is
//! exactly what makes coverage unjustified.

use frankenengine_engine::conformal_calibration::{
    Alpha, CalibrationSet, ConformalCalibrator, calibrate_over_ledger,
};
use frankenengine_engine::conformal_split_independence::{
    ConformalPublishVerdict, PublishRefusalReason, SplitIndependenceVerdict, SplitProvenance,
    gate_publish, verify_split_independence,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::martingale_decision_ledger::{MartingaleLedger, StoppingThreshold};
use frankenengine_engine::security_epoch::SecurityEpoch;

/// Deterministic, distinct content digest from a byte seed.
fn digest(seed: u8) -> ContentHash {
    ContentHash([seed; 32])
}

fn calibrator(scores: &[i64], alpha_m: u32) -> ConformalCalibrator {
    ConformalCalibrator::from_scores(
        scores.iter().copied(),
        Alpha::from_millionths(alpha_m).unwrap(),
    )
}

// ---------------------------------------------------------------------------
// The core negative test: leaked split is refused.
// ---------------------------------------------------------------------------

#[test]
fn refuses_claim_when_test_point_is_in_calibration_set() {
    // A large, otherwise-certifiable calibrator (n=39 certifies 95% coverage).
    let scores: Vec<i64> = (0..39).collect();
    let cal = calibrator(&scores, 50_000);

    // Honest, held-out split: the test observation (digest 200) is NOT among
    // the calibration observations (digests 0..39). The gate publishes.
    let held_out = SplitProvenance::held_out_single((0..39).map(|i| digest(i as u8)), digest(200));
    let ok = gate_publish(&cal, &held_out);
    assert!(ok.is_published(), "honest held-out split must publish");

    // Leaked split: the test observation's own digest (7) IS in the
    // calibration sample. Same calibrator, same would-be bound — but the
    // independence assumption is violated, so the gate REFUSES.
    let leaked = SplitProvenance::held_out_single((0..39).map(|i| digest(i as u8)), digest(7));
    let refused = gate_publish(&cal, &leaked);
    assert!(refused.is_refused(), "leaked split must refuse");
    assert_eq!(
        refused,
        ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::DependentSplit { overlap: 1 },
        }
    );
    assert!(refused.bound().is_none());
}

#[test]
fn refuses_when_calibration_set_equals_test_set() {
    // The most extreme "drawn from the same distribution" case: the calibration
    // set IS the test set. Every observation is reused.
    let shared = [digest(1), digest(2), digest(3), digest(4)];
    let p = SplitProvenance::from_digests(shared, shared);
    let v = verify_split_independence(&p);
    assert!(v.is_refused());
    assert_eq!(v.overlap(), 4);
}

#[test]
fn independence_is_checked_before_certifiability() {
    // Even with a fully certifiable calibrator, a dependent split refuses with
    // the *dependent-split* reason — independence takes precedence over the
    // (otherwise publishable) bound.
    let cal = calibrator(&(0..39).collect::<Vec<_>>(), 50_000);
    let leaked =
        SplitProvenance::from_digests((0..39).map(|i| digest(i as u8)), [digest(5), digest(99)]);
    match gate_publish(&cal, &leaked) {
        ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::DependentSplit { overlap },
        } => assert_eq!(overlap, 1),
        other => panic!("expected DependentSplit refusal, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Positive control: the strictly-causal ledger split is independent.
// ---------------------------------------------------------------------------

#[test]
fn causal_ledger_split_yields_independent_provenance() {
    // Build a ledger with distinct per-decision payload digests.
    let threshold = StoppingThreshold::try_from_log_millionths(2_995_732).unwrap();
    let mut ledger = MartingaleLedger::new(threshold, SecurityEpoch::from_raw(1));
    for i in 1..=6u8 {
        ledger
            .append(10_000, digest(i), i as u64 * 1_000)
            .expect("append");
    }

    // calibrate_over_ledger uses a strictly causal split: the bound for
    // decision i sees only earlier scores. Reconstruct that split's provenance
    // for the LAST decision and confirm it is independent (held-out).
    let scores: Vec<i64> = (0..6).map(|k| 100 + k * 10).collect();
    let bounds = calibrate_over_ledger(&ledger, &scores, Alpha::TEN_PERCENT).expect("calibrate");
    assert_eq!(bounds.len(), 6);

    let last = bounds.last().unwrap();
    let earlier_digests: Vec<ContentHash> = bounds
        .iter()
        .rev()
        .skip(1)
        .map(|b| b.payload_digest)
        .collect();
    let causal = SplitProvenance::held_out_single(earlier_digests, last.payload_digest);
    assert_eq!(
        verify_split_independence(&causal),
        SplitIndependenceVerdict::IndependentHeldOut {
            calibration_size: 5,
            test_size: 1,
        },
        "the strictly-causal ledger split must be an independent held-out split"
    );

    // Now corrupt the split by leaking the test decision's own digest into the
    // calibration sample — the gate must refuse.
    let mut leaked_digests: Vec<ContentHash> = bounds.iter().map(|b| b.payload_digest).collect(); // includes the last
    leaked_digests.sort();
    leaked_digests.dedup();
    let leaked = SplitProvenance::held_out_single(leaked_digests, last.payload_digest);
    assert!(
        verify_split_independence(&leaked).is_refused(),
        "leaking the test digest into calibration must refuse"
    );
}

// ---------------------------------------------------------------------------
// Why the gate matters: leakage inflates coverage.
// ---------------------------------------------------------------------------

#[test]
fn leakage_inflates_coverage_relative_to_held_out() {
    // Honest held-out calibrator.
    let held_out = calibrator(&[100, 200, 300, 400, 500, 600, 700, 800], 200_000);
    let honest = held_out.regret_bound();

    // Fold a tiny test score into the calibrator's OWN sample (leakage).
    let mut leaked = held_out.clone();
    leaked.observe(1);
    let leaked_bound = leaked.regret_bound();

    // The leaked bound is no larger than the honest one: it admits at least as
    // much, over-stating coverage. That anti-conservative bound is precisely
    // what the independence gate refuses to publish.
    assert!(leaked_bound.bound_millionths <= honest.bound_millionths);
}

// ---------------------------------------------------------------------------
// Degenerate inputs still fail closed.
// ---------------------------------------------------------------------------

#[test]
fn empty_calibration_fails_closed() {
    let cal = ConformalCalibrator::new(CalibrationSet::new(), Alpha::FIVE_PERCENT);
    let p = SplitProvenance::from_digests([], [digest(9)]);
    assert_eq!(
        gate_publish(&cal, &p),
        ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::EmptyCalibration,
        }
    );
}

#[test]
fn empty_test_fails_closed() {
    let cal = calibrator(&[1, 2, 3, 4, 5], 50_000);
    let p = SplitProvenance::from_digests([digest(1), digest(2)], []);
    assert_eq!(
        gate_publish(&cal, &p),
        ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::EmptyTest,
        }
    );
}

#[test]
fn independent_but_uncertifiable_split_refuses() {
    // Independent split, but only 3 calibration scores cannot certify 95%.
    let cal = calibrator(&[10, 20, 30], 50_000);
    let p = SplitProvenance::held_out_single([digest(1), digest(2), digest(3)], digest(9));
    match gate_publish(&cal, &p) {
        ConformalPublishVerdict::Refused {
            reason:
                PublishRefusalReason::Uncertifiable {
                    calibration_size, ..
                },
        } => assert_eq!(calibration_size, 3),
        other => panic!("expected Uncertifiable refusal, got {other}"),
    }
}

#[test]
fn verdict_serde_round_trips() {
    let v = SplitIndependenceVerdict::RefusedDependentSplit {
        overlap: 2,
        calibration_size: 10,
        test_size: 3,
        leaking_digests: vec![digest(1), digest(2)],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: SplitIndependenceVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}
