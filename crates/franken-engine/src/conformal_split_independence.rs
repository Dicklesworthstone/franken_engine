// Conformal Split-Independence Refusal Gate (bd-cixqu.33.4, GG.4 negative test).
//
// Track GG layers a distribution-free **conformal** validity guarantee on the
// martingale ledger (`conformal_calibration`, GG.1): a calibrated `1-α` regret
// bound on every decision. That guarantee rests on **exchangeability** of the
// calibration sample with the test point — operationally, the test observation
// must be a *fresh, held-out* draw that did **not** contribute its own score to
// the calibration sample. If the same observation appears in both the
// calibration sample and the test set ("drawn from the same draw"), the bound
// has *seen its own answer*: coverage is silently inflated and the published
// `1-α` claim is unjustified.
//
// GG.2 (`ConformalCalibrator::gate`) is the *freshness/adequacy* gate. This
// module is the orthogonal **independence** gate that GG.1's header anticipates
// (the strictly-causal split in `calibrate_over_ledger` is what *makes* a
// held-out split; this gate is the fail-closed check that the split actually
// stayed held-out before anything is published). The negative test that proves
// the gate refuses a leaked split lives in
// `tests/conformal_split_independence_negative.rs`.
//
// Operationalizing "independence": every calibration observation and every test
// observation is identified by its content digest (`ContentHash`, mirroring the
// ledger's content-addressed events). Two observations are "the same draw" iff
// they share a content digest. The split is independent iff the calibration and
// test digest sets are **disjoint**; any overlap is data leakage and the gate
// **refuses** — directing the guardplane to safe-mode, evidence-only output
// rather than an inflated confidence-bounded claim.
//
// Determinism: digests live in `BTreeSet`s (sorted, no `HashMap`), set algebra
// is exact, and there is no floating point. The verdict is bit-for-bit
// reproducible and replayable, matching the rest of Track GG.

use crate::conformal_calibration::CalibratedRegretBound;
use crate::conformal_calibration::ConformalCalibrator;
use crate::hash_tiers::ContentHash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// SplitProvenance — which observations formed each side of the split
// ---------------------------------------------------------------------------

/// The provenance of a conformal calibration/test split: the content digests
/// of the observations that contributed nonconformity scores to the
/// **calibration** sample, and the digests of the observations in the **test**
/// set whose `1-α` bound is being published.
///
/// Conformal coverage is only valid when these two sets are an *independent
/// held-out split* — i.e. **disjoint**. An observation present in both sides
/// is data leakage: its score was used both to build the bound and to be
/// bounded, so the coverage guarantee no longer holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitProvenance {
    /// Content digests of the calibration-sample observations.
    calibration_digests: BTreeSet<ContentHash>,
    /// Content digests of the test-set observations.
    test_digests: BTreeSet<ContentHash>,
}

impl SplitProvenance {
    /// An empty split provenance.
    pub fn new() -> Self {
        Self {
            calibration_digests: BTreeSet::new(),
            test_digests: BTreeSet::new(),
        }
    }

    /// Build from explicit calibration and test digest iterators.
    pub fn from_digests(
        calibration: impl IntoIterator<Item = ContentHash>,
        test: impl IntoIterator<Item = ContentHash>,
    ) -> Self {
        Self {
            calibration_digests: calibration.into_iter().collect(),
            test_digests: test.into_iter().collect(),
        }
    }

    /// The common held-out single-test case: a calibration sample and one
    /// test observation. This is exactly the shape produced by a strictly
    /// causal split (each decision bounded only by *earlier* decisions).
    pub fn held_out_single(
        calibration: impl IntoIterator<Item = ContentHash>,
        test_digest: ContentHash,
    ) -> Self {
        let mut test = BTreeSet::new();
        test.insert(test_digest);
        Self {
            calibration_digests: calibration.into_iter().collect(),
            test_digests: test,
        }
    }

    /// Record a calibration-sample observation (idempotent).
    pub fn observe_calibration(&mut self, digest: ContentHash) {
        self.calibration_digests.insert(digest);
    }

    /// Record a test-set observation (idempotent).
    pub fn observe_test(&mut self, digest: ContentHash) {
        self.test_digests.insert(digest);
    }

    /// Number of distinct calibration observations.
    pub fn calibration_size(&self) -> u64 {
        self.calibration_digests.len() as u64
    }

    /// Number of distinct test observations.
    pub fn test_size(&self) -> u64 {
        self.test_digests.len() as u64
    }

    /// Calibration digests (sorted).
    pub fn calibration_digests(&self) -> &BTreeSet<ContentHash> {
        &self.calibration_digests
    }

    /// Test digests (sorted).
    pub fn test_digests(&self) -> &BTreeSet<ContentHash> {
        &self.test_digests
    }

    /// Observations present on **both** sides of the split (sorted,
    /// deterministic). A non-empty overlap is a leakage of the test point's
    /// own score into the calibration sample.
    pub fn overlap(&self) -> Vec<ContentHash> {
        self.calibration_digests
            .intersection(&self.test_digests)
            .copied()
            .collect()
    }

    /// Whether the calibration and test draws are disjoint (no leakage).
    pub fn is_disjoint(&self) -> bool {
        self.calibration_digests.is_disjoint(&self.test_digests)
    }
}

// ---------------------------------------------------------------------------
// SplitIndependenceVerdict — the independence-gate decision
// ---------------------------------------------------------------------------

/// Verdict of the split-independence gate. Only
/// [`Self::IndependentHeldOut`] authorizes publishing a conformal claim; every
/// `Refused*` variant directs the guardplane to fall back to safe-mode,
/// evidence-only output (no confidence-bounded claim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitIndependenceVerdict {
    /// Calibration and test draws are disjoint: the held-out independence
    /// assumption holds, the conformal `1-α` claim may be published.
    IndependentHeldOut {
        /// Distinct calibration observations.
        calibration_size: u64,
        /// Distinct test observations.
        test_size: u64,
    },
    /// At least one observation appears in **both** the calibration sample and
    /// the test set (data reuse / "same draw"): the bound has seen its own
    /// answer, coverage is inflated. Refuse.
    RefusedDependentSplit {
        /// Count of observations present on both sides (the leakage).
        overlap: u64,
        /// Distinct calibration observations.
        calibration_size: u64,
        /// Distinct test observations.
        test_size: u64,
        /// The leaking digests, sorted and deterministic (for the audit trail).
        leaking_digests: Vec<ContentHash>,
    },
    /// The calibration sample is empty — there is nothing to calibrate against.
    RefusedEmptyCalibration,
    /// The test set is empty — there is no claim to publish.
    RefusedEmptyTest,
}

impl SplitIndependenceVerdict {
    /// Whether the gate authorized a confidence-bounded decision.
    pub fn is_independent(&self) -> bool {
        matches!(self, Self::IndependentHeldOut { .. })
    }

    /// Whether the gate refused (caller must fall back to safe-mode evidence).
    pub fn is_refused(&self) -> bool {
        !self.is_independent()
    }

    /// The count of leaking observations, if the refusal was due to a
    /// dependent split; `0` otherwise.
    pub fn overlap(&self) -> u64 {
        match self {
            Self::RefusedDependentSplit { overlap, .. } => *overlap,
            _ => 0,
        }
    }
}

impl fmt::Display for SplitIndependenceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndependentHeldOut {
                calibration_size,
                test_size,
            } => write!(
                f,
                "independent: held-out split (calibration n={calibration_size}, test n={test_size})"
            ),
            Self::RefusedDependentSplit {
                overlap,
                calibration_size,
                test_size,
                ..
            } => write!(
                f,
                "refused: dependent split (overlap={overlap}, calibration n={calibration_size}, test n={test_size})"
            ),
            Self::RefusedEmptyCalibration => {
                write!(f, "refused: empty calibration sample")
            }
            Self::RefusedEmptyTest => write!(f, "refused: empty test set"),
        }
    }
}

/// Fail-closed split-independence check (GG.4).
///
/// Returns [`SplitIndependenceVerdict::IndependentHeldOut`] only when the
/// calibration and test draws are **disjoint** (and both non-empty). Any
/// shared observation — the same content digest on both sides — is data
/// leakage and yields [`SplitIndependenceVerdict::RefusedDependentSplit`].
///
/// Checks run cheapest-first for precise diagnostics: empty calibration, then
/// empty test, then the disjointness check.
pub fn verify_split_independence(provenance: &SplitProvenance) -> SplitIndependenceVerdict {
    if provenance.calibration_digests.is_empty() {
        return SplitIndependenceVerdict::RefusedEmptyCalibration;
    }
    if provenance.test_digests.is_empty() {
        return SplitIndependenceVerdict::RefusedEmptyTest;
    }
    let leaking_digests = provenance.overlap();
    if !leaking_digests.is_empty() {
        return SplitIndependenceVerdict::RefusedDependentSplit {
            overlap: leaking_digests.len() as u64,
            calibration_size: provenance.calibration_size(),
            test_size: provenance.test_size(),
            leaking_digests,
        };
    }
    SplitIndependenceVerdict::IndependentHeldOut {
        calibration_size: provenance.calibration_size(),
        test_size: provenance.test_size(),
    }
}

// ---------------------------------------------------------------------------
// ConformalPublishVerdict — the full GG.4 publish gate
// ---------------------------------------------------------------------------

/// Why a conformal publish was refused, when it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishRefusalReason {
    /// Calibration and test draws share `overlap` observations (leakage).
    DependentSplit { overlap: u64 },
    /// Empty calibration sample — nothing to calibrate against.
    EmptyCalibration,
    /// Empty test set — no claim to publish.
    EmptyTest,
    /// Independent split, but the calibration sample cannot certify the
    /// requested coverage (the order-statistic bound saturates).
    Uncertifiable {
        calibration_size: u64,
        quantile_rank: u64,
    },
}

/// The full GG.4 publish decision. A confidence-bounded conformal claim is
/// authorized only when the split is an independent held-out draw **and** the
/// calibrator can certify the requested coverage. Independence is checked
/// **first**: a dependent split makes the bound's coverage meaningless
/// regardless of how large or fresh the sample is.
///
/// This composes the orthogonal independence dimension (GG.4) with the
/// calibrator's saturation check; epoch *freshness* (GG.2) is a separate
/// dimension the caller runs via [`ConformalCalibrator::gate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformalPublishVerdict {
    /// Independent split and a non-saturated bound: publish it.
    Publish { bound: CalibratedRegretBound },
    /// Refused — the caller must fall back to safe-mode, evidence-only output.
    Refused { reason: PublishRefusalReason },
}

impl ConformalPublishVerdict {
    /// Whether a confidence-bounded claim was authorized.
    pub fn is_published(&self) -> bool {
        matches!(self, Self::Publish { .. })
    }

    /// Whether the gate refused.
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }

    /// The certified bound, if any.
    pub fn bound(&self) -> Option<CalibratedRegretBound> {
        match self {
            Self::Publish { bound } => Some(*bound),
            Self::Refused { .. } => None,
        }
    }
}

impl fmt::Display for ConformalPublishVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publish { bound } => write!(f, "publish: {bound}"),
            Self::Refused { reason } => match reason {
                PublishRefusalReason::DependentSplit { overlap } => {
                    write!(f, "refused: dependent split (overlap={overlap})")
                }
                PublishRefusalReason::EmptyCalibration => {
                    write!(f, "refused: empty calibration")
                }
                PublishRefusalReason::EmptyTest => write!(f, "refused: empty test"),
                PublishRefusalReason::Uncertifiable {
                    calibration_size,
                    quantile_rank,
                } => write!(
                    f,
                    "refused: uncertifiable (n={calibration_size}, need rank {quantile_rank})"
                ),
            },
        }
    }
}

/// The full GG.4 publish gate: refuse a conformal claim whose calibration
/// sample is not an independent held-out draw from the test set, and otherwise
/// publish the calibrator's bound only if it is non-saturated.
///
/// The independence check runs first; only an [`SplitIndependenceVerdict::IndependentHeldOut`]
/// split proceeds to the calibrator's bound.
pub fn gate_publish(
    calibrator: &ConformalCalibrator,
    provenance: &SplitProvenance,
) -> ConformalPublishVerdict {
    match verify_split_independence(provenance) {
        SplitIndependenceVerdict::IndependentHeldOut { .. } => {
            let bound = calibrator.regret_bound();
            if bound.saturated {
                ConformalPublishVerdict::Refused {
                    reason: PublishRefusalReason::Uncertifiable {
                        calibration_size: bound.calibration_size,
                        quantile_rank: bound.quantile_rank,
                    },
                }
            } else {
                ConformalPublishVerdict::Publish { bound }
            }
        }
        SplitIndependenceVerdict::RefusedDependentSplit { overlap, .. } => {
            ConformalPublishVerdict::Refused {
                reason: PublishRefusalReason::DependentSplit { overlap },
            }
        }
        SplitIndependenceVerdict::RefusedEmptyCalibration => ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::EmptyCalibration,
        },
        SplitIndependenceVerdict::RefusedEmptyTest => ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::EmptyTest,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformal_calibration::{Alpha, CalibrationSet};

    /// Deterministic, distinct content digest from a single byte seed.
    fn digest(seed: u8) -> ContentHash {
        ContentHash([seed; 32])
    }

    fn calibrator(scores: &[i64], alpha_m: u32) -> ConformalCalibrator {
        ConformalCalibrator::from_scores(
            scores.iter().copied(),
            Alpha::from_millionths(alpha_m).unwrap(),
        )
    }

    // --- SplitProvenance ---------------------------------------------------

    #[test]
    fn empty_provenance_has_zero_sizes_and_is_disjoint() {
        let p = SplitProvenance::new();
        assert_eq!(p.calibration_size(), 0);
        assert_eq!(p.test_size(), 0);
        assert!(p.is_disjoint());
        assert!(p.overlap().is_empty());
    }

    #[test]
    fn from_digests_dedups_into_sets() {
        let p = SplitProvenance::from_digests(
            [digest(1), digest(1), digest(2)],
            [digest(9), digest(9)],
        );
        assert_eq!(p.calibration_size(), 2);
        assert_eq!(p.test_size(), 1);
    }

    #[test]
    fn held_out_single_has_one_test_point() {
        let p = SplitProvenance::held_out_single([digest(1), digest(2), digest(3)], digest(9));
        assert_eq!(p.calibration_size(), 3);
        assert_eq!(p.test_size(), 1);
        assert!(p.is_disjoint());
    }

    #[test]
    fn observe_is_idempotent() {
        let mut p = SplitProvenance::new();
        p.observe_calibration(digest(1));
        p.observe_calibration(digest(1));
        p.observe_test(digest(2));
        p.observe_test(digest(2));
        assert_eq!(p.calibration_size(), 1);
        assert_eq!(p.test_size(), 1);
    }

    #[test]
    fn overlap_is_sorted_and_deterministic() {
        // Insert in scrambled order; intersection must come back sorted.
        let p = SplitProvenance::from_digests(
            [digest(5), digest(3), digest(7), digest(1)],
            [digest(7), digest(1), digest(5)],
        );
        let overlap = p.overlap();
        assert_eq!(overlap, vec![digest(1), digest(5), digest(7)]);
        // Idempotent / stable across calls.
        assert_eq!(overlap, p.overlap());
    }

    #[test]
    fn disjoint_sets_report_disjoint() {
        let p = SplitProvenance::from_digests([digest(1), digest(2)], [digest(3), digest(4)]);
        assert!(p.is_disjoint());
        assert!(p.overlap().is_empty());
    }

    #[test]
    fn overlapping_sets_are_not_disjoint() {
        let p = SplitProvenance::from_digests([digest(1), digest(2)], [digest(2), digest(3)]);
        assert!(!p.is_disjoint());
        assert_eq!(p.overlap(), vec![digest(2)]);
    }

    // --- verify_split_independence -----------------------------------------

    #[test]
    fn independent_split_certifies() {
        let p = SplitProvenance::from_digests([digest(1), digest(2), digest(3)], [digest(9)]);
        let v = verify_split_independence(&p);
        assert!(v.is_independent());
        assert!(!v.is_refused());
        assert_eq!(v.overlap(), 0);
        assert_eq!(
            v,
            SplitIndependenceVerdict::IndependentHeldOut {
                calibration_size: 3,
                test_size: 1,
            }
        );
    }

    #[test]
    fn self_leakage_refuses() {
        // The single test point's own observation is in the calibration set:
        // the canonical "drawn from the same draw" violation.
        let p = SplitProvenance::held_out_single([digest(1), digest(2), digest(9)], digest(9));
        let v = verify_split_independence(&p);
        assert!(v.is_refused());
        assert!(!v.is_independent());
        assert_eq!(v.overlap(), 1);
        match v {
            SplitIndependenceVerdict::RefusedDependentSplit {
                overlap,
                calibration_size,
                test_size,
                leaking_digests,
            } => {
                assert_eq!(overlap, 1);
                assert_eq!(calibration_size, 3);
                assert_eq!(test_size, 1);
                assert_eq!(leaking_digests, vec![digest(9)]);
            }
            other => panic!("expected RefusedDependentSplit, got {other:?}"),
        }
    }

    #[test]
    fn full_overlap_refuses_with_every_digest_leaking() {
        // Calibration set == test set: the most extreme "same distribution"
        // case — every observation is reused.
        let shared = [digest(1), digest(2), digest(3)];
        let p = SplitProvenance::from_digests(shared, shared);
        let v = verify_split_independence(&p);
        assert!(v.is_refused());
        assert_eq!(v.overlap(), 3);
    }

    #[test]
    fn partial_overlap_refuses() {
        let p = SplitProvenance::from_digests(
            [digest(1), digest(2), digest(3), digest(4)],
            [digest(4), digest(5)],
        );
        let v = verify_split_independence(&p);
        assert!(v.is_refused());
        assert_eq!(v.overlap(), 1);
    }

    #[test]
    fn empty_calibration_refuses() {
        let p = SplitProvenance::from_digests([], [digest(9)]);
        assert_eq!(
            verify_split_independence(&p),
            SplitIndependenceVerdict::RefusedEmptyCalibration
        );
    }

    #[test]
    fn empty_test_refuses() {
        let p = SplitProvenance::from_digests([digest(1), digest(2)], []);
        assert_eq!(
            verify_split_independence(&p),
            SplitIndependenceVerdict::RefusedEmptyTest
        );
    }

    #[test]
    fn empty_calibration_checked_before_overlap() {
        // Both sides empty -> empty-calibration diagnostic wins (cheapest-first).
        let p = SplitProvenance::new();
        assert_eq!(
            verify_split_independence(&p),
            SplitIndependenceVerdict::RefusedEmptyCalibration
        );
    }

    // --- gate_publish (independence composed with the calibrator) ----------

    #[test]
    fn gate_publishes_on_independent_certifiable_split() {
        // n=39 calibrators certify 95% coverage (rank ceil(40*0.95)=38 <= 39).
        let scores: Vec<i64> = (0..39).collect();
        let cal = calibrator(&scores, 50_000);
        let p = SplitProvenance::held_out_single((0..39).map(|i| digest(i as u8)), digest(200));
        let verdict = gate_publish(&cal, &p);
        assert!(verdict.is_published());
        assert!(verdict.bound().is_some());
        assert!(!verdict.bound().unwrap().saturated);
    }

    #[test]
    fn gate_refuses_dependent_split_even_when_calibrator_could_certify() {
        // Same large, certifiable calibrator — but the test point leaked into
        // the calibration sample. Independence is checked first, so we refuse
        // regardless of the (otherwise publishable) bound.
        let scores: Vec<i64> = (0..39).collect();
        let cal = calibrator(&scores, 50_000);
        let p = SplitProvenance::held_out_single((0..39).map(|i| digest(i as u8)), digest(7));
        let verdict = gate_publish(&cal, &p);
        assert!(verdict.is_refused());
        assert_eq!(
            verdict,
            ConformalPublishVerdict::Refused {
                reason: PublishRefusalReason::DependentSplit { overlap: 1 },
            }
        );
        assert!(verdict.bound().is_none());
    }

    #[test]
    fn gate_refuses_uncertifiable_independent_split() {
        // Independent split, but only 3 calibration scores -> the 95% bound
        // saturates (rank ceil(4*0.95)=4 > 3), so the gate refuses.
        let cal = calibrator(&[10, 20, 30], 50_000);
        let p = SplitProvenance::held_out_single([digest(1), digest(2), digest(3)], digest(9));
        let verdict = gate_publish(&cal, &p);
        assert!(verdict.is_refused());
        match verdict {
            ConformalPublishVerdict::Refused {
                reason:
                    PublishRefusalReason::Uncertifiable {
                        calibration_size, ..
                    },
            } => assert_eq!(calibration_size, 3),
            other => panic!("expected Uncertifiable, got {other:?}"),
        }
    }

    #[test]
    fn gate_refuses_empty_calibration() {
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
    fn gate_refuses_empty_test() {
        let cal = calibrator(&[1, 2, 3], 50_000);
        let p = SplitProvenance::from_digests([digest(1), digest(2)], []);
        assert_eq!(
            gate_publish(&cal, &p),
            ConformalPublishVerdict::Refused {
                reason: PublishRefusalReason::EmptyTest,
            }
        );
    }

    // --- The statistical reason the gate matters: leakage inflates coverage.

    #[test]
    fn leakage_tightens_the_bound_relative_to_held_out() {
        // The independence assumption is load-bearing: if a small test score is
        // folded into its OWN calibration set (leakage), the order-statistic
        // bound is no larger than the honest held-out bound, so it admits more
        // and over-states coverage. This is exactly what the gate refuses.
        let held_out = calibrator(&[100, 200, 300, 400, 500, 600, 700, 800], 200_000);
        let honest_bound = held_out.regret_bound();

        // Leak a tiny test score (1) into the calibration sample.
        let mut leaked = held_out.clone();
        leaked.observe(1);
        let leaked_bound = leaked.regret_bound();

        // Folding in a small score cannot raise the order statistic; the leaked
        // bound is <= the honest one, i.e. coverage is over-stated.
        assert!(leaked_bound.bound_millionths <= honest_bound.bound_millionths);
    }

    #[test]
    fn leaked_bound_rejects_values_the_held_out_bound_covers() {
        // Honest held-out bound = 800 (8th order statistic, 80% coverage).
        // Leaking a tiny score (1) shrinks the bound to 700, so the leaked
        // bound is anti-conservative: a candidate at 750 is covered by the
        // honest bound but *rejected* by the leaked one — the under-coverage
        // (claimed 1-α not actually attained) the gate exists to refuse.
        let held_out = calibrator(&[100, 200, 300, 400, 500, 600, 700, 800], 200_000);
        let honest = held_out.regret_bound();
        let mut leaked = held_out.clone();
        leaked.observe(1);
        let leaked_b = leaked.regret_bound();
        assert!(leaked_b.bound_millionths < honest.bound_millionths);
        let probe = 750;
        assert!(honest.admits(probe), "honest bound covers {probe}");
        assert!(
            !leaked_b.admits(probe),
            "leaked bound wrongly rejects {probe}"
        );
    }

    // --- Verdict accessors / Display ---------------------------------------

    #[test]
    fn verdict_accessors_are_consistent() {
        let indep = SplitIndependenceVerdict::IndependentHeldOut {
            calibration_size: 10,
            test_size: 1,
        };
        assert!(indep.is_independent() && !indep.is_refused() && indep.overlap() == 0);

        let dep = SplitIndependenceVerdict::RefusedDependentSplit {
            overlap: 2,
            calibration_size: 10,
            test_size: 3,
            leaking_digests: vec![digest(1), digest(2)],
        };
        assert!(dep.is_refused() && !dep.is_independent() && dep.overlap() == 2);
    }

    #[test]
    fn publish_verdict_accessors_are_consistent() {
        let cal = calibrator(&(0..39).collect::<Vec<_>>(), 50_000);
        let bound = cal.regret_bound();
        let pub_v = ConformalPublishVerdict::Publish { bound };
        assert!(pub_v.is_published() && !pub_v.is_refused() && pub_v.bound().is_some());

        let ref_v = ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::DependentSplit { overlap: 1 },
        };
        assert!(ref_v.is_refused() && !ref_v.is_published() && ref_v.bound().is_none());
    }

    #[test]
    fn display_strings_distinguish_outcomes() {
        let indep = SplitIndependenceVerdict::IndependentHeldOut {
            calibration_size: 4,
            test_size: 1,
        };
        assert!(indep.to_string().contains("independent"));
        let dep = SplitIndependenceVerdict::RefusedDependentSplit {
            overlap: 1,
            calibration_size: 4,
            test_size: 1,
            leaking_digests: vec![digest(1)],
        };
        assert!(dep.to_string().contains("refused"));
        assert!(
            SplitIndependenceVerdict::RefusedEmptyCalibration
                .to_string()
                .contains("empty calibration")
        );
        assert!(
            SplitIndependenceVerdict::RefusedEmptyTest
                .to_string()
                .contains("empty test")
        );
    }

    #[test]
    fn publish_display_distinguishes_reasons() {
        let r = ConformalPublishVerdict::Refused {
            reason: PublishRefusalReason::Uncertifiable {
                calibration_size: 3,
                quantile_rank: 4,
            },
        };
        assert!(r.to_string().contains("uncertifiable"));
    }

    // --- serde round-trip --------------------------------------------------

    #[test]
    fn provenance_serde_round_trips() {
        let p = SplitProvenance::from_digests([digest(1), digest(2)], [digest(9)]);
        let json = serde_json::to_string(&p).unwrap();
        let back: SplitProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn verdict_serde_round_trips() {
        let v = SplitIndependenceVerdict::RefusedDependentSplit {
            overlap: 1,
            calibration_size: 4,
            test_size: 1,
            leaking_digests: vec![digest(9)],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: SplitIndependenceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn provenance_serialization_is_deterministic() {
        // BTreeSet ordering => identical JSON regardless of insertion order.
        let a = SplitProvenance::from_digests([digest(3), digest(1), digest(2)], [digest(9)]);
        let b = SplitProvenance::from_digests([digest(1), digest(2), digest(3)], [digest(9)]);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
