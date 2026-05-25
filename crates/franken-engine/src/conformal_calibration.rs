// Conformal Calibration Substrate over the Martingale Ledger (bd-cixqu.33.1, GG.1).
//
// Track GG sharpens Track AA: the martingale ledger
// (`martingale_decision_ledger`) gives *anytime-valid* stopping via an
// e-process (Ville's inequality), but it does not by itself bound the
// *regret* of each decision. This module layers a distribution-free
// **conformal** validity guarantee on top: from a calibration sample of
// observed nonconformity scores (e.g. realized regrets), it emits a
// **calibrated regret bound on every decision** that holds with coverage
// `1 - α` under exchangeability — with **finite-sample, distribution-free**
// validity, not an asymptotic approximation.
//
// Why conformal (Vovk/Gammerman/Shafer 2005; Lei et al. 2018; Angelopoulos
// & Bates 2023):
//
//   * The split-conformal upper bound at level `1-α` is the
//     `ceil((n+1)(1-α))`-th smallest calibration score. Under exchangeability
//     of the calibration scores and the test score, the next score is
//     `<=` that bound with probability `>= 1-α` — *for any score
//     distribution*, with no parametric assumption.
//   * The conformal p-value `p = (1 + #{i : s_i >= s}) / (n+1)` is
//     super-uniform under the null (`P(p <= α) <= α`). A test score lies in
//     the `1-α` prediction set iff `p > α`. These p-values compose with the
//     ledger's e-process for sequential (anytime-valid) calibration.
//
// Determinism: every quantity here is computed in exact integer / fixed-point
// arithmetic (scores in millionths, `1_000_000 = 1.0`, matching the
// martingale ledger). There is **no floating point** — the p-value is a
// rational `(1+c)/(n+1)` and the bound is an order statistic, so calibration
// is bit-for-bit reproducible across platforms and replayable.
//
// Scope (this bead): the substrate + per-decision bound emission over a
// ledger. Calibration-drift refusal (bd-cixqu.33.2) and the
// same-distribution negative test (bd-cixqu.33.4) build on this surface and
// are intentionally out of scope here.

use crate::hash_tiers::ContentHash;
use crate::martingale_decision_ledger::MartingaleLedger;
use crate::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Convention: 1.0 in millionths.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Alpha — the significance level
// ---------------------------------------------------------------------------

/// Significance level `α` in millionths (`1_000_000 = 1.0`).
///
/// Must lie strictly in `(0, 1)`: `α = 0` demands certainty (an infinite
/// bound) and `α >= 1` makes every prediction set empty, so both are
/// rejected at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Alpha {
    millionths: u32,
}

impl Alpha {
    /// `α = 0.05` (95% coverage) — the conventional default.
    pub const FIVE_PERCENT: Self = Self { millionths: 50_000 };
    /// `α = 0.10` (90% coverage).
    pub const TEN_PERCENT: Self = Self {
        millionths: 100_000,
    };

    /// Build an `α` from millionths, rejecting values outside `(0, 1)`.
    pub fn from_millionths(millionths: u32) -> Result<Self, ConformalError> {
        if millionths == 0 || millionths >= MILLION as u32 {
            return Err(ConformalError::InvalidAlpha { millionths });
        }
        Ok(Self { millionths })
    }

    /// The raw `α` in millionths.
    pub fn millionths(&self) -> u32 {
        self.millionths
    }

    /// The target coverage `1 - α` in millionths.
    pub fn coverage_millionths(&self) -> u32 {
        MILLION as u32 - self.millionths
    }
}

impl fmt::Display for Alpha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "α={}/1e6", self.millionths)
    }
}

// ---------------------------------------------------------------------------
// CalibrationSet — the sorted nonconformity sample
// ---------------------------------------------------------------------------

/// A sample of nonconformity scores (regrets/losses) in millionths, kept in
/// ascending sorted order so order-statistic queries are direct.
///
/// "Higher score = more nonconforming" is the convention: the calibrated
/// bound is an *upper* bound on the next score, and the p-value counts how
/// many calibration scores are at least as nonconforming as the test score.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSet {
    /// Ascending-sorted nonconformity scores, millionths.
    sorted_scores: Vec<i64>,
}

impl CalibrationSet {
    /// An empty calibration set.
    pub fn new() -> Self {
        Self {
            sorted_scores: Vec::new(),
        }
    }

    /// Build from an unordered batch of scores (copied and sorted).
    pub fn from_scores(scores: impl IntoIterator<Item = i64>) -> Self {
        let mut sorted_scores: Vec<i64> = scores.into_iter().collect();
        sorted_scores.sort_unstable();
        Self { sorted_scores }
    }

    /// Insert one score, preserving sorted order (binary-search insert).
    pub fn observe(&mut self, score: i64) {
        let idx = self.sorted_scores.partition_point(|&s| s < score);
        self.sorted_scores.insert(idx, score);
    }

    /// Number of calibration scores `n`.
    pub fn len(&self) -> usize {
        self.sorted_scores.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.sorted_scores.is_empty()
    }

    /// Ascending-sorted scores.
    pub fn scores(&self) -> &[i64] {
        &self.sorted_scores
    }

    /// Count of calibration scores `>=` the test score (the conformal rank
    /// numerator's `c`). Uses the sorted invariant for an O(log n) bound.
    fn count_at_least(&self, test_score: i64) -> u64 {
        // First index whose score is >= test_score; everything from there to
        // the end qualifies.
        let first_ge = self.sorted_scores.partition_point(|&s| s < test_score);
        (self.sorted_scores.len() - first_ge) as u64
    }
}

// ---------------------------------------------------------------------------
// ConformalPValue — the exact rational p-value
// ---------------------------------------------------------------------------

/// A conformal p-value `(1 + c) / (n + 1)` held as an exact rational, where
/// `c = #{calibration scores >= test score}` and `n` is the calibration size.
///
/// Kept exact (not pre-divided) so threshold comparisons are bit-exact via
/// cross-multiplication rather than lossy fixed-point division.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalPValue {
    /// `1 + c`.
    numerator: u64,
    /// `n + 1`.
    denominator: u64,
}

impl ConformalPValue {
    /// `1 + c`.
    pub fn numerator(&self) -> u64 {
        self.numerator
    }

    /// `n + 1`.
    pub fn denominator(&self) -> u64 {
        self.denominator
    }

    /// The p-value rendered in millionths (floor of `num/den * 1e6`), for
    /// display/telemetry. Comparisons should prefer [`Self::le_alpha`], which
    /// is exact.
    pub fn as_millionths(&self) -> u64 {
        // denominator >= 1 by construction (n+1).
        (self.numerator as u128 * MILLION as u128 / self.denominator as u128) as u64
    }

    /// Exact `p <= α` test, by cross-multiplication in `i128`:
    /// `(1+c)/(n+1) <= α/1e6  ⟺  (1+c)·1e6 <= α·(n+1)`.
    pub fn le_alpha(&self, alpha: Alpha) -> bool {
        let lhs = self.numerator as i128 * MILLION as i128;
        let rhs = alpha.millionths() as i128 * self.denominator as i128;
        lhs <= rhs
    }
}

impl fmt::Display for ConformalPValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p={}/{}", self.numerator, self.denominator)
    }
}

// ---------------------------------------------------------------------------
// CalibratedRegretBound — the (1-α) conformal upper bound
// ---------------------------------------------------------------------------

/// A distribution-free upper bound on the next nonconformity score (regret),
/// valid with coverage `>= 1-α` under exchangeability.
///
/// When the calibration set is too small to attain the requested coverage
/// (`ceil((n+1)(1-α)) > n`), no finite order statistic suffices: `saturated`
/// is set and `bound_millionths` is [`i64::MAX`]. A caller MUST treat a
/// saturated bound as "insufficient evidence — abstain", never as a real
/// numeric bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibratedRegretBound {
    /// Upper bound on the next regret/score, millionths. `i64::MAX` iff saturated.
    pub bound_millionths: i64,
    /// Target coverage `1 - α` in millionths.
    pub coverage_millionths: u32,
    /// Calibration size `n` used to derive the bound.
    pub calibration_size: u64,
    /// 1-indexed order statistic `k = ceil((n+1)(1-α))` selected (for audit).
    pub quantile_rank: u64,
    /// True when `k > n`: the sample cannot certify the requested coverage.
    pub saturated: bool,
}

impl CalibratedRegretBound {
    /// Whether `candidate` is within the certified region (`<= bound`). A
    /// saturated bound admits everything (it certifies nothing).
    pub fn admits(&self, candidate_millionths: i64) -> bool {
        candidate_millionths <= self.bound_millionths
    }
}

impl fmt::Display for CalibratedRegretBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.saturated {
            write!(
                f,
                "regret_bound=SATURATED (n={}, need rank {})",
                self.calibration_size, self.quantile_rank
            )
        } else {
            write!(
                f,
                "regret_bound={}/1e6 (coverage {}/1e6, n={}, rank {})",
                self.bound_millionths,
                self.coverage_millionths,
                self.calibration_size,
                self.quantile_rank
            )
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionRegretBound — a bound bound to a specific ledger decision
// ---------------------------------------------------------------------------

/// A calibrated regret bound attached to a specific martingale-ledger
/// decision, content-addressed for replay (mirrors the ledger's own design).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRegretBound {
    /// 1-indexed sequence position in the originating ledger.
    pub sequence: u64,
    /// Content digest of the decision's payload (from the ledger event).
    pub payload_digest: ContentHash,
    /// Security epoch the decision was recorded in.
    pub epoch: SecurityEpoch,
    /// The calibrated regret bound for this decision, from PAST scores only.
    pub bound: CalibratedRegretBound,
}

// ---------------------------------------------------------------------------
// ConformalError
// ---------------------------------------------------------------------------

/// Errors from the conformal calibration substrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformalError {
    /// `α` was outside the open interval `(0, 1)`.
    InvalidAlpha { millionths: u32 },
    /// A p-value was requested against an empty calibration set.
    EmptyCalibration,
    /// The supplied per-decision scores did not align 1:1 with the ledger.
    LengthMismatch { ledger_events: usize, scores: usize },
}

impl fmt::Display for ConformalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlpha { millionths } => {
                write!(f, "alpha {millionths}/1e6 is outside (0, 1)")
            }
            Self::EmptyCalibration => {
                f.write_str("conformal p-value requires a non-empty calibration set")
            }
            Self::LengthMismatch {
                ledger_events,
                scores,
            } => write!(
                f,
                "score count {scores} does not match ledger event count {ledger_events}"
            ),
        }
    }
}

impl std::error::Error for ConformalError {}

// ---------------------------------------------------------------------------
// quantile-rank helper
// ---------------------------------------------------------------------------

/// The 1-indexed split-conformal order-statistic rank `k = ceil((n+1)(1-α))`.
/// Computed in `u128` to avoid overflow for large `n`.
fn quantile_rank(n: u64, alpha: Alpha) -> u64 {
    let coverage = alpha.coverage_millionths() as u128; // (1-α)·1e6
    let numerator = (n as u128 + 1) * coverage; // (n+1)(1-α)·1e6
    // ceil(numerator / 1e6)
    let million = MILLION as u128;
    ((numerator + million - 1) / million) as u64
}

// ---------------------------------------------------------------------------
// ConformalCalibrator — the substrate
// ---------------------------------------------------------------------------

/// A conformal calibrator: a calibration sample paired with a significance
/// level, producing p-values and calibrated regret bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalCalibrator {
    calibration: CalibrationSet,
    alpha: Alpha,
}

impl ConformalCalibrator {
    /// Build a calibrator from an existing calibration set.
    pub fn new(calibration: CalibrationSet, alpha: Alpha) -> Self {
        Self { calibration, alpha }
    }

    /// Build a calibrator from a batch of scores.
    pub fn from_scores(scores: impl IntoIterator<Item = i64>, alpha: Alpha) -> Self {
        Self::new(CalibrationSet::from_scores(scores), alpha)
    }

    /// The significance level.
    pub fn alpha(&self) -> Alpha {
        self.alpha
    }

    /// The calibration sample.
    pub fn calibration(&self) -> &CalibrationSet {
        &self.calibration
    }

    /// Add a freshly observed nonconformity score to the calibration sample.
    pub fn observe(&mut self, score: i64) {
        self.calibration.observe(score);
    }

    /// The conformal p-value for a test score:
    /// `p = (1 + #{s_i >= s}) / (n + 1)`.
    pub fn p_value(&self, test_score: i64) -> Result<ConformalPValue, ConformalError> {
        if self.calibration.is_empty() {
            return Err(ConformalError::EmptyCalibration);
        }
        let c = self.calibration.count_at_least(test_score);
        Ok(ConformalPValue {
            numerator: 1 + c,
            denominator: self.calibration.len() as u64 + 1,
        })
    }

    /// Whether the test score lies in the `1-α` conformal prediction set
    /// (`p > α`). Fail-closed: an empty calibration set admits nothing.
    pub fn in_prediction_set(&self, test_score: i64) -> bool {
        match self.p_value(test_score) {
            Ok(p) => !p.le_alpha(self.alpha),
            Err(_) => false,
        }
    }

    /// The calibrated `1-α` regret bound from the current calibration sample.
    ///
    /// `bound = s_(k)` where `k = ceil((n+1)(1-α))` (1-indexed into the
    /// ascending scores). If `k > n` the sample is too small for the
    /// requested coverage and the bound is [`CalibratedRegretBound::saturated`].
    pub fn regret_bound(&self) -> CalibratedRegretBound {
        let n = self.calibration.len() as u64;
        let k = quantile_rank(n, self.alpha);
        let coverage_millionths = self.alpha.coverage_millionths();
        if k == 0 || k > n {
            return CalibratedRegretBound {
                bound_millionths: i64::MAX,
                coverage_millionths,
                calibration_size: n,
                quantile_rank: k,
                saturated: true,
            };
        }
        // k is 1-indexed; scores are ascending.
        let bound_millionths = self.calibration.scores()[(k - 1) as usize];
        CalibratedRegretBound {
            bound_millionths,
            coverage_millionths,
            calibration_size: n,
            quantile_rank: k,
            saturated: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Ledger integration — a calibrated regret bound on every decision
// ---------------------------------------------------------------------------

/// Emit a calibrated regret bound for **every decision** recorded in a
/// martingale ledger, using only **past** scores as the calibration sample
/// for each decision (a strictly causal split: the bound for decision `i`
/// never sees its own or any later score).
///
/// `nonconformity_scores` must align 1:1 with `ledger.events()` in order.
/// The strictly-causal split is also what makes the downstream
/// same-distribution negative test (bd-cixqu.33.4) meaningful: leakage of the
/// test score into its own calibration set would inflate coverage.
///
/// Each emitted bound is bound to its decision's `sequence`, `payload_digest`
/// and `epoch`, so the calibration is replayable and content-addressed in the
/// same way as the underlying ledger.
pub fn calibrate_over_ledger(
    ledger: &MartingaleLedger,
    nonconformity_scores: &[i64],
    alpha: Alpha,
) -> Result<Vec<DecisionRegretBound>, ConformalError> {
    let events = ledger.events();
    if events.len() != nonconformity_scores.len() {
        return Err(ConformalError::LengthMismatch {
            ledger_events: events.len(),
            scores: nonconformity_scores.len(),
        });
    }

    let mut bounds = Vec::with_capacity(events.len());
    let mut calibrator = ConformalCalibrator::new(CalibrationSet::new(), alpha);
    for (event, &score) in events.iter().zip(nonconformity_scores.iter()) {
        // Bound for this decision uses ONLY scores from earlier decisions.
        let bound = calibrator.regret_bound();
        bounds.push(DecisionRegretBound {
            sequence: event.sequence,
            payload_digest: event.payload_digest,
            epoch: event.epoch,
            bound,
        });
        // Now fold this decision's realized score into the calibration sample
        // for the benefit of subsequent decisions.
        calibrator.observe(score);
    }
    Ok(bounds)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::martingale_decision_ledger::{MartingaleLedger, StoppingThreshold};

    fn calib(scores: &[i64], alpha_m: u32) -> ConformalCalibrator {
        ConformalCalibrator::from_scores(
            scores.iter().copied(),
            Alpha::from_millionths(alpha_m).unwrap(),
        )
    }

    #[test]
    fn alpha_rejects_zero_and_one_and_above() {
        assert!(Alpha::from_millionths(0).is_err());
        assert!(Alpha::from_millionths(1_000_000).is_err());
        assert!(Alpha::from_millionths(1_500_000).is_err());
        assert!(Alpha::from_millionths(1).is_ok());
        assert!(Alpha::from_millionths(999_999).is_ok());
    }

    #[test]
    fn alpha_coverage_complements() {
        assert_eq!(Alpha::FIVE_PERCENT.coverage_millionths(), 950_000);
        assert_eq!(Alpha::TEN_PERCENT.coverage_millionths(), 900_000);
        assert_eq!(Alpha::from_millionths(50_000).unwrap().millionths(), 50_000);
    }

    #[test]
    fn calibration_set_stays_sorted_on_observe() {
        let mut set = CalibrationSet::new();
        for s in [5, 1, 3, 2, 4] {
            set.observe(s);
        }
        assert_eq!(set.scores(), &[1, 2, 3, 4, 5]);
        assert_eq!(set.len(), 5);
        assert!(!set.is_empty());
    }

    #[test]
    fn from_scores_sorts() {
        let set = CalibrationSet::from_scores([9, -3, 0, 7]);
        assert_eq!(set.scores(), &[-3, 0, 7, 9]);
    }

    #[test]
    fn count_at_least_handles_ties_and_extremes() {
        let set = CalibrationSet::from_scores([10, 20, 20, 30]);
        // >= 5 -> all 4
        assert_eq!(set.count_at_least(5), 4);
        // >= 20 -> the two 20s and the 30 = 3
        assert_eq!(set.count_at_least(20), 3);
        // >= 31 -> none
        assert_eq!(set.count_at_least(31), 0);
        // >= 30 -> just the 30
        assert_eq!(set.count_at_least(30), 1);
    }

    #[test]
    fn pvalue_empty_calibration_errors() {
        let c = ConformalCalibrator::new(CalibrationSet::new(), Alpha::FIVE_PERCENT);
        assert_eq!(c.p_value(0), Err(ConformalError::EmptyCalibration));
    }

    #[test]
    fn pvalue_formula_matches_definition() {
        // scores {10,20,30,40}, n=4. test=25 -> c = #{>=25} = {30,40} = 2.
        // p = (1+2)/(4+1) = 3/5.
        let c = calib(&[10, 20, 30, 40], 50_000);
        let p = c.p_value(25).unwrap();
        assert_eq!((p.numerator(), p.denominator()), (3, 5));
        assert_eq!(p.as_millionths(), 600_000);
    }

    #[test]
    fn pvalue_smallest_for_most_nonconforming() {
        // A test score above every calibration score: c=0 -> p = 1/(n+1) (the
        // smallest attainable p-value).
        let c = calib(&[1, 2, 3, 4], 50_000);
        let p = c.p_value(1_000).unwrap();
        assert_eq!((p.numerator(), p.denominator()), (1, 5));
    }

    #[test]
    fn pvalue_largest_for_least_nonconforming() {
        // A test score below every calibration score: c=n -> p = (n+1)/(n+1) = 1.
        let c = calib(&[1, 2, 3, 4], 50_000);
        let p = c.p_value(-1_000).unwrap();
        assert_eq!((p.numerator(), p.denominator()), (5, 5));
        assert_eq!(p.as_millionths(), 1_000_000);
    }

    #[test]
    fn le_alpha_is_exact_cross_multiplication() {
        // p = 1/5 = 0.2; α = 0.2 -> p <= α is true (equality).
        let p = ConformalPValue {
            numerator: 1,
            denominator: 5,
        };
        assert!(p.le_alpha(Alpha::from_millionths(200_000).unwrap()));
        // α = 0.199999 -> p (0.2) <= α false.
        assert!(!p.le_alpha(Alpha::from_millionths(199_999).unwrap()));
        // α = 0.200001 -> true.
        assert!(p.le_alpha(Alpha::from_millionths(200_001).unwrap()));
    }

    #[test]
    fn prediction_set_membership_is_p_gt_alpha() {
        let c = calib(&[10, 20, 30, 40], 200_000); // α=0.2
        // test=25 -> p=3/5=0.6 > 0.2 -> in set.
        assert!(c.in_prediction_set(25));
        // test above all -> p=1/5=0.2, not > 0.2 -> NOT in set.
        assert!(!c.in_prediction_set(10_000));
    }

    #[test]
    fn empty_calibration_admits_nothing() {
        let c = ConformalCalibrator::new(CalibrationSet::new(), Alpha::FIVE_PERCENT);
        assert!(!c.in_prediction_set(0));
    }

    #[test]
    fn quantile_rank_ceiling_formula() {
        // n=19, 1-α=0.95 -> (20)(0.95)=19 -> k=19.
        assert_eq!(quantile_rank(19, Alpha::FIVE_PERCENT), 19);
        // n=20, 1-α=0.95 -> (21)(0.95)=19.95 -> ceil=20.
        assert_eq!(quantile_rank(20, Alpha::FIVE_PERCENT), 20);
        // n=99, 1-α=0.95 -> (100)(0.95)=95 -> 95.
        assert_eq!(quantile_rank(99, Alpha::FIVE_PERCENT), 95);
    }

    #[test]
    fn regret_bound_selects_correct_order_statistic() {
        // scores 1..=100 sorted, α=0.05, n=100.
        // k=ceil(101*0.95)=ceil(95.95)=96 -> s_(96) = 96.
        let scores: Vec<i64> = (1..=100).collect();
        let c = ConformalCalibrator::from_scores(scores, Alpha::FIVE_PERCENT);
        let b = c.regret_bound();
        assert!(!b.saturated);
        assert_eq!(b.quantile_rank, 96);
        assert_eq!(b.bound_millionths, 96);
        assert_eq!(b.calibration_size, 100);
        assert_eq!(b.coverage_millionths, 950_000);
    }

    #[test]
    fn regret_bound_saturates_when_sample_too_small() {
        // n=10, α=0.05 -> k=ceil(11*0.95)=ceil(10.45)=11 > 10 -> saturated.
        let c = ConformalCalibrator::from_scores(1..=10, Alpha::FIVE_PERCENT);
        let b = c.regret_bound();
        assert!(b.saturated);
        assert_eq!(b.quantile_rank, 11);
        assert_eq!(b.bound_millionths, i64::MAX);
        // Saturated bound admits everything (certifies nothing).
        assert!(b.admits(i64::MAX));
    }

    #[test]
    fn regret_bound_just_attainable_boundary() {
        // n=19, α=0.05 -> k=19 <= 19 -> NOT saturated; bound = s_(19) = 19.
        let c = ConformalCalibrator::from_scores(1..=19, Alpha::FIVE_PERCENT);
        let b = c.regret_bound();
        assert!(!b.saturated);
        assert_eq!(b.quantile_rank, 19);
        assert_eq!(b.bound_millionths, 19);
    }

    #[test]
    fn regret_bound_admits_below_and_rejects_above() {
        let c = ConformalCalibrator::from_scores(1..=100, Alpha::FIVE_PERCENT);
        let b = c.regret_bound(); // bound = 96
        assert!(b.admits(50));
        assert!(b.admits(96));
        assert!(!b.admits(97));
    }

    #[test]
    fn coverage_is_distribution_free_empirical_check() {
        // Empirical coverage check: with n=99 calibration draws 1..=99 and
        // α=0.05, the bound is s_(95)=95. Of the "next" candidate scores
        // 1..=100 (a fresh exchangeable-ish grid), the fraction admitted must
        // be >= 1-α = 0.95.
        let c = ConformalCalibrator::from_scores(1..=99, Alpha::FIVE_PERCENT);
        let b = c.regret_bound();
        assert_eq!(b.bound_millionths, 95);
        let admitted = (1..=100).filter(|&s| b.admits(s)).count();
        assert!(admitted as f64 / 100.0 >= 0.95 - 1e-9);
    }

    #[test]
    fn observe_updates_bound() {
        let mut c = ConformalCalibrator::from_scores(1..=10, Alpha::TEN_PERCENT);
        // n=10, α=0.1 -> k=ceil(11*0.9)=ceil(9.9)=10 -> bound=s_(10)=10.
        assert_eq!(c.regret_bound().bound_millionths, 10);
        c.observe(100);
        // n=11 -> k=ceil(12*0.9)=ceil(10.8)=11 -> bound=s_(11)=100.
        let b = c.regret_bound();
        assert_eq!(b.calibration_size, 11);
        assert_eq!(b.bound_millionths, 100);
    }

    fn mk_ledger(n: usize) -> MartingaleLedger {
        let threshold = StoppingThreshold::try_from_log_millionths(2_995_732).unwrap();
        let mut ledger = MartingaleLedger::new(threshold, SecurityEpoch::from_raw(1));
        for i in 0..n {
            // Small negative log-LRs so the ledger never stops mid-sequence.
            // Signature: append(log_lr_millionths, payload_digest, timestamp_ns);
            // the epoch is taken from the ledger itself.
            ledger
                .append(
                    -10_000,
                    ContentHash::compute(format!("payload-{i}").as_bytes()),
                    (i as u64 + 1) * 1_000,
                )
                .expect("append within threshold");
        }
        ledger
    }

    #[test]
    fn calibrate_over_ledger_length_mismatch_errors() {
        let ledger = mk_ledger(3);
        let err = calibrate_over_ledger(&ledger, &[1, 2], Alpha::FIVE_PERCENT).unwrap_err();
        assert_eq!(
            err,
            ConformalError::LengthMismatch {
                ledger_events: 3,
                scores: 2
            }
        );
    }

    #[test]
    fn calibrate_over_ledger_is_strictly_causal() {
        let ledger = mk_ledger(5);
        let scores = [10_i64, 20, 30, 40, 50];
        let bounds = calibrate_over_ledger(&ledger, &scores, Alpha::FIVE_PERCENT).unwrap();
        assert_eq!(bounds.len(), 5);
        // Decision 0 has no prior calibration -> saturated (must abstain).
        assert!(bounds[0].bound.saturated);
        assert_eq!(bounds[0].bound.calibration_size, 0);
        // Each subsequent decision's calibration size equals its index (past
        // scores only — no leakage of its own/future score).
        for (i, b) in bounds.iter().enumerate() {
            assert_eq!(b.bound.calibration_size, i as u64);
        }
    }

    #[test]
    fn calibrate_over_ledger_binds_to_decision_identity() {
        let ledger = mk_ledger(4);
        let scores = [1_i64, 2, 3, 4];
        let bounds = calibrate_over_ledger(&ledger, &scores, Alpha::FIVE_PERCENT).unwrap();
        for (event, bound) in ledger.events().iter().zip(bounds.iter()) {
            assert_eq!(event.sequence, bound.sequence);
            assert_eq!(event.payload_digest, bound.payload_digest);
            assert_eq!(event.epoch, bound.epoch);
        }
        // Sequences are 1-indexed and contiguous.
        assert_eq!(
            bounds.iter().map(|b| b.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn empty_ledger_yields_no_bounds() {
        let ledger = mk_ledger(0);
        let bounds = calibrate_over_ledger(&ledger, &[], Alpha::FIVE_PERCENT).unwrap();
        assert!(bounds.is_empty());
    }

    #[test]
    fn calibration_is_deterministic_under_reordering() {
        // Conformal output must depend only on the multiset of scores, not
        // insertion order (determinism / replay invariance).
        let a = ConformalCalibrator::from_scores([3, 1, 4, 1, 5, 9, 2, 6], Alpha::TEN_PERCENT);
        let b = ConformalCalibrator::from_scores([9, 6, 5, 4, 3, 2, 1, 1], Alpha::TEN_PERCENT);
        assert_eq!(a.regret_bound(), b.regret_bound());
        assert_eq!(a.p_value(4).unwrap(), b.p_value(4).unwrap());
    }

    #[test]
    fn serde_round_trip_calibrator_and_bound() {
        let c = ConformalCalibrator::from_scores(1..=30, Alpha::FIVE_PERCENT);
        let json = serde_json::to_string(&c).unwrap();
        let back: ConformalCalibrator = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);

        let b = c.regret_bound();
        let bj = serde_json::to_string(&b).unwrap();
        let bb: CalibratedRegretBound = serde_json::from_str(&bj).unwrap();
        assert_eq!(b, bb);
    }

    #[test]
    fn negative_scores_supported() {
        // Regret/loss scores may be negative (e.g. a gain). Ordering still holds.
        let c = ConformalCalibrator::from_scores([-50, -10, -30, -20, -40], Alpha::TEN_PERCENT);
        // n=5, α=0.1 -> k=ceil(6*0.9)=ceil(5.4)=6 > 5 -> saturated.
        assert!(c.regret_bound().saturated);
        let p = c.p_value(-25).unwrap();
        // sorted: -50,-40,-30,-20,-10 ; >= -25 -> {-20,-10} = 2 ; p=(1+2)/6=3/6.
        assert_eq!((p.numerator(), p.denominator()), (3, 6));
    }

    #[test]
    fn display_renders_human_readable() {
        let c = ConformalCalibrator::from_scores(1..=100, Alpha::FIVE_PERCENT);
        let b = c.regret_bound();
        assert!(format!("{b}").contains("regret_bound=96"));
        let sat = ConformalCalibrator::from_scores(1..=3, Alpha::FIVE_PERCENT).regret_bound();
        assert!(format!("{sat}").contains("SATURATED"));
        assert_eq!(format!("{}", Alpha::FIVE_PERCENT), "α=50000/1e6");
    }
}
