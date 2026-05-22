// Expected Information-Value Scoring — Track W.1 substrate (bd-cixqu.23.1).
//
// For each active moonshot, compute the *expected information value*
// (EIV) of running the next observation: the expected reduction in
// posterior entropy on the success outcome given that the
// observation arrives. This is the per-moonshot signal the W.2
// weekly ranked report sorts by, and the operator-facing surface
// (bd-cixqu.23.3, `MOONSHOT_PORTFOLIO_REVIEW_SURFACE.md`) reads.
//
// Per the bead's "replaced by a submodular formulation in Track LL"
// note: this module's `eiv_millionths` value is the per-moonshot
// score; the submodular aggregation across the portfolio is the
// follow-up under Track LL. We deliberately keep the per-moonshot
// computation independent of how it's aggregated upstream so the
// submodular replacement can swap one without rewriting the other.
//
// Computation:
//
//   * Treat success on each moonshot as a Bernoulli random variable
//     `X ~ Bernoulli(p_success)`. The prior entropy is
//     `H(p) = -p log2 p - (1-p) log2 (1-p)` (binary entropy).
//   * A new observation arrives with binary outcome `D ∈ {success,
//     failure}`. Under a beta-conjugate update,
//     `p | D = success` has posterior mean
//     `(α + 1) / (α + β + 1)` where (α, β) are the prior pseudo-counts
//     derived from history. Symmetric for failure.
//   * The expected post-observation entropy is
//     `E[H(p|D)] = p · H(p|success) + (1-p) · H(p|failure)`.
//   * EIV = `H(p) - E[H(p|D)] ∈ [0, H(p)]`. Higher = more informative
//     observation.
//
// Numerics:
//
//   * All probabilities and EIV values are stored as fixed-point
//     millionths (1_000_000 = 1.0). Binary entropy is also stored in
//     millionths of a bit (max H is 1.0 bit at p = 0.5).
//   * The natural log uses a polynomial approximation accurate to
//     within ~1e-3 over (0, 1]; we then convert to log2. The
//     approximation is intentionally crude — what matters for ranking
//     is determinism + monotonicity, not numerical precision. Track LL
//     reformulation can pin a more precise approximation if needed.
//   * `compute_binary_entropy_millionths(0)` and `(1_000_000)` return
//     exactly zero (degenerate distributions carry no entropy and
//     no further observation can be informative).
//
// Reference: Lindley (1956) "On a Measure of the Information Provided
// by an Experiment" — the EIV criterion.

use crate::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::fmt;

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// PriorEvidence — the Bayesian prior at the per-moonshot level
// ---------------------------------------------------------------------------

/// Project-history-derived prior on a single moonshot's success
/// outcome. `success_pseudo_count + failure_pseudo_count` is the
/// effective sample size of the prior; higher means stronger prior
/// (less informative future observations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorEvidence {
    /// Bayesian α pseudo-count for success.
    pub success_pseudo_count: u32,
    /// Bayesian β pseudo-count for failure.
    pub failure_pseudo_count: u32,
}

impl PriorEvidence {
    /// Uninformative uniform prior (Beta(1, 1)).
    pub fn uniform() -> Self {
        Self {
            success_pseudo_count: 1,
            failure_pseudo_count: 1,
        }
    }

    /// Build a prior from raw pseudo-counts. Both fields must be
    /// strictly positive — a zero pseudo-count makes the EIV ill-
    /// defined.
    pub fn try_new(success: u32, failure: u32) -> Result<Self, EivError> {
        if success == 0 || failure == 0 {
            return Err(EivError::DegeneratePrior);
        }
        Ok(Self {
            success_pseudo_count: success,
            failure_pseudo_count: failure,
        })
    }

    /// Posterior mean P(success) in millionths.
    pub fn p_success_millionths(&self) -> i64 {
        let total = (self.success_pseudo_count + self.failure_pseudo_count) as i64;
        (self.success_pseudo_count as i64) * MILLION / total
    }

    /// Total pseudo-count (sample size of the prior).
    pub fn total(&self) -> u32 {
        self.success_pseudo_count + self.failure_pseudo_count
    }
}

// ---------------------------------------------------------------------------
// EivScore — per-moonshot EIV record
// ---------------------------------------------------------------------------

/// Per-moonshot EIV record. Aggregated over the active portfolio by
/// the W.2 ranked report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EivScore {
    /// The scored moonshot.
    pub moonshot_id: String,
    /// Prior entropy in millionths-of-a-bit.
    pub prior_entropy_millimillibits: i64,
    /// Expected post-observation entropy in millionths-of-a-bit.
    pub expected_post_entropy_millimillibits: i64,
    /// EIV = prior - expected_post, in millionths-of-a-bit. Always
    /// non-negative.
    pub eiv_millimillibits: i64,
    /// P(success) at the time of scoring, in millionths.
    pub p_success_millionths: i64,
    /// Pseudo-count totals supplied as the prior.
    pub prior_total_count: u32,
    /// Wall-clock-ish timestamp.
    pub computed_at_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl EivScore {
    /// Compute the EIV score for a moonshot.
    pub fn compute(
        moonshot_id: impl Into<String>,
        prior: PriorEvidence,
        computed_at_ns: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let p = prior.p_success_millionths();
        let q = MILLION - p;
        let prior_h = binary_entropy_millimillibits(p);

        // Posterior after observing success: alpha+1, beta unchanged.
        let post_success_p =
            (prior.success_pseudo_count as i64 + 1) * MILLION / ((prior.total() as i64) + 1);
        // Posterior after observing failure: alpha unchanged, beta+1.
        let post_failure_p =
            (prior.success_pseudo_count as i64) * MILLION / ((prior.total() as i64) + 1);

        let h_post_success = binary_entropy_millimillibits(post_success_p);
        let h_post_failure = binary_entropy_millimillibits(post_failure_p);

        // E[H(p|D)] = p·H(p|success) + (1-p)·H(p|failure). All in
        // millionths-of-a-bit; weight by probability in millionths
        // and divide once.
        let expected_post_i128 =
            (p as i128) * (h_post_success as i128) + (q as i128) * (h_post_failure as i128);
        let expected_post = (expected_post_i128 / (MILLION as i128)) as i64;

        let eiv = (prior_h - expected_post).max(0);

        Self {
            moonshot_id: moonshot_id.into(),
            prior_entropy_millimillibits: prior_h,
            expected_post_entropy_millimillibits: expected_post,
            eiv_millimillibits: eiv,
            p_success_millionths: p,
            prior_total_count: prior.total(),
            computed_at_ns,
            epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// Binary entropy in fixed-point millionths-of-a-bit
// ---------------------------------------------------------------------------

/// Binary entropy `H(p) = -p log2(p) - (1-p) log2(1-p)` in
/// millionths-of-a-bit. `p` is in millionths of probability.
///
/// At p = 0 or p = 1, H = 0 exactly. At p = 0.5, H = 1_000_000
/// (one bit). For other p, uses a deterministic polynomial
/// approximation accurate to within roughly 1e-3 — sufficient for
/// ranking but NOT a high-precision numerical primitive.
pub fn binary_entropy_millimillibits(p_millionths: i64) -> i64 {
    if p_millionths <= 0 || p_millionths >= MILLION {
        return 0;
    }
    let p = (p_millionths as f64) / (MILLION as f64);
    let q = 1.0 - p;
    // H(p) = -p log2(p) - q log2(q), in bits.
    let h_bits = -(p * p.log2() + q * q.log2());
    // Clamp to [0, 1] and scale to millionths-of-a-bit.
    let h_clamped = h_bits.clamp(0.0, 1.0);
    (h_clamped * (MILLION as f64)).round() as i64
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EivError {
    /// `PriorEvidence::try_new` was called with a zero pseudo-count.
    DegeneratePrior,
}

impl fmt::Display for EivError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegeneratePrior => {
                f.write_str("prior pseudo-counts must both be strictly positive")
            }
        }
    }
}

impl std::error::Error for EivError {}

// ---------------------------------------------------------------------------
// Tests — EIV correctness + ranking-relevant monotonicity properties
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // ----- PriorEvidence -----

    #[test]
    fn uniform_prior_is_beta_one_one() {
        let p = PriorEvidence::uniform();
        assert_eq!(p.success_pseudo_count, 1);
        assert_eq!(p.failure_pseudo_count, 1);
        assert_eq!(p.p_success_millionths(), 500_000);
        assert_eq!(p.total(), 2);
    }

    #[test]
    fn try_new_rejects_zero_success() {
        assert_eq!(
            PriorEvidence::try_new(0, 5).unwrap_err(),
            EivError::DegeneratePrior
        );
    }

    #[test]
    fn try_new_rejects_zero_failure() {
        assert_eq!(
            PriorEvidence::try_new(5, 0).unwrap_err(),
            EivError::DegeneratePrior
        );
    }

    #[test]
    fn p_success_millionths_reflects_pseudo_counts() {
        // 3 success, 1 failure → 75%.
        let p = PriorEvidence::try_new(3, 1).unwrap();
        assert_eq!(p.p_success_millionths(), 750_000);
        // 1 success, 3 failure → 25%.
        let p = PriorEvidence::try_new(1, 3).unwrap();
        assert_eq!(p.p_success_millionths(), 250_000);
    }

    // ----- binary_entropy_millimillibits -----

    #[test]
    fn binary_entropy_zero_at_endpoints() {
        assert_eq!(binary_entropy_millimillibits(0), 0);
        assert_eq!(binary_entropy_millimillibits(MILLION), 0);
    }

    #[test]
    fn binary_entropy_max_at_half() {
        let h = binary_entropy_millimillibits(500_000);
        // Should be very close to 1.0 bit = 1_000_000.
        assert!(h >= 999_000, "expected ~1.0 bit, got {h}");
        assert!(h <= 1_000_000);
    }

    #[test]
    fn binary_entropy_symmetry_around_half() {
        // H(p) == H(1-p).
        for p in [100_000, 250_000, 333_333, 400_000] {
            let h1 = binary_entropy_millimillibits(p);
            let h2 = binary_entropy_millimillibits(MILLION - p);
            assert_eq!(h1, h2, "symmetry violated at p={p}");
        }
    }

    #[test]
    fn binary_entropy_monotone_increasing_toward_half() {
        // For p < 0.5, H is increasing.
        let h1 = binary_entropy_millimillibits(100_000);
        let h2 = binary_entropy_millimillibits(200_000);
        let h3 = binary_entropy_millimillibits(400_000);
        let h_half = binary_entropy_millimillibits(500_000);
        assert!(h1 < h2);
        assert!(h2 < h3);
        assert!(h3 < h_half);
    }

    // ----- EIV scoring -----

    #[test]
    fn eiv_score_carries_all_inputs() {
        let s = EivScore::compute("m1", PriorEvidence::uniform(), 12345, epoch());
        assert_eq!(s.moonshot_id, "m1");
        assert_eq!(s.p_success_millionths, 500_000);
        assert_eq!(s.prior_total_count, 2);
        assert_eq!(s.computed_at_ns, 12345);
    }

    #[test]
    fn eiv_is_non_negative() {
        for (a, b) in [(1, 1), (3, 1), (5, 5), (10, 2), (1, 10)] {
            let s = EivScore::compute("m", PriorEvidence::try_new(a, b).unwrap(), 0, epoch());
            assert!(
                s.eiv_millimillibits >= 0,
                "eiv negative for (α={a}, β={b}): {}",
                s.eiv_millimillibits
            );
        }
    }

    #[test]
    fn eiv_is_zero_for_degenerate_distributions() {
        // Very lopsided prior: almost all the mass on one side. EIV
        // should approach zero — there's no information left to gain.
        let s = EivScore::compute("m", PriorEvidence::try_new(10_000, 1).unwrap(), 0, epoch());
        // Within 5_000 millionths-of-a-bit of zero (5e-3 bits).
        assert!(s.eiv_millimillibits.abs() <= 5_000);
    }

    #[test]
    fn eiv_is_largest_at_uniform_prior() {
        // The maximally-uncertain prior should produce the highest EIV.
        let uniform = EivScore::compute("m", PriorEvidence::uniform(), 0, epoch());
        for (a, b) in [(3, 1), (5, 1), (10, 1), (1, 5)] {
            let s = EivScore::compute("m", PriorEvidence::try_new(a, b).unwrap(), 0, epoch());
            assert!(
                uniform.eiv_millimillibits >= s.eiv_millimillibits,
                "uniform EIV {} should be ≥ ({},{}) EIV {}",
                uniform.eiv_millimillibits,
                a,
                b,
                s.eiv_millimillibits
            );
        }
    }

    #[test]
    fn eiv_decreases_as_sample_size_grows() {
        // Same posterior mean but more pseudo-counts → less informative
        // future observation.
        let small = EivScore::compute("m", PriorEvidence::try_new(1, 1).unwrap(), 0, epoch());
        let large = EivScore::compute("m", PriorEvidence::try_new(100, 100).unwrap(), 0, epoch());
        assert!(
            small.eiv_millimillibits > large.eiv_millimillibits,
            "small={} large={}",
            small.eiv_millimillibits,
            large.eiv_millimillibits
        );
    }

    #[test]
    fn eiv_components_consistent() {
        let s = EivScore::compute("m", PriorEvidence::try_new(3, 5).unwrap(), 0, epoch());
        // eiv = prior - expected_post (after clamping to ≥0).
        let derived =
            (s.prior_entropy_millimillibits - s.expected_post_entropy_millimillibits).max(0);
        assert_eq!(s.eiv_millimillibits, derived);
    }

    #[test]
    fn eiv_expected_post_below_prior() {
        // Observing reduces expected entropy (information non-negative).
        let s = EivScore::compute("m", PriorEvidence::try_new(3, 5).unwrap(), 0, epoch());
        assert!(s.expected_post_entropy_millimillibits <= s.prior_entropy_millimillibits);
    }

    // ----- Determinism -----

    #[test]
    fn eiv_computation_is_deterministic() {
        let p = PriorEvidence::try_new(7, 11).unwrap();
        let s1 = EivScore::compute("m", p, 100, epoch());
        let s2 = EivScore::compute("m", p, 100, epoch());
        assert_eq!(s1, s2);
    }

    #[test]
    fn eiv_score_is_independent_of_timestamp() {
        // Different timestamps → different `computed_at_ns` but same
        // scoring fields.
        let p = PriorEvidence::try_new(7, 11).unwrap();
        let s1 = EivScore::compute("m", p, 100, epoch());
        let s2 = EivScore::compute("m", p, 200, epoch());
        assert_eq!(
            s1.eiv_millimillibits, s2.eiv_millimillibits,
            "timestamp must not affect score"
        );
        assert_eq!(
            s1.prior_entropy_millimillibits,
            s2.prior_entropy_millimillibits
        );
        assert_ne!(s1.computed_at_ns, s2.computed_at_ns);
    }

    // ----- Ranking property -----

    #[test]
    fn ranking_orders_moonshots_by_eiv() {
        let priors = vec![
            ("m_uniform", PriorEvidence::uniform()),
            ("m_lopsided", PriorEvidence::try_new(100, 1).unwrap()),
            ("m_modest", PriorEvidence::try_new(3, 1).unwrap()),
        ];
        let mut scores: Vec<EivScore> = priors
            .into_iter()
            .map(|(id, p)| EivScore::compute(id, p, 0, epoch()))
            .collect();
        // Sort descending by EIV.
        scores.sort_by(|a, b| b.eiv_millimillibits.cmp(&a.eiv_millimillibits));
        // Highest should be uniform; lowest lopsided.
        assert_eq!(scores[0].moonshot_id, "m_uniform");
        assert_eq!(scores[2].moonshot_id, "m_lopsided");
    }

    // ----- Serde / display -----

    #[test]
    fn score_serde_round_trip() {
        let s = EivScore::compute("m-serde", PriorEvidence::try_new(2, 3).unwrap(), 0, epoch());
        let json = serde_json::to_string(&s).unwrap();
        let restored: EivScore = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn prior_serde_round_trip() {
        let p = PriorEvidence::try_new(7, 11).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let restored: PriorEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }

    #[test]
    fn error_display_message() {
        let s = format!("{}", EivError::DegeneratePrior);
        assert!(s.contains("strictly positive"));
    }
}
