//! PAC-Bayes upper bounds for optimization-promotion candidates.
//!
//! Implements a deterministic fixed-point Catoni-style upper bound:
//!
//! `R(Q) <= (1 - exp(-lambda * r_hat(Q) - (KL(Q||P) + ln(1/delta)) / n))
//!          / (1 - exp(-lambda))`
//!
//! Inputs and outputs use millionths (`1_000_000 = 1.0`) and deterministic
//! integer approximations for `ln` and `exp`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Schema version for serialized PAC-Bayes bound records.
pub const PAC_BAYES_SCHEMA_VERSION: &str = "franken-engine.pac-bayes-bound.v1";

/// Component name for logs and evidence records.
pub const PAC_BAYES_COMPONENT: &str = "pac_bayes_bound";

/// Bead that introduced this module.
pub const PAC_BAYES_BEAD_ID: &str = "bd-cixqu.44.1";

/// Fixed-point unit (`1.0`).
pub const MILLION: u64 = 1_000_000;

const MILLION_I64: i64 = 1_000_000;
const LN_2_MILLIONTHS: i64 = 693_147;
const MAX_CATONI_LAMBDA_MILLIONTHS: u64 = 10 * MILLION;

/// Conservative default Catoni lambda (`0.1`).
pub const DEFAULT_CATONI_LAMBDA_MILLIONTHS: u64 = 100_000;

/// A deterministic distribution over candidate hypotheses.
pub type HypothesisDistribution = BTreeMap<String, u64>;

/// Input for PAC-Bayes bound computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacBayesInput {
    /// Empirical posterior risk `r_hat(Q)` in millionths.
    pub empirical_error_millionths: u64,
    /// Prior distribution `P` over candidate hypotheses; masses sum to `MILLION`.
    pub prior: HypothesisDistribution,
    /// Posterior distribution `Q` over candidate hypotheses; masses sum to `MILLION`.
    pub posterior: HypothesisDistribution,
    /// Number of validation samples.
    pub sample_size: u64,
    /// Failure probability `delta` in millionths.
    pub delta_millionths: u64,
    /// Catoni lambda in millionths.
    pub catoni_lambda_millionths: u64,
}

impl PacBayesInput {
    /// Build input using the module default Catoni lambda.
    pub fn new(
        empirical_error_millionths: u64,
        prior: HypothesisDistribution,
        posterior: HypothesisDistribution,
        sample_size: u64,
        delta_millionths: u64,
    ) -> Self {
        Self {
            empirical_error_millionths,
            prior,
            posterior,
            sample_size,
            delta_millionths,
            catoni_lambda_millionths: DEFAULT_CATONI_LAMBDA_MILLIONTHS,
        }
    }

    /// Override Catoni lambda for tight-grid evaluation.
    pub fn with_catoni_lambda(mut self, catoni_lambda_millionths: u64) -> Self {
        self.catoni_lambda_millionths = catoni_lambda_millionths;
        self
    }
}

/// Computed Catoni PAC-Bayes upper bound and its typed components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacBayesUpperBound {
    /// Schema version.
    pub schema_version: String,
    /// Empirical posterior risk used as input.
    pub empirical_error_millionths: u64,
    /// `KL(Q||P)` in millionths.
    pub kl_divergence_millionths: u64,
    /// `(KL(Q||P) + ln(1/delta)) / n` in millionths.
    pub sample_complexity_millionths: u64,
    /// Catoni upper bound on true risk in millionths.
    pub bound_millionths: u64,
    /// Validation sample count.
    pub sample_size: u64,
    /// Failure probability used for the confidence guarantee.
    pub delta_millionths: u64,
    /// Catoni lambda used for the transform.
    pub catoni_lambda_millionths: u64,
    /// Positive posterior support size.
    pub hypothesis_count: usize,
}

impl PacBayesUpperBound {
    /// Compute the Catoni PAC-Bayes upper bound for the supplied posterior.
    pub fn compute(input: &PacBayesInput) -> Result<Self, PacBayesError> {
        validate_input(input)?;

        let kl_divergence_millionths = kl_divergence_millionths(&input.prior, &input.posterior)?;
        let confidence_millionths = confidence_penalty_millionths(input.delta_millionths);
        let numerator =
            u128::from(kl_divergence_millionths).saturating_add(u128::from(confidence_millionths));
        let sample_complexity_millionths = div_ceil_u128(numerator, input.sample_size);
        let bound_millionths = catoni_upper_bound_millionths(
            input.empirical_error_millionths,
            sample_complexity_millionths,
            input.catoni_lambda_millionths,
        )?;
        let hypothesis_count = input.posterior.values().filter(|mass| **mass > 0).count();

        Ok(Self {
            schema_version: PAC_BAYES_SCHEMA_VERSION.to_string(),
            empirical_error_millionths: input.empirical_error_millionths,
            kl_divergence_millionths,
            sample_complexity_millionths,
            bound_millionths,
            sample_size: input.sample_size,
            delta_millionths: input.delta_millionths,
            catoni_lambda_millionths: input.catoni_lambda_millionths,
            hypothesis_count,
        })
    }
}

/// Errors raised by fail-closed PAC-Bayes input validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PacBayesError {
    /// A probability-like field exceeded `1_000_000`.
    MillionthsOutOfRange { field: String, value: u64 },
    /// A distribution had no entries.
    EmptyDistribution { distribution: String },
    /// A distribution did not sum exactly to `1_000_000`.
    DistributionMassInvalid {
        distribution: String,
        total_millionths: u64,
    },
    /// A positive posterior mass has no positive prior support.
    PriorSupportMissing {
        hypothesis_id: String,
        posterior_mass_millionths: u64,
    },
    /// Sample size was zero.
    ZeroSampleSize,
    /// Delta was outside `(0, 1]`.
    InvalidDelta { delta_millionths: u64 },
    /// Catoni lambda was outside the supported positive range.
    InvalidCatoniLambda { catoni_lambda_millionths: u64 },
    /// Catoni transform denominator collapsed to zero.
    DegenerateCatoniDenominator { catoni_lambda_millionths: u64 },
}

impl fmt::Display for PacBayesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MillionthsOutOfRange { field, value } => {
                write!(f, "{field}={value} is outside fixed-point millionths")
            }
            Self::EmptyDistribution { distribution } => {
                write!(f, "{distribution} distribution is empty")
            }
            Self::DistributionMassInvalid {
                distribution,
                total_millionths,
            } => write!(
                f,
                "{distribution} distribution mass {total_millionths} != {MILLION}"
            ),
            Self::PriorSupportMissing {
                hypothesis_id,
                posterior_mass_millionths,
            } => write!(
                f,
                "posterior mass {posterior_mass_millionths} for {hypothesis_id} has no prior support"
            ),
            Self::ZeroSampleSize => write!(f, "sample_size must be positive"),
            Self::InvalidDelta { delta_millionths } => {
                write!(
                    f,
                    "delta_millionths={delta_millionths} is outside (0, {MILLION}]"
                )
            }
            Self::InvalidCatoniLambda {
                catoni_lambda_millionths,
            } => write!(
                f,
                "catoni_lambda_millionths={catoni_lambda_millionths} is outside supported range"
            ),
            Self::DegenerateCatoniDenominator {
                catoni_lambda_millionths,
            } => write!(
                f,
                "Catoni denominator collapsed for lambda {catoni_lambda_millionths}"
            ),
        }
    }
}

impl std::error::Error for PacBayesError {}

/// Build a distribution from fixed-point masses.
pub fn distribution(entries: &[(&str, u64)]) -> HypothesisDistribution {
    entries
        .iter()
        .map(|(hypothesis_id, mass)| ((*hypothesis_id).to_string(), *mass))
        .collect()
}

/// Compute `KL(Q||P)` in fixed-point millionths.
pub fn kl_divergence_millionths(
    prior: &HypothesisDistribution,
    posterior: &HypothesisDistribution,
) -> Result<u64, PacBayesError> {
    validate_distribution("prior", prior)?;
    validate_distribution("posterior", posterior)?;

    let mut kl_sum: i128 = 0;
    for (hypothesis_id, posterior_mass) in posterior {
        if *posterior_mass == 0 {
            continue;
        }
        let prior_mass = prior.get(hypothesis_id).copied().ok_or_else(|| {
            PacBayesError::PriorSupportMissing {
                hypothesis_id: hypothesis_id.clone(),
                posterior_mass_millionths: *posterior_mass,
            }
        })?;
        if prior_mass == 0 {
            return Err(PacBayesError::PriorSupportMissing {
                hypothesis_id: hypothesis_id.clone(),
                posterior_mass_millionths: *posterior_mass,
            });
        }

        let ratio_millionths =
            (u128::from(*posterior_mass) * u128::from(MILLION) / u128::from(prior_mass)) as u64;
        let ln_ratio_millionths = fixed_point_ln_millionths(ratio_millionths);
        let term =
            i128::from(*posterior_mass) * i128::from(ln_ratio_millionths) / i128::from(MILLION);
        kl_sum = kl_sum.saturating_add(term);
    }

    Ok(kl_sum.max(0).min(i128::from(u64::MAX)) as u64)
}

fn validate_input(input: &PacBayesInput) -> Result<(), PacBayesError> {
    if input.empirical_error_millionths > MILLION {
        return Err(PacBayesError::MillionthsOutOfRange {
            field: "empirical_error_millionths".to_string(),
            value: input.empirical_error_millionths,
        });
    }
    if input.sample_size == 0 {
        return Err(PacBayesError::ZeroSampleSize);
    }
    if input.delta_millionths == 0 || input.delta_millionths > MILLION {
        return Err(PacBayesError::InvalidDelta {
            delta_millionths: input.delta_millionths,
        });
    }
    if input.catoni_lambda_millionths == 0
        || input.catoni_lambda_millionths > MAX_CATONI_LAMBDA_MILLIONTHS
    {
        return Err(PacBayesError::InvalidCatoniLambda {
            catoni_lambda_millionths: input.catoni_lambda_millionths,
        });
    }
    validate_distribution("prior", &input.prior)?;
    validate_distribution("posterior", &input.posterior)?;
    validate_prior_support(&input.prior, &input.posterior)
}

fn validate_distribution(
    distribution_name: &str,
    distribution: &HypothesisDistribution,
) -> Result<(), PacBayesError> {
    if distribution.is_empty() {
        return Err(PacBayesError::EmptyDistribution {
            distribution: distribution_name.to_string(),
        });
    }

    let mut total = 0u64;
    for (hypothesis_id, mass) in distribution {
        if hypothesis_id.is_empty() || *mass > MILLION {
            return Err(PacBayesError::MillionthsOutOfRange {
                field: format!("{distribution_name}.{hypothesis_id}"),
                value: *mass,
            });
        }
        total = total.saturating_add(*mass);
    }

    if total != MILLION {
        return Err(PacBayesError::DistributionMassInvalid {
            distribution: distribution_name.to_string(),
            total_millionths: total,
        });
    }

    Ok(())
}

fn validate_prior_support(
    prior: &HypothesisDistribution,
    posterior: &HypothesisDistribution,
) -> Result<(), PacBayesError> {
    for (hypothesis_id, posterior_mass) in posterior {
        if *posterior_mass == 0 {
            continue;
        }
        if prior.get(hypothesis_id).copied().unwrap_or(0) == 0 {
            return Err(PacBayesError::PriorSupportMissing {
                hypothesis_id: hypothesis_id.clone(),
                posterior_mass_millionths: *posterior_mass,
            });
        }
    }
    Ok(())
}

fn confidence_penalty_millionths(delta_millionths: u64) -> u64 {
    let inverse_delta_millionths =
        (u128::from(MILLION) * u128::from(MILLION) / u128::from(delta_millionths)) as u64;
    fixed_point_ln_millionths(inverse_delta_millionths).max(0) as u64
}

fn catoni_upper_bound_millionths(
    empirical_error_millionths: u64,
    sample_complexity_millionths: u64,
    catoni_lambda_millionths: u64,
) -> Result<u64, PacBayesError> {
    let lambda_empirical = u128::from(catoni_lambda_millionths)
        .saturating_mul(u128::from(empirical_error_millionths))
        / u128::from(MILLION);
    let exponent_millionths =
        lambda_empirical.saturating_add(u128::from(sample_complexity_millionths));
    let exp_numerator =
        exp_neg_millionths(exponent_millionths.min(i128::from(i64::MAX) as u128) as u64);
    let exp_denominator = exp_neg_millionths(catoni_lambda_millionths);

    let numerator = MILLION.saturating_sub(exp_numerator.min(MILLION));
    let denominator = MILLION.saturating_sub(exp_denominator.min(MILLION));
    if denominator == 0 {
        return Err(PacBayesError::DegenerateCatoniDenominator {
            catoni_lambda_millionths,
        });
    }

    let bound = div_ceil_u128(
        u128::from(numerator).saturating_mul(u128::from(MILLION)),
        denominator,
    );
    Ok(bound.min(MILLION))
}

fn exp_neg_millionths(exponent_millionths: u64) -> u64 {
    let clamped = exponent_millionths.min((40 * MILLION) as u64) as i64;
    fixed_point_exp_millionths(-clamped)
}

fn div_ceil_u128(numerator: u128, denominator: u64) -> u64 {
    if numerator == 0 {
        return 0;
    }
    let denominator = u128::from(denominator);
    ((numerator.saturating_add(denominator - 1)) / denominator).min(u128::from(u64::MAX)) as u64
}

fn fixed_point_ln_millionths(x_millionths: u64) -> i64 {
    if x_millionths == 0 {
        return -100 * MILLION_I64;
    }
    if x_millionths == MILLION {
        return 0;
    }

    let mut x = i128::from(x_millionths);
    let million = i128::from(MILLION);
    let mut shifts = 0i64;
    while x > 2 * million {
        x /= 2;
        shifts += 1;
    }
    while x < million / 2 {
        x *= 2;
        shifts -= 1;
    }

    let z = (x - million) * million / (x + million);
    let z2 = z * z / million;
    let mut term = z;
    let mut sum = term;
    for denominator in [3i128, 5, 7, 9, 11] {
        term = term * z2 / million;
        sum += term / denominator;
    }

    let ln_reduced = 2 * sum;
    (ln_reduced + i128::from(shifts) * i128::from(LN_2_MILLIONTHS))
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn fixed_point_exp_millionths(x_millionths: i64) -> u64 {
    let x = i128::from(x_millionths.clamp(-40 * MILLION_I64, 40 * MILLION_I64));
    let ln2 = i128::from(LN_2_MILLIONTHS);
    let half_ln2 = ln2 / 2;

    let mut k = x.div_euclid(ln2);
    let mut r = x - k * ln2;
    if r > half_ln2 {
        r -= ln2;
        k += 1;
    }

    let million = i128::from(MILLION);
    let mut sum = million;
    let mut term = million;
    for n in 1..=12i128 {
        term = term.saturating_mul(r) / million;
        term /= n;
        sum = sum.saturating_add(term);
        if term == 0 {
            break;
        }
    }
    if sum <= 0 {
        return 1;
    }

    let scaled = if k >= 0 {
        let shift = u32::try_from(k).unwrap_or(u32::MAX).min(60);
        sum.checked_shl(shift).unwrap_or(i128::MAX)
    } else {
        let shift = u32::try_from(-k).unwrap_or(u32::MAX).min(120);
        sum >> shift
    };
    scaled.clamp(1, i128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform2() -> HypothesisDistribution {
        distribution(&[
            ("hostcall_elision", 500_000),
            ("typed_slot_fastpath", 500_000),
        ])
    }

    fn mild_posterior() -> HypothesisDistribution {
        distribution(&[
            ("hostcall_elision", 600_000),
            ("typed_slot_fastpath", 400_000),
        ])
    }

    fn skewed_posterior() -> HypothesisDistribution {
        distribution(&[
            ("hostcall_elision", 900_000),
            ("typed_slot_fastpath", 100_000),
        ])
    }

    fn base_input() -> PacBayesInput {
        PacBayesInput::new(120_000, uniform2(), mild_posterior(), 10_000, 50_000)
    }

    fn compute(input: PacBayesInput) -> PacBayesUpperBound {
        PacBayesUpperBound::compute(&input).expect("valid PAC-Bayes input")
    }

    #[test]
    fn constants_are_persistable_contracts() {
        assert_eq!(PAC_BAYES_COMPONENT, "pac_bayes_bound");
        assert!(PAC_BAYES_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(PAC_BAYES_BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn matching_prior_and_posterior_have_zero_kl() {
        let kl = kl_divergence_millionths(&uniform2(), &uniform2()).unwrap();
        assert_eq!(kl, 0);
    }

    #[test]
    fn skewed_posterior_has_positive_kl() {
        let kl = kl_divergence_millionths(&uniform2(), &skewed_posterior()).unwrap();
        assert!(kl > 0);
    }

    #[test]
    fn kl_increases_with_more_skew() {
        let mild = kl_divergence_millionths(&uniform2(), &mild_posterior()).unwrap();
        let skewed = kl_divergence_millionths(&uniform2(), &skewed_posterior()).unwrap();
        assert!(skewed > mild);
    }

    #[test]
    fn zero_posterior_mass_is_ignored_for_support() {
        let prior = distribution(&[("a", 1_000_000)]);
        let posterior = distribution(&[("a", 1_000_000), ("b", 0)]);
        assert_eq!(kl_divergence_millionths(&prior, &posterior).unwrap(), 0);
    }

    #[test]
    fn positive_posterior_without_prior_support_fails() {
        let prior = distribution(&[("a", 1_000_000)]);
        let posterior = distribution(&[("a", 900_000), ("b", 100_000)]);
        assert!(matches!(
            kl_divergence_millionths(&prior, &posterior),
            Err(PacBayesError::PriorSupportMissing { .. })
        ));
    }

    #[test]
    fn empty_prior_fails_closed() {
        let mut input = base_input();
        input.prior.clear();
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::EmptyDistribution { .. })
        ));
    }

    #[test]
    fn empty_posterior_fails_closed() {
        let mut input = base_input();
        input.posterior.clear();
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::EmptyDistribution { .. })
        ));
    }

    #[test]
    fn invalid_prior_mass_fails_closed() {
        let mut input = base_input();
        input.prior.insert("extra".to_string(), 1);
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::DistributionMassInvalid { .. })
        ));
    }

    #[test]
    fn invalid_posterior_mass_fails_closed() {
        let mut input = base_input();
        input
            .posterior
            .insert("typed_slot_fastpath".to_string(), 399_999);
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::DistributionMassInvalid { .. })
        ));
    }

    #[test]
    fn zero_sample_size_fails_closed() {
        let mut input = base_input();
        input.sample_size = 0;
        assert_eq!(
            PacBayesUpperBound::compute(&input).unwrap_err(),
            PacBayesError::ZeroSampleSize
        );
    }

    #[test]
    fn empirical_error_above_one_fails_closed() {
        let mut input = base_input();
        input.empirical_error_millionths = MILLION + 1;
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::MillionthsOutOfRange { .. })
        ));
    }

    #[test]
    fn zero_delta_fails_closed() {
        let mut input = base_input();
        input.delta_millionths = 0;
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::InvalidDelta { .. })
        ));
    }

    #[test]
    fn delta_above_one_fails_closed() {
        let mut input = base_input();
        input.delta_millionths = MILLION + 1;
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::InvalidDelta { .. })
        ));
    }

    #[test]
    fn zero_catoni_lambda_fails_closed() {
        let input = base_input().with_catoni_lambda(0);
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::InvalidCatoniLambda { .. })
        ));
    }

    #[test]
    fn huge_catoni_lambda_fails_closed() {
        let input = base_input().with_catoni_lambda(10 * MILLION + 1);
        assert!(matches!(
            PacBayesUpperBound::compute(&input),
            Err(PacBayesError::InvalidCatoniLambda { .. })
        ));
    }

    #[test]
    fn computed_bound_carries_components() {
        let bound = compute(base_input());
        assert_eq!(bound.schema_version, PAC_BAYES_SCHEMA_VERSION);
        assert_eq!(bound.empirical_error_millionths, 120_000);
        assert!(bound.kl_divergence_millionths > 0);
        assert!(bound.sample_complexity_millionths > 0);
        assert_eq!(bound.hypothesis_count, 2);
    }

    #[test]
    fn bound_is_at_least_empirical_error() {
        let bound = compute(base_input());
        assert!(bound.bound_millionths >= bound.empirical_error_millionths);
    }

    #[test]
    fn bound_is_monotone_in_kl() {
        let mild = compute(PacBayesInput::new(
            100_000,
            uniform2(),
            mild_posterior(),
            10_000,
            50_000,
        ));
        let skewed = compute(PacBayesInput::new(
            100_000,
            uniform2(),
            skewed_posterior(),
            10_000,
            50_000,
        ));
        assert!(skewed.kl_divergence_millionths > mild.kl_divergence_millionths);
        assert!(skewed.bound_millionths >= mild.bound_millionths);
    }

    #[test]
    fn sample_complexity_decreases_with_sample_size() {
        let small = compute(base_input());
        let mut large_input = base_input();
        large_input.sample_size = 1_000_000;
        let large = compute(large_input);
        assert!(large.sample_complexity_millionths < small.sample_complexity_millionths);
    }

    #[test]
    fn bound_decreases_with_sample_size() {
        let small = compute(base_input());
        let mut large_input = base_input();
        large_input.sample_size = 1_000_000;
        let large = compute(large_input);
        assert!(large.bound_millionths <= small.bound_millionths);
    }

    #[test]
    fn bound_increases_with_empirical_error() {
        let low = compute(PacBayesInput::new(
            50_000,
            uniform2(),
            mild_posterior(),
            10_000,
            50_000,
        ));
        let high = compute(PacBayesInput::new(
            200_000,
            uniform2(),
            mild_posterior(),
            10_000,
            50_000,
        ));
        assert!(high.bound_millionths > low.bound_millionths);
    }

    #[test]
    fn smaller_delta_increases_bound() {
        let loose = compute(PacBayesInput::new(
            100_000,
            uniform2(),
            mild_posterior(),
            10_000,
            100_000,
        ));
        let tight = compute(PacBayesInput::new(
            100_000,
            uniform2(),
            mild_posterior(),
            10_000,
            10_000,
        ));
        assert!(tight.bound_millionths >= loose.bound_millionths);
    }

    #[test]
    fn bound_clamps_at_one() {
        let bound = compute(PacBayesInput::new(
            1_000_000,
            uniform2(),
            skewed_posterior(),
            1,
            1,
        ));
        assert_eq!(bound.bound_millionths, MILLION);
    }

    #[test]
    fn large_n_low_kl_approaches_empirical_error_with_small_lambda() {
        let bound = compute(
            PacBayesInput::new(250_000, uniform2(), uniform2(), 1_000_000_000, MILLION)
                .with_catoni_lambda(10_000),
        );
        assert!(bound.bound_millionths <= 252_000);
    }

    #[test]
    fn input_serde_roundtrip() {
        let input = base_input();
        let json = serde_json::to_string(&input).unwrap();
        let back: PacBayesInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn output_serde_roundtrip() {
        let bound = compute(base_input());
        let json = serde_json::to_string(&bound).unwrap();
        let back: PacBayesUpperBound = serde_json::from_str(&json).unwrap();
        assert_eq!(bound, back);
    }

    #[test]
    fn output_is_deterministic() {
        let first = compute(base_input());
        let second = compute(base_input());
        assert_eq!(first, second);
    }

    #[test]
    fn btree_order_keeps_kl_deterministic() {
        let prior_a = distribution(&[("a", 500_000), ("b", 500_000)]);
        let prior_b = distribution(&[("b", 500_000), ("a", 500_000)]);
        let posterior_a = distribution(&[("a", 650_000), ("b", 350_000)]);
        let posterior_b = distribution(&[("b", 350_000), ("a", 650_000)]);
        assert_eq!(
            kl_divergence_millionths(&prior_a, &posterior_a).unwrap(),
            kl_divergence_millionths(&prior_b, &posterior_b).unwrap()
        );
    }
}
