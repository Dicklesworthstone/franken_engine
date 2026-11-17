//! (ε,δ)-differential privacy for posterior updates in federated learning.
//!
//! Calibrates the Gaussian mechanism for bounded posterior updates using
//! conservative fixed-point arithmetic. The caller must supply a suitable secure
//! Gaussian sampler; the deterministic test sampler is not a privacy mechanism.
//! Extension identity, epoch, cohort, confidence weights and prior are public
//! inputs to this contract. Raw evidence and uncloaked gradients are not releases.
//!
//! References:
//! - McMahan et al. 2017: "Communication-Efficient Learning of Deep Networks from Decentralized Data"
//! - Bonawitz et al. 2017: "Practical Secure Aggregation for Privacy-Preserving Machine Learning"
//! - Dwork & Roth 2014: "The Algorithmic Foundations of Differential Privacy"
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for deterministic
//! cross-platform operation. Privacy budget (ε,δ) is tracked per aggregation round
//! to prevent privacy leakage through composition.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bayesian_posterior::Posterior;
use crate::federated_posterior_aggregation::{AggregatedPosteriorUpdate, PosteriorDelta};
use crate::fleet_immune_protocol::NodeId;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point unit (1.0 = 1_000_000 millionths).
const MILLION: i64 = 1_000_000;

/// Default epsilon (privacy parameter) in millionths - conservative privacy setting.
/// 0.1 = 100_000 millionths provides strong privacy guarantees.
const DEFAULT_EPSILON_MILLIONTHS: u64 = 100_000;

/// Default delta (privacy parameter) in millionths - probability of privacy failure.
/// 1e-5 = 10 millionths is a common setting for delta in (ε,δ)-DP.
const DEFAULT_DELTA_MILLIONTHS: u64 = 10;

/// Maximum supported epsilon to prevent weak privacy settings.
/// 1.0 = 1_000_000 millionths is generally considered the upper bound for meaningful DP.
const MAX_EPSILON_MILLIONTHS: u64 = 1_000_000;

/// Maximum supported delta to maintain strong privacy guarantees.
/// 1e-4 = 100 millionths is an upper bound for reasonable delta values.
const MAX_DELTA_MILLIONTHS: u64 = 100;

/// Replace-one L2 sensitivity of a validated posterior delta. Four coordinates
/// in [-1, 1] have norm at most 2; replacing one such zero-sum vector by another
/// has distance at most 4. The bound is attained by opposite [1, 1, -1, -1]
/// vectors. Metadata and confidence weights are declared public.
pub(crate) const GLOBAL_SENSITIVITY_MILLIONTHS: u64 = 4_000_000;

/// Conservative upper bound for DP-SGD clipping norm validation.
const MAX_CLIPPING_NORM_MILLIONTHS: u64 = 4_000_000;

// ---------------------------------------------------------------------------
// PrivacyParameters - (ε,δ) configuration
// ---------------------------------------------------------------------------

/// Privacy parameters for (ε,δ)-differential privacy.
///
/// Epsilon (ε) controls the privacy-utility tradeoff: smaller values provide
/// stronger privacy but more noise. Delta (δ) bounds the probability that
/// the privacy guarantee fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyParameters {
    /// Epsilon parameter in millionths (privacy budget).
    pub epsilon_millionths: u64,
    /// Delta parameter in millionths (failure probability).
    pub delta_millionths: u64,
}

impl PrivacyParameters {
    /// Create privacy parameters with validation.
    pub fn new(
        epsilon_millionths: u64,
        delta_millionths: u64,
    ) -> Result<Self, DifferentialPrivacyError> {
        let parameters = Self {
            epsilon_millionths,
            delta_millionths,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    /// Validate public fields, including values restored from serialized input.
    /// The finite Gaussian mechanism requires strictly positive delta.
    pub fn validate(&self) -> Result<(), DifferentialPrivacyError> {
        if self.epsilon_millionths == 0 || self.epsilon_millionths > MAX_EPSILON_MILLIONTHS {
            return Err(DifferentialPrivacyError::InvalidEpsilon);
        }
        if self.delta_millionths == 0 || self.delta_millionths > MAX_DELTA_MILLIONTHS {
            return Err(DifferentialPrivacyError::InvalidDelta);
        }
        Ok(())
    }

    /// Strong privacy parameters (lower epsilon, lower delta).
    pub fn strong_privacy() -> Self {
        Self {
            epsilon_millionths: 50_000,
            delta_millionths: 5,
        }
    }

    /// Moderate privacy parameters (balanced privacy-utility).
    pub fn moderate_privacy() -> Self {
        Self {
            epsilon_millionths: 200_000,
            delta_millionths: 20,
        }
    }

    /// Conservative Gaussian scale in millionths:
    /// sigma = sensitivity * sqrt(2 * ln(1.25 / delta)) / epsilon.
    ///
    /// Dwork--Roth, Appendix A, applies for 0 < epsilon <= 1. Logarithm,
    /// square root and final division round upward, including the logarithm's
    /// omitted positive series tail. The result must fit the signed sampler
    /// interface; an unrepresentable scale is refused, never saturated.
    pub fn gaussian_noise_scale(
        &self,
        sensitivity_millionths: u64,
    ) -> Result<u64, DifferentialPrivacyError> {
        self.validate()?;
        // The logarithm uses M^2 precision. Its square root therefore has
        // M precision; omitting that second scale produces ~1000x too little
        // noise when taking the square root of a millionths logarithm.
        let ln_upper = gaussian_ln_ratio_upper(self.delta_millionths);
        let root = ceil_sqrt_u128(2 * ln_upper);
        // Validated delta bounds root by 6*M, so even u64::MAX sensitivity
        // multiplies without overflowing u128.
        let scale = (root * u128::from(sensitivity_millionths))
            .div_ceil(u128::from(self.epsilon_millionths));
        if scale > i64::MAX as u128 {
            return Err(DifferentialPrivacyError::NoiseScaleOutOfRange);
        }
        Ok(scale as u64)
    }
}

/// Upper bound for ln(1_250_000 / delta), scaled by M^2.
///
/// Range reduction uses exact integer ratios. For m in [1, 2],
/// ln(m) = 2 * sum(y^(2*j+1)/(2*j+1)), y = (m-1)/(m+1).
/// Every fixed-point operation rounds up. y_up <= 1/3 + 1/S < 1/2;
/// after 24 terms the omitted tail is at most
/// (8/3) * 2^-49 / 49 < 1/S. The final extra unit covers it.
fn gaussian_ln_ratio_upper(delta_millionths: u64) -> u128 {
    const SCALE: u128 = 1_000_000_000_000;
    const LN_2_UP: u128 = 693_147_180_560;
    const NUMERATOR: u128 = 1_250_000;

    let mut denominator = u128::from(delta_millionths);
    let mut powers_of_two = 0u128;
    while NUMERATOR > 2 * denominator {
        denominator *= 2;
        powers_of_two += 1;
    }

    let y = ((NUMERATOR - denominator) * SCALE).div_ceil(NUMERATOR + denominator);
    let y_squared = (y * y).div_ceil(SCALE);
    let mut power = y;
    let mut sum = y;
    for j in 1..24u128 {
        power = (power * y_squared).div_ceil(SCALE);
        sum += power.div_ceil(2 * j + 1);
    }
    powers_of_two * LN_2_UP + 2 * sum + 1
}

fn ceil_sqrt_u128(value: u128) -> u128 {
    let root = value.isqrt();
    root + u128::from(root * root != value)
}

impl Default for PrivacyParameters {
    fn default() -> Self {
        Self {
            epsilon_millionths: DEFAULT_EPSILON_MILLIONTHS,
            delta_millionths: DEFAULT_DELTA_MILLIONTHS,
        }
    }
}

// ---------------------------------------------------------------------------
// PrivacyBudget - Budget tracking per node/round
// ---------------------------------------------------------------------------

/// Tracks privacy budget consumption across multiple aggregation rounds.
///
/// Privacy budget is finite and must be carefully managed to prevent
/// privacy leakage through composition attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    /// Total epsilon budget allocated.
    pub total_epsilon_millionths: u64,
    /// Total delta budget allocated.
    pub total_delta_millionths: u64,
    /// Epsilon consumed so far.
    pub consumed_epsilon_millionths: u64,
    /// Delta consumed so far.
    pub consumed_delta_millionths: u64,
    /// Per-round budget consumption history.
    pub round_consumptions: BTreeMap<String, PrivacyParameters>,
    /// Budget creation epoch.
    pub epoch: SecurityEpoch,
}

impl PrivacyBudget {
    /// Create a new privacy budget with specified total allocation.
    pub fn new(
        total_epsilon_millionths: u64,
        total_delta_millionths: u64,
        epoch: SecurityEpoch,
    ) -> Result<Self, DifferentialPrivacyError> {
        if total_epsilon_millionths == 0 || total_epsilon_millionths > MAX_EPSILON_MILLIONTHS * 100
        {
            return Err(DifferentialPrivacyError::InvalidEpsilon);
        }
        if total_delta_millionths > MAX_DELTA_MILLIONTHS * 100 {
            return Err(DifferentialPrivacyError::InvalidDelta);
        }

        Ok(Self {
            total_epsilon_millionths,
            total_delta_millionths,
            consumed_epsilon_millionths: 0,
            consumed_delta_millionths: 0,
            round_consumptions: BTreeMap::new(),
            epoch,
        })
    }

    /// Check if budget is sufficient for a proposed allocation.
    pub fn can_allocate(&self, params: &PrivacyParameters) -> bool {
        if params.validate().is_err() {
            return false;
        }
        let Some(epsilon) = self
            .consumed_epsilon_millionths
            .checked_add(params.epsilon_millionths)
        else {
            return false;
        };
        let Some(delta) = self
            .consumed_delta_millionths
            .checked_add(params.delta_millionths)
        else {
            return false;
        };
        epsilon <= self.total_epsilon_millionths && delta <= self.total_delta_millionths
    }

    /// Allocate budget for a round (if sufficient budget exists).
    pub fn allocate_for_round(
        &mut self,
        round_id: &str,
        params: PrivacyParameters,
    ) -> Result<(), DifferentialPrivacyError> {
        params.validate()?;
        if !self.can_allocate(&params) {
            return Err(DifferentialPrivacyError::InsufficientBudget);
        }

        if self.round_consumptions.contains_key(round_id) {
            return Err(DifferentialPrivacyError::DuplicateRoundAllocation);
        }

        self.consumed_epsilon_millionths += params.epsilon_millionths;
        self.consumed_delta_millionths += params.delta_millionths;
        self.round_consumptions.insert(round_id.to_string(), params);

        Ok(())
    }

    /// Get remaining budget.
    pub fn remaining_epsilon(&self) -> u64 {
        self.total_epsilon_millionths
            .saturating_sub(self.consumed_epsilon_millionths)
    }

    pub fn remaining_delta(&self) -> u64 {
        self.total_delta_millionths
            .saturating_sub(self.consumed_delta_millionths)
    }

    /// Check if budget is nearly exhausted (less than 10% remaining).
    pub fn is_nearly_exhausted(&self) -> bool {
        self.remaining_epsilon() < self.total_epsilon_millionths / 10
            || self.remaining_delta() < self.total_delta_millionths / 10
    }
}

// ---------------------------------------------------------------------------
// PrivatePosteriorDelta - Differentially private posterior delta
// ---------------------------------------------------------------------------

/// A posterior delta with differential privacy noise applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePosteriorDelta {
    /// Underlying posterior delta.
    pub base_delta: PosteriorDelta,
    /// Applied privacy parameters.
    pub privacy_params: PrivacyParameters,
    /// Noise scale used (for transparency/debugging).
    pub noise_scale_millionths: u64,
    /// Round ID this delta belongs to.
    pub round_id: String,
}

impl PrivatePosteriorDelta {
    /// Perturb one bounded, zero-sum posterior delta. Extension identity, epoch,
    /// confidence weight and round id are public metadata, not private inputs.
    /// Nonempty extension and round identities are required. The source
    /// evidence hash is replaced by a digest of the released data.
    pub fn from_delta(
        delta: PosteriorDelta,
        privacy_params: PrivacyParameters,
        round_id: String,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Result<Self, DifferentialPrivacyError> {
        if round_id.is_empty() || delta.extension_id.is_empty() {
            return Err(DifferentialPrivacyError::InconsistentAggregationMetadata);
        }
        let scale = privacy_params.gaussian_noise_scale(GLOBAL_SENSITIVITY_MILLIONTHS)?;
        if !delta.is_valid() {
            return Err(DifferentialPrivacyError::InvalidPosteriorDelta);
        }
        Ok(Self::from_validated_delta(
            delta,
            privacy_params,
            round_id,
            scale,
            noise_generator,
        ))
    }

    /// All fallible validation happens before the budget is charged. Sampling
    /// and the following postprocessing cannot refund or partially spend it.
    fn from_validated_delta(
        mut delta: PosteriorDelta,
        privacy_params: PrivacyParameters,
        round_id: String,
        noise_scale: u64,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Self {
        let components = [
            delta.delta_benign_millionths,
            delta.delta_anomalous_millionths,
            delta.delta_malicious_millionths,
            delta.delta_unknown_millionths,
        ];
        // Clamping uses a public bound and only noisy coordinates. Centering
        // four values in [-MAX/2, MAX/2] remains representable in i64, even
        // when an injected sampler returns i64::MIN or i64::MAX.
        let limit = i128::from(i64::MAX / 2);
        let noisy = components.map(|component| {
            (i128::from(component)
                + i128::from(noise_generator.sample_gaussian(noise_scale as i64)))
            .clamp(-limit, limit)
        });
        let total: i128 = noisy.iter().sum();
        let mean = total.div_euclid(4);
        let remainder = total.rem_euclid(4) as usize;
        let mut centered = noisy.map(|value| value - mean);
        for value in centered.iter_mut().take(remainder) {
            *value -= 1;
        }

        delta.delta_benign_millionths = centered[0] as i64;
        delta.delta_anomalous_millionths = centered[1] as i64;
        delta.delta_malicious_millionths = centered[2] as i64;
        delta.delta_unknown_millionths = centered[3] as i64;
        let mut release = Self {
            base_delta: delta,
            privacy_params,
            noise_scale_millionths: noise_scale,
            round_id,
        };
        // The old hash committed to raw local evidence. A dictionary attack
        // on that hash is not protected by adding noise to the coordinates.
        release.base_delta.evidence_hash = release.release_fingerprint();
        release
    }

    /// Canonical provenance of the public release, independent of the source
    /// evidence hash or any caller-supplied replacement for that hash.
    pub(crate) fn release_fingerprint(&self) -> crate::hash_tiers::ContentHash {
        released_delta_fingerprint(
            &self.base_delta,
            self.privacy_params,
            self.noise_scale_millionths,
            &self.round_id,
        )
    }

    /// Get the noisy posterior delta for aggregation.
    pub fn get_noisy_delta(&self) -> &PosteriorDelta {
        &self.base_delta
    }
}

/// Canonical release provenance: domain-separated, length-framed public
/// metadata and noisy coordinates. It never includes the raw evidence hash.
fn released_delta_fingerprint(
    delta: &PosteriorDelta,
    parameters: PrivacyParameters,
    noise_scale: u64,
    round_id: &str,
) -> crate::hash_tiers::ContentHash {
    let mut encoded = b"frankenengine.private-posterior-release.v1\0".to_vec();
    for text in [&delta.extension_id[..], round_id] {
        encoded.extend_from_slice(&(text.len() as u64).to_le_bytes());
        encoded.extend_from_slice(text.as_bytes());
    }
    for value in [
        delta.epoch.as_u64(),
        delta.confidence_weight_millionths,
        parameters.epsilon_millionths,
        parameters.delta_millionths,
        noise_scale,
    ] {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    for value in [
        delta.delta_benign_millionths,
        delta.delta_anomalous_millionths,
        delta.delta_malicious_millionths,
        delta.delta_unknown_millionths,
    ] {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    crate::hash_tiers::ContentHash::compute(&encoded)
}

// ---------------------------------------------------------------------------
// NoiseGenerator - Trait for sampling from distributions
// ---------------------------------------------------------------------------

/// Trait for generating cryptographically secure noise for differential privacy.
pub trait NoiseGenerator {
    /// Sample from Gaussian distribution N(0, σ²) with given scale.
    fn sample_gaussian(&mut self, scale_millionths: i64) -> i64;
}

/// Simple deterministic noise generator for testing.
/// DO NOT USE IN PRODUCTION - this is for deterministic testing only.
pub struct DeterministicTestNoiseGenerator {
    counter: u64,
}

impl DeterministicTestNoiseGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Default for DeterministicTestNoiseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseGenerator for DeterministicTestNoiseGenerator {
    fn sample_gaussian(&mut self, scale_millionths: i64) -> i64 {
        // Simple deterministic "noise" for testing - not secure!
        self.counter = self.counter.wrapping_add(1);
        let pseudo_random = self
            .counter
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223)
            % (1u64 << 31);
        clamp_i128_to_i64(
            (i128::from(pseudo_random) - (1i128 << 30)) * i128::from(scale_millionths)
                / (1i128 << 29),
        )
    }
}

// ---------------------------------------------------------------------------
// DP-SGD posterior updates
// ---------------------------------------------------------------------------

/// Configuration for one differentially-private SGD posterior update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpSgdConfig {
    /// L2 clipping norm for each node gradient, in fixed-point millionths.
    pub clipping_norm_millionths: u64,
    /// SGD learning rate, in fixed-point millionths.
    pub learning_rate_millionths: u64,
    /// Privacy parameters spent by the round.
    pub privacy_params: PrivacyParameters,
}

impl DpSgdConfig {
    /// Create a validated DP-SGD configuration.
    pub fn new(
        clipping_norm_millionths: u64,
        learning_rate_millionths: u64,
        privacy_params: PrivacyParameters,
    ) -> Result<Self, DifferentialPrivacyError> {
        let config = Self {
            clipping_norm_millionths,
            learning_rate_millionths,
            privacy_params,
        };
        config.validate()?;
        Ok(config)
    }

    /// Revalidate public fields before any budget charge or noise sampling.
    pub fn validate(&self) -> Result<(), DifferentialPrivacyError> {
        if self.clipping_norm_millionths == 0
            || self.clipping_norm_millionths > MAX_CLIPPING_NORM_MILLIONTHS
        {
            return Err(DifferentialPrivacyError::InvalidClippingNorm);
        }
        if self.learning_rate_millionths == 0 || self.learning_rate_millionths > MILLION as u64 {
            return Err(DifferentialPrivacyError::InvalidLearningRate);
        }
        self.privacy_params.validate()
    }
}

/// A per-node posterior gradient for DP-SGD fleet learning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpSgdGradient {
    /// Extension being updated.
    pub extension_id: String,
    /// Gradient component for P(Benign), in millionths.
    pub gradient_benign_millionths: i64,
    /// Gradient component for P(Anomalous), in millionths.
    pub gradient_anomalous_millionths: i64,
    /// Gradient component for P(Malicious), in millionths.
    pub gradient_malicious_millionths: i64,
    /// Gradient component for P(Unknown), in millionths.
    pub gradient_unknown_millionths: i64,
    /// Security epoch for the local posterior update.
    pub epoch: SecurityEpoch,
}

impl DpSgdGradient {
    /// Adapt an existing posterior delta into a DP-SGD gradient.
    pub fn from_posterior_delta(delta: &PosteriorDelta) -> Self {
        Self {
            extension_id: delta.extension_id.clone(),
            gradient_benign_millionths: delta.delta_benign_millionths,
            gradient_anomalous_millionths: delta.delta_anomalous_millionths,
            gradient_malicious_millionths: delta.delta_malicious_millionths,
            gradient_unknown_millionths: delta.delta_unknown_millionths,
            epoch: delta.epoch,
        }
    }

    /// Return this gradient clipped to the configured L2 norm.
    pub fn clipped_to(&self, clipping_norm_millionths: u64) -> Self {
        let norm = self.l2_norm_upper_millionths();
        if norm == 0 || norm <= u128::from(clipping_norm_millionths) {
            return self.clone();
        }

        // Divide each component only once. Rounding toward zero with an upper
        // bound on the denominator cannot leave the result outside the ball.
        let scale = |component: i64| {
            (i128::from(component) * i128::from(clipping_norm_millionths) / norm as i128) as i64
        };
        Self {
            extension_id: self.extension_id.clone(),
            gradient_benign_millionths: scale(self.gradient_benign_millionths),
            gradient_anomalous_millionths: scale(self.gradient_anomalous_millionths),
            gradient_malicious_millionths: scale(self.gradient_malicious_millionths),
            gradient_unknown_millionths: scale(self.gradient_unknown_millionths),
            epoch: self.epoch,
        }
    }

    /// Upward-rounded integer L2 norm, capped at u64::MAX for this reporting API.
    /// Clipping uses the uncapped u128 bound internally.
    pub fn l2_norm_millionths(&self) -> u64 {
        self.l2_norm_upper_millionths().min(u128::from(u64::MAX)) as u64
    }

    fn l2_norm_upper_millionths(&self) -> u128 {
        let components = [
            self.gradient_benign_millionths,
            self.gradient_anomalous_millionths,
            self.gradient_malicious_millionths,
            self.gradient_unknown_millionths,
        ];
        let mut sum_squares = 0u128;
        for component in components {
            let magnitude = i128::from(component).unsigned_abs();
            let Some(next) = sum_squares.checked_add(magnitude * magnitude) else {
                // Four i64 coordinates have squared norm at most 2^128,
                // whose exact square root is 2^64 (representable in u128).
                return 1u128 << 64;
            };
            sum_squares = next;
        }
        ceil_sqrt_u128(sum_squares)
    }
}

/// Released result of one DP-SGD posterior update round. Only noisy gradients
/// are exposed; the exact clipped sums are private intermediates. The prior,
/// fixed participant roster, epoch and configuration are public inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpSgdPosteriorUpdate {
    /// Round identifier whose privacy budget was spent.
    pub round_id: String,
    /// Extension being updated.
    pub extension_id: String,
    /// Security epoch shared by all gradients.
    pub epoch: SecurityEpoch,
    /// Number of fleet nodes included in the minibatch.
    pub participant_count: u32,
    /// Applied clipping norm.
    pub clipping_norm_millionths: u64,
    /// Applied learning rate.
    pub learning_rate_millionths: u64,
    /// Privacy parameters spent by the round.
    pub privacy_params: PrivacyParameters,
    /// Gaussian noise scale used for gradient perturbation.
    pub noise_scale_millionths: u64,
    /// Noisy averaged gradient for P(Benign).
    pub noisy_gradient_benign_millionths: i64,
    /// Noisy averaged gradient for P(Anomalous).
    pub noisy_gradient_anomalous_millionths: i64,
    /// Noisy averaged gradient for P(Malicious).
    pub noisy_gradient_malicious_millionths: i64,
    /// Noisy averaged gradient for P(Unknown).
    pub noisy_gradient_unknown_millionths: i64,
    /// Normalized posterior after applying the noisy SGD step.
    pub updated_posterior: Posterior,
}

impl DpSgdPosteriorUpdate {
    /// Run one DP-SGD posterior update over a public, fixed fleet minibatch.
    /// Replace-one adjacency uses sensitivity 2*C for the clipped SUM; noise
    /// is added to that sum before division by the public participant count.
    pub fn from_gradients(
        prior: &Posterior,
        gradients: &BTreeMap<NodeId, DpSgdGradient>,
        config: DpSgdConfig,
        round_id: impl Into<String>,
        budget: &mut PrivacyBudget,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Result<Self, DifferentialPrivacyError> {
        config.validate()?;
        if !prior.is_valid() {
            return Err(DifferentialPrivacyError::InvalidPosterior);
        }
        if gradients.is_empty() {
            return Err(DifferentialPrivacyError::EmptyAggregation);
        }

        let participant_count_u32 = u32::try_from(gradients.len())
            .map_err(|_| DifferentialPrivacyError::TooManyParticipants)?;
        let round_id = round_id.into();
        let first_gradient = gradients
            .values()
            .next()
            .ok_or(DifferentialPrivacyError::EmptyAggregation)?;

        for gradient in gradients.values() {
            if gradient.extension_id != first_gradient.extension_id
                || gradient.epoch != first_gradient.epoch
                || gradient.epoch != budget.epoch
            {
                return Err(DifferentialPrivacyError::InconsistentGradientMetadata);
            }
        }

        // Config bounds make the multiplication exact. Complete calibration
        // before charging: invalid input cannot spend budget or sample noise.
        let noise_scale = config
            .privacy_params
            .gaussian_noise_scale(2 * config.clipping_norm_millionths)?;
        budget.allocate_for_round(&round_id, config.privacy_params)?;

        let mut sum_benign: i128 = 0;
        let mut sum_anomalous: i128 = 0;
        let mut sum_malicious: i128 = 0;
        let mut sum_unknown: i128 = 0;

        for gradient in gradients.values() {
            let clipped = gradient.clipped_to(config.clipping_norm_millionths);
            sum_benign += i128::from(clipped.gradient_benign_millionths);
            sum_anomalous += i128::from(clipped.gradient_anomalous_millionths);
            sum_malicious += i128::from(clipped.gradient_malicious_millionths);
            sum_unknown += i128::from(clipped.gradient_unknown_millionths);
        }

        let participant_count = i128::from(participant_count_u32);
        let noisy_gradient_benign_millionths =
            noisy_average(sum_benign, participant_count, noise_scale, noise_generator);
        let noisy_gradient_anomalous_millionths = noisy_average(
            sum_anomalous,
            participant_count,
            noise_scale,
            noise_generator,
        );
        let noisy_gradient_malicious_millionths = noisy_average(
            sum_malicious,
            participant_count,
            noise_scale,
            noise_generator,
        );
        let noisy_gradient_unknown_millionths =
            noisy_average(sum_unknown, participant_count, noise_scale, noise_generator);

        let step_benign = sgd_step(
            noisy_gradient_benign_millionths,
            config.learning_rate_millionths,
        );
        let step_anomalous = sgd_step(
            noisy_gradient_anomalous_millionths,
            config.learning_rate_millionths,
        );
        let step_malicious = sgd_step(
            noisy_gradient_malicious_millionths,
            config.learning_rate_millionths,
        );
        let step_unknown = sgd_step(
            noisy_gradient_unknown_millionths,
            config.learning_rate_millionths,
        );

        let updated_posterior = Posterior::from_millionths(
            add_i64(prior.p_benign, step_benign),
            add_i64(prior.p_anomalous, step_anomalous),
            add_i64(prior.p_malicious, step_malicious),
            add_i64(prior.p_unknown, step_unknown),
        );

        Ok(Self {
            round_id,
            extension_id: first_gradient.extension_id.clone(),
            epoch: first_gradient.epoch,
            participant_count: participant_count_u32,
            clipping_norm_millionths: config.clipping_norm_millionths,
            learning_rate_millionths: config.learning_rate_millionths,
            privacy_params: config.privacy_params,
            noise_scale_millionths: noise_scale,
            noisy_gradient_benign_millionths,
            noisy_gradient_anomalous_millionths,
            noisy_gradient_malicious_millionths,
            noisy_gradient_unknown_millionths,
            updated_posterior,
        })
    }
}

fn noisy_average(
    sum: i128,
    participant_count: i128,
    noise_scale_millionths: u64,
    noise_generator: &mut dyn NoiseGenerator,
) -> i64 {
    let noise = i128::from(noise_generator.sample_gaussian(noise_scale_millionths as i64));
    clamp_i128_to_i64((sum + noise) / participant_count)
}

fn sgd_step(gradient_millionths: i64, learning_rate_millionths: u64) -> i64 {
    clamp_i128_to_i64(
        i128::from(gradient_millionths) * i128::from(learning_rate_millionths)
            / i128::from(MILLION),
    )
}

fn add_i64(left: i64, right: i64) -> i64 {
    clamp_i128_to_i64(i128::from(left) + i128::from(right))
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

// ---------------------------------------------------------------------------
// PrivacyPreservingAggregator - Main orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates differentially private federated aggregation.
pub struct PrivacyPreservingAggregator {
    /// Per-node privacy budgets.
    node_budgets: BTreeMap<NodeId, PrivacyBudget>,
    /// Default privacy parameters for new rounds.
    default_privacy_params: PrivacyParameters,
    /// Security epoch.
    current_epoch: SecurityEpoch,
}

impl PrivacyPreservingAggregator {
    /// Create a new privacy-preserving aggregator.
    pub fn new(default_privacy_params: PrivacyParameters, current_epoch: SecurityEpoch) -> Self {
        Self {
            node_budgets: BTreeMap::new(),
            default_privacy_params,
            current_epoch,
        }
    }

    /// Initialize privacy budget for a node.
    pub fn initialize_node_budget(
        &mut self,
        node_id: NodeId,
        total_epsilon_millionths: u64,
        total_delta_millionths: u64,
    ) -> Result<(), DifferentialPrivacyError> {
        match self.node_budgets.entry(node_id) {
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(DifferentialPrivacyError::NodeBudgetAlreadyInitialized)
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let budget = PrivacyBudget::new(
                    total_epsilon_millionths,
                    total_delta_millionths,
                    self.current_epoch,
                )?;
                entry.insert(budget);
                Ok(())
            }
        }
    }

    /// Apply differential privacy to a posterior delta.
    /// Reject invalid public identities before spending budget or sampling.
    pub fn make_delta_private(
        &mut self,
        node_id: &NodeId,
        delta: PosteriorDelta,
        round_id: String,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Result<PrivatePosteriorDelta, DifferentialPrivacyError> {
        if round_id.is_empty() || delta.extension_id.is_empty() {
            return Err(DifferentialPrivacyError::InconsistentAggregationMetadata);
        }
        let noise_scale = self
            .default_privacy_params
            .gaussian_noise_scale(GLOBAL_SENSITIVITY_MILLIONTHS)?;
        if !delta.is_valid() {
            return Err(DifferentialPrivacyError::InvalidPosteriorDelta);
        }
        if delta.epoch != self.current_epoch {
            return Err(DifferentialPrivacyError::InconsistentGradientMetadata);
        }
        let budget = self
            .node_budgets
            .get_mut(node_id)
            .ok_or(DifferentialPrivacyError::NodeBudgetNotFound)?;

        // Check if budget allows this allocation
        if !budget.can_allocate(&self.default_privacy_params) {
            return Err(DifferentialPrivacyError::InsufficientBudget);
        }

        // Allocate budget for this round
        budget.allocate_for_round(&round_id, self.default_privacy_params)?;

        // Sampling begins only after the entire input and scale were validated
        // and the round was charged. No sampled release can refund its spend.
        Ok(PrivatePosteriorDelta::from_validated_delta(
            delta,
            self.default_privacy_params,
            round_id,
            noise_scale,
            noise_generator,
        ))
    }

    /// Aggregate releases from one extension, security epoch and public round.
    ///
    /// Confidence weights and participant/round metadata must be fixed public
    /// inputs to the release mechanism. This boundary checks their consistency;
    /// it does not authenticate participants or prove that a producer sampled
    /// noise. The caller supplies the timestamp so replay never reads a clock.
    ///
    /// The returned components retain confidence-weighted numerators, matching
    /// `AggregatedPosteriorUpdate` and the secure-aggregation transport. They
    /// are divided by the total confidence weight when applied to a posterior.
    pub fn aggregate_private_deltas(
        &self,
        private_deltas: Vec<PrivatePosteriorDelta>,
        round_id: String,
        now_ns: u64,
    ) -> Result<AggregatedPosteriorUpdate, DifferentialPrivacyError> {
        let first = private_deltas
            .first()
            .ok_or(DifferentialPrivacyError::EmptyAggregation)?;
        let participant_count = u32::try_from(private_deltas.len())
            .map_err(|_| DifferentialPrivacyError::TooManyParticipants)?;
        let first_params = first.privacy_params;
        first_params.validate()?;
        let expected_noise_scale =
            first_params.gaussian_noise_scale(GLOBAL_SENSITIVITY_MILLIONTHS)?;
        let extension_id = first.base_delta.extension_id.clone();
        if round_id.is_empty() || extension_id.is_empty() {
            return Err(DifferentialPrivacyError::InconsistentAggregationMetadata);
        }

        let mut weighted_sums = [0_i128; 4];
        let mut total_weight = 0_u64;
        let mut release_fingerprints = Vec::with_capacity(private_deltas.len());
        for release in &private_deltas {
            if release.privacy_params != first_params {
                return Err(DifferentialPrivacyError::InconsistentPrivacyParams);
            }
            let delta = &release.base_delta;
            if release.round_id != round_id
                || delta.extension_id != extension_id
                || delta.epoch != self.current_epoch
            {
                return Err(DifferentialPrivacyError::InconsistentAggregationMetadata);
            }
            if release.noise_scale_millionths != expected_noise_scale {
                return Err(DifferentialPrivacyError::NoiseScaleMismatch);
            }
            let weight = delta.confidence_weight_millionths;
            if weight == 0 || weight > MILLION as u64 {
                return Err(DifferentialPrivacyError::InvalidConfidenceWeight);
            }
            let components = [
                delta.delta_benign_millionths,
                delta.delta_anomalous_millionths,
                delta.delta_malicious_millionths,
                delta.delta_unknown_millionths,
            ];
            // Noisy releases need not fit the raw +/-1 probability range.
            // Their four-dimensional zero-sum invariant still applies.
            if components
                .iter()
                .map(|value| i128::from(*value))
                .sum::<i128>()
                != 0
            {
                return Err(DifferentialPrivacyError::InvalidPosteriorDelta);
            }
            for (sum, component) in weighted_sums.iter_mut().zip(components) {
                let weighted = i128::from(component) * i128::from(weight);
                *sum = sum
                    .checked_add(weighted)
                    .ok_or(DifferentialPrivacyError::AggregationOverflow)?;
            }
            total_weight = total_weight
                .checked_add(weight)
                .ok_or(DifferentialPrivacyError::AggregationOverflow)?;
            // Recompute from released fields, never from a caller-supplied
            // hash of raw evidence or a claimed provenance digest.
            release_fingerprints.push(release.release_fingerprint());
        }

        // Bind a canonical multiset: input order is irrelevant, but repeated
        // contributions remain represented. Participant authentication and
        // duplicate-node rejection belong to the admission protocol.
        release_fingerprints.sort_unstable();
        let mut fingerprint_input = b"frankenengine.private-posterior-aggregation.v1\0".to_vec();
        fingerprint_input.extend_from_slice(&(round_id.len() as u64).to_be_bytes());
        fingerprint_input.extend_from_slice(round_id.as_bytes());
        fingerprint_input.extend_from_slice(&(extension_id.len() as u64).to_be_bytes());
        fingerprint_input.extend_from_slice(extension_id.as_bytes());
        fingerprint_input.extend_from_slice(&self.current_epoch.as_u64().to_be_bytes());
        fingerprint_input.extend_from_slice(&now_ns.to_be_bytes());
        fingerprint_input.extend_from_slice(&participant_count.to_be_bytes());
        for fingerprint in release_fingerprints {
            fingerprint_input.extend_from_slice(fingerprint.as_bytes());
        }
        let evidence_fingerprint = crate::hash_tiers::ContentHash::compute(&fingerprint_input);
        let narrow =
            |value| i64::try_from(value).map_err(|_| DifferentialPrivacyError::AggregationOverflow);

        Ok(AggregatedPosteriorUpdate {
            extension_id,
            aggregate_delta_benign_millionths: narrow(weighted_sums[0])?,
            aggregate_delta_anomalous_millionths: narrow(weighted_sums[1])?,
            aggregate_delta_malicious_millionths: narrow(weighted_sums[2])?,
            aggregate_delta_unknown_millionths: narrow(weighted_sums[3])?,
            total_confidence_weight_millionths: total_weight,
            participant_count,
            evidence_fingerprint,
            epoch: self.current_epoch,
            aggregation_timestamp_ns: now_ns,
        })
    }

    /// Get remaining budget for a node.
    pub fn get_node_budget(&self, node_id: &NodeId) -> Option<&PrivacyBudget> {
        self.node_budgets.get(node_id)
    }

    /// Check if any nodes have nearly exhausted budgets.
    pub fn get_low_budget_nodes(&self) -> Vec<&NodeId> {
        self.node_budgets
            .iter()
            .filter(|(_, budget)| budget.is_nearly_exhausted())
            .map(|(node_id, _)| node_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

/// Errors that can occur in differential privacy operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DifferentialPrivacyError {
    /// Invalid epsilon parameter.
    InvalidEpsilon,
    /// Invalid delta parameter.
    InvalidDelta,
    /// Required Gaussian scale does not fit the signed sampler interface.
    NoiseScaleOutOfRange,
    /// Source delta is not a bounded, zero-sum probability change.
    InvalidPosteriorDelta,
    /// The public prior is not a normalized non-negative posterior.
    InvalidPosterior,
    /// A public participant count cannot be represented in the release.
    TooManyParticipants,
    /// Invalid DP-SGD clipping norm.
    InvalidClippingNorm,
    /// Invalid DP-SGD learning rate.
    InvalidLearningRate,
    /// Insufficient privacy budget remaining.
    InsufficientBudget,
    /// Node budget not initialized.
    NodeBudgetNotFound,
    /// An existing node's finite budget must not be reset by initialization.
    NodeBudgetAlreadyInitialized,
    /// Duplicate round allocation attempted.
    DuplicateRoundAllocation,
    /// Empty aggregation (no deltas provided).
    EmptyAggregation,
    /// Inconsistent privacy parameters across deltas.
    InconsistentPrivacyParams,
    /// Inconsistent DP-SGD gradient metadata across nodes.
    InconsistentGradientMetadata,
    /// A release has empty identities or belongs to another round, extension or epoch.
    InconsistentAggregationMetadata,
    /// Confidence weights must be positive public millionths ratios.
    InvalidConfidenceWeight,
    /// Declared noise scale does not match the release calibration.
    NoiseScaleMismatch,
    /// Weighted output cannot be represented without losing information.
    AggregationOverflow,
}

impl std::fmt::Display for DifferentialPrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEpsilon => write!(f, "Invalid epsilon parameter"),
            Self::InvalidDelta => write!(f, "Invalid delta parameter"),
            Self::NoiseScaleOutOfRange => write!(f, "Gaussian noise scale is out of range"),
            Self::InvalidPosteriorDelta => write!(f, "Invalid source posterior delta"),
            Self::InvalidPosterior => write!(f, "Invalid prior posterior"),
            Self::TooManyParticipants => write!(f, "Too many aggregation participants"),
            Self::InvalidClippingNorm => write!(f, "Invalid clipping norm"),
            Self::InvalidLearningRate => write!(f, "Invalid learning rate"),
            Self::InsufficientBudget => write!(f, "Insufficient privacy budget"),
            Self::NodeBudgetNotFound => write!(f, "Node budget not initialized"),
            Self::NodeBudgetAlreadyInitialized => write!(f, "Node budget already initialized"),
            Self::DuplicateRoundAllocation => write!(f, "Duplicate round allocation"),
            Self::EmptyAggregation => write!(f, "Empty aggregation"),
            Self::InconsistentPrivacyParams => write!(f, "Inconsistent privacy parameters"),
            Self::InconsistentGradientMetadata => write!(f, "Inconsistent gradient metadata"),
            Self::InconsistentAggregationMetadata => write!(f, "Inconsistent aggregation metadata"),
            Self::InvalidConfidenceWeight => write!(f, "Invalid confidence weight"),
            Self::NoiseScaleMismatch => write!(f, "Noise scale does not match calibration"),
            Self::AggregationOverflow => {
                write!(f, "Weighted aggregation exceeds its representation")
            }
        }
    }
}

impl std::error::Error for DifferentialPrivacyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bayesian_posterior::Evidence;

    #[test]
    fn privacy_parameters_validation() {
        // Valid parameters
        assert!(PrivacyParameters::new(100_000, 10).is_ok());

        // Invalid epsilon (too large)
        assert_eq!(
            PrivacyParameters::new(2_000_000, 10),
            Err(DifferentialPrivacyError::InvalidEpsilon)
        );

        // A finite Gaussian mechanism has no delta=0 configuration.
        for delta in [0, MAX_DELTA_MILLIONTHS + 1, u64::MAX] {
            assert_eq!(
                PrivacyParameters::new(100_000, delta),
                Err(DifferentialPrivacyError::InvalidDelta)
            );
        }
        assert_eq!(
            PrivacyParameters::new(0, 10),
            Err(DifferentialPrivacyError::InvalidEpsilon)
        );
    }

    #[test]
    fn privacy_budget_management() {
        let mut budget = PrivacyBudget::new(1_000_000, 1000, SecurityEpoch::from_raw(1)).unwrap();

        let params = PrivacyParameters::new(100_000, 10).unwrap();

        // Can allocate within budget
        assert!(budget.can_allocate(&params));

        // Successful allocation
        assert!(budget.allocate_for_round("round_1", params).is_ok());

        // Budget consumed
        assert_eq!(budget.consumed_epsilon_millionths, 100_000);
        assert_eq!(budget.consumed_delta_millionths, 10);

        // Can't double-allocate same round
        assert_eq!(
            budget.allocate_for_round("round_1", params),
            Err(DifferentialPrivacyError::DuplicateRoundAllocation)
        );
    }

    #[test]
    fn privacy_budget_composition_overflow_preserves_spent_state() {
        let mut budget = PrivacyBudget::new(1_000_000, 100, SecurityEpoch::from_raw(1)).unwrap();
        budget
            .allocate_for_round("spent", PrivacyParameters::new(100_000, 10).unwrap())
            .unwrap();
        let spent = budget.clone();
        // Public fields/serde input can carry values outside constructor bounds.
        // Each addition must reject independently, without debug panic or wrap.
        for (params, error) in [
            (
                PrivacyParameters {
                    epsilon_millionths: u64::MAX,
                    delta_millionths: 1,
                },
                DifferentialPrivacyError::InvalidEpsilon,
            ),
            (
                PrivacyParameters {
                    epsilon_millionths: 1,
                    delta_millionths: u64::MAX,
                },
                DifferentialPrivacyError::InvalidDelta,
            ),
        ] {
            assert!(!budget.can_allocate(&params));
            assert_eq!(budget.allocate_for_round("overflow", params), Err(error));
            assert_eq!(budget, spent);
        }
        budget
            .allocate_for_round("next-valid", PrivacyParameters::new(100_000, 10).unwrap())
            .unwrap();
        assert_eq!(budget.consumed_epsilon_millionths, 200_000);
        assert_eq!(budget.consumed_delta_millionths, 20);
        assert_eq!(budget.round_consumptions.len(), 2);
    }

    #[test]
    fn privacy_budget_reinitialization_cannot_erase_spending() {
        let epoch = SecurityEpoch::from_raw(1);
        let parameters = PrivacyParameters::new(100_000, 10).unwrap();
        let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
        let node = NodeId::new("node");
        aggregator
            .initialize_node_budget(node.clone(), 200_000, 20)
            .unwrap();
        let initial = aggregator.get_node_budget(&node).unwrap().clone();
        assert_eq!(
            aggregator.initialize_node_budget(node.clone(), 1_000_000, 100),
            Err(DifferentialPrivacyError::NodeBudgetAlreadyInitialized)
        );
        assert_eq!(aggregator.get_node_budget(&node), Some(&initial));
        aggregator
            .node_budgets
            .get_mut(&node)
            .unwrap()
            .allocate_for_round("spent", parameters)
            .unwrap();
        let spent = aggregator.get_node_budget(&node).unwrap().clone();
        assert_eq!(
            aggregator.initialize_node_budget(node.clone(), 1_000_000, 100),
            Err(DifferentialPrivacyError::NodeBudgetAlreadyInitialized)
        );
        assert_eq!(aggregator.get_node_budget(&node), Some(&spent));
        let other = NodeId::new("other-node");
        aggregator
            .initialize_node_budget(other.clone(), 100_000, 10)
            .unwrap();
        assert_eq!(
            aggregator
                .get_node_budget(&other)
                .unwrap()
                .remaining_epsilon(),
            100_000
        );
        assert_eq!(aggregator.get_node_budget(&node), Some(&spent));
    }

    #[test]
    fn gaussian_noise_scale_calculation() {
        // Independently evaluated ceil(2 / 0.1 * sqrt(2*ln(1.25/delta))*M).
        // The ceiling square root may add at most sensitivity/epsilon + 1.
        for (delta, reference) in [
            (1, 105_976_051),
            (5, 99_716_463),
            (10, 96_896_106),
            (20, 93_991_157),
            (100, 86_872_247),
        ] {
            let parameters = PrivacyParameters::new(100_000, delta).unwrap();
            let actual = parameters.gaussian_noise_scale(2_000_000).unwrap();
            assert!((reference..=reference + 21).contains(&actual));
        }
    }

    #[test]
    fn private_delta_maintains_properties() {
        let evidence = Evidence {
            extension_id: "test_ext".to_string(),
            hostcall_rate_millionths: 1_000_000,
            distinct_capabilities: 5,
            resource_score_millionths: 500_000,
            timing_anomaly_millionths: 200_000,
            denial_rate_millionths: 10_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        let base_delta = PosteriorDelta::from_evidence_update(
            "test_ext",
            &crate::bayesian_posterior::Posterior::default_prior(),
            &crate::bayesian_posterior::Posterior::uniform(),
            &evidence,
            800_000,
        );

        let params = PrivacyParameters::default();
        let mut noise_gen = DeterministicTestNoiseGenerator::new();

        let private_delta = PrivatePosteriorDelta::from_delta(
            base_delta,
            params,
            "test_round".to_string(),
            &mut noise_gen,
        )
        .unwrap();

        // Verify the private delta maintains the round ID and privacy params
        assert_eq!(private_delta.round_id, "test_round");
        assert_eq!(private_delta.privacy_params, params);
        assert!(private_delta.noise_scale_millionths > 0);
    }

    fn test_gradient(
        extension_id: &str,
        epoch: SecurityEpoch,
        benign: i64,
        anomalous: i64,
        malicious: i64,
        unknown: i64,
    ) -> DpSgdGradient {
        DpSgdGradient {
            extension_id: extension_id.to_string(),
            gradient_benign_millionths: benign,
            gradient_anomalous_millionths: anomalous,
            gradient_malicious_millionths: malicious,
            gradient_unknown_millionths: unknown,
            epoch,
        }
    }

    fn test_dp_sgd_config() -> DpSgdConfig {
        DpSgdConfig::new(
            1_000_000,
            500_000,
            PrivacyParameters::new(100_000, 10).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn dp_sgd_config_validation_rejects_unbounded_updates() {
        let params = PrivacyParameters::default();

        assert_eq!(
            DpSgdConfig::new(0, 500_000, params),
            Err(DifferentialPrivacyError::InvalidClippingNorm)
        );
        assert_eq!(
            DpSgdConfig::new(MAX_CLIPPING_NORM_MILLIONTHS + 1, 500_000, params),
            Err(DifferentialPrivacyError::InvalidClippingNorm)
        );
        assert_eq!(
            DpSgdConfig::new(1_000_000, 0, params),
            Err(DifferentialPrivacyError::InvalidLearningRate)
        );
        assert_eq!(
            DpSgdConfig::new(1_000_000, 1_000_001, params),
            Err(DifferentialPrivacyError::InvalidLearningRate)
        );
    }

    #[test]
    fn dp_sgd_gradient_clipping_caps_l2_norm() {
        let gradient = test_gradient(
            "test_ext",
            SecurityEpoch::from_raw(7),
            2_000_000,
            0,
            -2_000_000,
            0,
        );

        let clipped = gradient.clipped_to(1_000_000);

        assert!(clipped.l2_norm_millionths() <= 1_000_000);
        assert!(clipped.gradient_benign_millionths > 0);
        assert!(clipped.gradient_malicious_millionths < 0);
    }

    #[test]
    fn dp_sgd_round_is_deterministic_for_btree_ordering() {
        let epoch = SecurityEpoch::from_raw(9);
        let config = test_dp_sgd_config();
        let prior = crate::bayesian_posterior::Posterior::uniform();

        let gradient_a = test_gradient("test_ext", epoch, 200_000, -100_000, -50_000, -50_000);
        let gradient_b = test_gradient("test_ext", epoch, -100_000, 50_000, 100_000, -50_000);

        let mut first_order = BTreeMap::new();
        first_order.insert(NodeId::new("node_b"), gradient_b.clone());
        first_order.insert(NodeId::new("node_a"), gradient_a.clone());

        let mut second_order = BTreeMap::new();
        second_order.insert(NodeId::new("node_a"), gradient_a);
        second_order.insert(NodeId::new("node_b"), gradient_b);

        let mut first_budget = PrivacyBudget::new(500_000, 100, epoch).unwrap();
        let mut second_budget = PrivacyBudget::new(500_000, 100, epoch).unwrap();
        let mut first_noise = DeterministicTestNoiseGenerator::new();
        let mut second_noise = DeterministicTestNoiseGenerator::new();

        let first_update = DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &first_order,
            config,
            "round_qq_1",
            &mut first_budget,
            &mut first_noise,
        )
        .unwrap();
        let second_update = DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &second_order,
            config,
            "round_qq_1",
            &mut second_budget,
            &mut second_noise,
        )
        .unwrap();

        assert_eq!(first_update, second_update);
        assert!(first_update.updated_posterior.is_valid());
        assert_eq!(first_budget.consumed_epsilon_millionths, 100_000);
    }

    #[test]
    fn dp_sgd_round_refuses_duplicate_budget_spend() {
        let epoch = SecurityEpoch::from_raw(10);
        let config = test_dp_sgd_config();
        let prior = crate::bayesian_posterior::Posterior::uniform();
        let mut gradients = BTreeMap::new();
        gradients.insert(
            NodeId::new("node_a"),
            test_gradient("test_ext", epoch, 100_000, 0, -100_000, 0),
        );

        let mut budget = PrivacyBudget::new(500_000, 100, epoch).unwrap();
        let mut first_noise = DeterministicTestNoiseGenerator::new();
        let mut second_noise = DeterministicTestNoiseGenerator::new();

        DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &gradients,
            config,
            "round_qq_1",
            &mut budget,
            &mut first_noise,
        )
        .unwrap();

        let err = DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &gradients,
            config,
            "round_qq_1",
            &mut budget,
            &mut second_noise,
        )
        .unwrap_err();

        assert_eq!(err, DifferentialPrivacyError::DuplicateRoundAllocation);
    }

    #[test]
    fn dp_sgd_round_rejects_inconsistent_gradient_metadata() {
        let epoch = SecurityEpoch::from_raw(11);
        let config = test_dp_sgd_config();
        let prior = crate::bayesian_posterior::Posterior::uniform();
        let mut gradients = BTreeMap::new();
        gradients.insert(
            NodeId::new("node_a"),
            test_gradient("test_ext", epoch, 100_000, 0, -100_000, 0),
        );
        gradients.insert(
            NodeId::new("node_b"),
            test_gradient("other_ext", epoch, 100_000, 0, -100_000, 0),
        );

        let mut budget = PrivacyBudget::new(500_000, 100, epoch).unwrap();
        let mut noise = DeterministicTestNoiseGenerator::new();

        let err = DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &gradients,
            config,
            "round_qq_1",
            &mut budget,
            &mut noise,
        )
        .unwrap_err();

        assert_eq!(err, DifferentialPrivacyError::InconsistentGradientMetadata);
        assert_eq!(budget.consumed_epsilon_millionths, 0);
    }

    #[test]
    fn dp_sgd_update_serializes_as_persisted_evidence() {
        let epoch = SecurityEpoch::from_raw(12);
        let config = test_dp_sgd_config();
        let prior = crate::bayesian_posterior::Posterior::uniform();
        let mut gradients = BTreeMap::new();
        gradients.insert(
            NodeId::new("node_a"),
            test_gradient("test_ext", epoch, 100_000, 0, -100_000, 0),
        );

        let mut budget = PrivacyBudget::new(500_000, 100, epoch).unwrap();
        let mut noise = DeterministicTestNoiseGenerator::new();
        let update = DpSgdPosteriorUpdate::from_gradients(
            &prior,
            &gradients,
            config,
            "round_qq_serde",
            &mut budget,
            &mut noise,
        )
        .unwrap();

        let json = serde_json::to_string(&update).unwrap();
        let decoded: DpSgdPosteriorUpdate = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, update);
        assert_eq!(decoded.round_id, "round_qq_serde");
    }

    struct RecordingNoise {
        samples: [i64; 4],
        scales: Vec<i64>,
    }

    impl RecordingNoise {
        fn new(samples: [i64; 4]) -> Self {
            Self {
                samples,
                scales: Vec::new(),
            }
        }
    }

    impl NoiseGenerator for RecordingNoise {
        fn sample_gaussian(&mut self, scale_millionths: i64) -> i64 {
            let value = self.samples[self.scales.len() % self.samples.len()];
            self.scales.push(scale_millionths);
            value
        }
    }

    fn bounded_delta(epoch: SecurityEpoch) -> PosteriorDelta {
        PosteriorDelta {
            extension_id: "calibration-test".to_string(),
            delta_benign_millionths: 100_000,
            delta_anomalous_millionths: -50_000,
            delta_malicious_millionths: -30_000,
            delta_unknown_millionths: -20_000,
            confidence_weight_millionths: 800_000,
            evidence_hash: crate::hash_tiers::ContentHash::compute(b"private-local-evidence"),
            epoch,
        }
    }

    fn delta_sum(delta: &PosteriorDelta) -> i128 {
        i128::from(delta.delta_benign_millionths)
            + i128::from(delta.delta_anomalous_millionths)
            + i128::from(delta.delta_malicious_millionths)
            + i128::from(delta.delta_unknown_millionths)
    }

    #[test]
    fn gaussian_calibration_is_conservative_across_supported_delta_domain() {
        // Floating point is only an independent test oracle. Production
        // calibration and replay use integer arithmetic exclusively.
        for delta in 1..=MAX_DELTA_MILLIONTHS {
            for epsilon in [1, 37, 1_000, 50_000, 100_000, 1_000_000] {
                let parameters = PrivacyParameters::new(epsilon, delta).unwrap();
                for sensitivity in [1, 1_000_000, 4_000_000, 8_000_000] {
                    let actual = parameters.gaussian_noise_scale(sensitivity).unwrap();
                    let reference = sensitivity as f64 * MILLION as f64 / epsilon as f64
                        * (2.0 * (1_250_000.0 / delta as f64).ln()).sqrt();
                    assert!(
                        actual as f64 >= reference,
                        "under-calibrated epsilon={epsilon} delta={delta} sensitivity={sensitivity}"
                    );
                    assert!(
                        actual as f64 <= reference + sensitivity.div_ceil(epsilon) as f64 + 2.0
                    );
                }
            }
        }
    }

    #[test]
    fn gaussian_calibration_rejects_raw_invalid_parameters_and_unrepresentable_scales() {
        for parameters in [
            PrivacyParameters {
                epsilon_millionths: 0,
                delta_millionths: 10,
            },
            PrivacyParameters {
                epsilon_millionths: 100_000,
                delta_millionths: 0,
            },
            PrivacyParameters {
                epsilon_millionths: u64::MAX,
                delta_millionths: u64::MAX,
            },
        ] {
            assert!(parameters.gaussian_noise_scale(0).is_err());
            assert!(parameters.gaussian_noise_scale(u64::MAX).is_err());
        }
        let parameters = PrivacyParameters::new(1, 1).unwrap();
        assert_eq!(parameters.gaussian_noise_scale(0), Ok(0));
        assert_eq!(
            parameters.gaussian_noise_scale(u64::MAX),
            Err(DifferentialPrivacyError::NoiseScaleOutOfRange)
        );
        assert_eq!(ceil_sqrt_u128(u128::MAX), 1u128 << 64);
        assert_eq!(ceil_sqrt_u128(0), 0);
        assert_eq!(ceil_sqrt_u128(1), 1);
        assert_eq!(ceil_sqrt_u128(2), 2);
    }

    #[test]
    fn private_delta_projection_is_exact_for_extreme_noise_and_hides_raw_evidence_hash() {
        let epoch = SecurityEpoch::from_raw(25);
        let source = bounded_delta(epoch);
        for samples in [
            [1, 0, 0, 0],
            [-1, 0, 0, 0],
            [i64::MAX, i64::MIN, i64::MAX, i64::MIN],
            [i64::MAX, i64::MIN, i64::MIN, i64::MIN],
        ] {
            let mut noise = RecordingNoise::new(samples);
            let release = PrivatePosteriorDelta::from_delta(
                source.clone(),
                PrivacyParameters::default(),
                "release".to_string(),
                &mut noise,
            )
            .unwrap();
            assert_eq!(delta_sum(&release.base_delta), 0);
            assert_eq!(noise.scales.len(), 4);
            assert!(noise.scales.iter().all(|scale| *scale >= 193_792_211));
            assert_ne!(release.base_delta.evidence_hash, source.evidence_hash);
            assert_eq!(
                release.base_delta.evidence_hash,
                release.release_fingerprint()
            );

            let mut other_source = source.clone();
            other_source.evidence_hash =
                crate::hash_tiers::ContentHash::compute(b"other-private-evidence");
            let repeated = PrivatePosteriorDelta::from_delta(
                other_source,
                PrivacyParameters::default(),
                "release".to_string(),
                &mut RecordingNoise::new(samples),
            )
            .unwrap();
            assert_eq!(
                release, repeated,
                "source evidence hash must not be a release"
            );
        }
    }

    #[test]
    fn invalid_posterior_release_does_not_sample_or_spend_budget() {
        let epoch = SecurityEpoch::from_raw(26);
        let node = NodeId::new("node");
        let mut aggregator = PrivacyPreservingAggregator::new(PrivacyParameters::default(), epoch);
        aggregator
            .initialize_node_budget(node.clone(), 1_000_000, 100)
            .unwrap();
        let before = aggregator.get_node_budget(&node).unwrap().clone();
        let mut noise = RecordingNoise::new([0; 4]);
        let mut invalid = bounded_delta(epoch);
        invalid.delta_benign_millionths = i64::MIN;
        assert_eq!(
            aggregator.make_delta_private(&node, invalid, "bad".into(), &mut noise),
            Err(DifferentialPrivacyError::InvalidPosteriorDelta)
        );
        assert_eq!(aggregator.get_node_budget(&node), Some(&before));
        assert!(noise.scales.is_empty());

        let good = aggregator
            .make_delta_private(&node, bounded_delta(epoch), "good".into(), &mut noise)
            .unwrap();
        assert_eq!(delta_sum(&good.base_delta), 0);
        assert_eq!(noise.scales.len(), 4);
        assert_eq!(
            aggregator
                .get_node_budget(&node)
                .unwrap()
                .consumed_epsilon_millionths,
            100_000
        );
    }

    #[test]
    fn empty_release_identities_do_not_sample_or_spend_budget() {
        let epoch = SecurityEpoch::from_raw(26);
        let node = NodeId::new("identity-node");
        let parameters = PrivacyParameters::default();
        let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
        aggregator
            .initialize_node_budget(node.clone(), 1_000_000, 100)
            .unwrap();
        let before = aggregator.get_node_budget(&node).unwrap().clone();
        for (extension, round) in [("", "round"), ("extension", ""), ("", "")] {
            let mut source = bounded_delta(epoch);
            source.extension_id = extension.into();
            let mut noise = RecordingNoise::new([0; 4]);
            assert_eq!(
                PrivatePosteriorDelta::from_delta(
                    source.clone(),
                    parameters,
                    round.into(),
                    &mut noise,
                ),
                Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
            );
            assert!(noise.scales.is_empty());
            assert_eq!(
                aggregator.make_delta_private(&node, source, round.into(), &mut noise),
                Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
            );
            assert!(noise.scales.is_empty());
            assert_eq!(aggregator.get_node_budget(&node), Some(&before));
        }

        // Refused identities do not consume a round or prevent a valid release.
        let valid = aggregator
            .make_delta_private(
                &node,
                bounded_delta(epoch),
                "round".into(),
                &mut RecordingNoise::new([0; 4]),
            )
            .unwrap();
        assert_eq!(delta_sum(&valid.base_delta), 0);
        let after = aggregator.get_node_budget(&node).unwrap();
        assert_eq!(
            after.consumed_epsilon_millionths,
            parameters.epsilon_millionths
        );
        assert_eq!(after.consumed_delta_millionths, parameters.delta_millionths);
        assert_eq!(after.round_consumptions.len(), 1);
    }

    #[test]
    fn clipping_covers_nonsquare_boundary_and_full_width_gradient() {
        let epoch = SecurityEpoch::from_raw(27);
        let boundary = test_gradient("clip", epoch, 1_000_000, 1, 0, 0);
        assert_eq!(boundary.l2_norm_millionths(), 1_000_001);
        let clipped = boundary.clipped_to(1_000_000);
        assert!(clipped.gradient_benign_millionths < 1_000_000);

        for gradient in [
            boundary,
            test_gradient("clip", epoch, i64::MIN, i64::MIN, i64::MIN, i64::MIN),
            test_gradient("clip", epoch, i64::MAX, i64::MIN, 0, 1),
        ] {
            let clipped = gradient.clipped_to(1_000_000);
            let components = [
                clipped.gradient_benign_millionths,
                clipped.gradient_anomalous_millionths,
                clipped.gradient_malicious_millionths,
                clipped.gradient_unknown_millionths,
            ];
            let squared: u128 = components
                .into_iter()
                .map(|value| {
                    let magnitude = i128::from(value).unsigned_abs();
                    magnitude * magnitude
                })
                .sum();
            assert!(squared <= 1_000_000u128 * 1_000_000);
        }
    }

    #[test]
    fn dp_sgd_revalidates_public_config_before_sampling_or_budget_charge() {
        let epoch = SecurityEpoch::from_raw(28);
        let gradients = BTreeMap::from([(
            NodeId::new("node"),
            test_gradient("dp-sgd", epoch, 100_000, 0, -100_000, 0),
        )]);
        let valid = test_dp_sgd_config();
        for config in [
            DpSgdConfig {
                clipping_norm_millionths: u64::MAX,
                ..valid
            },
            DpSgdConfig {
                learning_rate_millionths: 0,
                ..valid
            },
            DpSgdConfig {
                privacy_params: PrivacyParameters {
                    epsilon_millionths: 0,
                    delta_millionths: 10,
                },
                ..valid
            },
            DpSgdConfig {
                privacy_params: PrivacyParameters {
                    epsilon_millionths: 100_000,
                    delta_millionths: 0,
                },
                ..valid
            },
        ] {
            let mut budget = PrivacyBudget::new(1_000_000, 100, epoch).unwrap();
            let before = budget.clone();
            let mut noise = RecordingNoise::new([0; 4]);
            assert!(
                DpSgdPosteriorUpdate::from_gradients(
                    &Posterior::uniform(),
                    &gradients,
                    config,
                    "invalid",
                    &mut budget,
                    &mut noise,
                )
                .is_err()
            );
            assert_eq!(budget, before);
            assert!(noise.scales.is_empty());
        }
    }

    #[test]
    fn dp_sgd_rejects_invalid_prior_and_wrong_budget_epoch_without_spending() {
        let epoch = SecurityEpoch::from_raw(29);
        let gradients = BTreeMap::from([(
            NodeId::new("node"),
            test_gradient("dp-sgd", epoch, 100_000, 0, -100_000, 0),
        )]);
        let mut prior = Posterior::uniform();
        prior.p_benign = i64::MAX;
        let mut budget = PrivacyBudget::new(1_000_000, 100, epoch).unwrap();
        let before = budget.clone();
        let mut noise = RecordingNoise::new([0; 4]);
        assert_eq!(
            DpSgdPosteriorUpdate::from_gradients(
                &prior,
                &gradients,
                test_dp_sgd_config(),
                "bad-prior",
                &mut budget,
                &mut noise,
            ),
            Err(DifferentialPrivacyError::InvalidPosterior)
        );
        assert_eq!(budget, before);
        budget.epoch = SecurityEpoch::from_raw(30);
        let before = budget.clone();
        assert_eq!(
            DpSgdPosteriorUpdate::from_gradients(
                &Posterior::uniform(),
                &gradients,
                test_dp_sgd_config(),
                "wrong-epoch",
                &mut budget,
                &mut noise,
            ),
            Err(DifferentialPrivacyError::InconsistentGradientMetadata)
        );
        assert_eq!(budget, before);
        assert!(noise.scales.is_empty());
    }

    #[test]
    fn dp_sgd_release_has_only_noisy_gradients_and_replace_one_calibration() {
        let epoch = SecurityEpoch::from_raw(31);
        let gradients = BTreeMap::from([
            (
                NodeId::new("node-a"),
                test_gradient("dp-sgd", epoch, 2_000_000, 0, -2_000_000, 0),
            ),
            (
                NodeId::new("node-b"),
                test_gradient("dp-sgd", epoch, i64::MIN, i64::MAX, 1, 0),
            ),
        ]);
        let mut budget = PrivacyBudget::new(1_000_000, 100, epoch).unwrap();
        let mut noise = RecordingNoise::new([i64::MAX, i64::MIN, 1, -1]);
        let update = DpSgdPosteriorUpdate::from_gradients(
            &Posterior::uniform(),
            &gradients,
            test_dp_sgd_config(),
            "release",
            &mut budget,
            &mut noise,
        )
        .unwrap();
        assert_eq!(update.participant_count, 2);
        assert_eq!(noise.scales.len(), 4);
        assert!(noise.scales.iter().all(|scale| *scale >= 96_896_106));
        assert!(update.updated_posterior.is_valid());
        assert_eq!(budget.consumed_epsilon_millionths, 100_000);
        let encoded = serde_json::to_value(&update).unwrap();
        let fields = encoded.as_object().unwrap();
        assert!(fields.contains_key("noisy_gradient_benign_millionths"));
        assert!(
            !fields
                .keys()
                .any(|key| key.starts_with("clipped_gradient_"))
        );
        assert!(!format!("{update:?}").contains("clipped_gradient_"));
        let restored: DpSgdPosteriorUpdate = serde_json::from_value(encoded).unwrap();
        assert_eq!(update, restored);
    }

    #[test]
    fn deterministic_test_noise_handles_full_calibration_range_without_wrapping() {
        let parameters = PrivacyParameters::new(1, 1).unwrap();
        let scale = parameters.gaussian_noise_scale(8_000_000).unwrap() as i64;
        assert!(scale > 40_000_000_000_000);
        let mut first = DeterministicTestNoiseGenerator::new();
        let mut second = DeterministicTestNoiseGenerator::new();
        for _ in 0..16 {
            assert_eq!(first.sample_gaussian(scale), second.sample_gaussian(scale));
        }
        first.counter = u64::MAX;
        let _ = first.sample_gaussian(i64::MAX);
        assert_eq!(first.counter, 0);
    }
}
