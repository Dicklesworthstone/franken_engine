//! (ε,δ)-differential privacy for posterior updates in federated learning.
//!
//! Implements the Gaussian mechanism for differential privacy on Bayesian posterior
//! deltas in federated fleet learning. Provides formal privacy guarantees while
//! enabling collective learning across nodes.
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

/// Global sensitivity of posterior deltas - the maximum possible L2 sensitivity.
/// Since posterior deltas sum to zero and are bounded by probability mass changes,
/// the global sensitivity is bounded by the maximum possible probability shift.
const GLOBAL_SENSITIVITY_MILLIONTHS: u64 = 2_000_000; // 2.0 in millionths

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
        if epsilon_millionths == 0 || epsilon_millionths > MAX_EPSILON_MILLIONTHS {
            return Err(DifferentialPrivacyError::InvalidEpsilon);
        }
        if delta_millionths > MAX_DELTA_MILLIONTHS {
            return Err(DifferentialPrivacyError::InvalidDelta);
        }

        Ok(Self {
            epsilon_millionths,
            delta_millionths,
        })
    }

    /// Default conservative privacy parameters.
    pub fn default() -> Self {
        Self {
            epsilon_millionths: DEFAULT_EPSILON_MILLIONTHS,
            delta_millionths: DEFAULT_DELTA_MILLIONTHS,
        }
    }

    /// Strong privacy parameters (lower epsilon, lower delta).
    pub fn strong_privacy() -> Self {
        Self {
            epsilon_millionths: 50_000, // ε = 0.05
            delta_millionths: 5,        // δ = 5e-6
        }
    }

    /// Moderate privacy parameters (balanced privacy-utility).
    pub fn moderate_privacy() -> Self {
        Self {
            epsilon_millionths: 200_000, // ε = 0.2
            delta_millionths: 20,        // δ = 2e-5
        }
    }

    /// Calculate noise scale for Gaussian mechanism.
    /// σ = sqrt(2 * ln(1.25/δ)) * Δ / ε
    pub fn gaussian_noise_scale(&self, sensitivity_millionths: u64) -> u64 {
        // Compute ln(1.25/δ) using fixed-point approximation
        let delta_ratio = (1_250_000u128 * MILLION as u128) / self.delta_millionths as u128;
        let ln_factor = self.approximate_ln(delta_ratio as u64);

        // σ = sqrt(2 * ln_factor) * sensitivity / epsilon
        let two_ln = 2u128 * ln_factor as u128;
        let sqrt_two_ln = self.approximate_sqrt(two_ln);

        let numerator = sqrt_two_ln * sensitivity_millionths as u128;
        let noise_scale = numerator / self.epsilon_millionths as u128;

        noise_scale.min(u64::MAX as u128) as u64
    }

    /// Fixed-point approximation of natural logarithm using Taylor series.
    fn approximate_ln(&self, x_millionths: u64) -> u64 {
        if x_millionths <= MILLION as u64 {
            return 0; // ln(x) ≤ 0 for x ≤ 1
        }

        // Use ln(x) ≈ (x-1) - (x-1)²/2 + (x-1)³/3 for x close to 1
        // For larger x, use ln(x) = ln(x/e) + 1 repeatedly
        let mut result = 0u64;
        let mut current = x_millionths;

        // Reduce to range near 1 by factoring out e ≈ 2.718282
        let e_millionths = 2_718_282u64;
        while current > 3 * MILLION as u64 {
            current = (current * MILLION as u64) / e_millionths;
            result += MILLION as u64; // Add ln(e) = 1
        }

        // Taylor series for ln(1 + y) where y = (current - 1)
        if current > MILLION as u64 {
            let y = current - MILLION as u64;
            let y2 = (y * y) / MILLION as u64;
            let y3 = (y2 * y) / MILLION as u64;

            result += y - y2 / 2 + y3 / 3;
        }

        result
    }

    /// Fixed-point square root using Newton's method.
    fn approximate_sqrt(&self, x: u128) -> u128 {
        if x == 0 {
            return 0;
        }
        if x <= 1 {
            return 1;
        }

        // Newton's method: x_{n+1} = (x_n + x/x_n) / 2
        let mut estimate = x / 2;
        for _ in 0..10 {
            // 10 iterations for convergence
            let new_estimate = (estimate + x / estimate) / 2;
            if new_estimate.abs_diff(estimate) <= 1 {
                break;
            }
            estimate = new_estimate;
        }
        estimate
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
        self.consumed_epsilon_millionths + params.epsilon_millionths
            <= self.total_epsilon_millionths
            && self.consumed_delta_millionths + params.delta_millionths
                <= self.total_delta_millionths
    }

    /// Allocate budget for a round (if sufficient budget exists).
    pub fn allocate_for_round(
        &mut self,
        round_id: &str,
        params: PrivacyParameters,
    ) -> Result<(), DifferentialPrivacyError> {
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
    /// Apply differential privacy noise to a posterior delta.
    pub fn from_delta(
        delta: PosteriorDelta,
        privacy_params: PrivacyParameters,
        round_id: String,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Self {
        let noise_scale = privacy_params.gaussian_noise_scale(GLOBAL_SENSITIVITY_MILLIONTHS);

        // Add Gaussian noise to each component of the delta
        let noisy_benign =
            delta.delta_benign_millionths + noise_generator.sample_gaussian(noise_scale as i64);
        let noisy_anomalous =
            delta.delta_anomalous_millionths + noise_generator.sample_gaussian(noise_scale as i64);
        let noisy_malicious =
            delta.delta_malicious_millionths + noise_generator.sample_gaussian(noise_scale as i64);
        let noisy_unknown =
            delta.delta_unknown_millionths + noise_generator.sample_gaussian(noise_scale as i64);

        // Renormalize to maintain probability conservation (deltas sum to zero)
        let total_noise = noisy_benign + noisy_anomalous + noisy_malicious + noisy_unknown
            - (delta.delta_benign_millionths
                + delta.delta_anomalous_millionths
                + delta.delta_malicious_millionths
                + delta.delta_unknown_millionths);

        // Distribute excess noise equally across all components
        let correction = total_noise / 4;

        let mut noisy_delta = delta.clone();
        noisy_delta.delta_benign_millionths = noisy_benign - correction;
        noisy_delta.delta_anomalous_millionths = noisy_anomalous - correction;
        noisy_delta.delta_malicious_millionths = noisy_malicious - correction;
        noisy_delta.delta_unknown_millionths = noisy_unknown - correction;

        Self {
            base_delta: noisy_delta,
            privacy_params,
            noise_scale_millionths: noise_scale,
            round_id,
        }
    }

    /// Get the noisy posterior delta for aggregation.
    pub fn get_noisy_delta(&self) -> &PosteriorDelta {
        &self.base_delta
    }
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

impl NoiseGenerator for DeterministicTestNoiseGenerator {
    fn sample_gaussian(&mut self, scale_millionths: i64) -> i64 {
        // Simple deterministic "noise" for testing - not secure!
        self.counter += 1;
        let pseudo_random = (self.counter * 1664525 + 1013904223) % (1u64 << 31);
        let normalized = (pseudo_random as i64 - (1i64 << 30)) * scale_millionths / (1i64 << 29);
        normalized
    }
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
        let budget = PrivacyBudget::new(
            total_epsilon_millionths,
            total_delta_millionths,
            self.current_epoch,
        )?;

        self.node_budgets.insert(node_id, budget);
        Ok(())
    }

    /// Apply differential privacy to a posterior delta.
    pub fn make_delta_private(
        &mut self,
        node_id: &NodeId,
        delta: PosteriorDelta,
        round_id: String,
        noise_generator: &mut dyn NoiseGenerator,
    ) -> Result<PrivatePosteriorDelta, DifferentialPrivacyError> {
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

        // Apply noise to the delta
        let private_delta = PrivatePosteriorDelta::from_delta(
            delta,
            self.default_privacy_params,
            round_id,
            noise_generator,
        );

        Ok(private_delta)
    }

    /// Aggregate private deltas into a differentially private update.
    pub fn aggregate_private_deltas(
        &self,
        private_deltas: Vec<PrivatePosteriorDelta>,
        round_id: String,
    ) -> Result<AggregatedPosteriorUpdate, DifferentialPrivacyError> {
        if private_deltas.is_empty() {
            return Err(DifferentialPrivacyError::EmptyAggregation);
        }

        // Verify all deltas use consistent privacy parameters
        let first_params = private_deltas[0].privacy_params;
        for delta in &private_deltas {
            if delta.privacy_params != first_params {
                return Err(DifferentialPrivacyError::InconsistentPrivacyParams);
            }
        }

        // Extract noisy deltas for aggregation
        let noisy_deltas: Vec<PosteriorDelta> = private_deltas
            .iter()
            .map(|pd| pd.base_delta.clone())
            .collect();

        // Perform standard aggregation on the noisy deltas
        // (This would integrate with the existing AggregationCoordinator)
        let extension_id = noisy_deltas[0].extension_id.clone();
        let epoch = noisy_deltas[0].epoch;

        // Aggregate with confidence weighting
        let mut weighted_benign_sum: i128 = 0;
        let mut weighted_anomalous_sum: i128 = 0;
        let mut weighted_malicious_sum: i128 = 0;
        let mut weighted_unknown_sum: i128 = 0;
        let mut total_weight: u128 = 0;

        for delta in &noisy_deltas {
            let weight = delta.confidence_weight_millionths as i128;
            weighted_benign_sum += delta.delta_benign_millionths as i128 * weight;
            weighted_anomalous_sum += delta.delta_anomalous_millionths as i128 * weight;
            weighted_malicious_sum += delta.delta_malicious_millionths as i128 * weight;
            weighted_unknown_sum += delta.delta_unknown_millionths as i128 * weight;
            total_weight += delta.confidence_weight_millionths as u128;
        }

        // Compute evidence fingerprint
        let fingerprint_input = format!("private_aggregation_{}", round_id);
        let evidence_fingerprint =
            crate::hash_tiers::ContentHash::compute(fingerprint_input.as_bytes());

        let aggregated = AggregatedPosteriorUpdate {
            extension_id,
            aggregate_delta_benign_millionths: weighted_benign_sum as i64,
            aggregate_delta_anomalous_millionths: weighted_anomalous_sum as i64,
            aggregate_delta_malicious_millionths: weighted_malicious_sum as i64,
            aggregate_delta_unknown_millionths: weighted_unknown_sum as i64,
            total_confidence_weight_millionths: total_weight as u64,
            participant_count: noisy_deltas.len() as u32,
            evidence_fingerprint,
            epoch,
            aggregation_timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        };

        Ok(aggregated)
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
    /// Insufficient privacy budget remaining.
    InsufficientBudget,
    /// Node budget not initialized.
    NodeBudgetNotFound,
    /// Duplicate round allocation attempted.
    DuplicateRoundAllocation,
    /// Empty aggregation (no deltas provided).
    EmptyAggregation,
    /// Inconsistent privacy parameters across deltas.
    InconsistentPrivacyParams,
}

impl std::fmt::Display for DifferentialPrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEpsilon => write!(f, "Invalid epsilon parameter"),
            Self::InvalidDelta => write!(f, "Invalid delta parameter"),
            Self::InsufficientBudget => write!(f, "Insufficient privacy budget"),
            Self::NodeBudgetNotFound => write!(f, "Node budget not initialized"),
            Self::DuplicateRoundAllocation => write!(f, "Duplicate round allocation"),
            Self::EmptyAggregation => write!(f, "Empty aggregation"),
            Self::InconsistentPrivacyParams => write!(f, "Inconsistent privacy parameters"),
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

        // Invalid delta (too large)
        assert_eq!(
            PrivacyParameters::new(100_000, 200),
            Err(DifferentialPrivacyError::InvalidDelta)
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
    fn gaussian_noise_scale_calculation() {
        let params = PrivacyParameters::new(100_000, 10).unwrap(); // ε=0.1, δ=1e-5

        let noise_scale = params.gaussian_noise_scale(GLOBAL_SENSITIVITY_MILLIONTHS);

        // Should produce reasonable noise scale
        assert!(noise_scale > 0);
        assert!(noise_scale < 100_000_000); // Should be reasonable magnitude
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
        );

        // Verify the private delta maintains the round ID and privacy params
        assert_eq!(private_delta.round_id, "test_round");
        assert_eq!(private_delta.privacy_params, params);
        assert!(private_delta.noise_scale_millionths > 0);
    }
}
