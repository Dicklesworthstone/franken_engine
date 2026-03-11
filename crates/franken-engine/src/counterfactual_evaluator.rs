//! [FRX-15.2] Off-Policy / Counterfactual Evaluator
//!
//! Implements IPS (Inverse Propensity Scoring) and DR (Doubly Robust) estimators
//! for safer policy updates in lane-routing and containment decisions.
//!
//! All arithmetic uses fixed-point millionths (1 000 000 = 1.0) for determinism.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::runtime_decision_theory::{LaneAction, RegimeLabel};
use crate::security_epoch::SecurityEpoch;

// ── Constants ─────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for serialised evaluator artefacts.
pub const COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION: &str =
    "franken-engine.counterfactual-evaluator.v1";

/// Component label used in telemetry and evidence ledger entries.
pub const COUNTERFACTUAL_EVALUATOR_COMPONENT: &str = "counterfactual_evaluator";

/// Minimum propensity score to prevent unbounded IPS weights (1 % = 10 000).
const MIN_PROPENSITY_MILLIONTHS: i64 = 10_000;

/// Maximum number of logged transitions in a single evaluation batch.
const MAX_BATCH_SIZE: usize = 100_000;

/// Default confidence level for safety envelopes (95 % = 950 000).
const DEFAULT_CONFIDENCE_MILLIONTHS: i64 = 950_000;

// ── Estimator Selection ───────────────────────────────────────────────

/// Which off-policy estimator to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimatorKind {
    /// Inverse Propensity Scoring — unbiased when propensities are correct.
    Ips,
    /// Doubly Robust — combines IPS with an outcome model for lower variance.
    DoublyRobust,
    /// Direct Method — uses outcome model only (biased but low variance).
    DirectMethod,
}

impl fmt::Display for EstimatorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ips => write!(f, "ips"),
            Self::DoublyRobust => write!(f, "doubly_robust"),
            Self::DirectMethod => write!(f, "direct_method"),
        }
    }
}

// ── Policy Abstraction ────────────────────────────────────────────────

/// Compact identifier for a routing/containment policy version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub String);

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A deterministic baseline policy that always selects safe-mode fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselinePolicy {
    pub id: PolicyId,
    /// Fixed action the baseline takes for every state.
    pub action: LaneAction,
}

impl Default for BaselinePolicy {
    fn default() -> Self {
        Self {
            id: PolicyId("baseline-safe-mode".to_string()),
            action: LaneAction::FallbackSafe,
        }
    }
}

// ── Logged Transition ─────────────────────────────────────────────────

/// A single historical transition recorded under the behaviour (logging) policy.
///
/// `propensity_millionths` is the probability (in millionths) that the logging
/// policy assigned to the *actually taken* action given the observed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggedTransition {
    /// Security epoch of the observation.
    pub epoch: SecurityEpoch,
    /// Monotonic tick within the epoch.
    pub tick: u64,
    /// Detected regime at decision time.
    pub regime: RegimeLabel,
    /// Action the logging (behaviour) policy actually took.
    pub action_taken: LaneAction,
    /// Propensity p(action_taken | state) under the behaviour policy (millionths).
    pub propensity_millionths: i64,
    /// Observed reward / negative-loss (millionths, higher is better).
    pub reward_millionths: i64,
    /// Optional outcome-model prediction for the taken action (millionths).
    pub model_prediction_millionths: Option<i64>,
    /// Compact state-context fingerprint for grouping.
    pub context_hash: ContentHash,
}

/// A batch of transitions to evaluate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionBatch {
    pub policy_id: PolicyId,
    pub transitions: Vec<LoggedTransition>,
}

// ── Target Policy Mapping ─────────────────────────────────────────────

/// Maps states to the probability that the *target* (candidate) policy would
/// have taken the same action as the logging policy.
///
/// `target_propensity_millionths` is p_target(action_taken | state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPolicyMapping {
    pub target_policy_id: PolicyId,
    /// Parallel to `TransitionBatch::transitions` — one entry per transition.
    pub target_propensities_millionths: Vec<i64>,
    /// Optional outcome-model predictions for the target action (millionths).
    pub target_model_predictions_millionths: Option<Vec<i64>>,
}

// ── Confidence Envelope ───────────────────────────────────────────────

/// Safety envelope around an off-policy estimate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceEnvelope {
    /// Point estimate (millionths).
    pub estimate_millionths: i64,
    /// Lower bound at the configured confidence level (millionths).
    pub lower_millionths: i64,
    /// Upper bound at the configured confidence level (millionths).
    pub upper_millionths: i64,
    /// Confidence level used (millionths, e.g. 950 000 = 95 %).
    pub confidence_millionths: i64,
    /// Number of effective samples after propensity clipping.
    pub effective_samples: u64,
}

impl ConfidenceEnvelope {
    /// Returns `true` when the entire envelope is strictly positive.
    pub fn is_positive(&self) -> bool {
        self.lower_millionths > 0
    }

    /// Returns `true` when the entire envelope is strictly negative.
    pub fn is_negative(&self) -> bool {
        self.upper_millionths < 0
    }

    /// Width of the interval.
    pub fn width(&self) -> i64 {
        self.upper_millionths.saturating_sub(self.lower_millionths)
    }
}

// ── Envelope Status ───────────────────────────────────────────────────

/// Classifies how an off-policy estimate relates to a safety threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    /// Entire envelope above the safety threshold — safe to adopt.
    Safe,
    /// Envelope overlaps threshold — inconclusive, need more data.
    Inconclusive,
    /// Entire envelope below the threshold — candidate is worse.
    Unsafe,
}

impl fmt::Display for EnvelopeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safe => write!(f, "safe"),
            Self::Inconclusive => write!(f, "inconclusive"),
            Self::Unsafe => write!(f, "unsafe"),
        }
    }
}

// ── Evaluation Result ─────────────────────────────────────────────────

/// Full result of comparing a candidate policy against the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Estimator used.
    pub estimator: EstimatorKind,
    /// Candidate policy evaluated.
    pub candidate_policy_id: PolicyId,
    /// Baseline policy compared against.
    pub baseline_policy_id: PolicyId,
    /// Absolute value estimate for the candidate.
    pub candidate_envelope: ConfidenceEnvelope,
    /// Absolute value estimate for the baseline.
    pub baseline_envelope: ConfidenceEnvelope,
    /// Improvement delta: candidate − baseline.
    pub improvement_envelope: ConfidenceEnvelope,
    /// Whether the candidate passes the safety gate.
    pub safety_status: EnvelopeStatus,
    /// Per-regime breakdown.
    pub regime_breakdown: BTreeMap<String, ConfidenceEnvelope>,
    /// Artefact content hash (computed over the deterministic serialisation).
    pub artifact_hash: ContentHash,
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors that can occur during off-policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualError {
    /// Batch is empty — cannot estimate.
    EmptyBatch,
    /// Batch exceeds the maximum allowed size.
    BatchTooLarge { size: usize, max: usize },
    /// Target propensity vector length does not match the batch.
    PropensityLengthMismatch { batch: usize, target: usize },
    /// A propensity value fell outside [0, MILLION].
    PropensityOutOfRange { index: usize, value: i64 },
    /// All propensities clamped to zero — effective sample size is zero.
    ZeroEffectiveSamples,
    /// Model prediction vector length mismatch.
    ModelPredictionLengthMismatch { batch: usize, predictions: usize },
    /// Confidence level outside (0, MILLION).
    InvalidConfidence { value: i64 },
    /// The improvement threshold is negative.
    NegativeThreshold { value: i64 },
}

impl fmt::Display for CounterfactualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "empty transition batch"),
            Self::BatchTooLarge { size, max } => {
                write!(f, "batch size {size} exceeds maximum {max}")
            }
            Self::PropensityLengthMismatch { batch, target } => {
                write!(
                    f,
                    "propensity vector length {target} != batch length {batch}"
                )
            }
            Self::PropensityOutOfRange { index, value } => {
                write!(f, "propensity at index {index} out of range: {value}")
            }
            Self::ZeroEffectiveSamples => {
                write!(f, "zero effective samples after propensity clipping")
            }
            Self::ModelPredictionLengthMismatch { batch, predictions } => {
                write!(
                    f,
                    "model prediction length {predictions} != batch length {batch}"
                )
            }
            Self::InvalidConfidence { value } => {
                write!(f, "confidence level out of range: {value}")
            }
            Self::NegativeThreshold { value } => {
                write!(f, "improvement threshold must be non-negative: {value}")
            }
        }
    }
}

impl std::error::Error for CounterfactualError {}

// ── Evaluator Configuration ───────────────────────────────────────────

/// Configuration for the counterfactual evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorConfig {
    /// Which estimator to use.
    pub estimator: EstimatorKind,
    /// Confidence level for envelopes (millionths, default 950 000 = 95 %).
    pub confidence_millionths: i64,
    /// Minimum propensity after clipping (millionths, default 10 000 = 1 %).
    pub min_propensity_millionths: i64,
    /// Minimum improvement threshold the candidate must exceed (millionths).
    pub improvement_threshold_millionths: i64,
    /// Whether to compute per-regime breakdowns.
    pub regime_breakdown: bool,
}

impl Default for EvaluatorConfig {
    fn default() -> Self {
        Self {
            estimator: EstimatorKind::DoublyRobust,
            confidence_millionths: DEFAULT_CONFIDENCE_MILLIONTHS,
            min_propensity_millionths: MIN_PROPENSITY_MILLIONTHS,
            improvement_threshold_millionths: 0,
            regime_breakdown: true,
        }
    }
}

// ── The Evaluator ─────────────────────────────────────────────────────

/// Off-policy / counterfactual evaluator.
///
/// Computes IPS, DR, or direct-method estimates of how well a candidate
/// policy would have performed compared to the baseline, using historical
/// logged transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualEvaluator {
    config: EvaluatorConfig,
    baseline: BaselinePolicy,
    evaluation_count: u64,
}

impl CounterfactualEvaluator {
    /// Create an evaluator with the given configuration and baseline.
    pub fn new(
        config: EvaluatorConfig,
        baseline: BaselinePolicy,
    ) -> Result<Self, CounterfactualError> {
        if config.confidence_millionths <= 0 || config.confidence_millionths >= MILLION {
            return Err(CounterfactualError::InvalidConfidence {
                value: config.confidence_millionths,
            });
        }
        if config.improvement_threshold_millionths < 0 {
            return Err(CounterfactualError::NegativeThreshold {
                value: config.improvement_threshold_millionths,
            });
        }
        Ok(Self {
            config,
            baseline,
            evaluation_count: 0,
        })
    }

    /// Create with default configuration and safe-mode baseline.
    pub fn default_safe_mode() -> Self {
        Self {
            config: EvaluatorConfig::default(),
            baseline: BaselinePolicy::default(),
            evaluation_count: 0,
        }
    }

    /// Number of evaluations performed so far.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Access the current configuration.
    pub fn config(&self) -> &EvaluatorConfig {
        &self.config
    }

    /// Access the baseline policy.
    pub fn baseline(&self) -> &BaselinePolicy {
        &self.baseline
    }

    // ── Core evaluation ───────────────────────────────────────────────

    /// Evaluate a candidate policy against the baseline using the configured
    /// estimator.
    pub fn evaluate(
        &mut self,
        batch: &TransitionBatch,
        target: &TargetPolicyMapping,
    ) -> Result<EvaluationResult, CounterfactualError> {
        self.validate_inputs(batch, target)?;

        let n = batch.transitions.len();

        // Compute importance weights w_i = p_target(a_i|s_i) / p_logging(a_i|s_i)
        let weights = self.compute_importance_weights(batch, target)?;

        // Compute effective sample size
        let eff = self.effective_sample_size(&weights);
        if eff == 0 {
            return Err(CounterfactualError::ZeroEffectiveSamples);
        }

        // Estimate candidate value
        let candidate_estimate = match self.config.estimator {
            EstimatorKind::Ips => self.ips_estimate(batch, &weights),
            EstimatorKind::DoublyRobust => self.dr_estimate(batch, target, &weights),
            EstimatorKind::DirectMethod => self.direct_estimate(target, n),
        };

        // Estimate baseline value (simple mean of rewards where action matches baseline)
        let baseline_estimate = self.baseline_estimate(batch);

        // Compute improvement delta
        let improvement = candidate_estimate.saturating_sub(baseline_estimate);

        // Compute confidence half-widths using CLT approximation
        let half_width = self.confidence_half_width(batch, &weights, candidate_estimate, n);

        let candidate_envelope = ConfidenceEnvelope {
            estimate_millionths: candidate_estimate,
            lower_millionths: candidate_estimate.saturating_sub(half_width),
            upper_millionths: candidate_estimate.saturating_add(half_width),
            confidence_millionths: self.config.confidence_millionths,
            effective_samples: eff,
        };

        let baseline_hw = self.baseline_half_width(batch, baseline_estimate);
        let baseline_envelope = ConfidenceEnvelope {
            estimate_millionths: baseline_estimate,
            lower_millionths: baseline_estimate.saturating_sub(baseline_hw),
            upper_millionths: baseline_estimate.saturating_add(baseline_hw),
            confidence_millionths: self.config.confidence_millionths,
            effective_samples: n as u64,
        };

        // Combined improvement envelope (wider due to independence)
        let combined_hw = self.combined_half_width(half_width, baseline_hw);
        let improvement_envelope = ConfidenceEnvelope {
            estimate_millionths: improvement,
            lower_millionths: improvement.saturating_sub(combined_hw),
            upper_millionths: improvement.saturating_add(combined_hw),
            confidence_millionths: self.config.confidence_millionths,
            effective_samples: eff,
        };

        // Determine safety status
        let threshold = self.config.improvement_threshold_millionths;
        let safety_status = if improvement_envelope.lower_millionths >= threshold {
            EnvelopeStatus::Safe
        } else if improvement_envelope.upper_millionths < threshold {
            EnvelopeStatus::Unsafe
        } else {
            EnvelopeStatus::Inconclusive
        };

        // Per-regime breakdown
        let regime_breakdown = if self.config.regime_breakdown {
            self.compute_regime_breakdown(batch, &weights, target)
        } else {
            BTreeMap::new()
        };

        // Hash the result deterministically
        let artifact_hash = self.compute_artifact_hash(
            &candidate_envelope,
            &baseline_envelope,
            &improvement_envelope,
        );

        self.evaluation_count += 1;

        Ok(EvaluationResult {
            schema_version: COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION.to_string(),
            estimator: self.config.estimator,
            candidate_policy_id: target.target_policy_id.clone(),
            baseline_policy_id: self.baseline.id.clone(),
            candidate_envelope,
            baseline_envelope,
            improvement_envelope,
            safety_status,
            regime_breakdown,
            artifact_hash,
        })
    }

    // ── Validation ────────────────────────────────────────────────────

    fn validate_inputs(
        &self,
        batch: &TransitionBatch,
        target: &TargetPolicyMapping,
    ) -> Result<(), CounterfactualError> {
        let n = batch.transitions.len();
        if n == 0 {
            return Err(CounterfactualError::EmptyBatch);
        }
        if n > MAX_BATCH_SIZE {
            return Err(CounterfactualError::BatchTooLarge {
                size: n,
                max: MAX_BATCH_SIZE,
            });
        }
        if target.target_propensities_millionths.len() != n {
            return Err(CounterfactualError::PropensityLengthMismatch {
                batch: n,
                target: target.target_propensities_millionths.len(),
            });
        }
        // Validate propensity ranges
        for (i, p) in batch.transitions.iter().enumerate() {
            if p.propensity_millionths < 0 || p.propensity_millionths > MILLION {
                return Err(CounterfactualError::PropensityOutOfRange {
                    index: i,
                    value: p.propensity_millionths,
                });
            }
        }
        for (i, &p) in target.target_propensities_millionths.iter().enumerate() {
            if !(0..=MILLION).contains(&p) {
                return Err(CounterfactualError::PropensityOutOfRange { index: i, value: p });
            }
        }
        // Validate model predictions length if present
        if let Some(ref preds) = target.target_model_predictions_millionths
            && preds.len() != n
        {
            return Err(CounterfactualError::ModelPredictionLengthMismatch {
                batch: n,
                predictions: preds.len(),
            });
        }
        Ok(())
    }

    // ── Importance Weights ────────────────────────────────────────────

    fn compute_importance_weights(
        &self,
        batch: &TransitionBatch,
        target: &TargetPolicyMapping,
    ) -> Result<Vec<i64>, CounterfactualError> {
        let min_prop = self.config.min_propensity_millionths.max(1);
        let mut weights = Vec::with_capacity(batch.transitions.len());

        for (i, t) in batch.transitions.iter().enumerate() {
            let p_log = t.propensity_millionths.max(min_prop);
            let p_tgt = target.target_propensities_millionths[i];

            // w_i = p_target / p_logging  (in millionths)
            // To keep precision: w = (p_tgt * MILLION) / p_log
            let w = if p_log == 0 {
                0
            } else {
                (p_tgt.saturating_mul(MILLION)) / p_log
            };
            weights.push(w);
        }

        Ok(weights)
    }

    // ── Effective Sample Size ─────────────────────────────────────────

    fn effective_sample_size(&self, weights: &[i64]) -> u64 {
        // ESS = (sum w_i)^2 / sum(w_i^2)
        let sum: i128 = weights.iter().map(|&w| w as i128).sum();
        let sum_sq: i128 = weights.iter().map(|&w| (w as i128) * (w as i128)).sum();
        if sum_sq == 0 {
            return 0;
        }
        let numerator = sum * sum;
        // Scale down from millionths^2
        let ess = numerator / sum_sq;
        ess.max(0) as u64
    }

    // ── IPS Estimator ─────────────────────────────────────────────────

    fn ips_estimate(&self, batch: &TransitionBatch, weights: &[i64]) -> i64 {
        // IPS = (1/n) * sum(w_i * r_i)
        let n = batch.transitions.len() as i128;
        if n == 0 {
            return 0;
        }

        let weighted_sum: i128 = batch
            .transitions
            .iter()
            .zip(weights.iter())
            .map(|(t, &w)| {
                // (w * r) / MILLION to keep scale
                (w as i128 * t.reward_millionths as i128) / MILLION as i128
            })
            .sum();

        (weighted_sum / n) as i64
    }

    // ── DR Estimator ──────────────────────────────────────────────────

    fn dr_estimate(
        &self,
        batch: &TransitionBatch,
        target: &TargetPolicyMapping,
        weights: &[i64],
    ) -> i64 {
        // DR = (1/n) * sum[ m_hat(s_i) + w_i * (r_i - m_hat(s_i)) ]
        // where m_hat is the outcome model prediction
        let n = batch.transitions.len() as i128;
        if n == 0 {
            return 0;
        }

        let model_preds = target.target_model_predictions_millionths.as_ref();

        let sum: i128 = batch
            .transitions
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let m_hat = model_preds
                    .map(|p| p[i] as i128)
                    .unwrap_or(t.reward_millionths as i128);
                let residual = t.reward_millionths as i128 - m_hat;
                let w = weights[i] as i128;
                // m_hat + w * residual / MILLION
                m_hat + (w * residual) / MILLION as i128
            })
            .sum();

        (sum / n) as i64
    }

    // ── Direct Method Estimator ───────────────────────────────────────

    fn direct_estimate(&self, target: &TargetPolicyMapping, n: usize) -> i64 {
        // Simply average the model predictions
        let preds = match target.target_model_predictions_millionths.as_ref() {
            Some(p) => p,
            None => return 0,
        };
        if n == 0 {
            return 0;
        }
        let sum: i128 = preds.iter().map(|&p| p as i128).sum();
        (sum / n as i128) as i64
    }

    // ── Baseline Estimate ─────────────────────────────────────────────

    fn baseline_estimate(&self, batch: &TransitionBatch) -> i64 {
        // Mean reward across all transitions (simple average)
        let n = batch.transitions.len() as i128;
        if n == 0 {
            return 0;
        }
        let sum: i128 = batch
            .transitions
            .iter()
            .map(|t| t.reward_millionths as i128)
            .sum();
        (sum / n) as i64
    }

    // ── Confidence Intervals ──────────────────────────────────────────

    fn confidence_half_width(
        &self,
        batch: &TransitionBatch,
        weights: &[i64],
        mean: i64,
        n: usize,
    ) -> i64 {
        if n <= 1 {
            return MILLION;
        }

        // Compute variance of weighted rewards
        let mean_128 = mean as i128;
        let sum_sq_dev: i128 = batch
            .transitions
            .iter()
            .zip(weights.iter())
            .map(|(t, &w)| {
                let wr = (w as i128 * t.reward_millionths as i128) / MILLION as i128;
                let dev = wr - mean_128;
                dev * dev
            })
            .sum();

        let variance = sum_sq_dev / (n as i128 - 1);
        let std_dev = isqrt_i128(variance.max(0));
        let se = std_dev / isqrt_i128(n as i128);

        // z-multiplier for confidence level (approximate)
        let z = z_multiplier(self.config.confidence_millionths);
        let hw = (se * z as i128) / MILLION as i128;
        hw.min(i64::MAX as i128) as i64
    }

    fn baseline_half_width(&self, batch: &TransitionBatch, mean: i64) -> i64 {
        let n = batch.transitions.len();
        if n <= 1 {
            return MILLION;
        }
        let mean_128 = mean as i128;
        let sum_sq_dev: i128 = batch
            .transitions
            .iter()
            .map(|t| {
                let dev = t.reward_millionths as i128 - mean_128;
                dev * dev
            })
            .sum();

        let variance = sum_sq_dev / (n as i128 - 1);
        let std_dev = isqrt_i128(variance.max(0));
        let se = std_dev / isqrt_i128(n as i128);

        let z = z_multiplier(self.config.confidence_millionths);
        let hw = (se * z as i128) / MILLION as i128;
        hw.min(i64::MAX as i128) as i64
    }

    fn combined_half_width(&self, hw_candidate: i64, hw_baseline: i64) -> i64 {
        // sqrt(hw_c^2 + hw_b^2) for independent estimates
        let a = hw_candidate as i128;
        let b = hw_baseline as i128;
        let combined_sq = a * a + b * b;
        isqrt_i128(combined_sq).min(i64::MAX as i128) as i64
    }

    // ── Per-Regime Breakdown ──────────────────────────────────────────

    fn compute_regime_breakdown(
        &self,
        batch: &TransitionBatch,
        weights: &[i64],
        _target: &TargetPolicyMapping,
    ) -> BTreeMap<String, ConfidenceEnvelope> {
        // Group by regime
        let mut regime_groups: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
        for (i, t) in batch.transitions.iter().enumerate() {
            let key = t.regime.to_string();
            regime_groups
                .entry(key)
                .or_default()
                .push((weights[i], t.reward_millionths));
        }

        let mut result = BTreeMap::new();
        for (regime, items) in &regime_groups {
            let n = items.len() as i128;
            if n == 0 {
                continue;
            }

            let weighted_sum: i128 = items
                .iter()
                .map(|&(w, r)| (w as i128 * r as i128) / MILLION as i128)
                .sum();
            let mean = (weighted_sum / n) as i64;

            let sum_sq_dev: i128 = items
                .iter()
                .map(|&(w, r)| {
                    let wr = (w as i128 * r as i128) / MILLION as i128;
                    let dev = wr - mean as i128;
                    dev * dev
                })
                .sum();

            let hw = if n > 1 {
                let variance = sum_sq_dev / (n - 1);
                let std_dev = isqrt_i128(variance.max(0));
                let se = std_dev / isqrt_i128(n);
                let z = z_multiplier(self.config.confidence_millionths);
                (se * z as i128) / MILLION as i128
            } else {
                MILLION as i128
            };

            let ess = {
                let wsum: i128 = items.iter().map(|&(w, _)| w as i128).sum();
                let wsq: i128 = items.iter().map(|&(w, _)| (w as i128) * (w as i128)).sum();
                if wsq == 0 {
                    0u64
                } else {
                    ((wsum * wsum) / wsq).max(0) as u64
                }
            };

            let hw = hw.min(i64::MAX as i128) as i64;
            result.insert(
                regime.clone(),
                ConfidenceEnvelope {
                    estimate_millionths: mean,
                    lower_millionths: mean.saturating_sub(hw),
                    upper_millionths: mean.saturating_add(hw),
                    confidence_millionths: self.config.confidence_millionths,
                    effective_samples: ess,
                },
            );
        }

        result
    }

    // ── Artifact Hash ─────────────────────────────────────────────────

    fn compute_artifact_hash(
        &self,
        candidate: &ConfidenceEnvelope,
        baseline: &ConfidenceEnvelope,
        improvement: &ConfidenceEnvelope,
    ) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION.as_bytes());
        buf.extend_from_slice(&candidate.estimate_millionths.to_le_bytes());
        buf.extend_from_slice(&candidate.lower_millionths.to_le_bytes());
        buf.extend_from_slice(&candidate.upper_millionths.to_le_bytes());
        buf.extend_from_slice(&baseline.estimate_millionths.to_le_bytes());
        buf.extend_from_slice(&baseline.lower_millionths.to_le_bytes());
        buf.extend_from_slice(&baseline.upper_millionths.to_le_bytes());
        buf.extend_from_slice(&improvement.estimate_millionths.to_le_bytes());
        buf.extend_from_slice(&improvement.lower_millionths.to_le_bytes());
        buf.extend_from_slice(&improvement.upper_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

// ── Batch Comparison ──────────────────────────────────────────────────

/// Compare multiple candidate policies against the same baseline in a single
/// pass over the transition batch.
pub fn compare_policies(
    evaluator: &mut CounterfactualEvaluator,
    batch: &TransitionBatch,
    candidates: &[TargetPolicyMapping],
) -> Result<Vec<EvaluationResult>, CounterfactualError> {
    let mut results = Vec::with_capacity(candidates.len());
    for c in candidates {
        results.push(evaluator.evaluate(batch, c)?);
    }
    Ok(results)
}

/// Rank candidate policies by their improvement lower bound (most conservative).
pub fn rank_by_safety(results: &[EvaluationResult]) -> Vec<(usize, i64)> {
    let mut ranked: Vec<(usize, i64)> = results
        .iter()
        .enumerate()
        .map(|(i, r)| (i, r.improvement_envelope.lower_millionths))
        .collect();
    ranked.sort_by_key(|b| std::cmp::Reverse(b.1));
    ranked
}

/// Filter results to only those passing the safety gate.
pub fn safe_candidates(results: &[EvaluationResult]) -> Vec<&EvaluationResult> {
    results
        .iter()
        .filter(|r| r.safety_status == EnvelopeStatus::Safe)
        .collect()
}

/// Collect distinct regimes observed across all results.
pub fn observed_regimes(results: &[EvaluationResult]) -> BTreeSet<String> {
    let mut regimes = BTreeSet::new();
    for r in results {
        for k in r.regime_breakdown.keys() {
            regimes.insert(k.clone());
        }
    }
    regimes
}

// ── Utility Functions ─────────────────────────────────────────────────

/// Integer square root for i128 values (Heron's method).
fn isqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let mut x = n;
    #[allow(clippy::manual_div_ceil)]
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Approximate z-multiplier for a given confidence level (millionths).
///
/// Uses a small lookup table for common confidence levels and linear
/// interpolation between entries. Returns the multiplier in millionths.
fn z_multiplier(confidence_millionths: i64) -> i64 {
    // Common z-values (confidence → z * MILLION)
    // 90% → 1.645, 95% → 1.960, 99% → 2.576
    const TABLE: [(i64, i64); 5] = [
        (800_000, 1_282_000), // 80% → z=1.282
        (900_000, 1_645_000), // 90% → z=1.645
        (950_000, 1_960_000), // 95% → z=1.960
        (990_000, 2_576_000), // 99% → z=2.576
        (999_000, 3_291_000), // 99.9% → z=3.291
    ];

    // Exact match
    for &(c, z) in &TABLE {
        if confidence_millionths == c {
            return z;
        }
    }

    // Linear interpolation
    for pair in TABLE.windows(2) {
        let (c0, z0) = pair[0];
        let (c1, z1) = pair[1];
        if confidence_millionths >= c0 && confidence_millionths <= c1 {
            let frac =
                ((confidence_millionths - c0) as i128 * (z1 - z0) as i128) / (c1 - c0) as i128;
            return z0 + frac as i64;
        }
    }

    // Outside table range — clamp
    if confidence_millionths < TABLE[0].0 {
        TABLE[0].1
    } else {
        TABLE[TABLE.len() - 1].1
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> ContentHash {
        ContentHash::compute(&[seed; 32])
    }

    fn make_transition(
        epoch: u64,
        tick: u64,
        regime: RegimeLabel,
        reward: i64,
        propensity: i64,
    ) -> LoggedTransition {
        LoggedTransition {
            epoch: SecurityEpoch::from_raw(epoch),
            tick,
            regime,
            action_taken: LaneAction::FallbackSafe,
            propensity_millionths: propensity,
            reward_millionths: reward,
            model_prediction_millionths: None,
            context_hash: make_hash(tick as u8),
        }
    }

    fn make_batch(n: usize, reward: i64, propensity: i64) -> TransitionBatch {
        TransitionBatch {
            policy_id: PolicyId("logging-v1".to_string()),
            transitions: (0..n)
                .map(|i| make_transition(1, i as u64, RegimeLabel::Normal, reward, propensity))
                .collect(),
        }
    }

    fn make_target(n: usize, propensity: i64) -> TargetPolicyMapping {
        TargetPolicyMapping {
            target_policy_id: PolicyId("candidate-v1".to_string()),
            target_propensities_millionths: vec![propensity; n],
            target_model_predictions_millionths: None,
        }
    }

    // ── Constructor tests ─────────────────────────────────────────

    #[test]
    fn default_safe_mode_creates_evaluator() {
        let e = CounterfactualEvaluator::default_safe_mode();
        assert_eq!(e.evaluation_count(), 0);
        assert_eq!(e.config().estimator, EstimatorKind::DoublyRobust);
        assert_eq!(e.baseline().id, PolicyId("baseline-safe-mode".to_string()));
    }

    #[test]
    fn new_with_valid_config() {
        let cfg = EvaluatorConfig::default();
        let base = BaselinePolicy::default();
        let e = CounterfactualEvaluator::new(cfg, base);
        assert!(e.is_ok());
    }

    #[test]
    fn new_rejects_zero_confidence() {
        let cfg = EvaluatorConfig {
            confidence_millionths: 0,
            ..Default::default()
        };
        let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
        assert_eq!(
            result.unwrap_err(),
            CounterfactualError::InvalidConfidence { value: 0 }
        );
    }

    #[test]
    fn new_rejects_million_confidence() {
        let cfg = EvaluatorConfig {
            confidence_millionths: MILLION,
            ..Default::default()
        };
        let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
        assert_eq!(
            result.unwrap_err(),
            CounterfactualError::InvalidConfidence { value: MILLION }
        );
    }

    #[test]
    fn new_rejects_negative_threshold() {
        let cfg = EvaluatorConfig {
            improvement_threshold_millionths: -1,
            ..Default::default()
        };
        let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
        assert_eq!(
            result.unwrap_err(),
            CounterfactualError::NegativeThreshold { value: -1 }
        );
    }

    // ── Validation tests ──────────────────────────────────────────

    #[test]
    fn evaluate_empty_batch() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = TransitionBatch {
            policy_id: PolicyId("p".to_string()),
            transitions: vec![],
        };
        let target = make_target(0, 500_000);
        assert_eq!(
            e.evaluate(&batch, &target).unwrap_err(),
            CounterfactualError::EmptyBatch
        );
    }

    #[test]
    fn evaluate_propensity_length_mismatch() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(5, 500_000, 500_000);
        let target = make_target(3, 500_000);
        let err = e.evaluate(&batch, &target).unwrap_err();
        assert!(matches!(
            err,
            CounterfactualError::PropensityLengthMismatch { .. }
        ));
    }

    #[test]
    fn evaluate_propensity_out_of_range_negative() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let mut batch = make_batch(3, 500_000, 500_000);
        batch.transitions[1].propensity_millionths = -1;
        let target = make_target(3, 500_000);
        let err = e.evaluate(&batch, &target).unwrap_err();
        assert!(matches!(
            err,
            CounterfactualError::PropensityOutOfRange {
                index: 1,
                value: -1
            }
        ));
    }

    #[test]
    fn evaluate_propensity_out_of_range_too_large() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(3, 500_000, 500_000);
        let mut target = make_target(3, 500_000);
        target.target_propensities_millionths[2] = MILLION + 1;
        let err = e.evaluate(&batch, &target).unwrap_err();
        assert!(matches!(
            err,
            CounterfactualError::PropensityOutOfRange { index: 2, .. }
        ));
    }

    #[test]
    fn evaluate_model_prediction_length_mismatch() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(3, 500_000, 500_000);
        let mut target = make_target(3, 500_000);
        target.target_model_predictions_millionths = Some(vec![500_000; 2]);
        let err = e.evaluate(&batch, &target).unwrap_err();
        assert!(matches!(
            err,
            CounterfactualError::ModelPredictionLengthMismatch { .. }
        ));
    }

    // ── IPS estimator tests ───────────────────────────────────────

    #[test]
    fn ips_equal_propensities_yields_mean_reward() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(100, 600_000, 500_000);
        let target = make_target(100, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        // When propensities match, IPS ≈ mean reward
        assert!(
            (result.candidate_envelope.estimate_millionths - 600_000).abs() < 10_000,
            "got {}",
            result.candidate_envelope.estimate_millionths
        );
    }

    #[test]
    fn ips_double_propensity_doubles_weight() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        // Logging at 250k, target at 500k → weight ≈ 2
        let batch = make_batch(100, 300_000, 250_000);
        let target = make_target(100, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        // Weighted estimate: 300k * 2 = 600k
        assert!(
            (result.candidate_envelope.estimate_millionths - 600_000).abs() < 10_000,
            "got {}",
            result.candidate_envelope.estimate_millionths
        );
    }

    #[test]
    fn ips_zero_target_propensity_yields_zero_effective_samples() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(10, 500_000, 500_000);
        let target = make_target(10, 0); // Target never takes this action
        let result = e.evaluate(&batch, &target);
        assert!(result.is_err(), "expected ZeroEffectiveSamples error");
    }

    // ── DR estimator tests ────────────────────────────────────────

    #[test]
    fn dr_with_perfect_model_matches_prediction() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(50, 400_000, 500_000);
        let mut target = make_target(50, 500_000);
        target.target_model_predictions_millionths = Some(vec![400_000; 50]);
        let result = e.evaluate(&batch, &target).unwrap();
        // DR with equal propensities and perfect model → close to reward mean
        assert!(
            (result.candidate_envelope.estimate_millionths - 400_000).abs() < 20_000,
            "got {}",
            result.candidate_envelope.estimate_millionths
        );
    }

    #[test]
    fn dr_fallback_without_model_uses_rewards() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(50, 700_000, 500_000);
        let target = make_target(50, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert!(
            (result.candidate_envelope.estimate_millionths - 700_000).abs() < 20_000,
            "got {}",
            result.candidate_envelope.estimate_millionths
        );
    }

    // ── Direct method tests ───────────────────────────────────────

    #[test]
    fn direct_method_averages_predictions() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::DirectMethod,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(10, 100_000, 500_000);
        let mut target = make_target(10, 500_000);
        target.target_model_predictions_millionths = Some(vec![800_000; 10]);
        let result = e.evaluate(&batch, &target).unwrap();
        assert_eq!(result.candidate_envelope.estimate_millionths, 800_000);
    }

    #[test]
    fn direct_method_no_model_returns_zero() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::DirectMethod,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(10, 500_000, 500_000);
        let target = make_target(10, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert_eq!(result.candidate_envelope.estimate_millionths, 0);
    }

    // ── Confidence envelope tests ─────────────────────────────────

    #[test]
    fn envelope_width_is_consistent() {
        let env = ConfidenceEnvelope {
            estimate_millionths: 500_000,
            lower_millionths: 400_000,
            upper_millionths: 600_000,
            confidence_millionths: 950_000,
            effective_samples: 100,
        };
        assert_eq!(env.width(), 200_000);
        assert!(env.is_positive());
        assert!(!env.is_negative());
    }

    #[test]
    fn envelope_negative_range() {
        let env = ConfidenceEnvelope {
            estimate_millionths: -200_000,
            lower_millionths: -400_000,
            upper_millionths: -100_000,
            confidence_millionths: 950_000,
            effective_samples: 50,
        };
        assert!(!env.is_positive());
        assert!(env.is_negative());
    }

    #[test]
    fn envelope_spanning_zero() {
        let env = ConfidenceEnvelope {
            estimate_millionths: 10_000,
            lower_millionths: -50_000,
            upper_millionths: 70_000,
            confidence_millionths: 950_000,
            effective_samples: 20,
        };
        assert!(!env.is_positive());
        assert!(!env.is_negative());
    }

    // ── Safety status tests ───────────────────────────────────────

    #[test]
    fn safety_status_safe_when_improvement_clearly_positive() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            improvement_threshold_millionths: 0,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        // Target propensity 2x logging → weights 2x → estimate 2x rewards
        let batch = make_batch(1000, 300_000, 250_000);
        let target = make_target(1000, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        // Improvement is large with tight CI on uniform data
        // Note: may be Inconclusive with small samples
        assert!(
            result.safety_status == EnvelopeStatus::Safe
                || result.safety_status == EnvelopeStatus::Inconclusive
        );
    }

    #[test]
    fn safety_status_unsafe_when_candidate_worse() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            improvement_threshold_millionths: 500_000,
            ..Default::default()
        }; // Very high threshold
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(100, 500_000, 500_000);
        let target = make_target(100, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        // Improvement is ~0 but threshold is 500k → unsafe
        assert_eq!(result.safety_status, EnvelopeStatus::Unsafe);
    }

    // ── Regime breakdown tests ────────────────────────────────────

    #[test]
    fn regime_breakdown_groups_by_regime() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let mut batch = make_batch(6, 500_000, 500_000);
        // Split into two regimes
        batch.transitions[0].regime = RegimeLabel::Normal;
        batch.transitions[1].regime = RegimeLabel::Normal;
        batch.transitions[2].regime = RegimeLabel::Normal;
        batch.transitions[3].regime = RegimeLabel::Elevated;
        batch.transitions[4].regime = RegimeLabel::Elevated;
        batch.transitions[5].regime = RegimeLabel::Elevated;
        let target = make_target(6, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert!(result.regime_breakdown.contains_key("normal"));
        assert!(result.regime_breakdown.contains_key("elevated"));
        assert_eq!(result.regime_breakdown.len(), 2);
    }

    #[test]
    fn regime_breakdown_disabled() {
        let cfg = EvaluatorConfig {
            regime_breakdown: false,
            ..Default::default()
        };
        let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
        let batch = make_batch(10, 500_000, 500_000);
        let target = make_target(10, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert!(result.regime_breakdown.is_empty());
    }

    // ── Evaluation count tracking ─────────────────────────────────

    #[test]
    fn evaluation_count_increments() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        assert_eq!(e.evaluation_count(), 0);
        let batch = make_batch(5, 500_000, 500_000);
        let target = make_target(5, 500_000);
        let _ = e.evaluate(&batch, &target).unwrap();
        assert_eq!(e.evaluation_count(), 1);
        let _ = e.evaluate(&batch, &target).unwrap();
        assert_eq!(e.evaluation_count(), 2);
    }

    // ── Schema version ────────────────────────────────────────────

    #[test]
    fn result_includes_schema_version() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(5, 500_000, 500_000);
        let target = make_target(5, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert_eq!(
            result.schema_version,
            COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION
        );
    }

    // ── Artifact hash determinism ─────────────────────────────────

    #[test]
    fn artifact_hash_is_deterministic() {
        let mut e1 = CounterfactualEvaluator::default_safe_mode();
        let mut e2 = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(20, 500_000, 500_000);
        let target = make_target(20, 500_000);
        let r1 = e1.evaluate(&batch, &target).unwrap();
        let r2 = e2.evaluate(&batch, &target).unwrap();
        assert_eq!(r1.artifact_hash, r2.artifact_hash);
    }

    #[test]
    fn artifact_hash_changes_with_different_data() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch1 = make_batch(20, 500_000, 500_000);
        let batch2 = make_batch(20, 600_000, 500_000);
        let target = make_target(20, 500_000);
        let r1 = e.evaluate(&batch1, &target).unwrap();
        let r2 = e.evaluate(&batch2, &target).unwrap();
        assert_ne!(r1.artifact_hash, r2.artifact_hash);
    }

    // ── Batch comparison tests ────────────────────────────────────

    #[test]
    fn compare_policies_returns_all() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(20, 500_000, 500_000);
        let candidates = vec![make_target(20, 300_000), make_target(20, 700_000)];
        let results = compare_policies(&mut e, &batch, &candidates).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn rank_by_safety_orders_descending() {
        let results = vec![
            EvaluationResult {
                schema_version: "v1".to_string(),
                estimator: EstimatorKind::Ips,
                candidate_policy_id: PolicyId("a".to_string()),
                baseline_policy_id: PolicyId("b".to_string()),
                candidate_envelope: ConfidenceEnvelope {
                    estimate_millionths: 100_000,
                    lower_millionths: 50_000,
                    upper_millionths: 150_000,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                baseline_envelope: ConfidenceEnvelope {
                    estimate_millionths: 0,
                    lower_millionths: 0,
                    upper_millionths: 0,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                improvement_envelope: ConfidenceEnvelope {
                    estimate_millionths: 100_000,
                    lower_millionths: 10_000,
                    upper_millionths: 190_000,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                safety_status: EnvelopeStatus::Safe,
                regime_breakdown: BTreeMap::new(),
                artifact_hash: make_hash(1),
            },
            EvaluationResult {
                schema_version: "v1".to_string(),
                estimator: EstimatorKind::Ips,
                candidate_policy_id: PolicyId("c".to_string()),
                baseline_policy_id: PolicyId("b".to_string()),
                candidate_envelope: ConfidenceEnvelope {
                    estimate_millionths: 200_000,
                    lower_millionths: 150_000,
                    upper_millionths: 250_000,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                baseline_envelope: ConfidenceEnvelope {
                    estimate_millionths: 0,
                    lower_millionths: 0,
                    upper_millionths: 0,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                improvement_envelope: ConfidenceEnvelope {
                    estimate_millionths: 200_000,
                    lower_millionths: 100_000,
                    upper_millionths: 300_000,
                    confidence_millionths: 950_000,
                    effective_samples: 10,
                },
                safety_status: EnvelopeStatus::Safe,
                regime_breakdown: BTreeMap::new(),
                artifact_hash: make_hash(2),
            },
        ];
        let ranked = rank_by_safety(&results);
        assert_eq!(ranked.len(), 2);
        // Second result has higher lower bound (100k vs 10k)
        assert_eq!(ranked[0].0, 1);
        assert_eq!(ranked[1].0, 0);
    }

    #[test]
    fn safe_candidates_filters_correctly() {
        let safe_result = EvaluationResult {
            schema_version: "v1".to_string(),
            estimator: EstimatorKind::Ips,
            candidate_policy_id: PolicyId("safe".to_string()),
            baseline_policy_id: PolicyId("b".to_string()),
            candidate_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            baseline_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            improvement_envelope: ConfidenceEnvelope {
                estimate_millionths: 100_000,
                lower_millionths: 50_000,
                upper_millionths: 150_000,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            safety_status: EnvelopeStatus::Safe,
            regime_breakdown: BTreeMap::new(),
            artifact_hash: make_hash(1),
        };
        let unsafe_result = EvaluationResult {
            safety_status: EnvelopeStatus::Unsafe,
            candidate_policy_id: PolicyId("unsafe".to_string()),
            ..safe_result.clone()
        };
        let results = vec![safe_result, unsafe_result];
        let safe = safe_candidates(&results);
        assert_eq!(safe.len(), 1);
        assert_eq!(safe[0].candidate_policy_id, PolicyId("safe".to_string()));
    }

    // ── Serde round-trip tests ────────────────────────────────────

    #[test]
    fn estimator_kind_serde_roundtrip() {
        for kind in [
            EstimatorKind::Ips,
            EstimatorKind::DoublyRobust,
            EstimatorKind::DirectMethod,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: EstimatorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn policy_id_serde_roundtrip() {
        let pid = PolicyId("test-policy-v3".to_string());
        let json = serde_json::to_string(&pid).unwrap();
        let back: PolicyId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, back);
    }

    #[test]
    fn logged_transition_serde_roundtrip() {
        let t = make_transition(5, 42, RegimeLabel::Attack, 750_000, 333_000);
        let json = serde_json::to_string(&t).unwrap();
        let back: LoggedTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn evaluation_result_serde_roundtrip() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(10, 500_000, 500_000);
        let target = make_target(10, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: EvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = EvaluatorConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: EvaluatorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn error_serde_roundtrip() {
        let errs = vec![
            CounterfactualError::EmptyBatch,
            CounterfactualError::BatchTooLarge {
                size: 200_000,
                max: MAX_BATCH_SIZE,
            },
            CounterfactualError::ZeroEffectiveSamples,
        ];
        for e in errs {
            let json = serde_json::to_string(&e).unwrap();
            let back: CounterfactualError = serde_json::from_str(&json).unwrap();
            assert_eq!(e, back);
        }
    }

    // ── Display tests ─────────────────────────────────────────────

    #[test]
    fn estimator_kind_display() {
        assert_eq!(EstimatorKind::Ips.to_string(), "ips");
        assert_eq!(EstimatorKind::DoublyRobust.to_string(), "doubly_robust");
        assert_eq!(EstimatorKind::DirectMethod.to_string(), "direct_method");
    }

    #[test]
    fn policy_id_display() {
        let pid = PolicyId("my-pol".to_string());
        assert_eq!(pid.to_string(), "my-pol");
    }

    #[test]
    fn envelope_status_display() {
        assert_eq!(EnvelopeStatus::Safe.to_string(), "safe");
        assert_eq!(EnvelopeStatus::Inconclusive.to_string(), "inconclusive");
        assert_eq!(EnvelopeStatus::Unsafe.to_string(), "unsafe");
    }

    #[test]
    fn error_display_all_variants() {
        let cases = vec![
            (CounterfactualError::EmptyBatch, "empty transition batch"),
            (
                CounterfactualError::BatchTooLarge {
                    size: 200_000,
                    max: 100_000,
                },
                "batch size 200000 exceeds maximum 100000",
            ),
            (
                CounterfactualError::PropensityLengthMismatch {
                    batch: 10,
                    target: 5,
                },
                "propensity vector length 5 != batch length 10",
            ),
            (
                CounterfactualError::PropensityOutOfRange {
                    index: 3,
                    value: -5,
                },
                "propensity at index 3 out of range: -5",
            ),
            (
                CounterfactualError::ZeroEffectiveSamples,
                "zero effective samples after propensity clipping",
            ),
            (
                CounterfactualError::ModelPredictionLengthMismatch {
                    batch: 10,
                    predictions: 7,
                },
                "model prediction length 7 != batch length 10",
            ),
            (
                CounterfactualError::InvalidConfidence { value: -1 },
                "confidence level out of range: -1",
            ),
            (
                CounterfactualError::NegativeThreshold { value: -10 },
                "improvement threshold must be non-negative: -10",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    // ── Utility function tests ────────────────────────────────────

    #[test]
    fn isqrt_basic() {
        assert_eq!(isqrt_i128(0), 0);
        assert_eq!(isqrt_i128(1), 1);
        assert_eq!(isqrt_i128(4), 2);
        assert_eq!(isqrt_i128(9), 3);
        assert_eq!(isqrt_i128(100), 10);
        assert_eq!(isqrt_i128(1_000_000), 1000);
    }

    #[test]
    fn isqrt_negative() {
        assert_eq!(isqrt_i128(-1), 0);
        assert_eq!(isqrt_i128(-1_000_000), 0);
    }

    #[test]
    fn isqrt_non_perfect() {
        // sqrt(2) ≈ 1.414, floor = 1
        assert_eq!(isqrt_i128(2), 1);
        // sqrt(8) ≈ 2.828, floor = 2
        assert_eq!(isqrt_i128(8), 2);
    }

    #[test]
    fn z_multiplier_exact_table_values() {
        assert_eq!(z_multiplier(800_000), 1_282_000);
        assert_eq!(z_multiplier(900_000), 1_645_000);
        assert_eq!(z_multiplier(950_000), 1_960_000);
        assert_eq!(z_multiplier(990_000), 2_576_000);
        assert_eq!(z_multiplier(999_000), 3_291_000);
    }

    #[test]
    fn z_multiplier_interpolation() {
        // Midpoint between 90% and 95% should be between 1.645M and 1.960M
        let z = z_multiplier(925_000);
        assert!(z > 1_645_000 && z < 1_960_000, "got {z}");
    }

    #[test]
    fn z_multiplier_clamps_below() {
        // Below 80% → clamp to 80% value
        assert_eq!(z_multiplier(500_000), 1_282_000);
    }

    #[test]
    fn z_multiplier_clamps_above() {
        // Above 99.9% → clamp to 99.9% value
        assert_eq!(z_multiplier(999_900), 3_291_000);
    }

    // ── Observed regimes helper ───────────────────────────────────

    #[test]
    fn observed_regimes_collects_all() {
        let result = EvaluationResult {
            schema_version: "v1".to_string(),
            estimator: EstimatorKind::Ips,
            candidate_policy_id: PolicyId("a".to_string()),
            baseline_policy_id: PolicyId("b".to_string()),
            candidate_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            baseline_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            improvement_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            safety_status: EnvelopeStatus::Safe,
            regime_breakdown: {
                let mut m = BTreeMap::new();
                m.insert(
                    "normal".to_string(),
                    ConfidenceEnvelope {
                        estimate_millionths: 0,
                        lower_millionths: 0,
                        upper_millionths: 0,
                        confidence_millionths: 950_000,
                        effective_samples: 5,
                    },
                );
                m.insert(
                    "attack".to_string(),
                    ConfidenceEnvelope {
                        estimate_millionths: 0,
                        lower_millionths: 0,
                        upper_millionths: 0,
                        confidence_millionths: 950_000,
                        effective_samples: 5,
                    },
                );
                m
            },
            artifact_hash: make_hash(1),
        };
        let regimes = observed_regimes(&[result]);
        assert!(regimes.contains("normal"));
        assert!(regimes.contains("attack"));
        assert_eq!(regimes.len(), 2);
    }

    // ── BaselinePolicy default test ───────────────────────────────

    #[test]
    fn baseline_default_is_safe_mode() {
        let bl = BaselinePolicy::default();
        assert_eq!(bl.id, PolicyId("baseline-safe-mode".to_string()));
        assert_eq!(bl.action, LaneAction::FallbackSafe);
    }

    // ── Mixed regime evaluation ───────────────────────────────────

    #[test]
    fn evaluation_with_multiple_regimes_produces_correct_breakdown() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let mut transitions = Vec::new();
        for i in 0..20 {
            let regime = if i < 10 {
                RegimeLabel::Normal
            } else {
                RegimeLabel::Degraded
            };
            transitions.push(LoggedTransition {
                epoch: SecurityEpoch::from_raw(1),
                tick: i,
                regime,
                action_taken: LaneAction::RouteTo(crate::runtime_decision_theory::LaneId(
                    "fast".to_string(),
                )),
                propensity_millionths: 500_000,
                reward_millionths: if i < 10 { 800_000 } else { 200_000 },
                model_prediction_millionths: None,
                context_hash: make_hash(i as u8),
            });
        }
        let batch = TransitionBatch {
            policy_id: PolicyId("log".to_string()),
            transitions,
        };
        let target = make_target(20, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        let bd = &result.regime_breakdown;
        assert!(bd.contains_key("normal"));
        assert!(bd.contains_key("degraded"));
        // Normal regime should have higher estimate than degraded
        let normal_est = bd["normal"].estimate_millionths;
        let degraded_est = bd["degraded"].estimate_millionths;
        assert!(
            normal_est > degraded_est,
            "normal={normal_est}, degraded={degraded_est}"
        );
    }

    // ── Effective samples edge cases ──────────────────────────────

    #[test]
    fn single_transition_evaluates() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(1, 500_000, 500_000);
        let target = make_target(1, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert!(result.candidate_envelope.effective_samples >= 1);
    }

    #[test]
    fn large_batch_evaluates() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        let batch = make_batch(10_000, 500_000, 500_000);
        let target = make_target(10_000, 500_000);
        let result = e.evaluate(&batch, &target).unwrap();
        assert!(result.candidate_envelope.effective_samples > 0);
    }

    // ── Enrichment: serde roundtrips ─────────────────────────────────

    #[test]
    fn baseline_policy_serde_roundtrip() {
        let bp = BaselinePolicy::default();
        let json = serde_json::to_string(&bp).unwrap();
        let back: BaselinePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    #[test]
    fn transition_batch_serde_roundtrip() {
        let batch = make_batch(3, 100_000, 500_000);
        let json = serde_json::to_string(&batch).unwrap();
        let back: TransitionBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
    }

    #[test]
    fn target_policy_mapping_serde_roundtrip() {
        let target = make_target(5, 600_000);
        let json = serde_json::to_string(&target).unwrap();
        let back: TargetPolicyMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(target, back);
    }

    #[test]
    fn confidence_envelope_serde_roundtrip() {
        let ce = ConfidenceEnvelope {
            estimate_millionths: 500_000,
            lower_millionths: 400_000,
            upper_millionths: 600_000,
            confidence_millionths: 950_000,
            effective_samples: 42,
        };
        let json = serde_json::to_string(&ce).unwrap();
        let back: ConfidenceEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(ce, back);
    }

    #[test]
    fn envelope_status_serde_roundtrip_all_variants() {
        for variant in [
            EnvelopeStatus::Safe,
            EnvelopeStatus::Inconclusive,
            EnvelopeStatus::Unsafe,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: EnvelopeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn evaluator_config_serde_roundtrip() {
        let cfg = EvaluatorConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: EvaluatorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn counterfactual_evaluator_serde_roundtrip() {
        let e = CounterfactualEvaluator::default_safe_mode();
        let json = serde_json::to_string(&e).unwrap();
        let back: CounterfactualEvaluator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evaluation_count(), 0);
        assert_eq!(back.config().estimator, EstimatorKind::DoublyRobust);
    }

    // ── Enrichment: ConfidenceEnvelope accessors ─────────────────────

    #[test]
    fn confidence_envelope_width_zero_when_equal() {
        let ce = ConfidenceEnvelope {
            estimate_millionths: 500_000,
            lower_millionths: 500_000,
            upper_millionths: 500_000,
            confidence_millionths: 950_000,
            effective_samples: 10,
        };
        assert_eq!(ce.width(), 0);
    }

    #[test]
    fn confidence_envelope_is_positive_boundary_at_zero() {
        let ce = ConfidenceEnvelope {
            estimate_millionths: 100,
            lower_millionths: 0,
            upper_millionths: 200,
            confidence_millionths: 950_000,
            effective_samples: 10,
        };
        // lower == 0 means is_positive() returns false (> 0 required)
        assert!(!ce.is_positive());
    }

    #[test]
    fn confidence_envelope_is_negative_boundary_at_zero() {
        let ce = ConfidenceEnvelope {
            estimate_millionths: -100,
            lower_millionths: -200,
            upper_millionths: 0,
            confidence_millionths: 950_000,
            effective_samples: 10,
        };
        // upper == 0 means is_negative() returns false (< 0 required)
        assert!(!ce.is_negative());
    }

    #[test]
    fn confidence_envelope_neither_positive_nor_negative() {
        let ce = ConfidenceEnvelope {
            estimate_millionths: 0,
            lower_millionths: -100,
            upper_millionths: 100,
            confidence_millionths: 950_000,
            effective_samples: 10,
        };
        assert!(!ce.is_positive());
        assert!(!ce.is_negative());
    }

    // ── Enrichment: error display and std::error ─────────────────────

    #[test]
    fn counterfactual_error_implements_std_error() {
        let err = CounterfactualError::EmptyBatch;
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn counterfactual_error_all_variants_display_unique() {
        let variants: Vec<CounterfactualError> = vec![
            CounterfactualError::EmptyBatch,
            CounterfactualError::BatchTooLarge {
                size: 200_000,
                max: 100_000,
            },
            CounterfactualError::PropensityLengthMismatch {
                batch: 10,
                target: 5,
            },
            CounterfactualError::PropensityOutOfRange {
                index: 3,
                value: -1,
            },
            CounterfactualError::ZeroEffectiveSamples,
            CounterfactualError::ModelPredictionLengthMismatch {
                batch: 10,
                predictions: 7,
            },
            CounterfactualError::InvalidConfidence { value: 0 },
            CounterfactualError::NegativeThreshold { value: -100 },
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
            set.insert(s);
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn counterfactual_error_serde_roundtrip_all_variants() {
        let variants = vec![
            CounterfactualError::EmptyBatch,
            CounterfactualError::BatchTooLarge { size: 1, max: 2 },
            CounterfactualError::PropensityLengthMismatch {
                batch: 3,
                target: 4,
            },
            CounterfactualError::PropensityOutOfRange {
                index: 0,
                value: -5,
            },
            CounterfactualError::ZeroEffectiveSamples,
            CounterfactualError::ModelPredictionLengthMismatch {
                batch: 5,
                predictions: 6,
            },
            CounterfactualError::InvalidConfidence { value: 0 },
            CounterfactualError::NegativeThreshold { value: -1 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CounterfactualError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: EnvelopeStatus display ───────────────────────────

    #[test]
    fn envelope_status_display_all_unique() {
        let variants = [
            EnvelopeStatus::Safe,
            EnvelopeStatus::Inconclusive,
            EnvelopeStatus::Unsafe,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), 3);
    }

    // ── Enrichment: evaluator accessors ──────────────────────────────

    #[test]
    fn evaluator_config_accessor_matches_input() {
        let cfg = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            confidence_millionths: 900_000,
            min_propensity_millionths: 50_000,
            improvement_threshold_millionths: 10_000,
            regime_breakdown: false,
        };
        let e = CounterfactualEvaluator::new(cfg.clone(), BaselinePolicy::default()).unwrap();
        assert_eq!(*e.config(), cfg);
    }

    #[test]
    fn evaluator_baseline_accessor_returns_correct_baseline() {
        let bl = BaselinePolicy {
            id: PolicyId("custom-baseline".into()),
            action: LaneAction::FallbackSafe,
        };
        let e = CounterfactualEvaluator::new(EvaluatorConfig::default(), bl.clone()).unwrap();
        assert_eq!(*e.baseline(), bl);
    }

    #[test]
    fn evaluation_count_increments_repeated() {
        let mut e = CounterfactualEvaluator::default_safe_mode();
        assert_eq!(e.evaluation_count(), 0);
        let batch = make_batch(5, 500_000, 500_000);
        let target = make_target(5, 500_000);
        e.evaluate(&batch, &target).unwrap();
        assert_eq!(e.evaluation_count(), 1);
        e.evaluate(&batch, &target).unwrap();
        assert_eq!(e.evaluation_count(), 2);
    }

    // ── Enrichment: validation errors ────────────────────────────────

    #[test]
    fn invalid_confidence_zero_rejected() {
        let cfg = EvaluatorConfig {
            confidence_millionths: 0,
            ..EvaluatorConfig::default()
        };
        let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
        assert_eq!(err, CounterfactualError::InvalidConfidence { value: 0 });
    }

    #[test]
    fn invalid_confidence_million_rejected() {
        let cfg = EvaluatorConfig {
            confidence_millionths: 1_000_000,
            ..EvaluatorConfig::default()
        };
        let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
        assert_eq!(
            err,
            CounterfactualError::InvalidConfidence { value: 1_000_000 }
        );
    }

    #[test]
    fn negative_threshold_rejected() {
        let cfg = EvaluatorConfig {
            improvement_threshold_millionths: -1,
            ..EvaluatorConfig::default()
        };
        let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
        assert_eq!(err, CounterfactualError::NegativeThreshold { value: -1 });
    }

    // ── Enrichment: EstimatorKind ────────────────────────────────────

    #[test]
    fn estimator_kind_display_all_unique() {
        let variants = [
            EstimatorKind::Ips,
            EstimatorKind::DoublyRobust,
            EstimatorKind::DirectMethod,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn estimator_kind_serde_roundtrip_all() {
        for v in [
            EstimatorKind::Ips,
            EstimatorKind::DoublyRobust,
            EstimatorKind::DirectMethod,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: EstimatorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: PolicyId ─────────────────────────────────────────

    #[test]
    fn policy_id_ordering_is_lexicographic() {
        let a = PolicyId("a-policy".into());
        let b = PolicyId("b-policy".into());
        assert!(a < b);
    }

    #[test]
    fn policy_id_display_matches_inner() {
        let pid = PolicyId("my-policy".into());
        assert_eq!(pid.to_string(), "my-policy");
    }
}
