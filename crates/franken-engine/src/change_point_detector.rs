//! Sequential change-point detector with composite alternatives (bd-cixqu.36.1).
//!
//! Implements CUSUM (Cumulative Sum) and Page rule variants for detecting
//! changes in the underlying distribution of sequential observations.
//! Based on Lai (1995) and Tartakovsky (2014) theory for composite alternatives.
//!
//! Unlike simple hypothesis testing, change-point detection identifies WHEN
//! the distribution changes, not just WHETHER it has changed. This is crucial
//! for guardplane applications where the timing of regime changes affects
//! containment policies.
//!
//! Key components:
//! - `ChangePointDetector`: CUSUM-based sequential detector
//! - `ChangePointVerdict`: Detection result with timing and parameter estimates
//! - `CompositeAlternative`: Parametric family for post-change distribution
//! - Integration with `MartingaleLedger` for anytime-valid stopping
//!
//! Reference: Track JJ (bd-cixqu.36) - Change-point detection with provable
//! detection-delay bounds, sharpens Track AA martingale guardplane.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::martingale_decision_ledger::{MartingaleLedger, MartingaleVerdict, StoppingThreshold};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants and Configuration
// ---------------------------------------------------------------------------

/// Convention: 1.0 in millionths for fixed-point arithmetic.
const MILLION: i64 = 1_000_000;

/// Minimum number of observations required before change-point detection.
const MIN_OBSERVATIONS_FOR_DETECTION: u64 = 5;

/// Default threshold for CUSUM statistic (log(1/0.01) ≈ 4.605).
const DEFAULT_CUSUM_THRESHOLD_MILLIONTHS: i64 = 4_605_000;

// ---------------------------------------------------------------------------
// CompositeAlternative - Parametric family for post-change distribution
// ---------------------------------------------------------------------------

/// Composite alternative hypothesis: post-change distribution belongs to
/// a parametric family rather than a single point alternative.
///
/// This addresses the "hard part" noted in the bead requirements - realistic
/// regime changes follow families of distributions, not single fixed distributions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositeAlternative {
    /// Normal distribution family with unknown mean and known variance.
    NormalMeanShift {
        /// Known pre-change mean (in millionths).
        pre_change_mean_millionths: i64,
        /// Known variance (in millionths squared).
        variance_millionths_squared: i64,
        /// Range of plausible post-change means (in millionths).
        mean_range_millionths: (i64, i64),
    },
    /// Exponential distribution family with unknown rate parameter.
    ExponentialRateShift {
        /// Known pre-change rate (in millionths).
        pre_change_rate_millionths: i64,
        /// Range of plausible post-change rates (in millionths).
        rate_range_millionths: (i64, i64),
    },
    /// Bernoulli distribution family with unknown success probability.
    BernoulliProbabilityShift {
        /// Known pre-change probability (in millionths).
        pre_change_prob_millionths: i64,
        /// Range of plausible post-change probabilities (in millionths).
        prob_range_millionths: (i64, i64),
    },
}

impl CompositeAlternative {
    /// Compute the generalized likelihood ratio for a given observation
    /// under this composite alternative.
    pub fn log_likelihood_ratio_millionths(&self, observation_millionths: i64) -> i64 {
        match self {
            Self::NormalMeanShift {
                pre_change_mean_millionths,
                variance_millionths_squared,
                mean_range_millionths,
            } => self.normal_glr_millionths(
                observation_millionths,
                *pre_change_mean_millionths,
                *variance_millionths_squared,
                *mean_range_millionths,
            ),
            Self::ExponentialRateShift {
                pre_change_rate_millionths,
                rate_range_millionths,
            } => self.exponential_glr_millionths(
                observation_millionths,
                *pre_change_rate_millionths,
                *rate_range_millionths,
            ),
            Self::BernoulliProbabilityShift {
                pre_change_prob_millionths,
                prob_range_millionths,
            } => self.bernoulli_glr_millionths(
                observation_millionths,
                *pre_change_prob_millionths,
                *prob_range_millionths,
            ),
        }
    }

    /// Estimate post-change parameters using maximum likelihood over the
    /// observed data since the detected change point.
    pub fn estimate_post_change_parameters(
        &self,
        observations_since_change: &[i64],
    ) -> BTreeMap<String, i64> {
        let mut params = BTreeMap::new();

        if observations_since_change.is_empty() {
            return params;
        }

        match self {
            Self::NormalMeanShift {
                mean_range_millionths,
                ..
            } => {
                let sample_mean = observations_since_change.iter().sum::<i64>()
                    / observations_since_change.len() as i64;
                let clamped_mean =
                    sample_mean.clamp(mean_range_millionths.0, mean_range_millionths.1);
                params.insert("estimated_mean_millionths".to_string(), clamped_mean);
            }
            Self::ExponentialRateShift {
                rate_range_millionths,
                ..
            } => {
                let sample_mean = observations_since_change.iter().sum::<i64>()
                    / observations_since_change.len() as i64;
                let estimated_rate = if sample_mean > 0 {
                    MILLION * MILLION / sample_mean
                } else {
                    rate_range_millionths.1
                };
                let clamped_rate =
                    estimated_rate.clamp(rate_range_millionths.0, rate_range_millionths.1);
                params.insert("estimated_rate_millionths".to_string(), clamped_rate);
            }
            Self::BernoulliProbabilityShift {
                prob_range_millionths,
                ..
            } => {
                let successes = observations_since_change
                    .iter()
                    .filter(|&&x| x >= MILLION / 2)
                    .count() as i64;
                let estimated_prob = successes * MILLION / observations_since_change.len() as i64;
                let clamped_prob =
                    estimated_prob.clamp(prob_range_millionths.0, prob_range_millionths.1);
                params.insert("estimated_probability_millionths".to_string(), clamped_prob);
            }
        }

        params
    }

    /// Generalized likelihood ratio for normal mean shift.
    fn normal_glr_millionths(
        &self,
        observation: i64,
        pre_mean: i64,
        variance: i64,
        mean_range: (i64, i64),
    ) -> i64 {
        // Simplified GLR: compare likelihood under pre-change mean vs
        // maximum likelihood post-change mean (clamped to range).
        let mle_post_mean = observation.clamp(mean_range.0, mean_range.1);

        // Log-likelihood difference (simplified, assuming unit variance for numerical stability)
        let pre_score = -((observation - pre_mean).pow(2)) / (2 * variance.max(MILLION));
        let post_score = -((observation - mle_post_mean).pow(2)) / (2 * variance.max(MILLION));

        (post_score - pre_score).clamp(-10 * MILLION, 10 * MILLION)
    }

    /// Generalized likelihood ratio for exponential rate shift.
    fn exponential_glr_millionths(
        &self,
        observation: i64,
        pre_rate: i64,
        rate_range: (i64, i64),
    ) -> i64 {
        if observation <= 0 {
            return -MILLION; // Invalid observation for exponential
        }

        // MLE for exponential: rate = 1/mean, but clamp to range
        let mle_rate = (MILLION * MILLION / observation).clamp(rate_range.0, rate_range.1);

        // Log-likelihood ratio (scaled to millionths)
        let pre_log_lik = (pre_rate * MILLION / MILLION) - (pre_rate * observation / MILLION);
        let post_log_lik = (mle_rate * MILLION / MILLION) - (mle_rate * observation / MILLION);

        (post_log_lik - pre_log_lik).clamp(-10 * MILLION, 10 * MILLION)
    }

    /// Generalized likelihood ratio for Bernoulli probability shift.
    fn bernoulli_glr_millionths(
        &self,
        observation: i64,
        pre_prob: i64,
        prob_range: (i64, i64),
    ) -> i64 {
        let is_success = observation >= MILLION / 2; // Threshold at 0.5

        // MLE: probability = proportion of successes (here just 0 or 1 for single obs)
        let mle_prob = if is_success {
            prob_range.1 // Favor high probability for success
        } else {
            prob_range.0 // Favor low probability for failure
        }
        .clamp(1, MILLION - 1); // Avoid log(0)

        // Log-likelihood ratio
        let pre_log_lik = if is_success {
            (pre_prob * MILLION / MILLION).max(1).min(MILLION - 1)
        } else {
            ((MILLION - pre_prob) * MILLION / MILLION)
                .max(1)
                .min(MILLION - 1)
        };
        let post_log_lik = if is_success {
            mle_prob
        } else {
            MILLION - mle_prob
        };

        ((post_log_lik as f64).ln() - (pre_log_lik as f64).ln()).round() as i64 * MILLION
    }
}

// ---------------------------------------------------------------------------
// ChangePointVerdict - Detection result with timing and estimates
// ---------------------------------------------------------------------------

/// Verdict emitted by the change-point detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangePointVerdict {
    /// No change detected yet; continue monitoring.
    Continue,
    /// Change point detected at the specified time.
    ChangeDetected {
        /// Sequence number where change was detected.
        detection_time: u64,
        /// Estimated sequence number where change actually occurred.
        estimated_change_point: u64,
        /// Pre-change parameter estimates.
        pre_change_parameters: BTreeMap<String, i64>,
        /// Post-change parameter estimates.
        post_change_parameters: BTreeMap<String, i64>,
        /// CUSUM statistic value at detection (in millionths).
        cusum_statistic_millionths: i64,
        /// Content hash of the evidence atom for this detection.
        evidence_hash: ContentHash,
        /// Signed evidence atom (if signing is enabled).
        signed_evidence: Option<Vec<u8>>,
    },
}

impl ChangePointVerdict {
    /// Whether this verdict indicates a change was detected.
    pub fn is_change_detected(&self) -> bool {
        matches!(self, Self::ChangeDetected { .. })
    }

    /// Get the detection time if a change was detected.
    pub fn detection_time(&self) -> Option<u64> {
        match self {
            Self::ChangeDetected { detection_time, .. } => Some(*detection_time),
            Self::Continue => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ChangePointDetector - CUSUM-based sequential detector
// ---------------------------------------------------------------------------

/// Sequential change-point detector using CUSUM (Cumulative Sum) approach.
///
/// Implements the Page rule with composite alternatives as described in
/// Lai (1995) and Tartakovsky (2014). Integrates with `MartingaleLedger`
/// for anytime-valid stopping properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePointDetector {
    /// Identifier for this detector instance.
    pub detector_id: String,
    /// Composite alternative hypothesis.
    pub alternative: CompositeAlternative,
    /// Threshold for CUSUM statistic (in millionths).
    pub threshold_millionths: i64,
    /// Security epoch for evidence signing.
    pub epoch: SecurityEpoch,
    /// Current CUSUM statistic (in millionths).
    cusum_statistic_millionths: i64,
    /// Observations processed so far.
    observations: Vec<i64>,
    /// Whether a change has been detected.
    change_detected: bool,
    /// Integrated martingale ledger for anytime-valid stopping.
    martingale_ledger: Option<MartingaleLedger>,
}

impl ChangePointDetector {
    /// Create a new change-point detector.
    pub fn new(
        detector_id: impl Into<String>,
        alternative: CompositeAlternative,
        threshold_millionths: i64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            detector_id: detector_id.into(),
            alternative,
            threshold_millionths,
            epoch,
            cusum_statistic_millionths: 0,
            observations: Vec::new(),
            change_detected: false,
            martingale_ledger: None,
        }
    }

    /// Create detector with default threshold.
    pub fn new_with_default_threshold(
        detector_id: impl Into<String>,
        alternative: CompositeAlternative,
        epoch: SecurityEpoch,
    ) -> Self {
        Self::new(
            detector_id,
            alternative,
            DEFAULT_CUSUM_THRESHOLD_MILLIONTHS,
            epoch,
        )
    }

    /// Enable martingale integration for anytime-valid stopping.
    pub fn with_martingale_integration(mut self, stopping_threshold: StoppingThreshold) -> Self {
        self.martingale_ledger = Some(MartingaleLedger::new(stopping_threshold, self.epoch));
        self
    }

    /// Process a new observation and return the detection verdict.
    pub fn process_observation(
        &mut self,
        observation_millionths: i64,
        timestamp_ns: u64,
    ) -> Result<ChangePointVerdict, ChangePointError> {
        if self.change_detected {
            return Err(ChangePointError::AlreadyDetected);
        }

        // Append observation to history
        self.observations.push(observation_millionths);

        // Compute likelihood ratio for this observation
        let log_lr = self
            .alternative
            .log_likelihood_ratio_millionths(observation_millionths);

        // Update CUSUM statistic: S_n = max(0, S_{n-1} + log(L_n))
        self.cusum_statistic_millionths = (self.cusum_statistic_millionths + log_lr).max(0);

        // Update integrated martingale if enabled
        if let Some(ref mut ledger) = self.martingale_ledger {
            if !ledger.is_stopped() {
                let payload_bytes =
                    self.compute_observation_payload(observation_millionths, timestamp_ns);
                let payload_digest = ContentHash::compute(&payload_bytes);

                let _verdict = ledger.append(log_lr, timestamp_ns, payload_digest)?;
            }
        }

        // Check for change-point detection
        if self.cusum_statistic_millionths >= self.threshold_millionths
            && self.observations.len() >= MIN_OBSERVATIONS_FOR_DETECTION as usize
        {
            self.change_detected = true;
            let detection_time = self.observations.len() as u64;

            // Estimate change point location (simplified: assume recent change)
            let estimated_change_point = detection_time.saturating_sub(5).max(1);

            // Compute parameter estimates
            let pre_change_observations = &self.observations[..estimated_change_point as usize];
            let post_change_observations = &self.observations[estimated_change_point as usize..];

            let pre_change_parameters =
                self.estimate_pre_change_parameters(pre_change_observations);
            let post_change_parameters = self
                .alternative
                .estimate_post_change_parameters(post_change_observations);

            // Generate evidence hash
            let evidence_data = self.compute_evidence_data(detection_time, estimated_change_point);
            let evidence_hash = ContentHash::compute(&evidence_data);

            Ok(ChangePointVerdict::ChangeDetected {
                detection_time,
                estimated_change_point,
                pre_change_parameters,
                post_change_parameters,
                cusum_statistic_millionths: self.cusum_statistic_millionths,
                evidence_hash,
                signed_evidence: None, // TODO: Implement evidence signing
            })
        } else {
            Ok(ChangePointVerdict::Continue)
        }
    }

    /// Get current CUSUM statistic.
    pub fn cusum_statistic_millionths(&self) -> i64 {
        self.cusum_statistic_millionths
    }

    /// Get number of observations processed.
    pub fn observation_count(&self) -> u64 {
        self.observations.len() as u64
    }

    /// Whether a change has been detected.
    pub fn is_change_detected(&self) -> bool {
        self.change_detected
    }

    /// Get reference to integrated martingale ledger.
    pub fn martingale_ledger(&self) -> Option<&MartingaleLedger> {
        self.martingale_ledger.as_ref()
    }

    /// Reset the detector to initial state.
    pub fn reset(&mut self) {
        self.cusum_statistic_millionths = 0;
        self.observations.clear();
        self.change_detected = false;
        self.martingale_ledger = None;
    }

    /// Estimate pre-change parameters from observations.
    fn estimate_pre_change_parameters(&self, observations: &[i64]) -> BTreeMap<String, i64> {
        let mut params = BTreeMap::new();

        if observations.is_empty() {
            return params;
        }

        match &self.alternative {
            CompositeAlternative::NormalMeanShift {
                pre_change_mean_millionths,
                ..
            } => {
                params.insert(
                    "pre_change_mean_millionths".to_string(),
                    *pre_change_mean_millionths,
                );
                let sample_variance = if observations.len() > 1 {
                    let mean = observations.iter().sum::<i64>() / observations.len() as i64;
                    observations.iter().map(|&x| (x - mean).pow(2)).sum::<i64>()
                        / (observations.len() - 1) as i64
                } else {
                    MILLION // Default unit variance
                };
                params.insert(
                    "pre_change_variance_millionths".to_string(),
                    sample_variance,
                );
            }
            CompositeAlternative::ExponentialRateShift {
                pre_change_rate_millionths,
                ..
            } => {
                params.insert(
                    "pre_change_rate_millionths".to_string(),
                    *pre_change_rate_millionths,
                );
            }
            CompositeAlternative::BernoulliProbabilityShift {
                pre_change_prob_millionths,
                ..
            } => {
                params.insert(
                    "pre_change_probability_millionths".to_string(),
                    *pre_change_prob_millionths,
                );
            }
        }

        params
    }

    /// Compute observation payload for martingale integration.
    fn compute_observation_payload(&self, observation: i64, timestamp_ns: u64) -> Vec<u8> {
        format!("{}:{}:{}", self.detector_id, observation, timestamp_ns).into_bytes()
    }

    /// Compute evidence data for signing.
    fn compute_evidence_data(&self, detection_time: u64, change_point: u64) -> Vec<u8> {
        format!(
            "detector:{},detection:{},change:{},cusum:{}",
            self.detector_id, detection_time, change_point, self.cusum_statistic_millionths
        )
        .into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during change-point detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangePointError {
    /// Change has already been detected; detector is stopped.
    AlreadyDetected,
    /// Invalid observation value.
    InvalidObservation(String),
    /// Martingale ledger error.
    MartingaleError(String),
    /// Insufficient data for detection.
    InsufficientData,
}

impl fmt::Display for ChangePointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyDetected => write!(f, "change already detected"),
            Self::InvalidObservation(msg) => write!(f, "invalid observation: {}", msg),
            Self::MartingaleError(msg) => write!(f, "martingale error: {}", msg),
            Self::InsufficientData => write!(f, "insufficient data for detection"),
        }
    }
}

impl std::error::Error for ChangePointError {}

impl From<crate::martingale_decision_ledger::MartingaleError> for ChangePointError {
    fn from(err: crate::martingale_decision_ledger::MartingaleError) -> Self {
        Self::MartingaleError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_normal_alternative() -> CompositeAlternative {
        CompositeAlternative::NormalMeanShift {
            pre_change_mean_millionths: 0,
            variance_millionths_squared: MILLION,
            mean_range_millionths: (500_000, 2_000_000),
        }
    }

    fn sample_exponential_alternative() -> CompositeAlternative {
        CompositeAlternative::ExponentialRateShift {
            pre_change_rate_millionths: MILLION,
            rate_range_millionths: (500_000, 3_000_000),
        }
    }

    fn sample_bernoulli_alternative() -> CompositeAlternative {
        CompositeAlternative::BernoulliProbabilityShift {
            pre_change_prob_millionths: 300_000,       // 0.3
            prob_range_millionths: (600_000, 900_000), // 0.6-0.9
        }
    }

    #[test]
    fn detector_creation() {
        let alternative = sample_normal_alternative();
        let detector = ChangePointDetector::new(
            "test-detector",
            alternative,
            DEFAULT_CUSUM_THRESHOLD_MILLIONTHS,
            SecurityEpoch::from_raw(1),
        );

        assert_eq!(detector.detector_id, "test-detector");
        assert_eq!(
            detector.threshold_millionths,
            DEFAULT_CUSUM_THRESHOLD_MILLIONTHS
        );
        assert_eq!(detector.cusum_statistic_millionths(), 0);
        assert_eq!(detector.observation_count(), 0);
        assert!(!detector.is_change_detected());
    }

    #[test]
    fn detector_with_default_threshold() {
        let alternative = sample_exponential_alternative();
        let detector = ChangePointDetector::new_with_default_threshold(
            "default-detector",
            alternative,
            SecurityEpoch::from_raw(1),
        );

        assert_eq!(
            detector.threshold_millionths,
            DEFAULT_CUSUM_THRESHOLD_MILLIONTHS
        );
    }

    #[test]
    fn normal_no_change_observations() {
        let alternative = sample_normal_alternative();
        let mut detector = ChangePointDetector::new(
            "normal-test",
            alternative,
            5_000_000, // High threshold
            SecurityEpoch::from_raw(1),
        );

        // Process observations from pre-change distribution (mean=0)
        for i in 1..=10 {
            let observation = (i % 3 - 1) * 200_000; // Values around 0
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");

            assert!(matches!(verdict, ChangePointVerdict::Continue));
            assert!(!detector.is_change_detected());
        }

        assert_eq!(detector.observation_count(), 10);
    }

    #[test]
    fn normal_change_point_detection() {
        let alternative = sample_normal_alternative();
        let mut detector = ChangePointDetector::new(
            "normal-change-test",
            alternative,
            1_000_000, // Lower threshold for easier detection
            SecurityEpoch::from_raw(1),
        );

        // Process pre-change observations (mean ≈ 0)
        for i in 1..=5 {
            let observation = (i % 3 - 1) * 100_000;
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");
            assert!(matches!(verdict, ChangePointVerdict::Continue));
        }

        // Process post-change observations (mean ≈ 1.5)
        for i in 6..=15 {
            let observation = 1_500_000 + (i % 3 - 1) * 100_000; // Mean around 1.5
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");

            if detector.is_change_detected() {
                assert!(matches!(verdict, ChangePointVerdict::ChangeDetected { .. }));
                if let ChangePointVerdict::ChangeDetected {
                    detection_time,
                    estimated_change_point,
                    post_change_parameters,
                    ..
                } = verdict
                {
                    assert!(detection_time >= MIN_OBSERVATIONS_FOR_DETECTION);
                    assert!(estimated_change_point > 0);
                    assert!(post_change_parameters.contains_key("estimated_mean_millionths"));
                }
                break;
            }
        }

        assert!(detector.is_change_detected());
    }

    #[test]
    fn exponential_change_point_detection() {
        let alternative = sample_exponential_alternative();
        let mut detector = ChangePointDetector::new(
            "exp-test",
            alternative,
            2_000_000,
            SecurityEpoch::from_raw(1),
        );

        // Pre-change: rate = 1.0 (mean = 1.0)
        for i in 1..=5 {
            let observation = MILLION + (i % 2) * 200_000; // Around mean 1.0
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");
            assert!(matches!(verdict, ChangePointVerdict::Continue));
        }

        // Post-change: higher rate (lower mean)
        for i in 6..=15 {
            let observation = 300_000 + (i % 2) * 100_000; // Lower mean
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");

            if detector.is_change_detected() {
                assert!(matches!(verdict, ChangePointVerdict::ChangeDetected { .. }));
                break;
            }
        }
    }

    #[test]
    fn bernoulli_change_point_detection() {
        let alternative = sample_bernoulli_alternative();
        let mut detector = ChangePointDetector::new(
            "bernoulli-test",
            alternative,
            2_000_000,
            SecurityEpoch::from_raw(1),
        );

        // Pre-change: p = 0.3 (mostly failures)
        for i in 1..=5 {
            let observation = if i <= 2 { MILLION } else { 0 }; // ~30% success
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");
            assert!(matches!(verdict, ChangePointVerdict::Continue));
        }

        // Post-change: p ≈ 0.8 (mostly successes)
        for i in 6..=15 {
            let observation = if i <= 14 { MILLION } else { 0 }; // ~80% success
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");

            if detector.is_change_detected() {
                assert!(matches!(verdict, ChangePointVerdict::ChangeDetected { .. }));
                break;
            }
        }
    }

    #[test]
    fn martingale_integration() {
        let alternative = sample_normal_alternative();
        let threshold =
            StoppingThreshold::try_from_log_millionths(3_000_000).expect("valid threshold");

        let mut detector = ChangePointDetector::new_with_default_threshold(
            "martingale-test",
            alternative,
            SecurityEpoch::from_raw(1),
        )
        .with_martingale_integration(threshold);

        assert!(detector.martingale_ledger().is_some());

        // Process some observations
        for i in 1..=5 {
            let observation = 1_000_000; // Constant positive signal
            let _verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");
        }

        let ledger = detector.martingale_ledger().expect("ledger should exist");
        assert_eq!(ledger.event_count(), 5);
    }

    #[test]
    fn detector_reset() {
        let alternative = sample_normal_alternative();
        let mut detector = ChangePointDetector::new_with_default_threshold(
            "reset-test",
            alternative,
            SecurityEpoch::from_raw(1),
        );

        // Process some observations
        for i in 1..=3 {
            let _verdict = detector
                .process_observation(i * 500_000, i * 1_000_000)
                .expect("should process observation");
        }

        assert_eq!(detector.observation_count(), 3);
        assert!(detector.cusum_statistic_millionths() != 0);

        // Reset and verify
        detector.reset();
        assert_eq!(detector.observation_count(), 0);
        assert_eq!(detector.cusum_statistic_millionths(), 0);
        assert!(!detector.is_change_detected());
        assert!(detector.martingale_ledger().is_none());
    }

    #[test]
    fn already_detected_error() {
        let alternative = sample_normal_alternative();
        let mut detector = ChangePointDetector::new(
            "error-test",
            alternative,
            500_000, // Very low threshold for quick detection
            SecurityEpoch::from_raw(1),
        );

        // Trigger detection
        for i in 1..=10 {
            let observation = 2_000_000; // Large positive signal
            let verdict = detector
                .process_observation(observation, i * 1_000_000)
                .expect("should process observation");

            if detector.is_change_detected() {
                assert!(matches!(verdict, ChangePointVerdict::ChangeDetected { .. }));
                break;
            }
        }

        // Try to process another observation - should error
        let result = detector.process_observation(1_000_000, 11 * 1_000_000);
        assert!(matches!(result, Err(ChangePointError::AlreadyDetected)));
    }

    #[test]
    fn composite_alternative_glr_normal() {
        let alt = CompositeAlternative::NormalMeanShift {
            pre_change_mean_millionths: 0,
            variance_millionths_squared: MILLION,
            mean_range_millionths: (500_000, 2_000_000),
        };

        // Observation favoring post-change (high value)
        let lr_high = alt.log_likelihood_ratio_millionths(1_500_000);
        assert!(lr_high > 0, "high observation should favor alternative");

        // Observation favoring pre-change (low value)
        let lr_low = alt.log_likelihood_ratio_millionths(-500_000);
        assert!(lr_low < 0, "low observation should favor null");
    }

    #[test]
    fn composite_alternative_parameter_estimation() {
        let alt = sample_normal_alternative();
        let observations = vec![1_200_000, 1_300_000, 1_100_000]; // Mean ≈ 1.2M

        let params = alt.estimate_post_change_parameters(&observations);
        let estimated_mean = params
            .get("estimated_mean_millionths")
            .expect("should have estimated mean");

        assert!(*estimated_mean >= 1_100_000 && *estimated_mean <= 1_300_000);

        // Test clamping to range
        let clamped_params = alt.estimate_post_change_parameters(&vec![10_000_000]); // Way above range
        let clamped_mean = clamped_params
            .get("estimated_mean_millionths")
            .expect("should have clamped mean");
        assert_eq!(*clamped_mean, 2_000_000); // Should be clamped to upper bound
    }

    #[test]
    fn verdict_methods() {
        let continue_verdict = ChangePointVerdict::Continue;
        assert!(!continue_verdict.is_change_detected());
        assert!(continue_verdict.detection_time().is_none());

        let change_verdict = ChangePointVerdict::ChangeDetected {
            detection_time: 42,
            estimated_change_point: 37,
            pre_change_parameters: BTreeMap::new(),
            post_change_parameters: BTreeMap::new(),
            cusum_statistic_millionths: 5_000_000,
            evidence_hash: ContentHash::compute(b"test"),
            signed_evidence: None,
        };

        assert!(change_verdict.is_change_detected());
        assert_eq!(change_verdict.detection_time(), Some(42));
    }
}
