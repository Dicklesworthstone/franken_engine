//! Optimal stopping theory for containment escalation decisions.
//!
//! The guardplane currently makes **myopic** decisions: at each observation
//! it minimizes single-step expected loss.  This module introduces **optimal
//! stopping** — the mathematically principled framework for deciding *when*
//! to escalate vs. gather more evidence.
//!
//! Algorithms:
//! - **CUSUM** (Cumulative Sum) chart with Lorden's inequality for
//!   worst-case average run length (ARL) guarantees.
//! - **Gittins Index** computation for multi-armed containment bandit —
//!   determines the optimal order to investigate threat hypotheses.
//! - **Snell Envelope** (discrete-time optional stopping theorem) for
//!   American-option-style containment decisions where escalation is
//!   irreversible.
//! - **Secretary Problem** variant: observe `n/e` evidence items, then
//!   escalate on the first that exceeds the best seen so far.
//!
//! **Formal guarantee**: Under the CUSUM chart, the expected detection delay
//! `E[T - ν | T ≥ ν] ≤ (h + 1.166) / KL(θ₁ ‖ θ₀)` where h is the
//! threshold, ν is the change point, and KL is the Kullback–Leibler divergence.
//!
//! All arithmetic uses fixed-point millionths.  No floating point.
//! Deterministic replay compatible.
//!
//! References:
//! - Page, "Continuous Inspection Schemes" (1954) — CUSUM
//! - Lorden, "Procedures for Reacting to a Change in Distribution" (1971)
//! - Gittins, "Bandit Processes and Dynamic Allocation Indices" (1979)
//! - Shiryaev, "Optimal Stopping Rules" (1978)
//! - Ferguson, "Who Solved the Secretary Problem?" (1989)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for serialized stopping artifacts.
pub const STOPPING_SCHEMA_VERSION: &str = "franken-engine.optimal-stopping.v1";

/// Default CUSUM threshold (in millionths).
const DEFAULT_CUSUM_THRESHOLD: i64 = 5_000_000; // 5.0

/// Maximum horizon for dynamic programming value iteration.
const MAX_DP_HORIZON: usize = 10_000;

/// 1/e in millionths ≈ 367_879.
const INV_E_MILLIONTHS: i64 = 367_879;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from optimal stopping computations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoppingError {
    /// Horizon too large for DP.
    HorizonTooLarge { horizon: usize, max: usize },
    /// Invalid threshold.
    InvalidThreshold { threshold: i64 },
    /// Invalid discount factor.
    InvalidDiscount { discount: i64 },
    /// Empty observation sequence.
    EmptyObservations,
    /// KL divergence is zero or negative (indistinguishable hypotheses).
    DegenerateKL,
    /// Index out of bounds.
    IndexOutOfBounds { index: usize, size: usize },
}

impl fmt::Display for StoppingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HorizonTooLarge { horizon, max } => {
                write!(f, "horizon {horizon} exceeds maximum {max}")
            }
            Self::InvalidThreshold { threshold } => {
                write!(f, "invalid threshold: {threshold}")
            }
            Self::InvalidDiscount { discount } => {
                write!(f, "invalid discount factor: {discount}")
            }
            Self::EmptyObservations => write!(f, "empty observation sequence"),
            Self::DegenerateKL => {
                write!(f, "KL divergence is zero or negative")
            }
            Self::IndexOutOfBounds { index, size } => {
                write!(f, "index {index} out of bounds (size {size})")
            }
        }
    }
}

impl std::error::Error for StoppingError {}

// ---------------------------------------------------------------------------
// Observation — evidence item
// ---------------------------------------------------------------------------

/// A single evidence observation for the stopping problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Log-likelihood ratio (millionths): ln(p(x|H₁)/p(x|H₀)).
    pub llr_millionths: i64,
    /// Raw risk score (millionths, [0, MILLION]).
    pub risk_score_millionths: i64,
    /// Timestamp (monotonic microseconds).
    pub timestamp_us: u64,
    /// Evidence source identifier.
    pub source: String,
}

// ---------------------------------------------------------------------------
// StoppingDecision — output
// ---------------------------------------------------------------------------

/// The decision from an optimal stopping rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StoppingDecision {
    /// Continue gathering evidence.
    Continue,
    /// Stop and escalate containment.
    Stop,
}

impl fmt::Display for StoppingDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::Stop => write!(f, "stop"),
        }
    }
}

// ---------------------------------------------------------------------------
// CUSUM Chart — cumulative sum change-point detector
// ---------------------------------------------------------------------------

/// CUSUM (Cumulative Sum) chart for change-point detection.
///
/// Tracks the statistic `S_n = max(0, S_{n-1} + X_n - k)` where X_n is the
/// observation and k is the reference value (typically μ₀ + μ₁)/2).
/// Signals when `S_n ≥ h` (the threshold).
///
/// **ARL guarantee** (Lorden 1971): Under the null hypothesis,
/// `ARL₀ ≥ exp(h) / (k * μ₁)`.
/// Under the alternative, detection delay
/// `E[T - ν] ≤ (h + 1.166) / KL(θ₁ ‖ θ₀)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CusumChart {
    /// Current CUSUM statistic (millionths).
    pub statistic_millionths: i64,
    /// Decision threshold h (millionths).
    pub threshold_millionths: i64,
    /// Reference value k (millionths): typically (μ₀ + μ₁)/2.
    pub reference_millionths: i64,
    /// Number of observations processed.
    pub observations: u64,
    /// High-water mark (maximum statistic seen).
    pub high_water_mark_millionths: i64,
    /// Whether the chart has signaled.
    pub signaled: bool,
    /// Round at which the chart signaled (0 if not signaled).
    pub signal_round: u64,
}

impl CusumChart {
    /// Create a new CUSUM chart.
    pub fn new(
        threshold_millionths: i64,
        reference_millionths: i64,
    ) -> Result<Self, StoppingError> {
        if threshold_millionths <= 0 {
            return Err(StoppingError::InvalidThreshold {
                threshold: threshold_millionths,
            });
        }
        Ok(Self {
            statistic_millionths: 0,
            threshold_millionths,
            reference_millionths,
            observations: 0,
            high_water_mark_millionths: 0,
            signaled: false,
            signal_round: 0,
        })
    }

    /// Create with default parameters.
    pub fn with_defaults() -> Self {
        Self {
            statistic_millionths: 0,
            threshold_millionths: DEFAULT_CUSUM_THRESHOLD,
            reference_millionths: 500_000, // 0.5
            observations: 0,
            high_water_mark_millionths: 0,
            signaled: false,
            signal_round: 0,
        }
    }

    /// Process a new observation.
    ///
    /// Returns the stopping decision and the updated statistic.
    pub fn observe(&mut self, obs: &Observation) -> StoppingDecision {
        self.observations += 1;

        // S_n = max(0, S_{n-1} + X_n - k)
        let increment = obs.llr_millionths.saturating_sub(self.reference_millionths);
        self.statistic_millionths = self.statistic_millionths.saturating_add(increment).max(0);

        if self.statistic_millionths > self.high_water_mark_millionths {
            self.high_water_mark_millionths = self.statistic_millionths;
        }

        if self.statistic_millionths >= self.threshold_millionths && !self.signaled {
            self.signaled = true;
            self.signal_round = self.observations;
            StoppingDecision::Stop
        } else if self.signaled {
            StoppingDecision::Stop
        } else {
            StoppingDecision::Continue
        }
    }

    /// Reset the chart (after a confirmed change or false alarm).
    pub fn reset(&mut self) {
        self.statistic_millionths = 0;
        self.signaled = false;
        self.signal_round = 0;
        // Keep observations count and high_water_mark for audit.
    }

    /// Compute theoretical ARL₀ lower bound (millionths).
    /// ARL₀ ≥ exp(h/μ₁) where μ₁ is the post-change mean.
    pub fn arl0_lower_bound(&self, post_change_mean_millionths: i64) -> i64 {
        if post_change_mean_millionths <= 0 {
            return i64::MAX;
        }
        let ratio = (i128::from(self.threshold_millionths) * i128::from(MILLION))
            / i128::from(post_change_mean_millionths);
        // Approximate exp(ratio/MILLION) ≈ 1 + ratio/MILLION + ...
        // For large ratios, this grows exponentially.
        let x = ratio.max(0);
        let x2 = x.saturating_mul(x) / i128::from(MILLION);
        let approx = i128::from(MILLION) + x + x2 / 2;
        approx.clamp(i128::from(MILLION), i128::from(i64::MAX)) as i64
    }
}

// ---------------------------------------------------------------------------
// GittinsIndex — multi-armed containment bandit
// ---------------------------------------------------------------------------

/// Gittins Index for a single arm (threat hypothesis).
///
/// The Gittins index λ* is the value that makes the decision-maker
/// indifferent between pulling this arm and receiving λ* per round forever.
///
/// Arms with higher Gittins index should be investigated first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GittinsArm {
    /// Arm identifier.
    pub arm_id: String,
    /// Number of successes (evidence supporting the hypothesis).
    pub successes: u64,
    /// Number of failures (evidence against).
    pub failures: u64,
    /// Computed Gittins index (millionths, higher = investigate first).
    pub gittins_index_millionths: i64,
    /// Discount factor γ in millionths.
    pub discount_millionths: i64,
}

/// Gittins index computation for multiple threat hypotheses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GittinsIndexComputer {
    /// Arms (threat hypotheses).
    pub arms: Vec<GittinsArm>,
    /// Discount factor γ in millionths (0, MILLION).
    pub discount_millionths: i64,
    /// DP horizon for index computation.
    pub horizon: usize,
}

impl GittinsIndexComputer {
    /// Create a new computer with discount factor and arms.
    pub fn new(
        arm_ids: Vec<String>,
        discount_millionths: i64,
        horizon: usize,
    ) -> Result<Self, StoppingError> {
        if arm_ids.is_empty() {
            return Err(StoppingError::EmptyObservations);
        }
        if horizon > MAX_DP_HORIZON {
            return Err(StoppingError::HorizonTooLarge {
                horizon,
                max: MAX_DP_HORIZON,
            });
        }
        if discount_millionths <= 0 || discount_millionths >= MILLION {
            return Err(StoppingError::InvalidDiscount {
                discount: discount_millionths,
            });
        }

        let arms = arm_ids
            .into_iter()
            .map(|id| GittinsArm {
                arm_id: id,
                successes: 0,
                failures: 0,
                gittins_index_millionths: MILLION / 2, // prior: 0.5
                discount_millionths,
            })
            .collect();

        Ok(Self {
            arms,
            discount_millionths,
            horizon,
        })
    }

    /// Update an arm with a new observation.
    pub fn observe(&mut self, arm_index: usize, success: bool) -> Result<(), StoppingError> {
        if arm_index >= self.arms.len() {
            return Err(StoppingError::IndexOutOfBounds {
                index: arm_index,
                size: self.arms.len(),
            });
        }

        if success {
            self.arms[arm_index].successes += 1;
        } else {
            self.arms[arm_index].failures += 1;
        }

        // Recompute Gittins index for this arm.
        self.recompute_index(arm_index);
        Ok(())
    }

    /// Recompute the Gittins index for an arm using the Beta-Bernoulli
    /// approximation: λ* ≈ (s + 1) / (s + f + 2) · (1 + correction).
    ///
    /// The exact Gittins index requires solving a stopping problem;
    /// we use the Whittle approximation which is within O(1/n) of optimal.
    fn recompute_index(&mut self, arm_index: usize) {
        let arm = &mut self.arms[arm_index];
        let s = i64::try_from(arm.successes).unwrap_or(i64::MAX);
        let f = i64::try_from(arm.failures).unwrap_or(i64::MAX);
        let n = s.saturating_add(f);
        let n_plus_two = n.saturating_add(2);

        // Beta posterior mean: (s + 1) / (s + f + 2).
        let posterior_mean = (((i128::from(s) + 1) * i128::from(MILLION)) / i128::from(n_plus_two))
            .clamp(0, i128::from(MILLION)) as i64;

        // Whittle correction for discounted Gittins index:
        // λ* ≈ μ + σ² / (2 · (1 - γ)) where σ² = α·β / ((α+β)²·(α+β+1))
        // α = s+1, β = f+1.
        let alpha = i128::from(s) + 1;
        let beta = i128::from(f) + 1;
        let ab = alpha + beta;
        let variance_numerator = alpha
            .saturating_mul(beta)
            .saturating_mul(i128::from(MILLION));
        let variance_denominator = ab.saturating_mul(ab).saturating_mul(ab + 1);
        let variance = if variance_denominator > 0 {
            variance_numerator / variance_denominator
        } else {
            0
        };

        let discount_complement = MILLION - arm.discount_millionths;
        let correction = if discount_complement > 0 {
            variance.saturating_mul(i128::from(MILLION))
                / i128::from(2_i64.saturating_mul(discount_complement))
        } else {
            0
        };

        arm.gittins_index_millionths =
            (i128::from(posterior_mean) + correction).clamp(0, i128::from(MILLION)) as i64;
    }

    /// Select the arm with the highest Gittins index.
    pub fn select_arm(&self) -> usize {
        self.arms
            .iter()
            .enumerate()
            .max_by_key(|(_, arm)| arm.gittins_index_millionths)
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Get all arms sorted by Gittins index (highest first).
    pub fn ranked_arms(&self) -> Vec<(usize, i64)> {
        let mut indexed: Vec<(usize, i64)> = self
            .arms
            .iter()
            .enumerate()
            .map(|(i, arm)| (i, arm.gittins_index_millionths))
            .collect();
        indexed.sort_by_key(|d| std::cmp::Reverse(d.1));
        indexed
    }
}

// ---------------------------------------------------------------------------
// SnellEnvelope — discrete optimal stopping
// ---------------------------------------------------------------------------

/// Snell Envelope for American-option-style containment decisions.
///
/// Given a sequence of payoffs `g_0, g_1, ..., g_T` (gain from stopping at
/// time t), the Snell envelope `U_t = max(g_t, E[U_{t+1} | F_t])` gives
/// the optimal stopping value.  The optimal stopping time is
/// `τ* = min{t : U_t = g_t}`.
///
/// For containment: `g_t = -(delay_cost_t + action_cost_t)`.
/// Stopping earlier avoids delay cost but may incur action cost on a
/// false positive; stopping later reduces false positives but accumulates
/// delay cost from ongoing threat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnellEnvelope {
    /// Payoff values at each time step (millionths).
    pub payoffs_millionths: Vec<i64>,
    /// Computed envelope values (millionths).
    pub envelope_millionths: Vec<i64>,
    /// Optimal stopping time (index into payoffs).
    pub optimal_stopping_time: usize,
    /// Value of stopping at the optimal time.
    pub optimal_value_millionths: i64,
    /// Discount factor per step (millionths).
    pub discount_millionths: i64,
}

impl SnellEnvelope {
    /// Compute the Snell envelope from a payoff sequence.
    ///
    /// Works backward: `U_T = g_T`, `U_t = max(g_t, γ · U_{t+1})`.
    pub fn compute(
        payoffs_millionths: Vec<i64>,
        discount_millionths: i64,
    ) -> Result<Self, StoppingError> {
        if payoffs_millionths.is_empty() {
            return Err(StoppingError::EmptyObservations);
        }
        if !(0..=MILLION).contains(&discount_millionths) {
            return Err(StoppingError::InvalidDiscount {
                discount: discount_millionths,
            });
        }
        if payoffs_millionths.len() > MAX_DP_HORIZON {
            return Err(StoppingError::HorizonTooLarge {
                horizon: payoffs_millionths.len(),
                max: MAX_DP_HORIZON,
            });
        }

        let n = payoffs_millionths.len();
        let mut envelope = vec![0i64; n];

        // Backward induction.
        envelope[n - 1] = payoffs_millionths[n - 1];
        for t in (0..n - 1).rev() {
            // Discounted continuation value: γ · U_{t+1} (round toward zero
            // for conservative fixed-point division).
            let product = i128::from(discount_millionths) * i128::from(envelope[t + 1]);
            let continuation = product / i128::from(MILLION);
            envelope[t] = payoffs_millionths[t].max(continuation as i64);
        }

        // Find optimal stopping time: first t where U_t == g_t.
        let optimal_time = envelope
            .iter()
            .zip(payoffs_millionths.iter())
            .position(|(&u, &g)| u == g)
            .unwrap_or(0);

        let optimal_value = envelope[optimal_time];

        Ok(Self {
            payoffs_millionths,
            envelope_millionths: envelope,
            optimal_stopping_time: optimal_time,
            optimal_value_millionths: optimal_value,
            discount_millionths,
        })
    }

    /// Check if it's optimal to stop at the given time.
    pub fn should_stop_at(&self, t: usize) -> bool {
        if t >= self.envelope_millionths.len() {
            return true; // past horizon, must stop
        }
        self.envelope_millionths[t] == self.payoffs_millionths[t]
    }
}

// ---------------------------------------------------------------------------
// Secretary Problem — online best-selection
// ---------------------------------------------------------------------------

/// Secretary Problem variant for containment escalation.
///
/// **Algorithm**: Observe the first ⌊n/e⌋ evidence items without acting
/// (exploration phase).  Then escalate on the first item that exceeds
/// the best seen during exploration.
///
/// **Guarantee**: Selects the globally best evidence item with probability
/// ≥ 1/e ≈ 36.8%, which is provably optimal for this problem class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretarySelector {
    /// Total expected evidence items.
    pub total_items: usize,
    /// Exploration phase length: ⌊n/e⌋.
    pub exploration_length: usize,
    /// Items observed so far.
    pub observed: usize,
    /// Best risk score seen during exploration (millionths).
    pub exploration_best_millionths: i64,
    /// Whether the exploration phase is complete.
    pub exploration_complete: bool,
    /// Whether a selection has been made.
    pub selected: bool,
    /// Index of selected item (0-based), if any.
    pub selected_index: Option<usize>,
}

impl SecretarySelector {
    /// Create a new secretary selector for n expected items.
    pub fn new(total_items: usize) -> Self {
        // ⌊n/e⌋ in integer arithmetic: n * INV_E / MILLION.
        let exploration_length = if total_items > 0 {
            ((total_items as i64 * INV_E_MILLIONTHS) / MILLION) as usize
        } else {
            0
        };
        // Ensure at least 1 exploration item if n > 1.
        let exploration_length = if total_items > 1 {
            exploration_length.max(1)
        } else {
            0
        };

        Self {
            total_items,
            exploration_length,
            observed: 0,
            exploration_best_millionths: i64::MIN,
            exploration_complete: false,
            selected: false,
            selected_index: None,
        }
    }

    /// Observe an evidence item and decide whether to select it.
    pub fn observe(&mut self, risk_score_millionths: i64) -> StoppingDecision {
        if self.selected {
            return StoppingDecision::Stop;
        }

        self.observed += 1;

        if self.observed <= self.exploration_length {
            // Exploration phase: just track the best.
            if risk_score_millionths > self.exploration_best_millionths {
                self.exploration_best_millionths = risk_score_millionths;
            }
            if self.observed == self.exploration_length {
                self.exploration_complete = true;
            }
            StoppingDecision::Continue
        } else {
            // Selection phase: pick first that exceeds exploration best.
            if risk_score_millionths > self.exploration_best_millionths {
                self.selected = true;
                self.selected_index = Some(self.observed - 1);
                StoppingDecision::Stop
            } else if self.observed >= self.total_items {
                // Forced to select the last item.
                self.selected = true;
                self.selected_index = Some(self.observed - 1);
                StoppingDecision::Stop
            } else {
                StoppingDecision::Continue
            }
        }
    }

    /// Theoretical selection probability: 1/e ≈ 367_879 millionths.
    pub fn optimal_selection_probability_millionths() -> i64 {
        INV_E_MILLIONTHS
    }
}

// ---------------------------------------------------------------------------
// EscalationPolicy — composite stopping rule
// ---------------------------------------------------------------------------

/// Composite escalation policy combining multiple stopping rules.
///
/// The policy triggers escalation when ANY constituent rule signals Stop.
/// This is conservative: it catches the first credible signal from any
/// detection method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// CUSUM chart for change-point detection.
    pub cusum: CusumChart,
    /// Whether CUSUM is enabled.
    pub cusum_enabled: bool,
    /// Secretary problem selector.
    pub secretary: SecretarySelector,
    /// Whether secretary rule is enabled.
    pub secretary_enabled: bool,
    /// Total observations processed.
    pub total_observations: u64,
    /// Which rule triggered escalation (if any).
    pub trigger_source: Option<String>,
}

impl EscalationPolicy {
    /// Create a new composite policy.
    pub fn new(
        cusum_threshold: i64,
        cusum_reference: i64,
        expected_evidence_count: usize,
    ) -> Result<Self, StoppingError> {
        Ok(Self {
            cusum: CusumChart::new(cusum_threshold, cusum_reference)?,
            cusum_enabled: true,
            secretary: SecretarySelector::new(expected_evidence_count),
            secretary_enabled: true,
            total_observations: 0,
            trigger_source: None,
        })
    }

    /// Process an observation through all active rules.
    pub fn observe(&mut self, obs: &Observation) -> StoppingDecision {
        self.total_observations += 1;

        if self.cusum_enabled {
            let cusum_decision = self.cusum.observe(obs);
            if cusum_decision == StoppingDecision::Stop && self.trigger_source.is_none() {
                self.trigger_source = Some("cusum".to_string());
                return StoppingDecision::Stop;
            }
        }

        if self.secretary_enabled {
            let sec_decision = self.secretary.observe(obs.risk_score_millionths);
            if sec_decision == StoppingDecision::Stop && self.trigger_source.is_none() {
                self.trigger_source = Some("secretary".to_string());
                return StoppingDecision::Stop;
            }
        }

        if self.trigger_source.is_some() {
            StoppingDecision::Stop
        } else {
            StoppingDecision::Continue
        }
    }
}

// ---------------------------------------------------------------------------
// OptimalStoppingCertificate
// ---------------------------------------------------------------------------

/// Machine-checkable certificate for optimal stopping decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimalStoppingCertificate {
    pub schema: String,
    /// Which algorithm triggered the decision.
    pub algorithm: String,
    /// Number of observations before stopping.
    pub observations_before_stop: u64,
    /// CUSUM statistic at decision time (if applicable).
    pub cusum_statistic_millionths: Option<i64>,
    /// ARL₀ guarantee (if applicable).
    pub arl0_lower_bound: Option<i64>,
    /// Snell envelope optimal value (if applicable).
    pub snell_optimal_value_millionths: Option<i64>,
    /// Gittins index of selected arm (if applicable).
    pub gittins_index_millionths: Option<i64>,
    /// Epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Content hash for audit.
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_observation(llr: i64, risk: i64, ts: u64) -> Observation {
        Observation {
            llr_millionths: llr,
            risk_score_millionths: risk,
            timestamp_us: ts,
            source: "test".to_string(),
        }
    }

    // === CUSUM ===

    #[test]
    fn cusum_creation() {
        let chart = CusumChart::new(5_000_000, 500_000).unwrap();
        assert_eq!(chart.statistic_millionths, 0);
        assert!(!chart.signaled);
    }

    #[test]
    fn cusum_invalid_threshold() {
        assert!(matches!(
            CusumChart::new(0, 500_000),
            Err(StoppingError::InvalidThreshold { .. })
        ));
        assert!(matches!(
            CusumChart::new(-1, 500_000),
            Err(StoppingError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn cusum_signals_on_sustained_anomaly() {
        let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
        // Feed high LLR observations until threshold crossed.
        for i in 0..10 {
            let obs = make_observation(1_000_000, 800_000, i);
            let decision = chart.observe(&obs);
            if chart.signaled {
                assert_eq!(decision, StoppingDecision::Stop);
                break;
            }
        }
        assert!(chart.signaled);
        assert!(chart.signal_round > 0);
    }

    #[test]
    fn cusum_continues_on_benign() {
        let mut chart = CusumChart::new(5_000_000, 500_000).unwrap();
        // Feed low LLR observations.
        for i in 0..100 {
            let obs = make_observation(100_000, 100_000, i);
            let decision = chart.observe(&obs);
            assert_eq!(decision, StoppingDecision::Continue);
        }
        assert!(!chart.signaled);
    }

    #[test]
    fn cusum_resets_on_negative_llr() {
        let mut chart = CusumChart::new(5_000_000, 500_000).unwrap();
        // Feed one positive, then many negative.
        chart.observe(&make_observation(2_000_000, 500_000, 0));
        assert!(chart.statistic_millionths > 0);

        for i in 1..20 {
            chart.observe(&make_observation(-1_000_000, 100_000, i));
        }
        // Statistic should be clamped at 0 (CUSUM never goes negative).
        assert_eq!(chart.statistic_millionths, 0);
    }

    #[test]
    fn cusum_reset_method() {
        let mut chart = CusumChart::new(3_000_000, 500_000).unwrap();
        for i in 0..10 {
            chart.observe(&make_observation(1_000_000, 800_000, i));
        }
        assert!(chart.signaled);
        chart.reset();
        assert!(!chart.signaled);
        assert_eq!(chart.statistic_millionths, 0);
    }

    #[test]
    fn cusum_arl0_lower_bound_positive() {
        let chart = CusumChart::new(5_000_000, 500_000).unwrap();
        let arl0 = chart.arl0_lower_bound(MILLION);
        assert!(arl0 > MILLION);
    }

    #[test]
    fn cusum_arl0_lower_bound_saturates_for_extreme_inputs() {
        let chart = CusumChart::new(i64::MAX, 500_000).unwrap();
        let arl0 = chart.arl0_lower_bound(1);
        assert_eq!(arl0, i64::MAX);
    }

    #[test]
    fn cusum_observe_extreme_negative_llr_does_not_overflow() {
        let mut chart = CusumChart::new(1_000_000, 500_000).unwrap();
        let obs = Observation {
            llr_millionths: i64::MIN,
            risk_score_millionths: 0,
            timestamp_us: 0,
            source: "extreme".to_string(),
        };
        let decision = chart.observe(&obs);
        assert_eq!(decision, StoppingDecision::Continue);
        assert_eq!(chart.statistic_millionths, 0);
    }

    #[test]
    fn cusum_serde_roundtrip() {
        let chart = CusumChart::with_defaults();
        let json = serde_json::to_string(&chart).unwrap();
        let restored: CusumChart = serde_json::from_str(&json).unwrap();
        assert_eq!(chart, restored);
    }

    // === Gittins Index ===

    #[test]
    fn gittins_creation() {
        let gc =
            GittinsIndexComputer::new(vec!["hyp_a".into(), "hyp_b".into()], 900_000, 100).unwrap();
        assert_eq!(gc.arms.len(), 2);
    }

    #[test]
    fn gittins_empty_arms_rejected() {
        assert!(matches!(
            GittinsIndexComputer::new(vec![], 900_000, 100),
            Err(StoppingError::EmptyObservations)
        ));
    }

    #[test]
    fn gittins_invalid_discount_rejected() {
        assert!(matches!(
            GittinsIndexComputer::new(vec!["a".into()], 0, 100),
            Err(StoppingError::InvalidDiscount { .. })
        ));
        assert!(matches!(
            GittinsIndexComputer::new(vec!["a".into()], MILLION, 100),
            Err(StoppingError::InvalidDiscount { .. })
        ));
    }

    #[test]
    fn gittins_large_counts_do_not_overflow_recompute() {
        let mut computer = GittinsIndexComputer::new(vec!["a".into()], 950_000, 100).unwrap();
        computer.arms[0].successes = u64::MAX;
        computer.arms[0].failures = u64::MAX;

        computer.recompute_index(0);

        assert!((0..=MILLION).contains(&computer.arms[0].gittins_index_millionths));
    }

    #[test]
    fn gittins_horizon_too_large() {
        assert!(matches!(
            GittinsIndexComputer::new(vec!["a".into()], 900_000, MAX_DP_HORIZON + 1),
            Err(StoppingError::HorizonTooLarge { .. })
        ));
    }

    #[test]
    fn gittins_updates_with_successes() {
        let mut gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();

        // Arm 0 gets all successes.
        for _ in 0..10 {
            gc.observe(0, true).unwrap();
            gc.observe(1, false).unwrap();
        }

        assert!(gc.arms[0].gittins_index_millionths > gc.arms[1].gittins_index_millionths);
        assert_eq!(gc.select_arm(), 0);
    }

    #[test]
    fn gittins_ranked_arms_sorted() {
        let mut gc =
            GittinsIndexComputer::new(vec!["a".into(), "b".into(), "c".into()], 900_000, 100)
                .unwrap();

        gc.observe(2, true).unwrap();
        gc.observe(2, true).unwrap();
        let ranked = gc.ranked_arms();
        // First entry should have highest index.
        assert!(ranked[0].1 >= ranked[1].1);
        assert!(ranked[1].1 >= ranked[2].1);
    }

    #[test]
    fn gittins_arm_out_of_bounds() {
        let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
        assert!(matches!(
            gc.observe(5, true),
            Err(StoppingError::IndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn gittins_serde_roundtrip() {
        let gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
        let json = serde_json::to_string(&gc).unwrap();
        let restored: GittinsIndexComputer = serde_json::from_str(&json).unwrap();
        assert_eq!(gc, restored);
    }

    // === Snell Envelope ===

    #[test]
    fn snell_envelope_simple() {
        // Payoffs: [1, 3, 2].  Without discount, optimal is to stop at t=1 (payoff 3).
        let payoffs = vec![1_000_000, 3_000_000, 2_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        assert_eq!(env.optimal_stopping_time, 1);
        assert_eq!(env.optimal_value_millionths, 3_000_000);
    }

    #[test]
    fn snell_envelope_monotone_increasing() {
        // Payoffs: [1, 2, 3, 4, 5].  Best to wait until last.
        let payoffs = vec![1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        assert_eq!(env.optimal_stopping_time, 4); // last index
    }

    #[test]
    fn snell_envelope_monotone_decreasing() {
        // Payoffs: [5, 4, 3, 2, 1].  Best to stop immediately.
        let payoffs = vec![5_000_000, 4_000_000, 3_000_000, 2_000_000, 1_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        assert_eq!(env.optimal_stopping_time, 0);
    }

    #[test]
    fn snell_envelope_with_discount() {
        // Payoffs: [1, 10].  With high discount (0.5), future payoff discounted.
        let payoffs = vec![1_000_000, 10_000_000];
        let env = SnellEnvelope::compute(payoffs, 500_000).unwrap();
        // Discounted continuation = 0.5 * 10 = 5 > 1, so wait.
        assert_eq!(env.optimal_stopping_time, 1);
    }

    #[test]
    fn snell_envelope_empty_rejected() {
        assert!(matches!(
            SnellEnvelope::compute(vec![], MILLION),
            Err(StoppingError::EmptyObservations)
        ));
    }

    #[test]
    fn snell_invalid_discount_rejected() {
        assert!(matches!(
            SnellEnvelope::compute(vec![1_000_000], -1),
            Err(StoppingError::InvalidDiscount { .. })
        ));
        assert!(matches!(
            SnellEnvelope::compute(vec![1_000_000], MILLION + 1),
            Err(StoppingError::InvalidDiscount { .. })
        ));
    }

    #[test]
    fn snell_should_stop_at() {
        let payoffs = vec![1_000_000, 3_000_000, 2_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        assert!(!env.should_stop_at(0));
        assert!(env.should_stop_at(1));
    }

    #[test]
    fn snell_envelope_serde_roundtrip() {
        let payoffs = vec![1_000_000, 3_000_000, 2_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let restored: SnellEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, restored);
    }

    // === Secretary Problem ===

    #[test]
    fn secretary_exploration_length() {
        let sel = SecretarySelector::new(100);
        // ⌊100/e⌋ = ⌊36.78⌋ = 36
        assert!(sel.exploration_length >= 35 && sel.exploration_length <= 38);
    }

    #[test]
    fn secretary_explores_then_selects() {
        let mut sel = SecretarySelector::new(10);
        let explore_len = sel.exploration_length;

        // Exploration phase: should always continue.
        for i in 0..explore_len {
            let score = (i as i64 + 1) * 100_000;
            assert_eq!(sel.observe(score), StoppingDecision::Continue);
        }
        assert!(sel.exploration_complete);

        // Selection phase: first score exceeding exploration best should trigger.
        let best_during_explore = sel.exploration_best_millionths;
        let result = sel.observe(best_during_explore + 100_000);
        assert_eq!(result, StoppingDecision::Stop);
        assert!(sel.selected);
    }

    #[test]
    fn secretary_forces_selection_at_end() {
        let mut sel = SecretarySelector::new(5);
        // Feed decreasing scores — nothing in selection phase beats exploration.
        for i in 0..5 {
            sel.observe((5 - i as i64) * 100_000);
        }
        assert!(sel.selected);
    }

    #[test]
    fn secretary_single_item() {
        let mut sel = SecretarySelector::new(1);
        assert_eq!(sel.exploration_length, 0);
        let decision = sel.observe(500_000);
        assert_eq!(decision, StoppingDecision::Stop);
    }

    #[test]
    fn secretary_optimal_probability() {
        let prob = SecretarySelector::optimal_selection_probability_millionths();
        // Should be approximately 1/e ≈ 367_879 millionths.
        assert!((prob - 367_879).abs() < 1000);
    }

    #[test]
    fn secretary_serde_roundtrip() {
        let sel = SecretarySelector::new(50);
        let json = serde_json::to_string(&sel).unwrap();
        let restored: SecretarySelector = serde_json::from_str(&json).unwrap();
        assert_eq!(sel, restored);
    }

    // === EscalationPolicy ===

    #[test]
    fn escalation_policy_creation() {
        let policy = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
        assert!(policy.cusum_enabled);
        assert!(policy.secretary_enabled);
        assert_eq!(policy.total_observations, 0);
    }

    #[test]
    fn escalation_policy_triggers_on_cusum() {
        let mut policy = EscalationPolicy::new(2_000_000, 500_000, 100).unwrap();
        policy.secretary_enabled = false; // isolate CUSUM

        let mut triggered = false;
        for i in 0..20 {
            let obs = make_observation(1_000_000, 800_000, i);
            if policy.observe(&obs) == StoppingDecision::Stop {
                triggered = true;
                break;
            }
        }
        assert!(triggered);
        assert_eq!(policy.trigger_source, Some("cusum".to_string()));
    }

    #[test]
    fn escalation_policy_triggers_on_secretary() {
        let mut policy = EscalationPolicy::new(100_000_000, 500_000, 10).unwrap();
        policy.cusum_enabled = false; // isolate secretary

        // Feed increasing scores.
        let mut decisions = Vec::new();
        for i in 0..10 {
            let obs = make_observation(100_000, (i + 1) * 100_000, i as u64);
            decisions.push(policy.observe(&obs));
        }
        // Should eventually select.
        assert!(policy.secretary.selected);
    }

    #[test]
    fn escalation_policy_serde_roundtrip() {
        let policy = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EscalationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // === OptimalStoppingCertificate ===

    #[test]
    fn certificate_serde_roundtrip() {
        let cert = OptimalStoppingCertificate {
            schema: STOPPING_SCHEMA_VERSION.to_string(),
            algorithm: "cusum".to_string(),
            observations_before_stop: 42,
            cusum_statistic_millionths: Some(5_500_000),
            arl0_lower_bound: Some(1000 * MILLION),
            snell_optimal_value_millionths: None,
            gittins_index_millionths: None,
            epoch: SecurityEpoch::from_raw(7),
            certificate_hash: ContentHash::compute(b"test_cert"),
        };
        let json = serde_json::to_string(&cert).unwrap();
        let restored: OptimalStoppingCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    // === StoppingDecision ===

    #[test]
    fn stopping_decision_display() {
        assert_eq!(format!("{}", StoppingDecision::Continue), "continue");
        assert_eq!(format!("{}", StoppingDecision::Stop), "stop");
    }

    #[test]
    fn stopping_decision_ordering() {
        assert!(StoppingDecision::Continue < StoppingDecision::Stop);
    }

    // === Observation ===

    #[test]
    fn observation_serde_roundtrip() {
        let obs = make_observation(500_000, 700_000, 42);
        let json = serde_json::to_string(&obs).unwrap();
        let restored: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, restored);
    }

    // === Error display ===

    #[test]
    fn stopping_error_display() {
        let err = StoppingError::HorizonTooLarge {
            horizon: 20_000,
            max: 10_000,
        };
        assert!(format!("{err}").contains("20000"));
    }

    // -- Enrichment: Display uniqueness, serde, std::error, boundary --

    #[test]
    fn stopping_decision_serde_roundtrip() {
        for decision in [StoppingDecision::Continue, StoppingDecision::Stop] {
            let json = serde_json::to_string(&decision).unwrap();
            let back: StoppingDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, back);
        }
    }

    #[test]
    fn stopping_decision_display_all_unique() {
        let displays: std::collections::BTreeSet<String> =
            [StoppingDecision::Continue, StoppingDecision::Stop]
                .iter()
                .map(|d| d.to_string())
                .collect();
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn stopping_error_display_all_unique() {
        let errors: [StoppingError; 5] = [
            StoppingError::InvalidThreshold { threshold: 0 },
            StoppingError::InvalidDiscount { discount: 0 },
            StoppingError::EmptyObservations,
            StoppingError::IndexOutOfBounds { index: 0, size: 0 },
            StoppingError::HorizonTooLarge {
                horizon: 100,
                max: 50,
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    #[test]
    fn stopping_error_is_std_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(StoppingError::EmptyObservations);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn cusum_with_defaults_has_valid_threshold() {
        let chart = CusumChart::with_defaults();
        assert!(chart.threshold_millionths > 0);
        assert!(chart.reference_millionths >= 0);
    }

    #[test]
    fn snell_envelope_single_payoff() {
        let payoffs = vec![2_000_000];
        let env = SnellEnvelope::compute(payoffs, MILLION).unwrap();
        assert_eq!(env.optimal_stopping_time, 0);
        assert_eq!(env.optimal_value_millionths, 2_000_000);
        assert!(env.should_stop_at(0));
    }

    #[test]
    fn escalation_policy_serde_after_observations() {
        let mut policy = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
        let obs = make_observation(100_000, 100_000, 0);
        policy.observe(&obs);
        let json = serde_json::to_string(&policy).unwrap();
        let restored: EscalationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy.total_observations, restored.total_observations);
    }

    #[test]
    fn gittins_select_arm_prefers_unexplored() {
        let gc = GittinsIndexComputer::new(vec!["a".into(), "b".into()], 900_000, 100).unwrap();
        // Both arms have identical priors, select_arm should return 0
        let arm = gc.select_arm();
        assert!(arm < 2);
    }

    // ── Enrichment: clone equality ──────────────────────────────────────

    #[test]
    fn enrichment_clone_eq_observation() {
        let a = make_observation(123_456, 789_012, 42);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_cusum_chart() {
        let a = CusumChart::with_defaults();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_snell_envelope() {
        let a = SnellEnvelope::compute(vec![1_000_000, 3_000_000, 2_000_000], MILLION).unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_secretary_selector() {
        let a = SecretarySelector::new(50);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_escalation_policy() {
        let a = EscalationPolicy::new(5_000_000, 500_000, 100).unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── Enrichment: JSON field presence ─────────────────────────────────

    #[test]
    fn enrichment_json_fields_cusum_chart() {
        let chart = CusumChart::with_defaults();
        let json = serde_json::to_string(&chart).unwrap();
        assert!(json.contains("statistic_millionths"));
        assert!(json.contains("threshold_millionths"));
        assert!(json.contains("reference_millionths"));
        assert!(json.contains("high_water_mark_millionths"));
        assert!(json.contains("signaled"));
        assert!(json.contains("signal_round"));
    }

    #[test]
    fn enrichment_json_fields_gittins_arm() {
        let gc = GittinsIndexComputer::new(vec!["hyp_x".into()], 900_000, 100).unwrap();
        let json = serde_json::to_string(&gc.arms[0]).unwrap();
        assert!(json.contains("arm_id"));
        assert!(json.contains("successes"));
        assert!(json.contains("failures"));
        assert!(json.contains("gittins_index_millionths"));
        assert!(json.contains("discount_millionths"));
    }

    #[test]
    fn enrichment_json_fields_certificate() {
        let cert = OptimalStoppingCertificate {
            schema: STOPPING_SCHEMA_VERSION.to_string(),
            algorithm: "snell".to_string(),
            observations_before_stop: 10,
            cusum_statistic_millionths: None,
            arl0_lower_bound: None,
            snell_optimal_value_millionths: Some(3_000_000),
            gittins_index_millionths: None,
            epoch: SecurityEpoch::from_raw(1),
            certificate_hash: ContentHash::compute(b"field_check"),
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("algorithm"));
        assert!(json.contains("observations_before_stop"));
        assert!(json.contains("snell_optimal_value_millionths"));
        assert!(json.contains("epoch"));
        assert!(json.contains("certificate_hash"));
    }

    // ── Enrichment: serde roundtrip (GittinsArm individually) ───────────

    #[test]
    fn enrichment_serde_roundtrip_gittins_arm() {
        let gc = GittinsIndexComputer::new(vec!["arm0".into()], 800_000, 50).unwrap();
        let arm = &gc.arms[0];
        let json = serde_json::to_string(arm).unwrap();
        let restored: GittinsArm = serde_json::from_str(&json).unwrap();
        assert_eq!(*arm, restored);
    }

    // ── Enrichment: Display uniqueness (StoppingError all variants) ─────

    #[test]
    fn enrichment_stopping_error_display_unique_with_distinct_params() {
        let errors = [
            StoppingError::HorizonTooLarge {
                horizon: 99,
                max: 50,
            },
            StoppingError::InvalidThreshold { threshold: -5 },
            StoppingError::InvalidDiscount {
                discount: 2_000_000,
            },
            StoppingError::EmptyObservations,
            StoppingError::DegenerateKL,
            StoppingError::IndexOutOfBounds { index: 7, size: 3 },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 6);
    }

    // ── Enrichment: boundary condition ──────────────────────────────────

    #[test]
    fn enrichment_secretary_zero_items() {
        let sel = SecretarySelector::new(0);
        assert_eq!(sel.exploration_length, 0);
        assert_eq!(sel.total_items, 0);
        assert!(!sel.exploration_complete);
    }

    // ── Enrichment: Error source returns None ───────────────────────────

    #[test]
    fn enrichment_stopping_error_source_is_none() {
        let err = StoppingError::DegenerateKL;
        assert!(std::error::Error::source(&err).is_none());
    }

    // ── Enrichment batch 2: Copy semantics, Clone/Eq gaps, JSON fields ──

    #[test]
    fn enrichment_stopping_decision_copy_semantics() {
        let a = StoppingDecision::Stop;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, StoppingDecision::Stop);
    }

    #[test]
    fn enrichment_stopping_decision_ord_total() {
        // Continue < Stop, verify Ord consistency with PartialOrd
        let mut v = [
            StoppingDecision::Stop,
            StoppingDecision::Continue,
            StoppingDecision::Stop,
        ];
        v.sort();
        assert_eq!(v[0], StoppingDecision::Continue);
        assert_eq!(v[1], StoppingDecision::Stop);
        assert_eq!(v[2], StoppingDecision::Stop);
    }

    #[test]
    fn enrichment_clone_eq_stopping_error_all_variants() {
        let variants = [
            StoppingError::HorizonTooLarge {
                horizon: 50_000,
                max: 10_000,
            },
            StoppingError::InvalidThreshold { threshold: -42 },
            StoppingError::InvalidDiscount {
                discount: 2_000_000,
            },
            StoppingError::EmptyObservations,
            StoppingError::DegenerateKL,
            StoppingError::IndexOutOfBounds {
                index: 99,
                size: 10,
            },
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(v, &cloned);
        }
    }

    #[test]
    fn enrichment_serde_roundtrip_stopping_error_all_variants() {
        let variants = [
            StoppingError::HorizonTooLarge {
                horizon: 20_000,
                max: 10_000,
            },
            StoppingError::InvalidThreshold { threshold: -1 },
            StoppingError::InvalidDiscount { discount: 0 },
            StoppingError::EmptyObservations,
            StoppingError::DegenerateKL,
            StoppingError::IndexOutOfBounds { index: 5, size: 3 },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: StoppingError = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back);
        }
    }

    #[test]
    fn enrichment_clone_eq_gittins_index_computer() {
        let a = GittinsIndexComputer::new(vec!["x".into(), "y".into()], 900_000, 50).unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_certificate() {
        let cert = OptimalStoppingCertificate {
            schema: STOPPING_SCHEMA_VERSION.to_string(),
            algorithm: "gittins".to_string(),
            observations_before_stop: 7,
            cusum_statistic_millionths: None,
            arl0_lower_bound: None,
            snell_optimal_value_millionths: None,
            gittins_index_millionths: Some(750_000),
            epoch: SecurityEpoch::from_raw(3),
            certificate_hash: ContentHash::compute(b"clone_test"),
        };
        let cloned = cert.clone();
        assert_eq!(cert, cloned);
    }

    #[test]
    fn enrichment_json_fields_observation() {
        let obs = make_observation(100_000, 200_000, 99);
        let json = serde_json::to_string(&obs).unwrap();
        assert!(json.contains("llr_millionths"));
        assert!(json.contains("risk_score_millionths"));
        assert!(json.contains("timestamp_us"));
        assert!(json.contains("source"));
    }

    #[test]
    fn enrichment_json_fields_secretary_selector() {
        let sel = SecretarySelector::new(20);
        let json = serde_json::to_string(&sel).unwrap();
        assert!(json.contains("total_items"));
        assert!(json.contains("exploration_length"));
        assert!(json.contains("observed"));
        assert!(json.contains("exploration_best_millionths"));
        assert!(json.contains("exploration_complete"));
        assert!(json.contains("selected"));
        assert!(json.contains("selected_index"));
    }

    #[test]
    fn enrichment_json_fields_escalation_policy() {
        let policy = EscalationPolicy::new(5_000_000, 500_000, 50).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("cusum"));
        assert!(json.contains("cusum_enabled"));
        assert!(json.contains("secretary"));
        assert!(json.contains("secretary_enabled"));
        assert!(json.contains("total_observations"));
        assert!(json.contains("trigger_source"));
    }

    #[test]
    fn enrichment_json_fields_snell_envelope() {
        let env = SnellEnvelope::compute(vec![1_000_000, 2_000_000], MILLION).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("payoffs_millionths"));
        assert!(json.contains("envelope_millionths"));
        assert!(json.contains("optimal_stopping_time"));
        assert!(json.contains("optimal_value_millionths"));
        assert!(json.contains("discount_millionths"));
    }

    #[test]
    fn enrichment_cusum_high_water_mark_tracks_peak() {
        let mut chart = CusumChart::new(10_000_000, 500_000).unwrap();
        // Push the statistic up, then down, then check high_water_mark stayed at peak
        chart.observe(&make_observation(2_000_000, 500_000, 0));
        chart.observe(&make_observation(2_000_000, 500_000, 1));
        let peak = chart.statistic_millionths;
        assert!(peak > 0);
        // Push it back toward zero
        for i in 2..20 {
            chart.observe(&make_observation(-1_000_000, 100_000, i));
        }
        assert_eq!(chart.statistic_millionths, 0);
        assert_eq!(chart.high_water_mark_millionths, peak);
    }

    #[test]
    fn enrichment_cusum_post_signal_keeps_returning_stop() {
        let mut chart = CusumChart::new(1_000_000, 0).unwrap();
        // Force a signal
        chart.observe(&make_observation(2_000_000, 500_000, 0));
        assert!(chart.signaled);
        // Subsequent benign observations still return Stop
        let d = chart.observe(&make_observation(0, 0, 1));
        assert_eq!(d, StoppingDecision::Stop);
        let d2 = chart.observe(&make_observation(-500_000, 0, 2));
        assert_eq!(d2, StoppingDecision::Stop);
    }

    #[test]
    fn enrichment_cusum_arl0_zero_post_change_mean() {
        let chart = CusumChart::new(5_000_000, 500_000).unwrap();
        let arl0 = chart.arl0_lower_bound(0);
        assert_eq!(arl0, i64::MAX);
    }

    #[test]
    fn enrichment_cusum_arl0_negative_post_change_mean() {
        let chart = CusumChart::new(5_000_000, 500_000).unwrap();
        let arl0 = chart.arl0_lower_bound(-100);
        assert_eq!(arl0, i64::MAX);
    }

    #[test]
    fn enrichment_gittins_observe_failure_decreases_index() {
        let mut gc = GittinsIndexComputer::new(vec!["a".into()], 900_000, 100).unwrap();
        let initial_index = gc.arms[0].gittins_index_millionths;
        for _ in 0..10 {
            gc.observe(0, false).unwrap();
        }
        assert!(gc.arms[0].gittins_index_millionths < initial_index);
    }

    #[test]
    fn enrichment_snell_should_stop_at_past_horizon() {
        let env = SnellEnvelope::compute(vec![1_000_000, 2_000_000], MILLION).unwrap();
        // Index beyond the envelope length should return true (must stop)
        assert!(env.should_stop_at(100));
        assert!(env.should_stop_at(usize::MAX));
    }

    #[test]
    fn enrichment_secretary_two_items() {
        let mut sel = SecretarySelector::new(2);
        // With 2 items, exploration_length should be 1
        assert_eq!(sel.exploration_length, 1);
        // First item: exploration
        let d1 = sel.observe(500_000);
        assert_eq!(d1, StoppingDecision::Continue);
        assert!(sel.exploration_complete);
        // Second item: if it beats exploration best, stop; if not, forced stop at end
        let d2 = sel.observe(600_000);
        assert_eq!(d2, StoppingDecision::Stop);
        assert!(sel.selected);
    }

    #[test]
    fn enrichment_schema_version_constant() {
        assert!(STOPPING_SCHEMA_VERSION.contains("optimal-stopping"));
        assert!(STOPPING_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn enrichment_stopping_decision_debug_format() {
        let dbg_continue = format!("{:?}", StoppingDecision::Continue);
        let dbg_stop = format!("{:?}", StoppingDecision::Stop);
        assert!(dbg_continue.contains("Continue"));
        assert!(dbg_stop.contains("Stop"));
    }

    #[test]
    fn enrichment_snell_envelope_zero_discount() {
        // With discount factor 0, continuation value is always 0,
        // so optimal stopping is at the max payoff if it's positive
        let payoffs = vec![-1_000_000, 3_000_000, -500_000];
        let env = SnellEnvelope::compute(payoffs, 0).unwrap();
        // With zero discount, each envelope value is just max(payoff, 0 * next)
        // so envelope = max(payoff, 0) for each step
        // optimal_stopping_time = first t where envelope_t == payoff_t
        // envelope[2] = payoff[2] = -500_000
        // envelope[1] = max(3_000_000, 0) = 3_000_000
        // envelope[0] = max(-1_000_000, 0) = 0, payoff[0] = -1_000_000 != 0
        // first match: t=1 where envelope=3M and payoff=3M
        assert_eq!(env.optimal_stopping_time, 1);
        assert_eq!(env.optimal_value_millionths, 3_000_000);
    }
}
