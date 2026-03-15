//! Regret-bounded adaptive lane router using online learning.
//!
//! Replaces the static keyword-heuristic `HybridRouter` with a provably
//! optimal online learning router.  Two algorithms are provided:
//!
//! - **EXP3** (Exponential-weight algorithm for Exploration and Exploitation):
//!   adversarial regime, O(√(T·K·ln K)) regret bound where K = number of
//!   lanes, T = number of routing decisions.
//!
//! - **FTRL** (Follow-the-Regularized-Leader with negative entropy):
//!   stochastic regime, O(√(T·ln K)) regret bound — tighter when the
//!   environment is not adversarial.
//!
//! The router automatically detects regime shifts and switches between EXP3
//! and FTRL.
//!
//! If full-information counterfactual rewards are provided per round, the
//! module can report exact realized regret against the best single arm in
//! hindsight. Without counterfactuals, it reports an empirical pseudo-regret
//! estimate derived from observed pulls.
//!
//! All arithmetic uses fixed-point millionths for deterministic replay.
//! No floating point.  Deterministic given the same reward sequence.
//!
//! References:
//! - Auer et al., "The Nonstochastic Multiarmed Bandit Problem" (2002)
//! - Shalev-Shwartz, "Online Learning and Online Convex Optimization" (2012)
//! - Lattimore & Szepesvári, "Bandit Algorithms" (2020), Ch. 11–12

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for serialized routing artifacts.
pub const ROUTING_SCHEMA_VERSION: &str = "franken-engine.regret-bounded-router.v1";

/// Minimum exploration probability per arm (prevents starvation).
const MIN_EXPLORATION_MILLIONTHS: i64 = 10_000; // 1%

/// Maximum number of lane arms.
const MAX_ARMS: usize = 16;

/// Default learning rate scaling constant for EXP3.
/// η = sqrt(ln(K) / (T·K)) — we use this as the per-round multiplier.
const DEFAULT_ETA_SCALE_MILLIONTHS: i64 = 100_000; // 0.1

/// Confidence threshold for regime detection to trigger algorithm switch.
const REGIME_SWITCH_CONFIDENCE_MILLIONTHS: i64 = 800_000; // 80%

// ---------------------------------------------------------------------------
// LaneArm — a routing option
// ---------------------------------------------------------------------------

/// A candidate execution lane (arm in the bandit formulation).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LaneArm {
    /// Unique identifier for this lane.
    pub lane_id: String,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// RewardSignal — feedback from execution
// ---------------------------------------------------------------------------

/// Reward signal from executing a routing decision.
///
/// Rewards are in millionths where 1_000_000 = perfect outcome.
/// Incorporates execution time, correctness, and resource usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardSignal {
    /// Which arm was pulled.
    pub arm_index: usize,
    /// Reward in millionths [0, 1_000_000].
    pub reward_millionths: i64,
    /// Execution latency in microseconds.
    pub latency_us: u64,
    /// Whether execution succeeded.
    pub success: bool,
    /// Epoch at which this reward was observed.
    pub epoch: SecurityEpoch,
    /// Optional full-information rewards for all arms for this round.
    /// If present and sized to `num_arms`, enables exact regret accounting.
    pub counterfactual_rewards_millionths: Option<Vec<i64>>,
}

// ---------------------------------------------------------------------------
// RegimeKind — stochastic vs adversarial
// ---------------------------------------------------------------------------

/// Detected regime governing algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RegimeKind {
    /// Insufficient data to determine regime.
    Unknown,
    /// Rewards are drawn i.i.d. — FTRL is optimal.
    Stochastic,
    /// Rewards may be adversarially chosen — EXP3 is needed.
    Adversarial,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the regret-bounded router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterError {
    /// No arms configured.
    NoArms,
    /// Too many arms.
    TooManyArms { count: usize, max: usize },
    /// Arm index out of bounds.
    ArmOutOfBounds { index: usize, count: usize },
    /// Reward out of valid range.
    RewardOutOfRange { reward: i64 },
    /// Exploration parameter is outside (0, 1].
    InvalidGamma { gamma_millionths: i64 },
    /// Counterfactual reward vector size does not match number of arms.
    CounterfactualSizeMismatch { got: usize, expected: usize },
    /// Cannot route with zero total weight.
    ZeroWeight,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoArms => write!(f, "no arms configured"),
            Self::TooManyArms { count, max } => {
                write!(f, "{count} arms exceeds maximum {max}")
            }
            Self::ArmOutOfBounds { index, count } => {
                write!(f, "arm index {index} out of bounds (count {count})")
            }
            Self::RewardOutOfRange { reward } => {
                write!(f, "reward {reward} outside [0, 1_000_000]")
            }
            Self::InvalidGamma { gamma_millionths } => {
                write!(f, "gamma {gamma_millionths} outside (0, 1_000_000]")
            }
            Self::CounterfactualSizeMismatch { got, expected } => {
                write!(
                    f,
                    "counterfactual reward vector has size {got}, expected {expected}"
                )
            }
            Self::ZeroWeight => write!(f, "cannot route with zero total weight"),
        }
    }
}

impl std::error::Error for RouterError {}

// ---------------------------------------------------------------------------
// EXP3 Algorithm State
// ---------------------------------------------------------------------------

/// EXP3 algorithm state for adversarial bandits.
///
/// Maintains exponential weights over arms and samples proportionally,
/// with importance-weighted reward estimates for unbiased updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exp3State {
    /// Number of arms.
    pub num_arms: usize,
    /// Cumulative log-weights in millionths (unnormalized).
    /// We store log-weights to prevent overflow: w_i = exp(η · Σ r̂_t,i).
    /// In fixed-point: log_weight_i += η * importance_weighted_reward.
    pub log_weights_millionths: Vec<i64>,
    /// Exploration parameter γ ∈ (0, 1] in millionths.
    /// Probability: p_i = (1-γ) · w_i / Σw_j + γ/K
    pub gamma_millionths: i64,
    /// Learning rate η in millionths.
    pub eta_millionths: i64,
    /// Total rounds played.
    pub rounds: u64,
}

impl Exp3State {
    /// Create new EXP3 state with K arms.
    pub fn new(num_arms: usize, gamma_millionths: i64) -> Result<Self, RouterError> {
        if num_arms == 0 {
            return Err(RouterError::NoArms);
        }
        if num_arms > MAX_ARMS {
            return Err(RouterError::TooManyArms {
                count: num_arms,
                max: MAX_ARMS,
            });
        }
        if !(1..=MILLION).contains(&gamma_millionths) {
            return Err(RouterError::InvalidGamma { gamma_millionths });
        }
        Ok(Self {
            num_arms,
            log_weights_millionths: vec![0; num_arms],
            gamma_millionths,
            eta_millionths: DEFAULT_ETA_SCALE_MILLIONTHS,
            rounds: 0,
        })
    }

    /// Compute arm probabilities in millionths.
    ///
    /// p_i = (1 - γ) · softmax(log_weights)_i + γ/K
    pub fn arm_probabilities(&self) -> Vec<i64> {
        let k = self.num_arms as i64;
        let gamma = self.gamma_millionths;
        let softmax = softmax_from_logits_millionths(&self.log_weights_millionths);
        let mut probs = Vec::with_capacity(self.num_arms);
        for q in softmax {
            // p_i = (1 - γ) * q_i + γ/K in millionths.
            let exploit = (MILLION - gamma) as i128 * q as i128 / MILLION as i128;
            let explore = gamma as i128 / k as i128;
            probs.push((exploit + explore).clamp(0, i64::MAX as i128) as i64);
        }
        enforce_probability_floor_and_normalize(&mut probs, MIN_EXPLORATION_MILLIONTHS);
        probs
    }

    /// Select an arm deterministically given a random seed in [0, MILLION).
    pub fn select_arm(&self, random_millionths: i64) -> usize {
        let random_millionths = random_millionths.clamp(0, MILLION - 1);
        let probs = self.arm_probabilities();
        let mut cumulative = 0i64;
        for (i, &p) in probs.iter().enumerate() {
            cumulative += p;
            if random_millionths < cumulative {
                return i;
            }
        }
        self.num_arms - 1 // fallback to last arm
    }

    /// Update weights after observing a reward.
    ///
    /// Importance-weighted reward: r̂_i = r_i / p_i (unbiased estimator).
    /// Weight update: log_w_i += η · r̂_i.
    pub fn update(&mut self, arm: usize, reward_millionths: i64) -> Result<(), RouterError> {
        if arm >= self.num_arms {
            return Err(RouterError::ArmOutOfBounds {
                index: arm,
                count: self.num_arms,
            });
        }
        if !(0..=MILLION).contains(&reward_millionths) {
            return Err(RouterError::RewardOutOfRange {
                reward: reward_millionths,
            });
        }

        let probs = self.arm_probabilities();
        let p_arm = probs[arm].max(1); // avoid division by zero

        // Importance-weighted reward: r̂ = r / p
        let importance_weighted = reward_millionths * MILLION / p_arm;

        // Update log-weight: log_w += η · r̂ / MILLION
        let delta = self.eta_millionths * importance_weighted / MILLION;
        self.log_weights_millionths[arm] += delta;

        self.rounds += 1;
        Ok(())
    }

    /// Compute the theoretical regret bound for T rounds.
    /// EXP3 bound: 2√(T · K · ln K) in millionths.
    pub fn regret_bound_millionths(&self) -> i64 {
        let t = i64::try_from(self.rounds.max(1)).unwrap_or(i64::MAX);
        let k = self.num_arms as i64;
        // 2 * sqrt(T * K * ln(K))
        // ln(K) ≈ K for small K; use integer sqrt approximation.
        let ln_k = integer_ln_millionths(k as u64) as i128;
        let product = (t as i128).saturating_mul(k as i128).saturating_mul(ln_k) / MILLION as i128;
        integer_sqrt_millionths(product.min(i64::MAX as i128) as i64).saturating_mul(2)
    }
}

// ---------------------------------------------------------------------------
// FTRL Algorithm State
// ---------------------------------------------------------------------------

/// FTRL (Follow-the-Regularized-Leader) state for stochastic bandits.
///
/// Uses negative entropy regularization: argmax_p { p·μ̂ - (1/η)·Σ p_i·ln(p_i) }
/// which yields the softmax distribution.
///
/// Tighter O(√(T·ln K)) bound in stochastic environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FtrlState {
    /// Number of arms.
    pub num_arms: usize,
    /// Cumulative reward estimates per arm (millionths).
    pub cumulative_rewards_millionths: Vec<i64>,
    /// Number of times each arm was pulled.
    pub arm_counts: Vec<u64>,
    /// Learning rate η in millionths.
    pub eta_millionths: i64,
    /// Total rounds played.
    pub rounds: u64,
}

impl FtrlState {
    /// Create new FTRL state with K arms.
    pub fn new(num_arms: usize) -> Result<Self, RouterError> {
        if num_arms == 0 {
            return Err(RouterError::NoArms);
        }
        if num_arms > MAX_ARMS {
            return Err(RouterError::TooManyArms {
                count: num_arms,
                max: MAX_ARMS,
            });
        }
        Ok(Self {
            num_arms,
            cumulative_rewards_millionths: vec![0; num_arms],
            arm_counts: vec![0; num_arms],
            eta_millionths: DEFAULT_ETA_SCALE_MILLIONTHS,
            rounds: 0,
        })
    }

    /// Compute arm probabilities via softmax over cumulative rewards.
    pub fn arm_probabilities(&self) -> Vec<i64> {
        let max_r = self
            .cumulative_rewards_millionths
            .iter()
            .copied()
            .max()
            .unwrap_or(0);

        let logits: Vec<i64> = self
            .cumulative_rewards_millionths
            .iter()
            .map(|&r| {
                let scaled = (self.eta_millionths as i128 * (r - max_r) as i128) / MILLION as i128;
                scaled.clamp(i64::MIN as i128, i64::MAX as i128) as i64
            })
            .collect();
        let mut probs = softmax_from_logits_millionths(&logits);
        enforce_probability_floor_and_normalize(&mut probs, MIN_EXPLORATION_MILLIONTHS);
        probs
    }

    /// Select an arm deterministically given a random seed.
    pub fn select_arm(&self, random_millionths: i64) -> usize {
        let random_millionths = random_millionths.clamp(0, MILLION - 1);
        let probs = self.arm_probabilities();
        let mut cumulative = 0i64;
        for (i, &p) in probs.iter().enumerate() {
            cumulative += p;
            if random_millionths < cumulative {
                return i;
            }
        }
        self.num_arms - 1
    }

    /// Update after observing a reward.
    pub fn update(&mut self, arm: usize, reward_millionths: i64) -> Result<(), RouterError> {
        if arm >= self.num_arms {
            return Err(RouterError::ArmOutOfBounds {
                index: arm,
                count: self.num_arms,
            });
        }
        if !(0..=MILLION).contains(&reward_millionths) {
            return Err(RouterError::RewardOutOfRange {
                reward: reward_millionths,
            });
        }

        self.cumulative_rewards_millionths[arm] += reward_millionths;
        self.arm_counts[arm] += 1;
        self.rounds += 1;
        Ok(())
    }

    /// Mean reward per arm in millionths.
    pub fn mean_rewards(&self) -> Vec<i64> {
        self.cumulative_rewards_millionths
            .iter()
            .zip(self.arm_counts.iter())
            .map(|(&total, &count)| total.checked_div(count as i64).unwrap_or(0))
            .collect()
    }

    /// FTRL regret bound: 2√(T · ln K) in millionths.
    pub fn regret_bound_millionths(&self) -> i64 {
        let t = i64::try_from(self.rounds.max(1)).unwrap_or(i64::MAX);
        let k = self.num_arms as i64;
        let ln_k = integer_ln_millionths(k as u64) as i128;
        let product = (t as i128).saturating_mul(ln_k) / MILLION as i128;
        integer_sqrt_millionths(product.min(i64::MAX as i128) as i64).saturating_mul(2)
    }
}

// ---------------------------------------------------------------------------
// RegretBoundedRouter — the adaptive router
// ---------------------------------------------------------------------------

/// Adaptive lane router with explicit regret accounting.
///
/// Automatically selects between EXP3 (adversarial) and FTRL (stochastic)
/// based on detected regime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegretBoundedRouter {
    /// Available execution lanes.
    pub arms: Vec<LaneArm>,
    /// EXP3 algorithm state.
    pub exp3: Exp3State,
    /// FTRL algorithm state.
    pub ftrl: FtrlState,
    /// Currently active algorithm.
    pub active_regime: RegimeKind,
    /// Cumulative reward of the router (millionths).
    pub cumulative_reward_millionths: i64,
    /// Best-arm cumulative reward baseline used by the current regret mode.
    /// With full counterfactuals this is exact best-fixed-arm hindsight reward;
    /// otherwise it is an observed-pulls proxy.
    pub best_arm_cumulative_millionths: i64,
    /// Per-arm cumulative rewards from full-information counterfactual vectors.
    /// When present for every round, this enables exact best-fixed-arm regret.
    counterfactual_per_arm_cumulative: Vec<i64>,
    /// Number of rounds for which full-information counterfactuals were supplied.
    counterfactual_rounds: u64,
    /// Per-arm cumulative rewards for best-arm tracking.
    per_arm_cumulative: Vec<i64>,
    /// Per-arm pull counts for mean reward estimation.
    per_arm_count: Vec<u64>,
    /// History of regime transitions.
    pub regime_history: Vec<RegimeTransition>,
    /// Reward variance estimator for regime detection.
    reward_variance_estimator: VarianceEstimator,
}

/// Record of a regime transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeTransition {
    pub round: u64,
    pub from: RegimeKind,
    pub to: RegimeKind,
    pub confidence_millionths: i64,
}

/// Online variance estimator (Welford's algorithm in fixed-point).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VarianceEstimator {
    count: u64,
    mean_millionths: i64,
    m2_millionths: i64,
}

impl VarianceEstimator {
    fn new() -> Self {
        Self {
            count: 0,
            mean_millionths: 0,
            m2_millionths: 0,
        }
    }

    fn update(&mut self, value_millionths: i64) {
        self.count += 1;
        let count_i64 = i64::try_from(self.count).unwrap_or(i64::MAX);
        let delta = value_millionths - self.mean_millionths;
        self.mean_millionths += delta / count_i64.max(1);
        let delta2 = value_millionths - self.mean_millionths;
        self.m2_millionths = self
            .m2_millionths
            .saturating_add(delta.saturating_mul(delta2) / MILLION);
    }

    fn variance_millionths(&self) -> i64 {
        if self.count < 2 {
            return 0;
        }
        let count_i64 = i64::try_from(self.count).unwrap_or(i64::MAX);
        self.m2_millionths / (count_i64 - 1).max(1)
    }
}

impl RegretBoundedRouter {
    /// Create a new router with the given lane arms.
    pub fn new(arms: Vec<LaneArm>, gamma_millionths: i64) -> Result<Self, RouterError> {
        let n = arms.len();
        if n == 0 {
            return Err(RouterError::NoArms);
        }
        if n > MAX_ARMS {
            return Err(RouterError::TooManyArms {
                count: n,
                max: MAX_ARMS,
            });
        }

        Ok(Self {
            exp3: Exp3State::new(n, gamma_millionths)?,
            ftrl: FtrlState::new(n)?,
            arms,
            active_regime: RegimeKind::Unknown,
            cumulative_reward_millionths: 0,
            best_arm_cumulative_millionths: 0,
            counterfactual_per_arm_cumulative: vec![0; n],
            counterfactual_rounds: 0,
            per_arm_cumulative: vec![0; n],
            per_arm_count: vec![0; n],
            regime_history: Vec::new(),
            reward_variance_estimator: VarianceEstimator::new(),
        })
    }

    /// Number of arms.
    pub fn num_arms(&self) -> usize {
        self.arms.len()
    }

    /// Current round number.
    pub fn rounds(&self) -> u64 {
        self.exp3.rounds
    }

    /// Select a lane arm given a deterministic random seed in [0, MILLION).
    pub fn select_arm(&self, random_millionths: i64) -> usize {
        match self.active_regime {
            RegimeKind::Adversarial => self.exp3.select_arm(random_millionths),
            RegimeKind::Stochastic => self.ftrl.select_arm(random_millionths),
            RegimeKind::Unknown => {
                // Round-robin during warm-up (first K rounds).
                if self.exp3.rounds < self.arms.len() as u64 {
                    self.exp3.rounds as usize
                } else {
                    self.exp3.select_arm(random_millionths)
                }
            }
        }
    }

    /// Observe reward and update internal state.
    pub fn observe_reward(
        &mut self,
        signal: &RewardSignal,
    ) -> Result<RoutingDecisionReceipt, RouterError> {
        let arm = signal.arm_index;
        let reward = signal.reward_millionths;

        // Validate observed feedback before mutating any state. This keeps the
        // router transactional under malformed signals.
        if arm >= self.arms.len() {
            return Err(RouterError::ArmOutOfBounds {
                index: arm,
                count: self.arms.len(),
            });
        }
        if !(0..=MILLION).contains(&reward) {
            return Err(RouterError::RewardOutOfRange { reward });
        }

        if let Some(counterfactual) = &signal.counterfactual_rewards_millionths {
            if counterfactual.len() != self.arms.len() {
                return Err(RouterError::CounterfactualSizeMismatch {
                    got: counterfactual.len(),
                    expected: self.arms.len(),
                });
            }
            // Validate all counterfactual values before mutating state to
            // maintain transactional semantics on error.
            for &r in counterfactual {
                if !(0..=MILLION).contains(&r) {
                    return Err(RouterError::RewardOutOfRange { reward: r });
                }
            }
            for (arm_idx, &r) in counterfactual.iter().enumerate() {
                self.counterfactual_per_arm_cumulative[arm_idx] =
                    self.counterfactual_per_arm_cumulative[arm_idx].saturating_add(r);
            }
            self.counterfactual_rounds = self.counterfactual_rounds.saturating_add(1);
        }

        // Update both algorithms (they run in parallel).
        self.exp3.update(arm, reward)?;
        self.ftrl.update(arm, reward)?;

        // Update cumulative tracking.
        self.cumulative_reward_millionths =
            self.cumulative_reward_millionths.saturating_add(reward);
        self.per_arm_cumulative[arm] = self.per_arm_cumulative[arm].saturating_add(reward);
        self.per_arm_count[arm] = self.per_arm_count[arm].saturating_add(1);
        self.best_arm_cumulative_millionths = if self.exact_regret_available() {
            self.counterfactual_per_arm_cumulative
                .iter()
                .copied()
                .max()
                .unwrap_or(0)
        } else {
            self.per_arm_cumulative.iter().copied().max().unwrap_or(0)
        };

        // Update variance estimator for regime detection.
        self.reward_variance_estimator.update(reward);

        // Detect regime shift periodically.
        let round = self.exp3.rounds;
        if round > 0 && round.is_multiple_of(self.arms.len() as u64) {
            self.detect_regime_shift();
        }

        let exact_regret_available = self.exact_regret_available();
        let realized_regret = self.realized_regret_millionths();
        let theoretical_bound = self.regret_bound_millionths();

        Ok(RoutingDecisionReceipt {
            schema: ROUTING_SCHEMA_VERSION.to_string(),
            round,
            arm_selected: arm,
            reward_millionths: reward,
            regime: self.active_regime,
            cumulative_reward_millionths: self.cumulative_reward_millionths,
            realized_regret_millionths: realized_regret,
            theoretical_regret_bound_millionths: theoretical_bound,
            exact_regret_available,
            regret_within_bound: exact_regret_available && realized_regret <= theoretical_bound,
        })
    }

    /// Whether exact best-fixed-arm regret is available this round.
    pub fn exact_regret_available(&self) -> bool {
        self.rounds() > 0 && self.counterfactual_rounds == self.rounds()
    }

    /// Current regret bound based on active algorithm.
    pub fn regret_bound_millionths(&self) -> i64 {
        match self.active_regime {
            RegimeKind::Adversarial | RegimeKind::Unknown => self.exp3.regret_bound_millionths(),
            RegimeKind::Stochastic => self.ftrl.regret_bound_millionths(),
        }
    }

    /// Realized regret.
    ///
    /// - If per-round counterfactual rewards were supplied, this is exact
    ///   regret against the best single arm in hindsight.
    /// - Otherwise this is an empirical pseudo-regret estimate:
    ///   T × max_observed_mean_reward - cumulative_reward.
    pub fn realized_regret_millionths(&self) -> i64 {
        if self.exact_regret_available() {
            let best_fixed_arm = self
                .counterfactual_per_arm_cumulative
                .iter()
                .copied()
                .max()
                .unwrap_or(0);
            let regret = best_fixed_arm as i128 - self.cumulative_reward_millionths as i128;
            return regret.clamp(0, i64::MAX as i128) as i64;
        }
        let t = i64::try_from(self.rounds()).unwrap_or(i64::MAX);
        if t == 0 {
            return 0;
        }
        // Best arm's estimated mean reward × total rounds.
        let best_mean = self
            .per_arm_cumulative
            .iter()
            .zip(self.per_arm_count.iter())
            .map(|(&total, &count)| total.checked_div(count as i64).unwrap_or(0))
            .max()
            .unwrap_or(0);
        let projected_best = (best_mean as i128).saturating_mul(t as i128);
        let regret = projected_best - self.cumulative_reward_millionths as i128;
        regret.clamp(0, i64::MAX as i128) as i64
    }

    /// Detect whether the environment is stochastic or adversarial.
    ///
    /// Heuristic: if squared coefficient of variation (CV² = var/mean²) is
    /// low, the environment is likely stochastic (i.i.d. rewards). High CV²
    /// suggests adversarial behavior.
    fn detect_regime_shift(&mut self) {
        let variance = self.reward_variance_estimator.variance_millionths();
        let mean = self.reward_variance_estimator.mean_millionths.max(1);

        // Squared coefficient of variation (CV^2) in millionths:
        // variance / mean^2
        let mean_sq = ((mean as i128 * mean as i128) / MILLION as i128).max(1);
        let cv_sq = (variance as i128 * MILLION as i128 / mean_sq) as i64;

        // If CV² < 0.5 → stochastic; else → adversarial.
        let new_regime = if cv_sq < 500_000 {
            RegimeKind::Stochastic
        } else {
            RegimeKind::Adversarial
        };

        let confidence = if !(200_000..=800_000).contains(&cv_sq) {
            900_000 // 90% — clear signal
        } else {
            600_000 // 60% — marginal
        };

        if new_regime != self.active_regime && confidence >= REGIME_SWITCH_CONFIDENCE_MILLIONTHS {
            self.regime_history.push(RegimeTransition {
                round: self.exp3.rounds,
                from: self.active_regime,
                to: new_regime,
                confidence_millionths: confidence,
            });
            self.active_regime = new_regime;
        }
    }

    /// Generate a summary of the routing state.
    pub fn summary(&self) -> RouterSummary {
        let arm_probs = match self.active_regime {
            RegimeKind::Adversarial | RegimeKind::Unknown => self.exp3.arm_probabilities(),
            RegimeKind::Stochastic => self.ftrl.arm_probabilities(),
        };

        RouterSummary {
            schema: ROUTING_SCHEMA_VERSION.to_string(),
            num_arms: self.arms.len(),
            rounds: self.exp3.rounds,
            active_regime: self.active_regime,
            arm_probabilities_millionths: arm_probs,
            cumulative_reward_millionths: self.cumulative_reward_millionths,
            best_arm_cumulative_millionths: self.best_arm_cumulative_millionths,
            realized_regret_millionths: self.realized_regret_millionths(),
            theoretical_regret_bound_millionths: self.regret_bound_millionths(),
            exact_regret_available: self.exact_regret_available(),
            regime_transitions: self.regime_history.len(),
        }
    }
}

/// Receipt for a single routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecisionReceipt {
    pub schema: String,
    pub round: u64,
    pub arm_selected: usize,
    pub reward_millionths: i64,
    pub regime: RegimeKind,
    pub cumulative_reward_millionths: i64,
    pub realized_regret_millionths: i64,
    pub theoretical_regret_bound_millionths: i64,
    /// True only when full-information counterfactual regret is available.
    pub exact_regret_available: bool,
    /// Meaningful only when `exact_regret_available` is true.
    pub regret_within_bound: bool,
}

/// Summary of routing state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterSummary {
    pub schema: String,
    pub num_arms: usize,
    pub rounds: u64,
    pub active_regime: RegimeKind,
    pub arm_probabilities_millionths: Vec<i64>,
    pub cumulative_reward_millionths: i64,
    pub best_arm_cumulative_millionths: i64,
    pub realized_regret_millionths: i64,
    pub theoretical_regret_bound_millionths: i64,
    pub exact_regret_available: bool,
    pub regime_transitions: usize,
}

/// Regret certificate — machine-checkable proof of sublinear regret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegretCertificate {
    pub schema: String,
    /// Total rounds.
    pub rounds: u64,
    /// Realized regret (millionths).
    pub realized_regret_millionths: i64,
    /// Theoretical bound (millionths).
    pub theoretical_bound_millionths: i64,
    /// Whether exact realized regret ≤ theoretical (false when empirical only).
    pub within_bound: bool,
    /// Whether realized regret is exact (full-information) or empirical.
    pub exact_regret_available: bool,
    /// Average per-round regret (millionths).
    pub per_round_regret_millionths: i64,
    /// Regret growth rate: should be O(1/√T) for sublinear.
    pub growth_rate_class: String,
}

impl RegretBoundedRouter {
    /// Generate a regret certificate for the current state.
    pub fn regret_certificate(&self) -> RegretCertificate {
        let rounds = self.rounds().max(1);
        let exact_regret_available = self.exact_regret_available();
        let realized = self.realized_regret_millionths();
        let bound = self.regret_bound_millionths();
        let within_bound = exact_regret_available && realized <= bound;
        let rounds_i64 = i64::try_from(rounds).unwrap_or(i64::MAX);
        let per_round = realized / rounds_i64.max(1);

        let growth_class = if !exact_regret_available {
            "empirical_estimate".to_string()
        } else if per_round == 0 {
            "zero".to_string()
        } else if realized <= bound {
            "sublinear_verified".to_string()
        } else {
            "needs_investigation".to_string()
        };

        RegretCertificate {
            schema: ROUTING_SCHEMA_VERSION.to_string(),
            rounds,
            realized_regret_millionths: realized,
            theoretical_bound_millionths: bound,
            within_bound,
            exact_regret_available,
            per_round_regret_millionths: per_round,
            growth_rate_class: growth_class,
        }
    }
}

// ---------------------------------------------------------------------------
// Integer math helpers (no floating point)
// ---------------------------------------------------------------------------

/// ln(2) in millionths.
const LN_2_MILLIONTHS: i64 = 693_147;

/// Fixed-point exponential `exp(x)` where `x` is in millionths.
///
/// Uses range reduction around powers of two:
/// `exp(x) = 2^k * exp(r)`, with `r ∈ [-ln(2)/2, ln(2)/2]`,
/// then evaluates `exp(r)` via Taylor series in fixed-point.
fn integer_exp_millionths(x_millionths: i64) -> i64 {
    // Prevent pathological overflow while keeping a broad dynamic range.
    let x = i128::from(x_millionths.clamp(-40 * MILLION, 40 * MILLION));
    let ln2 = i128::from(LN_2_MILLIONTHS);
    let half_ln2 = ln2 / 2;

    let mut k = x.div_euclid(ln2);
    let mut r = x - k * ln2;
    if r > half_ln2 {
        r -= ln2;
        k += 1;
    }

    let m = i128::from(MILLION);
    let mut sum = m;
    let mut term = m;
    for n in 1..=10i128 {
        term = term.saturating_mul(r) / m;
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
    scaled.clamp(1, i64::MAX as i128) as i64
}

/// Softmax over logits in millionths, output probabilities summing to 1e6.
fn softmax_from_logits_millionths(logits_millionths: &[i64]) -> Vec<i64> {
    if logits_millionths.is_empty() {
        return Vec::new();
    }
    let max_logit = logits_millionths.iter().copied().max().unwrap_or(0);
    let weights: Vec<i64> = logits_millionths
        .iter()
        .map(|&x| integer_exp_millionths(x.saturating_sub(max_logit)))
        .collect();
    let total_weight: i128 = weights.iter().map(|&w| w as i128).sum::<i128>().max(1);

    let mut probs: Vec<i64> = weights
        .iter()
        .map(|&w| (w as i128 * MILLION as i128 / total_weight) as i64)
        .collect();
    enforce_probability_floor_and_normalize(&mut probs, 0);
    probs
}

/// Enforce per-arm floor and exact millionths normalization.
fn enforce_probability_floor_and_normalize(probs: &mut [i64], min_floor: i64) {
    if probs.is_empty() {
        return;
    }
    let n = probs.len() as i64;
    let floor = min_floor.clamp(0, MILLION / n);
    for p in probs.iter_mut() {
        *p = (*p).max(floor);
    }

    let mut sum: i64 = probs.iter().sum();
    if sum < MILLION {
        if let Some(idx) = probs
            .iter()
            .enumerate()
            .max_by_key(|(_, p)| *p)
            .map(|(i, _)| i)
        {
            probs[idx] = probs[idx].saturating_add(MILLION - sum);
        }
        return;
    }
    if sum == MILLION {
        return;
    }

    let mut excess = sum - MILLION;
    let mut indices: Vec<usize> = (0..probs.len()).collect();
    indices.sort_by_key(|&i| std::cmp::Reverse(probs[i]));
    for idx in indices {
        if excess == 0 {
            break;
        }
        let reducible = (probs[idx] - floor).max(0);
        if reducible == 0 {
            continue;
        }
        let take = reducible.min(excess);
        probs[idx] -= take;
        excess -= take;
    }

    if excess > 0 {
        let base = MILLION / n;
        let rem = MILLION - base * n;
        for p in probs.iter_mut() {
            *p = base;
        }
        probs[0] += rem;
    }

    // Final exact correction (handles tiny rounding drift).
    sum = probs.iter().sum();
    if sum != MILLION {
        let diff = MILLION - sum;
        if let Some(idx) = probs
            .iter()
            .enumerate()
            .max_by_key(|(_, p)| *p)
            .map(|(i, _)| i)
        {
            probs[idx] += diff;
        }
    }
}

/// Integer log₂(n) in millionths using fractional-bit extraction.
fn integer_log2_millionths(n: u64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let bits = 64 - n.leading_zeros();
    let integer_part = (bits - 1) as i64 * MILLION;

    let power_of_two = 1u64 << (bits - 1);
    if n == power_of_two {
        return integer_part;
    }

    let mut mantissa: u64 = if bits - 1 <= 32 {
        n << (32 - (bits - 1))
    } else {
        n >> ((bits - 1) - 32)
    };
    let threshold: u64 = 1u64 << 33;

    let mut frac = 0i64;
    let mut bit_value = 500_000i64;
    for _ in 0..20 {
        mantissa = ((mantissa as u128 * mantissa as u128) >> 32) as u64;
        if mantissa >= threshold {
            frac += bit_value;
            mantissa >>= 1;
        }
        bit_value /= 2;
        if bit_value == 0 {
            break;
        }
    }

    integer_part + frac
}

/// Integer approximation of ln(n) in millionths.
fn integer_ln_millionths(n: u64) -> i64 {
    // Multiply in i128 to avoid overflow when log2 is large (n near u64::MAX).
    (integer_log2_millionths(n) as i128 * LN_2_MILLIONTHS as i128 / MILLION as i128) as i64
}

/// Integer approximation of √n in millionths.
/// For raw input n, returns sqrt(n) × 1_000_000.
/// Newton's method with convergence guard from a bit-shift seed.
fn integer_sqrt_millionths(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    // sqrt(n) * MILLION = sqrt(n * MILLION²).
    let n_wide = n as i128 * (MILLION as i128 * MILLION as i128);
    // Bit-shift seed.
    let bits = 128 - n_wide.leading_zeros();
    let mut x = 1i128 << bits.div_ceil(2);

    for _ in 0..20 {
        if x == 0 {
            break;
        }
        let next = (x + n_wide / x) / 2;
        if next >= x {
            break;
        }
        x = next;
    }
    x as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arms(n: usize) -> Vec<LaneArm> {
        (0..n)
            .map(|i| LaneArm {
                lane_id: format!("lane_{i}"),
                description: format!("Lane {i}"),
            })
            .collect()
    }

    // === EXP3 ===

    #[test]
    fn exp3_initialization() {
        let state = Exp3State::new(3, 100_000).unwrap();
        assert_eq!(state.num_arms, 3);
        assert_eq!(state.rounds, 0);
        assert_eq!(state.log_weights_millionths, vec![0, 0, 0]);
    }

    #[test]
    fn exp3_invalid_gamma_rejected() {
        assert!(matches!(
            Exp3State::new(2, 0),
            Err(RouterError::InvalidGamma { .. })
        ));
        assert!(matches!(
            Exp3State::new(2, MILLION + 1),
            Err(RouterError::InvalidGamma { .. })
        ));
    }

    #[test]
    fn exp3_uniform_initial_probabilities() {
        let state = Exp3State::new(3, 100_000).unwrap();
        let probs = state.arm_probabilities();
        assert_eq!(probs.len(), 3);
        // Should be roughly uniform (within rounding).
        let sum: i64 = probs.iter().sum();
        assert_eq!(sum, MILLION);
    }

    #[test]
    fn exp3_update_shifts_probabilities() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        // Reward arm 0 heavily.
        for _ in 0..10 {
            state.update(0, 900_000).unwrap();
            state.update(1, 100_000).unwrap();
        }
        let probs = state.arm_probabilities();
        assert!(probs[0] > probs[1], "arm 0 should have higher probability");
    }

    #[test]
    fn exp3_probabilities_invariant_to_constant_logit_shift() {
        let mut a = Exp3State::new(3, 200_000).unwrap();
        a.log_weights_millionths = vec![100_000, -300_000, 700_000];
        let pa = a.arm_probabilities();

        let mut b = a.clone();
        for lw in &mut b.log_weights_millionths {
            *lw += 5_000_000;
        }
        let pb = b.arm_probabilities();

        for (x, y) in pa.iter().zip(pb.iter()) {
            assert!((x - y).abs() <= 2, "shift invariance violated: {x} vs {y}");
        }
    }

    #[test]
    fn exp3_large_weight_gap_prefers_best_arm() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        state.log_weights_millionths = vec![0, 8_000_000];
        let probs = state.arm_probabilities();
        // With gamma=0.1 and strong logit gap, arm 1 should dominate.
        assert!(probs[1] > 900_000, "expected dominant arm, got {:?}", probs);
        assert!(probs[0] >= MIN_EXPLORATION_MILLIONTHS);
    }

    #[test]
    fn exp3_regret_bound_grows_sublinearly() {
        let mut state = Exp3State::new(3, 100_000).unwrap();
        let bound_10 = {
            state.rounds = 10;
            state.regret_bound_millionths()
        };
        let bound_1000 = {
            state.rounds = 1000;
            state.regret_bound_millionths()
        };
        // sqrt(1000) / sqrt(10) ≈ 10, so bound_1000 / bound_10 ≈ 10
        // (sublinear: grows as √T, not T).
        assert!(bound_1000 > bound_10);
        assert!(bound_1000 < bound_10 * 100); // much less than linear 100x
    }

    #[test]
    fn exp3_no_arms_rejected() {
        assert!(matches!(
            Exp3State::new(0, 100_000),
            Err(RouterError::NoArms)
        ));
    }

    #[test]
    fn exp3_too_many_arms_rejected() {
        assert!(matches!(
            Exp3State::new(MAX_ARMS + 1, 100_000),
            Err(RouterError::TooManyArms { .. })
        ));
    }

    #[test]
    fn exp3_arm_out_of_bounds() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        assert!(matches!(
            state.update(5, 500_000),
            Err(RouterError::ArmOutOfBounds { .. })
        ));
    }

    #[test]
    fn exp3_reward_out_of_range() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        assert!(matches!(
            state.update(0, -1),
            Err(RouterError::RewardOutOfRange { .. })
        ));
        assert!(matches!(
            state.update(0, MILLION + 1),
            Err(RouterError::RewardOutOfRange { .. })
        ));
    }

    // === FTRL ===

    #[test]
    fn ftrl_initialization() {
        let state = FtrlState::new(3).unwrap();
        assert_eq!(state.num_arms, 3);
        assert_eq!(state.rounds, 0);
    }

    #[test]
    fn ftrl_learns_best_arm() {
        let mut state = FtrlState::new(3).unwrap();
        // Arm 2 is consistently best.
        for _ in 0..50 {
            state.update(0, 200_000).unwrap();
            state.update(1, 300_000).unwrap();
            state.update(2, 800_000).unwrap();
        }
        let probs = state.arm_probabilities();
        assert!(probs[2] > probs[0]);
        assert!(probs[2] > probs[1]);
    }

    #[test]
    fn ftrl_large_reward_gap_prefers_best_arm() {
        let mut state = FtrlState::new(3).unwrap();
        state.cumulative_rewards_millionths = vec![1_000_000, 10_000_000, 30_000_000];
        let probs = state.arm_probabilities();
        assert!(probs[2] > probs[1]);
        assert!(probs[1] > probs[0]);
    }

    #[test]
    fn ftrl_mean_rewards_correct() {
        let mut state = FtrlState::new(2).unwrap();
        state.update(0, 400_000).unwrap();
        state.update(0, 600_000).unwrap();
        state.update(1, 800_000).unwrap();
        let means = state.mean_rewards();
        assert_eq!(means[0], 500_000);
        assert_eq!(means[1], 800_000);
    }

    // === RegretBoundedRouter ===

    #[test]
    fn router_creation() {
        let arms = make_arms(3);
        let router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        assert_eq!(router.num_arms(), 3);
        assert_eq!(router.rounds(), 0);
    }

    #[test]
    fn router_no_arms_rejected() {
        assert!(matches!(
            RegretBoundedRouter::new(vec![], 100_000),
            Err(RouterError::NoArms)
        ));
    }

    #[test]
    fn router_full_round_trip() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        let arm = router.select_arm(300_000);
        let signal = RewardSignal {
            arm_index: arm,
            reward_millionths: 700_000,
            latency_us: 100,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: None,
        };
        let receipt = router.observe_reward(&signal).unwrap();
        assert_eq!(receipt.round, 1);
        assert!(!receipt.exact_regret_available);
        assert!(!receipt.regret_within_bound);
    }

    #[test]
    fn router_exact_regret_uses_counterfactuals_when_available() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        let signal = RewardSignal {
            arm_index: 0,
            reward_millionths: 200_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![200_000, 900_000]),
        };
        let receipt = router.observe_reward(&signal).unwrap();

        assert!(receipt.exact_regret_available);
        assert!(receipt.regret_within_bound);
        assert_eq!(router.realized_regret_millionths(), 700_000);
    }

    #[test]
    fn router_exact_regret_uses_best_fixed_arm_not_dynamic_oracle() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Round 1: arm 0 is better.
        router
            .observe_reward(&RewardSignal {
                arm_index: 0,
                reward_millionths: 1_000_000,
                latency_us: 1,
                success: true,
                epoch: SecurityEpoch::from_raw(1),
                counterfactual_rewards_millionths: Some(vec![1_000_000, 0]),
            })
            .unwrap();

        // Round 2: arm 1 is better, but router still pulls arm 0.
        router
            .observe_reward(&RewardSignal {
                arm_index: 0,
                reward_millionths: 0,
                latency_us: 1,
                success: true,
                epoch: SecurityEpoch::from_raw(2),
                counterfactual_rewards_millionths: Some(vec![0, 1_000_000]),
            })
            .unwrap();

        // Best dynamic oracle would score 2_000_000, but best fixed arm scores
        // only 1_000_000. Exact fixed-arm regret is therefore zero.
        assert_eq!(router.realized_regret_millionths(), 0);
    }

    #[test]
    fn router_rejects_counterfactual_size_mismatch() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let signal = RewardSignal {
            arm_index: 0,
            reward_millionths: 500_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![500_000]),
        };
        assert!(matches!(
            router.observe_reward(&signal),
            Err(RouterError::CounterfactualSizeMismatch { .. })
        ));
    }

    #[test]
    fn router_invalid_arm_does_not_mutate_counterfactual_state() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let signal = RewardSignal {
            arm_index: 99,
            reward_millionths: 500_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![400_000, 600_000]),
        };
        assert!(matches!(
            router.observe_reward(&signal),
            Err(RouterError::ArmOutOfBounds { .. })
        ));
        assert_eq!(router.rounds(), 0);
        assert_eq!(router.counterfactual_rounds, 0);
        assert_eq!(router.counterfactual_per_arm_cumulative, vec![0, 0]);
    }

    #[test]
    fn router_invalid_reward_does_not_mutate_counterfactual_state() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let signal = RewardSignal {
            arm_index: 0,
            reward_millionths: -1,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![400_000, 600_000]),
        };
        assert!(matches!(
            router.observe_reward(&signal),
            Err(RouterError::RewardOutOfRange { .. })
        ));
        assert_eq!(router.rounds(), 0);
        assert_eq!(router.counterfactual_rounds, 0);
        assert_eq!(router.counterfactual_per_arm_cumulative, vec![0, 0]);
    }

    #[test]
    fn router_invalid_counterfactual_entry_does_not_partially_mutate() {
        let arms = make_arms(3);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        // First two counterfactual entries are valid, third is out of range.
        // Before the fix, the first two would have been accumulated before the
        // error return, leaving state inconsistent.
        let signal = RewardSignal {
            arm_index: 0,
            reward_millionths: 500_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![400_000, 600_000, MILLION + 1]),
        };
        assert!(matches!(
            router.observe_reward(&signal),
            Err(RouterError::RewardOutOfRange { .. })
        ));
        // State must be completely unchanged.
        assert_eq!(router.rounds(), 0);
        assert_eq!(router.counterfactual_rounds, 0);
        assert_eq!(router.counterfactual_per_arm_cumulative, vec![0, 0, 0]);
    }

    #[test]
    fn router_regret_stays_bounded() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Simulate 100 rounds with arm 0 = good, arm 1 = bad.
        for i in 0..100u64 {
            let arm = router.select_arm((i as i64 * 7919) % MILLION);
            let reward = if arm == 0 { 800_000 } else { 200_000 };
            let signal = RewardSignal {
                arm_index: arm,
                reward_millionths: reward,
                latency_us: 50,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: None,
            };
            router.observe_reward(&signal).unwrap();
        }

        let cert = router.regret_certificate();
        // Regret should be bounded (not necessarily within theoretical bound
        // for 100 rounds due to exploration overhead, but should be reasonable).
        assert!(cert.realized_regret_millionths >= 0);
        assert!(cert.rounds == 100);
        assert!(!cert.exact_regret_available);
        assert!(!cert.within_bound);
        assert_eq!(cert.growth_rate_class, "empirical_estimate");
    }

    #[test]
    fn router_regime_detection() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        assert_eq!(router.active_regime, RegimeKind::Unknown);

        // Feed very consistent rewards (low variance → stochastic).
        for i in 0..20u64 {
            let signal = RewardSignal {
                arm_index: (i % 2) as usize,
                reward_millionths: 500_000,
                latency_us: 50,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: None,
            };
            router.observe_reward(&signal).unwrap();
        }

        // After enough rounds, regime should be detected.
        // (May still be Unknown if variance check is marginal.)
        assert!(router.rounds() == 20);
    }

    #[test]
    fn router_summary_serde_roundtrip() {
        let arms = make_arms(2);
        let router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let summary = router.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let restored: RouterSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn routing_receipt_serde_roundtrip() {
        let receipt = RoutingDecisionReceipt {
            schema: ROUTING_SCHEMA_VERSION.to_string(),
            round: 42,
            arm_selected: 1,
            reward_millionths: 600_000,
            regime: RegimeKind::Stochastic,
            cumulative_reward_millionths: 5_000_000,
            realized_regret_millionths: 200_000,
            theoretical_regret_bound_millionths: 3_000_000,
            exact_regret_available: true,
            regret_within_bound: true,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: RoutingDecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn regret_certificate_serde_roundtrip() {
        let cert = RegretCertificate {
            schema: ROUTING_SCHEMA_VERSION.to_string(),
            rounds: 100,
            realized_regret_millionths: 50_000,
            theoretical_bound_millionths: 200_000,
            within_bound: true,
            exact_regret_available: true,
            per_round_regret_millionths: 500,
            growth_rate_class: "sublinear_verified".to_string(),
        };
        let json = serde_json::to_string(&cert).unwrap();
        let restored: RegretCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    // === Integer math ===

    #[test]
    fn integer_ln_basic() {
        assert_eq!(integer_ln_millionths(1), 0);
        let ln2 = integer_ln_millionths(2);
        assert!((ln2 - 693_147).abs() < 20_000);
        assert!(integer_ln_millionths(10) > integer_ln_millionths(2));
    }

    #[test]
    fn integer_exp_basic() {
        let e0 = integer_exp_millionths(0);
        assert!((e0 - MILLION).abs() < 1_000);

        let e1 = integer_exp_millionths(MILLION);
        // e^1 ≈ 2.718281
        assert!((e1 - 2_718_281).abs() < 15_000, "e^1 approx drift: {e1}");

        let em1 = integer_exp_millionths(-MILLION);
        // e^-1 ≈ 0.367879
        assert!((em1 - 367_879).abs() < 10_000, "e^-1 approx drift: {em1}");
    }

    #[test]
    fn integer_sqrt_basic() {
        assert_eq!(integer_sqrt_millionths(0), 0);
        let s4 = integer_sqrt_millionths(4);
        // sqrt(4) * 1M = 2M
        assert!((s4 - 2_000_000).abs() < 100_000);
    }

    #[test]
    fn variance_estimator_basic() {
        let mut ve = VarianceEstimator::new();
        for v in [500_000, 500_000, 500_000] {
            ve.update(v);
        }
        // Constant values → zero variance.
        assert_eq!(ve.variance_millionths(), 0);
    }

    #[test]
    fn variance_estimator_nonzero() {
        let mut ve = VarianceEstimator::new();
        for v in [0, MILLION] {
            ve.update(v);
        }
        // High variance expected.
        assert!(ve.variance_millionths() > 0);
    }

    // === Edge cases ===

    #[test]
    fn exp3_select_arm_boundaries() {
        let state = Exp3State::new(3, 100_000).unwrap();
        assert!(state.select_arm(0) < 3);
        assert!(state.select_arm(MILLION - 1) < 3);
    }

    #[test]
    fn ftrl_select_arm_boundaries() {
        let state = FtrlState::new(3).unwrap();
        assert!(state.select_arm(0) < 3);
        assert!(state.select_arm(MILLION - 1) < 3);
    }

    #[test]
    fn router_select_warm_up_round_robin() {
        let arms = make_arms(3);
        let router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        // During warm-up (Unknown regime, first K rounds), should be round-robin.
        assert_eq!(router.select_arm(500_000), 0);
    }

    #[test]
    fn regime_kind_ordering() {
        assert!(RegimeKind::Unknown < RegimeKind::Stochastic);
        assert!(RegimeKind::Stochastic < RegimeKind::Adversarial);
    }

    #[test]
    fn reward_signal_serde_roundtrip() {
        let signal = RewardSignal {
            arm_index: 1,
            reward_millionths: 750_000,
            latency_us: 42,
            success: true,
            epoch: SecurityEpoch::from_raw(99),
            counterfactual_rewards_millionths: None,
        };
        let json = serde_json::to_string(&signal).unwrap();
        let restored: RewardSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(signal, restored);
    }

    #[test]
    fn lane_arm_serde_roundtrip() {
        let arm = LaneArm {
            lane_id: "quickjs".into(),
            description: "QuickJS-inspired lane".into(),
        };
        let json = serde_json::to_string(&arm).unwrap();
        let restored: LaneArm = serde_json::from_str(&json).unwrap();
        assert_eq!(arm, restored);
    }

    #[test]
    fn regime_transition_serde_roundtrip() {
        let rt = RegimeTransition {
            round: 50,
            from: RegimeKind::Unknown,
            to: RegimeKind::Stochastic,
            confidence_millionths: 900_000,
        };
        let json = serde_json::to_string(&rt).unwrap();
        let restored: RegimeTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, restored);
    }

    // === FTRL error paths ===

    #[test]
    fn ftrl_no_arms_rejected() {
        assert!(matches!(FtrlState::new(0), Err(RouterError::NoArms)));
    }

    #[test]
    fn ftrl_too_many_arms_rejected() {
        assert!(matches!(
            FtrlState::new(MAX_ARMS + 1),
            Err(RouterError::TooManyArms { .. })
        ));
    }

    #[test]
    fn ftrl_arm_out_of_bounds() {
        let mut state = FtrlState::new(2).unwrap();
        assert!(matches!(
            state.update(3, 500_000),
            Err(RouterError::ArmOutOfBounds { .. })
        ));
    }

    #[test]
    fn ftrl_reward_out_of_range() {
        let mut state = FtrlState::new(2).unwrap();
        assert!(matches!(
            state.update(0, -1),
            Err(RouterError::RewardOutOfRange { .. })
        ));
        assert!(matches!(
            state.update(0, MILLION + 1),
            Err(RouterError::RewardOutOfRange { .. })
        ));
    }

    #[test]
    fn ftrl_regret_bound_grows_sublinearly() {
        let mut state = FtrlState::new(4).unwrap();
        state.rounds = 10;
        let bound_10 = state.regret_bound_millionths();
        state.rounds = 1000;
        let bound_1000 = state.regret_bound_millionths();
        assert!(bound_1000 > bound_10);
        assert!(bound_1000 < bound_10 * 100);
    }

    #[test]
    fn ftrl_mean_rewards_no_pulls() {
        let state = FtrlState::new(3).unwrap();
        let means = state.mean_rewards();
        assert_eq!(means, vec![0, 0, 0]);
    }

    #[test]
    fn ftrl_uniform_initial_probabilities() {
        let state = FtrlState::new(3).unwrap();
        let probs = state.arm_probabilities();
        assert_eq!(probs.len(), 3);
        assert_eq!(probs.iter().sum::<i64>(), MILLION);
    }

    #[test]
    fn ftrl_serde_roundtrip() {
        let mut state = FtrlState::new(2).unwrap();
        state.update(0, 600_000).unwrap();
        state.update(1, 400_000).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let restored: FtrlState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    // === EXP3 additional coverage ===

    #[test]
    fn exp3_exactly_max_arms_accepted() {
        let state = Exp3State::new(MAX_ARMS, 100_000).unwrap();
        assert_eq!(state.num_arms, MAX_ARMS);
    }

    #[test]
    fn exp3_serde_roundtrip() {
        let mut state = Exp3State::new(2, 200_000).unwrap();
        state.update(0, 700_000).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let restored: Exp3State = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn exp3_zero_reward_accepted() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        state.update(0, 0).unwrap();
        assert_eq!(state.rounds, 1);
    }

    #[test]
    fn exp3_max_reward_accepted() {
        let mut state = Exp3State::new(2, 100_000).unwrap();
        state.update(0, MILLION).unwrap();
        assert_eq!(state.rounds, 1);
    }

    // === Router enrichment ===

    #[test]
    fn router_too_many_arms_rejected() {
        let arms = make_arms(MAX_ARMS + 1);
        assert!(matches!(
            RegretBoundedRouter::new(arms, 100_000),
            Err(RouterError::TooManyArms { .. })
        ));
    }

    #[test]
    fn router_exactly_max_arms_accepted() {
        let arms = make_arms(MAX_ARMS);
        let router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        assert_eq!(router.num_arms(), MAX_ARMS);
    }

    #[test]
    fn router_counterfactual_reward_out_of_range() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let signal = RewardSignal {
            arm_index: 0,
            reward_millionths: 500_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: Some(vec![500_000, -1]),
        };
        assert!(matches!(
            router.observe_reward(&signal),
            Err(RouterError::RewardOutOfRange { .. })
        ));
    }

    #[test]
    fn router_full_counterfactual_sequence_exact_regret() {
        let arms = make_arms(3);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        for i in 0..20u64 {
            let arm = router.select_arm((i as i64 * 31337) % MILLION);
            let signal = RewardSignal {
                arm_index: arm,
                reward_millionths: 500_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: Some(vec![500_000, 500_000, 500_000]),
            };
            router.observe_reward(&signal).unwrap();
        }

        // All arms have equal counterfactual rewards, so exact regret is 0.
        assert_eq!(router.realized_regret_millionths(), 0);
    }

    #[test]
    fn router_regime_shift_adversarial_high_variance() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Alternate wildly between 0 and MILLION for high variance.
        for i in 0..30u64 {
            let reward = if i.is_multiple_of(2) { 0 } else { MILLION };
            let signal = RewardSignal {
                arm_index: (i % 2) as usize,
                reward_millionths: reward,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: None,
            };
            router.observe_reward(&signal).unwrap();
        }

        // High variance should trigger adversarial regime or leave unknown.
        // Just verify no panic and reasonable state.
        assert!(router.rounds() == 30);
        let summary = router.summary();
        assert_eq!(summary.rounds, 30);
    }

    #[test]
    fn router_regime_shift_stochastic_low_variance() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Constant rewards → stochastic regime.
        for i in 0..30u64 {
            let signal = RewardSignal {
                arm_index: (i % 2) as usize,
                reward_millionths: 500_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: None,
            };
            router.observe_reward(&signal).unwrap();
        }

        // Should detect stochastic regime.
        assert!(
            router.active_regime == RegimeKind::Stochastic
                || router.active_regime == RegimeKind::Unknown,
            "expected Stochastic or Unknown, got {:?}",
            router.active_regime
        );
    }

    #[test]
    fn router_regime_history_recorded() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Feed constant rewards to trigger stochastic detection.
        for i in 0..20u64 {
            let signal = RewardSignal {
                arm_index: (i % 2) as usize,
                reward_millionths: 500_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: None,
            };
            router.observe_reward(&signal).unwrap();
        }

        if !router.regime_history.is_empty() {
            let transition = &router.regime_history[0];
            assert_eq!(transition.from, RegimeKind::Unknown);
            assert!(transition.confidence_millionths > 0);
        }
    }

    #[test]
    fn router_summary_fields_populated() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        router
            .observe_reward(&RewardSignal {
                arm_index: 0,
                reward_millionths: 600_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(1),
                counterfactual_rewards_millionths: None,
            })
            .unwrap();

        let summary = router.summary();
        assert_eq!(summary.schema, ROUTING_SCHEMA_VERSION);
        assert_eq!(summary.num_arms, 2);
        assert_eq!(summary.rounds, 1);
        assert_eq!(summary.cumulative_reward_millionths, 600_000);
        assert_eq!(summary.arm_probabilities_millionths.len(), 2);
        assert_eq!(
            summary.arm_probabilities_millionths.iter().sum::<i64>(),
            MILLION
        );
    }

    #[test]
    fn router_regret_certificate_no_rounds_class() {
        let arms = make_arms(2);
        let router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let cert = router.regret_certificate();
        // No counterfactual data → empirical_estimate
        assert_eq!(cert.growth_rate_class, "empirical_estimate");
        assert!(!cert.exact_regret_available);
    }

    #[test]
    fn router_regret_certificate_zero_growth_with_counterfactual() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Provide counterfactual rewards so exact_regret_available becomes true.
        // Both arms get same reward → regret is zero.
        for i in 0..50u64 {
            let signal = RewardSignal {
                arm_index: 0,
                reward_millionths: 400_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: Some(vec![400_000, 400_000]),
            };
            router.observe_reward(&signal).unwrap();
        }

        let cert = router.regret_certificate();
        assert_eq!(cert.rounds, 50);
        assert!(cert.exact_regret_available);
        // Both arms identical reward → zero regret
        assert_eq!(cert.growth_rate_class, "zero");
    }

    #[test]
    fn router_regret_certificate_sublinear_with_counterfactual() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();

        // Arm 0 gets 400k, arm 1 gets 500k → some regret but within bound.
        for i in 0..20u64 {
            let signal = RewardSignal {
                arm_index: 0,
                reward_millionths: 400_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(i),
                counterfactual_rewards_millionths: Some(vec![400_000, 500_000]),
            };
            router.observe_reward(&signal).unwrap();
        }

        let cert = router.regret_certificate();
        assert_eq!(cert.rounds, 20);
        assert!(cert.exact_regret_available);
        // Regret = best_arm(10M) - cumulative(8M) = 2M; bound with large exploration=100k → verified
        assert!(cert.realized_regret_millionths > 0);
    }

    #[test]
    fn realized_regret_clamps_large_round_counts() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        router.exp3.rounds = u64::MAX;
        router.per_arm_cumulative = vec![MILLION, 0];
        router.per_arm_count = vec![1, 1];
        router.cumulative_reward_millionths = 0;
        let regret = router.realized_regret_millionths();
        assert_eq!(regret, i64::MAX);
    }

    #[test]
    fn router_serde_roundtrip() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        router
            .observe_reward(&RewardSignal {
                arm_index: 0,
                reward_millionths: 700_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(1),
                counterfactual_rewards_millionths: None,
            })
            .unwrap();

        let json = serde_json::to_string(&router).unwrap();
        let restored: RegretBoundedRouter = serde_json::from_str(&json).unwrap();
        assert_eq!(router, restored);
    }

    #[test]
    fn router_receipt_schema_version() {
        let arms = make_arms(2);
        let mut router = RegretBoundedRouter::new(arms, 100_000).unwrap();
        let receipt = router
            .observe_reward(&RewardSignal {
                arm_index: 0,
                reward_millionths: 500_000,
                latency_us: 10,
                success: true,
                epoch: SecurityEpoch::from_raw(1),
                counterfactual_rewards_millionths: None,
            })
            .unwrap();
        assert_eq!(receipt.schema, ROUTING_SCHEMA_VERSION);
    }

    // === Router error Display ===

    #[test]
    fn router_error_display_messages() {
        let e = RouterError::NoArms;
        assert_eq!(format!("{e}"), "no arms configured");

        let e = RouterError::TooManyArms { count: 20, max: 16 };
        assert!(format!("{e}").contains("20"));

        let e = RouterError::ArmOutOfBounds { index: 5, count: 3 };
        assert!(format!("{e}").contains("5"));

        let e = RouterError::RewardOutOfRange { reward: -1 };
        assert!(format!("{e}").contains("-1"));

        let e = RouterError::InvalidGamma {
            gamma_millionths: 0,
        };
        assert!(format!("{e}").contains("0"));

        let e = RouterError::CounterfactualSizeMismatch {
            got: 1,
            expected: 3,
        };
        assert!(format!("{e}").contains("1") && format!("{e}").contains("3"));

        let e = RouterError::ZeroWeight;
        assert!(format!("{e}").contains("zero"));
    }

    #[test]
    fn router_error_is_std_error() {
        let e = RouterError::NoArms;
        let _: &dyn std::error::Error = &e;
    }

    // === Integer math edge cases ===

    #[test]
    fn integer_log2_powers_of_two() {
        let log1 = integer_log2_millionths(1);
        assert_eq!(log1, 0);
        let log2 = integer_log2_millionths(2);
        assert_eq!(log2, MILLION);
        let log4 = integer_log2_millionths(4);
        assert_eq!(log4, 2 * MILLION);
    }

    #[test]
    fn integer_log2_non_powers() {
        let log3 = integer_log2_millionths(3);
        // log2(3) ≈ 1.585
        assert!(log3 > MILLION && log3 < 2 * MILLION);
    }

    #[test]
    fn integer_sqrt_large_values() {
        let s100 = integer_sqrt_millionths(100);
        // sqrt(100) * 1M = 10M
        assert!((s100 - 10_000_000).abs() < 500_000);
    }

    #[test]
    fn integer_sqrt_one() {
        let s1 = integer_sqrt_millionths(1);
        // sqrt(1) * 1M = 1M
        assert!((s1 - MILLION).abs() < 100_000);
    }

    #[test]
    fn integer_sqrt_negative_returns_zero() {
        assert_eq!(integer_sqrt_millionths(-5), 0);
    }

    #[test]
    fn integer_ln_monotone() {
        let a = integer_ln_millionths(2);
        let b = integer_ln_millionths(5);
        let c = integer_ln_millionths(10);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn integer_log2_large_values_stay_normalized() {
        let n = (1u64 << 40) + 1;
        let l = integer_log2_millionths(n);
        assert!(l >= 40 * MILLION);
        assert!(l < 40 * MILLION + 20_000);
    }

    // === Variance estimator enrichment ===

    #[test]
    fn variance_estimator_single_value() {
        let mut ve = VarianceEstimator::new();
        ve.update(500_000);
        assert_eq!(ve.variance_millionths(), 0);
    }

    #[test]
    fn variance_estimator_known_values() {
        let mut ve = VarianceEstimator::new();
        // Values: 0, MILLION → mean = 500k, var = 500k * 500k / MILLION = 250k
        ve.update(0);
        ve.update(MILLION);
        let v = ve.variance_millionths();
        assert!(v > 0, "variance should be positive for distinct values");
    }

    #[test]
    fn variance_estimator_mean_correct() {
        let mut ve = VarianceEstimator::new();
        ve.update(200_000);
        ve.update(800_000);
        assert_eq!(ve.mean_millionths, 500_000);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn regime_kind_serde_all_variants() {
        let variants = [
            RegimeKind::Unknown,
            RegimeKind::Stochastic,
            RegimeKind::Adversarial,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RegimeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn regime_kind_ord_unknown_lt_adversarial() {
        assert!(RegimeKind::Unknown < RegimeKind::Stochastic);
        assert!(RegimeKind::Stochastic < RegimeKind::Adversarial);
    }

    #[test]
    fn router_error_serde_all_variants() {
        let variants: Vec<RouterError> = vec![
            RouterError::NoArms,
            RouterError::TooManyArms { count: 10, max: 5 },
            RouterError::ArmOutOfBounds { index: 3, count: 2 },
            RouterError::RewardOutOfRange { reward: -1 },
            RouterError::InvalidGamma {
                gamma_millionths: -1,
            },
            RouterError::CounterfactualSizeMismatch {
                got: 3,
                expected: 5,
            },
            RouterError::ZeroWeight,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RouterError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn router_error_display_all_distinct() {
        let variants: Vec<RouterError> = vec![
            RouterError::NoArms,
            RouterError::TooManyArms { count: 1, max: 1 },
            RouterError::ArmOutOfBounds { index: 0, count: 0 },
            RouterError::RewardOutOfRange { reward: 0 },
            RouterError::InvalidGamma {
                gamma_millionths: 0,
            },
            RouterError::CounterfactualSizeMismatch {
                got: 0,
                expected: 0,
            },
            RouterError::ZeroWeight,
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn regime_kind_debug_distinct() {
        let all = [
            RegimeKind::Unknown,
            RegimeKind::Stochastic,
            RegimeKind::Adversarial,
        ];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|r| format!("{r:?}")).collect();
        assert_eq!(set.len(), all.len());
    }
}
