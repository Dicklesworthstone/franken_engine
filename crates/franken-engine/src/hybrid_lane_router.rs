//! Hybrid Lane Router (FRX-04.3)
//!
//! Risk-bounded adaptive controller that routes work between JS and WASM
//! runtime lanes. Provides:
//! - Baseline-safe policy (always available) plus adaptive policy (regret-bounded).
//! - Expected-loss selector constrained by compatibility and tail-latency risk budgets.
//! - Conformal validity checks and anytime evidence processes for online safety.
//! - Regime-shift/change-point monitoring with automatic demotion to safe policy.
//! - Full decision transparency: equation terms, values, chosen action, alternatives.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn router_schema() -> SchemaId {
    SchemaId::from_definition(b"hybrid_lane_router-v1")
}

/// Fixed-point multiplier: 1_000_000 ≡ 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Lane selection
// ---------------------------------------------------------------------------

/// Which runtime lane to route a work unit to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneChoice {
    /// Lightweight JS-side reactive graph (small/medium workloads).
    Js,
    /// WASM-compiled signal graph (large/high-churn workloads).
    Wasm,
}

impl LaneChoice {
    pub const ALL: [Self; 2] = [Self::Js, Self::Wasm];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Js => "js",
            Self::Wasm => "wasm",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Js => 0,
            Self::Wasm => 1,
        }
    }

    pub fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Js),
            1 => Some(Self::Wasm),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Routing policy
// ---------------------------------------------------------------------------

/// Which policy the router is currently following.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoutingPolicy {
    /// Always route to the baseline-safe lane (conservative fallback).
    Conservative,
    /// Use regret-bounded adaptive selection.
    Adaptive,
}

/// Reason the router demoted from adaptive to conservative.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DemotionReason {
    /// Change-point detector fired.
    ChangePointDetected {
        cusum_stat_millionths: i64,
        threshold_millionths: i64,
    },
    /// Conformal validity check failed.
    ConformalViolation {
        coverage_millionths: i64,
        target_millionths: i64,
    },
    /// Regret bound exceeded.
    RegretExceeded {
        realized_millionths: i64,
        bound_millionths: i64,
    },
    /// Tail-latency budget exhausted.
    TailLatencyBudgetExhausted {
        observed_p99_us: u64,
        budget_us: u64,
    },
    /// Compatibility risk budget exhausted.
    CompatibilityBudgetExhausted { errors_observed: u64, budget: u64 },
    /// Manual demotion requested.
    ManualDemotion,
}

/// Record of a policy transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTransition {
    pub round: u64,
    pub from: RoutingPolicy,
    pub to: RoutingPolicy,
    pub reason: Option<DemotionReason>,
}

// ---------------------------------------------------------------------------
// Evidence / observation
// ---------------------------------------------------------------------------

/// Observation after routing a work unit to a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneObservation {
    /// Which lane was used.
    pub lane: LaneChoice,
    /// Latency in microseconds.
    pub latency_us: u64,
    /// Whether the lane completed successfully.
    pub success: bool,
    /// Number of DOM ops emitted.
    pub dom_ops: u32,
    /// Number of signals evaluated.
    pub signals_evaluated: u32,
    /// Whether the lane entered safe mode during this flush.
    pub safe_mode_entered: bool,
    /// Compatibility errors detected (e.g. mismatched output).
    pub compatibility_errors: u32,
}

// ---------------------------------------------------------------------------
// Conformal validity
// ---------------------------------------------------------------------------

/// Configuration for conformal validity checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalConfig {
    /// Target coverage level in millionths (e.g. 900_000 = 90%).
    pub target_coverage_millionths: i64,
    /// Minimum observations before checking validity.
    pub min_observations: u64,
    /// Window size for rolling coverage computation.
    pub window_size: u64,
}

impl ConformalConfig {
    pub fn default_config() -> Self {
        Self {
            target_coverage_millionths: 900_000,
            min_observations: 20,
            window_size: 100,
        }
    }
}

/// State for conformal validity monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformalState {
    pub config: ConformalConfig,
    /// Rolling window of "in-bounds" indicators (1 = in bounds, 0 = out).
    pub window: Vec<i64>,
    pub total_observations: u64,
    pub total_in_bounds: u64,
}

impl ConformalState {
    pub fn new(config: ConformalConfig) -> Self {
        Self {
            config,
            window: Vec::new(),
            total_observations: 0,
            total_in_bounds: 0,
        }
    }

    /// Record whether an observation was within prediction bounds.
    pub fn observe(&mut self, in_bounds: bool) {
        let val = if in_bounds { MILLION } else { 0 };
        self.total_observations += 1;
        if in_bounds {
            self.total_in_bounds += 1;
        }

        self.window.push(val);
        if self.window.len() > self.config.window_size as usize {
            self.window.remove(0);
        }
    }

    /// Current rolling coverage in millionths.
    pub fn coverage_millionths(&self) -> i64 {
        if self.window.is_empty() {
            return MILLION; // vacuously valid
        }
        let sum: i64 = self.window.iter().sum();
        sum / self.window.len() as i64
    }

    /// Whether conformal validity holds.
    pub fn is_valid(&self) -> bool {
        if self.total_observations < self.config.min_observations {
            return true; // insufficient data — assume valid
        }
        self.coverage_millionths() >= self.config.target_coverage_millionths
    }

    /// Check validity and return a demotion reason if violated.
    pub fn check(&self) -> Option<DemotionReason> {
        if self.is_valid() {
            return None;
        }
        Some(DemotionReason::ConformalViolation {
            coverage_millionths: self.coverage_millionths(),
            target_millionths: self.config.target_coverage_millionths,
        })
    }
}

// ---------------------------------------------------------------------------
// Change-point monitor (CUSUM)
// ---------------------------------------------------------------------------

/// Configuration for CUSUM change-point detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePointConfig {
    /// CUSUM threshold in millionths — trigger when exceeded.
    pub threshold_millionths: i64,
    /// Drift parameter in millionths (slack before accumulation).
    pub drift_millionths: i64,
    /// Minimum observations before the monitor can fire.
    pub min_observations: u64,
}

impl ChangePointConfig {
    pub fn default_config() -> Self {
        Self {
            threshold_millionths: 2_000_000,
            drift_millionths: 50_000,
            min_observations: 10,
        }
    }
}

/// CUSUM change-point detector state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePointMonitor {
    pub config: ChangePointConfig,
    /// Upper CUSUM statistic (detects upward shift in loss).
    pub cusum_upper_millionths: i64,
    /// Lower CUSUM statistic (detects downward shift).
    pub cusum_lower_millionths: i64,
    /// Running mean of observations in millionths.
    pub running_mean_millionths: i64,
    pub observation_count: u64,
}

impl ChangePointMonitor {
    pub fn new(config: ChangePointConfig) -> Self {
        Self {
            config,
            cusum_upper_millionths: 0,
            cusum_lower_millionths: 0,
            running_mean_millionths: 0,
            observation_count: 0,
        }
    }

    /// Feed an observation (e.g. loss or latency) in millionths.
    pub fn observe(&mut self, value_millionths: i64) {
        self.observation_count += 1;

        // Update running mean incrementally
        let n = self.observation_count as i64;
        self.running_mean_millionths =
            self.running_mean_millionths + (value_millionths - self.running_mean_millionths) / n;

        // CUSUM update
        let deviation = value_millionths - self.running_mean_millionths;
        self.cusum_upper_millionths =
            (self.cusum_upper_millionths + deviation - self.config.drift_millionths).max(0);
        self.cusum_lower_millionths =
            (self.cusum_lower_millionths - deviation - self.config.drift_millionths).max(0);
    }

    /// Whether a change point has been detected.
    pub fn is_triggered(&self) -> bool {
        if self.observation_count < self.config.min_observations {
            return false;
        }
        // Fail-closed contract: non-positive thresholds intentionally force
        // deterministic demotion once minimum observation count is satisfied.
        if self.config.threshold_millionths <= 0 {
            return true;
        }
        self.cusum_upper_millionths >= self.config.threshold_millionths
            || self.cusum_lower_millionths >= self.config.threshold_millionths
    }

    /// Check and return demotion reason if triggered.
    pub fn check(&self) -> Option<DemotionReason> {
        if !self.is_triggered() {
            return None;
        }
        let stat = self.cusum_upper_millionths.max(self.cusum_lower_millionths);
        Some(DemotionReason::ChangePointDetected {
            cusum_stat_millionths: stat,
            threshold_millionths: self.config.threshold_millionths,
        })
    }

    /// Reset accumulators (after policy switch).
    pub fn reset(&mut self) {
        self.cusum_upper_millionths = 0;
        self.cusum_lower_millionths = 0;
        // Keep running mean and count for continuity
    }
}

// ---------------------------------------------------------------------------
// Risk budgets
// ---------------------------------------------------------------------------

/// Risk budgets constraining the adaptive policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBudget {
    /// Maximum p99 tail latency in microseconds.
    pub tail_latency_budget_us: u64,
    /// Maximum cumulative compatibility errors before demotion.
    pub compatibility_error_budget: u64,
    /// Maximum regret (in millionths) before demotion.
    pub regret_budget_millionths: i64,
}

impl RiskBudget {
    pub fn default_budget() -> Self {
        Self {
            tail_latency_budget_us: 16_000, // 16ms (one frame)
            compatibility_error_budget: 5,
            regret_budget_millionths: 500_000, // 0.5
        }
    }
}

/// Tracked risk consumption against budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAccumulator {
    /// Sorted latency observations for percentile estimation.
    pub latencies_us: Vec<u64>,
    /// Total compatibility errors observed.
    pub compatibility_errors: u64,
    /// Cumulative regret in millionths.
    pub cumulative_regret_millionths: i64,
    /// Per-lane cumulative rewards in millionths.
    pub cumulative_rewards: BTreeMap<LaneChoice, i64>,
    /// Number of pulls per lane.
    pub lane_pulls: BTreeMap<LaneChoice, u64>,
    /// Best single-lane cumulative reward in millionths.
    pub best_lane_reward_millionths: i64,
}

impl Default for RiskAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskAccumulator {
    pub fn new() -> Self {
        Self {
            latencies_us: Vec::new(),
            compatibility_errors: 0,
            cumulative_regret_millionths: 0,
            cumulative_rewards: BTreeMap::new(),
            lane_pulls: BTreeMap::new(),
            best_lane_reward_millionths: 0,
        }
    }

    /// Record a routing observation.
    pub fn record(&mut self, obs: &LaneObservation, reward_millionths: i64) {
        self.latencies_us.push(obs.latency_us);
        if self.latencies_us.len() > 1000 {
            self.latencies_us.remove(0);
        }
        self.compatibility_errors += obs.compatibility_errors as u64;

        let lane_reward = self.cumulative_rewards.entry(obs.lane).or_insert(0);
        *lane_reward += reward_millionths;

        let pulls = self.lane_pulls.entry(obs.lane).or_insert(0);
        *pulls += 1;

        // Estimate best mean reward across all pulled lanes
        let best_empirical_mean = self
            .cumulative_rewards
            .iter()
            .filter_map(|(lane, &total)| {
                let p = *self.lane_pulls.get(lane).unwrap_or(&0);
                if p > 0 { Some(total / p as i64) } else { None }
            })
            .max()
            .unwrap_or(0);

        // Update best lane (for legacy compatibility, keep it as the max total, though we don't strictly use it for regret now)
        self.best_lane_reward_millionths =
            self.cumulative_rewards.values().copied().max().unwrap_or(0);

        // Regret = best_mean * n - our_total
        let our_total: i64 = self.cumulative_rewards.values().sum();
        let n: i64 = self.lane_pulls.values().copied().sum::<u64>() as i64;
        if n > 0 {
            self.cumulative_regret_millionths = best_empirical_mean * n - our_total;
        }
    }

    /// Estimate p99 latency in microseconds.
    pub fn p99_latency_us(&self) -> u64 {
        if self.latencies_us.is_empty() {
            return 0;
        }
        let mut sorted = self.latencies_us.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() - 1) * 99) / 100;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Check all risk budgets and return first violation.
    pub fn check_budgets(&self, budget: &RiskBudget) -> Option<DemotionReason> {
        let p99 = self.p99_latency_us();
        if p99 > budget.tail_latency_budget_us {
            return Some(DemotionReason::TailLatencyBudgetExhausted {
                observed_p99_us: p99,
                budget_us: budget.tail_latency_budget_us,
            });
        }
        if self.compatibility_errors > budget.compatibility_error_budget {
            return Some(DemotionReason::CompatibilityBudgetExhausted {
                errors_observed: self.compatibility_errors,
                budget: budget.compatibility_error_budget,
            });
        }
        if self.cumulative_regret_millionths > budget.regret_budget_millionths {
            return Some(DemotionReason::RegretExceeded {
                realized_millionths: self.cumulative_regret_millionths,
                bound_millionths: budget.regret_budget_millionths,
            });
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Adaptive lane weights (EXP3-style)
// ---------------------------------------------------------------------------

/// EXP3-style adaptive weight state for two lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveWeights {
    /// Log-weights in millionths (one per lane).
    pub log_weights_millionths: Vec<i64>,
    /// Exploration rate in millionths (0, MILLION].
    pub gamma_millionths: i64,
    /// Learning rate in millionths.
    pub eta_millionths: i64,
    pub rounds: u64,
}

impl Default for AdaptiveWeights {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveWeights {
    /// Default exploration = 10%, learning rate = 100_000 (0.1).
    pub fn new() -> Self {
        Self {
            log_weights_millionths: vec![0, 0],
            gamma_millionths: 100_000,
            eta_millionths: 100_000,
            rounds: 0,
        }
    }

    /// Select a lane given a deterministic random value in [0, MILLION).
    pub fn select(&self, random_millionths: i64) -> LaneChoice {
        let weights = self.probabilities_millionths();
        if random_millionths < weights[0] {
            LaneChoice::Js
        } else {
            LaneChoice::Wasm
        }
    }

    /// Probability of each lane in millionths (sums to MILLION).
    pub fn probabilities_millionths(&self) -> Vec<i64> {
        let max_w = self
            .log_weights_millionths
            .iter()
            .copied()
            .max()
            .unwrap_or(0);

        // exp(w - max) in millionths for numerical stability
        let exps: Vec<i64> = self
            .log_weights_millionths
            .iter()
            .map(|w| exp_millionths(w - max_w))
            .collect();

        let sum: i64 = exps.iter().sum();
        if sum == 0 {
            return vec![MILLION / 2, MILLION / 2];
        }

        // Mix with uniform exploration
        let k = self.log_weights_millionths.len() as i64;
        let uniform = MILLION / k;
        let exploit_weight = MILLION - self.gamma_millionths;

        exps.iter()
            .map(|e| {
                let exploit_part = (exploit_weight * (e * MILLION / sum)) / MILLION;
                let explore_part = (self.gamma_millionths * uniform) / MILLION;
                (exploit_part + explore_part).clamp(0, MILLION)
            })
            .collect()
    }

    /// Update weights after observing reward for chosen lane.
    pub fn update(&mut self, lane: LaneChoice, reward_millionths: i64) {
        self.rounds += 1;
        let idx = lane.index();
        let probs = self.probabilities_millionths();
        let p = probs[idx].max(1); // avoid division by zero

        // Importance-weighted reward
        let iw_reward = (reward_millionths * MILLION) / p;
        let scaled = (self.eta_millionths * iw_reward) / MILLION;

        self.log_weights_millionths[idx] += scaled;

        // Clamp to prevent overflow
        for w in &mut self.log_weights_millionths {
            *w = (*w).clamp(-10 * MILLION, 10 * MILLION);
        }
    }
}

/// Fixed-point exp approximation: exp(x_millionths / MILLION) * MILLION.
/// Uses Taylor series: 1 + x + x²/2 + x³/6.
fn exp_millionths(x_millionths: i64) -> i64 {
    // Clamp to avoid overflow
    let x = x_millionths.clamp(-3 * MILLION, 3 * MILLION);
    let x_norm = x; // already in millionths

    let term0 = MILLION;
    let term1 = x_norm;
    let term2 = (x_norm * x_norm) / (2 * MILLION);
    let term3 = (x_norm * x_norm / MILLION * x_norm) / (6 * MILLION);

    (term0 + term1 + term2 + term3).max(1) // never zero
}

// ---------------------------------------------------------------------------
// Reward computation
// ---------------------------------------------------------------------------

/// Compute a reward signal from a lane observation.
/// Higher is better. Normalised to [0, MILLION].
pub fn compute_reward(obs: &LaneObservation, latency_baseline_us: u64) -> i64 {
    if !obs.success {
        return 0;
    }
    if obs.safe_mode_entered {
        return 100_000; // 0.1 — penalise but non-zero
    }
    if obs.compatibility_errors > 0 {
        return 200_000; // 0.2
    }

    // Latency reward: 1.0 at 0 latency, decays toward 0 at 2× baseline
    let ratio = if latency_baseline_us == 0 {
        0i64
    } else {
        ((obs.latency_us as i64) * MILLION) / (latency_baseline_us as i64)
    };
    let latency_reward = (MILLION - ratio / 2).clamp(0, MILLION);

    // Throughput bonus: more DOM ops = better (up to 0.2 bonus)
    let throughput_bonus = ((obs.dom_ops as i64) * 200_000 / 1000).min(200_000);

    ((latency_reward + throughput_bonus) * MILLION / (MILLION + 200_000)).clamp(0, MILLION)
}

// ---------------------------------------------------------------------------
// Decision trace (transparency)
// ---------------------------------------------------------------------------

/// Full decision trace for a single routing round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecisionTrace {
    pub round: u64,
    pub policy: RoutingPolicy,
    pub chosen_lane: LaneChoice,
    pub rejected_lanes: Vec<LaneChoice>,
    pub probabilities_millionths: Vec<i64>,
    pub random_draw_millionths: Option<i64>,
    pub reward_millionths: Option<i64>,
    pub cumulative_regret_millionths: i64,
    pub p99_latency_us: u64,
    pub compatibility_errors: u64,
    pub conformal_coverage_millionths: i64,
    pub cusum_stat_millionths: i64,
    pub demotion_reason: Option<DemotionReason>,
}

impl RoutingDecisionTrace {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "decision-round-{}-lane-{}",
            self.round,
            self.chosen_lane.as_str()
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hybrid-router",
            &router_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for decision trace")
    }
}

// ---------------------------------------------------------------------------
// Router configuration
// ---------------------------------------------------------------------------

/// Configuration for the hybrid lane router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Which lane is the baseline-safe default.
    pub baseline_lane: LaneChoice,
    /// Risk budget thresholds.
    pub risk_budget: RiskBudget,
    /// Conformal validity configuration.
    pub conformal: ConformalConfig,
    /// Change-point detection configuration.
    pub change_point: ChangePointConfig,
    /// Latency baseline in microseconds for reward computation.
    pub latency_baseline_us: u64,
    /// Maximum rounds in adaptive mode before mandatory re-evaluation.
    pub adaptive_horizon: u64,
}

impl RouterConfig {
    pub fn default_config() -> Self {
        Self {
            baseline_lane: LaneChoice::Js,
            risk_budget: RiskBudget::default_budget(),
            conformal: ConformalConfig::default_config(),
            change_point: ChangePointConfig::default_config(),
            latency_baseline_us: 8_000, // 8ms
            adaptive_horizon: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// Router errors
// ---------------------------------------------------------------------------

/// Errors from the hybrid lane router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterError {
    /// Already in conservative mode, cannot demote further.
    AlreadyConservative,
    /// Invalid random draw value.
    InvalidRandomDraw { value: i64 },
    /// Config validation failure.
    InvalidConfig { reason: String },
}

// ---------------------------------------------------------------------------
// Main router
// ---------------------------------------------------------------------------

/// Hybrid lane router: risk-bounded adaptive controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridLaneRouter {
    pub config: RouterConfig,
    pub policy: RoutingPolicy,
    pub weights: AdaptiveWeights,
    pub conformal: ConformalState,
    pub change_point: ChangePointMonitor,
    pub risk: RiskAccumulator,
    pub round: u64,
    pub policy_transitions: Vec<PolicyTransition>,
    pub decision_log: Vec<RoutingDecisionTrace>,
    pub consecutive_conservative_rounds: u64,
    pub total_js_routes: u64,
    pub total_wasm_routes: u64,
}

impl HybridLaneRouter {
    /// Create a new router with the given configuration.
    pub fn new(config: RouterConfig) -> Self {
        let conformal = ConformalState::new(config.conformal.clone());
        let change_point = ChangePointMonitor::new(config.change_point.clone());
        Self {
            config,
            policy: RoutingPolicy::Conservative,
            weights: AdaptiveWeights::new(),
            conformal,
            change_point,
            risk: RiskAccumulator::new(),
            round: 0,
            policy_transitions: Vec::new(),
            decision_log: Vec::new(),
            consecutive_conservative_rounds: 0,
            total_js_routes: 0,
            total_wasm_routes: 0,
        }
    }

    /// Create a router with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RouterConfig::default_config())
    }

    /// Select the next lane to route to.
    ///
    /// `random_millionths`: deterministic random value in [0, MILLION) for adaptive selection.
    /// Ignored when in conservative mode.
    pub fn select_lane(&self, random_millionths: i64) -> LaneChoice {
        match self.policy {
            RoutingPolicy::Conservative => self.config.baseline_lane,
            RoutingPolicy::Adaptive => self.weights.select(random_millionths),
        }
    }

    /// Record an observation after routing and update all monitors.
    ///
    /// Returns the decision trace and any demotion that occurred.
    pub fn observe(
        &mut self,
        lane: LaneChoice,
        obs: &LaneObservation,
        random_draw_millionths: Option<i64>,
    ) -> RoutingDecisionTrace {
        let reward = compute_reward(obs, self.config.latency_baseline_us);

        // Update adaptive weights
        self.weights.update(lane, reward);

        // Update risk accumulator
        self.risk.record(obs, reward);

        // Update conformal validity (in_bounds = success && no compat errors)
        let in_bounds = obs.success && obs.compatibility_errors == 0 && !obs.safe_mode_entered;
        self.conformal.observe(in_bounds);

        // Update change-point monitor with loss (inverted reward)
        let loss_millionths = MILLION - reward;
        self.change_point.observe(loss_millionths);

        // Track per-lane counts
        match lane {
            LaneChoice::Js => self.total_js_routes += 1,
            LaneChoice::Wasm => self.total_wasm_routes += 1,
        }

        // Check for demotion triggers
        let demotion_reason = self.check_demotion_triggers();

        // Build trace
        let rejected: Vec<LaneChoice> = LaneChoice::ALL
            .iter()
            .copied()
            .filter(|l| *l != lane)
            .collect();

        let trace = RoutingDecisionTrace {
            round: self.round,
            policy: self.policy,
            chosen_lane: lane,
            rejected_lanes: rejected,
            probabilities_millionths: self.weights.probabilities_millionths(),
            random_draw_millionths,
            reward_millionths: Some(reward),
            cumulative_regret_millionths: self.risk.cumulative_regret_millionths,
            p99_latency_us: self.risk.p99_latency_us(),
            compatibility_errors: self.risk.compatibility_errors,
            conformal_coverage_millionths: self.conformal.coverage_millionths(),
            cusum_stat_millionths: self
                .change_point
                .cusum_upper_millionths
                .max(self.change_point.cusum_lower_millionths),
            demotion_reason: demotion_reason.clone(),
        };

        // Apply demotion if triggered
        if let Some(reason) = demotion_reason {
            self.demote(reason);
        }

        // Track conservative rounds
        if self.policy == RoutingPolicy::Conservative {
            self.consecutive_conservative_rounds += 1;
        } else {
            self.consecutive_conservative_rounds = 0;
        }

        self.round += 1;

        // Trim decision log to last 1000 entries
        if self.decision_log.len() >= 1000 {
            self.decision_log.remove(0);
        }
        self.decision_log.push(trace.clone());

        trace
    }

    /// Check all demotion triggers. Returns the first reason found.
    fn check_demotion_triggers(&self) -> Option<DemotionReason> {
        if self.policy != RoutingPolicy::Adaptive {
            return None;
        }

        // 1. Change-point detection
        if let Some(reason) = self.change_point.check() {
            return Some(reason);
        }

        // 2. Conformal validity
        if let Some(reason) = self.conformal.check() {
            return Some(reason);
        }

        // 3. Risk budgets
        if let Some(reason) = self.risk.check_budgets(&self.config.risk_budget) {
            return Some(reason);
        }

        None
    }

    /// Demote to conservative policy.
    fn demote(&mut self, reason: DemotionReason) {
        if self.policy == RoutingPolicy::Conservative {
            return;
        }
        self.policy_transitions.push(PolicyTransition {
            round: self.round,
            from: RoutingPolicy::Adaptive,
            to: RoutingPolicy::Conservative,
            reason: Some(reason),
        });
        self.policy = RoutingPolicy::Conservative;
        self.change_point.reset();
    }

    /// Promote to adaptive policy (after conservative stabilisation).
    pub fn promote_to_adaptive(&mut self) -> Result<(), RouterError> {
        if self.policy == RoutingPolicy::Adaptive {
            return Ok(());
        }
        self.policy_transitions.push(PolicyTransition {
            round: self.round,
            from: RoutingPolicy::Conservative,
            to: RoutingPolicy::Adaptive,
            reason: None,
        });
        self.policy = RoutingPolicy::Adaptive;
        self.consecutive_conservative_rounds = 0;
        self.change_point.reset();
        Ok(())
    }

    /// Request manual demotion.
    pub fn manual_demote(&mut self) -> Result<(), RouterError> {
        if self.policy == RoutingPolicy::Conservative {
            return Err(RouterError::AlreadyConservative);
        }
        self.demote(DemotionReason::ManualDemotion);
        Ok(())
    }

    /// Current routing probabilities in millionths.
    pub fn lane_probabilities(&self) -> BTreeMap<LaneChoice, i64> {
        let probs = self.weights.probabilities_millionths();
        let mut map = BTreeMap::new();
        for lane in &LaneChoice::ALL {
            let p = match self.policy {
                RoutingPolicy::Conservative => {
                    if *lane == self.config.baseline_lane {
                        MILLION
                    } else {
                        0
                    }
                }
                RoutingPolicy::Adaptive => probs.get(lane.index()).copied().unwrap_or(0),
            };
            map.insert(*lane, p);
        }
        map
    }

    /// Summary statistics.
    pub fn summary(&self) -> RouterSummary {
        RouterSummary {
            round: self.round,
            policy: self.policy,
            total_js_routes: self.total_js_routes,
            total_wasm_routes: self.total_wasm_routes,
            p99_latency_us: self.risk.p99_latency_us(),
            cumulative_regret_millionths: self.risk.cumulative_regret_millionths,
            compatibility_errors: self.risk.compatibility_errors,
            conformal_coverage_millionths: self.conformal.coverage_millionths(),
            policy_transitions: self.policy_transitions.len() as u64,
            consecutive_conservative_rounds: self.consecutive_conservative_rounds,
        }
    }

    /// Derive a stable ID for this router state.
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("hybrid-router-round-{}", self.round);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hybrid-router",
            &router_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for router")
    }
}

/// Summary of router state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterSummary {
    pub round: u64,
    pub policy: RoutingPolicy,
    pub total_js_routes: u64,
    pub total_wasm_routes: u64,
    pub p99_latency_us: u64,
    pub cumulative_regret_millionths: i64,
    pub compatibility_errors: u64,
    pub conformal_coverage_millionths: i64,
    pub policy_transitions: u64,
    pub consecutive_conservative_rounds: u64,
}

impl RouterSummary {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("router-summary-round-{}", self.round);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hybrid-router",
            &router_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for summary")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- LaneChoice --

    #[test]
    fn lane_choice_as_str() {
        assert_eq!(LaneChoice::Js.as_str(), "js");
        assert_eq!(LaneChoice::Wasm.as_str(), "wasm");
    }

    #[test]
    fn lane_choice_index_roundtrip() {
        for lane in &LaneChoice::ALL {
            assert_eq!(LaneChoice::from_index(lane.index()), Some(*lane));
        }
        assert_eq!(LaneChoice::from_index(99), None);
    }

    #[test]
    fn lane_choice_ordering() {
        assert!(LaneChoice::Js < LaneChoice::Wasm);
    }

    #[test]
    fn lane_choice_serde_roundtrip() {
        let lane = LaneChoice::Wasm;
        let json = serde_json::to_string(&lane).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }

    // -- exp_millionths --

    #[test]
    fn exp_zero_is_million() {
        assert_eq!(exp_millionths(0), MILLION);
    }

    #[test]
    fn exp_positive_grows() {
        assert!(exp_millionths(500_000) > MILLION);
    }

    #[test]
    fn exp_negative_shrinks() {
        assert!(exp_millionths(-500_000) < MILLION);
    }

    #[test]
    fn exp_clamps_extreme() {
        // Very large values shouldn't overflow
        let big = exp_millionths(10 * MILLION);
        assert!(big > 0);
        let small = exp_millionths(-10 * MILLION);
        assert!(small > 0);
    }

    // -- AdaptiveWeights --

    #[test]
    fn adaptive_weights_initial_uniform() {
        let w = AdaptiveWeights::new();
        let probs = w.probabilities_millionths();
        // With equal weights and 10% exploration, should be ~50/50
        let diff = (probs[0] - probs[1]).abs();
        assert!(
            diff < 10_000,
            "initial probs should be near-uniform, got {probs:?}"
        );
    }

    #[test]
    fn adaptive_weights_select_deterministic() {
        let w = AdaptiveWeights::new();
        // With uniform weights, draw 0 should pick Js
        assert_eq!(w.select(0), LaneChoice::Js);
        // Draw near MILLION should pick Wasm
        assert_eq!(w.select(MILLION - 1), LaneChoice::Wasm);
    }

    #[test]
    fn adaptive_weights_update_shifts_weights() {
        let mut w = AdaptiveWeights::new();
        // Reward Wasm heavily multiple times
        for _ in 0..10 {
            w.update(LaneChoice::Wasm, MILLION);
        }
        let probs = w.probabilities_millionths();
        assert!(
            probs[1] > probs[0],
            "wasm prob should be higher after rewards, got {probs:?}"
        );
    }

    // -- ConformalState --

    #[test]
    fn conformal_initially_valid() {
        let cs = ConformalState::new(ConformalConfig::default_config());
        assert!(cs.is_valid());
        assert_eq!(cs.coverage_millionths(), MILLION);
    }

    #[test]
    fn conformal_all_in_bounds() {
        let mut cs = ConformalState::new(ConformalConfig::default_config());
        for _ in 0..30 {
            cs.observe(true);
        }
        assert!(cs.is_valid());
        assert_eq!(cs.coverage_millionths(), MILLION);
    }

    #[test]
    fn conformal_violation_triggers() {
        let mut cs = ConformalState::new(ConformalConfig {
            target_coverage_millionths: 900_000,
            min_observations: 10,
            window_size: 20,
        });
        // 15 out of bounds, 5 in bounds => coverage = 5/20 = 25% < 90%
        for _ in 0..15 {
            cs.observe(false);
        }
        for _ in 0..5 {
            cs.observe(true);
        }
        assert!(!cs.is_valid());
        let reason = cs.check();
        assert!(matches!(
            reason,
            Some(DemotionReason::ConformalViolation { .. })
        ));
    }

    #[test]
    fn conformal_valid_before_min_observations() {
        let mut cs = ConformalState::new(ConformalConfig {
            target_coverage_millionths: 900_000,
            min_observations: 20,
            window_size: 100,
        });
        for _ in 0..5 {
            cs.observe(false);
        }
        assert!(cs.is_valid()); // Not enough observations yet
    }

    // -- ChangePointMonitor --

    #[test]
    fn change_point_initially_not_triggered() {
        let m = ChangePointMonitor::new(ChangePointConfig::default_config());
        assert!(!m.is_triggered());
        assert!(m.check().is_none());
    }

    #[test]
    fn change_point_stable_observations() {
        let mut m = ChangePointMonitor::new(ChangePointConfig::default_config());
        for _ in 0..50 {
            m.observe(500_000); // stable at 0.5
        }
        assert!(!m.is_triggered());
    }

    #[test]
    fn change_point_detects_shift() {
        let mut m = ChangePointMonitor::new(ChangePointConfig {
            threshold_millionths: 1_000_000,
            drift_millionths: 50_000,
            min_observations: 5,
        });
        // Stable period
        for _ in 0..10 {
            m.observe(100_000);
        }
        // Sudden shift upward
        for _ in 0..20 {
            m.observe(900_000);
        }
        assert!(m.is_triggered());
        assert!(matches!(
            m.check(),
            Some(DemotionReason::ChangePointDetected { .. })
        ));
    }

    #[test]
    fn change_point_reset_clears_accumulators() {
        let mut m = ChangePointMonitor::new(ChangePointConfig::default_config());
        m.cusum_upper_millionths = 5_000_000;
        m.reset();
        assert_eq!(m.cusum_upper_millionths, 0);
        assert_eq!(m.cusum_lower_millionths, 0);
    }

    // -- RiskBudget / RiskAccumulator --

    #[test]
    fn risk_accumulator_empty() {
        let ra = RiskAccumulator::new();
        assert_eq!(ra.p99_latency_us(), 0);
        assert_eq!(ra.compatibility_errors, 0);
    }

    #[test]
    fn risk_accumulator_records() {
        let mut ra = RiskAccumulator::new();
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 5000,
            success: true,
            dom_ops: 100,
            signals_evaluated: 50,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        ra.record(&obs, 800_000);
        assert_eq!(ra.latencies_us.len(), 1);
        assert_eq!(ra.p99_latency_us(), 5000);
    }

    #[test]
    fn risk_budget_tail_latency_violation() {
        let mut ra = RiskAccumulator::new();
        let budget = RiskBudget {
            tail_latency_budget_us: 10_000,
            compatibility_error_budget: 5,
            regret_budget_millionths: 500_000,
        };

        // Add 100 observations with high latency
        for _ in 0..100 {
            let obs = LaneObservation {
                lane: LaneChoice::Js,
                latency_us: 20_000,
                success: true,
                dom_ops: 10,
                signals_evaluated: 5,
                safe_mode_entered: false,
                compatibility_errors: 0,
            };
            ra.record(&obs, 500_000);
        }

        let violation = ra.check_budgets(&budget);
        assert!(matches!(
            violation,
            Some(DemotionReason::TailLatencyBudgetExhausted { .. })
        ));
    }

    #[test]
    fn risk_budget_compat_error_violation() {
        let mut ra = RiskAccumulator::new();
        let budget = RiskBudget {
            tail_latency_budget_us: 100_000,
            compatibility_error_budget: 3,
            regret_budget_millionths: 10_000_000,
        };

        for _ in 0..5 {
            let obs = LaneObservation {
                lane: LaneChoice::Wasm,
                latency_us: 1000,
                success: true,
                dom_ops: 10,
                signals_evaluated: 5,
                safe_mode_entered: false,
                compatibility_errors: 1,
            };
            ra.record(&obs, 500_000);
        }

        let violation = ra.check_budgets(&budget);
        assert!(matches!(
            violation,
            Some(DemotionReason::CompatibilityBudgetExhausted { .. })
        ));
    }

    // -- compute_reward --

    #[test]
    fn reward_zero_on_failure() {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1000,
            success: false,
            dom_ops: 100,
            signals_evaluated: 50,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        assert_eq!(compute_reward(&obs, 8000), 0);
    }

    #[test]
    fn reward_penalised_on_safe_mode() {
        let obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1000,
            success: true,
            dom_ops: 100,
            signals_evaluated: 50,
            safe_mode_entered: true,
            compatibility_errors: 0,
        };
        assert_eq!(compute_reward(&obs, 8000), 100_000);
    }

    #[test]
    fn reward_penalised_on_compat_errors() {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1000,
            success: true,
            dom_ops: 100,
            signals_evaluated: 50,
            safe_mode_entered: false,
            compatibility_errors: 2,
        };
        assert_eq!(compute_reward(&obs, 8000), 200_000);
    }

    #[test]
    fn reward_good_observation() {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1000,
            success: true,
            dom_ops: 200,
            signals_evaluated: 100,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        let r = compute_reward(&obs, 8000);
        assert!(
            r > 500_000,
            "good observation should have high reward, got {r}"
        );
    }

    #[test]
    fn reward_bounded() {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 0,
            success: true,
            dom_ops: 10000,
            signals_evaluated: 5000,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        let r = compute_reward(&obs, 8000);
        assert!(
            r > 0 && r <= MILLION,
            "reward should be in [0, MILLION], got {r}"
        );
    }

    // -- HybridLaneRouter --

    #[test]
    fn router_starts_conservative() {
        let router = HybridLaneRouter::with_defaults();
        assert_eq!(router.policy, RoutingPolicy::Conservative);
        assert_eq!(router.round, 0);
    }

    #[test]
    fn router_conservative_always_baseline() {
        let router = HybridLaneRouter::with_defaults();
        for r in 0..100 {
            assert_eq!(router.select_lane(r * 10_000), router.config.baseline_lane);
        }
    }

    #[test]
    fn router_promote_to_adaptive() {
        let mut router = HybridLaneRouter::with_defaults();
        router.promote_to_adaptive().unwrap();
        assert_eq!(router.policy, RoutingPolicy::Adaptive);
        assert_eq!(router.policy_transitions.len(), 1);
    }

    #[test]
    fn router_adaptive_uses_random_draw() {
        let mut router = HybridLaneRouter::with_defaults();
        router.promote_to_adaptive().unwrap();
        // With equal weights, low draws -> Js, high draws -> Wasm
        let lane_low = router.select_lane(0);
        let lane_high = router.select_lane(MILLION - 1);
        assert_eq!(lane_low, LaneChoice::Js);
        assert_eq!(lane_high, LaneChoice::Wasm);
    }

    #[test]
    fn router_observe_increments_round() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
        assert_eq!(router.round, 1);
        router.observe(LaneChoice::Js, &obs, None);
        assert_eq!(router.round, 2);
    }

    #[test]
    fn router_observe_tracks_lane_counts() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs_js = good_observation(LaneChoice::Js);
        let obs_wasm = good_observation(LaneChoice::Wasm);
        router.observe(LaneChoice::Js, &obs_js, None);
        router.observe(LaneChoice::Js, &obs_js, None);
        router.observe(LaneChoice::Wasm, &obs_wasm, None);
        assert_eq!(router.total_js_routes, 2);
        assert_eq!(router.total_wasm_routes, 1);
    }

    #[test]
    fn router_observe_returns_trace() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        let trace = router.observe(LaneChoice::Js, &obs, Some(100_000));
        assert_eq!(trace.round, 0);
        assert_eq!(trace.chosen_lane, LaneChoice::Js);
        assert_eq!(trace.policy, RoutingPolicy::Conservative);
        assert!(trace.reward_millionths.is_some());
    }

    #[test]
    fn router_demotes_on_compat_errors() {
        let mut router = HybridLaneRouter::new(RouterConfig {
            risk_budget: RiskBudget {
                compatibility_error_budget: 2,
                ..RiskBudget::default_budget()
            },
            ..RouterConfig::default_config()
        });
        router.promote_to_adaptive().unwrap();

        let bad_obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1000,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 1,
        };

        // 3 compat errors > budget of 2
        for _ in 0..3 {
            router.observe(LaneChoice::Wasm, &bad_obs, None);
        }
        assert_eq!(router.policy, RoutingPolicy::Conservative);
    }

    #[test]
    fn router_demotes_on_conformal_violation() {
        let mut router = HybridLaneRouter::new(RouterConfig {
            conformal: ConformalConfig {
                target_coverage_millionths: 900_000,
                min_observations: 5,
                window_size: 10,
            },
            ..RouterConfig::default_config()
        });
        router.promote_to_adaptive().unwrap();

        let bad_obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1000,
            success: false, // failure -> out of bounds
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };

        // Enough failures to violate conformal coverage
        for _ in 0..10 {
            router.observe(LaneChoice::Wasm, &bad_obs, None);
        }
        assert_eq!(router.policy, RoutingPolicy::Conservative);
    }

    #[test]
    fn router_manual_demote() {
        let mut router = HybridLaneRouter::with_defaults();
        router.promote_to_adaptive().unwrap();
        router.manual_demote().unwrap();
        assert_eq!(router.policy, RoutingPolicy::Conservative);
    }

    #[test]
    fn router_manual_demote_when_conservative_errors() {
        let mut router = HybridLaneRouter::with_defaults();
        let err = router.manual_demote().unwrap_err();
        assert_eq!(err, RouterError::AlreadyConservative);
    }

    #[test]
    fn router_lane_probabilities_conservative() {
        let router = HybridLaneRouter::with_defaults();
        let probs = router.lane_probabilities();
        assert_eq!(*probs.get(&LaneChoice::Js).unwrap(), MILLION);
        assert_eq!(*probs.get(&LaneChoice::Wasm).unwrap(), 0);
    }

    #[test]
    fn router_lane_probabilities_adaptive() {
        let mut router = HybridLaneRouter::with_defaults();
        router.promote_to_adaptive().unwrap();
        let probs = router.lane_probabilities();
        let js_p = *probs.get(&LaneChoice::Js).unwrap();
        let wasm_p = *probs.get(&LaneChoice::Wasm).unwrap();
        // Both should have nonzero probability
        assert!(js_p > 0, "js prob should be > 0, got {js_p}");
        assert!(wasm_p > 0, "wasm prob should be > 0, got {wasm_p}");
    }

    #[test]
    fn router_summary() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
        let s = router.summary();
        assert_eq!(s.round, 1);
        assert_eq!(s.total_js_routes, 1);
        assert_eq!(s.total_wasm_routes, 0);
    }

    #[test]
    fn router_derive_id_stable() {
        let r1 = HybridLaneRouter::with_defaults();
        let r2 = HybridLaneRouter::with_defaults();
        assert_eq!(r1.derive_id(), r2.derive_id());
    }

    #[test]
    fn router_decision_trace_derive_id() {
        let trace = RoutingDecisionTrace {
            round: 42,
            policy: RoutingPolicy::Adaptive,
            chosen_lane: LaneChoice::Wasm,
            rejected_lanes: vec![LaneChoice::Js],
            probabilities_millionths: vec![400_000, 600_000],
            random_draw_millionths: Some(550_000),
            reward_millionths: Some(800_000),
            cumulative_regret_millionths: 100_000,
            p99_latency_us: 5000,
            compatibility_errors: 0,
            conformal_coverage_millionths: 950_000,
            cusum_stat_millionths: 300_000,
            demotion_reason: None,
        };
        let id = trace.derive_id();
        let id2 = trace.derive_id();
        assert_eq!(id, id2);
    }

    #[test]
    fn router_serde_roundtrip() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
        let json = serde_json::to_string(&router).unwrap();
        let back: HybridLaneRouter = serde_json::from_str(&json).unwrap();
        assert_eq!(router, back);
    }

    #[test]
    fn router_decision_log_trims() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        for _ in 0..1050 {
            router.observe(LaneChoice::Js, &obs, None);
        }
        assert!(router.decision_log.len() <= 1000);
    }

    #[test]
    fn e2e_adaptive_session() {
        let mut router = HybridLaneRouter::new(RouterConfig {
            change_point: ChangePointConfig {
                threshold_millionths: 50_000_000,
                ..ChangePointConfig::default_config()
            },
            risk_budget: RiskBudget {
                tail_latency_budget_us: 1_000_000,
                compatibility_error_budget: 100,
                regret_budget_millionths: 50_000_000,
            },
            ..RouterConfig::default_config()
        });
        router.promote_to_adaptive().unwrap();

        // Simulate 50 rounds with Wasm being slightly better
        for i in 0..50 {
            let random = ((i as i64) * 20_000) % MILLION;
            let lane = router.select_lane(random);
            let obs = LaneObservation {
                lane,
                latency_us: if lane == LaneChoice::Wasm { 3000 } else { 5000 },
                success: true,
                dom_ops: if lane == LaneChoice::Wasm { 200 } else { 100 },
                signals_evaluated: 50,
                safe_mode_entered: false,
                compatibility_errors: 0,
            };
            router.observe(lane, &obs, Some(random));
        }

        let summary = router.summary();
        assert_eq!(summary.round, 50);
        assert!(summary.total_js_routes + summary.total_wasm_routes == 50);
        // Should still be adaptive (no demotion triggers)
        assert_eq!(summary.policy, RoutingPolicy::Adaptive);
    }

    #[test]
    fn e2e_regime_shift_demotion() {
        let mut router = HybridLaneRouter::new(RouterConfig {
            change_point: ChangePointConfig {
                threshold_millionths: 500_000,
                drift_millionths: 10_000,
                min_observations: 5,
            },
            ..RouterConfig::default_config()
        });
        router.promote_to_adaptive().unwrap();

        // Good period
        for _ in 0..10 {
            let obs = good_observation(LaneChoice::Js);
            router.observe(LaneChoice::Js, &obs, None);
        }
        assert_eq!(router.policy, RoutingPolicy::Adaptive);

        // Regime shift: sudden failures
        for _ in 0..20 {
            let obs = LaneObservation {
                lane: LaneChoice::Js,
                latency_us: 1000,
                success: false,
                dom_ops: 0,
                signals_evaluated: 0,
                safe_mode_entered: false,
                compatibility_errors: 0,
            };
            router.observe(LaneChoice::Js, &obs, None);
        }

        // Should have demoted
        assert_eq!(router.policy, RoutingPolicy::Conservative);
        assert!(router.policy_transitions.len() >= 2); // promote + demote
    }

    #[test]
    fn e2e_promote_demote_promote() {
        let mut router = HybridLaneRouter::new(RouterConfig {
            risk_budget: RiskBudget {
                compatibility_error_budget: 1,
                ..RiskBudget::default_budget()
            },
            ..RouterConfig::default_config()
        });

        // Round 1: promote
        router.promote_to_adaptive().unwrap();
        assert_eq!(router.policy, RoutingPolicy::Adaptive);

        // Trigger demotion via compat errors
        let bad_obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1000,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 2,
        };
        router.observe(LaneChoice::Wasm, &bad_obs, None);
        assert_eq!(router.policy, RoutingPolicy::Conservative);

        // Re-promote
        router.promote_to_adaptive().unwrap();
        assert_eq!(router.policy, RoutingPolicy::Adaptive);
        assert_eq!(router.policy_transitions.len(), 3);
    }

    #[test]
    fn policy_transition_serde() {
        let pt = PolicyTransition {
            round: 42,
            from: RoutingPolicy::Adaptive,
            to: RoutingPolicy::Conservative,
            reason: Some(DemotionReason::ManualDemotion),
        };
        let json = serde_json::to_string(&pt).unwrap();
        let back: PolicyTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(pt, back);
    }

    #[test]
    fn demotion_reason_variants_serde() {
        let reasons = vec![
            DemotionReason::ChangePointDetected {
                cusum_stat_millionths: 3_000_000,
                threshold_millionths: 2_000_000,
            },
            DemotionReason::ConformalViolation {
                coverage_millionths: 800_000,
                target_millionths: 900_000,
            },
            DemotionReason::RegretExceeded {
                realized_millionths: 600_000,
                bound_millionths: 500_000,
            },
            DemotionReason::TailLatencyBudgetExhausted {
                observed_p99_us: 20_000,
                budget_us: 16_000,
            },
            DemotionReason::CompatibilityBudgetExhausted {
                errors_observed: 10,
                budget: 5,
            },
            DemotionReason::ManualDemotion,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: DemotionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn summary_derive_id_stable() {
        let s = RouterSummary {
            round: 100,
            policy: RoutingPolicy::Adaptive,
            total_js_routes: 60,
            total_wasm_routes: 40,
            p99_latency_us: 5000,
            cumulative_regret_millionths: 100_000,
            compatibility_errors: 0,
            conformal_coverage_millionths: 950_000,
            policy_transitions: 2,
            consecutive_conservative_rounds: 0,
        };
        let id1 = s.derive_id();
        let id2 = s.derive_id();
        assert_eq!(id1, id2);
    }

    // -- Helpers --

    fn good_observation(lane: LaneChoice) -> LaneObservation {
        LaneObservation {
            lane,
            latency_us: 2000,
            success: true,
            dom_ops: 150,
            signals_evaluated: 75,
            safe_mode_entered: false,
            compatibility_errors: 0,
        }
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn lane_choice_display_unique() {
        let displays: std::collections::BTreeSet<String> = LaneChoice::ALL
            .iter()
            .map(|l| l.as_str().to_string())
            .collect();
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn routing_policy_serde_roundtrip() {
        for policy in [RoutingPolicy::Conservative, RoutingPolicy::Adaptive] {
            let json = serde_json::to_string(&policy).unwrap();
            let back: RoutingPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    // ── Enrichment: LaneObservation serde ───────────────────────

    #[test]
    fn lane_observation_serde_roundtrip() {
        let obs = good_observation(LaneChoice::Wasm);
        let json = serde_json::to_string(&obs).unwrap();
        let back: LaneObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    // ── Enrichment: risk budget default ─────────────────────────

    #[test]
    fn risk_budget_default_has_positive_budgets() {
        let budget = RiskBudget::default_budget();
        assert!(budget.tail_latency_budget_us > 0);
        assert!(budget.compatibility_error_budget > 0);
        assert!(budget.regret_budget_millionths > 0);
    }

    // ── Enrichment: router config serde ─────────────────────────

    #[test]
    fn router_config_serde_roundtrip() {
        let config = RouterConfig::default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: RouterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Enrichment: promote when already adaptive fails ─────────

    #[test]
    fn promote_to_adaptive_idempotent() {
        let mut router = HybridLaneRouter::with_defaults();
        router.promote_to_adaptive().unwrap();
        // Calling again is idempotent (returns Ok)
        router.promote_to_adaptive().unwrap();
        assert_eq!(router.policy, RoutingPolicy::Adaptive);
    }

    // ── Enrichment: RouterError serde ───────────────────────────

    #[test]
    fn router_error_serde_roundtrip() {
        for err in [
            RouterError::AlreadyConservative,
            RouterError::InvalidConfig {
                reason: "bad".into(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: RouterError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // ── Enrichment: exp_millionths precision ────────────────────

    #[test]
    fn exp_millionths_one_million_is_e() {
        // e^1 ~ 2.718, so exp_millionths(1_000_000) should be ~ 2_718_000
        let val = exp_millionths(MILLION);
        assert!(
            val > 2_500_000 && val < 3_000_000,
            "exp(1.0) should be ~2.718M, got {val}"
        );
    }

    // ── Enrichment: conformal config serde ──────────────────────

    #[test]
    fn conformal_config_serde_roundtrip() {
        let config = ConformalConfig::default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: ConformalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn compute_reward_zero_baseline_no_panic() {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1000,
            success: true,
            dom_ops: 100,
            signals_evaluated: 50,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        let r = compute_reward(&obs, 0);
        assert!((0..=MILLION).contains(&r));
    }

    #[test]
    fn risk_accumulator_default_matches_new() {
        let a = RiskAccumulator::default();
        let b = RiskAccumulator::new();
        assert_eq!(a, b);
    }

    #[test]
    fn adaptive_weights_default_matches_new() {
        let a = AdaptiveWeights::default();
        let b = AdaptiveWeights::new();
        assert_eq!(a, b);
    }

    #[test]
    fn change_point_non_positive_threshold_triggers_after_min_obs() {
        let mut m = ChangePointMonitor::new(ChangePointConfig {
            threshold_millionths: 0,
            drift_millionths: 0,
            min_observations: 5,
        });
        for _ in 0..4 {
            m.observe(500_000);
        }
        assert!(!m.is_triggered()); // below min_observations
        m.observe(500_000);
        assert!(m.is_triggered()); // at min_observations with non-positive threshold
    }

    #[test]
    fn conformal_window_eviction() {
        let mut cs = ConformalState::new(ConformalConfig {
            target_coverage_millionths: 500_000,
            min_observations: 1,
            window_size: 3,
        });
        cs.observe(true);
        cs.observe(true);
        cs.observe(true);
        assert_eq!(cs.window.len(), 3);
        cs.observe(false); // evicts oldest
        assert_eq!(cs.window.len(), 3);
        // Window is now [true, true, false] = 2/3 ~ 666666
        assert!(cs.coverage_millionths() > 600_000);
    }

    #[test]
    fn router_consecutive_conservative_rounds_tracks() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
        router.observe(LaneChoice::Js, &obs, None);
        assert_eq!(router.consecutive_conservative_rounds, 2);

        // Promote and observe — counter resets
        router.promote_to_adaptive().unwrap();
        router.observe(LaneChoice::Js, &obs, None);
        assert_eq!(router.consecutive_conservative_rounds, 0);
    }

    #[test]
    fn change_point_config_serde_roundtrip() {
        let config = ChangePointConfig::default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: ChangePointConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn change_point_monitor_serde_roundtrip() {
        let mut m = ChangePointMonitor::new(ChangePointConfig::default_config());
        m.observe(500_000);
        m.observe(600_000);
        let json = serde_json::to_string(&m).unwrap();
        let back: ChangePointMonitor = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn risk_accumulator_serde_roundtrip() {
        let mut ra = RiskAccumulator::new();
        let obs = good_observation(LaneChoice::Js);
        ra.record(&obs, 800_000);
        let json = serde_json::to_string(&ra).unwrap();
        let back: RiskAccumulator = serde_json::from_str(&json).unwrap();
        assert_eq!(ra, back);
    }

    #[test]
    fn adaptive_weights_serde_roundtrip() {
        let mut w = AdaptiveWeights::new();
        w.update(LaneChoice::Wasm, 500_000);
        let json = serde_json::to_string(&w).unwrap();
        let back: AdaptiveWeights = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn router_summary_serde_roundtrip() {
        let mut router = HybridLaneRouter::with_defaults();
        let obs = good_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
        let summary = router.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let back: RouterSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn routing_decision_trace_serde_roundtrip() {
        let trace = RoutingDecisionTrace {
            round: 42,
            policy: RoutingPolicy::Adaptive,
            chosen_lane: LaneChoice::Wasm,
            rejected_lanes: vec![LaneChoice::Js],
            probabilities_millionths: vec![400_000, 600_000],
            random_draw_millionths: Some(550_000),
            reward_millionths: Some(800_000),
            cumulative_regret_millionths: 100_000,
            p99_latency_us: 5000,
            compatibility_errors: 0,
            conformal_coverage_millionths: 950_000,
            cusum_stat_millionths: 300_000,
            demotion_reason: None,
        };
        let json = serde_json::to_string(&trace).unwrap();
        let back: RoutingDecisionTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn router_error_serde_all_variants() {
        for err in [
            RouterError::AlreadyConservative,
            RouterError::InvalidRandomDraw { value: -1 },
            RouterError::InvalidConfig {
                reason: "bad".into(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: RouterError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn risk_accumulator_latencies_window_caps_at_1000() {
        let mut ra = RiskAccumulator::new();
        let obs = good_observation(LaneChoice::Js);
        for _ in 0..1050 {
            ra.record(&obs, 500_000);
        }
        assert!(ra.latencies_us.len() <= 1000);
    }

    #[test]
    fn routing_policy_ord_conservative_before_adaptive() {
        assert!(RoutingPolicy::Conservative < RoutingPolicy::Adaptive);
    }
}
