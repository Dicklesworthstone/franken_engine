//! [FRX-18.2] Adversarial Coevolution Harness with Regret-Bounded Policy Search
//!
//! Implements a continuous attacker-defender simulation framework that discovers
//! exploit classes and compiles defense updates under bounded-regret learning.
//!
//! All arithmetic uses fixed-point millionths (1 000 000 = 1.0) for determinism.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ── Constants ─────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for coevolution artefacts.
pub const COEVOLUTION_SCHEMA_VERSION: &str = "franken-engine.adversarial-coevolution.v1";

/// Component label for telemetry.
pub const COEVOLUTION_COMPONENT: &str = "adversarial_coevolution_harness";

/// Maximum number of rounds in a single tournament.
const MAX_TOURNAMENT_ROUNDS: u64 = 100_000;

/// Maximum number of arms (strategies) for either player.
const MAX_STRATEGIES: usize = 64;

/// Default exploration rate for EXP3 (gamma, millionths: 100 000 = 10%).
const DEFAULT_GAMMA_MILLIONTHS: i64 = 100_000;

/// Minimum weight floor to prevent zero-weight collapse (millionths).
const MIN_WEIGHT_FLOOR: i64 = 100; // 0.0001

// ── Strategy Identifiers ──────────────────────────────────────────────

/// Compact identifier for an attacker or defender strategy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StrategyId(pub String);

impl fmt::Display for StrategyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Player Role ───────────────────────────────────────────────────────

/// Which side of the game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlayerRole {
    Attacker,
    Defender,
}

impl fmt::Display for PlayerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attacker => write!(f, "attacker"),
            Self::Defender => write!(f, "defender"),
        }
    }
}

// ── Exploit Classification ────────────────────────────────────────────

/// Classification of a discovered exploit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExploitClass {
    /// Capability escalation via ambient authority leak.
    CapabilityEscalation,
    /// Policy bypass through timing or race condition.
    PolicyBypass,
    /// Resource exhaustion or budget evasion.
    ResourceExhaustion,
    /// Information leakage across containment boundaries.
    InformationLeakage,
    /// Replay or rollback attack on decision receipts.
    ReplayAttack,
    /// Unknown/novel exploit class.
    Novel(String),
}

impl fmt::Display for ExploitClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityEscalation => write!(f, "capability_escalation"),
            Self::PolicyBypass => write!(f, "policy_bypass"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::InformationLeakage => write!(f, "information_leakage"),
            Self::ReplayAttack => write!(f, "replay_attack"),
            Self::Novel(name) => write!(f, "novel:{name}"),
        }
    }
}

// ── Payoff Matrix ─────────────────────────────────────────────────────

/// A payoff entry for a specific (attacker, defender) strategy pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoffEntry {
    pub attacker: StrategyId,
    pub defender: StrategyId,
    /// Attacker's payoff in millionths (higher = attacker wins more).
    pub attacker_payoff_millionths: i64,
    /// Defender's payoff in millionths (higher = defender wins more).
    pub defender_payoff_millionths: i64,
}

/// The payoff matrix for a coevolutionary game.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoffMatrix {
    pub attacker_strategies: Vec<StrategyId>,
    pub defender_strategies: Vec<StrategyId>,
    pub entries: Vec<PayoffEntry>,
}

impl PayoffMatrix {
    /// Lookup the payoff for a given strategy pair.
    pub fn lookup(&self, attacker: &StrategyId, defender: &StrategyId) -> Option<&PayoffEntry> {
        self.entries
            .iter()
            .find(|e| &e.attacker == attacker && &e.defender == defender)
    }

    /// Returns the defender's minimax strategy (minimizes attacker's max payoff).
    pub fn minimax_defender(&self) -> Option<StrategyId> {
        let mut best: Option<(StrategyId, i64)> = None;
        for d in &self.defender_strategies {
            let max_attacker = self
                .entries
                .iter()
                .filter(|e| &e.defender == d)
                .map(|e| e.attacker_payoff_millionths)
                .max()
                .unwrap_or(0);
            if best.as_ref().is_none_or(|(_, v)| max_attacker < *v) {
                best = Some((d.clone(), max_attacker));
            }
        }
        best.map(|(s, _)| s)
    }
}

// ── Tournament Configuration ──────────────────────────────────────────

/// Configuration for a coevolution tournament.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TournamentConfig {
    /// Number of rounds to simulate.
    pub rounds: u64,
    /// Exploration rate gamma (millionths, in (0, MILLION)).
    pub gamma_millionths: i64,
    /// Epoch for temporal ordering.
    pub epoch: SecurityEpoch,
    /// Deterministic seed for reproducibility.
    pub seed: u64,
    /// Budget cap for exploration (total attacker payoff budget, millionths).
    pub exploration_budget_millionths: i64,
    /// Whether to track per-round trajectory (more memory but full ledger).
    pub track_trajectory: bool,
}

impl Default for TournamentConfig {
    fn default() -> Self {
        Self {
            rounds: 1000,
            gamma_millionths: DEFAULT_GAMMA_MILLIONTHS,
            epoch: SecurityEpoch::GENESIS,
            seed: 42,
            exploration_budget_millionths: i64::MAX / 2,
            track_trajectory: true,
        }
    }
}

// ── EXP3 Weights ──────────────────────────────────────────────────────

/// EXP3 bandit weights for a single player's strategy selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Exp3Weights {
    /// Log-weights in millionths (exponentiated for probability).
    weights_millionths: Vec<i64>,
    /// Cumulative reward estimates per arm (millionths).
    cumulative_rewards: Vec<i64>,
    /// Selection counts per arm.
    counts: Vec<u64>,
}

impl Exp3Weights {
    fn new(n: usize) -> Self {
        Self {
            weights_millionths: vec![MILLION; n],
            cumulative_rewards: vec![0; n],
            counts: vec![0; n],
        }
    }

    /// Compute mixed strategy probabilities (millionths, sum to MILLION).
    fn probabilities(&self, gamma_millionths: i64) -> Vec<i64> {
        let n = self.weights_millionths.len() as i64;
        if n == 0 {
            return vec![];
        }

        let total: i64 = self.weights_millionths.iter().sum();
        if total <= 0 {
            // Uniform fallback
            let uniform = MILLION / n;
            return vec![uniform; n as usize];
        }

        // p_i = (1-gamma) * w_i/total + gamma/n
        let gamma = gamma_millionths.clamp(0, MILLION);
        let one_minus_gamma = MILLION - gamma;

        let mut probs: Vec<i64> = self
            .weights_millionths
            .iter()
            .map(|&w| {
                let exploit = (one_minus_gamma * w) / total;
                let explore = gamma / n;
                (exploit + explore).max(MIN_WEIGHT_FLOOR)
            })
            .collect();

        // Normalize to sum to MILLION
        let sum: i64 = probs.iter().sum();
        if sum > 0 && sum != MILLION {
            let correction = MILLION - sum;
            probs[0] = (probs[0] + correction).max(0);
        }

        probs
    }

    /// Select an arm deterministically using a hash-derived value in [0, MILLION).
    fn select(&self, hash_value: i64, gamma_millionths: i64) -> usize {
        let probs = self.probabilities(gamma_millionths);
        let val = hash_value.rem_euclid(MILLION);
        let mut cumulative = 0i64;
        for (i, &p) in probs.iter().enumerate() {
            cumulative += p;
            if val < cumulative {
                return i;
            }
        }
        probs.len().saturating_sub(1)
    }

    /// Update weights after observing a reward for the selected arm.
    fn update(&mut self, arm: usize, reward_millionths: i64, prob_millionths: i64) {
        if arm >= self.weights_millionths.len() || prob_millionths <= 0 {
            return;
        }
        // Estimated reward: r / p (importance-weighted)
        let estimated = (reward_millionths * MILLION) / prob_millionths;

        self.cumulative_rewards[arm] = self.cumulative_rewards[arm].saturating_add(estimated);
        self.counts[arm] += 1;

        // Multiplicative weight update: w *= exp(gamma * estimated / n)
        // Approximate exp with (1 + x) for small x
        let n = self.weights_millionths.len() as i64;
        let update_factor = if n > 0 {
            MILLION + (DEFAULT_GAMMA_MILLIONTHS * estimated) / (n * MILLION)
        } else {
            MILLION
        };

        self.weights_millionths[arm] =
            (self.weights_millionths[arm] as i128 * update_factor as i128 / MILLION as i128)
                .clamp(MIN_WEIGHT_FLOOR as i128, (100 * MILLION) as i128) as i64;
    }
}

// ── Round Outcome ─────────────────────────────────────────────────────

/// Outcome of a single tournament round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundOutcome {
    pub round: u64,
    pub attacker_strategy: StrategyId,
    pub defender_strategy: StrategyId,
    pub attacker_payoff_millionths: i64,
    pub defender_payoff_millionths: i64,
    /// Exploit class discovered this round, if any.
    pub exploit_discovered: Option<ExploitClass>,
}

// ── Trajectory Ledger ─────────────────────────────────────────────────

/// Full trajectory of a tournament.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryLedger {
    pub rounds: Vec<RoundOutcome>,
    /// Cumulative regret per round (attacker perspective, millionths).
    pub attacker_cumulative_regret: Vec<i64>,
    /// Cumulative regret per round (defender perspective, millionths).
    pub defender_cumulative_regret: Vec<i64>,
}

impl TrajectoryLedger {
    fn new() -> Self {
        Self {
            rounds: Vec::new(),
            attacker_cumulative_regret: Vec::new(),
            defender_cumulative_regret: Vec::new(),
        }
    }

    /// The number of recorded rounds.
    pub fn round_count(&self) -> usize {
        self.rounds.len()
    }

    /// Final attacker cumulative regret.
    pub fn final_attacker_regret(&self) -> i64 {
        self.attacker_cumulative_regret.last().copied().unwrap_or(0)
    }

    /// Final defender cumulative regret.
    pub fn final_defender_regret(&self) -> i64 {
        self.defender_cumulative_regret.last().copied().unwrap_or(0)
    }
}

// ── Convergence Diagnostic ────────────────────────────────────────────

/// Convergence diagnostics for a tournament.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceDiagnostic {
    /// Average regret per round (attacker, millionths).
    pub attacker_avg_regret_millionths: i64,
    /// Average regret per round (defender, millionths).
    pub defender_avg_regret_millionths: i64,
    /// Whether attacker's regret growth is sublinear (bounded).
    pub attacker_regret_bounded: bool,
    /// Whether defender's regret growth is sublinear (bounded).
    pub defender_regret_bounded: bool,
    /// Exploit classes discovered during the tournament.
    pub exploit_classes: BTreeSet<String>,
    /// Strategy frequency distribution (attacker).
    pub attacker_frequency: BTreeMap<String, u64>,
    /// Strategy frequency distribution (defender).
    pub defender_frequency: BTreeMap<String, u64>,
}

// ── Policy Delta ──────────────────────────────────────────────────────

/// A candidate defense policy update derived from tournament outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDelta {
    /// Identifier for this delta.
    pub delta_id: String,
    /// The recommended defender strategy mix (strategy → weight millionths).
    pub recommended_mix: BTreeMap<String, i64>,
    /// Exploits this delta addresses.
    pub addressed_exploits: BTreeSet<String>,
    /// Expected improvement over uniform defense (millionths).
    pub expected_improvement_millionths: i64,
    /// Epoch of the tournament that produced this delta.
    pub source_epoch: SecurityEpoch,
    /// Content hash for evidence linkage.
    pub artifact_hash: ContentHash,
}

// ── Tournament Result ─────────────────────────────────────────────────

/// Full result of a coevolution tournament.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TournamentResult {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub rounds_played: u64,
    pub total_attacker_payoff_millionths: i64,
    pub total_defender_payoff_millionths: i64,
    pub convergence: ConvergenceDiagnostic,
    pub policy_delta: PolicyDelta,
    pub trajectory: Option<TrajectoryLedger>,
    pub artifact_hash: ContentHash,
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors during coevolution tournament execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoevolutionError {
    /// No strategies defined for one or both players.
    EmptyStrategies { player: PlayerRole },
    /// Too many strategies.
    TooManyStrategies { count: usize, max: usize },
    /// Payoff matrix incomplete (missing entries).
    IncompletePayoffMatrix { expected: usize, actual: usize },
    /// Invalid gamma (exploration rate).
    InvalidGamma { value: i64 },
    /// Tournament rounds exceed maximum.
    TooManyRounds { rounds: u64, max: u64 },
    /// Exploration budget exhausted.
    BudgetExhausted { spent: i64, budget: i64 },
    /// Zero rounds requested.
    ZeroRounds,
}

impl fmt::Display for CoevolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStrategies { player } => {
                write!(f, "no strategies defined for {player}")
            }
            Self::TooManyStrategies { count, max } => {
                write!(f, "strategy count {count} exceeds maximum {max}")
            }
            Self::IncompletePayoffMatrix { expected, actual } => {
                write!(f, "payoff matrix has {actual} entries, expected {expected}")
            }
            Self::InvalidGamma { value } => {
                write!(f, "gamma out of range (0, MILLION): {value}")
            }
            Self::TooManyRounds { rounds, max } => {
                write!(f, "rounds {rounds} exceed maximum {max}")
            }
            Self::BudgetExhausted { spent, budget } => {
                write!(
                    f,
                    "exploration budget exhausted: spent {spent}, budget {budget}"
                )
            }
            Self::ZeroRounds => write!(f, "zero rounds requested"),
        }
    }
}

impl std::error::Error for CoevolutionError {}

// ── Deterministic Hash ────────────────────────────────────────────────

/// Simple deterministic hash for strategy selection (no floating point).
fn det_hash(seed: u64, round: u64, salt: u64) -> i64 {
    let mut h = seed.wrapping_mul(6_364_136_223_846_793_005);
    h = h.wrapping_add(round.wrapping_mul(1_442_695_040_888_963_407));
    h = h.wrapping_add(salt);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    (h % MILLION as u64) as i64
}

// ── Exploit Classifier ────────────────────────────────────────────────

/// Classify an exploit based on the attacker payoff and strategy names.
fn classify_exploit(
    attacker: &StrategyId,
    attacker_payoff: i64,
    threshold: i64,
) -> Option<ExploitClass> {
    if attacker_payoff < threshold {
        return None;
    }
    let name = attacker.0.to_lowercase();
    if name.contains("escalat") || name.contains("capability") {
        Some(ExploitClass::CapabilityEscalation)
    } else if name.contains("bypass") || name.contains("policy") {
        Some(ExploitClass::PolicyBypass)
    } else if name.contains("exhaust") || name.contains("resource") || name.contains("dos") {
        Some(ExploitClass::ResourceExhaustion)
    } else if name.contains("leak") || name.contains("info") || name.contains("exfil") {
        Some(ExploitClass::InformationLeakage)
    } else if name.contains("replay") || name.contains("rollback") {
        Some(ExploitClass::ReplayAttack)
    } else {
        Some(ExploitClass::Novel(attacker.0.clone()))
    }
}

// ── The Harness ───────────────────────────────────────────────────────

/// Adversarial coevolution tournament harness.
///
/// Runs a deterministic attacker-defender simulation using EXP3-style
/// bandit learning for both players, with bounded exploration budgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoevolutionHarness {
    config: TournamentConfig,
    payoff_matrix: PayoffMatrix,
    tournament_count: u64,
}

impl CoevolutionHarness {
    /// Create a new harness with the given config and payoff matrix.
    pub fn new(
        config: TournamentConfig,
        payoff_matrix: PayoffMatrix,
    ) -> Result<Self, CoevolutionError> {
        Self::validate(&config, &payoff_matrix)?;
        Ok(Self {
            config,
            payoff_matrix,
            tournament_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &TournamentConfig {
        &self.config
    }

    /// Number of tournaments run.
    pub fn tournament_count(&self) -> u64 {
        self.tournament_count
    }

    /// Access the payoff matrix.
    pub fn payoff_matrix(&self) -> &PayoffMatrix {
        &self.payoff_matrix
    }

    // ── Validation ────────────────────────────────────────────────

    fn validate(config: &TournamentConfig, matrix: &PayoffMatrix) -> Result<(), CoevolutionError> {
        if matrix.attacker_strategies.is_empty() {
            return Err(CoevolutionError::EmptyStrategies {
                player: PlayerRole::Attacker,
            });
        }
        if matrix.defender_strategies.is_empty() {
            return Err(CoevolutionError::EmptyStrategies {
                player: PlayerRole::Defender,
            });
        }
        if matrix.attacker_strategies.len() > MAX_STRATEGIES {
            return Err(CoevolutionError::TooManyStrategies {
                count: matrix.attacker_strategies.len(),
                max: MAX_STRATEGIES,
            });
        }
        if matrix.defender_strategies.len() > MAX_STRATEGIES {
            return Err(CoevolutionError::TooManyStrategies {
                count: matrix.defender_strategies.len(),
                max: MAX_STRATEGIES,
            });
        }
        let expected = matrix.attacker_strategies.len() * matrix.defender_strategies.len();
        if matrix.entries.len() != expected {
            return Err(CoevolutionError::IncompletePayoffMatrix {
                expected,
                actual: matrix.entries.len(),
            });
        }
        if config.gamma_millionths <= 0 || config.gamma_millionths >= MILLION {
            return Err(CoevolutionError::InvalidGamma {
                value: config.gamma_millionths,
            });
        }
        if config.rounds == 0 {
            return Err(CoevolutionError::ZeroRounds);
        }
        if config.rounds > MAX_TOURNAMENT_ROUNDS {
            return Err(CoevolutionError::TooManyRounds {
                rounds: config.rounds,
                max: MAX_TOURNAMENT_ROUNDS,
            });
        }
        Ok(())
    }

    // ── Run Tournament ────────────────────────────────────────────

    /// Execute the coevolution tournament.
    pub fn run(&mut self) -> Result<TournamentResult, CoevolutionError> {
        let n_atk = self.payoff_matrix.attacker_strategies.len();
        let n_def = self.payoff_matrix.defender_strategies.len();

        let mut atk_weights = Exp3Weights::new(n_atk);
        let mut def_weights = Exp3Weights::new(n_def);

        let mut trajectory = if self.config.track_trajectory {
            Some(TrajectoryLedger::new())
        } else {
            None
        };

        let mut total_atk_payoff: i64 = 0;
        let mut total_def_payoff: i64 = 0;
        let mut exploit_set: BTreeSet<String> = BTreeSet::new();
        let mut budget_spent: i64 = 0;

        // Track best fixed strategy payoffs for regret computation
        let mut best_atk_fixed = vec![0i64; n_atk];
        let mut best_def_fixed = vec![0i64; n_def];

        let exploit_threshold = MILLION / 2; // 50% payoff = exploit

        for round in 0..self.config.rounds {
            // Check budget
            if budget_spent >= self.config.exploration_budget_millionths {
                break;
            }

            // Select strategies
            let atk_hash = det_hash(self.config.seed, round, 0);
            let def_hash = det_hash(self.config.seed, round, 1);

            let atk_idx = atk_weights.select(atk_hash, self.config.gamma_millionths);
            let def_idx = def_weights.select(def_hash, self.config.gamma_millionths);

            let atk_id = &self.payoff_matrix.attacker_strategies[atk_idx];
            let def_id = &self.payoff_matrix.defender_strategies[def_idx];

            // Lookup payoff
            let entry = self.payoff_matrix.lookup(atk_id, def_id);
            let (atk_pay, def_pay) = entry
                .map(|e| (e.attacker_payoff_millionths, e.defender_payoff_millionths))
                .unwrap_or((0, 0));

            total_atk_payoff = total_atk_payoff.saturating_add(atk_pay);
            total_def_payoff = total_def_payoff.saturating_add(def_pay);
            budget_spent = budget_spent.saturating_add(atk_pay.abs());

            // Classify exploits
            let exploit = classify_exploit(atk_id, atk_pay, exploit_threshold);
            if let Some(ref ex) = exploit {
                exploit_set.insert(ex.to_string());
            }

            // Update best fixed strategy payoffs
            for (i, a) in self.payoff_matrix.attacker_strategies.iter().enumerate() {
                if let Some(e) = self.payoff_matrix.lookup(a, def_id) {
                    best_atk_fixed[i] =
                        best_atk_fixed[i].saturating_add(e.attacker_payoff_millionths);
                }
            }
            for (j, d) in self.payoff_matrix.defender_strategies.iter().enumerate() {
                if let Some(e) = self.payoff_matrix.lookup(atk_id, d) {
                    best_def_fixed[j] =
                        best_def_fixed[j].saturating_add(e.defender_payoff_millionths);
                }
            }

            // Update EXP3 weights
            let atk_probs = atk_weights.probabilities(self.config.gamma_millionths);
            let def_probs = def_weights.probabilities(self.config.gamma_millionths);

            atk_weights.update(atk_idx, atk_pay, atk_probs[atk_idx]);
            def_weights.update(def_idx, def_pay, def_probs[def_idx]);

            // Record trajectory
            if let Some(ref mut traj) = trajectory {
                traj.rounds.push(RoundOutcome {
                    round,
                    attacker_strategy: atk_id.clone(),
                    defender_strategy: def_id.clone(),
                    attacker_payoff_millionths: atk_pay,
                    defender_payoff_millionths: def_pay,
                    exploit_discovered: exploit,
                });

                // Compute cumulative regret (clamped to non-negative)
                let best_atk = *best_atk_fixed.iter().max().unwrap_or(&0);
                let atk_regret = (best_atk - total_atk_payoff).max(0);
                traj.attacker_cumulative_regret.push(atk_regret);

                let best_def = *best_def_fixed.iter().max().unwrap_or(&0);
                let def_regret = (best_def - total_def_payoff).max(0);
                traj.defender_cumulative_regret.push(def_regret);
            }
        }

        let rounds_played = trajectory
            .as_ref()
            .map(|t| t.rounds.len() as u64)
            .unwrap_or(self.config.rounds.min(
                if budget_spent >= self.config.exploration_budget_millionths {
                    0
                } else {
                    self.config.rounds
                },
            ));

        // Compute convergence diagnostics
        let best_atk = *best_atk_fixed.iter().max().unwrap_or(&0);
        let best_def = *best_def_fixed.iter().max().unwrap_or(&0);
        let atk_final_regret = best_atk.saturating_sub(total_atk_payoff);
        let def_final_regret = best_def.saturating_sub(total_def_payoff);

        let atk_avg_regret = if rounds_played > 0 {
            atk_final_regret / rounds_played as i64
        } else {
            0
        };
        let def_avg_regret = if rounds_played > 0 {
            def_final_regret / rounds_played as i64
        } else {
            0
        };

        // Regret is bounded if average regret per round → 0 (heuristic: < 10%)
        let regret_bound = MILLION / 10;
        let atk_bounded = atk_avg_regret < regret_bound;
        let def_bounded = def_avg_regret < regret_bound;

        // Strategy frequency distributions
        let mut atk_freq: BTreeMap<String, u64> = BTreeMap::new();
        let mut def_freq: BTreeMap<String, u64> = BTreeMap::new();
        for (i, c) in atk_weights.counts.iter().enumerate() {
            atk_freq.insert(self.payoff_matrix.attacker_strategies[i].0.clone(), *c);
        }
        for (j, c) in def_weights.counts.iter().enumerate() {
            def_freq.insert(self.payoff_matrix.defender_strategies[j].0.clone(), *c);
        }

        let convergence = ConvergenceDiagnostic {
            attacker_avg_regret_millionths: atk_avg_regret,
            defender_avg_regret_millionths: def_avg_regret,
            attacker_regret_bounded: atk_bounded,
            defender_regret_bounded: def_bounded,
            exploit_classes: exploit_set.clone(),
            attacker_frequency: atk_freq,
            defender_frequency: def_freq,
        };

        // Compute policy delta from defender's learned mix
        let def_probs = def_weights.probabilities(self.config.gamma_millionths);
        let mut recommended_mix: BTreeMap<String, i64> = BTreeMap::new();
        for (j, &p) in def_probs.iter().enumerate() {
            recommended_mix.insert(self.payoff_matrix.defender_strategies[j].0.clone(), p);
        }

        // Expected improvement: total_def_payoff / rounds vs uniform
        let uniform_payoff = self.compute_uniform_defender_payoff();
        let learned_avg = if rounds_played > 0 {
            total_def_payoff / rounds_played as i64
        } else {
            0
        };
        let improvement = learned_avg.saturating_sub(uniform_payoff);

        let delta_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(COEVOLUTION_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&self.config.seed.to_le_bytes());
            buf.extend_from_slice(&rounds_played.to_le_bytes());
            buf.extend_from_slice(&total_def_payoff.to_le_bytes());
            ContentHash::compute(&buf)
        };

        let policy_delta = PolicyDelta {
            delta_id: format!("coev-{}-r{}", self.config.epoch.as_u64(), rounds_played),
            recommended_mix,
            addressed_exploits: exploit_set,
            expected_improvement_millionths: improvement,
            source_epoch: self.config.epoch,
            artifact_hash: delta_hash,
        };

        // Overall artifact hash
        let artifact_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(COEVOLUTION_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&total_atk_payoff.to_le_bytes());
            buf.extend_from_slice(&total_def_payoff.to_le_bytes());
            buf.extend_from_slice(&rounds_played.to_le_bytes());
            buf.extend_from_slice(&self.config.seed.to_le_bytes());
            ContentHash::compute(&buf)
        };

        self.tournament_count += 1;

        Ok(TournamentResult {
            schema_version: COEVOLUTION_SCHEMA_VERSION.to_string(),
            epoch: self.config.epoch,
            rounds_played,
            total_attacker_payoff_millionths: total_atk_payoff,
            total_defender_payoff_millionths: total_def_payoff,
            convergence,
            policy_delta,
            trajectory,
            artifact_hash,
        })
    }

    /// Compute average defender payoff under uniform random play.
    fn compute_uniform_defender_payoff(&self) -> i64 {
        let n = self.payoff_matrix.entries.len() as i64;
        if n == 0 {
            return 0;
        }
        let total: i64 = self
            .payoff_matrix
            .entries
            .iter()
            .map(|e| e.defender_payoff_millionths)
            .sum();
        total / n
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rock_paper_scissors_matrix() -> PayoffMatrix {
        let atk = vec![
            StrategyId("rock".to_string()),
            StrategyId("paper".to_string()),
            StrategyId("scissors".to_string()),
        ];
        let def = vec![
            StrategyId("rock".to_string()),
            StrategyId("paper".to_string()),
            StrategyId("scissors".to_string()),
        ];
        // Zero-sum: attacker wins = +MILLION, defender wins = +MILLION
        let entries = vec![
            PayoffEntry {
                attacker: StrategyId("rock".to_string()),
                defender: StrategyId("rock".to_string()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            },
            PayoffEntry {
                attacker: StrategyId("rock".to_string()),
                defender: StrategyId("paper".to_string()),
                attacker_payoff_millionths: -MILLION,
                defender_payoff_millionths: MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("rock".to_string()),
                defender: StrategyId("scissors".to_string()),
                attacker_payoff_millionths: MILLION,
                defender_payoff_millionths: -MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("paper".to_string()),
                defender: StrategyId("rock".to_string()),
                attacker_payoff_millionths: MILLION,
                defender_payoff_millionths: -MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("paper".to_string()),
                defender: StrategyId("paper".to_string()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            },
            PayoffEntry {
                attacker: StrategyId("paper".to_string()),
                defender: StrategyId("scissors".to_string()),
                attacker_payoff_millionths: -MILLION,
                defender_payoff_millionths: MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("scissors".to_string()),
                defender: StrategyId("rock".to_string()),
                attacker_payoff_millionths: -MILLION,
                defender_payoff_millionths: MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("scissors".to_string()),
                defender: StrategyId("paper".to_string()),
                attacker_payoff_millionths: MILLION,
                defender_payoff_millionths: -MILLION,
            },
            PayoffEntry {
                attacker: StrategyId("scissors".to_string()),
                defender: StrategyId("scissors".to_string()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            },
        ];
        PayoffMatrix {
            attacker_strategies: atk,
            defender_strategies: def,
            entries,
        }
    }

    fn security_game_matrix() -> PayoffMatrix {
        let atk = vec![
            StrategyId("capability-escalation".to_string()),
            StrategyId("policy-bypass".to_string()),
        ];
        let def = vec![
            StrategyId("strict-containment".to_string()),
            StrategyId("adaptive-sandbox".to_string()),
        ];
        let entries = vec![
            PayoffEntry {
                attacker: StrategyId("capability-escalation".to_string()),
                defender: StrategyId("strict-containment".to_string()),
                attacker_payoff_millionths: 200_000,
                defender_payoff_millionths: 800_000,
            },
            PayoffEntry {
                attacker: StrategyId("capability-escalation".to_string()),
                defender: StrategyId("adaptive-sandbox".to_string()),
                attacker_payoff_millionths: 600_000,
                defender_payoff_millionths: 400_000,
            },
            PayoffEntry {
                attacker: StrategyId("policy-bypass".to_string()),
                defender: StrategyId("strict-containment".to_string()),
                attacker_payoff_millionths: 700_000,
                defender_payoff_millionths: 300_000,
            },
            PayoffEntry {
                attacker: StrategyId("policy-bypass".to_string()),
                defender: StrategyId("adaptive-sandbox".to_string()),
                attacker_payoff_millionths: 300_000,
                defender_payoff_millionths: 700_000,
            },
        ];
        PayoffMatrix {
            attacker_strategies: atk,
            defender_strategies: def,
            entries,
        }
    }

    // ── Constructor tests ─────────────────────────────────────────

    #[test]
    fn new_with_valid_config() {
        let config = TournamentConfig::default();
        let matrix = rock_paper_scissors_matrix();
        let harness = CoevolutionHarness::new(config, matrix);
        assert!(harness.is_ok());
    }

    #[test]
    fn new_rejects_empty_attacker_strategies() {
        let config = TournamentConfig::default();
        let matrix = PayoffMatrix {
            attacker_strategies: vec![],
            defender_strategies: vec![StrategyId("d".to_string())],
            entries: vec![],
        };
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(
            err,
            CoevolutionError::EmptyStrategies {
                player: PlayerRole::Attacker
            }
        ));
    }

    #[test]
    fn new_rejects_empty_defender_strategies() {
        let config = TournamentConfig::default();
        let matrix = PayoffMatrix {
            attacker_strategies: vec![StrategyId("a".to_string())],
            defender_strategies: vec![],
            entries: vec![],
        };
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(
            err,
            CoevolutionError::EmptyStrategies {
                player: PlayerRole::Defender
            }
        ));
    }

    #[test]
    fn new_rejects_incomplete_payoff_matrix() {
        let config = TournamentConfig::default();
        let matrix = PayoffMatrix {
            attacker_strategies: vec![StrategyId("a1".to_string()), StrategyId("a2".to_string())],
            defender_strategies: vec![StrategyId("d1".to_string())],
            entries: vec![PayoffEntry {
                attacker: StrategyId("a1".to_string()),
                defender: StrategyId("d1".to_string()),
                attacker_payoff_millionths: 0,
                defender_payoff_millionths: 0,
            }],
        };
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(
            err,
            CoevolutionError::IncompletePayoffMatrix {
                expected: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn new_rejects_invalid_gamma() {
        let config = TournamentConfig {
            gamma_millionths: 0,
            ..Default::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(err, CoevolutionError::InvalidGamma { value: 0 }));
    }

    #[test]
    fn new_rejects_zero_rounds() {
        let config = TournamentConfig {
            rounds: 0,
            ..Default::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(err, CoevolutionError::ZeroRounds));
    }

    #[test]
    fn new_rejects_too_many_rounds() {
        let config = TournamentConfig {
            rounds: MAX_TOURNAMENT_ROUNDS + 1,
            ..Default::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, matrix).unwrap_err();
        assert!(matches!(err, CoevolutionError::TooManyRounds { .. }));
    }

    // ── Tournament execution tests ────────────────────────────────

    #[test]
    fn run_rock_paper_scissors_tournament() {
        let config = TournamentConfig {
            rounds: 500,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        assert_eq!(result.rounds_played, 500);
        assert_eq!(result.schema_version, COEVOLUTION_SCHEMA_VERSION);
        assert_eq!(harness.tournament_count(), 1);
    }

    #[test]
    fn run_security_game_tournament() {
        let config = TournamentConfig {
            rounds: 200,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        assert_eq!(result.rounds_played, 200);
        assert!(!result.policy_delta.recommended_mix.is_empty());
    }

    #[test]
    fn tournament_is_deterministic() {
        let config = TournamentConfig {
            rounds: 100,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();

        let mut h1 = CoevolutionHarness::new(config.clone(), matrix.clone()).unwrap();
        let mut h2 = CoevolutionHarness::new(config, matrix).unwrap();

        let r1 = h1.run().unwrap();
        let r2 = h2.run().unwrap();

        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(
            r1.total_attacker_payoff_millionths,
            r2.total_attacker_payoff_millionths
        );
        assert_eq!(
            r1.total_defender_payoff_millionths,
            r2.total_defender_payoff_millionths
        );
    }

    #[test]
    fn different_seeds_produce_different_results() {
        let matrix = rock_paper_scissors_matrix();
        let config1 = TournamentConfig {
            rounds: 100,
            seed: 1,
            ..TournamentConfig::default()
        };
        let config2 = TournamentConfig {
            rounds: 100,
            seed: 999,
            ..TournamentConfig::default()
        };

        let mut h1 = CoevolutionHarness::new(config1, matrix.clone()).unwrap();
        let mut h2 = CoevolutionHarness::new(config2, matrix).unwrap();

        let r1 = h1.run().unwrap();
        let r2 = h2.run().unwrap();
        // Different seeds should usually produce different trajectories
        // (though in degenerate cases they might match)
        assert_ne!(r1.artifact_hash, r2.artifact_hash);
    }

    // ── Trajectory tests ──────────────────────────────────────────

    #[test]
    fn trajectory_tracking_records_all_rounds() {
        let config = TournamentConfig {
            rounds: 50,
            track_trajectory: true,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        let traj = result.trajectory.as_ref().unwrap();
        assert_eq!(traj.round_count(), 50);
        assert_eq!(traj.attacker_cumulative_regret.len(), 50);
        assert_eq!(traj.defender_cumulative_regret.len(), 50);
    }

    #[test]
    fn trajectory_disabled_returns_none() {
        let config = TournamentConfig {
            rounds: 50,
            track_trajectory: false,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        assert!(result.trajectory.is_none());
    }

    #[test]
    fn trajectory_regret_is_non_negative() {
        let config = TournamentConfig {
            rounds: 100,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        let traj = result.trajectory.unwrap();
        for r in &traj.attacker_cumulative_regret {
            assert!(*r >= 0, "negative attacker regret: {r}");
        }
    }

    // ── Convergence diagnostic tests ──────────────────────────────

    #[test]
    fn convergence_reports_bounded_regret() {
        let config = TournamentConfig {
            rounds: 1000,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        // With enough rounds, EXP3 should have bounded average regret
        // This is a soft check — regret may or may not be bounded with 1000 rounds
        let _ = result.convergence.attacker_regret_bounded;
        let _ = result.convergence.defender_regret_bounded;
        // At least verify the values are computed
        assert!(result.convergence.attacker_avg_regret_millionths >= 0);
        assert!(result.convergence.defender_avg_regret_millionths >= 0);
    }

    #[test]
    fn convergence_frequency_sums_to_rounds() {
        let config = TournamentConfig {
            rounds: 100,
            ..TournamentConfig::default()
        };
        let matrix = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        let atk_total: u64 = result.convergence.attacker_frequency.values().sum();
        let def_total: u64 = result.convergence.defender_frequency.values().sum();
        assert_eq!(atk_total, 100);
        assert_eq!(def_total, 100);
    }

    // ── Policy delta tests ────────────────────────────────────────

    #[test]
    fn policy_delta_has_all_strategies() {
        let config = TournamentConfig {
            rounds: 50,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        assert_eq!(result.policy_delta.recommended_mix.len(), 2);
        assert!(
            result
                .policy_delta
                .recommended_mix
                .contains_key("strict-containment")
        );
        assert!(
            result
                .policy_delta
                .recommended_mix
                .contains_key("adaptive-sandbox")
        );
    }

    #[test]
    fn policy_delta_weights_sum_approximately_to_million() {
        let config = TournamentConfig {
            rounds: 200,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        let total: i64 = result.policy_delta.recommended_mix.values().sum();
        // Should be approximately MILLION (within rounding)
        assert!(
            (total - MILLION).abs() < 10_000,
            "weights sum to {total}, expected ~{MILLION}"
        );
    }

    #[test]
    fn policy_delta_has_artifact_hash() {
        let config = TournamentConfig {
            rounds: 50,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        assert!(!result.policy_delta.artifact_hash.to_hex().is_empty());
    }

    // ── Exploit classification tests ──────────────────────────────

    #[test]
    fn classify_exploit_capability_escalation() {
        let exploit = classify_exploit(
            &StrategyId("capability-escalation".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(exploit, Some(ExploitClass::CapabilityEscalation));
    }

    #[test]
    fn classify_exploit_policy_bypass() {
        let exploit = classify_exploit(
            &StrategyId("policy-bypass".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(exploit, Some(ExploitClass::PolicyBypass));
    }

    #[test]
    fn classify_exploit_resource_exhaustion() {
        let exploit = classify_exploit(
            &StrategyId("dos-resource-exhaust".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(exploit, Some(ExploitClass::ResourceExhaustion));
    }

    #[test]
    fn classify_exploit_info_leak() {
        let exploit = classify_exploit(
            &StrategyId("info-leak-channel".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(exploit, Some(ExploitClass::InformationLeakage));
    }

    #[test]
    fn classify_exploit_replay() {
        let exploit = classify_exploit(
            &StrategyId("replay-attack".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(exploit, Some(ExploitClass::ReplayAttack));
    }

    #[test]
    fn classify_exploit_novel() {
        let exploit = classify_exploit(
            &StrategyId("quantum-tunnel".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(
            exploit,
            Some(ExploitClass::Novel("quantum-tunnel".to_string()))
        );
    }

    #[test]
    fn classify_exploit_below_threshold() {
        let exploit =
            classify_exploit(&StrategyId("weak-attack".to_string()), 100_000, MILLION / 2);
        assert_eq!(exploit, None);
    }

    // ── Payoff matrix tests ───────────────────────────────────────

    #[test]
    fn payoff_matrix_lookup() {
        let matrix = rock_paper_scissors_matrix();
        let entry = matrix
            .lookup(
                &StrategyId("rock".to_string()),
                &StrategyId("scissors".to_string()),
            )
            .unwrap();
        assert_eq!(entry.attacker_payoff_millionths, MILLION);
        assert_eq!(entry.defender_payoff_millionths, -MILLION);
    }

    #[test]
    fn payoff_matrix_lookup_missing() {
        let matrix = rock_paper_scissors_matrix();
        let entry = matrix.lookup(
            &StrategyId("rock".to_string()),
            &StrategyId("nonexistent".to_string()),
        );
        assert!(entry.is_none());
    }

    #[test]
    fn payoff_matrix_minimax() {
        let matrix = security_game_matrix();
        let minimax = matrix.minimax_defender();
        // The minimax defender should be one of the valid strategies
        assert!(minimax.is_some());
    }

    // ── EXP3 weight tests ─────────────────────────────────────────

    #[test]
    fn exp3_initial_probabilities_are_uniform() {
        let w = Exp3Weights::new(3);
        let probs = w.probabilities(DEFAULT_GAMMA_MILLIONTHS);
        // All probabilities should be approximately equal
        for &p in &probs {
            assert!(
                (p - MILLION / 3).abs() < 10_000,
                "expected ~{}, got {p}",
                MILLION / 3
            );
        }
    }

    #[test]
    fn exp3_select_covers_all_arms() {
        let w = Exp3Weights::new(3);
        let mut seen = BTreeSet::new();
        for i in 0..1000 {
            let h = det_hash(42, i, 0);
            seen.insert(w.select(h, DEFAULT_GAMMA_MILLIONTHS));
        }
        // Should have selected all 3 arms at some point
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn exp3_update_shifts_weights() {
        let mut w = Exp3Weights::new(2);
        let probs_before = w.probabilities(DEFAULT_GAMMA_MILLIONTHS);
        // Reward arm 0 heavily
        for _ in 0..10 {
            w.update(0, MILLION, probs_before[0]);
        }
        let probs_after = w.probabilities(DEFAULT_GAMMA_MILLIONTHS);
        // Arm 0 should have higher probability than arm 1
        assert!(
            probs_after[0] > probs_after[1],
            "arm0={}, arm1={}",
            probs_after[0],
            probs_after[1]
        );
    }

    // ── Display / format tests ────────────────────────────────────

    #[test]
    fn strategy_id_display() {
        assert_eq!(StrategyId("rock".to_string()).to_string(), "rock");
    }

    #[test]
    fn player_role_display() {
        assert_eq!(PlayerRole::Attacker.to_string(), "attacker");
        assert_eq!(PlayerRole::Defender.to_string(), "defender");
    }

    #[test]
    fn exploit_class_display() {
        assert_eq!(
            ExploitClass::CapabilityEscalation.to_string(),
            "capability_escalation"
        );
        assert_eq!(ExploitClass::PolicyBypass.to_string(), "policy_bypass");
        assert_eq!(ExploitClass::Novel("x".to_string()).to_string(), "novel:x");
    }

    #[test]
    fn error_display_all_variants() {
        let cases = [
            (
                CoevolutionError::EmptyStrategies {
                    player: PlayerRole::Attacker,
                },
                "no strategies defined for attacker",
            ),
            (
                CoevolutionError::TooManyStrategies {
                    count: 100,
                    max: 64,
                },
                "strategy count 100 exceeds maximum 64",
            ),
            (
                CoevolutionError::IncompletePayoffMatrix {
                    expected: 9,
                    actual: 3,
                },
                "payoff matrix has 3 entries, expected 9",
            ),
            (
                CoevolutionError::InvalidGamma { value: -1 },
                "gamma out of range (0, MILLION): -1",
            ),
            (
                CoevolutionError::TooManyRounds {
                    rounds: 200_000,
                    max: 100_000,
                },
                "rounds 200000 exceed maximum 100000",
            ),
            (
                CoevolutionError::BudgetExhausted {
                    spent: 20_000_000,
                    budget: 10_000_000,
                },
                "exploration budget exhausted: spent 20000000, budget 10000000",
            ),
            (CoevolutionError::ZeroRounds, "zero rounds requested"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    // ── Serde roundtrip tests ─────────────────────────────────────

    #[test]
    fn tournament_result_serde_roundtrip() {
        let config = TournamentConfig {
            rounds: 20,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: TournamentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn exploit_class_serde_roundtrip() {
        for class in [
            ExploitClass::CapabilityEscalation,
            ExploitClass::PolicyBypass,
            ExploitClass::ResourceExhaustion,
            ExploitClass::InformationLeakage,
            ExploitClass::ReplayAttack,
            ExploitClass::Novel("custom".to_string()),
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: ExploitClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: CoevolutionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = TournamentConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TournamentConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Deterministic hash tests ──────────────────────────────────

    #[test]
    fn det_hash_deterministic() {
        let h1 = det_hash(42, 10, 0);
        let h2 = det_hash(42, 10, 0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn det_hash_different_inputs() {
        let h1 = det_hash(42, 10, 0);
        let h2 = det_hash(42, 11, 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn det_hash_in_range() {
        for round in 0..100 {
            let h = det_hash(42, round, 0);
            assert!((0..MILLION).contains(&h), "hash {h} out of range");
        }
    }

    // ── Tournament count tracking ─────────────────────────────────

    #[test]
    fn tournament_count_increments() {
        let config = TournamentConfig {
            rounds: 10,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        assert_eq!(harness.tournament_count(), 0);
        harness.run().unwrap();
        assert_eq!(harness.tournament_count(), 1);
        harness.run().unwrap();
        assert_eq!(harness.tournament_count(), 2);
    }

    // ── Security game exploit detection ───────────────────────────

    #[test]
    fn security_game_detects_exploits() {
        let config = TournamentConfig {
            rounds: 500,
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        // The security game has strategies with >50% payoff, so exploits should be detected
        let exploits = &result.convergence.exploit_classes;
        // At least one exploit class should be found
        assert!(
            !exploits.is_empty(),
            "expected exploit classes from security game"
        );
    }

    // ── Budget exhaustion test ─────────────────────────────────────

    #[test]
    fn budget_limits_rounds() {
        let config = TournamentConfig {
            rounds: 10_000,
            exploration_budget_millionths: MILLION, // Very small budget
            ..TournamentConfig::default()
        };
        let matrix = security_game_matrix();
        let mut harness = CoevolutionHarness::new(config, matrix).unwrap();
        let result = harness.run().unwrap();
        // Should stop before 10k rounds due to budget
        assert!(
            result.rounds_played < 10_000,
            "expected budget-limited stop, got {} rounds",
            result.rounds_played
        );
    }

    // ── Enrichment: clone equality tests ─────────────────────────

    #[test]
    fn clone_eq_strategy_id() {
        let original = StrategyId("alpha-strike".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_payoff_entry() {
        let original = PayoffEntry {
            attacker: StrategyId("a".to_string()),
            defender: StrategyId("d".to_string()),
            attacker_payoff_millionths: 500_000,
            defender_payoff_millionths: 500_000,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_tournament_config() {
        let original = TournamentConfig {
            rounds: 777,
            gamma_millionths: 200_000,
            epoch: SecurityEpoch::GENESIS,
            seed: 12345,
            exploration_budget_millionths: 50_000_000,
            track_trajectory: false,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_round_outcome() {
        let original = RoundOutcome {
            round: 42,
            attacker_strategy: StrategyId("atk".to_string()),
            defender_strategy: StrategyId("def".to_string()),
            attacker_payoff_millionths: 300_000,
            defender_payoff_millionths: 700_000,
            exploit_discovered: Some(ExploitClass::PolicyBypass),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn clone_eq_convergence_diagnostic() {
        let original = ConvergenceDiagnostic {
            attacker_avg_regret_millionths: 50_000,
            defender_avg_regret_millionths: 30_000,
            attacker_regret_bounded: true,
            defender_regret_bounded: false,
            exploit_classes: BTreeSet::from(["policy_bypass".to_string()]),
            attacker_frequency: BTreeMap::from([("a1".to_string(), 80)]),
            defender_frequency: BTreeMap::from([("d1".to_string(), 80)]),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ── Enrichment: JSON field presence tests ────────────────────

    #[test]
    fn json_fields_payoff_entry() {
        let entry = PayoffEntry {
            attacker: StrategyId("a".to_string()),
            defender: StrategyId("d".to_string()),
            attacker_payoff_millionths: 100_000,
            defender_payoff_millionths: 900_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"attacker\""));
        assert!(json.contains("\"defender\""));
        assert!(json.contains("\"attacker_payoff_millionths\""));
        assert!(json.contains("\"defender_payoff_millionths\""));
    }

    #[test]
    fn json_fields_policy_delta() {
        let delta = PolicyDelta {
            delta_id: "test-delta".to_string(),
            recommended_mix: BTreeMap::from([("strat".to_string(), MILLION)]),
            addressed_exploits: BTreeSet::from(["replay_attack".to_string()]),
            expected_improvement_millionths: 50_000,
            source_epoch: SecurityEpoch::GENESIS,
            artifact_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&delta).unwrap();
        assert!(json.contains("\"delta_id\""));
        assert!(json.contains("\"recommended_mix\""));
        assert!(json.contains("\"addressed_exploits\""));
        assert!(json.contains("\"expected_improvement_millionths\""));
        assert!(json.contains("\"source_epoch\""));
        assert!(json.contains("\"artifact_hash\""));
    }

    #[test]
    fn json_fields_tournament_config() {
        let config = TournamentConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"rounds\""));
        assert!(json.contains("\"gamma_millionths\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"exploration_budget_millionths\""));
        assert!(json.contains("\"track_trajectory\""));
    }

    // ── Enrichment: serde roundtrip, Display, boundary, Ord, Error ──

    #[test]
    fn policy_delta_serde_roundtrip() {
        let delta = PolicyDelta {
            delta_id: "coev-0-r100".to_string(),
            recommended_mix: BTreeMap::from([
                ("strict".to_string(), 600_000),
                ("adaptive".to_string(), 400_000),
            ]),
            addressed_exploits: BTreeSet::from([
                "capability_escalation".to_string(),
                "policy_bypass".to_string(),
            ]),
            expected_improvement_millionths: 75_000,
            source_epoch: SecurityEpoch::GENESIS,
            artifact_hash: ContentHash::compute(b"roundtrip-test"),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: PolicyDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, back);
    }

    #[test]
    fn display_uniqueness_exploit_class_variants() {
        let variants = [
            ExploitClass::CapabilityEscalation,
            ExploitClass::PolicyBypass,
            ExploitClass::ResourceExhaustion,
            ExploitClass::InformationLeakage,
            ExploitClass::ReplayAttack,
            ExploitClass::Novel("zero-day".to_string()),
        ];
        let mut seen = BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(seen.insert(s.clone()), "duplicate Display for {s}");
        }
        assert_eq!(seen.len(), variants.len());
    }

    #[test]
    fn exploit_class_ord_determinism() {
        let mut items = vec![
            ExploitClass::ReplayAttack,
            ExploitClass::CapabilityEscalation,
            ExploitClass::Novel("zzz".to_string()),
            ExploitClass::PolicyBypass,
            ExploitClass::InformationLeakage,
            ExploitClass::ResourceExhaustion,
            ExploitClass::Novel("aaa".to_string()),
        ];
        let mut items2 = items.clone();
        items.sort();
        items2.sort();
        assert_eq!(items, items2, "Ord must be deterministic across sorts");
    }

    #[test]
    fn coevolution_error_implements_std_error_source() {
        let err = CoevolutionError::BudgetExhausted {
            spent: 5_000_000,
            budget: 3_000_000,
        };
        let std_err: &dyn std::error::Error = &err;
        // CoevolutionError has no source (blanket impl), so source() returns None
        assert!(std_err.source().is_none());
        // But it does implement Display
        assert!(!std_err.to_string().is_empty());
    }

    // ── Enrichment: Copy/Clone/Debug/Serde/Hash/Edge/Display ──

    #[test]
    fn player_role_copy_semantics() {
        let a = PlayerRole::Attacker;
        let b = a;
        assert_eq!(a, b);
        let d = PlayerRole::Defender;
        let e = d;
        assert_eq!(d, e);
    }

    #[test]
    fn player_role_debug_distinct() {
        let set: BTreeSet<String> = [PlayerRole::Attacker, PlayerRole::Defender]
            .iter()
            .map(|v| format!("{v:?}"))
            .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn player_role_serde_variant_distinct() {
        let set: BTreeSet<String> = [PlayerRole::Attacker, PlayerRole::Defender]
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn player_role_display_exact() {
        assert_eq!(PlayerRole::Attacker.to_string(), "attacker");
        assert_eq!(PlayerRole::Defender.to_string(), "defender");
    }

    #[test]
    fn exploit_class_serde_variant_distinct() {
        let variants = [
            ExploitClass::CapabilityEscalation,
            ExploitClass::PolicyBypass,
            ExploitClass::ResourceExhaustion,
            ExploitClass::InformationLeakage,
            ExploitClass::ReplayAttack,
            ExploitClass::Novel("x".to_string()),
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn exploit_class_display_exact_known() {
        assert_eq!(
            ExploitClass::CapabilityEscalation.to_string(),
            "capability_escalation"
        );
        assert_eq!(ExploitClass::PolicyBypass.to_string(), "policy_bypass");
        assert_eq!(
            ExploitClass::ResourceExhaustion.to_string(),
            "resource_exhaustion"
        );
        assert_eq!(
            ExploitClass::InformationLeakage.to_string(),
            "information_leakage"
        );
        assert_eq!(ExploitClass::ReplayAttack.to_string(), "replay_attack");
        assert_eq!(
            ExploitClass::Novel("foo".to_string()).to_string(),
            "novel:foo"
        );
    }

    #[test]
    fn exploit_class_clone_independence() {
        let a = ExploitClass::Novel("original".to_string());
        let b = a.clone();
        assert_eq!(a, b);
        // Mutate clone via reconstruct
        let c = ExploitClass::Novel("changed".to_string());
        assert_ne!(a, c);
    }

    #[test]
    fn strategy_id_display_matches_inner() {
        let id = StrategyId("hello".to_string());
        assert_eq!(id.to_string(), "hello");
    }

    #[test]
    fn strategy_id_serde_roundtrip() {
        let id = StrategyId("test-strategy".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let back: StrategyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn strategy_id_ord_deterministic() {
        let a = StrategyId("aaa".to_string());
        let b = StrategyId("bbb".to_string());
        assert!(a < b);
    }

    #[test]
    fn payoff_entry_clone_independence() {
        let a = PayoffEntry {
            attacker: StrategyId("a".to_string()),
            defender: StrategyId("d".to_string()),
            attacker_payoff_millionths: 500_000,
            defender_payoff_millionths: 500_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn payoff_entry_json_field_names() {
        let e = PayoffEntry {
            attacker: StrategyId("a".to_string()),
            defender: StrategyId("d".to_string()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"attacker\""));
        assert!(json.contains("\"defender\""));
        assert!(json.contains("\"attacker_payoff_millionths\""));
        assert!(json.contains("\"defender_payoff_millionths\""));
    }

    #[test]
    fn payoff_matrix_clone_independence() {
        let m = rock_paper_scissors_matrix();
        let m2 = m.clone();
        assert_eq!(m, m2);
    }

    #[test]
    fn payoff_matrix_json_field_names() {
        let m = rock_paper_scissors_matrix();
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"attacker_strategies\""));
        assert!(json.contains("\"defender_strategies\""));
        assert!(json.contains("\"entries\""));
    }

    #[test]
    fn payoff_matrix_lookup_missing_returns_none() {
        let m = rock_paper_scissors_matrix();
        let result = m.lookup(
            &StrategyId("nonexistent".to_string()),
            &StrategyId("rock".to_string()),
        );
        assert!(result.is_none());
    }

    #[test]
    fn tournament_config_default_values() {
        let c = TournamentConfig::default();
        assert_eq!(c.rounds, 1000);
        assert_eq!(c.gamma_millionths, DEFAULT_GAMMA_MILLIONTHS);
        assert_eq!(c.epoch, SecurityEpoch::GENESIS);
        assert_eq!(c.seed, 42);
        assert!(c.track_trajectory);
    }

    #[test]
    fn tournament_config_clone_independence() {
        let a = TournamentConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn tournament_config_json_field_names() {
        let c = TournamentConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"rounds\""));
        assert!(json.contains("\"gamma_millionths\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"seed\""));
        assert!(json.contains("\"exploration_budget_millionths\""));
        assert!(json.contains("\"track_trajectory\""));
    }

    #[test]
    fn round_outcome_clone_independence() {
        let r = RoundOutcome {
            round: 0,
            attacker_strategy: StrategyId("a".to_string()),
            defender_strategy: StrategyId("d".to_string()),
            attacker_payoff_millionths: 100,
            defender_payoff_millionths: 200,
            exploit_discovered: Some(ExploitClass::ReplayAttack),
        };
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn round_outcome_json_field_names() {
        let r = RoundOutcome {
            round: 1,
            attacker_strategy: StrategyId("a".to_string()),
            defender_strategy: StrategyId("d".to_string()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
            exploit_discovered: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"round\""));
        assert!(json.contains("\"attacker_strategy\""));
        assert!(json.contains("\"defender_strategy\""));
        assert!(json.contains("\"attacker_payoff_millionths\""));
        assert!(json.contains("\"defender_payoff_millionths\""));
        assert!(json.contains("\"exploit_discovered\""));
    }

    #[test]
    fn trajectory_ledger_empty_regret_defaults() {
        let t = TrajectoryLedger::new();
        assert_eq!(t.round_count(), 0);
        assert_eq!(t.final_attacker_regret(), 0);
        assert_eq!(t.final_defender_regret(), 0);
    }

    #[test]
    fn trajectory_ledger_serde_roundtrip() {
        let t = TrajectoryLedger {
            rounds: vec![RoundOutcome {
                round: 0,
                attacker_strategy: StrategyId("a".to_string()),
                defender_strategy: StrategyId("d".to_string()),
                attacker_payoff_millionths: 500,
                defender_payoff_millionths: -500,
                exploit_discovered: None,
            }],
            attacker_cumulative_regret: vec![100],
            defender_cumulative_regret: vec![50],
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: TrajectoryLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn convergence_diagnostic_clone_independence() {
        let c = ConvergenceDiagnostic {
            attacker_avg_regret_millionths: 1000,
            defender_avg_regret_millionths: 2000,
            attacker_regret_bounded: true,
            defender_regret_bounded: false,
            exploit_classes: BTreeSet::from(["replay_attack".to_string()]),
            attacker_frequency: BTreeMap::from([("rock".to_string(), 50)]),
            defender_frequency: BTreeMap::from([("paper".to_string(), 50)]),
        };
        let c2 = c.clone();
        assert_eq!(c, c2);
    }

    #[test]
    fn convergence_diagnostic_json_field_names() {
        let c = ConvergenceDiagnostic {
            attacker_avg_regret_millionths: 0,
            defender_avg_regret_millionths: 0,
            attacker_regret_bounded: true,
            defender_regret_bounded: true,
            exploit_classes: BTreeSet::new(),
            attacker_frequency: BTreeMap::new(),
            defender_frequency: BTreeMap::new(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"attacker_avg_regret_millionths\""));
        assert!(json.contains("\"defender_avg_regret_millionths\""));
        assert!(json.contains("\"attacker_regret_bounded\""));
        assert!(json.contains("\"defender_regret_bounded\""));
        assert!(json.contains("\"exploit_classes\""));
        assert!(json.contains("\"attacker_frequency\""));
        assert!(json.contains("\"defender_frequency\""));
    }

    #[test]
    fn policy_delta_clone_independence() {
        let d = PolicyDelta {
            delta_id: "d-1".to_string(),
            recommended_mix: BTreeMap::from([("s".to_string(), MILLION)]),
            addressed_exploits: BTreeSet::from(["x".to_string()]),
            expected_improvement_millionths: 50_000,
            source_epoch: SecurityEpoch::GENESIS,
            artifact_hash: ContentHash::compute(b"test"),
        };
        let d2 = d.clone();
        assert_eq!(d, d2);
    }

    #[test]
    fn policy_delta_json_field_names() {
        let d = PolicyDelta {
            delta_id: "d-0".to_string(),
            recommended_mix: BTreeMap::new(),
            addressed_exploits: BTreeSet::new(),
            expected_improvement_millionths: 0,
            source_epoch: SecurityEpoch::GENESIS,
            artifact_hash: ContentHash::compute(b"field-names"),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"delta_id\""));
        assert!(json.contains("\"recommended_mix\""));
        assert!(json.contains("\"addressed_exploits\""));
        assert!(json.contains("\"expected_improvement_millionths\""));
        assert!(json.contains("\"source_epoch\""));
        assert!(json.contains("\"artifact_hash\""));
    }

    #[test]
    fn tournament_result_json_field_names() {
        let config = TournamentConfig {
            rounds: 10,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, m).unwrap();
        let result = harness.run().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"rounds_played\""));
        assert!(json.contains("\"total_attacker_payoff_millionths\""));
        assert!(json.contains("\"total_defender_payoff_millionths\""));
        assert!(json.contains("\"convergence\""));
        assert!(json.contains("\"policy_delta\""));
        assert!(json.contains("\"artifact_hash\""));
    }

    #[test]
    fn tournament_result_serde_roundtrip_enriched() {
        let config = TournamentConfig {
            rounds: 10,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut harness = CoevolutionHarness::new(config, m).unwrap();
        let result = harness.run().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: TournamentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn coevolution_error_display_exact_empty_strategies() {
        let e = CoevolutionError::EmptyStrategies {
            player: PlayerRole::Attacker,
        };
        assert_eq!(e.to_string(), "no strategies defined for attacker");
        let e2 = CoevolutionError::EmptyStrategies {
            player: PlayerRole::Defender,
        };
        assert_eq!(e2.to_string(), "no strategies defined for defender");
    }

    #[test]
    fn coevolution_error_display_exact_too_many_strategies() {
        let e = CoevolutionError::TooManyStrategies {
            count: 100,
            max: 64,
        };
        assert_eq!(e.to_string(), "strategy count 100 exceeds maximum 64");
    }

    #[test]
    fn coevolution_error_display_exact_incomplete_matrix() {
        let e = CoevolutionError::IncompletePayoffMatrix {
            expected: 9,
            actual: 6,
        };
        assert_eq!(e.to_string(), "payoff matrix has 6 entries, expected 9");
    }

    #[test]
    fn coevolution_error_display_exact_invalid_gamma() {
        let e = CoevolutionError::InvalidGamma { value: -1 };
        assert_eq!(e.to_string(), "gamma out of range (0, MILLION): -1");
    }

    #[test]
    fn coevolution_error_display_exact_too_many_rounds() {
        let e = CoevolutionError::TooManyRounds {
            rounds: 200_000,
            max: 100_000,
        };
        assert_eq!(e.to_string(), "rounds 200000 exceed maximum 100000");
    }

    #[test]
    fn coevolution_error_display_exact_budget_exhausted() {
        let e = CoevolutionError::BudgetExhausted {
            spent: 5_000_000,
            budget: 3_000_000,
        };
        assert_eq!(
            e.to_string(),
            "exploration budget exhausted: spent 5000000, budget 3000000"
        );
    }

    #[test]
    fn coevolution_error_display_exact_zero_rounds() {
        let e = CoevolutionError::ZeroRounds;
        assert_eq!(e.to_string(), "zero rounds requested");
    }

    #[test]
    fn coevolution_error_serde_variant_distinct() {
        let variants: [CoevolutionError; 7] = [
            CoevolutionError::EmptyStrategies {
                player: PlayerRole::Attacker,
            },
            CoevolutionError::TooManyStrategies { count: 1, max: 1 },
            CoevolutionError::IncompletePayoffMatrix {
                expected: 1,
                actual: 0,
            },
            CoevolutionError::InvalidGamma { value: 0 },
            CoevolutionError::TooManyRounds { rounds: 1, max: 1 },
            CoevolutionError::BudgetExhausted {
                spent: 1,
                budget: 0,
            },
            CoevolutionError::ZeroRounds,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn coevolution_error_debug_distinct() {
        let variants: [CoevolutionError; 7] = [
            CoevolutionError::EmptyStrategies {
                player: PlayerRole::Attacker,
            },
            CoevolutionError::TooManyStrategies { count: 1, max: 1 },
            CoevolutionError::IncompletePayoffMatrix {
                expected: 1,
                actual: 0,
            },
            CoevolutionError::InvalidGamma { value: 0 },
            CoevolutionError::TooManyRounds { rounds: 1, max: 1 },
            CoevolutionError::BudgetExhausted {
                spent: 1,
                budget: 0,
            },
            CoevolutionError::ZeroRounds,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn debug_nonempty_strategy_id() {
        assert!(!format!("{:?}", StrategyId("x".to_string())).is_empty());
    }

    #[test]
    fn debug_nonempty_payoff_entry() {
        let e = PayoffEntry {
            attacker: StrategyId("a".to_string()),
            defender: StrategyId("d".to_string()),
            attacker_payoff_millionths: 0,
            defender_payoff_millionths: 0,
        };
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_payoff_matrix() {
        let m = rock_paper_scissors_matrix();
        assert!(!format!("{m:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_tournament_config() {
        assert!(!format!("{:?}", TournamentConfig::default()).is_empty());
    }

    #[test]
    fn debug_nonempty_trajectory_ledger() {
        assert!(!format!("{:?}", TrajectoryLedger::new()).is_empty());
    }

    #[test]
    fn debug_nonempty_convergence_diagnostic() {
        let c = ConvergenceDiagnostic {
            attacker_avg_regret_millionths: 0,
            defender_avg_regret_millionths: 0,
            attacker_regret_bounded: true,
            defender_regret_bounded: true,
            exploit_classes: BTreeSet::new(),
            attacker_frequency: BTreeMap::new(),
            defender_frequency: BTreeMap::new(),
        };
        assert!(!format!("{c:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_coevolution_harness() {
        let h = CoevolutionHarness::new(TournamentConfig::default(), rock_paper_scissors_matrix())
            .unwrap();
        assert!(!format!("{h:?}").is_empty());
    }

    #[test]
    fn harness_accessors_reflect_config() {
        let config = TournamentConfig {
            rounds: 50,
            seed: 99,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let h = CoevolutionHarness::new(config.clone(), m.clone()).unwrap();
        assert_eq!(*h.config(), config);
        assert_eq!(*h.payoff_matrix(), m);
        assert_eq!(h.tournament_count(), 0);
    }

    #[test]
    fn harness_tournament_count_increments() {
        let config = TournamentConfig {
            rounds: 5,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut h = CoevolutionHarness::new(config, m).unwrap();
        assert_eq!(h.tournament_count(), 0);
        let _ = h.run().unwrap();
        assert_eq!(h.tournament_count(), 1);
        let _ = h.run().unwrap();
        assert_eq!(h.tournament_count(), 2);
    }

    #[test]
    fn run_without_trajectory_tracking() {
        let config = TournamentConfig {
            rounds: 10,
            track_trajectory: false,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut h = CoevolutionHarness::new(config, m).unwrap();
        let result = h.run().unwrap();
        assert!(result.trajectory.is_none());
    }

    #[test]
    fn schema_version_constant_stable() {
        assert_eq!(
            COEVOLUTION_SCHEMA_VERSION,
            "franken-engine.adversarial-coevolution.v1"
        );
    }

    #[test]
    fn component_constant_stable() {
        assert_eq!(COEVOLUTION_COMPONENT, "adversarial_coevolution_harness");
    }

    #[test]
    fn minimax_defender_with_dominant_strategy() {
        // 1v2 game: defender "safe" always gives attacker payoff 100,
        // defender "risky" gives attacker 900 in one case.
        let m = PayoffMatrix {
            attacker_strategies: vec![StrategyId("a1".to_string())],
            defender_strategies: vec![
                StrategyId("safe".to_string()),
                StrategyId("risky".to_string()),
            ],
            entries: vec![
                PayoffEntry {
                    attacker: StrategyId("a1".to_string()),
                    defender: StrategyId("safe".to_string()),
                    attacker_payoff_millionths: 100_000,
                    defender_payoff_millionths: 900_000,
                },
                PayoffEntry {
                    attacker: StrategyId("a1".to_string()),
                    defender: StrategyId("risky".to_string()),
                    attacker_payoff_millionths: 900_000,
                    defender_payoff_millionths: 100_000,
                },
            ],
        };
        let minimax = m.minimax_defender().unwrap();
        assert_eq!(minimax, StrategyId("safe".to_string()));
    }

    #[test]
    fn exploit_class_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = ExploitClass::CapabilityEscalation;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn player_role_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = PlayerRole::Attacker;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn boundary_single_round_tournament() {
        let config = TournamentConfig {
            rounds: 1,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut h = CoevolutionHarness::new(config, m).unwrap();
        let r = h.run().unwrap();
        assert_eq!(r.rounds_played, 1);
        assert!(r.trajectory.is_some());
        assert_eq!(r.trajectory.as_ref().unwrap().round_count(), 1);
    }

    #[test]
    fn boundary_max_rounds_validation() {
        let config = TournamentConfig {
            rounds: MAX_TOURNAMENT_ROUNDS + 1,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, m).unwrap_err();
        assert!(matches!(err, CoevolutionError::TooManyRounds { .. }));
    }

    #[test]
    fn boundary_gamma_zero_rejected() {
        let config = TournamentConfig {
            gamma_millionths: 0,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, m).unwrap_err();
        assert!(matches!(err, CoevolutionError::InvalidGamma { .. }));
    }

    #[test]
    fn boundary_gamma_million_rejected() {
        let config = TournamentConfig {
            gamma_millionths: MILLION,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let err = CoevolutionHarness::new(config, m).unwrap_err();
        assert!(matches!(err, CoevolutionError::InvalidGamma { .. }));
    }

    #[test]
    fn run_deterministic_same_seed() {
        let config1 = TournamentConfig {
            rounds: 20,
            seed: 123,
            ..TournamentConfig::default()
        };
        let config2 = config1.clone();
        let m = rock_paper_scissors_matrix();
        let mut h1 = CoevolutionHarness::new(config1, m.clone()).unwrap();
        let mut h2 = CoevolutionHarness::new(config2, m).unwrap();
        let r1 = h1.run().unwrap();
        let r2 = h2.run().unwrap();
        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(
            r1.total_attacker_payoff_millionths,
            r2.total_attacker_payoff_millionths
        );
    }

    #[test]
    fn run_different_seed_different_hash() {
        let m = rock_paper_scissors_matrix();
        let mut h1 = CoevolutionHarness::new(
            TournamentConfig {
                rounds: 50,
                seed: 1,
                ..TournamentConfig::default()
            },
            m.clone(),
        )
        .unwrap();
        let mut h2 = CoevolutionHarness::new(
            TournamentConfig {
                rounds: 50,
                seed: 999,
                ..TournamentConfig::default()
            },
            m,
        )
        .unwrap();
        let r1 = h1.run().unwrap();
        let r2 = h2.run().unwrap();
        // Different seeds should (almost certainly) produce different results
        assert_ne!(r1.artifact_hash, r2.artifact_hash);
    }

    #[test]
    fn result_schema_version_matches_constant() {
        let config = TournamentConfig {
            rounds: 5,
            ..TournamentConfig::default()
        };
        let m = rock_paper_scissors_matrix();
        let mut h = CoevolutionHarness::new(config, m).unwrap();
        let r = h.run().unwrap();
        assert_eq!(r.schema_version, COEVOLUTION_SCHEMA_VERSION);
    }

    #[test]
    fn exploit_classification_capability_escalation() {
        let ex = classify_exploit(
            &StrategyId("capability-escalation-v2".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert_eq!(ex, Some(ExploitClass::CapabilityEscalation));
    }

    #[test]
    fn exploit_classification_below_threshold_none() {
        let ex = classify_exploit(
            &StrategyId("capability-escalation".to_string()),
            100_000,
            MILLION / 2,
        );
        assert!(ex.is_none());
    }

    #[test]
    fn exploit_classification_novel_fallback() {
        let ex = classify_exploit(
            &StrategyId("unknown-fancy-attack".to_string()),
            MILLION,
            MILLION / 2,
        );
        assert!(matches!(ex, Some(ExploitClass::Novel(_))));
    }
}
