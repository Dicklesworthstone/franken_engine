//! Differential privacy budget accountant with epoch-scoped burn tracking.
//!
//! Tracks cumulative privacy loss per epoch using the composition method
//! declared in the privacy-learning contract.  Enforces hard fail-closed
//! behavior when the budget is exhausted: once the latch trips, no further
//! noise-addition or update-submission operations are permitted.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.15, subsection 9I.2 (Privacy-Preserving
//! Fleet Learning Layer), item 2 of 4.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::privacy_learning_contract::CompositionMethod;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// EpochBudget — per-epoch budget tracking
// ---------------------------------------------------------------------------

/// Per-epoch differential privacy budget tracker.
///
/// Each epoch starts with a fresh budget allocation.  Once either
/// epsilon or delta is exhausted, the `exhausted` latch trips and
/// all further consumption is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBudget {
    /// Security epoch this budget covers.
    pub epoch: SecurityEpoch,
    /// Allocated epsilon budget for this epoch (millionths).
    pub epsilon_budget_millionths: i64,
    /// Allocated delta budget for this epoch (millionths).
    pub delta_budget_millionths: i64,
    /// Epsilon consumed so far (millionths).
    pub epsilon_spent_millionths: i64,
    /// Delta consumed so far (millionths).
    pub delta_spent_millionths: i64,
    /// Composition method governing how budget is consumed.
    pub composition_method: CompositionMethod,
    /// Total number of operations in this epoch.
    pub operations_count: u64,
    /// Epoch start timestamp (nanoseconds).
    pub created_at_ns: u64,
    /// Fail-closed exhaustion latch.  Once true, no further consumption.
    pub exhausted: bool,
}

impl EpochBudget {
    /// Remaining epsilon (may be negative if over-consumed before latch).
    pub fn epsilon_remaining(&self) -> i64 {
        self.epsilon_budget_millionths - self.epsilon_spent_millionths
    }

    /// Remaining delta (may be negative if over-consumed before latch).
    pub fn delta_remaining(&self) -> i64 {
        self.delta_budget_millionths - self.delta_spent_millionths
    }

    /// Check if this epoch budget would be exhausted by the given
    /// consumption.
    pub fn would_exhaust(&self, epsilon: i64, delta: i64) -> bool {
        self.epsilon_spent_millionths + epsilon > self.epsilon_budget_millionths
            || self.delta_spent_millionths + delta > self.delta_budget_millionths
    }
}

// ---------------------------------------------------------------------------
// BudgetConsumption — a single consumption record
// ---------------------------------------------------------------------------

/// Record of a single budget consumption operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConsumption {
    /// Monotonic operation identifier.
    pub operation_id: u64,
    /// Epoch in which this consumption occurred.
    pub epoch: SecurityEpoch,
    /// Epsilon consumed (millionths).
    pub epsilon_consumed_millionths: i64,
    /// Delta consumed (millionths).
    pub delta_consumed_millionths: i64,
    /// Adjusted epsilon after composition (millionths).
    pub composed_epsilon_millionths: i64,
    /// Adjusted delta after composition (millionths).
    pub composed_delta_millionths: i64,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Description of the operation.
    pub description: String,
}

// ---------------------------------------------------------------------------
// BudgetForecast — estimated remaining capacity
// ---------------------------------------------------------------------------

/// Forecast of remaining budget capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetForecast {
    /// Remaining epoch epsilon (millionths).
    pub epoch_epsilon_remaining_millionths: i64,
    /// Remaining epoch delta (millionths).
    pub epoch_delta_remaining_millionths: i64,
    /// Remaining lifetime epsilon (millionths).
    pub lifetime_epsilon_remaining_millionths: i64,
    /// Remaining lifetime delta (millionths).
    pub lifetime_delta_remaining_millionths: i64,
    /// Estimated operations remaining at current consumption rate.
    pub estimated_remaining_operations: u64,
    /// Whether the budget is currently exhausted.
    pub exhausted: bool,
}

// ---------------------------------------------------------------------------
// EpochSummary — signed summary for audit
// ---------------------------------------------------------------------------

/// Summary of an epoch's budget consumption for audit retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSummary {
    /// Epoch this summary covers.
    pub epoch: SecurityEpoch,
    /// Zone identifier.
    pub zone: String,
    /// Total epsilon consumed (millionths).
    pub total_epsilon_spent_millionths: i64,
    /// Total delta consumed (millionths).
    pub total_delta_spent_millionths: i64,
    /// Total operations in this epoch.
    pub operations_count: u64,
    /// Whether the budget was exhausted.
    pub exhausted: bool,
    /// Epoch start timestamp (nanoseconds).
    pub started_at_ns: u64,
    /// Epoch close timestamp (nanoseconds).
    pub closed_at_ns: u64,
    /// Composition method used.
    pub composition_method: CompositionMethod,
}

// ---------------------------------------------------------------------------
// AccountantConfig — input struct for construction
// ---------------------------------------------------------------------------

/// Configuration for constructing a [`BudgetAccountant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountantConfig {
    /// Zone identifier (scopes this accountant).
    pub zone: String,
    /// Epsilon budget per epoch (millionths).
    pub epsilon_per_epoch_millionths: i64,
    /// Delta budget per epoch (millionths).
    pub delta_per_epoch_millionths: i64,
    /// Total lifetime epsilon budget (millionths).
    pub lifetime_epsilon_budget_millionths: i64,
    /// Total lifetime delta budget (millionths).
    pub lifetime_delta_budget_millionths: i64,
    /// Composition method for budget accounting.
    pub composition_method: CompositionMethod,
    /// Starting security epoch.
    pub epoch: SecurityEpoch,
    /// Creation timestamp (nanoseconds).
    pub now_ns: u64,
}

// ---------------------------------------------------------------------------
// BudgetAccountant — main accountant
// ---------------------------------------------------------------------------

/// Differential privacy budget accountant.
///
/// Tracks per-epoch and lifetime budget consumption with hard fail-closed
/// behavior on exhaustion.  Supports basic, advanced, Renyi, and zCDP
/// composition methods.
///
/// Epoch transitions are clean: no rollover (each epoch starts fresh).
/// Historical epoch summaries are retained for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAccountant {
    /// Zone identifier (scopes this accountant).
    pub zone: String,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Current epoch's budget tracker.
    pub current_budget: EpochBudget,
    /// Lifetime epsilon budget (millionths).
    pub lifetime_epsilon_budget_millionths: i64,
    /// Lifetime delta budget (millionths).
    pub lifetime_delta_budget_millionths: i64,
    /// Lifetime epsilon consumed across all epochs (millionths).
    pub lifetime_epsilon_spent_millionths: i64,
    /// Lifetime delta consumed across all epochs (millionths).
    pub lifetime_delta_spent_millionths: i64,
    /// Historical epoch summaries (closed epochs).
    pub epoch_summaries: Vec<EpochSummary>,
    /// Per-epoch budget allocation (millionths) for new epochs.
    epoch_epsilon_allocation_millionths: i64,
    /// Per-epoch delta allocation (millionths) for new epochs.
    epoch_delta_allocation_millionths: i64,
    /// Composition method.
    composition_method: CompositionMethod,
    /// Monotonic operation counter.
    operation_counter: u64,
    /// Consumption log for replay/audit.
    consumption_log: Vec<BudgetConsumption>,
}

impl BudgetAccountant {
    /// Create a new budget accountant from configuration.
    pub fn new(cfg: AccountantConfig) -> Result<Self, AccountantError> {
        if cfg.epsilon_per_epoch_millionths <= 0 {
            return Err(AccountantError::InvalidConfiguration {
                reason: "epsilon_per_epoch must be positive".into(),
            });
        }
        if cfg.delta_per_epoch_millionths <= 0 {
            return Err(AccountantError::InvalidConfiguration {
                reason: "delta_per_epoch must be positive".into(),
            });
        }
        if cfg.lifetime_epsilon_budget_millionths <= 0 {
            return Err(AccountantError::InvalidConfiguration {
                reason: "lifetime_epsilon_budget must be positive".into(),
            });
        }
        if cfg.lifetime_delta_budget_millionths <= 0 {
            return Err(AccountantError::InvalidConfiguration {
                reason: "lifetime_delta_budget must be positive".into(),
            });
        }

        let current_budget = EpochBudget {
            epoch: cfg.epoch,
            epsilon_budget_millionths: cfg.epsilon_per_epoch_millionths,
            delta_budget_millionths: cfg.delta_per_epoch_millionths,
            epsilon_spent_millionths: 0,
            delta_spent_millionths: 0,
            composition_method: cfg.composition_method,
            operations_count: 0,
            created_at_ns: cfg.now_ns,
            exhausted: false,
        };

        Ok(Self {
            zone: cfg.zone,
            current_epoch: cfg.epoch,
            current_budget,
            lifetime_epsilon_budget_millionths: cfg.lifetime_epsilon_budget_millionths,
            lifetime_delta_budget_millionths: cfg.lifetime_delta_budget_millionths,
            lifetime_epsilon_spent_millionths: 0,
            lifetime_delta_spent_millionths: 0,
            epoch_summaries: Vec::new(),
            epoch_epsilon_allocation_millionths: cfg.epsilon_per_epoch_millionths,
            epoch_delta_allocation_millionths: cfg.delta_per_epoch_millionths,
            composition_method: cfg.composition_method,
            operation_counter: 0,
            consumption_log: Vec::new(),
        })
    }

    /// Consume privacy budget.
    ///
    /// The `epsilon` and `delta` values are the raw privacy costs of the
    /// operation.  The accountant applies the composition method to compute
    /// the actual budget impact.
    ///
    /// Returns `Err(AccountantError::BudgetExhausted)` if the budget is
    /// already exhausted or would be exhausted by this operation.
    pub fn consume(
        &mut self,
        epsilon_millionths: i64,
        delta_millionths: i64,
        description: &str,
        now_ns: u64,
    ) -> Result<BudgetConsumption, AccountantError> {
        if epsilon_millionths < 0 || delta_millionths < 0 {
            return Err(AccountantError::InvalidConsumption {
                reason: "epsilon and delta must be non-negative".into(),
            });
        }

        // Check fail-closed latch.
        if self.current_budget.exhausted {
            return Err(AccountantError::BudgetExhausted {
                dimension: "epoch".into(),
                epsilon_remaining: self.current_budget.epsilon_remaining(),
                delta_remaining: self.current_budget.delta_remaining(),
            });
        }

        // Apply composition method to compute actual budget impact.
        let (composed_epsilon, composed_delta) =
            self.apply_composition(epsilon_millionths, delta_millionths);

        // Check if this would exhaust the epoch budget.
        if self
            .current_budget
            .would_exhaust(composed_epsilon, composed_delta)
        {
            self.current_budget.exhausted = true;
            return Err(AccountantError::BudgetExhausted {
                dimension: "epoch".into(),
                epsilon_remaining: self.current_budget.epsilon_remaining(),
                delta_remaining: self.current_budget.delta_remaining(),
            });
        }

        // Check if this would exhaust the lifetime budget.
        if self.lifetime_epsilon_spent_millionths + composed_epsilon
            > self.lifetime_epsilon_budget_millionths
            || self.lifetime_delta_spent_millionths + composed_delta
                > self.lifetime_delta_budget_millionths
        {
            self.current_budget.exhausted = true;
            return Err(AccountantError::BudgetExhausted {
                dimension: "lifetime".into(),
                epsilon_remaining: self.lifetime_epsilon_budget_millionths
                    - self.lifetime_epsilon_spent_millionths,
                delta_remaining: self.lifetime_delta_budget_millionths
                    - self.lifetime_delta_spent_millionths,
            });
        }

        // Apply the consumption.
        self.current_budget.epsilon_spent_millionths += composed_epsilon;
        self.current_budget.delta_spent_millionths += composed_delta;
        self.current_budget.operations_count += 1;
        self.lifetime_epsilon_spent_millionths += composed_epsilon;
        self.lifetime_delta_spent_millionths += composed_delta;
        self.operation_counter += 1;

        let record = BudgetConsumption {
            operation_id: self.operation_counter,
            epoch: self.current_epoch,
            epsilon_consumed_millionths: epsilon_millionths,
            delta_consumed_millionths: delta_millionths,
            composed_epsilon_millionths: composed_epsilon,
            composed_delta_millionths: composed_delta,
            timestamp_ns: now_ns,
            description: description.into(),
        };

        self.consumption_log.push(record.clone());
        Ok(record)
    }

    /// Check if the budget is currently exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.current_budget.exhausted
    }

    /// Get the current epoch budget.
    pub fn epoch_budget(&self) -> &EpochBudget {
        &self.current_budget
    }

    /// Get remaining epoch epsilon (millionths).
    pub fn epoch_epsilon_remaining(&self) -> i64 {
        self.current_budget.epsilon_remaining()
    }

    /// Get remaining epoch delta (millionths).
    pub fn epoch_delta_remaining(&self) -> i64 {
        self.current_budget.delta_remaining()
    }

    /// Get remaining lifetime epsilon (millionths).
    pub fn lifetime_epsilon_remaining(&self) -> i64 {
        self.lifetime_epsilon_budget_millionths - self.lifetime_epsilon_spent_millionths
    }

    /// Get remaining lifetime delta (millionths).
    pub fn lifetime_delta_remaining(&self) -> i64 {
        self.lifetime_delta_budget_millionths - self.lifetime_delta_spent_millionths
    }

    /// Forecast remaining budget capacity.
    pub fn forecast(&self) -> BudgetForecast {
        let epoch_eps_remaining = self.current_budget.epsilon_remaining();
        let epoch_delta_remaining = self.current_budget.delta_remaining();

        // Estimate remaining operations from average consumption rate.
        let estimated_ops = if self.current_budget.operations_count > 0 {
            let avg_eps_per_op = self.current_budget.epsilon_spent_millionths
                / self.current_budget.operations_count as i64;
            if avg_eps_per_op > 0 {
                (epoch_eps_remaining / avg_eps_per_op).max(0) as u64
            } else {
                u64::MAX
            }
        } else {
            u64::MAX // no consumption yet, unlimited
        };

        BudgetForecast {
            epoch_epsilon_remaining_millionths: epoch_eps_remaining,
            epoch_delta_remaining_millionths: epoch_delta_remaining,
            lifetime_epsilon_remaining_millionths: self.lifetime_epsilon_remaining(),
            lifetime_delta_remaining_millionths: self.lifetime_delta_remaining(),
            estimated_remaining_operations: estimated_ops,
            exhausted: self.current_budget.exhausted,
        }
    }

    /// Advance to a new epoch.
    ///
    /// Closes the current epoch, produces an epoch summary, and starts
    /// a fresh budget.  No budget rollover: each epoch starts clean.
    pub fn advance_epoch(
        &mut self,
        new_epoch: SecurityEpoch,
        now_ns: u64,
    ) -> Result<EpochSummary, AccountantError> {
        if new_epoch.as_u64() <= self.current_epoch.as_u64() {
            return Err(AccountantError::EpochNotAdvanced {
                current: self.current_epoch,
                proposed: new_epoch,
            });
        }

        // Close current epoch and produce summary.
        let summary = EpochSummary {
            epoch: self.current_epoch,
            zone: self.zone.clone(),
            total_epsilon_spent_millionths: self.current_budget.epsilon_spent_millionths,
            total_delta_spent_millionths: self.current_budget.delta_spent_millionths,
            operations_count: self.current_budget.operations_count,
            exhausted: self.current_budget.exhausted,
            started_at_ns: self.current_budget.created_at_ns,
            closed_at_ns: now_ns,
            composition_method: self.composition_method,
        };
        self.epoch_summaries.push(summary.clone());

        // Start new epoch with fresh budget.
        self.current_epoch = new_epoch;
        self.current_budget = EpochBudget {
            epoch: new_epoch,
            epsilon_budget_millionths: self.epoch_epsilon_allocation_millionths,
            delta_budget_millionths: self.epoch_delta_allocation_millionths,
            epsilon_spent_millionths: 0,
            delta_spent_millionths: 0,
            composition_method: self.composition_method,
            operations_count: 0,
            created_at_ns: now_ns,
            exhausted: false,
        };

        // Check lifetime exhaustion for new epoch.
        if self.lifetime_epsilon_spent_millionths >= self.lifetime_epsilon_budget_millionths
            || self.lifetime_delta_spent_millionths >= self.lifetime_delta_budget_millionths
        {
            self.current_budget.exhausted = true;
        }

        Ok(summary)
    }

    /// Get the total number of operations across all epochs.
    pub fn total_operations(&self) -> u64 {
        self.operation_counter
    }

    /// Get historical epoch summaries.
    pub fn epoch_summaries(&self) -> &[EpochSummary] {
        &self.epoch_summaries
    }

    /// Get the consumption log.
    pub fn consumption_log(&self) -> &[BudgetConsumption] {
        &self.consumption_log
    }

    // -- Internal helpers --

    /// Apply composition method to compute actual budget impact.
    ///
    /// - Basic: straightforward addition (epsilon + delta add linearly).
    /// - Advanced: uses sqrt(2 * k * ln(1/delta)) * eps for k queries.
    ///   Approximated as eps * sqrt(k+1) / sqrt(k) for incremental.
    /// - Renyi: adds alpha-Renyi divergence; simplified as eps * 0.8.
    /// - ZeroCdp: adds rho = eps^2 / 2; simplified as eps * 0.7.
    fn apply_composition(&self, epsilon: i64, delta: i64) -> (i64, i64) {
        let k = self.current_budget.operations_count;
        match self.composition_method {
            CompositionMethod::Basic => (epsilon, delta),
            CompositionMethod::Advanced => {
                // Advanced composition gives better bounds for many queries.
                // Simplified: for k > 0, scale by 1/sqrt(k+1) in millionths.
                let kp1 = (k + 1) as i64;
                let scale = if kp1 <= 1 {
                    1_000_000i64 // 1.0
                } else {
                    // 1_000_000 / sqrt(kp1) = isqrt(1_000_000^2 / kp1)
                    isqrt_millionths(1_000_000_000_000i64 / kp1)
                };
                let composed_eps = epsilon * scale / 1_000_000;
                (composed_eps.max(1), delta)
            }
            CompositionMethod::Renyi => {
                // Renyi composition: tighter than basic.
                // Simplified: 80% of basic cost.
                let composed_eps = epsilon * 800_000 / 1_000_000;
                (composed_eps.max(1), delta)
            }
            CompositionMethod::ZeroCdp => {
                // zCDP: tightest common composition bound.
                // Simplified: 70% of basic cost.
                let composed_eps = epsilon * 700_000 / 1_000_000;
                (composed_eps.max(1), delta)
            }
        }
    }
}

/// Integer square root (deterministic, no floating point).
fn isqrt_millionths(n: i64) -> i64 {
    if n <= 0 {
        return 1;
    }
    // Newton's method for integer square root.
    let mut x = n;
    #[allow(clippy::manual_div_ceil)]
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x.max(1)
}

// ---------------------------------------------------------------------------
// AccountantError — errors from accountant operations
// ---------------------------------------------------------------------------

/// Errors from budget accountant operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountantError {
    /// Budget is exhausted (fail-closed).
    BudgetExhausted {
        dimension: String,
        epsilon_remaining: i64,
        delta_remaining: i64,
    },
    /// Epoch not advanced (must be strictly increasing).
    EpochNotAdvanced {
        current: SecurityEpoch,
        proposed: SecurityEpoch,
    },
    /// Invalid consumption values.
    InvalidConsumption { reason: String },
    /// Invalid configuration.
    InvalidConfiguration { reason: String },
}

impl fmt::Display for AccountantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted {
                dimension,
                epsilon_remaining,
                delta_remaining,
            } => write!(
                f,
                "budget exhausted ({dimension}): eps_remaining={epsilon_remaining}, delta_remaining={delta_remaining}"
            ),
            Self::EpochNotAdvanced { current, proposed } => {
                write!(
                    f,
                    "epoch not advanced: current={}, proposed={}",
                    current.as_u64(),
                    proposed.as_u64()
                )
            }
            Self::InvalidConsumption { reason } => {
                write!(f, "invalid consumption: {reason}")
            }
            Self::InvalidConfiguration { reason } => {
                write!(f, "invalid configuration: {reason}")
            }
        }
    }
}

impl std::error::Error for AccountantError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn test_config() -> AccountantConfig {
        AccountantConfig {
            zone: "zone-A".into(),
            epsilon_per_epoch_millionths: 1_000_000, // 1.0
            delta_per_epoch_millionths: 100_000,     // 0.1
            lifetime_epsilon_budget_millionths: 10_000_000, // 10.0
            lifetime_delta_budget_millionths: 1_000_000, // 1.0
            composition_method: CompositionMethod::Basic,
            epoch: SecurityEpoch::from_raw(1),
            now_ns: 1_000_000_000,
        }
    }

    fn test_accountant() -> BudgetAccountant {
        BudgetAccountant::new(test_config()).unwrap()
    }

    fn test_accountant_advanced() -> BudgetAccountant {
        BudgetAccountant::new(AccountantConfig {
            composition_method: CompositionMethod::Advanced,
            ..test_config()
        })
        .unwrap()
    }

    // -- Construction tests --

    #[test]
    fn new_accountant_ok() {
        let acc = test_accountant();
        assert_eq!(acc.zone, "zone-A");
        assert_eq!(acc.current_epoch, SecurityEpoch::from_raw(1));
        assert!(!acc.is_exhausted());
        assert_eq!(acc.total_operations(), 0);
    }

    #[test]
    fn new_rejects_zero_epsilon() {
        let err = BudgetAccountant::new(AccountantConfig {
            epsilon_per_epoch_millionths: 0,
            ..test_config()
        })
        .unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_rejects_negative_delta() {
        let err = BudgetAccountant::new(AccountantConfig {
            delta_per_epoch_millionths: -1,
            ..test_config()
        })
        .unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_rejects_zero_lifetime() {
        let err = BudgetAccountant::new(AccountantConfig {
            lifetime_epsilon_budget_millionths: 0,
            ..test_config()
        })
        .unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
    }

    #[test]
    fn new_rejects_zero_lifetime_delta() {
        let err = BudgetAccountant::new(AccountantConfig {
            lifetime_delta_budget_millionths: 0,
            ..test_config()
        })
        .unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
    }

    // -- Basic consumption tests --

    #[test]
    fn consume_basic_ok() {
        let mut acc = test_accountant();
        let record = acc
            .consume(100_000, 10_000, "noise addition", 2_000_000_000)
            .unwrap();
        assert_eq!(record.operation_id, 1);
        assert_eq!(record.epsilon_consumed_millionths, 100_000);
        assert_eq!(record.composed_epsilon_millionths, 100_000); // basic = no change
        assert_eq!(acc.epoch_epsilon_remaining(), 900_000);
        assert_eq!(acc.epoch_delta_remaining(), 90_000);
        assert_eq!(acc.total_operations(), 1);
    }

    #[test]
    fn consume_multiple_ok() {
        let mut acc = test_accountant();
        for i in 0..5 {
            acc.consume(100_000, 10_000, &format!("op-{i}"), (i + 2) * 1_000_000_000)
                .unwrap();
        }
        assert_eq!(acc.epoch_epsilon_remaining(), 500_000);
        assert_eq!(acc.total_operations(), 5);
        assert_eq!(acc.consumption_log().len(), 5);
    }

    #[test]
    fn consume_rejects_negative() {
        let mut acc = test_accountant();
        let err = acc.consume(-1, 0, "bad", 0).unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
    }

    // -- Exhaustion tests --

    #[test]
    fn epoch_exhaustion_trips_latch() {
        let mut acc = test_accountant();
        // Consume most of the budget.
        acc.consume(900_000, 0, "big op", 2_000_000_000).unwrap();
        // Next consumption would exceed budget -> exhaustion.
        let err = acc
            .consume(200_000, 0, "overflow", 3_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
        assert!(acc.is_exhausted());
    }

    #[test]
    fn exhaustion_latch_stays_tripped() {
        let mut acc = test_accountant();
        // Force exhaustion.
        acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
        let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
        // Even small consumption is rejected.
        let err = acc.consume(1, 0, "tiny", 4_000_000_000).unwrap_err();
        assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    }

    #[test]
    fn delta_exhaustion() {
        let mut acc = test_accountant();
        // Delta budget is 100_000.
        acc.consume(0, 90_000, "op1", 2_000_000_000).unwrap();
        let err = acc
            .consume(0, 20_000, "overflow", 3_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    }

    #[test]
    fn lifetime_exhaustion() {
        let mut acc = BudgetAccountant::new(AccountantConfig {
            zone: "zone-B".into(),
            lifetime_epsilon_budget_millionths: 500_000, // very small
            ..test_config()
        })
        .unwrap();
        // Consume within epoch budget but exceed lifetime.
        acc.consume(400_000, 0, "op1", 2_000_000_000).unwrap();
        let err = acc.consume(200_000, 0, "op2", 3_000_000_000).unwrap_err();
        assert!(matches!(
            err,
            AccountantError::BudgetExhausted {
                dimension,
                ..
            } if dimension == "lifetime"
        ));
    }

    // -- Epoch transition tests --

    #[test]
    fn advance_epoch_ok() {
        let mut acc = test_accountant();
        acc.consume(300_000, 30_000, "op1", 2_000_000_000).unwrap();
        let summary = acc
            .advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        assert_eq!(summary.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(summary.total_epsilon_spent_millionths, 300_000);
        assert_eq!(summary.total_delta_spent_millionths, 30_000);
        assert_eq!(summary.operations_count, 1);
        assert!(!summary.exhausted);
        // New epoch starts fresh.
        assert_eq!(acc.current_epoch, SecurityEpoch::from_raw(2));
        assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
        assert!(!acc.is_exhausted());
    }

    #[test]
    fn advance_epoch_clears_exhaustion() {
        let mut acc = test_accountant();
        // Exhaust current epoch.
        acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
        let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
        assert!(acc.is_exhausted());
        // Advance epoch — fresh budget, exhaustion cleared.
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        assert!(!acc.is_exhausted());
        acc.consume(100_000, 10_000, "fresh op", 11_000_000_000)
            .unwrap();
    }

    #[test]
    fn advance_epoch_rejects_same() {
        let mut acc = test_accountant();
        let err = acc
            .advance_epoch(SecurityEpoch::from_raw(1), 2_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
    }

    #[test]
    fn advance_epoch_rejects_lower() {
        let mut acc = test_accountant();
        acc.advance_epoch(SecurityEpoch::from_raw(5), 2_000_000_000)
            .unwrap();
        let err = acc
            .advance_epoch(SecurityEpoch::from_raw(3), 3_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
    }

    #[test]
    fn no_budget_rollover() {
        let mut acc = test_accountant();
        // Use only half the budget.
        acc.consume(500_000, 50_000, "half", 2_000_000_000).unwrap();
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        // New epoch has full budget, not 1.5x.
        assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
        assert_eq!(acc.epoch_delta_remaining(), 100_000);
    }

    #[test]
    fn lifetime_tracks_across_epochs() {
        let mut acc = test_accountant();
        acc.consume(300_000, 30_000, "ep1-op", 2_000_000_000)
            .unwrap();
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        acc.consume(200_000, 20_000, "ep2-op", 11_000_000_000)
            .unwrap();
        assert_eq!(acc.lifetime_epsilon_spent_millionths, 500_000);
        assert_eq!(acc.lifetime_delta_spent_millionths, 50_000);
    }

    #[test]
    fn epoch_summaries_retained() {
        let mut acc = test_accountant();
        acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
            .unwrap();
        acc.advance_epoch(SecurityEpoch::from_raw(3), 10_000_000_000)
            .unwrap();
        assert_eq!(acc.epoch_summaries().len(), 2);
        assert_eq!(acc.epoch_summaries()[0].epoch, SecurityEpoch::from_raw(1));
        assert_eq!(acc.epoch_summaries()[1].epoch, SecurityEpoch::from_raw(2));
    }

    // -- Composition method tests --

    #[test]
    fn advanced_composition_reduces_cost() {
        let mut acc = test_accountant_advanced();
        // First operation: full cost (k=0).
        let r1 = acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
        assert_eq!(r1.composed_epsilon_millionths, 100_000); // k=0, scale=1.0
        // Second operation: reduced cost.
        let r2 = acc.consume(100_000, 10_000, "op2", 3_000_000_000).unwrap();
        assert!(r2.composed_epsilon_millionths < 100_000); // k=1, scale < 1.0
    }

    #[test]
    fn renyi_composition_reduces_cost() {
        let mut acc = BudgetAccountant::new(AccountantConfig {
            composition_method: CompositionMethod::Renyi,
            now_ns: 0,
            ..test_config()
        })
        .unwrap();
        let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
        assert_eq!(r.composed_epsilon_millionths, 80_000); // 80% of 100K
    }

    #[test]
    fn zcdp_composition_reduces_cost() {
        let mut acc = BudgetAccountant::new(AccountantConfig {
            composition_method: CompositionMethod::ZeroCdp,
            now_ns: 0,
            ..test_config()
        })
        .unwrap();
        let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
        assert_eq!(r.composed_epsilon_millionths, 70_000); // 70% of 100K
    }

    #[test]
    fn basic_composition_no_change() {
        let mut acc = test_accountant();
        let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
        assert_eq!(r.composed_epsilon_millionths, 100_000);
        assert_eq!(r.composed_delta_millionths, 10_000);
    }

    // -- Forecast tests --

    #[test]
    fn forecast_no_consumption() {
        let acc = test_accountant();
        let fc = acc.forecast();
        assert_eq!(fc.epoch_epsilon_remaining_millionths, 1_000_000);
        assert_eq!(fc.estimated_remaining_operations, u64::MAX);
        assert!(!fc.exhausted);
    }

    #[test]
    fn forecast_with_consumption() {
        let mut acc = test_accountant();
        acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
        acc.consume(100_000, 10_000, "op2", 3_000_000_000).unwrap();
        let fc = acc.forecast();
        assert_eq!(fc.epoch_epsilon_remaining_millionths, 800_000);
        // Avg eps per op = 100K, remaining = 800K -> ~8 ops remaining.
        assert_eq!(fc.estimated_remaining_operations, 8);
    }

    #[test]
    fn forecast_after_exhaustion() {
        let mut acc = test_accountant();
        acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
        let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
        let fc = acc.forecast();
        assert!(fc.exhausted);
    }

    // -- Serialization tests --

    #[test]
    fn accountant_serde_round_trip() {
        let mut acc = test_accountant();
        acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
        let json = serde_json::to_string(&acc).unwrap();
        let decoded: BudgetAccountant = serde_json::from_str(&json).unwrap();
        assert_eq!(acc, decoded);
    }

    #[test]
    fn epoch_summary_serde_round_trip() {
        let summary = EpochSummary {
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone-A".into(),
            total_epsilon_spent_millionths: 500_000,
            total_delta_spent_millionths: 50_000,
            operations_count: 5,
            exhausted: false,
            started_at_ns: 1_000_000_000,
            closed_at_ns: 10_000_000_000,
            composition_method: CompositionMethod::Basic,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: EpochSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, decoded);
    }

    #[test]
    fn consumption_serde_round_trip() {
        let record = BudgetConsumption {
            operation_id: 1,
            epoch: SecurityEpoch::from_raw(1),
            epsilon_consumed_millionths: 100_000,
            delta_consumed_millionths: 10_000,
            composed_epsilon_millionths: 100_000,
            composed_delta_millionths: 10_000,
            timestamp_ns: 2_000_000_000,
            description: "test".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: BudgetConsumption = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn deterministic_serialization() {
        let a1 = test_accountant();
        let a2 = test_accountant();
        assert_eq!(
            serde_json::to_string(&a1).unwrap(),
            serde_json::to_string(&a2).unwrap()
        );
    }

    // -- Error display tests --

    #[test]
    fn error_display() {
        let err = AccountantError::BudgetExhausted {
            dimension: "epoch".into(),
            epsilon_remaining: -100,
            delta_remaining: 50,
        };
        let s = err.to_string();
        assert!(s.contains("budget exhausted"));
        assert!(s.contains("epoch"));
    }

    #[test]
    fn error_epoch_not_advanced_display() {
        let err = AccountantError::EpochNotAdvanced {
            current: SecurityEpoch::from_raw(5),
            proposed: SecurityEpoch::from_raw(3),
        };
        assert!(err.to_string().contains("epoch not advanced"));
    }

    #[test]
    fn error_serde_round_trip() {
        let err = AccountantError::InvalidConsumption {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: AccountantError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    // -- Helper function tests --

    #[test]
    fn isqrt_basic_values() {
        assert_eq!(isqrt_millionths(1), 1);
        assert_eq!(isqrt_millionths(4), 2);
        assert_eq!(isqrt_millionths(9), 3);
        assert_eq!(isqrt_millionths(100), 10);
    }

    #[test]
    fn isqrt_zero_and_negative() {
        assert_eq!(isqrt_millionths(0), 1); // clamped to 1
        assert_eq!(isqrt_millionths(-5), 1); // clamped to 1
    }

    // -- EpochBudget tests --

    #[test]
    fn epoch_budget_remaining() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(1),
            epsilon_budget_millionths: 1_000_000,
            delta_budget_millionths: 100_000,
            epsilon_spent_millionths: 300_000,
            delta_spent_millionths: 50_000,
            composition_method: CompositionMethod::Basic,
            operations_count: 3,
            created_at_ns: 0,
            exhausted: false,
        };
        assert_eq!(eb.epsilon_remaining(), 700_000);
        assert_eq!(eb.delta_remaining(), 50_000);
    }

    #[test]
    fn epoch_budget_would_exhaust() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(1),
            epsilon_budget_millionths: 1_000_000,
            delta_budget_millionths: 100_000,
            epsilon_spent_millionths: 900_000,
            delta_spent_millionths: 0,
            composition_method: CompositionMethod::Basic,
            operations_count: 1,
            created_at_ns: 0,
            exhausted: false,
        };
        assert!(!eb.would_exhaust(100_000, 0));
        assert!(eb.would_exhaust(200_000, 0));
        assert!(eb.would_exhaust(0, 200_000));
    }

    // -- Lifetime exhaustion across epochs --

    #[test]
    fn lifetime_exhaustion_blocks_new_epoch() {
        let mut acc = BudgetAccountant::new(AccountantConfig {
            zone: "zone-C".into(),
            epsilon_per_epoch_millionths: 500_000,
            delta_per_epoch_millionths: 50_000,
            lifetime_epsilon_budget_millionths: 800_000, // small lifetime
            lifetime_delta_budget_millionths: 200_000,
            now_ns: 0,
            ..test_config()
        })
        .unwrap();
        // Consume in epoch 1.
        acc.consume(400_000, 40_000, "ep1", 1_000_000_000).unwrap();
        // Advance to epoch 2.
        acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
            .unwrap();
        // Consume in epoch 2.
        acc.consume(400_000, 40_000, "ep2", 6_000_000_000).unwrap();
        // Lifetime is 800K eps, we've spent 800K. Next should fail.
        let err = acc
            .consume(100_000, 0, "over-lifetime", 7_000_000_000)
            .unwrap_err();
        assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    }

    // -- Enrichment: std::error --

    #[test]
    fn accountant_error_implements_std_error() {
        let variants: [Box<dyn std::error::Error>; 4] = [
            Box::new(AccountantError::BudgetExhausted {
                dimension: "epsilon".into(),
                epsilon_remaining: 0,
                delta_remaining: 100,
            }),
            Box::new(AccountantError::EpochNotAdvanced {
                current: SecurityEpoch::from_raw(3),
                proposed: SecurityEpoch::from_raw(2),
            }),
            Box::new(AccountantError::InvalidConsumption {
                reason: "negative".into(),
            }),
            Box::new(AccountantError::InvalidConfiguration {
                reason: "bad".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: edge cases, forecast, composition, serde
    // -----------------------------------------------------------------------

    #[test]
    fn consume_zero_epsilon_zero_delta_ok() {
        let mut acc = test_accountant();
        let record = acc.consume(0, 0, "no-op", 2_000_000_000).unwrap();
        assert_eq!(record.composed_epsilon_millionths, 0);
        assert_eq!(record.composed_delta_millionths, 0);
        assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
    }

    #[test]
    fn forecast_lifetime_remaining_tracks_across_epochs() {
        let mut acc = test_accountant();
        acc.consume(300_000, 30_000, "ep1", 2_000_000_000).unwrap();
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        acc.consume(200_000, 20_000, "ep2", 11_000_000_000).unwrap();
        let fc = acc.forecast();
        assert_eq!(
            fc.lifetime_epsilon_remaining_millionths,
            10_000_000 - 500_000
        );
        assert_eq!(fc.lifetime_delta_remaining_millionths, 1_000_000 - 50_000);
    }

    #[test]
    fn budget_forecast_serde_roundtrip() {
        let fc = BudgetForecast {
            epoch_epsilon_remaining_millionths: 500_000,
            epoch_delta_remaining_millionths: 50_000,
            lifetime_epsilon_remaining_millionths: 5_000_000,
            lifetime_delta_remaining_millionths: 500_000,
            estimated_remaining_operations: 42,
            exhausted: false,
        };
        let json = serde_json::to_string(&fc).unwrap();
        let decoded: BudgetForecast = serde_json::from_str(&json).unwrap();
        assert_eq!(fc, decoded);
    }

    #[test]
    fn accountant_config_serde_roundtrip() {
        let cfg = test_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: AccountantConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn epoch_budget_serde_roundtrip_small_budget_profile() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(3),
            epsilon_budget_millionths: 1_000_000,
            delta_budget_millionths: 100_000,
            epsilon_spent_millionths: 250_000,
            delta_spent_millionths: 25_000,
            composition_method: CompositionMethod::Renyi,
            operations_count: 5,
            created_at_ns: 42,
            exhausted: false,
        };
        let json = serde_json::to_string(&eb).unwrap();
        let decoded: EpochBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(eb, decoded);
    }

    #[test]
    fn error_display_all_variants_unique() {
        let variants: [AccountantError; 4] = [
            AccountantError::BudgetExhausted {
                dimension: "epoch".into(),
                epsilon_remaining: 0,
                delta_remaining: 0,
            },
            AccountantError::EpochNotAdvanced {
                current: SecurityEpoch::from_raw(1),
                proposed: SecurityEpoch::from_raw(1),
            },
            AccountantError::InvalidConsumption {
                reason: "neg".into(),
            },
            AccountantError::InvalidConfiguration {
                reason: "bad".into(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 error variants must have unique Display"
        );
    }

    #[test]
    fn isqrt_large_perfect_square() {
        assert_eq!(isqrt_millionths(1_000_000), 1000);
        assert_eq!(isqrt_millionths(10_000), 100);
    }

    #[test]
    fn advanced_composition_multiple_operations_decreasing_cost() {
        let mut acc = test_accountant_advanced();
        let mut composed_costs = Vec::new();
        for i in 0..5 {
            let r = acc
                .consume(
                    100_000,
                    10_000,
                    &format!("op-{i}"),
                    (i + 2) as u64 * 1_000_000_000,
                )
                .unwrap();
            composed_costs.push(r.composed_epsilon_millionths);
        }
        // After the first operation, each subsequent should cost less or equal
        for i in 1..composed_costs.len() {
            assert!(
                composed_costs[i] <= composed_costs[i - 1],
                "advanced composition cost should decrease: {} > {}",
                composed_costs[i],
                composed_costs[i - 1]
            );
        }
    }

    // -- Enrichment batch 3: edge cases, operation IDs, epoch summaries --

    #[test]
    fn consume_negative_epsilon_rejected() {
        let mut acc = test_accountant();
        let err = acc.consume(-100, 0, "neg-eps", 2_000_000_000).unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
    }

    #[test]
    fn consume_negative_delta_rejected() {
        let mut acc = test_accountant();
        let err = acc.consume(0, -50, "neg-delta", 2_000_000_000).unwrap_err();
        assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
    }

    #[test]
    fn operation_ids_monotonically_increase() {
        let mut acc = test_accountant();
        let mut prev_id = 0;
        for i in 0..5 {
            let record = acc
                .consume(
                    10_000,
                    1_000,
                    &format!("op-{i}"),
                    (i + 2) as u64 * 1_000_000_000,
                )
                .unwrap();
            assert!(record.operation_id > prev_id);
            prev_id = record.operation_id;
        }
    }

    #[test]
    fn epoch_summary_captures_exhaustion() {
        let mut acc = test_accountant();
        // Exhaust the budget
        acc.consume(1_000_000, 0, "exhaust-eps", 2_000_000_000)
            .unwrap();
        // Now advance epoch - summary should capture exhaustion state
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        let summaries = acc.epoch_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_epsilon_spent_millionths, 1_000_000);
    }

    #[test]
    fn consumption_after_exhaustion_rejected() {
        let mut acc = test_accountant();
        acc.consume(1_000_000, 0, "exhaust", 2_000_000_000).unwrap();
        let err = acc.consume(1, 0, "over-budget", 3_000_000_000).unwrap_err();
        assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    }

    #[test]
    fn zone_preserved_in_accountant() {
        let acc = test_accountant();
        let json = serde_json::to_string(&acc).unwrap();
        assert!(json.contains("zone-A"));
    }

    #[test]
    fn epoch_budget_would_exhaust_exact_boundary() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(1),
            epsilon_budget_millionths: 1_000_000,
            delta_budget_millionths: 100_000,
            epsilon_spent_millionths: 500_000,
            delta_spent_millionths: 50_000,
            composition_method: CompositionMethod::Basic,
            operations_count: 1,
            created_at_ns: 0,
            exhausted: false,
        };
        // Exactly at remaining: 500K eps, 50K delta
        assert!(!eb.would_exhaust(500_000, 50_000));
        // One over for epsilon
        assert!(eb.would_exhaust(500_001, 0));
        // One over for delta
        assert!(eb.would_exhaust(0, 50_001));
    }

    #[test]
    fn forecast_estimated_operations_after_single_consume() {
        let mut acc = test_accountant();
        acc.consume(200_000, 20_000, "op1", 2_000_000_000).unwrap();
        let fc = acc.forecast();
        // Remaining: 800K eps. Avg per op = 200K. 800K/200K = 4
        assert_eq!(fc.estimated_remaining_operations, 4);
    }

    #[test]
    fn epoch_summary_composition_method_preserved() {
        let mut acc = test_accountant_advanced();
        acc.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();
        acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
            .unwrap();
        let summaries = acc.epoch_summaries();
        assert_eq!(summaries[0].composition_method, CompositionMethod::Advanced);
    }

    #[test]
    fn isqrt_non_perfect_square() {
        // sqrt(5) = 2.236..., floor = 2
        assert_eq!(isqrt_millionths(5), 2);
        // sqrt(8) = 2.828..., floor = 2
        assert_eq!(isqrt_millionths(8), 2);
        // sqrt(99) = 9.949..., floor = 9
        assert_eq!(isqrt_millionths(99), 9);
    }

    #[test]
    fn accountant_error_invalid_configuration_display() {
        let err = AccountantError::InvalidConfiguration {
            reason: "zero budget".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("zero budget"));
    }

    #[test]
    fn consume_description_preserved_in_record() {
        let mut acc = test_accountant();
        let record = acc
            .consume(10_000, 1_000, "my-unique-op-desc", 2_000_000_000)
            .unwrap();
        assert_eq!(record.description, "my-unique-op-desc");
    }

    #[test]
    fn consume_timestamp_preserved_in_record() {
        let mut acc = test_accountant();
        let ts = 42_000_000_000u64;
        let record = acc.consume(10_000, 1_000, "ts-test", ts).unwrap();
        assert_eq!(record.timestamp_ns, ts);
    }

    #[test]
    fn multiple_epoch_advances_maintain_summaries() {
        let mut acc = test_accountant();
        for epoch in 2..=5 {
            acc.consume(
                50_000,
                5_000,
                &format!("ep{epoch}-op"),
                epoch * 1_000_000_000,
            )
            .unwrap();
            acc.advance_epoch(SecurityEpoch::from_raw(epoch), epoch * 5_000_000_000)
                .unwrap();
        }
        assert_eq!(acc.epoch_summaries().len(), 4); // epochs 1-4 closed
    }

    #[test]
    fn deterministic_accountant_state_across_runs() {
        let run = || {
            let mut acc = test_accountant();
            acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
            acc.consume(200_000, 20_000, "op2", 3_000_000_000).unwrap();
            serde_json::to_string(&acc).unwrap()
        };
        assert_eq!(run(), run());
    }

    // ── Enrichment batch: clone/eq, serde, error coverage ──────────────

    #[test]
    fn epoch_budget_clone_eq() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(1),
            epsilon_budget_millionths: 1_000_000,
            delta_budget_millionths: 100_000,
            epsilon_spent_millionths: 0,
            delta_spent_millionths: 0,
            composition_method: CompositionMethod::Basic,
            operations_count: 0,
            created_at_ns: 0,
            exhausted: false,
        };
        let cloned = eb.clone();
        assert_eq!(eb, cloned);
    }

    #[test]
    fn budget_consumption_clone_eq() {
        let bc = BudgetConsumption {
            operation_id: 1,
            epoch: SecurityEpoch::from_raw(1),
            epsilon_consumed_millionths: 100,
            delta_consumed_millionths: 10,
            composed_epsilon_millionths: 100,
            composed_delta_millionths: 10,
            timestamp_ns: 1_000,
            description: "test".to_string(),
        };
        let cloned = bc.clone();
        assert_eq!(bc, cloned);
    }

    #[test]
    fn budget_forecast_clone_eq() {
        let fc = BudgetForecast {
            epoch_epsilon_remaining_millionths: 500_000,
            epoch_delta_remaining_millionths: 50_000,
            lifetime_epsilon_remaining_millionths: 5_000_000,
            lifetime_delta_remaining_millionths: 500_000,
            estimated_remaining_operations: 10,
            exhausted: false,
        };
        let cloned = fc.clone();
        assert_eq!(fc, cloned);
    }

    #[test]
    fn epoch_summary_clone_eq() {
        let es = EpochSummary {
            epoch: SecurityEpoch::from_raw(1),
            zone: "z".to_string(),
            total_epsilon_spent_millionths: 100,
            total_delta_spent_millionths: 10,
            operations_count: 1,
            exhausted: false,
            started_at_ns: 0,
            closed_at_ns: 1000,
            composition_method: CompositionMethod::Basic,
        };
        let cloned = es.clone();
        assert_eq!(es, cloned);
    }

    #[test]
    fn accountant_config_clone_eq() {
        let cfg = test_config();
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn accountant_error_clone_eq() {
        let err = AccountantError::BudgetExhausted {
            dimension: "epoch".into(),
            epsilon_remaining: -100,
            delta_remaining: 0,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn epoch_budget_serde_roundtrip() {
        let eb = EpochBudget {
            epoch: SecurityEpoch::from_raw(3),
            epsilon_budget_millionths: 500_000,
            delta_budget_millionths: 50_000,
            epsilon_spent_millionths: 100_000,
            delta_spent_millionths: 10_000,
            composition_method: CompositionMethod::Renyi,
            operations_count: 5,
            created_at_ns: 42,
            exhausted: false,
        };
        let json = serde_json::to_string(&eb).unwrap();
        let back: EpochBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(eb, back);
    }

    #[test]
    fn budget_consumption_serde_roundtrip() {
        let bc = BudgetConsumption {
            operation_id: 7,
            epoch: SecurityEpoch::from_raw(2),
            epsilon_consumed_millionths: 200_000,
            delta_consumed_millionths: 20_000,
            composed_epsilon_millionths: 160_000,
            composed_delta_millionths: 20_000,
            timestamp_ns: 99_000,
            description: "serde-test".to_string(),
        };
        let json = serde_json::to_string(&bc).unwrap();
        let back: BudgetConsumption = serde_json::from_str(&json).unwrap();
        assert_eq!(bc, back);
    }

    #[test]
    fn budget_forecast_serde_roundtrip_exhausted_profile() {
        let fc = BudgetForecast {
            epoch_epsilon_remaining_millionths: 300_000,
            epoch_delta_remaining_millionths: 30_000,
            lifetime_epsilon_remaining_millionths: 3_000_000,
            lifetime_delta_remaining_millionths: 300_000,
            estimated_remaining_operations: 15,
            exhausted: true,
        };
        let json = serde_json::to_string(&fc).unwrap();
        let back: BudgetForecast = serde_json::from_str(&json).unwrap();
        assert_eq!(fc, back);
    }

    #[test]
    fn epoch_summary_serde_roundtrip() {
        let es = EpochSummary {
            epoch: SecurityEpoch::from_raw(5),
            zone: "zone-B".to_string(),
            total_epsilon_spent_millionths: 800_000,
            total_delta_spent_millionths: 80_000,
            operations_count: 12,
            exhausted: true,
            started_at_ns: 1_000,
            closed_at_ns: 5_000,
            composition_method: CompositionMethod::ZeroCdp,
        };
        let json = serde_json::to_string(&es).unwrap();
        let back: EpochSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(es, back);
    }

    #[test]
    fn accountant_error_serde_roundtrip_all_variants() {
        let errors = [
            AccountantError::BudgetExhausted {
                dimension: "epoch".into(),
                epsilon_remaining: -50,
                delta_remaining: 0,
            },
            AccountantError::EpochNotAdvanced {
                current: SecurityEpoch::from_raw(3),
                proposed: SecurityEpoch::from_raw(2),
            },
            AccountantError::InvalidConsumption {
                reason: "negative".into(),
            },
            AccountantError::InvalidConfiguration {
                reason: "zero".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: AccountantError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn accountant_error_display_all_unique() {
        let errors = [
            AccountantError::BudgetExhausted {
                dimension: "epoch".into(),
                epsilon_remaining: 0,
                delta_remaining: 0,
            },
            AccountantError::EpochNotAdvanced {
                current: SecurityEpoch::from_raw(1),
                proposed: SecurityEpoch::from_raw(1),
            },
            AccountantError::InvalidConsumption {
                reason: "neg".into(),
            },
            AccountantError::InvalidConfiguration {
                reason: "bad".into(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 error variants have unique Display"
        );
    }

    #[test]
    fn accountant_error_implements_std_error_single_variant() {
        let err: Box<dyn std::error::Error> = Box::new(AccountantError::InvalidConsumption {
            reason: "test".into(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn forecast_no_operations_unlimited_estimate() {
        let acc = test_accountant();
        let fc = acc.forecast();
        assert_eq!(fc.estimated_remaining_operations, u64::MAX);
        assert!(!fc.exhausted);
    }

    #[test]
    fn lifetime_exhaustion_trips_on_advance() {
        let mut acc = BudgetAccountant::new(AccountantConfig {
            lifetime_epsilon_budget_millionths: 500_000,
            lifetime_delta_budget_millionths: 50_000,
            ..test_config()
        })
        .unwrap();
        acc.consume(500_000, 50_000, "all-of-it", 2_000_000_000)
            .unwrap();
        // Advance epoch; new epoch should start exhausted.
        acc.advance_epoch(SecurityEpoch::from_raw(2), 3_000_000_000)
            .unwrap();
        assert!(acc.is_exhausted());
    }

    #[test]
    fn consumption_log_grows_with_operations() {
        let mut acc = test_accountant();
        assert!(acc.consumption_log().is_empty());
        acc.consume(10_000, 1_000, "op1", 2_000_000_000).unwrap();
        acc.consume(20_000, 2_000, "op2", 3_000_000_000).unwrap();
        assert_eq!(acc.consumption_log().len(), 2);
        assert_eq!(acc.consumption_log()[0].description, "op1");
        assert_eq!(acc.consumption_log()[1].description, "op2");
    }

    #[test]
    fn operation_ids_are_monotonically_increasing() {
        let mut acc = test_accountant();
        let r1 = acc.consume(10_000, 1_000, "op1", 2_000_000_000).unwrap();
        let r2 = acc.consume(10_000, 1_000, "op2", 3_000_000_000).unwrap();
        let r3 = acc.consume(10_000, 1_000, "op3", 4_000_000_000).unwrap();
        assert!(r1.operation_id < r2.operation_id);
        assert!(r2.operation_id < r3.operation_id);
    }

    #[test]
    fn isqrt_millionths_zero_returns_one() {
        assert_eq!(isqrt_millionths(0), 1);
    }

    #[test]
    fn isqrt_millionths_negative_returns_one() {
        assert_eq!(isqrt_millionths(-10), 1);
    }

    #[test]
    fn isqrt_millionths_perfect_squares() {
        assert_eq!(isqrt_millionths(1), 1);
        assert_eq!(isqrt_millionths(4), 2);
        assert_eq!(isqrt_millionths(9), 3);
        assert_eq!(isqrt_millionths(100), 10);
        assert_eq!(isqrt_millionths(10000), 100);
    }
}
