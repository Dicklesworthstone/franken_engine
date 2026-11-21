//! Fleet-wide differential-privacy budget tracking with fail-closed refusal.
//!
//! Track QQ (bd-cixqu.43.3 / QQ.3): per-fleet privacy budget tracking + refusal.
//!
//! Where [`crate::dp_budget_accountant::BudgetAccountant`] tracks the privacy
//! loss of a *single* node across epochs, this module tracks the cumulative
//! `(ε, δ)` privacy loss of the *entire fleet* across its lifetime of
//! aggregation rounds.  The aggregator consults a [`FleetPrivacyBudget`]
//! *before* publishing each new aggregate and **refuses** to run a round once
//! the fleet-wide budget would be exhausted.
//!
//! Refusal is fail-closed and explicit: a refused round returns
//! [`FleetBudgetError`], never a silently-degraded aggregate.  Once the budget
//! latch trips it stays tripped — no further rounds are admitted.
//!
//! Privacy invariant (bd-cixqu.45 logging discipline): the ledger and the
//! emitted [`FleetBudgetEvent`]s record only *counts* (participant count, round
//! id) and the `(ε, δ)` figures.  No peer identity and no peer contribution
//! content is ever recorded here — recording it would defeat the purpose of
//! the secure-aggregation layer this gate protects.
//!
//! Fixed-point millionths (`1_000_000 = 1.0`) for all fractional values, matching
//! the rest of the privacy-learning layer.  No floating point; deterministic.
//!
//! Each round supplies a generic `(epsilon, delta)` guarantee, so this ledger
//! uses the additive upper bound for every configured composition method.
//! Native composition needs additional state and conversion delta; callers
//! needing that bound can use [`crate::dp_budget_accountant`].
//!
//! Plan references: Section 10.15, subsection 9I.2 (Privacy-Preserving Fleet
//! Learning Layer); Track QQ sharpens Track T.

use serde::{Deserialize, Serialize};

use crate::privacy_learning_contract::CompositionMethod;

const FLEET_ACCOUNTING_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`FleetPrivacyBudget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetBudgetConfig {
    /// Stable identifier for the fleet this budget scopes.
    pub fleet_id: String,
    /// Total lifetime epsilon budget for the whole fleet (millionths).
    pub lifetime_epsilon_budget_millionths: i64,
    /// Total lifetime delta budget for the whole fleet (millionths).
    pub lifetime_delta_budget_millionths: i64,
    /// Requested composition method, retained as policy metadata. This generic
    /// round ledger conservatively adds costs for every method.
    pub composition_method: CompositionMethod,
    /// Minimum participant cohort required for a round to be admitted.
    ///
    /// A round with fewer than this many contributing peers is refused: small
    /// cohorts make individual contributions easier to single out even under
    /// secure aggregation.  Set to `1` to disable the cohort floor.
    pub min_participants_per_round: usize,
    /// Hard cap on the number of admitted rounds over the fleet lifetime.
    /// `0` means "no round cap" (the budget ceiling is the only limit).
    pub max_rounds: u64,
}

impl FleetBudgetConfig {
    /// Validate the configuration, returning a descriptive error if unusable.
    pub fn validate(&self) -> Result<(), FleetBudgetError> {
        if self.fleet_id.trim().is_empty() {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "fleet_id must not be empty".into(),
            });
        }
        if self.lifetime_epsilon_budget_millionths <= 0 {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "lifetime_epsilon_budget must be positive".into(),
            });
        }
        if self.lifetime_delta_budget_millionths <= 0 {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "lifetime_delta_budget must be positive".into(),
            });
        }
        if self.min_participants_per_round == 0 {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "min_participants_per_round must be at least 1".into(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Ledger + receipts
// ---------------------------------------------------------------------------

/// A single admitted aggregation round recorded in the fleet ledger.
///
/// Records counts and `(ε, δ)` figures only — never peer identity or content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRoundLedgerEntry {
    /// Monotonic round identifier (1-based, in admission order).
    pub round_id: u64,
    /// Raw epsilon requested for this round (millionths).
    pub epsilon_requested_millionths: i64,
    /// Raw delta requested for this round (millionths).
    pub delta_requested_millionths: i64,
    /// Epsilon actually charged after composition (millionths).
    pub epsilon_charged_millionths: i64,
    /// Delta actually charged after composition (millionths).
    pub delta_charged_millionths: i64,
    /// Number of peers that contributed to this round (count only).
    pub participant_count: usize,
    /// Cumulative epsilon spent across the fleet lifetime after this round.
    pub cumulative_epsilon_millionths: i64,
    /// Cumulative delta spent across the fleet lifetime after this round.
    pub cumulative_delta_millionths: i64,
    /// Timestamp this round was admitted (nanoseconds).
    pub timestamp_ns: u64,
}

/// Receipt returned when a round is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetRoundReceipt {
    /// The committed ledger entry for the admitted round.
    pub entry: FleetRoundLedgerEntry,
    /// Lifetime epsilon remaining after this round (millionths).
    pub epsilon_remaining_millionths: i64,
    /// Lifetime delta remaining after this round (millionths).
    pub delta_remaining_millionths: i64,
    /// Whether this round exhausted the budget (no further rounds will admit).
    pub budget_now_exhausted: bool,
}

/// Forecast of remaining fleet budget capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetBudgetForecast {
    /// Remaining lifetime epsilon (millionths).
    pub epsilon_remaining_millionths: i64,
    /// Remaining lifetime delta (millionths).
    pub delta_remaining_millionths: i64,
    /// Number of rounds admitted so far.
    pub rounds_admitted: u64,
    /// Estimated additional rounds at the average per-round charge so far.
    /// `u64::MAX` when no rounds have been charged yet.
    pub estimated_rounds_remaining: u64,
    /// Whether the budget latch has tripped.
    pub exhausted: bool,
}

// ---------------------------------------------------------------------------
// Events (audit trail; counts only)
// ---------------------------------------------------------------------------

/// Audit event emitted for each admission decision.
///
/// Carries counts and `(ε, δ)` figures only — bd-cixqu.45 logging discipline
/// forbids recording peer identity or contribution content here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum FleetBudgetEvent {
    /// A round was admitted and charged against the budget.
    RoundAdmitted {
        fleet_id: String,
        round_id: u64,
        participant_count: usize,
        epsilon_charged_millionths: i64,
        delta_charged_millionths: i64,
        cumulative_epsilon_millionths: i64,
        cumulative_delta_millionths: i64,
        timestamp_ns: u64,
    },
    /// A round was refused; nothing was charged and no aggregate is published.
    RoundRefused {
        fleet_id: String,
        /// Saturates at `u64::MAX` only when no next identifier is representable;
        /// that terminal refusal never admits a round with a duplicate ID.
        attempted_round_id: u64,
        participant_count: usize,
        reason: String,
        epsilon_remaining_millionths: i64,
        delta_remaining_millionths: i64,
        timestamp_ns: u64,
    },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors / refusals from fleet budget operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetBudgetError {
    /// The round is refused because the fleet budget is (or would be) exhausted.
    Refused {
        /// Which dimension was exceeded: `"epsilon"` or `"delta"`.
        dimension: String,
        epsilon_remaining_millionths: i64,
        delta_remaining_millionths: i64,
    },
    /// The round is refused because the contributing cohort is too small.
    InsufficientCohort {
        participant_count: usize,
        required: usize,
    },
    /// The round is refused because the lifetime round cap has been reached.
    RoundCapReached { max_rounds: u64 },
    /// The supplied round cost is invalid (e.g. negative).
    InvalidCost { reason: String },
    /// The configuration is unusable.
    InvalidConfiguration { reason: String },
}

impl std::fmt::Display for FleetBudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused {
                dimension,
                epsilon_remaining_millionths,
                delta_remaining_millionths,
            } => write!(
                f,
                "fleet aggregation refused ({dimension} budget exhausted): \
                 eps_remaining={epsilon_remaining_millionths}, \
                 delta_remaining={delta_remaining_millionths}"
            ),
            Self::InsufficientCohort {
                participant_count,
                required,
            } => write!(
                f,
                "fleet aggregation refused: cohort too small ({participant_count} < {required})"
            ),
            Self::RoundCapReached { max_rounds } => {
                write!(
                    f,
                    "fleet aggregation refused: round cap {max_rounds} reached"
                )
            }
            Self::InvalidCost { reason } => write!(f, "invalid round cost: {reason}"),
            Self::InvalidConfiguration { reason } => {
                write!(f, "invalid fleet budget configuration: {reason}")
            }
        }
    }
}

impl std::error::Error for FleetBudgetError {}

// ---------------------------------------------------------------------------
// FleetPrivacyBudget — the aggregator-side gate
// ---------------------------------------------------------------------------

/// Aggregator-side, fleet-wide differential-privacy budget tracker.
///
/// Holds a single ledger of admitted rounds and a fail-closed exhaustion latch.
/// The aggregator calls [`FleetPrivacyBudget::try_admit_round`] before each new
/// aggregation; a non-`Ok` result means **do not publish** that aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPrivacyBudget {
    config: FleetBudgetConfig,
    lifetime_epsilon_spent_millionths: i64,
    lifetime_delta_spent_millionths: i64,
    rounds_admitted: u64,
    exhausted: bool,
    ledger: Vec<FleetRoundLedgerEntry>,
    events: Vec<FleetBudgetEvent>,
    /// Missing in snapshots produced by the old discounted composition rules.
    #[serde(default)]
    accounting_version: u8,
}

impl FleetPrivacyBudget {
    /// Create a new fleet budget from validated configuration.
    pub fn new(config: FleetBudgetConfig) -> Result<Self, FleetBudgetError> {
        config.validate()?;
        Ok(Self {
            config,
            lifetime_epsilon_spent_millionths: 0,
            lifetime_delta_spent_millionths: 0,
            rounds_admitted: 0,
            exhausted: false,
            ledger: Vec::new(),
            events: Vec::new(),
            accounting_version: FLEET_ACCOUNTING_VERSION,
        })
    }

    /// Remaining lifetime epsilon (millionths).  Never reported below zero.
    pub fn epsilon_remaining_millionths(&self) -> i64 {
        self.config
            .lifetime_epsilon_budget_millionths
            .saturating_sub(self.lifetime_epsilon_spent_millionths)
            .max(0)
    }

    /// Remaining lifetime delta (millionths).  Never reported below zero.
    pub fn delta_remaining_millionths(&self) -> i64 {
        self.config
            .lifetime_delta_budget_millionths
            .saturating_sub(self.lifetime_delta_spent_millionths)
            .max(0)
    }

    /// Whether the budget latch has tripped (fail-closed).
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Number of rounds admitted so far.
    pub fn rounds_admitted(&self) -> u64 {
        self.rounds_admitted
    }

    /// The committed round ledger.
    pub fn ledger(&self) -> &[FleetRoundLedgerEntry] {
        &self.ledger
    }

    /// The emitted audit events (counts only).
    pub fn events(&self) -> &[FleetBudgetEvent] {
        &self.events
    }

    /// The fleet identifier this budget scopes.
    pub fn fleet_id(&self) -> &str {
        &self.config.fleet_id
    }

    fn validate_accounting_policy(&self) -> Result<(), FleetBudgetError> {
        self.config.validate()?;
        if self.lifetime_epsilon_spent_millionths < 0
            || self.lifetime_delta_spent_millionths < 0
            || self.lifetime_epsilon_spent_millionths
                > self.config.lifetime_epsilon_budget_millionths
            || self.lifetime_delta_spent_millionths > self.config.lifetime_delta_budget_millionths
        {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "restored lifetime spend is outside the configured budget".into(),
            });
        }
        match self.accounting_version {
            FLEET_ACCOUNTING_VERSION => Ok(()),
            0 if self.config.composition_method == CompositionMethod::Basic => {
                // Validate a legacy additive snapshot once, before stamping its
                // first successful new admission with the current version.
                self.verify_ledger_integrity()
            }
            0 if self.rounds_admitted == 0
                && self.lifetime_epsilon_spent_millionths == 0
                && self.lifetime_delta_spent_millionths == 0
                && self.ledger.is_empty() => Ok(()),
            0 => Err(FleetBudgetError::InvalidConfiguration {
                reason: "legacy non-basic fleet history requires an audited migration; discounted charges cannot be reused".into(),
            }),
            _ => Err(FleetBudgetError::InvalidConfiguration {
                reason: "unsupported fleet accounting version".into(),
            }),
        }
    }

    /// Dry-run check: would a round of the given raw cost be refused on budget
    /// grounds right now?  Does not consider the cohort floor or round cap and
    /// does not mutate state.
    pub fn would_refuse(&self, epsilon_millionths: i64, delta_millionths: i64) -> bool {
        if self.exhausted {
            return true;
        }
        if epsilon_millionths < 0
            || delta_millionths < 0
            || self.validate_accounting_policy().is_err()
            || self.rounds_admitted == u64::MAX
        {
            return true;
        }
        checked_fleet_spend(
            self.lifetime_epsilon_spent_millionths,
            epsilon_millionths,
            self.config.lifetime_epsilon_budget_millionths,
        )
        .is_none()
            || checked_fleet_spend(
                self.lifetime_delta_spent_millionths,
                delta_millionths,
                self.config.lifetime_delta_budget_millionths,
            )
            .is_none()
    }

    /// Attempt to admit a new aggregation round.
    ///
    /// On `Ok`, the round is charged against the fleet budget, recorded in the
    /// ledger, and an admission event is emitted; the aggregator may publish.
    /// On `Err`, **nothing is charged** and the aggregator must not publish.
    /// A refusal also records a `RoundRefused` audit event.
    ///
    /// Refusal order is fixed and fail-closed: invalid cost, latch, persisted
    /// policy and counter validity, cohort floor, round cap, then budget ceiling.
    pub fn try_admit_round(
        &mut self,
        epsilon_millionths: i64,
        delta_millionths: i64,
        participant_count: usize,
        now_ns: u64,
    ) -> Result<FleetRoundReceipt, FleetBudgetError> {
        // 1. Invalid cost is a caller bug, not a refusal event.
        if epsilon_millionths < 0 || delta_millionths < 0 {
            return Err(FleetBudgetError::InvalidCost {
                reason: "epsilon and delta must be non-negative".into(),
            });
        }

        let next_round_id = self.rounds_admitted.checked_add(1);
        // Audit-only terminal marker. Admission below requires a checked ID.
        let attempted_round_id = next_round_id.unwrap_or(u64::MAX);

        // 2. Fail-closed latch: once tripped, stays tripped.
        if self.exhausted {
            let err = FleetBudgetError::Refused {
                dimension: "latched".into(),
                epsilon_remaining_millionths: self.epsilon_remaining_millionths(),
                delta_remaining_millionths: self.delta_remaining_millionths(),
            };
            self.record_refusal(attempted_round_id, participant_count, &err, now_ns);
            return Err(err);
        }

        if let Err(err) = self.validate_accounting_policy() {
            self.exhausted = true;
            self.record_refusal(attempted_round_id, participant_count, &err, now_ns);
            return Err(err);
        }
        let Some(attempted_round_id) = next_round_id else {
            self.exhausted = true;
            let err = FleetBudgetError::RoundCapReached {
                max_rounds: u64::MAX,
            };
            self.record_refusal(u64::MAX, participant_count, &err, now_ns);
            return Err(err);
        };

        // Cohort floor: refuse rounds with too few contributing peers.
        if participant_count < self.config.min_participants_per_round {
            let err = FleetBudgetError::InsufficientCohort {
                participant_count,
                required: self.config.min_participants_per_round,
            };
            self.record_refusal(attempted_round_id, participant_count, &err, now_ns);
            return Err(err);
        }

        // Configured round cap.
        if self.config.max_rounds != 0 && self.rounds_admitted >= self.config.max_rounds {
            let err = FleetBudgetError::RoundCapReached {
                max_rounds: self.config.max_rounds,
            };
            self.record_refusal(attempted_round_id, participant_count, &err, now_ns);
            return Err(err);
        }

        // Generic (epsilon, delta) guarantees compose additively. Neither a
        // constant discount nor epsilon/sqrt(k) is a valid replacement.
        let (composed_eps, composed_delta) = (epsilon_millionths, delta_millionths);
        let next_eps = checked_fleet_spend(
            self.lifetime_epsilon_spent_millionths,
            composed_eps,
            self.config.lifetime_epsilon_budget_millionths,
        );
        let next_delta = checked_fleet_spend(
            self.lifetime_delta_spent_millionths,
            composed_delta,
            self.config.lifetime_delta_budget_millionths,
        );
        let (Some(next_eps), Some(next_delta)) = (next_eps, next_delta) else {
            // Trip the latch: refusing on budget grounds is terminal.
            self.exhausted = true;
            let err = FleetBudgetError::Refused {
                dimension: if next_eps.is_none() {
                    "epsilon"
                } else {
                    "delta"
                }
                .into(),
                epsilon_remaining_millionths: self.epsilon_remaining_millionths(),
                delta_remaining_millionths: self.delta_remaining_millionths(),
            };
            self.record_refusal(attempted_round_id, participant_count, &err, now_ns);
            return Err(err);
        };

        // Commit the round.
        self.lifetime_epsilon_spent_millionths = next_eps;
        self.lifetime_delta_spent_millionths = next_delta;
        self.rounds_admitted = attempted_round_id;
        self.accounting_version = FLEET_ACCOUNTING_VERSION;

        let entry = FleetRoundLedgerEntry {
            round_id: attempted_round_id,
            epsilon_requested_millionths: epsilon_millionths,
            delta_requested_millionths: delta_millionths,
            epsilon_charged_millionths: composed_eps,
            delta_charged_millionths: composed_delta,
            participant_count,
            cumulative_epsilon_millionths: next_eps,
            cumulative_delta_millionths: next_delta,
            timestamp_ns: now_ns,
        };
        self.ledger.push(entry.clone());

        // If this round consumed the budget exactly, latch so the *next* call
        // refuses deterministically rather than re-deriving the boundary.
        let budget_now_exhausted = self.epsilon_remaining_millionths() == 0
            || self.delta_remaining_millionths() == 0
            || self.rounds_admitted == u64::MAX;
        if budget_now_exhausted {
            self.exhausted = true;
        }

        self.events.push(FleetBudgetEvent::RoundAdmitted {
            fleet_id: self.config.fleet_id.clone(),
            round_id: entry.round_id,
            participant_count,
            epsilon_charged_millionths: composed_eps,
            delta_charged_millionths: composed_delta,
            cumulative_epsilon_millionths: next_eps,
            cumulative_delta_millionths: next_delta,
            timestamp_ns: now_ns,
        });

        Ok(FleetRoundReceipt {
            entry,
            epsilon_remaining_millionths: self.epsilon_remaining_millionths(),
            delta_remaining_millionths: self.delta_remaining_millionths(),
            budget_now_exhausted,
        })
    }

    /// Record a `RoundRefused` audit event.  The reason is the `Display` of the
    /// refusal error; remaining figures reflect the budget at refusal time.
    /// Counts and `(ε, δ)` only — never peer identity or content.
    fn record_refusal(
        &mut self,
        attempted_round_id: u64,
        participant_count: usize,
        err: &FleetBudgetError,
        now_ns: u64,
    ) {
        self.events.push(FleetBudgetEvent::RoundRefused {
            fleet_id: self.config.fleet_id.clone(),
            attempted_round_id,
            participant_count,
            reason: err.to_string(),
            epsilon_remaining_millionths: self.epsilon_remaining_millionths(),
            delta_remaining_millionths: self.delta_remaining_millionths(),
            timestamp_ns: now_ns,
        });
    }

    /// Forecast remaining capacity at the average per-round charge so far.
    pub fn forecast(&self) -> FleetBudgetForecast {
        let eps_remaining = self.epsilon_remaining_millionths();
        let estimated_rounds_remaining = if self.rounds_admitted > 0 {
            let avg_eps = i128::from(self.lifetime_epsilon_spent_millionths)
                / i128::from(self.rounds_admitted);
            if avg_eps > 0 {
                (i128::from(eps_remaining) / avg_eps).max(0) as u64
            } else {
                u64::MAX
            }
        } else {
            u64::MAX
        };
        FleetBudgetForecast {
            epsilon_remaining_millionths: eps_remaining,
            delta_remaining_millionths: self.delta_remaining_millionths(),
            rounds_admitted: self.rounds_admitted,
            estimated_rounds_remaining,
            exhausted: self.exhausted,
        }
    }

    /// Recompute cumulative sums from the ledger and confirm they match the
    /// recorded running totals and additive raw charges. This is an explicit
    /// consistency audit, not authentication of an externally supplied ledger.
    pub fn verify_ledger_integrity(&self) -> Result<(), FleetBudgetError> {
        self.config.validate()?;
        let mut eps = 0i64;
        let mut delta = 0i64;
        let mut expected_round = 0u64;
        for (i, entry) in self.ledger.iter().enumerate() {
            expected_round = expected_round.checked_add(1).ok_or_else(|| {
                FleetBudgetError::InvalidConfiguration {
                    reason: "ledger round count overflow".into(),
                }
            })?;
            if entry.round_id != expected_round {
                return Err(FleetBudgetError::InvalidConfiguration {
                    reason: format!(
                        "ledger round_id out of order at index {i}: got {}, expected {expected_round}",
                        entry.round_id
                    ),
                });
            }
            if entry.epsilon_requested_millionths < 0
                || entry.delta_requested_millionths < 0
                || entry.epsilon_charged_millionths != entry.epsilon_requested_millionths
                || entry.delta_charged_millionths != entry.delta_requested_millionths
            {
                return Err(FleetBudgetError::InvalidConfiguration {
                    reason: format!(
                        "ledger has a non-additive or negative charge at round {}",
                        entry.round_id
                    ),
                });
            }
            eps = checked_fleet_spend(
                eps,
                entry.epsilon_charged_millionths,
                self.config.lifetime_epsilon_budget_millionths,
            )
            .ok_or_else(|| FleetBudgetError::InvalidConfiguration {
                reason: "ledger epsilon sum exceeds the budget or integer range".into(),
            })?;
            delta = checked_fleet_spend(
                delta,
                entry.delta_charged_millionths,
                self.config.lifetime_delta_budget_millionths,
            )
            .ok_or_else(|| FleetBudgetError::InvalidConfiguration {
                reason: "ledger delta sum exceeds the budget or integer range".into(),
            })?;
            if entry.cumulative_epsilon_millionths != eps
                || entry.cumulative_delta_millionths != delta
            {
                return Err(FleetBudgetError::InvalidConfiguration {
                    reason: format!("ledger cumulative mismatch at round {}", entry.round_id),
                });
            }
        }
        if expected_round != self.rounds_admitted
            || eps != self.lifetime_epsilon_spent_millionths
            || delta != self.lifetime_delta_spent_millionths
        {
            return Err(FleetBudgetError::InvalidConfiguration {
                reason: "ledger totals do not match recorded lifetime spend and round count".into(),
            });
        }
        Ok(())
    }
}

fn checked_fleet_spend(spent: i64, charge: i64, allocation: i64) -> Option<i64> {
    if spent < 0 || charge < 0 || allocation < 0 {
        return None;
    }
    spent.checked_add(charge).filter(|next| *next <= allocation)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_config() -> FleetBudgetConfig {
        FleetBudgetConfig {
            fleet_id: "fleet-alpha".into(),
            lifetime_epsilon_budget_millionths: 10_000_000, // 10.0
            lifetime_delta_budget_millionths: 1_000_000,    // 1.0
            composition_method: CompositionMethod::Basic,
            min_participants_per_round: 3,
            max_rounds: 0,
        }
    }

    fn budget() -> FleetPrivacyBudget {
        FleetPrivacyBudget::new(basic_config()).unwrap()
    }

    // -- construction / validation --

    #[test]
    fn new_budget_starts_empty() {
        let b = budget();
        assert_eq!(b.rounds_admitted(), 0);
        assert!(!b.is_exhausted());
        assert_eq!(b.epsilon_remaining_millionths(), 10_000_000);
        assert_eq!(b.delta_remaining_millionths(), 1_000_000);
        assert!(b.ledger().is_empty());
        assert!(b.events().is_empty());
        assert_eq!(b.fleet_id(), "fleet-alpha");
    }

    #[test]
    fn rejects_empty_fleet_id() {
        let mut cfg = basic_config();
        cfg.fleet_id = "   ".into();
        assert!(matches!(
            FleetPrivacyBudget::new(cfg),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn rejects_nonpositive_epsilon_budget() {
        let mut cfg = basic_config();
        cfg.lifetime_epsilon_budget_millionths = 0;
        assert!(matches!(
            FleetPrivacyBudget::new(cfg),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn rejects_nonpositive_delta_budget() {
        let mut cfg = basic_config();
        cfg.lifetime_delta_budget_millionths = -1;
        assert!(matches!(
            FleetPrivacyBudget::new(cfg),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn rejects_zero_min_participants() {
        let mut cfg = basic_config();
        cfg.min_participants_per_round = 0;
        assert!(matches!(
            FleetPrivacyBudget::new(cfg),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
    }

    // -- admission happy path --

    #[test]
    fn admits_round_within_budget() {
        let mut b = budget();
        let r = b.try_admit_round(1_000_000, 100_000, 5, 1).unwrap();
        assert_eq!(r.entry.round_id, 1);
        assert_eq!(r.entry.epsilon_charged_millionths, 1_000_000);
        assert_eq!(r.entry.participant_count, 5);
        assert_eq!(r.epsilon_remaining_millionths, 9_000_000);
        assert_eq!(r.delta_remaining_millionths, 900_000);
        assert!(!r.budget_now_exhausted);
        assert_eq!(b.rounds_admitted(), 1);
        assert_eq!(b.ledger().len(), 1);
    }

    #[test]
    fn cumulative_spend_accumulates_across_rounds() {
        let mut b = budget();
        b.try_admit_round(2_000_000, 100_000, 4, 1).unwrap();
        b.try_admit_round(3_000_000, 200_000, 4, 2).unwrap();
        let last = b.ledger().last().unwrap();
        assert_eq!(last.cumulative_epsilon_millionths, 5_000_000);
        assert_eq!(last.cumulative_delta_millionths, 300_000);
        assert_eq!(b.epsilon_remaining_millionths(), 5_000_000);
        assert_eq!(b.delta_remaining_millionths(), 700_000);
    }

    #[test]
    fn round_ids_are_monotonic() {
        let mut b = budget();
        for i in 0..4 {
            let r = b.try_admit_round(500_000, 10_000, 3, i).unwrap();
            assert_eq!(r.entry.round_id, i + 1);
        }
    }

    #[test]
    fn admission_emits_event() {
        let mut b = budget();
        b.try_admit_round(1_000_000, 50_000, 7, 42).unwrap();
        assert_eq!(b.events().len(), 1);
        match &b.events()[0] {
            FleetBudgetEvent::RoundAdmitted {
                round_id,
                participant_count,
                timestamp_ns,
                ..
            } => {
                assert_eq!(*round_id, 1);
                assert_eq!(*participant_count, 7);
                assert_eq!(*timestamp_ns, 42);
            }
            other => panic!("expected RoundAdmitted, got {other:?}"),
        }
    }

    // -- budget exhaustion / refusal --

    #[test]
    fn refuses_round_that_exceeds_epsilon_budget() {
        let mut b = budget();
        b.try_admit_round(9_000_000, 100_000, 4, 1).unwrap();
        let err = b.try_admit_round(2_000_000, 100_000, 4, 2).unwrap_err();
        match err {
            FleetBudgetError::Refused { dimension, .. } => assert_eq!(dimension, "epsilon"),
            other => panic!("expected Refused(epsilon), got {other:?}"),
        }
        // Nothing charged for the refused round.
        assert_eq!(b.rounds_admitted(), 1);
        assert_eq!(b.epsilon_remaining_millionths(), 1_000_000);
    }

    #[test]
    fn refuses_round_that_exceeds_delta_budget() {
        let mut b = budget();
        // Epsilon fine, delta blows the 1.0 ceiling.
        let err = b.try_admit_round(1_000_000, 2_000_000, 4, 1).unwrap_err();
        match err {
            FleetBudgetError::Refused { dimension, .. } => assert_eq!(dimension, "delta"),
            other => panic!("expected Refused(delta), got {other:?}"),
        }
        assert_eq!(b.rounds_admitted(), 0);
    }

    #[test]
    fn refusal_is_terminal_latch() {
        let mut b = budget();
        b.try_admit_round(10_000_000, 100_000, 4, 1).unwrap(); // exact epsilon ceiling -> latch
        assert!(b.is_exhausted());
        // Even a tiny subsequent round is refused.
        let err = b.try_admit_round(1, 1, 4, 2).unwrap_err();
        assert!(
            matches!(err, FleetBudgetError::Refused { dimension, .. } if dimension == "latched")
        );
    }

    #[test]
    fn exact_budget_consumption_latches() {
        let mut b = budget();
        let r = b.try_admit_round(10_000_000, 1_000_000, 4, 1).unwrap();
        assert!(r.budget_now_exhausted);
        assert!(b.is_exhausted());
        assert_eq!(b.epsilon_remaining_millionths(), 0);
        assert_eq!(b.delta_remaining_millionths(), 0);
    }

    #[test]
    fn refused_round_emits_refusal_event() {
        let mut b = budget();
        let _ = b.try_admit_round(99_000_000, 100_000, 4, 9).unwrap_err();
        assert_eq!(b.events().len(), 1);
        assert!(matches!(
            &b.events()[0],
            FleetBudgetEvent::RoundRefused { attempted_round_id, .. } if *attempted_round_id == 1
        ));
    }

    // -- cohort floor --

    #[test]
    fn refuses_round_with_too_few_participants() {
        let mut b = budget();
        let err = b.try_admit_round(1_000_000, 10_000, 2, 1).unwrap_err();
        match err {
            FleetBudgetError::InsufficientCohort {
                participant_count,
                required,
            } => {
                assert_eq!(participant_count, 2);
                assert_eq!(required, 3);
            }
            other => panic!("expected InsufficientCohort, got {other:?}"),
        }
        // Cohort refusal does not charge or trip the budget latch.
        assert!(!b.is_exhausted());
        assert_eq!(b.rounds_admitted(), 0);
    }

    #[test]
    fn cohort_floor_of_one_admits_single_peer() {
        let mut cfg = basic_config();
        cfg.min_participants_per_round = 1;
        let mut b = FleetPrivacyBudget::new(cfg).unwrap();
        assert!(b.try_admit_round(1_000_000, 10_000, 1, 1).is_ok());
    }

    // -- round cap --

    #[test]
    fn refuses_after_round_cap() {
        let mut cfg = basic_config();
        cfg.max_rounds = 2;
        let mut b = FleetPrivacyBudget::new(cfg).unwrap();
        b.try_admit_round(100_000, 10_000, 4, 1).unwrap();
        b.try_admit_round(100_000, 10_000, 4, 2).unwrap();
        let err = b.try_admit_round(100_000, 10_000, 4, 3).unwrap_err();
        assert!(matches!(
            err,
            FleetBudgetError::RoundCapReached { max_rounds: 2 }
        ));
    }

    // -- invalid cost --

    #[test]
    fn negative_cost_is_invalid_not_refusal() {
        let mut b = budget();
        assert!(matches!(
            b.try_admit_round(-1, 10_000, 4, 1),
            Err(FleetBudgetError::InvalidCost { .. })
        ));
        assert!(matches!(
            b.try_admit_round(10_000, -5, 4, 1),
            Err(FleetBudgetError::InvalidCost { .. })
        ));
        // No event for a caller bug.
        assert!(b.events().is_empty());
    }

    // -- would_refuse dry run --

    #[test]
    fn would_refuse_matches_admission() {
        let mut b = budget();
        assert!(!b.would_refuse(5_000_000, 100_000));
        b.try_admit_round(8_000_000, 100_000, 4, 1).unwrap();
        assert!(b.would_refuse(3_000_000, 100_000)); // 8+3 > 10
        assert!(!b.would_refuse(2_000_000, 100_000)); // 8+2 == 10, ok
    }

    #[test]
    fn would_refuse_true_when_latched() {
        let mut b = budget();
        b.try_admit_round(10_000_000, 1_000_000, 4, 1).unwrap();
        assert!(b.would_refuse(0, 0));
    }

    #[test]
    fn would_refuse_true_for_negative() {
        let b = budget();
        assert!(b.would_refuse(-1, 0));
    }

    // -- composition methods --

    #[test]
    fn advanced_policy_uses_the_additive_bound_for_each_round() {
        let mut cfg = basic_config();
        cfg.composition_method = CompositionMethod::Advanced;
        let mut b = FleetPrivacyBudget::new(cfg).unwrap();
        let r1 = b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        assert_eq!(r1.entry.epsilon_charged_millionths, 1_000_000);
        let r2 = b.try_admit_round(1_000_000, 10_000, 4, 2).unwrap();
        assert_eq!(r2.entry.epsilon_charged_millionths, 1_000_000);
        assert_eq!(r2.entry.cumulative_epsilon_millionths, 2_000_000);
    }

    #[test]
    fn renyi_policy_requires_native_statistics_before_any_discount() {
        let mut cfg = basic_config();
        cfg.composition_method = CompositionMethod::Renyi;
        let mut b = FleetPrivacyBudget::new(cfg).unwrap();
        let r = b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        assert_eq!(r.entry.epsilon_charged_millionths, 1_000_000);
    }

    #[test]
    fn zcdp_policy_requires_native_statistics_before_any_discount() {
        let mut cfg = basic_config();
        cfg.composition_method = CompositionMethod::ZeroCdp;
        let mut b = FleetPrivacyBudget::new(cfg).unwrap();
        let r = b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        assert_eq!(r.entry.epsilon_charged_millionths, 1_000_000);
    }

    // -- forecast --

    #[test]
    fn forecast_estimates_remaining_rounds() {
        let mut b = budget();
        b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        let f = b.forecast();
        assert_eq!(f.rounds_admitted, 1);
        // 9.0 remaining / 1.0 per round = 9 rounds.
        assert_eq!(f.estimated_rounds_remaining, 9);
        assert!(!f.exhausted);
    }

    #[test]
    fn forecast_unlimited_before_any_round() {
        let b = budget();
        assert_eq!(b.forecast().estimated_rounds_remaining, u64::MAX);
    }

    // -- ledger integrity --

    #[test]
    fn ledger_integrity_holds_after_rounds() {
        let mut b = budget();
        b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        b.try_admit_round(2_000_000, 20_000, 5, 2).unwrap();
        b.try_admit_round(500_000, 5_000, 6, 3).unwrap();
        assert!(b.verify_ledger_integrity().is_ok());
    }

    #[test]
    fn tampered_ledger_is_detected() {
        let mut b = budget();
        b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        b.try_admit_round(2_000_000, 20_000, 5, 2).unwrap();
        // Corrupt a cumulative figure.
        b.ledger[1].cumulative_epsilon_millionths += 1;
        assert!(b.verify_ledger_integrity().is_err());
    }

    fn assert_only_latch_and_refusal_changed(
        mut before: FleetPrivacyBudget,
        after: &FleetPrivacyBudget,
    ) {
        assert_eq!(after.events.len(), before.events.len() + 1);
        let event = after.events.last().unwrap().clone();
        assert!(matches!(event, FleetBudgetEvent::RoundRefused { .. }));
        before.exhausted = true;
        before.events.push(event);
        assert_eq!(
            &before, after,
            "refused rounds must not commit ledger entries or spend"
        );
    }

    #[test]
    fn round_identifier_exhaustion_is_atomic_and_never_wraps_the_audit_marker() {
        let mut b = budget();
        b.rounds_admitted = u64::MAX;
        let before = b.clone();
        assert!(b.would_refuse(0, 0));
        assert!(matches!(
            b.try_admit_round(1, 1, 3, 1),
            Err(FleetBudgetError::RoundCapReached {
                max_rounds: u64::MAX
            })
        ));
        assert_only_latch_and_refusal_changed(before, &b);
        assert!(matches!(
            b.events.last(),
            Some(FleetBudgetEvent::RoundRefused {
                attempted_round_id: u64::MAX,
                ..
            })
        ));
        assert!(b.try_admit_round(0, 0, 3, 2).is_err());
        assert_eq!(b.rounds_admitted, u64::MAX);
        assert!(b.ledger.is_empty());
    }

    #[test]
    fn ledger_audit_rejects_saturated_sums_and_undercharged_entries() {
        let mut b = FleetPrivacyBudget::new(FleetBudgetConfig {
            lifetime_epsilon_budget_millionths: i64::MAX,
            lifetime_delta_budget_millionths: i64::MAX,
            ..basic_config()
        })
        .unwrap();
        b.try_admit_round(i64::MAX - 1, 0, 3, 1).unwrap();
        let mut second = b.ledger[0].clone();
        second.round_id = 2;
        second.epsilon_requested_millionths = 2;
        second.epsilon_charged_millionths = 2;
        second.cumulative_epsilon_millionths = i64::MAX;
        b.ledger.push(second);
        b.rounds_admitted = 2;
        b.lifetime_epsilon_spent_millionths = i64::MAX;
        assert!(b.verify_ledger_integrity().is_err());

        let mut b = budget();
        b.try_admit_round(100_000, 0, 3, 1).unwrap();
        b.ledger[0].epsilon_requested_millionths = 200_000;
        assert!(b.verify_ledger_integrity().is_err());
        b.ledger[0].epsilon_requested_millionths = -1;
        assert!(b.verify_ledger_integrity().is_err());
    }

    #[test]
    fn legacy_basic_state_must_pass_the_full_additive_ledger_audit() {
        let mut b = budget();
        b.try_admit_round(100_000, 0, 3, 1).unwrap();
        b.accounting_version = 0;
        b.rounds_admitted += 1;
        let before = b.clone();
        assert!(b.would_refuse(0, 0));
        assert!(matches!(
            b.try_admit_round(0, 0, 3, 2),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
        assert_only_latch_and_refusal_changed(before, &b);
    }

    #[test]
    fn malformed_restored_spend_has_total_diagnostics_but_cannot_admit() {
        let mut b = budget();
        b.config.lifetime_epsilon_budget_millionths = i64::MAX;
        b.config.lifetime_delta_budget_millionths = i64::MAX;
        b.lifetime_epsilon_spent_millionths = i64::MIN;
        b.lifetime_delta_spent_millionths = i64::MIN;
        b.rounds_admitted = u64::MAX;
        let forecast = b.forecast();
        assert_eq!(forecast.epsilon_remaining_millionths, i64::MAX);
        assert_eq!(forecast.delta_remaining_millionths, i64::MAX);
        let before = b.clone();
        assert!(b.would_refuse(0, 0));
        assert!(matches!(
            b.try_admit_round(0, 0, 3, 1),
            Err(FleetBudgetError::InvalidConfiguration { .. })
        ));
        assert_only_latch_and_refusal_changed(before, &b);
    }

    // -- serde round trip --

    #[test]
    fn budget_serde_round_trip() {
        let mut b = budget();
        b.try_admit_round(1_000_000, 10_000, 4, 1).unwrap();
        let json = serde_json::to_string(&b).unwrap();
        let back: FleetPrivacyBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn error_serde_round_trip() {
        let e = FleetBudgetError::Refused {
            dimension: "epsilon".into(),
            epsilon_remaining_millionths: 0,
            delta_remaining_millionths: 5,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: FleetBudgetError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn error_display_is_descriptive() {
        let e = FleetBudgetError::InsufficientCohort {
            participant_count: 1,
            required: 3,
        };
        assert!(e.to_string().contains("cohort too small"));
    }
}
