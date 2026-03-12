//! Budget propagation, child-budget derivation, and cleanup-budget contracts.
//!
//! Defines explicit rules for how execution budgets propagate across
//! orchestration boundaries (parent → child cells, cleanup/finalize phases),
//! so budget behavior is contractual rather than incidental.
//!
//! Key invariants enforced:
//! - Child budgets never exceed their parent budget
//! - Cleanup budgets are bounded and carved from the parent allocation
//! - Budget derivation produces a deterministic audit trail
//! - Exhaustion semantics propagate fail-closed across boundaries
//!
//! Plan references: Section 10.13X.C1, bd-3nr.1.3.1.
//! Dependencies: control_plane adapter (Budget, ContextAdapter),
//!               execution_cell (CellKind), execution_orchestrator (OrchestratorConfig).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCALE: u64 = 1_000_000;

/// Default cleanup budget fraction (millionths): 10% of parent.
const DEFAULT_CLEANUP_FRACTION_MILLIONTHS: u64 = 100_000;

/// Minimum cleanup budget in milliseconds.
const MIN_CLEANUP_BUDGET_MS: u64 = 50;

/// Maximum cleanup budget in milliseconds.
const MAX_CLEANUP_BUDGET_MS: u64 = 30_000;

/// Default child fraction (millionths): 80% of parent.
const DEFAULT_CHILD_FRACTION_MILLIONTHS: u64 = 800_000;

/// Minimum child budget in milliseconds.
const MIN_CHILD_BUDGET_MS: u64 = 10;

/// Default finalize budget in milliseconds.
const DEFAULT_FINALIZE_BUDGET_MS: u64 = 500;

// ---------------------------------------------------------------------------
// BudgetBoundaryKind
// ---------------------------------------------------------------------------

/// Classification of the orchestration boundary being crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetBoundaryKind {
    /// Parent cell spawning a child extension cell.
    ParentToChildExtension,
    /// Parent cell spawning a child session cell.
    ParentToChildSession,
    /// Parent cell spawning a delegate computation.
    ParentToChildDelegate,
    /// Main execution entering cleanup/drain phase.
    ExecutionToCleanup,
    /// Cleanup entering finalize phase.
    CleanupToFinalize,
    /// Orchestrator allocating cell-close budget.
    OrchestratorToCellClose,
}

impl BudgetBoundaryKind {
    /// Human-readable label for the boundary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParentToChildExtension => "parent_to_child_extension",
            Self::ParentToChildSession => "parent_to_child_session",
            Self::ParentToChildDelegate => "parent_to_child_delegate",
            Self::ExecutionToCleanup => "execution_to_cleanup",
            Self::CleanupToFinalize => "cleanup_to_finalize",
            Self::OrchestratorToCellClose => "orchestrator_to_cell_close",
        }
    }

    /// Whether this boundary produces a child budget (vs. a phase budget).
    pub fn is_child_derivation(self) -> bool {
        matches!(
            self,
            Self::ParentToChildExtension | Self::ParentToChildSession | Self::ParentToChildDelegate
        )
    }
}

// ---------------------------------------------------------------------------
// BudgetDerivationStrategy
// ---------------------------------------------------------------------------

/// Strategy for deriving a child/phase budget from a parent budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDerivationStrategy {
    /// Fixed fraction of parent remaining budget (in millionths).
    FractionOfRemaining { fraction_millionths: u64 },
    /// Fixed absolute amount, capped by parent remaining.
    FixedAmount { amount_ms: u64 },
    /// Fraction with floor and ceiling bounds.
    BoundedFraction {
        fraction_millionths: u64,
        min_ms: u64,
        max_ms: u64,
    },
    /// All remaining parent budget transfers to child.
    AllRemaining,
}

impl BudgetDerivationStrategy {
    /// Compute the derived budget in milliseconds from a parent's remaining budget.
    pub fn derive(&self, parent_remaining_ms: u64) -> u64 {
        match *self {
            Self::FractionOfRemaining {
                fraction_millionths,
            } => {
                let raw = parent_remaining_ms
                    .saturating_mul(fraction_millionths)
                    .checked_div(SCALE)
                    .unwrap_or(0);
                raw.min(parent_remaining_ms)
            }
            Self::FixedAmount { amount_ms } => amount_ms.min(parent_remaining_ms),
            Self::BoundedFraction {
                fraction_millionths,
                min_ms,
                max_ms,
            } => {
                let raw = parent_remaining_ms
                    .saturating_mul(fraction_millionths)
                    .checked_div(SCALE)
                    .unwrap_or(0);
                let bounded = raw.max(min_ms).min(max_ms);
                bounded.min(parent_remaining_ms)
            }
            Self::AllRemaining => parent_remaining_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupBudgetPolicy
// ---------------------------------------------------------------------------

/// Policy governing cleanup/finalize budget allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CleanupBudgetPolicy {
    /// Strategy for computing the drain-phase budget.
    pub drain_strategy: BudgetDerivationStrategy,
    /// Fixed finalize budget (not derived from parent).
    pub finalize_budget_ms: u64,
    /// Whether cleanup budget is carved from the parent (reducing parent)
    /// or allocated independently.
    pub carved_from_parent: bool,
}

impl Default for CleanupBudgetPolicy {
    fn default() -> Self {
        Self {
            drain_strategy: BudgetDerivationStrategy::BoundedFraction {
                fraction_millionths: DEFAULT_CLEANUP_FRACTION_MILLIONTHS,
                min_ms: MIN_CLEANUP_BUDGET_MS,
                max_ms: MAX_CLEANUP_BUDGET_MS,
            },
            finalize_budget_ms: DEFAULT_FINALIZE_BUDGET_MS,
            carved_from_parent: true,
        }
    }
}

impl CleanupBudgetPolicy {
    /// Compute cleanup allocations given parent remaining budget.
    pub fn compute_allocation(&self, parent_remaining_ms: u64) -> CleanupBudgetAllocation {
        let drain_ms = self.drain_strategy.derive(parent_remaining_ms);
        let finalize_ms = self.finalize_budget_ms.min(if self.carved_from_parent {
            parent_remaining_ms.saturating_sub(drain_ms)
        } else {
            self.finalize_budget_ms
        });
        let total_ms = drain_ms.saturating_add(finalize_ms);
        let parent_after_carve = if self.carved_from_parent {
            parent_remaining_ms.saturating_sub(total_ms)
        } else {
            parent_remaining_ms
        };

        CleanupBudgetAllocation {
            drain_budget_ms: drain_ms,
            finalize_budget_ms: finalize_ms,
            total_cleanup_ms: total_ms,
            parent_remaining_after_ms: parent_after_carve,
            carved_from_parent: self.carved_from_parent,
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupBudgetAllocation
// ---------------------------------------------------------------------------

/// Computed cleanup budget allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupBudgetAllocation {
    /// Budget allocated to drain phase.
    pub drain_budget_ms: u64,
    /// Budget allocated to finalize phase.
    pub finalize_budget_ms: u64,
    /// Total cleanup budget (drain + finalize).
    pub total_cleanup_ms: u64,
    /// Parent remaining budget after carving (if applicable).
    pub parent_remaining_after_ms: u64,
    /// Whether this was carved from parent.
    pub carved_from_parent: bool,
}

// ---------------------------------------------------------------------------
// ChildBudgetRule
// ---------------------------------------------------------------------------

/// Rule governing child budget derivation at a specific boundary kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChildBudgetRule {
    /// Which boundary this rule applies to.
    pub boundary_kind: BudgetBoundaryKind,
    /// Strategy for computing the child budget.
    pub derivation: BudgetDerivationStrategy,
    /// Minimum budget the child must receive (or derivation fails).
    pub minimum_ms: u64,
    /// Whether the child budget is carved from the parent.
    pub carved_from_parent: bool,
}

impl ChildBudgetRule {
    /// Default rule for extension children.
    pub fn default_extension() -> Self {
        Self {
            boundary_kind: BudgetBoundaryKind::ParentToChildExtension,
            derivation: BudgetDerivationStrategy::BoundedFraction {
                fraction_millionths: DEFAULT_CHILD_FRACTION_MILLIONTHS,
                min_ms: MIN_CHILD_BUDGET_MS,
                max_ms: MAX_CLEANUP_BUDGET_MS,
            },
            minimum_ms: MIN_CHILD_BUDGET_MS,
            carved_from_parent: true,
        }
    }

    /// Default rule for session children.
    pub fn default_session() -> Self {
        Self {
            boundary_kind: BudgetBoundaryKind::ParentToChildSession,
            derivation: BudgetDerivationStrategy::FractionOfRemaining {
                fraction_millionths: DEFAULT_CHILD_FRACTION_MILLIONTHS,
            },
            minimum_ms: MIN_CHILD_BUDGET_MS,
            carved_from_parent: true,
        }
    }

    /// Default rule for delegate children.
    pub fn default_delegate() -> Self {
        Self {
            boundary_kind: BudgetBoundaryKind::ParentToChildDelegate,
            derivation: BudgetDerivationStrategy::FractionOfRemaining {
                fraction_millionths: 500_000, // 50% of parent
            },
            minimum_ms: MIN_CHILD_BUDGET_MS,
            carved_from_parent: true,
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetPropagationError
// ---------------------------------------------------------------------------

/// Errors from budget propagation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetPropagationError {
    /// Derived child budget would be below the required minimum.
    InsufficientBudget {
        boundary: BudgetBoundaryKind,
        derived_ms: u64,
        minimum_ms: u64,
        parent_remaining_ms: u64,
    },
    /// No rule configured for this boundary kind.
    NoRuleForBoundary { boundary: BudgetBoundaryKind },
    /// Parent budget already exhausted.
    ParentExhausted {
        boundary: BudgetBoundaryKind,
        parent_remaining_ms: u64,
    },
    /// Cleanup budget exceeds parent remaining.
    CleanupExceedsParent {
        cleanup_total_ms: u64,
        parent_remaining_ms: u64,
    },
    /// Invariant violation: child budget exceeds parent.
    ChildExceedsParent { child_ms: u64, parent_ms: u64 },
}

impl std::fmt::Display for BudgetPropagationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientBudget {
                boundary,
                derived_ms,
                minimum_ms,
                ..
            } => write!(
                f,
                "insufficient budget at {}: derived {}ms < minimum {}ms",
                boundary.as_str(),
                derived_ms,
                minimum_ms
            ),
            Self::NoRuleForBoundary { boundary } => {
                write!(f, "no propagation rule for boundary {}", boundary.as_str())
            }
            Self::ParentExhausted {
                boundary,
                parent_remaining_ms,
            } => write!(
                f,
                "parent exhausted at {}: {}ms remaining",
                boundary.as_str(),
                parent_remaining_ms
            ),
            Self::CleanupExceedsParent {
                cleanup_total_ms,
                parent_remaining_ms,
            } => write!(
                f,
                "cleanup {}ms exceeds parent {}ms",
                cleanup_total_ms, parent_remaining_ms
            ),
            Self::ChildExceedsParent {
                child_ms,
                parent_ms,
            } => {
                write!(f, "child {}ms exceeds parent {}ms", child_ms, parent_ms)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetPropagationEvent
// ---------------------------------------------------------------------------

/// Structured event emitted during budget propagation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BudgetPropagationEvent {
    /// Trace ID of the parent context.
    pub parent_trace_id: String,
    /// Trace ID of the derived child context (if applicable).
    pub child_trace_id: Option<String>,
    /// Boundary being crossed.
    pub boundary_kind: BudgetBoundaryKind,
    /// Parent budget before derivation.
    pub parent_before_ms: u64,
    /// Derived budget for child/phase.
    pub derived_ms: u64,
    /// Parent budget after carving (if carved).
    pub parent_after_ms: u64,
    /// Strategy used for derivation.
    pub strategy_used: String,
    /// Whether derivation succeeded.
    pub success: bool,
    /// Error detail (if failed).
    pub error: Option<String>,
    /// Monotonic event sequence number.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// BudgetDerivationResult
// ---------------------------------------------------------------------------

/// Successful budget derivation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetDerivationResult {
    /// Budget allocated to the child/phase.
    pub derived_budget_ms: u64,
    /// Parent remaining budget after derivation.
    pub parent_remaining_after_ms: u64,
    /// Boundary that was crossed.
    pub boundary_kind: BudgetBoundaryKind,
    /// Whether the child budget was carved from parent.
    pub carved_from_parent: bool,
}

// ---------------------------------------------------------------------------
// BudgetPropagationPolicy
// ---------------------------------------------------------------------------

/// Complete policy governing budget propagation across all boundary kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BudgetPropagationPolicy {
    /// Rules for each boundary kind.
    pub child_rules: BTreeMap<String, ChildBudgetRule>,
    /// Cleanup budget policy.
    pub cleanup_policy: CleanupBudgetPolicy,
    /// Whether to fail-closed on missing rules.
    pub fail_closed_on_missing_rule: bool,
    /// Minimum parent remaining after all carving.
    pub min_parent_reserve_ms: u64,
    /// Security epoch for the policy.
    pub epoch: SecurityEpoch,
}

impl Default for BudgetPropagationPolicy {
    fn default() -> Self {
        let mut child_rules = BTreeMap::new();
        let ext = ChildBudgetRule::default_extension();
        child_rules.insert(ext.boundary_kind.as_str().to_owned(), ext);
        let sess = ChildBudgetRule::default_session();
        child_rules.insert(sess.boundary_kind.as_str().to_owned(), sess);
        let del = ChildBudgetRule::default_delegate();
        child_rules.insert(del.boundary_kind.as_str().to_owned(), del);

        Self {
            child_rules,
            cleanup_policy: CleanupBudgetPolicy::default(),
            fail_closed_on_missing_rule: true,
            min_parent_reserve_ms: 5,
            epoch: SecurityEpoch::from_raw(1),
        }
    }
}

impl BudgetPropagationPolicy {
    /// Look up the rule for a given boundary kind.
    pub fn rule_for(&self, boundary: BudgetBoundaryKind) -> Option<&ChildBudgetRule> {
        self.child_rules.get(boundary.as_str())
    }
}

// ---------------------------------------------------------------------------
// BudgetPropagationValidator
// ---------------------------------------------------------------------------

/// Validates budget propagation against the policy and produces an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPropagationValidator {
    policy: BudgetPropagationPolicy,
    events: Vec<BudgetPropagationEvent>,
    event_counter: u64,
    violations: Vec<BudgetPropagationError>,
}

impl BudgetPropagationValidator {
    /// Create a new validator with the given policy.
    pub fn new(policy: BudgetPropagationPolicy) -> Self {
        Self {
            policy,
            events: Vec::new(),
            event_counter: 0,
            violations: Vec::new(),
        }
    }

    /// Create with default policy.
    pub fn with_defaults() -> Self {
        Self::new(BudgetPropagationPolicy::default())
    }

    /// Derive a child budget for the given boundary.
    pub fn derive_child_budget(
        &mut self,
        parent_trace_id: &str,
        child_trace_id: &str,
        parent_remaining_ms: u64,
        boundary: BudgetBoundaryKind,
    ) -> Result<BudgetDerivationResult, BudgetPropagationError> {
        // Check parent not exhausted
        if parent_remaining_ms == 0 {
            let err = BudgetPropagationError::ParentExhausted {
                boundary,
                parent_remaining_ms,
            };
            self.record_failure(parent_trace_id, Some(child_trace_id), boundary, 0, &err);
            self.violations.push(err.clone());
            return Err(err);
        }

        // Look up rule
        let rule = match self.policy.rule_for(boundary) {
            Some(r) => r.clone(),
            None => {
                if self.policy.fail_closed_on_missing_rule {
                    let err = BudgetPropagationError::NoRuleForBoundary { boundary };
                    self.record_failure(
                        parent_trace_id,
                        Some(child_trace_id),
                        boundary,
                        parent_remaining_ms,
                        &err,
                    );
                    self.violations.push(err.clone());
                    return Err(err);
                }
                // Fail-open: use all remaining
                let result = BudgetDerivationResult {
                    derived_budget_ms: parent_remaining_ms,
                    parent_remaining_after_ms: 0,
                    boundary_kind: boundary,
                    carved_from_parent: true,
                };
                self.record_success(
                    parent_trace_id,
                    child_trace_id,
                    boundary,
                    parent_remaining_ms,
                    parent_remaining_ms,
                    0,
                    "all_remaining_fallback",
                );
                return Ok(result);
            }
        };

        // Derive
        let derived_ms = rule.derivation.derive(parent_remaining_ms);

        // Check minimum
        if derived_ms < rule.minimum_ms {
            let err = BudgetPropagationError::InsufficientBudget {
                boundary,
                derived_ms,
                minimum_ms: rule.minimum_ms,
                parent_remaining_ms,
            };
            self.record_failure(
                parent_trace_id,
                Some(child_trace_id),
                boundary,
                parent_remaining_ms,
                &err,
            );
            self.violations.push(err.clone());
            return Err(err);
        }

        // Invariant: child never exceeds parent
        if derived_ms > parent_remaining_ms {
            let err = BudgetPropagationError::ChildExceedsParent {
                child_ms: derived_ms,
                parent_ms: parent_remaining_ms,
            };
            self.record_failure(
                parent_trace_id,
                Some(child_trace_id),
                boundary,
                parent_remaining_ms,
                &err,
            );
            self.violations.push(err.clone());
            return Err(err);
        }

        let parent_after = if rule.carved_from_parent {
            parent_remaining_ms.saturating_sub(derived_ms)
        } else {
            parent_remaining_ms
        };

        // Check parent reserve
        if rule.carved_from_parent && parent_after < self.policy.min_parent_reserve_ms {
            // Reduce child to maintain reserve
            let max_child = parent_remaining_ms.saturating_sub(self.policy.min_parent_reserve_ms);
            if max_child < rule.minimum_ms {
                let err = BudgetPropagationError::InsufficientBudget {
                    boundary,
                    derived_ms: max_child,
                    minimum_ms: rule.minimum_ms,
                    parent_remaining_ms,
                };
                self.record_failure(
                    parent_trace_id,
                    Some(child_trace_id),
                    boundary,
                    parent_remaining_ms,
                    &err,
                );
                self.violations.push(err.clone());
                return Err(err);
            }

            let result = BudgetDerivationResult {
                derived_budget_ms: max_child,
                parent_remaining_after_ms: parent_remaining_ms.saturating_sub(max_child),
                boundary_kind: boundary,
                carved_from_parent: true,
            };
            self.record_success(
                parent_trace_id,
                child_trace_id,
                boundary,
                parent_remaining_ms,
                max_child,
                parent_remaining_ms.saturating_sub(max_child),
                "bounded_by_reserve",
            );
            return Ok(result);
        }

        let result = BudgetDerivationResult {
            derived_budget_ms: derived_ms,
            parent_remaining_after_ms: parent_after,
            boundary_kind: boundary,
            carved_from_parent: rule.carved_from_parent,
        };
        self.record_success(
            parent_trace_id,
            child_trace_id,
            boundary,
            parent_remaining_ms,
            derived_ms,
            parent_after,
            "standard",
        );
        Ok(result)
    }

    /// Validate a cleanup budget allocation.
    pub fn validate_cleanup(
        &mut self,
        parent_trace_id: &str,
        parent_remaining_ms: u64,
    ) -> Result<CleanupBudgetAllocation, BudgetPropagationError> {
        let alloc = self
            .policy
            .cleanup_policy
            .compute_allocation(parent_remaining_ms);

        if alloc.carved_from_parent && alloc.total_cleanup_ms > parent_remaining_ms {
            let err = BudgetPropagationError::CleanupExceedsParent {
                cleanup_total_ms: alloc.total_cleanup_ms,
                parent_remaining_ms,
            };
            self.record_failure(
                parent_trace_id,
                None,
                BudgetBoundaryKind::ExecutionToCleanup,
                parent_remaining_ms,
                &err,
            );
            self.violations.push(err.clone());
            return Err(err);
        }

        self.record_success(
            parent_trace_id,
            "",
            BudgetBoundaryKind::ExecutionToCleanup,
            parent_remaining_ms,
            alloc.total_cleanup_ms,
            alloc.parent_remaining_after_ms,
            "cleanup_allocation",
        );

        Ok(alloc)
    }

    /// Return all recorded events.
    pub fn events(&self) -> &[BudgetPropagationEvent] {
        &self.events
    }

    /// Return all recorded violations.
    pub fn violations(&self) -> &[BudgetPropagationError] {
        &self.violations
    }

    /// Whether any violations were recorded.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Build a summary report.
    pub fn build_report(&self) -> BudgetPropagationReport {
        let successful = self.events.iter().filter(|e| e.success).count();
        let failed = self.events.iter().filter(|e| !e.success).count();

        let mut boundary_counts: BTreeMap<String, u64> = BTreeMap::new();
        for event in &self.events {
            *boundary_counts
                .entry(event.boundary_kind.as_str().to_owned())
                .or_insert(0) += 1;
        }

        let total_derived: u64 = self
            .events
            .iter()
            .filter(|e| e.success)
            .map(|e| e.derived_ms)
            .sum();

        let content = format!(
            "propagation_events={},success={},failed={},total_derived_ms={}",
            self.events.len(),
            successful,
            failed,
            total_derived,
        );
        let content_hash = ContentHash::compute(content.as_bytes());

        BudgetPropagationReport {
            total_events: self.events.len() as u64,
            successful_derivations: successful as u64,
            failed_derivations: failed as u64,
            total_budget_derived_ms: total_derived,
            boundary_event_counts: boundary_counts,
            violations: self.violations.clone(),
            content_hash,
            epoch: self.policy.epoch,
        }
    }

    // -- Internal helpers --

    #[allow(clippy::too_many_arguments)]
    fn record_success(
        &mut self,
        parent_trace_id: &str,
        child_trace_id: &str,
        boundary: BudgetBoundaryKind,
        parent_before: u64,
        derived: u64,
        parent_after: u64,
        strategy: &str,
    ) {
        self.event_counter += 1;
        self.events.push(BudgetPropagationEvent {
            parent_trace_id: parent_trace_id.to_owned(),
            child_trace_id: if child_trace_id.is_empty() {
                None
            } else {
                Some(child_trace_id.to_owned())
            },
            boundary_kind: boundary,
            parent_before_ms: parent_before,
            derived_ms: derived,
            parent_after_ms: parent_after,
            strategy_used: strategy.to_owned(),
            success: true,
            error: None,
            sequence: self.event_counter,
        });
    }

    fn record_failure(
        &mut self,
        parent_trace_id: &str,
        child_trace_id: Option<&str>,
        boundary: BudgetBoundaryKind,
        parent_before: u64,
        err: &BudgetPropagationError,
    ) {
        self.event_counter += 1;
        self.events.push(BudgetPropagationEvent {
            parent_trace_id: parent_trace_id.to_owned(),
            child_trace_id: child_trace_id.map(|s| s.to_owned()),
            boundary_kind: boundary,
            parent_before_ms: parent_before,
            derived_ms: 0,
            parent_after_ms: parent_before,
            strategy_used: "failed".to_owned(),
            success: false,
            error: Some(err.to_string()),
            sequence: self.event_counter,
        });
    }
}

// ---------------------------------------------------------------------------
// BudgetPropagationReport
// ---------------------------------------------------------------------------

/// Summary report of budget propagation activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPropagationReport {
    /// Total propagation events recorded.
    pub total_events: u64,
    /// Successful derivations.
    pub successful_derivations: u64,
    /// Failed derivations.
    pub failed_derivations: u64,
    /// Total budget derived across all successful derivations.
    pub total_budget_derived_ms: u64,
    /// Event counts per boundary kind.
    pub boundary_event_counts: BTreeMap<String, u64>,
    /// All violations encountered.
    pub violations: Vec<BudgetPropagationError>,
    /// Content hash of the report data.
    pub content_hash: ContentHash,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl BudgetPropagationReport {
    /// Whether the report indicates clean propagation.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_kind_as_str_roundtrip() {
        let kinds = [
            BudgetBoundaryKind::ParentToChildExtension,
            BudgetBoundaryKind::ParentToChildSession,
            BudgetBoundaryKind::ParentToChildDelegate,
            BudgetBoundaryKind::ExecutionToCleanup,
            BudgetBoundaryKind::CleanupToFinalize,
            BudgetBoundaryKind::OrchestratorToCellClose,
        ];
        for kind in kinds {
            assert!(!kind.as_str().is_empty());
        }
    }

    #[test]
    fn test_boundary_kind_is_child_derivation() {
        assert!(BudgetBoundaryKind::ParentToChildExtension.is_child_derivation());
        assert!(BudgetBoundaryKind::ParentToChildSession.is_child_derivation());
        assert!(BudgetBoundaryKind::ParentToChildDelegate.is_child_derivation());
        assert!(!BudgetBoundaryKind::ExecutionToCleanup.is_child_derivation());
        assert!(!BudgetBoundaryKind::CleanupToFinalize.is_child_derivation());
        assert!(!BudgetBoundaryKind::OrchestratorToCellClose.is_child_derivation());
    }

    #[test]
    fn test_fraction_derivation_basic() {
        let strat = BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: 500_000, // 50%
        };
        assert_eq!(strat.derive(1000), 500);
        assert_eq!(strat.derive(0), 0);
        assert_eq!(strat.derive(1), 0); // 50% of 1ms rounds to 0
    }

    #[test]
    fn test_fraction_derivation_full() {
        let strat = BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: SCALE,
        };
        assert_eq!(strat.derive(1000), 1000);
    }

    #[test]
    fn test_fixed_amount_derivation() {
        let strat = BudgetDerivationStrategy::FixedAmount { amount_ms: 500 };
        assert_eq!(strat.derive(1000), 500);
        assert_eq!(strat.derive(200), 200); // capped by parent
        assert_eq!(strat.derive(0), 0);
    }

    #[test]
    fn test_bounded_fraction_derivation() {
        let strat = BudgetDerivationStrategy::BoundedFraction {
            fraction_millionths: 100_000, // 10%
            min_ms: 50,
            max_ms: 500,
        };
        assert_eq!(strat.derive(10_000), 500); // 10% = 1000, capped at 500
        assert_eq!(strat.derive(1000), 100); // 10% = 100, within bounds
        assert_eq!(strat.derive(100), 50); // 10% = 10, floor to 50
        assert_eq!(strat.derive(30), 30); // floor 50 capped by parent 30
    }

    #[test]
    fn test_all_remaining_derivation() {
        let strat = BudgetDerivationStrategy::AllRemaining;
        assert_eq!(strat.derive(1000), 1000);
        assert_eq!(strat.derive(0), 0);
    }

    #[test]
    fn test_cleanup_policy_default() {
        let policy = CleanupBudgetPolicy::default();
        let alloc = policy.compute_allocation(10_000);
        assert!(alloc.drain_budget_ms >= MIN_CLEANUP_BUDGET_MS);
        assert!(alloc.drain_budget_ms <= MAX_CLEANUP_BUDGET_MS);
        assert_eq!(alloc.finalize_budget_ms, DEFAULT_FINALIZE_BUDGET_MS);
        assert!(alloc.total_cleanup_ms <= 10_000);
        assert!(alloc.carved_from_parent);
    }

    #[test]
    fn test_cleanup_allocation_small_parent() {
        let policy = CleanupBudgetPolicy::default();
        let alloc = policy.compute_allocation(100);
        assert!(alloc.total_cleanup_ms <= 100);
        assert!(alloc.drain_budget_ms >= MIN_CLEANUP_BUDGET_MS);
    }

    #[test]
    fn test_cleanup_allocation_zero_parent() {
        let policy = CleanupBudgetPolicy::default();
        let alloc = policy.compute_allocation(0);
        assert_eq!(alloc.drain_budget_ms, 0);
        assert_eq!(alloc.finalize_budget_ms, 0);
    }

    #[test]
    fn test_child_rule_defaults() {
        let ext = ChildBudgetRule::default_extension();
        assert_eq!(
            ext.boundary_kind,
            BudgetBoundaryKind::ParentToChildExtension
        );
        assert!(ext.carved_from_parent);

        let sess = ChildBudgetRule::default_session();
        assert_eq!(sess.boundary_kind, BudgetBoundaryKind::ParentToChildSession);

        let del = ChildBudgetRule::default_delegate();
        assert_eq!(del.boundary_kind, BudgetBoundaryKind::ParentToChildDelegate);
    }

    #[test]
    fn test_policy_default_has_all_child_rules() {
        let policy = BudgetPropagationPolicy::default();
        assert!(
            policy
                .rule_for(BudgetBoundaryKind::ParentToChildExtension)
                .is_some()
        );
        assert!(
            policy
                .rule_for(BudgetBoundaryKind::ParentToChildSession)
                .is_some()
        );
        assert!(
            policy
                .rule_for(BudgetBoundaryKind::ParentToChildDelegate)
                .is_some()
        );
        assert!(
            policy
                .rule_for(BudgetBoundaryKind::ExecutionToCleanup)
                .is_none()
        );
    }

    #[test]
    fn test_validator_derive_child_success() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        let result = validator
            .derive_child_budget(
                "trace-parent",
                "trace-child",
                10_000,
                BudgetBoundaryKind::ParentToChildExtension,
            )
            .unwrap();
        assert!(result.derived_budget_ms > 0);
        assert!(result.derived_budget_ms <= 10_000);
        assert!(result.carved_from_parent);
        assert!(!validator.has_violations());
        assert_eq!(validator.events().len(), 1);
    }

    #[test]
    fn test_validator_derive_child_exhausted_parent() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        let result = validator.derive_child_budget(
            "trace-parent",
            "trace-child",
            0,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        assert!(result.is_err());
        assert!(validator.has_violations());
        match result.unwrap_err() {
            BudgetPropagationError::ParentExhausted { .. } => {}
            other => panic!("expected ParentExhausted, got {:?}", other),
        }
    }

    #[test]
    fn test_validator_derive_child_insufficient_budget() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        // With only 1ms parent, derived will be below minimum
        let result = validator.derive_child_budget(
            "trace-parent",
            "trace-child",
            1,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        // Should fail because 80% of 1ms = 0ms which is < minimum 10ms
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_missing_rule_fail_closed() {
        let policy = BudgetPropagationPolicy {
            fail_closed_on_missing_rule: true,
            ..Default::default()
        };
        let mut validator = BudgetPropagationValidator::new(policy);
        let result = validator.derive_child_budget(
            "trace-parent",
            "trace-child",
            10_000,
            BudgetBoundaryKind::OrchestratorToCellClose,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BudgetPropagationError::NoRuleForBoundary { .. } => {}
            other => panic!("expected NoRuleForBoundary, got {:?}", other),
        }
    }

    #[test]
    fn test_validator_missing_rule_fail_open() {
        let policy = BudgetPropagationPolicy {
            fail_closed_on_missing_rule: false,
            ..Default::default()
        };
        let mut validator = BudgetPropagationValidator::new(policy);
        let result = validator
            .derive_child_budget(
                "trace-parent",
                "trace-child",
                10_000,
                BudgetBoundaryKind::OrchestratorToCellClose,
            )
            .unwrap();
        assert_eq!(result.derived_budget_ms, 10_000);
    }

    #[test]
    fn test_validator_cleanup_success() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        let alloc = validator.validate_cleanup("trace-parent", 10_000).unwrap();
        assert!(alloc.total_cleanup_ms <= 10_000);
        assert!(!validator.has_violations());
    }

    #[test]
    fn test_validator_multiple_derivations() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        let mut remaining = 10_000u64;

        // Derive multiple children
        for i in 0..3 {
            let result = validator
                .derive_child_budget(
                    "trace-parent",
                    &format!("trace-child-{}", i),
                    remaining,
                    BudgetBoundaryKind::ParentToChildSession,
                )
                .unwrap();
            remaining = result.parent_remaining_after_ms;
        }

        assert!(remaining < 10_000);
        assert_eq!(validator.events().len(), 3);
        assert!(!validator.has_violations());

        let report = validator.build_report();
        assert_eq!(report.successful_derivations, 3);
        assert_eq!(report.failed_derivations, 0);
        assert!(report.is_clean());
    }

    #[test]
    fn test_validator_report_content_hash_deterministic() {
        let mut v1 = BudgetPropagationValidator::with_defaults();
        let _ = v1.derive_child_budget(
            "trace-parent",
            "trace-child",
            10_000,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        let r1 = v1.build_report();

        let mut v2 = BudgetPropagationValidator::with_defaults();
        let _ = v2.derive_child_budget(
            "trace-parent",
            "trace-child",
            10_000,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        let r2 = v2.build_report();

        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_child_never_exceeds_parent() {
        let strategies = vec![
            BudgetDerivationStrategy::FractionOfRemaining {
                fraction_millionths: 1_500_000,
            },
            BudgetDerivationStrategy::FixedAmount { amount_ms: 99999 },
            BudgetDerivationStrategy::BoundedFraction {
                fraction_millionths: 2_000_000,
                min_ms: 0,
                max_ms: u64::MAX,
            },
            BudgetDerivationStrategy::AllRemaining,
        ];

        for strat in strategies {
            for parent in [0, 1, 10, 100, 1000, 10_000] {
                let derived = strat.derive(parent);
                assert!(
                    derived <= parent,
                    "derived {} exceeds parent {} for {:?}",
                    derived,
                    parent,
                    strat
                );
            }
        }
    }

    #[test]
    fn test_budget_propagation_error_display() {
        let err = BudgetPropagationError::InsufficientBudget {
            boundary: BudgetBoundaryKind::ParentToChildExtension,
            derived_ms: 5,
            minimum_ms: 10,
            parent_remaining_ms: 20,
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient"));
        assert!(msg.contains("5ms"));
        assert!(msg.contains("10ms"));
    }

    #[test]
    fn test_budget_propagation_event_serde_roundtrip() {
        let event = BudgetPropagationEvent {
            parent_trace_id: "parent-123".to_owned(),
            child_trace_id: Some("child-456".to_owned()),
            boundary_kind: BudgetBoundaryKind::ParentToChildSession,
            parent_before_ms: 10_000,
            derived_ms: 8_000,
            parent_after_ms: 2_000,
            strategy_used: "standard".to_owned(),
            success: true,
            error: None,
            sequence: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        let round: BudgetPropagationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, round);
    }

    #[test]
    fn test_cleanup_budget_policy_serde_roundtrip() {
        let policy = CleanupBudgetPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let round: CleanupBudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, round);
    }

    #[test]
    fn test_propagation_policy_serde_roundtrip() {
        let policy = BudgetPropagationPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let round: BudgetPropagationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, round);
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let mut validator = BudgetPropagationValidator::with_defaults();
        let _ = validator.derive_child_budget(
            "trace-parent",
            "trace-child",
            10_000,
            BudgetBoundaryKind::ParentToChildExtension,
        );
        let report = validator.build_report();
        let json = serde_json::to_string(&report).unwrap();
        let round: BudgetPropagationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn test_parent_reserve_enforcement() {
        let policy = BudgetPropagationPolicy {
            min_parent_reserve_ms: 5000, // 5s reserve
            ..Default::default()
        };
        let mut validator = BudgetPropagationValidator::new(policy);

        let result = validator
            .derive_child_budget(
                "trace-parent",
                "trace-child",
                6000,
                BudgetBoundaryKind::ParentToChildExtension,
            )
            .unwrap();

        // Should have been capped to maintain reserve
        assert!(result.parent_remaining_after_ms >= 5000 || !result.carved_from_parent);
    }

    #[test]
    fn test_delegate_gets_less_than_extension() {
        let policy = BudgetPropagationPolicy::default();
        let ext_rule = policy
            .rule_for(BudgetBoundaryKind::ParentToChildExtension)
            .unwrap();
        let del_rule = policy
            .rule_for(BudgetBoundaryKind::ParentToChildDelegate)
            .unwrap();

        let parent = 10_000;
        let ext_budget = ext_rule.derivation.derive(parent);
        let del_budget = del_rule.derivation.derive(parent);
        assert!(
            del_budget <= ext_budget,
            "delegate {} > extension {}",
            del_budget,
            ext_budget
        );
    }

    #[test]
    fn test_saturating_arithmetic_overflow_safety() {
        let strat = BudgetDerivationStrategy::FractionOfRemaining {
            fraction_millionths: u64::MAX,
        };
        // Should not panic due to overflow
        let derived = strat.derive(u64::MAX);
        // Verify the result is finite (no panic from saturating arithmetic).
        let _ = derived;
    }

    #[test]
    fn test_cleanup_not_carved_from_parent() {
        let policy = CleanupBudgetPolicy {
            drain_strategy: BudgetDerivationStrategy::FixedAmount { amount_ms: 100 },
            finalize_budget_ms: 50,
            carved_from_parent: false,
        };
        let alloc = policy.compute_allocation(1000);
        assert_eq!(alloc.drain_budget_ms, 100);
        assert_eq!(alloc.finalize_budget_ms, 50);
        assert_eq!(alloc.parent_remaining_after_ms, 1000); // not carved
    }
}
