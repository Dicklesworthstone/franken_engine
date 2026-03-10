//! Bounded contextual policy selector for optimization strategy choice.
//!
//! Implements [RGC-608A]: a replayable, overrideable selector that chooses
//! among bounded optimization strategies (tiering, cache, GC, specialization)
//! based on workload features and policy constraints.
//!
//! # Design
//!
//! - `WorkloadContext` captures the feature vector of the current workload.
//! - `OptimizationStrategy` enumerates bounded strategies with known cost/regret.
//! - `PolicyConstraint` specifies what the selector may and may not choose.
//! - `SelectionDecision` records the selected strategy with justification.
//! - `ContextualSelector` evaluates strategies against context and constraints.
//! - All decisions are deterministic and auditable via content hashing.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-608A]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.contextual-policy-selector.v1";

/// Component name.
pub const COMPONENT: &str = "contextual_policy_selector";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.8.1";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-608A";

/// Fixed-point unit.
#[allow(dead_code)]
const MILLION: u64 = 1_000_000;

/// Maximum number of strategies a selector can evaluate.
pub const MAX_STRATEGIES: usize = 32;

/// Default exploration budget (millionths). 5% = 50_000.
pub const DEFAULT_EXPLORATION_BUDGET: u64 = 50_000;

/// Maximum regret budget (millionths). 10% = 100_000.
pub const MAX_REGRET_BUDGET: u64 = 100_000;

// ---------------------------------------------------------------------------
// FeatureKey
// ---------------------------------------------------------------------------

/// Standard workload feature keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKey {
    /// Request rate (invocations per second, millionths).
    RequestRate,
    /// Average payload size (bytes, millionths).
    PayloadSize,
    /// Concurrency level (active workers, millionths).
    ConcurrencyLevel,
    /// Memory pressure (utilization fraction, millionths).
    MemoryPressure,
    /// Cache hit ratio (millionths).
    CacheHitRatio,
    /// GC pause frequency (pauses per second, millionths).
    GcPauseFrequency,
    /// Hot function count (millionths).
    HotFunctionCount,
    /// Module count (millionths).
    ModuleCount,
}

impl FeatureKey {
    pub const ALL: &[Self] = &[
        Self::RequestRate,
        Self::PayloadSize,
        Self::ConcurrencyLevel,
        Self::MemoryPressure,
        Self::CacheHitRatio,
        Self::GcPauseFrequency,
        Self::HotFunctionCount,
        Self::ModuleCount,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestRate => "request_rate",
            Self::PayloadSize => "payload_size",
            Self::ConcurrencyLevel => "concurrency_level",
            Self::MemoryPressure => "memory_pressure",
            Self::CacheHitRatio => "cache_hit_ratio",
            Self::GcPauseFrequency => "gc_pause_frequency",
            Self::HotFunctionCount => "hot_function_count",
            Self::ModuleCount => "module_count",
        }
    }
}

impl fmt::Display for FeatureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// StrategyKind
// ---------------------------------------------------------------------------

/// Kind of optimization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyKind {
    /// Tiering: interpreter → baseline → optimized.
    Tiering,
    /// Cache policy: LRU, LFU, S3-FIFO, etc.
    CachePolicy,
    /// GC strategy: concurrent, stop-world, generational, etc.
    GcStrategy,
    /// Specialization: monomorphic, polymorphic, megamorphic.
    Specialization,
    /// Module loading: eager, lazy, on-demand.
    ModuleLoading,
    /// Default: no optimization, baseline behavior.
    Default,
}

impl StrategyKind {
    pub const ALL: &[Self] = &[
        Self::Tiering,
        Self::CachePolicy,
        Self::GcStrategy,
        Self::Specialization,
        Self::ModuleLoading,
        Self::Default,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tiering => "tiering",
            Self::CachePolicy => "cache_policy",
            Self::GcStrategy => "gc_strategy",
            Self::Specialization => "specialization",
            Self::ModuleLoading => "module_loading",
            Self::Default => "default",
        }
    }
}

impl fmt::Display for StrategyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadContext
// ---------------------------------------------------------------------------

/// Feature vector of the current workload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadContext {
    /// Feature key → observed value (millionths).
    pub features: BTreeMap<FeatureKey, u64>,
    /// Optional label for debugging.
    pub label: Option<String>,
}

impl WorkloadContext {
    /// Create a new context with the given features.
    pub fn new(features: BTreeMap<FeatureKey, u64>) -> Self {
        Self {
            features,
            label: None,
        }
    }

    /// Create with a label.
    pub fn with_label(features: BTreeMap<FeatureKey, u64>, label: impl Into<String>) -> Self {
        Self {
            features,
            label: Some(label.into()),
        }
    }

    /// Get a feature value.
    pub fn get(&self, key: FeatureKey) -> Option<u64> {
        self.features.get(&key).copied()
    }

    /// Number of features present.
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }
}

// ---------------------------------------------------------------------------
// OptimizationStrategy
// ---------------------------------------------------------------------------

/// A concrete optimization strategy with cost and expected reward.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OptimizationStrategy {
    /// Unique strategy identifier.
    pub strategy_id: String,
    /// Kind of strategy.
    pub kind: StrategyKind,
    /// Human-readable name.
    pub name: String,
    /// Expected reward (millionths): higher is better.
    pub expected_reward_millionths: u64,
    /// Cost budget (millionths): overhead of applying this strategy.
    pub cost_millionths: u64,
    /// Worst-case regret (millionths): max loss if this strategy is wrong.
    pub worst_case_regret_millionths: u64,
    /// Required features: the context must have these features.
    pub required_features: BTreeSet<FeatureKey>,
}

impl OptimizationStrategy {
    /// Net expected value: reward - cost.
    pub fn net_value(&self) -> u64 {
        self.expected_reward_millionths
            .saturating_sub(self.cost_millionths)
    }

    /// Whether this strategy's regret is within the given budget.
    pub fn within_regret_budget(&self, budget: u64) -> bool {
        self.worst_case_regret_millionths <= budget
    }

    /// Whether the context has all required features.
    pub fn context_satisfies(&self, ctx: &WorkloadContext) -> bool {
        self.required_features
            .iter()
            .all(|f| ctx.features.contains_key(f))
    }
}

// ---------------------------------------------------------------------------
// PolicyConstraint
// ---------------------------------------------------------------------------

/// Constraint on what the selector may choose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyConstraint {
    /// Only these strategy kinds are allowed.
    AllowedKinds { kinds: BTreeSet<StrategyKind> },
    /// These specific strategy IDs are forbidden.
    ForbiddenStrategies { strategy_ids: BTreeSet<String> },
    /// Maximum cost budget (millionths).
    MaxCost { limit_millionths: u64 },
    /// Maximum regret budget (millionths).
    MaxRegret { limit_millionths: u64 },
    /// Require a specific minimum reward (millionths).
    MinReward { threshold_millionths: u64 },
    /// Operator override: force a specific strategy.
    ForceStrategy { strategy_id: String },
}

impl PolicyConstraint {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::AllowedKinds { .. } => "allowed_kinds",
            Self::ForbiddenStrategies { .. } => "forbidden_strategies",
            Self::MaxCost { .. } => "max_cost",
            Self::MaxRegret { .. } => "max_regret",
            Self::MinReward { .. } => "min_reward",
            Self::ForceStrategy { .. } => "force_strategy",
        }
    }
}

impl fmt::Display for PolicyConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowedKinds { kinds } => write!(f, "allowed kinds: {:?}", kinds),
            Self::ForbiddenStrategies { strategy_ids } => {
                write!(f, "forbidden: {:?}", strategy_ids)
            }
            Self::MaxCost { limit_millionths } => write!(f, "max cost: {}", limit_millionths),
            Self::MaxRegret { limit_millionths } => write!(f, "max regret: {}", limit_millionths),
            Self::MinReward {
                threshold_millionths,
            } => {
                write!(f, "min reward: {}", threshold_millionths)
            }
            Self::ForceStrategy { strategy_id } => write!(f, "force: {}", strategy_id),
        }
    }
}

// ---------------------------------------------------------------------------
// SelectionReason
// ---------------------------------------------------------------------------

/// Reason for selecting or rejecting a strategy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    /// Highest net value among feasible strategies.
    HighestNetValue { net_value_millionths: u64 },
    /// Forced by operator override.
    OperatorOverride { strategy_id: String },
    /// Fallback to default (no feasible strategies).
    FallbackToDefault,
    /// Rejected: kind not allowed.
    KindNotAllowed,
    /// Rejected: explicitly forbidden.
    Forbidden,
    /// Rejected: cost exceeds limit.
    CostExceeded { cost: u64, limit: u64 },
    /// Rejected: regret exceeds budget.
    RegretExceeded { regret: u64, budget: u64 },
    /// Rejected: reward below threshold.
    RewardBelowThreshold { reward: u64, threshold: u64 },
    /// Rejected: missing required features.
    MissingFeatures { missing: BTreeSet<FeatureKey> },
}

impl SelectionReason {
    pub fn is_acceptance(&self) -> bool {
        matches!(
            self,
            Self::HighestNetValue { .. } | Self::OperatorOverride { .. } | Self::FallbackToDefault
        )
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::HighestNetValue { .. } => "highest_net_value",
            Self::OperatorOverride { .. } => "operator_override",
            Self::FallbackToDefault => "fallback_default",
            Self::KindNotAllowed => "kind_not_allowed",
            Self::Forbidden => "forbidden",
            Self::CostExceeded { .. } => "cost_exceeded",
            Self::RegretExceeded { .. } => "regret_exceeded",
            Self::RewardBelowThreshold { .. } => "reward_below_threshold",
            Self::MissingFeatures { .. } => "missing_features",
        }
    }
}

// ---------------------------------------------------------------------------
// SelectionDecision
// ---------------------------------------------------------------------------

/// The outcome of running the policy selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionDecision {
    /// Schema version.
    pub schema_version: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Selected strategy ID (if any).
    pub selected_strategy_id: Option<String>,
    /// Selected strategy kind (if any).
    pub selected_kind: Option<StrategyKind>,
    /// Reason for selection.
    pub reason: SelectionReason,
    /// All candidate evaluations: strategy_id → reason.
    pub candidate_evaluations: Vec<(String, SelectionReason)>,
    /// Number of feasible candidates.
    pub feasible_count: usize,
    /// Number of infeasible candidates.
    pub infeasible_count: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SelectionDecision {
    /// Whether a strategy was selected.
    pub fn has_selection(&self) -> bool {
        self.selected_strategy_id.is_some()
    }

    /// Whether the selection was a fallback.
    pub fn is_fallback(&self) -> bool {
        matches!(self.reason, SelectionReason::FallbackToDefault)
    }

    /// Whether the selection was forced by operator.
    pub fn is_override(&self) -> bool {
        matches!(self.reason, SelectionReason::OperatorOverride { .. })
    }
}

// ---------------------------------------------------------------------------
// ContextualSelector
// ---------------------------------------------------------------------------

/// The policy selector: evaluates strategies against context and constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextualSelector {
    /// Available strategies.
    pub strategies: Vec<OptimizationStrategy>,
    /// Policy constraints.
    pub constraints: Vec<PolicyConstraint>,
    /// Exploration budget (millionths).
    pub exploration_budget: u64,
}

impl ContextualSelector {
    /// Create a new selector.
    pub fn new(
        strategies: Vec<OptimizationStrategy>,
        constraints: Vec<PolicyConstraint>,
        exploration_budget: u64,
    ) -> Self {
        Self {
            strategies,
            constraints,
            exploration_budget,
        }
    }

    /// Create with default exploration budget.
    pub fn with_defaults(
        strategies: Vec<OptimizationStrategy>,
        constraints: Vec<PolicyConstraint>,
    ) -> Self {
        Self::new(strategies, constraints, DEFAULT_EXPLORATION_BUDGET)
    }

    /// Select the best strategy for the given context.
    pub fn select(&self, ctx: &WorkloadContext, epoch: SecurityEpoch) -> SelectionDecision {
        // Check for operator override first
        for c in &self.constraints {
            if let PolicyConstraint::ForceStrategy { strategy_id } = c {
                let kind = self
                    .strategies
                    .iter()
                    .find(|s| s.strategy_id == *strategy_id)
                    .map(|s| s.kind);
                return self.build_decision(
                    epoch,
                    Some(strategy_id.clone()),
                    kind,
                    SelectionReason::OperatorOverride {
                        strategy_id: strategy_id.clone(),
                    },
                    Vec::new(),
                    0,
                    0,
                );
            }
        }

        // Evaluate each strategy
        let mut evaluations = Vec::new();
        let mut feasible: Vec<(&OptimizationStrategy, u64)> = Vec::new();

        for strategy in &self.strategies {
            match self.evaluate_strategy(strategy, ctx) {
                Ok(()) => {
                    let nv = strategy.net_value();
                    evaluations.push((
                        strategy.strategy_id.clone(),
                        SelectionReason::HighestNetValue {
                            net_value_millionths: nv,
                        },
                    ));
                    feasible.push((strategy, nv));
                }
                Err(reason) => {
                    evaluations.push((strategy.strategy_id.clone(), reason));
                }
            }
        }

        let infeasible_count = evaluations
            .iter()
            .filter(|(_, r)| !r.is_acceptance())
            .count();
        let feasible_count = feasible.len();

        if feasible.is_empty() {
            return self.build_decision(
                epoch,
                None,
                None,
                SelectionReason::FallbackToDefault,
                evaluations,
                0,
                infeasible_count,
            );
        }

        // Sort by net value descending, pick the best
        feasible.sort_by_key(|b| std::cmp::Reverse(b.1));
        let best = feasible[0].0;

        self.build_decision(
            epoch,
            Some(best.strategy_id.clone()),
            Some(best.kind),
            SelectionReason::HighestNetValue {
                net_value_millionths: best.net_value(),
            },
            evaluations,
            feasible_count,
            infeasible_count,
        )
    }

    /// Evaluate whether a strategy passes all constraints.
    fn evaluate_strategy(
        &self,
        strategy: &OptimizationStrategy,
        ctx: &WorkloadContext,
    ) -> Result<(), SelectionReason> {
        // Check context requirements
        let missing: BTreeSet<FeatureKey> = strategy
            .required_features
            .iter()
            .filter(|f| !ctx.features.contains_key(f))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(SelectionReason::MissingFeatures { missing });
        }

        // Check constraints
        for c in &self.constraints {
            match c {
                PolicyConstraint::AllowedKinds { kinds } => {
                    if !kinds.contains(&strategy.kind) {
                        return Err(SelectionReason::KindNotAllowed);
                    }
                }
                PolicyConstraint::ForbiddenStrategies { strategy_ids } => {
                    if strategy_ids.contains(&strategy.strategy_id) {
                        return Err(SelectionReason::Forbidden);
                    }
                }
                PolicyConstraint::MaxCost { limit_millionths } => {
                    if strategy.cost_millionths > *limit_millionths {
                        return Err(SelectionReason::CostExceeded {
                            cost: strategy.cost_millionths,
                            limit: *limit_millionths,
                        });
                    }
                }
                PolicyConstraint::MaxRegret { limit_millionths } => {
                    if strategy.worst_case_regret_millionths > *limit_millionths {
                        return Err(SelectionReason::RegretExceeded {
                            regret: strategy.worst_case_regret_millionths,
                            budget: *limit_millionths,
                        });
                    }
                }
                PolicyConstraint::MinReward {
                    threshold_millionths,
                } => {
                    if strategy.expected_reward_millionths < *threshold_millionths {
                        return Err(SelectionReason::RewardBelowThreshold {
                            reward: strategy.expected_reward_millionths,
                            threshold: *threshold_millionths,
                        });
                    }
                }
                PolicyConstraint::ForceStrategy { .. } => {
                    // Handled separately above
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_decision(
        &self,
        epoch: SecurityEpoch,
        selected_id: Option<String>,
        selected_kind: Option<StrategyKind>,
        reason: SelectionReason,
        evaluations: Vec<(String, SelectionReason)>,
        feasible_count: usize,
        infeasible_count: usize,
    ) -> SelectionDecision {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        if let Some(ref id) = selected_id {
            h.update(id.as_bytes());
        }
        h.update(reason.tag().as_bytes());
        h.update((evaluations.len() as u64).to_le_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        SelectionDecision {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            selected_strategy_id: selected_id,
            selected_kind,
            reason,
            candidate_evaluations: evaluations,
            feasible_count,
            infeasible_count,
            content_hash,
        }
    }

    /// Number of registered strategies.
    pub fn strategy_count(&self) -> usize {
        self.strategies.len()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(600)
    }

    fn basic_context() -> WorkloadContext {
        let mut features = BTreeMap::new();
        features.insert(FeatureKey::RequestRate, 500_000);
        features.insert(FeatureKey::MemoryPressure, 300_000);
        features.insert(FeatureKey::CacheHitRatio, 800_000);
        WorkloadContext::new(features)
    }

    fn tiering_strategy() -> OptimizationStrategy {
        OptimizationStrategy {
            strategy_id: "tier-aggressive".into(),
            kind: StrategyKind::Tiering,
            name: "Aggressive tiering".into(),
            expected_reward_millionths: 200_000,
            cost_millionths: 50_000,
            worst_case_regret_millionths: 80_000,
            required_features: BTreeSet::from([FeatureKey::RequestRate]),
        }
    }

    fn cache_strategy() -> OptimizationStrategy {
        OptimizationStrategy {
            strategy_id: "cache-s3fifo".into(),
            kind: StrategyKind::CachePolicy,
            name: "S3-FIFO cache".into(),
            expected_reward_millionths: 150_000,
            cost_millionths: 20_000,
            worst_case_regret_millionths: 40_000,
            required_features: BTreeSet::from([FeatureKey::CacheHitRatio]),
        }
    }

    fn expensive_strategy() -> OptimizationStrategy {
        OptimizationStrategy {
            strategy_id: "spec-mega".into(),
            kind: StrategyKind::Specialization,
            name: "Megamorphic specialization".into(),
            expected_reward_millionths: 300_000,
            cost_millionths: 250_000,
            worst_case_regret_millionths: 200_000,
            required_features: BTreeSet::from([FeatureKey::HotFunctionCount]),
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "contextual_policy_selector");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn budget_constraints() {
        assert!(DEFAULT_EXPLORATION_BUDGET > 0);
        assert!(DEFAULT_EXPLORATION_BUDGET < MILLION);
        assert!(MAX_REGRET_BUDGET > 0);
    }

    // --- FeatureKey ---

    #[test]
    fn feature_key_all_length() {
        assert_eq!(FeatureKey::ALL.len(), 8);
    }

    #[test]
    fn feature_key_names_unique() {
        let names: BTreeSet<&str> = FeatureKey::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), FeatureKey::ALL.len());
    }

    #[test]
    fn feature_key_display() {
        for k in FeatureKey::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn feature_key_serde() {
        for k in FeatureKey::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: FeatureKey = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- StrategyKind ---

    #[test]
    fn strategy_kind_all_length() {
        assert_eq!(StrategyKind::ALL.len(), 6);
    }

    #[test]
    fn strategy_kind_names_unique() {
        let names: BTreeSet<&str> = StrategyKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), StrategyKind::ALL.len());
    }

    #[test]
    fn strategy_kind_display() {
        for k in StrategyKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn strategy_kind_serde() {
        for k in StrategyKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: StrategyKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- WorkloadContext ---

    #[test]
    fn context_creation() {
        let ctx = basic_context();
        assert_eq!(ctx.feature_count(), 3);
        assert_eq!(ctx.get(FeatureKey::RequestRate), Some(500_000));
        assert!(ctx.get(FeatureKey::HotFunctionCount).is_none());
    }

    #[test]
    fn context_with_label() {
        let ctx = WorkloadContext::with_label(BTreeMap::new(), "test");
        assert_eq!(ctx.label.as_deref(), Some("test"));
    }

    #[test]
    fn context_serde() {
        let ctx = basic_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let back: WorkloadContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }

    // --- OptimizationStrategy ---

    #[test]
    fn strategy_net_value() {
        let s = tiering_strategy();
        assert_eq!(s.net_value(), 150_000); // 200k - 50k
    }

    #[test]
    fn strategy_regret_budget() {
        let s = tiering_strategy();
        assert!(s.within_regret_budget(100_000));
        assert!(!s.within_regret_budget(50_000));
    }

    #[test]
    fn strategy_context_satisfies() {
        let s = tiering_strategy();
        let ctx = basic_context();
        assert!(s.context_satisfies(&ctx));
    }

    #[test]
    fn strategy_context_missing_feature() {
        let s = expensive_strategy();
        let ctx = basic_context();
        assert!(!s.context_satisfies(&ctx));
    }

    #[test]
    fn strategy_serde() {
        let s = tiering_strategy();
        let json = serde_json::to_string(&s).unwrap();
        let back: OptimizationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- PolicyConstraint ---

    #[test]
    fn constraint_tags_unique() {
        let constraints = vec![
            PolicyConstraint::AllowedKinds {
                kinds: BTreeSet::new(),
            },
            PolicyConstraint::ForbiddenStrategies {
                strategy_ids: BTreeSet::new(),
            },
            PolicyConstraint::MaxCost {
                limit_millionths: 100_000,
            },
            PolicyConstraint::MaxRegret {
                limit_millionths: 100_000,
            },
            PolicyConstraint::MinReward {
                threshold_millionths: 50_000,
            },
            PolicyConstraint::ForceStrategy {
                strategy_id: "x".into(),
            },
        ];
        let tags: BTreeSet<&str> = constraints.iter().map(|c| c.tag()).collect();
        assert_eq!(tags.len(), 6);
    }

    #[test]
    fn constraint_display() {
        let c = PolicyConstraint::MaxCost {
            limit_millionths: 100_000,
        };
        assert!(c.to_string().contains("100000"));
    }

    #[test]
    fn constraint_serde() {
        let c = PolicyConstraint::AllowedKinds {
            kinds: BTreeSet::from([StrategyKind::Tiering, StrategyKind::CachePolicy]),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: PolicyConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- SelectionReason ---

    #[test]
    fn selection_reason_acceptance() {
        assert!(
            SelectionReason::HighestNetValue {
                net_value_millionths: 100
            }
            .is_acceptance()
        );
        assert!(
            SelectionReason::OperatorOverride {
                strategy_id: "x".into()
            }
            .is_acceptance()
        );
        assert!(SelectionReason::FallbackToDefault.is_acceptance());
        assert!(!SelectionReason::KindNotAllowed.is_acceptance());
        assert!(!SelectionReason::Forbidden.is_acceptance());
    }

    #[test]
    fn selection_reason_tags_unique() {
        let reasons = vec![
            SelectionReason::HighestNetValue {
                net_value_millionths: 0,
            },
            SelectionReason::OperatorOverride {
                strategy_id: "x".into(),
            },
            SelectionReason::FallbackToDefault,
            SelectionReason::KindNotAllowed,
            SelectionReason::Forbidden,
            SelectionReason::CostExceeded { cost: 0, limit: 0 },
            SelectionReason::RegretExceeded {
                regret: 0,
                budget: 0,
            },
            SelectionReason::RewardBelowThreshold {
                reward: 0,
                threshold: 0,
            },
            SelectionReason::MissingFeatures {
                missing: BTreeSet::new(),
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 9);
    }

    // --- ContextualSelector ---

    #[test]
    fn selector_empty_strategies_fallback() {
        let sel = ContextualSelector::with_defaults(Vec::new(), Vec::new());
        let d = sel.select(&basic_context(), epoch());
        assert!(d.is_fallback());
        assert!(!d.has_selection());
    }

    #[test]
    fn selector_picks_highest_net_value() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            Vec::new(),
        );
        let ctx = basic_context();
        let d = sel.select(&ctx, epoch());
        assert!(d.has_selection());
        assert_eq!(d.selected_strategy_id.as_deref(), Some("tier-aggressive"));
        assert_eq!(d.selected_kind, Some(StrategyKind::Tiering));
    }

    #[test]
    fn selector_respects_cost_constraint() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            vec![PolicyConstraint::MaxCost {
                limit_millionths: 30_000,
            }],
        );
        let d = sel.select(&basic_context(), epoch());
        // tiering costs 50k > 30k, so only cache (20k) is feasible
        assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-s3fifo"));
    }

    #[test]
    fn selector_respects_regret_constraint() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            vec![PolicyConstraint::MaxRegret {
                limit_millionths: 50_000,
            }],
        );
        let d = sel.select(&basic_context(), epoch());
        // tiering regret 80k > 50k, so only cache (40k) is feasible
        assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-s3fifo"));
    }

    #[test]
    fn selector_respects_kind_constraint() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            vec![PolicyConstraint::AllowedKinds {
                kinds: BTreeSet::from([StrategyKind::CachePolicy]),
            }],
        );
        let d = sel.select(&basic_context(), epoch());
        assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-s3fifo"));
    }

    #[test]
    fn selector_respects_forbidden_constraint() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            vec![PolicyConstraint::ForbiddenStrategies {
                strategy_ids: BTreeSet::from(["tier-aggressive".to_string()]),
            }],
        );
        let d = sel.select(&basic_context(), epoch());
        assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-s3fifo"));
    }

    #[test]
    fn selector_operator_override() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            vec![PolicyConstraint::ForceStrategy {
                strategy_id: "cache-s3fifo".into(),
            }],
        );
        let d = sel.select(&basic_context(), epoch());
        assert!(d.is_override());
        assert_eq!(d.selected_strategy_id.as_deref(), Some("cache-s3fifo"));
    }

    #[test]
    fn selector_missing_features_fallback() {
        // expensive_strategy requires HotFunctionCount, which basic_context doesn't have
        let sel = ContextualSelector::with_defaults(vec![expensive_strategy()], Vec::new());
        let d = sel.select(&basic_context(), epoch());
        assert!(d.is_fallback());
    }

    #[test]
    fn selector_decision_hash_deterministic() {
        let sel = ContextualSelector::with_defaults(vec![tiering_strategy()], Vec::new());
        let ctx = basic_context();
        let d1 = sel.select(&ctx, epoch());
        let d2 = sel.select(&ctx, epoch());
        assert_eq!(d1.content_hash, d2.content_hash);
    }

    #[test]
    fn selector_decision_serde() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            Vec::new(),
        );
        let d = sel.select(&basic_context(), epoch());
        let json = serde_json::to_string(&d).unwrap();
        let back: SelectionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn selector_serde() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy()],
            vec![PolicyConstraint::MaxCost {
                limit_millionths: 100_000,
            }],
        );
        let json = serde_json::to_string(&sel).unwrap();
        let back: ContextualSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(sel, back);
    }

    #[test]
    fn selector_strategy_count() {
        let sel = ContextualSelector::with_defaults(
            vec![tiering_strategy(), cache_strategy()],
            Vec::new(),
        );
        assert_eq!(sel.strategy_count(), 2);
    }
}
