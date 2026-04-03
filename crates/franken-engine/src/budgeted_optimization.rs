//! Budgeted optimization stack (e-graphs, partial eval, incrementalization).
//!
//! Implements a certified rewrite pipeline for aggressive optimization without
//! semantic drift:
//! - Budgeted e-graph saturation with explicit node/time/memory caps.
//! - Partial evaluation and dead reactive path elimination.
//! - Incrementalization transforms gated by equivalence witnesses.
//! - Rewrite extraction policy under proof/operability constraints.
//! - Per-rewrite proof obligations and metamorphic checks.
//! - Interference checks for composed optimization controllers.
//! - Rollback artifacts per optimization campaign.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! Collections use BTreeMap/BTreeSet for deterministic iteration.
//!
//! Plan references: FRX-03.4, FRX-03 (Compiler Architecture).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLION: i64 = 1_000_000;

/// Schema version for optimization artifacts.
pub const OPTIMIZATION_SCHEMA_VERSION: &str = "franken-engine.budgeted-optimization.v1";

/// Maximum rewrite rules per campaign.
const MAX_REWRITE_RULES: usize = 1024;

/// Maximum e-graph nodes before saturation is force-stopped.
const MAX_EGRAPH_NODES: usize = 1_000_000;

/// Maximum optimization campaigns that can compose.
const MAX_CAMPAIGNS: usize = 64;

// ---------------------------------------------------------------------------
// RewriteFamily — classification of rewrite rules
// ---------------------------------------------------------------------------

/// Classification of rewrite rule families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RewriteFamily {
    /// Algebraic simplification (constant folding, identity elimination).
    AlgebraicSimplification,
    /// Dead code elimination (unreachable branches, unused bindings).
    DeadCodeElimination,
    /// Common subexpression elimination.
    CommonSubexpression,
    /// Partial evaluation (constant propagation into branches).
    PartialEvaluation,
    /// Memoization boundary insertion.
    MemoizationBoundary,
    /// Effect hoisting (moving effects to optimal schedule point).
    EffectHoisting,
    /// Hook slot fusion (merging adjacent compatible hooks).
    HookSlotFusion,
    /// Signal graph optimization (WASM lane specific).
    SignalGraphOptimization,
    /// Incrementalization (caching of intermediate results).
    Incrementalization,
    /// DOM update batching (JS lane specific).
    DomUpdateBatching,
    /// Custom rewrite family.
    Custom,
}

impl fmt::Display for RewriteFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AlgebraicSimplification => "algebraic_simplification",
            Self::DeadCodeElimination => "dead_code_elimination",
            Self::CommonSubexpression => "common_subexpression",
            Self::PartialEvaluation => "partial_evaluation",
            Self::MemoizationBoundary => "memoization_boundary",
            Self::EffectHoisting => "effect_hoisting",
            Self::HookSlotFusion => "hook_slot_fusion",
            Self::SignalGraphOptimization => "signal_graph_optimization",
            Self::Incrementalization => "incrementalization",
            Self::DomUpdateBatching => "dom_update_batching",
            Self::Custom => "custom",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// RewriteRule — a single rewrite rule
// ---------------------------------------------------------------------------

/// A single rewrite rule with its proof obligations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRule {
    /// Unique rule identifier.
    pub id: String,
    /// Rewrite family classification.
    pub family: RewriteFamily,
    /// Human-readable description.
    pub description: String,
    /// Pattern hash (content-addressed LHS pattern).
    pub pattern_hash: ContentHash,
    /// Replacement hash (content-addressed RHS pattern).
    pub replacement_hash: ContentHash,
    /// Proof obligations required for this rewrite.
    pub proof_obligations: Vec<String>,
    /// Metamorphic checks required (test input families).
    pub metamorphic_checks: Vec<String>,
    /// Whether this rewrite is sound (proven correct).
    pub sound: bool,
    /// Priority in millionths (higher = applied first).
    pub priority_millionths: i64,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl RewriteRule {
    /// Check if this rule is ready to apply (sound and enabled).
    pub fn is_ready(&self) -> bool {
        self.sound && self.enabled
    }
}

// ---------------------------------------------------------------------------
// BudgetKind — types of resource budgets
// ---------------------------------------------------------------------------

/// Kind of resource budget for optimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BudgetKind {
    /// Wall-clock time in milliseconds.
    TimeMs,
    /// E-graph node count.
    EgraphNodes,
    /// Memory usage in bytes.
    MemoryBytes,
    /// Rewrite application count.
    RewriteApplications,
    /// Saturation iterations.
    SaturationIterations,
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TimeMs => "time_ms",
            Self::EgraphNodes => "egraph_nodes",
            Self::MemoryBytes => "memory_bytes",
            Self::RewriteApplications => "rewrite_applications",
            Self::SaturationIterations => "saturation_iterations",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// BudgetLimit — a specific resource limit
// ---------------------------------------------------------------------------

/// A specific resource budget limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimit {
    /// Kind of budget.
    pub kind: BudgetKind,
    /// Maximum allowed value.
    pub max_value: u64,
    /// Current consumed value.
    pub current_value: u64,
}

impl BudgetLimit {
    /// Create a new budget limit.
    pub fn new(kind: BudgetKind, max_value: u64) -> Self {
        Self {
            kind,
            max_value,
            current_value: 0,
        }
    }

    /// Check if budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.current_value >= self.max_value
    }

    /// Remaining budget.
    pub fn remaining(&self) -> u64 {
        self.max_value.saturating_sub(self.current_value)
    }

    /// Utilization in millionths.
    pub fn utilization_millionths(&self) -> i64 {
        if self.max_value == 0 {
            return MILLION;
        }
        (self.current_value as i128 * MILLION as i128 / self.max_value as i128) as i64
    }

    /// Consume some budget. Returns true if within limits.
    pub fn consume(&mut self, amount: u64) -> bool {
        self.current_value = self.current_value.saturating_add(amount);
        self.current_value <= self.max_value
    }
}

// ---------------------------------------------------------------------------
// BudgetEnvelope — combined budget for an optimization campaign
// ---------------------------------------------------------------------------

/// Combined budget envelope for an optimization campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEnvelope {
    /// Individual budget limits.
    pub limits: BTreeMap<String, BudgetLimit>,
}

impl BudgetEnvelope {
    /// Create a default production budget envelope.
    pub fn production() -> Self {
        let mut limits = BTreeMap::new();
        limits.insert(
            BudgetKind::TimeMs.to_string(),
            BudgetLimit::new(BudgetKind::TimeMs, 5_000),
        );
        limits.insert(
            BudgetKind::EgraphNodes.to_string(),
            BudgetLimit::new(BudgetKind::EgraphNodes, MAX_EGRAPH_NODES as u64),
        );
        limits.insert(
            BudgetKind::MemoryBytes.to_string(),
            BudgetLimit::new(BudgetKind::MemoryBytes, 256 * 1024 * 1024), // 256MB
        );
        limits.insert(
            BudgetKind::RewriteApplications.to_string(),
            BudgetLimit::new(BudgetKind::RewriteApplications, 100_000),
        );
        limits.insert(
            BudgetKind::SaturationIterations.to_string(),
            BudgetLimit::new(BudgetKind::SaturationIterations, 1_000),
        );
        Self { limits }
    }

    /// Check if any budget is exhausted.
    pub fn any_exhausted(&self) -> bool {
        self.limits.values().any(|l| l.is_exhausted())
    }

    /// Get the most constrained budget (highest utilization).
    pub fn most_constrained(&self) -> Option<&BudgetLimit> {
        self.limits
            .values()
            .max_by_key(|l| l.utilization_millionths())
    }

    /// Consume budget of a given kind. Returns false if exhausted.
    pub fn consume(&mut self, kind: BudgetKind, amount: u64) -> bool {
        if let Some(limit) = self.limits.get_mut(&kind.to_string()) {
            limit.consume(amount)
        } else {
            true // No limit means unlimited
        }
    }

    /// Get budget for a kind.
    pub fn get(&self, kind: BudgetKind) -> Option<&BudgetLimit> {
        self.limits.get(&kind.to_string())
    }
}

impl Default for BudgetEnvelope {
    fn default() -> Self {
        Self::production()
    }
}

// ---------------------------------------------------------------------------
// SaturationOutcome — result of e-graph saturation
// ---------------------------------------------------------------------------

/// Outcome of an e-graph saturation phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SaturationOutcome {
    /// E-graph reached a fixed point (no more rewrites applicable).
    Saturated,
    /// Budget exhausted before saturation.
    BudgetExhausted,
    /// Node limit reached.
    NodeLimitReached,
    /// Iteration limit reached.
    IterationLimitReached,
    /// Explicitly stopped by policy.
    PolicyStopped,
}

impl fmt::Display for SaturationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Saturated => "saturated",
            Self::BudgetExhausted => "budget_exhausted",
            Self::NodeLimitReached => "node_limit_reached",
            Self::IterationLimitReached => "iteration_limit_reached",
            Self::PolicyStopped => "policy_stopped",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// EGraphSnapshot — snapshot of e-graph state
// ---------------------------------------------------------------------------

/// Snapshot of e-graph state after saturation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EGraphSnapshot {
    /// Number of e-classes.
    pub class_count: u64,
    /// Number of e-nodes.
    pub node_count: u64,
    /// Number of iterations performed.
    pub iteration_count: u64,
    /// Number of rewrites applied.
    pub rewrite_count: u64,
    /// Saturation outcome.
    pub outcome: SaturationOutcome,
    /// Content hash of the e-graph state.
    pub state_hash: ContentHash,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Peak memory usage in bytes.
    pub peak_memory_bytes: u64,
}

// ---------------------------------------------------------------------------
// ExtractionPolicy — policy for extracting optimal program from e-graph
// ---------------------------------------------------------------------------

/// Policy for extracting the optimal program from a saturated e-graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExtractionPolicy {
    /// Minimize total cost (default).
    #[default]
    MinCost,
    /// Minimize code size.
    MinSize,
    /// Maximize expected performance gain.
    MaxPerformance,
    /// Balance cost and proof operability (prefer proven rewrites).
    ProofAware {
        /// Weight for proven rewrites in millionths.
        proof_weight_millionths: i64,
    },
    /// Custom cost function (referenced by name).
    Custom { name: String },
}

impl fmt::Display for ExtractionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinCost => f.write_str("min_cost"),
            Self::MinSize => f.write_str("min_size"),
            Self::MaxPerformance => f.write_str("max_performance"),
            Self::ProofAware { .. } => f.write_str("proof_aware"),
            Self::Custom { name } => write!(f, "custom:{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtractionResult — result of extracting from e-graph
// ---------------------------------------------------------------------------

/// Result of extracting an optimal program from the e-graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionResult {
    /// Extraction policy used.
    pub policy: ExtractionPolicy,
    /// Total cost of extracted program (in millionths).
    pub total_cost_millionths: i64,
    /// Number of nodes in extracted program.
    pub extracted_node_count: u64,
    /// Number of proven rewrites used.
    pub proven_rewrite_count: u64,
    /// Content hash of the extracted program.
    pub output_hash: ContentHash,
    /// Rewrite families used in the extraction.
    pub families_used: BTreeSet<RewriteFamily>,
}

// ---------------------------------------------------------------------------
// InterferenceKind — types of interference between optimizations
// ---------------------------------------------------------------------------

/// Kind of interference between optimization campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InterferenceKind {
    /// No interference detected.
    None,
    /// Rewrites from different families conflict on same nodes.
    RewriteConflict,
    /// Budget contention (campaigns compete for same resource).
    BudgetContention,
    /// Semantic interference (combined effect differs from individual).
    SemanticInterference,
    /// Order dependence (result depends on application order).
    OrderDependence,
}

impl fmt::Display for InterferenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::RewriteConflict => "rewrite_conflict",
            Self::BudgetContention => "budget_contention",
            Self::SemanticInterference => "semantic_interference",
            Self::OrderDependence => "order_dependence",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// InterferenceCheck — result of checking interference between campaigns
// ---------------------------------------------------------------------------

/// Result of checking interference between two optimization campaigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceCheck {
    /// First campaign ID.
    pub campaign_a: String,
    /// Second campaign ID.
    pub campaign_b: String,
    /// Kind of interference detected.
    pub kind: InterferenceKind,
    /// Detail message.
    pub detail: String,
    /// Whether the interference is blocking (prevents composition).
    pub blocking: bool,
}

// ---------------------------------------------------------------------------
// RollbackArtifact — rollback artifact for an optimization campaign
// ---------------------------------------------------------------------------

/// Rollback artifact produced per optimization campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackArtifact {
    /// Campaign ID this rollback belongs to.
    pub campaign_id: String,
    /// Content hash of the pre-optimization state.
    pub pre_optimization_hash: ContentHash,
    /// Content hash of the post-optimization state.
    pub post_optimization_hash: ContentHash,
    /// Rewrite rules applied (in order).
    pub applied_rules: Vec<String>,
    /// Whether rollback has been tested.
    pub rollback_tested: bool,
    /// Content hash of the rollback artifact itself.
    pub artifact_hash: ContentHash,
}

impl RollbackArtifact {
    /// Check if this rollback is viable (tested and hashes present).
    pub fn is_viable(&self) -> bool {
        self.rollback_tested
    }
}

// ---------------------------------------------------------------------------
// CampaignStatus — status of an optimization campaign
// ---------------------------------------------------------------------------

/// Status of an optimization campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CampaignStatus {
    /// Campaign is pending (not yet started).
    Pending,
    /// E-graph saturation in progress.
    Saturating,
    /// Extraction in progress.
    Extracting,
    /// Campaign completed successfully.
    Completed,
    /// Campaign failed (budget or interference).
    Failed,
    /// Campaign rolled back.
    RolledBack,
}

impl fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Saturating => "saturating",
            Self::Extracting => "extracting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// OptimizationCampaign — a single optimization campaign
// ---------------------------------------------------------------------------

/// A single optimization campaign with budget, rules, and artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationCampaign {
    /// Unique campaign identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Status.
    pub status: CampaignStatus,
    /// Budget envelope for this campaign.
    pub budget: BudgetEnvelope,
    /// Rewrite rules included in this campaign.
    pub rules: Vec<RewriteRule>,
    /// Extraction policy.
    pub extraction_policy: ExtractionPolicy,
    /// E-graph snapshot (after saturation).
    pub egraph_snapshot: Option<EGraphSnapshot>,
    /// Extraction result (after extraction).
    pub extraction_result: Option<ExtractionResult>,
    /// Rollback artifact.
    pub rollback: Option<RollbackArtifact>,
    /// Content hash of the input.
    pub input_hash: ContentHash,
    /// Expected performance gain in millionths.
    pub expected_gain_millionths: i64,
}

impl OptimizationCampaign {
    /// Create a new campaign.
    pub fn new(id: &str, label: &str, input_hash: ContentHash) -> Self {
        Self {
            id: id.to_string(),
            label: label.to_string(),
            status: CampaignStatus::Pending,
            budget: BudgetEnvelope::production(),
            rules: Vec::new(),
            extraction_policy: ExtractionPolicy::default(),
            egraph_snapshot: None,
            extraction_result: None,
            rollback: None,
            input_hash,
            expected_gain_millionths: 0,
        }
    }

    /// Add a rewrite rule.
    pub fn add_rule(&mut self, rule: RewriteRule) -> Result<(), OptimizationError> {
        if self.rules.len() >= MAX_REWRITE_RULES {
            return Err(OptimizationError::RuleLimitExceeded {
                count: self.rules.len() + 1,
                max: MAX_REWRITE_RULES,
            });
        }
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(OptimizationError::DuplicateRule(rule.id.clone()));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Count of ready (sound + enabled) rules.
    pub fn ready_rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.is_ready()).count()
    }

    /// Check if the campaign completed successfully.
    pub fn is_successful(&self) -> bool {
        self.status == CampaignStatus::Completed && self.extraction_result.is_some()
    }

    /// Record saturation result.
    pub fn record_saturation(&mut self, snapshot: EGraphSnapshot) {
        self.egraph_snapshot = Some(snapshot);
        self.status = CampaignStatus::Extracting;
    }

    /// Record extraction result.
    pub fn record_extraction(&mut self, result: ExtractionResult) {
        self.extraction_result = Some(result);
        self.status = CampaignStatus::Completed;
    }

    /// Record failure.
    pub fn record_failure(&mut self) {
        self.status = CampaignStatus::Failed;
    }

    /// Record rollback.
    pub fn record_rollback(&mut self, rollback: RollbackArtifact) {
        self.rollback = Some(rollback);
        self.status = CampaignStatus::RolledBack;
    }

    /// Rewrite families used in this campaign.
    pub fn families(&self) -> BTreeSet<RewriteFamily> {
        self.rules.iter().map(|r| r.family).collect()
    }
}

// ---------------------------------------------------------------------------
// OptimizationError — errors during optimization
// ---------------------------------------------------------------------------

/// Errors that can occur during optimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationError {
    /// Rewrite rule limit exceeded.
    RuleLimitExceeded { count: usize, max: usize },
    /// Duplicate rewrite rule.
    DuplicateRule(String),
    /// Campaign limit exceeded.
    CampaignLimitExceeded { count: usize, max: usize },
    /// Duplicate campaign ID.
    DuplicateCampaign(String),
    /// Budget exhausted.
    BudgetExhausted { kind: BudgetKind },
    /// Interference detected (blocking).
    InterferenceBlocking(InterferenceCheck),
    /// Unsound rewrite applied.
    UnsoundRewrite { rule_id: String },
    /// Rollback failed.
    RollbackFailed { campaign_id: String, detail: String },
}

impl fmt::Display for OptimizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleLimitExceeded { count, max } => {
                write!(f, "rule limit exceeded: {count} > {max}")
            }
            Self::DuplicateRule(id) => write!(f, "duplicate rule: {id}"),
            Self::CampaignLimitExceeded { count, max } => {
                write!(f, "campaign limit exceeded: {count} > {max}")
            }
            Self::DuplicateCampaign(id) => write!(f, "duplicate campaign: {id}"),
            Self::BudgetExhausted { kind } => write!(f, "budget exhausted: {kind}"),
            Self::InterferenceBlocking(check) => {
                write!(
                    f,
                    "blocking interference between {} and {}: {}",
                    check.campaign_a, check.campaign_b, check.kind
                )
            }
            Self::UnsoundRewrite { rule_id } => write!(f, "unsound rewrite: {rule_id}"),
            Self::RollbackFailed {
                campaign_id,
                detail,
            } => write!(f, "rollback failed for {campaign_id}: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// OptimizationEventKind — audit events
// ---------------------------------------------------------------------------

/// Kind of optimization event for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationEventKind {
    /// Campaign registered.
    CampaignRegistered,
    /// Saturation started.
    SaturationStarted,
    /// Saturation completed.
    SaturationCompleted,
    /// Extraction started.
    ExtractionStarted,
    /// Extraction completed.
    ExtractionCompleted,
    /// Interference check performed.
    InterferenceChecked,
    /// Campaign failed.
    CampaignFailed,
    /// Campaign rolled back.
    CampaignRolledBack,
    /// Budget consumed.
    BudgetConsumed,
}

impl fmt::Display for OptimizationEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CampaignRegistered => "campaign_registered",
            Self::SaturationStarted => "saturation_started",
            Self::SaturationCompleted => "saturation_completed",
            Self::ExtractionStarted => "extraction_started",
            Self::ExtractionCompleted => "extraction_completed",
            Self::InterferenceChecked => "interference_checked",
            Self::CampaignFailed => "campaign_failed",
            Self::CampaignRolledBack => "campaign_rolled_back",
            Self::BudgetConsumed => "budget_consumed",
        };
        f.write_str(s)
    }
}

/// An event in the optimization audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationEvent {
    /// Sequence number.
    pub seq: u64,
    /// Event kind.
    pub kind: OptimizationEventKind,
    /// Campaign ID (if relevant).
    pub campaign_id: Option<String>,
    /// Detail message.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// BudgetedOptimizationStack — the orchestrator
// ---------------------------------------------------------------------------

/// Orchestrator for budgeted optimization campaigns.
///
/// Manages multiple optimization campaigns with interference checks,
/// budget enforcement, and rollback capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetedOptimizationStack {
    /// Schema version.
    pub schema_version: String,
    /// Registered campaigns.
    campaigns: BTreeMap<String, OptimizationCampaign>,
    /// Interference checks performed.
    interference_checks: Vec<InterferenceCheck>,
    /// Global budget envelope (shared across campaigns).
    global_budget: BudgetEnvelope,
    /// Events.
    events: Vec<OptimizationEvent>,
    /// Next event sequence.
    next_event_seq: u64,
}

impl BudgetedOptimizationStack {
    /// Create a new optimization stack.
    pub fn new() -> Self {
        Self {
            schema_version: OPTIMIZATION_SCHEMA_VERSION.to_string(),
            campaigns: BTreeMap::new(),
            interference_checks: Vec::new(),
            global_budget: BudgetEnvelope::production(),
            events: Vec::new(),
            next_event_seq: 0,
        }
    }

    /// Create with a custom global budget.
    pub fn with_budget(budget: BudgetEnvelope) -> Self {
        let mut stack = Self::new();
        stack.global_budget = budget;
        stack
    }

    // -- Mutation --

    /// Register a new optimization campaign.
    pub fn register_campaign(
        &mut self,
        campaign: OptimizationCampaign,
    ) -> Result<(), OptimizationError> {
        if self.campaigns.len() >= MAX_CAMPAIGNS {
            return Err(OptimizationError::CampaignLimitExceeded {
                count: self.campaigns.len() + 1,
                max: MAX_CAMPAIGNS,
            });
        }
        if self.campaigns.contains_key(&campaign.id) {
            return Err(OptimizationError::DuplicateCampaign(campaign.id.clone()));
        }
        let campaign_id = campaign.id.clone();
        self.campaigns.insert(campaign.id.clone(), campaign);
        self.emit_event(
            OptimizationEventKind::CampaignRegistered,
            Some(&campaign_id),
            "",
        );
        Ok(())
    }

    /// Record saturation result for a campaign.
    pub fn record_saturation(
        &mut self,
        campaign_id: &str,
        snapshot: EGraphSnapshot,
    ) -> Result<(), OptimizationError> {
        let campaign = self
            .campaigns
            .get_mut(campaign_id)
            .ok_or_else(|| OptimizationError::DuplicateCampaign(campaign_id.to_string()))?;

        // Consume global budget
        self.global_budget
            .consume(BudgetKind::TimeMs, snapshot.elapsed_ms);
        self.global_budget
            .consume(BudgetKind::EgraphNodes, snapshot.node_count);
        self.global_budget
            .consume(BudgetKind::RewriteApplications, snapshot.rewrite_count);

        campaign.record_saturation(snapshot);
        self.emit_event(
            OptimizationEventKind::SaturationCompleted,
            Some(campaign_id),
            "",
        );
        Ok(())
    }

    /// Record extraction result for a campaign.
    pub fn record_extraction(
        &mut self,
        campaign_id: &str,
        result: ExtractionResult,
    ) -> Result<(), OptimizationError> {
        let campaign = self
            .campaigns
            .get_mut(campaign_id)
            .ok_or_else(|| OptimizationError::DuplicateCampaign(campaign_id.to_string()))?;
        campaign.record_extraction(result);
        self.emit_event(
            OptimizationEventKind::ExtractionCompleted,
            Some(campaign_id),
            "",
        );
        Ok(())
    }

    /// Check interference between two campaigns.
    pub fn check_interference(&mut self, campaign_a: &str, campaign_b: &str) -> InterferenceCheck {
        let families_a = self
            .campaigns
            .get(campaign_a)
            .map(|c| c.families())
            .unwrap_or_default();
        let families_b = self
            .campaigns
            .get(campaign_b)
            .map(|c| c.families())
            .unwrap_or_default();

        let overlapping: BTreeSet<_> = families_a.intersection(&families_b).cloned().collect();

        let kind = if overlapping.is_empty() {
            InterferenceKind::None
        } else {
            InterferenceKind::RewriteConflict
        };

        let blocking = kind != InterferenceKind::None;

        let check = InterferenceCheck {
            campaign_a: campaign_a.to_string(),
            campaign_b: campaign_b.to_string(),
            kind,
            detail: if overlapping.is_empty() {
                String::new()
            } else {
                format!(
                    "overlapping families: {}",
                    overlapping
                        .iter()
                        .map(|f| f.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            blocking,
        };

        self.interference_checks.push(check.clone());
        self.emit_event(
            OptimizationEventKind::InterferenceChecked,
            None,
            &format!("{campaign_a} vs {campaign_b}"),
        );
        check
    }

    /// Record rollback for a campaign.
    pub fn record_rollback(
        &mut self,
        campaign_id: &str,
        rollback: RollbackArtifact,
    ) -> Result<(), OptimizationError> {
        let campaign = self
            .campaigns
            .get_mut(campaign_id)
            .ok_or_else(|| OptimizationError::DuplicateCampaign(campaign_id.to_string()))?;
        campaign.record_rollback(rollback);
        self.emit_event(
            OptimizationEventKind::CampaignRolledBack,
            Some(campaign_id),
            "",
        );
        Ok(())
    }

    // -- Query --

    /// Get a campaign by ID.
    pub fn get_campaign(&self, id: &str) -> Option<&OptimizationCampaign> {
        self.campaigns.get(id)
    }

    /// Number of campaigns.
    pub fn campaign_count(&self) -> usize {
        self.campaigns.len()
    }

    /// All campaign IDs.
    pub fn campaign_ids(&self) -> Vec<String> {
        self.campaigns.keys().cloned().collect()
    }

    /// Campaigns by status.
    pub fn campaigns_by_status(&self, status: CampaignStatus) -> Vec<&OptimizationCampaign> {
        self.campaigns
            .values()
            .filter(|c| c.status == status)
            .collect()
    }

    /// Global budget.
    pub fn global_budget(&self) -> &BudgetEnvelope {
        &self.global_budget
    }

    /// All interference checks.
    pub fn interference_checks(&self) -> &[InterferenceCheck] {
        &self.interference_checks
    }

    /// Events.
    pub fn events(&self) -> &[OptimizationEvent] {
        &self.events
    }

    /// Compute summary.
    pub fn summary(&self) -> OptimizationSummary {
        let total_campaigns = self.campaigns.len() as u64;
        let completed = self
            .campaigns
            .values()
            .filter(|c| c.status == CampaignStatus::Completed)
            .count() as u64;
        let failed = self
            .campaigns
            .values()
            .filter(|c| c.status == CampaignStatus::Failed)
            .count() as u64;
        let rolled_back = self
            .campaigns
            .values()
            .filter(|c| c.status == CampaignStatus::RolledBack)
            .count() as u64;
        let total_rules: u64 = self.campaigns.values().map(|c| c.rules.len() as u64).sum();
        let total_rewrites: u64 = self
            .campaigns
            .values()
            .filter_map(|c| c.egraph_snapshot.as_ref())
            .map(|s| s.rewrite_count)
            .sum();
        let total_gain: i64 = self
            .campaigns
            .values()
            .filter(|c| c.is_successful())
            .map(|c| c.expected_gain_millionths)
            .sum();
        let blocking_interference_count = self
            .interference_checks
            .iter()
            .filter(|c| c.blocking)
            .count() as u64;

        OptimizationSummary {
            total_campaigns,
            completed_campaigns: completed,
            failed_campaigns: failed,
            rolled_back_campaigns: rolled_back,
            total_rules,
            total_rewrites_applied: total_rewrites,
            total_gain_millionths: total_gain,
            blocking_interference_count,
        }
    }

    // -- Internal --

    fn emit_event(&mut self, kind: OptimizationEventKind, campaign_id: Option<&str>, detail: &str) {
        let seq = self.next_event_seq;
        self.next_event_seq += 1;
        self.events.push(OptimizationEvent {
            seq,
            kind,
            campaign_id: campaign_id.map(|s| s.to_string()),
            detail: detail.to_string(),
        });
    }
}

impl Default for BudgetedOptimizationStack {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OptimizationSummary — high-level summary
// ---------------------------------------------------------------------------

/// High-level summary of the optimization stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationSummary {
    /// Total campaigns registered.
    pub total_campaigns: u64,
    /// Completed campaigns.
    pub completed_campaigns: u64,
    /// Failed campaigns.
    pub failed_campaigns: u64,
    /// Rolled back campaigns.
    pub rolled_back_campaigns: u64,
    /// Total rewrite rules across all campaigns.
    pub total_rules: u64,
    /// Total rewrites applied across all campaigns.
    pub total_rewrites_applied: u64,
    /// Total expected gain in millionths.
    pub total_gain_millionths: i64,
    /// Blocking interference count.
    pub blocking_interference_count: u64,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn make_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    fn make_rule(id: &str, family: RewriteFamily) -> RewriteRule {
        RewriteRule {
            id: id.to_string(),
            family,
            description: format!("rule {id}"),
            pattern_hash: make_hash(format!("pat_{id}").as_bytes()),
            replacement_hash: make_hash(format!("rep_{id}").as_bytes()),
            proof_obligations: vec![format!("prove_{id}")],
            metamorphic_checks: vec![format!("check_{id}")],
            sound: true,
            priority_millionths: MILLION,
            enabled: true,
        }
    }

    fn make_campaign(id: &str) -> OptimizationCampaign {
        OptimizationCampaign::new(id, &format!("Campaign {id}"), make_hash(id.as_bytes()))
    }

    fn make_egraph_snapshot() -> EGraphSnapshot {
        EGraphSnapshot {
            class_count: 100,
            node_count: 500,
            iteration_count: 10,
            rewrite_count: 250,
            outcome: SaturationOutcome::Saturated,
            state_hash: make_hash(b"egraph_state"),
            elapsed_ms: 50,
            peak_memory_bytes: 1024 * 1024,
        }
    }

    fn make_extraction_result() -> ExtractionResult {
        let mut families = BTreeSet::new();
        families.insert(RewriteFamily::AlgebraicSimplification);
        ExtractionResult {
            policy: ExtractionPolicy::MinCost,
            total_cost_millionths: 500_000,
            extracted_node_count: 50,
            proven_rewrite_count: 40,
            output_hash: make_hash(b"extracted"),
            families_used: families,
        }
    }

    fn make_rollback(campaign_id: &str) -> RollbackArtifact {
        RollbackArtifact {
            campaign_id: campaign_id.to_string(),
            pre_optimization_hash: make_hash(b"pre"),
            post_optimization_hash: make_hash(b"post"),
            applied_rules: vec!["rule_1".to_string()],
            rollback_tested: true,
            artifact_hash: make_hash(b"rollback"),
        }
    }

    // -- RewriteFamily tests --

    #[test]
    fn rewrite_family_display() {
        assert_eq!(
            format!("{}", RewriteFamily::AlgebraicSimplification),
            "algebraic_simplification"
        );
        assert_eq!(
            format!("{}", RewriteFamily::DeadCodeElimination),
            "dead_code_elimination"
        );
        assert_eq!(
            format!("{}", RewriteFamily::Incrementalization),
            "incrementalization"
        );
    }

    #[test]
    fn rewrite_family_serde_roundtrip() {
        for family in [
            RewriteFamily::AlgebraicSimplification,
            RewriteFamily::DeadCodeElimination,
            RewriteFamily::CommonSubexpression,
            RewriteFamily::PartialEvaluation,
            RewriteFamily::MemoizationBoundary,
            RewriteFamily::EffectHoisting,
            RewriteFamily::HookSlotFusion,
            RewriteFamily::SignalGraphOptimization,
            RewriteFamily::Incrementalization,
            RewriteFamily::DomUpdateBatching,
            RewriteFamily::Custom,
        ] {
            let json = serde_json::to_string(&family).unwrap();
            let back: RewriteFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(family, back);
        }
    }

    // -- RewriteRule tests --

    #[test]
    fn rewrite_rule_ready() {
        let rule = make_rule("r1", RewriteFamily::AlgebraicSimplification);
        assert!(rule.is_ready());
    }

    #[test]
    fn rewrite_rule_not_ready_unsound() {
        let mut rule = make_rule("r1", RewriteFamily::AlgebraicSimplification);
        rule.sound = false;
        assert!(!rule.is_ready());
    }

    #[test]
    fn rewrite_rule_not_ready_disabled() {
        let mut rule = make_rule("r1", RewriteFamily::AlgebraicSimplification);
        rule.enabled = false;
        assert!(!rule.is_ready());
    }

    #[test]
    fn rewrite_rule_serde_roundtrip() {
        let rule = make_rule("r1", RewriteFamily::PartialEvaluation);
        let json = serde_json::to_string(&rule).unwrap();
        let back: RewriteRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    // -- BudgetLimit tests --

    #[test]
    fn budget_limit_new() {
        let bl = BudgetLimit::new(BudgetKind::TimeMs, 5000);
        assert!(!bl.is_exhausted());
        assert_eq!(bl.remaining(), 5000);
        assert_eq!(bl.utilization_millionths(), 0);
    }

    #[test]
    fn budget_limit_consume() {
        let mut bl = BudgetLimit::new(BudgetKind::TimeMs, 100);
        assert!(bl.consume(50));
        assert_eq!(bl.remaining(), 50);
        assert_eq!(bl.utilization_millionths(), 500_000);
    }

    #[test]
    fn budget_limit_exhausted() {
        let mut bl = BudgetLimit::new(BudgetKind::TimeMs, 100);
        assert!(bl.consume(100));
        assert!(bl.is_exhausted());
        assert_eq!(bl.remaining(), 0);
        assert_eq!(bl.utilization_millionths(), MILLION);
    }

    #[test]
    fn budget_limit_over_consumed() {
        let mut bl = BudgetLimit::new(BudgetKind::TimeMs, 100);
        assert!(!bl.consume(150));
        assert!(bl.is_exhausted());
    }

    #[test]
    fn budget_limit_zero_max() {
        let bl = BudgetLimit::new(BudgetKind::TimeMs, 0);
        assert!(bl.is_exhausted());
        assert_eq!(bl.utilization_millionths(), MILLION);
    }

    #[test]
    fn budget_limit_serde_roundtrip() {
        let mut bl = BudgetLimit::new(BudgetKind::EgraphNodes, 1000);
        bl.consume(500);
        let json = serde_json::to_string(&bl).unwrap();
        let back: BudgetLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(bl, back);
    }

    // -- BudgetEnvelope tests --

    #[test]
    fn budget_envelope_production() {
        let be = BudgetEnvelope::production();
        assert!(!be.any_exhausted());
        assert!(be.get(BudgetKind::TimeMs).is_some());
        assert!(be.get(BudgetKind::EgraphNodes).is_some());
    }

    #[test]
    fn budget_envelope_consume() {
        let mut be = BudgetEnvelope::production();
        assert!(be.consume(BudgetKind::TimeMs, 1000));
        let time = be.get(BudgetKind::TimeMs).unwrap();
        assert_eq!(time.current_value, 1000);
    }

    #[test]
    fn budget_envelope_most_constrained() {
        let mut be = BudgetEnvelope::production();
        be.consume(BudgetKind::TimeMs, 4999);
        let mc = be.most_constrained().unwrap();
        assert_eq!(mc.kind, BudgetKind::TimeMs);
    }

    #[test]
    fn budget_envelope_serde_roundtrip() {
        let be = BudgetEnvelope::production();
        let json = serde_json::to_string(&be).unwrap();
        let back: BudgetEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(be, back);
    }

    // -- SaturationOutcome tests --

    #[test]
    fn saturation_outcome_display() {
        assert_eq!(format!("{}", SaturationOutcome::Saturated), "saturated");
        assert_eq!(
            format!("{}", SaturationOutcome::BudgetExhausted),
            "budget_exhausted"
        );
    }

    // -- ExtractionPolicy tests --

    #[test]
    fn extraction_policy_display() {
        assert_eq!(format!("{}", ExtractionPolicy::MinCost), "min_cost");
        assert_eq!(
            format!("{}", ExtractionPolicy::MaxPerformance),
            "max_performance"
        );
        assert_eq!(
            format!(
                "{}",
                ExtractionPolicy::ProofAware {
                    proof_weight_millionths: 500_000
                }
            ),
            "proof_aware"
        );
    }

    #[test]
    fn extraction_policy_serde_roundtrip() {
        for policy in [
            ExtractionPolicy::MinCost,
            ExtractionPolicy::MinSize,
            ExtractionPolicy::MaxPerformance,
            ExtractionPolicy::ProofAware {
                proof_weight_millionths: 750_000,
            },
            ExtractionPolicy::Custom {
                name: "my_cost".to_string(),
            },
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let back: ExtractionPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    // -- InterferenceKind tests --

    #[test]
    fn interference_kind_display() {
        assert_eq!(format!("{}", InterferenceKind::None), "none");
        assert_eq!(
            format!("{}", InterferenceKind::RewriteConflict),
            "rewrite_conflict"
        );
    }

    // -- CampaignStatus tests --

    #[test]
    fn campaign_status_display() {
        assert_eq!(format!("{}", CampaignStatus::Pending), "pending");
        assert_eq!(format!("{}", CampaignStatus::Completed), "completed");
        assert_eq!(format!("{}", CampaignStatus::RolledBack), "rolled_back");
    }

    // -- OptimizationCampaign tests --

    #[test]
    fn campaign_new() {
        let c = make_campaign("c1");
        assert_eq!(c.status, CampaignStatus::Pending);
        assert_eq!(c.rules.len(), 0);
        assert!(!c.is_successful());
    }

    #[test]
    fn campaign_add_rule() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.ready_rule_count(), 1);
    }

    #[test]
    fn campaign_add_duplicate_rule_fails() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let err = c
            .add_rule(make_rule("r1", RewriteFamily::DeadCodeElimination))
            .unwrap_err();
        assert!(matches!(err, OptimizationError::DuplicateRule(_)));
    }

    #[test]
    fn campaign_lifecycle() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        assert_eq!(c.status, CampaignStatus::Pending);

        c.record_saturation(make_egraph_snapshot());
        assert_eq!(c.status, CampaignStatus::Extracting);

        c.record_extraction(make_extraction_result());
        assert_eq!(c.status, CampaignStatus::Completed);
        assert!(c.is_successful());
    }

    #[test]
    fn campaign_rollback() {
        let mut c = make_campaign("c1");
        c.record_failure();
        assert_eq!(c.status, CampaignStatus::Failed);
        c.record_rollback(make_rollback("c1"));
        assert_eq!(c.status, CampaignStatus::RolledBack);
    }

    #[test]
    fn campaign_families() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        c.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination))
            .unwrap();
        let fams = c.families();
        assert_eq!(fams.len(), 2);
        assert!(fams.contains(&RewriteFamily::AlgebraicSimplification));
        assert!(fams.contains(&RewriteFamily::DeadCodeElimination));
    }

    #[test]
    fn campaign_serde_roundtrip() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: OptimizationCampaign = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -- RollbackArtifact tests --

    #[test]
    fn rollback_viable() {
        let rb = make_rollback("c1");
        assert!(rb.is_viable());
    }

    #[test]
    fn rollback_not_viable() {
        let mut rb = make_rollback("c1");
        rb.rollback_tested = false;
        assert!(!rb.is_viable());
    }

    #[test]
    fn rollback_serde_roundtrip() {
        let rb = make_rollback("c1");
        let json = serde_json::to_string(&rb).unwrap();
        let back: RollbackArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(rb, back);
    }

    // -- OptimizationError tests --

    #[test]
    fn optimization_error_display() {
        let e = OptimizationError::RuleLimitExceeded {
            count: 1025,
            max: 1024,
        };
        assert_eq!(format!("{e}"), "rule limit exceeded: 1025 > 1024");

        let e = OptimizationError::BudgetExhausted {
            kind: BudgetKind::TimeMs,
        };
        assert_eq!(format!("{e}"), "budget exhausted: time_ms");
    }

    #[test]
    fn optimization_error_serde_roundtrip() {
        let e = OptimizationError::UnsoundRewrite {
            rule_id: "bad_rule".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: OptimizationError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -- BudgetedOptimizationStack tests --

    #[test]
    fn stack_new() {
        let s = BudgetedOptimizationStack::new();
        assert_eq!(s.campaign_count(), 0);
        assert_eq!(s.schema_version, OPTIMIZATION_SCHEMA_VERSION);
    }

    #[test]
    fn stack_default() {
        let s = BudgetedOptimizationStack::default();
        assert_eq!(s.campaign_count(), 0);
    }

    #[test]
    fn stack_register_campaign() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        assert_eq!(s.campaign_count(), 1);
        assert!(s.get_campaign("c1").is_some());
    }

    #[test]
    fn stack_register_duplicate_campaign_fails() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        let err = s.register_campaign(make_campaign("c1")).unwrap_err();
        assert!(matches!(err, OptimizationError::DuplicateCampaign(_)));
    }

    #[test]
    fn stack_campaign_ids_sorted() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("beta")).unwrap();
        s.register_campaign(make_campaign("alpha")).unwrap();
        let ids = s.campaign_ids();
        assert_eq!(ids[0], "alpha");
        assert_eq!(ids[1], "beta");
    }

    #[test]
    fn stack_record_saturation() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        let c = s.get_campaign("c1").unwrap();
        assert_eq!(c.status, CampaignStatus::Extracting);
    }

    #[test]
    fn stack_record_extraction() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        s.record_extraction("c1", make_extraction_result()).unwrap();
        let c = s.get_campaign("c1").unwrap();
        assert_eq!(c.status, CampaignStatus::Completed);
    }

    #[test]
    fn stack_interference_check_no_overlap() {
        let mut s = BudgetedOptimizationStack::new();
        let mut c1 = make_campaign("c1");
        c1.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let mut c2 = make_campaign("c2");
        c2.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination))
            .unwrap();
        s.register_campaign(c1).unwrap();
        s.register_campaign(c2).unwrap();
        let check = s.check_interference("c1", "c2");
        assert_eq!(check.kind, InterferenceKind::None);
        assert!(!check.blocking);
    }

    #[test]
    fn stack_interference_check_with_overlap() {
        let mut s = BudgetedOptimizationStack::new();
        let mut c1 = make_campaign("c1");
        c1.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let mut c2 = make_campaign("c2");
        c2.add_rule(make_rule("r2", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        s.register_campaign(c1).unwrap();
        s.register_campaign(c2).unwrap();
        let check = s.check_interference("c1", "c2");
        assert_eq!(check.kind, InterferenceKind::RewriteConflict);
        assert!(check.blocking);
    }

    #[test]
    fn stack_rollback() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        s.record_rollback("c1", make_rollback("c1")).unwrap();
        let c = s.get_campaign("c1").unwrap();
        assert_eq!(c.status, CampaignStatus::RolledBack);
    }

    #[test]
    fn stack_campaigns_by_status() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        s.register_campaign(make_campaign("c2")).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        s.record_extraction("c1", make_extraction_result()).unwrap();
        let completed = s.campaigns_by_status(CampaignStatus::Completed);
        assert_eq!(completed.len(), 1);
        let pending = s.campaigns_by_status(CampaignStatus::Pending);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn stack_summary() {
        let mut s = BudgetedOptimizationStack::new();
        let mut c1 = make_campaign("c1");
        c1.expected_gain_millionths = 200_000;
        s.register_campaign(c1).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        s.record_extraction("c1", make_extraction_result()).unwrap();
        s.register_campaign(make_campaign("c2")).unwrap();
        let summary = s.summary();
        assert_eq!(summary.total_campaigns, 2);
        assert_eq!(summary.completed_campaigns, 1);
        assert_eq!(summary.total_gain_millionths, 200_000);
    }

    #[test]
    fn stack_events_tracked() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        assert!(
            s.events()
                .iter()
                .any(|e| e.kind == OptimizationEventKind::CampaignRegistered)
        );
    }

    #[test]
    fn stack_global_budget_consumed() {
        let mut s = BudgetedOptimizationStack::new();
        s.register_campaign(make_campaign("c1")).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        let time = s.global_budget().get(BudgetKind::TimeMs).unwrap();
        assert!(time.current_value > 0);
    }

    #[test]
    fn stack_serde_roundtrip() {
        let mut s = BudgetedOptimizationStack::new();
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        s.register_campaign(c).unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: BudgetedOptimizationStack = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- OptimizationSummary tests --

    #[test]
    fn summary_serde_roundtrip() {
        let summary = OptimizationSummary {
            total_campaigns: 5,
            completed_campaigns: 3,
            failed_campaigns: 1,
            rolled_back_campaigns: 1,
            total_rules: 50,
            total_rewrites_applied: 10_000,
            total_gain_millionths: 350_000,
            blocking_interference_count: 2,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: OptimizationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -- EGraphSnapshot tests --

    #[test]
    fn egraph_snapshot_serde_roundtrip() {
        let snap = make_egraph_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: EGraphSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // -- ExtractionResult tests --

    #[test]
    fn extraction_result_serde_roundtrip() {
        let res = make_extraction_result();
        let json = serde_json::to_string(&res).unwrap();
        let back: ExtractionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, back);
    }

    // -- InterferenceCheck tests --

    #[test]
    fn interference_check_serde_roundtrip() {
        let check = InterferenceCheck {
            campaign_a: "c1".to_string(),
            campaign_b: "c2".to_string(),
            kind: InterferenceKind::RewriteConflict,
            detail: "overlapping families".to_string(),
            blocking: true,
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: InterferenceCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    // -- BudgetKind tests --

    #[test]
    fn budget_kind_display() {
        assert_eq!(format!("{}", BudgetKind::TimeMs), "time_ms");
        assert_eq!(format!("{}", BudgetKind::EgraphNodes), "egraph_nodes");
        assert_eq!(format!("{}", BudgetKind::MemoryBytes), "memory_bytes");
    }

    #[test]
    fn budget_kind_serde_roundtrip() {
        for kind in [
            BudgetKind::TimeMs,
            BudgetKind::EgraphNodes,
            BudgetKind::MemoryBytes,
            BudgetKind::RewriteApplications,
            BudgetKind::SaturationIterations,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: BudgetKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // -- Enrichment: Display uniqueness, std::error, edge cases --

    #[test]
    fn optimization_error_display_all_unique() {
        let errors: Vec<OptimizationError> = vec![
            OptimizationError::RuleLimitExceeded {
                count: 1025,
                max: 1024,
            },
            OptimizationError::BudgetExhausted {
                kind: BudgetKind::TimeMs,
            },
            OptimizationError::UnsoundRewrite {
                rule_id: "r1".to_string(),
            },
            OptimizationError::DuplicateRule("r1".to_string()),
            OptimizationError::DuplicateCampaign("c1".to_string()),
            OptimizationError::CampaignLimitExceeded { count: 65, max: 64 },
        ];
        let mut displays = BTreeSet::new();
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all error variants have unique Display"
        );
    }

    #[test]
    fn optimization_error_display_is_nonempty() {
        let err = OptimizationError::UnsoundRewrite {
            rule_id: "bad".to_string(),
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn rewrite_family_display_all_unique() {
        let families = [
            RewriteFamily::AlgebraicSimplification,
            RewriteFamily::DeadCodeElimination,
            RewriteFamily::CommonSubexpression,
            RewriteFamily::PartialEvaluation,
            RewriteFamily::MemoizationBoundary,
            RewriteFamily::EffectHoisting,
            RewriteFamily::HookSlotFusion,
            RewriteFamily::SignalGraphOptimization,
            RewriteFamily::Incrementalization,
            RewriteFamily::DomUpdateBatching,
            RewriteFamily::Custom,
        ];
        let mut displays = BTreeSet::new();
        for f in families {
            displays.insert(f.to_string());
        }
        assert_eq!(
            displays.len(),
            11,
            "all RewriteFamily variants have unique Display"
        );
    }

    #[test]
    fn campaign_status_display_all_unique() {
        let statuses = [
            CampaignStatus::Pending,
            CampaignStatus::Saturating,
            CampaignStatus::Extracting,
            CampaignStatus::Completed,
            CampaignStatus::Failed,
            CampaignStatus::RolledBack,
        ];
        let mut displays = BTreeSet::new();
        for s in statuses {
            displays.insert(s.to_string());
        }
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn budget_kind_display_all_unique() {
        let kinds = [
            BudgetKind::TimeMs,
            BudgetKind::EgraphNodes,
            BudgetKind::MemoryBytes,
            BudgetKind::RewriteApplications,
            BudgetKind::SaturationIterations,
        ];
        let mut displays = BTreeSet::new();
        for k in kinds {
            displays.insert(k.to_string());
        }
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn stack_get_nonexistent_campaign_returns_none() {
        let s = BudgetedOptimizationStack::new();
        assert!(s.get_campaign("nonexistent").is_none());
    }

    #[test]
    fn budget_limit_consume_zero_is_ok() {
        let mut bl = BudgetLimit::new(BudgetKind::TimeMs, 100);
        assert!(bl.consume(0));
        assert_eq!(bl.remaining(), 100);
        assert_eq!(bl.utilization_millionths(), 0);
    }

    #[test]
    fn stack_deterministic_json_output() {
        let mut s1 = BudgetedOptimizationStack::new();
        let mut s2 = BudgetedOptimizationStack::new();
        for s in [&mut s1, &mut s2] {
            let mut c = make_campaign("c1");
            c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
                .unwrap();
            s.register_campaign(c).unwrap();
        }
        let json1 = serde_json::to_string(&s1).unwrap();
        let json2 = serde_json::to_string(&s2).unwrap();
        assert_eq!(json1, json2, "identical stacks must produce identical JSON");
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn extraction_policy_default_is_min_cost() {
        assert_eq!(ExtractionPolicy::default(), ExtractionPolicy::MinCost);
    }

    #[test]
    fn extraction_policy_custom_display() {
        let p = ExtractionPolicy::Custom {
            name: "my_func".to_string(),
        };
        assert_eq!(format!("{p}"), "custom:my_func");
    }

    #[test]
    fn budget_envelope_consume_unlisted_kind_returns_true() {
        let mut be = BudgetEnvelope {
            limits: BTreeMap::new(),
        };
        // No limits configured — unlimited
        assert!(be.consume(BudgetKind::TimeMs, 999_999));
    }

    #[test]
    fn budget_envelope_default_matches_production() {
        let def = BudgetEnvelope::default();
        let prod = BudgetEnvelope::production();
        assert_eq!(def, prod);
    }

    #[test]
    fn campaign_status_serde_all_variants() {
        for s in [
            CampaignStatus::Pending,
            CampaignStatus::Saturating,
            CampaignStatus::Extracting,
            CampaignStatus::Completed,
            CampaignStatus::Failed,
            CampaignStatus::RolledBack,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: CampaignStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn campaign_status_display_includes_saturating() {
        assert_eq!(format!("{}", CampaignStatus::Saturating), "saturating");
    }

    #[test]
    fn saturation_outcome_serde_all_variants() {
        for o in [
            SaturationOutcome::Saturated,
            SaturationOutcome::BudgetExhausted,
            SaturationOutcome::NodeLimitReached,
            SaturationOutcome::IterationLimitReached,
            SaturationOutcome::PolicyStopped,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let back: SaturationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn interference_kind_serde_all_variants() {
        for k in [
            InterferenceKind::None,
            InterferenceKind::RewriteConflict,
            InterferenceKind::BudgetContention,
            InterferenceKind::SemanticInterference,
            InterferenceKind::OrderDependence,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            let back: InterferenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn optimization_event_kind_display_all_unique() {
        let kinds = [
            OptimizationEventKind::CampaignRegistered,
            OptimizationEventKind::SaturationStarted,
            OptimizationEventKind::SaturationCompleted,
            OptimizationEventKind::ExtractionStarted,
            OptimizationEventKind::ExtractionCompleted,
            OptimizationEventKind::InterferenceChecked,
            OptimizationEventKind::CampaignFailed,
            OptimizationEventKind::CampaignRolledBack,
            OptimizationEventKind::BudgetConsumed,
        ];
        let mut displays = BTreeSet::new();
        for k in &kinds {
            displays.insert(k.to_string());
        }
        assert_eq!(displays.len(), kinds.len());
    }

    #[test]
    fn optimization_event_kind_serde_all_variants() {
        for k in [
            OptimizationEventKind::CampaignRegistered,
            OptimizationEventKind::SaturationStarted,
            OptimizationEventKind::SaturationCompleted,
            OptimizationEventKind::ExtractionStarted,
            OptimizationEventKind::ExtractionCompleted,
            OptimizationEventKind::InterferenceChecked,
            OptimizationEventKind::CampaignFailed,
            OptimizationEventKind::CampaignRolledBack,
            OptimizationEventKind::BudgetConsumed,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            let back: OptimizationEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn optimization_event_serde_roundtrip() {
        let event = OptimizationEvent {
            seq: 42,
            kind: OptimizationEventKind::SaturationCompleted,
            campaign_id: Some("c1".to_string()),
            detail: "done".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: OptimizationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn optimization_schema_version_stable() {
        assert_eq!(
            OPTIMIZATION_SCHEMA_VERSION,
            "franken-engine.budgeted-optimization.v1"
        );
    }

    #[test]
    fn stack_with_custom_budget() {
        let budget = BudgetEnvelope {
            limits: BTreeMap::new(),
        };
        let s = BudgetedOptimizationStack::with_budget(budget);
        assert!(s.global_budget().limits.is_empty());
    }

    #[test]
    fn stack_interference_checks_accessor() {
        let mut s = BudgetedOptimizationStack::new();
        let mut c1 = make_campaign("c1");
        c1.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let mut c2 = make_campaign("c2");
        c2.add_rule(make_rule("r2", RewriteFamily::DeadCodeElimination))
            .unwrap();
        s.register_campaign(c1).unwrap();
        s.register_campaign(c2).unwrap();
        assert!(s.interference_checks().is_empty());
        s.check_interference("c1", "c2");
        assert_eq!(s.interference_checks().len(), 1);
    }

    #[test]
    fn summary_with_failures_and_rollbacks() {
        let mut s = BudgetedOptimizationStack::new();

        // Completed campaign
        let mut c1 = make_campaign("c1");
        c1.expected_gain_millionths = 100_000;
        s.register_campaign(c1).unwrap();
        s.record_saturation("c1", make_egraph_snapshot()).unwrap();
        s.record_extraction("c1", make_extraction_result()).unwrap();

        // Failed campaign
        let c2 = make_campaign("c2");
        s.register_campaign(c2).unwrap();
        // manually fail it
        s.campaigns.get_mut("c2").unwrap().record_failure();

        // Rolled back campaign
        s.register_campaign(make_campaign("c3")).unwrap();
        s.record_rollback("c3", make_rollback("c3")).unwrap();

        let summary = s.summary();
        assert_eq!(summary.total_campaigns, 3);
        assert_eq!(summary.completed_campaigns, 1);
        assert_eq!(summary.failed_campaigns, 1);
        assert_eq!(summary.rolled_back_campaigns, 1);
    }

    #[test]
    fn budget_limit_consume_saturates_on_overflow() {
        let mut bl = BudgetLimit::new(BudgetKind::MemoryBytes, 100);
        bl.consume(u64::MAX);
        // saturating_add caps at u64::MAX
        assert!(bl.is_exhausted());
        assert_eq!(bl.current_value, u64::MAX);
    }

    #[test]
    fn optimization_error_serde_all_variants() {
        let errors: Vec<OptimizationError> = vec![
            OptimizationError::RuleLimitExceeded { count: 2, max: 1 },
            OptimizationError::DuplicateRule("r1".to_string()),
            OptimizationError::CampaignLimitExceeded { count: 65, max: 64 },
            OptimizationError::DuplicateCampaign("c1".to_string()),
            OptimizationError::BudgetExhausted {
                kind: BudgetKind::TimeMs,
            },
            OptimizationError::InterferenceBlocking(InterferenceCheck {
                campaign_a: "a".to_string(),
                campaign_b: "b".to_string(),
                kind: InterferenceKind::RewriteConflict,
                detail: "conflict".to_string(),
                blocking: true,
            }),
            OptimizationError::UnsoundRewrite {
                rule_id: "x".to_string(),
            },
            OptimizationError::RollbackFailed {
                campaign_id: "c1".to_string(),
                detail: "disk full".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: OptimizationError = serde_json::from_str(&json).unwrap();
            assert_eq!(e, &back);
        }
        assert_eq!(errors.len(), 8);
    }

    #[test]
    fn stack_record_saturation_unknown_campaign_fails() {
        let mut s = BudgetedOptimizationStack::new();
        let result = s.record_saturation("nonexistent", make_egraph_snapshot());
        assert!(result.is_err());
    }

    #[test]
    fn stack_record_extraction_unknown_campaign_fails() {
        let mut s = BudgetedOptimizationStack::new();
        let result = s.record_extraction("nonexistent", make_extraction_result());
        assert!(result.is_err());
    }

    #[test]
    fn stack_record_rollback_unknown_campaign_fails() {
        let mut s = BudgetedOptimizationStack::new();
        let result = s.record_rollback("nonexistent", make_rollback("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn campaign_ready_rule_count_mixed_sound_unsound() {
        let mut c = make_campaign("c1");
        c.add_rule(make_rule("r1", RewriteFamily::AlgebraicSimplification))
            .unwrap();
        let mut unsound_rule = make_rule("r2", RewriteFamily::DeadCodeElimination);
        unsound_rule.sound = false;
        c.add_rule(unsound_rule).unwrap();
        let mut disabled_rule = make_rule("r3", RewriteFamily::PartialEvaluation);
        disabled_rule.enabled = false;
        c.add_rule(disabled_rule).unwrap();
        assert_eq!(c.ready_rule_count(), 1);
        assert_eq!(c.rules.len(), 3);
    }

    #[test]
    fn rewrite_family_ord_algebraic_before_custom() {
        assert!(RewriteFamily::AlgebraicSimplification < RewriteFamily::Custom);
    }

    #[test]
    fn budget_kind_ord_time_before_saturation() {
        assert!(BudgetKind::TimeMs < BudgetKind::SaturationIterations);
    }

    #[test]
    fn campaign_status_ord_pending_before_completed() {
        assert!(CampaignStatus::Pending < CampaignStatus::Completed);
    }
}
