//! Hardware-aware code layout, alignment, and front-end stall governance.
//!
//! Bead: bd-1lsy.7.23.3 [RGC-623C]
//!
//! Optimises code placement, alignment, and front-end stall budgets so
//! quickened and traced paths translate into real hardware wins rather than
//! prettier IR.  Operators can tell when a layout policy should be pinned,
//! rolled back, or treated as hardware-specific.
//!
//! # Design
//!
//! - `LayoutStrategy` classifies the code-layout technique applied.
//! - `StallCategory` names the front-end stall mechanism being governed.
//! - `AlignmentEntry` records measured stall improvement for one function.
//! - `StallBudget` constrains per-category stall cycles.
//! - `LayoutPolicyEntry` binds a strategy to its applicable hardware set.
//! - `GovernanceConfig` holds all thresholds and required strategies.
//! - `GovernanceVerdict` is the final pass/fail/multi-violation result.
//! - `GovernanceEvaluator` accumulates entries and evaluates in one pass.
//! - `GovernanceReceipt` is the content-hashed, epoch-scoped audit receipt.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-623C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.hardware-code-layout-governance.v1";

/// Component name for diagnostics and receipt chaining.
pub const COMPONENT: &str = "hardware_code_layout_governance";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.7.23.3";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-623C";

/// Fixed-point unit: 1.0 in millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default maximum stall-budget usage (millionths). 200_000 = 20%.
pub const DEFAULT_MAX_STALL_BUDGET_MILLIONTHS: u64 = 200_000;

/// Default minimum improvement to consider an alignment worthwhile
/// (millionths). 10_000 = 1%.
pub const DEFAULT_MIN_IMPROVEMENT_MILLIONTHS: u64 = 10_000;

/// Default maximum alignment waste in bytes before rejection.
pub const DEFAULT_MAX_ALIGNMENT_WASTE_BYTES: u64 = 4096;

/// Default minimum hardware coverage ratio (millionths). 500_000 = 50%.
pub const DEFAULT_MIN_HARDWARE_COVERAGE: u64 = 500_000;

/// Maximum strategies configurable.
pub const MAX_STRATEGIES: usize = 32;

/// Maximum alignment entries per evaluation.
pub const MAX_ALIGNMENT_ENTRIES: usize = 4096;

/// Maximum stall budget entries per evaluation.
pub const MAX_STALL_BUDGETS: usize = 64;

/// Maximum layout policy entries per evaluation.
pub const MAX_POLICY_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// LayoutStrategy
// ---------------------------------------------------------------------------

/// Code-layout technique applied to a function or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutStrategy {
    /// Split hot and cold code into separate sections.
    HotColdSplit,
    /// Reorder functions by call-frequency profile.
    FunctionReordering,
    /// Align loop headers to cache-line boundaries.
    LoopAlignment,
    /// Align branch targets to reduce decode penalties.
    BranchAlignment,
    /// Reorganise data/code for cache-line friendliness.
    CacheFriendly,
    /// Insert NOP padding to satisfy alignment constraints.
    NopPadding,
    /// Group callee near caller to reduce I-cache working set.
    CallerCalleeColocation,
    /// Compact cold paths into a tail section.
    ColdTailCompaction,
}

impl LayoutStrategy {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::HotColdSplit,
        Self::FunctionReordering,
        Self::LoopAlignment,
        Self::BranchAlignment,
        Self::CacheFriendly,
        Self::NopPadding,
        Self::CallerCalleeColocation,
        Self::ColdTailCompaction,
    ];

    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HotColdSplit => "hot_cold_split",
            Self::FunctionReordering => "function_reordering",
            Self::LoopAlignment => "loop_alignment",
            Self::BranchAlignment => "branch_alignment",
            Self::CacheFriendly => "cache_friendly",
            Self::NopPadding => "nop_padding",
            Self::CallerCalleeColocation => "caller_callee_colocation",
            Self::ColdTailCompaction => "cold_tail_compaction",
        }
    }

    /// Whether this strategy may introduce padding waste.
    #[must_use]
    pub const fn introduces_waste(self) -> bool {
        matches!(
            self,
            Self::LoopAlignment | Self::BranchAlignment | Self::NopPadding
        )
    }

    /// Whether this strategy targets the instruction-cache.
    #[must_use]
    pub const fn targets_icache(self) -> bool {
        matches!(
            self,
            Self::HotColdSplit
                | Self::FunctionReordering
                | Self::CacheFriendly
                | Self::CallerCalleeColocation
                | Self::ColdTailCompaction
        )
    }
}

impl fmt::Display for LayoutStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// StallCategory
// ---------------------------------------------------------------------------

/// Front-end stall mechanism being governed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StallCategory {
    /// Instruction-cache miss stalls.
    InstructionCacheMiss,
    /// Branch mispredict pipeline flushes.
    BranchMispredict,
    /// Decode-stage bubbles from alignment/prefix issues.
    DecodeBubble,
    /// Micro-op cache overflow or eviction stalls.
    MicroOpCacheOverflow,
    /// Penalties from misaligned fetch/decode blocks.
    AlignmentPenalty,
    /// Front-end fetch bubbles (not I-cache or decode).
    FetchBubble,
}

impl StallCategory {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::InstructionCacheMiss,
        Self::BranchMispredict,
        Self::DecodeBubble,
        Self::MicroOpCacheOverflow,
        Self::AlignmentPenalty,
        Self::FetchBubble,
    ];

    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstructionCacheMiss => "instruction_cache_miss",
            Self::BranchMispredict => "branch_mispredict",
            Self::DecodeBubble => "decode_bubble",
            Self::MicroOpCacheOverflow => "micro_op_cache_overflow",
            Self::AlignmentPenalty => "alignment_penalty",
            Self::FetchBubble => "fetch_bubble",
        }
    }

    /// Whether this stall category is addressable by alignment changes.
    #[must_use]
    pub const fn addressable_by_alignment(self) -> bool {
        matches!(
            self,
            Self::DecodeBubble | Self::AlignmentPenalty | Self::FetchBubble
        )
    }

    /// Whether this stall category is addressable by code placement.
    #[must_use]
    pub const fn addressable_by_placement(self) -> bool {
        matches!(
            self,
            Self::InstructionCacheMiss | Self::MicroOpCacheOverflow
        )
    }
}

impl fmt::Display for StallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AlignmentEntry
// ---------------------------------------------------------------------------

/// Measured alignment result for a single function or region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlignmentEntry {
    /// Identifier of the function or region.
    pub function_id: String,
    /// Layout strategy applied.
    pub strategy: LayoutStrategy,
    /// Alignment in bytes (must be a power of two).
    pub alignment_bytes: u64,
    /// Measured front-end stall cycles after applying the strategy.
    pub measured_stall_cycles: u64,
    /// Baseline front-end stall cycles before the strategy.
    pub baseline_stall_cycles: u64,
    /// Computed improvement in millionths: (baseline - measured) / baseline.
    pub improvement_millionths: i64,
    /// Bytes of padding waste introduced.
    pub waste_bytes: u64,
    /// Content hash of this entry for audit chains.
    pub content_hash: ContentHash,
}

impl AlignmentEntry {
    /// Create a new entry, computing improvement and content hash.
    #[must_use]
    pub fn new(
        function_id: &str,
        strategy: LayoutStrategy,
        alignment_bytes: u64,
        measured_stall_cycles: u64,
        baseline_stall_cycles: u64,
        waste_bytes: u64,
    ) -> Self {
        let improvement_millionths =
            compute_improvement(baseline_stall_cycles, measured_stall_cycles);
        let mut buf = Vec::with_capacity(128);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, function_id);
        append_str(&mut buf, strategy.as_str());
        append_u64(&mut buf, alignment_bytes);
        append_u64(&mut buf, measured_stall_cycles);
        append_u64(&mut buf, baseline_stall_cycles);
        append_u64(&mut buf, waste_bytes);
        let content_hash = compute_digest(&buf);
        Self {
            function_id: function_id.to_string(),
            strategy,
            alignment_bytes,
            measured_stall_cycles,
            baseline_stall_cycles,
            improvement_millionths,
            waste_bytes,
            content_hash,
        }
    }

    /// Whether alignment bytes is a valid power of two.
    #[must_use]
    pub fn is_valid_alignment(&self) -> bool {
        self.alignment_bytes > 0 && self.alignment_bytes.is_power_of_two()
    }

    /// Whether the entry shows a positive improvement.
    #[must_use]
    pub fn is_improvement(&self) -> bool {
        self.improvement_millionths > 0
    }

    /// Whether the entry shows a regression.
    #[must_use]
    pub fn is_regression(&self) -> bool {
        self.improvement_millionths < 0
    }
}

impl fmt::Display for AlignmentEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlignmentEntry({} strategy={} align={}B stalls={}/{} imp={} waste={}B)",
            self.function_id,
            self.strategy,
            self.alignment_bytes,
            self.measured_stall_cycles,
            self.baseline_stall_cycles,
            self.improvement_millionths,
            self.waste_bytes
        )
    }
}

// ---------------------------------------------------------------------------
// StallBudget
// ---------------------------------------------------------------------------

/// Per-category stall-cycle budget and measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StallBudget {
    /// Which stall category this budget governs.
    pub category: StallCategory,
    /// Budgeted stall cycles per million instructions.
    pub budget_cycles_per_million: u64,
    /// Measured stall cycles per million instructions.
    pub measured_cycles_per_million: u64,
    /// Whether the measured value is within the budget.
    pub within_budget: bool,
    /// Overshoot in millionths: (measured - budget) / budget.  Negative if
    /// within budget.
    pub overshoot_millionths: i64,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl StallBudget {
    /// Create a new stall budget with computed within-budget flag.
    #[must_use]
    pub fn new(
        category: StallCategory,
        budget_cycles_per_million: u64,
        measured_cycles_per_million: u64,
    ) -> Self {
        let within_budget = measured_cycles_per_million <= budget_cycles_per_million;
        let overshoot_millionths = if budget_cycles_per_million == 0 {
            if measured_cycles_per_million == 0 {
                0
            } else {
                FIXED_ONE as i64
            }
        } else {
            let diff = measured_cycles_per_million as i128 - budget_cycles_per_million as i128;
            (diff * FIXED_ONE as i128 / budget_cycles_per_million as i128) as i64
        };

        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, category.as_str());
        append_u64(&mut buf, budget_cycles_per_million);
        append_u64(&mut buf, measured_cycles_per_million);
        let content_hash = compute_digest(&buf);

        Self {
            category,
            budget_cycles_per_million,
            measured_cycles_per_million,
            within_budget,
            overshoot_millionths,
            content_hash,
        }
    }

    /// Absolute overshoot in cycles (0 if within budget).
    #[must_use]
    pub fn overshoot_cycles(&self) -> u64 {
        self.measured_cycles_per_million
            .saturating_sub(self.budget_cycles_per_million)
    }
}

impl fmt::Display for StallBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StallBudget({} budget={} measured={} ok={})",
            self.category,
            self.budget_cycles_per_million,
            self.measured_cycles_per_million,
            self.within_budget
        )
    }
}

// ---------------------------------------------------------------------------
// LayoutPolicyEntry
// ---------------------------------------------------------------------------

/// Binds a layout strategy to its applicable hardware set with
/// pin/rollback recommendations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutPolicyEntry {
    /// Which strategy is governed.
    pub strategy: LayoutStrategy,
    /// Hardware identifiers (e.g., micro-architecture names) where this
    /// strategy is applicable.
    pub applicable_hardware: BTreeSet<String>,
    /// Whether the strategy should be pinned (not auto-rotated).
    pub pin_recommended: bool,
    /// Whether the strategy should be rolled back on regression.
    pub rollback_if_regressed: bool,
    /// Minimum improvement (millionths) to keep the strategy active.
    pub min_improvement_for_keep: u64,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl LayoutPolicyEntry {
    /// Create a new policy entry.
    #[must_use]
    pub fn new(
        strategy: LayoutStrategy,
        applicable_hardware: BTreeSet<String>,
        pin_recommended: bool,
        rollback_if_regressed: bool,
        min_improvement_for_keep: u64,
    ) -> Self {
        let mut buf = Vec::with_capacity(128);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, strategy.as_str());
        for hw in &applicable_hardware {
            append_str(&mut buf, hw);
        }
        append_u64(&mut buf, if pin_recommended { 1 } else { 0 });
        append_u64(&mut buf, if rollback_if_regressed { 1 } else { 0 });
        append_u64(&mut buf, min_improvement_for_keep);
        let content_hash = compute_digest(&buf);

        Self {
            strategy,
            applicable_hardware,
            pin_recommended,
            rollback_if_regressed,
            min_improvement_for_keep,
            content_hash,
        }
    }

    /// How many hardware targets this policy covers.
    #[must_use]
    pub fn hardware_count(&self) -> usize {
        self.applicable_hardware.len()
    }

    /// Whether this policy covers a specific hardware target.
    #[must_use]
    pub fn covers_hardware(&self, target: &str) -> bool {
        self.applicable_hardware.contains(target)
    }
}

impl fmt::Display for LayoutPolicyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LayoutPolicy({} hw={} pin={} rollback={})",
            self.strategy,
            self.applicable_hardware.len(),
            self.pin_recommended,
            self.rollback_if_regressed
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configuration for hardware code-layout governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Maximum allowed stall-budget usage across all categories
    /// (millionths).  Evaluations with total overshoot above this
    /// threshold are rejected.
    pub max_stall_budget_millionths: u64,
    /// Minimum improvement (millionths) required for an alignment entry
    /// to count as beneficial.
    pub min_improvement_millionths: u64,
    /// Maximum alignment waste in bytes across all entries before the
    /// verdict is `AlignmentWasteExceeded`.
    pub max_alignment_waste_bytes: u64,
    /// Minimum hardware coverage ratio (millionths).  The fraction of
    /// known hardware targets covered by at least one policy must meet
    /// this threshold.
    pub min_hardware_coverage: u64,
    /// Required strategies — all must appear in at least one alignment
    /// entry or policy for approval.
    pub required_strategies: BTreeSet<LayoutStrategy>,
    /// Set of all known hardware targets (for coverage computation).
    pub known_hardware: BTreeSet<String>,
    /// Whether to fail-closed (deny) when no entries are submitted.
    pub fail_closed_on_empty: bool,
}

impl GovernanceConfig {
    /// Builder: set required strategies.
    #[must_use]
    pub fn with_required_strategies(mut self, strategies: BTreeSet<LayoutStrategy>) -> Self {
        self.required_strategies = strategies;
        self
    }

    /// Builder: set known hardware targets.
    #[must_use]
    pub fn with_known_hardware(mut self, hw: BTreeSet<String>) -> Self {
        self.known_hardware = hw;
        self
    }

    /// Builder: set max stall budget.
    #[must_use]
    pub fn with_max_stall_budget(mut self, val: u64) -> Self {
        self.max_stall_budget_millionths = val;
        self
    }

    /// Builder: set min improvement.
    #[must_use]
    pub fn with_min_improvement(mut self, val: u64) -> Self {
        self.min_improvement_millionths = val;
        self
    }

    /// Builder: set max alignment waste.
    #[must_use]
    pub fn with_max_alignment_waste(mut self, val: u64) -> Self {
        self.max_alignment_waste_bytes = val;
        self
    }

    /// Builder: set min hardware coverage.
    #[must_use]
    pub fn with_min_hardware_coverage(mut self, val: u64) -> Self {
        self.min_hardware_coverage = val;
        self
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            max_stall_budget_millionths: DEFAULT_MAX_STALL_BUDGET_MILLIONTHS,
            min_improvement_millionths: DEFAULT_MIN_IMPROVEMENT_MILLIONTHS,
            max_alignment_waste_bytes: DEFAULT_MAX_ALIGNMENT_WASTE_BYTES,
            min_hardware_coverage: DEFAULT_MIN_HARDWARE_COVERAGE,
            known_hardware: BTreeSet::new(),
            required_strategies: BTreeSet::new(),
            fail_closed_on_empty: true,
        }
    }
}

impl fmt::Display for GovernanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceConfig(stall_budget={} min_imp={} max_waste={} hw_cov={} req_strat={})",
            self.max_stall_budget_millionths,
            self.min_improvement_millionths,
            self.max_alignment_waste_bytes,
            self.min_hardware_coverage,
            self.required_strategies.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ViolationKind
// ---------------------------------------------------------------------------

/// Specific violation detected during governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Total stall-budget overshoot exceeded the maximum.
    StallBudgetExceeded {
        total_overshoot_millionths: u64,
        threshold_millionths: u64,
    },
    /// Improvement was below the required minimum.
    ImprovementInsufficient {
        measured_millionths: i64,
        threshold_millionths: u64,
    },
    /// Total alignment waste exceeded the maximum.
    AlignmentWasteExceeded {
        total_waste_bytes: u64,
        threshold_bytes: u64,
    },
    /// Hardware coverage was below the required minimum.
    HardwareCoverageGap {
        coverage_millionths: u64,
        threshold_millionths: u64,
        uncovered: BTreeSet<String>,
    },
    /// A required strategy was missing from all entries.
    MissingRequiredStrategy { strategy: LayoutStrategy },
    /// Two or more policies conflict on the same hardware target.
    PolicyConflict {
        hardware: String,
        conflicting_strategies: BTreeSet<LayoutStrategy>,
    },
    /// An alignment entry used an invalid (non-power-of-two) alignment.
    InvalidAlignment {
        function_id: String,
        alignment_bytes: u64,
    },
    /// No entries were submitted and fail-closed is enabled.
    EmptyEvaluation,
}

impl ViolationKind {
    /// Tag for diagnostics.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::StallBudgetExceeded { .. } => "stall_budget_exceeded",
            Self::ImprovementInsufficient { .. } => "improvement_insufficient",
            Self::AlignmentWasteExceeded { .. } => "alignment_waste_exceeded",
            Self::HardwareCoverageGap { .. } => "hardware_coverage_gap",
            Self::MissingRequiredStrategy { .. } => "missing_required_strategy",
            Self::PolicyConflict { .. } => "policy_conflict",
            Self::InvalidAlignment { .. } => "invalid_alignment",
            Self::EmptyEvaluation => "empty_evaluation",
        }
    }
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StallBudgetExceeded {
                total_overshoot_millionths,
                threshold_millionths,
            } => write!(
                f,
                "stall budget exceeded: overshoot={total_overshoot_millionths} threshold={threshold_millionths}"
            ),
            Self::ImprovementInsufficient {
                measured_millionths,
                threshold_millionths,
            } => write!(
                f,
                "improvement insufficient: measured={measured_millionths} threshold={threshold_millionths}"
            ),
            Self::AlignmentWasteExceeded {
                total_waste_bytes,
                threshold_bytes,
            } => write!(
                f,
                "alignment waste exceeded: waste={total_waste_bytes}B threshold={threshold_bytes}B"
            ),
            Self::HardwareCoverageGap {
                coverage_millionths,
                threshold_millionths,
                uncovered,
            } => write!(
                f,
                "hardware coverage gap: coverage={coverage_millionths} threshold={threshold_millionths} uncovered={}",
                uncovered.len()
            ),
            Self::MissingRequiredStrategy { strategy } => {
                write!(f, "missing required strategy: {strategy}")
            }
            Self::PolicyConflict {
                hardware,
                conflicting_strategies,
            } => write!(
                f,
                "policy conflict on {hardware}: {} strategies",
                conflicting_strategies.len()
            ),
            Self::InvalidAlignment {
                function_id,
                alignment_bytes,
            } => write!(
                f,
                "invalid alignment: {function_id} align={alignment_bytes}B"
            ),
            Self::EmptyEvaluation => f.write_str("empty evaluation with fail-closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Top-level verdict from governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks passed.
    Approved,
    /// Stall budget was exceeded.
    StallBudgetExceeded,
    /// Improvement was below the minimum threshold.
    ImprovementInsufficient,
    /// Alignment waste was excessive.
    AlignmentWasteExceeded,
    /// Hardware coverage was below the minimum threshold.
    HardwareCoverageGap,
    /// Policy entries conflict on a hardware target.
    PolicyConflict,
    /// Multiple violations detected simultaneously.
    MultipleViolations { count: usize },
}

impl GovernanceVerdict {
    /// Whether the verdict allows publication.
    #[must_use]
    pub fn allows_publication(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Stable tag for logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::StallBudgetExceeded => "stall_budget_exceeded",
            Self::ImprovementInsufficient => "improvement_insufficient",
            Self::AlignmentWasteExceeded => "alignment_waste_exceeded",
            Self::HardwareCoverageGap => "hardware_coverage_gap",
            Self::PolicyConflict => "policy_conflict",
            Self::MultipleViolations { .. } => "multiple_violations",
        }
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleViolations { count } => {
                write!(f, "multiple_violations(count={count})")
            }
            other => f.write_str(other.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Content-hashed audit receipt for a governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Final verdict.
    pub verdict: GovernanceVerdict,
    /// Security epoch of the evaluation.
    pub epoch: SecurityEpoch,
    /// All alignment entry hashes included in the evaluation.
    pub entry_hashes: Vec<ContentHash>,
    /// All stall budget hashes included.
    pub budget_hashes: Vec<ContentHash>,
    /// All policy entry hashes included.
    pub policy_hashes: Vec<ContentHash>,
    /// Violations found during evaluation.
    pub violations: Vec<ViolationKind>,
    /// Content hash of this receipt (computed from all fields above).
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    /// Whether the receipt records a clean pass.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.verdict.allows_publication() && self.violations.is_empty()
    }

    /// Number of violations in the receipt.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

impl fmt::Display for GovernanceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceReceipt(verdict={} epoch={} entries={} budgets={} policies={} violations={})",
            self.verdict,
            self.epoch.as_u64(),
            self.entry_hashes.len(),
            self.budget_hashes.len(),
            self.policy_hashes.len(),
            self.violations.len()
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Accumulates alignment entries, stall budgets, and layout policies, then
/// evaluates them against a `GovernanceConfig` to produce a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    config: GovernanceConfig,
    epoch: SecurityEpoch,
    alignment_entries: Vec<AlignmentEntry>,
    stall_budgets: Vec<StallBudget>,
    policies: Vec<LayoutPolicyEntry>,
    evaluation_count: u64,
}

impl GovernanceEvaluator {
    /// Create a new evaluator with the given config and epoch.
    #[must_use]
    pub fn new(config: GovernanceConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            epoch,
            alignment_entries: Vec::new(),
            stall_budgets: Vec::new(),
            policies: Vec::new(),
            evaluation_count: 0,
        }
    }

    /// Create an evaluator with default config.
    #[must_use]
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GovernanceConfig::default(), epoch)
    }

    /// Access the configuration.
    #[must_use]
    pub fn config(&self) -> &GovernanceConfig {
        &self.config
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> &SecurityEpoch {
        &self.epoch
    }

    /// Number of evaluations performed.
    #[must_use]
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Number of alignment entries currently loaded.
    #[must_use]
    pub fn alignment_entry_count(&self) -> usize {
        self.alignment_entries.len()
    }

    /// Number of stall budgets currently loaded.
    #[must_use]
    pub fn stall_budget_count(&self) -> usize {
        self.stall_budgets.len()
    }

    /// Number of policy entries currently loaded.
    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Add an alignment entry.
    pub fn add_alignment(&mut self, entry: AlignmentEntry) {
        self.alignment_entries.push(entry);
    }

    /// Add a stall budget.
    pub fn add_stall_budget(&mut self, budget: StallBudget) {
        self.stall_budgets.push(budget);
    }

    /// Add a layout policy.
    pub fn add_policy(&mut self, policy: LayoutPolicyEntry) {
        self.policies.push(policy);
    }

    /// Clear all accumulated entries for a fresh evaluation.
    pub fn clear(&mut self) {
        self.alignment_entries.clear();
        self.stall_budgets.clear();
        self.policies.clear();
    }

    /// Compute total alignment waste across all entries.
    #[must_use]
    pub fn total_waste_bytes(&self) -> u64 {
        self.alignment_entries.iter().map(|e| e.waste_bytes).sum()
    }

    /// Compute mean improvement (millionths) across all alignment entries.
    /// Returns 0 if no entries.
    #[must_use]
    pub fn mean_improvement(&self) -> i64 {
        if self.alignment_entries.is_empty() {
            return 0;
        }
        let sum: i128 = self
            .alignment_entries
            .iter()
            .map(|e| e.improvement_millionths as i128)
            .sum();
        (sum / self.alignment_entries.len() as i128) as i64
    }

    /// Compute the set of hardware targets covered by all policies.
    #[must_use]
    pub fn covered_hardware(&self) -> BTreeSet<String> {
        let mut covered = BTreeSet::new();
        for p in &self.policies {
            for hw in &p.applicable_hardware {
                covered.insert(hw.clone());
            }
        }
        covered
    }

    /// Compute hardware coverage ratio in millionths.
    #[must_use]
    pub fn hardware_coverage_millionths(&self) -> u64 {
        if self.config.known_hardware.is_empty() {
            return FIXED_ONE;
        }
        let covered = self.covered_hardware();
        let covered_count = self
            .config
            .known_hardware
            .iter()
            .filter(|hw| covered.contains(*hw))
            .count() as u64;
        let total = self.config.known_hardware.len() as u64;
        covered_count
            .saturating_mul(FIXED_ONE)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Collect the set of strategies present in alignment entries and policies.
    #[must_use]
    pub fn present_strategies(&self) -> BTreeSet<LayoutStrategy> {
        let mut strategies = BTreeSet::new();
        for e in &self.alignment_entries {
            strategies.insert(e.strategy);
        }
        for p in &self.policies {
            strategies.insert(p.strategy);
        }
        strategies
    }

    /// Detect policy conflicts: two or more policies covering the same
    /// hardware with different strategies where both want `pin_recommended`.
    #[must_use]
    pub fn detect_policy_conflicts(&self) -> Vec<ViolationKind> {
        let mut hw_strategies: std::collections::BTreeMap<String, BTreeSet<LayoutStrategy>> =
            std::collections::BTreeMap::new();
        for p in &self.policies {
            if p.pin_recommended {
                for hw in &p.applicable_hardware {
                    hw_strategies
                        .entry(hw.clone())
                        .or_default()
                        .insert(p.strategy);
                }
            }
        }
        let mut conflicts = Vec::new();
        for (hw, strategies) in &hw_strategies {
            if strategies.len() > 1 {
                conflicts.push(ViolationKind::PolicyConflict {
                    hardware: hw.clone(),
                    conflicting_strategies: strategies.clone(),
                });
            }
        }
        conflicts
    }

    /// Run full governance evaluation and produce a receipt.
    #[must_use]
    pub fn evaluate(&mut self) -> GovernanceReceipt {
        self.evaluation_count += 1;
        let mut violations = Vec::new();

        // 1. Empty check
        let has_entries = !self.alignment_entries.is_empty()
            || !self.stall_budgets.is_empty()
            || !self.policies.is_empty();
        if !has_entries && self.config.fail_closed_on_empty {
            violations.push(ViolationKind::EmptyEvaluation);
        }

        // 2. Invalid alignment check
        for entry in &self.alignment_entries {
            if !entry.is_valid_alignment() {
                violations.push(ViolationKind::InvalidAlignment {
                    function_id: entry.function_id.clone(),
                    alignment_bytes: entry.alignment_bytes,
                });
            }
        }

        // 3. Stall budget check
        let total_overshoot: u64 = self
            .stall_budgets
            .iter()
            .filter(|b| !b.within_budget)
            .map(|b| b.overshoot_millionths.unsigned_abs())
            .sum();
        if total_overshoot > self.config.max_stall_budget_millionths {
            violations.push(ViolationKind::StallBudgetExceeded {
                total_overshoot_millionths: total_overshoot,
                threshold_millionths: self.config.max_stall_budget_millionths,
            });
        }

        // 4. Improvement check
        if !self.alignment_entries.is_empty() {
            let mean = self.mean_improvement();
            if mean < self.config.min_improvement_millionths as i64 {
                violations.push(ViolationKind::ImprovementInsufficient {
                    measured_millionths: mean,
                    threshold_millionths: self.config.min_improvement_millionths,
                });
            }
        }

        // 5. Alignment waste check
        let total_waste = self.total_waste_bytes();
        if total_waste > self.config.max_alignment_waste_bytes {
            violations.push(ViolationKind::AlignmentWasteExceeded {
                total_waste_bytes: total_waste,
                threshold_bytes: self.config.max_alignment_waste_bytes,
            });
        }

        // 6. Hardware coverage check
        if !self.config.known_hardware.is_empty() {
            let coverage = self.hardware_coverage_millionths();
            if coverage < self.config.min_hardware_coverage {
                let covered = self.covered_hardware();
                let uncovered: BTreeSet<String> = self
                    .config
                    .known_hardware
                    .iter()
                    .filter(|hw| !covered.contains(*hw))
                    .cloned()
                    .collect();
                violations.push(ViolationKind::HardwareCoverageGap {
                    coverage_millionths: coverage,
                    threshold_millionths: self.config.min_hardware_coverage,
                    uncovered,
                });
            }
        }

        // 7. Required strategies check
        let present = self.present_strategies();
        for req in &self.config.required_strategies {
            if !present.contains(req) {
                violations.push(ViolationKind::MissingRequiredStrategy { strategy: *req });
            }
        }

        // 8. Policy conflict check
        let conflicts = self.detect_policy_conflicts();
        violations.extend(conflicts);

        // Determine verdict
        let verdict = if violations.is_empty() {
            GovernanceVerdict::Approved
        } else if violations.len() == 1 {
            match &violations[0] {
                ViolationKind::StallBudgetExceeded { .. } => GovernanceVerdict::StallBudgetExceeded,
                ViolationKind::ImprovementInsufficient { .. } => {
                    GovernanceVerdict::ImprovementInsufficient
                }
                ViolationKind::AlignmentWasteExceeded { .. } => {
                    GovernanceVerdict::AlignmentWasteExceeded
                }
                ViolationKind::HardwareCoverageGap { .. } => GovernanceVerdict::HardwareCoverageGap,
                ViolationKind::PolicyConflict { .. } => GovernanceVerdict::PolicyConflict,
                _ => GovernanceVerdict::MultipleViolations {
                    count: violations.len(),
                },
            }
        } else {
            GovernanceVerdict::MultipleViolations {
                count: violations.len(),
            }
        };

        // Build receipt
        let entry_hashes: Vec<ContentHash> = self
            .alignment_entries
            .iter()
            .map(|e| e.content_hash)
            .collect();
        let budget_hashes: Vec<ContentHash> =
            self.stall_budgets.iter().map(|b| b.content_hash).collect();
        let policy_hashes: Vec<ContentHash> =
            self.policies.iter().map(|p| p.content_hash).collect();

        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, COMPONENT);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, verdict.as_str());
        append_u64(&mut buf, entry_hashes.len() as u64);
        for h in &entry_hashes {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, budget_hashes.len() as u64);
        for h in &budget_hashes {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, policy_hashes.len() as u64);
        for h in &policy_hashes {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, violations.len() as u64);
        let content_hash = compute_digest(&buf);

        GovernanceReceipt {
            verdict,
            epoch: self.epoch,
            entry_hashes,
            budget_hashes,
            policy_hashes,
            violations,
            content_hash,
        }
    }
}

impl fmt::Display for GovernanceEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceEvaluator(epoch={} alignments={} budgets={} policies={} evals={})",
            self.epoch.as_u64(),
            self.alignment_entries.len(),
            self.stall_budgets.len(),
            self.policies.len(),
            self.evaluation_count
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute improvement in millionths: (baseline - measured) / baseline.
///
/// Positive means measured is better (fewer stall cycles).
/// Negative means measured is worse (regression).
/// Returns 0 if baseline is zero.
#[must_use]
pub fn compute_improvement(baseline: u64, measured: u64) -> i64 {
    if baseline == 0 {
        return 0;
    }
    let diff = baseline as i128 - measured as i128;
    (diff * FIXED_ONE as i128 / baseline as i128) as i64
}

/// Validate that an alignment value is a power of two and within
/// reasonable bounds (1..=4096 bytes).
#[must_use]
pub fn is_valid_alignment_bytes(val: u64) -> bool {
    val > 0 && val <= 4096 && val.is_power_of_two()
}

/// Compute the coverage ratio (millionths) of a set of covered targets
/// against a set of known targets.
#[must_use]
pub fn compute_coverage_ratio(covered: &BTreeSet<String>, known: &BTreeSet<String>) -> u64 {
    if known.is_empty() {
        return FIXED_ONE;
    }
    let hit = known.iter().filter(|k| covered.contains(*k)).count() as u64;
    let total = known.len() as u64;
    hit.saturating_mul(FIXED_ONE)
        .checked_div(total)
        .unwrap_or(0)
}

/// Check whether a layout strategy should be rolled back given its
/// measured improvement and its policy entry.
#[must_use]
pub fn should_rollback(policy: &LayoutPolicyEntry, measured_improvement_millionths: i64) -> bool {
    if !policy.rollback_if_regressed {
        return false;
    }
    measured_improvement_millionths < 0
        || (measured_improvement_millionths as u64) < policy.min_improvement_for_keep
}

/// Summarise the overall stall-budget health.  Returns the total
/// overshoot in millionths (0 means all budgets are met).
#[must_use]
pub fn total_stall_overshoot(budgets: &[StallBudget]) -> u64 {
    budgets
        .iter()
        .filter(|b| !b.within_budget)
        .map(|b| b.overshoot_millionths.unsigned_abs())
        .sum()
}

/// Check which strategies from a required set are missing.
#[must_use]
pub fn missing_strategies(
    required: &BTreeSet<LayoutStrategy>,
    present: &BTreeSet<LayoutStrategy>,
) -> Vec<LayoutStrategy> {
    required
        .iter()
        .filter(|s| !present.contains(s))
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_entry(
        function_id: &str,
        strategy: LayoutStrategy,
        baseline: u64,
        measured: u64,
        waste: u64,
    ) -> AlignmentEntry {
        AlignmentEntry::new(function_id, strategy, 64, measured, baseline, waste)
    }

    fn make_budget(cat: StallCategory, budget: u64, measured: u64) -> StallBudget {
        StallBudget::new(cat, budget, measured)
    }

    fn make_policy(
        strategy: LayoutStrategy,
        hw: &[&str],
        pin: bool,
        rollback: bool,
    ) -> LayoutPolicyEntry {
        let applicable: BTreeSet<String> = hw.iter().map(|s| s.to_string()).collect();
        LayoutPolicyEntry::new(strategy, applicable, pin, rollback, 10_000)
    }

    fn default_config() -> GovernanceConfig {
        GovernanceConfig::default()
    }

    fn hw_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn strat_set(strats: &[LayoutStrategy]) -> BTreeSet<LayoutStrategy> {
        strats.iter().copied().collect()
    }

    // -- Constants --

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("hardware-code-layout-governance"));
        assert!(SCHEMA_VERSION.contains("v1"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "hardware_code_layout_governance");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.23.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-623C");
    }

    #[test]
    fn test_fixed_one() {
        assert_eq!(FIXED_ONE, 1_000_000);
    }

    // -- LayoutStrategy --

    #[test]
    fn test_layout_strategy_all_count() {
        assert_eq!(LayoutStrategy::ALL.len(), 8);
    }

    #[test]
    fn test_layout_strategy_display() {
        assert_eq!(LayoutStrategy::HotColdSplit.to_string(), "hot_cold_split");
        assert_eq!(
            LayoutStrategy::FunctionReordering.to_string(),
            "function_reordering"
        );
        assert_eq!(LayoutStrategy::LoopAlignment.to_string(), "loop_alignment");
        assert_eq!(
            LayoutStrategy::BranchAlignment.to_string(),
            "branch_alignment"
        );
        assert_eq!(LayoutStrategy::CacheFriendly.to_string(), "cache_friendly");
        assert_eq!(LayoutStrategy::NopPadding.to_string(), "nop_padding");
        assert_eq!(
            LayoutStrategy::CallerCalleeColocation.to_string(),
            "caller_callee_colocation"
        );
        assert_eq!(
            LayoutStrategy::ColdTailCompaction.to_string(),
            "cold_tail_compaction"
        );
    }

    #[test]
    fn test_layout_strategy_introduces_waste() {
        assert!(!LayoutStrategy::HotColdSplit.introduces_waste());
        assert!(!LayoutStrategy::FunctionReordering.introduces_waste());
        assert!(LayoutStrategy::LoopAlignment.introduces_waste());
        assert!(LayoutStrategy::BranchAlignment.introduces_waste());
        assert!(!LayoutStrategy::CacheFriendly.introduces_waste());
        assert!(LayoutStrategy::NopPadding.introduces_waste());
        assert!(!LayoutStrategy::CallerCalleeColocation.introduces_waste());
        assert!(!LayoutStrategy::ColdTailCompaction.introduces_waste());
    }

    #[test]
    fn test_layout_strategy_targets_icache() {
        assert!(LayoutStrategy::HotColdSplit.targets_icache());
        assert!(LayoutStrategy::FunctionReordering.targets_icache());
        assert!(!LayoutStrategy::LoopAlignment.targets_icache());
        assert!(!LayoutStrategy::BranchAlignment.targets_icache());
        assert!(LayoutStrategy::CacheFriendly.targets_icache());
        assert!(!LayoutStrategy::NopPadding.targets_icache());
        assert!(LayoutStrategy::CallerCalleeColocation.targets_icache());
        assert!(LayoutStrategy::ColdTailCompaction.targets_icache());
    }

    #[test]
    fn test_layout_strategy_serde_roundtrip() {
        for s in LayoutStrategy::ALL {
            let j = serde_json::to_string(s).unwrap();
            let back: LayoutStrategy = serde_json::from_str(&j).unwrap();
            assert_eq!(*s, back);
        }
    }

    // -- StallCategory --

    #[test]
    fn test_stall_category_all_count() {
        assert_eq!(StallCategory::ALL.len(), 6);
    }

    #[test]
    fn test_stall_category_display() {
        assert_eq!(
            StallCategory::InstructionCacheMiss.to_string(),
            "instruction_cache_miss"
        );
        assert_eq!(
            StallCategory::BranchMispredict.to_string(),
            "branch_mispredict"
        );
        assert_eq!(StallCategory::DecodeBubble.to_string(), "decode_bubble");
        assert_eq!(
            StallCategory::MicroOpCacheOverflow.to_string(),
            "micro_op_cache_overflow"
        );
        assert_eq!(
            StallCategory::AlignmentPenalty.to_string(),
            "alignment_penalty"
        );
        assert_eq!(StallCategory::FetchBubble.to_string(), "fetch_bubble");
    }

    #[test]
    fn test_stall_category_addressable_by_alignment() {
        assert!(!StallCategory::InstructionCacheMiss.addressable_by_alignment());
        assert!(!StallCategory::BranchMispredict.addressable_by_alignment());
        assert!(StallCategory::DecodeBubble.addressable_by_alignment());
        assert!(!StallCategory::MicroOpCacheOverflow.addressable_by_alignment());
        assert!(StallCategory::AlignmentPenalty.addressable_by_alignment());
        assert!(StallCategory::FetchBubble.addressable_by_alignment());
    }

    #[test]
    fn test_stall_category_addressable_by_placement() {
        assert!(StallCategory::InstructionCacheMiss.addressable_by_placement());
        assert!(!StallCategory::BranchMispredict.addressable_by_placement());
        assert!(!StallCategory::DecodeBubble.addressable_by_placement());
        assert!(StallCategory::MicroOpCacheOverflow.addressable_by_placement());
        assert!(!StallCategory::AlignmentPenalty.addressable_by_placement());
        assert!(!StallCategory::FetchBubble.addressable_by_placement());
    }

    #[test]
    fn test_stall_category_serde_roundtrip() {
        for c in StallCategory::ALL {
            let j = serde_json::to_string(c).unwrap();
            let back: StallCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(*c, back);
        }
    }

    // -- AlignmentEntry --

    #[test]
    fn test_alignment_entry_improvement_positive() {
        let e = make_entry("f1", LayoutStrategy::LoopAlignment, 1000, 800, 64);
        assert!(e.is_improvement());
        assert!(!e.is_regression());
        // (1000 - 800) / 1000 = 0.2 = 200_000 millionths
        assert_eq!(e.improvement_millionths, 200_000);
    }

    #[test]
    fn test_alignment_entry_regression() {
        let e = make_entry("f2", LayoutStrategy::BranchAlignment, 1000, 1200, 32);
        assert!(!e.is_improvement());
        assert!(e.is_regression());
        assert_eq!(e.improvement_millionths, -200_000);
    }

    #[test]
    fn test_alignment_entry_zero_baseline() {
        let e = make_entry("f3", LayoutStrategy::NopPadding, 0, 100, 16);
        assert_eq!(e.improvement_millionths, 0);
    }

    #[test]
    fn test_alignment_entry_valid_alignment() {
        let e = make_entry("f4", LayoutStrategy::LoopAlignment, 100, 50, 8);
        assert!(e.is_valid_alignment()); // 64 bytes
        let e2 = AlignmentEntry::new("f5", LayoutStrategy::LoopAlignment, 3, 100, 50, 8);
        assert!(!e2.is_valid_alignment()); // 3 is not power of two
    }

    #[test]
    fn test_alignment_entry_display() {
        let e = make_entry("fn_a", LayoutStrategy::HotColdSplit, 500, 400, 0);
        let s = e.to_string();
        assert!(s.contains("fn_a"));
        assert!(s.contains("hot_cold_split"));
    }

    #[test]
    fn test_alignment_entry_content_hash_deterministic() {
        let e1 = make_entry("same", LayoutStrategy::NopPadding, 100, 80, 4);
        let e2 = make_entry("same", LayoutStrategy::NopPadding, 100, 80, 4);
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn test_alignment_entry_content_hash_differs() {
        let e1 = make_entry("a", LayoutStrategy::NopPadding, 100, 80, 4);
        let e2 = make_entry("b", LayoutStrategy::NopPadding, 100, 80, 4);
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    // -- StallBudget --

    #[test]
    fn test_stall_budget_within() {
        let b = make_budget(StallCategory::DecodeBubble, 100, 80);
        assert!(b.within_budget);
        assert!(b.overshoot_millionths < 0);
        assert_eq!(b.overshoot_cycles(), 0);
    }

    #[test]
    fn test_stall_budget_exceeded() {
        let b = make_budget(StallCategory::BranchMispredict, 100, 150);
        assert!(!b.within_budget);
        assert!(b.overshoot_millionths > 0);
        // overshoot = (150 - 100) / 100 = 0.5 = 500_000 millionths
        assert_eq!(b.overshoot_millionths, 500_000);
        assert_eq!(b.overshoot_cycles(), 50);
    }

    #[test]
    fn test_stall_budget_zero_budget_zero_measured() {
        let b = make_budget(StallCategory::FetchBubble, 0, 0);
        assert!(b.within_budget);
        assert_eq!(b.overshoot_millionths, 0);
    }

    #[test]
    fn test_stall_budget_zero_budget_nonzero_measured() {
        let b = make_budget(StallCategory::FetchBubble, 0, 50);
        assert!(!b.within_budget);
        assert_eq!(b.overshoot_millionths, FIXED_ONE as i64);
    }

    #[test]
    fn test_stall_budget_exact() {
        let b = make_budget(StallCategory::AlignmentPenalty, 200, 200);
        assert!(b.within_budget);
        assert_eq!(b.overshoot_millionths, 0);
        assert_eq!(b.overshoot_cycles(), 0);
    }

    #[test]
    fn test_stall_budget_display() {
        let b = make_budget(StallCategory::InstructionCacheMiss, 1000, 500);
        let s = b.to_string();
        assert!(s.contains("instruction_cache_miss"));
        assert!(s.contains("1000"));
        assert!(s.contains("500"));
    }

    #[test]
    fn test_stall_budget_content_hash_deterministic() {
        let b1 = make_budget(StallCategory::DecodeBubble, 100, 80);
        let b2 = make_budget(StallCategory::DecodeBubble, 100, 80);
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    // -- LayoutPolicyEntry --

    #[test]
    fn test_policy_entry_hardware_count() {
        let p = make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3", "alderlake", "neoverse_n2"],
            true,
            false,
        );
        assert_eq!(p.hardware_count(), 3);
    }

    #[test]
    fn test_policy_entry_covers_hardware() {
        let p = make_policy(
            LayoutStrategy::LoopAlignment,
            &["zen3", "alderlake"],
            false,
            true,
        );
        assert!(p.covers_hardware("zen3"));
        assert!(p.covers_hardware("alderlake"));
        assert!(!p.covers_hardware("skylake"));
    }

    #[test]
    fn test_policy_entry_display() {
        let p = make_policy(LayoutStrategy::CacheFriendly, &["zen3"], true, true);
        let s = p.to_string();
        assert!(s.contains("cache_friendly"));
        assert!(s.contains("pin=true"));
    }

    #[test]
    fn test_policy_entry_content_hash_deterministic() {
        let p1 = make_policy(LayoutStrategy::NopPadding, &["zen3"], false, false);
        let p2 = make_policy(LayoutStrategy::NopPadding, &["zen3"], false, false);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    // -- GovernanceConfig --

    #[test]
    fn test_governance_config_defaults() {
        let cfg = default_config();
        assert_eq!(
            cfg.max_stall_budget_millionths,
            DEFAULT_MAX_STALL_BUDGET_MILLIONTHS
        );
        assert_eq!(
            cfg.min_improvement_millionths,
            DEFAULT_MIN_IMPROVEMENT_MILLIONTHS
        );
        assert_eq!(
            cfg.max_alignment_waste_bytes,
            DEFAULT_MAX_ALIGNMENT_WASTE_BYTES
        );
        assert_eq!(cfg.min_hardware_coverage, DEFAULT_MIN_HARDWARE_COVERAGE);
        assert!(cfg.required_strategies.is_empty());
        assert!(cfg.known_hardware.is_empty());
        assert!(cfg.fail_closed_on_empty);
    }

    #[test]
    fn test_governance_config_builder() {
        let cfg = default_config()
            .with_max_stall_budget(300_000)
            .with_min_improvement(20_000)
            .with_max_alignment_waste(8192)
            .with_min_hardware_coverage(750_000)
            .with_known_hardware(hw_set(&["zen3", "alderlake"]))
            .with_required_strategies(strat_set(&[LayoutStrategy::HotColdSplit]));
        assert_eq!(cfg.max_stall_budget_millionths, 300_000);
        assert_eq!(cfg.min_improvement_millionths, 20_000);
        assert_eq!(cfg.max_alignment_waste_bytes, 8192);
        assert_eq!(cfg.min_hardware_coverage, 750_000);
        assert_eq!(cfg.known_hardware.len(), 2);
        assert_eq!(cfg.required_strategies.len(), 1);
    }

    #[test]
    fn test_governance_config_display() {
        let cfg = default_config();
        let s = cfg.to_string();
        assert!(s.contains("GovernanceConfig"));
        assert!(s.contains(&DEFAULT_MAX_STALL_BUDGET_MILLIONTHS.to_string()));
    }

    #[test]
    fn test_governance_config_serde_roundtrip() {
        let cfg = default_config()
            .with_known_hardware(hw_set(&["zen3"]))
            .with_required_strategies(strat_set(&[LayoutStrategy::LoopAlignment]));
        let j = serde_json::to_string(&cfg).unwrap();
        let back: GovernanceConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(cfg, back);
    }

    // -- ViolationKind --

    #[test]
    fn test_violation_kind_tags() {
        assert_eq!(
            ViolationKind::StallBudgetExceeded {
                total_overshoot_millionths: 0,
                threshold_millionths: 0
            }
            .tag(),
            "stall_budget_exceeded"
        );
        assert_eq!(
            ViolationKind::ImprovementInsufficient {
                measured_millionths: 0,
                threshold_millionths: 0
            }
            .tag(),
            "improvement_insufficient"
        );
        assert_eq!(
            ViolationKind::AlignmentWasteExceeded {
                total_waste_bytes: 0,
                threshold_bytes: 0
            }
            .tag(),
            "alignment_waste_exceeded"
        );
        assert_eq!(
            ViolationKind::HardwareCoverageGap {
                coverage_millionths: 0,
                threshold_millionths: 0,
                uncovered: BTreeSet::new()
            }
            .tag(),
            "hardware_coverage_gap"
        );
        assert_eq!(
            ViolationKind::MissingRequiredStrategy {
                strategy: LayoutStrategy::NopPadding
            }
            .tag(),
            "missing_required_strategy"
        );
        assert_eq!(
            ViolationKind::PolicyConflict {
                hardware: String::new(),
                conflicting_strategies: BTreeSet::new()
            }
            .tag(),
            "policy_conflict"
        );
        assert_eq!(
            ViolationKind::InvalidAlignment {
                function_id: String::new(),
                alignment_bytes: 0
            }
            .tag(),
            "invalid_alignment"
        );
        assert_eq!(ViolationKind::EmptyEvaluation.tag(), "empty_evaluation");
    }

    #[test]
    fn test_violation_kind_display() {
        let v = ViolationKind::StallBudgetExceeded {
            total_overshoot_millionths: 500_000,
            threshold_millionths: 200_000,
        };
        let s = v.to_string();
        assert!(s.contains("500000"));
        assert!(s.contains("200000"));
    }

    // -- GovernanceVerdict --

    #[test]
    fn test_verdict_allows_publication() {
        assert!(GovernanceVerdict::Approved.allows_publication());
        assert!(!GovernanceVerdict::StallBudgetExceeded.allows_publication());
        assert!(!GovernanceVerdict::ImprovementInsufficient.allows_publication());
        assert!(!GovernanceVerdict::AlignmentWasteExceeded.allows_publication());
        assert!(!GovernanceVerdict::HardwareCoverageGap.allows_publication());
        assert!(!GovernanceVerdict::PolicyConflict.allows_publication());
        assert!(!GovernanceVerdict::MultipleViolations { count: 2 }.allows_publication());
    }

    #[test]
    fn test_verdict_as_str() {
        assert_eq!(GovernanceVerdict::Approved.as_str(), "approved");
        assert_eq!(
            GovernanceVerdict::StallBudgetExceeded.as_str(),
            "stall_budget_exceeded"
        );
        assert_eq!(
            GovernanceVerdict::PolicyConflict.as_str(),
            "policy_conflict"
        );
        assert_eq!(
            GovernanceVerdict::MultipleViolations { count: 3 }.as_str(),
            "multiple_violations"
        );
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
        assert_eq!(
            GovernanceVerdict::MultipleViolations { count: 5 }.to_string(),
            "multiple_violations(count=5)"
        );
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        let verdicts = vec![
            GovernanceVerdict::Approved,
            GovernanceVerdict::StallBudgetExceeded,
            GovernanceVerdict::ImprovementInsufficient,
            GovernanceVerdict::AlignmentWasteExceeded,
            GovernanceVerdict::HardwareCoverageGap,
            GovernanceVerdict::PolicyConflict,
            GovernanceVerdict::MultipleViolations { count: 2 },
        ];
        for v in &verdicts {
            let j = serde_json::to_string(v).unwrap();
            let back: GovernanceVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- GovernanceReceipt --

    #[test]
    fn test_receipt_is_clean() {
        let receipt = GovernanceReceipt {
            verdict: GovernanceVerdict::Approved,
            epoch: ep(1),
            entry_hashes: vec![],
            budget_hashes: vec![],
            policy_hashes: vec![],
            violations: vec![],
            content_hash: compute_digest(b"test"),
        };
        assert!(receipt.is_clean());
        assert_eq!(receipt.violation_count(), 0);
    }

    #[test]
    fn test_receipt_not_clean_with_violations() {
        let receipt = GovernanceReceipt {
            verdict: GovernanceVerdict::StallBudgetExceeded,
            epoch: ep(2),
            entry_hashes: vec![],
            budget_hashes: vec![],
            policy_hashes: vec![],
            violations: vec![ViolationKind::EmptyEvaluation],
            content_hash: compute_digest(b"test"),
        };
        assert!(!receipt.is_clean());
        assert_eq!(receipt.violation_count(), 1);
    }

    #[test]
    fn test_receipt_display() {
        let receipt = GovernanceReceipt {
            verdict: GovernanceVerdict::Approved,
            epoch: ep(42),
            entry_hashes: vec![compute_digest(b"a")],
            budget_hashes: vec![],
            policy_hashes: vec![compute_digest(b"b")],
            violations: vec![],
            content_hash: compute_digest(b"receipt"),
        };
        let s = receipt.to_string();
        assert!(s.contains("approved"));
        assert!(s.contains("42"));
        assert!(s.contains("entries=1"));
        assert!(s.contains("policies=1"));
    }

    // -- GovernanceEvaluator --

    #[test]
    fn test_evaluator_empty_fail_closed() {
        let mut eval = GovernanceEvaluator::with_defaults(ep(1));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert!(
            receipt
                .violations
                .iter()
                .any(|v| matches!(v, ViolationKind::EmptyEvaluation))
        );
    }

    #[test]
    fn test_evaluator_empty_not_fail_closed() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        let receipt = eval.evaluate();
        assert!(receipt.is_clean());
    }

    #[test]
    fn test_evaluator_approved_simple() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 50_000,
            max_alignment_waste_bytes: 1000,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(5));
        // 100 baseline -> 50 measured = 50% improvement
        eval.add_alignment(make_entry(
            "fn_hot",
            LayoutStrategy::LoopAlignment,
            100,
            50,
            32,
        ));
        eval.add_stall_budget(make_budget(StallCategory::DecodeBubble, 500, 300));
        let receipt = eval.evaluate();
        assert!(receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
        assert_eq!(receipt.entry_hashes.len(), 1);
        assert_eq!(receipt.budget_hashes.len(), 1);
    }

    #[test]
    fn test_evaluator_stall_budget_exceeded() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            max_stall_budget_millionths: 100_000,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(3));
        // budget 100 vs measured 300 => overshoot = 200%
        eval.add_stall_budget(make_budget(StallCategory::BranchMispredict, 100, 300));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::StallBudgetExceeded);
    }

    #[test]
    fn test_evaluator_improvement_insufficient() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 300_000, // Need 30% improvement
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(4));
        // 100 -> 90 = 10% improvement, not enough
        eval.add_alignment(make_entry("fn1", LayoutStrategy::HotColdSplit, 100, 90, 0));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::ImprovementInsufficient);
    }

    #[test]
    fn test_evaluator_alignment_waste_exceeded() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            max_alignment_waste_bytes: 100,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(6));
        eval.add_alignment(make_entry("f1", LayoutStrategy::NopPadding, 100, 50, 80));
        eval.add_alignment(make_entry("f2", LayoutStrategy::NopPadding, 100, 50, 80));
        // total waste = 160 > 100
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::AlignmentWasteExceeded);
    }

    #[test]
    fn test_evaluator_hardware_coverage_gap() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            min_hardware_coverage: 800_000, // 80%
            known_hardware: hw_set(&["zen3", "alderlake", "neoverse_n2", "apple_m2"]),
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(7));
        // only cover zen3 => 25% coverage
        eval.add_policy(make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3"],
            false,
            false,
        ));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::HardwareCoverageGap);
        // Check uncovered set
        let gap = receipt
            .violations
            .iter()
            .find(|v| matches!(v, ViolationKind::HardwareCoverageGap { .. }));
        if let Some(ViolationKind::HardwareCoverageGap { uncovered, .. }) = gap {
            assert_eq!(uncovered.len(), 3);
            assert!(uncovered.contains("alderlake"));
            assert!(uncovered.contains("neoverse_n2"));
            assert!(uncovered.contains("apple_m2"));
        } else {
            panic!("expected HardwareCoverageGap violation");
        }
    }

    #[test]
    fn test_evaluator_missing_required_strategy() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            required_strategies: strat_set(&[
                LayoutStrategy::HotColdSplit,
                LayoutStrategy::LoopAlignment,
            ]),
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(8));
        // Only provide HotColdSplit
        eval.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert!(receipt.violations.iter().any(|v| matches!(
            v,
            ViolationKind::MissingRequiredStrategy {
                strategy: LayoutStrategy::LoopAlignment
            }
        )));
    }

    #[test]
    fn test_evaluator_policy_conflict() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(9));
        // Two pinned policies covering the same hardware
        eval.add_policy(make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3"],
            true,
            false,
        ));
        eval.add_policy(make_policy(
            LayoutStrategy::FunctionReordering,
            &["zen3"],
            true,
            false,
        ));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert_eq!(receipt.verdict, GovernanceVerdict::PolicyConflict);
    }

    #[test]
    fn test_evaluator_multiple_violations() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 500_000, // 50%
            max_alignment_waste_bytes: 10,
            max_stall_budget_millionths: 10_000,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(10));
        // Low improvement + high waste + stall exceeded
        eval.add_alignment(make_entry("f1", LayoutStrategy::NopPadding, 100, 95, 500));
        eval.add_stall_budget(make_budget(StallCategory::DecodeBubble, 10, 100));
        let receipt = eval.evaluate();
        assert!(!receipt.is_clean());
        assert!(matches!(
            receipt.verdict,
            GovernanceVerdict::MultipleViolations { count } if count >= 2
        ));
    }

    #[test]
    fn test_evaluator_invalid_alignment() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(11));
        // alignment_bytes = 3, not a power of two
        eval.add_alignment(AlignmentEntry::new(
            "f_bad",
            LayoutStrategy::LoopAlignment,
            3,
            100,
            200,
            0,
        ));
        let receipt = eval.evaluate();
        assert!(receipt.violations.iter().any(|v| matches!(
            v,
            ViolationKind::InvalidAlignment { function_id, alignment_bytes }
                if function_id == "f_bad" && *alignment_bytes == 3
        )));
    }

    #[test]
    fn test_evaluator_clear() {
        let mut eval = GovernanceEvaluator::with_defaults(ep(1));
        eval.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        eval.add_stall_budget(make_budget(StallCategory::DecodeBubble, 100, 50));
        eval.add_policy(make_policy(
            LayoutStrategy::NopPadding,
            &["zen3"],
            false,
            false,
        ));
        assert_eq!(eval.alignment_entry_count(), 1);
        assert_eq!(eval.stall_budget_count(), 1);
        assert_eq!(eval.policy_count(), 1);
        eval.clear();
        assert_eq!(eval.alignment_entry_count(), 0);
        assert_eq!(eval.stall_budget_count(), 0);
        assert_eq!(eval.policy_count(), 0);
    }

    #[test]
    fn test_evaluator_evaluation_count() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        assert_eq!(eval.evaluation_count(), 0);
        let _ = eval.evaluate();
        assert_eq!(eval.evaluation_count(), 1);
        let _ = eval.evaluate();
        assert_eq!(eval.evaluation_count(), 2);
    }

    #[test]
    fn test_evaluator_receipt_content_hash_deterministic() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval1 = GovernanceEvaluator::new(cfg.clone(), ep(1));
        eval1.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        let r1 = eval1.evaluate();

        let mut eval2 = GovernanceEvaluator::new(cfg, ep(1));
        eval2.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        let r2 = eval2.evaluate();

        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_evaluator_covered_hardware() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        eval.add_policy(make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3", "alderlake"],
            false,
            false,
        ));
        eval.add_policy(make_policy(
            LayoutStrategy::LoopAlignment,
            &["alderlake", "neoverse_n2"],
            false,
            false,
        ));
        let covered = eval.covered_hardware();
        assert_eq!(covered.len(), 3);
        assert!(covered.contains("zen3"));
        assert!(covered.contains("alderlake"));
        assert!(covered.contains("neoverse_n2"));
    }

    #[test]
    fn test_evaluator_present_strategies() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        eval.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        eval.add_policy(make_policy(
            LayoutStrategy::LoopAlignment,
            &["zen3"],
            false,
            false,
        ));
        let present = eval.present_strategies();
        assert_eq!(present.len(), 2);
        assert!(present.contains(&LayoutStrategy::HotColdSplit));
        assert!(present.contains(&LayoutStrategy::LoopAlignment));
    }

    #[test]
    fn test_evaluator_mean_improvement() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        // 50% improvement
        eval.add_alignment(make_entry("f1", LayoutStrategy::HotColdSplit, 100, 50, 0));
        // 0% improvement
        eval.add_alignment(make_entry("f2", LayoutStrategy::LoopAlignment, 100, 100, 0));
        // Mean = (500_000 + 0) / 2 = 250_000
        assert_eq!(eval.mean_improvement(), 250_000);
    }

    #[test]
    fn test_evaluator_mean_improvement_empty() {
        let eval = GovernanceEvaluator::with_defaults(ep(1));
        assert_eq!(eval.mean_improvement(), 0);
    }

    #[test]
    fn test_evaluator_display() {
        let eval = GovernanceEvaluator::with_defaults(ep(42));
        let s = eval.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("GovernanceEvaluator"));
    }

    #[test]
    fn test_evaluator_no_conflict_different_hardware() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        eval.add_policy(make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3"],
            true,
            false,
        ));
        eval.add_policy(make_policy(
            LayoutStrategy::FunctionReordering,
            &["alderlake"],
            true,
            false,
        ));
        let receipt = eval.evaluate();
        assert!(receipt.is_clean());
    }

    #[test]
    fn test_evaluator_no_conflict_unpinned() {
        let cfg = GovernanceConfig {
            fail_closed_on_empty: false,
            min_improvement_millionths: 0,
            ..Default::default()
        };
        let mut eval = GovernanceEvaluator::new(cfg, ep(1));
        // Same hardware, different strategies, but neither is pinned
        eval.add_policy(make_policy(
            LayoutStrategy::HotColdSplit,
            &["zen3"],
            false,
            false,
        ));
        eval.add_policy(make_policy(
            LayoutStrategy::FunctionReordering,
            &["zen3"],
            false,
            false,
        ));
        let receipt = eval.evaluate();
        // No conflict because neither is pinned
        assert!(receipt.is_clean());
    }

    // -- Core functions --

    #[test]
    fn test_compute_improvement_positive() {
        // baseline 1000, measured 800 => 20% = 200_000
        assert_eq!(compute_improvement(1000, 800), 200_000);
    }

    #[test]
    fn test_compute_improvement_regression() {
        // baseline 1000, measured 1200 => -20% = -200_000
        assert_eq!(compute_improvement(1000, 1200), -200_000);
    }

    #[test]
    fn test_compute_improvement_zero_baseline() {
        assert_eq!(compute_improvement(0, 100), 0);
    }

    #[test]
    fn test_compute_improvement_identical() {
        assert_eq!(compute_improvement(500, 500), 0);
    }

    #[test]
    fn test_is_valid_alignment_bytes() {
        assert!(is_valid_alignment_bytes(1));
        assert!(is_valid_alignment_bytes(2));
        assert!(is_valid_alignment_bytes(4));
        assert!(is_valid_alignment_bytes(64));
        assert!(is_valid_alignment_bytes(4096));
        assert!(!is_valid_alignment_bytes(0));
        assert!(!is_valid_alignment_bytes(3));
        assert!(!is_valid_alignment_bytes(5));
        assert!(!is_valid_alignment_bytes(8192));
    }

    #[test]
    fn test_compute_coverage_ratio_empty_known() {
        let covered = hw_set(&["zen3"]);
        let known = BTreeSet::new();
        assert_eq!(compute_coverage_ratio(&covered, &known), FIXED_ONE);
    }

    #[test]
    fn test_compute_coverage_ratio_full() {
        let both = hw_set(&["zen3", "alderlake"]);
        assert_eq!(compute_coverage_ratio(&both, &both), FIXED_ONE);
    }

    #[test]
    fn test_compute_coverage_ratio_half() {
        let covered = hw_set(&["zen3"]);
        let known = hw_set(&["zen3", "alderlake"]);
        assert_eq!(compute_coverage_ratio(&covered, &known), 500_000);
    }

    #[test]
    fn test_compute_coverage_ratio_none() {
        let covered = BTreeSet::new();
        let known = hw_set(&["zen3"]);
        assert_eq!(compute_coverage_ratio(&covered, &known), 0);
    }

    #[test]
    fn test_should_rollback_no_flag() {
        let p = make_policy(LayoutStrategy::HotColdSplit, &["zen3"], false, false);
        assert!(!should_rollback(&p, -100_000));
    }

    #[test]
    fn test_should_rollback_regression() {
        let p = make_policy(LayoutStrategy::HotColdSplit, &["zen3"], false, true);
        assert!(should_rollback(&p, -50_000));
    }

    #[test]
    fn test_should_rollback_below_keep_threshold() {
        let p = make_policy(LayoutStrategy::HotColdSplit, &["zen3"], false, true);
        // min_improvement_for_keep = 10_000 (from make_policy)
        // measured = 5_000 < 10_000 => rollback
        assert!(should_rollback(&p, 5_000));
    }

    #[test]
    fn test_should_rollback_above_keep_threshold() {
        let p = make_policy(LayoutStrategy::HotColdSplit, &["zen3"], false, true);
        // measured = 20_000 > 10_000 => no rollback
        assert!(!should_rollback(&p, 20_000));
    }

    #[test]
    fn test_total_stall_overshoot_all_within() {
        let budgets = vec![
            make_budget(StallCategory::DecodeBubble, 100, 50),
            make_budget(StallCategory::FetchBubble, 200, 100),
        ];
        assert_eq!(total_stall_overshoot(&budgets), 0);
    }

    #[test]
    fn test_total_stall_overshoot_some_exceeded() {
        let budgets = vec![
            make_budget(StallCategory::DecodeBubble, 100, 50),
            make_budget(StallCategory::BranchMispredict, 100, 200),
        ];
        // second budget: overshoot = (200 - 100)/100 = 100% = 1_000_000
        assert_eq!(total_stall_overshoot(&budgets), 1_000_000);
    }

    #[test]
    fn test_missing_strategies_none_missing() {
        let required = strat_set(&[LayoutStrategy::HotColdSplit]);
        let present = strat_set(&[LayoutStrategy::HotColdSplit, LayoutStrategy::LoopAlignment]);
        assert!(missing_strategies(&required, &present).is_empty());
    }

    #[test]
    fn test_missing_strategies_some_missing() {
        let required = strat_set(&[LayoutStrategy::HotColdSplit, LayoutStrategy::NopPadding]);
        let present = strat_set(&[LayoutStrategy::HotColdSplit]);
        let missing = missing_strategies(&required, &present);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], LayoutStrategy::NopPadding);
    }
}
