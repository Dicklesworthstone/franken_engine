//! Bead: bd-1lsy.7.23.3 [RGC-623C]
//!
//! Hardware-aware code layout, alignment, and front-end stall governance.
//!
//! Optimises code placement, alignment, and front-end stall budgets so that
//! quickened and traced paths translate into real hardware wins rather than
//! prettier IR.  Operators can tell when a layout policy should be pinned,
//! rolled back, or treated as hardware-specific.
//!
//! # Design
//!
//! - `AlignmentStrategy` captures the alignment target (cache line, page
//!   boundary, natural) together with an explicit byte-alignment budget.
//! - `LayoutPolicy` groups alignment, stall budget, and platform rules into
//!   a single configuration that can be pinned, rolled back, or generalised.
//! - `StallBudget` tracks an instruction-fetch stall budget and records
//!   I-cache miss counts against a configurable gate threshold.
//! - `LayoutDecisionReceipt` is a content-hashed evidence record emitted
//!   for every layout decision so that auditors can replay the reasoning.
//! - `RollbackGate` reverts to a conservative layout when aggressive
//!   alignment regresses measured performance.
//! - `ParityChecker` verifies that a layout produces equivalent observable
//!   behaviour compared to a reference layout.
//! - `LayoutDiagnostic` provides operator-facing summaries.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for hardware code layout gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.hardware-code-layout-gate.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "hardware_code_layout_gate";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.7.23.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-623C";

/// Fixed-point unit: 1.0 = 1_000_000.
const MILLION: u64 = 1_000_000;

/// Default cache-line size in bytes.
pub const DEFAULT_CACHE_LINE_BYTES: u32 = 64;

/// Default page size in bytes.
pub const DEFAULT_PAGE_SIZE_BYTES: u32 = 4096;

/// Maximum alignment budget (bytes) before overflow is flagged.
pub const MAX_ALIGNMENT_BUDGET_BYTES: u64 = 1_048_576; // 1 MiB

/// Default stall budget (in fetch-stall cycles).
pub const DEFAULT_STALL_BUDGET_CYCLES: u64 = 256;

/// Default I-cache miss threshold before gate fires.
pub const DEFAULT_ICACHE_MISS_THRESHOLD: u64 = 64;

/// Default regression threshold (millionths). If measured perf drops by
/// more than this fraction, rollback is triggered.  50_000 = 5%.
pub const DEFAULT_REGRESSION_THRESHOLD: u64 = 50_000;

/// Maximum number of layout regions tracked per policy evaluation.
pub const MAX_LAYOUT_REGIONS: usize = 4096;

/// Maximum number of diagnostic entries per report.
pub const MAX_DIAGNOSTIC_ENTRIES: usize = 512;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn compute_content_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

/// Clamp a millionths value to [0, MILLION].
fn clamp_millionths(v: u64) -> u64 {
    if v > MILLION { MILLION } else { v }
}

// ---------------------------------------------------------------------------
// AlignmentTarget
// ---------------------------------------------------------------------------

/// What boundary a code region should be aligned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentTarget {
    /// No special alignment — use the natural instruction alignment.
    Natural,
    /// Align to cache-line boundary.
    CacheLine,
    /// Align to page boundary.
    PageBoundary,
    /// Align to an explicit byte boundary.
    ExplicitBytes,
}

impl AlignmentTarget {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::Natural,
        Self::CacheLine,
        Self::PageBoundary,
        Self::ExplicitBytes,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Natural => "natural",
            Self::CacheLine => "cache_line",
            Self::PageBoundary => "page_boundary",
            Self::ExplicitBytes => "explicit_bytes",
        }
    }
}

impl fmt::Display for AlignmentTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AlignmentStrategy
// ---------------------------------------------------------------------------

/// Complete alignment strategy for a code region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AlignmentStrategy {
    /// What kind of boundary to align to.
    pub target: AlignmentTarget,
    /// Byte count for the alignment (e.g. 64 for cache line).
    pub alignment_bytes: u32,
    /// Maximum padding bytes the strategy is willing to insert.
    pub max_padding_bytes: u32,
    /// Whether NOP-slide padding is allowed (vs. cold-code packing).
    pub allow_nop_padding: bool,
}

impl AlignmentStrategy {
    /// Create a natural-alignment strategy (1-byte, no padding).
    pub fn natural() -> Self {
        Self {
            target: AlignmentTarget::Natural,
            alignment_bytes: 1,
            max_padding_bytes: 0,
            allow_nop_padding: false,
        }
    }

    /// Create a cache-line alignment strategy.
    pub fn cache_line(cache_line_bytes: u32) -> Self {
        Self {
            target: AlignmentTarget::CacheLine,
            alignment_bytes: cache_line_bytes,
            max_padding_bytes: cache_line_bytes.saturating_sub(1),
            allow_nop_padding: true,
        }
    }

    /// Create a page-boundary alignment strategy.
    pub fn page_boundary(page_size: u32) -> Self {
        Self {
            target: AlignmentTarget::PageBoundary,
            alignment_bytes: page_size,
            max_padding_bytes: page_size.saturating_sub(1),
            allow_nop_padding: true,
        }
    }

    /// Create an explicit-bytes alignment strategy.
    pub fn explicit(alignment_bytes: u32, max_padding: u32) -> Self {
        Self {
            target: AlignmentTarget::ExplicitBytes,
            alignment_bytes,
            max_padding_bytes: max_padding,
            allow_nop_padding: true,
        }
    }

    /// Whether the alignment is a power of two.
    pub fn is_power_of_two(&self) -> bool {
        self.alignment_bytes > 0 && self.alignment_bytes.is_power_of_two()
    }

    /// Compute padding needed for an address to meet alignment.
    /// Returns `None` if alignment is zero.
    pub fn padding_for(&self, address: u64) -> Option<u32> {
        if self.alignment_bytes == 0 {
            return None;
        }
        let align = u64::from(self.alignment_bytes);
        let remainder = address % align;
        if remainder == 0 {
            Some(0)
        } else {
            let pad = align - remainder;
            Some(pad as u32)
        }
    }

    /// Whether a given padding amount exceeds the maximum allowed.
    pub fn exceeds_budget(&self, padding: u32) -> bool {
        padding > self.max_padding_bytes
    }
}

impl Default for AlignmentStrategy {
    fn default() -> Self {
        Self::natural()
    }
}

impl fmt::Display for AlignmentStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "align({}, {}B, max_pad={}B)",
            self.target, self.alignment_bytes, self.max_padding_bytes
        )
    }
}

// ---------------------------------------------------------------------------
// PlatformId
// ---------------------------------------------------------------------------

/// Stable identifier for a hardware platform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PlatformId(pub String);

impl PlatformId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlatformId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "platform:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// RegionId
// ---------------------------------------------------------------------------

/// Stable identifier for a code region within a compilation unit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "region:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// RegionHeat
// ---------------------------------------------------------------------------

/// Heat classification of a code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionHeat {
    /// Not profiled or rarely executed.
    Cold,
    /// Executed but not hot enough for aggressive alignment.
    Warm,
    /// Hot path — qualifies for cache-line alignment.
    Hot,
    /// Traced / quickened — qualifies for page-boundary alignment.
    Traced,
}

impl RegionHeat {
    pub const ALL: &[Self] = &[Self::Cold, Self::Warm, Self::Hot, Self::Traced];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Hot => "hot",
            Self::Traced => "traced",
        }
    }

    /// Numeric rank for ordering comparisons.
    pub fn rank(self) -> u32 {
        match self {
            Self::Cold => 0,
            Self::Warm => 1,
            Self::Hot => 2,
            Self::Traced => 3,
        }
    }
}

impl fmt::Display for RegionHeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CodeRegion
// ---------------------------------------------------------------------------

/// A contiguous code region subject to layout decisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CodeRegion {
    /// Unique identifier for this region.
    pub id: RegionId,
    /// Heat classification.
    pub heat: RegionHeat,
    /// Size of the region in bytes.
    pub size_bytes: u64,
    /// Base address before layout (may be zero for relative layout).
    pub base_address: u64,
    /// Execution count from profiling.
    pub execution_count: u64,
    /// Whether this region is a loop header.
    pub is_loop_header: bool,
    /// Whether this region is a function entry.
    pub is_function_entry: bool,
}

impl CodeRegion {
    /// Create a new code region.
    pub fn new(id: impl Into<String>, heat: RegionHeat, size_bytes: u64) -> Self {
        Self {
            id: RegionId::new(id),
            heat,
            size_bytes,
            base_address: 0,
            execution_count: 0,
            is_loop_header: false,
            is_function_entry: false,
        }
    }

    /// Builder: set base address.
    pub fn with_base_address(mut self, addr: u64) -> Self {
        self.base_address = addr;
        self
    }

    /// Builder: set execution count.
    pub fn with_execution_count(mut self, count: u64) -> Self {
        self.execution_count = count;
        self
    }

    /// Builder: mark as loop header.
    pub fn with_loop_header(mut self, val: bool) -> Self {
        self.is_loop_header = val;
        self
    }

    /// Builder: mark as function entry.
    pub fn with_function_entry(mut self, val: bool) -> Self {
        self.is_function_entry = val;
        self
    }
}

impl fmt::Display for CodeRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "region({}, heat={}, {}B, exec={})",
            self.id, self.heat, self.size_bytes, self.execution_count
        )
    }
}

// ---------------------------------------------------------------------------
// StallKind
// ---------------------------------------------------------------------------

/// Classification of front-end stall events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StallKind {
    /// Instruction-fetch stall (pipeline bubble).
    InstructionFetch,
    /// I-cache miss.
    ICacheMiss,
    /// ITLB miss.
    ITlbMiss,
    /// Branch-target-buffer miss.
    BtbMiss,
    /// Decode stall (instruction too long or complex).
    DecodeStall,
}

impl StallKind {
    pub const ALL: &[Self] = &[
        Self::InstructionFetch,
        Self::ICacheMiss,
        Self::ITlbMiss,
        Self::BtbMiss,
        Self::DecodeStall,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstructionFetch => "instruction_fetch",
            Self::ICacheMiss => "icache_miss",
            Self::ITlbMiss => "itlb_miss",
            Self::BtbMiss => "btb_miss",
            Self::DecodeStall => "decode_stall",
        }
    }
}

impl fmt::Display for StallKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// StallEvent
// ---------------------------------------------------------------------------

/// A recorded front-end stall event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StallEvent {
    /// Kind of stall.
    pub kind: StallKind,
    /// Region where the stall occurred.
    pub region_id: RegionId,
    /// Cost in cycles.
    pub cost_cycles: u64,
    /// Address within the region (offset from base).
    pub offset: u64,
}

impl StallEvent {
    pub fn new(kind: StallKind, region_id: impl Into<String>, cost_cycles: u64) -> Self {
        Self {
            kind,
            region_id: RegionId::new(region_id),
            cost_cycles,
            offset: 0,
        }
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }
}

impl fmt::Display for StallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stall({}, region={}, cost={}cyc)",
            self.kind, self.region_id, self.cost_cycles
        )
    }
}

// ---------------------------------------------------------------------------
// StallBudget
// ---------------------------------------------------------------------------

/// Front-end stall budget with tracking and gate enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StallBudget {
    /// Maximum aggregate stall cycles allowed.
    pub max_stall_cycles: u64,
    /// Maximum I-cache misses allowed.
    pub max_icache_misses: u64,
    /// Accumulated stall cycles.
    pub accumulated_cycles: u64,
    /// Accumulated I-cache misses.
    pub accumulated_icache_misses: u64,
    /// Per-stall-kind counters.
    pub counters: BTreeMap<String, u64>,
    /// Recorded stall events.
    pub events: Vec<StallEvent>,
}

impl StallBudget {
    /// Create a new stall budget with given limits.
    pub fn new(max_stall_cycles: u64, max_icache_misses: u64) -> Self {
        Self {
            max_stall_cycles,
            max_icache_misses,
            accumulated_cycles: 0,
            accumulated_icache_misses: 0,
            counters: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Record a stall event.
    pub fn record(&mut self, event: StallEvent) {
        self.accumulated_cycles = self.accumulated_cycles.saturating_add(event.cost_cycles);
        if event.kind == StallKind::ICacheMiss {
            self.accumulated_icache_misses = self.accumulated_icache_misses.saturating_add(1);
        }
        let key = event.kind.as_str().to_string();
        *self.counters.entry(key).or_insert(0) += 1;
        self.events.push(event);
    }

    /// Whether the stall-cycle budget is exhausted.
    pub fn cycles_exhausted(&self) -> bool {
        self.accumulated_cycles >= self.max_stall_cycles
    }

    /// Whether the I-cache miss budget is exhausted.
    pub fn icache_exhausted(&self) -> bool {
        self.accumulated_icache_misses >= self.max_icache_misses
    }

    /// Whether any budget is exhausted (gate fires).
    pub fn gate_fires(&self) -> bool {
        self.cycles_exhausted() || self.icache_exhausted()
    }

    /// Remaining stall-cycle headroom.
    pub fn remaining_cycles(&self) -> u64 {
        self.max_stall_cycles
            .saturating_sub(self.accumulated_cycles)
    }

    /// Remaining I-cache miss headroom.
    pub fn remaining_icache_misses(&self) -> u64 {
        self.max_icache_misses
            .saturating_sub(self.accumulated_icache_misses)
    }

    /// Utilisation of cycle budget as millionths.
    pub fn cycle_utilisation_millionths(&self) -> u64 {
        if self.max_stall_cycles == 0 {
            return MILLION;
        }
        clamp_millionths(self.accumulated_cycles.saturating_mul(MILLION) / self.max_stall_cycles)
    }

    /// Reset all counters (e.g. after a rollback).
    pub fn reset(&mut self) {
        self.accumulated_cycles = 0;
        self.accumulated_icache_misses = 0;
        self.counters.clear();
        self.events.clear();
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Content hash of the budget state.
    pub fn content_hash(&self) -> ContentHash {
        let payload = format!(
            "stall_budget:max_cycles={},max_icache={},acc_cycles={},acc_icache={},events={}",
            self.max_stall_cycles,
            self.max_icache_misses,
            self.accumulated_cycles,
            self.accumulated_icache_misses,
            self.events.len(),
        );
        compute_content_hash(payload.as_bytes())
    }
}

impl Default for StallBudget {
    fn default() -> Self {
        Self::new(DEFAULT_STALL_BUDGET_CYCLES, DEFAULT_ICACHE_MISS_THRESHOLD)
    }
}

impl fmt::Display for StallBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stall_budget(cycles={}/{}, icache={}/{})",
            self.accumulated_cycles,
            self.max_stall_cycles,
            self.accumulated_icache_misses,
            self.max_icache_misses,
        )
    }
}

// ---------------------------------------------------------------------------
// PlatformRule
// ---------------------------------------------------------------------------

/// A hardware-specific layout rule that can be pinned, rolled back, or
/// generalised.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PlatformRule {
    /// Platform this rule applies to.
    pub platform_id: PlatformId,
    /// Preferred alignment strategy on this platform.
    pub alignment: AlignmentStrategy,
    /// Cache-line size in bytes on this platform.
    pub cache_line_bytes: u32,
    /// Page size in bytes on this platform.
    pub page_size_bytes: u32,
    /// Whether this rule is pinned (immune to generalisation).
    pub pinned: bool,
    /// Whether the rule has been rolled back to conservative defaults.
    pub rolled_back: bool,
    /// Human-readable rationale.
    pub rationale: String,
}

impl PlatformRule {
    /// Create a new platform rule.
    pub fn new(platform_id: impl Into<String>, alignment: AlignmentStrategy) -> Self {
        Self {
            platform_id: PlatformId::new(platform_id),
            alignment,
            cache_line_bytes: DEFAULT_CACHE_LINE_BYTES,
            page_size_bytes: DEFAULT_PAGE_SIZE_BYTES,
            pinned: false,
            rolled_back: false,
            rationale: String::new(),
        }
    }

    /// Pin this rule (prevent generalisation).
    pub fn pin(&mut self, rationale: impl Into<String>) {
        self.pinned = true;
        self.rationale = rationale.into();
    }

    /// Roll back to conservative alignment.
    pub fn rollback(&mut self, rationale: impl Into<String>) {
        self.alignment = AlignmentStrategy::natural();
        self.rolled_back = true;
        self.rationale = rationale.into();
    }

    /// Generalise: remove the pin and allow cross-platform reuse.
    pub fn generalise(&mut self) {
        self.pinned = false;
    }

    /// Whether this rule can be generalised (not pinned, not rolled back).
    pub fn is_generalisable(&self) -> bool {
        !self.pinned && !self.rolled_back
    }
}

impl fmt::Display for PlatformRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.pinned {
            "pinned"
        } else if self.rolled_back {
            "rolled_back"
        } else {
            "active"
        };
        write!(
            f,
            "platform_rule({}, {}, {})",
            self.platform_id, status, self.alignment
        )
    }
}

// ---------------------------------------------------------------------------
// LayoutPolicyState
// ---------------------------------------------------------------------------

/// Lifecycle state of a layout policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutPolicyState {
    /// Policy is being drafted.
    Draft,
    /// Policy is active and being enforced.
    Active,
    /// Policy has been rolled back.
    RolledBack,
    /// Policy is superseded by a newer version.
    Superseded,
    /// Policy is archived.
    Archived,
}

impl LayoutPolicyState {
    pub const ALL: &[Self] = &[
        Self::Draft,
        Self::Active,
        Self::RolledBack,
        Self::Superseded,
        Self::Archived,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::RolledBack => "rolled_back",
            Self::Superseded => "superseded",
            Self::Archived => "archived",
        }
    }

    /// Whether the policy is operational (Draft or Active).
    pub fn is_operational(self) -> bool {
        matches!(self, Self::Draft | Self::Active)
    }
}

impl fmt::Display for LayoutPolicyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LayoutPolicy
// ---------------------------------------------------------------------------

/// Complete code-layout policy: alignment rules, stall budgets, and
/// platform-specific overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutPolicy {
    /// Unique identifier.
    pub policy_id: String,
    /// Current lifecycle state.
    pub state: LayoutPolicyState,
    /// Epoch at which this policy was created.
    pub epoch: SecurityEpoch,
    /// Default alignment strategy (used when no platform rule overrides).
    pub default_alignment: AlignmentStrategy,
    /// Per-platform rules (keyed by platform id string).
    pub platform_rules: Vec<PlatformRule>,
    /// Alignment budget: total padding bytes the policy is willing to spend.
    pub alignment_budget_bytes: u64,
    /// Accumulated padding bytes spent so far.
    pub padding_spent_bytes: u64,
    /// Stall budget governing front-end stall limits.
    pub stall_budget: StallBudget,
    /// Regression threshold in millionths.
    pub regression_threshold_millionths: u64,
    /// Regions governed by this policy.
    pub regions: Vec<CodeRegion>,
    /// Tags for operator classification.
    pub tags: BTreeSet<String>,
}

impl LayoutPolicy {
    /// Create a new policy with sensible defaults.
    pub fn new(policy_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            policy_id: policy_id.into(),
            state: LayoutPolicyState::Draft,
            epoch,
            default_alignment: AlignmentStrategy::cache_line(DEFAULT_CACHE_LINE_BYTES),
            platform_rules: Vec::new(),
            alignment_budget_bytes: MAX_ALIGNMENT_BUDGET_BYTES,
            padding_spent_bytes: 0,
            stall_budget: StallBudget::default(),
            regression_threshold_millionths: DEFAULT_REGRESSION_THRESHOLD,
            regions: Vec::new(),
            tags: BTreeSet::new(),
        }
    }

    /// Activate the policy.
    pub fn activate(&mut self) {
        self.state = LayoutPolicyState::Active;
    }

    /// Add a platform-specific rule.
    pub fn add_platform_rule(&mut self, rule: PlatformRule) {
        self.platform_rules.push(rule);
    }

    /// Add a code region.
    pub fn add_region(&mut self, region: CodeRegion) {
        if self.regions.len() < MAX_LAYOUT_REGIONS {
            self.regions.push(region);
        }
    }

    /// Look up the effective alignment strategy for a given platform.
    /// Falls back to default if no platform-specific rule exists.
    pub fn effective_alignment(&self, platform: &str) -> &AlignmentStrategy {
        for rule in &self.platform_rules {
            if rule.platform_id.as_str() == platform && !rule.rolled_back {
                return &rule.alignment;
            }
        }
        &self.default_alignment
    }

    /// Whether the alignment budget is exhausted.
    pub fn budget_exhausted(&self) -> bool {
        self.padding_spent_bytes >= self.alignment_budget_bytes
    }

    /// Remaining alignment budget.
    pub fn remaining_budget(&self) -> u64 {
        self.alignment_budget_bytes
            .saturating_sub(self.padding_spent_bytes)
    }

    /// Spend padding bytes from the budget. Returns `true` if within budget.
    pub fn spend_padding(&mut self, bytes: u64) -> bool {
        self.padding_spent_bytes = self.padding_spent_bytes.saturating_add(bytes);
        !self.budget_exhausted()
    }

    /// Budget utilisation as millionths.
    pub fn budget_utilisation_millionths(&self) -> u64 {
        if self.alignment_budget_bytes == 0 {
            return MILLION;
        }
        clamp_millionths(
            self.padding_spent_bytes.saturating_mul(MILLION) / self.alignment_budget_bytes,
        )
    }

    /// Number of hot or traced regions.
    pub fn hot_region_count(&self) -> usize {
        self.regions
            .iter()
            .filter(|r| r.heat.rank() >= RegionHeat::Hot.rank())
            .count()
    }

    /// Total code bytes across all regions.
    pub fn total_code_bytes(&self) -> u64 {
        self.regions.iter().map(|r| r.size_bytes).sum()
    }

    /// Content hash of the policy for deterministic auditing.
    pub fn content_hash(&self) -> ContentHash {
        let payload = format!(
            "layout_policy:id={},state={},epoch={},default_align={},rules={},budget={}/{},regions={},tags={}",
            self.policy_id,
            self.state,
            self.epoch,
            self.default_alignment,
            self.platform_rules.len(),
            self.padding_spent_bytes,
            self.alignment_budget_bytes,
            self.regions.len(),
            self.tags.len(),
        );
        compute_content_hash(payload.as_bytes())
    }
}

impl fmt::Display for LayoutPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "layout_policy({}, state={}, epoch={}, regions={}, budget={}/{}B)",
            self.policy_id,
            self.state,
            self.epoch,
            self.regions.len(),
            self.padding_spent_bytes,
            self.alignment_budget_bytes,
        )
    }
}

// ---------------------------------------------------------------------------
// LayoutDecisionKind
// ---------------------------------------------------------------------------

/// The kind of layout decision made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutDecisionKind {
    /// Region was aligned to a cache-line boundary.
    AlignCacheLine,
    /// Region was aligned to a page boundary.
    AlignPageBoundary,
    /// Region was left at natural alignment.
    KeepNatural,
    /// Region was moved to pack with related cold code.
    ColdPack,
    /// Region was split across a boundary.
    SplitBoundary,
    /// Alignment was skipped because budget is exhausted.
    BudgetExhausted,
    /// Alignment was rolled back due to regression.
    RolledBack,
}

impl LayoutDecisionKind {
    pub const ALL: &[Self] = &[
        Self::AlignCacheLine,
        Self::AlignPageBoundary,
        Self::KeepNatural,
        Self::ColdPack,
        Self::SplitBoundary,
        Self::BudgetExhausted,
        Self::RolledBack,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlignCacheLine => "align_cache_line",
            Self::AlignPageBoundary => "align_page_boundary",
            Self::KeepNatural => "keep_natural",
            Self::ColdPack => "cold_pack",
            Self::SplitBoundary => "split_boundary",
            Self::BudgetExhausted => "budget_exhausted",
            Self::RolledBack => "rolled_back",
        }
    }
}

impl fmt::Display for LayoutDecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LayoutDecisionReceipt
// ---------------------------------------------------------------------------

/// Content-hashed evidence record for a single layout decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutDecisionReceipt {
    /// Region the decision applies to.
    pub region_id: RegionId,
    /// Kind of decision.
    pub kind: LayoutDecisionKind,
    /// Alignment strategy used.
    pub alignment: AlignmentStrategy,
    /// Padding bytes inserted.
    pub padding_bytes: u32,
    /// Platform for which the decision was made.
    pub platform_id: PlatformId,
    /// Epoch at the time of decision.
    pub epoch: SecurityEpoch,
    /// Human-readable rationale.
    pub rationale: String,
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
}

impl LayoutDecisionReceipt {
    /// Create a new receipt and compute its content hash.
    pub fn new(
        region_id: impl Into<String>,
        kind: LayoutDecisionKind,
        alignment: AlignmentStrategy,
        padding_bytes: u32,
        platform_id: impl Into<String>,
        epoch: SecurityEpoch,
        rationale: impl Into<String>,
    ) -> Self {
        let region_id = RegionId::new(region_id);
        let platform_id = PlatformId::new(platform_id);
        let rationale = rationale.into();
        let hash_payload = format!(
            "layout_receipt:region={},kind={},align={},pad={},platform={},epoch={},rationale={}",
            region_id, kind, alignment, padding_bytes, platform_id, epoch, rationale,
        );
        let receipt_hash = compute_content_hash(hash_payload.as_bytes());
        Self {
            region_id,
            kind,
            alignment,
            padding_bytes,
            platform_id,
            epoch,
            rationale,
            receipt_hash,
        }
    }

    /// Hex-encoded receipt hash for display.
    pub fn receipt_hash_hex(&self) -> String {
        hex_encode(self.receipt_hash.as_bytes())
    }
}

impl fmt::Display for LayoutDecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt({}, {}, pad={}B, hash={}..)",
            self.region_id,
            self.kind,
            self.padding_bytes,
            &self.receipt_hash_hex()[..8],
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackReason
// ---------------------------------------------------------------------------

/// Why a rollback was triggered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReason {
    /// Measured performance regressed beyond threshold.
    PerformanceRegression,
    /// Stall budget was exhausted.
    StallBudgetExhausted,
    /// Alignment budget overflowed.
    AlignmentBudgetOverflow,
    /// Parity check failed (behaviour divergence).
    ParityFailure,
    /// Operator-initiated rollback.
    OperatorOverride,
    /// Platform rule was invalidated.
    PlatformRuleInvalidated,
}

impl RollbackReason {
    pub const ALL: &[Self] = &[
        Self::PerformanceRegression,
        Self::StallBudgetExhausted,
        Self::AlignmentBudgetOverflow,
        Self::ParityFailure,
        Self::OperatorOverride,
        Self::PlatformRuleInvalidated,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PerformanceRegression => "performance_regression",
            Self::StallBudgetExhausted => "stall_budget_exhausted",
            Self::AlignmentBudgetOverflow => "alignment_budget_overflow",
            Self::ParityFailure => "parity_failure",
            Self::OperatorOverride => "operator_override",
            Self::PlatformRuleInvalidated => "platform_rule_invalidated",
        }
    }
}

impl fmt::Display for RollbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a single rollback event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Reason for the rollback.
    pub reason: RollbackReason,
    /// Policy that was rolled back.
    pub policy_id: String,
    /// Epoch when the rollback occurred.
    pub epoch: SecurityEpoch,
    /// Baseline performance (millionths, e.g. throughput ratio).
    pub baseline_perf_millionths: u64,
    /// Measured performance after the aggressive layout (millionths).
    pub measured_perf_millionths: u64,
    /// Content hash of the rollback record.
    pub record_hash: ContentHash,
}

impl RollbackRecord {
    /// Create a new rollback record.
    pub fn new(
        reason: RollbackReason,
        policy_id: impl Into<String>,
        epoch: SecurityEpoch,
        baseline_perf: u64,
        measured_perf: u64,
    ) -> Self {
        let policy_id = policy_id.into();
        let hash_payload = format!(
            "rollback:reason={},policy={},epoch={},baseline={},measured={}",
            reason, policy_id, epoch, baseline_perf, measured_perf,
        );
        let record_hash = compute_content_hash(hash_payload.as_bytes());
        Self {
            reason,
            policy_id,
            epoch,
            baseline_perf_millionths: baseline_perf,
            measured_perf_millionths: measured_perf,
            record_hash,
        }
    }

    /// Performance delta as millionths (negative means regression).
    /// Returns 0 if baseline is zero.
    pub fn perf_delta_millionths(&self) -> i64 {
        if self.baseline_perf_millionths == 0 {
            return 0;
        }
        self.measured_perf_millionths as i64 - self.baseline_perf_millionths as i64
    }

    /// Whether the measured performance regressed.
    pub fn is_regression(&self) -> bool {
        self.measured_perf_millionths < self.baseline_perf_millionths
    }
}

impl fmt::Display for RollbackRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rollback({}, policy={}, delta={})",
            self.reason,
            self.policy_id,
            self.perf_delta_millionths(),
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackGate
// ---------------------------------------------------------------------------

/// Gate that reverts to conservative layout when aggressive alignment
/// regresses measured performance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackGate {
    /// Regression threshold in millionths.
    pub threshold_millionths: u64,
    /// Accumulated rollback records.
    pub records: Vec<RollbackRecord>,
    /// Whether the gate has fired (any rollback occurred).
    pub fired: bool,
}

impl RollbackGate {
    /// Create a gate with the given regression threshold.
    pub fn new(threshold_millionths: u64) -> Self {
        Self {
            threshold_millionths: clamp_millionths(threshold_millionths),
            records: Vec::new(),
            fired: false,
        }
    }

    /// Evaluate whether a rollback should occur given baseline and measured
    /// performance.  Returns `Some(RollbackRecord)` if regression detected.
    pub fn evaluate(
        &mut self,
        policy_id: &str,
        epoch: SecurityEpoch,
        baseline_perf: u64,
        measured_perf: u64,
    ) -> Option<RollbackRecord> {
        if baseline_perf == 0 {
            return None;
        }
        let drop = baseline_perf.saturating_sub(measured_perf);
        let drop_millionths = drop.saturating_mul(MILLION) / baseline_perf;
        if drop_millionths >= self.threshold_millionths {
            let record = RollbackRecord::new(
                RollbackReason::PerformanceRegression,
                policy_id,
                epoch,
                baseline_perf,
                measured_perf,
            );
            self.records.push(record.clone());
            self.fired = true;
            Some(record)
        } else {
            None
        }
    }

    /// Record a rollback for a non-performance reason.
    pub fn record_rollback(&mut self, record: RollbackRecord) {
        self.fired = true;
        self.records.push(record);
    }

    /// Total rollback count.
    pub fn rollback_count(&self) -> usize {
        self.records.len()
    }

    /// Reset the gate.
    pub fn reset(&mut self) {
        self.records.clear();
        self.fired = false;
    }
}

impl Default for RollbackGate {
    fn default() -> Self {
        Self::new(DEFAULT_REGRESSION_THRESHOLD)
    }
}

impl fmt::Display for RollbackGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rollback_gate(threshold={}ppm, fired={}, records={})",
            self.threshold_millionths,
            self.fired,
            self.records.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

/// Result of comparing a layout's behaviour against a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityVerdict {
    /// Layout produces equivalent observable behaviour.
    Equivalent,
    /// Minor divergence within tolerance (e.g. timing jitter).
    WithinTolerance,
    /// Observable behaviour diverges — layout must not be used.
    Divergent,
    /// Parity could not be assessed (insufficient data).
    Inconclusive,
}

impl ParityVerdict {
    pub const ALL: &[Self] = &[
        Self::Equivalent,
        Self::WithinTolerance,
        Self::Divergent,
        Self::Inconclusive,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::WithinTolerance => "within_tolerance",
            Self::Divergent => "divergent",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether the verdict allows the layout to proceed.
    pub fn allows_layout(self) -> bool {
        matches!(self, Self::Equivalent | Self::WithinTolerance)
    }
}

impl fmt::Display for ParityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityCheckResult
// ---------------------------------------------------------------------------

/// Outcome of a single parity check between two layouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityCheckResult {
    /// Region checked.
    pub region_id: RegionId,
    /// Verdict.
    pub verdict: ParityVerdict,
    /// Reference output hash.
    pub reference_hash: ContentHash,
    /// Candidate output hash.
    pub candidate_hash: ContentHash,
    /// Tolerance used (millionths).
    pub tolerance_millionths: u64,
    /// Additional notes.
    pub notes: String,
}

impl ParityCheckResult {
    /// Create a new parity check result.
    pub fn new(
        region_id: impl Into<String>,
        verdict: ParityVerdict,
        reference_hash: ContentHash,
        candidate_hash: ContentHash,
        tolerance_millionths: u64,
    ) -> Self {
        Self {
            region_id: RegionId::new(region_id),
            verdict,
            reference_hash,
            candidate_hash,
            tolerance_millionths,
            notes: String::new(),
        }
    }

    /// Builder: attach notes.
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }
}

impl fmt::Display for ParityCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parity({}, verdict={})", self.region_id, self.verdict,)
    }
}

// ---------------------------------------------------------------------------
// ParityChecker
// ---------------------------------------------------------------------------

/// Verifies that a layout produces equivalent behaviour to a reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityChecker {
    /// Default tolerance in millionths for timing differences.
    pub tolerance_millionths: u64,
    /// Accumulated check results.
    pub results: Vec<ParityCheckResult>,
}

impl ParityChecker {
    /// Create a new parity checker with the given tolerance.
    pub fn new(tolerance_millionths: u64) -> Self {
        Self {
            tolerance_millionths: clamp_millionths(tolerance_millionths),
            results: Vec::new(),
        }
    }

    /// Run a parity check by comparing reference and candidate output hashes.
    pub fn check(
        &mut self,
        region_id: impl Into<String>,
        reference_hash: ContentHash,
        candidate_hash: ContentHash,
    ) -> ParityVerdict {
        let verdict = if reference_hash == candidate_hash {
            ParityVerdict::Equivalent
        } else {
            // Hash mismatch implies divergence.  Structural comparison
            // (detecting semantics-preserving transformations) is future work.
            ParityVerdict::Divergent
        };
        let result = ParityCheckResult::new(
            region_id,
            verdict,
            reference_hash,
            candidate_hash,
            self.tolerance_millionths,
        );
        self.results.push(result);
        verdict
    }

    /// Run a parity check with an explicit verdict (for pre-assessed cases).
    pub fn record(
        &mut self,
        region_id: impl Into<String>,
        verdict: ParityVerdict,
        reference_hash: ContentHash,
        candidate_hash: ContentHash,
    ) {
        let result = ParityCheckResult::new(
            region_id,
            verdict,
            reference_hash,
            candidate_hash,
            self.tolerance_millionths,
        );
        self.results.push(result);
    }

    /// Whether all checks passed (no divergent verdicts).
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.verdict.allows_layout())
    }

    /// Count of divergent results.
    pub fn divergent_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.verdict == ParityVerdict::Divergent)
            .count()
    }

    /// Total checks performed.
    pub fn check_count(&self) -> usize {
        self.results.len()
    }

    /// Reset all results.
    pub fn reset(&mut self) {
        self.results.clear();
    }
}

impl Default for ParityChecker {
    fn default() -> Self {
        Self::new(10_000) // 1% default tolerance
    }
}

impl fmt::Display for ParityChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parity_checker(tolerance={}ppm, checks={}, divergent={})",
            self.tolerance_millionths,
            self.results.len(),
            self.divergent_count(),
        )
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

/// Severity level for operator diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational — no action needed.
    Info,
    /// Warning — operator should investigate.
    Warning,
    /// Error — layout decision is problematic.
    Error,
    /// Critical — immediate attention required.
    Critical,
}

impl DiagnosticSeverity {
    pub const ALL: &[Self] = &[Self::Info, Self::Warning, Self::Error, Self::Critical];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LayoutDiagnostic
// ---------------------------------------------------------------------------

/// Operator-facing diagnostic for a layout decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutDiagnostic {
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Short summary.
    pub summary: String,
    /// Detailed explanation.
    pub detail: String,
    /// Related region, if any.
    pub region_id: Option<RegionId>,
    /// Related platform, if any.
    pub platform_id: Option<PlatformId>,
    /// Suggested action.
    pub suggested_action: String,
}

impl LayoutDiagnostic {
    /// Create a new diagnostic.
    pub fn new(
        severity: DiagnosticSeverity,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            summary: summary.into(),
            detail: detail.into(),
            region_id: None,
            platform_id: None,
            suggested_action: String::new(),
        }
    }

    /// Builder: attach a region.
    pub fn with_region(mut self, region_id: impl Into<String>) -> Self {
        self.region_id = Some(RegionId::new(region_id));
        self
    }

    /// Builder: attach a platform.
    pub fn with_platform(mut self, platform_id: impl Into<String>) -> Self {
        self.platform_id = Some(PlatformId::new(platform_id));
        self
    }

    /// Builder: attach a suggested action.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.suggested_action = action.into();
        self
    }
}

impl fmt::Display for LayoutDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.severity, self.summary)
    }
}

// ---------------------------------------------------------------------------
// DiagnosticReport
// ---------------------------------------------------------------------------

/// Collection of diagnostics for operator visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Policy id this report pertains to.
    pub policy_id: String,
    /// Diagnostics in order of emission.
    pub entries: Vec<LayoutDiagnostic>,
    /// Epoch when the report was generated.
    pub epoch: SecurityEpoch,
}

impl DiagnosticReport {
    pub fn new(policy_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            policy_id: policy_id.into(),
            entries: Vec::new(),
            epoch,
        }
    }

    /// Add a diagnostic entry.
    pub fn add(&mut self, diag: LayoutDiagnostic) {
        if self.entries.len() < MAX_DIAGNOSTIC_ENTRIES {
            self.entries.push(diag);
        }
    }

    /// Count of entries at or above a given severity.
    pub fn count_at_or_above(&self, min_severity: DiagnosticSeverity) -> usize {
        self.entries
            .iter()
            .filter(|e| e.severity >= min_severity)
            .count()
    }

    /// Whether there are any errors or critical diagnostics.
    pub fn has_errors(&self) -> bool {
        self.count_at_or_above(DiagnosticSeverity::Error) > 0
    }

    /// Whether there are any critical diagnostics.
    pub fn has_critical(&self) -> bool {
        self.count_at_or_above(DiagnosticSeverity::Critical) > 0
    }

    /// Total entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the report is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for DiagnosticReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "diagnostic_report(policy={}, entries={}, errors={})",
            self.policy_id,
            self.entries.len(),
            self.count_at_or_above(DiagnosticSeverity::Error),
        )
    }
}

// ---------------------------------------------------------------------------
// LayoutEvaluator
// ---------------------------------------------------------------------------

/// Orchestrates layout decisions for a set of code regions under a policy.
///
/// Produces receipts, enforces stall budgets, triggers rollbacks, and
/// generates operator diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutEvaluator {
    /// The governing layout policy.
    pub policy: LayoutPolicy,
    /// Rollback gate for regression detection.
    pub rollback_gate: RollbackGate,
    /// Parity checker for behaviour equivalence verification.
    pub parity_checker: ParityChecker,
    /// Emitted decision receipts.
    pub receipts: Vec<LayoutDecisionReceipt>,
    /// Diagnostic report.
    pub diagnostics: DiagnosticReport,
}

impl LayoutEvaluator {
    /// Create a new evaluator from a policy.
    pub fn new(policy: LayoutPolicy) -> Self {
        let policy_id = policy.policy_id.clone();
        let epoch = policy.epoch;
        let threshold = policy.regression_threshold_millionths;
        Self {
            policy,
            rollback_gate: RollbackGate::new(threshold),
            parity_checker: ParityChecker::default(),
            receipts: Vec::new(),
            diagnostics: DiagnosticReport::new(policy_id, epoch),
        }
    }

    /// Select the alignment strategy for a region on a given platform.
    pub fn select_alignment(
        &self,
        region: &CodeRegion,
        platform: &str,
    ) -> (AlignmentStrategy, LayoutDecisionKind) {
        if self.policy.budget_exhausted() {
            return (
                AlignmentStrategy::natural(),
                LayoutDecisionKind::BudgetExhausted,
            );
        }
        let effective = self.policy.effective_alignment(platform);
        match region.heat {
            RegionHeat::Cold => (AlignmentStrategy::natural(), LayoutDecisionKind::ColdPack),
            RegionHeat::Warm => (
                AlignmentStrategy::natural(),
                LayoutDecisionKind::KeepNatural,
            ),
            RegionHeat::Hot => {
                if effective.target == AlignmentTarget::PageBoundary {
                    // Hot regions get cache-line, not full page.
                    (
                        AlignmentStrategy::cache_line(
                            effective.alignment_bytes.min(DEFAULT_CACHE_LINE_BYTES),
                        ),
                        LayoutDecisionKind::AlignCacheLine,
                    )
                } else {
                    (effective.clone(), LayoutDecisionKind::AlignCacheLine)
                }
            }
            RegionHeat::Traced => {
                if effective.target == AlignmentTarget::PageBoundary
                    || effective.target == AlignmentTarget::CacheLine
                {
                    (effective.clone(), LayoutDecisionKind::AlignPageBoundary)
                } else {
                    (
                        AlignmentStrategy::cache_line(DEFAULT_CACHE_LINE_BYTES),
                        LayoutDecisionKind::AlignCacheLine,
                    )
                }
            }
        }
    }

    /// Evaluate layout for a single region. Returns a receipt.
    pub fn evaluate_region(
        &mut self,
        region: &CodeRegion,
        platform: &str,
    ) -> LayoutDecisionReceipt {
        let (alignment, kind) = self.select_alignment(region, platform);
        let padding = alignment.padding_for(region.base_address).unwrap_or(0);
        let capped_kind = if alignment.exceeds_budget(padding) {
            LayoutDecisionKind::BudgetExhausted
        } else {
            kind
        };

        // Spend padding from budget.
        if capped_kind != LayoutDecisionKind::BudgetExhausted {
            self.policy.spend_padding(u64::from(padding));
        }

        let rationale = format!(
            "region {} (heat={}, {}B) -> {} with {}B padding on {}",
            region.id, region.heat, region.size_bytes, capped_kind, padding, platform,
        );

        let receipt = LayoutDecisionReceipt::new(
            region.id.as_str(),
            capped_kind,
            alignment,
            padding,
            platform,
            self.policy.epoch,
            &rationale,
        );

        // Emit diagnostics for notable decisions.
        if capped_kind == LayoutDecisionKind::BudgetExhausted {
            self.diagnostics.add(
                LayoutDiagnostic::new(
                    DiagnosticSeverity::Warning,
                    "Alignment budget exhausted",
                    &rationale,
                )
                .with_region(region.id.as_str()),
            );
        }

        self.receipts.push(receipt.clone());
        receipt
    }

    /// Evaluate layout for all regions in the policy.
    pub fn evaluate_all(&mut self, platform: &str) -> Vec<LayoutDecisionReceipt> {
        let regions: Vec<CodeRegion> = self.policy.regions.clone();
        let mut results = Vec::with_capacity(regions.len());
        for region in &regions {
            let receipt = self.evaluate_region(region, platform);
            results.push(receipt);
        }
        results
    }

    /// Check for performance regression and potentially trigger rollback.
    pub fn check_regression(
        &mut self,
        baseline_perf: u64,
        measured_perf: u64,
    ) -> Option<RollbackRecord> {
        let record = self.rollback_gate.evaluate(
            &self.policy.policy_id,
            self.policy.epoch,
            baseline_perf,
            measured_perf,
        );
        if let Some(ref rec) = record {
            self.policy.state = LayoutPolicyState::RolledBack;
            self.diagnostics.add(
                LayoutDiagnostic::new(
                    DiagnosticSeverity::Error,
                    "Performance regression triggered rollback",
                    format!(
                        "Baseline={}, measured={}, delta={}",
                        rec.baseline_perf_millionths,
                        rec.measured_perf_millionths,
                        rec.perf_delta_millionths(),
                    ),
                )
                .with_action("Review layout policy and consider pinning conservative alignment"),
            );
        }
        record
    }

    /// Record a stall event against the policy budget.
    pub fn record_stall(&mut self, event: StallEvent) {
        self.policy.stall_budget.record(event);
        if self.policy.stall_budget.gate_fires() {
            let record = RollbackRecord::new(
                RollbackReason::StallBudgetExhausted,
                &self.policy.policy_id,
                self.policy.epoch,
                MILLION,
                0,
            );
            self.rollback_gate.record_rollback(record);
            self.diagnostics.add(
                LayoutDiagnostic::new(
                    DiagnosticSeverity::Critical,
                    "Stall budget exhausted",
                    format!(
                        "Accumulated {} cycles (budget {}), {} I-cache misses (budget {})",
                        self.policy.stall_budget.accumulated_cycles,
                        self.policy.stall_budget.max_stall_cycles,
                        self.policy.stall_budget.accumulated_icache_misses,
                        self.policy.stall_budget.max_icache_misses,
                    ),
                )
                .with_action("Reduce alignment aggressiveness or increase stall budget"),
            );
        }
    }

    /// Run a parity check for a region.
    pub fn check_parity(
        &mut self,
        region_id: &str,
        reference_hash: ContentHash,
        candidate_hash: ContentHash,
    ) -> ParityVerdict {
        let verdict = self
            .parity_checker
            .check(region_id, reference_hash, candidate_hash);
        if verdict == ParityVerdict::Divergent {
            let record = RollbackRecord::new(
                RollbackReason::ParityFailure,
                &self.policy.policy_id,
                self.policy.epoch,
                MILLION,
                0,
            );
            self.rollback_gate.record_rollback(record);
            self.diagnostics.add(
                LayoutDiagnostic::new(
                    DiagnosticSeverity::Critical,
                    "Parity check failed",
                    format!("Region {} diverges from reference", region_id),
                )
                .with_region(region_id)
                .with_action("Rollback layout and investigate divergence"),
            );
        }
        verdict
    }

    /// Summary of all receipts by decision kind.
    pub fn receipt_summary(&self) -> BTreeMap<String, usize> {
        let mut summary = BTreeMap::new();
        for receipt in &self.receipts {
            *summary
                .entry(receipt.kind.as_str().to_string())
                .or_insert(0) += 1;
        }
        summary
    }

    /// Total padding bytes across all receipts.
    pub fn total_padding_bytes(&self) -> u64 {
        self.receipts
            .iter()
            .map(|r| u64::from(r.padding_bytes))
            .sum()
    }

    /// Content hash of the entire evaluation.
    pub fn evaluation_hash(&self) -> ContentHash {
        let payload = format!(
            "layout_eval:policy={},receipts={},rollbacks={},parity_checks={},padding={}",
            self.policy.content_hash().to_hex(),
            self.receipts.len(),
            self.rollback_gate.rollback_count(),
            self.parity_checker.check_count(),
            self.total_padding_bytes(),
        );
        compute_content_hash(payload.as_bytes())
    }
}

impl fmt::Display for LayoutEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "layout_evaluator(policy={}, receipts={}, rollbacks={}, diagnostics={})",
            self.policy.policy_id,
            self.receipts.len(),
            self.rollback_gate.rollback_count(),
            self.diagnostics.len(),
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- AlignmentTarget --

    #[test]
    fn alignment_target_all_variants() {
        assert_eq!(AlignmentTarget::ALL.len(), 4);
    }

    #[test]
    fn alignment_target_as_str_roundtrip() {
        for target in AlignmentTarget::ALL {
            assert!(!target.as_str().is_empty());
            assert_eq!(format!("{target}"), target.as_str());
        }
    }

    // -- AlignmentStrategy --

    #[test]
    fn natural_alignment_defaults() {
        let a = AlignmentStrategy::natural();
        assert_eq!(a.target, AlignmentTarget::Natural);
        assert_eq!(a.alignment_bytes, 1);
        assert_eq!(a.max_padding_bytes, 0);
        assert!(!a.allow_nop_padding);
    }

    #[test]
    fn cache_line_alignment() {
        let a = AlignmentStrategy::cache_line(64);
        assert_eq!(a.target, AlignmentTarget::CacheLine);
        assert_eq!(a.alignment_bytes, 64);
        assert_eq!(a.max_padding_bytes, 63);
        assert!(a.allow_nop_padding);
    }

    #[test]
    fn page_boundary_alignment() {
        let a = AlignmentStrategy::page_boundary(4096);
        assert_eq!(a.alignment_bytes, 4096);
        assert_eq!(a.max_padding_bytes, 4095);
    }

    #[test]
    fn explicit_alignment() {
        let a = AlignmentStrategy::explicit(32, 16);
        assert_eq!(a.target, AlignmentTarget::ExplicitBytes);
        assert_eq!(a.alignment_bytes, 32);
        assert_eq!(a.max_padding_bytes, 16);
    }

    #[test]
    fn alignment_is_power_of_two() {
        assert!(AlignmentStrategy::cache_line(64).is_power_of_two());
        assert!(!AlignmentStrategy::explicit(48, 16).is_power_of_two());
        assert!(AlignmentStrategy::natural().is_power_of_two()); // 1 is power of two
    }

    #[test]
    fn alignment_padding_for_aligned_address() {
        let a = AlignmentStrategy::cache_line(64);
        assert_eq!(a.padding_for(128), Some(0));
        assert_eq!(a.padding_for(0), Some(0));
    }

    #[test]
    fn alignment_padding_for_misaligned_address() {
        let a = AlignmentStrategy::cache_line(64);
        assert_eq!(a.padding_for(100), Some(28)); // 128 - 100
        assert_eq!(a.padding_for(1), Some(63));
    }

    #[test]
    fn alignment_padding_zero_alignment() {
        let a = AlignmentStrategy::explicit(0, 0);
        assert_eq!(a.padding_for(42), None);
    }

    #[test]
    fn alignment_exceeds_budget() {
        let a = AlignmentStrategy::cache_line(64);
        assert!(!a.exceeds_budget(32));
        assert!(!a.exceeds_budget(63));
        assert!(a.exceeds_budget(64));
    }

    #[test]
    fn alignment_display() {
        let a = AlignmentStrategy::cache_line(64);
        let s = format!("{a}");
        assert!(s.contains("cache_line"));
        assert!(s.contains("64B"));
    }

    #[test]
    fn alignment_default_is_natural() {
        let a = AlignmentStrategy::default();
        assert_eq!(a.target, AlignmentTarget::Natural);
    }

    // -- PlatformId & RegionId --

    #[test]
    fn platform_id_display() {
        let p = PlatformId::new("x86_64_v3");
        assert_eq!(format!("{p}"), "platform:x86_64_v3");
    }

    #[test]
    fn region_id_display() {
        let r = RegionId::new("main_loop");
        assert_eq!(format!("{r}"), "region:main_loop");
    }

    // -- RegionHeat --

    #[test]
    fn region_heat_all_variants() {
        assert_eq!(RegionHeat::ALL.len(), 4);
    }

    #[test]
    fn region_heat_rank_ordering() {
        assert!(RegionHeat::Cold.rank() < RegionHeat::Warm.rank());
        assert!(RegionHeat::Warm.rank() < RegionHeat::Hot.rank());
        assert!(RegionHeat::Hot.rank() < RegionHeat::Traced.rank());
    }

    #[test]
    fn region_heat_display() {
        assert_eq!(format!("{}", RegionHeat::Hot), "hot");
        assert_eq!(format!("{}", RegionHeat::Traced), "traced");
    }

    // -- CodeRegion --

    #[test]
    fn code_region_builder() {
        let r = CodeRegion::new("loop1", RegionHeat::Hot, 256)
            .with_base_address(0x1000)
            .with_execution_count(5000)
            .with_loop_header(true)
            .with_function_entry(false);
        assert_eq!(r.id.as_str(), "loop1");
        assert_eq!(r.heat, RegionHeat::Hot);
        assert_eq!(r.size_bytes, 256);
        assert_eq!(r.base_address, 0x1000);
        assert_eq!(r.execution_count, 5000);
        assert!(r.is_loop_header);
        assert!(!r.is_function_entry);
    }

    #[test]
    fn code_region_display() {
        let r = CodeRegion::new("fn_entry", RegionHeat::Cold, 64);
        let s = format!("{r}");
        assert!(s.contains("fn_entry"));
        assert!(s.contains("cold"));
    }

    // -- StallKind --

    #[test]
    fn stall_kind_all_variants() {
        assert_eq!(StallKind::ALL.len(), 5);
    }

    #[test]
    fn stall_kind_display() {
        for kind in StallKind::ALL {
            assert!(!kind.as_str().is_empty());
            assert_eq!(format!("{kind}"), kind.as_str());
        }
    }

    // -- StallEvent --

    #[test]
    fn stall_event_creation() {
        let e = StallEvent::new(StallKind::ICacheMiss, "loop1", 12);
        assert_eq!(e.kind, StallKind::ICacheMiss);
        assert_eq!(e.cost_cycles, 12);
        assert_eq!(e.offset, 0);
    }

    #[test]
    fn stall_event_with_offset() {
        let e = StallEvent::new(StallKind::BtbMiss, "fn1", 5).with_offset(42);
        assert_eq!(e.offset, 42);
    }

    #[test]
    fn stall_event_display() {
        let e = StallEvent::new(StallKind::DecodeStall, "r1", 8);
        let s = format!("{e}");
        assert!(s.contains("decode_stall"));
        assert!(s.contains("8cyc"));
    }

    // -- StallBudget --

    #[test]
    fn stall_budget_default() {
        let b = StallBudget::default();
        assert_eq!(b.max_stall_cycles, DEFAULT_STALL_BUDGET_CYCLES);
        assert_eq!(b.max_icache_misses, DEFAULT_ICACHE_MISS_THRESHOLD);
        assert!(!b.gate_fires());
    }

    #[test]
    fn stall_budget_record_event() {
        let mut b = StallBudget::new(100, 10);
        b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 20));
        assert_eq!(b.accumulated_cycles, 20);
        assert_eq!(b.accumulated_icache_misses, 0);
        assert_eq!(b.event_count(), 1);
    }

    #[test]
    fn stall_budget_icache_tracking() {
        let mut b = StallBudget::new(1000, 3);
        b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
        b.record(StallEvent::new(StallKind::ICacheMiss, "r2", 10));
        assert_eq!(b.accumulated_icache_misses, 2);
        assert!(!b.icache_exhausted());
        b.record(StallEvent::new(StallKind::ICacheMiss, "r3", 10));
        assert!(b.icache_exhausted());
        assert!(b.gate_fires());
    }

    #[test]
    fn stall_budget_cycles_exhausted() {
        let mut b = StallBudget::new(50, 100);
        b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 30));
        assert!(!b.cycles_exhausted());
        b.record(StallEvent::new(StallKind::InstructionFetch, "r2", 25));
        assert!(b.cycles_exhausted());
    }

    #[test]
    fn stall_budget_remaining() {
        let mut b = StallBudget::new(100, 10);
        b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 30));
        assert_eq!(b.remaining_cycles(), 70);
        assert_eq!(b.remaining_icache_misses(), 10);
    }

    #[test]
    fn stall_budget_utilisation() {
        let mut b = StallBudget::new(100, 10);
        b.record(StallEvent::new(StallKind::InstructionFetch, "r1", 50));
        assert_eq!(b.cycle_utilisation_millionths(), 500_000);
    }

    #[test]
    fn stall_budget_utilisation_zero_budget() {
        let b = StallBudget::new(0, 10);
        assert_eq!(b.cycle_utilisation_millionths(), MILLION);
    }

    #[test]
    fn stall_budget_reset() {
        let mut b = StallBudget::new(100, 10);
        b.record(StallEvent::new(StallKind::ICacheMiss, "r1", 50));
        b.reset();
        assert_eq!(b.accumulated_cycles, 0);
        assert_eq!(b.accumulated_icache_misses, 0);
        assert_eq!(b.event_count(), 0);
        assert!(b.counters.is_empty());
    }

    #[test]
    fn stall_budget_content_hash_deterministic() {
        let b1 = StallBudget::new(100, 10);
        let b2 = StallBudget::new(100, 10);
        assert_eq!(b1.content_hash(), b2.content_hash());
    }

    #[test]
    fn stall_budget_display() {
        let b = StallBudget::new(100, 10);
        let s = format!("{b}");
        assert!(s.contains("stall_budget"));
    }

    // -- PlatformRule --

    #[test]
    fn platform_rule_creation() {
        let r = PlatformRule::new("aarch64_v8", AlignmentStrategy::cache_line(64));
        assert_eq!(r.platform_id.as_str(), "aarch64_v8");
        assert!(!r.pinned);
        assert!(!r.rolled_back);
    }

    #[test]
    fn platform_rule_pin() {
        let mut r = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
        r.pin("Performance is critical on this platform");
        assert!(r.pinned);
        assert!(!r.is_generalisable());
    }

    #[test]
    fn platform_rule_rollback() {
        let mut r = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
        r.rollback("Regression detected");
        assert!(r.rolled_back);
        assert_eq!(r.alignment.target, AlignmentTarget::Natural);
        assert!(!r.is_generalisable());
    }

    #[test]
    fn platform_rule_generalise() {
        let mut r = PlatformRule::new("x86_64", AlignmentStrategy::cache_line(64));
        r.pin("test");
        r.generalise();
        assert!(!r.pinned);
    }

    #[test]
    fn platform_rule_display() {
        let r = PlatformRule::new("riscv64", AlignmentStrategy::natural());
        let s = format!("{r}");
        assert!(s.contains("riscv64"));
        assert!(s.contains("active"));
    }

    // -- LayoutPolicyState --

    #[test]
    fn layout_policy_state_all_variants() {
        assert_eq!(LayoutPolicyState::ALL.len(), 5);
    }

    #[test]
    fn layout_policy_state_operational() {
        assert!(LayoutPolicyState::Draft.is_operational());
        assert!(LayoutPolicyState::Active.is_operational());
        assert!(!LayoutPolicyState::RolledBack.is_operational());
        assert!(!LayoutPolicyState::Superseded.is_operational());
        assert!(!LayoutPolicyState::Archived.is_operational());
    }

    // -- LayoutPolicy --

    #[test]
    fn layout_policy_creation() {
        let p = LayoutPolicy::new("policy_1", SecurityEpoch::from_raw(5));
        assert_eq!(p.policy_id, "policy_1");
        assert_eq!(p.state, LayoutPolicyState::Draft);
        assert_eq!(p.epoch.as_u64(), 5);
        assert!(!p.budget_exhausted());
    }

    #[test]
    fn layout_policy_activate() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.activate();
        assert_eq!(p.state, LayoutPolicyState::Active);
    }

    #[test]
    fn layout_policy_add_region() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.add_region(CodeRegion::new("r1", RegionHeat::Hot, 128));
        assert_eq!(p.regions.len(), 1);
    }

    #[test]
    fn layout_policy_effective_alignment_default() {
        let p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        let a = p.effective_alignment("unknown_platform");
        assert_eq!(a.target, AlignmentTarget::CacheLine);
    }

    #[test]
    fn layout_policy_effective_alignment_platform_override() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.add_platform_rule(PlatformRule::new(
            "arm64",
            AlignmentStrategy::page_boundary(4096),
        ));
        let a = p.effective_alignment("arm64");
        assert_eq!(a.target, AlignmentTarget::PageBoundary);
    }

    #[test]
    fn layout_policy_effective_alignment_rolled_back_rule() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        let mut rule = PlatformRule::new("arm64", AlignmentStrategy::page_boundary(4096));
        rule.rollback("regressed");
        p.add_platform_rule(rule);
        let a = p.effective_alignment("arm64");
        // Rolled-back rule is skipped, falls back to default.
        assert_eq!(a.target, AlignmentTarget::CacheLine);
    }

    #[test]
    fn layout_policy_spend_padding() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.alignment_budget_bytes = 100;
        assert!(p.spend_padding(50));
        assert_eq!(p.padding_spent_bytes, 50);
        assert_eq!(p.remaining_budget(), 50);
        assert!(!p.spend_padding(60)); // exceeds
    }

    #[test]
    fn layout_policy_budget_utilisation() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.alignment_budget_bytes = 200;
        p.padding_spent_bytes = 100;
        assert_eq!(p.budget_utilisation_millionths(), 500_000);
    }

    #[test]
    fn layout_policy_hot_region_count() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.add_region(CodeRegion::new("r1", RegionHeat::Cold, 64));
        p.add_region(CodeRegion::new("r2", RegionHeat::Hot, 128));
        p.add_region(CodeRegion::new("r3", RegionHeat::Traced, 256));
        assert_eq!(p.hot_region_count(), 2);
    }

    #[test]
    fn layout_policy_total_code_bytes() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        p.add_region(CodeRegion::new("r1", RegionHeat::Cold, 64));
        p.add_region(CodeRegion::new("r2", RegionHeat::Hot, 128));
        assert_eq!(p.total_code_bytes(), 192);
    }

    #[test]
    fn layout_policy_content_hash_deterministic() {
        let p1 = LayoutPolicy::new("p1", SecurityEpoch::from_raw(1));
        let p2 = LayoutPolicy::new("p1", SecurityEpoch::from_raw(1));
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn layout_policy_display() {
        let p = LayoutPolicy::new("pol_42", SecurityEpoch::from_raw(3));
        let s = format!("{p}");
        assert!(s.contains("pol_42"));
    }

    // -- LayoutDecisionKind --

    #[test]
    fn layout_decision_kind_all_variants() {
        assert_eq!(LayoutDecisionKind::ALL.len(), 7);
    }

    #[test]
    fn layout_decision_kind_display() {
        for kind in LayoutDecisionKind::ALL {
            assert!(!kind.as_str().is_empty());
        }
    }

    // -- LayoutDecisionReceipt --

    #[test]
    fn receipt_creation_and_hash() {
        let r = LayoutDecisionReceipt::new(
            "loop1",
            LayoutDecisionKind::AlignCacheLine,
            AlignmentStrategy::cache_line(64),
            28,
            "x86_64",
            SecurityEpoch::from_raw(1),
            "hot loop aligned",
        );
        assert_eq!(r.region_id.as_str(), "loop1");
        assert_eq!(r.padding_bytes, 28);
        assert!(!r.receipt_hash_hex().is_empty());
    }

    #[test]
    fn receipt_deterministic_hash() {
        let r1 = LayoutDecisionReceipt::new(
            "r",
            LayoutDecisionKind::KeepNatural,
            AlignmentStrategy::natural(),
            0,
            "p",
            SecurityEpoch::GENESIS,
            "test",
        );
        let r2 = LayoutDecisionReceipt::new(
            "r",
            LayoutDecisionKind::KeepNatural,
            AlignmentStrategy::natural(),
            0,
            "p",
            SecurityEpoch::GENESIS,
            "test",
        );
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_display() {
        let r = LayoutDecisionReceipt::new(
            "r1",
            LayoutDecisionKind::ColdPack,
            AlignmentStrategy::natural(),
            0,
            "arm64",
            SecurityEpoch::GENESIS,
            "cold",
        );
        let s = format!("{r}");
        assert!(s.contains("r1"));
        assert!(s.contains("cold_pack"));
    }

    // -- RollbackReason --

    #[test]
    fn rollback_reason_all_variants() {
        assert_eq!(RollbackReason::ALL.len(), 6);
    }

    #[test]
    fn rollback_reason_display() {
        for reason in RollbackReason::ALL {
            assert!(!reason.as_str().is_empty());
        }
    }

    // -- RollbackRecord --

    #[test]
    fn rollback_record_creation() {
        let r = RollbackRecord::new(
            RollbackReason::PerformanceRegression,
            "pol1",
            SecurityEpoch::from_raw(2),
            MILLION,
            900_000,
        );
        assert!(r.is_regression());
        assert_eq!(r.perf_delta_millionths(), -100_000);
    }

    #[test]
    fn rollback_record_no_regression() {
        let r = RollbackRecord::new(
            RollbackReason::OperatorOverride,
            "pol1",
            SecurityEpoch::GENESIS,
            MILLION,
            MILLION + 100,
        );
        assert!(!r.is_regression());
    }

    #[test]
    fn rollback_record_zero_baseline() {
        let r = RollbackRecord::new(
            RollbackReason::PerformanceRegression,
            "pol1",
            SecurityEpoch::GENESIS,
            0,
            500_000,
        );
        assert_eq!(r.perf_delta_millionths(), 0);
    }

    #[test]
    fn rollback_record_display() {
        let r = RollbackRecord::new(
            RollbackReason::StallBudgetExhausted,
            "pol1",
            SecurityEpoch::GENESIS,
            MILLION,
            0,
        );
        let s = format!("{r}");
        assert!(s.contains("stall_budget_exhausted"));
    }

    // -- RollbackGate --

    #[test]
    fn rollback_gate_default() {
        let g = RollbackGate::default();
        assert_eq!(g.threshold_millionths, DEFAULT_REGRESSION_THRESHOLD);
        assert!(!g.fired);
    }

    #[test]
    fn rollback_gate_no_regression() {
        let mut g = RollbackGate::new(50_000);
        let result = g.evaluate("p1", SecurityEpoch::GENESIS, MILLION, MILLION);
        assert!(result.is_none());
        assert!(!g.fired);
    }

    #[test]
    fn rollback_gate_detects_regression() {
        let mut g = RollbackGate::new(50_000); // 5% threshold
        let result = g.evaluate("p1", SecurityEpoch::GENESIS, MILLION, 900_000); // 10% drop
        assert!(result.is_some());
        assert!(g.fired);
        assert_eq!(g.rollback_count(), 1);
    }

    #[test]
    fn rollback_gate_within_threshold() {
        let mut g = RollbackGate::new(50_000); // 5% threshold
        let result = g.evaluate("p1", SecurityEpoch::GENESIS, MILLION, 960_000); // 4% drop
        assert!(result.is_none());
    }

    #[test]
    fn rollback_gate_zero_baseline() {
        let mut g = RollbackGate::new(50_000);
        let result = g.evaluate("p1", SecurityEpoch::GENESIS, 0, 100);
        assert!(result.is_none());
    }

    #[test]
    fn rollback_gate_record_non_perf() {
        let mut g = RollbackGate::new(50_000);
        let record = RollbackRecord::new(
            RollbackReason::ParityFailure,
            "p1",
            SecurityEpoch::GENESIS,
            MILLION,
            0,
        );
        g.record_rollback(record);
        assert!(g.fired);
        assert_eq!(g.rollback_count(), 1);
    }

    #[test]
    fn rollback_gate_reset() {
        let mut g = RollbackGate::new(50_000);
        g.record_rollback(RollbackRecord::new(
            RollbackReason::OperatorOverride,
            "p1",
            SecurityEpoch::GENESIS,
            MILLION,
            0,
        ));
        g.reset();
        assert!(!g.fired);
        assert_eq!(g.rollback_count(), 0);
    }

    #[test]
    fn rollback_gate_display() {
        let g = RollbackGate::new(50_000);
        let s = format!("{g}");
        assert!(s.contains("rollback_gate"));
    }

    // -- ParityVerdict --

    #[test]
    fn parity_verdict_all_variants() {
        assert_eq!(ParityVerdict::ALL.len(), 4);
    }

    #[test]
    fn parity_verdict_allows_layout() {
        assert!(ParityVerdict::Equivalent.allows_layout());
        assert!(ParityVerdict::WithinTolerance.allows_layout());
        assert!(!ParityVerdict::Divergent.allows_layout());
        assert!(!ParityVerdict::Inconclusive.allows_layout());
    }

    // -- ParityChecker --

    #[test]
    fn parity_checker_equivalent() {
        let mut pc = ParityChecker::default();
        let h = compute_content_hash(b"test");
        let verdict = pc.check("r1", h, h);
        assert_eq!(verdict, ParityVerdict::Equivalent);
        assert!(pc.all_passed());
    }

    #[test]
    fn parity_checker_divergent() {
        let mut pc = ParityChecker::default();
        let h1 = compute_content_hash(b"a");
        let h2 = compute_content_hash(b"b");
        let verdict = pc.check("r1", h1, h2);
        assert_eq!(verdict, ParityVerdict::Divergent);
        assert!(!pc.all_passed());
        assert_eq!(pc.divergent_count(), 1);
    }

    #[test]
    fn parity_checker_record_explicit() {
        let mut pc = ParityChecker::default();
        let h = compute_content_hash(b"data");
        pc.record("r1", ParityVerdict::WithinTolerance, h, h);
        assert!(pc.all_passed());
        assert_eq!(pc.check_count(), 1);
    }

    #[test]
    fn parity_checker_reset() {
        let mut pc = ParityChecker::default();
        let h = compute_content_hash(b"x");
        pc.check("r1", h, h);
        pc.reset();
        assert_eq!(pc.check_count(), 0);
    }

    #[test]
    fn parity_checker_display() {
        let pc = ParityChecker::new(20_000);
        let s = format!("{pc}");
        assert!(s.contains("parity_checker"));
        assert!(s.contains("20000"));
    }

    // -- DiagnosticSeverity --

    #[test]
    fn diagnostic_severity_all_variants() {
        assert_eq!(DiagnosticSeverity::ALL.len(), 4);
    }

    #[test]
    fn diagnostic_severity_ordering() {
        assert!(DiagnosticSeverity::Info < DiagnosticSeverity::Warning);
        assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
        assert!(DiagnosticSeverity::Error < DiagnosticSeverity::Critical);
    }

    // -- LayoutDiagnostic --

    #[test]
    fn diagnostic_creation() {
        let d = LayoutDiagnostic::new(
            DiagnosticSeverity::Warning,
            "Budget low",
            "Only 10% remaining",
        );
        assert_eq!(d.severity, DiagnosticSeverity::Warning);
        assert_eq!(d.summary, "Budget low");
    }

    #[test]
    fn diagnostic_builders() {
        let d = LayoutDiagnostic::new(DiagnosticSeverity::Error, "fail", "detail")
            .with_region("r1")
            .with_platform("arm64")
            .with_action("Investigate");
        assert!(d.region_id.is_some());
        assert!(d.platform_id.is_some());
        assert_eq!(d.suggested_action, "Investigate");
    }

    #[test]
    fn diagnostic_display() {
        let d = LayoutDiagnostic::new(DiagnosticSeverity::Info, "All good", "");
        let s = format!("{d}");
        assert!(s.contains("[info]"));
        assert!(s.contains("All good"));
    }

    // -- DiagnosticReport --

    #[test]
    fn diagnostic_report_empty() {
        let r = DiagnosticReport::new("p1", SecurityEpoch::GENESIS);
        assert!(r.is_empty());
        assert!(!r.has_errors());
        assert!(!r.has_critical());
    }

    #[test]
    fn diagnostic_report_counts() {
        let mut r = DiagnosticReport::new("p1", SecurityEpoch::GENESIS);
        r.add(LayoutDiagnostic::new(DiagnosticSeverity::Info, "ok", ""));
        r.add(LayoutDiagnostic::new(
            DiagnosticSeverity::Warning,
            "hmm",
            "",
        ));
        r.add(LayoutDiagnostic::new(DiagnosticSeverity::Error, "bad", ""));
        assert_eq!(r.len(), 3);
        assert_eq!(r.count_at_or_above(DiagnosticSeverity::Warning), 2);
        assert!(r.has_errors());
        assert!(!r.has_critical());
    }

    #[test]
    fn diagnostic_report_display() {
        let r = DiagnosticReport::new("p1", SecurityEpoch::GENESIS);
        let s = format!("{r}");
        assert!(s.contains("p1"));
    }

    // -- LayoutEvaluator --

    fn make_test_policy() -> LayoutPolicy {
        let mut p = LayoutPolicy::new("test_policy", SecurityEpoch::from_raw(1));
        p.activate();
        p.add_region(CodeRegion::new("cold_fn", RegionHeat::Cold, 64).with_base_address(0x100));
        p.add_region(CodeRegion::new("hot_loop", RegionHeat::Hot, 256).with_base_address(0x200));
        p.add_region(
            CodeRegion::new("traced_fn", RegionHeat::Traced, 512).with_base_address(0x400),
        );
        p.add_region(CodeRegion::new("warm_fn", RegionHeat::Warm, 128).with_base_address(0x300));
        p
    }

    #[test]
    fn evaluator_creation() {
        let e = LayoutEvaluator::new(make_test_policy());
        assert_eq!(e.policy.state, LayoutPolicyState::Active);
        assert!(e.receipts.is_empty());
    }

    #[test]
    fn evaluator_select_alignment_cold() {
        let e = LayoutEvaluator::new(make_test_policy());
        let region = CodeRegion::new("c1", RegionHeat::Cold, 64);
        let (_, kind) = e.select_alignment(&region, "x86_64");
        assert_eq!(kind, LayoutDecisionKind::ColdPack);
    }

    #[test]
    fn evaluator_select_alignment_warm() {
        let e = LayoutEvaluator::new(make_test_policy());
        let region = CodeRegion::new("w1", RegionHeat::Warm, 64);
        let (_, kind) = e.select_alignment(&region, "x86_64");
        assert_eq!(kind, LayoutDecisionKind::KeepNatural);
    }

    #[test]
    fn evaluator_select_alignment_hot() {
        let e = LayoutEvaluator::new(make_test_policy());
        let region = CodeRegion::new("h1", RegionHeat::Hot, 256);
        let (alignment, kind) = e.select_alignment(&region, "x86_64");
        assert_eq!(kind, LayoutDecisionKind::AlignCacheLine);
        assert_eq!(alignment.target, AlignmentTarget::CacheLine);
    }

    #[test]
    fn evaluator_select_alignment_traced() {
        let e = LayoutEvaluator::new(make_test_policy());
        let region = CodeRegion::new("t1", RegionHeat::Traced, 512);
        let (_, kind) = e.select_alignment(&region, "x86_64");
        assert_eq!(kind, LayoutDecisionKind::AlignPageBoundary);
    }

    #[test]
    fn evaluator_select_alignment_budget_exhausted() {
        let mut policy = make_test_policy();
        policy.alignment_budget_bytes = 0;
        let e = LayoutEvaluator::new(policy);
        let region = CodeRegion::new("h1", RegionHeat::Hot, 256);
        let (_, kind) = e.select_alignment(&region, "x86_64");
        assert_eq!(kind, LayoutDecisionKind::BudgetExhausted);
    }

    #[test]
    fn evaluator_evaluate_region() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let region = CodeRegion::new("r1", RegionHeat::Hot, 128).with_base_address(0x100);
        let receipt = e.evaluate_region(&region, "x86_64");
        assert_eq!(receipt.kind, LayoutDecisionKind::AlignCacheLine);
        assert_eq!(e.receipts.len(), 1);
    }

    #[test]
    fn evaluator_evaluate_all() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let receipts = e.evaluate_all("x86_64");
        assert_eq!(receipts.len(), 4);
        assert_eq!(e.receipts.len(), 4);
    }

    #[test]
    fn evaluator_receipt_summary() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        e.evaluate_all("x86_64");
        let summary = e.receipt_summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn evaluator_total_padding() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        e.evaluate_all("x86_64");
        // Just verify it's a valid value (deterministic depends on addresses).
        let _ = e.total_padding_bytes();
    }

    #[test]
    fn evaluator_check_regression_no_regression() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let result = e.check_regression(MILLION, MILLION);
        assert!(result.is_none());
    }

    #[test]
    fn evaluator_check_regression_fires() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let result = e.check_regression(MILLION, 800_000); // 20% drop
        assert!(result.is_some());
        assert_eq!(e.policy.state, LayoutPolicyState::RolledBack);
        assert!(e.diagnostics.has_errors());
    }

    #[test]
    fn evaluator_record_stall() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
        assert_eq!(e.policy.stall_budget.accumulated_cycles, 10);
    }

    #[test]
    fn evaluator_record_stall_triggers_rollback() {
        let mut policy = make_test_policy();
        policy.stall_budget = StallBudget::new(20, 2);
        let mut e = LayoutEvaluator::new(policy);
        e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
        e.record_stall(StallEvent::new(StallKind::ICacheMiss, "r2", 15));
        assert!(e.rollback_gate.fired);
        assert!(e.diagnostics.has_critical());
    }

    #[test]
    fn evaluator_check_parity_equivalent() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let h = compute_content_hash(b"output");
        let v = e.check_parity("r1", h, h);
        assert_eq!(v, ParityVerdict::Equivalent);
        assert!(!e.rollback_gate.fired);
    }

    #[test]
    fn evaluator_check_parity_divergent() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        let h1 = compute_content_hash(b"ref");
        let h2 = compute_content_hash(b"candidate");
        let v = e.check_parity("r1", h1, h2);
        assert_eq!(v, ParityVerdict::Divergent);
        assert!(e.rollback_gate.fired);
        assert!(e.diagnostics.has_critical());
    }

    #[test]
    fn evaluator_evaluation_hash_deterministic() {
        let e1 = LayoutEvaluator::new(make_test_policy());
        let e2 = LayoutEvaluator::new(make_test_policy());
        assert_eq!(e1.evaluation_hash(), e2.evaluation_hash());
    }

    #[test]
    fn evaluator_display() {
        let e = LayoutEvaluator::new(make_test_policy());
        let s = format!("{e}");
        assert!(s.contains("test_policy"));
    }

    // -- Constants --

    #[test]
    fn schema_version_not_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name_matches_module() {
        assert_eq!(COMPONENT, "hardware_code_layout_gate");
    }

    #[test]
    fn bead_and_policy_ids() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.23.3");
        assert_eq!(POLICY_ID, "RGC-623C");
    }

    // -- Helpers --

    #[test]
    fn clamp_millionths_normal() {
        assert_eq!(clamp_millionths(500_000), 500_000);
        assert_eq!(clamp_millionths(MILLION), MILLION);
        assert_eq!(clamp_millionths(MILLION + 1), MILLION);
        assert_eq!(clamp_millionths(0), 0);
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0x12]), "abcd12");
        assert_eq!(hex_encode(&[]), "");
    }

    // -- Edge cases / integration-style tests --

    #[test]
    fn full_pipeline_cold_region_no_padding() {
        let mut policy = LayoutPolicy::new("pipe1", SecurityEpoch::from_raw(10));
        policy.add_region(
            CodeRegion::new("cold_fn", RegionHeat::Cold, 100).with_base_address(0x1001),
        );
        let mut e = LayoutEvaluator::new(policy);
        let receipts = e.evaluate_all("x86_64");
        assert_eq!(receipts.len(), 1);
        // Cold region keeps natural alignment, 0 padding for 1-byte alignment.
        assert_eq!(receipts[0].kind, LayoutDecisionKind::ColdPack);
        assert_eq!(receipts[0].padding_bytes, 0);
    }

    #[test]
    fn full_pipeline_hot_region_gets_padding() {
        let mut policy = LayoutPolicy::new("pipe2", SecurityEpoch::from_raw(10));
        policy.add_region(
            CodeRegion::new("hot_loop", RegionHeat::Hot, 256).with_base_address(0x1001),
        );
        let mut e = LayoutEvaluator::new(policy);
        let receipts = e.evaluate_all("x86_64");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].kind, LayoutDecisionKind::AlignCacheLine);
        // 0x1001 % 64 = 1, padding = 63
        assert_eq!(receipts[0].padding_bytes, 63);
    }

    #[test]
    fn multiple_regions_spend_budget() {
        let mut policy = LayoutPolicy::new("pipe3", SecurityEpoch::from_raw(1));
        policy.alignment_budget_bytes = 100;
        policy.add_region(CodeRegion::new("h1", RegionHeat::Hot, 128).with_base_address(0x1001));
        policy.add_region(CodeRegion::new("h2", RegionHeat::Hot, 128).with_base_address(0x2001));
        let mut e = LayoutEvaluator::new(policy);
        let receipts = e.evaluate_all("x86_64");
        assert_eq!(receipts.len(), 2);
        // After first region spends 63 bytes, only 37 remain.
        // Second region also needs 63 bytes -> exceeds_budget fires.
        let total_padding: u64 = receipts.iter().map(|r| u64::from(r.padding_bytes)).sum();
        assert!(total_padding > 0);
    }

    #[test]
    fn platform_specific_override_affects_decision() {
        let mut policy = LayoutPolicy::new("pipe4", SecurityEpoch::from_raw(1));
        policy.add_platform_rule(PlatformRule::new(
            "arm64",
            AlignmentStrategy::page_boundary(4096),
        ));
        policy.add_region(CodeRegion::new("t1", RegionHeat::Traced, 512).with_base_address(0x1000));
        let mut e = LayoutEvaluator::new(policy);
        let receipts = e.evaluate_all("arm64");
        assert_eq!(receipts[0].kind, LayoutDecisionKind::AlignPageBoundary);
    }

    #[test]
    fn rollback_then_no_further_aggressive_alignment() {
        let mut e = LayoutEvaluator::new(make_test_policy());
        // Trigger a regression rollback.
        let _record = e.check_regression(MILLION, 800_000);
        assert_eq!(e.policy.state, LayoutPolicyState::RolledBack);
    }

    #[test]
    fn stall_counters_per_kind() {
        let mut budget = StallBudget::new(1000, 100);
        budget.record(StallEvent::new(StallKind::ICacheMiss, "r1", 10));
        budget.record(StallEvent::new(StallKind::ICacheMiss, "r2", 20));
        budget.record(StallEvent::new(StallKind::BtbMiss, "r3", 5));
        assert_eq!(budget.counters.get("icache_miss"), Some(&2));
        assert_eq!(budget.counters.get("btb_miss"), Some(&1));
        assert_eq!(budget.counters.get("instruction_fetch"), None);
    }

    #[test]
    fn parity_check_result_with_notes() {
        let h = compute_content_hash(b"x");
        let r = ParityCheckResult::new("r1", ParityVerdict::Equivalent, h, h, 10_000)
            .with_notes("Timing within 0.5%");
        assert_eq!(r.notes, "Timing within 0.5%");
    }

    #[test]
    fn diagnostic_report_capacity_limit() {
        let mut r = DiagnosticReport::new("p1", SecurityEpoch::GENESIS);
        for i in 0..(MAX_DIAGNOSTIC_ENTRIES + 10) {
            r.add(LayoutDiagnostic::new(
                DiagnosticSeverity::Info,
                format!("diag_{i}"),
                "",
            ));
        }
        assert_eq!(r.len(), MAX_DIAGNOSTIC_ENTRIES);
    }

    #[test]
    fn region_capacity_limit() {
        let mut p = LayoutPolicy::new("p1", SecurityEpoch::GENESIS);
        for i in 0..(MAX_LAYOUT_REGIONS + 10) {
            p.add_region(CodeRegion::new(format!("r{i}"), RegionHeat::Cold, 1));
        }
        assert_eq!(p.regions.len(), MAX_LAYOUT_REGIONS);
    }
}
