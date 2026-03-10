#![forbid(unsafe_code)]

//! Optimized substrates for hot runtime metadata [RGC-626B].
//!
//! Implements explicit optimized substrate selection for hot runtime metadata,
//! with deterministic override, rollback, and generic-fallback paths for
//! debugging and portability triage.
//!
//! # Design decisions
//!
//! - `evaluate_substrate` drives the recommendation pipeline: profile in,
//!   decision out, with optional operator overrides.
//! - `compute_transition_cost` models migration cost in fixed-point millionths.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! - `SubstrateCertificate` content-addresses a decision so identical
//!   evaluations always produce the same hash.
//! - `build_canonical_inventory` returns 8+ realistic substrate profiles for
//!   testing and portability audits.
//! - `run_substrate_evidence` produces a manifest for CI evidence gates.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for this module.
pub const SUBSTRATE_OPT_SCHEMA_VERSION: &str = "franken-engine.metadata-substrate-optimized.v1";

/// Component name.
pub const SUBSTRATE_OPT_COMPONENT: &str = "metadata_substrate_optimized";

/// Policy identifier.
pub const SUBSTRATE_OPT_POLICY_ID: &str = "RGC-626B";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// SubstrateKind
// ---------------------------------------------------------------------------

/// Classification of the underlying optimized data structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateKind {
    /// Swiss-table (open addressing, SIMD probing).
    SwissTable,
    /// Adaptive radix tree.
    ArtTree,
    /// Flat contiguous array.
    FlatArray,
    /// Compact bitmap index.
    CompactBitmap,
    /// Inline cache stub.
    InlineCache,
    /// Pointer-swizzled page layout.
    Swizzled,
    /// Generic fallback for debugging / portability.
    GenericFallback,
}

impl fmt::Display for SubstrateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SwissTable => "swiss_table",
            Self::ArtTree => "art_tree",
            Self::FlatArray => "flat_array",
            Self::CompactBitmap => "compact_bitmap",
            Self::InlineCache => "inline_cache",
            Self::Swizzled => "swizzled",
            Self::GenericFallback => "generic_fallback",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// OptimizationLevel
// ---------------------------------------------------------------------------

/// The optimization tier applied to a substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationLevel {
    /// No optimization applied.
    Unoptimized,
    /// Locality-aware layout but no hardware-specific tuning.
    LocalityAware,
    /// Cache-line aligned structures.
    CacheLine,
    /// Software-prefetch hints injected.
    Prefetched,
    /// Fully pointer-swizzled for minimal indirection.
    FullySwizzled,
}

impl fmt::Display for OptimizationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unoptimized => "unoptimized",
            Self::LocalityAware => "locality_aware",
            Self::CacheLine => "cache_line",
            Self::Prefetched => "prefetched",
            Self::FullySwizzled => "fully_swizzled",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// FallbackPath
// ---------------------------------------------------------------------------

/// Strategy when the optimized substrate cannot service a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackPath {
    /// Linear scan of the source data.
    GenericScan,
    /// Sorted-array binary search.
    SortedArray,
    /// BTree lookup.
    BTreeLookup,
    /// Linear probing hash table.
    LinearProbe,
    /// No fallback — fail closed.
    Abstain,
}

impl fmt::Display for FallbackPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::GenericScan => "generic_scan",
            Self::SortedArray => "sorted_array",
            Self::BTreeLookup => "btree_lookup",
            Self::LinearProbe => "linear_probe",
            Self::Abstain => "abstain",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// RollbackStrategy
// ---------------------------------------------------------------------------

/// How to revert the substrate when an epoch or optimization rollback occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStrategy {
    /// Restore from a point-in-time snapshot.
    SnapshotRestore,
    /// Invalidate entries via epoch fencing.
    EpochInvalidate,
    /// Copy-on-write clone from the previous version.
    CowClone,
    /// Rebuild the substrate from scratch.
    Rebuild,
    /// No rollback — data may be lost.
    NoRollback,
}

impl fmt::Display for RollbackStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::SnapshotRestore => "snapshot_restore",
            Self::EpochInvalidate => "epoch_invalidate",
            Self::CowClone => "cow_clone",
            Self::Rebuild => "rebuild",
            Self::NoRollback => "no_rollback",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// TransitionTrigger
// ---------------------------------------------------------------------------

/// What caused a substrate transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    /// Access count exceeded the hotness threshold.
    HotnessThreshold,
    /// System under memory pressure.
    MemoryPressure,
    /// Latency spike detected.
    LatencySpike,
    /// Operator forced a substrate change.
    ManualOverride,
    /// Primary substrate fell through to fallback.
    FallbackTriggered,
    /// Portability check required a more portable substrate.
    PortabilityCheck,
}

impl fmt::Display for TransitionTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::HotnessThreshold => "hotness_threshold",
            Self::MemoryPressure => "memory_pressure",
            Self::LatencySpike => "latency_spike",
            Self::ManualOverride => "manual_override",
            Self::FallbackTriggered => "fallback_triggered",
            Self::PortabilityCheck => "portability_check",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// SubstrateError
// ---------------------------------------------------------------------------

/// Errors that can occur during substrate evaluation and transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateError {
    /// The inventory is empty and cannot be evaluated.
    EmptyInventory,
    /// A substrate profile is invalid.
    InvalidProfile {
        /// Reason the profile is invalid.
        reason: String,
    },
    /// The requested transition is forbidden.
    TransitionForbidden {
        /// Source substrate kind.
        from: SubstrateKind,
        /// Target substrate kind.
        to: SubstrateKind,
    },
    /// An operator override conflicts with the evaluation.
    OverrideConflict {
        /// Description of the conflict.
        reason: String,
    },
}

impl fmt::Display for SubstrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInventory => write!(f, "empty inventory"),
            Self::InvalidProfile { reason } => {
                write!(f, "invalid profile: {reason}")
            }
            Self::TransitionForbidden { from, to } => {
                write!(f, "transition forbidden: {from} -> {to}")
            }
            Self::OverrideConflict { reason } => {
                write!(f, "override conflict: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SubstrateProfile
// ---------------------------------------------------------------------------

/// Runtime profile of a single substrate, capturing access patterns and
/// resource consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateProfile {
    /// Unique identifier for this substrate instance.
    pub id: String,
    /// The current underlying data structure.
    pub kind: SubstrateKind,
    /// Total number of accesses observed.
    pub access_count: u64,
    /// Cache hit rate in millionths (1_000_000 = 100%).
    pub hit_rate_millionths: u64,
    /// Average lookup latency in millionths of a microsecond.
    pub avg_latency_millionths: u64,
    /// Memory consumed in bytes.
    pub memory_bytes: u64,
    /// Whether this substrate is considered hot.
    pub is_hot: bool,
}

impl fmt::Display for SubstrateProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateProfile({} kind={} accesses={} hot={})",
            self.id, self.kind, self.access_count, self.is_hot,
        )
    }
}

// ---------------------------------------------------------------------------
// OptimizationDecision
// ---------------------------------------------------------------------------

/// The output of evaluating a substrate profile: what should be done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationDecision {
    /// Which substrate this decision applies to.
    pub substrate_id: String,
    /// The current substrate kind.
    pub current_kind: SubstrateKind,
    /// The recommended replacement kind.
    pub recommended_kind: SubstrateKind,
    /// Target optimization level.
    pub optimization_level: OptimizationLevel,
    /// Fallback path if the recommended substrate fails.
    pub fallback: FallbackPath,
    /// How to rollback if the optimization is reverted.
    pub rollback: RollbackStrategy,
    /// Expected speedup in millionths (1_000_000 = 1x, 2_000_000 = 2x).
    pub expected_speedup_millionths: u64,
    /// Confidence in this recommendation (millionths; 1_000_000 = 100%).
    pub confidence_millionths: u64,
}

impl fmt::Display for OptimizationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OptimizationDecision({} {} -> {} level={} speedup={})",
            self.substrate_id,
            self.current_kind,
            self.recommended_kind,
            self.optimization_level,
            self.expected_speedup_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// OverrideConfig
// ---------------------------------------------------------------------------

/// Operator-supplied overrides that force specific substrate decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideConfig {
    /// Force a specific substrate kind regardless of profile.
    pub force_kind: Option<SubstrateKind>,
    /// Force a specific fallback path.
    pub force_fallback: Option<FallbackPath>,
    /// Force a specific rollback strategy.
    pub force_rollback: Option<RollbackStrategy>,
    /// Disable all optimization (force GenericFallback).
    pub disable_optimization: bool,
    /// Enable debug mode (extra logging, slower paths).
    pub debug_mode: bool,
}

impl Default for OverrideConfig {
    fn default() -> Self {
        Self {
            force_kind: None,
            force_fallback: None,
            force_rollback: None,
            disable_optimization: false,
            debug_mode: false,
        }
    }
}

impl fmt::Display for OverrideConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OverrideConfig(force_kind={:?} disable={} debug={})",
            self.force_kind, self.disable_optimization, self.debug_mode,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateTransition
// ---------------------------------------------------------------------------

/// Records a transition from one substrate kind to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateTransition {
    /// Source substrate kind.
    pub from_kind: SubstrateKind,
    /// Target substrate kind.
    pub to_kind: SubstrateKind,
    /// What triggered the transition.
    pub trigger: TransitionTrigger,
    /// Estimated cost of the migration in millionths.
    pub cost_millionths: u64,
}

impl fmt::Display for SubstrateTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateTransition({} -> {} trigger={} cost={})",
            self.from_kind, self.to_kind, self.trigger, self.cost_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateCertificate
// ---------------------------------------------------------------------------

/// Content-addressed certificate binding a substrate evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateCertificate {
    /// Schema version.
    pub schema_version: String,
    /// Which substrate this certificate covers.
    pub substrate_id: String,
    /// The optimization decision.
    pub decision: OptimizationDecision,
    /// Transitions recorded during this evaluation.
    pub transitions: Vec<SubstrateTransition>,
    /// Whether operator overrides were applied.
    pub overrides_applied: bool,
    /// Deterministic hash over the certificate contents.
    pub certificate_hash: ContentHash,
}

impl fmt::Display for SubstrateCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateCertificate({} overrides={} hash={})",
            self.substrate_id,
            self.overrides_applied,
            self.certificate_hash.to_hex(),
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateInventoryReport
// ---------------------------------------------------------------------------

/// Summary report over a batch of substrate evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateInventoryReport {
    /// All substrate profiles that were evaluated.
    pub profiles: Vec<SubstrateProfile>,
    /// All optimization decisions produced.
    pub decisions: Vec<OptimizationDecision>,
    /// Number of hot substrates.
    pub hot_count: u32,
    /// Number of substrates that received a non-trivial optimization.
    pub optimized_count: u32,
    /// Number of substrates that fell back to generic paths.
    pub fallback_count: u32,
    /// Deterministic hash over the report contents.
    pub report_hash: ContentHash,
}

impl fmt::Display for SubstrateInventoryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateInventoryReport(profiles={} hot={} optimized={} fallback={})",
            self.profiles.len(),
            self.hot_count,
            self.optimized_count,
            self.fallback_count,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateEvidenceManifest
// ---------------------------------------------------------------------------

/// Evidence manifest for CI gates, summarizing substrate evaluation results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Total substrates evaluated.
    pub substrates_evaluated: u32,
    /// How many received an optimization.
    pub optimized_count: u32,
    /// How many fell back to generic paths.
    pub fallback_count: u32,
    /// Certificates produced.
    pub certificates: Vec<SubstrateCertificate>,
    /// Deterministic hash over the manifest.
    pub manifest_hash: ContentHash,
    /// Optional error message if the evidence run failed.
    pub error: Option<String>,
}

impl fmt::Display for SubstrateEvidenceManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateEvidenceManifest(evaluated={} optimized={} fallback={} error={:?})",
            self.substrates_evaluated, self.optimized_count, self.fallback_count, self.error,
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Recommend a substrate kind based on the access profile.
///
/// Heuristics:
/// - Very high access count + hot -> SwissTable (best throughput).
/// - High hit rate + moderate access -> InlineCache.
/// - Large memory footprint -> ArtTree (space-efficient).
/// - Low access count -> FlatArray (simple, cache-friendly).
/// - Bitmap-eligible (very high hit rate, low memory) -> CompactBitmap.
/// - If marked not-hot -> GenericFallback.
pub fn recommend_substrate_kind(profile: &SubstrateProfile) -> SubstrateKind {
    if !profile.is_hot {
        return SubstrateKind::GenericFallback;
    }

    // Very high access count: swiss table for throughput.
    if profile.access_count > 100_000 && profile.hit_rate_millionths >= 800_000 {
        return SubstrateKind::SwissTable;
    }

    // High hit rate with compact memory: bitmap index.
    if profile.hit_rate_millionths >= 950_000 && profile.memory_bytes < 4096 {
        return SubstrateKind::CompactBitmap;
    }

    // High hit rate: inline cache.
    if profile.hit_rate_millionths >= 900_000 {
        return SubstrateKind::InlineCache;
    }

    // Large memory footprint: ART for compression.
    if profile.memory_bytes > 1_048_576 {
        return SubstrateKind::ArtTree;
    }

    // Moderate access: swizzled for pointer-heavy layouts.
    if profile.access_count > 10_000 {
        return SubstrateKind::Swizzled;
    }

    // Default for hot but low-access: flat array.
    SubstrateKind::FlatArray
}

/// Compute the migration cost in millionths when transitioning between
/// substrate kinds. Higher costs reflect more work (data copying, rehashing,
/// pointer fixup).
pub fn compute_transition_cost(from: SubstrateKind, to: SubstrateKind) -> u64 {
    if from == to {
        return 0;
    }

    // Base cost: every transition has at least some overhead.
    let base: u64 = 100_000; // 0.1x

    let structural_cost = match (from, to) {
        // Swizzled -> anything: pointer un-swizzling is expensive.
        (SubstrateKind::Swizzled, _) => 800_000,
        // Anything -> Swizzled: pointer swizzling is expensive.
        (_, SubstrateKind::Swizzled) => 700_000,
        // GenericFallback -> optimized: moderate rebuild.
        (SubstrateKind::GenericFallback, _) => 300_000,
        // Optimized -> GenericFallback: cheap teardown.
        (_, SubstrateKind::GenericFallback) => 50_000,
        // SwissTable <-> ArtTree: different hash/tree structure.
        (SubstrateKind::SwissTable, SubstrateKind::ArtTree)
        | (SubstrateKind::ArtTree, SubstrateKind::SwissTable) => 500_000,
        // FlatArray -> anything: simple copy.
        (SubstrateKind::FlatArray, _) => 200_000,
        // Anything -> FlatArray: flatten.
        (_, SubstrateKind::FlatArray) => 150_000,
        // InlineCache transitions: moderate.
        (SubstrateKind::InlineCache, _) | (_, SubstrateKind::InlineCache) => 350_000,
        // CompactBitmap transitions: moderate.
        (SubstrateKind::CompactBitmap, _) | (_, SubstrateKind::CompactBitmap) => 250_000,
        // Same-family fallthrough (shouldn't happen with from != to).
        _ => 400_000,
    };

    base.saturating_add(structural_cost)
}

/// Determine the optimization level based on the substrate profile.
fn select_optimization_level(profile: &SubstrateProfile) -> OptimizationLevel {
    if !profile.is_hot {
        return OptimizationLevel::Unoptimized;
    }
    if profile.access_count > 500_000 && profile.hit_rate_millionths >= 950_000 {
        return OptimizationLevel::FullySwizzled;
    }
    if profile.access_count > 100_000 {
        return OptimizationLevel::Prefetched;
    }
    if profile.access_count > 10_000 {
        return OptimizationLevel::CacheLine;
    }
    OptimizationLevel::LocalityAware
}

/// Select a fallback path based on the recommended substrate kind.
fn select_fallback(recommended: SubstrateKind) -> FallbackPath {
    match recommended {
        SubstrateKind::SwissTable => FallbackPath::LinearProbe,
        SubstrateKind::ArtTree => FallbackPath::BTreeLookup,
        SubstrateKind::FlatArray => FallbackPath::GenericScan,
        SubstrateKind::CompactBitmap => FallbackPath::SortedArray,
        SubstrateKind::InlineCache => FallbackPath::LinearProbe,
        SubstrateKind::Swizzled => FallbackPath::BTreeLookup,
        SubstrateKind::GenericFallback => FallbackPath::Abstain,
    }
}

/// Select a rollback strategy based on the optimization level.
fn select_rollback(level: OptimizationLevel) -> RollbackStrategy {
    match level {
        OptimizationLevel::Unoptimized => RollbackStrategy::NoRollback,
        OptimizationLevel::LocalityAware => RollbackStrategy::Rebuild,
        OptimizationLevel::CacheLine => RollbackStrategy::EpochInvalidate,
        OptimizationLevel::Prefetched => RollbackStrategy::CowClone,
        OptimizationLevel::FullySwizzled => RollbackStrategy::SnapshotRestore,
    }
}

/// Compute expected speedup in millionths based on the profile and
/// recommended kind.
fn compute_expected_speedup(profile: &SubstrateProfile, recommended: SubstrateKind) -> u64 {
    if profile.kind == recommended {
        return MILLIONTHS; // 1.0x — no change.
    }
    if recommended == SubstrateKind::GenericFallback {
        return MILLIONTHS; // 1.0x — fallback is not faster.
    }
    // Base speedup from moving to a better substrate.
    let base_speedup: u64 = match recommended {
        SubstrateKind::SwissTable => 2_500_000,    // 2.5x
        SubstrateKind::InlineCache => 3_000_000,   // 3.0x
        SubstrateKind::CompactBitmap => 2_000_000, // 2.0x
        SubstrateKind::ArtTree => 1_800_000,       // 1.8x
        SubstrateKind::Swizzled => 1_500_000,      // 1.5x
        SubstrateKind::FlatArray => 1_200_000,     // 1.2x
        SubstrateKind::GenericFallback => MILLIONTHS,
    };
    // Scale by hit rate: higher hit rate means more benefit.
    let scaled = base_speedup.saturating_mul(profile.hit_rate_millionths) / MILLIONTHS;
    // Floor at 1.0x.
    scaled.max(MILLIONTHS)
}

/// Compute confidence in millionths based on how much data we have.
fn compute_confidence(profile: &SubstrateProfile) -> u64 {
    if profile.access_count == 0 {
        return 0;
    }
    // More accesses = higher confidence, capped at 950_000 (95%).
    let raw = (profile.access_count as u128).saturating_mul(MILLIONTHS as u128) / 1_000_000u128;
    let clamped = raw.min(950_000) as u64;
    clamped
}

/// Evaluate a substrate profile and produce an optimization decision.
///
/// If `override_config` is provided, the decision is adjusted accordingly.
pub fn evaluate_substrate(
    profile: &SubstrateProfile,
    override_config: Option<&OverrideConfig>,
) -> OptimizationDecision {
    let recommended = recommend_substrate_kind(profile);
    let level = select_optimization_level(profile);
    let fallback = select_fallback(recommended);
    let rollback = select_rollback(level);
    let speedup = compute_expected_speedup(profile, recommended);
    let confidence = compute_confidence(profile);

    let mut decision = OptimizationDecision {
        substrate_id: profile.id.clone(),
        current_kind: profile.kind,
        recommended_kind: recommended,
        optimization_level: level,
        fallback,
        rollback,
        expected_speedup_millionths: speedup,
        confidence_millionths: confidence,
    };

    if let Some(config) = override_config {
        apply_override(&mut decision, config);
    }

    decision
}

/// Apply operator overrides to a decision, mutating it in place.
pub fn apply_override(decision: &mut OptimizationDecision, config: &OverrideConfig) {
    if config.disable_optimization {
        decision.recommended_kind = SubstrateKind::GenericFallback;
        decision.optimization_level = OptimizationLevel::Unoptimized;
        decision.fallback = FallbackPath::Abstain;
        decision.rollback = RollbackStrategy::NoRollback;
        decision.expected_speedup_millionths = MILLIONTHS;
        return;
    }

    if let Some(kind) = config.force_kind {
        decision.recommended_kind = kind;
    }
    if let Some(fb) = config.force_fallback {
        decision.fallback = fb;
    }
    if let Some(rb) = config.force_rollback {
        decision.rollback = rb;
    }
    if config.debug_mode {
        // In debug mode, reduce confidence to signal the decision is
        // operator-overridden and should be treated with caution.
        decision.confidence_millionths = decision.confidence_millionths.min(500_000);
    }
}

/// Produce a content-addressed certificate for a substrate evaluation.
pub fn certify_substrate(
    profile: &SubstrateProfile,
    decision: &OptimizationDecision,
) -> SubstrateCertificate {
    let transition = SubstrateTransition {
        from_kind: profile.kind,
        to_kind: decision.recommended_kind,
        trigger: if profile.kind == decision.recommended_kind {
            TransitionTrigger::PortabilityCheck
        } else if decision.recommended_kind == SubstrateKind::GenericFallback {
            TransitionTrigger::FallbackTriggered
        } else {
            TransitionTrigger::HotnessThreshold
        },
        cost_millionths: compute_transition_cost(profile.kind, decision.recommended_kind),
    };

    let overrides_applied =
        decision.recommended_kind == SubstrateKind::GenericFallback && profile.is_hot;

    let transitions = if profile.kind == decision.recommended_kind {
        Vec::new()
    } else {
        vec![transition]
    };

    let canonical = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        SUBSTRATE_OPT_SCHEMA_VERSION,
        decision.substrate_id,
        decision.current_kind,
        decision.recommended_kind,
        decision.optimization_level,
        decision.fallback,
        decision.rollback,
        decision.expected_speedup_millionths,
        decision.confidence_millionths,
    );

    SubstrateCertificate {
        schema_version: SUBSTRATE_OPT_SCHEMA_VERSION.to_string(),
        substrate_id: decision.substrate_id.clone(),
        decision: decision.clone(),
        transitions,
        overrides_applied,
        certificate_hash: ContentHash::compute(canonical.as_bytes()),
    }
}

/// Build a canonical inventory of 8 realistic substrate profiles for testing
/// and portability audits.
pub fn build_canonical_inventory() -> SubstrateInventoryReport {
    let profiles = vec![
        SubstrateProfile {
            id: "shape_table_primary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 500_000,
            hit_rate_millionths: 960_000,
            avg_latency_millionths: 50,
            memory_bytes: 65_536,
            is_hot: true,
        },
        SubstrateProfile {
            id: "ic_stub_cache".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 1_200_000,
            hit_rate_millionths: 980_000,
            avg_latency_millionths: 30,
            memory_bytes: 16_384,
            is_hot: true,
        },
        SubstrateProfile {
            id: "string_intern_table".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 200_000,
            hit_rate_millionths: 850_000,
            avg_latency_millionths: 120,
            memory_bytes: 2_097_152,
            is_hot: true,
        },
        SubstrateProfile {
            id: "scope_chain_index".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 50_000,
            hit_rate_millionths: 920_000,
            avg_latency_millionths: 80,
            memory_bytes: 8_192,
            is_hot: true,
        },
        SubstrateProfile {
            id: "module_graph_edges".into(),
            kind: SubstrateKind::ArtTree,
            access_count: 5_000,
            hit_rate_millionths: 700_000,
            avg_latency_millionths: 200,
            memory_bytes: 32_768,
            is_hot: true,
        },
        SubstrateProfile {
            id: "prototype_chain".into(),
            kind: SubstrateKind::SwissTable,
            access_count: 800_000,
            hit_rate_millionths: 950_000,
            avg_latency_millionths: 40,
            memory_bytes: 2_048,
            is_hot: true,
        },
        SubstrateProfile {
            id: "gc_mark_bitmap".into(),
            kind: SubstrateKind::CompactBitmap,
            access_count: 100,
            hit_rate_millionths: 500_000,
            avg_latency_millionths: 500,
            memory_bytes: 4_194_304,
            is_hot: false,
        },
        SubstrateProfile {
            id: "alloc_site_tracker".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 15_000,
            hit_rate_millionths: 750_000,
            avg_latency_millionths: 150,
            memory_bytes: 131_072,
            is_hot: true,
        },
    ];

    let mut decisions = Vec::new();
    let mut hot_count: u32 = 0;
    let mut optimized_count: u32 = 0;
    let mut fallback_count: u32 = 0;

    for profile in &profiles {
        let decision = evaluate_substrate(profile, None);
        if profile.is_hot {
            hot_count += 1;
        }
        if decision.recommended_kind != SubstrateKind::GenericFallback {
            optimized_count += 1;
        } else {
            fallback_count += 1;
        }
        decisions.push(decision);
    }

    let canonical = format!(
        "{}:inventory:{}:{}:{}:{}",
        SUBSTRATE_OPT_SCHEMA_VERSION,
        profiles.len(),
        hot_count,
        optimized_count,
        fallback_count,
    );

    SubstrateInventoryReport {
        profiles,
        decisions,
        hot_count,
        optimized_count,
        fallback_count,
        report_hash: ContentHash::compute(canonical.as_bytes()),
    }
}

/// Run a substrate evidence corpus, producing a manifest for CI gates.
pub fn run_substrate_evidence() -> SubstrateEvidenceManifest {
    let report = build_canonical_inventory();
    let mut certificates = Vec::new();

    for (profile, decision) in report.profiles.iter().zip(report.decisions.iter()) {
        let cert = certify_substrate(profile, decision);
        certificates.push(cert);
    }

    let canonical = format!(
        "{}:evidence:{}:{}:{}:{}",
        SUBSTRATE_OPT_SCHEMA_VERSION,
        report.profiles.len(),
        report.optimized_count,
        report.fallback_count,
        certificates.len(),
    );

    SubstrateEvidenceManifest {
        schema_version: SUBSTRATE_OPT_SCHEMA_VERSION.to_string(),
        substrates_evaluated: report.profiles.len() as u32,
        optimized_count: report.optimized_count,
        fallback_count: report.fallback_count,
        certificates,
        manifest_hash: ContentHash::compute(canonical.as_bytes()),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hot_profile(id: &str, kind: SubstrateKind, accesses: u64) -> SubstrateProfile {
        SubstrateProfile {
            id: id.into(),
            kind,
            access_count: accesses,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 100,
            memory_bytes: 32_768,
            is_hot: true,
        }
    }

    fn cold_profile(id: &str, kind: SubstrateKind) -> SubstrateProfile {
        SubstrateProfile {
            id: id.into(),
            kind,
            access_count: 100,
            hit_rate_millionths: 300_000,
            avg_latency_millionths: 500,
            memory_bytes: 65_536,
            is_hot: false,
        }
    }

    // --- Constant tests ---

    #[test]
    fn test_constants() {
        assert_eq!(
            SUBSTRATE_OPT_SCHEMA_VERSION,
            "franken-engine.metadata-substrate-optimized.v1"
        );
        assert_eq!(SUBSTRATE_OPT_COMPONENT, "metadata_substrate_optimized");
        assert_eq!(SUBSTRATE_OPT_POLICY_ID, "RGC-626B");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // --- Display tests ---

    #[test]
    fn test_substrate_kind_display() {
        assert_eq!(SubstrateKind::SwissTable.to_string(), "swiss_table");
        assert_eq!(SubstrateKind::ArtTree.to_string(), "art_tree");
        assert_eq!(SubstrateKind::FlatArray.to_string(), "flat_array");
        assert_eq!(SubstrateKind::CompactBitmap.to_string(), "compact_bitmap");
        assert_eq!(SubstrateKind::InlineCache.to_string(), "inline_cache");
        assert_eq!(SubstrateKind::Swizzled.to_string(), "swizzled");
        assert_eq!(
            SubstrateKind::GenericFallback.to_string(),
            "generic_fallback"
        );
    }

    #[test]
    fn test_optimization_level_display() {
        assert_eq!(OptimizationLevel::Unoptimized.to_string(), "unoptimized");
        assert_eq!(
            OptimizationLevel::LocalityAware.to_string(),
            "locality_aware"
        );
        assert_eq!(OptimizationLevel::CacheLine.to_string(), "cache_line");
        assert_eq!(OptimizationLevel::Prefetched.to_string(), "prefetched");
        assert_eq!(
            OptimizationLevel::FullySwizzled.to_string(),
            "fully_swizzled"
        );
    }

    #[test]
    fn test_fallback_path_display() {
        assert_eq!(FallbackPath::GenericScan.to_string(), "generic_scan");
        assert_eq!(FallbackPath::SortedArray.to_string(), "sorted_array");
        assert_eq!(FallbackPath::BTreeLookup.to_string(), "btree_lookup");
        assert_eq!(FallbackPath::LinearProbe.to_string(), "linear_probe");
        assert_eq!(FallbackPath::Abstain.to_string(), "abstain");
    }

    #[test]
    fn test_rollback_strategy_display() {
        assert_eq!(
            RollbackStrategy::SnapshotRestore.to_string(),
            "snapshot_restore"
        );
        assert_eq!(
            RollbackStrategy::EpochInvalidate.to_string(),
            "epoch_invalidate"
        );
        assert_eq!(RollbackStrategy::CowClone.to_string(), "cow_clone");
        assert_eq!(RollbackStrategy::Rebuild.to_string(), "rebuild");
        assert_eq!(RollbackStrategy::NoRollback.to_string(), "no_rollback");
    }

    #[test]
    fn test_transition_trigger_display() {
        assert_eq!(
            TransitionTrigger::HotnessThreshold.to_string(),
            "hotness_threshold"
        );
        assert_eq!(
            TransitionTrigger::MemoryPressure.to_string(),
            "memory_pressure"
        );
        assert_eq!(TransitionTrigger::LatencySpike.to_string(), "latency_spike");
        assert_eq!(
            TransitionTrigger::ManualOverride.to_string(),
            "manual_override"
        );
        assert_eq!(
            TransitionTrigger::FallbackTriggered.to_string(),
            "fallback_triggered"
        );
        assert_eq!(
            TransitionTrigger::PortabilityCheck.to_string(),
            "portability_check"
        );
    }

    #[test]
    fn test_substrate_error_display() {
        assert_eq!(
            SubstrateError::EmptyInventory.to_string(),
            "empty inventory"
        );
        let inv = SubstrateError::InvalidProfile {
            reason: "missing id".into(),
        };
        assert_eq!(inv.to_string(), "invalid profile: missing id");
        let tf = SubstrateError::TransitionForbidden {
            from: SubstrateKind::Swizzled,
            to: SubstrateKind::CompactBitmap,
        };
        assert!(tf.to_string().contains("swizzled"));
        let oc = SubstrateError::OverrideConflict {
            reason: "both force and disable".into(),
        };
        assert!(oc.to_string().contains("both force and disable"));
    }

    // --- Serde roundtrip tests ---

    #[test]
    fn test_substrate_kind_serde_roundtrip() {
        let all = [
            SubstrateKind::SwissTable,
            SubstrateKind::ArtTree,
            SubstrateKind::FlatArray,
            SubstrateKind::CompactBitmap,
            SubstrateKind::InlineCache,
            SubstrateKind::Swizzled,
            SubstrateKind::GenericFallback,
        ];
        for kind in &all {
            let json = serde_json::to_string(kind).unwrap();
            let back: SubstrateKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn test_optimization_level_serde_roundtrip() {
        let all = [
            OptimizationLevel::Unoptimized,
            OptimizationLevel::LocalityAware,
            OptimizationLevel::CacheLine,
            OptimizationLevel::Prefetched,
            OptimizationLevel::FullySwizzled,
        ];
        for level in &all {
            let json = serde_json::to_string(level).unwrap();
            let back: OptimizationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn test_fallback_path_serde_roundtrip() {
        let all = [
            FallbackPath::GenericScan,
            FallbackPath::SortedArray,
            FallbackPath::BTreeLookup,
            FallbackPath::LinearProbe,
            FallbackPath::Abstain,
        ];
        for fb in &all {
            let json = serde_json::to_string(fb).unwrap();
            let back: FallbackPath = serde_json::from_str(&json).unwrap();
            assert_eq!(*fb, back);
        }
    }

    #[test]
    fn test_decision_serde_roundtrip() {
        let profile = hot_profile("test_s", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let json = serde_json::to_string(&decision).unwrap();
        let back: OptimizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn test_certificate_serde_roundtrip() {
        let profile = hot_profile("cert_s", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        let json = serde_json::to_string(&cert).unwrap();
        let back: SubstrateCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // --- Recommendation tests ---

    #[test]
    fn test_cold_profile_gets_generic_fallback() {
        let profile = cold_profile("cold_1", SubstrateKind::FlatArray);
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::GenericFallback);
    }

    #[test]
    fn test_high_access_hot_gets_swiss_table() {
        let profile = SubstrateProfile {
            id: "hot_swiss".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 200_000,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_compact_high_hit_gets_bitmap() {
        let profile = SubstrateProfile {
            id: "bitmap_candidate".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 960_000,
            avg_latency_millionths: 20,
            memory_bytes: 2_048,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::CompactBitmap);
    }

    #[test]
    fn test_large_memory_gets_art_tree() {
        let profile = SubstrateProfile {
            id: "large_mem".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 200,
            memory_bytes: 2_097_152,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::ArtTree);
    }

    #[test]
    fn test_moderate_access_gets_swizzled() {
        let profile = SubstrateProfile {
            id: "moderate".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 50_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: 65_536,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::Swizzled);
    }

    #[test]
    fn test_low_access_hot_gets_flat_array() {
        let profile = SubstrateProfile {
            id: "low_access".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 500,
            hit_rate_millionths: 600_000,
            avg_latency_millionths: 300,
            memory_bytes: 4_096,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::FlatArray);
    }

    // --- Transition cost tests ---

    #[test]
    fn test_same_kind_zero_cost() {
        let cost = compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::SwissTable);
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_swizzled_to_flat_is_expensive() {
        let cost = compute_transition_cost(SubstrateKind::Swizzled, SubstrateKind::FlatArray);
        // Swizzled -> anything should have high structural cost.
        assert!(cost > 500_000);
    }

    #[test]
    fn test_generic_teardown_is_cheap() {
        let cost =
            compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::GenericFallback);
        // Optimized -> GenericFallback is cheap teardown.
        assert!(cost < 300_000);
    }

    // --- Override tests ---

    #[test]
    fn test_disable_optimization_override() {
        let profile = hot_profile("override_test", SubstrateKind::FlatArray, 500_000);
        let config = OverrideConfig {
            disable_optimization: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
        assert_eq!(decision.optimization_level, OptimizationLevel::Unoptimized);
        assert_eq!(decision.fallback, FallbackPath::Abstain);
        assert_eq!(decision.rollback, RollbackStrategy::NoRollback);
        assert_eq!(decision.expected_speedup_millionths, MILLIONTHS);
    }

    #[test]
    fn test_force_kind_override() {
        let profile = hot_profile("force_kind", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::CompactBitmap),
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert_eq!(decision.recommended_kind, SubstrateKind::CompactBitmap);
    }

    #[test]
    fn test_force_fallback_override() {
        let profile = hot_profile("force_fb", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            force_fallback: Some(FallbackPath::Abstain),
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert_eq!(decision.fallback, FallbackPath::Abstain);
    }

    #[test]
    fn test_debug_mode_caps_confidence() {
        let profile = hot_profile("debug_mode", SubstrateKind::FlatArray, 500_000);
        let config = OverrideConfig {
            debug_mode: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert!(decision.confidence_millionths <= 500_000);
    }

    // --- Certificate tests ---

    #[test]
    fn test_certificate_determinism() {
        let profile = hot_profile("cert_det", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let c1 = certify_substrate(&profile, &decision);
        let c2 = certify_substrate(&profile, &decision);
        assert_eq!(c1.certificate_hash, c2.certificate_hash);
    }

    #[test]
    fn test_certificate_no_transition_when_same_kind() {
        let profile = hot_profile("same_kind", SubstrateKind::InlineCache, 50_000);
        // InlineCache with 50k accesses, 900k hit rate -> InlineCache.
        let mut decision = evaluate_substrate(&profile, None);
        decision.recommended_kind = profile.kind; // Force same kind.
        let cert = certify_substrate(&profile, &decision);
        assert!(cert.transitions.is_empty());
    }

    #[test]
    fn test_certificate_has_transition_when_different_kind() {
        let profile = hot_profile("diff_kind", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        assert_ne!(decision.recommended_kind, SubstrateKind::FlatArray);
        let cert = certify_substrate(&profile, &decision);
        assert_eq!(cert.transitions.len(), 1);
        assert_eq!(cert.transitions[0].from_kind, SubstrateKind::FlatArray);
        assert_eq!(cert.transitions[0].to_kind, decision.recommended_kind);
    }

    // --- Inventory tests ---

    #[test]
    fn test_canonical_inventory_has_8_profiles() {
        let report = build_canonical_inventory();
        assert!(report.profiles.len() >= 8);
        assert_eq!(report.decisions.len(), report.profiles.len());
    }

    #[test]
    fn test_canonical_inventory_counts_consistent() {
        let report = build_canonical_inventory();
        let total = report.optimized_count + report.fallback_count;
        assert_eq!(total, report.profiles.len() as u32);
        assert!(report.hot_count > 0);
    }

    #[test]
    fn test_canonical_inventory_hash_determinism() {
        let r1 = build_canonical_inventory();
        let r2 = build_canonical_inventory();
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    // --- Evidence manifest tests ---

    #[test]
    fn test_evidence_manifest_no_error() {
        let manifest = run_substrate_evidence();
        assert!(manifest.error.is_none());
    }

    #[test]
    fn test_evidence_manifest_has_certificates() {
        let manifest = run_substrate_evidence();
        assert!(manifest.certificates.len() >= 8);
        assert_eq!(
            manifest.substrates_evaluated,
            manifest.certificates.len() as u32
        );
    }

    #[test]
    fn test_evidence_manifest_hash_determinism() {
        let m1 = run_substrate_evidence();
        let m2 = run_substrate_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn test_evidence_manifest_schema_version() {
        let manifest = run_substrate_evidence();
        assert_eq!(manifest.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
    }

    // --- Edge case tests ---

    #[test]
    fn test_zero_access_zero_confidence() {
        let profile = SubstrateProfile {
            id: "zero_access".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 0,
            hit_rate_millionths: 0,
            avg_latency_millionths: 0,
            memory_bytes: 0,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        assert_eq!(decision.confidence_millionths, 0);
    }

    #[test]
    fn test_no_override_passes_through_unchanged() {
        let profile = hot_profile("no_override", SubstrateKind::FlatArray, 200_000);
        let d1 = evaluate_substrate(&profile, None);
        let d2 = evaluate_substrate(&profile, Some(&OverrideConfig::default()));
        // Default override config should not change the decision.
        assert_eq!(d1.recommended_kind, d2.recommended_kind);
        assert_eq!(d1.fallback, d2.fallback);
        assert_eq!(d1.rollback, d2.rollback);
    }

    #[test]
    fn test_override_config_default() {
        let config = OverrideConfig::default();
        assert!(config.force_kind.is_none());
        assert!(config.force_fallback.is_none());
        assert!(config.force_rollback.is_none());
        assert!(!config.disable_optimization);
        assert!(!config.debug_mode);
    }

    #[test]
    fn test_inline_cache_recommendation() {
        // High hit rate (910k) but not extreme, moderate accesses
        let profile = SubstrateProfile {
            id: "ic_candidate".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 50_000,
            hit_rate_millionths: 910_000,
            avg_latency_millionths: 70,
            memory_bytes: 16_384,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::InlineCache);
    }

    #[test]
    fn test_force_rollback_override() {
        let profile = hot_profile("force_rb", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            force_rollback: Some(RollbackStrategy::SnapshotRestore),
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert_eq!(decision.rollback, RollbackStrategy::SnapshotRestore);
    }
}
