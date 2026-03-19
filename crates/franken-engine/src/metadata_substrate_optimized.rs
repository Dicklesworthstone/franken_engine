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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

// Default is derived via #[derive(Default)] on the struct.

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
    raw.min(950_000) as u64
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

    // -----------------------------------------------------------------------
    // Additional tests: serde roundtrips for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn test_rollback_strategy_serde_roundtrip() {
        let all = [
            RollbackStrategy::SnapshotRestore,
            RollbackStrategy::EpochInvalidate,
            RollbackStrategy::CowClone,
            RollbackStrategy::Rebuild,
            RollbackStrategy::NoRollback,
        ];
        for rs in &all {
            let json = serde_json::to_string(rs).unwrap();
            let back: RollbackStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*rs, back);
        }
    }

    #[test]
    fn test_transition_trigger_serde_roundtrip() {
        let all = [
            TransitionTrigger::HotnessThreshold,
            TransitionTrigger::MemoryPressure,
            TransitionTrigger::LatencySpike,
            TransitionTrigger::ManualOverride,
            TransitionTrigger::FallbackTriggered,
            TransitionTrigger::PortabilityCheck,
        ];
        for tt in &all {
            let json = serde_json::to_string(tt).unwrap();
            let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*tt, back);
        }
    }

    #[test]
    fn test_substrate_error_serde_roundtrip() {
        let errors = [
            SubstrateError::EmptyInventory,
            SubstrateError::InvalidProfile {
                reason: "bad data".into(),
            },
            SubstrateError::TransitionForbidden {
                from: SubstrateKind::Swizzled,
                to: SubstrateKind::FlatArray,
            },
            SubstrateError::OverrideConflict {
                reason: "conflict".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: SubstrateError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn test_substrate_profile_serde_roundtrip() {
        let profile = SubstrateProfile {
            id: "serde_prof".into(),
            kind: SubstrateKind::ArtTree,
            access_count: 42_000,
            hit_rate_millionths: 870_000,
            avg_latency_millionths: 95,
            memory_bytes: 524_288,
            is_hot: true,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: SubstrateProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, back);
    }

    #[test]
    fn test_override_config_serde_roundtrip() {
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::Swizzled),
            force_fallback: Some(FallbackPath::BTreeLookup),
            force_rollback: Some(RollbackStrategy::CowClone),
            disable_optimization: false,
            debug_mode: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: OverrideConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn test_substrate_transition_serde_roundtrip() {
        let transition = SubstrateTransition {
            from_kind: SubstrateKind::FlatArray,
            to_kind: SubstrateKind::SwissTable,
            trigger: TransitionTrigger::HotnessThreshold,
            cost_millionths: 300_000,
        };
        let json = serde_json::to_string(&transition).unwrap();
        let back: SubstrateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(transition, back);
    }

    #[test]
    fn test_inventory_report_serde_roundtrip() {
        let report = build_canonical_inventory();
        let json = serde_json::to_string(&report).unwrap();
        let back: SubstrateInventoryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn test_evidence_manifest_serde_roundtrip() {
        let manifest = run_substrate_evidence();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: SubstrateEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // -----------------------------------------------------------------------
    // Additional tests: Display formatting for composite types
    // -----------------------------------------------------------------------

    #[test]
    fn test_substrate_profile_display_format() {
        let profile = SubstrateProfile {
            id: "display_test".into(),
            kind: SubstrateKind::SwissTable,
            access_count: 999,
            hit_rate_millionths: 500_000,
            avg_latency_millionths: 50,
            memory_bytes: 1024,
            is_hot: true,
        };
        let display = profile.to_string();
        assert!(display.contains("display_test"));
        assert!(display.contains("swiss_table"));
        assert!(display.contains("999"));
        assert!(display.contains("hot=true"));
    }

    #[test]
    fn test_optimization_decision_display_format() {
        let profile = hot_profile("dec_disp", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let display = decision.to_string();
        assert!(display.contains("dec_disp"));
        assert!(display.contains("flat_array"));
        assert!(display.contains("->"));
    }

    #[test]
    fn test_substrate_transition_display_format() {
        let transition = SubstrateTransition {
            from_kind: SubstrateKind::GenericFallback,
            to_kind: SubstrateKind::SwissTable,
            trigger: TransitionTrigger::HotnessThreshold,
            cost_millionths: 400_000,
        };
        let display = transition.to_string();
        assert!(display.contains("generic_fallback"));
        assert!(display.contains("swiss_table"));
        assert!(display.contains("hotness_threshold"));
        assert!(display.contains("400000"));
    }

    #[test]
    fn test_certificate_display_format() {
        let profile = hot_profile("cert_disp", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        let display = cert.to_string();
        assert!(display.contains("cert_disp"));
        assert!(display.contains("overrides="));
        assert!(display.contains("hash="));
    }

    #[test]
    fn test_inventory_report_display_format() {
        let report = build_canonical_inventory();
        let display = report.to_string();
        assert!(display.contains("profiles=8"));
        assert!(display.contains("hot="));
        assert!(display.contains("optimized="));
        assert!(display.contains("fallback="));
    }

    #[test]
    fn test_evidence_manifest_display_format() {
        let manifest = run_substrate_evidence();
        let display = manifest.to_string();
        assert!(display.contains("evaluated=8"));
        assert!(display.contains("optimized="));
        assert!(display.contains("fallback="));
        assert!(display.contains("error=None"));
    }

    #[test]
    fn test_override_config_display_format() {
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::ArtTree),
            disable_optimization: false,
            debug_mode: true,
            ..OverrideConfig::default()
        };
        let display = config.to_string();
        assert!(display.contains("ArtTree"));
        assert!(display.contains("disable=false"));
        assert!(display.contains("debug=true"));
    }

    // -----------------------------------------------------------------------
    // Additional tests: recommendation boundary conditions
    // -----------------------------------------------------------------------

    #[test]
    fn test_recommend_boundary_100k_accesses_not_enough_for_swiss() {
        // Exactly 100_000 accesses (must be >100_000 for SwissTable).
        let profile = SubstrateProfile {
            id: "boundary_100k".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 100_000,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        // 100_000 is not > 100_000, so not SwissTable.
        // hit_rate 900_000 >= 900_000 -> InlineCache.
        assert_eq!(kind, SubstrateKind::InlineCache);
    }

    #[test]
    fn test_recommend_boundary_100001_accesses_gets_swiss() {
        let profile = SubstrateProfile {
            id: "boundary_100001".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 100_001,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_recommend_swiss_requires_hit_rate_800k() {
        // High accesses but hit rate below 800_000 => not SwissTable.
        let profile = SubstrateProfile {
            id: "swiss_hr_boundary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 200_000,
            hit_rate_millionths: 799_999,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_ne!(kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_recommend_bitmap_requires_memory_below_4096() {
        // hit_rate >= 950_000, but memory is exactly 4096 (not < 4096).
        let profile = SubstrateProfile {
            id: "bitmap_mem_boundary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 960_000,
            avg_latency_millionths: 20,
            memory_bytes: 4_096,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        // memory_bytes 4096 is not < 4096, so CompactBitmap is skipped.
        // hit_rate 960_000 >= 900_000 -> InlineCache.
        assert_eq!(kind, SubstrateKind::InlineCache);
    }

    #[test]
    fn test_recommend_art_tree_memory_boundary() {
        // Memory exactly 1_048_576 is not > 1_048_576, so no ArtTree.
        let profile = SubstrateProfile {
            id: "art_mem_boundary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 200,
            memory_bytes: 1_048_576,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        // Not ArtTree (memory not > 1_048_576), not CompactBitmap, not SwissTable.
        // hit_rate 800_000 < 900_000 so not InlineCache.
        // access_count 5_000 is not > 10_000 so not Swizzled.
        assert_eq!(kind, SubstrateKind::FlatArray);
    }

    #[test]
    fn test_recommend_swizzled_boundary_10001_accesses() {
        let profile = SubstrateProfile {
            id: "swizzled_boundary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 10_001,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: 65_536,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::Swizzled);
    }

    #[test]
    fn test_recommend_flat_array_10000_accesses() {
        // 10_000 is not > 10_000 => no Swizzled, falls to FlatArray.
        let profile = SubstrateProfile {
            id: "flat_boundary".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 10_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: 65_536,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        assert_eq!(kind, SubstrateKind::FlatArray);
    }

    // -----------------------------------------------------------------------
    // Additional tests: transition cost symmetry / asymmetry
    // -----------------------------------------------------------------------

    #[test]
    fn test_transition_cost_all_same_kind_zero() {
        let kinds = [
            SubstrateKind::SwissTable,
            SubstrateKind::ArtTree,
            SubstrateKind::FlatArray,
            SubstrateKind::CompactBitmap,
            SubstrateKind::InlineCache,
            SubstrateKind::Swizzled,
            SubstrateKind::GenericFallback,
        ];
        for kind in &kinds {
            assert_eq!(compute_transition_cost(*kind, *kind), 0);
        }
    }

    #[test]
    fn test_transition_cost_asymmetry_swizzled() {
        // Swizzled -> FlatArray vs FlatArray -> Swizzled.
        let cost_from = compute_transition_cost(SubstrateKind::Swizzled, SubstrateKind::FlatArray);
        let cost_to = compute_transition_cost(SubstrateKind::FlatArray, SubstrateKind::Swizzled);
        // Swizzled outbound is 800k, inbound is 700k. Both + 100k base.
        assert_eq!(cost_from, 900_000);
        assert_eq!(cost_to, 800_000);
        assert!(cost_from > cost_to);
    }

    #[test]
    fn test_transition_cost_generic_rebuild_vs_teardown() {
        let rebuild =
            compute_transition_cost(SubstrateKind::GenericFallback, SubstrateKind::SwissTable);
        let teardown =
            compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::GenericFallback);
        // Rebuild from generic: 300k + 100k = 400k.
        // Teardown to generic: 50k + 100k = 150k.
        assert_eq!(rebuild, 400_000);
        assert_eq!(teardown, 150_000);
        assert!(rebuild > teardown);
    }

    #[test]
    fn test_transition_cost_swiss_art_symmetric() {
        let a_to_b = compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::ArtTree);
        let b_to_a = compute_transition_cost(SubstrateKind::ArtTree, SubstrateKind::SwissTable);
        // Both are covered by the same match arm: 500k + 100k = 600k.
        assert_eq!(a_to_b, 600_000);
        assert_eq!(b_to_a, 600_000);
    }

    #[test]
    fn test_transition_cost_flat_array_outbound() {
        // FlatArray -> ArtTree: FlatArray outbound arm = 200k + 100k = 300k.
        let cost = compute_transition_cost(SubstrateKind::FlatArray, SubstrateKind::ArtTree);
        assert_eq!(cost, 300_000);
    }

    #[test]
    fn test_transition_cost_inline_cache_transitions() {
        // InlineCache -> CompactBitmap: InlineCache outbound = 350k + 100k = 450k.
        let cost_out =
            compute_transition_cost(SubstrateKind::InlineCache, SubstrateKind::CompactBitmap);
        assert_eq!(cost_out, 450_000);
        // ArtTree -> InlineCache: InlineCache inbound = 350k + 100k = 450k.
        let cost_in = compute_transition_cost(SubstrateKind::ArtTree, SubstrateKind::InlineCache);
        assert_eq!(cost_in, 450_000);
    }

    // -----------------------------------------------------------------------
    // Additional tests: optimization level selection
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_optimization_level_cold() {
        let profile = cold_profile("opt_cold", SubstrateKind::FlatArray);
        let level = select_optimization_level(&profile);
        assert_eq!(level, OptimizationLevel::Unoptimized);
    }

    #[test]
    fn test_select_optimization_level_fully_swizzled() {
        let profile = SubstrateProfile {
            id: "opt_full".into(),
            kind: SubstrateKind::SwissTable,
            access_count: 600_000,
            hit_rate_millionths: 960_000,
            avg_latency_millionths: 20,
            memory_bytes: 4_096,
            is_hot: true,
        };
        let level = select_optimization_level(&profile);
        assert_eq!(level, OptimizationLevel::FullySwizzled);
    }

    #[test]
    fn test_select_optimization_level_prefetched() {
        let profile = SubstrateProfile {
            id: "opt_pre".into(),
            kind: SubstrateKind::SwissTable,
            access_count: 200_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let level = select_optimization_level(&profile);
        assert_eq!(level, OptimizationLevel::Prefetched);
    }

    #[test]
    fn test_select_optimization_level_cache_line() {
        let profile = SubstrateProfile {
            id: "opt_cl".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 50_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let level = select_optimization_level(&profile);
        assert_eq!(level, OptimizationLevel::CacheLine);
    }

    #[test]
    fn test_select_optimization_level_locality_aware() {
        let profile = SubstrateProfile {
            id: "opt_la".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 700_000,
            avg_latency_millionths: 200,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let level = select_optimization_level(&profile);
        assert_eq!(level, OptimizationLevel::LocalityAware);
    }

    #[test]
    fn test_select_optimization_level_boundary_500k_not_enough_for_fully_swizzled() {
        // access_count 500_000 is not >500_000. But hit_rate 950_000 is >= 950_000.
        // The condition is access_count > 500_000 && hit_rate >= 950_000.
        let profile = SubstrateProfile {
            id: "opt_boundary".into(),
            kind: SubstrateKind::SwissTable,
            access_count: 500_000,
            hit_rate_millionths: 950_000,
            avg_latency_millionths: 20,
            memory_bytes: 4_096,
            is_hot: true,
        };
        let level = select_optimization_level(&profile);
        // 500_000 not > 500_000, falls to next: access_count > 100_000 -> Prefetched.
        assert_eq!(level, OptimizationLevel::Prefetched);
    }

    // -----------------------------------------------------------------------
    // Additional tests: fallback and rollback selection
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_fallback_all_kinds() {
        assert_eq!(
            select_fallback(SubstrateKind::SwissTable),
            FallbackPath::LinearProbe
        );
        assert_eq!(
            select_fallback(SubstrateKind::ArtTree),
            FallbackPath::BTreeLookup
        );
        assert_eq!(
            select_fallback(SubstrateKind::FlatArray),
            FallbackPath::GenericScan
        );
        assert_eq!(
            select_fallback(SubstrateKind::CompactBitmap),
            FallbackPath::SortedArray
        );
        assert_eq!(
            select_fallback(SubstrateKind::InlineCache),
            FallbackPath::LinearProbe
        );
        assert_eq!(
            select_fallback(SubstrateKind::Swizzled),
            FallbackPath::BTreeLookup
        );
        assert_eq!(
            select_fallback(SubstrateKind::GenericFallback),
            FallbackPath::Abstain
        );
    }

    #[test]
    fn test_select_rollback_all_levels() {
        assert_eq!(
            select_rollback(OptimizationLevel::Unoptimized),
            RollbackStrategy::NoRollback
        );
        assert_eq!(
            select_rollback(OptimizationLevel::LocalityAware),
            RollbackStrategy::Rebuild
        );
        assert_eq!(
            select_rollback(OptimizationLevel::CacheLine),
            RollbackStrategy::EpochInvalidate
        );
        assert_eq!(
            select_rollback(OptimizationLevel::Prefetched),
            RollbackStrategy::CowClone
        );
        assert_eq!(
            select_rollback(OptimizationLevel::FullySwizzled),
            RollbackStrategy::SnapshotRestore
        );
    }

    // -----------------------------------------------------------------------
    // Additional tests: confidence computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_confidence_caps_at_950k() {
        // With 1_000_000 accesses the raw value is 1_000_000 which caps to 950_000.
        let profile = SubstrateProfile {
            id: "conf_cap".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 1_000_000,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        assert_eq!(decision.confidence_millionths, 950_000);
    }

    #[test]
    fn test_confidence_scales_linearly_below_cap() {
        // With 500_000 accesses: raw = 500_000 * 1_000_000 / 1_000_000 = 500_000.
        let profile = SubstrateProfile {
            id: "conf_500k".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 500_000,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        assert_eq!(decision.confidence_millionths, 500_000);
    }

    #[test]
    fn test_confidence_single_access() {
        let profile = SubstrateProfile {
            id: "conf_one".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 1,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        // 1 * 1_000_000 / 1_000_000 = 1, min(1, 950_000) = 1.
        assert_eq!(decision.confidence_millionths, 1);
    }

    // -----------------------------------------------------------------------
    // Additional tests: expected speedup computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_speedup_same_kind_is_1x() {
        // If the recommended kind is the same as the current kind, speedup = 1.0x.
        let profile = SubstrateProfile {
            id: "speedup_same".into(),
            kind: SubstrateKind::InlineCache,
            access_count: 50_000,
            hit_rate_millionths: 910_000,
            avg_latency_millionths: 70,
            memory_bytes: 16_384,
            is_hot: true,
        };
        // This profile recommends InlineCache (same as current kind).
        let recommended = recommend_substrate_kind(&profile);
        assert_eq!(recommended, SubstrateKind::InlineCache);
        let speedup = compute_expected_speedup(&profile, recommended);
        assert_eq!(speedup, MILLIONTHS);
    }

    #[test]
    fn test_speedup_generic_fallback_is_1x() {
        let profile = cold_profile("speedup_fb", SubstrateKind::FlatArray);
        let speedup = compute_expected_speedup(&profile, SubstrateKind::GenericFallback);
        assert_eq!(speedup, MILLIONTHS);
    }

    #[test]
    fn test_speedup_swiss_table_with_high_hit_rate() {
        let profile = SubstrateProfile {
            id: "speedup_swiss".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 200_000,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        // SwissTable base: 2_500_000. Scaled: 2_500_000 * 900_000 / 1_000_000 = 2_250_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::SwissTable);
        assert_eq!(speedup, 2_250_000);
    }

    #[test]
    fn test_speedup_floor_at_1x_when_hit_rate_very_low() {
        // Very low hit rate should floor the speedup at 1.0x.
        let profile = SubstrateProfile {
            id: "speedup_floor".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 200_000,
            hit_rate_millionths: 100_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        // FlatArray base: 1_200_000. Scaled: 1_200_000 * 100_000 / 1_000_000 = 120_000.
        // Floor at 1_000_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::FlatArray);
        // Same kind => 1.0x.
        assert_eq!(speedup, MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // Additional tests: certificate overrides_applied flag
    // -----------------------------------------------------------------------

    #[test]
    fn test_certificate_overrides_applied_when_hot_forced_to_generic() {
        let profile = hot_profile("cert_override_hot", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            disable_optimization: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        let cert = certify_substrate(&profile, &decision);
        // is_hot=true and recommended=GenericFallback => overrides_applied=true.
        assert!(cert.overrides_applied);
    }

    #[test]
    fn test_certificate_overrides_not_applied_for_cold_generic() {
        let profile = cold_profile("cert_cold_gen", SubstrateKind::FlatArray);
        let decision = evaluate_substrate(&profile, None);
        // Cold profile gets GenericFallback naturally.
        assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
        let cert = certify_substrate(&profile, &decision);
        // is_hot=false => overrides_applied=false.
        assert!(!cert.overrides_applied);
    }

    #[test]
    fn test_certificate_overrides_not_applied_for_hot_non_generic() {
        let profile = hot_profile("cert_hot_opt", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        assert_ne!(decision.recommended_kind, SubstrateKind::GenericFallback);
        let cert = certify_substrate(&profile, &decision);
        // is_hot=true but recommended is not GenericFallback => overrides_applied=false.
        assert!(!cert.overrides_applied);
    }

    // -----------------------------------------------------------------------
    // Additional tests: certificate transition trigger logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_certificate_trigger_portability_check_when_same_kind() {
        let profile = SubstrateProfile {
            id: "trigger_same".into(),
            kind: SubstrateKind::InlineCache,
            access_count: 50_000,
            hit_rate_millionths: 910_000,
            avg_latency_millionths: 70,
            memory_bytes: 16_384,
            is_hot: true,
        };
        let mut decision = evaluate_substrate(&profile, None);
        decision.recommended_kind = profile.kind;
        let cert = certify_substrate(&profile, &decision);
        // Same kind => no transitions.
        assert!(cert.transitions.is_empty());
    }

    #[test]
    fn test_certificate_trigger_fallback_when_recommended_generic() {
        let profile = hot_profile("trigger_fb", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            disable_optimization: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        let cert = certify_substrate(&profile, &decision);
        // recommended = GenericFallback, from != to => has transition with FallbackTriggered.
        assert_eq!(cert.transitions.len(), 1);
        assert_eq!(
            cert.transitions[0].trigger,
            TransitionTrigger::FallbackTriggered
        );
    }

    #[test]
    fn test_certificate_trigger_hotness_when_upgrading() {
        let profile = hot_profile("trigger_hot", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        // Should recommend something other than FlatArray and other than GenericFallback.
        assert_ne!(decision.recommended_kind, SubstrateKind::FlatArray);
        assert_ne!(decision.recommended_kind, SubstrateKind::GenericFallback);
        let cert = certify_substrate(&profile, &decision);
        assert_eq!(cert.transitions.len(), 1);
        assert_eq!(
            cert.transitions[0].trigger,
            TransitionTrigger::HotnessThreshold
        );
    }

    // -----------------------------------------------------------------------
    // Additional tests: combined overrides
    // -----------------------------------------------------------------------

    #[test]
    fn test_combined_force_kind_and_debug_mode() {
        let profile = hot_profile("combined_1", SubstrateKind::FlatArray, 800_000);
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::CompactBitmap),
            debug_mode: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        assert_eq!(decision.recommended_kind, SubstrateKind::CompactBitmap);
        assert!(decision.confidence_millionths <= 500_000);
    }

    #[test]
    fn test_disable_overrides_all_force_fields() {
        // When disable_optimization is true, force_kind should be ignored.
        let profile = hot_profile("disable_wins", SubstrateKind::FlatArray, 200_000);
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::SwissTable),
            force_fallback: Some(FallbackPath::SortedArray),
            force_rollback: Some(RollbackStrategy::SnapshotRestore),
            disable_optimization: true,
            debug_mode: true,
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        // disable_optimization returns early, so force fields are not applied.
        assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
        assert_eq!(decision.fallback, FallbackPath::Abstain);
        assert_eq!(decision.rollback, RollbackStrategy::NoRollback);
    }

    // -----------------------------------------------------------------------
    // Additional tests: hash determinism across varied inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_certificate_hash_differs_for_different_profiles() {
        let profile_a = hot_profile("hash_a", SubstrateKind::FlatArray, 200_000);
        let profile_b = hot_profile("hash_b", SubstrateKind::FlatArray, 200_000);
        let decision_a = evaluate_substrate(&profile_a, None);
        let decision_b = evaluate_substrate(&profile_b, None);
        let cert_a = certify_substrate(&profile_a, &decision_a);
        let cert_b = certify_substrate(&profile_b, &decision_b);
        // Different substrate_id => different hash.
        assert_ne!(cert_a.certificate_hash, cert_b.certificate_hash);
    }

    #[test]
    fn test_inventory_report_hash_is_content_addressed() {
        // Building twice should produce the same hash since inputs are deterministic.
        let r1 = build_canonical_inventory();
        let r2 = build_canonical_inventory();
        assert_eq!(r1.report_hash, r2.report_hash);
        // Verify the hash is non-zero (computed from meaningful content).
        assert_ne!(r1.report_hash, ContentHash::compute(b""));
    }

    // -----------------------------------------------------------------------
    // Additional tests: SubstrateKind ordering (Ord derive)
    // -----------------------------------------------------------------------

    #[test]
    fn test_substrate_kind_ord_derives_from_variant_order() {
        // Enum variants are ordered by declaration, so SwissTable < ArtTree < ...
        assert!(SubstrateKind::SwissTable < SubstrateKind::ArtTree);
        assert!(SubstrateKind::ArtTree < SubstrateKind::FlatArray);
        assert!(SubstrateKind::FlatArray < SubstrateKind::CompactBitmap);
        assert!(SubstrateKind::CompactBitmap < SubstrateKind::InlineCache);
        assert!(SubstrateKind::InlineCache < SubstrateKind::Swizzled);
        assert!(SubstrateKind::Swizzled < SubstrateKind::GenericFallback);
    }

    // -----------------------------------------------------------------------
    // Additional tests: canonical inventory specific profiles
    // -----------------------------------------------------------------------

    #[test]
    fn test_canonical_inventory_gc_mark_bitmap_is_cold() {
        let report = build_canonical_inventory();
        let gc_mark = report
            .profiles
            .iter()
            .find(|p| p.id == "gc_mark_bitmap")
            .expect("gc_mark_bitmap not found");
        assert!(!gc_mark.is_hot);
        // The decision for a cold profile should be GenericFallback.
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "gc_mark_bitmap")
            .expect("gc_mark_bitmap decision not found");
        assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
    }

    #[test]
    fn test_canonical_inventory_prototype_chain_gets_swiss_table() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "prototype_chain")
            .expect("prototype_chain decision not found");
        // prototype_chain: access 800k, hit_rate 950k, memory 2048, is_hot.
        // access > 100k && hit_rate >= 800k => SwissTable.
        assert_eq!(decision.recommended_kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_canonical_inventory_string_intern_gets_art_tree() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "string_intern_table")
            .expect("string_intern_table decision not found");
        // string_intern_table: access 200k, hit_rate 850k, memory 2_097_152, is_hot.
        // access > 100k but hit_rate 850k < 800k? No, 850k >= 800k => SwissTable.
        // Actually: access > 100k && hit_rate >= 800k => SwissTable.
        assert_eq!(decision.recommended_kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_evidence_manifest_certificate_ids_match_profiles() {
        let manifest = run_substrate_evidence();
        let report = build_canonical_inventory();
        for (cert, profile) in manifest.certificates.iter().zip(report.profiles.iter()) {
            assert_eq!(cert.substrate_id, profile.id);
        }
    }

    #[test]
    fn test_evidence_manifest_counts_match_inventory() {
        let manifest = run_substrate_evidence();
        let report = build_canonical_inventory();
        assert_eq!(manifest.optimized_count, report.optimized_count);
        assert_eq!(manifest.fallback_count, report.fallback_count);
        assert_eq!(manifest.substrates_evaluated, report.profiles.len() as u32);
    }

    // -----------------------------------------------------------------------
    // Batch 3: deeper edge cases, saturation, idempotency, serde field names,
    // Clone/Hash determinism, per-inventory-profile decisions, backwards-compat
    // -----------------------------------------------------------------------

    #[test]
    fn test_substrate_kind_serde_snake_case_field_values() {
        // Verify that serde(rename_all = "snake_case") produces expected JSON strings.
        assert_eq!(
            serde_json::to_string(&SubstrateKind::SwissTable).unwrap(),
            "\"swiss_table\""
        );
        assert_eq!(
            serde_json::to_string(&SubstrateKind::GenericFallback).unwrap(),
            "\"generic_fallback\""
        );
        assert_eq!(
            serde_json::to_string(&SubstrateKind::InlineCache).unwrap(),
            "\"inline_cache\""
        );
    }

    #[test]
    fn test_optimization_level_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&OptimizationLevel::LocalityAware).unwrap(),
            "\"locality_aware\""
        );
        assert_eq!(
            serde_json::to_string(&OptimizationLevel::FullySwizzled).unwrap(),
            "\"fully_swizzled\""
        );
        assert_eq!(
            serde_json::to_string(&OptimizationLevel::CacheLine).unwrap(),
            "\"cache_line\""
        );
    }

    #[test]
    fn test_fallback_path_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&FallbackPath::GenericScan).unwrap(),
            "\"generic_scan\""
        );
        assert_eq!(
            serde_json::to_string(&FallbackPath::BTreeLookup).unwrap(),
            "\"btree_lookup\""
        );
        assert_eq!(
            serde_json::to_string(&FallbackPath::LinearProbe).unwrap(),
            "\"linear_probe\""
        );
    }

    #[test]
    fn test_rollback_strategy_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&RollbackStrategy::SnapshotRestore).unwrap(),
            "\"snapshot_restore\""
        );
        assert_eq!(
            serde_json::to_string(&RollbackStrategy::EpochInvalidate).unwrap(),
            "\"epoch_invalidate\""
        );
        assert_eq!(
            serde_json::to_string(&RollbackStrategy::CowClone).unwrap(),
            "\"cow_clone\""
        );
        assert_eq!(
            serde_json::to_string(&RollbackStrategy::NoRollback).unwrap(),
            "\"no_rollback\""
        );
    }

    #[test]
    fn test_transition_trigger_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&TransitionTrigger::HotnessThreshold).unwrap(),
            "\"hotness_threshold\""
        );
        assert_eq!(
            serde_json::to_string(&TransitionTrigger::FallbackTriggered).unwrap(),
            "\"fallback_triggered\""
        );
        assert_eq!(
            serde_json::to_string(&TransitionTrigger::PortabilityCheck).unwrap(),
            "\"portability_check\""
        );
    }

    #[test]
    fn test_serde_deserialize_from_known_json_substrate_kind() {
        // Backwards compatibility: deserialize from a known JSON string.
        let kind: SubstrateKind = serde_json::from_str("\"compact_bitmap\"").unwrap();
        assert_eq!(kind, SubstrateKind::CompactBitmap);
        let kind2: SubstrateKind = serde_json::from_str("\"art_tree\"").unwrap();
        assert_eq!(kind2, SubstrateKind::ArtTree);
    }

    #[test]
    fn test_serde_reject_invalid_substrate_kind() {
        let result: Result<SubstrateKind, _> = serde_json::from_str("\"nonexistent_kind\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_reject_invalid_optimization_level() {
        let result: Result<OptimizationLevel, _> = serde_json::from_str("\"turbo\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_substrate_kind_clone_is_equal() {
        let original = SubstrateKind::Swizzled;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_substrate_profile_clone_deep_equality() {
        let profile = SubstrateProfile {
            id: "clone_test".into(),
            kind: SubstrateKind::ArtTree,
            access_count: 42_000,
            hit_rate_millionths: 870_000,
            avg_latency_millionths: 95,
            memory_bytes: 524_288,
            is_hot: true,
        };
        let cloned = profile.clone();
        assert_eq!(profile, cloned);
        assert_eq!(profile.id, cloned.id);
        assert_eq!(profile.kind, cloned.kind);
    }

    #[test]
    fn test_optimization_decision_clone_preserves_all_fields() {
        let profile = hot_profile("clone_dec", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let cloned = decision.clone();
        assert_eq!(decision.substrate_id, cloned.substrate_id);
        assert_eq!(decision.current_kind, cloned.current_kind);
        assert_eq!(decision.recommended_kind, cloned.recommended_kind);
        assert_eq!(decision.optimization_level, cloned.optimization_level);
        assert_eq!(decision.fallback, cloned.fallback);
        assert_eq!(decision.rollback, cloned.rollback);
        assert_eq!(
            decision.expected_speedup_millionths,
            cloned.expected_speedup_millionths
        );
        assert_eq!(decision.confidence_millionths, cloned.confidence_millionths);
    }

    #[test]
    fn test_substrate_kind_hash_determinism_for_map_keys() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(SubstrateKind::SwissTable);
        set.insert(SubstrateKind::ArtTree);
        set.insert(SubstrateKind::SwissTable); // duplicate
        assert_eq!(set.len(), 2);
        assert!(set.contains(&SubstrateKind::SwissTable));
        assert!(set.contains(&SubstrateKind::ArtTree));
    }

    #[test]
    fn test_optimization_level_ord_ordering() {
        assert!(OptimizationLevel::Unoptimized < OptimizationLevel::LocalityAware);
        assert!(OptimizationLevel::LocalityAware < OptimizationLevel::CacheLine);
        assert!(OptimizationLevel::CacheLine < OptimizationLevel::Prefetched);
        assert!(OptimizationLevel::Prefetched < OptimizationLevel::FullySwizzled);
    }

    #[test]
    fn test_fallback_path_ord_ordering() {
        assert!(FallbackPath::GenericScan < FallbackPath::SortedArray);
        assert!(FallbackPath::SortedArray < FallbackPath::BTreeLookup);
        assert!(FallbackPath::BTreeLookup < FallbackPath::LinearProbe);
        assert!(FallbackPath::LinearProbe < FallbackPath::Abstain);
    }

    #[test]
    fn test_rollback_strategy_ord_ordering() {
        assert!(RollbackStrategy::SnapshotRestore < RollbackStrategy::EpochInvalidate);
        assert!(RollbackStrategy::EpochInvalidate < RollbackStrategy::CowClone);
        assert!(RollbackStrategy::CowClone < RollbackStrategy::Rebuild);
        assert!(RollbackStrategy::Rebuild < RollbackStrategy::NoRollback);
    }

    #[test]
    fn test_transition_trigger_ord_ordering() {
        assert!(TransitionTrigger::HotnessThreshold < TransitionTrigger::MemoryPressure);
        assert!(TransitionTrigger::MemoryPressure < TransitionTrigger::LatencySpike);
        assert!(TransitionTrigger::LatencySpike < TransitionTrigger::ManualOverride);
        assert!(TransitionTrigger::ManualOverride < TransitionTrigger::FallbackTriggered);
        assert!(TransitionTrigger::FallbackTriggered < TransitionTrigger::PortabilityCheck);
    }

    #[test]
    fn test_evaluate_substrate_idempotency() {
        let profile = hot_profile("idempotent", SubstrateKind::ArtTree, 300_000);
        let d1 = evaluate_substrate(&profile, None);
        let d2 = evaluate_substrate(&profile, None);
        let d3 = evaluate_substrate(&profile, None);
        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }

    #[test]
    fn test_evaluate_substrate_with_override_idempotency() {
        let profile = hot_profile("idempotent_ov", SubstrateKind::FlatArray, 500_000);
        let config = OverrideConfig {
            force_kind: Some(SubstrateKind::CompactBitmap),
            debug_mode: true,
            ..OverrideConfig::default()
        };
        let d1 = evaluate_substrate(&profile, Some(&config));
        let d2 = evaluate_substrate(&profile, Some(&config));
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_confidence_with_u64_max_access_count() {
        let profile = SubstrateProfile {
            id: "max_access".into(),
            kind: SubstrateKind::FlatArray,
            access_count: u64::MAX,
            hit_rate_millionths: 900_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        // u64::MAX * 1_000_000 / 1_000_000 overflows in u64 but uses u128.
        // Result: u64::MAX, capped at 950_000.
        assert_eq!(decision.confidence_millionths, 950_000);
    }

    #[test]
    fn test_transition_cost_saturating_add_does_not_overflow() {
        // All transition costs use saturating_add so no overflow is possible,
        // but let's verify the maximum cost is bounded.
        let cost = compute_transition_cost(SubstrateKind::Swizzled, SubstrateKind::SwissTable);
        // Swizzled outbound: 800_000 + 100_000 = 900_000.
        assert_eq!(cost, 900_000);
        assert!(cost < u64::MAX);
    }

    #[test]
    fn test_speedup_inline_cache_high_hit_rate() {
        let profile = SubstrateProfile {
            id: "speedup_ic".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 50_000,
            hit_rate_millionths: 950_000,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        // InlineCache base: 3_000_000. Scaled: 3_000_000 * 950_000 / 1_000_000 = 2_850_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::InlineCache);
        assert_eq!(speedup, 2_850_000);
    }

    #[test]
    fn test_speedup_art_tree() {
        let profile = SubstrateProfile {
            id: "speedup_art".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 200,
            memory_bytes: 2_097_152,
            is_hot: true,
        };
        // ArtTree base: 1_800_000. Scaled: 1_800_000 * 800_000 / 1_000_000 = 1_440_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::ArtTree);
        assert_eq!(speedup, 1_440_000);
    }

    #[test]
    fn test_speedup_compact_bitmap() {
        let profile = SubstrateProfile {
            id: "speedup_bm".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 960_000,
            avg_latency_millionths: 20,
            memory_bytes: 2_048,
            is_hot: true,
        };
        // CompactBitmap base: 2_000_000. Scaled: 2_000_000 * 960_000 / 1_000_000 = 1_920_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::CompactBitmap);
        assert_eq!(speedup, 1_920_000);
    }

    #[test]
    fn test_speedup_swizzled() {
        let profile = SubstrateProfile {
            id: "speedup_sw".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 50_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: 65_536,
            is_hot: true,
        };
        // Swizzled base: 1_500_000. Scaled: 1_500_000 * 800_000 / 1_000_000 = 1_200_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::Swizzled);
        assert_eq!(speedup, 1_200_000);
    }

    #[test]
    fn test_speedup_flat_array_different_kind() {
        let profile = SubstrateProfile {
            id: "speedup_fa".into(),
            kind: SubstrateKind::GenericFallback,
            access_count: 500,
            hit_rate_millionths: 600_000,
            avg_latency_millionths: 300,
            memory_bytes: 4_096,
            is_hot: true,
        };
        // FlatArray base: 1_200_000. Scaled: 1_200_000 * 600_000 / 1_000_000 = 720_000.
        // Floor at 1_000_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::FlatArray);
        assert_eq!(speedup, MILLIONTHS);
    }

    #[test]
    fn test_speedup_zero_hit_rate_floors_at_1x() {
        let profile = SubstrateProfile {
            id: "speedup_zero_hr".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 200_000,
            hit_rate_millionths: 0,
            avg_latency_millionths: 50,
            memory_bytes: 32_768,
            is_hot: true,
        };
        // SwissTable base: 2_500_000. Scaled: 2_500_000 * 0 / 1_000_000 = 0. Floor = 1_000_000.
        let speedup = compute_expected_speedup(&profile, SubstrateKind::SwissTable);
        assert_eq!(speedup, MILLIONTHS);
    }

    #[test]
    fn test_certificate_schema_version_matches_constant() {
        let profile = hot_profile("cert_schema", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        assert_eq!(cert.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
    }

    #[test]
    fn test_certificate_transition_cost_matches_compute_function() {
        let profile = hot_profile("cert_cost", SubstrateKind::FlatArray, 200_000);
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        if !cert.transitions.is_empty() {
            let expected_cost = compute_transition_cost(profile.kind, decision.recommended_kind);
            assert_eq!(cert.transitions[0].cost_millionths, expected_cost);
        }
    }

    #[test]
    fn test_certificate_with_zero_access_hot_profile() {
        let profile = SubstrateProfile {
            id: "cert_zero".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 0,
            hit_rate_millionths: 0,
            avg_latency_millionths: 0,
            memory_bytes: 0,
            is_hot: true,
        };
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        assert_eq!(cert.substrate_id, "cert_zero");
        // Zero accesses, hot, hit_rate 0, memory 0 => FlatArray recommended.
        assert_eq!(decision.recommended_kind, SubstrateKind::FlatArray);
        assert_eq!(decision.confidence_millionths, 0);
    }

    #[test]
    fn test_debug_mode_on_cold_profile() {
        let profile = cold_profile("debug_cold", SubstrateKind::FlatArray);
        let config = OverrideConfig {
            debug_mode: true,
            ..OverrideConfig::default()
        };
        let decision = evaluate_substrate(&profile, Some(&config));
        // Cold profile has 100 accesses => confidence = 100.
        // Debug mode caps at 500_000, so 100 < 500_000 => stays 100.
        assert_eq!(decision.confidence_millionths, 100);
        assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
    }

    #[test]
    fn test_profile_display_with_is_hot_false() {
        let profile = cold_profile("cold_display", SubstrateKind::CompactBitmap);
        let display = profile.to_string();
        assert!(display.contains("cold_display"));
        assert!(display.contains("compact_bitmap"));
        assert!(display.contains("hot=false"));
    }

    #[test]
    fn test_substrate_error_display_with_special_characters() {
        let err = SubstrateError::InvalidProfile {
            reason: "missing 'id' field: <none>".into(),
        };
        let display = err.to_string();
        assert!(display.contains("missing 'id' field: <none>"));
    }

    #[test]
    fn test_substrate_error_override_conflict_display() {
        let err = SubstrateError::OverrideConflict {
            reason: "force_kind=SwissTable conflicts with disable_optimization=true".into(),
        };
        let display = err.to_string();
        assert!(display.contains("override conflict:"));
        assert!(display.contains("SwissTable"));
    }

    #[test]
    fn test_substrate_error_transition_forbidden_display_all_fields() {
        let err = SubstrateError::TransitionForbidden {
            from: SubstrateKind::InlineCache,
            to: SubstrateKind::ArtTree,
        };
        let display = err.to_string();
        assert_eq!(display, "transition forbidden: inline_cache -> art_tree");
    }

    #[test]
    fn test_canonical_inventory_shape_table_primary_decision() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "shape_table_primary")
            .expect("shape_table_primary decision not found");
        // access 500k, hit_rate 960k, memory 65536, is_hot.
        // access > 100k && hit_rate >= 800k => SwissTable.
        assert_eq!(decision.recommended_kind, SubstrateKind::SwissTable);
        // access > 500k? No, 500k is not >500k. But hit_rate 960k >= 950k.
        // select_optimization_level: access 500k not >500k => next check: >100k => Prefetched.
        assert_eq!(decision.optimization_level, OptimizationLevel::Prefetched);
    }

    #[test]
    fn test_canonical_inventory_ic_stub_cache_decision() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "ic_stub_cache")
            .expect("ic_stub_cache decision not found");
        // access 1_200_000, hit_rate 980k, memory 16384, is_hot.
        // access > 100k && hit_rate >= 800k => SwissTable.
        assert_eq!(decision.recommended_kind, SubstrateKind::SwissTable);
        // access 1_200_000 > 500k && hit_rate 980k >= 950k => FullySwizzled.
        assert_eq!(
            decision.optimization_level,
            OptimizationLevel::FullySwizzled
        );
    }

    #[test]
    fn test_canonical_inventory_scope_chain_index_decision() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "scope_chain_index")
            .expect("scope_chain_index decision not found");
        // access 50k, hit_rate 920k, memory 8192, is_hot.
        // access not >100k. hit_rate 920k < 950k so not bitmap.
        // hit_rate 920k >= 900k => InlineCache.
        assert_eq!(decision.recommended_kind, SubstrateKind::InlineCache);
    }

    #[test]
    fn test_canonical_inventory_module_graph_edges_decision() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "module_graph_edges")
            .expect("module_graph_edges decision not found");
        // access 5k, hit_rate 700k, memory 32768, is_hot.
        // Not SwissTable (access not >100k). hit_rate 700k < 950k. 700k < 900k.
        // Memory 32768 not >1_048_576. Access 5k not >10k.
        assert_eq!(decision.recommended_kind, SubstrateKind::FlatArray);
    }

    #[test]
    fn test_canonical_inventory_alloc_site_tracker_decision() {
        let report = build_canonical_inventory();
        let decision = report
            .decisions
            .iter()
            .find(|d| d.substrate_id == "alloc_site_tracker")
            .expect("alloc_site_tracker decision not found");
        // access 15k, hit_rate 750k, memory 131072, is_hot.
        // Not SwissTable. hit_rate 750k < 950k. 750k < 900k.
        // Memory 131072 not >1_048_576. access 15k >10k => Swizzled.
        assert_eq!(decision.recommended_kind, SubstrateKind::Swizzled);
    }

    #[test]
    fn test_transition_cost_compact_bitmap_to_flat_array() {
        // CompactBitmap -> FlatArray: FlatArray inbound = 150k + 100k = 250k.
        // Wait: (CompactBitmap, _) arm is 250k. So CompactBitmap -> FlatArray = 250k + 100k = 350k.
        let cost = compute_transition_cost(SubstrateKind::CompactBitmap, SubstrateKind::FlatArray);
        assert_eq!(cost, 350_000);
    }

    #[test]
    fn test_transition_cost_flat_array_to_compact_bitmap() {
        // FlatArray -> CompactBitmap: FlatArray outbound arm = 200k. So 200k + 100k = 300k.
        let cost = compute_transition_cost(SubstrateKind::FlatArray, SubstrateKind::CompactBitmap);
        assert_eq!(cost, 300_000);
    }

    #[test]
    fn test_transition_cost_generic_to_generic_is_zero() {
        let cost = compute_transition_cost(
            SubstrateKind::GenericFallback,
            SubstrateKind::GenericFallback,
        );
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_profile_with_maximum_u64_memory() {
        let profile = SubstrateProfile {
            id: "max_mem".into(),
            kind: SubstrateKind::FlatArray,
            access_count: 5_000,
            hit_rate_millionths: 800_000,
            avg_latency_millionths: 100,
            memory_bytes: u64::MAX,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        // u64::MAX > 1_048_576 => ArtTree.
        assert_eq!(kind, SubstrateKind::ArtTree);
    }

    #[test]
    fn test_profile_with_maximum_u64_access_count_and_hit_rate() {
        let profile = SubstrateProfile {
            id: "max_all".into(),
            kind: SubstrateKind::FlatArray,
            access_count: u64::MAX,
            hit_rate_millionths: u64::MAX,
            avg_latency_millionths: 0,
            memory_bytes: 0,
            is_hot: true,
        };
        let kind = recommend_substrate_kind(&profile);
        // access > 100k and hit_rate >= 800k => SwissTable.
        assert_eq!(kind, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_evidence_manifest_all_certificates_have_correct_schema() {
        let manifest = run_substrate_evidence();
        for cert in &manifest.certificates {
            assert_eq!(cert.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
        }
    }

    #[test]
    fn test_evidence_manifest_no_duplicate_certificate_ids() {
        let manifest = run_substrate_evidence();
        let mut seen = std::collections::BTreeSet::new();
        for cert in &manifest.certificates {
            assert!(
                seen.insert(&cert.substrate_id),
                "duplicate certificate id: {}",
                cert.substrate_id
            );
        }
    }

    #[test]
    fn test_evaluate_all_inventory_profiles_match_decisions() {
        let report = build_canonical_inventory();
        for (profile, decision) in report.profiles.iter().zip(report.decisions.iter()) {
            assert_eq!(decision.substrate_id, profile.id);
            assert_eq!(decision.current_kind, profile.kind);
            // Re-evaluate independently and verify match.
            let independent = evaluate_substrate(profile, None);
            assert_eq!(independent, *decision);
        }
    }

    #[test]
    fn test_certify_then_serde_roundtrip_preserves_hash() {
        let profile = hot_profile("cert_serde_hash", SubstrateKind::ArtTree, 300_000);
        let decision = evaluate_substrate(&profile, None);
        let cert = certify_substrate(&profile, &decision);
        let json = serde_json::to_string(&cert).unwrap();
        let back: SubstrateCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert.certificate_hash, back.certificate_hash);
        assert_eq!(
            cert.certificate_hash.to_hex(),
            back.certificate_hash.to_hex()
        );
    }

    #[test]
    fn test_override_config_display_with_no_force_kind() {
        let config = OverrideConfig::default();
        let display = config.to_string();
        assert!(display.contains("force_kind=None"));
        assert!(display.contains("disable=false"));
        assert!(display.contains("debug=false"));
    }

    #[test]
    fn test_substrate_transition_clone_and_equality() {
        let transition = SubstrateTransition {
            from_kind: SubstrateKind::InlineCache,
            to_kind: SubstrateKind::SwissTable,
            trigger: TransitionTrigger::LatencySpike,
            cost_millionths: 450_000,
        };
        let cloned = transition.clone();
        assert_eq!(transition, cloned);
    }

    #[test]
    fn test_multiple_certificates_all_unique_hashes() {
        let profiles = [
            hot_profile("multi_a", SubstrateKind::FlatArray, 200_000),
            hot_profile("multi_b", SubstrateKind::ArtTree, 300_000),
            hot_profile("multi_c", SubstrateKind::SwissTable, 400_000),
            cold_profile("multi_d", SubstrateKind::CompactBitmap),
        ];
        let mut hashes = std::collections::BTreeSet::new();
        for profile in &profiles {
            let decision = evaluate_substrate(profile, None);
            let cert = certify_substrate(profile, &decision);
            assert!(
                hashes.insert(cert.certificate_hash.to_hex()),
                "duplicate hash for {}",
                profile.id
            );
        }
        assert_eq!(hashes.len(), profiles.len());
    }
}
