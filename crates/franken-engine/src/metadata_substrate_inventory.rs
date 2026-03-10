#![forbid(unsafe_code)]

//! Metadata substrate inventory: hot runtime metadata structure cataloging
//! and substrate contract assignment.
//!
//! Bead: bd-1lsy.7.26.1 [RGC-626A]
//!
//! Inventories hot runtime metadata structures (shape tables, IC caches,
//! string tables, scope chains, module graphs, prototype chains, etc.) and
//! assigns each a substrate contract specifying locality goals, fallback
//! semantics, and rollback rules.
//!
//! # Design decisions
//!
//! - Every metadata structure kind receives exactly one canonical substrate
//!   contract via `default_substrate_assignments`.
//! - `SubstrateContract` is content-addressed: its `content_hash` is computed
//!   deterministically from the serialized fields so that identical contracts
//!   always produce the same hash.
//! - `SubstrateInventory` tracks coverage of all known structure kinds,
//!   reporting any missing assignments through `coverage_report`.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the metadata substrate inventory.
pub const METADATA_SUBSTRATE_SCHEMA_VERSION: &str =
    "franken-engine.metadata-substrate-inventory.v1";

/// Bead identifier for this module.
pub const METADATA_SUBSTRATE_BEAD_ID: &str = "bd-1lsy.7.26.1";

/// Component name.
pub const COMPONENT: &str = "metadata_substrate_inventory";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// MetadataStructureKind
// ---------------------------------------------------------------------------

/// Classification of a hot runtime metadata structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataStructureKind {
    /// Hidden-class / transition map shape tables.
    ShapeTable,
    /// Inline cache (IC) stub/entry tables.
    InlineCacheTable,
    /// Interned string / atom tables.
    StringTable,
    /// Scope chain linkage tables.
    ScopeChainTable,
    /// Module dependency graphs.
    ModuleGraph,
    /// Prototype chain lookup tables.
    PrototypeChainTable,
    /// Type feedback vectors for speculative optimization.
    TypeFeedbackVector,
    /// Compilation artifact caches (bytecode, JIT code).
    CompilationCache,
    /// GC metadata (mark bitmaps, remembered sets, card tables).
    GcMetadata,
    /// Allocation site tracking tables.
    AllocationSiteTable,
}

impl MetadataStructureKind {
    /// All known structure kinds, in canonical order.
    pub const ALL: &[Self] = &[
        Self::ShapeTable,
        Self::InlineCacheTable,
        Self::StringTable,
        Self::ScopeChainTable,
        Self::ModuleGraph,
        Self::PrototypeChainTable,
        Self::TypeFeedbackVector,
        Self::CompilationCache,
        Self::GcMetadata,
        Self::AllocationSiteTable,
    ];
}

impl fmt::Display for MetadataStructureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ShapeTable => "shape_table",
            Self::InlineCacheTable => "inline_cache_table",
            Self::StringTable => "string_table",
            Self::ScopeChainTable => "scope_chain_table",
            Self::ModuleGraph => "module_graph",
            Self::PrototypeChainTable => "prototype_chain_table",
            Self::TypeFeedbackVector => "type_feedback_vector",
            Self::CompilationCache => "compilation_cache",
            Self::GcMetadata => "gc_metadata",
            Self::AllocationSiteTable => "allocation_site_table",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// SubstrateKind
// ---------------------------------------------------------------------------

/// The underlying data structure used to implement a metadata table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateKind {
    /// Flat contiguous array.
    FlatArray,
    /// Swiss-table (open addressing, SIMD probing).
    SwissTable,
    /// Adaptive radix tree.
    ArtTree,
    /// Hash-array mapped trie.
    HashArray,
    /// Pointer-swizzled page layout.
    Swizzled,
    /// Cache-oblivious van Emde Boas layout.
    CacheOblivious,
    /// Linear probing hash table.
    LinearProbe,
    /// B-tree index.
    BTreeIndex,
}

impl fmt::Display for SubstrateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FlatArray => "flat_array",
            Self::SwissTable => "swiss_table",
            Self::ArtTree => "art_tree",
            Self::HashArray => "hash_array",
            Self::Swizzled => "swizzled",
            Self::CacheOblivious => "cache_oblivious",
            Self::LinearProbe => "linear_probe",
            Self::BTreeIndex => "btree_index",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// LocalityGoal
// ---------------------------------------------------------------------------

/// Cache-locality objective for a metadata structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalityGoal {
    /// Must reside in L1 cache for hot-path access.
    L1Hot,
    /// Warm data — L2 residency acceptable.
    L2Warm,
    /// Cold data — L3 residency acceptable.
    L3Cold,
    /// Resident in DRAM but not necessarily cached.
    DramResident,
    /// May be evicted to slower tiers or disk.
    Evictable,
}

impl fmt::Display for LocalityGoal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::L1Hot => "l1_hot",
            Self::L2Warm => "l2_warm",
            Self::L3Cold => "l3_cold",
            Self::DramResident => "dram_resident",
            Self::Evictable => "evictable",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// FallbackMode
// ---------------------------------------------------------------------------

/// Strategy when the primary substrate cannot service a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMode {
    /// Fall back to a linear scan of the source data.
    LinearScan,
    /// Rehash into a fresh substrate.
    Rehash,
    /// Deoptimize the affected code path.
    Deoptimize,
    /// Trigger recompilation of affected code.
    Recompile,
    /// Abstain — no fallback, fail closed.
    Abstain,
}

impl fmt::Display for FallbackMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::LinearScan => "linear_scan",
            Self::Rehash => "rehash",
            Self::Deoptimize => "deoptimize",
            Self::Recompile => "recompile",
            Self::Abstain => "abstain",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// RollbackRule
// ---------------------------------------------------------------------------

/// Rollback semantics for a metadata structure during epoch transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackRule {
    /// Structure is immutable once created; rollback is a no-op.
    Immutable,
    /// Copy-on-write snapshotting at epoch boundaries.
    SnapshottedCow,
    /// Epoch-fenced: entries are invalidated on epoch advance.
    EpochFenced,
    /// Entire structure is rebuilt from source on rollback.
    Rebuilds,
    /// No rollback support — data may be lost on revert.
    NoRollback,
}

impl fmt::Display for RollbackRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Immutable => "immutable",
            Self::SnapshottedCow => "snapshotted_cow",
            Self::EpochFenced => "epoch_fenced",
            Self::Rebuilds => "rebuilds",
            Self::NoRollback => "no_rollback",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// SubstrateContract
// ---------------------------------------------------------------------------

/// A substrate contract for a metadata structure, specifying the chosen
/// substrate, locality goal, fallback mode, rollback rule, and sizing hints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateContract {
    /// Which metadata structure this contract governs.
    pub structure_kind: MetadataStructureKind,
    /// The substrate data structure to use.
    pub substrate_kind: SubstrateKind,
    /// Cache-locality goal.
    pub locality_goal: LocalityGoal,
    /// Fallback strategy on substrate failure.
    pub fallback_mode: FallbackMode,
    /// Rollback semantics.
    pub rollback_rule: RollbackRule,
    /// Maximum number of entries the substrate must support.
    pub max_entry_count: u64,
    /// Expected fraction of entries that are hot (millionths).
    pub expected_hot_fraction_millionths: u64,
    /// Content-addressed hash computed deterministically from fields above.
    pub content_hash: ContentHash,
}

impl SubstrateContract {
    /// Create a new substrate contract, computing the content hash from the
    /// canonical field representation.
    pub fn new(
        structure_kind: MetadataStructureKind,
        substrate_kind: SubstrateKind,
        locality_goal: LocalityGoal,
        fallback_mode: FallbackMode,
        rollback_rule: RollbackRule,
        max_entry_count: u64,
        expected_hot_fraction_millionths: u64,
    ) -> Self {
        let content_hash = Self::compute_hash(
            structure_kind,
            substrate_kind,
            locality_goal,
            fallback_mode,
            rollback_rule,
            max_entry_count,
            expected_hot_fraction_millionths,
        );
        Self {
            structure_kind,
            substrate_kind,
            locality_goal,
            fallback_mode,
            rollback_rule,
            max_entry_count,
            expected_hot_fraction_millionths,
            content_hash,
        }
    }

    /// Deterministic content hash from the canonical field representation.
    fn compute_hash(
        structure_kind: MetadataStructureKind,
        substrate_kind: SubstrateKind,
        locality_goal: LocalityGoal,
        fallback_mode: FallbackMode,
        rollback_rule: RollbackRule,
        max_entry_count: u64,
        expected_hot_fraction_millionths: u64,
    ) -> ContentHash {
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            structure_kind,
            substrate_kind,
            locality_goal,
            fallback_mode,
            rollback_rule,
            max_entry_count,
            expected_hot_fraction_millionths,
        );
        ContentHash::compute(canonical.as_bytes())
    }
}

impl fmt::Display for SubstrateContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateContract({} -> {} @ {} fallback={} rollback={} max={} hot={})",
            self.structure_kind,
            self.substrate_kind,
            self.locality_goal,
            self.fallback_mode,
            self.rollback_rule,
            self.max_entry_count,
            self.expected_hot_fraction_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateAssignment
// ---------------------------------------------------------------------------

/// A substrate assignment records a contract together with provenance metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateAssignment {
    /// The substrate contract.
    pub contract: SubstrateContract,
    /// Epoch at which this assignment was made.
    pub assigned_epoch: SecurityEpoch,
    /// Human-readable rationale for why this substrate was chosen.
    pub rationale: String,
    /// Confidence in the assignment (millionths; 1_000_000 = 100%).
    pub confidence_millionths: u64,
}

impl fmt::Display for SubstrateAssignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateAssignment({} epoch={} confidence={})",
            self.contract.structure_kind,
            self.assigned_epoch.as_u64(),
            self.confidence_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// InventoryCoverageReport
// ---------------------------------------------------------------------------

/// Coverage report summarizing which metadata structure kinds have
/// substrate assignments and which are missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCoverageReport {
    /// Total number of known structure kinds.
    pub total_structure_kinds: usize,
    /// Number of structure kinds with at least one assignment.
    pub assigned_structure_kinds: usize,
    /// Coverage as millionths (1_000_000 = 100%).
    pub coverage_millionths: u64,
    /// Structure kinds that have no assignment.
    pub missing_kinds: Vec<MetadataStructureKind>,
}

impl fmt::Display for InventoryCoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InventoryCoverageReport(assigned={}/{} coverage={} missing={})",
            self.assigned_structure_kinds,
            self.total_structure_kinds,
            self.coverage_millionths,
            self.missing_kinds.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateInventory
// ---------------------------------------------------------------------------

/// The top-level inventory of substrate assignments for all metadata
/// structure kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateInventory {
    /// All substrate assignments.
    pub assignments: Vec<SubstrateAssignment>,
    /// Schema version string.
    pub schema_version: String,
}

impl SubstrateInventory {
    /// Create an empty inventory with the current schema version.
    pub fn new() -> Self {
        Self {
            assignments: Vec::new(),
            schema_version: METADATA_SUBSTRATE_SCHEMA_VERSION.into(),
        }
    }

    /// Add an assignment to the inventory.
    pub fn add_assignment(&mut self, assignment: SubstrateAssignment) {
        self.assignments.push(assignment);
    }

    /// Look up all assignments for a given metadata structure kind.
    pub fn lookup(&self, kind: MetadataStructureKind) -> Vec<&SubstrateAssignment> {
        self.assignments
            .iter()
            .filter(|a| a.contract.structure_kind == kind)
            .collect()
    }

    /// Compute a coverage report over all known structure kinds.
    pub fn coverage_report(&self) -> InventoryCoverageReport {
        let all_kinds: BTreeSet<MetadataStructureKind> =
            MetadataStructureKind::ALL.iter().copied().collect();
        let assigned_kinds: BTreeSet<MetadataStructureKind> = self
            .assignments
            .iter()
            .map(|a| a.contract.structure_kind)
            .collect();
        let missing_kinds: Vec<MetadataStructureKind> =
            all_kinds.difference(&assigned_kinds).copied().collect();
        let total = all_kinds.len();
        let assigned = assigned_kinds.intersection(&all_kinds).count();
        let coverage = if total == 0 {
            0
        } else {
            (assigned as u64).saturating_mul(MILLION) / (total as u64)
        };
        InventoryCoverageReport {
            total_structure_kinds: total,
            assigned_structure_kinds: assigned,
            coverage_millionths: coverage,
            missing_kinds,
        }
    }

    /// Compute a deterministic content hash over the entire inventory.
    pub fn content_hash(&self) -> ContentHash {
        let mut canonical = String::new();
        canonical.push_str(&self.schema_version);
        canonical.push(':');
        for assignment in &self.assignments {
            canonical.push_str(&assignment.contract.content_hash.to_hex());
            canonical.push(':');
            canonical.push_str(&assignment.assigned_epoch.as_u64().to_string());
            canonical.push(':');
            canonical.push_str(&assignment.rationale);
            canonical.push(':');
            canonical.push_str(&assignment.confidence_millionths.to_string());
            canonical.push(';');
        }
        ContentHash::compute(canonical.as_bytes())
    }
}

impl Default for SubstrateInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SubstrateInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateInventory(assignments={} schema={})",
            self.assignments.len(),
            self.schema_version,
        )
    }
}

// ---------------------------------------------------------------------------
// InventoryEvidenceEntry
// ---------------------------------------------------------------------------

/// Evidence entry for specimen corpus validation of substrate assignments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InventoryEvidenceEntry {
    /// The metadata structure family being evidenced.
    pub family: MetadataStructureKind,
    /// Expected substrate assignment.
    pub expected_substrate: SubstrateKind,
    /// Expected locality goal.
    pub expected_locality: LocalityGoal,
}

impl fmt::Display for InventoryEvidenceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InventoryEvidenceEntry({} -> {} @ {})",
            self.family, self.expected_substrate, self.expected_locality,
        )
    }
}

// ---------------------------------------------------------------------------
// MetadataSubstrateSpecimenFamily
// ---------------------------------------------------------------------------

/// Specimen families corresponding to each metadata structure kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSubstrateSpecimenFamily {
    /// Shape table specimens.
    ShapeTable,
    /// Inline cache table specimens.
    InlineCacheTable,
    /// String table specimens.
    StringTable,
    /// Scope chain table specimens.
    ScopeChainTable,
    /// Module graph specimens.
    ModuleGraph,
    /// Prototype chain table specimens.
    PrototypeChainTable,
    /// Type feedback vector specimens.
    TypeFeedbackVector,
    /// Compilation cache specimens.
    CompilationCache,
    /// GC metadata specimens.
    GcMetadata,
    /// Allocation site table specimens.
    AllocationSiteTable,
}

impl MetadataSubstrateSpecimenFamily {
    /// All specimen families in canonical order.
    pub const ALL: &[Self] = &[
        Self::ShapeTable,
        Self::InlineCacheTable,
        Self::StringTable,
        Self::ScopeChainTable,
        Self::ModuleGraph,
        Self::PrototypeChainTable,
        Self::TypeFeedbackVector,
        Self::CompilationCache,
        Self::GcMetadata,
        Self::AllocationSiteTable,
    ];

    /// Convert from the corresponding `MetadataStructureKind`.
    pub fn from_structure_kind(kind: MetadataStructureKind) -> Self {
        match kind {
            MetadataStructureKind::ShapeTable => Self::ShapeTable,
            MetadataStructureKind::InlineCacheTable => Self::InlineCacheTable,
            MetadataStructureKind::StringTable => Self::StringTable,
            MetadataStructureKind::ScopeChainTable => Self::ScopeChainTable,
            MetadataStructureKind::ModuleGraph => Self::ModuleGraph,
            MetadataStructureKind::PrototypeChainTable => Self::PrototypeChainTable,
            MetadataStructureKind::TypeFeedbackVector => Self::TypeFeedbackVector,
            MetadataStructureKind::CompilationCache => Self::CompilationCache,
            MetadataStructureKind::GcMetadata => Self::GcMetadata,
            MetadataStructureKind::AllocationSiteTable => Self::AllocationSiteTable,
        }
    }
}

impl fmt::Display for MetadataSubstrateSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ShapeTable => "shape_table",
            Self::InlineCacheTable => "inline_cache_table",
            Self::StringTable => "string_table",
            Self::ScopeChainTable => "scope_chain_table",
            Self::ModuleGraph => "module_graph",
            Self::PrototypeChainTable => "prototype_chain_table",
            Self::TypeFeedbackVector => "type_feedback_vector",
            Self::CompilationCache => "compilation_cache",
            Self::GcMetadata => "gc_metadata",
            Self::AllocationSiteTable => "allocation_site_table",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// default_substrate_assignments
// ---------------------------------------------------------------------------

/// Creates the canonical default substrate inventory covering all 10 metadata
/// structure kinds with well-chosen defaults.
pub fn default_substrate_assignments(epoch: SecurityEpoch) -> SubstrateInventory {
    let mut inventory = SubstrateInventory::new();

    // Shape tables: Swiss tables for fast lookup, L1 hot, epoch-fenced rollback
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::EpochFenced,
            65_536,
            800_000, // 80% hot
        ),
        assigned_epoch: epoch,
        rationale: "Shape tables are the most frequently accessed metadata; \
                    Swiss table + L1 residency minimizes transition lookup latency"
            .into(),
        confidence_millionths: 950_000,
    });

    // Inline cache tables: flat arrays for sequential IC stubs, L1 hot
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::InlineCacheTable,
            SubstrateKind::FlatArray,
            LocalityGoal::L1Hot,
            FallbackMode::Deoptimize,
            RollbackRule::Rebuilds,
            16_384,
            900_000, // 90% hot
        ),
        assigned_epoch: epoch,
        rationale: "IC stubs are small and accessed on every property load; \
                    flat arrays keep them cache-line aligned"
            .into(),
        confidence_millionths: 980_000,
    });

    // String tables: ART for prefix-compressed interning, L2 warm
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
            LocalityGoal::L2Warm,
            FallbackMode::Rehash,
            RollbackRule::Immutable,
            1_048_576,
            300_000, // 30% hot
        ),
        assigned_epoch: epoch,
        rationale: "String tables are large with many cold entries; \
                    ART provides prefix compression for common JS property names"
            .into(),
        confidence_millionths: 850_000,
    });

    // Scope chain tables: B-tree index for ordered scope lookup
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::ScopeChainTable,
            SubstrateKind::BTreeIndex,
            LocalityGoal::L2Warm,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            8_192,
            600_000, // 60% hot
        ),
        assigned_epoch: epoch,
        rationale: "Scope chains are moderately accessed and benefit from \
                    ordered traversal during variable resolution"
            .into(),
        confidence_millionths: 900_000,
    });

    // Module graphs: hash-array mapped trie for graph traversal
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::ModuleGraph,
            SubstrateKind::HashArray,
            LocalityGoal::L3Cold,
            FallbackMode::Recompile,
            RollbackRule::Immutable,
            4_096,
            200_000, // 20% hot
        ),
        assigned_epoch: epoch,
        rationale: "Module graphs are built once at startup and rarely mutated; \
                    HAMT provides structural sharing for incremental updates"
            .into(),
        confidence_millionths: 920_000,
    });

    // Prototype chain tables: linear probing for short chains
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::PrototypeChainTable,
            SubstrateKind::LinearProbe,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::EpochFenced,
            32_768,
            700_000, // 70% hot
        ),
        assigned_epoch: epoch,
        rationale: "Prototype chains are short (typically 2-4 levels) and \
                    accessed on every method dispatch; linear probing keeps them compact"
            .into(),
        confidence_millionths: 940_000,
    });

    // Type feedback vectors: flat arrays for profiling counters
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::TypeFeedbackVector,
            SubstrateKind::FlatArray,
            LocalityGoal::L2Warm,
            FallbackMode::Deoptimize,
            RollbackRule::Rebuilds,
            32_768,
            500_000, // 50% hot
        ),
        assigned_epoch: epoch,
        rationale: "Type feedback vectors track per-site type profiles; \
                    flat layout ensures sequential counter updates are cache-friendly"
            .into(),
        confidence_millionths: 910_000,
    });

    // Compilation caches: Swiss table for code cache lookup
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::CompilationCache,
            SubstrateKind::SwissTable,
            LocalityGoal::L3Cold,
            FallbackMode::Recompile,
            RollbackRule::Rebuilds,
            8_192,
            100_000, // 10% hot
        ),
        assigned_epoch: epoch,
        rationale: "Compilation caches are accessed only on cache miss paths; \
                    Swiss table provides O(1) lookup when recompilation is needed"
            .into(),
        confidence_millionths: 870_000,
    });

    // GC metadata: cache-oblivious layout for traversal patterns
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::GcMetadata,
            SubstrateKind::CacheOblivious,
            LocalityGoal::DramResident,
            FallbackMode::Abstain,
            RollbackRule::NoRollback,
            2_097_152,
            50_000, // 5% hot
        ),
        assigned_epoch: epoch,
        rationale: "GC metadata is large and accessed in bulk during collection; \
                    cache-oblivious layout optimizes for unknown traversal order"
            .into(),
        confidence_millionths: 800_000,
    });

    // Allocation site tables: swizzled layout for pointer-rich data
    inventory.add_assignment(SubstrateAssignment {
        contract: SubstrateContract::new(
            MetadataStructureKind::AllocationSiteTable,
            SubstrateKind::Swizzled,
            LocalityGoal::L3Cold,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            131_072,
            150_000, // 15% hot
        ),
        assigned_epoch: epoch,
        rationale: "Allocation site tables track object origins for optimization; \
                    swizzled layout enables efficient pointer chasing through sites"
            .into(),
        confidence_millionths: 830_000,
    });

    inventory
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn make_contract(kind: MetadataStructureKind, substrate: SubstrateKind) -> SubstrateContract {
        SubstrateContract::new(
            kind,
            substrate,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::Immutable,
            1024,
            500_000,
        )
    }

    fn make_assignment(
        kind: MetadataStructureKind,
        substrate: SubstrateKind,
    ) -> SubstrateAssignment {
        SubstrateAssignment {
            contract: make_contract(kind, substrate),
            assigned_epoch: test_epoch(),
            rationale: format!("test assignment for {kind}"),
            confidence_millionths: 900_000,
        }
    }

    // --- Display tests ---

    #[test]
    fn test_metadata_structure_kind_display() {
        assert_eq!(MetadataStructureKind::ShapeTable.to_string(), "shape_table");
        assert_eq!(
            MetadataStructureKind::InlineCacheTable.to_string(),
            "inline_cache_table"
        );
        assert_eq!(
            MetadataStructureKind::StringTable.to_string(),
            "string_table"
        );
        assert_eq!(
            MetadataStructureKind::ScopeChainTable.to_string(),
            "scope_chain_table"
        );
        assert_eq!(
            MetadataStructureKind::ModuleGraph.to_string(),
            "module_graph"
        );
        assert_eq!(
            MetadataStructureKind::PrototypeChainTable.to_string(),
            "prototype_chain_table"
        );
        assert_eq!(
            MetadataStructureKind::TypeFeedbackVector.to_string(),
            "type_feedback_vector"
        );
        assert_eq!(
            MetadataStructureKind::CompilationCache.to_string(),
            "compilation_cache"
        );
        assert_eq!(MetadataStructureKind::GcMetadata.to_string(), "gc_metadata");
        assert_eq!(
            MetadataStructureKind::AllocationSiteTable.to_string(),
            "allocation_site_table"
        );
    }

    #[test]
    fn test_substrate_kind_display() {
        assert_eq!(SubstrateKind::FlatArray.to_string(), "flat_array");
        assert_eq!(SubstrateKind::SwissTable.to_string(), "swiss_table");
        assert_eq!(SubstrateKind::ArtTree.to_string(), "art_tree");
        assert_eq!(SubstrateKind::HashArray.to_string(), "hash_array");
        assert_eq!(SubstrateKind::Swizzled.to_string(), "swizzled");
        assert_eq!(SubstrateKind::CacheOblivious.to_string(), "cache_oblivious");
        assert_eq!(SubstrateKind::LinearProbe.to_string(), "linear_probe");
        assert_eq!(SubstrateKind::BTreeIndex.to_string(), "btree_index");
    }

    #[test]
    fn test_locality_goal_display() {
        assert_eq!(LocalityGoal::L1Hot.to_string(), "l1_hot");
        assert_eq!(LocalityGoal::L2Warm.to_string(), "l2_warm");
        assert_eq!(LocalityGoal::L3Cold.to_string(), "l3_cold");
        assert_eq!(LocalityGoal::DramResident.to_string(), "dram_resident");
        assert_eq!(LocalityGoal::Evictable.to_string(), "evictable");
    }

    #[test]
    fn test_fallback_mode_display() {
        assert_eq!(FallbackMode::LinearScan.to_string(), "linear_scan");
        assert_eq!(FallbackMode::Rehash.to_string(), "rehash");
        assert_eq!(FallbackMode::Deoptimize.to_string(), "deoptimize");
        assert_eq!(FallbackMode::Recompile.to_string(), "recompile");
        assert_eq!(FallbackMode::Abstain.to_string(), "abstain");
    }

    #[test]
    fn test_rollback_rule_display() {
        assert_eq!(RollbackRule::Immutable.to_string(), "immutable");
        assert_eq!(RollbackRule::SnapshottedCow.to_string(), "snapshotted_cow");
        assert_eq!(RollbackRule::EpochFenced.to_string(), "epoch_fenced");
        assert_eq!(RollbackRule::Rebuilds.to_string(), "rebuilds");
        assert_eq!(RollbackRule::NoRollback.to_string(), "no_rollback");
    }

    // --- Serde roundtrip tests ---

    #[test]
    fn test_metadata_structure_kind_serde_roundtrip() {
        for kind in MetadataStructureKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: MetadataStructureKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn test_substrate_kind_serde_roundtrip() {
        let all = [
            SubstrateKind::FlatArray,
            SubstrateKind::SwissTable,
            SubstrateKind::ArtTree,
            SubstrateKind::HashArray,
            SubstrateKind::Swizzled,
            SubstrateKind::CacheOblivious,
            SubstrateKind::LinearProbe,
            SubstrateKind::BTreeIndex,
        ];
        for kind in &all {
            let json = serde_json::to_string(kind).unwrap();
            let back: SubstrateKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn test_locality_goal_serde_roundtrip() {
        let all = [
            LocalityGoal::L1Hot,
            LocalityGoal::L2Warm,
            LocalityGoal::L3Cold,
            LocalityGoal::DramResident,
            LocalityGoal::Evictable,
        ];
        for goal in &all {
            let json = serde_json::to_string(goal).unwrap();
            let back: LocalityGoal = serde_json::from_str(&json).unwrap();
            assert_eq!(*goal, back);
        }
    }

    #[test]
    fn test_fallback_mode_serde_roundtrip() {
        let all = [
            FallbackMode::LinearScan,
            FallbackMode::Rehash,
            FallbackMode::Deoptimize,
            FallbackMode::Recompile,
            FallbackMode::Abstain,
        ];
        for mode in &all {
            let json = serde_json::to_string(mode).unwrap();
            let back: FallbackMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn test_rollback_rule_serde_roundtrip() {
        let all = [
            RollbackRule::Immutable,
            RollbackRule::SnapshottedCow,
            RollbackRule::EpochFenced,
            RollbackRule::Rebuilds,
            RollbackRule::NoRollback,
        ];
        for rule in &all {
            let json = serde_json::to_string(rule).unwrap();
            let back: RollbackRule = serde_json::from_str(&json).unwrap();
            assert_eq!(*rule, back);
        }
    }

    #[test]
    fn test_substrate_contract_serde_roundtrip() {
        let contract = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
        let json = serde_json::to_string(&contract).unwrap();
        let back: SubstrateContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, back);
    }

    #[test]
    fn test_substrate_assignment_serde_roundtrip() {
        let assignment = make_assignment(
            MetadataStructureKind::InlineCacheTable,
            SubstrateKind::FlatArray,
        );
        let json = serde_json::to_string(&assignment).unwrap();
        let back: SubstrateAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(assignment, back);
    }

    #[test]
    fn test_substrate_inventory_serde_roundtrip() {
        let inventory = default_substrate_assignments(test_epoch());
        let json = serde_json::to_string(&inventory).unwrap();
        let back: SubstrateInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inventory, back);
    }

    // --- Content hash tests ---

    #[test]
    fn test_contract_hash_determinism() {
        let c1 = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
        let c2 = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn test_different_contracts_different_hashes() {
        let c1 = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
        let c2 = make_contract(MetadataStructureKind::StringTable, SubstrateKind::ArtTree);
        assert_ne!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn test_inventory_hash_determinism() {
        let inv1 = default_substrate_assignments(test_epoch());
        let inv2 = default_substrate_assignments(test_epoch());
        assert_eq!(inv1.content_hash(), inv2.content_hash());
    }

    #[test]
    fn test_inventory_hash_changes_with_additions() {
        let inv1 = default_substrate_assignments(test_epoch());
        let h1 = inv1.content_hash();
        let mut inv2 = default_substrate_assignments(test_epoch());
        inv2.add_assignment(make_assignment(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::FlatArray,
        ));
        let h2 = inv2.content_hash();
        assert_ne!(h1, h2);
    }

    // --- Inventory operation tests ---

    #[test]
    fn test_empty_inventory() {
        let inv = SubstrateInventory::new();
        assert!(inv.assignments.is_empty());
        assert_eq!(inv.schema_version, METADATA_SUBSTRATE_SCHEMA_VERSION);
    }

    #[test]
    fn test_add_and_lookup() {
        let mut inv = SubstrateInventory::new();
        inv.add_assignment(make_assignment(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
        ));
        inv.add_assignment(make_assignment(
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
        ));
        let shapes = inv.lookup(MetadataStructureKind::ShapeTable);
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].contract.substrate_kind, SubstrateKind::SwissTable);
        let strings = inv.lookup(MetadataStructureKind::StringTable);
        assert_eq!(strings.len(), 1);
        let empty = inv.lookup(MetadataStructureKind::GcMetadata);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_lookup_multiple_assignments_for_same_kind() {
        let mut inv = SubstrateInventory::new();
        inv.add_assignment(make_assignment(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
        ));
        inv.add_assignment(make_assignment(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::FlatArray,
        ));
        let results = inv.lookup(MetadataStructureKind::ShapeTable);
        assert_eq!(results.len(), 2);
    }

    // --- Coverage report tests ---

    #[test]
    fn test_empty_inventory_coverage() {
        let inv = SubstrateInventory::new();
        let report = inv.coverage_report();
        assert_eq!(report.total_structure_kinds, 10);
        assert_eq!(report.assigned_structure_kinds, 0);
        assert_eq!(report.coverage_millionths, 0);
        assert_eq!(report.missing_kinds.len(), 10);
    }

    #[test]
    fn test_partial_coverage() {
        let mut inv = SubstrateInventory::new();
        inv.add_assignment(make_assignment(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
        ));
        inv.add_assignment(make_assignment(
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
        ));
        let report = inv.coverage_report();
        assert_eq!(report.total_structure_kinds, 10);
        assert_eq!(report.assigned_structure_kinds, 2);
        assert_eq!(report.coverage_millionths, 200_000); // 20%
        assert_eq!(report.missing_kinds.len(), 8);
        assert!(
            !report
                .missing_kinds
                .contains(&MetadataStructureKind::ShapeTable)
        );
        assert!(
            !report
                .missing_kinds
                .contains(&MetadataStructureKind::StringTable)
        );
    }

    #[test]
    fn test_full_coverage() {
        let inv = default_substrate_assignments(test_epoch());
        let report = inv.coverage_report();
        assert_eq!(report.total_structure_kinds, 10);
        assert_eq!(report.assigned_structure_kinds, 10);
        assert_eq!(report.coverage_millionths, MILLION);
        assert!(report.missing_kinds.is_empty());
    }

    // --- default_substrate_assignments tests ---

    #[test]
    fn test_default_assignments_cover_all_kinds() {
        let inv = default_substrate_assignments(test_epoch());
        assert_eq!(inv.assignments.len(), 10);
        let assigned_kinds: BTreeSet<MetadataStructureKind> = inv
            .assignments
            .iter()
            .map(|a| a.contract.structure_kind)
            .collect();
        for kind in MetadataStructureKind::ALL {
            assert!(
                assigned_kinds.contains(kind),
                "Missing assignment for {kind}"
            );
        }
    }

    #[test]
    fn test_default_assignments_epoch_propagation() {
        let epoch = SecurityEpoch::from_raw(42);
        let inv = default_substrate_assignments(epoch);
        for assignment in &inv.assignments {
            assert_eq!(assignment.assigned_epoch, epoch);
        }
    }

    #[test]
    fn test_default_assignments_confidence_above_zero() {
        let inv = default_substrate_assignments(test_epoch());
        for assignment in &inv.assignments {
            assert!(
                assignment.confidence_millionths > 0,
                "Confidence must be positive for {}",
                assignment.contract.structure_kind,
            );
        }
    }

    #[test]
    fn test_default_assignments_rationale_nonempty() {
        let inv = default_substrate_assignments(test_epoch());
        for assignment in &inv.assignments {
            assert!(
                !assignment.rationale.is_empty(),
                "Rationale must be non-empty for {}",
                assignment.contract.structure_kind,
            );
        }
    }

    // --- Specimen family tests ---

    #[test]
    fn test_specimen_family_all_count() {
        assert_eq!(MetadataSubstrateSpecimenFamily::ALL.len(), 10);
    }

    #[test]
    fn test_specimen_family_from_structure_kind() {
        for kind in MetadataStructureKind::ALL {
            let family = MetadataSubstrateSpecimenFamily::from_structure_kind(*kind);
            assert_eq!(family.to_string(), kind.to_string());
        }
    }

    #[test]
    fn test_specimen_family_display() {
        assert_eq!(
            MetadataSubstrateSpecimenFamily::ShapeTable.to_string(),
            "shape_table"
        );
        assert_eq!(
            MetadataSubstrateSpecimenFamily::GcMetadata.to_string(),
            "gc_metadata"
        );
    }

    // --- Evidence entry tests ---

    #[test]
    fn test_evidence_entry_display() {
        let entry = InventoryEvidenceEntry {
            family: MetadataStructureKind::ShapeTable,
            expected_substrate: SubstrateKind::SwissTable,
            expected_locality: LocalityGoal::L1Hot,
        };
        let display = entry.to_string();
        assert!(display.contains("shape_table"));
        assert!(display.contains("swiss_table"));
        assert!(display.contains("l1_hot"));
    }

    #[test]
    fn test_evidence_entry_serde_roundtrip() {
        let entry = InventoryEvidenceEntry {
            family: MetadataStructureKind::ModuleGraph,
            expected_substrate: SubstrateKind::HashArray,
            expected_locality: LocalityGoal::L3Cold,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: InventoryEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- Constants and schema tests ---

    #[test]
    fn test_schema_version_constant() {
        assert!(METADATA_SUBSTRATE_SCHEMA_VERSION.contains("metadata-substrate-inventory"));
        assert!(METADATA_SUBSTRATE_SCHEMA_VERSION.contains(".v1"));
    }

    #[test]
    fn test_bead_id_constant() {
        assert_eq!(METADATA_SUBSTRATE_BEAD_ID, "bd-1lsy.7.26.1");
    }

    #[test]
    fn test_all_structure_kinds_count() {
        assert_eq!(MetadataStructureKind::ALL.len(), 10);
    }

    // --- Display for aggregate types ---

    #[test]
    fn test_substrate_contract_display() {
        let contract = make_contract(MetadataStructureKind::ShapeTable, SubstrateKind::SwissTable);
        let display = contract.to_string();
        assert!(display.contains("shape_table"));
        assert!(display.contains("swiss_table"));
    }

    #[test]
    fn test_substrate_assignment_display() {
        let assignment = make_assignment(
            MetadataStructureKind::GcMetadata,
            SubstrateKind::CacheOblivious,
        );
        let display = assignment.to_string();
        assert!(display.contains("gc_metadata"));
        assert!(display.contains("epoch=1"));
    }

    #[test]
    fn test_inventory_display() {
        let inv = default_substrate_assignments(test_epoch());
        let display = inv.to_string();
        assert!(display.contains("assignments=10"));
    }

    #[test]
    fn test_coverage_report_display() {
        let inv = default_substrate_assignments(test_epoch());
        let report = inv.coverage_report();
        let display = report.to_string();
        assert!(display.contains("10/10"));
        assert!(display.contains("missing=0"));
    }

    // --- Edge cases ---

    #[test]
    fn test_contract_max_entry_count_zero() {
        let contract = SubstrateContract::new(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::FlatArray,
            LocalityGoal::Evictable,
            FallbackMode::Abstain,
            RollbackRule::NoRollback,
            0,
            0,
        );
        // Should still produce a valid hash
        assert_ne!(contract.content_hash, ContentHash::default());
    }

    #[test]
    fn test_contract_max_hot_fraction() {
        let contract = SubstrateContract::new(
            MetadataStructureKind::InlineCacheTable,
            SubstrateKind::FlatArray,
            LocalityGoal::L1Hot,
            FallbackMode::Deoptimize,
            RollbackRule::Rebuilds,
            u64::MAX,
            MILLION, // 100% hot
        );
        assert!(contract.expected_hot_fraction_millionths == MILLION);
    }

    #[test]
    fn test_inventory_default_impl() {
        let inv = SubstrateInventory::default();
        assert!(inv.assignments.is_empty());
        assert_eq!(inv.schema_version, METADATA_SUBSTRATE_SCHEMA_VERSION);
    }
}
