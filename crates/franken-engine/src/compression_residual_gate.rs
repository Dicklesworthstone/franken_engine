//! Bead: bd-1lsy.7.18.3 [RGC-618C]
//!
//! Compression residual gate: gates cold-start, memory, and proof-surface
//! claims on semantic-compression residuals so compactness wins are real,
//! reversible, and supportable.
//!
//! The runtime and benchmark surfaces should only claim compression wins when
//! the residual ledger says the remaining duplicate mass, restoration overhead,
//! and support costs are acceptable for the declared surface.
//!
//! ## Architecture
//!
//! 1. **Residual tracking** — remaining duplicate mass after compression passes.
//! 2. **Restoration overhead** — cost to decompress/reconstruct artifacts.
//! 3. **Cold-start claim gates** — block cold-start claims when decompression
//!    cost is too high.
//! 4. **Memory claim gates** — block memory-savings claims when hidden
//!    expansion exists.
//! 5. **Proof-surface claim gates** — block proof-size claims when compressed
//!    proofs hide overhead.
//! 6. **Reversibility verification** — ensure compressed artifacts can be
//!    fully restored.
//! 7. **Support cost estimation** — how much overhead compression adds to
//!    debugging/support.
//! 8. **Residual ledger** — persistent record of what was compressed, what
//!    remains, and what was lost.
//! 9. **Decision receipts** — for all compression claim verdicts.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! determinism. No floating point.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ── Constants ─────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for compression residual gate artifacts.
pub const COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION: &str =
    "franken-engine.compression-residual-gate.v1";

/// Component label for telemetry and evidence ledger entries.
pub const COMPRESSION_RESIDUAL_GATE_COMPONENT: &str = "compression_residual_gate";

/// Bead identifier.
pub const COMPRESSION_RESIDUAL_GATE_BEAD_ID: &str = "bd-1lsy.7.18.3";

/// Maximum number of compression entries in a single ledger.
const MAX_LEDGER_ENTRIES: usize = 10_000;

/// Maximum number of artifacts tracked in a single pass.
const MAX_ARTIFACTS_PER_PASS: usize = 1_000;

/// Default cold-start decompression budget (millionths of total startup time).
/// 50_000 = 5% of cold-start budget allowed for decompression.
const DEFAULT_COLD_START_DECOMPRESSION_BUDGET_MILLIONTHS: i64 = 50_000;

/// Default memory hidden expansion threshold (millionths).
/// 100_000 = 10% hidden expansion tolerance.
const DEFAULT_MEMORY_HIDDEN_EXPANSION_THRESHOLD_MILLIONTHS: i64 = 100_000;

/// Default proof overhead threshold (millionths).
/// 150_000 = 15% proof overhead tolerance.
const DEFAULT_PROOF_OVERHEAD_THRESHOLD_MILLIONTHS: i64 = 150_000;

/// Default support cost ceiling (millionths).
/// 200_000 = 20% support cost ceiling.
const DEFAULT_SUPPORT_COST_CEILING_MILLIONTHS: i64 = 200_000;

/// Default reversibility threshold (millionths).
/// 999_000 = 99.9% restoration fidelity required.
const DEFAULT_REVERSIBILITY_THRESHOLD_MILLIONTHS: i64 = 999_000;

// ── Claim surface ─────────────────────────────────────────────────────

/// The surface on which a compression claim is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSurface {
    /// Cold-start performance claim (startup time reduction via compression).
    ColdStart,
    /// Memory savings claim (reduced resident footprint).
    Memory,
    /// Proof-surface claim (smaller proof artifacts).
    ProofSurface,
}

impl ClaimSurface {
    /// All surfaces in canonical order.
    pub const ALL: [ClaimSurface; 3] = [
        ClaimSurface::ColdStart,
        ClaimSurface::Memory,
        ClaimSurface::ProofSurface,
    ];
}

impl fmt::Display for ClaimSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ColdStart => "cold_start",
            Self::Memory => "memory",
            Self::ProofSurface => "proof_surface",
        };
        write!(f, "{label}")
    }
}

// ── Compression pass kind ─────────────────────────────────────────────

/// The kind of compression pass that was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionPassKind {
    /// Deduplication: identical artifacts collapsed to a single copy.
    Deduplication,
    /// Structural sharing: sub-tree sharing across artifacts.
    StructuralSharing,
    /// Delta encoding: store diffs against a base.
    DeltaEncoding,
    /// Entropy coding: statistical compression.
    EntropyCoding,
    /// Proof compaction: merge/fold proof nodes.
    ProofCompaction,
    /// Semantic folding: merge semantically equivalent subtrees.
    SemanticFolding,
}

impl fmt::Display for CompressionPassKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Deduplication => "deduplication",
            Self::StructuralSharing => "structural_sharing",
            Self::DeltaEncoding => "delta_encoding",
            Self::EntropyCoding => "entropy_coding",
            Self::ProofCompaction => "proof_compaction",
            Self::SemanticFolding => "semantic_folding",
        };
        write!(f, "{label}")
    }
}

// ── Artifact record ───────────────────────────────────────────────────

/// A record of a single artifact that underwent compression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Unique identifier for this artifact.
    pub artifact_id: String,
    /// Size before compression (bytes).
    pub original_size_bytes: u64,
    /// Size after compression (bytes).
    pub compressed_size_bytes: u64,
    /// Content hash of the original artifact.
    pub original_hash: ContentHash,
    /// Content hash of the compressed artifact.
    pub compressed_hash: ContentHash,
    /// Which compression pass was applied.
    pub pass_kind: CompressionPassKind,
    /// Whether the artifact was fully reversible (decompressed matches original).
    pub reversible: bool,
    /// Restoration overhead in microseconds (time to decompress).
    pub restoration_overhead_us: u64,
    /// Number of duplicate fragments removed.
    pub duplicates_removed: u64,
    /// Number of duplicate fragments remaining.
    pub duplicates_remaining: u64,
}

impl ArtifactRecord {
    /// Compression ratio in millionths (1_000_000 = 1:1, 500_000 = 2:1).
    pub fn compression_ratio_millionths(&self) -> i64 {
        if self.original_size_bytes == 0 {
            return MILLION;
        }
        (self.compressed_size_bytes as i128 * MILLION as i128 / self.original_size_bytes as i128)
            as i64
    }

    /// Space savings in millionths (1_000_000 = 100% savings).
    pub fn space_savings_millionths(&self) -> i64 {
        MILLION - self.compression_ratio_millionths()
    }

    /// Remaining duplicate mass as a fraction of original in millionths.
    pub fn remaining_duplicate_mass_millionths(&self) -> i64 {
        let total = self.duplicates_removed + self.duplicates_remaining;
        if total == 0 {
            return 0;
        }
        (self.duplicates_remaining as i128 * MILLION as i128 / total as i128) as i64
    }
}

// ── Compression pass result ───────────────────────────────────────────

/// Result of a single compression pass across a set of artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionPassResult {
    /// Unique pass identifier.
    pub pass_id: String,
    /// Kind of compression applied.
    pub pass_kind: CompressionPassKind,
    /// Artifacts processed in this pass.
    pub artifacts: Vec<ArtifactRecord>,
    /// Total original size across all artifacts (bytes).
    pub total_original_bytes: u64,
    /// Total compressed size across all artifacts (bytes).
    pub total_compressed_bytes: u64,
    /// Total restoration overhead (microseconds).
    pub total_restoration_overhead_us: u64,
    /// Total duplicates removed.
    pub total_duplicates_removed: u64,
    /// Total duplicates remaining.
    pub total_duplicates_remaining: u64,
    /// Number of artifacts that are fully reversible.
    pub reversible_count: usize,
    /// Number of artifacts that are NOT fully reversible.
    pub irreversible_count: usize,
    /// Security epoch when this pass was executed.
    pub epoch: SecurityEpoch,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

impl CompressionPassResult {
    /// Aggregate compression ratio in millionths.
    pub fn aggregate_compression_ratio_millionths(&self) -> i64 {
        if self.total_original_bytes == 0 {
            return MILLION;
        }
        (self.total_compressed_bytes as i128 * MILLION as i128 / self.total_original_bytes as i128)
            as i64
    }

    /// Aggregate space savings in millionths.
    pub fn aggregate_savings_millionths(&self) -> i64 {
        MILLION - self.aggregate_compression_ratio_millionths()
    }

    /// Whether all artifacts in this pass are reversible.
    pub fn fully_reversible(&self) -> bool {
        self.irreversible_count == 0
    }

    /// Remaining duplicate mass ratio in millionths.
    pub fn remaining_duplicate_mass_millionths(&self) -> i64 {
        let total = self.total_duplicates_removed + self.total_duplicates_remaining;
        if total == 0 {
            return 0;
        }
        (self.total_duplicates_remaining as i128 * MILLION as i128 / total as i128) as i64
    }
}

// ── Hidden expansion record ───────────────────────────────────────────

/// Tracks hidden memory expansion caused by compression metadata/indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenExpansionRecord {
    /// Artifact or subsystem identifier.
    pub source_id: String,
    /// Memory saved by compression (bytes).
    pub memory_saved_bytes: u64,
    /// Hidden memory cost: decompression buffers, lookup tables, indexes.
    pub hidden_cost_bytes: u64,
    /// Net memory change (positive = net savings, negative = net expansion).
    pub net_change_bytes: i64,
    /// Explanation of what causes the hidden cost.
    pub cost_explanation: String,
}

impl HiddenExpansionRecord {
    /// Hidden expansion ratio in millionths: hidden_cost / memory_saved.
    /// Values above 1_000_000 mean hidden cost exceeds savings.
    pub fn expansion_ratio_millionths(&self) -> i64 {
        if self.memory_saved_bytes == 0 {
            if self.hidden_cost_bytes > 0 {
                return MILLION * 2; // infinite expansion, cap at 2x
            }
            return 0;
        }
        (self.hidden_cost_bytes as i128 * MILLION as i128 / self.memory_saved_bytes as i128) as i64
    }

    /// Whether this record shows net savings (true) or net expansion (false).
    pub fn is_net_savings(&self) -> bool {
        self.net_change_bytes > 0
    }
}

// ── Support cost record ───────────────────────────────────────────────

/// Estimates debugging/support overhead introduced by compression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportCostRecord {
    /// Subsystem or artifact identifier.
    pub source_id: String,
    /// Baseline support cost (arbitrary units, millionths-scaled).
    pub baseline_cost_millionths: i64,
    /// Additional support cost introduced by compression.
    pub compression_overhead_millionths: i64,
    /// Number of additional indirection layers added.
    pub indirection_layers: u32,
    /// Whether compressed artifacts produce readable debug output.
    pub debug_readable: bool,
    /// Whether stack traces through compressed code are accurate.
    pub stack_traces_accurate: bool,
    /// Explanation of support cost drivers.
    pub explanation: String,
}

impl SupportCostRecord {
    /// Total support cost in millionths.
    pub fn total_cost_millionths(&self) -> i64 {
        self.baseline_cost_millionths
            .saturating_add(self.compression_overhead_millionths)
    }

    /// Overhead ratio: compression_overhead / baseline.
    pub fn overhead_ratio_millionths(&self) -> i64 {
        if self.baseline_cost_millionths <= 0 {
            if self.compression_overhead_millionths > 0 {
                return MILLION * 2;
            }
            return 0;
        }
        (self.compression_overhead_millionths as i128 * MILLION as i128
            / self.baseline_cost_millionths as i128) as i64
    }
}

// ── Reversibility check ───────────────────────────────────────────────

/// Result of a reversibility verification for a single artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibilityCheck {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Original content hash.
    pub original_hash: ContentHash,
    /// Hash of the restored (decompressed) content.
    pub restored_hash: ContentHash,
    /// Whether the restored content matches the original exactly.
    pub exact_match: bool,
    /// Restoration fidelity in millionths (1_000_000 = perfect).
    pub fidelity_millionths: i64,
    /// Bytes that differ between original and restored.
    pub divergent_bytes: u64,
    /// Total bytes compared.
    pub total_bytes: u64,
    /// Restoration time in microseconds.
    pub restoration_time_us: u64,
}

impl ReversibilityCheck {
    /// Whether the fidelity meets a given threshold (millionths).
    pub fn meets_fidelity_threshold(&self, threshold_millionths: i64) -> bool {
        self.fidelity_millionths >= threshold_millionths
    }
}

// ── Gate verdict ──────────────────────────────────────────────────────

/// Verdict for a compression claim gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionClaimVerdict {
    /// Claim is approved: residuals are acceptable.
    Approved,
    /// Claim is approved with caveats (residuals are marginal).
    ApprovedWithCaveats,
    /// Claim is blocked: residuals are unacceptable.
    Blocked,
    /// Insufficient data to evaluate the claim.
    Insufficient,
}

impl fmt::Display for CompressionClaimVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Approved => "approved",
            Self::ApprovedWithCaveats => "approved_with_caveats",
            Self::Blocked => "blocked",
            Self::Insufficient => "insufficient",
        };
        write!(f, "{label}")
    }
}

// ── Blocking reason ───────────────────────────────────────────────────

/// Reason why a compression claim was blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimBlockingReason {
    /// Decompression cost exceeds cold-start budget.
    DecompressionCostExceedsBudget {
        observed_millionths: i64,
        budget_millionths: i64,
    },
    /// Hidden memory expansion exceeds threshold.
    HiddenExpansionExceedsThreshold {
        observed_millionths: i64,
        threshold_millionths: i64,
    },
    /// Proof overhead exceeds threshold.
    ProofOverheadExceedsThreshold {
        observed_millionths: i64,
        threshold_millionths: i64,
    },
    /// Remaining duplicate mass is too high.
    ExcessiveDuplicateMass {
        remaining_millionths: i64,
        max_millionths: i64,
    },
    /// Artifact is not reversible.
    IrreversibleArtifact { artifact_id: String },
    /// Restoration fidelity below required threshold.
    InsufficientFidelity {
        artifact_id: String,
        fidelity_millionths: i64,
        required_millionths: i64,
    },
    /// Support cost ceiling exceeded.
    SupportCostCeilingExceeded {
        observed_millionths: i64,
        ceiling_millionths: i64,
    },
    /// No compression pass data available.
    NoCompressionData,
    /// Net memory expansion (compression made things larger).
    NetMemoryExpansion { net_change_bytes: i64 },
    /// Debug readability lost.
    DebugReadabilityLost { source_id: String },
    /// Stack trace accuracy lost.
    StackTraceAccuracyLost { source_id: String },
}

impl fmt::Display for ClaimBlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecompressionCostExceedsBudget {
                observed_millionths,
                budget_millionths,
            } => write!(
                f,
                "decompression cost {observed_millionths} exceeds budget {budget_millionths}"
            ),
            Self::HiddenExpansionExceedsThreshold {
                observed_millionths,
                threshold_millionths,
            } => write!(
                f,
                "hidden expansion {observed_millionths} exceeds threshold {threshold_millionths}"
            ),
            Self::ProofOverheadExceedsThreshold {
                observed_millionths,
                threshold_millionths,
            } => write!(
                f,
                "proof overhead {observed_millionths} exceeds threshold {threshold_millionths}"
            ),
            Self::ExcessiveDuplicateMass {
                remaining_millionths,
                max_millionths,
            } => write!(
                f,
                "remaining duplicate mass {remaining_millionths} exceeds max {max_millionths}"
            ),
            Self::IrreversibleArtifact { artifact_id } => {
                write!(f, "artifact {artifact_id} is not reversible")
            }
            Self::InsufficientFidelity {
                artifact_id,
                fidelity_millionths,
                required_millionths,
            } => write!(
                f,
                "artifact {artifact_id} fidelity {fidelity_millionths} < required {required_millionths}"
            ),
            Self::SupportCostCeilingExceeded {
                observed_millionths,
                ceiling_millionths,
            } => write!(
                f,
                "support cost {observed_millionths} exceeds ceiling {ceiling_millionths}"
            ),
            Self::NoCompressionData => write!(f, "no compression data available"),
            Self::NetMemoryExpansion { net_change_bytes } => {
                write!(f, "net memory expansion: {net_change_bytes} bytes")
            }
            Self::DebugReadabilityLost { source_id } => {
                write!(f, "debug readability lost for {source_id}")
            }
            Self::StackTraceAccuracyLost { source_id } => {
                write!(f, "stack trace accuracy lost for {source_id}")
            }
        }
    }
}

// ── Decision receipt ──────────────────────────────────────────────────

/// A decision receipt for a compression claim verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component label.
    pub component: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Claim surface evaluated.
    pub surface: ClaimSurface,
    /// Verdict.
    pub verdict: CompressionClaimVerdict,
    /// Blocking reasons (empty if approved).
    pub blocking_reasons: Vec<ClaimBlockingReason>,
    /// Caveats (non-empty only for ApprovedWithCaveats).
    pub caveats: Vec<String>,
    /// Aggregate compression ratio (millionths).
    pub aggregate_compression_ratio_millionths: i64,
    /// Aggregate remaining duplicate mass (millionths).
    pub aggregate_duplicate_mass_millionths: i64,
    /// Total restoration overhead (microseconds).
    pub total_restoration_overhead_us: u64,
    /// Net memory change from all hidden expansion records (bytes).
    pub net_memory_change_bytes: i64,
    /// Aggregate support cost overhead (millionths).
    pub aggregate_support_overhead_millionths: i64,
    /// Reversibility check summary: count of passing checks.
    pub reversibility_pass_count: usize,
    /// Reversibility check summary: count of failing checks.
    pub reversibility_fail_count: usize,
    /// Number of compression passes considered.
    pub passes_considered: usize,
    /// Number of artifacts considered.
    pub artifacts_considered: usize,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Deterministic content hash of this receipt.
    pub receipt_hash: ContentHash,
}

// ── Residual ledger entry ─────────────────────────────────────────────

/// A single entry in the residual ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualLedgerEntry {
    /// Entry sequence number.
    pub sequence: u64,
    /// Artifact identifier.
    pub artifact_id: String,
    /// Compression pass that produced this entry.
    pub pass_kind: CompressionPassKind,
    /// Original size (bytes).
    pub original_size_bytes: u64,
    /// Compressed size (bytes).
    pub compressed_size_bytes: u64,
    /// Bytes of duplicate mass removed.
    pub duplicate_mass_removed_bytes: u64,
    /// Bytes of duplicate mass remaining.
    pub duplicate_mass_remaining_bytes: u64,
    /// Whether the artifact is fully reversible.
    pub reversible: bool,
    /// Bytes lost (irreversible data).
    pub bytes_lost: u64,
    /// Restoration overhead (microseconds).
    pub restoration_overhead_us: u64,
    /// Security epoch at recording time.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Content hash of this entry for chaining.
    pub entry_hash: ContentHash,
}

// ── Residual ledger ───────────────────────────────────────────────────

/// Input for appending a new entry to the residual ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerAppendInput {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Kind of compression pass.
    pub pass_kind: CompressionPassKind,
    /// Original size in bytes.
    pub original_size_bytes: u64,
    /// Compressed size in bytes.
    pub compressed_size_bytes: u64,
    /// Bytes of duplicate mass removed.
    pub duplicate_mass_removed_bytes: u64,
    /// Bytes of duplicate mass remaining.
    pub duplicate_mass_remaining_bytes: u64,
    /// Whether the artifact is fully reversible.
    pub reversible: bool,
    /// Bytes lost (irreversible data).
    pub bytes_lost: u64,
    /// Restoration overhead in microseconds.
    pub restoration_overhead_us: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Persistent append-only ledger of compression residuals.
///
/// Records what was compressed, what remains, and what was lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualLedger {
    /// All ledger entries in append order.
    entries: Vec<ResidualLedgerEntry>,
    /// Next sequence number.
    next_sequence: u64,
    /// Total original bytes across all entries.
    total_original_bytes: u64,
    /// Total compressed bytes across all entries.
    total_compressed_bytes: u64,
    /// Total bytes lost (irreversible).
    total_bytes_lost: u64,
    /// Total duplicate mass removed.
    total_duplicate_mass_removed: u64,
    /// Total duplicate mass remaining.
    total_duplicate_mass_remaining: u64,
    /// Index: artifact_id -> list of sequence numbers.
    artifact_index: BTreeMap<String, Vec<u64>>,
}

impl ResidualLedger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
            total_original_bytes: 0,
            total_compressed_bytes: 0,
            total_bytes_lost: 0,
            total_duplicate_mass_removed: 0,
            total_duplicate_mass_remaining: 0,
            artifact_index: BTreeMap::new(),
        }
    }

    /// Number of entries in the ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append an entry to the ledger. Returns the assigned sequence number.
    pub fn append(&mut self, input: &LedgerAppendInput) -> Result<u64, CompressionResidualError> {
        if self.entries.len() >= MAX_LEDGER_ENTRIES {
            return Err(CompressionResidualError::LedgerFull {
                count: self.entries.len(),
                max: MAX_LEDGER_ENTRIES,
            });
        }

        let seq = self.next_sequence;
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            seq,
            input.artifact_id,
            input.pass_kind,
            input.original_size_bytes,
            input.compressed_size_bytes,
            input.bytes_lost,
            input.epoch,
            input.timestamp_ns,
        );
        let entry_hash = ContentHash::compute(hash_input.as_bytes());

        let entry = ResidualLedgerEntry {
            sequence: seq,
            artifact_id: input.artifact_id.clone(),
            pass_kind: input.pass_kind,
            original_size_bytes: input.original_size_bytes,
            compressed_size_bytes: input.compressed_size_bytes,
            duplicate_mass_removed_bytes: input.duplicate_mass_removed_bytes,
            duplicate_mass_remaining_bytes: input.duplicate_mass_remaining_bytes,
            reversible: input.reversible,
            bytes_lost: input.bytes_lost,
            restoration_overhead_us: input.restoration_overhead_us,
            epoch: input.epoch,
            timestamp_ns: input.timestamp_ns,
            entry_hash,
        };

        self.total_original_bytes = self
            .total_original_bytes
            .saturating_add(input.original_size_bytes);
        self.total_compressed_bytes = self
            .total_compressed_bytes
            .saturating_add(input.compressed_size_bytes);
        self.total_bytes_lost = self.total_bytes_lost.saturating_add(input.bytes_lost);
        self.total_duplicate_mass_removed = self
            .total_duplicate_mass_removed
            .saturating_add(input.duplicate_mass_removed_bytes);
        self.total_duplicate_mass_remaining = self
            .total_duplicate_mass_remaining
            .saturating_add(input.duplicate_mass_remaining_bytes);

        self.artifact_index
            .entry(input.artifact_id.clone())
            .or_default()
            .push(seq);

        self.entries.push(entry);
        self.next_sequence += 1;
        Ok(seq)
    }

    /// Get all entries for a given artifact.
    pub fn entries_for_artifact(&self, artifact_id: &str) -> Vec<&ResidualLedgerEntry> {
        match self.artifact_index.get(artifact_id) {
            Some(seqs) => seqs
                .iter()
                .filter_map(|&s| self.entries.get(s as usize))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ResidualLedgerEntry] {
        &self.entries
    }

    /// Total original bytes.
    pub fn total_original_bytes(&self) -> u64 {
        self.total_original_bytes
    }

    /// Total compressed bytes.
    pub fn total_compressed_bytes(&self) -> u64 {
        self.total_compressed_bytes
    }

    /// Total bytes lost.
    pub fn total_bytes_lost(&self) -> u64 {
        self.total_bytes_lost
    }

    /// Aggregate compression ratio in millionths.
    pub fn aggregate_compression_ratio_millionths(&self) -> i64 {
        if self.total_original_bytes == 0 {
            return MILLION;
        }
        (self.total_compressed_bytes as i128 * MILLION as i128 / self.total_original_bytes as i128)
            as i64
    }

    /// Aggregate remaining duplicate mass ratio in millionths.
    pub fn aggregate_duplicate_mass_millionths(&self) -> i64 {
        let total = self
            .total_duplicate_mass_removed
            .saturating_add(self.total_duplicate_mass_remaining);
        if total == 0 {
            return 0;
        }
        (self.total_duplicate_mass_remaining as i128 * MILLION as i128 / total as i128) as i64
    }

    /// Number of distinct artifacts in the ledger.
    pub fn distinct_artifact_count(&self) -> usize {
        self.artifact_index.len()
    }

    /// Whether any entries are irreversible.
    pub fn has_irreversible_entries(&self) -> bool {
        self.entries.iter().any(|e| !e.reversible)
    }

    /// Count of irreversible entries.
    pub fn irreversible_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.reversible).count()
    }

    /// Total restoration overhead across all entries (microseconds).
    pub fn total_restoration_overhead_us(&self) -> u64 {
        self.entries.iter().map(|e| e.restoration_overhead_us).sum()
    }
}

impl Default for ResidualLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ── Gate configuration ────────────────────────────────────────────────

/// Configuration for the compression residual gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum decompression cost as fraction of cold-start budget (millionths).
    pub cold_start_decompression_budget_millionths: i64,
    /// Maximum hidden memory expansion ratio (millionths).
    pub memory_hidden_expansion_threshold_millionths: i64,
    /// Maximum proof overhead ratio (millionths).
    pub proof_overhead_threshold_millionths: i64,
    /// Maximum support cost overhead ratio (millionths).
    pub support_cost_ceiling_millionths: i64,
    /// Minimum reversibility fidelity (millionths, 1_000_000 = perfect).
    pub reversibility_threshold_millionths: i64,
    /// Maximum remaining duplicate mass (millionths).
    pub max_duplicate_mass_millionths: i64,
    /// Whether to require all artifacts to be reversible.
    pub require_full_reversibility: bool,
    /// Whether to require debug readability for memory claims.
    pub require_debug_readability: bool,
    /// Whether to require stack trace accuracy for all claims.
    pub require_stack_trace_accuracy: bool,
    /// Maximum cold-start restoration overhead (microseconds).
    pub max_cold_start_restoration_us: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            cold_start_decompression_budget_millionths:
                DEFAULT_COLD_START_DECOMPRESSION_BUDGET_MILLIONTHS,
            memory_hidden_expansion_threshold_millionths:
                DEFAULT_MEMORY_HIDDEN_EXPANSION_THRESHOLD_MILLIONTHS,
            proof_overhead_threshold_millionths: DEFAULT_PROOF_OVERHEAD_THRESHOLD_MILLIONTHS,
            support_cost_ceiling_millionths: DEFAULT_SUPPORT_COST_CEILING_MILLIONTHS,
            reversibility_threshold_millionths: DEFAULT_REVERSIBILITY_THRESHOLD_MILLIONTHS,
            max_duplicate_mass_millionths: 200_000, // 20%
            require_full_reversibility: true,
            require_debug_readability: true,
            require_stack_trace_accuracy: true,
            max_cold_start_restoration_us: 500_000, // 500ms
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors from compression residual gate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionResidualError {
    /// Ledger is full.
    LedgerFull { count: usize, max: usize },
    /// Too many artifacts in a single pass.
    TooManyArtifacts { count: usize, max: usize },
    /// Configuration validation failure.
    InvalidConfig { reason: String },
    /// Empty input.
    EmptyInput { context: String },
}

impl fmt::Display for CompressionResidualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerFull { count, max } => {
                write!(f, "ledger full: {count} entries (max {max})")
            }
            Self::TooManyArtifacts { count, max } => {
                write!(f, "too many artifacts: {count} (max {max})")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::EmptyInput { context } => {
                write!(f, "empty input: {context}")
            }
        }
    }
}

impl std::error::Error for CompressionResidualError {}

// ── Gate input ────────────────────────────────────────────────────────

/// Input to the compression residual gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateInput {
    /// Claim surface being evaluated.
    pub surface: ClaimSurface,
    /// Compression pass results to evaluate.
    pub pass_results: Vec<CompressionPassResult>,
    /// Hidden expansion records (for memory claims).
    pub hidden_expansions: Vec<HiddenExpansionRecord>,
    /// Support cost records.
    pub support_costs: Vec<SupportCostRecord>,
    /// Reversibility checks.
    pub reversibility_checks: Vec<ReversibilityCheck>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Evaluation timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Cold-start total budget (microseconds) for ratio calculation.
    pub cold_start_total_budget_us: u64,
    /// Proof total size (bytes) for overhead ratio calculation.
    pub proof_total_size_bytes: u64,
}

// ── Gate engine ───────────────────────────────────────────────────────

/// The compression residual gate engine.
///
/// Evaluates compression claims against residual thresholds and produces
/// decision receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionResidualGate {
    config: GateConfig,
    ledger: ResidualLedger,
    receipts: Vec<DecisionReceipt>,
    evaluations_run: u64,
    claims_approved: u64,
    claims_blocked: u64,
    claims_with_caveats: u64,
    claims_insufficient: u64,
}

impl CompressionResidualGate {
    /// Create a new gate with default configuration.
    pub fn new() -> Self {
        Self {
            config: GateConfig::default(),
            ledger: ResidualLedger::new(),
            receipts: Vec::new(),
            evaluations_run: 0,
            claims_approved: 0,
            claims_blocked: 0,
            claims_with_caveats: 0,
            claims_insufficient: 0,
        }
    }

    /// Create a new gate with custom configuration.
    pub fn with_config(config: GateConfig) -> Result<Self, CompressionResidualError> {
        if config.cold_start_decompression_budget_millionths < 0 {
            return Err(CompressionResidualError::InvalidConfig {
                reason: "cold_start_decompression_budget_millionths must be non-negative".into(),
            });
        }
        if config.reversibility_threshold_millionths < 0
            || config.reversibility_threshold_millionths > MILLION
        {
            return Err(CompressionResidualError::InvalidConfig {
                reason: "reversibility_threshold_millionths must be in [0, 1_000_000]".into(),
            });
        }
        if config.max_duplicate_mass_millionths < 0 {
            return Err(CompressionResidualError::InvalidConfig {
                reason: "max_duplicate_mass_millionths must be non-negative".into(),
            });
        }
        Ok(Self {
            config,
            ledger: ResidualLedger::new(),
            receipts: Vec::new(),
            evaluations_run: 0,
            claims_approved: 0,
            claims_blocked: 0,
            claims_with_caveats: 0,
            claims_insufficient: 0,
        })
    }

    /// Access the gate configuration.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Access the residual ledger.
    pub fn ledger(&self) -> &ResidualLedger {
        &self.ledger
    }

    /// Mutable access to the residual ledger.
    pub fn ledger_mut(&mut self) -> &mut ResidualLedger {
        &mut self.ledger
    }

    /// Access all decision receipts.
    pub fn receipts(&self) -> &[DecisionReceipt] {
        &self.receipts
    }

    /// Number of evaluations run.
    pub fn evaluations_run(&self) -> u64 {
        self.evaluations_run
    }

    /// Number of claims approved.
    pub fn claims_approved(&self) -> u64 {
        self.claims_approved
    }

    /// Number of claims blocked.
    pub fn claims_blocked(&self) -> u64 {
        self.claims_blocked
    }

    /// Evaluate a compression claim and produce a decision receipt.
    pub fn evaluate(
        &mut self,
        input: &GateInput,
    ) -> Result<DecisionReceipt, CompressionResidualError> {
        // Validate input sizes.
        let total_artifacts: usize = input.pass_results.iter().map(|p| p.artifacts.len()).sum();
        if total_artifacts > MAX_ARTIFACTS_PER_PASS {
            return Err(CompressionResidualError::TooManyArtifacts {
                count: total_artifacts,
                max: MAX_ARTIFACTS_PER_PASS,
            });
        }

        let mut blocking_reasons = Vec::new();
        let mut caveats = Vec::new();

        // Check if we have any compression data.
        if input.pass_results.is_empty() {
            blocking_reasons.push(ClaimBlockingReason::NoCompressionData);
        }

        // Aggregate metrics from pass results.
        let mut agg_original_bytes: u64 = 0;
        let mut agg_compressed_bytes: u64 = 0;
        let mut agg_restoration_us: u64 = 0;
        let mut agg_dup_removed: u64 = 0;
        let mut agg_dup_remaining: u64 = 0;
        let mut total_artifacts_count: usize = 0;

        for pass in &input.pass_results {
            agg_original_bytes = agg_original_bytes.saturating_add(pass.total_original_bytes);
            agg_compressed_bytes = agg_compressed_bytes.saturating_add(pass.total_compressed_bytes);
            agg_restoration_us =
                agg_restoration_us.saturating_add(pass.total_restoration_overhead_us);
            agg_dup_removed = agg_dup_removed.saturating_add(pass.total_duplicates_removed);
            agg_dup_remaining = agg_dup_remaining.saturating_add(pass.total_duplicates_remaining);
            total_artifacts_count += pass.artifacts.len();

            // Check irreversibility if required.
            if self.config.require_full_reversibility && pass.irreversible_count > 0 {
                for artifact in &pass.artifacts {
                    if !artifact.reversible {
                        blocking_reasons.push(ClaimBlockingReason::IrreversibleArtifact {
                            artifact_id: artifact.artifact_id.clone(),
                        });
                    }
                }
            }
        }

        let agg_compression_ratio = if agg_original_bytes == 0 {
            MILLION
        } else {
            (agg_compressed_bytes as i128 * MILLION as i128 / agg_original_bytes as i128) as i64
        };

        let agg_dup_total = agg_dup_removed.saturating_add(agg_dup_remaining);
        let agg_dup_mass = if agg_dup_total == 0 {
            0
        } else {
            (agg_dup_remaining as i128 * MILLION as i128 / agg_dup_total as i128) as i64
        };

        // Check duplicate mass threshold.
        if agg_dup_mass > self.config.max_duplicate_mass_millionths {
            blocking_reasons.push(ClaimBlockingReason::ExcessiveDuplicateMass {
                remaining_millionths: agg_dup_mass,
                max_millionths: self.config.max_duplicate_mass_millionths,
            });
        }

        // Surface-specific checks.
        match input.surface {
            ClaimSurface::ColdStart => {
                self.evaluate_cold_start(
                    input,
                    agg_restoration_us,
                    &mut blocking_reasons,
                    &mut caveats,
                );
            }
            ClaimSurface::Memory => {
                self.evaluate_memory(input, &mut blocking_reasons, &mut caveats);
            }
            ClaimSurface::ProofSurface => {
                self.evaluate_proof_surface(
                    input,
                    agg_compressed_bytes,
                    agg_original_bytes,
                    &mut blocking_reasons,
                    &mut caveats,
                );
            }
        }

        // Check reversibility.
        self.evaluate_reversibility(input, &mut blocking_reasons);

        // Check support costs.
        let agg_support_overhead =
            self.evaluate_support_costs(input, &mut blocking_reasons, &mut caveats);

        // Determine pass/fail counts for reversibility.
        let rev_pass = input
            .reversibility_checks
            .iter()
            .filter(|c| c.exact_match)
            .count();
        let rev_fail = input.reversibility_checks.len() - rev_pass;

        // Determine verdict.
        let verdict = if !blocking_reasons.is_empty() {
            CompressionClaimVerdict::Blocked
        } else if input.pass_results.is_empty() {
            CompressionClaimVerdict::Insufficient
        } else if !caveats.is_empty() {
            CompressionClaimVerdict::ApprovedWithCaveats
        } else {
            CompressionClaimVerdict::Approved
        };

        // Build receipt hash.
        let receipt_hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION,
            input.surface,
            verdict,
            agg_compression_ratio,
            agg_dup_mass,
            agg_restoration_us,
            input.epoch,
            input.timestamp_ns,
        );
        let receipt_hash = ContentHash::compute(receipt_hash_input.as_bytes());

        let receipt = DecisionReceipt {
            schema_version: COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION.to_string(),
            component: COMPRESSION_RESIDUAL_GATE_COMPONENT.to_string(),
            bead_id: COMPRESSION_RESIDUAL_GATE_BEAD_ID.to_string(),
            surface: input.surface,
            verdict,
            blocking_reasons,
            caveats,
            aggregate_compression_ratio_millionths: agg_compression_ratio,
            aggregate_duplicate_mass_millionths: agg_dup_mass,
            total_restoration_overhead_us: agg_restoration_us,
            net_memory_change_bytes: input
                .hidden_expansions
                .iter()
                .map(|h| h.net_change_bytes)
                .sum(),
            aggregate_support_overhead_millionths: agg_support_overhead,
            reversibility_pass_count: rev_pass,
            reversibility_fail_count: rev_fail,
            passes_considered: input.pass_results.len(),
            artifacts_considered: total_artifacts_count,
            epoch: input.epoch,
            timestamp_ns: input.timestamp_ns,
            receipt_hash,
        };

        // Update counters.
        self.evaluations_run += 1;
        match receipt.verdict {
            CompressionClaimVerdict::Approved => self.claims_approved += 1,
            CompressionClaimVerdict::ApprovedWithCaveats => self.claims_with_caveats += 1,
            CompressionClaimVerdict::Blocked => self.claims_blocked += 1,
            CompressionClaimVerdict::Insufficient => self.claims_insufficient += 1,
        }

        // Record pass results into the ledger.
        for pass in &input.pass_results {
            for artifact in &pass.artifacts {
                let _ = self.ledger.append(&LedgerAppendInput {
                    artifact_id: artifact.artifact_id.clone(),
                    pass_kind: artifact.pass_kind,
                    original_size_bytes: artifact.original_size_bytes,
                    compressed_size_bytes: artifact.compressed_size_bytes,
                    duplicate_mass_removed_bytes: artifact.duplicates_removed,
                    duplicate_mass_remaining_bytes: artifact.duplicates_remaining,
                    reversible: artifact.reversible,
                    bytes_lost: if artifact.reversible {
                        0
                    } else {
                        artifact
                            .original_size_bytes
                            .saturating_sub(artifact.compressed_size_bytes)
                    },
                    restoration_overhead_us: artifact.restoration_overhead_us,
                    epoch: input.epoch,
                    timestamp_ns: input.timestamp_ns,
                });
            }
        }

        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Cold-start specific checks.
    fn evaluate_cold_start(
        &self,
        input: &GateInput,
        agg_restoration_us: u64,
        blocking_reasons: &mut Vec<ClaimBlockingReason>,
        caveats: &mut Vec<String>,
    ) {
        // Check decompression cost against cold-start budget.
        if input.cold_start_total_budget_us > 0 {
            let decompression_ratio = (agg_restoration_us as i128 * MILLION as i128
                / input.cold_start_total_budget_us as i128)
                as i64;
            if decompression_ratio > self.config.cold_start_decompression_budget_millionths {
                blocking_reasons.push(ClaimBlockingReason::DecompressionCostExceedsBudget {
                    observed_millionths: decompression_ratio,
                    budget_millionths: self.config.cold_start_decompression_budget_millionths,
                });
            } else if decompression_ratio
                > self.config.cold_start_decompression_budget_millionths * 3 / 4
            {
                caveats.push(format!(
                    "decompression cost is {decompression_ratio} millionths, \
                     approaching budget of {}",
                    self.config.cold_start_decompression_budget_millionths
                ));
            }
        }

        // Check absolute restoration overhead.
        if agg_restoration_us > self.config.max_cold_start_restoration_us {
            blocking_reasons.push(ClaimBlockingReason::DecompressionCostExceedsBudget {
                observed_millionths: agg_restoration_us as i64,
                budget_millionths: self.config.max_cold_start_restoration_us as i64,
            });
        }
    }

    /// Memory-specific checks.
    fn evaluate_memory(
        &self,
        input: &GateInput,
        blocking_reasons: &mut Vec<ClaimBlockingReason>,
        caveats: &mut Vec<String>,
    ) {
        // Aggregate hidden expansion.
        let mut total_saved: u64 = 0;
        let mut total_hidden: u64 = 0;
        let mut net_expansion_detected = false;

        for expansion in &input.hidden_expansions {
            total_saved = total_saved.saturating_add(expansion.memory_saved_bytes);
            total_hidden = total_hidden.saturating_add(expansion.hidden_cost_bytes);

            if !expansion.is_net_savings() {
                net_expansion_detected = true;
                blocking_reasons.push(ClaimBlockingReason::NetMemoryExpansion {
                    net_change_bytes: expansion.net_change_bytes,
                });
            }
        }

        if total_saved > 0 {
            let expansion_ratio =
                (total_hidden as i128 * MILLION as i128 / total_saved as i128) as i64;
            if expansion_ratio > self.config.memory_hidden_expansion_threshold_millionths {
                blocking_reasons.push(ClaimBlockingReason::HiddenExpansionExceedsThreshold {
                    observed_millionths: expansion_ratio,
                    threshold_millionths: self.config.memory_hidden_expansion_threshold_millionths,
                });
            } else if expansion_ratio
                > self.config.memory_hidden_expansion_threshold_millionths * 3 / 4
                && !net_expansion_detected
            {
                caveats.push(format!(
                    "hidden expansion ratio is {expansion_ratio} millionths, \
                     approaching threshold of {}",
                    self.config.memory_hidden_expansion_threshold_millionths
                ));
            }
        }

        // Check debug readability if required.
        if self.config.require_debug_readability {
            for cost in &input.support_costs {
                if !cost.debug_readable {
                    blocking_reasons.push(ClaimBlockingReason::DebugReadabilityLost {
                        source_id: cost.source_id.clone(),
                    });
                }
            }
        }
    }

    /// Proof-surface specific checks.
    fn evaluate_proof_surface(
        &self,
        input: &GateInput,
        agg_compressed_bytes: u64,
        agg_original_bytes: u64,
        blocking_reasons: &mut Vec<ClaimBlockingReason>,
        caveats: &mut Vec<String>,
    ) {
        // Proof overhead: how much of the proof total is overhead from compression.
        if input.proof_total_size_bytes > 0 && agg_original_bytes > 0 {
            // Overhead = (compressed_size + metadata) - original_size_claim
            // We approximate metadata overhead as: compressed / original ratio
            // above what was claimed. If compressed > original, that's pure overhead.
            let overhead_bytes = agg_compressed_bytes.saturating_sub(agg_original_bytes);
            let overhead_ratio = (overhead_bytes as i128 * MILLION as i128
                / input.proof_total_size_bytes as i128) as i64;

            if overhead_ratio > self.config.proof_overhead_threshold_millionths {
                blocking_reasons.push(ClaimBlockingReason::ProofOverheadExceedsThreshold {
                    observed_millionths: overhead_ratio,
                    threshold_millionths: self.config.proof_overhead_threshold_millionths,
                });
            } else if overhead_ratio > self.config.proof_overhead_threshold_millionths * 3 / 4 {
                caveats.push(format!(
                    "proof overhead ratio is {overhead_ratio} millionths, \
                     approaching threshold of {}",
                    self.config.proof_overhead_threshold_millionths
                ));
            }
        }

        // For proofs, reversibility is critical — all proofs must round-trip.
        for check in &input.reversibility_checks {
            if !check.exact_match {
                blocking_reasons.push(ClaimBlockingReason::IrreversibleArtifact {
                    artifact_id: check.artifact_id.clone(),
                });
            }
        }
    }

    /// Reversibility checks common to all surfaces.
    fn evaluate_reversibility(
        &self,
        input: &GateInput,
        blocking_reasons: &mut Vec<ClaimBlockingReason>,
    ) {
        for check in &input.reversibility_checks {
            if !check.meets_fidelity_threshold(self.config.reversibility_threshold_millionths) {
                blocking_reasons.push(ClaimBlockingReason::InsufficientFidelity {
                    artifact_id: check.artifact_id.clone(),
                    fidelity_millionths: check.fidelity_millionths,
                    required_millionths: self.config.reversibility_threshold_millionths,
                });
            }
        }
    }

    /// Support cost checks. Returns aggregate support overhead in millionths.
    fn evaluate_support_costs(
        &self,
        input: &GateInput,
        blocking_reasons: &mut Vec<ClaimBlockingReason>,
        caveats: &mut Vec<String>,
    ) -> i64 {
        if input.support_costs.is_empty() {
            return 0;
        }

        let mut total_baseline: i64 = 0;
        let mut total_overhead: i64 = 0;

        for cost in &input.support_costs {
            total_baseline = total_baseline.saturating_add(cost.baseline_cost_millionths);
            total_overhead = total_overhead.saturating_add(cost.compression_overhead_millionths);

            if self.config.require_stack_trace_accuracy && !cost.stack_traces_accurate {
                blocking_reasons.push(ClaimBlockingReason::StackTraceAccuracyLost {
                    source_id: cost.source_id.clone(),
                });
            }
        }

        let agg_overhead = if total_baseline > 0 {
            (total_overhead as i128 * MILLION as i128 / total_baseline as i128) as i64
        } else if total_overhead > 0 {
            MILLION * 2
        } else {
            0
        };

        if agg_overhead > self.config.support_cost_ceiling_millionths {
            blocking_reasons.push(ClaimBlockingReason::SupportCostCeilingExceeded {
                observed_millionths: agg_overhead,
                ceiling_millionths: self.config.support_cost_ceiling_millionths,
            });
        } else if agg_overhead > self.config.support_cost_ceiling_millionths * 3 / 4 {
            caveats.push(format!(
                "support cost overhead is {agg_overhead} millionths, \
                 approaching ceiling of {}",
                self.config.support_cost_ceiling_millionths
            ));
        }

        agg_overhead
    }

    /// Evaluate all three surfaces and return receipts for each.
    ///
    /// The `template` input's `surface` field is ignored; all three surfaces
    /// are evaluated using the remaining fields from the template.
    pub fn evaluate_all_surfaces(
        &mut self,
        template: &GateInput,
    ) -> Result<Vec<DecisionReceipt>, CompressionResidualError> {
        let mut results = Vec::new();
        for surface in ClaimSurface::ALL {
            let input = GateInput {
                surface,
                pass_results: template.pass_results.clone(),
                hidden_expansions: template.hidden_expansions.clone(),
                support_costs: template.support_costs.clone(),
                reversibility_checks: template.reversibility_checks.clone(),
                epoch: template.epoch,
                timestamp_ns: template.timestamp_ns,
                cold_start_total_budget_us: template.cold_start_total_budget_us,
                proof_total_size_bytes: template.proof_total_size_bytes,
            };
            results.push(self.evaluate(&input)?);
        }
        Ok(results)
    }

    /// Summary statistics.
    pub fn summary(&self) -> GateSummary {
        GateSummary {
            evaluations_run: self.evaluations_run,
            claims_approved: self.claims_approved,
            claims_blocked: self.claims_blocked,
            claims_with_caveats: self.claims_with_caveats,
            claims_insufficient: self.claims_insufficient,
            ledger_entries: self.ledger.len() as u64,
            distinct_artifacts: self.ledger.distinct_artifact_count() as u64,
            ledger_compression_ratio_millionths: self
                .ledger
                .aggregate_compression_ratio_millionths(),
            ledger_duplicate_mass_millionths: self.ledger.aggregate_duplicate_mass_millionths(),
            total_bytes_lost: self.ledger.total_bytes_lost(),
        }
    }
}

impl Default for CompressionResidualGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics from the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evaluations run.
    pub evaluations_run: u64,
    /// Claims approved.
    pub claims_approved: u64,
    /// Claims blocked.
    pub claims_blocked: u64,
    /// Claims approved with caveats.
    pub claims_with_caveats: u64,
    /// Claims with insufficient data.
    pub claims_insufficient: u64,
    /// Ledger entries.
    pub ledger_entries: u64,
    /// Distinct artifacts in ledger.
    pub distinct_artifacts: u64,
    /// Ledger aggregate compression ratio (millionths).
    pub ledger_compression_ratio_millionths: i64,
    /// Ledger aggregate duplicate mass (millionths).
    pub ledger_duplicate_mass_millionths: i64,
    /// Total bytes lost.
    pub total_bytes_lost: u64,
}

// ── Helper: build test fixtures ───────────────────────────────────────

/// Input for building a simple artifact record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildArtifactInput {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Original size in bytes.
    pub original_size: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// Compression pass kind.
    pub pass_kind: CompressionPassKind,
    /// Whether the artifact is reversible.
    pub reversible: bool,
    /// Restoration overhead in microseconds.
    pub restoration_us: u64,
    /// Number of duplicate fragments removed.
    pub duplicates_removed: u64,
    /// Number of duplicate fragments remaining.
    pub duplicates_remaining: u64,
}

/// Build a simple artifact record for testing/construction.
pub fn build_artifact_record(input: &BuildArtifactInput) -> ArtifactRecord {
    ArtifactRecord {
        artifact_id: input.artifact_id.clone(),
        original_size_bytes: input.original_size,
        compressed_size_bytes: input.compressed_size,
        original_hash: ContentHash::compute(
            format!("orig:{}:{}", input.artifact_id, input.original_size).as_bytes(),
        ),
        compressed_hash: ContentHash::compute(
            format!("comp:{}:{}", input.artifact_id, input.compressed_size).as_bytes(),
        ),
        pass_kind: input.pass_kind,
        reversible: input.reversible,
        restoration_overhead_us: input.restoration_us,
        duplicates_removed: input.duplicates_removed,
        duplicates_remaining: input.duplicates_remaining,
    }
}

/// Build a compression pass result from a list of artifact records.
pub fn build_pass_result(
    pass_id: &str,
    pass_kind: CompressionPassKind,
    artifacts: Vec<ArtifactRecord>,
    epoch: SecurityEpoch,
    timestamp_ns: u64,
) -> CompressionPassResult {
    let total_original: u64 = artifacts.iter().map(|a| a.original_size_bytes).sum();
    let total_compressed: u64 = artifacts.iter().map(|a| a.compressed_size_bytes).sum();
    let total_restoration: u64 = artifacts.iter().map(|a| a.restoration_overhead_us).sum();
    let total_dup_removed: u64 = artifacts.iter().map(|a| a.duplicates_removed).sum();
    let total_dup_remaining: u64 = artifacts.iter().map(|a| a.duplicates_remaining).sum();
    let reversible_count = artifacts.iter().filter(|a| a.reversible).count();
    let irreversible_count = artifacts.len() - reversible_count;

    CompressionPassResult {
        pass_id: pass_id.to_string(),
        pass_kind,
        artifacts,
        total_original_bytes: total_original,
        total_compressed_bytes: total_compressed,
        total_restoration_overhead_us: total_restoration,
        total_duplicates_removed: total_dup_removed,
        total_duplicates_remaining: total_dup_remaining,
        reversible_count,
        irreversible_count,
        epoch,
        timestamp_ns,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn ts() -> u64 {
        1_000_000_000
    }

    fn simple_artifact(id: &str, orig: u64, comp: u64, reversible: bool) -> ArtifactRecord {
        build_artifact_record(&BuildArtifactInput {
            artifact_id: id.to_string(),
            original_size: orig,
            compressed_size: comp,
            pass_kind: CompressionPassKind::Deduplication,
            reversible,
            restoration_us: 100,
            duplicates_removed: 10,
            duplicates_remaining: 2,
        })
    }

    fn simple_pass(artifacts: Vec<ArtifactRecord>) -> CompressionPassResult {
        build_pass_result(
            "pass-1",
            CompressionPassKind::Deduplication,
            artifacts,
            epoch(),
            ts(),
        )
    }

    fn simple_reversibility_check(id: &str, exact: bool) -> ReversibilityCheck {
        let hash = ContentHash::compute(id.as_bytes());
        ReversibilityCheck {
            artifact_id: id.to_string(),
            original_hash: hash.clone(),
            restored_hash: if exact {
                hash
            } else {
                ContentHash::compute(b"different")
            },
            exact_match: exact,
            fidelity_millionths: if exact { MILLION } else { 900_000 },
            divergent_bytes: if exact { 0 } else { 100 },
            total_bytes: 1000,
            restoration_time_us: 50,
        }
    }

    fn simple_hidden_expansion(id: &str, saved: u64, hidden: u64) -> HiddenExpansionRecord {
        let net = saved as i64 - hidden as i64;
        HiddenExpansionRecord {
            source_id: id.to_string(),
            memory_saved_bytes: saved,
            hidden_cost_bytes: hidden,
            net_change_bytes: net,
            cost_explanation: "test".to_string(),
        }
    }

    fn simple_support_cost(id: &str, baseline: i64, overhead: i64) -> SupportCostRecord {
        SupportCostRecord {
            source_id: id.to_string(),
            baseline_cost_millionths: baseline,
            compression_overhead_millionths: overhead,
            indirection_layers: 1,
            debug_readable: true,
            stack_traces_accurate: true,
            explanation: "test".to_string(),
        }
    }

    fn ledger_input(
        artifact_id: &str,
        pass_kind: CompressionPassKind,
        original_size_bytes: u64,
        compressed_size_bytes: u64,
        dup_removed: u64,
        dup_remaining: u64,
        reversible: bool,
    ) -> LedgerAppendInput {
        LedgerAppendInput {
            artifact_id: artifact_id.to_string(),
            pass_kind,
            original_size_bytes,
            compressed_size_bytes,
            duplicate_mass_removed_bytes: dup_removed,
            duplicate_mass_remaining_bytes: dup_remaining,
            reversible,
            bytes_lost: if reversible {
                0
            } else {
                original_size_bytes.saturating_sub(compressed_size_bytes)
            },
            restoration_overhead_us: 100,
            epoch: epoch(),
            timestamp_ns: ts(),
        }
    }

    fn cold_start_input(pass: CompressionPassResult) -> GateInput {
        GateInput {
            surface: ClaimSurface::ColdStart,
            pass_results: vec![pass],
            hidden_expansions: Vec::new(),
            support_costs: Vec::new(),
            reversibility_checks: Vec::new(),
            epoch: epoch(),
            timestamp_ns: ts(),
            cold_start_total_budget_us: 1_000_000,
            proof_total_size_bytes: 0,
        }
    }

    fn memory_input(
        pass: CompressionPassResult,
        expansions: Vec<HiddenExpansionRecord>,
    ) -> GateInput {
        GateInput {
            surface: ClaimSurface::Memory,
            pass_results: vec![pass],
            hidden_expansions: expansions,
            support_costs: Vec::new(),
            reversibility_checks: Vec::new(),
            epoch: epoch(),
            timestamp_ns: ts(),
            cold_start_total_budget_us: 0,
            proof_total_size_bytes: 0,
        }
    }

    fn proof_input(pass: CompressionPassResult) -> GateInput {
        GateInput {
            surface: ClaimSurface::ProofSurface,
            pass_results: vec![pass],
            hidden_expansions: Vec::new(),
            support_costs: Vec::new(),
            reversibility_checks: Vec::new(),
            epoch: epoch(),
            timestamp_ns: ts(),
            cold_start_total_budget_us: 0,
            proof_total_size_bytes: 10_000,
        }
    }

    // ── Basic construction tests ──────────────────────────────────────

    #[test]
    fn test_gate_default_construction() {
        let gate = CompressionResidualGate::new();
        assert_eq!(gate.evaluations_run(), 0);
        assert_eq!(gate.claims_approved(), 0);
        assert_eq!(gate.claims_blocked(), 0);
        assert!(gate.ledger().is_empty());
        assert!(gate.receipts().is_empty());
    }

    #[test]
    fn test_gate_with_config() {
        let config = GateConfig::default();
        let gate = CompressionResidualGate::with_config(config).unwrap();
        assert_eq!(
            gate.config().cold_start_decompression_budget_millionths,
            DEFAULT_COLD_START_DECOMPRESSION_BUDGET_MILLIONTHS
        );
    }

    #[test]
    fn test_gate_invalid_config_negative_budget() {
        let config = GateConfig {
            cold_start_decompression_budget_millionths: -1,
            ..GateConfig::default()
        };
        let result = CompressionResidualGate::with_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_invalid_config_bad_reversibility() {
        let config = GateConfig {
            reversibility_threshold_millionths: MILLION + 1,
            ..GateConfig::default()
        };
        let result = CompressionResidualGate::with_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_invalid_config_negative_dup_mass() {
        let config = GateConfig {
            max_duplicate_mass_millionths: -5,
            ..GateConfig::default()
        };
        let result = CompressionResidualGate::with_config(config);
        assert!(result.is_err());
    }

    // ── Claim surface tests ───────────────────────────────────────────

    #[test]
    fn test_claim_surface_display() {
        assert_eq!(ClaimSurface::ColdStart.to_string(), "cold_start");
        assert_eq!(ClaimSurface::Memory.to_string(), "memory");
        assert_eq!(ClaimSurface::ProofSurface.to_string(), "proof_surface");
    }

    #[test]
    fn test_claim_surface_all() {
        assert_eq!(ClaimSurface::ALL.len(), 3);
    }

    // ── Compression pass kind tests ───────────────────────────────────

    #[test]
    fn test_pass_kind_display() {
        assert_eq!(
            CompressionPassKind::Deduplication.to_string(),
            "deduplication"
        );
        assert_eq!(
            CompressionPassKind::SemanticFolding.to_string(),
            "semantic_folding"
        );
    }

    // ── Artifact record tests ─────────────────────────────────────────

    #[test]
    fn test_artifact_compression_ratio() {
        let art = simple_artifact("a1", 1000, 500, true);
        assert_eq!(art.compression_ratio_millionths(), 500_000);
    }

    #[test]
    fn test_artifact_space_savings() {
        let art = simple_artifact("a1", 1000, 250, true);
        assert_eq!(art.space_savings_millionths(), 750_000);
    }

    #[test]
    fn test_artifact_compression_ratio_zero_original() {
        let art = simple_artifact("a1", 0, 0, true);
        assert_eq!(art.compression_ratio_millionths(), MILLION);
    }

    #[test]
    fn test_artifact_remaining_duplicate_mass() {
        let art = build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100,
            duplicates_removed: 8,
            duplicates_remaining: 2,
        });
        // 2 / (8+2) = 0.2 = 200_000 millionths
        assert_eq!(art.remaining_duplicate_mass_millionths(), 200_000);
    }

    #[test]
    fn test_artifact_no_duplicates() {
        let art = build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::EntropyCoding,
            reversible: true,
            restoration_us: 50,
            duplicates_removed: 0,
            duplicates_remaining: 0,
        });
        assert_eq!(art.remaining_duplicate_mass_millionths(), 0);
    }

    // ── Pass result tests ─────────────────────────────────────────────

    #[test]
    fn test_pass_result_aggregate_ratio() {
        let arts = vec![
            simple_artifact("a1", 1000, 500, true),
            simple_artifact("a2", 2000, 1000, true),
        ];
        let pass = simple_pass(arts);
        // 1500 / 3000 = 0.5
        assert_eq!(pass.aggregate_compression_ratio_millionths(), 500_000);
    }

    #[test]
    fn test_pass_result_savings() {
        let arts = vec![simple_artifact("a1", 1000, 200, true)];
        let pass = simple_pass(arts);
        assert_eq!(pass.aggregate_savings_millionths(), 800_000);
    }

    #[test]
    fn test_pass_result_fully_reversible() {
        let arts = vec![
            simple_artifact("a1", 1000, 500, true),
            simple_artifact("a2", 2000, 1000, true),
        ];
        let pass = simple_pass(arts);
        assert!(pass.fully_reversible());
    }

    #[test]
    fn test_pass_result_not_fully_reversible() {
        let arts = vec![
            simple_artifact("a1", 1000, 500, true),
            simple_artifact("a2", 2000, 1000, false),
        ];
        let pass = simple_pass(arts);
        assert!(!pass.fully_reversible());
    }

    #[test]
    fn test_pass_result_dup_mass() {
        let pass = simple_pass(vec![simple_artifact("a1", 1000, 500, true)]);
        // 2 / (10+2) = 166_666
        assert!(pass.remaining_duplicate_mass_millionths() > 0);
    }

    // ── Hidden expansion tests ────────────────────────────────────────

    #[test]
    fn test_hidden_expansion_ratio() {
        let h = simple_hidden_expansion("s1", 1000, 100);
        assert_eq!(h.expansion_ratio_millionths(), 100_000);
    }

    #[test]
    fn test_hidden_expansion_net_savings() {
        let h = simple_hidden_expansion("s1", 1000, 100);
        assert!(h.is_net_savings());
    }

    #[test]
    fn test_hidden_expansion_net_loss() {
        let h = simple_hidden_expansion("s1", 100, 200);
        assert!(!h.is_net_savings());
    }

    #[test]
    fn test_hidden_expansion_zero_saved() {
        let h = simple_hidden_expansion("s1", 0, 100);
        assert_eq!(h.expansion_ratio_millionths(), MILLION * 2);
    }

    #[test]
    fn test_hidden_expansion_zero_both() {
        let h = simple_hidden_expansion("s1", 0, 0);
        assert_eq!(h.expansion_ratio_millionths(), 0);
    }

    // ── Support cost tests ────────────────────────────────────────────

    #[test]
    fn test_support_cost_total() {
        let sc = simple_support_cost("s1", 500_000, 100_000);
        assert_eq!(sc.total_cost_millionths(), 600_000);
    }

    #[test]
    fn test_support_cost_overhead_ratio() {
        let sc = simple_support_cost("s1", 1_000_000, 200_000);
        assert_eq!(sc.overhead_ratio_millionths(), 200_000);
    }

    #[test]
    fn test_support_cost_zero_baseline() {
        let sc = simple_support_cost("s1", 0, 100_000);
        assert_eq!(sc.overhead_ratio_millionths(), MILLION * 2);
    }

    #[test]
    fn test_support_cost_zero_both() {
        let sc = simple_support_cost("s1", 0, 0);
        assert_eq!(sc.overhead_ratio_millionths(), 0);
    }

    // ── Reversibility check tests ─────────────────────────────────────

    #[test]
    fn test_reversibility_check_exact() {
        let check = simple_reversibility_check("a1", true);
        assert!(check.exact_match);
        assert!(check.meets_fidelity_threshold(MILLION));
    }

    #[test]
    fn test_reversibility_check_inexact() {
        let check = simple_reversibility_check("a1", false);
        assert!(!check.exact_match);
        assert!(check.meets_fidelity_threshold(900_000));
        assert!(!check.meets_fidelity_threshold(950_000));
    }

    // ── Verdict display tests ─────────────────────────────────────────

    #[test]
    fn test_verdict_display() {
        assert_eq!(CompressionClaimVerdict::Approved.to_string(), "approved");
        assert_eq!(CompressionClaimVerdict::Blocked.to_string(), "blocked");
        assert_eq!(
            CompressionClaimVerdict::ApprovedWithCaveats.to_string(),
            "approved_with_caveats"
        );
        assert_eq!(
            CompressionClaimVerdict::Insufficient.to_string(),
            "insufficient"
        );
    }

    // ── Blocking reason display tests ─────────────────────────────────

    #[test]
    fn test_blocking_reason_display_decompression() {
        let reason = ClaimBlockingReason::DecompressionCostExceedsBudget {
            observed_millionths: 100_000,
            budget_millionths: 50_000,
        };
        let s = reason.to_string();
        assert!(s.contains("100000"));
        assert!(s.contains("50000"));
    }

    #[test]
    fn test_blocking_reason_display_hidden_expansion() {
        let reason = ClaimBlockingReason::HiddenExpansionExceedsThreshold {
            observed_millionths: 200_000,
            threshold_millionths: 100_000,
        };
        assert!(reason.to_string().contains("hidden expansion"));
    }

    #[test]
    fn test_blocking_reason_display_irreversible() {
        let reason = ClaimBlockingReason::IrreversibleArtifact {
            artifact_id: "art-42".to_string(),
        };
        assert!(reason.to_string().contains("art-42"));
    }

    #[test]
    fn test_blocking_reason_display_no_data() {
        let reason = ClaimBlockingReason::NoCompressionData;
        assert!(reason.to_string().contains("no compression data"));
    }

    #[test]
    fn test_blocking_reason_display_net_expansion() {
        let reason = ClaimBlockingReason::NetMemoryExpansion {
            net_change_bytes: -500,
        };
        assert!(reason.to_string().contains("-500"));
    }

    #[test]
    fn test_blocking_reason_display_debug_readability() {
        let reason = ClaimBlockingReason::DebugReadabilityLost {
            source_id: "mod-x".to_string(),
        };
        assert!(reason.to_string().contains("mod-x"));
    }

    #[test]
    fn test_blocking_reason_display_stack_trace() {
        let reason = ClaimBlockingReason::StackTraceAccuracyLost {
            source_id: "mod-y".to_string(),
        };
        assert!(reason.to_string().contains("mod-y"));
    }

    #[test]
    fn test_blocking_reason_display_support_ceiling() {
        let reason = ClaimBlockingReason::SupportCostCeilingExceeded {
            observed_millionths: 300_000,
            ceiling_millionths: 200_000,
        };
        assert!(reason.to_string().contains("300000"));
    }

    #[test]
    fn test_blocking_reason_display_proof_overhead() {
        let reason = ClaimBlockingReason::ProofOverheadExceedsThreshold {
            observed_millionths: 250_000,
            threshold_millionths: 150_000,
        };
        assert!(reason.to_string().contains("proof overhead"));
    }

    #[test]
    fn test_blocking_reason_display_dup_mass() {
        let reason = ClaimBlockingReason::ExcessiveDuplicateMass {
            remaining_millionths: 300_000,
            max_millionths: 200_000,
        };
        assert!(reason.to_string().contains("duplicate mass"));
    }

    #[test]
    fn test_blocking_reason_display_fidelity() {
        let reason = ClaimBlockingReason::InsufficientFidelity {
            artifact_id: "art-1".to_string(),
            fidelity_millionths: 800_000,
            required_millionths: 999_000,
        };
        assert!(reason.to_string().contains("art-1"));
    }

    // ── Ledger tests ──────────────────────────────────────────────────

    #[test]
    fn test_ledger_new_is_empty() {
        let ledger = ResidualLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn test_ledger_append_and_query() {
        let mut ledger = ResidualLedger::new();
        let seq = ledger
            .append(&ledger_input(
                "art-1",
                CompressionPassKind::Deduplication,
                1000,
                500,
                10,
                2,
                true,
            ))
            .unwrap();
        assert_eq!(seq, 0);
        assert_eq!(ledger.len(), 1);
        assert!(!ledger.is_empty());
    }

    #[test]
    fn test_ledger_entries_for_artifact() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&ledger_input(
                "art-1",
                CompressionPassKind::Deduplication,
                1000,
                500,
                10,
                2,
                true,
            ))
            .unwrap();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 200,
                ..ledger_input(
                    "art-2",
                    CompressionPassKind::EntropyCoding,
                    2000,
                    800,
                    5,
                    1,
                    true,
                )
            })
            .unwrap();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 50,
                ..ledger_input(
                    "art-1",
                    CompressionPassKind::DeltaEncoding,
                    500,
                    200,
                    3,
                    1,
                    true,
                )
            })
            .unwrap();

        let entries = ledger.entries_for_artifact("art-1");
        assert_eq!(entries.len(), 2);
        let entries2 = ledger.entries_for_artifact("art-2");
        assert_eq!(entries2.len(), 1);
        let entries3 = ledger.entries_for_artifact("art-3");
        assert_eq!(entries3.len(), 0);
    }

    #[test]
    fn test_ledger_aggregates() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&ledger_input(
                "a",
                CompressionPassKind::Deduplication,
                1000,
                500,
                10,
                2,
                true,
            ))
            .unwrap();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 200,
                ..ledger_input(
                    "b",
                    CompressionPassKind::Deduplication,
                    2000,
                    800,
                    20,
                    4,
                    true,
                )
            })
            .unwrap();

        assert_eq!(ledger.total_original_bytes(), 3000);
        assert_eq!(ledger.total_compressed_bytes(), 1300);
        assert_eq!(ledger.total_bytes_lost(), 0);
        assert_eq!(ledger.distinct_artifact_count(), 2);
    }

    #[test]
    fn test_ledger_compression_ratio() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 0,
                ..ledger_input(
                    "a",
                    CompressionPassKind::Deduplication,
                    1000,
                    500,
                    0,
                    0,
                    true,
                )
            })
            .unwrap();
        assert_eq!(ledger.aggregate_compression_ratio_millionths(), 500_000);
    }

    #[test]
    fn test_ledger_duplicate_mass() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 0,
                ..ledger_input(
                    "a",
                    CompressionPassKind::Deduplication,
                    1000,
                    500,
                    80,
                    20,
                    true,
                )
            })
            .unwrap();
        // 20 / (80+20) = 200_000
        assert_eq!(ledger.aggregate_duplicate_mass_millionths(), 200_000);
    }

    #[test]
    fn test_ledger_irreversible_tracking() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 0,
                ..ledger_input(
                    "a",
                    CompressionPassKind::Deduplication,
                    1000,
                    500,
                    0,
                    0,
                    true,
                )
            })
            .unwrap();
        assert!(!ledger.has_irreversible_entries());
        assert_eq!(ledger.irreversible_count(), 0);

        ledger
            .append(&LedgerAppendInput {
                bytes_lost: 200,
                restoration_overhead_us: 0,
                ..ledger_input(
                    "b",
                    CompressionPassKind::ProofCompaction,
                    2000,
                    800,
                    0,
                    0,
                    false,
                )
            })
            .unwrap();
        assert!(ledger.has_irreversible_entries());
        assert_eq!(ledger.irreversible_count(), 1);
    }

    #[test]
    fn test_ledger_restoration_overhead() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&ledger_input(
                "a",
                CompressionPassKind::Deduplication,
                1000,
                500,
                0,
                0,
                true,
            ))
            .unwrap();
        ledger
            .append(&LedgerAppendInput {
                restoration_overhead_us: 250,
                ..ledger_input(
                    "b",
                    CompressionPassKind::Deduplication,
                    1000,
                    500,
                    0,
                    0,
                    true,
                )
            })
            .unwrap();
        assert_eq!(ledger.total_restoration_overhead_us(), 350);
    }

    #[test]
    fn test_ledger_empty_ratio() {
        let ledger = ResidualLedger::new();
        assert_eq!(ledger.aggregate_compression_ratio_millionths(), MILLION);
    }

    #[test]
    fn test_ledger_empty_dup_mass() {
        let ledger = ResidualLedger::new();
        assert_eq!(ledger.aggregate_duplicate_mass_millionths(), 0);
    }

    // ── Cold-start gate tests ─────────────────────────────────────────

    #[test]
    fn test_cold_start_approved() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
        assert!(receipt.blocking_reasons.is_empty());
    }

    #[test]
    fn test_cold_start_blocked_high_decompression() {
        let mut gate = CompressionResidualGate::new();
        // Restoration: 100_000us out of 1_000_000us budget = 100_000 millionths = 10%
        // Budget is 50_000 = 5%, so this should block.
        let arts = vec![build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100_000, // 100ms restoration
            duplicates_removed: 10,
            duplicates_remaining: 2,
        })];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
        assert!(!receipt.blocking_reasons.is_empty());
    }

    #[test]
    fn test_cold_start_caveat_near_budget() {
        let mut gate = CompressionResidualGate::new();
        // 40_000 / 1_000_000 = 40_000 millionths. Budget is 50_000.
        // 40_000 > 50_000 * 3/4 = 37_500, so caveat.
        let arts = vec![build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 40_000,
            duplicates_removed: 10,
            duplicates_remaining: 2,
        })];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(
            receipt.verdict,
            CompressionClaimVerdict::ApprovedWithCaveats
        );
        assert!(!receipt.caveats.is_empty());
    }

    // ── Memory gate tests ─────────────────────────────────────────────

    #[test]
    fn test_memory_approved() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let expansions = vec![simple_hidden_expansion("s1", 500, 10)];
        let input = memory_input(pass, expansions);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
    }

    #[test]
    fn test_memory_blocked_net_expansion() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let expansions = vec![simple_hidden_expansion("s1", 100, 200)];
        let input = memory_input(pass, expansions);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    #[test]
    fn test_memory_blocked_high_hidden_expansion() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        // 200/1000 = 200_000 millionths > threshold of 100_000.
        let expansions = vec![simple_hidden_expansion("s1", 1000, 200)];
        let input = memory_input(pass, expansions);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    #[test]
    fn test_memory_blocked_debug_readability() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let mut input = memory_input(pass, vec![simple_hidden_expansion("s1", 1000, 10)]);
        input.support_costs.push(SupportCostRecord {
            source_id: "s1".to_string(),
            baseline_cost_millionths: 100_000,
            compression_overhead_millionths: 10_000,
            indirection_layers: 1,
            debug_readable: false,
            stack_traces_accurate: true,
            explanation: "compressed output not readable".to_string(),
        });
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Proof-surface gate tests ──────────────────────────────────────

    #[test]
    fn test_proof_approved() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = proof_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
    }

    #[test]
    fn test_proof_blocked_irreversible() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let mut input = proof_input(pass);
        input
            .reversibility_checks
            .push(simple_reversibility_check("a1", false));
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    #[test]
    fn test_proof_blocked_overhead() {
        let mut gate = CompressionResidualGate::new();
        // compressed > original means overhead
        let arts = vec![simple_artifact("a1", 1000, 3000, true)];
        let pass = simple_pass(arts);
        let input = proof_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Reversibility gate tests ──────────────────────────────────────

    #[test]
    fn test_reversibility_blocks_low_fidelity() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let mut input = cold_start_input(pass);
        input.reversibility_checks.push(ReversibilityCheck {
            artifact_id: "a1".to_string(),
            original_hash: ContentHash::compute(b"orig"),
            restored_hash: ContentHash::compute(b"restored"),
            exact_match: false,
            fidelity_millionths: 900_000, // below 999_000 threshold
            divergent_bytes: 100,
            total_bytes: 1000,
            restoration_time_us: 50,
        });
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Support cost gate tests ───────────────────────────────────────

    #[test]
    fn test_support_cost_blocks_ceiling() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let mut input = cold_start_input(pass);
        // overhead / baseline = 500_000 / 1_000_000 = 500_000 millionths > 200_000 ceiling
        input
            .support_costs
            .push(simple_support_cost("s1", 1_000_000, 500_000));
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    #[test]
    fn test_support_cost_blocks_stack_traces() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let mut input = cold_start_input(pass);
        input.support_costs.push(SupportCostRecord {
            source_id: "s1".to_string(),
            baseline_cost_millionths: 1_000_000,
            compression_overhead_millionths: 10_000,
            indirection_layers: 1,
            debug_readable: true,
            stack_traces_accurate: false,
            explanation: "stack traces lost".to_string(),
        });
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Duplicate mass gate tests ─────────────────────────────────────

    #[test]
    fn test_duplicate_mass_blocks() {
        let mut gate = CompressionResidualGate::new();
        // 50 / (50+50) = 500_000 > 200_000 threshold
        let arts = vec![build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100,
            duplicates_removed: 50,
            duplicates_remaining: 50,
        })];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Empty input tests ─────────────────────────────────────────────

    #[test]
    fn test_no_pass_results_blocked() {
        let mut gate = CompressionResidualGate::new();
        let input = GateInput {
            surface: ClaimSurface::ColdStart,
            pass_results: Vec::new(),
            hidden_expansions: Vec::new(),
            support_costs: Vec::new(),
            reversibility_checks: Vec::new(),
            epoch: epoch(),
            timestamp_ns: ts(),
            cold_start_total_budget_us: 1_000_000,
            proof_total_size_bytes: 0,
        };
        let receipt = gate.evaluate(&input).unwrap();
        // No pass results means NoCompressionData -> Blocked
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    // ── Irreversible artifact gate tests ──────────────────────────────

    #[test]
    fn test_irreversible_artifact_blocks_when_required() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, false)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    }

    #[test]
    fn test_irreversible_artifact_ok_when_not_required() {
        let config = GateConfig {
            require_full_reversibility: false,
            ..GateConfig::default()
        };
        let mut gate = CompressionResidualGate::with_config(config).unwrap();
        let arts = vec![simple_artifact("a1", 1000, 500, false)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        // Not blocked by irreversibility (other checks may still pass)
        let has_irreversible_block = receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::IrreversibleArtifact { .. }));
        assert!(!has_irreversible_block);
    }

    // ── Evaluate all surfaces test ────────────────────────────────────

    #[test]
    fn test_evaluate_all_surfaces() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let template = GateInput {
            surface: ClaimSurface::ColdStart, // ignored by evaluate_all_surfaces
            pass_results: vec![pass],
            hidden_expansions: vec![simple_hidden_expansion("s1", 1000, 10)],
            support_costs: Vec::new(),
            reversibility_checks: Vec::new(),
            epoch: epoch(),
            timestamp_ns: ts(),
            cold_start_total_budget_us: 1_000_000,
            proof_total_size_bytes: 10_000,
        };
        let results = gate.evaluate_all_surfaces(&template).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].surface, ClaimSurface::ColdStart);
        assert_eq!(results[1].surface, ClaimSurface::Memory);
        assert_eq!(results[2].surface, ClaimSurface::ProofSurface);
    }

    // ── Counter/summary tests ─────────────────────────────────────────

    #[test]
    fn test_counters_increment() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        gate.evaluate(&input).unwrap();
        assert_eq!(gate.evaluations_run(), 1);
        assert_eq!(gate.claims_approved(), 1);
        assert_eq!(gate.claims_blocked(), 0);
    }

    #[test]
    fn test_summary() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        gate.evaluate(&input).unwrap();
        let summary = gate.summary();
        assert_eq!(summary.evaluations_run, 1);
        assert_eq!(summary.claims_approved, 1);
        assert!(summary.ledger_entries > 0);
    }

    // ── Receipt hash determinism ──────────────────────────────────────

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut gate1 = CompressionResidualGate::new();
        let mut gate2 = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass1 = simple_pass(arts.clone());
        let pass2 = simple_pass(arts);
        let input1 = cold_start_input(pass1);
        let input2 = cold_start_input(pass2);
        let r1 = gate1.evaluate(&input1).unwrap();
        let r2 = gate2.evaluate(&input2).unwrap();
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_receipt_hash_changes_with_surface() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass1 = simple_pass(arts.clone());
        let pass2 = simple_pass(arts);
        let input1 = cold_start_input(pass1);
        let input2 = proof_input(pass2);
        let r1 = gate.evaluate(&input1).unwrap();
        let r2 = gate.evaluate(&input2).unwrap();
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    // ── Ledger population from evaluate ───────────────────────────────

    #[test]
    fn test_evaluate_populates_ledger() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![
            simple_artifact("a1", 1000, 500, true),
            simple_artifact("a2", 2000, 800, true),
        ];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        gate.evaluate(&input).unwrap();
        assert_eq!(gate.ledger().len(), 2);
        assert_eq!(gate.ledger().distinct_artifact_count(), 2);
    }

    // ── Error tests ───────────────────────────────────────────────────

    #[test]
    fn test_error_display_ledger_full() {
        let err = CompressionResidualError::LedgerFull {
            count: 10_000,
            max: 10_000,
        };
        assert!(err.to_string().contains("ledger full"));
    }

    #[test]
    fn test_error_display_too_many_artifacts() {
        let err = CompressionResidualError::TooManyArtifacts {
            count: 2000,
            max: 1000,
        };
        assert!(err.to_string().contains("too many artifacts"));
    }

    #[test]
    fn test_error_display_invalid_config() {
        let err = CompressionResidualError::InvalidConfig {
            reason: "bad value".to_string(),
        };
        assert!(err.to_string().contains("bad value"));
    }

    #[test]
    fn test_error_display_empty_input() {
        let err = CompressionResidualError::EmptyInput {
            context: "test".to_string(),
        };
        assert!(err.to_string().contains("empty input"));
    }

    // ── Schema version in receipt ─────────────────────────────────────

    #[test]
    fn test_receipt_schema_version() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        assert_eq!(
            receipt.schema_version,
            COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION
        );
        assert_eq!(receipt.component, COMPRESSION_RESIDUAL_GATE_COMPONENT);
        assert_eq!(receipt.bead_id, COMPRESSION_RESIDUAL_GATE_BEAD_ID);
    }

    // ── Serde round-trip tests ────────────────────────────────────────

    #[test]
    fn test_serde_round_trip_verdict() {
        let v = CompressionClaimVerdict::ApprovedWithCaveats;
        let json = serde_json::to_string(&v).unwrap();
        let v2: CompressionClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_serde_round_trip_surface() {
        let s = ClaimSurface::ProofSurface;
        let json = serde_json::to_string(&s).unwrap();
        let s2: ClaimSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn test_serde_round_trip_pass_kind() {
        let k = CompressionPassKind::SemanticFolding;
        let json = serde_json::to_string(&k).unwrap();
        let k2: CompressionPassKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, k2);
    }

    #[test]
    fn test_serde_round_trip_receipt() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let receipt2: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, receipt2);
    }

    #[test]
    fn test_serde_round_trip_ledger_entry() {
        let mut ledger = ResidualLedger::new();
        ledger
            .append(&ledger_input(
                "art-1",
                CompressionPassKind::Deduplication,
                1000,
                500,
                10,
                2,
                true,
            ))
            .unwrap();
        let entry = &ledger.entries()[0];
        let json = serde_json::to_string(entry).unwrap();
        let entry2: ResidualLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, entry2);
    }

    #[test]
    fn test_serde_round_trip_gate_summary() {
        let gate = CompressionResidualGate::new();
        let summary = gate.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let summary2: GateSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, summary2);
    }

    #[test]
    fn test_serde_round_trip_hidden_expansion() {
        let h = simple_hidden_expansion("s1", 1000, 100);
        let json = serde_json::to_string(&h).unwrap();
        let h2: HiddenExpansionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_serde_round_trip_support_cost() {
        let sc = simple_support_cost("s1", 100_000, 50_000);
        let json = serde_json::to_string(&sc).unwrap();
        let sc2: SupportCostRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(sc, sc2);
    }

    // ── Multiple evaluations ──────────────────────────────────────────

    #[test]
    fn test_multiple_evaluations_accumulate() {
        let mut gate = CompressionResidualGate::new();
        for i in 0..5 {
            let arts = vec![simple_artifact(&format!("a{i}"), 1000, 500, true)];
            let pass = simple_pass(arts);
            let input = cold_start_input(pass);
            gate.evaluate(&input).unwrap();
        }
        assert_eq!(gate.evaluations_run(), 5);
        assert_eq!(gate.claims_approved(), 5);
        assert_eq!(gate.receipts().len(), 5);
        assert_eq!(gate.ledger().len(), 5);
    }

    // ── Edge case: large values ───────────────────────────────────────

    #[test]
    fn test_large_artifact_sizes() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![build_artifact_record(&BuildArtifactInput {
            artifact_id: "big".to_string(),
            original_size: u64::MAX / 2,
            compressed_size: u64::MAX / 4,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100,
            duplicates_removed: 10,
            duplicates_remaining: 2,
        })];
        let pass = simple_pass(arts);
        let input = cold_start_input(pass);
        let receipt = gate.evaluate(&input).unwrap();
        // Should not panic from overflow
        assert!(receipt.aggregate_compression_ratio_millionths > 0);
    }

    // ── Config customization ──────────────────────────────────────────

    #[test]
    fn test_relaxed_config_allows_more() {
        let config = GateConfig {
            max_duplicate_mass_millionths: MILLION, // allow 100%
            require_full_reversibility: false,
            require_debug_readability: false,
            require_stack_trace_accuracy: false,
            cold_start_decompression_budget_millionths: MILLION,
            support_cost_ceiling_millionths: MILLION * 2,
            reversibility_threshold_millionths: 0,
            max_cold_start_restoration_us: u64::MAX,
            ..GateConfig::default()
        };

        let mut gate = CompressionResidualGate::with_config(config).unwrap();
        let arts = vec![build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: false,
            restoration_us: 999_999,
            duplicates_removed: 50,
            duplicates_remaining: 50,
        })];
        let pass = simple_pass(arts);
        let mut input = cold_start_input(pass);
        input.support_costs.push(SupportCostRecord {
            source_id: "s1".to_string(),
            baseline_cost_millionths: 100_000,
            compression_overhead_millionths: 90_000,
            indirection_layers: 5,
            debug_readable: false,
            stack_traces_accurate: false,
            explanation: "everything broken".to_string(),
        });
        let receipt = gate.evaluate(&input).unwrap();
        // Caveat expected: decompression ratio 999_999 > budget * 3/4 = 750_000.
        assert_eq!(
            receipt.verdict,
            CompressionClaimVerdict::ApprovedWithCaveats
        );
    }

    // ── Default trait ─────────────────────────────────────────────────

    #[test]
    fn test_gate_default_trait() {
        let gate: CompressionResidualGate = Default::default();
        assert_eq!(gate.evaluations_run(), 0);
    }

    #[test]
    fn test_ledger_default_trait() {
        let ledger: ResidualLedger = Default::default();
        assert!(ledger.is_empty());
    }

    // ── Mixed verdict tracking ────────────────────────────────────────

    #[test]
    fn test_mixed_verdict_counters() {
        let mut gate = CompressionResidualGate::new();

        // Approved
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        gate.evaluate(&cold_start_input(pass)).unwrap();

        // Blocked (irreversible)
        let arts2 = vec![simple_artifact("a2", 1000, 500, false)];
        let pass2 = simple_pass(arts2);
        gate.evaluate(&cold_start_input(pass2)).unwrap();

        assert_eq!(gate.evaluations_run(), 2);
        assert_eq!(gate.claims_approved(), 1);
        assert_eq!(gate.claims_blocked(), 1);
    }

    // ── Net memory change in receipt ──────────────────────────────────

    #[test]
    fn test_receipt_net_memory_change() {
        let mut gate = CompressionResidualGate::new();
        let arts = vec![simple_artifact("a1", 1000, 500, true)];
        let pass = simple_pass(arts);
        let input = memory_input(
            pass,
            vec![
                simple_hidden_expansion("s1", 500, 10),
                simple_hidden_expansion("s2", 300, 5),
            ],
        );
        let receipt = gate.evaluate(&input).unwrap();
        // net = (500-10) + (300-5) = 490 + 295 = 785
        assert_eq!(receipt.net_memory_change_bytes, 785);
    }

    // ── Build helpers ─────────────────────────────────────────────────

    #[test]
    fn test_build_artifact_record_hashes_differ() {
        let a1 = build_artifact_record(&BuildArtifactInput {
            artifact_id: "a1".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100,
            duplicates_removed: 10,
            duplicates_remaining: 2,
        });
        let a2 = build_artifact_record(&BuildArtifactInput {
            artifact_id: "a2".to_string(),
            original_size: 1000,
            compressed_size: 500,
            pass_kind: CompressionPassKind::Deduplication,
            reversible: true,
            restoration_us: 100,
            duplicates_removed: 10,
            duplicates_remaining: 2,
        });
        assert_ne!(a1.original_hash, a2.original_hash);
    }

    #[test]
    fn test_build_pass_result_aggregates() {
        let arts = vec![
            simple_artifact("a1", 1000, 500, true),
            simple_artifact("a2", 2000, 800, false),
        ];
        let pass = build_pass_result(
            "p1",
            CompressionPassKind::Deduplication,
            arts,
            epoch(),
            ts(),
        );
        assert_eq!(pass.total_original_bytes, 3000);
        assert_eq!(pass.total_compressed_bytes, 1300);
        assert_eq!(pass.reversible_count, 1);
        assert_eq!(pass.irreversible_count, 1);
    }

    // ── Compression pass kind ordering ────────────────────────────────

    #[test]
    fn test_pass_kind_ordering() {
        assert!(CompressionPassKind::Deduplication < CompressionPassKind::StructuralSharing);
        assert!(CompressionPassKind::EntropyCoding < CompressionPassKind::ProofCompaction);
    }

    // ── Claim surface ordering ────────────────────────────────────────

    #[test]
    fn test_claim_surface_ordering() {
        assert!(ClaimSurface::ColdStart < ClaimSurface::Memory);
        assert!(ClaimSurface::Memory < ClaimSurface::ProofSurface);
    }

    // ── Verdict ordering ──────────────────────────────────────────────

    #[test]
    fn test_verdict_ordering() {
        assert!(CompressionClaimVerdict::Approved < CompressionClaimVerdict::ApprovedWithCaveats);
        assert!(CompressionClaimVerdict::Blocked < CompressionClaimVerdict::Insufficient);
    }
}
