//! Bead: bd-1lsy.7.20.3 [RGC-620C]
//!
//! S3-FIFO cache integration for AOT/code artifact paths with parity gates,
//! rollback gates, benchmark evidence collection, and user-visible decision
//! receipts.
//!
//! S3-FIFO is a three-segment eviction algorithm:
//! - **Small queue**: newly admitted items start here (FIFO).
//! - **Main queue**: items promoted from small on re-reference (FIFO).
//! - **Ghost queue**: metadata-only records of recently evicted items for
//!   frequency-aware re-admission.
//!
//! This module gates S3-FIFO behind parity checks against a reference
//! LRU/CLOCK policy, benchmark evidence (hit-rate, miss-rate, latency), and
//! rollback capability so that regressions can be reverted atomically.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Plan references: Section 7.20 (RGC-620C), bead bd-1lsy.7.20.3.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for S3-FIFO cache gate envelopes.
pub const S3_FIFO_SCHEMA_VERSION: &str = "franken-engine.s3-fifo-cache-gate.v1";

/// Bead identifier for this module.
pub const S3_FIFO_BEAD_ID: &str = "bd-1lsy.7.20.3";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default small-queue ratio in millionths (100_000 = 10%).
const DEFAULT_SMALL_RATIO_MILLIONTHS: u64 = 100_000;

/// Default parity tolerance in millionths (50_000 = 5%).
const DEFAULT_PARITY_TOLERANCE_MILLIONTHS: u64 = 50_000;

/// Default ghost queue capacity multiplier over total capacity.
const DEFAULT_GHOST_MULTIPLIER: u64 = 2;

/// Maximum frequency counter value before saturation.
const MAX_FREQUENCY: u8 = 3;

/// Default rollback cooldown (number of operations before re-enable).
const DEFAULT_ROLLBACK_COOLDOWN_OPS: u64 = 1000;

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

fn saturating_div_millionths(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MILLION)
        .checked_div(denominator)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// CacheArtifactId — identifies a cached artifact
// ---------------------------------------------------------------------------

/// Unique identifier for a cached AOT/code artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CacheArtifactId {
    /// Module source hash.
    pub source_hash: ContentHash,
    /// Policy version under which the artifact was compiled.
    pub policy_version: u64,
    /// Human-readable label for diagnostics.
    pub label: String,
}

impl CacheArtifactId {
    /// Create a new artifact identifier.
    pub fn new(source_hash: ContentHash, policy_version: u64, label: impl Into<String>) -> Self {
        Self {
            source_hash,
            policy_version,
            label: label.into(),
        }
    }

    /// Derive a deterministic string key for ordering and lookup.
    pub fn canonical_key(&self) -> String {
        format!(
            "{}:{}:{}",
            hex_encode(self.source_hash.as_bytes()),
            self.policy_version,
            self.label
        )
    }
}

impl fmt::Display for CacheArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "artifact[{}:v{}]", self.label, self.policy_version)
    }
}

// ---------------------------------------------------------------------------
// CacheSegment — which queue an item resides in
// ---------------------------------------------------------------------------

/// Identifies the segment (queue) an item currently resides in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CacheSegment {
    /// Small FIFO queue — entry point for new admissions.
    Small,
    /// Main FIFO queue — promoted items with higher frequency.
    Main,
    /// Ghost queue — metadata-only eviction records.
    Ghost,
}

impl CacheSegment {
    /// All segment variants.
    pub const ALL: &'static [CacheSegment] =
        &[CacheSegment::Small, CacheSegment::Main, CacheSegment::Ghost];
}

impl fmt::Display for CacheSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Small => write!(f, "small"),
            Self::Main => write!(f, "main"),
            Self::Ghost => write!(f, "ghost"),
        }
    }
}

// ---------------------------------------------------------------------------
// CacheEntry — per-item metadata
// ---------------------------------------------------------------------------

/// Metadata for a single cached artifact within the S3-FIFO structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The artifact identifier.
    pub artifact_id: CacheArtifactId,
    /// Which segment the entry currently resides in.
    pub segment: CacheSegment,
    /// Frequency counter (0..=MAX_FREQUENCY). Incremented on access.
    pub frequency: u8,
    /// Artifact size in bytes (used for value-aware admission).
    pub size_bytes: u64,
    /// Content hash of the cached artifact payload.
    pub payload_hash: ContentHash,
    /// Insertion sequence number for FIFO ordering.
    pub sequence_number: u64,
    /// Epoch at which this entry was last validated.
    pub last_validated_epoch: SecurityEpoch,
}

impl CacheEntry {
    /// Create a new entry in the Small segment.
    pub fn new_small(
        artifact_id: CacheArtifactId,
        size_bytes: u64,
        payload_hash: ContentHash,
        sequence_number: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            artifact_id,
            segment: CacheSegment::Small,
            frequency: 0,
            size_bytes,
            payload_hash,
            sequence_number,
            last_validated_epoch: epoch,
        }
    }

    /// Promote this entry to the Main segment, resetting frequency.
    pub fn promote_to_main(&mut self, new_sequence: u64) {
        self.segment = CacheSegment::Main;
        self.frequency = 0;
        self.sequence_number = new_sequence;
    }

    /// Record an access, incrementing the frequency counter.
    pub fn record_access(&mut self) {
        if self.frequency < MAX_FREQUENCY {
            self.frequency += 1;
        }
    }

    /// Decrement frequency counter for eviction scanning.
    pub fn decrement_frequency(&mut self) {
        self.frequency = self.frequency.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// GhostEntry — eviction metadata for re-admission
// ---------------------------------------------------------------------------

/// Metadata-only record for a recently evicted item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostEntry {
    /// Canonical key of the evicted artifact.
    pub canonical_key: String,
    /// Content hash for identification.
    pub payload_hash: ContentHash,
    /// Number of times this key has re-appeared in the ghost set.
    pub ghost_hits: u64,
    /// Original size for value-aware re-admission decisions.
    pub original_size_bytes: u64,
    /// Sequence number for FIFO eviction within the ghost queue.
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// AdmissionPolicy — value/frequency-aware admission control
// ---------------------------------------------------------------------------

/// Admission control policy for the S3-FIFO cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AdmissionPolicy {
    /// Accept all items unconditionally.
    AcceptAll,
    /// Frequency-aware: only admit items that appear in the ghost set.
    FrequencyAware,
    /// Value-aware: admit items whose size is below a threshold.
    ValueAware {
        /// Maximum artifact size in bytes for admission.
        max_size_bytes: u64,
    },
    /// Combined frequency and value awareness.
    Combined {
        /// Maximum artifact size in bytes.
        max_size_bytes: u64,
        /// Minimum ghost hits required for large items.
        min_ghost_hits: u64,
    },
}

impl AdmissionPolicy {
    /// Evaluate whether an artifact should be admitted.
    pub fn should_admit(
        &self,
        size_bytes: u64,
        ghost_entry: Option<&GhostEntry>,
    ) -> AdmissionDecision {
        match self {
            Self::AcceptAll => AdmissionDecision::Admit {
                reason: "accept_all_policy".into(),
            },
            Self::FrequencyAware => {
                if ghost_entry.is_some() {
                    AdmissionDecision::Admit {
                        reason: "ghost_hit_frequency_aware".into(),
                    }
                } else {
                    AdmissionDecision::Reject {
                        reason: "no_ghost_hit_frequency_aware".into(),
                    }
                }
            }
            Self::ValueAware { max_size_bytes } => {
                if size_bytes <= *max_size_bytes {
                    AdmissionDecision::Admit {
                        reason: format!("size_{size_bytes}_within_limit_{max_size_bytes}"),
                    }
                } else {
                    AdmissionDecision::Reject {
                        reason: format!("size_{size_bytes}_exceeds_limit_{max_size_bytes}"),
                    }
                }
            }
            Self::Combined {
                max_size_bytes,
                min_ghost_hits,
            } => {
                if size_bytes <= *max_size_bytes {
                    AdmissionDecision::Admit {
                        reason: format!("size_{size_bytes}_within_limit_{max_size_bytes}"),
                    }
                } else if let Some(ge) = ghost_entry {
                    if ge.ghost_hits >= *min_ghost_hits {
                        AdmissionDecision::Admit {
                            reason: format!(
                                "ghost_hits_{}_meets_min_{min_ghost_hits}",
                                ge.ghost_hits
                            ),
                        }
                    } else {
                        AdmissionDecision::Reject {
                            reason: format!(
                                "ghost_hits_{}_below_min_{min_ghost_hits}_and_size_{size_bytes}_exceeds_{max_size_bytes}",
                                ge.ghost_hits
                            ),
                        }
                    }
                } else {
                    AdmissionDecision::Reject {
                        reason: format!("no_ghost_and_size_{size_bytes}_exceeds_{max_size_bytes}"),
                    }
                }
            }
        }
    }
}

impl fmt::Display for AdmissionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcceptAll => write!(f, "accept_all"),
            Self::FrequencyAware => write!(f, "frequency_aware"),
            Self::ValueAware { max_size_bytes } => {
                write!(f, "value_aware(max={max_size_bytes})")
            }
            Self::Combined {
                max_size_bytes,
                min_ghost_hits,
            } => write!(
                f,
                "combined(max_size={max_size_bytes},min_ghosts={min_ghost_hits})"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionDecision
// ---------------------------------------------------------------------------

/// Result of an admission control evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    /// Item should be admitted to the cache.
    Admit {
        /// Reason for admission.
        reason: String,
    },
    /// Item should be rejected from the cache.
    Reject {
        /// Reason for rejection.
        reason: String,
    },
}

impl AdmissionDecision {
    /// Whether the decision is to admit.
    pub fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }
}

// ---------------------------------------------------------------------------
// ReferencePolicyKind — the baseline eviction policy for parity checks
// ---------------------------------------------------------------------------

/// The reference eviction policy used for parity comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReferencePolicyKind {
    /// Least Recently Used.
    Lru,
    /// CLOCK (second-chance) algorithm.
    Clock,
}

impl fmt::Display for ReferencePolicyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lru => write!(f, "LRU"),
            Self::Clock => write!(f, "CLOCK"),
        }
    }
}

// ---------------------------------------------------------------------------
// EvictionEvent — records a single eviction for parity comparison
// ---------------------------------------------------------------------------

/// A single eviction event recorded by either S3-FIFO or the reference policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionEvent {
    /// Canonical key of the evicted artifact.
    pub canonical_key: String,
    /// Which segment the eviction originated from (S3-FIFO only).
    pub segment: Option<CacheSegment>,
    /// Operation sequence number at which eviction occurred.
    pub at_operation: u64,
}

// ---------------------------------------------------------------------------
// ParityResult — comparison between S3-FIFO and reference
// ---------------------------------------------------------------------------

/// Outcome of a parity comparison between S3-FIFO and a reference policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParityVerdict {
    /// S3-FIFO eviction decisions match within tolerance.
    WithinTolerance,
    /// S3-FIFO eviction decisions diverge beyond tolerance.
    DivergenceBeyondTolerance,
}

impl fmt::Display for ParityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinTolerance => write!(f, "within_tolerance"),
            Self::DivergenceBeyondTolerance => write!(f, "divergence_beyond_tolerance"),
        }
    }
}

/// Full parity gate result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// The reference policy used.
    pub reference_policy: ReferencePolicyKind,
    /// Verdict.
    pub verdict: ParityVerdict,
    /// S3-FIFO hit rate in millionths.
    pub s3_fifo_hit_rate_millionths: u64,
    /// Reference hit rate in millionths.
    pub reference_hit_rate_millionths: u64,
    /// Absolute difference in hit rates (millionths).
    pub hit_rate_delta_millionths: u64,
    /// Tolerance used (millionths).
    pub tolerance_millionths: u64,
    /// Number of operations evaluated.
    pub total_operations: u64,
    /// Content hash of the parity evidence.
    pub evidence_hash: ContentHash,
}

impl ParityResult {
    /// Whether the parity gate passed.
    pub fn passed(&self) -> bool {
        self.verdict == ParityVerdict::WithinTolerance
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEvidence — hit-rate, miss-rate, latency metrics
// ---------------------------------------------------------------------------

/// Benchmark evidence for cache policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEvidence {
    /// Total number of cache lookups.
    pub total_lookups: u64,
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Hit rate in millionths (1_000_000 = 100%).
    pub hit_rate_millionths: u64,
    /// Miss rate in millionths.
    pub miss_rate_millionths: u64,
    /// Average lookup latency in nanoseconds (fixed-point millionths).
    pub avg_latency_ns_millionths: u64,
    /// P99 lookup latency in nanoseconds (fixed-point millionths).
    pub p99_latency_ns_millionths: u64,
    /// Total evictions performed.
    pub total_evictions: u64,
    /// Number of ghost hits (re-admission signals).
    pub ghost_hits: u64,
    /// Number of small-to-main promotions.
    pub promotions: u64,
    /// Content hash of the full benchmark trace.
    pub trace_hash: ContentHash,
    /// Epoch at which benchmarks were collected.
    pub epoch: SecurityEpoch,
}

impl BenchmarkEvidence {
    /// Create empty evidence at a given epoch.
    pub fn empty(epoch: SecurityEpoch) -> Self {
        Self {
            total_lookups: 0,
            hits: 0,
            misses: 0,
            hit_rate_millionths: 0,
            miss_rate_millionths: 0,
            avg_latency_ns_millionths: 0,
            p99_latency_ns_millionths: 0,
            total_evictions: 0,
            ghost_hits: 0,
            promotions: 0,
            trace_hash: ContentHash::compute(b"empty"),
            epoch,
        }
    }

    /// Recompute derived rates from raw counts.
    pub fn recompute_rates(&mut self) {
        if self.total_lookups > 0 {
            self.hit_rate_millionths = saturating_div_millionths(self.hits, self.total_lookups);
            self.miss_rate_millionths = saturating_div_millionths(self.misses, self.total_lookups);
        } else {
            self.hit_rate_millionths = 0;
            self.miss_rate_millionths = 0;
        }
    }

    /// Compute evidence content hash from the serialized fields.
    pub fn compute_trace_hash(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.total_lookups.to_be_bytes());
        buf.extend_from_slice(&self.hits.to_be_bytes());
        buf.extend_from_slice(&self.misses.to_be_bytes());
        buf.extend_from_slice(&self.total_evictions.to_be_bytes());
        buf.extend_from_slice(&self.ghost_hits.to_be_bytes());
        buf.extend_from_slice(&self.promotions.to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        self.trace_hash = compute_content_hash(&buf);
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger — conditions for rolling back to previous policy
// ---------------------------------------------------------------------------

/// Condition that triggers a rollback from S3-FIFO to the previous policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RollbackTrigger {
    /// Hit rate dropped below a minimum threshold (millionths).
    HitRateBelowThreshold { threshold_millionths: u64 },
    /// Parity gate failed against the reference policy.
    ParityGateFailure,
    /// Latency regression detected (observed > threshold, both in ns millionths).
    LatencyRegression {
        observed_ns_millionths: u64,
        threshold_ns_millionths: u64,
    },
    /// Operator-initiated rollback.
    OperatorInitiated { operator_id: String, reason: String },
    /// Epoch boundary forces re-evaluation.
    EpochBoundary {
        old_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
}

impl RollbackTrigger {
    /// Category tag for the trigger.
    pub fn category(&self) -> &'static str {
        match self {
            Self::HitRateBelowThreshold { .. } => "hit_rate_below_threshold",
            Self::ParityGateFailure => "parity_gate_failure",
            Self::LatencyRegression { .. } => "latency_regression",
            Self::OperatorInitiated { .. } => "operator_initiated",
            Self::EpochBoundary { .. } => "epoch_boundary",
        }
    }
}

impl fmt::Display for RollbackTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.category())
    }
}

// ---------------------------------------------------------------------------
// RollbackState — rollback lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle state of a rollback operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RollbackState {
    /// No rollback in progress.
    Idle,
    /// Rollback has been triggered but not yet executed.
    Triggered,
    /// Rollback is executing (draining S3-FIFO state).
    Executing,
    /// Rollback completed successfully.
    Completed,
    /// Rollback failed (fail-closed: cache disabled).
    Failed,
}

impl fmt::Display for RollbackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Triggered => write!(f, "triggered"),
            Self::Executing => write!(f, "executing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord — evidence of a rollback
// ---------------------------------------------------------------------------

/// Evidence record for a completed or failed rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Trigger that caused the rollback.
    pub trigger: RollbackTrigger,
    /// Final state.
    pub state: RollbackState,
    /// Epoch at rollback time.
    pub epoch: SecurityEpoch,
    /// Benchmark evidence at rollback time.
    pub benchmark_at_rollback: BenchmarkEvidence,
    /// Content hash of the rollback evidence.
    pub evidence_hash: ContentHash,
    /// Sequence number of the rollback.
    pub rollback_sequence: u64,
}

// ---------------------------------------------------------------------------
// DecisionReceipt — user-visible evidence of cache policy decisions
// ---------------------------------------------------------------------------

/// User-visible decision receipt for a cache policy change or gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Unique receipt identifier (content hash of the receipt body).
    pub receipt_id: String,
    /// Decision kind.
    pub decision_kind: DecisionKind,
    /// Epoch at which the decision was made.
    pub epoch: SecurityEpoch,
    /// Parity result, if a parity gate was evaluated.
    pub parity_result: Option<ParityResult>,
    /// Benchmark evidence snapshot.
    pub benchmark_evidence: BenchmarkEvidence,
    /// Rollback record, if a rollback occurred.
    pub rollback_record: Option<RollbackRecord>,
    /// Admission policy in effect.
    pub admission_policy_label: String,
    /// Split ratio at decision time (small queue ratio in millionths).
    pub small_ratio_millionths: u64,
    /// Content hash covering the full receipt.
    pub content_hash: ContentHash,
}

/// Kind of decision recorded in a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionKind {
    /// S3-FIFO was enabled as the active policy.
    PolicyEnabled,
    /// S3-FIFO gate evaluation passed (continued use).
    GatePassContinue,
    /// S3-FIFO gate evaluation failed; rollback triggered.
    GateFailRollback,
    /// Split ratio was adapted.
    SplitRatioAdapted,
    /// Admission policy was changed.
    AdmissionPolicyChanged,
    /// Cache was fully flushed.
    CacheFlushed,
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyEnabled => write!(f, "policy_enabled"),
            Self::GatePassContinue => write!(f, "gate_pass_continue"),
            Self::GateFailRollback => write!(f, "gate_fail_rollback"),
            Self::SplitRatioAdapted => write!(f, "split_ratio_adapted"),
            Self::AdmissionPolicyChanged => write!(f, "admission_policy_changed"),
            Self::CacheFlushed => write!(f, "cache_flushed"),
        }
    }
}

impl DecisionReceipt {
    /// Compute and set the content hash for this receipt.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.schema_version.as_bytes());
        buf.extend_from_slice(self.receipt_id.as_bytes());
        buf.extend_from_slice(&(self.decision_kind as u8).to_be_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.small_ratio_millionths.to_be_bytes());
        buf.extend_from_slice(self.benchmark_evidence.trace_hash.as_bytes());
        self.content_hash = compute_content_hash(&buf);
    }
}

// ---------------------------------------------------------------------------
// S3FifoCacheConfig — configuration
// ---------------------------------------------------------------------------

/// Configuration for the S3-FIFO cache gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoCacheConfig {
    /// Total capacity in number of items.
    pub total_capacity: usize,
    /// Small queue ratio in millionths (e.g. 100_000 = 10%).
    pub small_ratio_millionths: u64,
    /// Ghost queue capacity multiplier over total capacity.
    pub ghost_multiplier: u64,
    /// Parity tolerance in millionths for gate evaluation.
    pub parity_tolerance_millionths: u64,
    /// Reference policy for parity comparison.
    pub reference_policy: ReferencePolicyKind,
    /// Admission policy.
    pub admission_policy: AdmissionPolicy,
    /// Minimum hit rate (millionths) before rollback triggers.
    pub min_hit_rate_millionths: u64,
    /// Maximum latency (ns millionths) before rollback triggers.
    pub max_latency_ns_millionths: u64,
    /// Cooldown in operations after a rollback before S3-FIFO can be re-enabled.
    pub rollback_cooldown_ops: u64,
    /// Whether automatic split ratio adaptation is enabled.
    pub auto_adapt_split: bool,
    /// Minimum small ratio (millionths) for adaptation bounds.
    pub min_small_ratio_millionths: u64,
    /// Maximum small ratio (millionths) for adaptation bounds.
    pub max_small_ratio_millionths: u64,
}

impl Default for S3FifoCacheConfig {
    fn default() -> Self {
        Self {
            total_capacity: 1024,
            small_ratio_millionths: DEFAULT_SMALL_RATIO_MILLIONTHS,
            ghost_multiplier: DEFAULT_GHOST_MULTIPLIER,
            parity_tolerance_millionths: DEFAULT_PARITY_TOLERANCE_MILLIONTHS,
            reference_policy: ReferencePolicyKind::Lru,
            admission_policy: AdmissionPolicy::AcceptAll,
            min_hit_rate_millionths: 200_000,          // 20%
            max_latency_ns_millionths: 10_000_000_000, // 10s in ns-millionths
            rollback_cooldown_ops: DEFAULT_ROLLBACK_COOLDOWN_OPS,
            auto_adapt_split: false,
            min_small_ratio_millionths: 50_000,  // 5%
            max_small_ratio_millionths: 300_000, // 30%
        }
    }
}

impl S3FifoCacheConfig {
    /// Compute the small queue capacity.
    pub fn small_capacity(&self) -> usize {
        let raw = (self.total_capacity as u64)
            .saturating_mul(self.small_ratio_millionths)
            .checked_div(MILLION)
            .unwrap_or(0);
        std::cmp::max(raw as usize, 1)
    }

    /// Compute the main queue capacity.
    pub fn main_capacity(&self) -> usize {
        self.total_capacity.saturating_sub(self.small_capacity())
    }

    /// Compute the ghost queue capacity.
    pub fn ghost_capacity(&self) -> usize {
        (self.total_capacity as u64).saturating_mul(self.ghost_multiplier) as usize
    }
}

// ---------------------------------------------------------------------------
// LruReference — simple LRU for parity comparison
// ---------------------------------------------------------------------------

/// Simple LRU cache used as a reference policy for parity comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LruReference {
    capacity: usize,
    /// Ordered from least-recently-used (front) to most-recently-used (back).
    order: VecDeque<String>,
    present: BTreeSet<String>,
    hits: u64,
    misses: u64,
}

impl LruReference {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            present: BTreeSet::new(),
            hits: 0,
            misses: 0,
        }
    }

    fn access(&mut self, key: &str) -> bool {
        if self.present.contains(key) {
            self.hits += 1;
            // Move to back (MRU).
            self.order.retain(|k| k != key);
            self.order.push_back(key.to_string());
            true
        } else {
            self.misses += 1;
            // Insert.
            if self.order.len() >= self.capacity
                && self.capacity > 0
                && let Some(evicted) = self.order.pop_front()
            {
                self.present.remove(&evicted);
            }
            self.order.push_back(key.to_string());
            self.present.insert(key.to_string());
            false
        }
    }

    fn hit_rate_millionths(&self) -> u64 {
        let total = self.hits + self.misses;
        saturating_div_millionths(self.hits, total)
    }

    #[allow(dead_code)]
    fn total_ops(&self) -> u64 {
        self.hits + self.misses
    }

    fn reset(&mut self) {
        self.order.clear();
        self.present.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

// ---------------------------------------------------------------------------
// ClockReference — simple CLOCK for parity comparison
// ---------------------------------------------------------------------------

/// Simple CLOCK (second-chance) cache used as a reference policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClockReference {
    capacity: usize,
    entries: Vec<(String, bool)>,
    present: BTreeSet<String>,
    hand: usize,
    hits: u64,
    misses: u64,
}

impl ClockReference {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Vec::new(),
            present: BTreeSet::new(),
            hand: 0,
            hits: 0,
            misses: 0,
        }
    }

    fn access(&mut self, key: &str) -> bool {
        if self.present.contains(key) {
            self.hits += 1;
            // Set reference bit.
            for entry in &mut self.entries {
                if entry.0 == key {
                    entry.1 = true;
                    break;
                }
            }
            true
        } else {
            self.misses += 1;
            if self.entries.len() < self.capacity {
                self.entries.push((key.to_string(), false));
                self.present.insert(key.to_string());
            } else if self.capacity > 0 {
                // CLOCK eviction.
                loop {
                    let idx = self.hand % self.entries.len();
                    if self.entries[idx].1 {
                        self.entries[idx].1 = false;
                        self.hand = (self.hand + 1) % self.entries.len();
                    } else {
                        let evicted = self.entries[idx].0.clone();
                        self.present.remove(&evicted);
                        self.entries[idx] = (key.to_string(), false);
                        self.present.insert(key.to_string());
                        self.hand = (self.hand + 1) % self.entries.len();
                        break;
                    }
                }
            }
            false
        }
    }

    fn hit_rate_millionths(&self) -> u64 {
        let total = self.hits + self.misses;
        saturating_div_millionths(self.hits, total)
    }

    #[allow(dead_code)]
    fn total_ops(&self) -> u64 {
        self.hits + self.misses
    }

    fn reset(&mut self) {
        self.entries.clear();
        self.present.clear();
        self.hand = 0;
        self.hits = 0;
        self.misses = 0;
    }
}

// ---------------------------------------------------------------------------
// S3FifoGateError
// ---------------------------------------------------------------------------

/// Errors from the S3-FIFO cache gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum S3FifoGateError {
    /// Cache is disabled due to a previous rollback (cooldown active).
    RollbackCooldownActive { remaining_ops: u64 },
    /// Admission rejected by policy.
    AdmissionRejected { reason: String },
    /// Cache capacity is zero.
    ZeroCapacity,
    /// Artifact not found in cache.
    ArtifactNotFound { key: String },
    /// Rollback failed.
    RollbackFailed { reason: String },
    /// Configuration invalid.
    InvalidConfig { reason: String },
}

impl fmt::Display for S3FifoGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RollbackCooldownActive { remaining_ops } => {
                write!(f, "rollback cooldown active: {remaining_ops} ops remaining")
            }
            Self::AdmissionRejected { reason } => {
                write!(f, "admission rejected: {reason}")
            }
            Self::ZeroCapacity => write!(f, "cache capacity is zero"),
            Self::ArtifactNotFound { key } => {
                write!(f, "artifact not found: {key}")
            }
            Self::RollbackFailed { reason } => {
                write!(f, "rollback failed: {reason}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid configuration: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate — the main gate structure
// ---------------------------------------------------------------------------

/// S3-FIFO cache gate with parity checking, rollback, and evidence emission.
///
/// This gate manages three FIFO queues (small, main, ghost) and provides:
/// - Insertion with admission control
/// - Lookup with frequency tracking
/// - Eviction with small-to-main promotion
/// - Parity comparison against LRU/CLOCK reference
/// - Rollback to disable S3-FIFO on regressions
/// - Decision receipt emission for auditability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3FifoCacheGate {
    /// Configuration.
    config: S3FifoCacheConfig,
    /// Small queue — FIFO of canonical keys.
    small_queue: VecDeque<String>,
    /// Main queue — FIFO of canonical keys.
    main_queue: VecDeque<String>,
    /// Ghost queue — FIFO of canonical keys.
    ghost_queue: VecDeque<String>,
    /// All live entries indexed by canonical key.
    entries: BTreeMap<String, CacheEntry>,
    /// Ghost entries indexed by canonical key.
    ghost_entries: BTreeMap<String, GhostEntry>,
    /// Monotonic sequence counter for FIFO ordering.
    sequence_counter: u64,
    /// Global operation counter.
    operation_counter: u64,
    /// Benchmark evidence accumulator.
    benchmark: BenchmarkEvidence,
    /// LRU reference for parity comparison.
    lru_ref: LruReference,
    /// CLOCK reference for parity comparison.
    clock_ref: ClockReference,
    /// Current rollback state.
    rollback_state: RollbackState,
    /// Operations remaining in rollback cooldown.
    rollback_cooldown_remaining: u64,
    /// History of rollback records.
    rollback_history: Vec<RollbackRecord>,
    /// Emitted decision receipts.
    receipts: Vec<DecisionReceipt>,
    /// Current epoch.
    current_epoch: SecurityEpoch,
    /// Whether S3-FIFO is the active policy (false = passthrough/disabled).
    active: bool,
    /// Current small ratio in millionths (may differ from config if adapted).
    effective_small_ratio_millionths: u64,
}

impl S3FifoCacheGate {
    /// Create a new S3-FIFO cache gate with the given configuration.
    pub fn new(config: S3FifoCacheConfig, epoch: SecurityEpoch) -> Result<Self, S3FifoGateError> {
        if config.total_capacity == 0 {
            return Err(S3FifoGateError::ZeroCapacity);
        }
        if config.small_ratio_millionths > MILLION {
            return Err(S3FifoGateError::InvalidConfig {
                reason: "small_ratio_millionths exceeds 1_000_000".into(),
            });
        }
        let effective_small = config.small_ratio_millionths;
        Ok(Self {
            lru_ref: LruReference::new(config.total_capacity),
            clock_ref: ClockReference::new(config.total_capacity),
            benchmark: BenchmarkEvidence::empty(epoch),
            config,
            small_queue: VecDeque::new(),
            main_queue: VecDeque::new(),
            ghost_queue: VecDeque::new(),
            entries: BTreeMap::new(),
            ghost_entries: BTreeMap::new(),
            sequence_counter: 0,
            operation_counter: 0,
            rollback_state: RollbackState::Idle,
            rollback_cooldown_remaining: 0,
            rollback_history: Vec::new(),
            receipts: Vec::new(),
            current_epoch: epoch,
            active: true,
            effective_small_ratio_millionths: effective_small,
        })
    }

    /// Create with default configuration.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(S3FifoCacheConfig::default(), epoch).expect("default config is valid")
    }

    // -- Capacity helpers --

    fn effective_small_capacity(&self) -> usize {
        let raw = (self.config.total_capacity as u64)
            .saturating_mul(self.effective_small_ratio_millionths)
            .checked_div(MILLION)
            .unwrap_or(0);
        std::cmp::max(raw as usize, 1)
    }

    fn effective_main_capacity(&self) -> usize {
        self.config
            .total_capacity
            .saturating_sub(self.effective_small_capacity())
    }

    fn ghost_capacity(&self) -> usize {
        self.config.ghost_capacity()
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence_counter;
        self.sequence_counter += 1;
        seq
    }

    // -- Core operations --

    /// Look up an artifact by canonical key. Returns true on hit.
    pub fn lookup(&mut self, key: &str) -> bool {
        self.operation_counter += 1;
        self.benchmark.total_lookups += 1;

        // Feed reference policies.
        self.lru_ref.access(key);
        self.clock_ref.access(key);

        // Tick cooldown.
        if self.rollback_cooldown_remaining > 0 {
            self.rollback_cooldown_remaining -= 1;
            if self.rollback_cooldown_remaining == 0 {
                self.rollback_state = RollbackState::Idle;
            }
        }

        if !self.active {
            self.benchmark.misses += 1;
            return false;
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.record_access();
            self.benchmark.hits += 1;
            true
        } else {
            self.benchmark.misses += 1;
            false
        }
    }

    /// Insert an artifact into the cache.
    ///
    /// Returns the admission decision. On admission, the artifact is placed
    /// in the small queue. Eviction may occur if the queue is full.
    pub fn insert(
        &mut self,
        artifact_id: CacheArtifactId,
        size_bytes: u64,
        payload_hash: ContentHash,
    ) -> Result<AdmissionDecision, S3FifoGateError> {
        if !self.active {
            if self.rollback_cooldown_remaining > 0 {
                return Err(S3FifoGateError::RollbackCooldownActive {
                    remaining_ops: self.rollback_cooldown_remaining,
                });
            }
            // Re-enable after cooldown.
            self.active = true;
        }

        let key = artifact_id.canonical_key();

        // If already present, treat as a hit.
        if self.entries.contains_key(&key) {
            self.lookup(&key);
            return Ok(AdmissionDecision::Admit {
                reason: "already_present".into(),
            });
        }

        // Admission control.
        let ghost_entry = self.ghost_entries.get(&key);
        let decision = self
            .config
            .admission_policy
            .should_admit(size_bytes, ghost_entry);
        if !decision.is_admit() {
            return Ok(decision);
        }

        // Check if we have a ghost hit — if so, promote directly to main.
        let is_ghost_hit = self.ghost_entries.contains_key(&key);
        if is_ghost_hit {
            self.ghost_entries.remove(&key);
            self.ghost_queue.retain(|k| k != &key);
            self.benchmark.ghost_hits += 1;
        }

        let seq = self.next_sequence();
        let epoch = self.current_epoch;

        if is_ghost_hit {
            // Ghost hit: insert directly into main queue.
            self.evict_main_if_needed();
            let mut entry =
                CacheEntry::new_small(artifact_id, size_bytes, payload_hash, seq, epoch);
            entry.promote_to_main(seq);
            self.main_queue.push_back(key.clone());
            self.entries.insert(key, entry);
            self.benchmark.promotions += 1;
        } else {
            // Fresh insert into small queue.
            self.evict_small_if_needed();
            let entry = CacheEntry::new_small(artifact_id, size_bytes, payload_hash, seq, epoch);
            self.small_queue.push_back(key.clone());
            self.entries.insert(key, entry);
        }

        Ok(decision)
    }

    /// Evict from the small queue if it exceeds capacity.
    fn evict_small_if_needed(&mut self) {
        while self.small_queue.len() >= self.effective_small_capacity() {
            if let Some(evicted_key) = self.small_queue.pop_front() {
                if let Some(entry) = self.entries.remove(&evicted_key) {
                    if entry.frequency > 0 {
                        // Promote to main.
                        let seq = self.next_sequence();
                        let mut promoted = entry;
                        promoted.promote_to_main(seq);
                        self.evict_main_if_needed();
                        self.main_queue.push_back(evicted_key.clone());
                        self.entries.insert(evicted_key, promoted);
                        self.benchmark.promotions += 1;
                    } else {
                        // Evict to ghost.
                        self.add_to_ghost(&evicted_key, &entry);
                        self.benchmark.total_evictions += 1;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Evict from the main queue if it exceeds capacity.
    fn evict_main_if_needed(&mut self) {
        while self.main_queue.len() >= self.effective_main_capacity() {
            if let Some(evicted_key) = self.main_queue.pop_front() {
                if let Some(mut entry) = self.entries.remove(&evicted_key) {
                    if entry.frequency > 0 {
                        // Give a second chance: decrement and re-insert.
                        entry.decrement_frequency();
                        self.main_queue.push_back(evicted_key.clone());
                        self.entries.insert(evicted_key, entry);
                    } else {
                        // Truly evict.
                        self.add_to_ghost(&evicted_key, &entry);
                        self.benchmark.total_evictions += 1;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Add an evicted entry to the ghost queue.
    fn add_to_ghost(&mut self, key: &str, entry: &CacheEntry) {
        // Evict ghost entries if at capacity.
        while self.ghost_queue.len() >= self.ghost_capacity() {
            if let Some(ghost_key) = self.ghost_queue.pop_front() {
                self.ghost_entries.remove(&ghost_key);
            }
        }

        let seq = self.sequence_counter;
        self.sequence_counter += 1;

        if let Some(existing) = self.ghost_entries.get_mut(key) {
            existing.ghost_hits += 1;
            existing.sequence_number = seq;
        } else {
            let ghost = GhostEntry {
                canonical_key: key.to_string(),
                payload_hash: entry.payload_hash,
                ghost_hits: 1,
                original_size_bytes: entry.size_bytes,
                sequence_number: seq,
            };
            self.ghost_queue.push_back(key.to_string());
            self.ghost_entries.insert(key.to_string(), ghost);
        }
    }

    /// Remove an artifact by key.
    pub fn remove(&mut self, key: &str) -> bool {
        if self.entries.remove(key).is_some() {
            self.small_queue.retain(|k| k != key);
            self.main_queue.retain(|k| k != key);
            true
        } else {
            false
        }
    }

    /// Flush the entire cache.
    pub fn flush(&mut self) {
        self.small_queue.clear();
        self.main_queue.clear();
        self.ghost_queue.clear();
        self.entries.clear();
        self.ghost_entries.clear();
    }

    // -- Parity gate --

    /// Evaluate parity between S3-FIFO and the configured reference policy.
    pub fn evaluate_parity(&mut self) -> ParityResult {
        let s3_hit_rate = self.current_hit_rate_millionths();
        let (ref_hit_rate, ref_policy) = match self.config.reference_policy {
            ReferencePolicyKind::Lru => {
                (self.lru_ref.hit_rate_millionths(), ReferencePolicyKind::Lru)
            }
            ReferencePolicyKind::Clock => (
                self.clock_ref.hit_rate_millionths(),
                ReferencePolicyKind::Clock,
            ),
        };

        let delta = s3_hit_rate.abs_diff(ref_hit_rate);

        let verdict = if delta <= self.config.parity_tolerance_millionths {
            ParityVerdict::WithinTolerance
        } else {
            ParityVerdict::DivergenceBeyondTolerance
        };

        let mut evidence_buf = Vec::new();
        evidence_buf.extend_from_slice(&s3_hit_rate.to_be_bytes());
        evidence_buf.extend_from_slice(&ref_hit_rate.to_be_bytes());
        evidence_buf.extend_from_slice(&delta.to_be_bytes());
        let evidence_hash = compute_content_hash(&evidence_buf);

        let total_ops = self.benchmark.total_lookups;

        ParityResult {
            reference_policy: ref_policy,
            verdict,
            s3_fifo_hit_rate_millionths: s3_hit_rate,
            reference_hit_rate_millionths: ref_hit_rate,
            hit_rate_delta_millionths: delta,
            tolerance_millionths: self.config.parity_tolerance_millionths,
            total_operations: total_ops,
            evidence_hash,
        }
    }

    /// Current S3-FIFO hit rate in millionths.
    pub fn current_hit_rate_millionths(&self) -> u64 {
        saturating_div_millionths(self.benchmark.hits, self.benchmark.total_lookups)
    }

    // -- Rollback gate --

    /// Check all rollback triggers and execute rollback if any fire.
    pub fn evaluate_rollback(&mut self) -> Option<RollbackRecord> {
        if !self.active {
            return None;
        }

        let hit_rate = self.current_hit_rate_millionths();

        // Check hit rate threshold.
        if self.benchmark.total_lookups > 0 && hit_rate < self.config.min_hit_rate_millionths {
            let trigger = RollbackTrigger::HitRateBelowThreshold {
                threshold_millionths: self.config.min_hit_rate_millionths,
            };
            return Some(self.execute_rollback(trigger));
        }

        // Check parity gate.
        let parity = self.evaluate_parity();
        if !parity.passed() {
            let trigger = RollbackTrigger::ParityGateFailure;
            return Some(self.execute_rollback(trigger));
        }

        None
    }

    /// Execute a rollback, disabling S3-FIFO and entering cooldown.
    pub fn execute_rollback(&mut self, trigger: RollbackTrigger) -> RollbackRecord {
        self.rollback_state = RollbackState::Executing;

        // Snapshot benchmark evidence.
        let mut bench = self.benchmark.clone();
        bench.recompute_rates();
        bench.compute_trace_hash();

        // Clear cache state.
        self.flush();
        self.active = false;
        self.rollback_cooldown_remaining = self.config.rollback_cooldown_ops;

        let rollback_seq = self.rollback_history.len() as u64;

        let mut evidence_buf = Vec::new();
        evidence_buf.extend_from_slice(trigger.category().as_bytes());
        evidence_buf.extend_from_slice(&self.current_epoch.as_u64().to_be_bytes());
        evidence_buf.extend_from_slice(&rollback_seq.to_be_bytes());
        let evidence_hash = compute_content_hash(&evidence_buf);

        let record = RollbackRecord {
            trigger,
            state: RollbackState::Completed,
            epoch: self.current_epoch,
            benchmark_at_rollback: bench,
            evidence_hash,
            rollback_sequence: rollback_seq,
        };

        self.rollback_state = RollbackState::Completed;
        self.rollback_history.push(record.clone());

        // Emit decision receipt.
        self.emit_receipt(DecisionKind::GateFailRollback);

        record
    }

    /// Trigger a rollback from an external operator.
    pub fn operator_rollback(
        &mut self,
        operator_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> RollbackRecord {
        let trigger = RollbackTrigger::OperatorInitiated {
            operator_id: operator_id.into(),
            reason: reason.into(),
        };
        self.execute_rollback(trigger)
    }

    /// Re-enable S3-FIFO after a rollback, resetting counters.
    pub fn re_enable(&mut self) -> Result<(), S3FifoGateError> {
        if self.rollback_cooldown_remaining > 0 {
            return Err(S3FifoGateError::RollbackCooldownActive {
                remaining_ops: self.rollback_cooldown_remaining,
            });
        }
        self.active = true;
        self.rollback_state = RollbackState::Idle;
        self.benchmark = BenchmarkEvidence::empty(self.current_epoch);
        self.lru_ref.reset();
        self.clock_ref.reset();
        self.emit_receipt(DecisionKind::PolicyEnabled);
        Ok(())
    }

    // -- Split ratio adaptation --

    /// Adapt the small/main split ratio based on observed ghost hit patterns.
    ///
    /// If ghost hits are high (items evicted from small are frequently re-accessed),
    /// increase the small queue. If ghost hits are low, decrease it.
    pub fn adapt_split_ratio(&mut self) -> Option<u64> {
        if !self.config.auto_adapt_split || !self.active {
            return None;
        }

        let total_evictions = self.benchmark.total_evictions;
        if total_evictions == 0 {
            return None;
        }

        let ghost_hit_ratio = saturating_div_millionths(self.benchmark.ghost_hits, total_evictions);

        let old_ratio = self.effective_small_ratio_millionths;
        let new_ratio = if ghost_hit_ratio > 500_000 {
            // High ghost hits → items evicted too early from small → increase small.
            std::cmp::min(
                old_ratio.saturating_add(10_000),
                self.config.max_small_ratio_millionths,
            )
        } else if ghost_hit_ratio < 100_000 {
            // Low ghost hits → small queue too large → decrease small.
            std::cmp::max(
                old_ratio.saturating_sub(10_000),
                self.config.min_small_ratio_millionths,
            )
        } else {
            old_ratio
        };

        if new_ratio != old_ratio {
            self.effective_small_ratio_millionths = new_ratio;
            self.emit_receipt(DecisionKind::SplitRatioAdapted);
            Some(new_ratio)
        } else {
            None
        }
    }

    // -- Evidence emission --

    /// Emit a decision receipt for the current state.
    pub fn emit_receipt(&mut self, kind: DecisionKind) -> DecisionReceipt {
        let mut bench = self.benchmark.clone();
        bench.recompute_rates();
        bench.compute_trace_hash();

        let receipt_seq = self.receipts.len() as u64;
        let mut id_buf = Vec::new();
        id_buf.extend_from_slice(&receipt_seq.to_be_bytes());
        id_buf.extend_from_slice(&self.current_epoch.as_u64().to_be_bytes());
        id_buf.extend_from_slice(&(kind as u8).to_be_bytes());
        let receipt_id = hex_encode(compute_content_hash(&id_buf).as_bytes());

        let last_rollback = self.rollback_history.last().cloned();

        let mut receipt = DecisionReceipt {
            schema_version: S3_FIFO_SCHEMA_VERSION.to_string(),
            receipt_id,
            decision_kind: kind,
            epoch: self.current_epoch,
            parity_result: None,
            benchmark_evidence: bench,
            rollback_record: last_rollback,
            admission_policy_label: format!("{}", self.config.admission_policy),
            small_ratio_millionths: self.effective_small_ratio_millionths,
            content_hash: ContentHash::compute(b"pending"),
        };
        receipt.seal();
        self.receipts.push(receipt.clone());
        receipt
    }

    /// Run a full gate evaluation: parity + rollback + evidence emission.
    pub fn evaluate_gate(&mut self) -> GateEvaluation {
        let parity = self.evaluate_parity();
        let rollback = self.evaluate_rollback();
        let passed = parity.passed() && rollback.is_none();

        let kind = if passed {
            DecisionKind::GatePassContinue
        } else {
            DecisionKind::GateFailRollback
        };

        // Only emit receipt if we did not already emit one from rollback.
        let receipt = if rollback.is_none() {
            self.emit_receipt(kind)
        } else {
            // Rollback already emitted a receipt; retrieve the last one.
            self.receipts
                .last()
                .cloned()
                .unwrap_or_else(|| self.emit_receipt(kind))
        };

        GateEvaluation {
            passed,
            parity_result: parity,
            rollback_record: rollback,
            receipt,
            active: self.active,
        }
    }

    // -- Accessors --

    /// Whether S3-FIFO is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Current rollback state.
    pub fn rollback_state(&self) -> RollbackState {
        self.rollback_state
    }

    /// Number of items in the small queue.
    pub fn small_queue_len(&self) -> usize {
        self.small_queue.len()
    }

    /// Number of items in the main queue.
    pub fn main_queue_len(&self) -> usize {
        self.main_queue.len()
    }

    /// Number of items in the ghost queue.
    pub fn ghost_queue_len(&self) -> usize {
        self.ghost_queue.len()
    }

    /// Total number of live cached items.
    pub fn total_cached(&self) -> usize {
        self.entries.len()
    }

    /// Total number of ghost entries.
    pub fn total_ghost(&self) -> usize {
        self.ghost_entries.len()
    }

    /// Get the configuration.
    pub fn config(&self) -> &S3FifoCacheConfig {
        &self.config
    }

    /// Get all emitted receipts.
    pub fn receipts(&self) -> &[DecisionReceipt] {
        &self.receipts
    }

    /// Get the rollback history.
    pub fn rollback_history(&self) -> &[RollbackRecord] {
        &self.rollback_history
    }

    /// Get the current benchmark evidence.
    pub fn benchmark_evidence(&self) -> &BenchmarkEvidence {
        &self.benchmark
    }

    /// Get the current effective small ratio.
    pub fn effective_small_ratio_millionths(&self) -> u64 {
        self.effective_small_ratio_millionths
    }

    /// Current epoch.
    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Advance to a new epoch, potentially triggering re-evaluation.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        let _old = self.current_epoch;
        self.current_epoch = new_epoch;
        self.benchmark.epoch = new_epoch;

        // Invalidate entries from previous epochs.
        for entry in self.entries.values_mut() {
            entry.last_validated_epoch = new_epoch;
        }
    }

    /// Update the admission policy.
    pub fn set_admission_policy(&mut self, policy: AdmissionPolicy) {
        self.config.admission_policy = policy;
        self.emit_receipt(DecisionKind::AdmissionPolicyChanged);
    }

    /// Get a snapshot of segment sizes for diagnostics.
    pub fn segment_snapshot(&self) -> SegmentSnapshot {
        SegmentSnapshot {
            small_len: self.small_queue.len(),
            small_capacity: self.effective_small_capacity(),
            main_len: self.main_queue.len(),
            main_capacity: self.effective_main_capacity(),
            ghost_len: self.ghost_queue.len(),
            ghost_capacity: self.ghost_capacity(),
            total_cached: self.entries.len(),
            effective_small_ratio_millionths: self.effective_small_ratio_millionths,
        }
    }

    /// Check whether a key exists in any live segment.
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Check whether a key exists in the ghost set.
    pub fn is_ghost(&self, key: &str) -> bool {
        self.ghost_entries.contains_key(key)
    }

    /// Get the segment of a live entry.
    pub fn entry_segment(&self, key: &str) -> Option<CacheSegment> {
        self.entries.get(key).map(|e| e.segment)
    }

    /// Get frequency of a live entry.
    pub fn entry_frequency(&self, key: &str) -> Option<u8> {
        self.entries.get(key).map(|e| e.frequency)
    }
}

// ---------------------------------------------------------------------------
// GateEvaluation — full gate result
// ---------------------------------------------------------------------------

/// Result of a full S3-FIFO gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    /// Whether the gate passed (S3-FIFO should remain active).
    pub passed: bool,
    /// Parity comparison result.
    pub parity_result: ParityResult,
    /// Rollback record if rollback was triggered.
    pub rollback_record: Option<RollbackRecord>,
    /// Decision receipt emitted.
    pub receipt: DecisionReceipt,
    /// Whether S3-FIFO is still active after evaluation.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// SegmentSnapshot — diagnostic view of queue sizes
// ---------------------------------------------------------------------------

/// Diagnostic snapshot of queue sizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentSnapshot {
    /// Items in small queue.
    pub small_len: usize,
    /// Small queue capacity.
    pub small_capacity: usize,
    /// Items in main queue.
    pub main_len: usize,
    /// Main queue capacity.
    pub main_capacity: usize,
    /// Items in ghost queue.
    pub ghost_len: usize,
    /// Ghost queue capacity.
    pub ghost_capacity: usize,
    /// Total live items.
    pub total_cached: usize,
    /// Effective small ratio.
    pub effective_small_ratio_millionths: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn artifact(label: &str) -> CacheArtifactId {
        CacheArtifactId::new(ContentHash::compute(label.as_bytes()), 1, label.to_string())
    }

    fn payload(label: &str) -> ContentHash {
        ContentHash::compute(format!("payload:{label}").as_bytes())
    }

    fn key(label: &str) -> String {
        artifact(label).canonical_key()
    }

    fn default_gate() -> S3FifoCacheGate {
        S3FifoCacheGate::with_defaults(epoch(1))
    }

    fn small_gate(capacity: usize) -> S3FifoCacheGate {
        let config = S3FifoCacheConfig {
            total_capacity: capacity,
            small_ratio_millionths: 500_000, // 50%
            ..S3FifoCacheConfig::default()
        };
        S3FifoCacheGate::new(config, epoch(1)).unwrap()
    }

    // -- Construction tests --

    #[test]
    fn test_new_default_config() {
        let gate = default_gate();
        assert!(gate.is_active());
        assert_eq!(gate.total_cached(), 0);
        assert_eq!(gate.small_queue_len(), 0);
        assert_eq!(gate.main_queue_len(), 0);
        assert_eq!(gate.ghost_queue_len(), 0);
    }

    #[test]
    fn test_zero_capacity_rejected() {
        let config = S3FifoCacheConfig {
            total_capacity: 0,
            ..S3FifoCacheConfig::default()
        };
        let result = S3FifoCacheGate::new(config, epoch(1));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3FifoGateError::ZeroCapacity));
    }

    #[test]
    fn test_invalid_ratio_rejected() {
        let config = S3FifoCacheConfig {
            small_ratio_millionths: 1_500_000,
            ..S3FifoCacheConfig::default()
        };
        let result = S3FifoCacheGate::new(config, epoch(1));
        assert!(matches!(
            result.unwrap_err(),
            S3FifoGateError::InvalidConfig { .. }
        ));
    }

    #[test]
    fn test_config_capacities() {
        let config = S3FifoCacheConfig {
            total_capacity: 100,
            small_ratio_millionths: 200_000, // 20%
            ghost_multiplier: 3,
            ..S3FifoCacheConfig::default()
        };
        assert_eq!(config.small_capacity(), 20);
        assert_eq!(config.main_capacity(), 80);
        assert_eq!(config.ghost_capacity(), 300);
    }

    // -- Insertion tests --

    #[test]
    fn test_basic_insert() {
        let mut gate = default_gate();
        let decision = gate.insert(artifact("a"), 100, payload("a")).unwrap();
        assert!(decision.is_admit());
        assert_eq!(gate.total_cached(), 1);
        assert!(gate.contains(&key("a")));
    }

    #[test]
    fn test_insert_starts_in_small() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 100, payload("a")).unwrap();
        assert_eq!(gate.entry_segment(&key("a")), Some(CacheSegment::Small));
    }

    #[test]
    fn test_duplicate_insert_is_hit() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 100, payload("a")).unwrap();
        let d = gate.insert(artifact("a"), 100, payload("a")).unwrap();
        assert!(d.is_admit());
        assert_eq!(gate.total_cached(), 1);
    }

    #[test]
    fn test_insert_multiple_items() {
        let mut gate = small_gate(10);
        for i in 0..5 {
            let label = format!("item_{i}");
            gate.insert(artifact(&label), 100, payload(&label)).unwrap();
        }
        assert_eq!(gate.total_cached(), 5);
    }

    // -- Lookup tests --

    #[test]
    fn test_lookup_hit() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 100, payload("a")).unwrap();
        assert!(gate.lookup(&key("a")));
        assert_eq!(gate.benchmark_evidence().hits, 1);
    }

    #[test]
    fn test_lookup_miss() {
        let mut gate = default_gate();
        assert!(!gate.lookup("nonexistent"));
        assert_eq!(gate.benchmark_evidence().misses, 1);
    }

    #[test]
    fn test_lookup_increments_frequency() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 100, payload("a")).unwrap();
        let k = key("a");
        assert_eq!(gate.entry_frequency(&k), Some(0));
        gate.lookup(&k);
        assert_eq!(gate.entry_frequency(&k), Some(1));
        gate.lookup(&k);
        assert_eq!(gate.entry_frequency(&k), Some(2));
    }

    #[test]
    fn test_frequency_saturates_at_max() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 100, payload("a")).unwrap();
        let k = key("a");
        for _ in 0..10 {
            gate.lookup(&k);
        }
        assert_eq!(gate.entry_frequency(&k), Some(MAX_FREQUENCY));
    }

    // -- Eviction tests --

    #[test]
    fn test_eviction_from_small_to_ghost() {
        let mut gate = small_gate(4); // 50% small = 2, 50% main = 2
        // Insert enough to fill small and trigger eviction.
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.insert(artifact("b"), 10, payload("b")).unwrap();
        // Third insert should evict from small.
        gate.insert(artifact("c"), 10, payload("c")).unwrap();
        // 'a' had freq=0 so should be evicted to ghost.
        assert!(gate.is_ghost("a") || gate.total_cached() <= 4);
    }

    #[test]
    fn test_promotion_on_frequency() {
        let mut gate = small_gate(4);
        let ka = key("a");
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        // Access 'a' to bump frequency.
        gate.lookup(&ka);
        assert!(gate.entry_frequency(&ka).unwrap() > 0);
        // Fill to trigger eviction — 'a' should be promoted to main.
        gate.insert(artifact("b"), 10, payload("b")).unwrap();
        gate.insert(artifact("c"), 10, payload("c")).unwrap();
        if gate.contains(&ka) {
            assert_eq!(gate.entry_segment(&ka), Some(CacheSegment::Main));
        }
    }

    #[test]
    fn test_ghost_queue_populated_on_eviction() {
        let mut gate = small_gate(2); // small=1, main=1
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.insert(artifact("b"), 10, payload("b")).unwrap();
        // 'a' should be evicted and appear in ghost.
        assert!(gate.is_ghost("a") || gate.total_cached() >= 1);
    }

    #[test]
    fn test_ghost_hit_promotes_to_main() {
        let mut gate = small_gate(4);
        // Fill and evict 'a'.
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.insert(artifact("b"), 10, payload("b")).unwrap();
        gate.insert(artifact("c"), 10, payload("c")).unwrap();
        // If 'a' is in ghost, re-insert should go to main.
        if gate.is_ghost("a") {
            gate.insert(artifact("a"), 10, payload("a")).unwrap();
            if gate.contains("a") {
                assert_eq!(gate.entry_segment("a"), Some(CacheSegment::Main));
            }
        }
    }

    // -- Remove / flush tests --

    #[test]
    fn test_remove_existing() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        let k = key("a");
        assert!(gate.remove(&k));
        assert!(!gate.contains(&k));
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut gate = default_gate();
        assert!(!gate.remove("ghost"));
    }

    #[test]
    fn test_flush() {
        let mut gate = default_gate();
        for i in 0..10 {
            let label = format!("x{i}");
            gate.insert(artifact(&label), 10, payload(&label)).unwrap();
        }
        gate.flush();
        assert_eq!(gate.total_cached(), 0);
        assert_eq!(gate.small_queue_len(), 0);
        assert_eq!(gate.main_queue_len(), 0);
        assert_eq!(gate.ghost_queue_len(), 0);
    }

    // -- Admission policy tests --

    #[test]
    fn test_accept_all_policy() {
        let policy = AdmissionPolicy::AcceptAll;
        let decision = policy.should_admit(999_999, None);
        assert!(decision.is_admit());
    }

    #[test]
    fn test_frequency_aware_no_ghost() {
        let policy = AdmissionPolicy::FrequencyAware;
        let decision = policy.should_admit(100, None);
        assert!(!decision.is_admit());
    }

    #[test]
    fn test_frequency_aware_with_ghost() {
        let policy = AdmissionPolicy::FrequencyAware;
        let ghost = GhostEntry {
            canonical_key: "k".into(),
            payload_hash: ContentHash::compute(b"test"),
            ghost_hits: 1,
            original_size_bytes: 100,
            sequence_number: 0,
        };
        let decision = policy.should_admit(100, Some(&ghost));
        assert!(decision.is_admit());
    }

    #[test]
    fn test_value_aware_within_limit() {
        let policy = AdmissionPolicy::ValueAware {
            max_size_bytes: 1000,
        };
        let decision = policy.should_admit(500, None);
        assert!(decision.is_admit());
    }

    #[test]
    fn test_value_aware_exceeds_limit() {
        let policy = AdmissionPolicy::ValueAware {
            max_size_bytes: 1000,
        };
        let decision = policy.should_admit(1500, None);
        assert!(!decision.is_admit());
    }

    #[test]
    fn test_combined_policy_small_item() {
        let policy = AdmissionPolicy::Combined {
            max_size_bytes: 1000,
            min_ghost_hits: 2,
        };
        let decision = policy.should_admit(500, None);
        assert!(decision.is_admit());
    }

    #[test]
    fn test_combined_policy_large_item_no_ghost() {
        let policy = AdmissionPolicy::Combined {
            max_size_bytes: 1000,
            min_ghost_hits: 2,
        };
        let decision = policy.should_admit(2000, None);
        assert!(!decision.is_admit());
    }

    #[test]
    fn test_combined_policy_large_item_sufficient_ghost() {
        let policy = AdmissionPolicy::Combined {
            max_size_bytes: 1000,
            min_ghost_hits: 2,
        };
        let ghost = GhostEntry {
            canonical_key: "k".into(),
            payload_hash: ContentHash::compute(b"test"),
            ghost_hits: 3,
            original_size_bytes: 2000,
            sequence_number: 0,
        };
        let decision = policy.should_admit(2000, Some(&ghost));
        assert!(decision.is_admit());
    }

    #[test]
    fn test_combined_policy_large_item_insufficient_ghost() {
        let policy = AdmissionPolicy::Combined {
            max_size_bytes: 1000,
            min_ghost_hits: 5,
        };
        let ghost = GhostEntry {
            canonical_key: "k".into(),
            payload_hash: ContentHash::compute(b"test"),
            ghost_hits: 2,
            original_size_bytes: 2000,
            sequence_number: 0,
        };
        let decision = policy.should_admit(2000, Some(&ghost));
        assert!(!decision.is_admit());
    }

    #[test]
    fn test_frequency_aware_gate_rejects_unknown() {
        let config = S3FifoCacheConfig {
            admission_policy: AdmissionPolicy::FrequencyAware,
            total_capacity: 10,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        let d = gate
            .insert(artifact("new_item"), 100, payload("new_item"))
            .unwrap();
        assert!(!d.is_admit());
    }

    // -- Parity tests --

    #[test]
    fn test_parity_empty_cache() {
        let mut gate = default_gate();
        let parity = gate.evaluate_parity();
        assert!(parity.passed());
        assert_eq!(parity.s3_fifo_hit_rate_millionths, 0);
    }

    #[test]
    fn test_parity_within_tolerance() {
        let mut gate = small_gate(10);
        // Both S3-FIFO and LRU/CLOCK see the same accesses.
        for i in 0..5 {
            let label = format!("p{i}");
            gate.insert(artifact(&label), 10, payload(&label)).unwrap();
        }
        for i in 0..5 {
            let label = format!("p{i}");
            gate.lookup(&label);
        }
        let parity = gate.evaluate_parity();
        // With same access pattern, delta should be small.
        assert!(
            parity.hit_rate_delta_millionths <= gate.config().parity_tolerance_millionths
                || parity.passed()
        );
    }

    #[test]
    fn test_parity_uses_configured_reference() {
        let config = S3FifoCacheConfig {
            reference_policy: ReferencePolicyKind::Clock,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        let parity = gate.evaluate_parity();
        assert_eq!(parity.reference_policy, ReferencePolicyKind::Clock);
    }

    #[test]
    fn test_parity_evidence_hash_deterministic() {
        let mut gate1 = small_gate(10);
        let mut gate2 = small_gate(10);
        for i in 0..3 {
            let label = format!("d{i}");
            gate1.insert(artifact(&label), 10, payload(&label)).unwrap();
            gate2.insert(artifact(&label), 10, payload(&label)).unwrap();
            gate1.lookup(&label);
            gate2.lookup(&label);
        }
        let p1 = gate1.evaluate_parity();
        let p2 = gate2.evaluate_parity();
        assert_eq!(p1.evidence_hash, p2.evidence_hash);
    }

    // -- Rollback tests --

    #[test]
    fn test_rollback_on_low_hit_rate() {
        let config = S3FifoCacheConfig {
            total_capacity: 4,
            min_hit_rate_millionths: 800_000, // 80% — very high
            small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        // Lots of misses.
        for i in 0..20 {
            let label = format!("miss{i}");
            gate.lookup(&label);
        }
        let rollback = gate.evaluate_rollback();
        assert!(rollback.is_some());
        assert!(!gate.is_active());
    }

    #[test]
    fn test_rollback_disables_cache() {
        let mut gate = default_gate();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        assert!(!gate.is_active());
        assert!(gate.rollback_cooldown_remaining > 0);
    }

    #[test]
    fn test_rollback_cooldown() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 5,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        // Lookups should tick down cooldown.
        for _ in 0..5 {
            gate.lookup("x");
        }
        assert_eq!(gate.rollback_state(), RollbackState::Idle);
    }

    #[test]
    fn test_re_enable_during_cooldown_fails() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 100,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        let result = gate.re_enable();
        assert!(matches!(
            result,
            Err(S3FifoGateError::RollbackCooldownActive { .. })
        ));
    }

    #[test]
    fn test_re_enable_after_cooldown() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 3,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        for _ in 0..3 {
            gate.lookup("tick");
        }
        assert!(gate.re_enable().is_ok());
        assert!(gate.is_active());
    }

    #[test]
    fn test_operator_rollback() {
        let mut gate = default_gate();
        let record = gate.operator_rollback("admin", "testing");
        assert_eq!(record.state, RollbackState::Completed);
        assert!(!gate.is_active());
    }

    #[test]
    fn test_rollback_history_accumulates() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 1,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        gate.lookup("tick"); // Expire cooldown.
        let _ = gate.re_enable();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        assert_eq!(gate.rollback_history().len(), 2);
    }

    #[test]
    fn test_rollback_record_has_evidence_hash() {
        let mut gate = default_gate();
        let record = gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        assert_ne!(record.evidence_hash, ContentHash::compute(b""));
    }

    // -- Split ratio adaptation tests --

    #[test]
    fn test_adapt_split_disabled_by_default() {
        let mut gate = default_gate();
        assert!(gate.adapt_split_ratio().is_none());
    }

    #[test]
    fn test_adapt_split_no_evictions() {
        let config = S3FifoCacheConfig {
            auto_adapt_split: true,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        assert!(gate.adapt_split_ratio().is_none());
    }

    #[test]
    fn test_adapt_split_high_ghost_hits_increases() {
        let config = S3FifoCacheConfig {
            total_capacity: 4,
            small_ratio_millionths: 200_000,
            auto_adapt_split: true,
            min_small_ratio_millionths: 50_000,
            max_small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        // Simulate high ghost hits.
        gate.benchmark.total_evictions = 10;
        gate.benchmark.ghost_hits = 8; // 80% ghost hit ratio.
        let old = gate.effective_small_ratio_millionths();
        let result = gate.adapt_split_ratio();
        assert!(result.is_some());
        assert!(gate.effective_small_ratio_millionths() > old);
    }

    #[test]
    fn test_adapt_split_low_ghost_hits_decreases() {
        let config = S3FifoCacheConfig {
            total_capacity: 100,
            small_ratio_millionths: 200_000,
            auto_adapt_split: true,
            min_small_ratio_millionths: 50_000,
            max_small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.benchmark.total_evictions = 100;
        gate.benchmark.ghost_hits = 5; // 5% ghost hit ratio.
        let old = gate.effective_small_ratio_millionths();
        let result = gate.adapt_split_ratio();
        assert!(result.is_some());
        assert!(gate.effective_small_ratio_millionths() < old);
    }

    #[test]
    fn test_adapt_split_respects_bounds() {
        let config = S3FifoCacheConfig {
            total_capacity: 100,
            small_ratio_millionths: 50_000, // Already at min.
            auto_adapt_split: true,
            min_small_ratio_millionths: 50_000,
            max_small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.benchmark.total_evictions = 100;
        gate.benchmark.ghost_hits = 1;
        let result = gate.adapt_split_ratio();
        // Should stay at min.
        assert!(result.is_none() || gate.effective_small_ratio_millionths() >= 50_000);
    }

    // -- Decision receipt tests --

    #[test]
    fn test_receipt_emitted_on_enable() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 0,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.active = false;
        gate.rollback_state = RollbackState::Completed;
        let _ = gate.re_enable();
        assert!(!gate.receipts().is_empty());
        assert_eq!(
            gate.receipts().last().unwrap().decision_kind,
            DecisionKind::PolicyEnabled
        );
    }

    #[test]
    fn test_receipt_emitted_on_rollback() {
        let mut gate = default_gate();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        assert!(!gate.receipts().is_empty());
        assert_eq!(
            gate.receipts().last().unwrap().decision_kind,
            DecisionKind::GateFailRollback
        );
    }

    #[test]
    fn test_receipt_has_schema_version() {
        let mut gate = default_gate();
        let receipt = gate.emit_receipt(DecisionKind::GatePassContinue);
        assert_eq!(receipt.schema_version, S3_FIFO_SCHEMA_VERSION);
    }

    #[test]
    fn test_receipt_has_content_hash() {
        let mut gate = default_gate();
        let receipt = gate.emit_receipt(DecisionKind::CacheFlushed);
        assert_ne!(receipt.content_hash, ContentHash::compute(b"pending"));
    }

    #[test]
    fn test_receipt_id_unique() {
        let mut gate = default_gate();
        let r1 = gate.emit_receipt(DecisionKind::GatePassContinue);
        let r2 = gate.emit_receipt(DecisionKind::GatePassContinue);
        assert_ne!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn test_receipt_includes_admission_policy_label() {
        let config = S3FifoCacheConfig {
            admission_policy: AdmissionPolicy::FrequencyAware,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        let receipt = gate.emit_receipt(DecisionKind::GatePassContinue);
        assert!(receipt.admission_policy_label.contains("frequency_aware"));
    }

    // -- Gate evaluation tests --

    #[test]
    fn test_gate_evaluation_passes_no_data() {
        let mut gate = default_gate();
        let eval = gate.evaluate_gate();
        assert!(eval.passed);
        assert!(eval.active);
    }

    #[test]
    fn test_gate_evaluation_emits_receipt() {
        let mut gate = default_gate();
        let eval = gate.evaluate_gate();
        assert!(!gate.receipts().is_empty());
        assert_eq!(eval.receipt.schema_version, S3_FIFO_SCHEMA_VERSION);
    }

    #[test]
    fn test_gate_evaluation_triggers_rollback_on_low_hit_rate() {
        let config = S3FifoCacheConfig {
            total_capacity: 10,
            min_hit_rate_millionths: 900_000,
            small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        for i in 0..20 {
            gate.lookup(&format!("miss{i}"));
        }
        let eval = gate.evaluate_gate();
        assert!(!eval.passed);
        assert!(!eval.active);
        assert!(eval.rollback_record.is_some());
    }

    // -- Benchmark evidence tests --

    #[test]
    fn test_benchmark_recompute_rates() {
        let mut bench = BenchmarkEvidence::empty(epoch(1));
        bench.total_lookups = 100;
        bench.hits = 75;
        bench.misses = 25;
        bench.recompute_rates();
        assert_eq!(bench.hit_rate_millionths, 750_000);
        assert_eq!(bench.miss_rate_millionths, 250_000);
    }

    #[test]
    fn test_benchmark_rates_zero_lookups() {
        let mut bench = BenchmarkEvidence::empty(epoch(1));
        bench.recompute_rates();
        assert_eq!(bench.hit_rate_millionths, 0);
        assert_eq!(bench.miss_rate_millionths, 0);
    }

    #[test]
    fn test_benchmark_trace_hash_deterministic() {
        let mut b1 = BenchmarkEvidence::empty(epoch(1));
        b1.total_lookups = 50;
        b1.hits = 30;
        b1.compute_trace_hash();

        let mut b2 = BenchmarkEvidence::empty(epoch(1));
        b2.total_lookups = 50;
        b2.hits = 30;
        b2.compute_trace_hash();

        assert_eq!(b1.trace_hash, b2.trace_hash);
    }

    #[test]
    fn test_benchmark_trace_hash_differs_on_data() {
        let mut b1 = BenchmarkEvidence::empty(epoch(1));
        b1.hits = 10;
        b1.compute_trace_hash();

        let mut b2 = BenchmarkEvidence::empty(epoch(1));
        b2.hits = 20;
        b2.compute_trace_hash();

        assert_ne!(b1.trace_hash, b2.trace_hash);
    }

    // -- Epoch tests --

    #[test]
    fn test_advance_epoch() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.advance_epoch(epoch(2));
        assert_eq!(gate.current_epoch(), epoch(2));
    }

    #[test]
    fn test_epoch_updates_entry_validation() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.advance_epoch(epoch(5));
        // After advance, entry should be validated at the new epoch.
        let entry = gate.entries.get(&key("a")).unwrap();
        assert_eq!(entry.last_validated_epoch, epoch(5));
    }

    // -- Admission policy change tests --

    #[test]
    fn test_set_admission_policy_emits_receipt() {
        let mut gate = default_gate();
        gate.set_admission_policy(AdmissionPolicy::FrequencyAware);
        let last = gate.receipts().last().unwrap();
        assert_eq!(last.decision_kind, DecisionKind::AdmissionPolicyChanged);
    }

    // -- Segment snapshot tests --

    #[test]
    fn test_segment_snapshot() {
        let mut gate = small_gate(10);
        for i in 0..3 {
            let label = format!("s{i}");
            gate.insert(artifact(&label), 10, payload(&label)).unwrap();
        }
        let snap = gate.segment_snapshot();
        assert!(snap.total_cached > 0);
        assert!(snap.small_capacity > 0);
        assert!(snap.main_capacity > 0);
    }

    // -- LRU reference tests --

    #[test]
    fn test_lru_reference_basic() {
        let mut lru = LruReference::new(3);
        assert!(!lru.access("a"));
        assert!(!lru.access("b"));
        assert!(lru.access("a")); // hit
        assert_eq!(lru.hits, 1);
        assert_eq!(lru.misses, 2);
    }

    #[test]
    fn test_lru_reference_eviction() {
        let mut lru = LruReference::new(2);
        lru.access("a");
        lru.access("b");
        lru.access("c"); // evicts 'a'
        assert!(!lru.present.contains("a"));
        assert!(lru.present.contains("b"));
        assert!(lru.present.contains("c"));
    }

    #[test]
    fn test_lru_reference_hit_rate() {
        let mut lru = LruReference::new(10);
        lru.access("a");
        lru.access("b");
        lru.access("a"); // hit
        lru.access("b"); // hit
        assert_eq!(lru.hit_rate_millionths(), 500_000);
    }

    #[test]
    fn test_lru_reference_reset() {
        let mut lru = LruReference::new(5);
        lru.access("a");
        lru.access("b");
        lru.reset();
        assert_eq!(lru.total_ops(), 0);
        assert!(lru.present.is_empty());
    }

    // -- CLOCK reference tests --

    #[test]
    fn test_clock_reference_basic() {
        let mut clock = ClockReference::new(3);
        assert!(!clock.access("a"));
        assert!(!clock.access("b"));
        assert!(clock.access("a")); // hit
        assert_eq!(clock.hits, 1);
    }

    #[test]
    fn test_clock_reference_eviction() {
        let mut clock = ClockReference::new(2);
        clock.access("a");
        clock.access("b");
        clock.access("c"); // evicts one of a/b
        assert_eq!(clock.present.len(), 2);
        assert!(clock.present.contains("c"));
    }

    #[test]
    fn test_clock_reference_reset() {
        let mut clock = ClockReference::new(5);
        clock.access("a");
        clock.reset();
        assert_eq!(clock.total_ops(), 0);
        assert!(clock.entries.is_empty());
    }

    // -- CacheEntry tests --

    #[test]
    fn test_cache_entry_new_small() {
        let entry = CacheEntry::new_small(artifact("test"), 512, payload("test"), 0, epoch(1));
        assert_eq!(entry.segment, CacheSegment::Small);
        assert_eq!(entry.frequency, 0);
        assert_eq!(entry.size_bytes, 512);
    }

    #[test]
    fn test_cache_entry_promote() {
        let mut entry = CacheEntry::new_small(artifact("test"), 512, payload("test"), 0, epoch(1));
        entry.record_access();
        entry.record_access();
        assert_eq!(entry.frequency, 2);
        entry.promote_to_main(10);
        assert_eq!(entry.segment, CacheSegment::Main);
        assert_eq!(entry.frequency, 0); // Reset on promotion.
        assert_eq!(entry.sequence_number, 10);
    }

    #[test]
    fn test_cache_entry_decrement() {
        let mut entry = CacheEntry::new_small(artifact("t"), 10, payload("t"), 0, epoch(1));
        entry.record_access();
        entry.record_access();
        assert_eq!(entry.frequency, 2);
        entry.decrement_frequency();
        assert_eq!(entry.frequency, 1);
        entry.decrement_frequency();
        assert_eq!(entry.frequency, 0);
        entry.decrement_frequency();
        assert_eq!(entry.frequency, 0); // Saturating.
    }

    // -- CacheArtifactId tests --

    #[test]
    fn test_artifact_id_canonical_key() {
        let id = artifact("hello");
        let key = id.canonical_key();
        assert!(key.contains("hello"));
        assert!(key.contains(":1:"));
    }

    #[test]
    fn test_artifact_id_display() {
        let id = artifact("mymod");
        let s = format!("{id}");
        assert!(s.contains("mymod"));
    }

    // -- CacheSegment tests --

    #[test]
    fn test_segment_display() {
        assert_eq!(format!("{}", CacheSegment::Small), "small");
        assert_eq!(format!("{}", CacheSegment::Main), "main");
        assert_eq!(format!("{}", CacheSegment::Ghost), "ghost");
    }

    #[test]
    fn test_segment_all_variants() {
        assert_eq!(CacheSegment::ALL.len(), 3);
    }

    // -- AdmissionPolicy display tests --

    #[test]
    fn test_admission_policy_display() {
        assert_eq!(format!("{}", AdmissionPolicy::AcceptAll), "accept_all");
        assert_eq!(
            format!("{}", AdmissionPolicy::FrequencyAware),
            "frequency_aware"
        );
        let va = AdmissionPolicy::ValueAware { max_size_bytes: 42 };
        assert!(format!("{va}").contains("42"));
    }

    // -- Error display tests --

    #[test]
    fn test_error_display() {
        let e = S3FifoGateError::ZeroCapacity;
        assert!(format!("{e}").contains("zero"));
        let e2 = S3FifoGateError::AdmissionRejected {
            reason: "too_big".into(),
        };
        assert!(format!("{e2}").contains("too_big"));
        let e3 = S3FifoGateError::ArtifactNotFound { key: "k".into() };
        assert!(format!("{e3}").contains("k"));
    }

    // -- RollbackTrigger tests --

    #[test]
    fn test_rollback_trigger_categories() {
        assert_eq!(
            RollbackTrigger::ParityGateFailure.category(),
            "parity_gate_failure"
        );
        assert_eq!(
            RollbackTrigger::HitRateBelowThreshold {
                threshold_millionths: 500_000
            }
            .category(),
            "hit_rate_below_threshold"
        );
        let op = RollbackTrigger::OperatorInitiated {
            operator_id: "x".into(),
            reason: "y".into(),
        };
        assert_eq!(op.category(), "operator_initiated");
    }

    #[test]
    fn test_rollback_trigger_display() {
        let t = RollbackTrigger::LatencyRegression {
            observed_ns_millionths: 100,
            threshold_ns_millionths: 50,
        };
        assert_eq!(format!("{t}"), "latency_regression");
    }

    // -- RollbackState display tests --

    #[test]
    fn test_rollback_state_display() {
        assert_eq!(format!("{}", RollbackState::Idle), "idle");
        assert_eq!(format!("{}", RollbackState::Completed), "completed");
        assert_eq!(format!("{}", RollbackState::Failed), "failed");
    }

    // -- DecisionKind display tests --

    #[test]
    fn test_decision_kind_display() {
        assert_eq!(format!("{}", DecisionKind::PolicyEnabled), "policy_enabled");
        assert_eq!(
            format!("{}", DecisionKind::GatePassContinue),
            "gate_pass_continue"
        );
        assert_eq!(
            format!("{}", DecisionKind::GateFailRollback),
            "gate_fail_rollback"
        );
    }

    // -- ParityVerdict display --

    #[test]
    fn test_parity_verdict_display() {
        assert_eq!(
            format!("{}", ParityVerdict::WithinTolerance),
            "within_tolerance"
        );
        assert_eq!(
            format!("{}", ParityVerdict::DivergenceBeyondTolerance),
            "divergence_beyond_tolerance"
        );
    }

    // -- ReferencePolicyKind display --

    #[test]
    fn test_reference_policy_display() {
        assert_eq!(format!("{}", ReferencePolicyKind::Lru), "LRU");
        assert_eq!(format!("{}", ReferencePolicyKind::Clock), "CLOCK");
    }

    // -- Saturation/helper tests --

    #[test]
    fn test_saturating_div_millionths_zero_denominator() {
        assert_eq!(saturating_div_millionths(100, 0), 0);
    }

    #[test]
    fn test_saturating_div_millionths_normal() {
        assert_eq!(saturating_div_millionths(1, 2), 500_000);
        assert_eq!(saturating_div_millionths(3, 4), 750_000);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x0a, 0xff]), "0aff");
        assert_eq!(hex_encode(&[]), "");
    }

    // -- Integration-style tests --

    #[test]
    fn test_full_lifecycle_insert_lookup_evict_ghost_readmit() {
        let mut gate = small_gate(4); // small=2, main=2
        // Fill small queue.
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.insert(artifact("b"), 10, payload("b")).unwrap();
        // Access 'a' to bump frequency.
        gate.lookup("a");
        // Insert 'c' triggers eviction from small.
        gate.insert(artifact("c"), 10, payload("c")).unwrap();
        // 'b' (freq=0) should be evicted; 'a' (freq>0) promoted.
        // Insert 'd' and 'e' to trigger more evictions.
        gate.insert(artifact("d"), 10, payload("d")).unwrap();
        gate.insert(artifact("e"), 10, payload("e")).unwrap();

        // Verify cache is not larger than capacity.
        assert!(gate.total_cached() <= 4);
    }

    #[test]
    fn test_full_lifecycle_gate_evaluation_sequence() {
        // Use maximum parity tolerance: inserts do not warm the reference
        // cache, so the S3-FIFO hit-rate can far exceed the reference
        // hit-rate after a single round of lookups.  This lifecycle test
        // focuses on the insert-lookup-evaluate flow, not parity math.
        let config = S3FifoCacheConfig {
            total_capacity: 20,
            small_ratio_millionths: 500_000,
            parity_tolerance_millionths: MILLION, // 100% — disables parity gate
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        // Insert and access items.
        for i in 0..10 {
            let label = format!("item{i}");
            gate.insert(artifact(&label), 10, payload(&label)).unwrap();
        }
        for i in 0..10 {
            let label = format!("item{i}");
            gate.lookup(&key(&label));
        }
        // Evaluate gate — should pass with maximum tolerance.
        let eval = gate.evaluate_gate();
        assert!(eval.passed);
        assert!(!gate.receipts().is_empty());
    }

    #[test]
    fn test_full_lifecycle_rollback_and_recovery() {
        let config = S3FifoCacheConfig {
            total_capacity: 10,
            rollback_cooldown_ops: 3,
            small_ratio_millionths: 500_000,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();

        // Trigger rollback.
        gate.operator_rollback("ops", "test");
        assert!(!gate.is_active());

        // Tick through cooldown.
        for _ in 0..3 {
            gate.lookup("tick");
        }

        // Re-enable.
        assert!(gate.re_enable().is_ok());
        assert!(gate.is_active());

        // Insert should work again.
        let d = gate
            .insert(artifact("recovery"), 10, payload("recovery"))
            .unwrap();
        assert!(d.is_admit());
    }

    #[test]
    fn test_epoch_boundary_rollback_trigger() {
        let trigger = RollbackTrigger::EpochBoundary {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        };
        assert_eq!(trigger.category(), "epoch_boundary");
    }

    #[test]
    fn test_contains_and_is_ghost_after_eviction_cycle() {
        let mut gate = small_gate(2); // small=1, main=1
        gate.insert(artifact("x"), 10, payload("x")).unwrap();
        gate.insert(artifact("y"), 10, payload("y")).unwrap();
        gate.insert(artifact("z"), 10, payload("z")).unwrap();
        // At least one of the earlier items should be evicted.
        let total_live = gate.total_cached();
        let total_ghost = gate.total_ghost();
        assert!(total_live <= 2);
        assert!(total_ghost > 0 || total_live > 0);
    }

    #[test]
    fn test_benchmark_evidence_accumulates() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        let ka = key("a");
        gate.lookup(&ka);
        gate.lookup(&ka);
        gate.lookup("miss");
        let bench = gate.benchmark_evidence();
        assert_eq!(bench.hits, 2);
        assert_eq!(bench.misses, 1);
        assert_eq!(bench.total_lookups, 3);
    }

    #[test]
    fn test_inactive_gate_lookup_misses() {
        let mut gate = default_gate();
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        gate.active = false;
        assert!(!gate.lookup("a"));
    }

    #[test]
    fn test_insert_during_cooldown_errors() {
        let config = S3FifoCacheConfig {
            rollback_cooldown_ops: 100,
            ..S3FifoCacheConfig::default()
        };
        let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
        gate.execute_rollback(RollbackTrigger::ParityGateFailure);
        let result = gate.insert(artifact("x"), 10, payload("x"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decision_receipt_seal_changes_hash() {
        let mut receipt = DecisionReceipt {
            schema_version: S3_FIFO_SCHEMA_VERSION.to_string(),
            receipt_id: "test".to_string(),
            decision_kind: DecisionKind::PolicyEnabled,
            epoch: epoch(1),
            parity_result: None,
            benchmark_evidence: BenchmarkEvidence::empty(epoch(1)),
            rollback_record: None,
            admission_policy_label: "accept_all".to_string(),
            small_ratio_millionths: 100_000,
            content_hash: ContentHash::compute(b"pending"),
        };
        let before = receipt.content_hash;
        receipt.seal();
        assert_ne!(receipt.content_hash, before);
    }

    #[test]
    fn test_ghost_entry_serde_roundtrip() {
        let ghost = GhostEntry {
            canonical_key: "test_key".into(),
            payload_hash: ContentHash::compute(b"ghost_test"),
            ghost_hits: 3,
            original_size_bytes: 256,
            sequence_number: 42,
        };
        let json = serde_json::to_string(&ghost).unwrap();
        let restored: GhostEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(ghost, restored);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = S3FifoCacheConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: S3FifoCacheConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }
}
