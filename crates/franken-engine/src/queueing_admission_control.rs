#![forbid(unsafe_code)]

//! Queueing-theoretic admission control and worker-pool sizing for tail SLOs.
//!
//! Bead: bd-1lsy.7.11.2 [RGC-611B]
//!
//! Implements explicit admission control, queue partitioning, and worker-pool
//! sizing so overload is managed with queueing-theoretic guarantees instead of
//! letting burst pressure destroy tail latency.
//!
//! Key design:
//! - M/D/c-style steady-state analysis for worker pool sizing
//! - Token-bucket admission with per-stage budget partitions
//! - Explicit overload shedding with priority-aware rejection
//! - Deterministic decisions with content-addressed audit receipts
//!
//! All latencies are in nanoseconds, utilizations in millionths (1_000_000 = 100%).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const ADMISSION_SCHEMA_VERSION: &str = "franken-engine.queueing-admission-control.v1";
pub const ADMISSION_BEAD_ID: &str = "bd-1lsy.7.11.2";

/// Fixed-point millionths unit.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum queue depth before shedding.
pub const DEFAULT_MAX_QUEUE_DEPTH: u64 = 1024;

/// Default target utilization (80%).
pub const DEFAULT_TARGET_UTILIZATION_MILLIONTHS: u64 = 800_000;

/// Default burst token capacity.
pub const DEFAULT_BURST_CAPACITY: u64 = 128;

/// Default token refill rate per epoch-tick.
pub const DEFAULT_REFILL_RATE: u64 = 64;

// ---------------------------------------------------------------------------
// Admission priority
// ---------------------------------------------------------------------------

/// Priority class for incoming work items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionPriority {
    /// System-critical: GC, security epoch rotation, etc.
    Critical,
    /// High: user-visible latency-sensitive paths.
    High,
    /// Normal: standard request processing.
    Normal,
    /// Low: background compilation, prefetch, cache warming.
    Low,
    /// BestEffort: deferrable work that can be dropped under load.
    BestEffort,
}

impl AdmissionPriority {
    /// Numeric rank for ordering (lower = higher priority).
    pub fn rank(self) -> u32 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
            Self::BestEffort => 4,
        }
    }

    /// Minimum priority that is never shed under overload.
    pub fn is_unshedable(self) -> bool {
        matches!(self, Self::Critical)
    }
}

impl fmt::Display for AdmissionPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
            Self::BestEffort => "best_effort",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Admission decision
// ---------------------------------------------------------------------------

/// Outcome of an admission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    /// Admitted: work can proceed.
    Admit,
    /// Queued: work is accepted but must wait.
    Queue {
        /// Estimated wait time in nanoseconds.
        estimated_wait_ns: u64,
        /// Queue position.
        position: u64,
    },
    /// Shed: work is rejected under overload.
    Shed {
        /// Reason for shedding.
        reason: ShedReason,
    },
}

impl fmt::Display for AdmissionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admit => write!(f, "admit"),
            Self::Queue { position, .. } => write!(f, "queue(pos={position})"),
            Self::Shed { reason } => write!(f, "shed({reason})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shed reason
// ---------------------------------------------------------------------------

/// Why a work item was shed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedReason {
    /// Queue is full.
    QueueFull { current_depth: u64, max_depth: u64 },
    /// Token bucket exhausted.
    TokensExhausted {
        tokens_available: u64,
        tokens_required: u64,
    },
    /// Utilization exceeds shed threshold.
    UtilizationOverload {
        current_utilization_millionths: u64,
        shed_threshold_millionths: u64,
    },
    /// Priority too low for current load level.
    PriorityShed {
        item_priority: AdmissionPriority,
        min_admitted_priority: AdmissionPriority,
    },
    /// Stage-specific budget exhausted.
    StageBudgetExhausted {
        stage: ExecutionStage,
        stage_queue_depth: u64,
        stage_max_depth: u64,
    },
}

impl fmt::Display for ShedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull {
                current_depth,
                max_depth,
            } => write!(f, "queue_full({current_depth}/{max_depth})"),
            Self::TokensExhausted {
                tokens_available,
                tokens_required,
            } => write!(f, "tokens_exhausted({tokens_available}/{tokens_required})"),
            Self::UtilizationOverload {
                current_utilization_millionths,
                ..
            } => write!(
                f,
                "utilization_overload({current_utilization_millionths}/1M)"
            ),
            Self::PriorityShed {
                item_priority,
                min_admitted_priority,
            } => write!(f, "priority_shed({item_priority}<{min_admitted_priority})"),
            Self::StageBudgetExhausted {
                stage,
                stage_queue_depth,
                stage_max_depth,
            } => write!(
                f,
                "stage_exhausted({stage}:{stage_queue_depth}/{stage_max_depth})"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// Deterministic token-bucket rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity).
    pub capacity: u64,
    /// Current available tokens.
    pub available: u64,
    /// Tokens added per refill tick.
    pub refill_rate: u64,
    /// Total tokens consumed since creation.
    pub total_consumed: u64,
    /// Total refills applied.
    pub total_refills: u64,
}

impl TokenBucket {
    /// Create a full bucket.
    pub fn new(capacity: u64, refill_rate: u64) -> Self {
        Self {
            capacity,
            available: capacity,
            refill_rate,
            total_consumed: 0,
            total_refills: 0,
        }
    }

    /// Try to consume `count` tokens. Returns true if successful.
    pub fn try_consume(&mut self, count: u64) -> bool {
        if self.available >= count {
            self.available -= count;
            self.total_consumed += count;
            true
        } else {
            false
        }
    }

    /// Refill the bucket by one tick.
    pub fn refill(&mut self) {
        self.available = self
            .available
            .saturating_add(self.refill_rate)
            .min(self.capacity);
        self.total_refills += 1;
    }

    /// Current fill ratio in millionths.
    pub fn fill_ratio_millionths(&self) -> u64 {
        if self.capacity == 0 {
            return 0;
        }
        self.available
            .saturating_mul(MILLIONTHS)
            .checked_div(self.capacity)
            .unwrap_or(0)
    }

    /// Whether the bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.available == 0
    }
}

// ---------------------------------------------------------------------------
// Queue partition
// ---------------------------------------------------------------------------

/// Per-stage queue partition tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuePartition {
    /// Stage this partition belongs to.
    pub stage: ExecutionStage,
    /// Current queue depth for this stage.
    pub current_depth: u64,
    /// Maximum queue depth for this stage.
    pub max_depth: u64,
    /// Total items admitted to this partition.
    pub total_admitted: u64,
    /// Total items shed from this partition.
    pub total_shed: u64,
    /// Total items completed from this partition.
    pub total_completed: u64,
}

impl QueuePartition {
    /// Create a new partition.
    pub fn new(stage: ExecutionStage, max_depth: u64) -> Self {
        Self {
            stage,
            current_depth: 0,
            max_depth,
            total_admitted: 0,
            total_shed: 0,
            total_completed: 0,
        }
    }

    /// Whether the partition is at capacity.
    pub fn is_full(&self) -> bool {
        self.current_depth >= self.max_depth
    }

    /// Admit an item.
    pub fn admit(&mut self) {
        self.current_depth += 1;
        self.total_admitted += 1;
    }

    /// Complete an item (dequeue).
    pub fn complete(&mut self) {
        self.current_depth = self.current_depth.saturating_sub(1);
        self.total_completed += 1;
    }

    /// Record a shed.
    pub fn record_shed(&mut self) {
        self.total_shed += 1;
    }

    /// Utilization ratio in millionths.
    pub fn utilization_millionths(&self) -> u64 {
        if self.max_depth == 0 {
            return 0;
        }
        self.current_depth
            .saturating_mul(MILLIONTHS)
            .checked_div(self.max_depth)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Worker pool sizing
// ---------------------------------------------------------------------------

/// Worker pool configuration derived from queueing analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPoolSizing {
    /// Recommended number of workers.
    pub recommended_workers: u64,
    /// Minimum workers for SLO compliance.
    pub min_workers_for_slo: u64,
    /// Maximum useful workers (beyond which utilization drops below threshold).
    pub max_useful_workers: u64,
    /// Estimated steady-state utilization in millionths with recommended workers.
    pub estimated_utilization_millionths: u64,
    /// Target p99 latency in nanoseconds.
    pub target_p99_ns: u64,
    /// Estimated p99 wait time with recommended workers.
    pub estimated_p99_wait_ns: u64,
    /// The arrival rate (items/epoch-tick) used for this sizing.
    pub arrival_rate_millionths: u64,
    /// The mean service time in nanoseconds.
    pub mean_service_ns: u64,
}

/// Input for worker pool sizing computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizingInput {
    /// Mean arrival rate in items per epoch-tick (millionths).
    pub arrival_rate_millionths: u64,
    /// Mean service time per item in nanoseconds.
    pub mean_service_ns: u64,
    /// Target p99 latency SLO in nanoseconds.
    pub target_p99_ns: u64,
    /// Target utilization in millionths.
    pub target_utilization_millionths: u64,
    /// Maximum workers available.
    pub max_workers: u64,
}

/// Compute recommended worker pool size using M/D/c approximation.
///
/// Uses the Kingman/Allen-Cunneen approximation for M/D/c queues:
/// - Traffic intensity ρ = λ / (c * µ)
/// - Mean wait ≈ (C²_a + C²_s) / 2 * ρ / (1-ρ) * mean_service / c
///   where C²_s = 0 for deterministic service (M/D/c).
pub fn compute_worker_pool_sizing(input: &SizingInput) -> WorkerPoolSizing {
    // Convert arrival rate from millionths to effective rate
    // arrival_rate_millionths / MILLIONTHS gives items per tick
    // We work in millionths throughout for determinism.
    let lambda_m = input.arrival_rate_millionths; // items/tick * 10^6
    let service_ns = input.mean_service_ns.max(1);

    // Find minimum workers where utilization < target
    // ρ = λ * service / (c * tick_duration)
    // For simplicity, we model ρ = lambda_m * service_ns / (c * MILLIONTHS * tick_ns)
    // Since we want utilization in millionths: ρ_m = lambda_m * service_ns / (c * tick_ns)
    // But we don't have tick_ns. Instead, use the ratio directly:
    // Offered load (Erlang) = arrival_rate * service_time
    // In our units: offered_load_m = lambda_m * service_ns / 1_000_000_000
    // (normalizing ns to seconds conceptually, but we keep it all relative)

    // Simpler approach: offered load in abstract units
    let offered_load = lambda_m.saturating_mul(service_ns);

    let mut best_c = 1u64;
    let mut best_util = MILLIONTHS; // start at 100%

    for c in 1..=input.max_workers.max(1) {
        // utilization = offered_load / (c * normalization)
        // We normalize so that at c=1 with lambda_m=1_000_000 and service_ns=1_000_000_000,
        // utilization = 100% (1_000_000)
        let denom = c.saturating_mul(MILLIONTHS).saturating_mul(1_000_000_000);
        let util_m = if denom == 0 {
            MILLIONTHS
        } else {
            offered_load
                .saturating_mul(MILLIONTHS)
                .checked_div(denom)
                .unwrap_or(MILLIONTHS)
        };

        if util_m <= input.target_utilization_millionths {
            best_c = c;
            best_util = util_m;
            break;
        }
        best_c = c;
        best_util = util_m;
    }

    // Minimum workers for SLO: need enough that estimated wait < target_p99
    // Wait approximation for M/D/c: W_q ≈ (ρ^(√(2(c+1)))) / (c(1-ρ)) * service
    // Simplified: as c increases, wait drops. Find smallest c where wait fits.
    let min_c = find_min_workers_for_slo(
        offered_load,
        service_ns,
        input.target_p99_ns,
        input.max_workers,
    );

    // Max useful: workers beyond which utilization drops below 10%
    let max_useful = find_max_useful_workers(offered_load, input.max_workers);

    let recommended = best_c.max(min_c);
    let estimated_wait = estimate_p99_wait(offered_load, service_ns, recommended);

    WorkerPoolSizing {
        recommended_workers: recommended,
        min_workers_for_slo: min_c,
        max_useful_workers: max_useful,
        estimated_utilization_millionths: best_util,
        target_p99_ns: input.target_p99_ns,
        estimated_p99_wait_ns: estimated_wait,
        arrival_rate_millionths: input.arrival_rate_millionths,
        mean_service_ns: service_ns,
    }
}

fn find_min_workers_for_slo(
    offered_load: u64,
    service_ns: u64,
    target_p99_ns: u64,
    max_workers: u64,
) -> u64 {
    for c in 1..=max_workers.max(1) {
        let wait = estimate_p99_wait(offered_load, service_ns, c);
        if wait <= target_p99_ns {
            return c;
        }
    }
    max_workers.max(1)
}

fn find_max_useful_workers(offered_load: u64, max_workers: u64) -> u64 {
    let min_useful_utilization = 100_000u64; // 10%
    for c in (1..=max_workers.max(1)).rev() {
        let denom = c.saturating_mul(MILLIONTHS).saturating_mul(1_000_000_000);
        let util_m = if denom == 0 {
            0
        } else {
            offered_load
                .saturating_mul(MILLIONTHS)
                .checked_div(denom)
                .unwrap_or(0)
        };
        if util_m >= min_useful_utilization {
            return c;
        }
    }
    1
}

/// Estimate p99 wait time using M/D/c approximation.
fn estimate_p99_wait(offered_load: u64, service_ns: u64, num_workers: u64) -> u64 {
    let c = num_workers.max(1);
    let denom = c.saturating_mul(MILLIONTHS).saturating_mul(1_000_000_000);
    let rho_m = if denom == 0 {
        MILLIONTHS
    } else {
        offered_load
            .saturating_mul(MILLIONTHS)
            .checked_div(denom)
            .unwrap_or(MILLIONTHS)
            .min(MILLIONTHS)
    };

    if rho_m >= MILLIONTHS {
        // System is saturated or oversaturated
        return service_ns.saturating_mul(100); // Very large wait
    }

    // M/D/c mean wait approximation:
    // Wq ≈ ρ / (2 * c * (1-ρ)) * mean_service (for deterministic service)
    // P99 ≈ Wq * ln(100) ≈ Wq * 4.6
    let one_minus_rho = MILLIONTHS.saturating_sub(rho_m);
    if one_minus_rho == 0 {
        return service_ns.saturating_mul(100);
    }

    // mean_wait = rho * service / (2 * c * (1 - rho))
    // In millionths: rho_m * service_ns / (2 * c * one_minus_rho_m / MILLIONTHS)
    let numerator = rho_m.saturating_mul(service_ns);
    let denominator = 2u64
        .saturating_mul(c)
        .saturating_mul(one_minus_rho)
        .checked_div(MILLIONTHS)
        .unwrap_or(1)
        .max(1);

    let mean_wait = numerator.checked_div(denominator).unwrap_or(0);

    // p99 ≈ mean_wait * 4.6 ≈ mean_wait * 46 / 10
    mean_wait.saturating_mul(46).checked_div(10).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Admission control policy
// ---------------------------------------------------------------------------

/// Configuration for the admission controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionControlPolicy {
    /// Global maximum queue depth.
    pub max_queue_depth: u64,
    /// Per-stage maximum queue depths.
    pub stage_max_depths: BTreeMap<ExecutionStage, u64>,
    /// Target utilization in millionths.
    pub target_utilization_millionths: u64,
    /// Shed threshold in millionths (above this, start shedding low-priority).
    pub shed_threshold_millionths: u64,
    /// Emergency shed threshold (shed everything except Critical).
    pub emergency_threshold_millionths: u64,
    /// Token bucket capacity.
    pub token_capacity: u64,
    /// Token refill rate.
    pub token_refill_rate: u64,
    /// Tokens consumed per admission.
    pub tokens_per_admission: u64,
    /// Percentile target for SLO compliance.
    pub slo_percentile: LatencyPercentile,
    /// Target latency SLO in nanoseconds.
    pub slo_target_ns: u64,
    /// Maximum receipts to retain.
    pub max_receipts: usize,
}

impl Default for AdmissionControlPolicy {
    fn default() -> Self {
        Self {
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            stage_max_depths: BTreeMap::new(),
            target_utilization_millionths: DEFAULT_TARGET_UTILIZATION_MILLIONTHS,
            shed_threshold_millionths: 900_000,      // 90%
            emergency_threshold_millionths: 950_000, // 95%
            token_capacity: DEFAULT_BURST_CAPACITY,
            token_refill_rate: DEFAULT_REFILL_RATE,
            tokens_per_admission: 1,
            slo_percentile: LatencyPercentile::P99,
            slo_target_ns: 10_000_000, // 10ms
            max_receipts: 1024,
        }
    }
}

impl AdmissionControlPolicy {
    /// Content hash for audit.
    pub fn policy_hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Admission receipt
// ---------------------------------------------------------------------------

/// Content-addressed audit receipt for an admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Decision made.
    pub decision: AdmissionDecision,
    /// Priority of the work item.
    pub priority: AdmissionPriority,
    /// Target stage.
    pub stage: ExecutionStage,
    /// Current global queue depth at decision time.
    pub queue_depth_snapshot: u64,
    /// Current utilization at decision time in millionths.
    pub utilization_snapshot_millionths: u64,
    /// Tokens available at decision time.
    pub tokens_snapshot: u64,
    /// Decision sequence number.
    pub sequence: u64,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl AdmissionReceipt {
    /// Create a new receipt.
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        decision: AdmissionDecision,
        priority: AdmissionPriority,
        stage: ExecutionStage,
        queue_depth: u64,
        utilization_m: u64,
        tokens: u64,
        sequence: u64,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(ADMISSION_SCHEMA_VERSION.as_bytes());
        h.update(sequence.to_le_bytes());
        h.update(format!("{decision}").as_bytes());
        h.update(format!("{priority}").as_bytes());
        h.update(format!("{stage}").as_bytes());
        h.update(queue_depth.to_le_bytes());
        h.update(utilization_m.to_le_bytes());
        let hash_bytes: [u8; 32] = h.finalize().into();
        let content_hash = ContentHash::compute(&hash_bytes);

        Self {
            receipt_id: format!("adm-{sequence:08x}"),
            schema_version: ADMISSION_SCHEMA_VERSION.to_string(),
            decision,
            priority,
            stage,
            queue_depth_snapshot: queue_depth,
            utilization_snapshot_millionths: utilization_m,
            tokens_snapshot: tokens,
            sequence,
            content_hash,
        }
    }
}

impl fmt::Display for AdmissionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Receipt({}: {} for {} at {})",
            self.receipt_id, self.decision, self.priority, self.stage
        )
    }
}

// ---------------------------------------------------------------------------
// Admission summary
// ---------------------------------------------------------------------------

/// Aggregate admission statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionSummary {
    /// Total admission checks.
    pub total_checks: u64,
    /// Total admissions.
    pub total_admitted: u64,
    /// Total queued.
    pub total_queued: u64,
    /// Total shed.
    pub total_shed: u64,
    /// Admission ratio in millionths.
    pub admission_ratio_millionths: u64,
    /// Current global queue depth.
    pub current_queue_depth: u64,
    /// Current utilization in millionths.
    pub current_utilization_millionths: u64,
    /// Number of active partitions.
    pub partition_count: usize,
}

// ---------------------------------------------------------------------------
// Admission controller
// ---------------------------------------------------------------------------

/// Core admission controller implementing queueing-theoretic admission control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionController {
    /// Policy configuration.
    pub policy: AdmissionControlPolicy,
    /// Global token bucket.
    pub token_bucket: TokenBucket,
    /// Per-stage queue partitions.
    pub partitions: BTreeMap<ExecutionStage, QueuePartition>,
    /// Global queue depth.
    pub global_queue_depth: u64,
    /// Current utilization estimate in millionths.
    pub utilization_millionths: u64,
    /// Decision sequence counter.
    pub decision_sequence: u64,
    /// Audit receipts.
    pub receipts: Vec<AdmissionReceipt>,
    /// Total admitted.
    total_admitted: u64,
    /// Total queued.
    total_queued: u64,
    /// Total shed.
    total_shed: u64,
    /// Policy hash for receipts.
    policy_hash: ContentHash,
}

impl AdmissionController {
    /// Create a new controller with the given policy.
    pub fn new(policy: AdmissionControlPolicy) -> Self {
        let token_bucket = TokenBucket::new(policy.token_capacity, policy.token_refill_rate);
        let policy_hash = policy.policy_hash();
        Self {
            policy,
            token_bucket,
            partitions: BTreeMap::new(),
            global_queue_depth: 0,
            utilization_millionths: 0,
            decision_sequence: 0,
            receipts: Vec::new(),
            total_admitted: 0,
            total_queued: 0,
            total_shed: 0,
            policy_hash,
        }
    }

    /// Initialize a stage partition.
    pub fn init_partition(&mut self, stage: ExecutionStage, max_depth: u64) {
        self.partitions
            .entry(stage)
            .or_insert_with(|| QueuePartition::new(stage, max_depth));
    }

    /// Update the utilization estimate (called externally with measured values).
    pub fn update_utilization(&mut self, utilization_millionths: u64) {
        self.utilization_millionths = utilization_millionths.min(MILLIONTHS);
    }

    /// Refill the token bucket (called once per epoch-tick).
    pub fn tick(&mut self) {
        self.token_bucket.refill();
    }

    /// Record a completion (item finished processing).
    pub fn record_completion(&mut self, stage: ExecutionStage) {
        self.global_queue_depth = self.global_queue_depth.saturating_sub(1);
        if let Some(partition) = self.partitions.get_mut(&stage) {
            partition.complete();
        }
    }

    /// Check admission for a work item.
    pub fn check_admission(
        &mut self,
        stage: ExecutionStage,
        priority: AdmissionPriority,
    ) -> AdmissionReceipt {
        let decision = self.compute_decision(stage, priority);

        // Update counters
        match &decision {
            AdmissionDecision::Admit => {
                self.total_admitted += 1;
                self.global_queue_depth += 1;
                self.token_bucket
                    .try_consume(self.policy.tokens_per_admission);
                if let Some(partition) = self.partitions.get_mut(&stage) {
                    partition.admit();
                }
            }
            AdmissionDecision::Queue { .. } => {
                self.total_queued += 1;
                self.global_queue_depth += 1;
                self.token_bucket
                    .try_consume(self.policy.tokens_per_admission);
                if let Some(partition) = self.partitions.get_mut(&stage) {
                    partition.admit();
                }
            }
            AdmissionDecision::Shed { .. } => {
                self.total_shed += 1;
                if let Some(partition) = self.partitions.get_mut(&stage) {
                    partition.record_shed();
                }
            }
        }

        self.decision_sequence += 1;
        let receipt = AdmissionReceipt::from_parts(
            decision,
            priority,
            stage,
            self.global_queue_depth,
            self.utilization_millionths,
            self.token_bucket.available,
            self.decision_sequence,
        );

        if self.receipts.len() >= self.policy.max_receipts {
            self.receipts.remove(0);
        }
        self.receipts.push(receipt.clone());
        receipt
    }

    /// Compute the admission decision without side effects.
    fn compute_decision(
        &self,
        stage: ExecutionStage,
        priority: AdmissionPriority,
    ) -> AdmissionDecision {
        // Critical items always admitted
        if priority.is_unshedable() {
            return if self.global_queue_depth > 0 {
                AdmissionDecision::Queue {
                    estimated_wait_ns: self.estimate_wait_ns(),
                    position: self.global_queue_depth,
                }
            } else {
                AdmissionDecision::Admit
            };
        }

        // Check emergency threshold: shed everything except Critical
        if self.utilization_millionths >= self.policy.emergency_threshold_millionths {
            return AdmissionDecision::Shed {
                reason: ShedReason::UtilizationOverload {
                    current_utilization_millionths: self.utilization_millionths,
                    shed_threshold_millionths: self.policy.emergency_threshold_millionths,
                },
            };
        }

        // Check global queue depth
        if self.global_queue_depth >= self.policy.max_queue_depth {
            return AdmissionDecision::Shed {
                reason: ShedReason::QueueFull {
                    current_depth: self.global_queue_depth,
                    max_depth: self.policy.max_queue_depth,
                },
            };
        }

        // Check stage-specific queue depth
        if let Some(partition) = self.partitions.get(&stage)
            && partition.is_full()
        {
            return AdmissionDecision::Shed {
                reason: ShedReason::StageBudgetExhausted {
                    stage,
                    stage_queue_depth: partition.current_depth,
                    stage_max_depth: partition.max_depth,
                },
            };
        }

        // Check token bucket
        if self.token_bucket.available < self.policy.tokens_per_admission {
            return AdmissionDecision::Shed {
                reason: ShedReason::TokensExhausted {
                    tokens_available: self.token_bucket.available,
                    tokens_required: self.policy.tokens_per_admission,
                },
            };
        }

        // Check shed threshold with priority-aware shedding
        if self.utilization_millionths >= self.policy.shed_threshold_millionths {
            let min_admitted = self.min_priority_for_load();
            if priority.rank() > min_admitted.rank() {
                return AdmissionDecision::Shed {
                    reason: ShedReason::PriorityShed {
                        item_priority: priority,
                        min_admitted_priority: min_admitted,
                    },
                };
            }
        }

        // Admitted but possibly queued
        if self.global_queue_depth > 0 {
            AdmissionDecision::Queue {
                estimated_wait_ns: self.estimate_wait_ns(),
                position: self.global_queue_depth,
            }
        } else {
            AdmissionDecision::Admit
        }
    }

    /// Determine the minimum priority admitted at current load.
    fn min_priority_for_load(&self) -> AdmissionPriority {
        if self.utilization_millionths >= self.policy.emergency_threshold_millionths {
            AdmissionPriority::Critical
        } else if self.utilization_millionths >= self.policy.shed_threshold_millionths {
            // Shed BestEffort and Low at high utilization
            AdmissionPriority::Normal
        } else {
            AdmissionPriority::BestEffort
        }
    }

    /// Rough wait estimate based on queue depth and target SLO.
    fn estimate_wait_ns(&self) -> u64 {
        // Simple estimate: queue_depth * target_slo / max_queue_depth
        // This gives a proportional estimate
        if self.policy.max_queue_depth == 0 {
            return 0;
        }
        self.global_queue_depth
            .saturating_mul(self.policy.slo_target_ns)
            .checked_div(self.policy.max_queue_depth)
            .unwrap_or(0)
    }

    /// Get admission summary statistics.
    pub fn summary(&self) -> AdmissionSummary {
        let total_checks = self.total_admitted + self.total_queued + self.total_shed;
        let admission_ratio = if total_checks == 0 {
            MILLIONTHS
        } else {
            self.total_admitted
                .saturating_add(self.total_queued)
                .saturating_mul(MILLIONTHS)
                .checked_div(total_checks)
                .unwrap_or(0)
        };

        AdmissionSummary {
            total_checks,
            total_admitted: self.total_admitted,
            total_queued: self.total_queued,
            total_shed: self.total_shed,
            admission_ratio_millionths: admission_ratio,
            current_queue_depth: self.global_queue_depth,
            current_utilization_millionths: self.utilization_millionths,
            partition_count: self.partitions.len(),
        }
    }

    /// Get all receipts.
    pub fn receipts(&self) -> &[AdmissionReceipt] {
        &self.receipts
    }

    /// Get the decision sequence.
    pub fn decision_sequence(&self) -> u64 {
        self.decision_sequence
    }

    /// Get the policy hash.
    pub fn policy_hash(&self) -> &ContentHash {
        &self.policy_hash
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Top-level container for admission control state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionControlManifest {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Policy configuration.
    pub policy: AdmissionControlPolicy,
    /// Summary statistics.
    pub summary: AdmissionSummary,
    /// Worker pool sizing recommendation.
    pub sizing: Option<WorkerPoolSizing>,
    /// Per-stage partition states.
    pub partitions: Vec<QueuePartition>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl AdmissionControlManifest {
    /// Create from a controller.
    pub fn from_controller(controller: &AdmissionController) -> Self {
        let summary = controller.summary();
        let partitions: Vec<QueuePartition> = controller.partitions.values().cloned().collect();

        let mut h = Sha256::new();
        h.update(ADMISSION_SCHEMA_VERSION.as_bytes());
        h.update(ADMISSION_BEAD_ID.as_bytes());
        let summary_bytes = serde_json::to_vec(&summary).unwrap_or_default();
        h.update(&summary_bytes);
        let hash_bytes: [u8; 32] = h.finalize().into();

        Self {
            schema_version: ADMISSION_SCHEMA_VERSION.to_string(),
            bead_id: ADMISSION_BEAD_ID.to_string(),
            policy: controller.policy.clone(),
            summary,
            sizing: None,
            partitions,
            content_hash: ContentHash::compute(&hash_bytes),
        }
    }

    /// Attach sizing recommendation.
    pub fn with_sizing(mut self, sizing: WorkerPoolSizing) -> Self {
        self.sizing = Some(sizing);
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy() -> AdmissionControlPolicy {
        AdmissionControlPolicy::default()
    }

    fn make_controller() -> AdmissionController {
        AdmissionController::new(make_policy())
    }

    // --- Priority tests ---

    #[test]
    fn test_priority_ordering() {
        assert!(AdmissionPriority::Critical.rank() < AdmissionPriority::High.rank());
        assert!(AdmissionPriority::High.rank() < AdmissionPriority::Normal.rank());
        assert!(AdmissionPriority::Normal.rank() < AdmissionPriority::Low.rank());
        assert!(AdmissionPriority::Low.rank() < AdmissionPriority::BestEffort.rank());
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(format!("{}", AdmissionPriority::Critical), "critical");
        assert_eq!(format!("{}", AdmissionPriority::BestEffort), "best_effort");
    }

    #[test]
    fn test_critical_unshedable() {
        assert!(AdmissionPriority::Critical.is_unshedable());
        assert!(!AdmissionPriority::High.is_unshedable());
        assert!(!AdmissionPriority::Normal.is_unshedable());
        assert!(!AdmissionPriority::Low.is_unshedable());
        assert!(!AdmissionPriority::BestEffort.is_unshedable());
    }

    // --- Token bucket tests ---

    #[test]
    fn test_token_bucket_new() {
        let tb = TokenBucket::new(100, 10);
        assert_eq!(tb.capacity, 100);
        assert_eq!(tb.available, 100);
        assert_eq!(tb.refill_rate, 10);
        assert_eq!(tb.total_consumed, 0);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut tb = TokenBucket::new(100, 10);
        assert!(tb.try_consume(50));
        assert_eq!(tb.available, 50);
        assert_eq!(tb.total_consumed, 50);
    }

    #[test]
    fn test_token_bucket_consume_fail() {
        let mut tb = TokenBucket::new(10, 5);
        assert!(!tb.try_consume(11));
        assert_eq!(tb.available, 10);
        assert_eq!(tb.total_consumed, 0);
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut tb = TokenBucket::new(100, 10);
        tb.try_consume(100);
        assert!(tb.is_empty());
        tb.refill();
        assert_eq!(tb.available, 10);
        tb.refill();
        assert_eq!(tb.available, 20);
    }

    #[test]
    fn test_token_bucket_refill_cap() {
        let mut tb = TokenBucket::new(100, 50);
        tb.try_consume(20);
        tb.refill();
        assert_eq!(tb.available, 100); // capped at capacity
    }

    #[test]
    fn test_token_bucket_fill_ratio() {
        let tb = TokenBucket::new(100, 10);
        assert_eq!(tb.fill_ratio_millionths(), 1_000_000);
        let mut tb2 = TokenBucket::new(100, 10);
        tb2.try_consume(50);
        assert_eq!(tb2.fill_ratio_millionths(), 500_000);
    }

    #[test]
    fn test_token_bucket_fill_ratio_zero_capacity() {
        let tb = TokenBucket::new(0, 0);
        assert_eq!(tb.fill_ratio_millionths(), 0);
    }

    // --- Queue partition tests ---

    #[test]
    fn test_partition_new() {
        let p = QueuePartition::new(ExecutionStage::Parse, 64);
        assert_eq!(p.stage, ExecutionStage::Parse);
        assert_eq!(p.max_depth, 64);
        assert_eq!(p.current_depth, 0);
        assert!(!p.is_full());
    }

    #[test]
    fn test_partition_admit_complete() {
        let mut p = QueuePartition::new(ExecutionStage::GcPause, 10);
        p.admit();
        assert_eq!(p.current_depth, 1);
        assert_eq!(p.total_admitted, 1);
        p.complete();
        assert_eq!(p.current_depth, 0);
        assert_eq!(p.total_completed, 1);
    }

    #[test]
    fn test_partition_full() {
        let mut p = QueuePartition::new(ExecutionStage::ModuleLoad, 2);
        p.admit();
        p.admit();
        assert!(p.is_full());
    }

    #[test]
    fn test_partition_utilization() {
        let mut p = QueuePartition::new(ExecutionStage::Parse, 4);
        p.admit();
        assert_eq!(p.utilization_millionths(), 250_000); // 25%
        p.admit();
        assert_eq!(p.utilization_millionths(), 500_000); // 50%
    }

    #[test]
    fn test_partition_zero_max_utilization() {
        let p = QueuePartition::new(ExecutionStage::Custom, 0);
        assert_eq!(p.utilization_millionths(), 0);
    }

    // --- Default policy tests ---

    #[test]
    fn test_default_policy() {
        let p = AdmissionControlPolicy::default();
        assert_eq!(p.max_queue_depth, DEFAULT_MAX_QUEUE_DEPTH);
        assert_eq!(
            p.target_utilization_millionths,
            DEFAULT_TARGET_UTILIZATION_MILLIONTHS
        );
        assert_eq!(p.shed_threshold_millionths, 900_000);
        assert_eq!(p.emergency_threshold_millionths, 950_000);
        assert_eq!(p.token_capacity, DEFAULT_BURST_CAPACITY);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = AdmissionControlPolicy::default();
        let p2 = AdmissionControlPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn test_policy_hash_varies() {
        let p1 = AdmissionControlPolicy::default();
        let p2 = AdmissionControlPolicy {
            max_queue_depth: 512,
            ..Default::default()
        };
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    // --- Admission controller tests ---

    #[test]
    fn test_admit_empty_queue() {
        let mut ctrl = make_controller();
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert_eq!(receipt.decision, AdmissionDecision::Admit);
        assert_eq!(receipt.sequence, 1);
    }

    #[test]
    fn test_queued_when_depth_nonzero() {
        let mut ctrl = make_controller();
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(matches!(receipt.decision, AdmissionDecision::Queue { .. }));
    }

    #[test]
    fn test_shed_queue_full() {
        let mut policy = make_policy();
        policy.max_queue_depth = 2;
        let mut ctrl = AdmissionController::new(policy);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::QueueFull { .. }
            }
        ));
    }

    #[test]
    fn test_shed_tokens_exhausted() {
        let mut policy = make_policy();
        policy.token_capacity = 2;
        policy.token_refill_rate = 0;
        policy.tokens_per_admission = 1;
        let mut ctrl = AdmissionController::new(policy);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        // Drain items so queue doesn't fill
        ctrl.record_completion(ExecutionStage::Parse);
        ctrl.record_completion(ExecutionStage::Parse);
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::TokensExhausted { .. }
            }
        ));
    }

    #[test]
    fn test_shed_utilization_overload() {
        let mut ctrl = make_controller();
        ctrl.update_utilization(960_000); // 96% > emergency 95%
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::UtilizationOverload { .. }
            }
        ));
    }

    #[test]
    fn test_critical_not_shed_at_emergency() {
        let mut ctrl = make_controller();
        ctrl.update_utilization(960_000); // 96%
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Critical);
        // Critical is unshedable
        assert!(!matches!(receipt.decision, AdmissionDecision::Shed { .. }));
    }

    #[test]
    fn test_priority_shedding() {
        let mut ctrl = make_controller();
        ctrl.update_utilization(910_000); // 91% — above shed threshold
        let r_normal = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        // Normal should still be admitted at 91%
        assert!(!matches!(r_normal.decision, AdmissionDecision::Shed { .. }));
        let r_low = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Low);
        assert!(matches!(
            r_low.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::PriorityShed { .. }
            }
        ));
    }

    #[test]
    fn test_stage_partition_shedding() {
        let mut ctrl = make_controller();
        ctrl.init_partition(ExecutionStage::ModuleLoad, 1);
        ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
        let receipt = ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
        assert!(matches!(
            receipt.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::StageBudgetExhausted { .. }
            }
        ));
    }

    #[test]
    fn test_tick_refills_tokens() {
        let mut ctrl = make_controller();
        // Exhaust tokens
        for _ in 0..DEFAULT_BURST_CAPACITY {
            ctrl.token_bucket.try_consume(1);
        }
        assert!(ctrl.token_bucket.is_empty());
        ctrl.tick();
        assert_eq!(ctrl.token_bucket.available, DEFAULT_REFILL_RATE);
    }

    #[test]
    fn test_record_completion() {
        let mut ctrl = make_controller();
        ctrl.init_partition(ExecutionStage::Parse, 64);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert_eq!(ctrl.global_queue_depth, 1);
        ctrl.record_completion(ExecutionStage::Parse);
        assert_eq!(ctrl.global_queue_depth, 0);
    }

    #[test]
    fn test_receipt_sequence_monotonic() {
        let mut ctrl = make_controller();
        for _ in 0..5 {
            ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        }
        let receipts = ctrl.receipts();
        for i in 1..receipts.len() {
            assert!(receipts[i].sequence > receipts[i - 1].sequence);
        }
    }

    #[test]
    fn test_receipt_unique_ids() {
        let mut ctrl = make_controller();
        for _ in 0..5 {
            ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        }
        let ids: Vec<&str> = ctrl
            .receipts()
            .iter()
            .map(|r| r.receipt_id.as_str())
            .collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }
    }

    #[test]
    fn test_receipts_bounded() {
        let mut policy = make_policy();
        policy.max_receipts = 3;
        let mut ctrl = AdmissionController::new(policy);
        for _ in 0..10 {
            ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        }
        assert!(ctrl.receipts().len() <= 3);
    }

    #[test]
    fn test_summary_counts() {
        let mut ctrl = make_controller();
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let summary = ctrl.summary();
        assert_eq!(summary.total_checks, 2);
        assert!(summary.total_admitted + summary.total_queued + summary.total_shed == 2);
    }

    #[test]
    fn test_summary_admission_ratio() {
        let mut ctrl = make_controller();
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let summary = ctrl.summary();
        // Should be 100% (all admitted)
        assert_eq!(summary.admission_ratio_millionths, 1_000_000);
    }

    #[test]
    fn test_decision_display() {
        assert_eq!(format!("{}", AdmissionDecision::Admit), "admit");
        let q = AdmissionDecision::Queue {
            estimated_wait_ns: 100,
            position: 5,
        };
        assert!(format!("{q}").contains("5"));
    }

    #[test]
    fn test_shed_reason_display() {
        let r = ShedReason::QueueFull {
            current_depth: 100,
            max_depth: 100,
        };
        assert!(format!("{r}").contains("100"));
    }

    // --- Worker pool sizing tests ---

    #[test]
    fn test_sizing_basic() {
        let input = SizingInput {
            arrival_rate_millionths: 100_000, // 0.1 items/tick
            mean_service_ns: 1_000_000,       // 1ms
            target_p99_ns: 10_000_000,        // 10ms
            target_utilization_millionths: 800_000,
            max_workers: 16,
        };
        let sizing = compute_worker_pool_sizing(&input);
        assert!(sizing.recommended_workers >= 1);
        assert!(sizing.min_workers_for_slo >= 1);
        assert!(sizing.max_useful_workers >= 1);
    }

    #[test]
    fn test_sizing_high_load() {
        let input = SizingInput {
            arrival_rate_millionths: 900_000,
            mean_service_ns: 5_000_000,
            target_p99_ns: 20_000_000,
            target_utilization_millionths: 700_000,
            max_workers: 64,
        };
        let sizing = compute_worker_pool_sizing(&input);
        assert!(sizing.recommended_workers > 1);
    }

    #[test]
    fn test_sizing_zero_arrival() {
        let input = SizingInput {
            arrival_rate_millionths: 0,
            mean_service_ns: 1_000_000,
            target_p99_ns: 10_000_000,
            target_utilization_millionths: 800_000,
            max_workers: 8,
        };
        let sizing = compute_worker_pool_sizing(&input);
        assert_eq!(sizing.recommended_workers, 1);
    }

    // --- Manifest tests ---

    #[test]
    fn test_manifest_from_controller() {
        let mut ctrl = make_controller();
        ctrl.init_partition(ExecutionStage::Parse, 64);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let manifest = AdmissionControlManifest::from_controller(&ctrl);
        assert_eq!(manifest.schema_version, ADMISSION_SCHEMA_VERSION);
        assert_eq!(manifest.bead_id, ADMISSION_BEAD_ID);
        assert_eq!(manifest.summary.total_checks, 1);
        assert_eq!(manifest.partitions.len(), 1);
    }

    #[test]
    fn test_manifest_with_sizing() {
        let ctrl = make_controller();
        let manifest = AdmissionControlManifest::from_controller(&ctrl);
        assert!(manifest.sizing.is_none());
        let sizing = WorkerPoolSizing {
            recommended_workers: 4,
            min_workers_for_slo: 2,
            max_useful_workers: 8,
            estimated_utilization_millionths: 500_000,
            target_p99_ns: 10_000_000,
            estimated_p99_wait_ns: 2_000_000,
            arrival_rate_millionths: 100_000,
            mean_service_ns: 1_000_000,
        };
        let manifest = manifest.with_sizing(sizing);
        assert!(manifest.sizing.is_some());
    }

    // --- Serde tests ---

    #[test]
    fn test_serde_round_trip_policy() {
        let policy = make_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: AdmissionControlPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn test_serde_round_trip_receipt() {
        let mut ctrl = make_controller();
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let receipt = &ctrl.receipts()[0];
        let json = serde_json::to_string(receipt).unwrap();
        let restored: AdmissionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, &restored);
    }

    #[test]
    fn test_serde_round_trip_manifest() {
        let ctrl = make_controller();
        let manifest = AdmissionControlManifest::from_controller(&ctrl);
        let json = serde_json::to_string(&manifest).unwrap();
        let restored: AdmissionControlManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, restored);
    }

    #[test]
    fn test_serde_round_trip_token_bucket() {
        let tb = TokenBucket::new(100, 10);
        let json = serde_json::to_string(&tb).unwrap();
        let restored: TokenBucket = serde_json::from_str(&json).unwrap();
        assert_eq!(tb, restored);
    }

    #[test]
    fn test_receipt_display() {
        let mut ctrl = make_controller();
        let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        let display = format!("{receipt}");
        assert!(display.contains("adm-"));
    }

    #[test]
    fn test_partition_shed_counted() {
        let mut ctrl = make_controller();
        ctrl.init_partition(ExecutionStage::ModuleLoad, 1);
        ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
        ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
        let partition = ctrl.partitions.get(&ExecutionStage::ModuleLoad).unwrap();
        assert_eq!(partition.total_shed, 1);
    }

    #[test]
    fn test_multiple_stages_independent() {
        let mut ctrl = make_controller();
        ctrl.init_partition(ExecutionStage::Parse, 2);
        ctrl.init_partition(ExecutionStage::GcPause, 2);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        // Parse is full, but GC should still work
        let gc = ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);
        // GC should not be shed by parse stage limit
        assert!(!matches!(
            gc.decision,
            AdmissionDecision::Shed {
                reason: ShedReason::StageBudgetExhausted { .. }
            }
        ));
    }
}
