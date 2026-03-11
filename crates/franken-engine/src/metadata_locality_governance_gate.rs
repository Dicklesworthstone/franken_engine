#![forbid(unsafe_code)]

//! Locality, NUMA, and portability governance gate for runtime metadata substrates.
//!
//! Bead: bd-1lsy.7.26.3 \[RGC-626C\]
//!
//! Gates runtime metadata substrates on cache-miss, NUMA, portability, and
//! observability-mode evidence so locality wins do not turn into
//! machine-specific or instrumentation-free delusions.
//!
//! # Design
//!
//! - `evaluate_cache_locality` checks L1/L2/L3/TLB miss rates against
//!   configurable thresholds.
//! - `evaluate_numa` checks local-access fraction and latency penalty.
//! - `evaluate_portability` checks transferable fraction across topologies.
//! - `evaluate` combines all evidence dimensions into a single `GateResult`
//!   with blocking reasons, recommendations, and a content-addressed receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: \[RGC-626C\]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for this module.
pub const SCHEMA_VERSION: &str = "franken-engine.metadata-locality-governance-gate.v1";

/// Component name.
pub const COMPONENT: &str = "metadata_locality_governance_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.26.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-626C";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum L1 miss rate (millionths). 5% = 50_000.
pub const DEFAULT_MAX_L1_MISS_RATE: u64 = 50_000;

/// Default maximum L2 miss rate (millionths). 10% = 100_000.
pub const DEFAULT_MAX_L2_MISS_RATE: u64 = 100_000;

/// Default maximum L3 miss rate (millionths). 20% = 200_000.
pub const DEFAULT_MAX_L3_MISS_RATE: u64 = 200_000;

/// Default maximum TLB miss rate (millionths). 2% = 20_000.
pub const DEFAULT_MAX_TLB_MISS_RATE: u64 = 20_000;

/// Default minimum local-access fraction for NUMA (millionths). 80% = 800_000.
pub const DEFAULT_MIN_LOCAL_ACCESS_FRACTION: u64 = 800_000;

/// Default maximum observability overhead (millionths). 5% = 50_000.
pub const DEFAULT_MAX_OBSERVABILITY_OVERHEAD: u64 = 50_000;

/// Default minimum portability fraction (millionths). 70% = 700_000.
pub const DEFAULT_MIN_PORTABILITY_FRACTION: u64 = 700_000;

/// Minimum sample count for cache evidence to be considered valid.
pub const MIN_SAMPLE_COUNT: u64 = 10;

/// Conditional threshold multiplier. Miss rates between max and 1.5x max are
/// conditionally approved.
const CONDITIONAL_MULTIPLIER: u64 = 1_500_000; // 1.5 in millionths

// ---------------------------------------------------------------------------
// LocalityDomain
// ---------------------------------------------------------------------------

/// Locality domain indicating the hardware distance of a metadata access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalityDomain {
    /// Cache-line resident — fastest access.
    CacheLine,
    /// TLB-covered page — one extra translation step.
    TlbPage,
    /// Same NUMA node — local memory.
    NumaNode,
    /// Same CPU socket — may cross NUMA boundary.
    SocketLocal,
    /// Across sockets — significant latency.
    CrossSocket,
    /// Remote (disaggregated) memory — highest latency.
    RemoteMemory,
}

impl LocalityDomain {
    /// All variants for iteration.
    pub const ALL: &[Self] = &[
        Self::CacheLine,
        Self::TlbPage,
        Self::NumaNode,
        Self::SocketLocal,
        Self::CrossSocket,
        Self::RemoteMemory,
    ];

    /// Human-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CacheLine => "cache_line",
            Self::TlbPage => "tlb_page",
            Self::NumaNode => "numa_node",
            Self::SocketLocal => "socket_local",
            Self::CrossSocket => "cross_socket",
            Self::RemoteMemory => "remote_memory",
        }
    }

    /// Relative latency weight in millionths (higher = slower).
    pub const fn latency_weight(self) -> u64 {
        match self {
            Self::CacheLine => 10_000,
            Self::TlbPage => 50_000,
            Self::NumaNode => 200_000,
            Self::SocketLocal => 400_000,
            Self::CrossSocket => 700_000,
            Self::RemoteMemory => 1_000_000,
        }
    }
}

impl fmt::Display for LocalityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PortabilityVerdict
// ---------------------------------------------------------------------------

/// Portability assessment for a metadata substrate across topologies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortabilityVerdict {
    /// Substrate is fully portable across topologies.
    Portable,
    /// Substrate works on target but with degraded performance.
    ConditionallyPortable,
    /// Substrate relies on machine-specific features.
    MachineSpecific,
    /// Insufficient evidence to determine portability.
    Unknown,
}

impl PortabilityVerdict {
    pub const ALL: &[Self] = &[
        Self::Portable,
        Self::ConditionallyPortable,
        Self::MachineSpecific,
        Self::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::ConditionallyPortable => "conditionally_portable",
            Self::MachineSpecific => "machine_specific",
            Self::Unknown => "unknown",
        }
    }

    /// Whether deployment is permitted without additional review.
    pub fn permits_deployment(self) -> bool {
        matches!(self, Self::Portable | Self::ConditionallyPortable)
    }
}

impl fmt::Display for PortabilityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceDecision
// ---------------------------------------------------------------------------

/// Gate decision for a metadata substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDecision {
    /// Substrate passes all gates — deploy freely.
    Approve,
    /// Substrate passes with caveats — deploy with monitoring.
    ConditionalApprove,
    /// Substrate fails one or more gates — do not deploy.
    Reject,
    /// Insufficient evidence — gather more data before deciding.
    RequireEvidence,
}

impl GovernanceDecision {
    pub const ALL: &[Self] = &[
        Self::Approve,
        Self::ConditionalApprove,
        Self::Reject,
        Self::RequireEvidence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ConditionalApprove => "conditional_approve",
            Self::Reject => "reject",
            Self::RequireEvidence => "require_evidence",
        }
    }

    /// Whether this decision allows deployment.
    pub fn allows_deployment(self) -> bool {
        matches!(self, Self::Approve | Self::ConditionalApprove)
    }
}

impl fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NumaPolicy
// ---------------------------------------------------------------------------

/// NUMA memory allocation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPolicy {
    /// Pages allocated on first access — workload-dependent locality.
    FirstTouch,
    /// Pages interleaved across NUMA nodes — best for bandwidth.
    Interleave,
    /// Pages bound to a specific NUMA node.
    Bind,
    /// Preferred node but fallback allowed.
    Preferred,
}

impl NumaPolicy {
    pub const ALL: &[Self] = &[
        Self::FirstTouch,
        Self::Interleave,
        Self::Bind,
        Self::Preferred,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstTouch => "first_touch",
            Self::Interleave => "interleave",
            Self::Bind => "bind",
            Self::Preferred => "preferred",
        }
    }
}

impl fmt::Display for NumaPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CacheMissEvidence
// ---------------------------------------------------------------------------

/// Evidence of cache-miss rates for a metadata substrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMissEvidence {
    /// Domain label identifying the substrate region.
    pub domain: String,
    /// L1 cache miss rate in millionths (0 = never misses, 1_000_000 = always misses).
    pub l1_miss_rate: u64,
    /// L2 cache miss rate in millionths.
    pub l2_miss_rate: u64,
    /// L3 cache miss rate in millionths.
    pub l3_miss_rate: u64,
    /// TLB miss rate in millionths.
    pub tlb_miss_rate: u64,
    /// Number of samples collected for this evidence.
    pub sample_count: u64,
    /// Epoch when the measurement was taken.
    pub epoch: SecurityEpoch,
}

impl CacheMissEvidence {
    /// Create new cache-miss evidence.
    pub fn new(
        domain: impl Into<String>,
        l1_miss_rate: u64,
        l2_miss_rate: u64,
        l3_miss_rate: u64,
        tlb_miss_rate: u64,
        sample_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            domain: domain.into(),
            l1_miss_rate,
            l2_miss_rate,
            l3_miss_rate,
            tlb_miss_rate,
            sample_count,
            epoch,
        }
    }

    /// Whether the sample count is sufficient for statistical validity.
    pub fn has_sufficient_samples(&self) -> bool {
        self.sample_count >= MIN_SAMPLE_COUNT
    }

    /// Compute a content hash of this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"cache_miss_evidence");
        hasher.update(self.domain.as_bytes());
        hasher.update(self.l1_miss_rate.to_le_bytes());
        hasher.update(self.l2_miss_rate.to_le_bytes());
        hasher.update(self.l3_miss_rate.to_le_bytes());
        hasher.update(self.tlb_miss_rate.to_le_bytes());
        hasher.update(self.sample_count.to_le_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    /// Dominant locality domain based on miss rates.
    pub fn dominant_domain(&self) -> LocalityDomain {
        if self.l1_miss_rate == 0 {
            LocalityDomain::CacheLine
        } else if self.l2_miss_rate == 0 {
            LocalityDomain::TlbPage
        } else if self.l3_miss_rate == 0 {
            LocalityDomain::NumaNode
        } else {
            LocalityDomain::CrossSocket
        }
    }
}

impl fmt::Display for CacheMissEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CacheMiss[{}](L1={}, L2={}, L3={}, TLB={}, n={})",
            self.domain,
            self.l1_miss_rate,
            self.l2_miss_rate,
            self.l3_miss_rate,
            self.tlb_miss_rate,
            self.sample_count,
        )
    }
}

// ---------------------------------------------------------------------------
// NumaEvidence
// ---------------------------------------------------------------------------

/// Evidence of NUMA access patterns for a metadata substrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaEvidence {
    /// NUMA node identifier.
    pub node_id: u32,
    /// Fraction of accesses that hit local memory (millionths).
    pub local_access_fraction: u64,
    /// Fraction of accesses that cross sockets (millionths).
    pub cross_socket_fraction: u64,
    /// Bandwidth utilization in millionths of peak.
    pub bandwidth_utilization: u64,
    /// Latency penalty from remote accesses in millionths (relative to local).
    pub latency_penalty: u64,
    /// Epoch when the measurement was taken.
    pub epoch: SecurityEpoch,
}

impl NumaEvidence {
    /// Create new NUMA evidence.
    pub fn new(
        node_id: u32,
        local_access_fraction: u64,
        cross_socket_fraction: u64,
        bandwidth_utilization: u64,
        latency_penalty: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            node_id,
            local_access_fraction,
            cross_socket_fraction,
            bandwidth_utilization,
            latency_penalty,
            epoch,
        }
    }

    /// Compute a content hash of this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"numa_evidence");
        hasher.update(self.node_id.to_le_bytes());
        hasher.update(self.local_access_fraction.to_le_bytes());
        hasher.update(self.cross_socket_fraction.to_le_bytes());
        hasher.update(self.bandwidth_utilization.to_le_bytes());
        hasher.update(self.latency_penalty.to_le_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    /// Whether this node shows healthy locality (local >= threshold).
    pub fn is_local_dominant(&self, threshold: u64) -> bool {
        self.local_access_fraction >= threshold
    }

    /// Effective latency multiplier: 1.0 + penalty fraction (millionths).
    pub fn effective_latency_multiplier(&self) -> u64 {
        MILLIONTHS.saturating_add(self.latency_penalty)
    }
}

impl fmt::Display for NumaEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NUMA[node={}](local={}, cross={}, penalty={})",
            self.node_id,
            self.local_access_fraction,
            self.cross_socket_fraction,
            self.latency_penalty,
        )
    }
}

// ---------------------------------------------------------------------------
// PortabilityEvidence
// ---------------------------------------------------------------------------

/// Evidence of portability across hardware topologies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortabilityEvidence {
    /// Source topology identifier (e.g. "x86_64_epyc_7742").
    pub source_topology: String,
    /// Target topology identifier (e.g. "aarch64_graviton3").
    pub target_topology: String,
    /// Fraction of performance that transfers (millionths).
    pub transferable_fraction: u64,
    /// Factors that cause performance degradation on target.
    pub degradation_factors: Vec<String>,
    /// Epoch when the evidence was gathered.
    pub epoch: SecurityEpoch,
}

impl PortabilityEvidence {
    /// Create new portability evidence.
    pub fn new(
        source_topology: impl Into<String>,
        target_topology: impl Into<String>,
        transferable_fraction: u64,
        degradation_factors: Vec<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            source_topology: source_topology.into(),
            target_topology: target_topology.into(),
            transferable_fraction,
            degradation_factors,
            epoch,
        }
    }

    /// Compute a content hash of this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"portability_evidence");
        hasher.update(self.source_topology.as_bytes());
        hasher.update(self.target_topology.as_bytes());
        hasher.update(self.transferable_fraction.to_le_bytes());
        for factor in &self.degradation_factors {
            hasher.update(factor.as_bytes());
        }
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    /// Whether there are known degradation factors.
    pub fn has_degradation(&self) -> bool {
        !self.degradation_factors.is_empty()
    }

    /// Number of degradation factors.
    pub fn degradation_count(&self) -> usize {
        self.degradation_factors.len()
    }
}

impl fmt::Display for PortabilityEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Portability[{} -> {}](transfer={}, degradation_count={})",
            self.source_topology,
            self.target_topology,
            self.transferable_fraction,
            self.degradation_factors.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// ObservabilityImpact
// ---------------------------------------------------------------------------

/// Impact of instrumentation/observability on metadata substrate performance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityImpact {
    /// Overhead when instrumentation is active (millionths).
    pub instrumented_overhead: u64,
    /// Baseline performance without instrumentation (millionths, typically 0).
    pub uninstrumented_baseline: u64,
    /// Delta between instrumented and uninstrumented (millionths).
    pub delta_fraction: u64,
    /// Whether the delta is within acceptable bounds.
    pub acceptable: bool,
}

impl ObservabilityImpact {
    /// Create new observability impact evidence.
    pub fn new(instrumented_overhead: u64, uninstrumented_baseline: u64, acceptable: bool) -> Self {
        let delta_fraction = instrumented_overhead.saturating_sub(uninstrumented_baseline);
        Self {
            instrumented_overhead,
            uninstrumented_baseline,
            delta_fraction,
            acceptable,
        }
    }

    /// Whether the overhead exceeds the threshold.
    pub fn exceeds_threshold(&self, max_overhead: u64) -> bool {
        self.delta_fraction > max_overhead
    }

    /// Overhead ratio: instrumented / (uninstrumented + 1) in millionths.
    pub fn overhead_ratio(&self) -> u64 {
        let base = if self.uninstrumented_baseline == 0 {
            1
        } else {
            self.uninstrumented_baseline
        };
        self.instrumented_overhead
            .saturating_mul(MILLIONTHS)
            .checked_div(base)
            .unwrap_or(0)
    }
}

impl fmt::Display for ObservabilityImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Observability(overhead={}, baseline={}, delta={}, ok={})",
            self.instrumented_overhead,
            self.uninstrumented_baseline,
            self.delta_fraction,
            self.acceptable,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration thresholds for the locality governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum acceptable L1 cache miss rate (millionths).
    pub max_l1_miss_rate: u64,
    /// Maximum acceptable L2 cache miss rate (millionths).
    pub max_l2_miss_rate: u64,
    /// Maximum acceptable L3 cache miss rate (millionths).
    pub max_l3_miss_rate: u64,
    /// Maximum acceptable TLB miss rate (millionths).
    pub max_tlb_miss_rate: u64,
    /// Minimum local-access fraction for NUMA approval (millionths).
    pub min_local_access_fraction: u64,
    /// Maximum acceptable observability overhead (millionths).
    pub max_observability_overhead: u64,
    /// Minimum portability transferable fraction (millionths).
    pub min_portability_fraction: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_l1_miss_rate: DEFAULT_MAX_L1_MISS_RATE,
            max_l2_miss_rate: DEFAULT_MAX_L2_MISS_RATE,
            max_l3_miss_rate: DEFAULT_MAX_L3_MISS_RATE,
            max_tlb_miss_rate: DEFAULT_MAX_TLB_MISS_RATE,
            min_local_access_fraction: DEFAULT_MIN_LOCAL_ACCESS_FRACTION,
            max_observability_overhead: DEFAULT_MAX_OBSERVABILITY_OVERHEAD,
            min_portability_fraction: DEFAULT_MIN_PORTABILITY_FRACTION,
        }
    }
}

impl fmt::Display for GateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateConfig(L1<={}, L2<={}, L3<={}, TLB<={}, local>={}, obs<={}, port>={})",
            self.max_l1_miss_rate,
            self.max_l2_miss_rate,
            self.max_l3_miss_rate,
            self.max_tlb_miss_rate,
            self.min_local_access_fraction,
            self.max_observability_overhead,
            self.min_portability_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Combined result of the locality governance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall governance decision.
    pub decision: GovernanceDecision,
    /// Assessed locality domain based on cache evidence.
    pub locality_verdict: LocalityDomain,
    /// Assessed portability verdict.
    pub portability_verdict: PortabilityVerdict,
    /// Reasons that block or degrade the decision.
    pub blocking_reasons: Vec<String>,
    /// Recommendations for improvement.
    pub recommendations: Vec<String>,
    /// Content-addressed receipt hash.
    pub receipt_hash: ContentHash,
}

impl GateResult {
    /// Whether the substrate is approved for deployment.
    pub fn is_approved(&self) -> bool {
        self.decision.allows_deployment()
    }

    /// Number of blocking reasons.
    pub fn blocking_count(&self) -> usize {
        self.blocking_reasons.len()
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateResult({}, locality={}, portability={}, blocks={})",
            self.decision,
            self.locality_verdict,
            self.portability_verdict,
            self.blocking_reasons.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Content-addressed receipt of a governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of the receipt.
    pub receipt_hash: ContentHash,
    /// Component that issued the receipt.
    pub component: String,
    /// Epoch of the decision.
    pub epoch: SecurityEpoch,
    /// The decision rendered.
    pub decision: GovernanceDecision,
    /// Hash of the combined evidence.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new decision receipt.
    pub fn new(
        component: impl Into<String>,
        epoch: SecurityEpoch,
        decision: GovernanceDecision,
        evidence_hash: ContentHash,
    ) -> Self {
        let component = component.into();
        let mut hasher = Sha256::new();
        hasher.update(b"decision_receipt");
        hasher.update(component.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(decision.as_str().as_bytes());
        hasher.update(evidence_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&hasher.finalize());
        Self {
            receipt_hash,
            component,
            epoch,
            decision,
            evidence_hash,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Receipt({}, {}, epoch={})",
            self.component,
            self.decision,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Aggregate statistics from a batch of gate evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total number of substrates evaluated.
    pub total_evaluated: u64,
    /// Number approved (Approve).
    pub approved: u64,
    /// Number conditionally approved.
    pub conditional: u64,
    /// Number rejected.
    pub rejected: u64,
    /// Number requiring additional evidence.
    pub insufficient: u64,
    /// Pass rate in millionths (approved + conditional) / total.
    pub pass_rate: u64,
}

impl GateSummary {
    /// Create a new empty summary.
    pub fn new() -> Self {
        Self {
            total_evaluated: 0,
            approved: 0,
            conditional: 0,
            rejected: 0,
            insufficient: 0,
            pass_rate: 0,
        }
    }

    /// Record a decision into the summary.
    pub fn record(&mut self, decision: GovernanceDecision) {
        self.total_evaluated += 1;
        match decision {
            GovernanceDecision::Approve => self.approved += 1,
            GovernanceDecision::ConditionalApprove => self.conditional += 1,
            GovernanceDecision::Reject => self.rejected += 1,
            GovernanceDecision::RequireEvidence => self.insufficient += 1,
        }
        self.recompute_pass_rate();
    }

    /// Recompute the pass rate.
    fn recompute_pass_rate(&mut self) {
        let passing = self.approved.saturating_add(self.conditional);
        self.pass_rate = passing
            .saturating_mul(MILLIONTHS)
            .checked_div(self.total_evaluated)
            .unwrap_or(0);
    }

    /// Whether all evaluated substrates passed.
    pub fn all_passed(&self) -> bool {
        self.total_evaluated > 0 && self.rejected == 0 && self.insufficient == 0
    }

    /// Failure rate in millionths.
    pub fn failure_rate(&self) -> u64 {
        MILLIONTHS.saturating_sub(self.pass_rate)
    }
}

impl Default for GateSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateSummary(total={}, approved={}, conditional={}, rejected={}, insufficient={}, pass_rate={})",
            self.total_evaluated,
            self.approved,
            self.conditional,
            self.rejected,
            self.insufficient,
            self.pass_rate,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate cache-miss evidence against the gate configuration.
///
/// Returns `RequireEvidence` if samples are insufficient.
/// Returns `Approve` if all miss rates are within thresholds.
/// Returns `ConditionalApprove` if miss rates are between 1x and 1.5x thresholds.
/// Returns `Reject` if any miss rate exceeds 1.5x threshold.
pub fn evaluate_cache_locality(
    evidence: &CacheMissEvidence,
    config: &GateConfig,
) -> GovernanceDecision {
    if !evidence.has_sufficient_samples() {
        return GovernanceDecision::RequireEvidence;
    }

    let checks = [
        (evidence.l1_miss_rate, config.max_l1_miss_rate),
        (evidence.l2_miss_rate, config.max_l2_miss_rate),
        (evidence.l3_miss_rate, config.max_l3_miss_rate),
        (evidence.tlb_miss_rate, config.max_tlb_miss_rate),
    ];

    let mut any_conditional = false;

    for (actual, threshold) in checks {
        let upper = threshold
            .saturating_mul(CONDITIONAL_MULTIPLIER)
            .checked_div(MILLIONTHS)
            .unwrap_or(threshold);
        if actual > upper {
            return GovernanceDecision::Reject;
        }
        if actual > threshold {
            any_conditional = true;
        }
    }

    if any_conditional {
        GovernanceDecision::ConditionalApprove
    } else {
        GovernanceDecision::Approve
    }
}

/// Evaluate NUMA evidence against the gate configuration.
///
/// Returns `Approve` if local access fraction meets the minimum.
/// Returns `ConditionalApprove` if local access is within 80%-100% of the
/// minimum threshold.
/// Returns `Reject` otherwise.
pub fn evaluate_numa(evidence: &NumaEvidence, config: &GateConfig) -> GovernanceDecision {
    if evidence.local_access_fraction >= config.min_local_access_fraction {
        return GovernanceDecision::Approve;
    }

    // Conditional band: between 80% and 100% of threshold.
    let conditional_floor = config
        .min_local_access_fraction
        .saturating_mul(800_000)
        .checked_div(MILLIONTHS)
        .unwrap_or(0);

    if evidence.local_access_fraction >= conditional_floor {
        GovernanceDecision::ConditionalApprove
    } else {
        GovernanceDecision::Reject
    }
}

/// Evaluate portability evidence against the gate configuration.
///
/// Returns `Portable` if transferable fraction meets the minimum and no
/// degradation factors exist.
/// Returns `ConditionallyPortable` if transferable fraction meets the minimum
/// but degradation factors are present.
/// Returns `MachineSpecific` if transferable fraction is below the minimum.
/// Returns `Unknown` if evidence is absent or pathological.
pub fn evaluate_portability(
    evidence: &PortabilityEvidence,
    config: &GateConfig,
) -> PortabilityVerdict {
    if evidence.transferable_fraction >= config.min_portability_fraction {
        if evidence.degradation_factors.is_empty() {
            PortabilityVerdict::Portable
        } else {
            PortabilityVerdict::ConditionallyPortable
        }
    } else if evidence.transferable_fraction == 0
        && evidence.source_topology == evidence.target_topology
    {
        // Same topology with zero transfer is pathological.
        PortabilityVerdict::Unknown
    } else {
        PortabilityVerdict::MachineSpecific
    }
}

/// Compute a combined evidence hash from optional evidence sources.
fn compute_evidence_hash(
    cache_ev: Option<&CacheMissEvidence>,
    numa_ev: Option<&NumaEvidence>,
    port_ev: Option<&PortabilityEvidence>,
    obs_ev: Option<&ObservabilityImpact>,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"combined_locality_evidence");
    if let Some(ce) = cache_ev {
        hasher.update(ce.content_hash().as_bytes());
    }
    if let Some(ne) = numa_ev {
        hasher.update(ne.content_hash().as_bytes());
    }
    if let Some(pe) = port_ev {
        hasher.update(pe.content_hash().as_bytes());
    }
    if let Some(oe) = obs_ev {
        hasher.update(oe.instrumented_overhead.to_le_bytes());
        hasher.update(oe.uninstrumented_baseline.to_le_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Run the full locality governance gate.
///
/// Evaluates cache locality, NUMA, portability, and observability evidence.
/// Combines the individual verdicts into a single `GateResult`.
///
/// If no evidence is provided at all, returns `RequireEvidence`.
pub fn evaluate(
    cache_ev: Option<&CacheMissEvidence>,
    numa_ev: Option<&NumaEvidence>,
    port_ev: Option<&PortabilityEvidence>,
    obs_ev: Option<&ObservabilityImpact>,
    config: &GateConfig,
) -> GateResult {
    let mut blocking_reasons: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();
    let mut worst_decision = GovernanceDecision::Approve;

    // No evidence at all — require evidence.
    if cache_ev.is_none() && numa_ev.is_none() && port_ev.is_none() && obs_ev.is_none() {
        let receipt_hash = compute_evidence_hash(None, None, None, None);
        return GateResult {
            decision: GovernanceDecision::RequireEvidence,
            locality_verdict: LocalityDomain::RemoteMemory,
            portability_verdict: PortabilityVerdict::Unknown,
            blocking_reasons: vec!["no evidence provided".to_string()],
            recommendations: vec![
                "collect cache, NUMA, portability, and observability evidence".to_string(),
            ],
            receipt_hash,
        };
    }

    // --- Cache locality ---
    let locality_verdict = if let Some(ce) = cache_ev {
        let cache_decision = evaluate_cache_locality(ce, config);
        worst_decision = merge_decisions(worst_decision, cache_decision);
        match cache_decision {
            GovernanceDecision::Reject => {
                blocking_reasons.push(format!(
                    "cache miss rates exceed thresholds: L1={}, L2={}, L3={}, TLB={}",
                    ce.l1_miss_rate, ce.l2_miss_rate, ce.l3_miss_rate, ce.tlb_miss_rate,
                ));
                recommendations.push("optimize data layout for cache locality".to_string());
            }
            GovernanceDecision::ConditionalApprove => {
                recommendations
                    .push("cache miss rates are marginal — consider layout tuning".to_string());
            }
            GovernanceDecision::RequireEvidence => {
                blocking_reasons.push(format!(
                    "insufficient cache samples: {} < {}",
                    ce.sample_count, MIN_SAMPLE_COUNT,
                ));
                recommendations.push("collect more cache-miss samples".to_string());
            }
            GovernanceDecision::Approve => {}
        }
        ce.dominant_domain()
    } else {
        recommendations.push("no cache-miss evidence provided".to_string());
        LocalityDomain::NumaNode
    };

    // --- NUMA ---
    if let Some(ne) = numa_ev {
        let numa_decision = evaluate_numa(ne, config);
        worst_decision = merge_decisions(worst_decision, numa_decision);
        match numa_decision {
            GovernanceDecision::Reject => {
                blocking_reasons.push(format!(
                    "NUMA local access fraction {} below threshold {}",
                    ne.local_access_fraction, config.min_local_access_fraction,
                ));
                recommendations.push("rebind substrate to local NUMA node".to_string());
            }
            GovernanceDecision::ConditionalApprove => {
                recommendations.push("NUMA locality is marginal — consider rebinding".to_string());
            }
            _ => {}
        }
    }

    // --- Portability ---
    let portability_verdict = if let Some(pe) = port_ev {
        let pv = evaluate_portability(pe, config);
        match pv {
            PortabilityVerdict::MachineSpecific => {
                worst_decision = merge_decisions(worst_decision, GovernanceDecision::Reject);
                blocking_reasons.push(format!(
                    "substrate is machine-specific: transferable fraction {} below {}",
                    pe.transferable_fraction, config.min_portability_fraction,
                ));
                recommendations
                    .push("remove hardware-specific optimizations or provide fallback".to_string());
            }
            PortabilityVerdict::Unknown => {
                worst_decision =
                    merge_decisions(worst_decision, GovernanceDecision::RequireEvidence);
                blocking_reasons.push("portability is unknown — pathological evidence".to_string());
                recommendations
                    .push("re-run portability assessment with valid topologies".to_string());
            }
            PortabilityVerdict::ConditionallyPortable => {
                worst_decision =
                    merge_decisions(worst_decision, GovernanceDecision::ConditionalApprove);
                for factor in &pe.degradation_factors {
                    recommendations.push(format!("address degradation factor: {factor}"));
                }
            }
            PortabilityVerdict::Portable => {}
        }
        pv
    } else {
        recommendations.push("no portability evidence provided".to_string());
        PortabilityVerdict::Unknown
    };

    // --- Observability ---
    if let Some(oe) = obs_ev {
        if oe.exceeds_threshold(config.max_observability_overhead) {
            worst_decision = merge_decisions(worst_decision, GovernanceDecision::Reject);
            blocking_reasons.push(format!(
                "observability overhead {} exceeds maximum {}",
                oe.delta_fraction, config.max_observability_overhead,
            ));
            recommendations.push("reduce instrumentation overhead or use sampling".to_string());
        } else if !oe.acceptable {
            worst_decision =
                merge_decisions(worst_decision, GovernanceDecision::ConditionalApprove);
            recommendations
                .push("observability impact flagged as unacceptable by operator".to_string());
        }
    }

    let receipt_hash = compute_evidence_hash(cache_ev, numa_ev, port_ev, obs_ev);

    GateResult {
        decision: worst_decision,
        locality_verdict,
        portability_verdict,
        blocking_reasons,
        recommendations,
        receipt_hash,
    }
}

/// Merge two governance decisions, keeping the worst (most restrictive).
///
/// Priority: Reject > RequireEvidence > ConditionalApprove > Approve.
fn merge_decisions(a: GovernanceDecision, b: GovernanceDecision) -> GovernanceDecision {
    let rank = |d: GovernanceDecision| -> u8 {
        match d {
            GovernanceDecision::Approve => 0,
            GovernanceDecision::ConditionalApprove => 1,
            GovernanceDecision::RequireEvidence => 2,
            GovernanceDecision::Reject => 3,
        }
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// Build a `DecisionReceipt` from a `GateResult`.
pub fn build_receipt(result: &GateResult, epoch: SecurityEpoch) -> DecisionReceipt {
    DecisionReceipt::new(
        COMPONENT,
        epoch,
        result.decision,
        result.receipt_hash.clone(),
    )
}

/// Build a default set of realistic cache-miss evidence profiles for testing
/// and portability audits.
pub fn build_canonical_evidence() -> Vec<CacheMissEvidence> {
    let epoch = SecurityEpoch::from_raw(1);
    vec![
        CacheMissEvidence::new("hot_metadata", 10_000, 30_000, 50_000, 5_000, 1000, epoch),
        CacheMissEvidence::new(
            "cold_metadata",
            80_000,
            200_000,
            400_000,
            30_000,
            500,
            epoch,
        ),
        CacheMissEvidence::new(
            "mixed_metadata",
            40_000,
            90_000,
            150_000,
            15_000,
            800,
            epoch,
        ),
        CacheMissEvidence::new("streaming", 60_000, 150_000, 300_000, 25_000, 200, epoch),
        CacheMissEvidence::new(
            "pointer_chasing",
            90_000,
            250_000,
            500_000,
            40_000,
            300,
            epoch,
        ),
        CacheMissEvidence::new("sequential_scan", 5_000, 10_000, 20_000, 2_000, 2000, epoch),
        CacheMissEvidence::new(
            "random_access",
            100_000,
            300_000,
            600_000,
            50_000,
            150,
            epoch,
        ),
        CacheMissEvidence::new(
            "prefetch_friendly",
            15_000,
            25_000,
            40_000,
            3_000,
            1200,
            epoch,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn good_cache_evidence() -> CacheMissEvidence {
        CacheMissEvidence::new("test", 10_000, 30_000, 50_000, 5_000, 100, test_epoch())
    }

    fn bad_cache_evidence() -> CacheMissEvidence {
        CacheMissEvidence::new(
            "test",
            200_000,
            500_000,
            800_000,
            100_000,
            100,
            test_epoch(),
        )
    }

    fn marginal_cache_evidence() -> CacheMissEvidence {
        // L1 just above threshold (50_000) but below 1.5x (75_000)
        CacheMissEvidence::new("test", 60_000, 50_000, 100_000, 10_000, 100, test_epoch())
    }

    fn good_numa_evidence() -> NumaEvidence {
        NumaEvidence::new(0, 900_000, 100_000, 500_000, 50_000, test_epoch())
    }

    fn bad_numa_evidence() -> NumaEvidence {
        NumaEvidence::new(0, 300_000, 700_000, 900_000, 500_000, test_epoch())
    }

    fn good_portability_evidence() -> PortabilityEvidence {
        PortabilityEvidence::new("x86_64", "aarch64", 900_000, vec![], test_epoch())
    }

    fn good_observability() -> ObservabilityImpact {
        ObservabilityImpact::new(20_000, 5_000, true)
    }

    fn default_config() -> GateConfig {
        GateConfig::default()
    }

    // --- LocalityDomain tests ---

    #[test]
    fn locality_domain_all_variants() {
        assert_eq!(LocalityDomain::ALL.len(), 6);
    }

    #[test]
    fn locality_domain_display() {
        assert_eq!(LocalityDomain::CacheLine.to_string(), "cache_line");
        assert_eq!(LocalityDomain::RemoteMemory.to_string(), "remote_memory");
    }

    #[test]
    fn locality_domain_latency_ordering() {
        let weights: Vec<u64> = LocalityDomain::ALL
            .iter()
            .map(|d| d.latency_weight())
            .collect();
        for i in 1..weights.len() {
            assert!(
                weights[i] >= weights[i - 1],
                "latency should be non-decreasing"
            );
        }
    }

    // --- PortabilityVerdict tests ---

    #[test]
    fn portability_verdict_display() {
        assert_eq!(PortabilityVerdict::Portable.to_string(), "portable");
        assert_eq!(
            PortabilityVerdict::MachineSpecific.to_string(),
            "machine_specific"
        );
    }

    #[test]
    fn portability_verdict_permits_deployment() {
        assert!(PortabilityVerdict::Portable.permits_deployment());
        assert!(PortabilityVerdict::ConditionallyPortable.permits_deployment());
        assert!(!PortabilityVerdict::MachineSpecific.permits_deployment());
        assert!(!PortabilityVerdict::Unknown.permits_deployment());
    }

    // --- GovernanceDecision tests ---

    #[test]
    fn governance_decision_display() {
        assert_eq!(GovernanceDecision::Approve.to_string(), "approve");
        assert_eq!(GovernanceDecision::Reject.to_string(), "reject");
    }

    #[test]
    fn governance_decision_allows_deployment() {
        assert!(GovernanceDecision::Approve.allows_deployment());
        assert!(GovernanceDecision::ConditionalApprove.allows_deployment());
        assert!(!GovernanceDecision::Reject.allows_deployment());
        assert!(!GovernanceDecision::RequireEvidence.allows_deployment());
    }

    // --- NumaPolicy tests ---

    #[test]
    fn numa_policy_display() {
        assert_eq!(NumaPolicy::FirstTouch.to_string(), "first_touch");
        assert_eq!(NumaPolicy::Interleave.to_string(), "interleave");
        assert_eq!(NumaPolicy::Bind.to_string(), "bind");
        assert_eq!(NumaPolicy::Preferred.to_string(), "preferred");
    }

    #[test]
    fn numa_policy_all_variants() {
        assert_eq!(NumaPolicy::ALL.len(), 4);
    }

    // --- CacheMissEvidence tests ---

    #[test]
    fn cache_miss_evidence_new() {
        let ev = good_cache_evidence();
        assert_eq!(ev.domain, "test");
        assert_eq!(ev.l1_miss_rate, 10_000);
        assert!(ev.has_sufficient_samples());
    }

    #[test]
    fn cache_miss_evidence_insufficient_samples() {
        let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 3, test_epoch());
        assert!(!ev.has_sufficient_samples());
    }

    #[test]
    fn cache_miss_evidence_content_hash_deterministic() {
        let a = good_cache_evidence();
        let b = good_cache_evidence();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn cache_miss_evidence_display() {
        let ev = good_cache_evidence();
        let s = ev.to_string();
        assert!(s.contains("CacheMiss"));
        assert!(s.contains("test"));
    }

    #[test]
    fn cache_miss_dominant_domain_l1_zero() {
        let ev = CacheMissEvidence::new("x", 0, 10_000, 20_000, 5_000, 100, test_epoch());
        assert_eq!(ev.dominant_domain(), LocalityDomain::CacheLine);
    }

    #[test]
    fn cache_miss_dominant_domain_all_nonzero() {
        let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 100, test_epoch());
        assert_eq!(ev.dominant_domain(), LocalityDomain::CrossSocket);
    }

    // --- NumaEvidence tests ---

    #[test]
    fn numa_evidence_new() {
        let ev = good_numa_evidence();
        assert_eq!(ev.node_id, 0);
        assert_eq!(ev.local_access_fraction, 900_000);
    }

    #[test]
    fn numa_evidence_is_local_dominant() {
        let ev = good_numa_evidence();
        assert!(ev.is_local_dominant(800_000));
        assert!(!ev.is_local_dominant(950_000));
    }

    #[test]
    fn numa_evidence_effective_latency_multiplier() {
        let ev = good_numa_evidence();
        // 1_000_000 + 50_000 = 1_050_000
        assert_eq!(ev.effective_latency_multiplier(), 1_050_000);
    }

    #[test]
    fn numa_evidence_content_hash_deterministic() {
        let a = good_numa_evidence();
        let b = good_numa_evidence();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn numa_evidence_display() {
        let ev = good_numa_evidence();
        let s = ev.to_string();
        assert!(s.contains("NUMA"));
        assert!(s.contains("node=0"));
    }

    // --- PortabilityEvidence tests ---

    #[test]
    fn portability_evidence_new() {
        let ev = good_portability_evidence();
        assert_eq!(ev.source_topology, "x86_64");
        assert_eq!(ev.transferable_fraction, 900_000);
        assert!(!ev.has_degradation());
    }

    #[test]
    fn portability_evidence_with_degradation() {
        let ev = PortabilityEvidence::new(
            "x86_64",
            "aarch64",
            800_000,
            vec!["simd_width_mismatch".to_string()],
            test_epoch(),
        );
        assert!(ev.has_degradation());
        assert_eq!(ev.degradation_count(), 1);
    }

    #[test]
    fn portability_evidence_content_hash_deterministic() {
        let a = good_portability_evidence();
        let b = good_portability_evidence();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    // --- ObservabilityImpact tests ---

    #[test]
    fn observability_impact_new() {
        let oi = good_observability();
        assert_eq!(oi.delta_fraction, 15_000);
        assert!(oi.acceptable);
    }

    #[test]
    fn observability_impact_exceeds_threshold() {
        let oi = ObservabilityImpact::new(200_000, 10_000, false);
        assert!(oi.exceeds_threshold(50_000));
        assert!(!oi.exceeds_threshold(200_000));
    }

    #[test]
    fn observability_impact_overhead_ratio() {
        let oi = ObservabilityImpact::new(200_000, 100_000, false);
        // 200_000 * 1_000_000 / 100_000 = 2_000_000
        assert_eq!(oi.overhead_ratio(), 2_000_000);
    }

    #[test]
    fn observability_impact_display() {
        let oi = good_observability();
        let s = oi.to_string();
        assert!(s.contains("Observability"));
    }

    // --- GateConfig tests ---

    #[test]
    fn gate_config_default() {
        let cfg = GateConfig::default();
        assert_eq!(cfg.max_l1_miss_rate, DEFAULT_MAX_L1_MISS_RATE);
        assert_eq!(
            cfg.min_local_access_fraction,
            DEFAULT_MIN_LOCAL_ACCESS_FRACTION
        );
        assert_eq!(
            cfg.max_observability_overhead,
            DEFAULT_MAX_OBSERVABILITY_OVERHEAD
        );
        assert_eq!(
            cfg.min_portability_fraction,
            DEFAULT_MIN_PORTABILITY_FRACTION
        );
    }

    #[test]
    fn gate_config_display() {
        let cfg = default_config();
        let s = cfg.to_string();
        assert!(s.contains("GateConfig"));
    }

    // --- evaluate_cache_locality tests ---

    #[test]
    fn cache_locality_approve_good_evidence() {
        let ev = good_cache_evidence();
        let decision = evaluate_cache_locality(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::Approve);
    }

    #[test]
    fn cache_locality_reject_bad_evidence() {
        let ev = bad_cache_evidence();
        let decision = evaluate_cache_locality(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::Reject);
    }

    #[test]
    fn cache_locality_conditional_marginal_evidence() {
        let ev = marginal_cache_evidence();
        let decision = evaluate_cache_locality(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::ConditionalApprove);
    }

    #[test]
    fn cache_locality_require_evidence_insufficient_samples() {
        let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 5, test_epoch());
        let decision = evaluate_cache_locality(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::RequireEvidence);
    }

    // --- evaluate_numa tests ---

    #[test]
    fn numa_approve_good_evidence() {
        let ev = good_numa_evidence();
        let decision = evaluate_numa(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::Approve);
    }

    #[test]
    fn numa_reject_bad_evidence() {
        let ev = bad_numa_evidence();
        let decision = evaluate_numa(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::Reject);
    }

    #[test]
    fn numa_conditional_marginal_evidence() {
        // min_local_access_fraction is 800_000, conditional floor is 640_000.
        let ev = NumaEvidence::new(0, 700_000, 300_000, 500_000, 100_000, test_epoch());
        let decision = evaluate_numa(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::ConditionalApprove);
    }

    // --- evaluate_portability tests ---

    #[test]
    fn portability_portable() {
        let ev = good_portability_evidence();
        let verdict = evaluate_portability(&ev, &default_config());
        assert_eq!(verdict, PortabilityVerdict::Portable);
    }

    #[test]
    fn portability_conditionally_portable_with_degradation() {
        let ev = PortabilityEvidence::new(
            "x86_64",
            "aarch64",
            900_000,
            vec!["cache_line_size_difference".to_string()],
            test_epoch(),
        );
        let verdict = evaluate_portability(&ev, &default_config());
        assert_eq!(verdict, PortabilityVerdict::ConditionallyPortable);
    }

    #[test]
    fn portability_machine_specific() {
        let ev = PortabilityEvidence::new("x86_64", "aarch64", 200_000, vec![], test_epoch());
        let verdict = evaluate_portability(&ev, &default_config());
        assert_eq!(verdict, PortabilityVerdict::MachineSpecific);
    }

    #[test]
    fn portability_unknown_same_topology_zero_transfer() {
        let ev = PortabilityEvidence::new("x86_64", "x86_64", 0, vec![], test_epoch());
        let verdict = evaluate_portability(&ev, &default_config());
        assert_eq!(verdict, PortabilityVerdict::Unknown);
    }

    // --- evaluate (combined) tests ---

    #[test]
    fn evaluate_no_evidence_requires_evidence() {
        let result = evaluate(None, None, None, None, &default_config());
        assert_eq!(result.decision, GovernanceDecision::RequireEvidence);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_all_good_approves() {
        let cache = good_cache_evidence();
        let numa = good_numa_evidence();
        let port = good_portability_evidence();
        let obs = good_observability();
        let result = evaluate(
            Some(&cache),
            Some(&numa),
            Some(&port),
            Some(&obs),
            &default_config(),
        );
        assert_eq!(result.decision, GovernanceDecision::Approve);
        assert!(result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_bad_cache_rejects() {
        let cache = bad_cache_evidence();
        let numa = good_numa_evidence();
        let result = evaluate(Some(&cache), Some(&numa), None, None, &default_config());
        assert_eq!(result.decision, GovernanceDecision::Reject);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_bad_numa_rejects() {
        let cache = good_cache_evidence();
        let numa = bad_numa_evidence();
        let result = evaluate(Some(&cache), Some(&numa), None, None, &default_config());
        assert_eq!(result.decision, GovernanceDecision::Reject);
    }

    #[test]
    fn evaluate_machine_specific_portability_rejects() {
        let port = PortabilityEvidence::new("x86_64", "aarch64", 100_000, vec![], test_epoch());
        let result = evaluate(None, None, Some(&port), None, &default_config());
        assert_eq!(result.decision, GovernanceDecision::Reject);
    }

    #[test]
    fn evaluate_high_observability_overhead_rejects() {
        let cache = good_cache_evidence();
        let obs = ObservabilityImpact::new(500_000, 10_000, false);
        let result = evaluate(Some(&cache), None, None, Some(&obs), &default_config());
        assert_eq!(result.decision, GovernanceDecision::Reject);
        assert!(result
            .blocking_reasons
            .iter()
            .any(|r| r.contains("observability")));
    }

    #[test]
    fn evaluate_unacceptable_obs_conditionally_approves() {
        let cache = good_cache_evidence();
        // Delta 15_000 is under threshold 50_000 but acceptable = false.
        let obs = ObservabilityImpact::new(20_000, 5_000, false);
        let result = evaluate(Some(&cache), None, None, Some(&obs), &default_config());
        assert_eq!(result.decision, GovernanceDecision::ConditionalApprove);
    }

    #[test]
    fn evaluate_result_has_receipt_hash() {
        let cache = good_cache_evidence();
        let result = evaluate(Some(&cache), None, None, None, &default_config());
        // Receipt hash should be non-trivial (not all zeros).
        let bytes = result.receipt_hash.as_bytes();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    // --- GateResult tests ---

    #[test]
    fn gate_result_is_approved() {
        let cache = good_cache_evidence();
        let result = evaluate(Some(&cache), None, None, None, &default_config());
        assert!(result.is_approved());
    }

    #[test]
    fn gate_result_blocking_count() {
        let result = evaluate(None, None, None, None, &default_config());
        assert!(result.blocking_count() > 0);
    }

    #[test]
    fn gate_result_display() {
        let cache = good_cache_evidence();
        let result = evaluate(Some(&cache), None, None, None, &default_config());
        let s = result.to_string();
        assert!(s.contains("GateResult"));
    }

    // --- DecisionReceipt tests ---

    #[test]
    fn decision_receipt_new() {
        let hash = ContentHash::compute(b"test");
        let receipt =
            DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, hash);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.decision, GovernanceDecision::Approve);
    }

    #[test]
    fn decision_receipt_display() {
        let hash = ContentHash::compute(b"test");
        let receipt =
            DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, hash);
        let s = receipt.to_string();
        assert!(s.contains("Receipt"));
        assert!(s.contains(COMPONENT));
    }

    #[test]
    fn decision_receipt_deterministic() {
        let hash = ContentHash::compute(b"test");
        let a = DecisionReceipt::new(
            COMPONENT,
            test_epoch(),
            GovernanceDecision::Approve,
            hash.clone(),
        );
        let b = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, hash);
        assert_eq!(a.receipt_hash, b.receipt_hash);
    }

    // --- GateSummary tests ---

    #[test]
    fn gate_summary_new_empty() {
        let s = GateSummary::new();
        assert_eq!(s.total_evaluated, 0);
        assert_eq!(s.pass_rate, 0);
    }

    #[test]
    fn gate_summary_record_approve() {
        let mut s = GateSummary::new();
        s.record(GovernanceDecision::Approve);
        assert_eq!(s.total_evaluated, 1);
        assert_eq!(s.approved, 1);
        assert_eq!(s.pass_rate, MILLIONTHS);
    }

    #[test]
    fn gate_summary_mixed_decisions() {
        let mut s = GateSummary::new();
        s.record(GovernanceDecision::Approve);
        s.record(GovernanceDecision::ConditionalApprove);
        s.record(GovernanceDecision::Reject);
        s.record(GovernanceDecision::RequireEvidence);
        assert_eq!(s.total_evaluated, 4);
        assert_eq!(s.approved, 1);
        assert_eq!(s.conditional, 1);
        assert_eq!(s.rejected, 1);
        assert_eq!(s.insufficient, 1);
        assert_eq!(s.pass_rate, 500_000); // 2/4 = 50%
    }

    #[test]
    fn gate_summary_all_passed() {
        let mut s = GateSummary::new();
        s.record(GovernanceDecision::Approve);
        s.record(GovernanceDecision::ConditionalApprove);
        assert!(s.all_passed());
    }

    #[test]
    fn gate_summary_not_all_passed_with_reject() {
        let mut s = GateSummary::new();
        s.record(GovernanceDecision::Approve);
        s.record(GovernanceDecision::Reject);
        assert!(!s.all_passed());
    }

    #[test]
    fn gate_summary_failure_rate() {
        let mut s = GateSummary::new();
        s.record(GovernanceDecision::Approve);
        s.record(GovernanceDecision::Reject);
        assert_eq!(s.failure_rate(), 500_000);
    }

    #[test]
    fn gate_summary_display() {
        let s = GateSummary::new();
        let d = s.to_string();
        assert!(d.contains("GateSummary"));
    }

    // --- merge_decisions tests ---

    #[test]
    fn merge_decisions_keeps_worst() {
        assert_eq!(
            merge_decisions(GovernanceDecision::Approve, GovernanceDecision::Reject),
            GovernanceDecision::Reject,
        );
        assert_eq!(
            merge_decisions(GovernanceDecision::Reject, GovernanceDecision::Approve),
            GovernanceDecision::Reject,
        );
        assert_eq!(
            merge_decisions(
                GovernanceDecision::ConditionalApprove,
                GovernanceDecision::RequireEvidence
            ),
            GovernanceDecision::RequireEvidence,
        );
    }

    // --- build_receipt tests ---

    #[test]
    fn build_receipt_from_result() {
        let cache = good_cache_evidence();
        let result = evaluate(Some(&cache), None, None, None, &default_config());
        let receipt = build_receipt(&result, test_epoch());
        assert_eq!(receipt.decision, result.decision);
        assert_eq!(receipt.component, COMPONENT);
    }

    // --- build_canonical_evidence tests ---

    #[test]
    fn canonical_evidence_has_entries() {
        let profiles = build_canonical_evidence();
        assert!(profiles.len() >= 8);
        for profile in &profiles {
            assert!(profile.has_sufficient_samples());
        }
    }

    // --- Serde round-trip tests ---

    #[test]
    fn serde_round_trip_locality_domain() {
        for domain in LocalityDomain::ALL {
            let json = serde_json::to_string(domain).unwrap();
            let back: LocalityDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*domain, back);
        }
    }

    #[test]
    fn serde_round_trip_governance_decision() {
        for d in GovernanceDecision::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: GovernanceDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    #[test]
    fn serde_round_trip_gate_result() {
        let cache = good_cache_evidence();
        let result = evaluate(Some(&cache), None, None, None, &default_config());
        let json = serde_json::to_string(&result).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- Constants tests ---

    #[test]
    fn constants_are_sane() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
        assert_eq!(POLICY_ID, "RGC-626C");
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    // --- Edge case tests ---

    #[test]
    fn cache_zero_miss_rates_approve() {
        let ev = CacheMissEvidence::new("perfect", 0, 0, 0, 0, 100, test_epoch());
        let decision = evaluate_cache_locality(&ev, &default_config());
        assert_eq!(decision, GovernanceDecision::Approve);
    }

    #[test]
    fn observability_zero_baseline_overhead_ratio() {
        let oi = ObservabilityImpact::new(100_000, 0, true);
        // With zero baseline, uses 1 as denominator.
        assert_eq!(oi.overhead_ratio(), 100_000 * MILLIONTHS);
    }

    #[test]
    fn evaluate_only_observability_good() {
        let obs = good_observability();
        let result = evaluate(None, None, None, Some(&obs), &default_config());
        // With only good observability and no other evidence:
        // no cache/numa/port evidence triggers recommendations but not blocking.
        assert!(result.decision.allows_deployment());
    }
}
