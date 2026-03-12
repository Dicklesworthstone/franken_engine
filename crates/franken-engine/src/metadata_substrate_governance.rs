//! Locality, NUMA, and portability governance for runtime metadata substrates.
//!
//! Bead: bd-1lsy.7.26.3 [RGC-626C]
//!
//! Gates runtime metadata substrates on cache-miss, NUMA, portability, and
//! observability-mode evidence so locality wins do not turn into
//! machine-specific or instrumentation-free delusions.
//!
//! # Design
//!
//! - `LocalityDimension` classifies the locality axis (L1 cache, L2, NUMA, etc.).
//! - `PortabilityTarget` classifies target platforms.
//! - `CacheMissEntry` records cache-miss rate measurements.
//! - `NumaEntry` records NUMA-specific locality measurements.
//! - `PortabilityEntry` records cross-platform portability assessments.
//! - `GovernanceConfig` configures thresholds.
//! - `GovernanceVerdict` is the top-level gate output.
//! - `GovernanceReceipt` is a content-hashed audit trail.
//!
//! All ratios use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-626C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.metadata-substrate-governance.v1";

/// Component name.
pub const COMPONENT: &str = "metadata_substrate_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.26.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-626C";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default maximum cache-miss rate (millionths). 50_000 = 5%.
pub const DEFAULT_MAX_CACHE_MISS_RATE: u64 = 50_000;

/// Default maximum NUMA remote-access ratio (millionths). 100_000 = 10%.
pub const DEFAULT_MAX_NUMA_REMOTE_RATIO: u64 = 100_000;

/// Default minimum portability score (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_PORTABILITY_SCORE: u64 = 800_000;

/// Default minimum samples.
pub const DEFAULT_MIN_SAMPLES: u64 = 30;

/// Default minimum observability coverage (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_OBSERVABILITY_COVERAGE: u64 = 800_000;

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
// LocalityDimension
// ---------------------------------------------------------------------------

/// Classification of the locality axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalityDimension {
    /// L1 data cache.
    L1Data,
    /// L1 instruction cache.
    L1Instruction,
    /// L2 unified cache.
    L2Unified,
    /// L3 / last-level cache.
    L3LastLevel,
    /// TLB (translation lookaside buffer).
    Tlb,
    /// Page table walk.
    PageTableWalk,
    /// Memory bus bandwidth.
    MemoryBus,
    /// Prefetch efficiency.
    PrefetchEfficiency,
}

impl LocalityDimension {
    /// All dimensions.
    pub fn all() -> &'static [Self] {
        &[
            Self::L1Data,
            Self::L1Instruction,
            Self::L2Unified,
            Self::L3LastLevel,
            Self::Tlb,
            Self::PageTableWalk,
            Self::MemoryBus,
            Self::PrefetchEfficiency,
        ]
    }
}

impl fmt::Display for LocalityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::L1Data => "l1_data",
            Self::L1Instruction => "l1_instruction",
            Self::L2Unified => "l2_unified",
            Self::L3LastLevel => "l3_last_level",
            Self::Tlb => "tlb",
            Self::PageTableWalk => "page_table_walk",
            Self::MemoryBus => "memory_bus",
            Self::PrefetchEfficiency => "prefetch_efficiency",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// PortabilityTarget
// ---------------------------------------------------------------------------

/// Target platform for portability assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortabilityTarget {
    /// x86-64 Linux.
    X64Linux,
    /// x86-64 macOS.
    X64Macos,
    /// ARM64 Linux.
    Arm64Linux,
    /// ARM64 macOS (Apple Silicon).
    Arm64Macos,
    /// x86-64 Windows.
    X64Windows,
    /// ARM64 Windows.
    Arm64Windows,
    /// Generic WASM target.
    Wasm,
}

impl PortabilityTarget {
    /// All targets.
    pub fn all() -> &'static [Self] {
        &[
            Self::X64Linux,
            Self::X64Macos,
            Self::Arm64Linux,
            Self::Arm64Macos,
            Self::X64Windows,
            Self::Arm64Windows,
            Self::Wasm,
        ]
    }
}

impl fmt::Display for PortabilityTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::X64Linux => "x64_linux",
            Self::X64Macos => "x64_macos",
            Self::Arm64Linux => "arm64_linux",
            Self::Arm64Macos => "arm64_macos",
            Self::X64Windows => "x64_windows",
            Self::Arm64Windows => "arm64_windows",
            Self::Wasm => "wasm",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CacheMissEntry
// ---------------------------------------------------------------------------

/// Cache-miss rate measurement for a substrate operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMissEntry {
    /// Locality dimension.
    pub dimension: LocalityDimension,
    /// Operation identifier.
    pub operation_id: String,
    /// Total accesses.
    pub total_accesses: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Miss rate in millionths.
    pub miss_rate_millionths: u64,
    /// Whether miss rate is within budget.
    pub within_budget: bool,
    /// Sample count.
    pub sample_count: u64,
    /// Evidence hash.
    pub entry_hash: ContentHash,
}

impl CacheMissEntry {
    /// Create with computed miss rate.
    pub fn new(
        dimension: LocalityDimension,
        operation_id: String,
        total_accesses: u64,
        cache_misses: u64,
        sample_count: u64,
        max_miss_rate: u64,
    ) -> Self {
        let miss_rate_millionths = if total_accesses == 0 {
            0
        } else {
            cache_misses.saturating_mul(FIXED_ONE) / total_accesses
        };
        let within_budget = miss_rate_millionths <= max_miss_rate;
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &dimension.to_string());
        append_str(&mut buf, &operation_id);
        append_u64(&mut buf, total_accesses);
        append_u64(&mut buf, cache_misses);
        append_u64(&mut buf, sample_count);
        let entry_hash = compute_digest(&buf);
        Self {
            dimension,
            operation_id,
            total_accesses,
            cache_misses,
            miss_rate_millionths,
            within_budget,
            sample_count,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// NumaEntry
// ---------------------------------------------------------------------------

/// NUMA locality measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaEntry {
    /// Operation identifier.
    pub operation_id: String,
    /// Total memory accesses.
    pub total_accesses: u64,
    /// Remote-node accesses.
    pub remote_accesses: u64,
    /// Remote ratio in millionths.
    pub remote_ratio_millionths: u64,
    /// Whether ratio is within budget.
    pub within_budget: bool,
    /// NUMA node count.
    pub node_count: u32,
    /// Entry hash.
    pub entry_hash: ContentHash,
}

impl NumaEntry {
    /// Create with computed ratio.
    pub fn new(
        operation_id: String,
        total_accesses: u64,
        remote_accesses: u64,
        node_count: u32,
        max_remote_ratio: u64,
    ) -> Self {
        let remote_ratio_millionths = if total_accesses == 0 {
            0
        } else {
            remote_accesses.saturating_mul(FIXED_ONE) / total_accesses
        };
        let within_budget = remote_ratio_millionths <= max_remote_ratio;
        let mut buf = Vec::with_capacity(48);
        append_str(&mut buf, &operation_id);
        append_u64(&mut buf, total_accesses);
        append_u64(&mut buf, remote_accesses);
        append_u64(&mut buf, node_count as u64);
        let entry_hash = compute_digest(&buf);
        Self {
            operation_id,
            total_accesses,
            remote_accesses,
            remote_ratio_millionths,
            within_budget,
            node_count,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// PortabilityEntry
// ---------------------------------------------------------------------------

/// Cross-platform portability assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortabilityEntry {
    /// Operation identifier.
    pub operation_id: String,
    /// Target platform.
    pub target: PortabilityTarget,
    /// Whether the operation works on this target.
    pub functional: bool,
    /// Performance ratio vs reference (millionths). FIXED_ONE = same perf.
    pub perf_ratio_millionths: u64,
    /// Entry hash.
    pub entry_hash: ContentHash,
}

impl PortabilityEntry {
    /// Create with hash.
    pub fn new(
        operation_id: String,
        target: PortabilityTarget,
        functional: bool,
        perf_ratio_millionths: u64,
    ) -> Self {
        let mut buf = Vec::with_capacity(48);
        append_str(&mut buf, &operation_id);
        append_str(&mut buf, &target.to_string());
        append_u64(&mut buf, if functional { 1 } else { 0 });
        append_u64(&mut buf, perf_ratio_millionths);
        let entry_hash = compute_digest(&buf);
        Self {
            operation_id,
            target,
            functional,
            perf_ratio_millionths,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configurable thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Maximum cache-miss rate (millionths).
    pub max_cache_miss_rate: u64,
    /// Maximum NUMA remote-access ratio (millionths).
    pub max_numa_remote_ratio: u64,
    /// Minimum portability score (millionths).
    pub min_portability_score: u64,
    /// Minimum samples.
    pub min_samples: u64,
    /// Minimum observability coverage (millionths).
    pub min_observability_coverage: u64,
    /// Required portability targets (empty = none required).
    pub required_targets: BTreeSet<PortabilityTarget>,
}

impl GovernanceConfig {
    /// Strict configuration.
    pub fn strict() -> Self {
        Self {
            max_cache_miss_rate: 20_000,
            max_numa_remote_ratio: 50_000,
            min_portability_score: 950_000,
            min_samples: 100,
            min_observability_coverage: 950_000,
            required_targets: PortabilityTarget::all().iter().copied().collect(),
        }
    }

    /// Relaxed configuration.
    pub fn relaxed() -> Self {
        Self {
            max_cache_miss_rate: DEFAULT_MAX_CACHE_MISS_RATE,
            max_numa_remote_ratio: DEFAULT_MAX_NUMA_REMOTE_RATIO,
            min_portability_score: DEFAULT_MIN_PORTABILITY_SCORE,
            min_samples: DEFAULT_MIN_SAMPLES,
            min_observability_coverage: DEFAULT_MIN_OBSERVABILITY_COVERAGE,
            required_targets: BTreeSet::new(),
        }
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self::relaxed()
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Top-level gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks pass.
    Approved,
    /// Cache-miss rate exceeded.
    CacheMissExceeded,
    /// NUMA remote ratio exceeded.
    NumaRemoteExceeded,
    /// Portability score too low.
    PortabilityInsufficient,
    /// Required targets missing.
    TargetsMissing,
    /// Multiple issues.
    MultipleViolations,
}

impl GovernanceVerdict {
    /// Whether this verdict blocks publication.
    pub fn blocks_publication(self) -> bool {
        self != Self::Approved
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Approved => "approved",
            Self::CacheMissExceeded => "cache_miss_exceeded",
            Self::NumaRemoteExceeded => "numa_remote_exceeded",
            Self::PortabilityInsufficient => "portability_insufficient",
            Self::TargetsMissing => "targets_missing",
            Self::MultipleViolations => "multiple_violations",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ViolationDetail
// ---------------------------------------------------------------------------

/// Detail about a governance violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationDetail {
    /// Category.
    pub category: GovernanceVerdict,
    /// Summary.
    pub summary: String,
    /// Measured value (millionths).
    pub measured_millionths: u64,
    /// Threshold (millionths).
    pub threshold_millionths: u64,
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Content-hashed audit receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Overall verdict.
    pub verdict: GovernanceVerdict,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Cache-miss entries.
    pub cache_miss_entries: Vec<CacheMissEntry>,
    /// NUMA entries.
    pub numa_entries: Vec<NumaEntry>,
    /// Portability entries.
    pub portability_entries: Vec<PortabilityEntry>,
    /// Portability score (millionths).
    pub portability_score_millionths: u64,
    /// Targets covered.
    pub targets_covered: BTreeSet<PortabilityTarget>,
    /// Targets missing.
    pub targets_missing: BTreeSet<PortabilityTarget>,
    /// All violations.
    pub violations: Vec<ViolationDetail>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    fn compute_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &format!("{}", self.verdict));
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.cache_miss_entries.len() as u64);
        for c in &self.cache_miss_entries {
            buf.extend_from_slice(c.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.numa_entries.len() as u64);
        for n in &self.numa_entries {
            buf.extend_from_slice(n.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.portability_entries.len() as u64);
        for p in &self.portability_entries {
            buf.extend_from_slice(p.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.violations.len() as u64);
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Evaluates metadata substrate governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    /// Configuration.
    pub config: GovernanceConfig,
    /// Cache-miss entries.
    pub cache_miss_entries: Vec<CacheMissEntry>,
    /// NUMA entries.
    pub numa_entries: Vec<NumaEntry>,
    /// Portability entries.
    pub portability_entries: Vec<PortabilityEntry>,
}

impl GovernanceEvaluator {
    /// Create with config.
    pub fn new(config: GovernanceConfig) -> Self {
        Self {
            config,
            cache_miss_entries: Vec::new(),
            numa_entries: Vec::new(),
            portability_entries: Vec::new(),
        }
    }

    /// Add cache-miss measurement.
    pub fn add_cache_miss(
        &mut self,
        dimension: LocalityDimension,
        operation_id: String,
        total_accesses: u64,
        cache_misses: u64,
        sample_count: u64,
    ) {
        let entry = CacheMissEntry::new(
            dimension,
            operation_id,
            total_accesses,
            cache_misses,
            sample_count,
            self.config.max_cache_miss_rate,
        );
        self.cache_miss_entries.push(entry);
    }

    /// Add NUMA measurement.
    pub fn add_numa(
        &mut self,
        operation_id: String,
        total_accesses: u64,
        remote_accesses: u64,
        node_count: u32,
    ) {
        let entry = NumaEntry::new(
            operation_id,
            total_accesses,
            remote_accesses,
            node_count,
            self.config.max_numa_remote_ratio,
        );
        self.numa_entries.push(entry);
    }

    /// Add portability assessment.
    pub fn add_portability(
        &mut self,
        operation_id: String,
        target: PortabilityTarget,
        functional: bool,
        perf_ratio_millionths: u64,
    ) {
        let entry = PortabilityEntry::new(operation_id, target, functional, perf_ratio_millionths);
        self.portability_entries.push(entry);
    }

    /// Compute portability score across entries.
    fn portability_score(&self) -> u64 {
        if self.portability_entries.is_empty() {
            return FIXED_ONE;
        }
        let functional_count = self
            .portability_entries
            .iter()
            .filter(|e| e.functional)
            .count() as u64;
        let total = self.portability_entries.len() as u64;
        functional_count.saturating_mul(FIXED_ONE) / total
    }

    /// Covered targets.
    fn covered_targets(&self) -> BTreeSet<PortabilityTarget> {
        self.portability_entries
            .iter()
            .filter(|e| e.functional)
            .map(|e| e.target)
            .collect()
    }

    /// Evaluate and produce receipt.
    pub fn evaluate(&self, epoch: SecurityEpoch) -> GovernanceReceipt {
        let mut violations = Vec::new();

        // Check cache-miss rates.
        for c in &self.cache_miss_entries {
            if !c.within_budget {
                violations.push(ViolationDetail {
                    category: GovernanceVerdict::CacheMissExceeded,
                    summary: format!(
                        "{} miss rate on {} = {} > {}",
                        c.dimension,
                        c.operation_id,
                        c.miss_rate_millionths,
                        self.config.max_cache_miss_rate
                    ),
                    measured_millionths: c.miss_rate_millionths,
                    threshold_millionths: self.config.max_cache_miss_rate,
                });
            }
        }

        // Check NUMA.
        for n in &self.numa_entries {
            if !n.within_budget {
                violations.push(ViolationDetail {
                    category: GovernanceVerdict::NumaRemoteExceeded,
                    summary: format!(
                        "NUMA remote ratio on {} = {} > {}",
                        n.operation_id,
                        n.remote_ratio_millionths,
                        self.config.max_numa_remote_ratio
                    ),
                    measured_millionths: n.remote_ratio_millionths,
                    threshold_millionths: self.config.max_numa_remote_ratio,
                });
            }
        }

        // Check portability.
        let port_score = self.portability_score();
        if !self.portability_entries.is_empty() && port_score < self.config.min_portability_score {
            violations.push(ViolationDetail {
                category: GovernanceVerdict::PortabilityInsufficient,
                summary: format!(
                    "Portability score {} < {}",
                    port_score, self.config.min_portability_score
                ),
                measured_millionths: port_score,
                threshold_millionths: self.config.min_portability_score,
            });
        }

        // Check required targets.
        let covered = self.covered_targets();
        let mut targets_missing = BTreeSet::new();
        for t in &self.config.required_targets {
            if !covered.contains(t) {
                targets_missing.insert(*t);
                violations.push(ViolationDetail {
                    category: GovernanceVerdict::TargetsMissing,
                    summary: format!("Required target {t} missing"),
                    measured_millionths: 0,
                    threshold_millionths: 0,
                });
            }
        }

        let verdict = if violations.is_empty() {
            GovernanceVerdict::Approved
        } else {
            let categories: BTreeSet<GovernanceVerdict> =
                violations.iter().map(|v| v.category).collect();
            if categories.len() == 1 {
                *categories.iter().next().unwrap()
            } else {
                GovernanceVerdict::MultipleViolations
            }
        };

        let mut receipt = GovernanceReceipt {
            verdict,
            epoch,
            cache_miss_entries: self.cache_miss_entries.clone(),
            numa_entries: self.numa_entries.clone(),
            portability_entries: self.portability_entries.clone(),
            portability_score_millionths: port_score,
            targets_covered: covered,
            targets_missing,
            violations,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.content_hash = receipt.compute_hash();
        receipt
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("metadata-substrate-governance"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "metadata_substrate_governance");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-626C");
    }

    #[test]
    fn test_locality_dimension_all_count() {
        assert_eq!(LocalityDimension::all().len(), 8);
    }

    #[test]
    fn test_locality_dimension_ordering() {
        assert!(LocalityDimension::L1Data < LocalityDimension::PrefetchEfficiency);
    }

    #[test]
    fn test_locality_dimension_display() {
        assert_eq!(LocalityDimension::L2Unified.to_string(), "l2_unified");
    }

    #[test]
    fn test_portability_target_all_count() {
        assert_eq!(PortabilityTarget::all().len(), 7);
    }

    #[test]
    fn test_portability_target_display() {
        assert_eq!(PortabilityTarget::Arm64Macos.to_string(), "arm64_macos");
    }

    #[test]
    fn test_cache_miss_within_budget() {
        let c = CacheMissEntry::new(
            LocalityDimension::L1Data,
            "lookup_op".into(),
            10000,
            200,
            50,
            DEFAULT_MAX_CACHE_MISS_RATE,
        );
        assert!(c.within_budget);
        assert_eq!(c.miss_rate_millionths, 20_000);
    }

    #[test]
    fn test_cache_miss_exceeds() {
        let c = CacheMissEntry::new(
            LocalityDimension::L1Data,
            "lookup_op".into(),
            10000,
            1000,
            50,
            DEFAULT_MAX_CACHE_MISS_RATE,
        );
        assert!(!c.within_budget);
    }

    #[test]
    fn test_cache_miss_zero_accesses() {
        let c = CacheMissEntry::new(
            LocalityDimension::L1Data,
            "lookup_op".into(),
            0,
            0,
            50,
            DEFAULT_MAX_CACHE_MISS_RATE,
        );
        assert_eq!(c.miss_rate_millionths, 0);
        assert!(c.within_budget);
    }

    #[test]
    fn test_cache_miss_hash_deterministic() {
        let a = CacheMissEntry::new(
            LocalityDimension::L2Unified,
            "op1".into(),
            5000,
            100,
            30,
            DEFAULT_MAX_CACHE_MISS_RATE,
        );
        let b = CacheMissEntry::new(
            LocalityDimension::L2Unified,
            "op1".into(),
            5000,
            100,
            30,
            DEFAULT_MAX_CACHE_MISS_RATE,
        );
        assert_eq!(a.entry_hash, b.entry_hash);
    }

    #[test]
    fn test_numa_within_budget() {
        let n = NumaEntry::new("op1".into(), 10000, 500, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
        assert!(n.within_budget);
        assert_eq!(n.remote_ratio_millionths, 50_000);
    }

    #[test]
    fn test_numa_exceeds() {
        let n = NumaEntry::new("op1".into(), 10000, 2000, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
        assert!(!n.within_budget);
    }

    #[test]
    fn test_numa_zero_accesses() {
        let n = NumaEntry::new("op1".into(), 0, 0, 2, DEFAULT_MAX_NUMA_REMOTE_RATIO);
        assert_eq!(n.remote_ratio_millionths, 0);
    }

    #[test]
    fn test_portability_functional() {
        let p = PortabilityEntry::new("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
        assert!(p.functional);
    }

    #[test]
    fn test_portability_nonfunctional() {
        let p = PortabilityEntry::new("op1".into(), PortabilityTarget::Wasm, false, 0);
        assert!(!p.functional);
    }

    #[test]
    fn test_config_strict() {
        let c = GovernanceConfig::strict();
        assert_eq!(c.required_targets.len(), 7);
    }

    #[test]
    fn test_config_relaxed() {
        let c = GovernanceConfig::relaxed();
        assert!(c.required_targets.is_empty());
    }

    #[test]
    fn test_verdict_blocks_publication() {
        assert!(!GovernanceVerdict::Approved.blocks_publication());
        assert!(GovernanceVerdict::CacheMissExceeded.blocks_publication());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
    }

    #[test]
    fn test_evaluator_empty_approved() {
        let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluator_cache_miss_pass() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluator_cache_miss_fail() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::CacheMissExceeded);
    }

    #[test]
    fn test_evaluator_numa_fail() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_numa("op1".into(), 10000, 2000, 2);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::NumaRemoteExceeded);
    }

    #[test]
    fn test_evaluator_portability_fail() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
        eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, false, 0);
        eval.add_portability("op1".into(), PortabilityTarget::X64Macos, false, 0);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::PortabilityInsufficient);
    }

    #[test]
    fn test_evaluator_targets_missing() {
        let mut config = GovernanceConfig::relaxed();
        config.required_targets.insert(PortabilityTarget::Wasm);
        let eval = GovernanceEvaluator::new(config);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
    }

    #[test]
    fn test_evaluator_multiple_violations() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 1000, 50);
        eval.add_numa("op1".into(), 10000, 2000, 2);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
        let r1 = eval.evaluate(epoch());
        let r2 = eval.evaluate(epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_hash_changes() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        let r1 = eval.evaluate(epoch());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
        let r2 = eval.evaluate(epoch());
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_portability_score_all_functional() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
        eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, true, 900_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.portability_score_millionths, FIXED_ONE);
    }

    #[test]
    fn test_portability_score_half_functional() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
        eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, false, 0);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.portability_score_millionths, 500_000);
    }

    #[test]
    fn test_e2e_full_pass() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cache_miss(LocalityDimension::L1Data, "op1".into(), 10000, 200, 50);
        eval.add_numa("op1".into(), 10000, 500, 2);
        eval.add_portability("op1".into(), PortabilityTarget::X64Linux, true, FIXED_ONE);
        eval.add_portability("op1".into(), PortabilityTarget::Arm64Linux, true, 950_000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_strict_requires_all_targets() {
        let eval = GovernanceEvaluator::new(GovernanceConfig::strict());
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::TargetsMissing);
        assert_eq!(receipt.targets_missing.len(), 7);
    }
}
