//! Standardized tier telemetry and publication-ready benchmark evidence contracts.
//!
//! Defines the telemetry, artifact, and publication contract that benchmark
//! and diagnostic systems must use when referring to execution tiers. Provides
//! content-addressed evidence bundles, publication readiness evaluation, and
//! tier distribution snapshots.
//!
//! All ratios and percentages use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-310C], bead bd-1lsy.4.11.3

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for tier telemetry contract artifacts.
pub const TELEMETRY_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.tier-telemetry-contract.v1";

/// Bead reference.
pub const TELEMETRY_CONTRACT_BEAD_ID: &str = "bd-1lsy.4.11.3";

/// Policy reference.
pub const TELEMETRY_CONTRACT_POLICY_ID: &str = "RGC-310C";

/// Component name for logging/tracing.
pub const COMPONENT: &str = "tier_telemetry_contract";

/// Fixed-point denominator: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// TelemetryTier
// ---------------------------------------------------------------------------

/// Canonical telemetry representation of an execution tier.
///
/// Mirrors `tier_eligibility_substrate::ExecutionTier` but serves as the
/// canonical representation for telemetry and benchmark reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryTier {
    /// Interpreted execution (slowest, no compilation).
    Interpreted,
    /// Baseline-compiled (fast compilation, minimal optimization).
    Baseline,
    /// Optimized compilation (significant optimization passes).
    Optimized,
    /// Specialized compilation (type-specialized, maximal optimization).
    Specialized,
    /// Deoptimized: fell back from a higher tier due to speculation failure.
    Deoptimized,
}

impl TelemetryTier {
    /// All tier variants in canonical order.
    pub const ALL: &'static [TelemetryTier] = &[
        TelemetryTier::Interpreted,
        TelemetryTier::Baseline,
        TelemetryTier::Optimized,
        TelemetryTier::Specialized,
        TelemetryTier::Deoptimized,
    ];

    /// String key used in distribution maps.
    pub fn as_key(&self) -> &'static str {
        match self {
            Self::Interpreted => "interpreted",
            Self::Baseline => "baseline",
            Self::Optimized => "optimized",
            Self::Specialized => "specialized",
            Self::Deoptimized => "deoptimized",
        }
    }
}

impl fmt::Display for TelemetryTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_key())
    }
}

// ---------------------------------------------------------------------------
// TelemetryEventKind
// ---------------------------------------------------------------------------

/// The kind of telemetry event being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// A function transitioned between execution tiers.
    TierTransition,
    /// A deoptimization event occurred.
    DeoptOccurrence,
    /// A probe was updated with new profiling data.
    ProbeUpdate,
    /// A benchmark measurement was taken.
    BenchmarkSample,
    /// A latency observation was recorded.
    LatencyObservation,
    /// A throughput observation was recorded.
    ThroughputObservation,
    /// An error rate measurement was taken.
    ErrorRate,
    /// A custom application-defined metric.
    CustomMetric,
}

impl fmt::Display for TelemetryEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TierTransition => write!(f, "tier_transition"),
            Self::DeoptOccurrence => write!(f, "deopt_occurrence"),
            Self::ProbeUpdate => write!(f, "probe_update"),
            Self::BenchmarkSample => write!(f, "benchmark_sample"),
            Self::LatencyObservation => write!(f, "latency_observation"),
            Self::ThroughputObservation => write!(f, "throughput_observation"),
            Self::ErrorRate => write!(f, "error_rate"),
            Self::CustomMetric => write!(f, "custom_metric"),
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetryEvent
// ---------------------------------------------------------------------------

/// A single telemetry event recording a tier-related observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Unique identifier for this event.
    pub event_id: String,
    /// The kind of event.
    pub kind: TelemetryEventKind,
    /// The execution tier associated with this event.
    pub tier: TelemetryTier,
    /// Timestamp in nanoseconds (monotonic).
    pub timestamp_nanos: u64,
    /// Measured value in fixed-point millionths.
    pub value_millionths: i64,
    /// Arbitrary string labels for grouping/filtering.
    pub labels: BTreeMap<String, String>,
    /// Content-addressed hash of this event.
    pub content_hash: ContentHash,
}

impl fmt::Display for TelemetryEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryEvent({}, {}, tier={}, value={})",
            self.event_id, self.kind, self.tier, self.value_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEvidenceKind
// ---------------------------------------------------------------------------

/// The kind of benchmark evidence being collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkEvidenceKind {
    /// Operations per second.
    Throughput,
    /// Response time / execution latency.
    Latency,
    /// Memory consumption.
    MemoryUsage,
    /// CPU utilization.
    CpuUtilization,
    /// Cache hit rate.
    CacheHitRate,
    /// Deoptimization rate.
    DeoptRate,
    /// Distribution of functions across tiers.
    TierDistribution,
}

impl fmt::Display for BenchmarkEvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Throughput => write!(f, "throughput"),
            Self::Latency => write!(f, "latency"),
            Self::MemoryUsage => write!(f, "memory_usage"),
            Self::CpuUtilization => write!(f, "cpu_utilization"),
            Self::CacheHitRate => write!(f, "cache_hit_rate"),
            Self::DeoptRate => write!(f, "deopt_rate"),
            Self::TierDistribution => write!(f, "tier_distribution"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeltaClassification
// ---------------------------------------------------------------------------

/// Classification of a benchmark delta relative to baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaClassification {
    /// Performance regressed beyond the threshold.
    Regression,
    /// Performance improved beyond the threshold.
    Improvement,
    /// Change is within the noise threshold.
    Neutral,
}

impl fmt::Display for DeltaClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regression => write!(f, "regression"),
            Self::Improvement => write!(f, "improvement"),
            Self::Neutral => write!(f, "neutral"),
        }
    }
}

/// Classify a delta value against a threshold.
///
/// - If `delta_millionths < -(threshold_millionths as i64)`, it is a `Regression`.
/// - If `delta_millionths > threshold_millionths as i64`, it is an `Improvement`.
/// - Otherwise, it is `Neutral`.
pub fn classify_delta(delta_millionths: i64, threshold_millionths: u64) -> DeltaClassification {
    let threshold = threshold_millionths as i64;
    if delta_millionths < -threshold {
        DeltaClassification::Regression
    } else if delta_millionths > threshold {
        DeltaClassification::Improvement
    } else {
        DeltaClassification::Neutral
    }
}

// ---------------------------------------------------------------------------
// BenchmarkSample
// ---------------------------------------------------------------------------

/// A single benchmark measurement with baseline comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSample {
    /// Unique identifier for this sample.
    pub sample_id: String,
    /// The kind of benchmark evidence.
    pub kind: BenchmarkEvidenceKind,
    /// The execution tier this sample was measured against.
    pub tier: TelemetryTier,
    /// Measured value in fixed-point millionths.
    pub value_millionths: i64,
    /// Baseline value in fixed-point millionths.
    pub baseline_millionths: i64,
    /// Delta from baseline (value - baseline) in fixed-point millionths.
    pub delta_millionths: i64,
    /// Whether this sample represents a regression.
    pub is_regression: bool,
    /// Confidence level in fixed-point millionths (0..1_000_000).
    pub confidence_millionths: u64,
    /// Content-addressed hash of this sample.
    pub content_hash: ContentHash,
}

impl fmt::Display for BenchmarkSample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let classification = if self.is_regression {
            "REGRESSION"
        } else {
            "ok"
        };
        write!(
            f,
            "BenchmarkSample({}, {}, tier={}, delta={}, {})",
            self.sample_id, self.kind, self.tier, self.delta_millionths, classification
        )
    }
}

/// Build a benchmark sample with computed delta and regression flag.
pub fn build_benchmark_sample(
    kind: BenchmarkEvidenceKind,
    tier: TelemetryTier,
    value_millionths: i64,
    baseline_millionths: i64,
    confidence_millionths: u64,
) -> BenchmarkSample {
    let delta_millionths = value_millionths - baseline_millionths;
    let is_regression = delta_millionths < 0;

    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"benchmark_sample");
    hasher.update(format!("{kind:?}").as_bytes());
    hasher.update(format!("{tier:?}").as_bytes());
    hasher.update(value_millionths.to_le_bytes());
    hasher.update(baseline_millionths.to_le_bytes());
    hasher.update(confidence_millionths.to_le_bytes());
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let sample_id = format!("sample-{}-{}-{}", kind, tier, &content_hash.to_hex()[..16]);

    BenchmarkSample {
        sample_id,
        kind,
        tier,
        value_millionths,
        baseline_millionths,
        delta_millionths,
        is_regression,
        confidence_millionths,
        content_hash,
    }
}

/// Returns `true` if the sample represents a regression.
pub fn is_regression(sample: &BenchmarkSample) -> bool {
    sample.is_regression
}

// ---------------------------------------------------------------------------
// BenchmarkEvidenceBundle
// ---------------------------------------------------------------------------

/// A bundle of benchmark samples with aggregate statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEvidenceBundle {
    /// Unique identifier for this bundle.
    pub bundle_id: String,
    /// The security epoch at which this bundle was created.
    pub epoch: SecurityEpoch,
    /// Individual benchmark samples.
    pub samples: Vec<BenchmarkSample>,
    /// Distribution of functions across tiers (tier_key -> count).
    pub tier_distribution: BTreeMap<String, u64>,
    /// Total number of samples in this bundle.
    pub total_samples: u64,
    /// Number of regression samples.
    pub regression_count: u64,
    /// Number of improvement samples.
    pub improvement_count: u64,
    /// Number of neutral samples.
    pub neutral_count: u64,
    /// Overall delta across all samples in fixed-point millionths.
    pub overall_delta_millionths: i64,
    /// Whether this bundle meets publication criteria.
    pub is_publishable: bool,
    /// Content-addressed hash of this bundle.
    pub content_hash: ContentHash,
}

impl fmt::Display for BenchmarkEvidenceBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EvidenceBundle({}, samples={}, regressions={}, publishable={})",
            self.bundle_id, self.total_samples, self.regression_count, self.is_publishable
        )
    }
}

/// Build an evidence bundle from samples and an epoch.
///
/// Aggregates sample statistics, computes tier distribution from sample tiers,
/// and produces a content-addressed bundle.
pub fn build_evidence_bundle(
    samples: Vec<BenchmarkSample>,
    epoch: &SecurityEpoch,
) -> BenchmarkEvidenceBundle {
    let total_samples = samples.len() as u64;
    let mut regression_count: u64 = 0;
    let mut improvement_count: u64 = 0;
    let mut neutral_count: u64 = 0;
    let mut overall_delta: i64 = 0;
    let mut tier_distribution: BTreeMap<String, u64> = BTreeMap::new();

    let default_threshold = 50_000_u64; // 5% threshold for classification

    for sample in &samples {
        overall_delta = overall_delta.saturating_add(sample.delta_millionths);

        match classify_delta(sample.delta_millionths, default_threshold) {
            DeltaClassification::Regression => regression_count += 1,
            DeltaClassification::Improvement => improvement_count += 1,
            DeltaClassification::Neutral => neutral_count += 1,
        }

        *tier_distribution
            .entry(sample.tier.as_key().to_string())
            .or_insert(0) += 1;
    }

    let overall_delta_millionths = if total_samples > 0 {
        overall_delta / total_samples as i64
    } else {
        0
    };

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"evidence_bundle");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(total_samples.to_le_bytes());
    for sample in &samples {
        hasher.update(sample.content_hash.as_bytes());
    }
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let bundle_id = format!("bundle-{}", &content_hash.to_hex()[..16]);

    BenchmarkEvidenceBundle {
        bundle_id,
        epoch: *epoch,
        samples,
        tier_distribution,
        total_samples,
        regression_count,
        improvement_count,
        neutral_count,
        overall_delta_millionths,
        is_publishable: true, // provisional; evaluated by evaluate_publication
        content_hash,
    }
}

/// Compute the regression rate for a bundle in fixed-point millionths.
///
/// Returns `regression_count / total_samples * 1_000_000`.
pub fn regression_rate(bundle: &BenchmarkEvidenceBundle) -> u64 {
    if bundle.total_samples == 0 {
        return 0;
    }
    (bundle.regression_count * MILLIONTHS) / bundle.total_samples
}

// ---------------------------------------------------------------------------
// PublicationContract
// ---------------------------------------------------------------------------

/// Contract governing when benchmark evidence is publication-ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationContract {
    /// Unique identifier for this contract.
    pub contract_id: String,
    /// Minimum number of samples required.
    pub required_min_samples: u64,
    /// Minimum confidence level in fixed-point millionths.
    pub required_confidence_millionths: u64,
    /// Maximum acceptable regression rate in fixed-point millionths.
    pub max_regression_rate_millionths: u64,
    /// Whether all tiers must have at least one sample.
    pub require_all_tiers_represented: bool,
    /// Maximum number of epochs since data collection before results are stale.
    pub staleness_limit_epochs: u64,
    /// Content-addressed hash of this contract.
    pub content_hash: ContentHash,
}

impl PublicationContract {
    /// Create a contract with sensible defaults.
    ///
    /// - 10 minimum samples
    /// - 950_000 (95%) minimum confidence
    /// - 100_000 (10%) maximum regression rate
    /// - All tiers must be represented
    /// - 5 epoch staleness limit
    pub fn default_contract() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
        hasher.update(b"default_publication_contract");
        let hash_bytes: [u8; 32] = hasher.finalize().into();

        Self {
            contract_id: "publication-contract-default-v1".to_string(),
            required_min_samples: 10,
            required_confidence_millionths: 950_000,
            max_regression_rate_millionths: 100_000,
            require_all_tiers_represented: true,
            staleness_limit_epochs: 5,
            content_hash: ContentHash(hash_bytes),
        }
    }
}

impl fmt::Display for PublicationContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicationContract({}, min_samples={}, max_reg_rate={})",
            self.contract_id, self.required_min_samples, self.max_regression_rate_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// PublicationVerdict
// ---------------------------------------------------------------------------

/// The result of evaluating an evidence bundle against a publication contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationVerdict {
    /// Unique identifier for this verdict.
    pub verdict_id: String,
    /// The epoch at which the verdict was rendered.
    pub epoch: SecurityEpoch,
    /// Whether the evidence bundle is publishable.
    pub is_publishable: bool,
    /// Reasons for the verdict (empty if publishable, otherwise failure reasons).
    pub reasons: Vec<String>,
    /// The bundle that was evaluated.
    pub evidence_bundle_id: String,
    /// The contract used for evaluation.
    pub contract_id: String,
    /// Content-addressed hash of this verdict.
    pub content_hash: ContentHash,
}

impl fmt::Display for PublicationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_publishable {
            "PUBLISHABLE"
        } else {
            "NOT_PUBLISHABLE"
        };
        write!(
            f,
            "PublicationVerdict({}, {}, reasons={})",
            self.verdict_id,
            status,
            self.reasons.len()
        )
    }
}

/// Evaluate whether an evidence bundle meets a publication contract.
///
/// Checks:
/// 1. Minimum sample count
/// 2. All samples meet minimum confidence
/// 3. Regression rate within limits
/// 4. All tiers represented (if required)
/// 5. Data not stale (epoch difference within limit)
pub fn evaluate_publication(
    bundle: &BenchmarkEvidenceBundle,
    contract: &PublicationContract,
    epoch: &SecurityEpoch,
) -> PublicationVerdict {
    let mut reasons = Vec::new();
    let mut is_publishable = true;

    // Check 1: minimum samples
    if bundle.total_samples < contract.required_min_samples {
        is_publishable = false;
        reasons.push(format!(
            "insufficient samples: {} < {}",
            bundle.total_samples, contract.required_min_samples
        ));
    }

    // Check 2: minimum confidence on all samples
    for sample in &bundle.samples {
        if sample.confidence_millionths < contract.required_confidence_millionths {
            is_publishable = false;
            reasons.push(format!(
                "sample {} confidence {} < required {}",
                sample.sample_id,
                sample.confidence_millionths,
                contract.required_confidence_millionths
            ));
        }
    }

    // Check 3: regression rate
    let rate = regression_rate(bundle);
    if rate > contract.max_regression_rate_millionths {
        is_publishable = false;
        reasons.push(format!(
            "regression rate {} > max {}",
            rate, contract.max_regression_rate_millionths
        ));
    }

    // Check 4: all tiers represented
    if contract.require_all_tiers_represented {
        for tier in TelemetryTier::ALL {
            if !bundle.tier_distribution.contains_key(tier.as_key()) {
                is_publishable = false;
                reasons.push(format!("missing tier: {tier}"));
            }
        }
    }

    // Check 5: staleness
    let bundle_epoch = bundle.epoch.as_u64();
    let current_epoch = epoch.as_u64();
    if current_epoch > bundle_epoch {
        let age = current_epoch - bundle_epoch;
        if age > contract.staleness_limit_epochs {
            is_publishable = false;
            reasons.push(format!(
                "stale data: age {} epochs > limit {}",
                age, contract.staleness_limit_epochs
            ));
        }
    }

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"publication_verdict");
    hasher.update(bundle.content_hash.as_bytes());
    hasher.update(contract.content_hash.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(if is_publishable { &[1u8] } else { &[0u8] });
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let verdict_id = format!("verdict-{}", &content_hash.to_hex()[..16]);

    PublicationVerdict {
        verdict_id,
        epoch: *epoch,
        is_publishable,
        reasons,
        evidence_bundle_id: bundle.bundle_id.clone(),
        contract_id: contract.contract_id.clone(),
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// TierDistributionSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of function distribution across tiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierDistributionSnapshot {
    /// Unique identifier for this snapshot.
    pub snapshot_id: String,
    /// The security epoch when the snapshot was taken.
    pub epoch: SecurityEpoch,
    /// Distribution of functions across tiers (tier_key -> count).
    pub distribution: BTreeMap<String, u64>,
    /// Total number of functions tracked.
    pub total_functions: u64,
    /// The tier with the most functions.
    pub dominant_tier: String,
    /// Ratio of dominant tier to total in fixed-point millionths.
    pub dominance_ratio_millionths: u64,
    /// Content-addressed hash of this snapshot.
    pub content_hash: ContentHash,
}

impl fmt::Display for TierDistributionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TierDistribution(total={}, dominant={}, ratio={})",
            self.total_functions, self.dominant_tier, self.dominance_ratio_millionths
        )
    }
}

/// Compute a tier distribution snapshot from telemetry events.
///
/// Counts the number of events per tier and identifies the dominant tier.
pub fn compute_tier_distribution(
    events: &[TelemetryEvent],
    epoch: &SecurityEpoch,
) -> TierDistributionSnapshot {
    let mut distribution: BTreeMap<String, u64> = BTreeMap::new();

    for event in events {
        *distribution
            .entry(event.tier.as_key().to_string())
            .or_insert(0) += 1;
    }

    let total_functions = events.len() as u64;

    let (dominant_tier, dominant_count) = distribution
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(k, v)| (k.clone(), *v))
        .unwrap_or_else(|| ("none".to_string(), 0));

    let dominance_ratio_millionths = if total_functions > 0 {
        (dominant_count * MILLIONTHS) / total_functions
    } else {
        0
    };

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"tier_distribution_snapshot");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(total_functions.to_le_bytes());
    for (key, count) in &distribution {
        hasher.update(key.as_bytes());
        hasher.update(count.to_le_bytes());
    }
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let snapshot_id = format!("snapshot-{}", &content_hash.to_hex()[..16]);

    TierDistributionSnapshot {
        snapshot_id,
        epoch: *epoch,
        distribution,
        total_functions,
        dominant_tier,
        dominance_ratio_millionths,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// TelemetryReport
// ---------------------------------------------------------------------------

/// Comprehensive telemetry report aggregating events, bundles, verdicts, and
/// distribution snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryReport {
    /// Unique identifier for this report.
    pub report_id: String,
    /// The security epoch for this report.
    pub epoch: SecurityEpoch,
    /// All telemetry events in this report.
    pub events: Vec<TelemetryEvent>,
    /// Evidence bundles produced from the events.
    pub bundles: Vec<BenchmarkEvidenceBundle>,
    /// Publication verdicts for the bundles.
    pub verdicts: Vec<PublicationVerdict>,
    /// Tier distribution snapshot.
    pub distribution_snapshot: Option<TierDistributionSnapshot>,
    /// Total number of events.
    pub total_events: u64,
    /// Content-addressed hash of this report.
    pub content_hash: ContentHash,
}

impl fmt::Display for TelemetryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryReport({}, events={}, bundles={}, verdicts={})",
            self.report_id,
            self.total_events,
            self.bundles.len(),
            self.verdicts.len()
        )
    }
}

/// Build a telemetry report from its components.
pub fn build_telemetry_report(
    events: Vec<TelemetryEvent>,
    bundles: Vec<BenchmarkEvidenceBundle>,
    verdicts: Vec<PublicationVerdict>,
    snapshot: Option<TierDistributionSnapshot>,
    epoch: &SecurityEpoch,
) -> TelemetryReport {
    let total_events = events.len() as u64;

    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"telemetry_report");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(total_events.to_le_bytes());
    for event in &events {
        hasher.update(event.content_hash.as_bytes());
    }
    for bundle in &bundles {
        hasher.update(bundle.content_hash.as_bytes());
    }
    for verdict in &verdicts {
        hasher.update(verdict.content_hash.as_bytes());
    }
    if let Some(ref snap) = snapshot {
        hasher.update(snap.content_hash.as_bytes());
    }
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let report_id = format!("report-{}", &content_hash.to_hex()[..16]);

    TelemetryReport {
        report_id,
        epoch: *epoch,
        events,
        bundles,
        verdicts,
        distribution_snapshot: snapshot,
        total_events,
        content_hash,
    }
}

/// Produce a manifest report with no events -- used for schema registration.
pub fn franken_engine_tier_telemetry_manifest() -> TelemetryReport {
    let epoch = SecurityEpoch::from_raw(0);
    build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &epoch)
}

// ---------------------------------------------------------------------------
// Helper: build a TelemetryEvent
// ---------------------------------------------------------------------------

/// Build a telemetry event with a computed content hash.
pub fn build_telemetry_event(
    kind: TelemetryEventKind,
    tier: TelemetryTier,
    timestamp_nanos: u64,
    value_millionths: i64,
    labels: BTreeMap<String, String>,
) -> TelemetryEvent {
    let mut hasher = Sha256::new();
    hasher.update(TELEMETRY_CONTRACT_SCHEMA_VERSION.as_bytes());
    hasher.update(b"telemetry_event");
    hasher.update(format!("{kind:?}").as_bytes());
    hasher.update(format!("{tier:?}").as_bytes());
    hasher.update(timestamp_nanos.to_le_bytes());
    hasher.update(value_millionths.to_le_bytes());
    for (k, v) in &labels {
        hasher.update(k.as_bytes());
        hasher.update(v.as_bytes());
    }
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let content_hash = ContentHash(hash_bytes);

    let event_id = format!("event-{}-{}", kind, &content_hash.to_hex()[..16]);

    TelemetryEvent {
        event_id,
        kind,
        tier,
        timestamp_nanos,
        value_millionths,
        labels,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(
            TELEMETRY_CONTRACT_SCHEMA_VERSION,
            "franken-engine.tier-telemetry-contract.v1"
        );
        assert_eq!(TELEMETRY_CONTRACT_BEAD_ID, "bd-1lsy.4.11.3");
        assert_eq!(TELEMETRY_CONTRACT_POLICY_ID, "RGC-310C");
        assert_eq!(COMPONENT, "tier_telemetry_contract");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn test_telemetry_tier_display() {
        assert_eq!(TelemetryTier::Interpreted.to_string(), "interpreted");
        assert_eq!(TelemetryTier::Baseline.to_string(), "baseline");
        assert_eq!(TelemetryTier::Optimized.to_string(), "optimized");
        assert_eq!(TelemetryTier::Specialized.to_string(), "specialized");
        assert_eq!(TelemetryTier::Deoptimized.to_string(), "deoptimized");
    }

    #[test]
    fn test_telemetry_tier_as_key() {
        assert_eq!(TelemetryTier::Interpreted.as_key(), "interpreted");
        assert_eq!(TelemetryTier::Deoptimized.as_key(), "deoptimized");
    }

    #[test]
    fn test_telemetry_tier_all_variants() {
        assert_eq!(TelemetryTier::ALL.len(), 5);
        assert_eq!(TelemetryTier::ALL[0], TelemetryTier::Interpreted);
        assert_eq!(TelemetryTier::ALL[4], TelemetryTier::Deoptimized);
    }

    #[test]
    fn test_telemetry_event_kind_display() {
        assert_eq!(
            TelemetryEventKind::TierTransition.to_string(),
            "tier_transition"
        );
        assert_eq!(
            TelemetryEventKind::DeoptOccurrence.to_string(),
            "deopt_occurrence"
        );
        assert_eq!(
            TelemetryEventKind::CustomMetric.to_string(),
            "custom_metric"
        );
    }

    #[test]
    fn test_classify_delta_regression() {
        let result = classify_delta(-200_000, 50_000);
        assert_eq!(result, DeltaClassification::Regression);
    }

    #[test]
    fn test_classify_delta_improvement() {
        let result = classify_delta(200_000, 50_000);
        assert_eq!(result, DeltaClassification::Improvement);
    }

    #[test]
    fn test_classify_delta_neutral() {
        let result = classify_delta(10_000, 50_000);
        assert_eq!(result, DeltaClassification::Neutral);
    }

    #[test]
    fn test_classify_delta_boundary_negative() {
        // Exactly at the boundary is neutral
        let result = classify_delta(-50_000, 50_000);
        assert_eq!(result, DeltaClassification::Neutral);
    }

    #[test]
    fn test_classify_delta_boundary_positive() {
        let result = classify_delta(50_000, 50_000);
        assert_eq!(result, DeltaClassification::Neutral);
    }

    #[test]
    fn test_classify_delta_zero() {
        let result = classify_delta(0, 50_000);
        assert_eq!(result, DeltaClassification::Neutral);
    }

    #[test]
    fn test_build_benchmark_sample() {
        let sample = build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_200_000,
            1_000_000,
            950_000,
        );
        assert_eq!(sample.kind, BenchmarkEvidenceKind::Throughput);
        assert_eq!(sample.tier, TelemetryTier::Optimized);
        assert_eq!(sample.value_millionths, 1_200_000);
        assert_eq!(sample.baseline_millionths, 1_000_000);
        assert_eq!(sample.delta_millionths, 200_000);
        assert!(!sample.is_regression);
        assert_eq!(sample.confidence_millionths, 950_000);
        assert!(sample.sample_id.starts_with("sample-"));
    }

    #[test]
    fn test_build_benchmark_sample_regression() {
        let sample = build_benchmark_sample(
            BenchmarkEvidenceKind::Latency,
            TelemetryTier::Baseline,
            800_000,
            1_000_000,
            990_000,
        );
        assert!(sample.is_regression);
        assert_eq!(sample.delta_millionths, -200_000);
    }

    #[test]
    fn test_is_regression_function() {
        let sample = build_benchmark_sample(
            BenchmarkEvidenceKind::Latency,
            TelemetryTier::Interpreted,
            500_000,
            1_000_000,
            950_000,
        );
        assert!(is_regression(&sample));

        let sample2 = build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_200_000,
            1_000_000,
            950_000,
        );
        assert!(!is_regression(&sample2));
    }

    #[test]
    fn test_build_evidence_bundle() {
        let samples = vec![
            build_benchmark_sample(
                BenchmarkEvidenceKind::Throughput,
                TelemetryTier::Interpreted,
                1_100_000,
                1_000_000,
                950_000,
            ),
            build_benchmark_sample(
                BenchmarkEvidenceKind::Latency,
                TelemetryTier::Baseline,
                900_000,
                1_000_000,
                960_000,
            ),
            build_benchmark_sample(
                BenchmarkEvidenceKind::MemoryUsage,
                TelemetryTier::Optimized,
                1_000_000,
                1_000_000,
                980_000,
            ),
        ];

        let epoch = SecurityEpoch::from_raw(5);
        let bundle = build_evidence_bundle(samples, &epoch);

        assert_eq!(bundle.total_samples, 3);
        assert_eq!(bundle.regression_count, 1);
        assert!(bundle.bundle_id.starts_with("bundle-"));
        assert_eq!(bundle.epoch, epoch);
    }

    #[test]
    fn test_build_evidence_bundle_empty() {
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(Vec::new(), &epoch);
        assert_eq!(bundle.total_samples, 0);
        assert_eq!(bundle.regression_count, 0);
        assert_eq!(bundle.improvement_count, 0);
        assert_eq!(bundle.neutral_count, 0);
        assert_eq!(bundle.overall_delta_millionths, 0);
    }

    #[test]
    fn test_regression_rate() {
        let samples = vec![
            build_benchmark_sample(
                BenchmarkEvidenceKind::Throughput,
                TelemetryTier::Interpreted,
                500_000,
                1_000_000,
                950_000,
            ),
            build_benchmark_sample(
                BenchmarkEvidenceKind::Latency,
                TelemetryTier::Baseline,
                1_200_000,
                1_000_000,
                960_000,
            ),
        ];
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let rate = regression_rate(&bundle);
        assert_eq!(rate, 500_000); // 50%
    }

    #[test]
    fn test_regression_rate_empty() {
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(Vec::new(), &epoch);
        assert_eq!(regression_rate(&bundle), 0);
    }

    #[test]
    fn test_publication_contract_default() {
        let contract = PublicationContract::default_contract();
        assert_eq!(contract.required_min_samples, 10);
        assert_eq!(contract.required_confidence_millionths, 950_000);
        assert_eq!(contract.max_regression_rate_millionths, 100_000);
        assert!(contract.require_all_tiers_represented);
        assert_eq!(contract.staleness_limit_epochs, 5);
        assert!(
            contract
                .contract_id
                .starts_with("publication-contract-default")
        );
    }

    #[test]
    fn test_evaluate_publication_publishable() {
        let contract = PublicationContract {
            contract_id: "test-contract".to_string(),
            required_min_samples: 5,
            required_confidence_millionths: 900_000,
            max_regression_rate_millionths: 200_000,
            require_all_tiers_represented: false,
            staleness_limit_epochs: 10,
            content_hash: ContentHash::compute(b"test"),
        };

        let samples: Vec<BenchmarkSample> = (0..5)
            .map(|i| {
                build_benchmark_sample(
                    BenchmarkEvidenceKind::Throughput,
                    TelemetryTier::Optimized,
                    1_000_000 + i * 10_000,
                    1_000_000,
                    950_000,
                )
            })
            .collect();

        let epoch = SecurityEpoch::from_raw(3);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);

        assert!(verdict.is_publishable);
        assert!(verdict.reasons.is_empty());
    }

    #[test]
    fn test_evaluate_publication_insufficient_samples() {
        let contract = PublicationContract::default_contract();
        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_100_000,
            1_000_000,
            950_000,
        )];
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);

        assert!(!verdict.is_publishable);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("insufficient samples"))
        );
    }

    #[test]
    fn test_evaluate_publication_too_many_regressions() {
        let contract = PublicationContract {
            contract_id: "strict-contract".to_string(),
            required_min_samples: 2,
            required_confidence_millionths: 900_000,
            max_regression_rate_millionths: 100_000,
            require_all_tiers_represented: false,
            staleness_limit_epochs: 100,
            content_hash: ContentHash::compute(b"strict"),
        };

        let samples: Vec<BenchmarkSample> = (0..5)
            .map(|_| {
                build_benchmark_sample(
                    BenchmarkEvidenceKind::Latency,
                    TelemetryTier::Baseline,
                    500_000,
                    1_000_000,
                    950_000,
                )
            })
            .collect();

        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);

        assert!(!verdict.is_publishable);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("regression rate"))
        );
    }

    #[test]
    fn test_evaluate_publication_missing_tiers() {
        let contract = PublicationContract {
            contract_id: "tier-strict".to_string(),
            required_min_samples: 1,
            required_confidence_millionths: 0,
            max_regression_rate_millionths: MILLIONTHS,
            require_all_tiers_represented: true,
            staleness_limit_epochs: 100,
            content_hash: ContentHash::compute(b"tier-strict"),
        };

        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            1_000_000,
            MILLIONTHS,
        )];

        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);

        assert!(!verdict.is_publishable);
        assert!(verdict.reasons.iter().any(|r| r.contains("missing tier")));
    }

    #[test]
    fn test_evaluate_publication_stale_data() {
        let contract = PublicationContract {
            contract_id: "freshness-strict".to_string(),
            required_min_samples: 1,
            required_confidence_millionths: 0,
            max_regression_rate_millionths: MILLIONTHS,
            require_all_tiers_represented: false,
            staleness_limit_epochs: 3,
            content_hash: ContentHash::compute(b"freshness"),
        };

        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            1_000_000,
            MILLIONTHS,
        )];

        let bundle_epoch = SecurityEpoch::from_raw(1);
        let current_epoch = SecurityEpoch::from_raw(10);
        let bundle = build_evidence_bundle(samples, &bundle_epoch);
        let verdict = evaluate_publication(&bundle, &contract, &current_epoch);

        assert!(!verdict.is_publishable);
        assert!(verdict.reasons.iter().any(|r| r.contains("stale data")));
    }

    #[test]
    fn test_compute_tier_distribution() {
        let events = vec![
            build_telemetry_event(
                TelemetryEventKind::TierTransition,
                TelemetryTier::Interpreted,
                100,
                1_000_000,
                BTreeMap::new(),
            ),
            build_telemetry_event(
                TelemetryEventKind::TierTransition,
                TelemetryTier::Interpreted,
                200,
                1_000_000,
                BTreeMap::new(),
            ),
            build_telemetry_event(
                TelemetryEventKind::ProbeUpdate,
                TelemetryTier::Optimized,
                300,
                500_000,
                BTreeMap::new(),
            ),
        ];

        let epoch = SecurityEpoch::from_raw(1);
        let snapshot = compute_tier_distribution(&events, &epoch);

        assert_eq!(snapshot.total_functions, 3);
        assert_eq!(snapshot.dominant_tier, "interpreted");
        assert_eq!(snapshot.distribution.get("interpreted"), Some(&2));
        assert_eq!(snapshot.distribution.get("optimized"), Some(&1));
        assert_eq!(snapshot.dominance_ratio_millionths, 666_666);
    }

    #[test]
    fn test_compute_tier_distribution_empty() {
        let epoch = SecurityEpoch::from_raw(1);
        let snapshot = compute_tier_distribution(&[], &epoch);
        assert_eq!(snapshot.total_functions, 0);
        assert_eq!(snapshot.dominant_tier, "none");
        assert_eq!(snapshot.dominance_ratio_millionths, 0);
    }

    #[test]
    fn test_build_telemetry_event() {
        let mut labels = BTreeMap::new();
        labels.insert("module".to_string(), "test_module".to_string());

        let event = build_telemetry_event(
            TelemetryEventKind::BenchmarkSample,
            TelemetryTier::Specialized,
            42_000,
            1_500_000,
            labels.clone(),
        );

        assert_eq!(event.kind, TelemetryEventKind::BenchmarkSample);
        assert_eq!(event.tier, TelemetryTier::Specialized);
        assert_eq!(event.timestamp_nanos, 42_000);
        assert_eq!(event.value_millionths, 1_500_000);
        assert_eq!(event.labels, labels);
        assert!(event.event_id.starts_with("event-"));
    }

    #[test]
    fn test_build_telemetry_report() {
        let epoch = SecurityEpoch::from_raw(5);
        let report = build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &epoch);
        assert_eq!(report.total_events, 0);
        assert_eq!(report.epoch, epoch);
        assert!(report.report_id.starts_with("report-"));
        assert!(report.distribution_snapshot.is_none());
    }

    #[test]
    fn test_manifest() {
        let manifest = franken_engine_tier_telemetry_manifest();
        assert_eq!(manifest.epoch, SecurityEpoch::from_raw(0));
        assert_eq!(manifest.total_events, 0);
        assert!(manifest.events.is_empty());
        assert!(manifest.bundles.is_empty());
        assert!(manifest.verdicts.is_empty());
    }

    #[test]
    fn test_content_hash_determinism() {
        let s1 = build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            900_000,
            950_000,
        );
        let s2 = build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            900_000,
            950_000,
        );
        assert_eq!(s1.content_hash, s2.content_hash);
        assert_eq!(s1.sample_id, s2.sample_id);
    }

    #[test]
    fn test_content_hash_varies_with_input() {
        let s1 = build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            900_000,
            950_000,
        );
        let s2 = build_benchmark_sample(
            BenchmarkEvidenceKind::Latency,
            TelemetryTier::Optimized,
            1_000_000,
            900_000,
            950_000,
        );
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_serde_roundtrip_telemetry_tier() {
        for tier in TelemetryTier::ALL {
            let json = serde_json::to_string(tier).unwrap();
            let back: TelemetryTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, back);
        }
    }

    #[test]
    fn test_serde_roundtrip_benchmark_sample() {
        let sample = build_benchmark_sample(
            BenchmarkEvidenceKind::CacheHitRate,
            TelemetryTier::Baseline,
            800_000,
            750_000,
            960_000,
        );
        let json = serde_json::to_string(&sample).unwrap();
        let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn test_serde_roundtrip_evidence_bundle() {
        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            1_000_000,
            950_000,
        )];
        let epoch = SecurityEpoch::from_raw(3);
        let bundle = build_evidence_bundle(samples, &epoch);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: BenchmarkEvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn test_serde_roundtrip_publication_verdict() {
        let contract = PublicationContract::default_contract();
        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            1_000_000,
            950_000,
        )];
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);
        let json = serde_json::to_string(&verdict).unwrap();
        let back: PublicationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }

    #[test]
    fn test_delta_classification_display() {
        assert_eq!(DeltaClassification::Regression.to_string(), "regression");
        assert_eq!(DeltaClassification::Improvement.to_string(), "improvement");
        assert_eq!(DeltaClassification::Neutral.to_string(), "neutral");
    }

    #[test]
    fn test_benchmark_evidence_kind_display() {
        assert_eq!(BenchmarkEvidenceKind::Throughput.to_string(), "throughput");
        assert_eq!(BenchmarkEvidenceKind::DeoptRate.to_string(), "deopt_rate");
        assert_eq!(
            BenchmarkEvidenceKind::TierDistribution.to_string(),
            "tier_distribution"
        );
    }

    #[test]
    fn test_publication_contract_display() {
        let contract = PublicationContract::default_contract();
        let display = contract.to_string();
        assert!(display.contains("PublicationContract"));
        assert!(display.contains("min_samples=10"));
    }

    #[test]
    fn test_evidence_bundle_display() {
        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(Vec::new(), &epoch);
        let display = bundle.to_string();
        assert!(display.contains("EvidenceBundle"));
        assert!(display.contains("samples=0"));
    }

    #[test]
    fn test_telemetry_report_with_snapshot() {
        let events = vec![build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            100,
            1_000_000,
            BTreeMap::new(),
        )];
        let epoch = SecurityEpoch::from_raw(2);
        let snapshot = compute_tier_distribution(&events, &epoch);
        let report = build_telemetry_report(
            events,
            Vec::new(),
            Vec::new(),
            Some(snapshot.clone()),
            &epoch,
        );
        assert_eq!(report.total_events, 1);
        assert_eq!(report.distribution_snapshot, Some(snapshot));
    }

    #[test]
    fn test_evaluate_publication_low_confidence() {
        let contract = PublicationContract {
            contract_id: "confidence-strict".to_string(),
            required_min_samples: 1,
            required_confidence_millionths: 990_000,
            max_regression_rate_millionths: MILLIONTHS,
            require_all_tiers_represented: false,
            staleness_limit_epochs: 100,
            content_hash: ContentHash::compute(b"confidence"),
        };

        let samples = vec![build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Optimized,
            1_000_000,
            1_000_000,
            500_000,
        )];

        let epoch = SecurityEpoch::from_raw(1);
        let bundle = build_evidence_bundle(samples, &epoch);
        let verdict = evaluate_publication(&bundle, &contract, &epoch);

        assert!(!verdict.is_publishable);
        assert!(verdict.reasons.iter().any(|r| r.contains("confidence")));
    }
}
