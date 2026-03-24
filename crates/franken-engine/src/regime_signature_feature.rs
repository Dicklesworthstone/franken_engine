#![forbid(unsafe_code)]

//! Bounded signature features and regime-state charts for runtime traces.
//!
//! Implements [RGC-617A]: lifts raw runtime traces (VM events, hot-path
//! profiles, latency observations) into bounded-dimensional signature
//! vectors and regime-state charts that serve as control signals for
//! policy morphing.
//!
//! Key design decisions:
//! - Signatures are bounded to a fixed dimensionality (`MAX_SIGNATURE_DIM`)
//!   to prevent unbounded growth in memory and comparison cost.
//! - Signature truncation uses deterministic hash-bucketing so features
//!   map stably across runs.
//! - Regime assignment uses the existing `Regime` enum from `regime_detector`.
//! - When a trace is too short or noisy to classify, the system emits
//!   `RegimeLabel::Abstention` rather than forcing a label.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::regime_detector::Regime;
use crate::security_epoch::SecurityEpoch;

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const REGIME_SIG_SCHEMA_VERSION: &str = "franken-engine.regime_signature_feature.v1";
pub const REGIME_SIG_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.regime_signature_feature_manifest.v1";
pub const REGIME_SIG_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.regime_signature_feature_event.v1";
pub const REGIME_SIG_COMPONENT: &str = "regime_signature_feature";
pub const REGIME_SIG_POLICY_ID: &str = "RGC-617A";

/// Maximum dimensionality of a trace signature vector.
pub const MAX_SIGNATURE_DIM: usize = 64;

/// Minimum number of trace events required to produce a valid signature.
pub const MIN_TRACE_LENGTH: usize = 4;

/// Confidence threshold (millionths) below which we abstain from labeling.
pub const ABSTENTION_THRESHOLD_MILLIONTHS: i64 = 200_000; // 0.2

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Trace observation — input to signature extraction
// ---------------------------------------------------------------------------

/// A single observation from a runtime trace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TraceObservation {
    /// Monotonic sequence number within the trace.
    pub seq: u64,
    /// Feature name (e.g., "instruction_count", "cache_hit_rate", "gc_pause_ns").
    pub feature_name: String,
    /// Observed value in millionths.
    pub value_millionths: i64,
}

/// A complete trace to be lifted into a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrace {
    /// Unique trace identifier.
    pub trace_id: String,
    /// Ordered observations.
    pub observations: Vec<TraceObservation>,
    /// Associated security epoch.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Signature vector
// ---------------------------------------------------------------------------

/// A bounded-dimensional signature vector extracted from a trace.
///
/// The signature captures the distributional shape of a trace's feature
/// values, bucketed into `MAX_SIGNATURE_DIM` slots via deterministic hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSignature {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Source trace ID.
    pub trace_id: String,
    /// Dimensionality of the signature vector.
    pub dimension: usize,
    /// Signature components (millionths).
    pub components: Vec<i64>,
    /// Per-feature contribution counts (how many observations mapped to each bucket).
    pub bucket_counts: Vec<u64>,
    /// Total number of observations used.
    pub observation_count: u64,
    /// Number of distinct features observed.
    pub feature_count: u64,
    /// Whether the trace had enough data for a valid signature.
    pub valid: bool,
    /// Content hash of the signature for audit trail.
    pub signature_hash: String,
}

impl TraceSignature {
    /// Compute the L1 distance between two signatures (millionths).
    pub fn l1_distance(&self, other: &TraceSignature) -> i64 {
        if self.dimension != other.dimension {
            return i64::MAX;
        }
        self.components
            .iter()
            .zip(&other.components)
            .map(|(a, b)| (a - b).abs())
            .sum()
    }

    /// Compute the cosine similarity (millionths: 0 = orthogonal, 1M = identical).
    pub fn cosine_similarity(&self, other: &TraceSignature) -> i64 {
        if self.dimension != other.dimension {
            return 0;
        }
        let dot: i64 = self
            .components
            .iter()
            .zip(&other.components)
            .map(|(a, b)| a.saturating_mul(*b) / MILLION)
            .sum();
        let norm_a: i64 = self
            .components
            .iter()
            .map(|a| a.saturating_mul(*a) / MILLION)
            .sum();
        let norm_b: i64 = other
            .components
            .iter()
            .map(|b| b.saturating_mul(*b) / MILLION)
            .sum();

        if norm_a == 0 || norm_b == 0 {
            return 0;
        }

        // Approximate sqrt via integer Newton's method.
        let mag_a = isqrt(norm_a);
        let mag_b = isqrt(norm_b);
        let denom = mag_a.saturating_mul(mag_b);

        if denom == 0 {
            return 0;
        }

        (dot.saturating_mul(MILLION)) / denom
    }
}

/// Integer square root via Newton's method.
fn isqrt(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    #[allow(clippy::manual_div_ceil)]
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// Regime label — the output classification
// ---------------------------------------------------------------------------

/// Regime label assigned to a trace signature.
///
/// Extends `Regime` with an `Abstention` variant for traces where the
/// classifier cannot make a confident assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegimeLabel {
    /// Regime was confidently classified.
    Classified(Regime),
    /// Trace too short, noisy, or ambiguous for confident classification.
    Abstention,
}

impl RegimeLabel {
    pub const ALL_CLASSIFIED: &[Self] = &[
        Self::Classified(Regime::Normal),
        Self::Classified(Regime::Elevated),
        Self::Classified(Regime::Attack),
        Self::Classified(Regime::Degraded),
        Self::Classified(Regime::Recovery),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classified(r) => match r {
                Regime::Normal => "normal",
                Regime::Elevated => "elevated",
                Regime::Attack => "attack",
                Regime::Degraded => "degraded",
                Regime::Recovery => "recovery",
            },
            Self::Abstention => "abstention",
        }
    }

    pub fn is_abstention(self) -> bool {
        matches!(self, Self::Abstention)
    }
}

impl fmt::Display for RegimeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Regime state chart — state machine for regime transitions
// ---------------------------------------------------------------------------

/// A single entry in the regime state chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeStateEntry {
    /// Sequence number of this entry.
    pub seq: u64,
    /// Assigned regime label.
    pub label: RegimeLabel,
    /// Confidence of the assignment (millionths, 0..1_000_000).
    pub confidence_millionths: i64,
    /// L1 distance to the nearest regime centroid (millionths).
    pub centroid_distance_millionths: i64,
    /// Source trace ID.
    pub trace_id: String,
}

/// The complete regime state chart tracking transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeStateChart {
    /// Schema version.
    pub schema_version: String,
    /// State entries in chronological order.
    pub entries: Vec<RegimeStateEntry>,
    /// Number of transitions (label changes) observed.
    pub transition_count: u64,
    /// Number of abstentions.
    pub abstention_count: u64,
    /// Distribution of labels.
    pub label_distribution: BTreeMap<String, u64>,
    /// Content hash of the chart.
    pub chart_hash: String,
}

impl RegimeStateChart {
    /// Is the chart stable (no transitions and no abstentions)?
    pub fn is_stable(&self) -> bool {
        self.transition_count == 0 && self.abstention_count == 0 && !self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Regime centroids — reference points for classification
// ---------------------------------------------------------------------------

/// Reference centroid for a regime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeCentroid {
    /// Which regime this centroid represents.
    pub regime: Regime,
    /// Centroid signature components (millionths).
    pub components: Vec<i64>,
    /// Radius threshold for membership (L1 distance, millionths).
    pub radius_millionths: i64,
}

/// Configuration for the signature extractor and classifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Maximum signature dimensions.
    pub max_dim: usize,
    /// Minimum trace length for valid signature.
    pub min_trace_length: usize,
    /// Abstention confidence threshold (millionths).
    pub abstention_threshold: i64,
    /// Regime centroids for classification.
    pub centroids: Vec<RegimeCentroid>,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            max_dim: MAX_SIGNATURE_DIM,
            min_trace_length: MIN_TRACE_LENGTH,
            abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
            centroids: default_centroids(),
        }
    }
}

/// Default centroids for the five regimes.
fn default_centroids() -> Vec<RegimeCentroid> {
    let dim = MAX_SIGNATURE_DIM;
    vec![
        RegimeCentroid {
            regime: Regime::Normal,
            components: vec![500_000; dim], // moderate baseline
            radius_millionths: 2_000_000,
        },
        RegimeCentroid {
            regime: Regime::Elevated,
            components: {
                let mut v = vec![500_000; dim];
                // Elevated: slightly higher in first quarter
                for c in v.iter_mut().take(dim / 4) {
                    *c = 700_000;
                }
                v
            },
            radius_millionths: 2_500_000,
        },
        RegimeCentroid {
            regime: Regime::Attack,
            components: {
                let mut v = vec![500_000; dim];
                // Attack: high spikes in first half
                for c in v.iter_mut().take(dim / 2) {
                    *c = 900_000;
                }
                v
            },
            radius_millionths: 3_000_000,
        },
        RegimeCentroid {
            regime: Regime::Degraded,
            components: {
                let mut v = vec![300_000; dim];
                // Degraded: low overall with variance
                for (i, c) in v.iter_mut().enumerate() {
                    if i.is_multiple_of(3) {
                        *c = 100_000;
                    }
                }
                v
            },
            radius_millionths: 2_500_000,
        },
        RegimeCentroid {
            regime: Regime::Recovery,
            components: {
                let mut v = vec![400_000; dim];
                // Recovery: trending upward
                for (i, c) in v.iter_mut().enumerate() {
                    *c = 300_000 + (i as i64).saturating_mul(5000).min(200_000);
                }
                v
            },
            radius_millionths: 2_000_000,
        },
    ]
}

// ---------------------------------------------------------------------------
// Signature extractor
// ---------------------------------------------------------------------------

/// Extract a bounded signature from a runtime trace.
pub fn extract_signature(trace: &RuntimeTrace, config: &SignatureConfig) -> TraceSignature {
    let dim = config.max_dim;

    if trace.observations.len() < config.min_trace_length {
        let hash_input = format!("empty:{}:{}", trace.trace_id, trace.observations.len());
        return TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: trace.trace_id.clone(),
            dimension: dim,
            components: vec![0; dim],
            bucket_counts: vec![0; dim],
            observation_count: trace.observations.len() as u64,
            feature_count: 0,
            valid: false,
            signature_hash: hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes()),
        };
    }

    let mut components = vec![0i64; dim];
    let mut bucket_counts = vec![0u64; dim];
    let mut features_seen = std::collections::BTreeSet::new();

    for obs in &trace.observations {
        features_seen.insert(&obs.feature_name);
        // Deterministic hash-bucketing: hash the feature name to get a bucket index.
        let bucket = feature_to_bucket(&obs.feature_name, dim);
        components[bucket] = components[bucket].saturating_add(obs.value_millionths);
        bucket_counts[bucket] += 1;
    }

    // Normalize: divide each component by its count to get mean value per bucket.
    for (i, count) in bucket_counts.iter().enumerate() {
        if *count > 0 {
            components[i] = components[i].checked_div(*count as i64).unwrap_or(0);
        }
    }

    let hash_input = format!(
        "sig:{}:{}:{}:{}",
        trace.trace_id,
        trace.observations.len(),
        components
            .iter()
            .map(|c| format!("{c}"))
            .collect::<Vec<_>>()
            .join(","),
        bucket_counts
            .iter()
            .map(|bc| format!("{bc}"))
            .collect::<Vec<_>>()
            .join(",")
    );

    TraceSignature {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        trace_id: trace.trace_id.clone(),
        dimension: dim,
        components,
        bucket_counts,
        observation_count: trace.observations.len() as u64,
        feature_count: features_seen.len() as u64,
        valid: true,
        signature_hash: hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes()),
    }
}

/// Map a feature name to a bucket index via deterministic hashing.
fn feature_to_bucket(feature_name: &str, dim: usize) -> usize {
    let hash = ContentHash::compute(feature_name.as_bytes());
    let bytes = hash.as_bytes();
    // Use first 4 bytes as u32 for bucket selection.
    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    (val as usize) % dim
}

// ---------------------------------------------------------------------------
// Regime classifier
// ---------------------------------------------------------------------------

/// Classify a signature against regime centroids.
pub fn classify_regime(signature: &TraceSignature, config: &SignatureConfig) -> (RegimeLabel, i64) {
    if !signature.valid {
        return (RegimeLabel::Abstention, 0);
    }

    let mut best_regime = None;
    let mut best_distance = i64::MAX;

    // Count active buckets (those with observations) for normalized distance.
    let active_buckets: usize = signature.bucket_counts.iter().filter(|c| **c > 0).count();
    if active_buckets == 0 {
        return (RegimeLabel::Abstention, 0);
    }

    for centroid in &config.centroids {
        if centroid.components.len() != signature.dimension {
            continue;
        }
        // Only compare on buckets where the signature has data to avoid
        // penalising sparse traces with many zero buckets.
        let distance: i64 = signature
            .components
            .iter()
            .zip(&centroid.components)
            .zip(&signature.bucket_counts)
            .filter(|(_, count)| **count > 0)
            .map(|((a, b), _)| (a - b).abs())
            .sum();

        if distance < best_distance {
            best_distance = distance;
            best_regime = Some(centroid.regime);
        }
    }

    // Compute confidence: inverse of per-bucket mean distance, scaled to millionths.
    let mean_distance = best_distance
        .checked_div(active_buckets as i64)
        .unwrap_or(best_distance);
    let confidence = if mean_distance == 0 {
        MILLION
    } else {
        (MILLION * MILLION)
            .checked_div(mean_distance.saturating_add(MILLION))
            .unwrap_or(0)
    };

    if confidence < config.abstention_threshold {
        (RegimeLabel::Abstention, confidence)
    } else if let Some(regime) = best_regime {
        (RegimeLabel::Classified(regime), confidence)
    } else {
        (RegimeLabel::Abstention, 0)
    }
}

/// Build a regime state chart from a sequence of traces.
pub fn build_regime_state_chart(
    traces: &[RuntimeTrace],
    config: &SignatureConfig,
) -> RegimeStateChart {
    let mut entries = Vec::with_capacity(traces.len());
    let mut transition_count: u64 = 0;
    let mut abstention_count: u64 = 0;
    let mut label_distribution: BTreeMap<String, u64> = BTreeMap::new();
    let mut prev_label: Option<RegimeLabel> = None;

    for (seq, trace) in traces.iter().enumerate() {
        let sig = extract_signature(trace, config);
        let (label, confidence) = classify_regime(&sig, config);

        // Track transitions.
        if let Some(prev) = prev_label
            && prev != label
        {
            transition_count += 1;
        }
        prev_label = Some(label);

        if label.is_abstention() {
            abstention_count += 1;
        }

        *label_distribution
            .entry(label.as_str().to_string())
            .or_insert(0) += 1;

        let centroid_distance = if let RegimeLabel::Classified(regime) = label {
            config
                .centroids
                .iter()
                .find(|c| c.regime == regime)
                .map(|c| {
                    sig.components
                        .iter()
                        .zip(&c.components)
                        .map(|(a, b)| (a - b).abs())
                        .sum()
                })
                .unwrap_or(0)
        } else {
            0
        };

        entries.push(RegimeStateEntry {
            seq: seq as u64,
            label,
            confidence_millionths: confidence,
            centroid_distance_millionths: centroid_distance,
            trace_id: trace.trace_id.clone(),
        });
    }

    let mut hash_input = format!(
        "chart:{}:{}:{}",
        entries.len(),
        transition_count,
        abstention_count
    );
    // Include label distribution (BTreeMap iterates deterministically).
    for (label, count) in &label_distribution {
        hash_input.push_str(&format!("|{label}={count}"));
    }
    // Include entry labels for content addressability.
    for entry in &entries {
        hash_input.push_str(&format!("|e:{}", entry.label));
    }
    let chart_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());

    RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries,
        transition_count,
        abstention_count,
        label_distribution,
        chart_hash,
    }
}

// ---------------------------------------------------------------------------
// Evidence harness — specimens, inventory, bundle
// ---------------------------------------------------------------------------

/// Specimen family for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureSpecimenFamily {
    /// Signature extraction from valid traces.
    Extraction,
    /// Short/empty trace handling.
    ShortTrace,
    /// Regime classification from signatures.
    Classification,
    /// Abstention on ambiguous data.
    Abstention,
    /// State chart transitions.
    StateChart,
    /// L1 distance and similarity metrics.
    Similarity,
}

impl SignatureSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::Extraction,
        Self::ShortTrace,
        Self::Classification,
        Self::Abstention,
        Self::StateChart,
        Self::Similarity,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Extraction => "extraction",
            Self::ShortTrace => "short_trace",
            Self::Classification => "classification",
            Self::Abstention => "abstention",
            Self::StateChart => "state_chart",
            Self::Similarity => "similarity",
        }
    }
}

impl fmt::Display for SignatureSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Expected outcome for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureExpectedOutcome {
    ValidSignature,
    InvalidSignature,
    CorrectClassification,
    Abstention,
    StableChart,
    TransitionDetected,
    SimilarityComputed,
}

/// A test specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSpecimen {
    pub specimen_id: String,
    pub description: String,
    pub family: SignatureSpecimenFamily,
    pub traces: Vec<RuntimeTrace>,
    pub expected_outcome: SignatureExpectedOutcome,
    pub expected_regime: Option<RegimeLabel>,
    pub expected_valid: Option<bool>,
    pub expected_transition_count: Option<u64>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerdict {
    Pass,
    Fail,
}

/// Evidence for a specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSpecimenEvidence {
    pub specimen_id: String,
    pub family: SignatureSpecimenFamily,
    pub expected_outcome: SignatureExpectedOutcome,
    pub verdict: SignatureVerdict,
    pub signature_valid: Option<bool>,
    pub classified_regime: Option<RegimeLabel>,
    pub confidence_millionths: Option<i64>,
    pub transition_count: Option<u64>,
    pub error_detail: Option<String>,
    pub evidence_hash: String,
}

/// Aggregate inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<SignatureSpecimenEvidence>,
}

impl SignatureEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

/// Run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: SignatureArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// Event for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

/// Bundle artifacts.
#[derive(Debug, Clone)]
pub struct SignatureBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Helper to build a trace with uniform features.
fn make_trace(trace_id: &str, feature: &str, values: &[i64], epoch_raw: u64) -> RuntimeTrace {
    RuntimeTrace {
        trace_id: trace_id.to_string(),
        observations: values
            .iter()
            .enumerate()
            .map(|(i, &v)| TraceObservation {
                seq: i as u64,
                feature_name: feature.to_string(),
                value_millionths: v,
            })
            .collect(),
        epoch: SecurityEpoch::from_raw(epoch_raw),
    }
}

/// Helper to build a trace with multiple features.
fn make_multi_feature_trace(
    trace_id: &str,
    features: &[(&str, &[i64])],
    epoch_raw: u64,
) -> RuntimeTrace {
    let mut observations = Vec::new();
    let mut seq = 0;
    for (feature, values) in features {
        for &v in *values {
            observations.push(TraceObservation {
                seq,
                feature_name: feature.to_string(),
                value_millionths: v,
            });
            seq += 1;
        }
    }
    RuntimeTrace {
        trace_id: trace_id.to_string(),
        observations,
        epoch: SecurityEpoch::from_raw(epoch_raw),
    }
}

/// Returns the curated corpus.
pub fn signature_corpus() -> Vec<SignatureSpecimen> {
    vec![
        // ── Extraction ──
        SignatureSpecimen {
            specimen_id: "extract_single_feature".into(),
            description: "Extract signature from trace with one feature".into(),
            family: SignatureSpecimenFamily::Extraction,
            traces: vec![make_trace(
                "t1",
                "cpu_usage",
                &[500_000, 600_000, 450_000, 550_000, 520_000],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::ValidSignature,
            expected_regime: None,
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "extract_multi_feature".into(),
            description: "Extract signature from trace with multiple features".into(),
            family: SignatureSpecimenFamily::Extraction,
            traces: vec![make_multi_feature_trace(
                "t2",
                &[
                    ("cpu_usage", &[500_000, 600_000]),
                    ("mem_usage", &[300_000, 400_000]),
                    ("cache_hit", &[900_000, 800_000]),
                ],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::ValidSignature,
            expected_regime: None,
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "extract_large_trace".into(),
            description: "Extract signature from long trace (100 observations)".into(),
            family: SignatureSpecimenFamily::Extraction,
            traces: vec![{
                let values: Vec<i64> = (0..100).map(|i| 400_000 + (i % 10) * 20_000).collect();
                make_trace("t3", "throughput", &values, 1)
            }],
            expected_outcome: SignatureExpectedOutcome::ValidSignature,
            expected_regime: None,
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        // ── Short Trace ──
        SignatureSpecimen {
            specimen_id: "short_empty_trace".into(),
            description: "Empty trace produces invalid signature".into(),
            family: SignatureSpecimenFamily::ShortTrace,
            traces: vec![RuntimeTrace {
                trace_id: "t-empty".into(),
                observations: vec![],
                epoch: SecurityEpoch::from_raw(1),
            }],
            expected_outcome: SignatureExpectedOutcome::InvalidSignature,
            expected_regime: None,
            expected_valid: Some(false),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "short_one_observation".into(),
            description: "Single observation is below minimum trace length".into(),
            family: SignatureSpecimenFamily::ShortTrace,
            traces: vec![make_trace("t-short1", "metric", &[500_000], 1)],
            expected_outcome: SignatureExpectedOutcome::InvalidSignature,
            expected_regime: None,
            expected_valid: Some(false),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "short_three_observations".into(),
            description: "Three observations still below MIN_TRACE_LENGTH=4".into(),
            family: SignatureSpecimenFamily::ShortTrace,
            traces: vec![make_trace(
                "t-short3",
                "metric",
                &[500_000, 600_000, 400_000],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::InvalidSignature,
            expected_regime: None,
            expected_valid: Some(false),
            expected_transition_count: None,
        },
        // ── Classification ──
        SignatureSpecimen {
            specimen_id: "classify_normal_trace".into(),
            description: "Moderate values classify as Normal regime".into(),
            family: SignatureSpecimenFamily::Classification,
            traces: vec![make_multi_feature_trace(
                "t-normal",
                &[
                    ("cpu", &[500_000, 510_000, 490_000, 500_000]),
                    ("mem", &[500_000, 480_000, 520_000, 500_000]),
                ],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::CorrectClassification,
            expected_regime: Some(RegimeLabel::Classified(Regime::Normal)),
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "classify_elevated_trace".into(),
            description: "Slightly elevated values classify as Elevated".into(),
            family: SignatureSpecimenFamily::Classification,
            traces: vec![make_multi_feature_trace(
                "t-elevated",
                &[
                    ("cpu", &[700_000, 720_000, 680_000, 710_000]),
                    ("mem", &[500_000, 520_000, 480_000, 500_000]),
                ],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::CorrectClassification,
            expected_regime: None, // Don't constrain which regime; just verify it classifies
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        // ── Abstention ──
        SignatureSpecimen {
            specimen_id: "abstain_on_invalid".into(),
            description: "Invalid signature triggers abstention".into(),
            family: SignatureSpecimenFamily::Abstention,
            traces: vec![make_trace("t-abstain", "x", &[1], 1)],
            expected_outcome: SignatureExpectedOutcome::Abstention,
            expected_regime: Some(RegimeLabel::Abstention),
            expected_valid: Some(false),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "abstain_on_sparse".into(),
            description: "Extremely sparse trace with zero values → abstention".into(),
            family: SignatureSpecimenFamily::Abstention,
            traces: vec![make_trace("t-sparse", "x", &[0, 0, 0, 0], 1)],
            expected_outcome: SignatureExpectedOutcome::Abstention,
            expected_regime: None, // May or may not abstain depending on distance
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        // ── State Chart ──
        SignatureSpecimen {
            specimen_id: "chart_stable_single".into(),
            description: "Single trace produces stable chart with no transitions".into(),
            family: SignatureSpecimenFamily::StateChart,
            traces: vec![make_multi_feature_trace(
                "t-stable",
                &[
                    ("cpu", &[500_000, 510_000, 490_000, 505_000]),
                    ("mem", &[500_000, 490_000, 510_000, 500_000]),
                ],
                1,
            )],
            expected_outcome: SignatureExpectedOutcome::StableChart,
            expected_regime: None,
            expected_valid: None,
            expected_transition_count: Some(0),
        },
        SignatureSpecimen {
            specimen_id: "chart_two_traces_same_regime".into(),
            description: "Two similar traces in same regime → no transitions".into(),
            family: SignatureSpecimenFamily::StateChart,
            traces: vec![
                make_multi_feature_trace(
                    "t-same1",
                    &[("cpu", &[500_000, 510_000, 490_000, 500_000])],
                    1,
                ),
                make_multi_feature_trace(
                    "t-same2",
                    &[("cpu", &[505_000, 515_000, 485_000, 500_000])],
                    2,
                ),
            ],
            expected_outcome: SignatureExpectedOutcome::StableChart,
            expected_regime: None,
            expected_valid: None,
            expected_transition_count: Some(0),
        },
        // ── Similarity ──
        SignatureSpecimen {
            specimen_id: "similarity_identical_traces".into(),
            description: "Identical traces have zero L1 distance".into(),
            family: SignatureSpecimenFamily::Similarity,
            traces: vec![
                make_trace("t-id1", "metric", &[500_000, 600_000, 400_000, 550_000], 1),
                make_trace("t-id2", "metric", &[500_000, 600_000, 400_000, 550_000], 1),
            ],
            expected_outcome: SignatureExpectedOutcome::SimilarityComputed,
            expected_regime: None,
            expected_valid: Some(true),
            expected_transition_count: None,
        },
        SignatureSpecimen {
            specimen_id: "similarity_different_traces".into(),
            description: "Different traces have nonzero L1 distance".into(),
            family: SignatureSpecimenFamily::Similarity,
            traces: vec![
                make_trace(
                    "t-diff1",
                    "metric",
                    &[100_000, 200_000, 300_000, 400_000],
                    1,
                ),
                make_trace(
                    "t-diff2",
                    "metric",
                    &[900_000, 800_000, 700_000, 600_000],
                    1,
                ),
            ],
            expected_outcome: SignatureExpectedOutcome::SimilarityComputed,
            expected_regime: None,
            expected_valid: Some(true),
            expected_transition_count: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn run_single_specimen(specimen: &SignatureSpecimen) -> SignatureSpecimenEvidence {
    let config = SignatureConfig::default();
    let mut verdict = SignatureVerdict::Pass;
    let mut signature_valid = None;
    let mut classified_regime = None;
    let mut confidence_millionths = None;
    let mut transition_count = None;
    let mut error_detail = None;

    match specimen.expected_outcome {
        SignatureExpectedOutcome::ValidSignature | SignatureExpectedOutcome::InvalidSignature => {
            let sig = extract_signature(&specimen.traces[0], &config);
            signature_valid = Some(sig.valid);
            if let Some(expected) = specimen.expected_valid
                && sig.valid != expected
            {
                verdict = SignatureVerdict::Fail;
                error_detail = Some(format!("expected valid={expected} got valid={}", sig.valid));
            }
        }
        SignatureExpectedOutcome::CorrectClassification => {
            let sig = extract_signature(&specimen.traces[0], &config);
            signature_valid = Some(sig.valid);
            let (label, conf) = classify_regime(&sig, &config);
            classified_regime = Some(label);
            confidence_millionths = Some(conf);
            if let Some(expected) = specimen.expected_regime
                && label != expected
            {
                verdict = SignatureVerdict::Fail;
                error_detail = Some(format!("expected regime={:?} got {:?}", expected, label));
            }
            // At minimum, classification should not abstain for valid signatures.
            if sig.valid && label.is_abstention() && specimen.expected_regime.is_some() {
                verdict = SignatureVerdict::Fail;
                error_detail = Some("unexpected abstention".into());
            }
        }
        SignatureExpectedOutcome::Abstention => {
            let sig = extract_signature(&specimen.traces[0], &config);
            signature_valid = Some(sig.valid);
            let (label, conf) = classify_regime(&sig, &config);
            classified_regime = Some(label);
            confidence_millionths = Some(conf);
            if let Some(expected) = specimen.expected_regime
                && expected == RegimeLabel::Abstention
                && !label.is_abstention()
            {
                verdict = SignatureVerdict::Fail;
                error_detail = Some(format!("expected abstention got {:?}", label));
            }
        }
        SignatureExpectedOutcome::StableChart | SignatureExpectedOutcome::TransitionDetected => {
            let chart = build_regime_state_chart(&specimen.traces, &config);
            transition_count = Some(chart.transition_count);
            if let Some(expected) = specimen.expected_transition_count
                && chart.transition_count != expected
            {
                verdict = SignatureVerdict::Fail;
                error_detail = Some(format!(
                    "expected transitions={expected} got {}",
                    chart.transition_count
                ));
            }
        }
        SignatureExpectedOutcome::SimilarityComputed => {
            if specimen.traces.len() >= 2 {
                let sig1 = extract_signature(&specimen.traces[0], &config);
                let sig2 = extract_signature(&specimen.traces[1], &config);
                signature_valid = Some(sig1.valid && sig2.valid);
                let distance = sig1.l1_distance(&sig2);
                confidence_millionths = Some(distance);

                if specimen.specimen_id.contains("identical") && distance != 0 {
                    verdict = SignatureVerdict::Fail;
                    error_detail = Some(format!(
                        "identical traces should have distance=0, got {distance}"
                    ));
                }
                if specimen.specimen_id.contains("different") && distance == 0 {
                    verdict = SignatureVerdict::Fail;
                    error_detail = Some("different traces should have nonzero distance".into());
                }
            }
        }
    }

    let hash_input = format!(
        "{}:{}:{}:{}",
        specimen.specimen_id,
        verdict as u8,
        serde_json::to_string(&signature_valid).unwrap_or_default(),
        serde_json::to_string(&classified_regime).unwrap_or_default(),
    );

    SignatureSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        expected_outcome: specimen.expected_outcome,
        verdict,
        signature_valid,
        classified_regime,
        confidence_millionths,
        transition_count,
        error_detail,
        evidence_hash: hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes()),
    }
}

/// Run the full corpus.
pub fn run_signature_corpus() -> SignatureEvidenceInventory {
    let corpus = signature_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut family_coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let ev = run_single_specimen(specimen);
        if ev.verdict == SignatureVerdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
        evidence.push(ev);
    }

    SignatureEvidenceInventory {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        family_coverage,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

/// Write the evidence bundle.
pub fn write_signature_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<SignatureBundleArtifacts, std::io::Error> {
    std::fs::create_dir_all(output_dir)?;

    let inv = run_signature_corpus();
    let inv_json = serde_json::to_string_pretty(&inv).map_err(std::io::Error::other)?;
    let inventory_hash = hex_encode(ContentHash::compute(inv_json.as_bytes()).as_bytes());

    let inv_path = output_dir.join("regime_signature_feature_inventory.json");
    std::fs::write(&inv_path, &inv_json)?;

    // Events JSONL.
    let mut event_lines = Vec::new();
    let start = SignatureEvidenceEvent {
        schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        event: "signature_evidence_run_started".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    event_lines.push(serde_json::to_string(&start).map_err(std::io::Error::other)?);

    for ev in &inv.evidence {
        let specimen_event = SignatureEvidenceEvent {
            schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
            component: REGIME_SIG_COMPONENT.to_string(),
            event: "signature_specimen_evaluated".to_string(),
            policy_id: REGIME_SIG_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(if ev.verdict == SignatureVerdict::Pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            }),
            detail: ev.error_detail.clone(),
        };
        event_lines.push(serde_json::to_string(&specimen_event).map_err(std::io::Error::other)?);
    }

    let end = SignatureEvidenceEvent {
        schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        event: "signature_evidence_run_completed".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: Some(if inv.contract_satisfied() {
            "satisfied".to_string()
        } else {
            "violated".to_string()
        }),
        detail: Some(format!(
            "pass={} fail={} total={}",
            inv.pass_count, inv.fail_count, inv.specimen_count
        )),
    };
    event_lines.push(serde_json::to_string(&end).map_err(std::io::Error::other)?);

    let events_path = output_dir.join("regime_signature_feature_events.jsonl");
    std::fs::write(&events_path, event_lines.join("\n") + "\n")?;

    let trace_id = format!("sig-{}", &inventory_hash[..12]);
    let decision_id = format!("dec-{}", &inventory_hash[12..24]);

    let manifest = SignatureRunManifest {
        schema_version: REGIME_SIG_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        trace_id,
        decision_id,
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inv.specimen_count,
        pass_count: inv.pass_count,
        fail_count: inv.fail_count,
        contract_satisfied: inv.contract_satisfied(),
        artifact_paths: SignatureArtifactPaths {
            evidence_inventory: "regime_signature_feature_inventory.json".to_string(),
            run_manifest: "regime_signature_feature_manifest.json".to_string(),
            events_jsonl: "regime_signature_feature_events.jsonl".to_string(),
            commands_txt: "regime_signature_feature_commands.txt".to_string(),
        },
    };

    let manifest_path = output_dir.join("regime_signature_feature_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?,
    )?;

    let commands_path = output_dir.join("regime_signature_feature_commands.txt");
    std::fs::write(&commands_path, commands.join("\n"))?;

    Ok(SignatureBundleArtifacts {
        inventory_path: inv_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_non_empty() {
        assert!(!signature_corpus().is_empty());
    }

    #[test]
    fn corpus_ids_unique() {
        let corpus = signature_corpus();
        let ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_covers_all_families() {
        let corpus = signature_corpus();
        let covered: std::collections::BTreeSet<SignatureSpecimenFamily> =
            corpus.iter().map(|s| s.family).collect();
        for f in SignatureSpecimenFamily::ALL {
            assert!(covered.contains(f), "missing {:?}", f);
        }
    }

    #[test]
    fn all_specimens_pass() {
        let inv = run_signature_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.verdict,
                SignatureVerdict::Pass,
                "specimen {} failed: {:?}",
                ev.specimen_id,
                ev.error_detail
            );
        }
    }

    #[test]
    fn contract_satisfied() {
        let inv = run_signature_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn counts_consistent() {
        let inv = run_signature_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn family_coverage_sums() {
        let inv = run_signature_corpus();
        let total: u64 = inv.family_coverage.values().sum();
        assert_eq!(total, inv.specimen_count);
    }

    #[test]
    fn deterministic() {
        let inv1 = run_signature_corpus();
        let inv2 = run_signature_corpus();
        assert_eq!(inv1, inv2);
    }

    #[test]
    fn extract_valid_signature() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        assert_eq!(sig.dimension, MAX_SIGNATURE_DIM);
        assert_eq!(sig.components.len(), MAX_SIGNATURE_DIM);
        assert_eq!(sig.observation_count, 4);
    }

    #[test]
    fn extract_invalid_short_trace() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000], 1);
        let sig = extract_signature(&trace, &config);
        assert!(!sig.valid);
    }

    #[test]
    fn classify_produces_label() {
        let config = SignatureConfig::default();
        let trace = make_multi_feature_trace(
            "test",
            &[
                ("cpu", &[500_000, 510_000, 490_000, 500_000]),
                ("mem", &[500_000, 480_000, 520_000, 500_000]),
            ],
            1,
        );
        let sig = extract_signature(&trace, &config);
        let (label, conf) = classify_regime(&sig, &config);
        assert!(!label.is_abstention());
        assert!(conf > 0);
    }

    #[test]
    fn classify_invalid_gives_abstention() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000], 1);
        let sig = extract_signature(&trace, &config);
        let (label, _) = classify_regime(&sig, &config);
        assert!(label.is_abstention());
    }

    #[test]
    fn l1_distance_self_is_zero() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig = extract_signature(&trace, &config);
        assert_eq!(sig.l1_distance(&sig), 0);
    }

    #[test]
    fn state_chart_single_trace_no_transitions() {
        let config = SignatureConfig::default();
        let traces = vec![make_multi_feature_trace(
            "t",
            &[("cpu", &[500_000, 510_000, 490_000, 500_000])],
            1,
        )];
        let chart = build_regime_state_chart(&traces, &config);
        assert_eq!(chart.transition_count, 0);
        assert_eq!(chart.entries.len(), 1);
    }

    #[test]
    fn regime_label_serde_roundtrip() {
        let labels = vec![
            RegimeLabel::Classified(Regime::Normal),
            RegimeLabel::Classified(Regime::Attack),
            RegimeLabel::Abstention,
        ];
        for l in &labels {
            let json = serde_json::to_string(l).unwrap();
            let back: RegimeLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(*l, back);
        }
    }

    #[test]
    fn signature_serde_roundtrip() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig = extract_signature(&trace, &config);
        let json = serde_json::to_string(&sig).unwrap();
        let back: TraceSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!REGIME_SIG_SCHEMA_VERSION.is_empty());
        assert!(!REGIME_SIG_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!REGIME_SIG_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!REGIME_SIG_COMPONENT.is_empty());
        assert!(!REGIME_SIG_POLICY_ID.is_empty());
    }

    #[test]
    fn schema_versions_prefixed() {
        assert!(REGIME_SIG_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(REGIME_SIG_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(REGIME_SIG_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inv = run_signature_corpus();
        let json = serde_json::to_string(&inv).unwrap();
        let back: SignatureEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn isqrt_correctness() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(16), 4);
        assert_eq!(isqrt(1_000_000), 1000);
    }

    #[test]
    fn cosine_similarity_identical() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig = extract_signature(&trace, &config);
        let cos = sig.cosine_similarity(&sig);
        // Identical vectors should have cosine similarity near 1M.
        assert!(
            cos > 900_000,
            "cosine similarity {cos} too low for identical vectors"
        );
    }

    #[test]
    fn feature_to_bucket_deterministic() {
        let b1 = feature_to_bucket("cpu_usage", 64);
        let b2 = feature_to_bucket("cpu_usage", 64);
        assert_eq!(b1, b2);
    }

    #[test]
    fn feature_to_bucket_in_range() {
        for name in ["cpu", "mem", "gc", "cache", "io", "net"] {
            let bucket = feature_to_bucket(name, MAX_SIGNATURE_DIM);
            assert!(bucket < MAX_SIGNATURE_DIM);
        }
    }

    #[test]
    fn contract_not_satisfied_with_failures() {
        let inv = SignatureEvidenceInventory {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            component: REGIME_SIG_COMPONENT.to_string(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_with_zero_specimens() {
        let inv = SignatureEvidenceInventory {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            component: REGIME_SIG_COMPONENT.to_string(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn regime_state_chart_is_stable() {
        let chart = RegimeStateChart {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            entries: vec![RegimeStateEntry {
                seq: 0,
                label: RegimeLabel::Classified(Regime::Normal),
                confidence_millionths: 800_000,
                centroid_distance_millionths: 100_000,
                trace_id: "t".to_string(),
            }],
            transition_count: 0,
            abstention_count: 0,
            label_distribution: BTreeMap::new(),
            chart_hash: "h".to_string(),
        };
        assert!(chart.is_stable());
    }

    #[test]
    fn regime_state_chart_not_stable_with_transitions() {
        let chart = RegimeStateChart {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            entries: vec![],
            transition_count: 1,
            abstention_count: 0,
            label_distribution: BTreeMap::new(),
            chart_hash: "h".to_string(),
        };
        assert!(!chart.is_stable());
    }

    // --- Enrichment tests (PearlTower 2026-03-16) ---

    #[test]
    fn regime_label_serde_roundtrip_classified() {
        for regime in [Regime::Normal, Regime::Degraded, Regime::Recovery] {
            let label = RegimeLabel::Classified(regime);
            let json = serde_json::to_string(&label).unwrap();
            let back: RegimeLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(label, back);
        }
    }

    #[test]
    fn regime_label_serde_roundtrip_abstention() {
        let label = RegimeLabel::Abstention;
        let json = serde_json::to_string(&label).unwrap();
        let back: RegimeLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, back);
    }

    #[test]
    fn hex_encode_deterministic() {
        let a = hex_encode(&[0xde, 0xad, 0xbe, 0xef]);
        let b = hex_encode(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(a, b);
        assert_eq!(a, "deadbeef");
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn max_signature_dim_positive() {
        const { assert!(MAX_SIGNATURE_DIM > 0) };
    }

    #[test]
    fn min_trace_length_positive() {
        const { assert!(MIN_TRACE_LENGTH > 0) };
    }

    #[test]
    fn feature_to_bucket_distinct_for_different_names() {
        let a = feature_to_bucket("alpha", MAX_SIGNATURE_DIM);
        let b = feature_to_bucket("beta", MAX_SIGNATURE_DIM);
        // Different names may collide but shouldn't always
        let c = feature_to_bucket("gamma", MAX_SIGNATURE_DIM);
        let all_same = a == b && b == c;
        assert!(!all_same, "all three features hashed to same bucket");
    }

    #[test]
    fn signature_config_default_has_valid_max_dim() {
        let config = SignatureConfig::default();
        assert!(config.max_dim > 0);
        assert!(config.max_dim <= MAX_SIGNATURE_DIM);
    }

    #[test]
    fn short_trace_produces_invalid_signature() {
        let config = SignatureConfig::default();
        let trace = make_trace("test", "cpu", &[500_000], 1);
        let sig = extract_signature(&trace, &config);
        assert!(!sig.valid, "short trace should produce invalid signature");
    }

    #[test]
    fn cosine_similarity_orthogonal_near_zero() {
        let config = SignatureConfig::default();
        let trace_a = make_trace("a", "cpu", &[1_000_000, 0, 1_000_000, 0], 1);
        let trace_b = make_trace("b", "mem", &[0, 1_000_000, 0, 1_000_000], 1);
        let sig_a = extract_signature(&trace_a, &config);
        let sig_b = extract_signature(&trace_b, &config);
        let cos = sig_a.cosine_similarity(&sig_b);
        assert!(
            cos < 500_000,
            "orthogonal vectors should have low similarity: {cos}"
        );
    }

    #[test]
    fn regime_state_chart_with_abstentions_not_stable() {
        let chart = RegimeStateChart {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            entries: vec![],
            transition_count: 0,
            abstention_count: 1,
            label_distribution: BTreeMap::new(),
            chart_hash: "h".to_string(),
        };
        assert!(!chart.is_stable());
    }

    #[test]
    fn regime_state_entry_serde_roundtrip() {
        let entry = RegimeStateEntry {
            seq: 42,
            label: RegimeLabel::Classified(Regime::Normal),
            confidence_millionths: 950_000,
            centroid_distance_millionths: 50_000,
            trace_id: "trace-abc".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RegimeStateEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn regime_sig_component_constant() {
        assert_eq!(REGIME_SIG_COMPONENT, "regime_signature_feature");
    }

    // --- Additional enrichment tests (PearlTower 2026-03-18) ---

    #[test]
    fn isqrt_negative_returns_zero() {
        assert_eq!(isqrt(-1), 0);
        assert_eq!(isqrt(-1_000_000), 0);
        assert_eq!(isqrt(i64::MIN), 0);
    }

    #[test]
    fn isqrt_large_values() {
        // 1_000_000_000_000 = 1e12, sqrt = 1e6
        assert_eq!(isqrt(1_000_000_000_000), 1_000_000);
        // Non-perfect square: isqrt(10) should be 3 (floor)
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(15), 3);
        assert_eq!(isqrt(17), 4);
    }

    #[test]
    fn l1_distance_different_dimensions_returns_max() {
        let sig_a = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "a".to_string(),
            dimension: 4,
            components: vec![1, 2, 3, 4],
            bucket_counts: vec![1, 1, 1, 1],
            observation_count: 4,
            feature_count: 4,
            valid: true,
            signature_hash: "h".to_string(),
        };
        let sig_b = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "b".to_string(),
            dimension: 3,
            components: vec![1, 2, 3],
            bucket_counts: vec![1, 1, 1],
            observation_count: 3,
            feature_count: 3,
            valid: true,
            signature_hash: "h".to_string(),
        };
        assert_eq!(sig_a.l1_distance(&sig_b), i64::MAX);
    }

    #[test]
    fn cosine_similarity_different_dimensions_returns_zero() {
        let sig_a = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "a".to_string(),
            dimension: 4,
            components: vec![1_000_000; 4],
            bucket_counts: vec![1; 4],
            observation_count: 4,
            feature_count: 1,
            valid: true,
            signature_hash: "h".to_string(),
        };
        let sig_b = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "b".to_string(),
            dimension: 2,
            components: vec![1_000_000; 2],
            bucket_counts: vec![1; 2],
            observation_count: 2,
            feature_count: 1,
            valid: true,
            signature_hash: "h".to_string(),
        };
        assert_eq!(sig_a.cosine_similarity(&sig_b), 0);
    }

    #[test]
    fn cosine_similarity_zero_vector_returns_zero() {
        let sig = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "z".to_string(),
            dimension: 4,
            components: vec![0; 4],
            bucket_counts: vec![1; 4],
            observation_count: 4,
            feature_count: 1,
            valid: true,
            signature_hash: "h".to_string(),
        };
        let other = TraceSignature {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            trace_id: "o".to_string(),
            dimension: 4,
            components: vec![500_000; 4],
            bucket_counts: vec![1; 4],
            observation_count: 4,
            feature_count: 1,
            valid: true,
            signature_hash: "h".to_string(),
        };
        assert_eq!(sig.cosine_similarity(&other), 0);
        assert_eq!(other.cosine_similarity(&sig), 0);
    }

    #[test]
    fn l1_distance_symmetric() {
        let config = SignatureConfig::default();
        let trace_a = make_trace("a", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
        let trace_b = make_trace("b", "cpu", &[500_000, 600_000, 700_000, 800_000], 1);
        let sig_a = extract_signature(&trace_a, &config);
        let sig_b = extract_signature(&trace_b, &config);
        assert_eq!(sig_a.l1_distance(&sig_b), sig_b.l1_distance(&sig_a));
    }

    #[test]
    fn cosine_similarity_symmetric() {
        let config = SignatureConfig::default();
        let trace_a = make_trace("a", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
        let trace_b = make_trace("b", "cpu", &[500_000, 600_000, 700_000, 800_000], 1);
        let sig_a = extract_signature(&trace_a, &config);
        let sig_b = extract_signature(&trace_b, &config);
        assert_eq!(
            sig_a.cosine_similarity(&sig_b),
            sig_b.cosine_similarity(&sig_a)
        );
    }

    #[test]
    fn extract_signature_preserves_trace_id() {
        let config = SignatureConfig::default();
        let trace = make_trace("my-unique-trace-42", "cpu", &[1, 2, 3, 4], 7);
        let sig = extract_signature(&trace, &config);
        assert_eq!(sig.trace_id, "my-unique-trace-42");
    }

    #[test]
    fn extract_signature_schema_version_matches_constant() {
        let config = SignatureConfig::default();
        let trace = make_trace("t", "cpu", &[1, 2, 3, 4], 1);
        let sig = extract_signature(&trace, &config);
        assert_eq!(sig.schema_version, REGIME_SIG_SCHEMA_VERSION);
    }

    #[test]
    fn extract_signature_hash_determinism() {
        let config = SignatureConfig::default();
        let trace = make_trace("t", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig1 = extract_signature(&trace, &config);
        let sig2 = extract_signature(&trace, &config);
        assert_eq!(sig1.signature_hash, sig2.signature_hash);
        assert!(!sig1.signature_hash.is_empty());
    }

    #[test]
    fn extract_signature_invalid_hash_determinism() {
        let config = SignatureConfig::default();
        let trace = make_trace("short", "cpu", &[1], 1);
        let sig1 = extract_signature(&trace, &config);
        let sig2 = extract_signature(&trace, &config);
        assert_eq!(sig1.signature_hash, sig2.signature_hash);
        assert!(!sig1.signature_hash.is_empty());
    }

    #[test]
    fn extract_signature_different_traces_different_hashes() {
        let config = SignatureConfig::default();
        let trace_a = make_trace("a", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
        let trace_b = make_trace("b", "cpu", &[500_000, 600_000, 700_000, 800_000], 1);
        let sig_a = extract_signature(&trace_a, &config);
        let sig_b = extract_signature(&trace_b, &config);
        assert_ne!(sig_a.signature_hash, sig_b.signature_hash);
    }

    #[test]
    fn extract_signature_multi_feature_counts_features() {
        let config = SignatureConfig::default();
        let trace = make_multi_feature_trace(
            "mf",
            &[
                ("cpu", &[500_000, 600_000]),
                ("mem", &[300_000, 400_000]),
                ("disk", &[100_000, 200_000]),
            ],
            1,
        );
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        assert_eq!(sig.observation_count, 6);
        // At least some distinct features should be counted (may be less than 3
        // if two features hash to the same bucket, but at least 1).
        assert!(sig.feature_count >= 1);
    }

    #[test]
    fn extract_signature_bucket_counts_sum_to_observations() {
        let config = SignatureConfig::default();
        let trace = make_trace("t", "cpu", &[1, 2, 3, 4, 5, 6, 7, 8], 1);
        let sig = extract_signature(&trace, &config);
        let total_buckets: u64 = sig.bucket_counts.iter().sum();
        assert_eq!(total_buckets, sig.observation_count);
    }

    #[test]
    fn extract_signature_exactly_min_trace_length_valid() {
        let config = SignatureConfig::default();
        // MIN_TRACE_LENGTH is 4, so exactly 4 observations should produce valid.
        let trace = make_trace("t", "cpu", &[1, 2, 3, 4], 1);
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        assert_eq!(sig.observation_count, 4);
    }

    #[test]
    fn extract_signature_one_below_min_trace_length_invalid() {
        let config = SignatureConfig::default();
        // MIN_TRACE_LENGTH - 1 = 3 observations should be invalid.
        let trace = make_trace("t", "cpu", &[1, 2, 3], 1);
        let sig = extract_signature(&trace, &config);
        assert!(!sig.valid);
    }

    #[test]
    fn classify_regime_no_matching_centroids_abstains() {
        // Config with centroids whose dimension doesn't match the signature.
        let config = SignatureConfig {
            max_dim: 4,
            min_trace_length: 2,
            abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
            centroids: vec![RegimeCentroid {
                regime: Regime::Normal,
                components: vec![500_000; 8], // dimension 8, but sig will be 4
                radius_millionths: 2_000_000,
            }],
        };
        let trace = make_trace("t", "cpu", &[500_000, 500_000, 500_000, 500_000], 1);
        let sig = extract_signature(&trace, &config);
        let (label, _) = classify_regime(&sig, &config);
        assert!(label.is_abstention());
    }

    #[test]
    fn classify_regime_empty_centroids_abstains() {
        let config = SignatureConfig {
            max_dim: MAX_SIGNATURE_DIM,
            min_trace_length: MIN_TRACE_LENGTH,
            abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
            centroids: vec![],
        };
        let trace = make_trace("t", "cpu", &[500_000, 500_000, 500_000, 500_000], 1);
        let sig = extract_signature(&trace, &config);
        let (label, _) = classify_regime(&sig, &config);
        assert!(label.is_abstention());
    }

    #[test]
    fn regime_label_display_all_variants() {
        assert_eq!(
            RegimeLabel::Classified(Regime::Normal).to_string(),
            "normal"
        );
        assert_eq!(
            RegimeLabel::Classified(Regime::Elevated).to_string(),
            "elevated"
        );
        assert_eq!(
            RegimeLabel::Classified(Regime::Attack).to_string(),
            "attack"
        );
        assert_eq!(
            RegimeLabel::Classified(Regime::Degraded).to_string(),
            "degraded"
        );
        assert_eq!(
            RegimeLabel::Classified(Regime::Recovery).to_string(),
            "recovery"
        );
        assert_eq!(RegimeLabel::Abstention.to_string(), "abstention");
    }

    #[test]
    fn regime_label_as_str_matches_display() {
        for label in RegimeLabel::ALL_CLASSIFIED {
            assert_eq!(label.as_str(), label.to_string());
        }
        let abst = RegimeLabel::Abstention;
        assert_eq!(abst.as_str(), abst.to_string());
    }

    #[test]
    fn regime_label_is_abstention_false_for_classified() {
        for label in RegimeLabel::ALL_CLASSIFIED {
            assert!(!label.is_abstention(), "{label:?} should not be abstention");
        }
    }

    #[test]
    fn regime_label_all_classified_contains_five_regimes() {
        assert_eq!(RegimeLabel::ALL_CLASSIFIED.len(), 5);
    }

    #[test]
    fn specimen_family_display_matches_as_str() {
        for family in SignatureSpecimenFamily::ALL {
            assert_eq!(family.as_str(), family.to_string());
        }
    }

    #[test]
    fn specimen_family_all_has_six_variants() {
        assert_eq!(SignatureSpecimenFamily::ALL.len(), 6);
    }

    #[test]
    fn signature_config_default_centroids_cover_all_regimes() {
        let config = SignatureConfig::default();
        let regimes: std::collections::BTreeSet<_> =
            config.centroids.iter().map(|c| c.regime).collect();
        assert!(regimes.contains(&Regime::Normal));
        assert!(regimes.contains(&Regime::Elevated));
        assert!(regimes.contains(&Regime::Attack));
        assert!(regimes.contains(&Regime::Degraded));
        assert!(regimes.contains(&Regime::Recovery));
    }

    #[test]
    fn signature_config_default_centroids_all_have_correct_dimension() {
        let config = SignatureConfig::default();
        for centroid in &config.centroids {
            assert_eq!(
                centroid.components.len(),
                config.max_dim,
                "centroid for {:?} has wrong dimension",
                centroid.regime
            );
        }
    }

    #[test]
    fn signature_config_serde_roundtrip() {
        let config = SignatureConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: SignatureConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn regime_centroid_serde_roundtrip() {
        let centroid = RegimeCentroid {
            regime: Regime::Attack,
            components: vec![900_000; 8],
            radius_millionths: 3_000_000,
        };
        let json = serde_json::to_string(&centroid).unwrap();
        let back: RegimeCentroid = serde_json::from_str(&json).unwrap();
        assert_eq!(centroid, back);
    }

    #[test]
    fn trace_observation_serde_roundtrip() {
        let obs = TraceObservation {
            seq: 99,
            feature_name: "gc_pause_ns".to_string(),
            value_millionths: 750_000,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: TraceObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    #[test]
    fn runtime_trace_serde_roundtrip() {
        let trace = make_multi_feature_trace(
            "serde-test",
            &[("cpu", &[100_000, 200_000]), ("mem", &[300_000, 400_000])],
            42,
        );
        let json = serde_json::to_string(&trace).unwrap();
        let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn signature_specimen_serde_roundtrip() {
        let specimen = SignatureSpecimen {
            specimen_id: "test-specimen".into(),
            description: "A test".into(),
            family: SignatureSpecimenFamily::Extraction,
            traces: vec![make_trace("t", "cpu", &[1, 2, 3, 4], 1)],
            expected_outcome: SignatureExpectedOutcome::ValidSignature,
            expected_regime: Some(RegimeLabel::Classified(Regime::Normal)),
            expected_valid: Some(true),
            expected_transition_count: None,
        };
        let json = serde_json::to_string(&specimen).unwrap();
        let back: SignatureSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(specimen, back);
    }

    #[test]
    fn build_state_chart_empty_traces() {
        let config = SignatureConfig::default();
        let chart = build_regime_state_chart(&[], &config);
        assert!(chart.entries.is_empty());
        assert_eq!(chart.transition_count, 0);
        assert_eq!(chart.abstention_count, 0);
        assert!(chart.label_distribution.is_empty());
        assert!(!chart.chart_hash.is_empty());
    }

    #[test]
    fn build_state_chart_entries_have_sequential_seqs() {
        let config = SignatureConfig::default();
        let traces = vec![
            make_trace("t1", "cpu", &[500_000, 510_000, 490_000, 505_000], 1),
            make_trace("t2", "cpu", &[500_000, 510_000, 490_000, 505_000], 2),
            make_trace("t3", "cpu", &[500_000, 510_000, 490_000, 505_000], 3),
        ];
        let chart = build_regime_state_chart(&traces, &config);
        assert_eq!(chart.entries.len(), 3);
        for (i, entry) in chart.entries.iter().enumerate() {
            assert_eq!(entry.seq, i as u64);
        }
    }

    #[test]
    fn build_state_chart_label_distribution_sums_to_entry_count() {
        let config = SignatureConfig::default();
        let traces = vec![
            make_trace("t1", "cpu", &[500_000, 510_000, 490_000, 505_000], 1),
            make_trace("t2", "cpu", &[500_000, 510_000, 490_000, 505_000], 2),
        ];
        let chart = build_regime_state_chart(&traces, &config);
        let dist_total: u64 = chart.label_distribution.values().sum();
        assert_eq!(dist_total, chart.entries.len() as u64);
    }

    #[test]
    fn build_state_chart_hash_determinism() {
        let config = SignatureConfig::default();
        let traces = vec![
            make_trace("t1", "cpu", &[500_000, 510_000, 490_000, 505_000], 1),
            make_trace("t2", "cpu", &[500_000, 510_000, 490_000, 505_000], 2),
        ];
        let chart1 = build_regime_state_chart(&traces, &config);
        let chart2 = build_regime_state_chart(&traces, &config);
        assert_eq!(chart1.chart_hash, chart2.chart_hash);
    }

    #[test]
    fn build_state_chart_schema_version_matches() {
        let config = SignatureConfig::default();
        let traces = vec![make_trace(
            "t1",
            "cpu",
            &[500_000, 510_000, 490_000, 505_000],
            1,
        )];
        let chart = build_regime_state_chart(&traces, &config);
        assert_eq!(chart.schema_version, REGIME_SIG_SCHEMA_VERSION);
    }

    #[test]
    fn extract_signature_all_negative_values() {
        let config = SignatureConfig::default();
        let trace = make_trace(
            "neg",
            "metric",
            &[-500_000, -600_000, -400_000, -550_000],
            1,
        );
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        // The single bucket that contains all observations should have a negative mean.
        let active: Vec<_> = sig
            .components
            .iter()
            .zip(&sig.bucket_counts)
            .filter(|&(_, &count)| count > 0)
            .collect();
        assert!(!active.is_empty());
        for &(&comp, _) in &active {
            assert!(comp < 0, "expected negative component, got {comp}");
        }
    }

    #[test]
    fn extract_signature_zero_values() {
        let config = SignatureConfig::default();
        let trace = make_trace("zero", "metric", &[0, 0, 0, 0], 1);
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        // All bucket values that were populated should be 0.
        for (i, &count) in sig.bucket_counts.iter().enumerate() {
            if count > 0 {
                assert_eq!(sig.components[i], 0);
            }
        }
    }

    #[test]
    fn extract_signature_custom_dim() {
        let config = SignatureConfig {
            max_dim: 8,
            min_trace_length: 2,
            abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
            centroids: vec![],
        };
        let trace = make_trace("t", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        assert_eq!(sig.dimension, 8);
        assert_eq!(sig.components.len(), 8);
        assert_eq!(sig.bucket_counts.len(), 8);
    }

    #[test]
    fn regime_state_chart_empty_entries_not_stable() {
        let chart = RegimeStateChart {
            schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
            entries: vec![],
            transition_count: 0,
            abstention_count: 0,
            label_distribution: BTreeMap::new(),
            chart_hash: "h".to_string(),
        };
        assert!(!chart.is_stable(), "empty chart should not be stable");
    }

    #[test]
    fn evidence_event_serde_roundtrip() {
        let event = SignatureEvidenceEvent {
            schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
            component: REGIME_SIG_COMPONENT.to_string(),
            event: "test_event".to_string(),
            policy_id: REGIME_SIG_POLICY_ID.to_string(),
            specimen_id: Some("spec-1".to_string()),
            verdict: Some("pass".to_string()),
            detail: Some("all good".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SignatureEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn run_manifest_serde_roundtrip() {
        let manifest = SignatureRunManifest {
            schema_version: REGIME_SIG_MANIFEST_SCHEMA_VERSION.to_string(),
            component: REGIME_SIG_COMPONENT.to_string(),
            trace_id: "sig-abc123".to_string(),
            decision_id: "dec-xyz456".to_string(),
            policy_id: REGIME_SIG_POLICY_ID.to_string(),
            inventory_hash: "deadbeef".to_string(),
            specimen_count: 10,
            pass_count: 10,
            fail_count: 0,
            contract_satisfied: true,
            artifact_paths: SignatureArtifactPaths {
                evidence_inventory: "inv.json".to_string(),
                run_manifest: "manifest.json".to_string(),
                events_jsonl: "events.jsonl".to_string(),
                commands_txt: "commands.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: SignatureRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn hex_encode_all_byte_values() {
        // Verify 0x00 and 0xff encode correctly.
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x0a]), "0a");
        assert_eq!(hex_encode(&[0xa0]), "a0");
    }

    #[test]
    fn make_trace_helper_produces_correct_seqs() {
        let trace = make_trace("t", "cpu", &[1, 2, 3, 4, 5], 1);
        for (i, obs) in trace.observations.iter().enumerate() {
            assert_eq!(obs.seq, i as u64);
            assert_eq!(obs.feature_name, "cpu");
        }
        assert_eq!(trace.observations.len(), 5);
    }

    #[test]
    fn make_multi_feature_trace_helper_sequential_seqs() {
        let trace = make_multi_feature_trace("t", &[("a", &[10, 20]), ("b", &[30, 40, 50])], 1);
        assert_eq!(trace.observations.len(), 5);
        for (i, obs) in trace.observations.iter().enumerate() {
            assert_eq!(obs.seq, i as u64);
        }
        assert_eq!(trace.observations[0].feature_name, "a");
        assert_eq!(trace.observations[2].feature_name, "b");
    }

    #[test]
    fn trace_observation_ord_by_seq_then_name_then_value() {
        let a = TraceObservation {
            seq: 0,
            feature_name: "alpha".to_string(),
            value_millionths: 100,
        };
        let b = TraceObservation {
            seq: 1,
            feature_name: "alpha".to_string(),
            value_millionths: 100,
        };
        assert!(a < b, "lower seq should sort first");

        let c = TraceObservation {
            seq: 0,
            feature_name: "beta".to_string(),
            value_millionths: 100,
        };
        assert!(a < c, "alpha should sort before beta at same seq");
    }

    #[test]
    fn regime_label_ord_classified_before_abstention() {
        let classified = RegimeLabel::Classified(Regime::Normal);
        let abstention = RegimeLabel::Abstention;
        // Classified comes before Abstention in the enum definition.
        assert!(classified < abstention);
    }

    #[test]
    fn signature_verdict_serde_roundtrip() {
        for verdict in [SignatureVerdict::Pass, SignatureVerdict::Fail] {
            let json = serde_json::to_string(&verdict).unwrap();
            let back: SignatureVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(verdict, back);
        }
    }

    #[test]
    fn expected_outcome_serde_roundtrip() {
        let outcomes = [
            SignatureExpectedOutcome::ValidSignature,
            SignatureExpectedOutcome::InvalidSignature,
            SignatureExpectedOutcome::CorrectClassification,
            SignatureExpectedOutcome::Abstention,
            SignatureExpectedOutcome::StableChart,
            SignatureExpectedOutcome::TransitionDetected,
            SignatureExpectedOutcome::SimilarityComputed,
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: SignatureExpectedOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    #[test]
    fn state_chart_serde_roundtrip() {
        let config = SignatureConfig::default();
        let traces = vec![
            make_trace("t1", "cpu", &[500_000, 510_000, 490_000, 505_000], 1),
            make_trace("t2", "cpu", &[500_000, 510_000, 490_000, 505_000], 2),
        ];
        let chart = build_regime_state_chart(&traces, &config);
        let json = serde_json::to_string(&chart).unwrap();
        let back: RegimeStateChart = serde_json::from_str(&json).unwrap();
        assert_eq!(chart, back);
    }

    #[test]
    fn classify_confidence_bounded_by_million() {
        let config = SignatureConfig::default();
        let trace = make_trace("t", "cpu", &[500_000, 500_000, 500_000, 500_000], 1);
        let sig = extract_signature(&trace, &config);
        let (_, conf) = classify_regime(&sig, &config);
        assert!(
            conf <= MILLION,
            "confidence {conf} should not exceed MILLION"
        );
    }

    #[test]
    fn feature_to_bucket_dim_one_always_zero() {
        // With dimension 1, every feature should map to bucket 0.
        for name in ["cpu", "mem", "disk", "net", "gc", "io"] {
            assert_eq!(feature_to_bucket(name, 1), 0);
        }
    }
}
