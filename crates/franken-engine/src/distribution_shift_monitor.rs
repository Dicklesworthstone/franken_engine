#![forbid(unsafe_code)]

//! Sliding-window kernelized shift monitors for benchmark vs live workload
//! streams.
//!
//! Implements [RGC-706A]: detects when the declared benchmark board no longer
//! reflects actual production workload distribution by comparing
//! kernel-mean-embeddings over sliding windows of workload features, using
//! the Maximum Mean Discrepancy (MMD) statistic.
//!
//! # Design decisions
//!
//! - **Fixed-point millionths** — all scores, thresholds, and kernel outputs
//!   use `u64` with `1_000_000 = 1.0` for full determinism.
//! - **Kernel-mean-embedding** — each window of observations is summarized
//!   by its mean embedding in a reproducing-kernel Hilbert space.
//! - **MMD (Maximum Mean Discrepancy)** — the squared distance between two
//!   KME summaries serves as a calibrated test statistic.
//! - **Sliding windows** — configurable window size and slide step.
//! - **Explicit abstention** — insufficient data triggers `Abstained` or
//!   `InsufficientSamples` rather than a wrong answer.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for distribution-shift-monitor artifacts.
pub const SHIFT_MONITOR_SCHEMA_VERSION: &str = "franken-engine.distribution-shift-monitor.v1";

/// Component name.
pub const SHIFT_MONITOR_COMPONENT: &str = "distribution_shift_monitor";

/// Policy identifier.
pub const SHIFT_MONITOR_POLICY_ID: &str = "RGC-706A";

/// Fixed-point unit: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// StreamKind
// ---------------------------------------------------------------------------

/// Which stream a window of embeddings originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    /// Benchmark workload stream.
    Benchmark,
    /// Live (production) workload stream.
    LiveWorkload,
}

impl fmt::Display for StreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Benchmark => write!(f, "benchmark"),
            Self::LiveWorkload => write!(f, "live_workload"),
        }
    }
}

// ---------------------------------------------------------------------------
// WindowConfig
// ---------------------------------------------------------------------------

/// Configuration for a sliding window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Number of observations per window.
    pub window_size: u64,
    /// Number of observations to slide forward.
    pub slide_step: u64,
    /// Minimum number of samples before producing a verdict.
    pub min_samples: u64,
}

// ---------------------------------------------------------------------------
// KernelKind
// ---------------------------------------------------------------------------

/// Kernel function for computing similarity in the RKHS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelKind {
    /// Linear (dot product) kernel.
    Linear,
    /// Polynomial kernel with the given degree.
    Polynomial {
        /// Polynomial degree.
        degree: u32,
    },
    /// Gaussian RBF kernel with the given bandwidth (millionths).
    GaussianRbf {
        /// Bandwidth parameter in millionths (1_000_000 = 1.0).
        bandwidth_millionths: u64,
    },
}

// ---------------------------------------------------------------------------
// EmbeddingVector
// ---------------------------------------------------------------------------

/// A fixed-point embedding vector with provenance hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingVector {
    /// Dimension values in millionths (1_000_000 = 1.0 per component).
    pub dimensions: Vec<u64>,
    /// Content hash of the source data that produced this embedding.
    pub source_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// StreamWindow
// ---------------------------------------------------------------------------

/// A window of embedding observations from a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamWindow {
    /// Which stream this window belongs to.
    pub stream_kind: StreamKind,
    /// Start index (inclusive) in the observation timeline.
    pub start_index: u64,
    /// End index (exclusive) in the observation timeline.
    pub end_index: u64,
    /// Embedding vectors within this window.
    pub embeddings: Vec<EmbeddingVector>,
    /// Hash of the window contents.
    pub window_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// MmdResult
// ---------------------------------------------------------------------------

/// Result of a two-sample MMD^2 test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdResult {
    /// Squared MMD value in millionths.
    pub mmd_squared_millionths: u64,
    /// Significance threshold in millionths.
    pub threshold_millionths: u64,
    /// Whether the test indicates a distribution shift.
    pub is_shifted: bool,
    /// Number of samples in the left (benchmark) set.
    pub sample_count_left: u64,
    /// Number of samples in the right (live) set.
    pub sample_count_right: u64,
}

// ---------------------------------------------------------------------------
// ShiftVerdict
// ---------------------------------------------------------------------------

/// Outcome of distribution-shift detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftVerdict {
    /// No shift detected — benchmark and live distributions are compatible.
    NoShift,
    /// A statistically significant shift was detected.
    ShiftDetected {
        /// Squared MMD value in millionths.
        mmd_squared: u64,
    },
    /// Not enough data to make a determination.
    InsufficientSamples {
        /// Number of samples available.
        available: u64,
        /// Number of samples required.
        required: u64,
    },
    /// The monitor explicitly abstains from judging.
    Abstained {
        /// Human-readable reason for abstention.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// MonitorConfig
// ---------------------------------------------------------------------------

/// Full configuration for a shift monitor run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Sliding window parameters.
    pub window: WindowConfig,
    /// Kernel function.
    pub kernel: KernelKind,
    /// Significance threshold in millionths — MMD^2 above this means shift.
    pub significance_threshold_millionths: u64,
    /// Minimum effect size in millionths below which we ignore the signal.
    pub min_effect_size_millionths: u64,
    /// If total samples are below this floor the monitor abstains.
    pub abstention_sample_floor: u64,
}

impl MonitorConfig {
    /// A sensible default configuration: window 100, slide 50, Gaussian RBF
    /// kernel with bandwidth 1.0, significance threshold 10%, minimum effect
    /// size 1%, abstention floor 10.
    pub fn default_config() -> Self {
        Self {
            window: WindowConfig {
                window_size: 100,
                slide_step: 50,
                min_samples: 10,
            },
            kernel: KernelKind::GaussianRbf {
                bandwidth_millionths: MILLIONTHS,
            },
            significance_threshold_millionths: 100_000, // 0.10
            min_effect_size_millionths: 10_000,         // 0.01
            abstention_sample_floor: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// ShiftCertificate
// ---------------------------------------------------------------------------

/// Certificate recording the outcome of a single shift-detection comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftCertificate {
    /// Schema version.
    pub schema_version: String,
    /// The benchmark window that was compared.
    pub benchmark_window: StreamWindow,
    /// The live window that was compared.
    pub live_window: StreamWindow,
    /// Verdict produced by the monitor.
    pub verdict: ShiftVerdict,
    /// Detailed MMD result, if computed.
    pub mmd: Option<MmdResult>,
    /// Hash of the monitor configuration used.
    pub config_hash: ContentHash,
    /// Certificate hash (over all fields).
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// MonitorState
// ---------------------------------------------------------------------------

/// Aggregate state across multiple windows and certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorState {
    /// Accumulated benchmark windows.
    pub benchmark_windows: Vec<StreamWindow>,
    /// Accumulated live windows.
    pub live_windows: Vec<StreamWindow>,
    /// Certificates produced so far.
    pub certificates: Vec<ShiftCertificate>,
    /// Hash of the full state.
    pub state_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ShiftError
// ---------------------------------------------------------------------------

/// Errors that can occur during shift detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftError {
    /// One or both windows contain no embeddings.
    EmptyWindow,
    /// Embedding dimensionality mismatch between two vectors.
    DimensionMismatch {
        /// Expected dimensionality.
        expected: usize,
        /// Actual dimensionality found.
        actual: usize,
    },
    /// The monitor configuration is invalid.
    InvalidConfig {
        /// Reason the configuration is invalid.
        reason: String,
    },
    /// Not enough data to perform the test.
    InsufficientData,
}

impl fmt::Display for ShiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWindow => write!(f, "empty window"),
            Self::DimensionMismatch { expected, actual } => {
                write!(f, "dimension mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::InsufficientData => write!(f, "insufficient data"),
        }
    }
}

// ---------------------------------------------------------------------------
// ShiftEvidenceManifest
// ---------------------------------------------------------------------------

/// Evidence manifest summarising a full shift-evidence corpus run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Number of window-pairs compared.
    pub windows_compared: u32,
    /// Number of comparisons that detected a shift.
    pub shifts_detected: u32,
    /// Number of comparisons where the monitor abstained.
    pub abstentions: u32,
    /// Certificates produced.
    pub certificates: Vec<ShiftCertificate>,
    /// Hash of the manifest.
    pub manifest_hash: ContentHash,
    /// Error message if the run failed early.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Kernel evaluation
// ---------------------------------------------------------------------------

/// Compute a dot product in fixed-point millionths.
///
/// For two vectors a and b, returns sum(a_i * b_i) / MILLIONTHS for each
/// component, saturating on overflow.
fn dot_product_millionths(a: &[u64], b: &[u64]) -> u64 {
    a.iter().zip(b.iter()).fold(0u64, |acc, (&ai, &bi)| {
        let product = (ai as u128)
            .saturating_mul(bi as u128)
            .checked_div(MILLIONTHS as u128)
            .unwrap_or(0) as u64;
        acc.saturating_add(product)
    })
}

/// Compute squared Euclidean distance in millionths between two vectors.
fn squared_distance_millionths(a: &[u64], b: &[u64]) -> u64 {
    a.iter().zip(b.iter()).fold(0u64, |acc, (&ai, &bi)| {
        let diff = if ai >= bi { ai - bi } else { bi - ai };
        let sq = (diff as u128)
            .saturating_mul(diff as u128)
            .checked_div(MILLIONTHS as u128)
            .unwrap_or(0) as u64;
        acc.saturating_add(sq)
    })
}

/// Fixed-point integer-exponentiation (base in millionths, result in
/// millionths). Uses repeated squaring.
fn pow_millionths(base: u64, exp: u32) -> u64 {
    if exp == 0 {
        return MILLIONTHS;
    }
    let mut result: u128 = MILLIONTHS as u128;
    let mut b: u128 = base as u128;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.saturating_mul(b) / (MILLIONTHS as u128);
        }
        e >>= 1;
        if e > 0 {
            b = b.saturating_mul(b) / (MILLIONTHS as u128);
        }
    }
    result.min(u64::MAX as u128) as u64
}

/// Evaluate a kernel function on two embedding vectors, returning the
/// kernel value in millionths.
///
/// # Errors
///
/// Returns `ShiftError::DimensionMismatch` if the vectors have different
/// dimensionality.
pub fn compute_kernel_value(a: &EmbeddingVector, b: &EmbeddingVector, kernel: &KernelKind) -> u64 {
    // If dimensions differ, return 0 as a safe fallback (the caller should
    // validate beforehand via `validate_dimensions`).
    if a.dimensions.len() != b.dimensions.len() {
        return 0;
    }
    match kernel {
        KernelKind::Linear => dot_product_millionths(&a.dimensions, &b.dimensions),
        KernelKind::Polynomial { degree } => {
            let dot = dot_product_millionths(&a.dimensions, &b.dimensions);
            // k(a,b) = (dot + 1.0)^degree  — shift by MILLIONTHS to add 1.0
            let shifted = dot.saturating_add(MILLIONTHS);
            pow_millionths(shifted, *degree)
        }
        KernelKind::GaussianRbf {
            bandwidth_millionths,
        } => {
            let sq_dist = squared_distance_millionths(&a.dimensions, &b.dimensions);
            // k(a,b) = exp(-sq_dist / (2 * bw^2))
            // Approximate exp(-x) for x in millionths as:
            //   MILLIONTHS * max(0, 1 - x/MILLIONTHS)  (linear clamp)
            // This is a conservative lower-bound approximation suitable for
            // shift detection (it never overestimates similarity).
            let bw = *bandwidth_millionths;
            if bw == 0 {
                return if sq_dist == 0 { MILLIONTHS } else { 0 };
            }
            let two_bw_sq = 2u128.saturating_mul((bw as u128).saturating_mul(bw as u128))
                / (MILLIONTHS as u128);
            if two_bw_sq == 0 {
                return if sq_dist == 0 { MILLIONTHS } else { 0 };
            }
            let exponent = (sq_dist as u128).saturating_mul(MILLIONTHS as u128) / two_bw_sq;
            // Linear approximation of exp(-exponent/MILLIONTHS):
            if exponent >= MILLIONTHS as u128 {
                0
            } else {
                (MILLIONTHS as u128 - exponent).min(MILLIONTHS as u128) as u64
            }
        }
    }
}

/// Validate that all embeddings in a slice have the same dimensionality.
fn validate_dimensions(embeddings: &[EmbeddingVector]) -> Result<usize, ShiftError> {
    let first = embeddings.first().ok_or(ShiftError::EmptyWindow)?;
    let dim = first.dimensions.len();
    for emb in embeddings.iter().skip(1) {
        if emb.dimensions.len() != dim {
            return Err(ShiftError::DimensionMismatch {
                expected: dim,
                actual: emb.dimensions.len(),
            });
        }
    }
    Ok(dim)
}

// ---------------------------------------------------------------------------
// MMD computation
// ---------------------------------------------------------------------------

/// Compute the biased MMD^2 estimator between two sets of embeddings.
///
/// MMD^2 = E[k(x,x')] + E[k(y,y')] - 2 E[k(x,y)]
///
/// where x,x' ~ left and y,y' ~ right.
///
/// # Errors
///
/// - `EmptyWindow` if either slice is empty.
/// - `DimensionMismatch` if vectors within or across sets differ in length.
pub fn compute_mmd_squared(
    left: &[EmbeddingVector],
    right: &[EmbeddingVector],
    kernel: &KernelKind,
) -> Result<MmdResult, ShiftError> {
    if left.is_empty() || right.is_empty() {
        return Err(ShiftError::EmptyWindow);
    }
    let dim_l = validate_dimensions(left)?;
    let dim_r = validate_dimensions(right)?;
    if dim_l != dim_r {
        return Err(ShiftError::DimensionMismatch {
            expected: dim_l,
            actual: dim_r,
        });
    }

    let n_l = left.len() as u128;
    let n_r = right.len() as u128;

    // E[k(x,x')]
    let mut sum_ll: u128 = 0;
    for i in 0..left.len() {
        for j in 0..left.len() {
            sum_ll += compute_kernel_value(&left[i], &left[j], kernel) as u128;
        }
    }
    let mean_ll = sum_ll / (n_l * n_l);

    // E[k(y,y')]
    let mut sum_rr: u128 = 0;
    for i in 0..right.len() {
        for j in 0..right.len() {
            sum_rr += compute_kernel_value(&right[i], &right[j], kernel) as u128;
        }
    }
    let mean_rr = sum_rr / (n_r * n_r);

    // E[k(x,y)]
    let mut sum_lr: u128 = 0;
    for x in left {
        for y in right {
            sum_lr += compute_kernel_value(x, y, kernel) as u128;
        }
    }
    let mean_lr = sum_lr / (n_l * n_r);

    // MMD^2 = mean_ll + mean_rr - 2*mean_lr
    let mmd_sq = (mean_ll + mean_rr).saturating_sub(2 * mean_lr) as u64;

    Ok(MmdResult {
        mmd_squared_millionths: mmd_sq,
        threshold_millionths: 0, // filled in by detect_shift
        is_shifted: false,       // filled in by detect_shift
        sample_count_left: left.len() as u64,
        sample_count_right: right.len() as u64,
    })
}

// ---------------------------------------------------------------------------
// Window builder
// ---------------------------------------------------------------------------

/// Build a `StreamWindow` from a set of embeddings.
pub fn build_window(
    kind: StreamKind,
    embeddings: Vec<EmbeddingVector>,
    start: u64,
) -> StreamWindow {
    let end = start + embeddings.len() as u64;
    let hash_data = serde_json::to_vec(&embeddings).unwrap_or_default();
    StreamWindow {
        stream_kind: kind,
        start_index: start,
        end_index: end,
        embeddings,
        window_hash: ContentHash::compute(&hash_data),
    }
}

// ---------------------------------------------------------------------------
// Shift detection
// ---------------------------------------------------------------------------

/// Run shift detection comparing a benchmark window against a live window.
///
/// Produces a `ShiftCertificate` with the verdict. If either window is too
/// small, the certificate records `InsufficientSamples` or `Abstained`.
pub fn detect_shift(
    benchmark: &StreamWindow,
    live: &StreamWindow,
    config: &MonitorConfig,
) -> ShiftCertificate {
    let config_bytes = serde_json::to_vec(config).unwrap_or_default();
    let config_hash = ContentHash::compute(&config_bytes);

    let total_samples = benchmark.embeddings.len() as u64 + live.embeddings.len() as u64;

    // Abstention check: total sample floor.
    if total_samples < config.abstention_sample_floor {
        let verdict = ShiftVerdict::Abstained {
            reason: format!(
                "total samples ({total_samples}) below abstention floor ({})",
                config.abstention_sample_floor
            ),
        };
        let cert_bytes = serde_json::to_vec(&(&benchmark.window_hash, &live.window_hash, &verdict))
            .unwrap_or_default();
        return ShiftCertificate {
            schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
            benchmark_window: benchmark.clone(),
            live_window: live.clone(),
            verdict,
            mmd: None,
            config_hash,
            certificate_hash: ContentHash::compute(&cert_bytes),
        };
    }

    // Minimum-samples check per window.
    let bench_count = benchmark.embeddings.len() as u64;
    let live_count = live.embeddings.len() as u64;
    if bench_count < config.window.min_samples || live_count < config.window.min_samples {
        let available = bench_count.min(live_count);
        let verdict = ShiftVerdict::InsufficientSamples {
            available,
            required: config.window.min_samples,
        };
        let cert_bytes = serde_json::to_vec(&(&benchmark.window_hash, &live.window_hash, &verdict))
            .unwrap_or_default();
        return ShiftCertificate {
            schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
            benchmark_window: benchmark.clone(),
            live_window: live.clone(),
            verdict,
            mmd: None,
            config_hash,
            certificate_hash: ContentHash::compute(&cert_bytes),
        };
    }

    // Compute MMD^2.
    let mmd_result = compute_mmd_squared(&benchmark.embeddings, &live.embeddings, &config.kernel);

    match mmd_result {
        Ok(mut mmd) => {
            mmd.threshold_millionths = config.significance_threshold_millionths;
            mmd.is_shifted = mmd.mmd_squared_millionths > config.significance_threshold_millionths
                && mmd.mmd_squared_millionths > config.min_effect_size_millionths;

            let verdict = if mmd.is_shifted {
                ShiftVerdict::ShiftDetected {
                    mmd_squared: mmd.mmd_squared_millionths,
                }
            } else {
                ShiftVerdict::NoShift
            };

            let cert_bytes =
                serde_json::to_vec(&(&benchmark.window_hash, &live.window_hash, &verdict, &mmd))
                    .unwrap_or_default();
            ShiftCertificate {
                schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
                benchmark_window: benchmark.clone(),
                live_window: live.clone(),
                verdict,
                mmd: Some(mmd),
                config_hash,
                certificate_hash: ContentHash::compute(&cert_bytes),
            }
        }
        Err(_e) => {
            let verdict = ShiftVerdict::Abstained {
                reason: "MMD computation failed".to_string(),
            };
            let cert_bytes =
                serde_json::to_vec(&(&benchmark.window_hash, &live.window_hash, &verdict))
                    .unwrap_or_default();
            ShiftCertificate {
                schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
                benchmark_window: benchmark.clone(),
                live_window: live.clone(),
                verdict,
                mmd: None,
                config_hash,
                certificate_hash: ContentHash::compute(&cert_bytes),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

/// Run the shift-evidence corpus and produce a manifest.
///
/// Constructs a small synthetic benchmark and live stream, compares them,
/// and returns the resulting evidence manifest.
pub fn run_shift_evidence() -> ShiftEvidenceManifest {
    let config = MonitorConfig::default_config();

    // Build synthetic benchmark embeddings — three 2-D vectors near (0.5, 0.5).
    let bench_embeddings: Vec<EmbeddingVector> = (0..12)
        .map(|i| EmbeddingVector {
            dimensions: vec![
                500_000u64.saturating_add(i * 1_000),
                500_000u64.saturating_add(i * 500),
            ],
            source_hash: ContentHash::compute(format!("bench-{i}").as_bytes()),
        })
        .collect();

    // Build synthetic live embeddings — three 2-D vectors near (0.8, 0.8)
    // to simulate a shift.
    let live_embeddings: Vec<EmbeddingVector> = (0..12)
        .map(|i| EmbeddingVector {
            dimensions: vec![
                800_000u64.saturating_add(i * 1_000),
                800_000u64.saturating_add(i * 500),
            ],
            source_hash: ContentHash::compute(format!("live-{i}").as_bytes()),
        })
        .collect();

    // Also build a "similar" live set that should NOT trigger a shift.
    let similar_live: Vec<EmbeddingVector> = (0..12)
        .map(|i| EmbeddingVector {
            dimensions: vec![
                500_000u64.saturating_add(i * 1_100),
                500_000u64.saturating_add(i * 600),
            ],
            source_hash: ContentHash::compute(format!("similar-{i}").as_bytes()),
        })
        .collect();

    let bench_window = build_window(StreamKind::Benchmark, bench_embeddings, 0);
    let live_window = build_window(StreamKind::LiveWorkload, live_embeddings, 0);
    let similar_window = build_window(StreamKind::LiveWorkload, similar_live, 0);

    let cert_shifted = detect_shift(&bench_window, &live_window, &config);
    let cert_similar = detect_shift(&bench_window, &similar_window, &config);

    let certificates = vec![cert_shifted, cert_similar];
    let shifts = certificates
        .iter()
        .filter(|c| matches!(c.verdict, ShiftVerdict::ShiftDetected { .. }))
        .count() as u32;
    let abstentions = certificates
        .iter()
        .filter(|c| matches!(c.verdict, ShiftVerdict::Abstained { .. }))
        .count() as u32;

    let hash_data = serde_json::to_vec(&certificates).unwrap_or_default();

    ShiftEvidenceManifest {
        schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
        windows_compared: certificates.len() as u32,
        shifts_detected: shifts,
        abstentions,
        certificates,
        manifest_hash: ContentHash::compute(&hash_data),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create a simple embedding vector.
    fn emb(dims: &[u64]) -> EmbeddingVector {
        EmbeddingVector {
            dimensions: dims.to_vec(),
            source_hash: ContentHash::compute(
                &dims
                    .iter()
                    .map(|d| d.to_le_bytes())
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
        }
    }

    // ---- Constants ----

    #[test]
    fn test_constants() {
        assert_eq!(SHIFT_MONITOR_POLICY_ID, "RGC-706A");
        assert_eq!(SHIFT_MONITOR_COMPONENT, "distribution_shift_monitor");
        assert!(SHIFT_MONITOR_SCHEMA_VERSION.contains("distribution-shift-monitor"));
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // ---- StreamKind ----

    #[test]
    fn test_stream_kind_display() {
        assert_eq!(StreamKind::Benchmark.to_string(), "benchmark");
        assert_eq!(StreamKind::LiveWorkload.to_string(), "live_workload");
    }

    #[test]
    fn test_stream_kind_serde_roundtrip() {
        let kinds = [StreamKind::Benchmark, StreamKind::LiveWorkload];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: StreamKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, kind);
        }
    }

    // ---- WindowConfig ----

    #[test]
    fn test_window_config_serde() {
        let wc = WindowConfig {
            window_size: 100,
            slide_step: 50,
            min_samples: 10,
        };
        let json = serde_json::to_string(&wc).unwrap();
        let back: WindowConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wc);
    }

    // ---- KernelKind ----

    #[test]
    fn test_kernel_kind_serde_linear() {
        let k = KernelKind::Linear;
        let json = serde_json::to_string(&k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn test_kernel_kind_serde_polynomial() {
        let k = KernelKind::Polynomial { degree: 3 };
        let json = serde_json::to_string(&k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn test_kernel_kind_serde_gaussian() {
        let k = KernelKind::GaussianRbf {
            bandwidth_millionths: 500_000,
        };
        let json = serde_json::to_string(&k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    // ---- EmbeddingVector ----

    #[test]
    fn test_embedding_vector_serde() {
        let ev = emb(&[500_000, 750_000]);
        let json = serde_json::to_string(&ev).unwrap();
        let back: EmbeddingVector = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    // ---- Dot product ----

    #[test]
    fn test_dot_product_identical() {
        // (1.0, 1.0) . (1.0, 1.0) = 2.0 = 2_000_000
        let result = dot_product_millionths(&[MILLIONTHS, MILLIONTHS], &[MILLIONTHS, MILLIONTHS]);
        assert_eq!(result, 2_000_000);
    }

    #[test]
    fn test_dot_product_orthogonal() {
        // (1.0, 0.0) . (0.0, 1.0) = 0
        let result = dot_product_millionths(&[MILLIONTHS, 0], &[0, MILLIONTHS]);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_dot_product_half() {
        // (0.5, 0.5) . (0.5, 0.5) = 0.5 = 500_000
        let result = dot_product_millionths(&[500_000, 500_000], &[500_000, 500_000]);
        assert_eq!(result, 500_000);
    }

    // ---- Squared distance ----

    #[test]
    fn test_squared_distance_identical() {
        let result = squared_distance_millionths(&[500_000, 500_000], &[500_000, 500_000]);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_squared_distance_unit() {
        // distance^2 between (0, 0) and (1.0, 0) = 1.0 = 1_000_000
        let result = squared_distance_millionths(&[0, 0], &[MILLIONTHS, 0]);
        assert_eq!(result, MILLIONTHS);
    }

    // ---- Pow millionths ----

    #[test]
    fn test_pow_zero() {
        assert_eq!(pow_millionths(500_000, 0), MILLIONTHS);
    }

    #[test]
    fn test_pow_one() {
        assert_eq!(pow_millionths(500_000, 1), 500_000);
    }

    #[test]
    fn test_pow_two() {
        // (0.5)^2 = 0.25 = 250_000
        assert_eq!(pow_millionths(500_000, 2), 250_000);
    }

    #[test]
    fn test_pow_identity() {
        // (1.0)^5 = 1.0
        assert_eq!(pow_millionths(MILLIONTHS, 5), MILLIONTHS);
    }

    // ---- Kernel value ----

    #[test]
    fn test_linear_kernel_identical() {
        let a = emb(&[MILLIONTHS, 0]);
        let b = emb(&[MILLIONTHS, 0]);
        let val = compute_kernel_value(&a, &b, &KernelKind::Linear);
        assert_eq!(val, MILLIONTHS);
    }

    #[test]
    fn test_linear_kernel_orthogonal() {
        let a = emb(&[MILLIONTHS, 0]);
        let b = emb(&[0, MILLIONTHS]);
        let val = compute_kernel_value(&a, &b, &KernelKind::Linear);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_polynomial_kernel_degree_1() {
        let a = emb(&[MILLIONTHS]);
        let b = emb(&[MILLIONTHS]);
        // (dot + 1)^1 = (1.0 + 1.0)^1 = 2.0
        let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 1 });
        assert_eq!(val, 2_000_000);
    }

    #[test]
    fn test_gaussian_kernel_identical() {
        let a = emb(&[500_000, 500_000]);
        let b = emb(&[500_000, 500_000]);
        let val = compute_kernel_value(
            &a,
            &b,
            &KernelKind::GaussianRbf {
                bandwidth_millionths: MILLIONTHS,
            },
        );
        // distance = 0, so exp(0) = 1.0 = MILLIONTHS
        assert_eq!(val, MILLIONTHS);
    }

    #[test]
    fn test_gaussian_kernel_distant() {
        let a = emb(&[0]);
        let b = emb(&[2_000_000]); // 2.0
        let val = compute_kernel_value(
            &a,
            &b,
            &KernelKind::GaussianRbf {
                bandwidth_millionths: MILLIONTHS,
            },
        );
        // Far apart: should be close to 0.
        assert!(val < 100_000);
    }

    #[test]
    fn test_kernel_dimension_mismatch_returns_zero() {
        let a = emb(&[500_000, 500_000]);
        let b = emb(&[500_000]);
        let val = compute_kernel_value(&a, &b, &KernelKind::Linear);
        assert_eq!(val, 0);
    }

    // ---- MMD squared ----

    #[test]
    fn test_mmd_identical_sets() {
        let vecs: Vec<EmbeddingVector> = (0..5).map(|_| emb(&[500_000, 500_000])).collect();
        let result = compute_mmd_squared(&vecs, &vecs, &KernelKind::Linear).unwrap();
        assert_eq!(result.mmd_squared_millionths, 0);
        assert_eq!(result.sample_count_left, 5);
        assert_eq!(result.sample_count_right, 5);
    }

    #[test]
    fn test_mmd_different_sets() {
        let left: Vec<EmbeddingVector> = (0..3).map(|_| emb(&[200_000])).collect();
        let right: Vec<EmbeddingVector> = (0..3).map(|_| emb(&[800_000])).collect();
        let result = compute_mmd_squared(&left, &right, &KernelKind::Linear).unwrap();
        // Should be non-zero because distributions differ.
        assert!(result.mmd_squared_millionths > 0);
    }

    #[test]
    fn test_mmd_empty_left() {
        let right = vec![emb(&[500_000])];
        let result = compute_mmd_squared(&[], &right, &KernelKind::Linear);
        assert_eq!(result, Err(ShiftError::EmptyWindow));
    }

    #[test]
    fn test_mmd_empty_right() {
        let left = vec![emb(&[500_000])];
        let result = compute_mmd_squared(&left, &[], &KernelKind::Linear);
        assert_eq!(result, Err(ShiftError::EmptyWindow));
    }

    #[test]
    fn test_mmd_dimension_mismatch() {
        let left = vec![emb(&[500_000, 500_000])];
        let right = vec![emb(&[500_000])];
        let result = compute_mmd_squared(&left, &right, &KernelKind::Linear);
        assert!(matches!(result, Err(ShiftError::DimensionMismatch { .. })));
    }

    // ---- build_window ----

    #[test]
    fn test_build_window_basic() {
        let embeddings = vec![emb(&[100_000]), emb(&[200_000]), emb(&[300_000])];
        let w = build_window(StreamKind::Benchmark, embeddings, 10);
        assert_eq!(w.stream_kind, StreamKind::Benchmark);
        assert_eq!(w.start_index, 10);
        assert_eq!(w.end_index, 13);
        assert_eq!(w.embeddings.len(), 3);
    }

    #[test]
    fn test_build_window_empty() {
        let w = build_window(StreamKind::LiveWorkload, vec![], 0);
        assert_eq!(w.start_index, 0);
        assert_eq!(w.end_index, 0);
        assert!(w.embeddings.is_empty());
    }

    #[test]
    fn test_build_window_hash_determinism() {
        let embeddings = vec![emb(&[500_000, 500_000])];
        let w1 = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
        let w2 = build_window(StreamKind::Benchmark, embeddings, 0);
        assert_eq!(w1.window_hash, w2.window_hash);
    }

    // ---- detect_shift ----

    #[test]
    fn test_detect_shift_no_shift() {
        let config = MonitorConfig::default_config();
        let embeddings: Vec<EmbeddingVector> = (0..12)
            .map(|i| emb(&[500_000 + i * 100, 500_000 + i * 100]))
            .collect();
        let bench = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
        let live = build_window(StreamKind::LiveWorkload, embeddings, 0);
        let cert = detect_shift(&bench, &live, &config);
        assert_eq!(cert.verdict, ShiftVerdict::NoShift);
        assert!(cert.mmd.is_some());
    }

    #[test]
    fn test_detect_shift_shifted() {
        let mut config = MonitorConfig::default_config();
        config.significance_threshold_millionths = 1_000; // very low threshold
        config.min_effect_size_millionths = 500;

        let bench_embs: Vec<EmbeddingVector> = (0..12).map(|_| emb(&[100_000])).collect();
        let live_embs: Vec<EmbeddingVector> = (0..12).map(|_| emb(&[900_000])).collect();
        let bench = build_window(StreamKind::Benchmark, bench_embs, 0);
        let live = build_window(StreamKind::LiveWorkload, live_embs, 0);
        let cert = detect_shift(&bench, &live, &config);
        assert!(
            matches!(cert.verdict, ShiftVerdict::ShiftDetected { .. }),
            "expected ShiftDetected, got {:?}",
            cert.verdict,
        );
    }

    #[test]
    fn test_detect_shift_insufficient_samples() {
        let config = MonitorConfig {
            window: WindowConfig {
                window_size: 100,
                slide_step: 50,
                min_samples: 20,
            },
            kernel: KernelKind::Linear,
            significance_threshold_millionths: 100_000,
            min_effect_size_millionths: 10_000,
            abstention_sample_floor: 1,
        };
        let bench = build_window(StreamKind::Benchmark, vec![emb(&[500_000])], 0);
        let live = build_window(StreamKind::LiveWorkload, vec![emb(&[500_000])], 0);
        let cert = detect_shift(&bench, &live, &config);
        assert!(matches!(
            cert.verdict,
            ShiftVerdict::InsufficientSamples { .. }
        ));
    }

    #[test]
    fn test_detect_shift_abstained_sample_floor() {
        let config = MonitorConfig {
            window: WindowConfig {
                window_size: 100,
                slide_step: 50,
                min_samples: 1,
            },
            kernel: KernelKind::Linear,
            significance_threshold_millionths: 100_000,
            min_effect_size_millionths: 10_000,
            abstention_sample_floor: 100,
        };
        let bench = build_window(StreamKind::Benchmark, vec![emb(&[500_000])], 0);
        let live = build_window(StreamKind::LiveWorkload, vec![emb(&[500_000])], 0);
        let cert = detect_shift(&bench, &live, &config);
        assert!(matches!(cert.verdict, ShiftVerdict::Abstained { .. }));
    }

    #[test]
    fn test_detect_shift_certificate_schema_version() {
        let config = MonitorConfig::default_config();
        let embeddings: Vec<EmbeddingVector> = (0..12).map(|_| emb(&[500_000])).collect();
        let bench = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
        let live = build_window(StreamKind::LiveWorkload, embeddings, 0);
        let cert = detect_shift(&bench, &live, &config);
        assert_eq!(cert.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    }

    #[test]
    fn test_detect_shift_certificate_hash_determinism() {
        let config = MonitorConfig::default_config();
        let embeddings: Vec<EmbeddingVector> = (0..12).map(|_| emb(&[500_000])).collect();
        let bench = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
        let live = build_window(StreamKind::LiveWorkload, embeddings.clone(), 0);
        let cert1 = detect_shift(&bench, &live, &config);

        let bench2 = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
        let live2 = build_window(StreamKind::LiveWorkload, embeddings, 0);
        let cert2 = detect_shift(&bench2, &live2, &config);

        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
    }

    // ---- MonitorConfig ----

    #[test]
    fn test_default_config() {
        let c = MonitorConfig::default_config();
        assert_eq!(c.window.window_size, 100);
        assert_eq!(c.window.slide_step, 50);
        assert_eq!(c.window.min_samples, 10);
        assert!(matches!(
            c.kernel,
            KernelKind::GaussianRbf {
                bandwidth_millionths: MILLIONTHS
            }
        ));
        assert_eq!(c.significance_threshold_millionths, 100_000);
        assert_eq!(c.min_effect_size_millionths, 10_000);
        assert_eq!(c.abstention_sample_floor, 10);
    }

    #[test]
    fn test_monitor_config_serde() {
        let c = MonitorConfig::default_config();
        let json = serde_json::to_string(&c).unwrap();
        let back: MonitorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    // ---- ShiftVerdict ----

    #[test]
    fn test_shift_verdict_serde_no_shift() {
        let v = ShiftVerdict::NoShift;
        let json = serde_json::to_string(&v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn test_shift_verdict_serde_detected() {
        let v = ShiftVerdict::ShiftDetected {
            mmd_squared: 42_000,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn test_shift_verdict_serde_insufficient() {
        let v = ShiftVerdict::InsufficientSamples {
            available: 5,
            required: 20,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn test_shift_verdict_serde_abstained() {
        let v = ShiftVerdict::Abstained {
            reason: "too few".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    // ---- ShiftError ----

    #[test]
    fn test_shift_error_display() {
        assert_eq!(ShiftError::EmptyWindow.to_string(), "empty window");
        assert_eq!(
            ShiftError::DimensionMismatch {
                expected: 3,
                actual: 5,
            }
            .to_string(),
            "dimension mismatch: expected 3, got 5"
        );
        assert_eq!(
            ShiftError::InvalidConfig {
                reason: "bad".to_string(),
            }
            .to_string(),
            "invalid config: bad"
        );
        assert_eq!(
            ShiftError::InsufficientData.to_string(),
            "insufficient data"
        );
    }

    #[test]
    fn test_shift_error_serde() {
        let errors = vec![
            ShiftError::EmptyWindow,
            ShiftError::DimensionMismatch {
                expected: 2,
                actual: 4,
            },
            ShiftError::InvalidConfig {
                reason: "test".to_string(),
            },
            ShiftError::InsufficientData,
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: ShiftError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, e);
        }
    }

    // ---- MonitorState ----

    #[test]
    fn test_monitor_state_serde() {
        let state = MonitorState {
            benchmark_windows: vec![],
            live_windows: vec![],
            certificates: vec![],
            state_hash: ContentHash::compute(b"test-state"),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: MonitorState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    // ---- Evidence manifest ----

    #[test]
    fn test_run_shift_evidence_produces_manifest() {
        let manifest = run_shift_evidence();
        assert_eq!(manifest.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
        assert!(manifest.error.is_none());
        assert_eq!(manifest.windows_compared, 2);
        assert_eq!(manifest.certificates.len(), 2);
    }

    #[test]
    fn test_run_shift_evidence_deterministic() {
        let m1 = run_shift_evidence();
        let m2 = run_shift_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
        assert_eq!(m1.shifts_detected, m2.shifts_detected);
        assert_eq!(m1.abstentions, m2.abstentions);
    }

    #[test]
    fn test_evidence_manifest_serde() {
        let manifest = run_shift_evidence();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ShiftEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    // ---- Validate dimensions ----

    #[test]
    fn test_validate_dimensions_consistent() {
        let vecs = vec![emb(&[1, 2, 3]), emb(&[4, 5, 6])];
        assert_eq!(validate_dimensions(&vecs), Ok(3));
    }

    #[test]
    fn test_validate_dimensions_mismatch() {
        let vecs = vec![emb(&[1, 2]), emb(&[4, 5, 6])];
        assert!(matches!(
            validate_dimensions(&vecs),
            Err(ShiftError::DimensionMismatch {
                expected: 2,
                actual: 3
            })
        ));
    }

    #[test]
    fn test_validate_dimensions_empty() {
        let vecs: Vec<EmbeddingVector> = vec![];
        assert_eq!(validate_dimensions(&vecs), Err(ShiftError::EmptyWindow));
    }

    // ---- MmdResult serde ----

    #[test]
    fn test_mmd_result_serde() {
        let mmd = MmdResult {
            mmd_squared_millionths: 42_000,
            threshold_millionths: 100_000,
            is_shifted: true,
            sample_count_left: 10,
            sample_count_right: 10,
        };
        let json = serde_json::to_string(&mmd).unwrap();
        let back: MmdResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mmd);
    }
}
