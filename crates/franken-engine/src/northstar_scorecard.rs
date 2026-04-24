//! North-Star Scorecard — objective metric stack and success scorecard
//! for FrankenEngine runtime.
//!
//! Tracks the key performance, correctness, and reliability metrics that
//! determine alpha/beta/GA readiness.  Every metric uses fixed-point
//! millionths (1_000_000 = 1.0) for deterministic cross-platform arithmetic.
//!
//! Scorecard dimensions:
//! - **Compatibility**: pass rate against the canonical React behavior corpus
//! - **Responsiveness**: input-to-paint latency (p50/p95/p99)
//! - **Render latency**: per-update latency distribution
//! - **Footprint**: bundle size + runtime memory usage
//! - **Fallback frequency**: how often safe-mode fallback fires
//! - **Rollback latency**: time from incident detection to safe-mode restore
//! - **Evidence completeness**: fraction of high-impact decisions with signed receipts
//!
//! Plan reference: FRX-01.2 (North-Star Scorecard).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Milestone — alpha / beta / GA
// ---------------------------------------------------------------------------

/// Release milestone for threshold evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Milestone {
    /// Internal prototype; relaxed thresholds.
    Alpha,
    /// External beta; tighter thresholds.
    Beta,
    /// General availability; full thresholds.
    Ga,
}

impl fmt::Display for Milestone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alpha => write!(f, "alpha"),
            Self::Beta => write!(f, "beta"),
            Self::Ga => write!(f, "ga"),
        }
    }
}

// ---------------------------------------------------------------------------
// MetricKind — the seven scorecard dimensions
// ---------------------------------------------------------------------------

/// Scorecard metric dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MetricKind {
    /// Compatibility pass rate (millionths; MILLION = 100%).
    CompatibilityPassRate,
    /// Input-to-paint responsiveness p99 (microseconds).
    ResponsivenessP99Us,
    /// Render/update latency p50 (microseconds).
    RenderLatencyP50Us,
    /// Render/update latency p95 (microseconds).
    RenderLatencyP95Us,
    /// Render/update latency p99 (microseconds).
    RenderLatencyP99Us,
    /// Bundle size (bytes).
    BundleSizeBytes,
    /// Runtime memory footprint (bytes).
    RuntimeMemoryBytes,
    /// Fallback frequency (millionths; MILLION = 100%).
    FallbackFrequency,
    /// Rollback latency p99 (microseconds).
    RollbackLatencyP99Us,
    /// Evidence completeness (millionths; MILLION = 100%).
    EvidenceCompleteness,
}

impl MetricKind {
    pub const ALL: [MetricKind; 10] = [
        MetricKind::CompatibilityPassRate,
        MetricKind::ResponsivenessP99Us,
        MetricKind::RenderLatencyP50Us,
        MetricKind::RenderLatencyP95Us,
        MetricKind::RenderLatencyP99Us,
        MetricKind::BundleSizeBytes,
        MetricKind::RuntimeMemoryBytes,
        MetricKind::FallbackFrequency,
        MetricKind::RollbackLatencyP99Us,
        MetricKind::EvidenceCompleteness,
    ];

    /// Whether higher values are better for this metric.
    pub fn higher_is_better(&self) -> bool {
        matches!(
            self,
            MetricKind::CompatibilityPassRate | MetricKind::EvidenceCompleteness
        )
    }
}

impl fmt::Display for MetricKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CompatibilityPassRate => "compatibility_pass_rate",
            Self::ResponsivenessP99Us => "responsiveness_p99_us",
            Self::RenderLatencyP50Us => "render_latency_p50_us",
            Self::RenderLatencyP95Us => "render_latency_p95_us",
            Self::RenderLatencyP99Us => "render_latency_p99_us",
            Self::BundleSizeBytes => "bundle_size_bytes",
            Self::RuntimeMemoryBytes => "runtime_memory_bytes",
            Self::FallbackFrequency => "fallback_frequency",
            Self::RollbackLatencyP99Us => "rollback_latency_p99_us",
            Self::EvidenceCompleteness => "evidence_completeness",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Threshold — per-milestone pass/fail boundary
// ---------------------------------------------------------------------------

/// Threshold definition for a single metric at a given milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    pub metric: MetricKind,
    pub milestone: Milestone,
    /// For "higher is better" metrics: value must be >= this.
    /// For "lower is better" metrics: value must be <= this.
    pub boundary: i64,
}

/// Default threshold set for alpha/beta/GA.
pub fn default_thresholds() -> Vec<Threshold> {
    vec![
        // -- Compatibility pass rate --
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000, // 80%
        },
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Beta,
            boundary: 950_000, // 95%
        },
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Ga,
            boundary: 990_000, // 99%
        },
        // -- Responsiveness p99 --
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Alpha,
            boundary: 100_000, // 100ms
        },
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Beta,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Ga,
            boundary: 16_000, // 16ms (single frame)
        },
        // -- Render latency p50 --
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Alpha,
            boundary: 10_000, // 10ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Beta,
            boundary: 5_000, // 5ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Ga,
            boundary: 2_000, // 2ms
        },
        // -- Render latency p95 --
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Alpha,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Beta,
            boundary: 16_000, // 16ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Ga,
            boundary: 8_000, // 8ms
        },
        // -- Render latency p99 --
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Alpha,
            boundary: 100_000, // 100ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Beta,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Ga,
            boundary: 16_000, // 16ms
        },
        // -- Bundle size --
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000_000, // 10MB
        },
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Beta,
            boundary: 5_000_000, // 5MB
        },
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Ga,
            boundary: 2_000_000, // 2MB
        },
        // -- Runtime memory --
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Alpha,
            boundary: 256_000_000, // 256MB
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Beta,
            boundary: 128_000_000, // 128MB
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Ga,
            boundary: 64_000_000, // 64MB
        },
        // -- Fallback frequency --
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Alpha,
            boundary: 200_000, // 20%
        },
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Beta,
            boundary: 50_000, // 5%
        },
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Ga,
            boundary: 10_000, // 1%
        },
        // -- Rollback latency p99 --
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Alpha,
            boundary: 500_000, // 500ms
        },
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Beta,
            boundary: 250_000, // 250ms
        },
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Ga,
            boundary: 100_000, // 100ms
        },
        // -- Evidence completeness --
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Alpha,
            boundary: 500_000, // 50%
        },
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Beta,
            boundary: 900_000, // 90%
        },
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            boundary: 990_000, // 99%
        },
    ]
}

// ---------------------------------------------------------------------------
// MetricSample — a single metric observation
// ---------------------------------------------------------------------------

/// A single metric observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSample {
    pub kind: MetricKind,
    pub value: i64,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// MetricSummary — aggregated statistics for a single metric
// ---------------------------------------------------------------------------

/// Aggregated summary for a single metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSummary {
    pub kind: MetricKind,
    /// Number of observations.
    pub count: u64,
    /// Minimum observed value.
    pub min: i64,
    /// Maximum observed value.
    pub max: i64,
    /// Mean (millionths for rate-type metrics; raw for absolute-value metrics).
    pub mean: i64,
    /// p50 quantile.
    pub p50: i64,
    /// p95 quantile.
    pub p95: i64,
    /// p99 quantile.
    pub p99: i64,
}

// ---------------------------------------------------------------------------
// ScorecardEvaluation — pass/fail per metric per milestone
// ---------------------------------------------------------------------------

/// Result of evaluating a metric against a milestone threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdResult {
    /// Metric meets the threshold.
    Pass {
        metric: MetricKind,
        milestone: Milestone,
        value: i64,
        threshold: i64,
        headroom: i64,
    },
    /// Metric fails the threshold.
    Fail {
        metric: MetricKind,
        milestone: Milestone,
        value: i64,
        threshold: i64,
        shortfall: i64,
    },
    /// Insufficient data to evaluate.
    InsufficientData {
        metric: MetricKind,
        milestone: Milestone,
    },
}

impl ThresholdResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, ThresholdResult::Pass { .. })
    }
}

/// Full scorecard evaluation for a milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardEvaluation {
    pub milestone: Milestone,
    pub epoch: SecurityEpoch,
    pub results: Vec<ThresholdResult>,
    /// Overall pass: all metrics meet threshold.
    pub overall_pass: bool,
    /// Number of passing metrics.
    pub pass_count: u64,
    /// Number of failing metrics.
    pub fail_count: u64,
    /// Pass rate (millionths).
    pub pass_rate_millionths: i64,
}

// ---------------------------------------------------------------------------
// Scorecard — the tracker
// ---------------------------------------------------------------------------

/// Tracks all scorecard metrics and evaluates against milestone thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scorecard {
    /// Threshold definitions.
    thresholds: Vec<Threshold>,
    /// Observations per metric kind (kept in chronological order).
    observations: BTreeMap<MetricKind, Vec<i64>>,
    /// Maximum observations to keep per metric (ring-buffer semantics).
    max_observations: usize,
    /// Current epoch.
    epoch: SecurityEpoch,
}

impl Scorecard {
    /// Create with default thresholds.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            thresholds: default_thresholds(),
            observations: BTreeMap::new(),
            max_observations: 10_000,
            epoch,
        }
    }

    /// Create with custom thresholds.
    pub fn with_thresholds(thresholds: Vec<Threshold>, epoch: SecurityEpoch) -> Self {
        Self {
            thresholds,
            observations: BTreeMap::new(),
            max_observations: 10_000,
            epoch,
        }
    }

    /// Record a metric observation.
    pub fn record(&mut self, sample: MetricSample) {
        let values = self.observations.entry(sample.kind).or_default();
        // Append in chronological order.
        values.push(sample.value);
        // Trim oldest if over limit.
        if values.len() > self.max_observations {
            values.remove(0);
        }
        self.epoch = sample.epoch;
    }

    /// Get summary statistics for a metric.
    pub fn summary(&self, kind: MetricKind) -> Option<MetricSummary> {
        let values = self.observations.get(&kind)?;
        if values.is_empty() {
            return None;
        }
        let n = values.len();

        let mut sorted = values.clone();
        sorted.sort_unstable();

        let min = sorted[0];
        let max = sorted[n - 1];
        let sum: i64 = sorted.iter().fold(0i64, |acc, &x| acc.saturating_add(x));
        let mean = sum / n as i64;
        let p50 = sorted[n / 2];
        let p95 = sorted[(n * 95) / 100];
        let p99 = sorted[(n * 99) / 100];

        Some(MetricSummary {
            kind,
            count: n as u64,
            min,
            max,
            mean,
            p50,
            p95,
            p99,
        })
    }

    /// Get the current value for a metric (latest observation's representative).
    ///
    /// For rate-type metrics (CompatibilityPassRate, FallbackFrequency,
    /// EvidenceCompleteness), returns the mean.
    /// For latency/size metrics, returns the appropriate quantile.
    pub fn current_value(&self, kind: MetricKind) -> Option<i64> {
        let summary = self.summary(kind)?;
        match kind {
            MetricKind::CompatibilityPassRate
            | MetricKind::FallbackFrequency
            | MetricKind::EvidenceCompleteness => Some(summary.mean),
            MetricKind::ResponsivenessP99Us
            | MetricKind::RenderLatencyP99Us
            | MetricKind::RollbackLatencyP99Us => Some(summary.p99),
            MetricKind::RenderLatencyP50Us => Some(summary.p50),
            MetricKind::RenderLatencyP95Us => Some(summary.p95),
            MetricKind::BundleSizeBytes | MetricKind::RuntimeMemoryBytes => Some(summary.max),
        }
    }

    /// Evaluate the scorecard against a specific milestone.
    pub fn evaluate(&self, milestone: Milestone) -> ScorecardEvaluation {
        let relevant: Vec<&Threshold> = self
            .thresholds
            .iter()
            .filter(|t| t.milestone == milestone)
            .collect();

        let mut results = Vec::new();
        let mut pass_count = 0u64;
        let mut fail_count = 0u64;

        for threshold in &relevant {
            let value = self.current_value(threshold.metric);
            match value {
                None => {
                    results.push(ThresholdResult::InsufficientData {
                        metric: threshold.metric,
                        milestone,
                    });
                    fail_count += 1;
                }
                Some(v) => {
                    let passes = if threshold.metric.higher_is_better() {
                        v >= threshold.boundary
                    } else {
                        v <= threshold.boundary
                    };
                    if passes {
                        let headroom = if threshold.metric.higher_is_better() {
                            v - threshold.boundary
                        } else {
                            threshold.boundary - v
                        };
                        results.push(ThresholdResult::Pass {
                            metric: threshold.metric,
                            milestone,
                            value: v,
                            threshold: threshold.boundary,
                            headroom,
                        });
                        pass_count += 1;
                    } else {
                        let shortfall = if threshold.metric.higher_is_better() {
                            threshold.boundary - v
                        } else {
                            v - threshold.boundary
                        };
                        results.push(ThresholdResult::Fail {
                            metric: threshold.metric,
                            milestone,
                            value: v,
                            threshold: threshold.boundary,
                            shortfall,
                        });
                        fail_count += 1;
                    }
                }
            }
        }

        let total = pass_count + fail_count;
        let pass_rate = if total == 0 {
            0
        } else {
            (pass_count as i64).saturating_mul(MILLION) / (total as i64)
        };

        ScorecardEvaluation {
            milestone,
            epoch: self.epoch,
            results,
            overall_pass: fail_count == 0 && pass_count > 0,
            pass_count,
            fail_count,
            pass_rate_millionths: pass_rate,
        }
    }

    /// Evaluate all milestones and return the highest passing one.
    pub fn highest_passing_milestone(&self) -> Option<Milestone> {
        for ms in [Milestone::Ga, Milestone::Beta, Milestone::Alpha] {
            let eval = self.evaluate(ms);
            if eval.overall_pass {
                return Some(ms);
            }
        }
        None
    }

    /// Get observation count for a metric.
    pub fn observation_count(&self, kind: MetricKind) -> u64 {
        self.observations
            .get(&kind)
            .map(|v| v.len() as u64)
            .unwrap_or(0)
    }

    /// Total observations across all metrics.
    pub fn total_observations(&self) -> u64 {
        self.observations.values().map(|v| v.len() as u64).sum()
    }

    /// Get the threshold definitions.
    pub fn thresholds(&self) -> &[Threshold] {
        &self.thresholds
    }

    /// Set the epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Generate a human-readable report string.
    pub fn report(&self, milestone: Milestone) -> String {
        let eval = self.evaluate(milestone);
        let mut lines = Vec::new();
        lines.push(format!(
            "=== North-Star Scorecard: {milestone} (epoch {}) ===",
            eval.epoch.as_u64()
        ));
        lines.push(format!(
            "Overall: {} ({}/{} pass, {:.1}%)",
            if eval.overall_pass { "PASS" } else { "FAIL" },
            eval.pass_count,
            eval.pass_count + eval.fail_count,
            eval.pass_rate_millionths as f64 / 10_000.0,
        ));
        lines.push(String::new());
        for result in &eval.results {
            match result {
                ThresholdResult::Pass {
                    metric,
                    value,
                    threshold,
                    headroom,
                    ..
                } => {
                    lines.push(format!(
                        "  [PASS] {metric}: {value} (threshold: {threshold}, headroom: {headroom})"
                    ));
                }
                ThresholdResult::Fail {
                    metric,
                    value,
                    threshold,
                    shortfall,
                    ..
                } => {
                    lines.push(format!(
                        "  [FAIL] {metric}: {value} (threshold: {threshold}, shortfall: {shortfall})"
                    ));
                }
                ThresholdResult::InsufficientData { metric, .. } => {
                    lines.push(format!("  [----] {metric}: insufficient data"));
                }
            }
        }
        lines.join("\n")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn sample(kind: MetricKind, value: i64, ep: u64) -> MetricSample {
        MetricSample {
            kind,
            value,
            epoch: epoch(ep),
        }
    }

    // -----------------------------------------------------------------------
    // Milestone tests
    // -----------------------------------------------------------------------

    #[test]
    fn milestone_display() {
        assert_eq!(format!("{}", Milestone::Alpha), "alpha");
        assert_eq!(format!("{}", Milestone::Beta), "beta");
        assert_eq!(format!("{}", Milestone::Ga), "ga");
    }

    #[test]
    fn milestone_serde_roundtrip() {
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let json = serde_json::to_string(&ms).expect("serde deserialization should succeed");
            let back: Milestone =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(ms, back);
        }
    }

    #[test]
    fn milestone_ordering() {
        assert!(Milestone::Alpha < Milestone::Beta);
        assert!(Milestone::Beta < Milestone::Ga);
    }

    // -----------------------------------------------------------------------
    // MetricKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_kind_all_ten() {
        assert_eq!(MetricKind::ALL.len(), 10);
    }

    #[test]
    fn metric_kind_display() {
        assert_eq!(
            format!("{}", MetricKind::CompatibilityPassRate),
            "compatibility_pass_rate"
        );
        assert_eq!(
            format!("{}", MetricKind::RollbackLatencyP99Us),
            "rollback_latency_p99_us"
        );
    }

    #[test]
    fn metric_kind_higher_is_better() {
        assert!(MetricKind::CompatibilityPassRate.higher_is_better());
        assert!(MetricKind::EvidenceCompleteness.higher_is_better());
        assert!(!MetricKind::ResponsivenessP99Us.higher_is_better());
        assert!(!MetricKind::FallbackFrequency.higher_is_better());
        assert!(!MetricKind::BundleSizeBytes.higher_is_better());
    }

    #[test]
    fn metric_kind_serde_roundtrip() {
        for kind in &MetricKind::ALL {
            let json = serde_json::to_string(kind).expect("serde deserialization should succeed");
            let back: MetricKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*kind, back);
        }
    }

    // -----------------------------------------------------------------------
    // Threshold tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_thresholds_cover_all_milestones() {
        let thresholds = default_thresholds();
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let count = thresholds.iter().filter(|t| t.milestone == ms).count();
            assert_eq!(count, 10, "milestone {ms} should have 10 thresholds");
        }
    }

    #[test]
    fn default_thresholds_serde_roundtrip() {
        let thresholds = default_thresholds();
        let json =
            serde_json::to_string(&thresholds).expect("serde deserialization should succeed");
        let back: Vec<Threshold> =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(thresholds.len(), back.len());
    }

    #[test]
    fn thresholds_get_stricter_from_alpha_to_ga() {
        let thresholds = default_thresholds();
        // For CompatibilityPassRate (higher is better): alpha < beta < ga.
        let cpr: Vec<&Threshold> = thresholds
            .iter()
            .filter(|t| t.metric == MetricKind::CompatibilityPassRate)
            .collect();
        assert!(cpr[0].boundary < cpr[1].boundary);
        assert!(cpr[1].boundary < cpr[2].boundary);

        // For ResponsivenessP99Us (lower is better): alpha > beta > ga.
        let resp: Vec<&Threshold> = thresholds
            .iter()
            .filter(|t| t.metric == MetricKind::ResponsivenessP99Us)
            .collect();
        assert!(resp[0].boundary > resp[1].boundary);
        assert!(resp[1].boundary > resp[2].boundary);
    }

    // -----------------------------------------------------------------------
    // Scorecard basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_new_empty() {
        let sc = Scorecard::new(epoch(1));
        assert_eq!(sc.total_observations(), 0);
        assert_eq!(sc.thresholds().len(), 30); // 10 metrics × 3 milestones
    }

    #[test]
    fn scorecard_record_and_summary() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP50Us, i * 100, 1));
        }
        let summary = sc
            .summary(MetricKind::RenderLatencyP50Us)
            .expect("serde deserialization should succeed");
        assert_eq!(summary.count, 100);
        assert_eq!(summary.min, 0);
        assert_eq!(summary.max, 9900);
        assert_eq!(summary.p50, 5000);
    }

    #[test]
    fn scorecard_no_data_returns_none() {
        let sc = Scorecard::new(epoch(1));
        assert!(sc.summary(MetricKind::BundleSizeBytes).is_none());
        assert!(sc.current_value(MetricKind::BundleSizeBytes).is_none());
    }

    #[test]
    fn scorecard_observation_count() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 2000, 1));
        assert_eq!(sc.observation_count(MetricKind::BundleSizeBytes), 2);
        assert_eq!(sc.observation_count(MetricKind::RuntimeMemoryBytes), 0);
    }

    // -----------------------------------------------------------------------
    // Evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_all_insufficient_data() {
        let sc = Scorecard::new(epoch(1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(!eval.overall_pass);
        assert_eq!(eval.fail_count, 10);
        assert_eq!(eval.pass_count, 0);
    }

    #[test]
    fn evaluate_passes_alpha_with_good_data() {
        let mut sc = Scorecard::new(epoch(1));
        // Set all metrics to values that pass alpha.
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1)); // 90% > 80%
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1)); // 50ms < 100ms
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1)); // 5ms < 10ms
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1)); // 20ms < 50ms
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1)); // 50ms < 100ms
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1)); // 5MB < 10MB
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1)); // 100MB < 256MB
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1)); // 10% < 20%
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1)); // 200ms < 500ms
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1)); // 60% > 50%
        }
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass, "alpha should pass: {eval:?}");
        assert_eq!(eval.pass_count, 10);
        assert_eq!(eval.fail_count, 0);
    }

    #[test]
    fn evaluate_fails_ga_with_alpha_data() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 850_000, 1)); // 85% < 99%
            sc.record(sample(MetricKind::ResponsivenessP99Us, 80_000, 1)); // 80ms > 16ms
            sc.record(sample(MetricKind::RenderLatencyP50Us, 8_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 40_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 80_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 8_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 200_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 150_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 400_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 550_000, 1));
        }
        let eval = sc.evaluate(Milestone::Ga);
        assert!(!eval.overall_pass, "GA should fail with alpha-level data");
        assert!(eval.fail_count > 0);
    }

    #[test]
    fn highest_passing_milestone_none_initially() {
        let sc = Scorecard::new(epoch(1));
        assert_eq!(sc.highest_passing_milestone(), None);
    }

    #[test]
    fn highest_passing_milestone_alpha() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
        }
        assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Alpha));
    }

    // -----------------------------------------------------------------------
    // ThresholdResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_result_is_pass() {
        let pass = ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        };
        assert!(pass.is_pass());

        let fail = ThresholdResult::Fail {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Ga,
            value: 800_000,
            threshold: 990_000,
            shortfall: 190_000,
        };
        assert!(!fail.is_pass());

        let insuf = ThresholdResult::InsufficientData {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
        };
        assert!(!insuf.is_pass());
    }

    #[test]
    fn threshold_result_serde_roundtrip() {
        let results = vec![
            ThresholdResult::Pass {
                metric: MetricKind::CompatibilityPassRate,
                milestone: Milestone::Alpha,
                value: 900_000,
                threshold: 800_000,
                headroom: 100_000,
            },
            ThresholdResult::Fail {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Ga,
                value: 5_000_000,
                threshold: 2_000_000,
                shortfall: 3_000_000,
            },
        ];
        for result in &results {
            let json = serde_json::to_string(result).expect("serde deserialization should succeed");
            let back: ThresholdResult =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*result, back);
        }
    }

    // -----------------------------------------------------------------------
    // ScorecardEvaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_evaluation_serde_roundtrip() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Beta,
            epoch: epoch(42),
            results: vec![],
            overall_pass: false,
            pass_count: 0,
            fail_count: 0,
            pass_rate_millionths: 0,
        };
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        let back: ScorecardEvaluation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eval, back);
    }

    // -----------------------------------------------------------------------
    // Report tests
    // -----------------------------------------------------------------------

    #[test]
    fn report_contains_milestone_name() {
        let sc = Scorecard::new(epoch(1));
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("alpha"));
        assert!(report.contains("FAIL"));
    }

    #[test]
    fn report_pass_with_data() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 999_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 1_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 999_000, 1));
        }
        let report = sc.report(Milestone::Ga);
        assert!(report.contains("PASS"), "report: {report}");
    }

    // -----------------------------------------------------------------------
    // Scorecard serde tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_serde_roundtrip() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
        let json = serde_json::to_string(&sc).expect("serde deserialization should succeed");
        let back: Scorecard =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sc.total_observations(), back.total_observations());
    }

    // -----------------------------------------------------------------------
    // MetricSample tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_sample_serde_roundtrip() {
        let s = sample(MetricKind::CompatibilityPassRate, 950_000, 42);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: MetricSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // MetricSummary tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_summary_serde_roundtrip() {
        let summary = MetricSummary {
            kind: MetricKind::BundleSizeBytes,
            count: 100,
            min: 1000,
            max: 5000,
            mean: 3000,
            p50: 3000,
            p95: 4500,
            p99: 4900,
        };
        let json = serde_json::to_string(&summary).expect("serde deserialization should succeed");
        let back: MetricSummary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(summary, back);
    }

    // -----------------------------------------------------------------------
    // Custom threshold tests
    // -----------------------------------------------------------------------

    #[test]
    fn custom_thresholds_used() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 1_000, // very strict
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass);

        let mut sc2 = Scorecard::with_thresholds(
            vec![Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 100,
            }],
            epoch(1),
        );
        sc2.record(sample(MetricKind::BundleSizeBytes, 500, 1));
        let eval2 = sc2.evaluate(Milestone::Alpha);
        assert!(!eval2.overall_pass);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_observation_summary() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::RenderLatencyP50Us, 42, 1));
        let summary = sc
            .summary(MetricKind::RenderLatencyP50Us)
            .expect("serde deserialization should succeed");
        assert_eq!(summary.count, 1);
        assert_eq!(summary.min, 42);
        assert_eq!(summary.max, 42);
        assert_eq!(summary.mean, 42);
        assert_eq!(summary.p50, 42);
    }

    #[test]
    fn current_value_uses_correct_quantile() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP50Us, i, 1));
        }
        // p50 for RenderLatencyP50Us.
        let val = sc
            .current_value(MetricKind::RenderLatencyP50Us)
            .expect("serde deserialization should succeed");
        assert_eq!(val, 50); // p50 of 0..99

        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP99Us, i, 1));
        }
        // p99 for RenderLatencyP99Us.
        let val99 = sc
            .current_value(MetricKind::RenderLatencyP99Us)
            .expect("serde deserialization should succeed");
        assert_eq!(val99, 99); // p99 of 0..99
    }

    #[test]
    fn set_epoch_updates() {
        let mut sc = Scorecard::new(epoch(1));
        sc.set_epoch(epoch(42));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.epoch, epoch(42));
    }

    #[test]
    fn pass_rate_computation() {
        let thresholds = vec![
            Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
            Threshold {
                metric: MetricKind::RuntimeMemoryBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
        ];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1)); // pass
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 20_000, 1)); // fail
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.pass_count, 1);
        assert_eq!(eval.fail_count, 1);
        assert_eq!(eval.pass_rate_millionths, 500_000); // 50%
    }

    #[test]
    fn headroom_and_shortfall_correct() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
            assert_eq!(*headroom, 100_000);
        } else {
            panic!("expected pass");
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: MetricKind display all 10 variants unique
    // -----------------------------------------------------------------------

    #[test]
    fn metric_kind_display_all_unique() {
        let displays: std::collections::BTreeSet<String> =
            MetricKind::ALL.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            displays.len(),
            10,
            "all 10 MetricKinds have distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: Threshold serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_serde_roundtrip() {
        let t = Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Beta,
            boundary: 5_000_000,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: Threshold =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(t, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: evaluate with empty thresholds returns vacuous pass
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_empty_thresholds_no_pass() {
        let sc = Scorecard::with_thresholds(vec![], epoch(1));
        let eval = sc.evaluate(Milestone::Alpha);
        // No thresholds → pass_count=0, fail_count=0, overall_pass=false.
        assert!(!eval.overall_pass);
        assert_eq!(eval.pass_count, 0);
        assert_eq!(eval.fail_count, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: current_value for BundleSizeBytes uses max
    // -----------------------------------------------------------------------

    #[test]
    fn current_value_bundle_size_uses_max() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
        // BundleSizeBytes → max
        assert_eq!(sc.current_value(MetricKind::BundleSizeBytes), Some(5_000));
    }

    // -----------------------------------------------------------------------
    // Enrichment: current_value for FallbackFrequency uses mean
    // -----------------------------------------------------------------------

    #[test]
    fn current_value_fallback_frequency_uses_mean() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
        sc.record(sample(MetricKind::FallbackFrequency, 200_000, 1));
        // mean = (100_000 + 200_000) / 2 = 150_000
        assert_eq!(
            sc.current_value(MetricKind::FallbackFrequency),
            Some(150_000)
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: current_value for RenderLatencyP95Us uses p95
    // -----------------------------------------------------------------------

    #[test]
    fn current_value_render_latency_p95_uses_p95() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP95Us, i * 10, 1));
        }
        // p95 of [0, 10, 20, ..., 990]
        let val = sc
            .current_value(MetricKind::RenderLatencyP95Us)
            .expect("serde deserialization should succeed");
        assert_eq!(val, 950); // index 95 in sorted 0..99
    }

    // -----------------------------------------------------------------------
    // Enrichment: highest_passing_milestone returns GA
    // -----------------------------------------------------------------------

    #[test]
    fn highest_passing_milestone_ga() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 999_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 1_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 999_000, 1));
        }
        assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Ga));
    }

    // -----------------------------------------------------------------------
    // Enrichment: report insufficient data mentions "insufficient"
    // -----------------------------------------------------------------------

    #[test]
    fn report_insufficient_data_says_insufficient() {
        let sc = Scorecard::new(epoch(1));
        let report = sc.report(Milestone::Alpha);
        assert!(
            report.contains("insufficient"),
            "report should mention insufficient: {report}"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: total observations correct
    // -----------------------------------------------------------------------

    #[test]
    fn total_observations_across_metrics() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 2000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 3000, 1));
        assert_eq!(sc.total_observations(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: shortfall computed correctly
    // -----------------------------------------------------------------------

    #[test]
    fn shortfall_correct_for_lower_is_better() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 1_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        if let ThresholdResult::Fail { shortfall, .. } = &eval.results[0] {
            assert_eq!(*shortfall, 2_000); // 3000 - 1000
        } else {
            panic!("expected fail");
        }
    }

    #[test]
    fn shortfall_correct_for_higher_is_better() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 900_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        if let ThresholdResult::Fail { shortfall, .. } = &eval.results[0] {
            assert_eq!(*shortfall, 100_000); // 900k - 800k
        } else {
            panic!("expected fail");
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: InsufficientData serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn insufficient_data_serde_roundtrip() {
        let result = ThresholdResult::InsufficientData {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Ga,
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: ThresholdResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    // ── Enrichment batch 2: edge cases & boundary conditions ────

    #[test]
    fn milestone_ordering_strict() {
        assert!(Milestone::Alpha < Milestone::Beta);
        assert!(Milestone::Beta < Milestone::Ga);
    }

    #[test]
    fn milestone_serde_roundtrip_all_variants() {
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let json = serde_json::to_string(&ms).expect("serde deserialization should succeed");
            let back: Milestone =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(ms, back);
        }
    }

    #[test]
    fn two_observation_summary_correct() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 100, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 200, 1));
        let summary = sc
            .summary(MetricKind::BundleSizeBytes)
            .expect("serde deserialization should succeed");
        assert_eq!(summary.count, 2);
        assert_eq!(summary.min, 100);
        assert_eq!(summary.max, 200);
        assert_eq!(summary.mean, 150);
    }

    #[test]
    fn current_value_evidence_completeness_uses_mean() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::EvidenceCompleteness, 800_000, 1));
        sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
        // EvidenceCompleteness → mean
        assert_eq!(
            sc.current_value(MetricKind::EvidenceCompleteness),
            Some(700_000)
        );
    }

    #[test]
    fn current_value_responsiveness_p99_uses_p99() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::ResponsivenessP99Us, i * 100, 1));
        }
        let val = sc
            .current_value(MetricKind::ResponsivenessP99Us)
            .expect("serde deserialization should succeed");
        assert_eq!(val, 9900); // p99 of [0, 100, 200, ..., 9900]
    }

    #[test]
    fn current_value_runtime_memory_uses_max() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 50_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 30_000, 1));
        assert_eq!(
            sc.current_value(MetricKind::RuntimeMemoryBytes),
            Some(50_000)
        );
    }

    #[test]
    fn scorecard_many_observations_correct_count() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..1000 {
            sc.record(sample(MetricKind::RenderLatencyP50Us, i, 1));
        }
        assert_eq!(sc.observation_count(MetricKind::RenderLatencyP50Us), 1000);
        assert_eq!(sc.total_observations(), 1000);
    }

    #[test]
    fn evaluate_beta_requires_stricter_thresholds() {
        let mut sc = Scorecard::new(epoch(1));
        // Alpha-level data
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
        }
        let alpha = sc.evaluate(Milestone::Alpha);
        let beta = sc.evaluate(Milestone::Beta);
        // Alpha should pass, but beta may fail on some stricter thresholds
        assert!(alpha.overall_pass);
        assert!(beta.fail_count >= alpha.fail_count);
    }

    #[test]
    fn report_pass_contains_pass_word() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 999_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 1_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 999_000, 1));
        }
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("PASS"));
    }

    #[test]
    fn evaluation_pass_rate_all_pass() {
        let thresholds = vec![
            Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
            Threshold {
                metric: MetricKind::RuntimeMemoryBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
        ];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 5_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.pass_rate_millionths, 1_000_000); // 100%
    }

    #[test]
    fn current_value_rollback_latency_uses_p99() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RollbackLatencyP99Us, i * 1000, 1));
        }
        let val = sc
            .current_value(MetricKind::RollbackLatencyP99Us)
            .expect("serde deserialization should succeed");
        assert_eq!(val, 99_000); // p99
    }

    #[test]
    fn scorecard_deterministic_evaluation() {
        let build_sc = || {
            let mut sc = Scorecard::new(epoch(5));
            for i in 0..50 {
                sc.record(sample(MetricKind::CompatibilityPassRate, 950_000 + i, 1));
                sc.record(sample(MetricKind::BundleSizeBytes, 1_000_000 + i * 100, 1));
            }
            sc
        };
        let eval1 = build_sc().evaluate(Milestone::Alpha);
        let eval2 = build_sc().evaluate(Milestone::Alpha);
        assert_eq!(eval1.pass_count, eval2.pass_count);
        assert_eq!(eval1.fail_count, eval2.fail_count);
        assert_eq!(eval1.overall_pass, eval2.overall_pass);
    }

    // ===================================================================
    // Enrichment batch 3: Copy semantics
    // ===================================================================

    #[test]
    fn milestone_copy_semantics() {
        let a = Milestone::Alpha;
        let b = a; // copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, Milestone::Alpha);
    }

    #[test]
    fn metric_kind_copy_semantics() {
        let a = MetricKind::BundleSizeBytes;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, MetricKind::BundleSizeBytes);
    }

    #[test]
    fn milestone_copy_all_variants() {
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let copied = ms;
            assert_eq!(ms, copied);
        }
    }

    #[test]
    fn metric_kind_copy_all_variants() {
        for kind in MetricKind::ALL {
            let copied = kind;
            assert_eq!(kind, copied);
        }
    }

    // ===================================================================
    // Enrichment batch 3: Debug distinctness
    // ===================================================================

    #[test]
    fn milestone_debug_all_distinct() {
        let debugs: std::collections::BTreeSet<String> =
            [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
                .iter()
                .map(|m| format!("{m:?}"))
                .collect();
        assert_eq!(
            debugs.len(),
            3,
            "all Milestone variants have distinct Debug"
        );
    }

    #[test]
    fn metric_kind_debug_all_distinct() {
        let debugs: std::collections::BTreeSet<String> =
            MetricKind::ALL.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(
            debugs.len(),
            10,
            "all 10 MetricKind variants have distinct Debug"
        );
    }

    #[test]
    fn threshold_result_debug_all_variants_distinct() {
        let pass = ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        };
        let fail = ThresholdResult::Fail {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 700_000,
            threshold: 800_000,
            shortfall: 100_000,
        };
        let insuf = ThresholdResult::InsufficientData {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
        };
        let debugs: std::collections::BTreeSet<String> = [&pass, &fail, &insuf]
            .iter()
            .map(|r| format!("{r:?}"))
            .collect();
        assert_eq!(
            debugs.len(),
            3,
            "all ThresholdResult variants distinct Debug"
        );
    }

    // ===================================================================
    // Enrichment batch 3: Serde variant distinctness
    // ===================================================================

    #[test]
    fn milestone_serde_variant_distinctness() {
        let jsons: std::collections::BTreeSet<String> =
            [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
                .iter()
                .map(|m| serde_json::to_string(m).expect("serde deserialization should succeed"))
                .collect();
        assert_eq!(
            jsons.len(),
            3,
            "all Milestone variants serialize distinctly"
        );
    }

    #[test]
    fn metric_kind_serde_variant_distinctness() {
        let jsons: std::collections::BTreeSet<String> = MetricKind::ALL
            .iter()
            .map(|k| serde_json::to_string(k).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(
            jsons.len(),
            10,
            "all 10 MetricKind variants serialize distinctly"
        );
    }

    #[test]
    fn threshold_result_serde_variant_distinctness() {
        let pass = ThresholdResult::Pass {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            value: 5_000,
            threshold: 10_000,
            headroom: 5_000,
        };
        let fail = ThresholdResult::Fail {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            value: 15_000,
            threshold: 10_000,
            shortfall: 5_000,
        };
        let insuf = ThresholdResult::InsufficientData {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
        };
        let jsons: std::collections::BTreeSet<String> = [&pass, &fail, &insuf]
            .iter()
            .map(|r| serde_json::to_string(r).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 3);
    }

    // ===================================================================
    // Enrichment batch 3: Clone independence
    // ===================================================================

    #[test]
    fn threshold_clone_independence() {
        let original = Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        };
        let mut cloned = original.clone();
        cloned.boundary = 99_999;
        assert_eq!(original.boundary, 10_000);
        assert_eq!(cloned.boundary, 99_999);
    }

    #[test]
    fn metric_sample_clone_independence() {
        let original = sample(MetricKind::CompatibilityPassRate, 900_000, 1);
        let mut cloned = original.clone();
        cloned.value = 0;
        assert_eq!(original.value, 900_000);
        assert_eq!(cloned.value, 0);
    }

    #[test]
    fn metric_summary_clone_independence() {
        let original = MetricSummary {
            kind: MetricKind::BundleSizeBytes,
            count: 10,
            min: 100,
            max: 5000,
            mean: 2500,
            p50: 2500,
            p95: 4500,
            p99: 4900,
        };
        let mut cloned = original.clone();
        cloned.count = 999;
        cloned.min = 0;
        assert_eq!(original.count, 10);
        assert_eq!(original.min, 100);
        assert_eq!(cloned.count, 999);
        assert_eq!(cloned.min, 0);
    }

    #[test]
    fn scorecard_evaluation_clone_independence() {
        let original = ScorecardEvaluation {
            milestone: Milestone::Beta,
            epoch: epoch(1),
            results: vec![ThresholdResult::InsufficientData {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Beta,
            }],
            overall_pass: false,
            pass_count: 0,
            fail_count: 1,
            pass_rate_millionths: 0,
        };
        let mut cloned = original.clone();
        cloned.overall_pass = true;
        cloned.results.clear();
        assert!(!original.overall_pass);
        assert_eq!(original.results.len(), 1);
    }

    #[test]
    fn scorecard_clone_independence() {
        let mut original = Scorecard::new(epoch(1));
        original.record(sample(MetricKind::BundleSizeBytes, 1_000, 1));
        let mut cloned = original.clone();
        cloned.record(sample(MetricKind::BundleSizeBytes, 2_000, 2));
        assert_eq!(original.observation_count(MetricKind::BundleSizeBytes), 1);
        assert_eq!(cloned.observation_count(MetricKind::BundleSizeBytes), 2);
    }

    // ===================================================================
    // Enrichment batch 3: JSON field-name stability
    // ===================================================================

    #[test]
    fn threshold_json_field_names() {
        let t = Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        assert!(json.contains("\"metric\""), "missing 'metric' field");
        assert!(json.contains("\"milestone\""), "missing 'milestone' field");
        assert!(json.contains("\"boundary\""), "missing 'boundary' field");
    }

    #[test]
    fn metric_sample_json_field_names() {
        let s = sample(MetricKind::CompatibilityPassRate, 950_000, 42);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        assert!(json.contains("\"kind\""), "missing 'kind' field");
        assert!(json.contains("\"value\""), "missing 'value' field");
        assert!(json.contains("\"epoch\""), "missing 'epoch' field");
    }

    #[test]
    fn metric_summary_json_field_names() {
        let summary = MetricSummary {
            kind: MetricKind::BundleSizeBytes,
            count: 10,
            min: 100,
            max: 5000,
            mean: 2500,
            p50: 2500,
            p95: 4500,
            p99: 4900,
        };
        let json = serde_json::to_string(&summary).expect("serde deserialization should succeed");
        for field in ["kind", "count", "min", "max", "mean", "p50", "p95", "p99"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing '{field}' field in MetricSummary JSON"
            );
        }
    }

    #[test]
    fn scorecard_evaluation_json_field_names() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Alpha,
            epoch: epoch(1),
            results: vec![],
            overall_pass: true,
            pass_count: 10,
            fail_count: 0,
            pass_rate_millionths: 1_000_000,
        };
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        for field in [
            "milestone",
            "epoch",
            "results",
            "overall_pass",
            "pass_count",
            "fail_count",
            "pass_rate_millionths",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing '{field}' field in ScorecardEvaluation JSON"
            );
        }
    }

    #[test]
    fn threshold_result_pass_json_field_names() {
        let pass = ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        };
        let json = serde_json::to_string(&pass).expect("serde deserialization should succeed");
        for field in ["metric", "milestone", "value", "threshold", "headroom"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing '{field}' in ThresholdResult::Pass JSON"
            );
        }
    }

    #[test]
    fn threshold_result_fail_json_field_names() {
        let fail = ThresholdResult::Fail {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Ga,
            value: 5_000_000,
            threshold: 2_000_000,
            shortfall: 3_000_000,
        };
        let json = serde_json::to_string(&fail).expect("serde deserialization should succeed");
        for field in ["metric", "milestone", "value", "threshold", "shortfall"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing '{field}' in ThresholdResult::Fail JSON"
            );
        }
    }

    #[test]
    fn threshold_result_insufficient_json_field_names() {
        let insuf = ThresholdResult::InsufficientData {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Beta,
        };
        let json = serde_json::to_string(&insuf).expect("serde deserialization should succeed");
        assert!(json.contains("\"metric\""));
        assert!(json.contains("\"milestone\""));
    }

    // ===================================================================
    // Enrichment batch 3: Display format checks
    // ===================================================================

    #[test]
    fn milestone_display_format_exact() {
        assert_eq!(Milestone::Alpha.to_string(), "alpha");
        assert_eq!(Milestone::Beta.to_string(), "beta");
        assert_eq!(Milestone::Ga.to_string(), "ga");
    }

    #[test]
    fn metric_kind_display_format_exact_all() {
        let expected = [
            (MetricKind::CompatibilityPassRate, "compatibility_pass_rate"),
            (MetricKind::ResponsivenessP99Us, "responsiveness_p99_us"),
            (MetricKind::RenderLatencyP50Us, "render_latency_p50_us"),
            (MetricKind::RenderLatencyP95Us, "render_latency_p95_us"),
            (MetricKind::RenderLatencyP99Us, "render_latency_p99_us"),
            (MetricKind::BundleSizeBytes, "bundle_size_bytes"),
            (MetricKind::RuntimeMemoryBytes, "runtime_memory_bytes"),
            (MetricKind::FallbackFrequency, "fallback_frequency"),
            (MetricKind::RollbackLatencyP99Us, "rollback_latency_p99_us"),
            (MetricKind::EvidenceCompleteness, "evidence_completeness"),
        ];
        for (kind, name) in expected {
            assert_eq!(kind.to_string(), name, "Display mismatch for {kind:?}");
        }
    }

    #[test]
    fn milestone_display_all_distinct() {
        let displays: std::collections::BTreeSet<String> =
            [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
                .iter()
                .map(|m| m.to_string())
                .collect();
        assert_eq!(displays.len(), 3);
    }

    // ===================================================================
    // Enrichment batch 3: Hash consistency
    // ===================================================================

    #[test]
    fn milestone_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            ms.hash(&mut h1);
            ms.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish(), "hash not consistent for {ms:?}");
        }
    }

    #[test]
    fn metric_kind_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for kind in MetricKind::ALL {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            kind.hash(&mut h1);
            kind.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish(), "hash not consistent for {kind:?}");
        }
    }

    #[test]
    fn milestone_hash_distinct_variants() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let hashes: std::collections::BTreeSet<u64> =
            [Milestone::Alpha, Milestone::Beta, Milestone::Ga]
                .iter()
                .map(|ms| {
                    let mut h = DefaultHasher::new();
                    ms.hash(&mut h);
                    h.finish()
                })
                .collect();
        assert_eq!(hashes.len(), 3, "Milestone variants have distinct hashes");
    }

    #[test]
    fn metric_kind_hash_distinct_variants() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let hashes: std::collections::BTreeSet<u64> = MetricKind::ALL
            .iter()
            .map(|k| {
                let mut h = DefaultHasher::new();
                k.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 10, "MetricKind variants have distinct hashes");
    }

    // ===================================================================
    // Enrichment batch 3: Boundary/edge cases
    // ===================================================================

    #[test]
    fn metric_sample_zero_value() {
        let s = sample(MetricKind::CompatibilityPassRate, 0, 1);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: MetricSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.value, 0);
    }

    #[test]
    fn metric_sample_negative_value() {
        let s = sample(MetricKind::CompatibilityPassRate, -1, 1);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: MetricSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.value, -1);
    }

    #[test]
    fn metric_sample_i64_max() {
        let s = sample(MetricKind::BundleSizeBytes, i64::MAX, 1);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: MetricSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.value, i64::MAX);
    }

    #[test]
    fn metric_sample_i64_min() {
        let s = sample(MetricKind::BundleSizeBytes, i64::MIN, 1);
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: MetricSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.value, i64::MIN);
    }

    #[test]
    fn metric_summary_zero_count_edge() {
        // MetricSummary with count=0 should still roundtrip
        let summary = MetricSummary {
            kind: MetricKind::FallbackFrequency,
            count: 0,
            min: 0,
            max: 0,
            mean: 0,
            p50: 0,
            p95: 0,
            p99: 0,
        };
        let json = serde_json::to_string(&summary).expect("serde deserialization should succeed");
        let back: MetricSummary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(summary, back);
    }

    #[test]
    fn metric_summary_u64_max_count() {
        let summary = MetricSummary {
            kind: MetricKind::BundleSizeBytes,
            count: u64::MAX,
            min: i64::MIN,
            max: i64::MAX,
            mean: 0,
            p50: 0,
            p95: 0,
            p99: 0,
        };
        let json = serde_json::to_string(&summary).expect("serde deserialization should succeed");
        let back: MetricSummary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(summary.count, back.count);
        assert_eq!(summary.min, back.min);
        assert_eq!(summary.max, back.max);
    }

    #[test]
    fn threshold_boundary_zero() {
        let t = Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 0,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: Threshold =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.boundary, 0);
    }

    #[test]
    fn threshold_boundary_negative() {
        let t = Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: -1,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: Threshold =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.boundary, -1);
    }

    #[test]
    fn scorecard_epoch_zero() {
        let sc = Scorecard::new(epoch(0));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.epoch, epoch(0));
    }

    #[test]
    fn scorecard_epoch_u64_max() {
        let sc = Scorecard::new(epoch(u64::MAX));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.epoch, epoch(u64::MAX));
    }

    #[test]
    fn scorecard_evaluation_empty_results_serde() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Ga,
            epoch: epoch(0),
            results: vec![],
            overall_pass: false,
            pass_count: 0,
            fail_count: 0,
            pass_rate_millionths: 0,
        };
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        let back: ScorecardEvaluation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eval, back);
    }

    #[test]
    fn scorecard_evaluation_max_counts() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Alpha,
            epoch: epoch(u64::MAX),
            results: vec![],
            overall_pass: false,
            pass_count: u64::MAX,
            fail_count: u64::MAX,
            pass_rate_millionths: i64::MAX,
        };
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        let back: ScorecardEvaluation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eval, back);
    }

    #[test]
    fn evaluate_exact_boundary_higher_is_better_passes() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 800_000, 1)); // exactly at boundary
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(
            eval.overall_pass,
            "exact boundary should pass for higher-is-better"
        );
    }

    #[test]
    fn evaluate_exact_boundary_lower_is_better_passes() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 10_000, 1)); // exactly at boundary
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(
            eval.overall_pass,
            "exact boundary should pass for lower-is-better"
        );
    }

    #[test]
    fn evaluate_one_above_boundary_higher_is_better_passes() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 800_001, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass);
    }

    #[test]
    fn evaluate_one_below_boundary_higher_is_better_fails() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 799_999, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(!eval.overall_pass);
    }

    #[test]
    fn evaluate_one_below_boundary_lower_is_better_passes() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 9_999, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass);
    }

    #[test]
    fn evaluate_one_above_boundary_lower_is_better_fails() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 10_001, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(!eval.overall_pass);
    }

    // ===================================================================
    // Enrichment batch 3: Serde roundtrips (complex structs)
    // ===================================================================

    #[test]
    fn scorecard_full_serde_roundtrip() {
        let mut sc = Scorecard::new(epoch(42));
        for i in 0..20 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000 + i, 42));
            sc.record(sample(
                MetricKind::BundleSizeBytes,
                1_000_000 + i * 1000,
                42,
            ));
            sc.record(sample(MetricKind::FallbackFrequency, 50_000 + i, 42));
        }
        let json = serde_json::to_string(&sc).expect("serde deserialization should succeed");
        let back: Scorecard =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sc.total_observations(), back.total_observations());
        assert_eq!(
            sc.observation_count(MetricKind::CompatibilityPassRate),
            back.observation_count(MetricKind::CompatibilityPassRate)
        );
        assert_eq!(
            sc.observation_count(MetricKind::BundleSizeBytes),
            back.observation_count(MetricKind::BundleSizeBytes)
        );
        // Evaluation results should match
        let eval_orig = sc.evaluate(Milestone::Alpha);
        let eval_back = back.evaluate(Milestone::Alpha);
        assert_eq!(eval_orig.overall_pass, eval_back.overall_pass);
        assert_eq!(eval_orig.pass_count, eval_back.pass_count);
    }

    #[test]
    fn scorecard_evaluation_full_serde_roundtrip() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
        }
        let eval = sc.evaluate(Milestone::Alpha);
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        let back: ScorecardEvaluation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eval, back);
        assert!(back.overall_pass);
        assert_eq!(back.pass_count, 10);
    }

    #[test]
    fn threshold_result_pass_serde_preserves_all_fields() {
        let result = ThresholdResult::Pass {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            value: 995_000,
            threshold: 990_000,
            headroom: 5_000,
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: ThresholdResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        if let ThresholdResult::Pass {
            metric,
            milestone,
            value,
            threshold,
            headroom,
        } = back
        {
            assert_eq!(metric, MetricKind::EvidenceCompleteness);
            assert_eq!(milestone, Milestone::Ga);
            assert_eq!(value, 995_000);
            assert_eq!(threshold, 990_000);
            assert_eq!(headroom, 5_000);
        } else {
            panic!("expected Pass variant after roundtrip");
        }
    }

    #[test]
    fn threshold_result_fail_serde_preserves_all_fields() {
        let result = ThresholdResult::Fail {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Beta,
            value: 300_000,
            threshold: 250_000,
            shortfall: 50_000,
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: ThresholdResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        if let ThresholdResult::Fail {
            metric,
            milestone,
            value,
            threshold,
            shortfall,
        } = back
        {
            assert_eq!(metric, MetricKind::RollbackLatencyP99Us);
            assert_eq!(milestone, Milestone::Beta);
            assert_eq!(value, 300_000);
            assert_eq!(threshold, 250_000);
            assert_eq!(shortfall, 50_000);
        } else {
            panic!("expected Fail variant after roundtrip");
        }
    }

    // ===================================================================
    // Enrichment batch 3: Additional coverage
    // ===================================================================

    #[test]
    fn higher_is_better_all_metric_kinds() {
        // Ensure every metric has a defined polarity
        for kind in MetricKind::ALL {
            let _result = kind.higher_is_better();
        }
        // Only two should be higher-is-better
        let higher_count = MetricKind::ALL
            .iter()
            .filter(|k| k.higher_is_better())
            .count();
        assert_eq!(higher_count, 2);
        let lower_count = MetricKind::ALL
            .iter()
            .filter(|k| !k.higher_is_better())
            .count();
        assert_eq!(lower_count, 8);
    }

    #[test]
    fn metric_kind_ord_is_deterministic() {
        let mut kinds: Vec<MetricKind> = MetricKind::ALL.to_vec();
        let sorted1 = {
            let mut v = kinds.clone();
            v.sort();
            v
        };
        let sorted2 = {
            kinds.sort();
            kinds
        };
        assert_eq!(sorted1, sorted2);
    }

    #[test]
    fn milestone_ord_is_deterministic() {
        let mut ms = vec![Milestone::Ga, Milestone::Alpha, Milestone::Beta];
        ms.sort();
        assert_eq!(ms, vec![Milestone::Alpha, Milestone::Beta, Milestone::Ga]);
    }

    #[test]
    fn report_contains_epoch() {
        let sc = Scorecard::new(epoch(999));
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("999"), "report should contain epoch number");
    }

    #[test]
    fn report_contains_headroom_for_passing_metric() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("headroom"));
    }

    #[test]
    fn report_contains_shortfall_for_failing_metric() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 1_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("shortfall"));
    }

    #[test]
    fn default_thresholds_30_total() {
        let thresholds = default_thresholds();
        assert_eq!(thresholds.len(), 30);
    }

    #[test]
    fn default_thresholds_each_metric_has_all_milestones() {
        let thresholds = default_thresholds();
        for kind in MetricKind::ALL {
            for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
                assert!(
                    thresholds
                        .iter()
                        .any(|t| t.metric == kind && t.milestone == ms),
                    "missing threshold for {kind:?} at {ms:?}"
                );
            }
        }
    }

    #[test]
    fn scorecard_record_updates_epoch() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1_000, 5));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.epoch, epoch(5));
    }

    #[test]
    fn scorecard_record_preserves_sorted_order() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1_000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 3_000, 1));
        let summary = sc
            .summary(MetricKind::BundleSizeBytes)
            .expect("serde deserialization should succeed");
        assert_eq!(summary.min, 1_000);
        assert_eq!(summary.max, 5_000);
    }

    #[test]
    fn scorecard_with_thresholds_empty_no_metrics() {
        let sc = Scorecard::with_thresholds(vec![], epoch(1));
        assert_eq!(sc.thresholds().len(), 0);
        assert_eq!(sc.total_observations(), 0);
    }

    #[test]
    fn highest_passing_milestone_beta() {
        let mut sc = Scorecard::new(epoch(1));
        // Data that passes beta but fails GA
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 970_000, 1)); // > 95% (beta) but < 99% (GA)
            sc.record(sample(MetricKind::ResponsivenessP99Us, 40_000, 1)); // < 50ms (beta) but > 16ms (GA)
            sc.record(sample(MetricKind::RenderLatencyP50Us, 4_000, 1)); // < 5ms (beta) but > 2ms (GA)
            sc.record(sample(MetricKind::RenderLatencyP95Us, 15_000, 1)); // < 16ms (beta) but > 8ms (GA)
            sc.record(sample(MetricKind::RenderLatencyP99Us, 40_000, 1)); // < 50ms (beta) but > 16ms (GA)
            sc.record(sample(MetricKind::BundleSizeBytes, 4_000_000, 1)); // < 5MB (beta) but > 2MB (GA)
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 120_000_000, 1)); // < 128MB (beta) but > 64MB (GA)
            sc.record(sample(MetricKind::FallbackFrequency, 40_000, 1)); // < 5% (beta) but > 1% (GA)
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1)); // < 250ms (beta) but > 100ms (GA)
            sc.record(sample(MetricKind::EvidenceCompleteness, 920_000, 1)); // > 90% (beta) but < 99% (GA)
        }
        assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Beta));
    }

    #[test]
    fn scorecard_evaluation_with_mixed_results_serde() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Beta,
            epoch: epoch(77),
            results: vec![
                ThresholdResult::Pass {
                    metric: MetricKind::CompatibilityPassRate,
                    milestone: Milestone::Beta,
                    value: 960_000,
                    threshold: 950_000,
                    headroom: 10_000,
                },
                ThresholdResult::Fail {
                    metric: MetricKind::BundleSizeBytes,
                    milestone: Milestone::Beta,
                    value: 6_000_000,
                    threshold: 5_000_000,
                    shortfall: 1_000_000,
                },
                ThresholdResult::InsufficientData {
                    metric: MetricKind::FallbackFrequency,
                    milestone: Milestone::Beta,
                },
            ],
            overall_pass: false,
            pass_count: 1,
            fail_count: 2,
            pass_rate_millionths: 333_333,
        };
        let json = serde_json::to_string(&eval).expect("serde deserialization should succeed");
        let back: ScorecardEvaluation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eval, back);
        assert_eq!(back.results.len(), 3);
    }

    #[test]
    fn scorecard_json_field_names() {
        let sc = Scorecard::new(epoch(1));
        let json = serde_json::to_string(&sc).expect("serde deserialization should succeed");
        for field in ["thresholds", "observations", "max_observations", "epoch"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing '{field}' in Scorecard JSON"
            );
        }
    }

    #[test]
    fn pass_rate_zero_for_all_failures() {
        let thresholds = vec![
            Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 1,
            },
            Threshold {
                metric: MetricKind::RuntimeMemoryBytes,
                milestone: Milestone::Alpha,
                boundary: 1,
            },
        ];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 100_000, 1));
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.pass_rate_millionths, 0);
        assert_eq!(eval.pass_count, 0);
        assert_eq!(eval.fail_count, 2);
    }

    #[test]
    fn metric_kind_all_contains_all_variants() {
        // Verify ALL array covers every variant
        assert!(MetricKind::ALL.contains(&MetricKind::CompatibilityPassRate));
        assert!(MetricKind::ALL.contains(&MetricKind::ResponsivenessP99Us));
        assert!(MetricKind::ALL.contains(&MetricKind::RenderLatencyP50Us));
        assert!(MetricKind::ALL.contains(&MetricKind::RenderLatencyP95Us));
        assert!(MetricKind::ALL.contains(&MetricKind::RenderLatencyP99Us));
        assert!(MetricKind::ALL.contains(&MetricKind::BundleSizeBytes));
        assert!(MetricKind::ALL.contains(&MetricKind::RuntimeMemoryBytes));
        assert!(MetricKind::ALL.contains(&MetricKind::FallbackFrequency));
        assert!(MetricKind::ALL.contains(&MetricKind::RollbackLatencyP99Us));
        assert!(MetricKind::ALL.contains(&MetricKind::EvidenceCompleteness));
    }

    #[test]
    fn threshold_clone_preserves_metric_and_milestone() {
        let original = Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            boundary: 990_000,
        };
        let cloned = original.clone();
        assert_eq!(cloned.metric, MetricKind::EvidenceCompleteness);
        assert_eq!(cloned.milestone, Milestone::Ga);
        assert_eq!(cloned.boundary, 990_000);
    }

    #[test]
    fn threshold_result_clone_independence() {
        let original = ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // They are independent (enum variants are value types with Clone)
        assert!(cloned.is_pass());
    }
}
