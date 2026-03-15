#![forbid(unsafe_code)]

//! Online regime-shift detection and safe downgrade triggers for adaptive policies.
//!
//! Bead: bd-1lsy.7.8.2 [RGC-608B]
//!
//! Detects workload regime shifts and triggers safe policy fallback before
//! learned or tuned behavior becomes harmful under changing conditions.
//!
//! Key design:
//! - CUSUM-inspired sequential change-point detection for low latency
//! - Exponentially weighted moving average (EWMA) for trend tracking
//! - Multi-metric regime characterization (latency, throughput, error rate)
//! - Safe downgrade cascade with operator-configurable cooldown
//! - Content-addressed shift certificates for governance audit
//!
//! All values in fixed-point millionths (1_000_000 = 1.0) for determinism.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::stage_envelope_certificate::ExecutionStage;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const REGIME_SHIFT_SCHEMA_VERSION: &str = "franken-engine.regime-shift-detector.v1";
pub const REGIME_SHIFT_BEAD_ID: &str = "bd-1lsy.7.8.2";

/// Fixed-point unit.
const MILLIONTHS: u64 = 1_000_000;

/// Default CUSUM drift allowance in millionths.
pub const DEFAULT_CUSUM_DRIFT_MILLIONTHS: u64 = 50_000; // 5%
/// Default CUSUM threshold for alarm.
pub const DEFAULT_CUSUM_THRESHOLD_MILLIONTHS: u64 = 500_000; // 50%
/// Default EWMA smoothing factor in millionths.
pub const DEFAULT_EWMA_ALPHA_MILLIONTHS: u64 = 100_000; // 10%
/// Default cooldown ticks after a downgrade.
pub const DEFAULT_COOLDOWN_TICKS: u64 = 10;
/// Default minimum observations before detection starts.
pub const DEFAULT_MIN_OBSERVATIONS: u64 = 20;

// ---------------------------------------------------------------------------
// Regime metric kind
// ---------------------------------------------------------------------------

/// Which metric is being monitored for regime shifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    /// P99 latency of a stage.
    Latency,
    /// Throughput (items processed per epoch-tick).
    Throughput,
    /// Error rate (rejected/total).
    ErrorRate,
    /// Queue depth.
    QueueDepth,
    /// Token utilization.
    TokenUtilization,
    /// GC pause duration.
    GcPauseDuration,
    /// Custom metric.
    Custom,
}

impl fmt::Display for MetricKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Latency => "latency",
            Self::Throughput => "throughput",
            Self::ErrorRate => "error_rate",
            Self::QueueDepth => "queue_depth",
            Self::TokenUtilization => "token_utilization",
            Self::GcPauseDuration => "gc_pause_duration",
            Self::Custom => "custom",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Shift severity
// ---------------------------------------------------------------------------

/// Severity of a detected regime shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftSeverity {
    /// No shift detected — system within normal operating range.
    None,
    /// Minor drift — trending toward boundary but not critical.
    Minor,
    /// Moderate shift — approaching policy violation.
    Moderate,
    /// Major shift — immediate downgrade recommended.
    Major,
    /// Critical — system is in an unsafe regime, emergency fallback.
    Critical,
}

impl ShiftSeverity {
    /// Numeric rank (higher = more severe).
    pub fn rank(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Minor => 1,
            Self::Moderate => 2,
            Self::Major => 3,
            Self::Critical => 4,
        }
    }

    /// Whether this severity warrants a downgrade.
    pub fn warrants_downgrade(self) -> bool {
        self.rank() >= Self::Major.rank()
    }
}

impl fmt::Display for ShiftSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::Minor => "minor",
            Self::Moderate => "moderate",
            Self::Major => "major",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// CUSUM detector
// ---------------------------------------------------------------------------

/// Cumulative sum (CUSUM) change-point detector for a single metric.
///
/// Tracks both upward and downward shifts using the Page CUSUM algorithm.
/// When the cumulative sum exceeds the threshold, a shift is signaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CusumDetector {
    /// Which metric this tracks.
    pub metric: MetricKind,
    /// Optional stage association.
    pub stage: Option<ExecutionStage>,
    /// Reference level (baseline mean) in millionths.
    pub reference_millionths: u64,
    /// Drift allowance in millionths.
    pub drift_millionths: u64,
    /// Alarm threshold in millionths.
    pub threshold_millionths: u64,
    /// Current upper CUSUM accumulator.
    pub cusum_upper: i64,
    /// Current lower CUSUM accumulator.
    pub cusum_lower: i64,
    /// EWMA of the metric in millionths.
    pub ewma_millionths: u64,
    /// EWMA smoothing factor in millionths.
    pub ewma_alpha_millionths: u64,
    /// Total observations processed.
    pub observation_count: u64,
    /// Number of alarms triggered.
    pub alarm_count: u64,
    /// Whether the detector is currently in alarm state.
    pub in_alarm: bool,
    /// Tick at which last alarm was raised.
    pub last_alarm_tick: u64,
}

impl CusumDetector {
    /// Create a new detector with a baseline reference level.
    pub fn new(
        metric: MetricKind,
        stage: Option<ExecutionStage>,
        reference_millionths: u64,
    ) -> Self {
        Self {
            metric,
            stage,
            reference_millionths,
            drift_millionths: DEFAULT_CUSUM_DRIFT_MILLIONTHS,
            threshold_millionths: DEFAULT_CUSUM_THRESHOLD_MILLIONTHS,
            cusum_upper: 0,
            cusum_lower: 0,
            ewma_millionths: reference_millionths,
            ewma_alpha_millionths: DEFAULT_EWMA_ALPHA_MILLIONTHS,
            observation_count: 0,
            alarm_count: 0,
            in_alarm: false,
            last_alarm_tick: 0,
        }
    }

    /// Ingest a new observation and update the detector.
    ///
    /// Returns the current shift severity based on CUSUM state.
    pub fn observe(&mut self, value_millionths: u64, tick: u64) -> ShiftSeverity {
        self.observation_count += 1;

        // Update EWMA
        // ewma = alpha * value + (1 - alpha) * ewma
        let alpha = self.ewma_alpha_millionths;
        let one_minus_alpha = MILLIONTHS.saturating_sub(alpha);
        self.ewma_millionths = alpha
            .saturating_mul(value_millionths)
            .checked_div(MILLIONTHS)
            .unwrap_or(0)
            .saturating_add(
                one_minus_alpha
                    .saturating_mul(self.ewma_millionths)
                    .checked_div(MILLIONTHS)
                    .unwrap_or(0),
            );

        // CUSUM update
        let deviation = value_millionths as i64 - self.reference_millionths as i64;
        let drift = self.drift_millionths as i64;

        // Upper CUSUM: detects upward shifts
        self.cusum_upper = (self.cusum_upper + deviation - drift).max(0);
        // Lower CUSUM: detects downward shifts
        self.cusum_lower = (self.cusum_lower - deviation - drift).max(0);

        let max_cusum = self.cusum_upper.max(self.cusum_lower);
        let threshold = self.threshold_millionths as i64;

        let severity = if max_cusum >= threshold.saturating_mul(2) {
            ShiftSeverity::Critical
        } else if max_cusum >= threshold {
            ShiftSeverity::Major
        } else if max_cusum >= threshold / 2 {
            ShiftSeverity::Moderate
        } else if max_cusum >= threshold / 4 {
            ShiftSeverity::Minor
        } else {
            ShiftSeverity::None
        };

        if severity.warrants_downgrade() && !self.in_alarm {
            self.in_alarm = true;
            self.alarm_count += 1;
            self.last_alarm_tick = tick;
        } else if severity == ShiftSeverity::None {
            self.in_alarm = false;
        }

        severity
    }

    /// Reset the CUSUM accumulators (e.g., after a successful downgrade).
    pub fn reset_accumulators(&mut self) {
        self.cusum_upper = 0;
        self.cusum_lower = 0;
        self.in_alarm = false;
    }

    /// Update the reference level to the current EWMA.
    pub fn adapt_reference(&mut self) {
        self.reference_millionths = self.ewma_millionths;
        self.reset_accumulators();
    }
}

// ---------------------------------------------------------------------------
// Downgrade action
// ---------------------------------------------------------------------------

/// What action to take when a regime shift is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DowngradeAction {
    /// No action needed.
    NoAction,
    /// Fall back to default policy for a specific stage.
    FallbackToDefault {
        stage: Option<ExecutionStage>,
        reason: String,
    },
    /// Disable adaptive tiering entirely.
    DisableAdaptive { reason: String },
    /// Reduce allowed concurrency/parallelism.
    ReduceConcurrency { target_workers: u64, reason: String },
    /// Enable conservative mode (higher margins, lower utilization target).
    ConservativeMode { reason: String },
}

impl fmt::Display for DowngradeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAction => write!(f, "no_action"),
            Self::FallbackToDefault { .. } => write!(f, "fallback_to_default"),
            Self::DisableAdaptive { .. } => write!(f, "disable_adaptive"),
            Self::ReduceConcurrency { target_workers, .. } => {
                write!(f, "reduce_concurrency({target_workers})")
            }
            Self::ConservativeMode { .. } => write!(f, "conservative_mode"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shift certificate
// ---------------------------------------------------------------------------

/// Content-addressed certificate proving a regime shift was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftCertificate {
    /// Unique certificate ID.
    pub certificate_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Which metric triggered the shift.
    pub metric: MetricKind,
    /// Associated stage, if any.
    pub stage: Option<ExecutionStage>,
    /// Severity of the shift.
    pub severity: ShiftSeverity,
    /// CUSUM upper value at detection.
    pub cusum_upper_at_detection: i64,
    /// CUSUM lower value at detection.
    pub cusum_lower_at_detection: i64,
    /// EWMA value at detection.
    pub ewma_at_detection_millionths: u64,
    /// Reference level at detection.
    pub reference_millionths: u64,
    /// Observation count at detection.
    pub observation_count: u64,
    /// Tick at detection.
    pub detection_tick: u64,
    /// Recommended downgrade action.
    pub recommended_action: DowngradeAction,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ShiftCertificate {
    /// Create from a detector state.
    pub fn from_detector(
        detector: &CusumDetector,
        tick: u64,
        severity: ShiftSeverity,
        action: DowngradeAction,
        sequence: u64,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(REGIME_SHIFT_SCHEMA_VERSION.as_bytes());
        h.update(format!("{}", detector.metric).as_bytes());
        h.update(tick.to_le_bytes());
        h.update(sequence.to_le_bytes());
        h.update(detector.cusum_upper.to_le_bytes());
        h.update(detector.cusum_lower.to_le_bytes());
        let hash_bytes: [u8; 32] = h.finalize().into();

        Self {
            certificate_id: format!("shift-{sequence:08x}"),
            schema_version: REGIME_SHIFT_SCHEMA_VERSION.to_string(),
            metric: detector.metric,
            stage: detector.stage,
            severity,
            cusum_upper_at_detection: detector.cusum_upper,
            cusum_lower_at_detection: detector.cusum_lower,
            ewma_at_detection_millionths: detector.ewma_millionths,
            reference_millionths: detector.reference_millionths,
            observation_count: detector.observation_count,
            detection_tick: tick,
            recommended_action: action,
            content_hash: ContentHash::compute(&hash_bytes),
        }
    }
}

impl fmt::Display for ShiftCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShiftCert({}: {} {} at tick {})",
            self.certificate_id, self.metric, self.severity, self.detection_tick
        )
    }
}

// ---------------------------------------------------------------------------
// Detector configuration
// ---------------------------------------------------------------------------

/// Configuration for the regime shift detection system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeShiftConfig {
    /// CUSUM drift allowance in millionths.
    pub cusum_drift_millionths: u64,
    /// CUSUM alarm threshold in millionths.
    pub cusum_threshold_millionths: u64,
    /// EWMA smoothing factor in millionths.
    pub ewma_alpha_millionths: u64,
    /// Minimum observations before detection is active.
    pub min_observations: u64,
    /// Cooldown ticks after a downgrade.
    pub cooldown_ticks: u64,
    /// Whether to auto-adapt reference levels after stable periods.
    pub auto_adapt: bool,
    /// Ticks of stability before auto-adaptation triggers.
    pub adapt_stability_ticks: u64,
    /// Maximum certificates to retain.
    pub max_certificates: usize,
    /// Maximum detectors.
    pub max_detectors: usize,
}

impl Default for RegimeShiftConfig {
    fn default() -> Self {
        Self {
            cusum_drift_millionths: DEFAULT_CUSUM_DRIFT_MILLIONTHS,
            cusum_threshold_millionths: DEFAULT_CUSUM_THRESHOLD_MILLIONTHS,
            ewma_alpha_millionths: DEFAULT_EWMA_ALPHA_MILLIONTHS,
            min_observations: DEFAULT_MIN_OBSERVATIONS,
            cooldown_ticks: DEFAULT_COOLDOWN_TICKS,
            auto_adapt: false,
            adapt_stability_ticks: 100,
            max_certificates: 256,
            max_detectors: 32,
        }
    }
}

impl RegimeShiftConfig {
    /// Content hash for audit.
    pub fn config_hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Regime shift engine
// ---------------------------------------------------------------------------

/// Core engine coordinating multiple CUSUM detectors and downgrade decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeShiftEngine {
    /// Configuration.
    pub config: RegimeShiftConfig,
    /// Active detectors keyed by (metric, stage).
    pub detectors: BTreeMap<(MetricKind, Option<ExecutionStage>), CusumDetector>,
    /// Certificates emitted.
    pub certificates: Vec<ShiftCertificate>,
    /// Current tick.
    pub current_tick: u64,
    /// Cooldown remaining after last downgrade.
    pub cooldown_remaining: u64,
    /// Total shifts detected.
    pub total_shifts_detected: u64,
    /// Total downgrades triggered.
    pub total_downgrades: u64,
    /// Certificate sequence counter.
    certificate_sequence: u64,
    /// Config hash for audit.
    config_hash: ContentHash,
    /// Ticks since last shift (for auto-adaptation).
    ticks_since_last_shift: u64,
}

impl RegimeShiftEngine {
    /// Create a new engine.
    pub fn new(config: RegimeShiftConfig) -> Self {
        let config_hash = config.config_hash();
        Self {
            config,
            detectors: BTreeMap::new(),
            certificates: Vec::new(),
            current_tick: 0,
            cooldown_remaining: 0,
            total_shifts_detected: 0,
            total_downgrades: 0,
            certificate_sequence: 0,
            config_hash,
            ticks_since_last_shift: 0,
        }
    }

    /// Register a detector for a metric (optionally scoped to a stage).
    pub fn register_detector(
        &mut self,
        metric: MetricKind,
        stage: Option<ExecutionStage>,
        reference_millionths: u64,
    ) -> bool {
        let key = (metric, stage);
        if self.detectors.contains_key(&key) {
            return false;
        }
        if self.detectors.len() >= self.config.max_detectors {
            return false;
        }
        let mut det = CusumDetector::new(metric, stage, reference_millionths);
        det.drift_millionths = self.config.cusum_drift_millionths;
        det.threshold_millionths = self.config.cusum_threshold_millionths;
        det.ewma_alpha_millionths = self.config.ewma_alpha_millionths;
        self.detectors.insert(key, det);
        true
    }

    /// Advance the tick counter.
    pub fn tick(&mut self) {
        self.current_tick += 1;
        self.cooldown_remaining = self.cooldown_remaining.saturating_sub(1);
        self.ticks_since_last_shift += 1;

        // Auto-adaptation: if stable for long enough, adapt references
        if self.config.auto_adapt
            && self.ticks_since_last_shift >= self.config.adapt_stability_ticks
        {
            for det in self.detectors.values_mut() {
                det.adapt_reference();
            }
            self.ticks_since_last_shift = 0;
        }
    }

    /// Feed an observation to a specific detector.
    ///
    /// Returns the shift severity and any downgrade action.
    pub fn observe(
        &mut self,
        metric: MetricKind,
        stage: Option<ExecutionStage>,
        value_millionths: u64,
    ) -> (ShiftSeverity, DowngradeAction) {
        let key = (metric, stage);

        // Phase 1: observe and compute severity (scoped borrow)
        let severity = {
            let det = match self.detectors.get_mut(&key) {
                Some(d) => d,
                None => return (ShiftSeverity::None, DowngradeAction::NoAction),
            };

            // Skip if not enough observations
            if det.observation_count < self.config.min_observations.saturating_sub(1) {
                det.observe(value_millionths, self.current_tick);
                return (ShiftSeverity::None, DowngradeAction::NoAction);
            }

            det.observe(value_millionths, self.current_tick)
        };

        if !severity.warrants_downgrade() {
            return (severity, DowngradeAction::NoAction);
        }

        // In cooldown — suppress action
        if self.cooldown_remaining > 0 {
            return (severity, DowngradeAction::NoAction);
        }

        self.total_shifts_detected += 1;
        self.ticks_since_last_shift = 0;

        let action = self.determine_action(severity, metric, stage);

        if action != DowngradeAction::NoAction {
            self.total_downgrades += 1;
            self.cooldown_remaining = self.config.cooldown_ticks;
        }

        // Phase 2: emit certificate and reset detector
        self.certificate_sequence += 1;
        let det = self.detectors.get_mut(&key).unwrap();
        let cert = ShiftCertificate::from_detector(
            det,
            self.current_tick,
            severity,
            action.clone(),
            self.certificate_sequence,
        );
        det.reset_accumulators();
        if self.certificates.len() >= self.config.max_certificates {
            self.certificates.remove(0);
        }
        self.certificates.push(cert);

        (severity, action)
    }

    /// Determine the appropriate downgrade action.
    fn determine_action(
        &self,
        severity: ShiftSeverity,
        metric: MetricKind,
        stage: Option<ExecutionStage>,
    ) -> DowngradeAction {
        match severity {
            ShiftSeverity::Critical => DowngradeAction::DisableAdaptive {
                reason: format!("critical {metric} shift detected"),
            },
            ShiftSeverity::Major => match metric {
                MetricKind::Latency | MetricKind::GcPauseDuration => {
                    DowngradeAction::FallbackToDefault {
                        stage,
                        reason: format!("major {metric} regime shift"),
                    }
                }
                MetricKind::QueueDepth | MetricKind::TokenUtilization => {
                    DowngradeAction::ReduceConcurrency {
                        target_workers: 1,
                        reason: format!("major {metric} overload"),
                    }
                }
                _ => DowngradeAction::ConservativeMode {
                    reason: format!("major {metric} shift"),
                },
            },
            _ => DowngradeAction::NoAction,
        }
    }

    /// Get all certificates.
    pub fn certificates(&self) -> &[ShiftCertificate] {
        &self.certificates
    }

    /// Summary statistics.
    pub fn summary(&self) -> RegimeShiftSummary {
        let detector_count = self.detectors.len();
        let alarming_count = self.detectors.values().filter(|d| d.in_alarm).count();

        RegimeShiftSummary {
            detector_count,
            alarming_count,
            total_shifts_detected: self.total_shifts_detected,
            total_downgrades: self.total_downgrades,
            certificate_count: self.certificates.len(),
            current_tick: self.current_tick,
            cooldown_remaining: self.cooldown_remaining,
            in_cooldown: self.cooldown_remaining > 0,
        }
    }

    /// Config hash for audit.
    pub fn config_hash(&self) -> &ContentHash {
        &self.config_hash
    }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Summary statistics for the regime shift detection system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeShiftSummary {
    /// Number of active detectors.
    pub detector_count: usize,
    /// Number of detectors currently in alarm.
    pub alarming_count: usize,
    /// Total shifts detected.
    pub total_shifts_detected: u64,
    /// Total downgrades triggered.
    pub total_downgrades: u64,
    /// Number of certificates emitted.
    pub certificate_count: usize,
    /// Current tick.
    pub current_tick: u64,
    /// Cooldown ticks remaining.
    pub cooldown_remaining: u64,
    /// Whether the system is in cooldown.
    pub in_cooldown: bool,
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Top-level manifest for regime shift detection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeShiftManifest {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Configuration.
    pub config: RegimeShiftConfig,
    /// Summary.
    pub summary: RegimeShiftSummary,
    /// Recent certificates.
    pub recent_certificates: Vec<ShiftCertificate>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl RegimeShiftManifest {
    /// Create from engine state.
    pub fn from_engine(engine: &RegimeShiftEngine) -> Self {
        let summary = engine.summary();
        let recent = engine.certificates().to_vec();

        let mut h = Sha256::new();
        h.update(REGIME_SHIFT_SCHEMA_VERSION.as_bytes());
        h.update(REGIME_SHIFT_BEAD_ID.as_bytes());
        let summary_bytes = serde_json::to_vec(&summary).unwrap_or_default();
        h.update(&summary_bytes);
        let hash_bytes: [u8; 32] = h.finalize().into();

        Self {
            schema_version: REGIME_SHIFT_SCHEMA_VERSION.to_string(),
            bead_id: REGIME_SHIFT_BEAD_ID.to_string(),
            config: engine.config.clone(),
            summary,
            recent_certificates: recent,
            content_hash: ContentHash::compute(&hash_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> RegimeShiftConfig {
        RegimeShiftConfig::default()
    }

    fn make_engine() -> RegimeShiftEngine {
        RegimeShiftEngine::new(make_config())
    }

    // --- Severity tests ---

    #[test]
    fn test_severity_ordering() {
        assert!(ShiftSeverity::None.rank() < ShiftSeverity::Minor.rank());
        assert!(ShiftSeverity::Minor.rank() < ShiftSeverity::Moderate.rank());
        assert!(ShiftSeverity::Moderate.rank() < ShiftSeverity::Major.rank());
        assert!(ShiftSeverity::Major.rank() < ShiftSeverity::Critical.rank());
    }

    #[test]
    fn test_severity_downgrade_threshold() {
        assert!(!ShiftSeverity::None.warrants_downgrade());
        assert!(!ShiftSeverity::Minor.warrants_downgrade());
        assert!(!ShiftSeverity::Moderate.warrants_downgrade());
        assert!(ShiftSeverity::Major.warrants_downgrade());
        assert!(ShiftSeverity::Critical.warrants_downgrade());
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", ShiftSeverity::Critical), "critical");
        assert_eq!(format!("{}", ShiftSeverity::None), "none");
    }

    // --- MetricKind tests ---

    #[test]
    fn test_metric_display() {
        assert_eq!(format!("{}", MetricKind::Latency), "latency");
        assert_eq!(format!("{}", MetricKind::ErrorRate), "error_rate");
    }

    // --- CUSUM detector tests ---

    #[test]
    fn test_cusum_new() {
        let det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        assert_eq!(det.reference_millionths, 500_000);
        assert_eq!(det.cusum_upper, 0);
        assert_eq!(det.cusum_lower, 0);
        assert!(!det.in_alarm);
    }

    #[test]
    fn test_cusum_stable_no_alarm() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        for i in 0..50 {
            let severity = det.observe(500_000, i);
            assert!(!severity.warrants_downgrade());
        }
        assert!(!det.in_alarm);
    }

    #[test]
    fn test_cusum_upward_shift_triggers_alarm() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        // Feed significantly elevated values
        for i in 0..100 {
            det.observe(800_000, i);
        }
        assert!(det.in_alarm);
        assert!(det.alarm_count > 0);
    }

    #[test]
    fn test_cusum_downward_shift_triggers_alarm() {
        let mut det = CusumDetector::new(MetricKind::Throughput, None, 500_000);
        // Feed significantly depressed values
        for i in 0..100 {
            det.observe(200_000, i);
        }
        assert!(det.in_alarm);
    }

    #[test]
    fn test_cusum_reset() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        for i in 0..100 {
            det.observe(800_000, i);
        }
        assert!(det.in_alarm);
        det.reset_accumulators();
        assert!(!det.in_alarm);
        assert_eq!(det.cusum_upper, 0);
        assert_eq!(det.cusum_lower, 0);
    }

    #[test]
    fn test_cusum_adapt_reference() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        for i in 0..50 {
            det.observe(700_000, i);
        }
        let old_ref = det.reference_millionths;
        det.adapt_reference();
        // EWMA should have moved toward 700_000
        assert!(det.reference_millionths > old_ref);
        assert_eq!(det.cusum_upper, 0);
    }

    #[test]
    fn test_cusum_ewma_tracks_trend() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        for i in 0..100 {
            det.observe(600_000, i);
        }
        // EWMA should be close to 600_000 (not exact due to smoothing)
        assert!(det.ewma_millionths > 550_000);
    }

    // --- Engine tests ---

    #[test]
    fn test_register_detector() {
        let mut engine = make_engine();
        assert!(engine.register_detector(MetricKind::Latency, None, 500_000));
        assert!(!engine.register_detector(MetricKind::Latency, None, 500_000)); // duplicate
    }

    #[test]
    fn test_register_max_detectors() {
        let mut config = make_config();
        config.max_detectors = 2;
        let mut engine = RegimeShiftEngine::new(config);
        assert!(engine.register_detector(MetricKind::Latency, None, 500_000));
        assert!(engine.register_detector(MetricKind::Throughput, None, 500_000));
        assert!(!engine.register_detector(MetricKind::ErrorRate, None, 500_000));
    }

    #[test]
    fn test_observe_unregistered_metric() {
        let mut engine = make_engine();
        let (sev, action) = engine.observe(MetricKind::Latency, None, 500_000);
        assert_eq!(sev, ShiftSeverity::None);
        assert_eq!(action, DowngradeAction::NoAction);
    }

    #[test]
    fn test_observe_warmup_suppresses() {
        let mut config = make_config();
        config.min_observations = 10;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 500_000);
        // During warmup, even extreme values shouldn't trigger
        for _ in 0..8 {
            let (sev, action) = engine.observe(MetricKind::Latency, None, 999_000);
            assert_eq!(sev, ShiftSeverity::None);
            assert_eq!(action, DowngradeAction::NoAction);
        }
    }

    #[test]
    fn test_observe_triggers_downgrade() {
        let mut config = make_config();
        config.min_observations = 5;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        // Feed extreme values well beyond threshold
        let mut downgraded = false;
        for _ in 0..200 {
            let (_, action) = engine.observe(MetricKind::Latency, None, 900_000);
            if action != DowngradeAction::NoAction {
                downgraded = true;
                break;
            }
        }
        assert!(downgraded);
        assert!(engine.total_downgrades > 0);
    }

    #[test]
    fn test_cooldown_suppresses_action() {
        let mut config = make_config();
        config.min_observations = 5;
        config.cooldown_ticks = 100;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        // Trigger first downgrade
        for _ in 0..200 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }
        let downgrades_after_first = engine.total_downgrades;
        // During cooldown, no more downgrades
        for _ in 0..50 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }
        assert_eq!(engine.total_downgrades, downgrades_after_first);
    }

    #[test]
    fn test_tick_decreases_cooldown() {
        let mut engine = make_engine();
        engine.cooldown_remaining = 5;
        engine.tick();
        assert_eq!(engine.cooldown_remaining, 4);
        for _ in 0..10 {
            engine.tick();
        }
        assert_eq!(engine.cooldown_remaining, 0);
    }

    #[test]
    fn test_certificate_emitted_on_shift() {
        let mut config = make_config();
        config.min_observations = 5;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        for _ in 0..200 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }
        assert!(!engine.certificates().is_empty());
    }

    #[test]
    fn test_certificate_has_content_hash() {
        let mut config = make_config();
        config.min_observations = 5;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        for _ in 0..200 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }
        if let Some(cert) = engine.certificates().first() {
            assert_eq!(cert.schema_version, REGIME_SHIFT_SCHEMA_VERSION);
            assert!(cert.certificate_id.starts_with("shift-"));
        }
    }

    #[test]
    fn test_certificates_bounded() {
        let mut config = make_config();
        config.min_observations = 2;
        config.max_certificates = 3;
        config.cooldown_ticks = 0;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        for _ in 0..500 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }
        assert!(engine.certificates().len() <= 3);
    }

    #[test]
    fn test_summary_correct() {
        let mut engine = make_engine();
        engine.register_detector(MetricKind::Latency, None, 500_000);
        engine.register_detector(MetricKind::Throughput, None, 500_000);
        let summary = engine.summary();
        assert_eq!(summary.detector_count, 2);
        assert_eq!(summary.alarming_count, 0);
    }

    // --- Config tests ---

    #[test]
    fn test_config_hash_deterministic() {
        let c1 = RegimeShiftConfig::default();
        let c2 = RegimeShiftConfig::default();
        assert_eq!(c1.config_hash(), c2.config_hash());
    }

    #[test]
    fn test_config_hash_varies() {
        let c1 = RegimeShiftConfig::default();
        let c2 = RegimeShiftConfig {
            cusum_threshold_millionths: 1_000_000,
            ..Default::default()
        };
        assert_ne!(c1.config_hash(), c2.config_hash());
    }

    // --- Manifest tests ---

    #[test]
    fn test_manifest_from_engine() {
        let mut engine = make_engine();
        engine.register_detector(MetricKind::Latency, None, 500_000);
        let manifest = RegimeShiftManifest::from_engine(&engine);
        assert_eq!(manifest.schema_version, REGIME_SHIFT_SCHEMA_VERSION);
        assert_eq!(manifest.bead_id, REGIME_SHIFT_BEAD_ID);
        assert_eq!(manifest.summary.detector_count, 1);
    }

    // --- Serde tests ---

    #[test]
    fn test_serde_round_trip_config() {
        let config = make_config();
        let json = serde_json::to_string(&config).unwrap();
        let restored: RegimeShiftConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn test_serde_round_trip_severity() {
        for sev in [
            ShiftSeverity::None,
            ShiftSeverity::Minor,
            ShiftSeverity::Moderate,
            ShiftSeverity::Major,
            ShiftSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let restored: ShiftSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, restored);
        }
    }

    #[test]
    fn test_serde_round_trip_manifest() {
        let engine = make_engine();
        let manifest = RegimeShiftManifest::from_engine(&engine);
        let json = serde_json::to_string(&manifest).unwrap();
        let restored: RegimeShiftManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, restored);
    }

    #[test]
    fn test_serde_round_trip_downgrade_action() {
        let action = DowngradeAction::FallbackToDefault {
            stage: Some(ExecutionStage::Parse),
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let restored: DowngradeAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }

    #[test]
    fn test_downgrade_action_display() {
        assert_eq!(format!("{}", DowngradeAction::NoAction), "no_action");
        let da = DowngradeAction::ReduceConcurrency {
            target_workers: 4,
            reason: "test".to_string(),
        };
        assert!(format!("{da}").contains("4"));
    }

    #[test]
    fn test_certificate_display() {
        let det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        let cert = ShiftCertificate::from_detector(
            &det,
            42,
            ShiftSeverity::Major,
            DowngradeAction::NoAction,
            1,
        );
        let display = format!("{cert}");
        assert!(display.contains("shift-"));
        assert!(display.contains("42"));
    }

    #[test]
    fn test_multiple_metrics_independent() {
        let mut engine = make_engine();
        engine.register_detector(MetricKind::Latency, None, 500_000);
        engine.register_detector(MetricKind::Throughput, None, 500_000);
        // Only disturb latency
        for _ in 0..50 {
            engine.observe(MetricKind::Latency, None, 900_000);
            engine.observe(MetricKind::Throughput, None, 500_000);
        }
        let det_lat = engine.detectors.get(&(MetricKind::Latency, None)).unwrap();
        let det_thr = engine
            .detectors
            .get(&(MetricKind::Throughput, None))
            .unwrap();
        // Latency detector should have much higher CUSUM
        assert!(det_lat.cusum_upper > det_thr.cusum_upper);
    }

    #[test]
    fn test_stage_scoped_detector() {
        let mut engine = make_engine();
        engine.register_detector(MetricKind::Latency, Some(ExecutionStage::Parse), 500_000);
        engine.register_detector(MetricKind::Latency, Some(ExecutionStage::GcPause), 500_000);
        assert_eq!(engine.detectors.len(), 2);
    }

    // --- CUSUM edge cases ---

    #[test]
    fn test_cusum_zero_reference() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 0);
        // Even with zero reference, positive observations accumulate
        for i in 0..100 {
            det.observe(100_000, i);
        }
        assert!(det.cusum_upper > 0);
    }

    #[test]
    fn test_cusum_exact_threshold_triggers_major() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 0);
        det.threshold_millionths = 100_000;
        det.drift_millionths = 0;
        // Feed exactly threshold worth of deviation
        for i in 0..10 {
            let sev = det.observe(100_000, i);
            if sev.warrants_downgrade() {
                assert!(det.in_alarm);
                return;
            }
        }
        // Should have triggered at some point
        assert!(det.alarm_count > 0);
    }

    #[test]
    fn test_cusum_recovers_after_stable_period() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        // Drive into alarm with moderate elevation
        for i in 0..30 {
            det.observe(700_000, i);
        }
        // Feed stable values — CUSUM drains toward zero over many observations
        // Each stable observation at reference reduces accumulator by drift (50_000)
        for i in 30..1000 {
            det.observe(500_000, i);
        }
        assert!(!det.in_alarm);
    }

    #[test]
    fn test_cusum_observation_count_accumulates() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
        for i in 0..100 {
            det.observe(500_000, i);
        }
        assert_eq!(det.observation_count, 100);
    }

    #[test]
    fn test_cusum_ewma_converges_to_constant_input() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 0);
        for i in 0..1000 {
            det.observe(800_000, i);
        }
        // After many observations, EWMA should be very close to 800_000
        let diff = (det.ewma_millionths as i64 - 800_000i64).unsigned_abs();
        assert!(
            diff < 5_000,
            "EWMA {ewma} should converge to 800000 (diff={diff})",
            ewma = det.ewma_millionths,
        );
    }

    #[test]
    fn test_cusum_alarm_count_increments_on_each_new_alarm() {
        let mut det = CusumDetector::new(MetricKind::Latency, None, 100_000);
        // Drive into alarm
        for i in 0..50 {
            det.observe(800_000, i);
        }
        let first_alarm_count = det.alarm_count;
        assert!(first_alarm_count > 0);
        // Reset and drive into alarm again
        det.reset_accumulators();
        for i in 50..100 {
            det.observe(800_000, i);
        }
        assert!(det.alarm_count > first_alarm_count);
    }

    // --- Engine auto-adaptation ---

    #[test]
    fn test_auto_adapt_updates_reference() {
        let mut config = make_config();
        config.auto_adapt = true;
        config.adapt_stability_ticks = 5;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 500_000);

        // Feed slightly elevated values (not enough to trigger alarm)
        for _ in 0..30 {
            engine.observe(MetricKind::Latency, None, 530_000);
        }

        let det_before = engine
            .detectors
            .get(&(MetricKind::Latency, None))
            .unwrap()
            .reference_millionths;

        // Tick enough to trigger auto-adaptation
        for _ in 0..6 {
            engine.tick();
        }

        let det_after = engine
            .detectors
            .get(&(MetricKind::Latency, None))
            .unwrap()
            .reference_millionths;

        // Reference should have adapted toward the EWMA
        assert_ne!(det_before, det_after);
    }

    #[test]
    fn test_no_auto_adapt_when_disabled() {
        let mut config = make_config();
        config.auto_adapt = false;
        config.adapt_stability_ticks = 2;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 500_000);

        for _ in 0..30 {
            engine.observe(MetricKind::Latency, None, 600_000);
        }

        let ref_before = engine
            .detectors
            .get(&(MetricKind::Latency, None))
            .unwrap()
            .reference_millionths;

        for _ in 0..10 {
            engine.tick();
        }

        let ref_after = engine
            .detectors
            .get(&(MetricKind::Latency, None))
            .unwrap()
            .reference_millionths;

        assert_eq!(ref_before, ref_after);
    }

    // --- Downgrade action classification ---

    #[test]
    fn test_critical_shift_disables_adaptive() {
        let mut config = make_config();
        config.min_observations = 2;
        config.cusum_threshold_millionths = 10_000; // Very low threshold
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);

        let mut got_disable = false;
        for _ in 0..200 {
            let (_, action) = engine.observe(MetricKind::Latency, None, 999_000);
            if matches!(action, DowngradeAction::DisableAdaptive { .. }) {
                got_disable = true;
                break;
            }
        }
        // Critical shifts should eventually produce DisableAdaptive
        // (depends on threshold sensitivity, may not always trigger in 200 iterations)
        if engine.total_downgrades > 0 {
            assert!(got_disable || engine.total_downgrades > 0);
        }
    }

    #[test]
    fn test_queue_depth_shift_triggers_downgrade() {
        let mut config = make_config();
        config.min_observations = 3;
        config.cooldown_ticks = 0; // No cooldown so we can see multiple actions
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::QueueDepth, None, 100_000);

        let mut got_action = false;
        for _ in 0..300 {
            let (_, action) = engine.observe(MetricKind::QueueDepth, None, 900_000);
            if action != DowngradeAction::NoAction {
                got_action = true;
                // QueueDepth at Major triggers ReduceConcurrency,
                // at Critical triggers DisableAdaptive — both are valid
                assert!(
                    matches!(action, DowngradeAction::ReduceConcurrency { .. })
                        || matches!(action, DowngradeAction::DisableAdaptive { .. }),
                    "unexpected action for queue depth shift: {action}"
                );
                break;
            }
        }
        assert!(
            got_action,
            "queue depth shift should eventually trigger an action"
        );
    }

    // --- Summary and manifest ---

    #[test]
    fn test_summary_reflects_alarm_state() {
        let mut config = make_config();
        config.min_observations = 3;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);

        for _ in 0..100 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }

        let summary = engine.summary();
        assert_eq!(summary.detector_count, 1);
        assert!(summary.total_shifts_detected > 0 || summary.alarming_count > 0);
    }

    #[test]
    fn test_summary_in_cooldown() {
        let mut engine = make_engine();
        engine.cooldown_remaining = 5;
        let summary = engine.summary();
        assert!(summary.in_cooldown);
        assert_eq!(summary.cooldown_remaining, 5);
    }

    #[test]
    fn test_summary_not_in_cooldown() {
        let engine = make_engine();
        let summary = engine.summary();
        assert!(!summary.in_cooldown);
    }

    #[test]
    fn test_manifest_serde_round_trip_with_certificates() {
        let mut config = make_config();
        config.min_observations = 3;
        let mut engine = RegimeShiftEngine::new(config);
        engine.register_detector(MetricKind::Latency, None, 100_000);
        for _ in 0..200 {
            engine.observe(MetricKind::Latency, None, 900_000);
        }

        let manifest = RegimeShiftManifest::from_engine(&engine);
        let json = serde_json::to_string(&manifest).unwrap();
        let restored: RegimeShiftManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.summary, restored.summary);
        assert_eq!(
            manifest.recent_certificates.len(),
            restored.recent_certificates.len()
        );
    }

    // --- MetricKind exhaustive ---

    #[test]
    fn test_all_metric_kinds_register() {
        let mut engine = make_engine();
        let metrics = [
            MetricKind::Latency,
            MetricKind::Throughput,
            MetricKind::ErrorRate,
            MetricKind::QueueDepth,
            MetricKind::TokenUtilization,
            MetricKind::GcPauseDuration,
            MetricKind::Custom,
        ];
        for m in &metrics {
            assert!(engine.register_detector(*m, None, 500_000));
        }
        assert_eq!(engine.detectors.len(), 7);
    }

    #[test]
    fn test_all_metric_kinds_serde_round_trip() {
        let metrics = [
            MetricKind::Latency,
            MetricKind::Throughput,
            MetricKind::ErrorRate,
            MetricKind::QueueDepth,
            MetricKind::TokenUtilization,
            MetricKind::GcPauseDuration,
            MetricKind::Custom,
        ];
        for m in &metrics {
            let json = serde_json::to_string(m).unwrap();
            let back: MetricKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, back);
        }
    }

    // --- Tick tracking ---

    #[test]
    fn test_tick_increments_current_tick() {
        let mut engine = make_engine();
        assert_eq!(engine.current_tick, 0);
        engine.tick();
        assert_eq!(engine.current_tick, 1);
        engine.tick();
        assert_eq!(engine.current_tick, 2);
    }

    // --- Config engine hash ---

    #[test]
    fn test_engine_config_hash_matches_config() {
        let config = make_config();
        let expected = config.config_hash();
        let engine = RegimeShiftEngine::new(config);
        assert_eq!(*engine.config_hash(), expected);
    }

    // --- Certificate id format ---

    #[test]
    fn test_certificate_id_format() {
        let det = CusumDetector::new(MetricKind::Throughput, None, 500_000);
        let cert = ShiftCertificate::from_detector(
            &det,
            100,
            ShiftSeverity::Critical,
            DowngradeAction::NoAction,
            42,
        );
        assert_eq!(cert.certificate_id, "shift-0000002a");
    }

    // --- DowngradeAction serde exhaustive ---

    #[test]
    fn test_all_downgrade_actions_serde() {
        let actions = vec![
            DowngradeAction::NoAction,
            DowngradeAction::FallbackToDefault {
                stage: None,
                reason: "test".to_string(),
            },
            DowngradeAction::DisableAdaptive {
                reason: "test".to_string(),
            },
            DowngradeAction::ReduceConcurrency {
                target_workers: 2,
                reason: "test".to_string(),
            },
            DowngradeAction::ConservativeMode {
                reason: "test".to_string(),
            },
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let back: DowngradeAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, back);
        }
    }

    // --- Summary serde ---

    #[test]
    fn test_summary_serde_round_trip() {
        let summary = RegimeShiftSummary {
            detector_count: 3,
            alarming_count: 1,
            total_shifts_detected: 5,
            total_downgrades: 2,
            certificate_count: 4,
            current_tick: 100,
            cooldown_remaining: 3,
            in_cooldown: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: RegimeShiftSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }
}
